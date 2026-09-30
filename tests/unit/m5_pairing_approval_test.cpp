// Issue #2 (HEY-20260929-001): passwordless pairing approval over a real
// two-node LAN pair. A establishes a restricted connection to B and submits
// a trust request through Node::request_pairing_approval; B observes the
// pending request (device identity, wire request id, requested scopes) via
// set_pairing_request_observer and resolves it through approve_pairing /
// reject_pairing. Contracts under test: one observer-fired pending request
// per admitted submission, exactly one terminal pairing-observer outcome per
// side, policy-intersected grants bound to the request nonce, stable denials
// without grants, deadline resolution, duplicate discipline, and shutdown
// resolution. Session-level wire semantics live in m5_session_test.cpp.

#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/trust_grant.hpp>

#include <executor/comm.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

constexpr std::uint64_t kNow = 1'700'000'000'000U;
constexpr const char* kApplicationId = "com.example.m5-pairing-approval";
constexpr std::string_view kTargetPassword = "target-password";

template <typename Storage, std::size_t Size = sizeof(Storage)>
Storage filled(std::uint8_t seed) {
  Storage storage{};
  auto* bytes = reinterpret_cast<std::uint8_t*>(&storage);
  for (std::size_t index = 0U; index < Size; ++index) {
    bytes[index] = static_cast<std::uint8_t>(seed + index);
  }
  return storage;
}

LanConfiguration fast_lan_only() {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  return configuration;
}

// One pairing-observer terminal outcome, flattened for thread-safe recording
// (the observer runs on the node's strand).
struct RecordedPairingOutcome {
  DeviceEndpointKey peer;
  bool success{false};
  ErrorCode code{ErrorCode::internal};
  std::string component;
  std::string detail;
  std::vector<std::string> scopes;
};

class PairingObserverRecorder {
 public:
  void attach(Node& node) {
    node.set_pairing_observer(
        [this](const DeviceEndpointKey& peer, const NodePairingOutcome& outcome) {
          RecordedPairingOutcome recorded;
          recorded.peer = peer;
          if (const auto* scopes = outcome.value_if()) {
            recorded.success = true;
            recorded.scopes = *scopes;
          } else {
            recorded.code = outcome.error_if()->code();
            recorded.component = std::string{outcome.error_if()->component()};
            recorded.detail = std::string{outcome.error_if()->safe_detail()};
          }
          const std::lock_guard<std::mutex> guard{mutex_};
          events_.push_back(std::move(recorded));
        });
  }

  [[nodiscard]] std::vector<RecordedPairingOutcome> snapshot() const {
    const std::lock_guard<std::mutex> guard{mutex_};
    return events_;
  }

  [[nodiscard]] std::size_t size() const {
    const std::lock_guard<std::mutex> guard{mutex_};
    return events_.size();
  }

 private:
  mutable std::mutex mutex_;
  std::vector<RecordedPairingOutcome> events_;
};

// Receiver-side pending-approval observations: exactly one per admitted
// request while the app must decide.
struct RecordedApprovalRequest {
  DeviceEndpointKey peer;
  RequestId request_id;
  PairingNonce nonce;
  std::vector<std::string> requested_scopes;
};

class ApprovalRequestRecorder {
 public:
  void attach(Node& node) {
    node.set_pairing_request_observer(
        [this](const DeviceEndpointKey& peer,
               const PairingApprovalRequestBody& request) {
          RecordedApprovalRequest recorded;
          recorded.peer = peer;
          recorded.request_id = request.request_id;
          recorded.nonce = request.nonce;
          recorded.requested_scopes = request.requested_scopes;
          const std::lock_guard<std::mutex> guard{mutex_};
          events_.push_back(std::move(recorded));
        });
  }

  [[nodiscard]] std::vector<RecordedApprovalRequest> snapshot() const {
    const std::lock_guard<std::mutex> guard{mutex_};
    return events_;
  }

  [[nodiscard]] std::size_t size() const {
    const std::lock_guard<std::mutex> guard{mutex_};
    return events_.size();
  }

 private:
  mutable std::mutex mutex_;
  std::vector<RecordedApprovalRequest> events_;
};

struct NodePairHandles {
  std::optional<ProfileStore> first_store;   // initiator (A)
  std::optional<ProfileStore> second_store;  // responder / approver (B)
  std::optional<Node> first;
  std::optional<Node> second;
  DeviceEndpointKey first_key;
  DeviceEndpointKey second_key;
};

class M5PairingApprovalTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M5_PAIRING_APPROVAL_TEST_STATE_DIR} /
            ("node-" + std::to_string(
                           ::testing::UnitTest::GetInstance()->random_seed()));
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
    std::filesystem::create_directories(root_);
    std::filesystem::permissions(root_.parent_path(),
                                 std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    std::filesystem::permissions(root_, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
  }

  void TearDown() override {
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
  }

  Result<ProfileStore> initialized_profile(
      const std::string& name, std::optional<std::string_view> password,
      const std::vector<std::string>& policy_scopes) {
    ProfileOpenOptions options;
    options.secret_backend.prefer_os_backend = false;
    auto profile = ProfileStore::create(root_ / name / "profile.sqlite", options);
    if (!profile) {
      return profile;
    }
    PasswordVerifier verifier{.format_version = 1U,
                              .parameters = PasswordHashParameters{},
                              .encoded = "$argon2id$v=19$m=65536,t=2,p=1$test$test"};
    if (password.has_value()) {
      auto created = create_password_verifier(*password, PasswordHashParameters{});
      if (!created) {
        return Result<ProfileStore>::failure(*created.error_if());
      }
      verifier = std::move(*created.value_if());
    }
    PairingPolicy policy{};
    policy.default_scopes = policy_scopes;
    LocalProfileInitialization initialization{
        .application_id = kApplicationId,
        .password_verifier = std::move(verifier),
        .password_generation = 1U,
        .pairing_policy = policy,
        .lan = fast_lan_only()};
    auto initialized = profile.value_if()->initialize_local(initialization);
    if (!initialized) {
      return Result<ProfileStore>::failure(*initialized.error_if());
    }
    return profile;
  }

  static NodeConfig node_config(ProfileStore& store,
                                std::chrono::milliseconds pairing_deadline,
                                bool approval_enabled) {
    return NodeConfig{.profile = &store,
                      .runtime = nullptr,
                      .application_id = kApplicationId,
                      .lan_override = fast_lan_only(),
                      .runtime_config = RuntimeConfig{},
                      .signaling_validator = {},
                      .signaling_handler = {},
                      .relay_override = std::nullopt,
                      .path_policy_override = std::nullopt,
                      .pairing_failure_threshold = 0U,
                      .pairing_backoff_base = std::chrono::milliseconds{0},
                      .pairing_backoff_max = std::chrono::milliseconds{0},
                      .pairing_grant_ttl_milliseconds = 0U,
                      .pairing_approval_enabled = approval_enabled,
                      .pairing_deadline = pairing_deadline,
                      .event_subscriber_queue_items = 0U,
                      .event_max_subscriptions_per_peer = 0U,
                      .file_receive_roots = {},
                      .file_max_peer_receive_bytes = 0U,
                      .shell_profiles = {},
                      .gateway_profiles = {},
                      .gateway_confirm_sink = {}};
  }

  template <typename Predicate>
  bool wait_until(Predicate&& predicate, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    executor::comm::PhaseGate poll{"m5-pairing-approval-poll"};
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
        return true;
      }
      (void)poll.wait_for(1U, std::chrono::milliseconds{2});
    }
    return predicate();
  }

  static bool discovered(const Node& node, const DeviceEndpointKey& peer) {
    const auto entries = node.endpoints();
    return std::any_of(entries.begin(), entries.end(),
                       [&](const auto& entry) { return entry.key == peer; });
  }

  static std::optional<NodePeerSessionSnapshot> latest_session_for(
      const Node& node, const DeviceEndpointKey& peer) {
    const auto sessions = node.peer_sessions();
    std::optional<NodePeerSessionSnapshot> live;
    std::optional<NodePeerSessionSnapshot> closed;
    for (const auto& session : sessions) {
      if (session.peer != peer) continue;
      if (session.state != NodePeerSessionState::closed && !live.has_value()) {
        live = session;
      }
      if (session.state == NodePeerSessionState::closed) {
        closed = session;
      }
    }
    return live.has_value() ? live : closed;
  }

  bool lan_interfaces_unavailable(const Node& first, const Node& second) const {
    return first.snapshot().interfaces.empty() ||
           second.snapshot().interfaces.empty();
  }

  // Brings up two grant-less nodes whose identity-verified sessions land in
  // pairing_restricted on both sides (RULE-03 default deny). `deadline_a`
  // bounds A's initiator-side approval window; `deadline_b` bounds B's
  // pending-approval registry window (both reuse NodeConfig::pairing_deadline).
  // `approval_on_b` arms the receiver-side approval flow on B.
  bool establish_restricted_pair(NodePairHandles& pair,
                                 std::chrono::milliseconds deadline_a,
                                 std::chrono::milliseconds deadline_b,
                                 bool approval_on_b) {
    auto first_profile =
        initialized_profile("approval-initiator", std::nullopt, {});
    auto second_profile = initialized_profile(
        "approval-target", kTargetPassword, {"message.send", "stream.open"});
    if (!first_profile || !second_profile) {
      return false;
    }
    pair.first_store.emplace(std::move(*first_profile.value_if()));
    pair.second_store.emplace(std::move(*second_profile.value_if()));

    auto first_node = Node::create(node_config(*pair.first_store, deadline_a, false));
    auto second_node =
        Node::create(node_config(*pair.second_store, deadline_b, approval_on_b));
    if (!first_node || !second_node) {
      return false;
    }
    pair.first.emplace(std::move(*first_node.value_if()));
    pair.second.emplace(std::move(*second_node.value_if()));
    if (lan_interfaces_unavailable(pair.first.value(), pair.second.value())) {
      return false;
    }
    pair.first_key = DeviceEndpointKey{pair.first.value().snapshot().device_id,
                                       pair.first.value().snapshot().endpoint_id};
    pair.second_key =
        DeviceEndpointKey{pair.second.value().snapshot().device_id,
                          pair.second.value().snapshot().endpoint_id};

    if (!wait_until(
            [&] {
              return discovered(pair.first.value(), pair.second_key) &&
                     discovered(pair.second.value(), pair.first_key);
            },
            std::chrono::milliseconds{8000})) {
      return false;
    }
    if (!pair.first.value().connect_lan(pair.second_key)) {
      return false;
    }
    return wait_until(
        [&] {
          const auto left = latest_session_for(pair.first.value(), pair.second_key);
          const auto right =
              latest_session_for(pair.second.value(), pair.first_key);
          return left.has_value() &&
                 left->state == NodePeerSessionState::pairing_restricted &&
                 right.has_value() &&
                 right->state == NodePeerSessionState::pairing_restricted;
        },
        std::chrono::seconds{12});
  }

  std::filesystem::path root_;
};

// B1: the approve happy path. B's request observer fires exactly once with
// the requester, the stable wire request id, and the requested scopes;
// approve_pairing issues a policy-intersected grant bound to the request
// nonce; A reports exactly one success terminal with the effective scopes,
// the session upgrades, and the grants land with the right directions.
// Afterwards the pending entry is gone: a second approve fails with
// pairing_approval_not_pending and has no side effects.
TEST_F(M5PairingApprovalTest, ApproveIssuesGrantAndReportsExactlyOneOutcomePerSide) {
  NodePairHandles pair;
  ASSERT_TRUE(establish_restricted_pair(pair, std::chrono::milliseconds{0},
                                        std::chrono::milliseconds{0}, true));
  PairingObserverRecorder initiator_outcomes;
  initiator_outcomes.attach(pair.first.value());
  PairingObserverRecorder approver_outcomes;
  approver_outcomes.attach(pair.second.value());
  ApprovalRequestRecorder requests;
  requests.attach(pair.second.value());

  const auto admitted = pair.first.value().request_pairing_approval(
      pair.second_key, {"message.send", "shell.open:x"});
  ASSERT_TRUE(admitted) << admitted.error_if()->safe_detail();
  const auto request_id = *admitted.value_if();
  EXPECT_FALSE(request_id.is_zero());
  EXPECT_EQ(initiator_outcomes.size(), 0U);

  // B observes the pending request exactly once, intact.
  ASSERT_TRUE(wait_until([&] { return requests.size() >= 1U; },
                         std::chrono::seconds{10}));
  const auto observed = requests.snapshot();
  ASSERT_EQ(observed.size(), 1U);
  EXPECT_EQ(observed[0].peer, pair.first_key);
  EXPECT_EQ(observed[0].request_id, request_id);
  EXPECT_EQ(observed[0].requested_scopes,
            (std::vector<std::string>{"message.send", "shell.open:x"}));
  bool nonce_zero = true;
  for (const auto byte : observed[0].nonce) {
    nonce_zero = nonce_zero && byte == std::byte{0};
  }
  EXPECT_FALSE(nonce_zero);
  EXPECT_EQ(approver_outcomes.size(), 0U);

  // B approves a subset: the effective grant is the confirmed set further
  // narrowed by B's pairing policy (shell is not in the template).
  const auto approved = pair.second.value().approve_pairing(
      pair.first_key, request_id, {"message.send"});
  ASSERT_TRUE(approved) << approved.error_if()->safe_detail();

  // Exactly one success terminal per side with the effective scopes.
  ASSERT_TRUE(wait_until([&] { return initiator_outcomes.size() >= 1U; },
                         std::chrono::seconds{15}));
  ASSERT_TRUE(wait_until([&] { return approver_outcomes.size() >= 1U; },
                         std::chrono::seconds{15}));
  (void)wait_until([] { return false; }, std::chrono::milliseconds{300});
  const auto initiator_events = initiator_outcomes.snapshot();
  const auto approver_events = approver_outcomes.snapshot();
  ASSERT_EQ(initiator_events.size(), 1U);
  ASSERT_EQ(approver_events.size(), 1U);
  EXPECT_TRUE(initiator_events[0].success);
  EXPECT_EQ(initiator_events[0].peer, pair.second_key);
  EXPECT_EQ(initiator_events[0].scopes,
            (std::vector<std::string>{"message.send"}));
  EXPECT_TRUE(approver_events[0].success);
  EXPECT_EQ(approver_events[0].peer, pair.first_key);
  EXPECT_EQ(approver_events[0].scopes,
            (std::vector<std::string>{"message.send"}));

  // A's restricted session upgraded on the accepted grant.
  ASSERT_TRUE(wait_until(
      [&] {
        const auto session =
            latest_session_for(pair.first.value(), pair.second_key);
        return session.has_value() &&
               session->state == NodePeerSessionState::authenticated;
      },
      std::chrono::seconds{10}));

  // Grant directions and scopes on both ends. The grant was accepted, which
  // proves the nonce binding (the initiator's accept path verifies the
  // request-nonce echo before persisting anything).
  const auto received = pair.first.value().trust_grants_for(pair.second_key);
  ASSERT_TRUE(received);
  ASSERT_EQ(received.value_if()->size(), 1U);
  EXPECT_EQ(received.value_if()->front().direction,
            TrustGrantDirection::received);
  EXPECT_EQ(received.value_if()->front().scopes,
            (std::vector<std::string>{"message.send"}));
  const auto issued = pair.second.value().trust_grants_for(pair.first_key);
  ASSERT_TRUE(issued);
  ASSERT_EQ(issued.value_if()->size(), 1U);
  EXPECT_EQ(issued.value_if()->front().direction, TrustGrantDirection::issued);

  // Pending cleared: a second approve for the same request is a stable
  // failure without side effects.
  const auto again = pair.second.value().approve_pairing(
      pair.first_key, request_id, {"message.send"});
  ASSERT_FALSE(again);
  EXPECT_EQ(again.error_if()->code(), ErrorCode::pairing_required);
  EXPECT_EQ(again.error_if()->safe_detail(), "pairing_approval_not_pending");
  EXPECT_EQ(initiator_outcomes.size(), 1U);
  EXPECT_EQ(approver_outcomes.size(), 1U);
  EXPECT_EQ(requests.size(), 1U);
  ASSERT_TRUE(pair.second.value().trust_grants_for(pair.first_key));
  EXPECT_EQ(pair.second.value().trust_grants_for(pair.first_key)
                .value_if()
                ->size(),
            1U);

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// B2: reject path. A stable permission denial resolves A's attempt exactly
// once, no grant lands anywhere, and B records the rejection audit.
TEST_F(M5PairingApprovalTest, RejectDeniesWithoutGrantsAndRecordsAudit) {
  NodePairHandles pair;
  ASSERT_TRUE(establish_restricted_pair(pair, std::chrono::milliseconds{0},
                                        std::chrono::milliseconds{0}, true));
  PairingObserverRecorder initiator_outcomes;
  initiator_outcomes.attach(pair.first.value());
  ApprovalRequestRecorder requests;
  requests.attach(pair.second.value());

  const auto admitted = pair.first.value().request_pairing_approval(
      pair.second_key, {"message.send"});
  ASSERT_TRUE(admitted) << admitted.error_if()->safe_detail();
  ASSERT_TRUE(wait_until([&] { return requests.size() >= 1U; },
                         std::chrono::seconds{10}));
  ASSERT_EQ(requests.snapshot().size(), 1U);

  const auto rejected = pair.second.value().reject_pairing(
      pair.first_key, *admitted.value_if());
  ASSERT_TRUE(rejected) << rejected.error_if()->safe_detail();

  ASSERT_TRUE(wait_until([&] { return initiator_outcomes.size() >= 1U; },
                         std::chrono::seconds{15}));
  const auto events = initiator_outcomes.snapshot();
  ASSERT_EQ(events.size(), 1U);
  EXPECT_FALSE(events[0].success);
  EXPECT_EQ(events[0].peer, pair.second_key);
  EXPECT_EQ(events[0].code, ErrorCode::pairing_denied);

  // No grants on either side.
  const auto received = pair.first.value().trust_grants_for(pair.second_key);
  ASSERT_TRUE(received);
  EXPECT_EQ(received.value_if()->size(), 0U);
  const auto issued = pair.second.value().trust_grants_for(pair.first_key);
  ASSERT_TRUE(issued);
  EXPECT_EQ(issued.value_if()->size(), 0U);

  // B's audit funnel recorded the rejection with the wire request id.
  const auto audits = pair.second.value().pairing_audit_records();
  const auto rejection = std::find_if(
      audits.begin(), audits.end(), [&](const PairingAuditEvent& event) {
        return std::string_view{event.detail} == "approval_rejected" &&
               event.request_id.has_value() &&
               *event.request_id == *admitted.value_if();
      });
  EXPECT_TRUE(rejection != audits.end());

  // Exactly once: the losing side stays quiet.
  (void)wait_until([] { return false; }, std::chrono::milliseconds{300});
  EXPECT_EQ(initiator_outcomes.size(), 1U);
  EXPECT_EQ(requests.size(), 1U);

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// B3: deadline. B observes the request but never resolves it; A's short
// initiator window resolves the attempt with exactly one timeout terminal,
// the restricted session closes, and the attempt is retired.
//
// Independent approval windows: A's initiator window (300ms here) and B's
// approval window (B's own NodeConfig::pairing_deadline, the protocol
// default 60s) are separate clocks on separate devices. A timing out only
// resolves A's pending attempt and terminal outcome - B cannot know A gave
// up, and approving the abandoned request inside B's own window is a legal
// distributed outcome (B intends to trust A; the issued grant is harmless).
// So after A's timeout the late approve_pairing follows a two-branch
// contract: it either fails stably with pairing_approval_not_pending (the
// teardown race cleared B's pending entry first) or succeeds with exactly
// one success outcome on B's pairing observer and an issued grant. Either
// way A reports exactly once.
TEST_F(M5PairingApprovalTest, DeadlineResolvesPendingApprovalExactlyOnce) {
  NodePairHandles pair;
  ASSERT_TRUE(establish_restricted_pair(pair, std::chrono::milliseconds{300},
                                        std::chrono::milliseconds{0}, true));
  PairingObserverRecorder initiator_outcomes;
  initiator_outcomes.attach(pair.first.value());
  PairingObserverRecorder approver_outcomes;
  approver_outcomes.attach(pair.second.value());
  ApprovalRequestRecorder requests;
  requests.attach(pair.second.value());

  const auto admitted = pair.first.value().request_pairing_approval(
      pair.second_key, {"message.send"});
  ASSERT_TRUE(admitted) << admitted.error_if()->safe_detail();
  ASSERT_TRUE(wait_until([&] { return requests.size() >= 1U; },
                         std::chrono::seconds{10}));
  ASSERT_EQ(requests.snapshot().size(), 1U);

  // Nobody resolves the request: A's bounded window must fire exactly once.
  ASSERT_TRUE(wait_until([&] { return initiator_outcomes.size() >= 1U; },
                         std::chrono::seconds{15}));
  const auto events = initiator_outcomes.snapshot();
  ASSERT_EQ(events.size(), 1U);
  EXPECT_FALSE(events[0].success);
  EXPECT_EQ(events[0].code, ErrorCode::timeout);
  EXPECT_EQ(events[0].detail, "pairing_deadline_exceeded");

  // The restricted session is closed and the attempt retired.
  ASSERT_TRUE(wait_until(
      [&] {
        const auto session =
            latest_session_for(pair.first.value(), pair.second_key);
        return session.has_value() && session->state == NodePeerSessionState::closed;
      },
      std::chrono::seconds{10}));
  const auto again = pair.first.value().request_pairing_approval(
      pair.second_key, {"message.send"});
  ASSERT_FALSE(again);
  EXPECT_NE(again.error_if()->safe_detail(),
            std::string_view{"pairing_already_pending"});

  // Late resolution of the abandoned request inside B's own (still open)
  // approval window: two legal branches, no third. The branch key is B's
  // own observable state, because approve_pairing's return value can race
  // A's dead session (the result-frame send may fail after the grant was
  // already issued and reported).
  const auto approve_expired = pair.second.value().approve_pairing(
      pair.first_key, *admitted.value_if(), {"message.send"});
  const bool b_window_open =
      approve_expired ||
      approve_expired.error_if()->safe_detail() !=
          "pairing_approval_not_pending";
  if (b_window_open) {
    // B's window was open and its pending entry intact: the approval is
    // observable on B's side - exactly one success outcome and the issued
    // grant. approve_pairing may additionally report the result-frame send
    // racing A's dead session; that return value is not the contract here.
    ASSERT_TRUE(wait_until([&] { return approver_outcomes.size() >= 1U; },
                           std::chrono::seconds{15}));
    const auto approver_events = approver_outcomes.snapshot();
    ASSERT_EQ(approver_events.size(), 1U);
    EXPECT_TRUE(approver_events[0].success);
    EXPECT_EQ(approver_events[0].peer, pair.first_key);
    EXPECT_EQ(approver_events[0].scopes,
              (std::vector<std::string>{"message.send"}));
    const auto issued = pair.second.value().trust_grants_for(pair.first_key);
    ASSERT_TRUE(issued);
    ASSERT_EQ(issued.value_if()->size(), 1U);
    EXPECT_EQ(issued.value_if()->front().direction,
              TrustGrantDirection::issued);
    EXPECT_EQ(issued.value_if()->front().scopes,
              (std::vector<std::string>{"message.send"}));
  } else {
    // The teardown race cleared B's pending entry first: stable no-op, no
    // grant, no observer event.
    EXPECT_EQ(approve_expired.error_if()->code(), ErrorCode::pairing_required);
    EXPECT_EQ(approve_expired.error_if()->safe_detail(),
              "pairing_approval_not_pending");
    EXPECT_EQ(approver_outcomes.size(), 0U);
    EXPECT_EQ(pair.second.value().trust_grants_for(pair.first_key)
                  .value_if()
                  ->size(),
              0U);
  }

  // Exactly once on A regardless of branch.
  (void)wait_until([] { return false; }, std::chrono::milliseconds{300});
  EXPECT_EQ(initiator_outcomes.size(), 1U);

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// B4: the policy default. With B's pairing_approval_enabled left off, an
// approval request resolves with a stable denial and never surfaces on B's
// request observer.
TEST_F(M5PairingApprovalTest, DisabledReceiverDeniesStableWithoutPendingObservation) {
  NodePairHandles pair;
  ASSERT_TRUE(establish_restricted_pair(pair, std::chrono::milliseconds{0},
                                        std::chrono::milliseconds{0}, false));
  PairingObserverRecorder initiator_outcomes;
  initiator_outcomes.attach(pair.first.value());
  ApprovalRequestRecorder requests;
  requests.attach(pair.second.value());

  const auto admitted = pair.first.value().request_pairing_approval(
      pair.second_key, {"message.send"});
  ASSERT_TRUE(admitted) << admitted.error_if()->safe_detail();

  // A resolves with exactly one stable denial.
  ASSERT_TRUE(wait_until([&] { return initiator_outcomes.size() >= 1U; },
                         std::chrono::seconds{15}));
  const auto events = initiator_outcomes.snapshot();
  ASSERT_EQ(events.size(), 1U);
  EXPECT_FALSE(events[0].success);
  EXPECT_EQ(events[0].code, ErrorCode::pairing_denied);

  // B never observed a pending request and never gained trust.
  EXPECT_EQ(requests.size(), 0U);
  const auto issued = pair.second.value().trust_grants_for(pair.first_key);
  ASSERT_TRUE(issued);
  EXPECT_EQ(issued.value_if()->size(), 0U);

  // The attempt was consumed (not still pending): resubmission is refused
  // for a reason other than an in-flight duplicate.
  ASSERT_TRUE(wait_until(
      [&] {
        const auto session =
            latest_session_for(pair.first.value(), pair.second_key);
        return session.has_value() && session->state == NodePeerSessionState::closed;
      },
      std::chrono::seconds{10}));
  const auto again = pair.first.value().request_pairing_approval(
      pair.second_key, {"message.send"});
  ASSERT_FALSE(again);
  EXPECT_NE(again.error_if()->safe_detail(),
            std::string_view{"pairing_already_pending"});

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// B5: duplicate discipline. While B's pending request is unresolved, a second
// submission from A fails stably (pairing_already_pending on the initiator's
// bounded admission) and the first pending request stays intact and
// approvable.
TEST_F(M5PairingApprovalTest, DuplicateSubmissionWhilePendingLeavesFirstIntact) {
  NodePairHandles pair;
  ASSERT_TRUE(establish_restricted_pair(pair, std::chrono::milliseconds{0},
                                        std::chrono::milliseconds{0}, true));
  PairingObserverRecorder initiator_outcomes;
  initiator_outcomes.attach(pair.first.value());
  PairingObserverRecorder approver_outcomes;
  approver_outcomes.attach(pair.second.value());
  ApprovalRequestRecorder requests;
  requests.attach(pair.second.value());

  const auto admitted = pair.first.value().request_pairing_approval(
      pair.second_key, {"message.send"});
  ASSERT_TRUE(admitted) << admitted.error_if()->safe_detail();
  ASSERT_TRUE(wait_until([&] { return requests.size() >= 1U; },
                         std::chrono::seconds{10}));
  ASSERT_EQ(requests.snapshot().size(), 1U);

  // Second submission while the first is in flight: stable rejection.
  const auto duplicate = pair.first.value().request_pairing_approval(
      pair.second_key, {"message.send"});
  ASSERT_FALSE(duplicate);
  EXPECT_EQ(duplicate.error_if()->code(), ErrorCode::pairing_required);
  EXPECT_EQ(duplicate.error_if()->safe_detail(), "pairing_already_pending");
  EXPECT_EQ(requests.size(), 1U);
  EXPECT_EQ(approver_outcomes.size(), 0U);

  // The first pending request is untouched and still approvable.
  const auto approved = pair.second.value().approve_pairing(
      pair.first_key, *admitted.value_if(), {"message.send"});
  ASSERT_TRUE(approved) << approved.error_if()->safe_detail();
  ASSERT_TRUE(wait_until([&] { return initiator_outcomes.size() >= 1U; },
                         std::chrono::seconds{15}));
  EXPECT_TRUE(initiator_outcomes.snapshot().front().success);

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// B6: disconnect terminal. A pending approval resolved by B's shutdown gives
// A exactly one failure terminal of transport class (never a denial), and
// A's pending attempt is cleaned up.
TEST_F(M5PairingApprovalTest, TargetShutdownResolvesPendingApprovalExactlyOnce) {
  NodePairHandles pair;
  ASSERT_TRUE(establish_restricted_pair(pair, std::chrono::milliseconds{0},
                                        std::chrono::milliseconds{0}, true));
  PairingObserverRecorder initiator_outcomes;
  initiator_outcomes.attach(pair.first.value());
  ApprovalRequestRecorder requests;
  requests.attach(pair.second.value());

  const auto admitted = pair.first.value().request_pairing_approval(
      pair.second_key, {"message.send"});
  ASSERT_TRUE(admitted) << admitted.error_if()->safe_detail();
  ASSERT_TRUE(wait_until([&] { return requests.size() >= 1U; },
                         std::chrono::seconds{10}));
  ASSERT_EQ(requests.snapshot().size(), 1U);
  EXPECT_EQ(initiator_outcomes.size(), 0U);

  EXPECT_TRUE(pair.second.value().shutdown().stopped);

  // Exactly one failure terminal, never a stable denial class: the attempt
  // died with the transport, not by policy.
  ASSERT_TRUE(wait_until([&] { return initiator_outcomes.size() >= 1U; },
                         std::chrono::seconds{25}));
  const auto events = initiator_outcomes.snapshot();
  ASSERT_EQ(events.size(), 1U);
  EXPECT_FALSE(events[0].success);
  EXPECT_NE(events[0].code, ErrorCode::pairing_denied);
  EXPECT_NE(events[0].code, ErrorCode::pairing_required);
  EXPECT_NE(events[0].code, ErrorCode::permission);

  // A's pending cleared: the retired attempt is not re-admissible as a
  // duplicate.
  const auto again = pair.first.value().request_pairing_approval(
      pair.second_key, {"message.send"});
  ASSERT_FALSE(again);
  EXPECT_NE(again.error_if()->safe_detail(),
            std::string_view{"pairing_already_pending"});

  // Exactly once.
  (void)wait_until([] { return false; }, std::chrono::milliseconds{500});
  EXPECT_EQ(initiator_outcomes.size(), 1U);

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
}

}  // namespace
}  // namespace heyaki
