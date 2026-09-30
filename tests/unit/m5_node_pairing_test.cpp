// Issue #1: Node::pair_peer admission outcome contract over a real two-node
// LAN pair. The old implementation posted to the strand and returned success
// unconditionally, discarding the admission decision; the fix makes admission
// synchronous and bounded, returns the stable wire request id, and guarantees
// exactly one pairing-observer terminal outcome per admitted request
// (success with effective scopes, denial, deadline, disconnect, cancel,
// shutdown) while duplicates fail with pairing_already_pending and never
// disturb the in-flight attempt.
//
// Session-level wire semantics (request-id propagation, late-result
// idempotency) live in m5_session_test.cpp; this file covers the Node-level
// admission surface.

#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/trust_grant.hpp>

#include <executor/comm.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
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
constexpr const char* kApplicationId = "com.example.m5-node-pairing";
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

bool environment_requires_lan_interfaces() {
  const char* value = std::getenv("HEYAKI_REQUIRE_LAN_INTERFACES");
  return value != nullptr && std::string_view{value} == "1";
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

// One observer-reported terminal outcome, flattened for thread-safe
// recording (the observer runs on the node's strand).
struct RecordedPairingOutcome {
  DeviceEndpointKey peer;
  bool success{false};
  ErrorCode code{ErrorCode::internal};
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

// Seeds ONE grant record - issued by `issuer` for `subject` - into the
// issuer's store only. Unlike test::seed_one_way_trust, the subject's store
// stays empty, so the subject's own authorizer still denies the issuer: the
// session comes up with the ISSUER authenticated and the SUBJECT restricted.
Result<void> seed_issued_grant_only(ProfileStore& issuer, const DeviceId& subject,
                                    const std::vector<std::string>& scopes,
                                    std::uint8_t slot) {
  auto identity = issuer.load_identity();
  if (!identity) return Result<void>::failure(*identity.error_if());
  auto normalized = normalize_trust_scopes(scopes);
  if (!normalized) return Result<void>::failure(*normalized.error_if());
  SignedTrustGrant grant;
  grant.issuer = issuer.device_id();
  grant.subject = subject;
  GrantId::Storage grant_bytes{};
  const auto& issuer_bytes = grant.issuer.bytes();
  const auto& subject_bytes = subject.bytes();
  for (std::size_t index = 0U; index < grant_bytes.size(); ++index) {
    grant_bytes[index] = static_cast<std::byte>(
        (std::to_integer<std::uint8_t>(issuer_bytes[index % issuer_bytes.size()]) *
             11U +
         std::to_integer<std::uint8_t>(subject_bytes[index % subject_bytes.size()]) *
             17U +
         static_cast<unsigned>(slot) * 37U + index * 41U + 7U) &
        0xFFU);
  }
  grant.grant_id = GrantId{grant_bytes};
  if (grant.grant_id.is_zero()) {
    return Result<void>::failure(Error{ErrorCode::internal, "m5_node_pairing_test",
                                       "grant_id_zero"});
  }
  grant.granted_scopes = *normalized.value_if();
  grant.password_generation = 1U;
  grant.issued_unix_milliseconds = kNow;
  PairingNonce nonce{};
  for (std::size_t index = 0U; index < nonce.size(); ++index) {
    nonce[index] = static_cast<std::byte>((index * 19U + 5U) & 0xFFU);
  }
  grant.nonce = nonce;
  auto signed_grant = sign_signed_trust_grant(grant, *identity.value_if());
  if (!signed_grant) return Result<void>::failure(*signed_grant.error_if());
  TrustGrantRecord record;
  record.grant_id = grant.grant_id;
  record.direction = TrustGrantDirection::issued;
  record.issuer = grant.issuer;
  record.subject = grant.subject;
  record.scopes = grant.granted_scopes;
  record.password_generation = grant.password_generation;
  record.issued_unix_milliseconds = grant.issued_unix_milliseconds;
  record.expires_unix_milliseconds = std::nullopt;
  record.signature.assign(grant.signature.begin(), grant.signature.end());
  record.revoked = false;
  return issuer.put_trust_grant(record);
}

struct NodePairHandles {
  std::optional<ProfileStore> first_store;   // initiator (A)
  std::optional<ProfileStore> second_store;  // responder / target (B)
  std::optional<Node> first;
  std::optional<Node> second;
  DeviceEndpointKey first_key;
  DeviceEndpointKey second_key;
};

class M5NodePairingTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M5_NODE_PAIRING_TEST_STATE_DIR} /
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

  // `password` arms the profile's pairing verifier; nullopt installs a dummy
  // verifier like every other Node-level suite (the profile never pairs
  // inbound then). `policy_scopes` becomes the pairing policy intersection
  // set on the target side.
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
                                std::chrono::milliseconds pairing_deadline) {
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
    executor::comm::PhaseGate poll{"m5-node-pairing-poll"};
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

  // Live attempt first (peer_sessions lists active attempts before the
  // closed diagnostic history); falls back to the newest closed entry.
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

  // Brings up two grant-less nodes: identity-verified sessions on both sides
  // land in pairing_restricted (RULE-03 default deny). Returns false when the
  // environment cannot host the pair (no multicast interface, no discovery).
  bool establish_restricted_pair(NodePairHandles& pair,
                                 std::chrono::milliseconds deadline_a =
                                     std::chrono::milliseconds{0}) {
    auto first_profile =
        initialized_profile("pairing-initiator", std::nullopt, {});
    auto second_profile = initialized_profile(
        "pairing-target", kTargetPassword, {"message.send", "stream.open"});
    if (!first_profile || !second_profile) {
      return false;
    }
    pair.first_store.emplace(std::move(*first_profile.value_if()));
    pair.second_store.emplace(std::move(*second_profile.value_if()));

    auto first_node = Node::create(node_config(*pair.first_store, deadline_a));
    auto second_node = Node::create(node_config(*pair.second_store,
                                                std::chrono::milliseconds{0}));
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

// Admission rejections never reach the wire and never produce an
// observer outcome: the operation was not admitted.
TEST_F(M5NodePairingTest, AdmissionRejectionsProduceNoObserverOutcome) {
  auto profile = initialized_profile("admission-rejections", kTargetPassword, {});
  ASSERT_TRUE(profile);
  auto node = Node::create(node_config(*profile.value_if(),
                                       std::chrono::milliseconds{0}));
  ASSERT_TRUE(node) << node.error_if()->safe_detail();
  Node& subject = *node.value_if();
  PairingObserverRecorder recorder;
  recorder.attach(subject);

  // Unknown peer: strand admission fails with peer_session_missing.
  const DeviceEndpointKey unknown{filled<DeviceId>(0x11U),
                                  filled<EndpointId>(0x22U)};
  const auto missing = subject.pair_peer(unknown, "pw", {"message.send"});
  ASSERT_FALSE(missing);
  EXPECT_EQ(missing.error_if()->code(), ErrorCode::peer_offline);
  EXPECT_EQ(missing.error_if()->safe_detail(), "peer_session_missing");

  // Zero peer key and empty password fail the local pre-checks.
  const auto zero_peer = subject.pair_peer(DeviceEndpointKey{}, "pw",
                                           {"message.send"});
  ASSERT_FALSE(zero_peer);
  EXPECT_EQ(zero_peer.error_if()->code(), ErrorCode::configuration);
  EXPECT_EQ(zero_peer.error_if()->safe_detail(), "pairing_peer_invalid");

  const auto empty_password =
      subject.pair_peer(unknown, "", {"message.send"});
  ASSERT_FALSE(empty_password);
  EXPECT_EQ(empty_password.error_if()->code(), ErrorCode::configuration);
  EXPECT_EQ(empty_password.error_if()->safe_detail(), "pairing_password_empty");

  // Not a single observer outcome for any rejected admission.
  (void)wait_until([] { return false; }, std::chrono::milliseconds{200});
  EXPECT_EQ(recorder.size(), 0U);

  EXPECT_TRUE(subject.shutdown().stopped);
}

// Case 5 + 6: an admitted request reports no observer outcome while in
// flight, a duplicate fails with pairing_already_pending without disturbing
// the in-flight attempt, and completion reports exactly one success terminal
// outcome carrying the effective (policy-intersected) scopes. Afterwards the
// session is no longer pairing-restricted and the grants carry the right
// directions on both ends.
TEST_F(M5NodePairingTest, AdmittedPairingHasExactlyOneSuccessOutcomeAndRejectsDuplicates) {
  NodePairHandles pair;
  ASSERT_TRUE(establish_restricted_pair(pair));
  PairingObserverRecorder recorder;
  recorder.attach(pair.first.value());

  const auto admitted = pair.first.value().pair_peer(
      pair.second_key, kTargetPassword,
      {"message.send", "stream.open", "shell.open:x"});
  ASSERT_TRUE(admitted) << admitted.error_if()->safe_detail();
  const auto first_request_id = *admitted.value_if();
  EXPECT_FALSE(first_request_id.is_zero());

  // In flight: no terminal outcome yet.
  EXPECT_EQ(recorder.size(), 0U);

  // Duplicate admission: rejected, and the in-flight request is untouched.
  const auto duplicate = pair.first.value().pair_peer(
      pair.second_key, kTargetPassword, {"message.send"});
  ASSERT_FALSE(duplicate);
  EXPECT_EQ(duplicate.error_if()->code(), ErrorCode::pairing_required);
  EXPECT_EQ(duplicate.error_if()->safe_detail(), "pairing_already_pending");
  EXPECT_EQ(recorder.size(), 0U);

  // Exactly one terminal outcome: success with the effective scopes - the
  // policy intersection drops the out-of-template shell scope.
  ASSERT_TRUE(wait_until([&] { return recorder.size() >= 1U; },
                         std::chrono::seconds{15}));
  const auto events = recorder.snapshot();
  ASSERT_EQ(events.size(), 1U);
  EXPECT_TRUE(events[0].success);
  EXPECT_EQ(events[0].peer, pair.second_key);
  EXPECT_EQ(events[0].scopes, (std::vector<std::string>{"message.send", "stream.open"}));

  // Pending cleared: re-admission now fails with session_not_pairing_restricted.
  const auto after = pair.first.value().pair_peer(pair.second_key, kTargetPassword,
                                                  {"message.send"});
  ASSERT_FALSE(after);
  EXPECT_EQ(after.error_if()->code(), ErrorCode::pairing_required);
  EXPECT_EQ(after.error_if()->safe_detail(), "session_not_pairing_restricted");
  EXPECT_EQ(recorder.size(), 1U);

  // Grant directions: the receiver issued, the initiator received, and the
  // stored scopes match the reported effective scopes.
  const auto issued =
      pair.second.value().trust_grants_for(pair.first_key);
  ASSERT_TRUE(issued);
  ASSERT_EQ(issued.value_if()->size(), 1U);
  EXPECT_EQ(issued.value_if()->front().direction, TrustGrantDirection::issued);
  EXPECT_EQ(issued.value_if()->front().scopes,
            (std::vector<std::string>{"message.send", "stream.open"}));
  const auto received = pair.first.value().trust_grants_for(pair.second_key);
  ASSERT_TRUE(received);
  ASSERT_EQ(received.value_if()->size(), 1U);
  EXPECT_EQ(received.value_if()->front().direction,
            TrustGrantDirection::received);

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// Case 5 (denial half): a wrong password admits, reports exactly one
// failure terminal outcome, clears the pending state, and after a fresh
// restricted session the peer can be admitted again.
TEST_F(M5NodePairingTest, WrongPasswordFailsExactlyOnceAndReadmitsAfterReconnect) {
  NodePairHandles pair;
  ASSERT_TRUE(establish_restricted_pair(pair));
  PairingObserverRecorder recorder;
  recorder.attach(pair.first.value());

  const auto admitted = pair.first.value().pair_peer(
      pair.second_key, "wrong-password", {"message.send"});
  ASSERT_TRUE(admitted) << admitted.error_if()->safe_detail();
  EXPECT_FALSE(admitted.value_if()->is_zero());
  EXPECT_EQ(recorder.size(), 0U);

  ASSERT_TRUE(wait_until([&] { return recorder.size() >= 1U; },
                         std::chrono::seconds{15}));
  auto events = recorder.snapshot();
  ASSERT_EQ(events.size(), 1U);
  EXPECT_FALSE(events[0].success);
  EXPECT_EQ(events[0].peer, pair.second_key);
  EXPECT_EQ(events[0].code, ErrorCode::pairing_denied);

  // The denied restricted session is closed on the initiator side.
  ASSERT_TRUE(wait_until(
      [&] {
        const auto session = latest_session_for(pair.first.value(), pair.second_key);
        return session.has_value() && session->state == NodePeerSessionState::closed;
      },
      std::chrono::seconds{10}));

  // Re-admission after a fresh restricted session succeeds: the pending
  // state of the failed attempt is fully cleared. The reconnect request can
  // land while the denied attempt's LAN signaling connection is still being
  // torn down (start_outbound_connection drops peers with a live connection),
  // so re-issue connect_lan until both sides report a fresh restricted
  // session instead of racing one shot against the teardown.
  const bool reconnected = [&] {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{30};
    while (std::chrono::steady_clock::now() < deadline) {
      (void)pair.first.value().connect_lan(pair.second_key);
      const auto left = latest_session_for(pair.first.value(), pair.second_key);
      const auto right = latest_session_for(pair.second.value(), pair.first_key);
      if (left.has_value() &&
          left->state == NodePeerSessionState::pairing_restricted &&
          right.has_value() &&
          right->state == NodePeerSessionState::pairing_restricted) {
        return true;
      }
      (void)wait_until([] { return false; }, std::chrono::milliseconds{300});
    }
    return false;
  }();
  if (!reconnected) {
    const auto left = latest_session_for(pair.first.value(), pair.second_key);
    const auto right = latest_session_for(pair.second.value(), pair.first_key);
    ADD_FAILURE() << "reconnect did not reach pairing_restricted"
                  << "; a_state=" << (left ? static_cast<int>(left->state) : -1)
                  << " a_err=" << (left && left->error.has_value()
                                       ? std::string{left->error->safe_detail()}
                                       : std::string{"-"})
                  << " b_state=" << (right ? static_cast<int>(right->state) : -1)
                  << " b_err=" << (right && right->error.has_value()
                                       ? std::string{right->error->safe_detail()}
                                       : std::string{"-"});
    for (const auto& session : pair.first.value().peer_sessions()) {
      ADD_FAILURE() << "a session peer=" << (session.peer == pair.second_key)
                    << " state=" << static_cast<int>(session.state);
    }
    for (const auto& session : pair.second.value().peer_sessions()) {
      ADD_FAILURE() << "b session peer=" << (session.peer == pair.first_key)
                    << " state=" << static_cast<int>(session.state);
    }
  }
  const auto readmitted = pair.first.value().pair_peer(
      pair.second_key, kTargetPassword, {"message.send"});
  ASSERT_TRUE(readmitted) << readmitted.error_if()->safe_detail();
  EXPECT_NE(*readmitted.value_if(), *admitted.value_if());

  ASSERT_TRUE(wait_until([&] { return recorder.size() >= 2U; },
                         std::chrono::seconds{15}));
  events = recorder.snapshot();
  ASSERT_EQ(events.size(), 2U);
  EXPECT_TRUE(events[1].success);
  EXPECT_EQ(events[1].scopes, (std::vector<std::string>{"message.send"}));

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// Case 7: the armed deadline fires exactly once when the responder stays
// silent. Silence is constructed deterministically: the target holds an
// ISSUED grant for the initiator (its store only), so the target's session
// authorizes at hello while the initiator's session stays restricted. The
// target's pairing frame handler counts an authenticated peer's
// pairing_request and never answers; the initiator's deadline then expires
// the pending attempt, reports exactly one timeout outcome, clears the
// pending entry, and closes the restricted session.
TEST_F(M5NodePairingTest, PairingDeadlineExpiresSilentResponderExactlyOnce) {
  NodePairHandles pair;
  auto first_profile = initialized_profile("deadline-initiator", std::nullopt, {});
  auto second_profile = initialized_profile(
      "deadline-target", kTargetPassword, {"message.send", "stream.open"});
  ASSERT_TRUE(first_profile && second_profile);
  pair.first_store.emplace(std::move(*first_profile.value_if()));
  pair.second_store.emplace(std::move(*second_profile.value_if()));
  // One-directional trust: B is authorized for A's session, A is not.
  ASSERT_TRUE(seed_issued_grant_only(*pair.second_store,
                                     pair.first_store->device_id(),
                                     {"message.send"}, 0xAU));

  auto first_node = Node::create(
      node_config(*pair.first_store, std::chrono::milliseconds{300}));
  auto second_node =
      Node::create(node_config(*pair.second_store, std::chrono::milliseconds{0}));
  ASSERT_TRUE(first_node && second_node);
  pair.first.emplace(std::move(*first_node.value_if()));
  pair.second.emplace(std::move(*second_node.value_if()));
  if (lan_interfaces_unavailable(pair.first.value(), pair.second.value())) {
    (void)pair.first.value().shutdown();
    (void)pair.second.value().shutdown();
    if (environment_requires_lan_interfaces()) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  pair.first_key = DeviceEndpointKey{pair.first.value().snapshot().device_id,
                                     pair.first.value().snapshot().endpoint_id};
  pair.second_key = DeviceEndpointKey{pair.second.value().snapshot().device_id,
                                      pair.second.value().snapshot().endpoint_id};
  ASSERT_TRUE(wait_until(
      [&] {
        return discovered(pair.first.value(), pair.second_key) &&
               discovered(pair.second.value(), pair.first_key);
      },
      std::chrono::milliseconds{8000}));
  ASSERT_TRUE(pair.first.value().connect_lan(pair.second_key));
  // The asymmetric handshake: A restricted, B authenticated.
  ASSERT_TRUE(wait_until(
      [&] {
        const auto left = latest_session_for(pair.first.value(), pair.second_key);
        const auto right = latest_session_for(pair.second.value(), pair.first_key);
        return left.has_value() &&
               left->state == NodePeerSessionState::pairing_restricted &&
               right.has_value() &&
               right->state == NodePeerSessionState::authenticated;
      },
      std::chrono::seconds{12}));

  PairingObserverRecorder recorder;
  recorder.attach(pair.first.value());
  const auto admitted = pair.first.value().pair_peer(
      pair.second_key, kTargetPassword, {"message.send"});
  ASSERT_TRUE(admitted) << admitted.error_if()->safe_detail();
  EXPECT_FALSE(admitted.value_if()->is_zero());
  EXPECT_EQ(recorder.size(), 0U);

  // The authenticated target never answers; the armed deadline fires.
  ASSERT_TRUE(wait_until([&] { return recorder.size() >= 1U; },
                         std::chrono::seconds{10}));
  const auto events = recorder.snapshot();
  ASSERT_EQ(events.size(), 1U);
  EXPECT_FALSE(events[0].success);
  EXPECT_EQ(events[0].peer, pair.second_key);
  EXPECT_EQ(events[0].code, ErrorCode::timeout);
  EXPECT_EQ(events[0].detail, "pairing_deadline_exceeded");

  // The restricted session is closed locally and no second outcome fires.
  ASSERT_TRUE(wait_until(
      [&] {
        const auto session = latest_session_for(pair.first.value(), pair.second_key);
        return session.has_value() && session->state == NodePeerSessionState::closed;
      },
      std::chrono::seconds{10}));
  (void)wait_until([] { return false; }, std::chrono::milliseconds{500});
  EXPECT_EQ(recorder.size(), 1U);

  // Pending cleared: the dead attempt cannot be re-admitted.
  const auto again = pair.first.value().pair_peer(pair.second_key, kTargetPassword,
                                                  {"message.send"});
  ASSERT_FALSE(again);
  EXPECT_NE(again.error_if()->safe_detail(), std::string_view{"pairing_already_pending"});
  EXPECT_EQ(recorder.size(), 1U);

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

}  // namespace
}  // namespace heyaki
