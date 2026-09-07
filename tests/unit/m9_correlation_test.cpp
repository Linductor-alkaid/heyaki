// M9-03 correlation id tests: pairing audit events carry the wire pairing
// RequestId and the GrantId, RPC completions and admission failures name
// their operation id, the Node-level pairing audit ring records events that
// arrive through the public API (cross-thread posting path), and the relay
// snapshot anchors registration cycles in wall clock. Ids are random
// non-secret wire values; none of these surfaces may carry credentials.

#include "m6_support.hpp"
#include "pairing_service.hpp"

#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <executor/comm.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace heyaki {
namespace {

// ---------- pairing service audit funnel ----------

class M9PairingAuditTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root = std::filesystem::temp_directory_path() /
           ("heyaki-m9-correlation-" + std::to_string(::testing::UnitTest::
                                                          GetInstance()
                                                              ->random_seed()));
    std::filesystem::create_directories(root);
    std::filesystem::permissions(root, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    ProfileOpenOptions open_options;
    open_options.secret_backend.prefer_os_backend = false;
    auto target = ProfileStore::create(root / "target.sqlite", open_options);
    ASSERT_TRUE(target);
    target_store.emplace(std::move(*target.value_if()));
    auto initiator = ProfileStore::create(root / "initiator.sqlite", open_options);
    ASSERT_TRUE(initiator);
    initiator_store.emplace(std::move(*initiator.value_if()));

    auto verifier =
        create_password_verifier("target-password", PasswordHashParameters{});
    ASSERT_TRUE(verifier);
    PairingPolicy policy;
    policy.default_scopes = {"message.send"};
    LocalProfileInitialization initialization;
    initialization.application_id = "com.example.test";
    initialization.password_verifier = std::move(*verifier.value_if());
    initialization.password_generation = 1U;
    initialization.pairing_policy = policy;
    ASSERT_TRUE(target_store->initialize_local(initialization));
    ASSERT_TRUE(initiator_store->initialize_local(initialization));

    auto target_identity = target_store->load_identity();
    ASSERT_TRUE(target_identity);
    PairingServiceConfig target_config{
        .profile = &*target_store,
        .identity = std::move(*target_identity.value_if())};
    target_config.wall_clock = [this] { return wall_clock; };
    target_config.audit_sink = [this](const PairingAuditEvent& event) {
      target_events.push_back(event);
    };
    target_service = std::make_unique<PairingService>(std::move(target_config));

    auto initiator_identity = initiator_store->load_identity();
    ASSERT_TRUE(initiator_identity);
    PairingServiceConfig initiator_config{
        .profile = &*initiator_store,
        .identity = std::move(*initiator_identity.value_if())};
    initiator_config.wall_clock = [this] { return wall_clock; };
    initiator_config.audit_sink = [this](const PairingAuditEvent& event) {
      initiator_events.push_back(event);
    };
    initiator_service = std::make_unique<PairingService>(std::move(initiator_config));
  }

  void TearDown() override {
    target_service.reset();
    initiator_service.reset();
    target_store.reset();
    initiator_store.reset();
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
  }

  PairingRequestBody request(std::string_view password,
                             std::vector<std::string> scopes) {
    PairingRequestBody body;
    RequestId::Storage bytes{};
    bytes[0] = static_cast<std::byte>((request_sequence += 1U) & 0xFFU);
    bytes[1] = std::byte{1U};
    body.request_id = RequestId{bytes};
    body.nonce = PairingNonce{};
    body.nonce[0] = static_cast<std::byte>((request_sequence += 1U) & 0xFFU);
    body.nonce[1] = std::byte{2U};
    body.password_utf8 = std::string{password};
    body.requested_scopes = std::move(scopes);
    return body;
  }

  std::filesystem::path root;
  std::optional<ProfileStore> target_store;
  std::optional<ProfileStore> initiator_store;
  std::unique_ptr<PairingService> target_service;
  std::unique_ptr<PairingService> initiator_service;
  std::uint64_t wall_clock = 1'700'000'000'000U;
  std::uint32_t request_sequence = 0U;
  std::vector<PairingAuditEvent> target_events;
  std::vector<PairingAuditEvent> initiator_events;
};

TEST_F(M9PairingAuditTest, AuditEventsCarryRequestAndGrantIds) {
  const auto peer = initiator_store->device_id();
  const auto peer_key = initiator_store->identity_public_key();

  // Granted path: attempt and granted both echo the wire request id; the
  // grant event additionally names the issued TrustGrant.
  const auto granted_request = request("target-password", {"message.send"});
  const auto granted_id = granted_request.request_id;
  auto evaluated = target_service->evaluate(granted_request, peer, peer_key);
  ASSERT_TRUE(evaluated);
  ASSERT_EQ(evaluated.value_if()->status, StableStatus::ok);
  ASSERT_TRUE(evaluated.value_if()->grant.has_value());
  const auto grant_id = evaluated.value_if()->grant->grant_id;

  ASSERT_GE(target_events.size(), 2U);
  const auto& attempt = target_events[target_events.size() - 2U];
  const auto& granted = target_events.back();
  EXPECT_EQ(attempt.kind, PairingAuditKind::attempt);
  ASSERT_TRUE(attempt.request_id.has_value());
  EXPECT_EQ(*attempt.request_id, granted_id);
  EXPECT_FALSE(attempt.grant_id.has_value());
  EXPECT_EQ(granted.kind, PairingAuditKind::granted);
  ASSERT_TRUE(granted.request_id.has_value());
  EXPECT_EQ(*granted.request_id, granted_id);
  ASSERT_TRUE(granted.grant_id.has_value());
  EXPECT_EQ(*granted.grant_id, grant_id);

  // Denied path echoes the request id of the failed attempt.
  const auto denied_request = request("wrong-password", {"message.send"});
  const auto denied_id = denied_request.request_id;
  auto denied = target_service->evaluate(denied_request, peer, peer_key);
  ASSERT_TRUE(denied);
  ASSERT_EQ(denied.value_if()->status, StableStatus::unauthenticated);
  const auto& denied_event = target_events.back();
  EXPECT_EQ(denied_event.kind, PairingAuditKind::denied_password);
  ASSERT_TRUE(denied_event.request_id.has_value());
  EXPECT_EQ(*denied_event.request_id, denied_id);
  EXPECT_FALSE(denied_event.grant_id.has_value());

  // Initiator side: a stored grant carries both ids; a binding mismatch
  // still names the claimed ids before failing.
  auto stored = initiator_service->accept_grant(
      *evaluated.value_if(), granted_id, granted_request.nonce,
      target_store->device_id(), target_store->identity_public_key(),
      {"message.send"});
  ASSERT_TRUE(stored);
  ASSERT_EQ(initiator_events.size(), 1U);
  EXPECT_EQ(initiator_events.back().kind, PairingAuditKind::grant_accepted);
  ASSERT_TRUE(initiator_events.back().request_id.has_value());
  EXPECT_EQ(*initiator_events.back().request_id, granted_id);
  ASSERT_TRUE(initiator_events.back().grant_id.has_value());
  EXPECT_EQ(*initiator_events.back().grant_id, grant_id);

  PairingNonce wrong_nonce{};
  wrong_nonce[0] = std::byte{0xEEU};
  auto mismatched = initiator_service->accept_grant(
      *evaluated.value_if(), granted_id, wrong_nonce,
      target_store->device_id(), target_store->identity_public_key(),
      {"message.send"});
  ASSERT_FALSE(mismatched);
  EXPECT_EQ(initiator_events.back().kind, PairingAuditKind::grant_rejected);
  ASSERT_TRUE(initiator_events.back().request_id.has_value());
  EXPECT_EQ(*initiator_events.back().request_id, granted_id);
  ASSERT_TRUE(initiator_events.back().grant_id.has_value());
  EXPECT_EQ(*initiator_events.back().grant_id, grant_id);

  // Revocation is grant-scoped: the grant id names the revoked grant, no
  // request id exists on this path.
  ASSERT_TRUE(target_service->revoke_grant(grant_id));
  EXPECT_EQ(target_events.back().kind, PairingAuditKind::grant_revoked);
  EXPECT_FALSE(target_events.back().request_id.has_value());
  ASSERT_TRUE(target_events.back().grant_id.has_value());
  EXPECT_EQ(*target_events.back().grant_id, grant_id);

  // The M9-01 counter invariant survives the correlation threading: every
  // audited event still bumps exactly one counter.
  const auto& stats = target_service->stats();
  EXPECT_EQ(stats.attempts, 2U);
  EXPECT_EQ(stats.granted, 1U);
  EXPECT_EQ(stats.denied_password, 1U);
  EXPECT_EQ(stats.grant_revoked, 1U);
  EXPECT_EQ(initiator_service->stats().grant_accepted, 1U);
  EXPECT_EQ(initiator_service->stats().grant_rejected, 1U);
}

// ---------- RPC operation ids ----------

TEST(M9CorrelationTest, RpcCompletionsCarryRequestIds) {
  test::M6ServicePair harness;
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "echo", 1U, "rpc.device.read", false},
      [](const RpcCallContext& context) {
        RpcHandlerResult result;
        result.payload.assign(context.payload().begin(), context.payload().end());
        return result;
      }));

  // Success path: the outcome names the operation the caller started.
  std::vector<Result<RpcCallOutcome>> results;
  const auto started = harness.left_rpc->call(
      "device", "echo", {std::byte{0x42}}, RpcCallOptions{},
      [&results](const DeviceEndpointKey&, Result<RpcCallOutcome> outcome) {
        results.push_back(std::move(outcome));
      });
  ASSERT_TRUE(started);
  const auto started_id = *started.value_if();
  harness.cycle();
  ASSERT_EQ(results.size(), 1U);
  ASSERT_TRUE(results.front());
  EXPECT_EQ(results.front().value_if()->status, StableStatus::ok);
  EXPECT_EQ(results.front().value_if()->request_id, started_id);

  // Session loss finalizes the pending call with outcome_unknown and the
  // completion still names the operation (M6-12 + M9-03).
  RequestId::Storage explicit_bytes{};
  explicit_bytes[0] = std::byte{0xC7U};
  explicit_bytes[15] = std::byte{0x9DU};
  const RequestId explicit_id{explicit_bytes};
  ASSERT_TRUE(harness.left_rpc->call(
      "device", "echo", {}, RpcCallOptions{},
      [&results](const DeviceEndpointKey&, Result<RpcCallOutcome> outcome) {
        results.push_back(std::move(outcome));
      },
      explicit_id));
  harness.pump();
  ASSERT_EQ(harness.left_rpc->pending_calls(), 1U);
  harness.left->close(transport::CloseReason::transport_failed);
  harness.left_rpc->handle_session_closed();
  ASSERT_EQ(results.size(), 2U);
  ASSERT_TRUE(results.back());
  EXPECT_EQ(results.back().value_if()->status, StableStatus::outcome_unknown);
  EXPECT_EQ(results.back().value_if()->request_id, explicit_id);
}

TEST(M9CorrelationTest, RpcAdmissionFailureErrorNamesOperation) {
  test::M6ServicePair harness;
  RequestId::Storage bytes{};
  bytes[0] = std::byte{0x5AU};
  bytes[15] = std::byte{0xA5U};
  const RequestId id{bytes};

  const auto unused = [](const DeviceEndpointKey&, Result<RpcCallOutcome>) {};
  ASSERT_TRUE(harness.left_rpc->call("device", "anything", {}, RpcCallOptions{},
                                     unused, id));
  ASSERT_EQ(harness.left_rpc->pending_calls(), 1U);

  // The duplicate id is rejected before the wire: the Error must name the
  // rejected operation (architecture §13.1), because a caller passing a
  // generated id never saw it otherwise.
  const auto rejected = harness.left_rpc->call(
      "device", "anything", {}, RpcCallOptions{}, unused, id);
  ASSERT_FALSE(rejected);
  ASSERT_TRUE(rejected.error_if()->operation_id().has_value());
  // The wire request id is the operation id; the Identifier kind tag differs.
  EXPECT_EQ(rejected.error_if()->operation_id()->bytes(), id.bytes());
  EXPECT_EQ(rejected.error_if()->code(), ErrorCode::configuration);
}

// ---------- Node-level pairing audit ring ----------

class M9NodeAuditRingTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root = std::filesystem::temp_directory_path() /
           ("heyaki-m9-audit-ring-" + std::to_string(::testing::UnitTest::
                                                         GetInstance()
                                                             ->random_seed()));
    std::filesystem::create_directories(root);
    std::filesystem::permissions(root, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    ProfileOpenOptions open_options;
    open_options.secret_backend.prefer_os_backend = false;
    auto profile = ProfileStore::create(root / "profile.sqlite", open_options);
    ASSERT_TRUE(profile);
    PasswordVerifier verifier{.format_version = 1U,
                              .parameters = PasswordHashParameters{},
                              .encoded = "$argon2id$v=19$m=65536,t=2,p=1$test$test"};
    LocalProfileInitialization initialization{
        .application_id = "com.example.audit",
        .password_verifier = std::move(verifier),
        .password_generation = 1U,
        .pairing_policy = PairingPolicy{},
        .lan = LanConfiguration{}};
    ASSERT_TRUE(profile.value_if()->initialize_local(initialization));
    store.emplace(std::move(*profile.value_if()));
  }

  void TearDown() override {
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
  }

  template <typename Predicate>
  bool wait_until(Predicate&& predicate, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    executor::comm::PhaseGate poll{"m9-correlation-poll"};
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
        return true;
      }
      (void)poll.wait_for(1U, std::chrono::milliseconds{1});
    }
    return predicate();
  }

  std::filesystem::path root;
  std::optional<ProfileStore> store;
};

TEST_F(M9NodeAuditRingTest, RecordsRevocationWithGrantId) {
  // Seed one issued grant directly: revocation does not re-verify the
  // signature, and put_trust_grant only requires a non-empty one.
  GrantId::Storage grant_bytes{};
  grant_bytes.fill(std::byte{0x6EU});
  const GrantId grant_id{grant_bytes};
  DeviceId::Storage subject_bytes{};
  subject_bytes.fill(std::byte{0x33U});
  TrustGrantRecord record;
  record.grant_id = grant_id;
  record.direction = TrustGrantDirection::issued;
  record.issuer = store->device_id();
  record.subject = DeviceId{subject_bytes};
  record.scopes = {"message.send"};
  record.password_generation = 1U;
  record.issued_unix_milliseconds = 1U;
  record.signature = {std::byte{0x01U}};
  record.revoked = false;
  ASSERT_TRUE(store->put_trust_grant(record));

  LanConfiguration lan;
  lan.enabled = false;
  NodeConfig node_config{
      .profile = &*store,
      .runtime = nullptr,
      .application_id = "com.example.audit",
      .lan_override = lan,
      .runtime_config = RuntimeConfig{},
      .signaling_validator = {},
      .signaling_handler = {},
      .relay_override = std::nullopt,
      .path_policy_override = std::nullopt,
      .pairing_failure_threshold = 0U,
      .pairing_backoff_base = std::chrono::milliseconds{0},
      .pairing_backoff_max = std::chrono::milliseconds{0},
      .pairing_grant_ttl_milliseconds = 0U,
      .event_subscriber_queue_items = 0U,
      .event_max_subscriptions_per_peer = 0U,
      .file_receive_roots = {},
      .file_max_peer_receive_bytes = 0U,
      .shell_profiles = {}};
  auto node = Node::create(std::move(node_config));
  ASSERT_TRUE(node) << node.error_if()->safe_detail();

  EXPECT_TRUE(node.value_if()->pairing_audit_records().empty());

  // The public revoke API runs on the caller's thread; the audit event must
  // still land on the node strand's bounded ring with its correlation id.
  ASSERT_TRUE(node.value_if()->revoke_trust_grant(grant_id));
  const auto recorded = wait_until(
      [&] {
        const auto events = node.value_if()->pairing_audit_records();
        return !events.empty() &&
               events.back().kind == PairingAuditKind::grant_revoked;
      },
      std::chrono::seconds{5});
  ASSERT_TRUE(recorded) << "revocation audit event never landed on the ring";
  const auto events = node.value_if()->pairing_audit_records();
  ASSERT_EQ(events.back().kind, PairingAuditKind::grant_revoked);
  ASSERT_TRUE(events.back().grant_id.has_value());
  EXPECT_EQ(*events.back().grant_id, grant_id);
  EXPECT_FALSE(events.back().request_id.has_value());

  EXPECT_TRUE(node.value_if()->shutdown().stopped);
}

}  // namespace
}  // namespace heyaki
