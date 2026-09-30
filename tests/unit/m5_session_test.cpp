// M5 session tests over the loopback transport: default-deny authorization
// (M5-07/M5-08/M5-14), password pairing upgrade with TrustGrant issuance and
// verification (M5-09..M5-12), and ByteStream semantics end to end
// (M5-15..M5-18).

#include "byte_stream.hpp"
#include "m4_support.hpp"
#include "peer_session.hpp"

#include <heyaki/pairing_protocol.hpp>
#include <heyaki/password.hpp>
#include <heyaki/trust_grant.hpp>

#include <gtest/gtest.h>

#include <cstring>
#include <map>
#include <random>
#include <optional>
#include <vector>

namespace heyaki {
namespace {

constexpr std::uint64_t kNow = 1'700'000'000'000U;

template <typename Storage, std::size_t Size = sizeof(Storage)>
Storage filled(std::uint8_t seed) {
  Storage storage{};
  auto* bytes = reinterpret_cast<std::uint8_t*>(&storage);
  for (std::size_t index = 0U; index < Size; ++index) {
    bytes[index] = static_cast<std::uint8_t>(seed + index);
  }
  return storage;
}

template <std::size_t Size>
std::array<std::byte, Size> filled_array(std::uint8_t seed) {
  std::array<std::byte, Size> value{};
  for (std::size_t index = 0U; index < Size; ++index) {
    value[index] = static_cast<std::byte>(seed + index);
  }
  return value;
}

ProtocolHello pairing_protocol() {
  return {.version = current_protocol_version,
          .supported = {protocol_1_2_capability_bits},
          .required = {static_cast<std::uint64_t>(Capability::session)}};
}

// Caller-owned stable wire request id for submit_pairing_request; non-zero
// and deterministic per seed so tests can correlate admission, wire frames,
// and result frames.
RequestId deterministic_request_id(std::uint8_t seed) {
  return RequestId{filled<RequestId::Storage>(seed)};
}

// Both sides of one loopback session with full M5 wiring. The RIGHT side is
// the pairing target (verifier + policy); the LEFT side is the initiator.
struct M5SessionPair {
  test::LoopbackTransportPair pair;
  Result<IdentityKeyPair> left_identity{create_identity()};
  Result<IdentityKeyPair> right_identity{create_identity()};
  PasswordVerifier verifier;
  // Trust state consulted by each side's authorizer.
  std::map<DeviceId, std::vector<std::string>> left_trust;
  std::map<DeviceId, std::vector<std::string>> right_trust;
  // Target-side pairing observations.
  std::uint64_t target_wall_clock = kNow;
  std::uint64_t initiator_wall_clock = kNow;
  bool grant_received = false;
  std::optional<SignedTrustGrant> received_grant;
  std::vector<std::pair<RequestId, PairingNonce>> initiator_pending;
  // Pairing observability for the request-id and idempotency contracts: the
  // request ids the target-side evaluator saw on the wire, and how many
  // times the initiator's result sink accepted a grant.
  std::vector<RequestId> evaluator_request_ids;
  std::size_t grant_sink_calls = 0;
  std::shared_ptr<PeerSession> left;
  std::shared_ptr<PeerSession> right;
  std::uint64_t stream_clock = kNow;

  M5SessionPair() {
    EXPECT_TRUE(left_identity && right_identity);
    auto created = create_password_verifier("target-password", PasswordHashParameters{});
    EXPECT_TRUE(created);
    verifier = std::move(*created.value_if());
    pair.connect();
    // The loopback transport matches inbound delivery by channel kind, so
    // both sides need their control channel open before the hellos flow
    // (the same setup the M4 session tests use).
    transport::ChannelOptions control_options;
    pair.left().async_open_channel(transport::ChannelKind::control, control_options,
                                   [](Result<transport::TransportChannel*>) {});
    pair.right().async_open_channel(transport::ChannelKind::control, control_options,
                                    [](Result<transport::TransportChannel*>) {});
    build_sessions();
  }

  [[nodiscard]] DeviceEndpointKey left_key() const {
    return {left_identity.value_if()->device_id(), filled<EndpointId>(0x20U)};
  }
  [[nodiscard]] DeviceEndpointKey right_key() const {
    return {right_identity.value_if()->device_id(), filled<EndpointId>(0x40U)};
  }

  void build_sessions() {
    const auto session_id = filled<SessionId>(0x60U);
    const auto initiator_nonce = filled_array<signaling_nonce_bytes>(0x10U);
    const auto responder_nonce = filled_array<signaling_nonce_bytes>(0x30U);
    const auto transcript = filled_array<signaling_transcript_sha256_bytes>(0x50U);
    auto left_transport = std::shared_ptr<transport::TransportSession>(
        &pair.left(), [](transport::TransportSession*) {});
    auto right_transport = std::shared_ptr<transport::TransportSession>(
        &pair.right(), [](transport::TransportSession*) {});
    VerifiedSessionBinding left_binding{
        {right_key(), left_key(), session_id, 1U, initiator_nonce, responder_nonce,
         transcript},
        {},
        "peer-ufrag",
        true};
    VerifiedSessionBinding right_binding{
        {left_key(), right_key(), session_id, 1U, initiator_nonce, responder_nonce,
         transcript},
        {},
        "peer-ufrag",
        false};

    auto left_timeline = std::make_shared<ConnectionAttemptTimeline>();
    EXPECT_TRUE(left_timeline->transition(ConnectionStage::resolving_endpoint, "test",
                                          "endpoint_selected"));
    EXPECT_TRUE(left_timeline->transition(ConnectionStage::signaling, "test",
                                          "attempt_accepted"));
    auto right_timeline = std::make_shared<ConnectionAttemptTimeline>();
    EXPECT_TRUE(right_timeline->transition(ConnectionStage::resolving_endpoint, "test",
                                           "endpoint_selected"));
    EXPECT_TRUE(right_timeline->transition(ConnectionStage::signaling, "test",
                                           "attempt_accepted"));
    auto left_created = PeerSession::create_verified(
        {.transport = left_transport,
         .binding = left_binding,
         .local_identity = &*left_identity.value_if(),
         .peer_public_key = right_identity.value_if()->public_key(),
         .local_protocol = pairing_protocol(),
         .expires_unix_milliseconds = kNow + 60'000U,
         .now_unix_milliseconds = kNow,
         .observer = {},
         .timeline = left_timeline,
         .clock = {},
         .trust_authorizer = [this](std::uint64_t now) {
           SessionAuthorization authorization;
           auto found = left_trust.find(right_identity.value_if()->device_id());
           if (found != left_trust.end()) {
             authorization.trusted = true;
             authorization.scopes = found->second;
           }
           authorization.pairing_allowed = true;
           (void)now;
           return Result<SessionAuthorization>::success(authorization);
         },
             .pairing_result_sink =
             [this](const PairingResultBody& result, const RequestId& pending_id,
                    const PairingNonce& pending_nonce,
                    const std::vector<std::string>& requested_scopes) {
               (void)pending_id;  // nonce is the binding checked below
               ++grant_sink_calls;
               if (!result.grant.has_value()) {
                 return Result<void>::failure(
                     Error{ErrorCode::authentication, "m5_test", "result_without_grant"});
               }
               const auto& grant = *result.grant;
               if (grant.nonce != pending_nonce ||
                   grant.issuer != right_identity.value_if()->device_id() ||
                   grant.subject != left_identity.value_if()->device_id()) {
                 return Result<void>::failure(
                     Error{ErrorCode::authentication, "m5_test", "grant_binding"});
               }
               auto verified = verify_signed_trust_grant(
                   grant,
                   std::span<const std::byte>{
                       right_identity.value_if()->public_key().data(),
                       right_identity.value_if()->public_key().size()},
                   initiator_wall_clock);
               if (!verified) return verified;
               for (const auto& scope : grant.granted_scopes) {
                 if (std::find(requested_scopes.begin(), requested_scopes.end(),
                               scope) == requested_scopes.end()) {
                   return Result<void>::failure(
                       Error{ErrorCode::authentication, "m5_test", "scope_overreach"});
                 }
               }
               grant_received = true;
               received_grant = grant;
               left_trust[grant.issuer] = grant.granted_scopes;
               return Result<void>::success();
             },
         .wall_clock = [this] { return initiator_wall_clock; }});
    ASSERT_TRUE(left_created);
    left = *left_created.value_if();

    auto right_created = PeerSession::create_verified(
        {.transport = right_transport,
         .binding = right_binding,
         .local_identity = &*right_identity.value_if(),
         .peer_public_key = left_identity.value_if()->public_key(),
         .local_protocol = pairing_protocol(),
         .expires_unix_milliseconds = kNow + 60'000U,
         .now_unix_milliseconds = kNow,
         .observer = {},
         .timeline = right_timeline,
         .clock = {},
         .trust_authorizer = [this](std::uint64_t now) {
           SessionAuthorization authorization;
           auto found = right_trust.find(left_identity.value_if()->device_id());
           if (found != right_trust.end()) {
             authorization.trusted = true;
             authorization.scopes = found->second;
           }
           authorization.pairing_allowed = true;
           (void)now;
           return Result<SessionAuthorization>::success(authorization);
         },
         .pairing_evaluator =
             [this](const PairingRequestBody& request) {
               evaluator_request_ids.push_back(request.request_id);
               // Target-side evaluation (M5-09): constant-time verifier check,
               // policy scope intersection, grant issuance bound to the
               // pairing nonce.
               auto verified = verify_password(request.password_utf8, verifier);
               if (!verified) {
                 return Result<PairingResultBody>::failure(*verified.error_if());
               }
               PairingResultBody result;
               result.request_id = request.request_id;
               if (!*verified.value_if()) {
                 result.status = StableStatus::unauthenticated;
                 return Result<PairingResultBody>::success(result);
               }
               const std::vector<std::string> policy_scopes = {"message.send",
                                                               "stream.open"};
               auto adjudication = adjudicate_trust_scopes(request.requested_scopes,
                                                           policy_scopes, std::nullopt);
               if (!adjudication.authorized) {
                 result.status = StableStatus::permission_denied;
                 return Result<PairingResultBody>::success(result);
               }
               SignedTrustGrant grant;
               GrantId::Storage grant_bytes = filled<GrantId::Storage>(0x77U);
               grant.grant_id = GrantId{grant_bytes};
               grant.issuer = right_identity.value_if()->device_id();
               grant.subject = left_identity.value_if()->device_id();
               grant.granted_scopes = adjudication.allowed_scopes;
               grant.password_generation = 1U;
               grant.issued_unix_milliseconds = target_wall_clock;
               grant.nonce = request.nonce;
               auto signed_grant =
                   sign_signed_trust_grant(grant, *right_identity.value_if());
               if (!signed_grant) {
                 return Result<PairingResultBody>::failure(*signed_grant.error_if());
               }
               right_trust[grant.subject] = grant.granted_scopes;
               result.status = StableStatus::ok;
               result.grant = std::move(grant);
               return Result<PairingResultBody>::success(result);
             },
         .wall_clock = [this] { return target_wall_clock; }});
    ASSERT_TRUE(right_created);
    right = *right_created.value_if();
  }

  // Drives both loopback directions until quiet; bounded to catch livelock.
  void pump_all(int rounds = 8) {
    for (int round = 0; round < rounds; ++round) {
      pair.left().pump();
      pair.right().pump();
    }
  }
};

TEST(M5PeerSession, UntrustedPeersArePairingRestrictedByDefault) {
  M5SessionPair harness;
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  EXPECT_TRUE(harness.left->pairing_restricted());
  EXPECT_TRUE(harness.right->pairing_restricted());
  EXPECT_FALSE(harness.left->authenticated());
  // RULE-03: restricted sessions refuse business frames.
  Frame business;
  business.type = static_cast<std::uint8_t>(FrameType::message);
  business.channel_id = 3U;
  business.message_id = filled<MessageId>(0x01U);
  business.payload.assign(8U, std::byte{0});
  const auto opened = harness.left->open_business_channel(
      session::ChannelDomain::message, session::QueueFullPolicy::reject, 4U, 4096U,
      [](const FrameView&) {});
  ASSERT_FALSE(opened);
  EXPECT_EQ(opened.error_if()->code(), ErrorCode::pairing_required);
}

TEST(M5PeerSession, PasswordPairingIssuesGrantAndUpgradesBothSides) {
  M5SessionPair harness;
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  ASSERT_TRUE(harness.left->pairing_restricted());

  const auto submitted = harness.left->submit_pairing_request(
      deterministic_request_id(0xA1U), "target-password",
      {"message.send", "stream.open", "shell.open:x"});
  ASSERT_TRUE(submitted);
  harness.pump_all();

  EXPECT_TRUE(harness.grant_received);
  ASSERT_TRUE(harness.received_grant.has_value());
  // The grant carries the policy intersection: shell is not in the template.
  EXPECT_EQ(harness.received_grant->granted_scopes,
            (std::vector<std::string>{"message.send", "stream.open"}));
  EXPECT_TRUE(harness.left->authenticated());
  EXPECT_TRUE(harness.right->authenticated());
  EXPECT_EQ(harness.left->authorized_scopes(),
            (std::vector<std::string>{"message.send", "stream.open"}));
  EXPECT_EQ(harness.right->authorized_scopes(),
            (std::vector<std::string>{"message.send", "stream.open"}));

  // M5-14: only after the upgrade can business channels open.
  const auto opened = harness.left->open_business_channel(
      session::ChannelDomain::stream, session::QueueFullPolicy::reject, 8U, 1U << 20U,
      [](const FrameView&) {});
  ASSERT_TRUE(opened);
  EXPECT_EQ(*opened.value_if() % 2U, 1U);
}

TEST(M5PeerSession, WrongPasswordClosesRestrictedSessionWithStableDenial) {
  M5SessionPair harness;
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();

  const auto submitted = harness.left->submit_pairing_request(
      deterministic_request_id(0xA2U), "wrong-password", {"message.send"});
  ASSERT_TRUE(submitted);
  harness.pump_all();

  const auto left_state = harness.left->diagnostics();
  const auto right_state = harness.right->diagnostics();
  EXPECT_EQ(left_state.state, PeerSessionState::closed);
  EXPECT_EQ(right_state.state, PeerSessionState::closed);
  ASSERT_TRUE(left_state.last_error.has_value());
  EXPECT_EQ(left_state.last_error->code(), ErrorCode::pairing_denied);
  EXPECT_FALSE(harness.grant_received);
  EXPECT_EQ(right_state.pairing_results_sent, 1U);
  EXPECT_EQ(left_state.pairing_results_received, 1U);
}

TEST(M5PeerSession, TrustedPeersAuthorizeWithoutPassword) {
  // Exit condition: an authorized device reconnects without re-entering the
  // password because both TrustStores already carry valid grants.
  M5SessionPair harness;
  harness.left_trust[harness.right_identity.value_if()->device_id()] = {
      "message.send"};
  harness.right_trust[harness.left_identity.value_if()->device_id()] = {
      "message.send"};
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  EXPECT_TRUE(harness.left->authenticated());
  EXPECT_TRUE(harness.right->authenticated());
  EXPECT_EQ(harness.left->authorized_scopes(), (std::vector<std::string>{"message.send"}));
  EXPECT_EQ(harness.left->diagnostics().pairing_requests_sent, 0U);
}

TEST(M5PeerSession, PairingDeadlineClosesExpiredRestrictedSession) {
  M5SessionPair harness;
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  ASSERT_TRUE(harness.left->pairing_restricted());

  // Advance both wall clocks past the restricted-session lifetime cap.
  harness.target_wall_clock += 61'000U;
  harness.initiator_wall_clock += 61'000U;
  const auto submitted = harness.left->submit_pairing_request(
      deterministic_request_id(0xA3U), "target-password", {"message.send"});
  // The initiator's own deadline check fires before any bytes hit the wire.
  ASSERT_FALSE(submitted);
  EXPECT_EQ(submitted.error_if()->safe_detail(), "pairing_deadline_exceeded");
}

void pair_loopback_control_send(M5SessionPair& harness, const Frame& frame);

TEST(M5PeerSession, DuplicatePairingResultClosesAsProtocolViolation) {
  M5SessionPair harness;
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  // An unsolicited PAIRING_RESULT on a restricted session with no pending
  // request is a protocol error and closes the session.
  PairingResultBody bogus;
  RequestId::Storage id_bytes = filled<RequestId::Storage>(0x9U);
  bogus.request_id = RequestId{id_bytes};
  bogus.status = StableStatus::permission_denied;
  auto encoded = encode_pairing_result(bogus);
  ASSERT_TRUE(encoded);
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::pairing_result);
  frame.channel_id = 0U;
  frame.message_id = filled<MessageId>(0x2U);
  frame.payload = std::move(*encoded.value_if());
  pair_loopback_control_send(harness, frame);
  const auto state = harness.right->diagnostics();
  EXPECT_EQ(state.state, PeerSessionState::closed);
}

void pair_loopback_control_send(M5SessionPair& harness, const Frame& frame) {
  auto encoded = encode_frame(frame);
  ASSERT_TRUE(encoded);
  // Inject the frame through the left transport's control channel: the
  // loopback pair delivers it to the right session's message handler, the
  // same path real transport bytes take.
  transport::ChannelOptions options;
  harness.pair.left().async_open_channel(
      transport::ChannelKind::control, options,
      [&](Result<transport::TransportChannel*> channel) {
        ASSERT_TRUE(channel);
        (void)(*channel.value_if())->send(*encoded.value_if());
      });
  harness.pair.left().pump();
  harness.pair.right().pump();
}

// Same injection path directed at the INITIATOR (left) session: the frame
// enters the left inbound queue before the helper pumps, so tests can order
// adversarial frames ahead of legitimate traffic.
void pair_loopback_control_send_to_initiator(M5SessionPair& harness,
                                             const Frame& frame) {
  auto encoded = encode_frame(frame);
  ASSERT_TRUE(encoded);
  transport::ChannelOptions options;
  harness.pair.right().async_open_channel(
      transport::ChannelKind::control, options,
      [&](Result<transport::TransportChannel*> channel) {
        ASSERT_TRUE(channel);
        (void)(*channel.value_if())->send(*encoded.value_if());
      });
  harness.pair.right().pump();
  harness.pair.left().pump();
}

Frame pairing_result_frame(const PairingResultBody& body, std::uint8_t seed) {
  auto encoded = encode_pairing_result(body);
  EXPECT_TRUE(encoded);
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::pairing_result);
  frame.channel_id = 0U;
  frame.message_id = filled<MessageId>(seed);
  if (encoded) {
    frame.payload = std::move(*encoded.value_if());
  }
  return frame;
}

// Issue #1 contract, wire level: the caller-owned request id submitted
// through submit_pairing_request is the id the target sees in the
// pairing_request frame, and the result frame echoing that same id is the
// one accepted for the upgrade.
TEST(M5PeerSession, CallerRequestIdFlowsThroughWireAndResultEcho) {
  M5SessionPair harness;
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  ASSERT_TRUE(harness.left->pairing_restricted());

  const auto request_id = deterministic_request_id(0xB1U);
  const auto submitted = harness.left->submit_pairing_request(
      request_id, "target-password", {"message.send"});
  ASSERT_TRUE(submitted);
  EXPECT_EQ(harness.left->diagnostics().pairing_requests_sent, 1U);
  harness.pump_all();

  // The target-side evaluator saw exactly the caller's id on the wire.
  ASSERT_EQ(harness.evaluator_request_ids.size(), 1U);
  EXPECT_EQ(harness.evaluator_request_ids[0], request_id);
  // The result frame echoed the same id and was accepted for the upgrade
  // (a mismatched id fails the protocol - covered by the mismatch test).
  EXPECT_TRUE(harness.left->authenticated());
  EXPECT_TRUE(harness.right->authenticated());
  EXPECT_EQ(harness.left->diagnostics().pairing_results_received, 1U);
}

// Original semantics kept: while the initiator is restricted with a pending
// request, a result frame carrying a DIFFERENT request id is a protocol
// violation that fails the session.
TEST(M5PeerSession, MismatchedResultIdFailsProtocolWhileRestrictedAndPending) {
  M5SessionPair harness;
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  ASSERT_TRUE(harness.left->pairing_restricted());

  const auto submitted = harness.left->submit_pairing_request(
      deterministic_request_id(0xB2U), "target-password", {"message.send"});
  ASSERT_TRUE(submitted);

  // Inject a result for a different request id BEFORE the legitimate result
  // is pumped: the injected frame enters the initiator's inbound queue first.
  PairingResultBody bogus;
  bogus.request_id = deterministic_request_id(0xB3U);
  bogus.status = StableStatus::permission_denied;
  pair_loopback_control_send_to_initiator(
      harness, pairing_result_frame(bogus, 0x4U));

  const auto state = harness.left->diagnostics();
  EXPECT_EQ(state.state, PeerSessionState::closed);
  ASSERT_TRUE(state.last_error.has_value());
  EXPECT_EQ(state.last_error->code(), ErrorCode::protocol);
  EXPECT_EQ(state.last_error->safe_detail(), "pairing_result_request_mismatch");
  EXPECT_FALSE(harness.grant_received);
}

// Issue #1 contract: after the pairing completed, a late or retransmitted
// result frame (same id or arbitrary id) is counted and ignored - it never
// resurrects a terminal state, never re-runs the grant sink, and never
// fails the healthy session. The same holds on the target side.
TEST(M5PeerSession, LateResultAfterAuthorizationIsCountedAndIgnored) {
  M5SessionPair harness;
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  ASSERT_TRUE(harness.left->pairing_restricted());

  const auto request_id = deterministic_request_id(0xC1U);
  const auto submitted = harness.left->submit_pairing_request(
      request_id, "target-password", {"message.send", "stream.open"});
  ASSERT_TRUE(submitted);
  harness.pump_all();
  ASSERT_TRUE(harness.left->authenticated());
  ASSERT_TRUE(harness.right->authenticated());
  ASSERT_EQ(harness.grant_sink_calls, 1U);
  ASSERT_EQ(harness.left->diagnostics().pairing_results_received, 1U);
  ASSERT_EQ(harness.right->diagnostics().pairing_results_received, 0U);
  const auto authorized_scopes = harness.left->authorized_scopes();

  // Retransmission of the consumed result on the initiator: identical id,
  // identical grant body.
  PairingResultBody retransmitted;
  retransmitted.request_id = request_id;
  retransmitted.status = StableStatus::ok;
  retransmitted.grant = harness.received_grant;
  pair_loopback_control_send_to_initiator(
      harness, pairing_result_frame(retransmitted, 0x5U));

  const auto left_state = harness.left->diagnostics();
  EXPECT_EQ(left_state.state, PeerSessionState::authenticated);
  EXPECT_EQ(left_state.pairing_results_received, 2U);
  EXPECT_EQ(harness.grant_sink_calls, 1U);
  EXPECT_EQ(harness.left->authorized_scopes(), authorized_scopes);
  EXPECT_EQ(harness.left->authorized_scopes(),
            (std::vector<std::string>{"message.send", "stream.open"}));

  // A stray result on the TARGET side (never had a pending request, now
  // trust-authorized) is also counted and ignored.
  PairingResultBody stray;
  stray.request_id = deterministic_request_id(0xC9U);
  stray.status = StableStatus::permission_denied;
  pair_loopback_control_send(harness, pairing_result_frame(stray, 0x6U));

  const auto right_state = harness.right->diagnostics();
  EXPECT_EQ(right_state.state, PeerSessionState::authenticated);
  EXPECT_EQ(right_state.pairing_results_received, 1U);
  EXPECT_EQ(harness.grant_sink_calls, 1U);
  EXPECT_TRUE(harness.left->authenticated());
  EXPECT_TRUE(harness.right->authenticated());
}

// Issue #3: an already-authorized target answers a legal pairing request
// (repair / renewal) with a stable result and WITHOUT closing or re-upgrading
// its session: the fresh grant lives in the TrustStore, the session keeps its
// state and scopes. The initiator-side result is consumed as a late frame on
// the authorized requester (counted, ignored).
TEST(M5PeerSession, AuthorizedTargetAnswersPairingRequestWithoutClosing) {
  M5SessionPair harness;
  // Mutual pre-trust: both sides authorize at hello; the session under test
  // (right, the pairing target) is authorized while a pairing request lands.
  harness.left_trust[harness.right_identity.value_if()->device_id()] = {"message.send"};
  harness.right_trust[harness.left_identity.value_if()->device_id()] = {"message.send"};
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  ASSERT_TRUE(harness.left->authenticated());
  ASSERT_TRUE(harness.right->authenticated());

  PairingRequestBody renewal;
  renewal.request_id = deterministic_request_id(0xD1U);
  renewal.nonce = filled<PairingNonce>(0x3U);
  renewal.nonce[0] = std::byte{0x5U};
  renewal.password_utf8 = "target-password";
  renewal.requested_scopes = {"stream.open"};
  auto encoded = encode_pairing_request(renewal);
  ASSERT_TRUE(encoded);
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::pairing_request);
  frame.channel_id = 0U;
  frame.message_id = filled<MessageId>(0x7U);
  frame.payload = std::move(*encoded.value_if());
  pair_loopback_control_send(harness, frame);
  // The helper pumps left before right answers; drain the answer into the
  // authorized requester.
  harness.pump_all();

  // The authorized target evaluated and answered; the session survived with
  // its original scopes (no re-upgrade to the renewal's grant scopes).
  const auto right_state = harness.right->diagnostics();
  EXPECT_EQ(right_state.state, PeerSessionState::authenticated);
  EXPECT_EQ(right_state.pairing_requests_received, 1U);
  EXPECT_EQ(right_state.pairing_results_sent, 1U);
  EXPECT_EQ(harness.right->authorized_scopes(),
            (std::vector<std::string>{"message.send"}));
  ASSERT_EQ(harness.evaluator_request_ids.size(), 1U);
  EXPECT_EQ(harness.evaluator_request_ids[0], renewal.request_id);

  // The authorized requester consumed the result as a late frame: counted,
  // ignored, no grant sink re-run, session alive.
  const auto left_state = harness.left->diagnostics();
  EXPECT_EQ(left_state.state, PeerSessionState::authenticated);
  EXPECT_EQ(left_state.pairing_results_received, 1U);
  EXPECT_EQ(harness.grant_sink_calls, 0U);
  EXPECT_TRUE(harness.left->authenticated());
  EXPECT_TRUE(harness.right->authenticated());
}

// Issue #3: a malformed pairing request on an authorized session is counted
// and ignored - no result frame, no session failure.
TEST(M5PeerSession, MalformedPairingRequestOnAuthorizedTargetIsIgnored) {
  M5SessionPair harness;
  harness.left_trust[harness.right_identity.value_if()->device_id()] = {"message.send"};
  harness.right_trust[harness.left_identity.value_if()->device_id()] = {"message.send"};
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  ASSERT_TRUE(harness.left->authenticated());
  ASSERT_TRUE(harness.right->authenticated());

  Frame garbage;
  garbage.type = static_cast<std::uint8_t>(FrameType::pairing_request);
  garbage.channel_id = 0U;
  garbage.message_id = filled<MessageId>(0x8U);
  garbage.payload.assign(16U, std::byte{0});
  pair_loopback_control_send(harness, garbage);

  const auto right_state = harness.right->diagnostics();
  EXPECT_EQ(right_state.state, PeerSessionState::authenticated);
  EXPECT_EQ(right_state.pairing_requests_received, 1U);
  // No answer for malformed input, and the evaluator never ran.
  EXPECT_EQ(right_state.pairing_results_sent, 0U);
  EXPECT_TRUE(harness.evaluator_request_ids.empty());
  // Nothing crossed back to the requester either.
  EXPECT_EQ(harness.left->diagnostics().pairing_results_received, 0U);
  EXPECT_TRUE(harness.left->authenticated());
  EXPECT_TRUE(harness.right->authenticated());
}

// Issue #3: an authorized initiator with a pending request consumes a denial
// result and STAYS authorized - the diagnostics record the consumed result
// binding (request id + status) instead of the session dying.
TEST(M5PeerSession, AuthorizedInitiatorConsumesDenialResultAndStaysAuthorized) {
  M5SessionPair harness;
  harness.left_trust[harness.right_identity.value_if()->device_id()] = {"message.send"};
  harness.right_trust[harness.left_identity.value_if()->device_id()] = {"message.send"};
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  ASSERT_TRUE(harness.left->authenticated());
  ASSERT_TRUE(harness.right->authenticated());

  const auto request_id = deterministic_request_id(0xE1U);
  const auto submitted = harness.left->submit_pairing_request(
      request_id, "target-password", {"stream.open"});
  ASSERT_TRUE(submitted) << submitted.error_if()->safe_detail();

  // Inject a denial for the pending id toward the authorized initiator. The
  // helper pumps the target first (its own ok answer for the submitted
  // request queues behind the injected denial), then the initiator drains
  // the denial and the late ok - both consumed without a failure.
  PairingResultBody denial;
  denial.request_id = request_id;
  denial.status = StableStatus::permission_denied;
  pair_loopback_control_send_to_initiator(
      harness, pairing_result_frame(denial, 0x9U));

  const auto left_state = harness.left->diagnostics();
  EXPECT_EQ(left_state.state, PeerSessionState::authenticated);
  EXPECT_TRUE(harness.left->authenticated());
  EXPECT_FALSE(harness.left->pairing_restricted());
  EXPECT_EQ(harness.left->authorized_scopes(),
            (std::vector<std::string>{"message.send"}));
  // The consumed result binding is published for the Node's active-session
  // pairing resolution.
  EXPECT_EQ(left_state.pairing_result_request_id, request_id);
  EXPECT_EQ(left_state.pairing_result_status, StableStatus::permission_denied);
  // Denial consumed + the target's ok answer for the same request ignored.
  EXPECT_EQ(left_state.pairing_results_received, 2U);
  EXPECT_FALSE(left_state.last_error.has_value());
  EXPECT_TRUE(harness.right->authenticated());
}

TEST(M5ByteStream, StreamsCarryBytesWindowsAndHalfClose) {
  M5SessionPair harness;
  harness.left_trust[harness.right_identity.value_if()->device_id()] = {"stream.open"};
  harness.right_trust[harness.left_identity.value_if()->device_id()] = {"stream.open"};
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  ASSERT_TRUE(harness.left->authenticated() && harness.right->authenticated());

  ByteStreamLimits limits;
  limits.default_receive_window_bytes = 4096U;
  limits.default_receive_window_frames = 4U;
  limits.max_data_chunk_bytes = 1024U;
  ByteStreamService right_service(*harness.right, limits);
  ASSERT_TRUE(right_service.attach());
  ByteStreamService left_service(*harness.left, limits);
  ASSERT_TRUE(left_service.attach());
  harness.pump_all();

  std::vector<std::shared_ptr<ByteStreamHandle>> inbound;
  right_service.set_inbound_handler(
      [&](const std::shared_ptr<ByteStreamHandle>& stream) {
        inbound.push_back(stream);
      });

  auto stream = left_service.open_stream(4096U, 4U);
  ASSERT_TRUE(stream);
  harness.pump_all();
  ASSERT_EQ(inbound.size(), 1U);
  EXPECT_EQ(inbound[0]->state(), StreamState::open);
  // The peer's OPEN granted us the full initial window (M5-16).
  EXPECT_EQ((*stream.value_if())->window().send_credit_bytes, 4096U);

  // A write larger than one chunk splits; completion means every byte
  // entered the send window (M5-18).
  std::string payload(2600U, 'x');
  std::size_t completed_bytes = 0U;
  std::optional<Error> completion_error;
  (*stream.value_if())
      ->async_write(std::span{reinterpret_cast<const std::byte*>(payload.data()),
                              payload.size()},
                    [&](StreamIoResult result) {
                      completed_bytes = result.bytes;
                      completion_error = result.error;
                    });
  EXPECT_EQ(completed_bytes, payload.size());
  EXPECT_FALSE(completion_error.has_value());
  EXPECT_EQ((*stream.value_if())->window().send_credit_bytes, 4096U - 2600U);
  harness.pump_all();

  // The receiving side buffers strictly ordered bytes and hands them to reads.
  std::vector<std::byte> received(2600U, std::byte{0});
  std::size_t total_read = 0U;
  while (total_read < received.size()) {
    bool progressed = false;
    inbound[0]->async_read_some(
        std::span<std::byte>{received.data() + total_read, received.size() - total_read},
        [&](StreamIoResult result) {
          if (result.error.has_value()) {
            ADD_FAILURE() << "read error: " << result.error->safe_detail();
          }
          if (result.bytes > 0U) progressed = true;
          total_read += result.bytes;
        });
    if (total_read == received.size()) break;
    ASSERT_TRUE(progressed);
  }
  EXPECT_EQ(std::memcmp(received.data(), payload.data(), payload.size()), 0);

  // Reads replenish the peer's window: WINDOW_UPDATE flowed back and credit
  // recovered (M5-16).
  harness.pump_all();
  EXPECT_GT((*stream.value_if())->window().send_credit_bytes, 4096U - 2600U);

  // Half-close: FIN after pending bytes; the peer reads EOF. One-sided FIN
  // leaves the closer half-closed; the stream reaches closed only after the
  // peer also finishes its write direction (M5-17).
  EXPECT_EQ((*stream.value_if())->state(), StreamState::open);
  const auto fin = (*stream.value_if())->shutdown_write();
  EXPECT_TRUE(fin);
  harness.pump_all();
  std::array<std::byte, 16U> tail{};
  bool eof_seen = false;
  inbound[0]->async_read_some(tail, [&](StreamIoResult result) {
    if (result.bytes == 0U && !result.error.has_value()) eof_seen = true;
  });
  EXPECT_TRUE(eof_seen);
  EXPECT_EQ((*stream.value_if())->state(), StreamState::half_closed_local);
  EXPECT_EQ(inbound[0]->state(), StreamState::half_closed_remote);
  EXPECT_TRUE(inbound[0]->shutdown_write());
  harness.pump_all();
  EXPECT_EQ((*stream.value_if())->state(), StreamState::closed);
}

TEST(M5ByteStream, ResetFailsOnlyTheStreamAndDeadlineCompletesPartial) {
  M5SessionPair harness;
  harness.left_trust[harness.right_identity.value_if()->device_id()] = {"stream.open"};
  harness.right_trust[harness.left_identity.value_if()->device_id()] = {"stream.open"};
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();

  ByteStreamLimits limits;
  limits.default_receive_window_bytes = 1024U;
  limits.default_receive_window_frames = 2U;
  limits.max_data_chunk_bytes = 512U;
  ByteStreamService right_service(*harness.right, limits,
                                   [&clock = harness.stream_clock] { return clock; });
  ByteStreamService left_service(*harness.left, limits,
                                 [&clock = harness.stream_clock] { return clock; });
  ASSERT_TRUE(right_service.attach() && left_service.attach());
  harness.pump_all();
  right_service.set_inbound_handler(
      [](const std::shared_ptr<ByteStreamHandle>&) {});

  auto stream = left_service.open_stream(1024U, 2U);
  ASSERT_TRUE(stream);
  harness.pump_all();

  // Consume the whole send window so the next write stalls.
  std::size_t admitted = 0U;
  std::optional<Error> stalled_error;
  std::vector<std::byte> filler(1024U, std::byte{1U});
  (*stream.value_if())->async_write(filler, [&](StreamIoResult result) {
    admitted = result.bytes;
    stalled_error = result.error;
  });
  EXPECT_EQ(admitted, 1024U);
  EXPECT_FALSE(stalled_error.has_value());
  EXPECT_EQ((*stream.value_if())->window().send_credit_bytes, 0U);

  // A further write admits nothing until credit returns; its deadline then
  // completes it with zero bytes and a timeout error (M5-17).
  std::size_t late_bytes = 999U;
  std::optional<Error> late_error;
  (*stream.value_if())
      ->async_write(std::span{reinterpret_cast<const std::byte*>("more"), 4U},
                    [&](StreamIoResult result) {
                      late_bytes = result.bytes;
                      late_error = result.error;
                    },
                    harness.stream_clock + 1U);
  // Advance the injectable stream clock past the deadline; the sweep then
  // fires deterministically.
  harness.stream_clock += 2U;
  left_service.check_deadlines();
  EXPECT_EQ(late_bytes, 0U);
  ASSERT_TRUE(late_error.has_value());
  EXPECT_EQ(late_error->code(), ErrorCode::timeout);

  // Reset fails exactly this stream (M5-15); the session survives.
  (*stream.value_if())->reset(StableStatus::cancelled);
  harness.pump_all();
  EXPECT_EQ((*stream.value_if())->state(), StreamState::reset);
  EXPECT_TRUE(harness.left->authenticated());
  EXPECT_TRUE(harness.right->authenticated());
  EXPECT_EQ(right_service.active_streams(), 0U);
}


TEST(M5ByteStream, RandomizedMisbehavingDataNeverCorruptsTheSession) {
  // Exit-condition sweep (deterministic seed): duplicated DATA, out-of-order
  // offsets, window-overflowing chunks, unknown REQUIRED frames, and frames
  // for foreign streams must fail at most the one stream — the session and
  // its transport stay trustworthy (wire 6.3 / M5-06).
  M5SessionPair harness;
  harness.left_trust[harness.right_identity.value_if()->device_id()] = {"stream.open"};
  harness.right_trust[harness.left_identity.value_if()->device_id()] = {"stream.open"};
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();

  ByteStreamLimits limits;
  limits.default_receive_window_bytes = 2048U;
  limits.default_receive_window_frames = 4U;
  limits.max_data_chunk_bytes = 512U;
  ByteStreamService right_service(*harness.right, limits);
  ByteStreamService left_service(*harness.left, limits);
  ASSERT_TRUE(right_service.attach() && left_service.attach());
  harness.pump_all();
  right_service.set_inbound_handler(
      [](const std::shared_ptr<ByteStreamHandle>&) {});

  auto stream = left_service.open_stream(2048U, 4U);
  ASSERT_TRUE(stream);
  harness.pump_all();

  std::mt19937 rng{0xC0FFEEU};
  auto send_data = [&](std::uint64_t offset, std::size_t size) {
    std::vector<std::byte> payload(28U + size, std::byte{0});
    const auto id = (*stream.value_if())->stream_id();
    std::copy_n(id.begin(), 16U, payload.begin());
    for (std::size_t index = 0U; index < 8U; ++index) {
      payload[16U + index] =
          static_cast<std::byte>((offset >> (56U - index * 8U)) & 0xFFU);
    }
    payload[24U] = static_cast<std::byte>((size >> 24U) & 0xFFU);
    payload[25U] = static_cast<std::byte>((size >> 16U) & 0xFFU);
    payload[26U] = static_cast<std::byte>((size >> 8U) & 0xFFU);
    payload[27U] = static_cast<std::byte>(size & 0xFFU);
    Frame frame;
    frame.type = static_cast<std::uint8_t>(FrameType::stream_data);
    frame.channel_id = 1U;
    frame.message_id = filled<MessageId>(0x1U);
    frame.payload = std::move(payload);
    auto opened = harness.left->send_frame(1U, session::FrameClass::bulk,
                                           std::move(frame));
    harness.pump_all();
    return opened;
  };

  // Some adversarial frames close the stream channel by design (unknown
  // REQUIRED frames close their channel, M5-06); later sends may then fail
  // admission. The assertions that matter are the per-round invariants.
  std::uint64_t expected_offset = 0U;
  for (int round = 0; round < 64; ++round) {
    const auto choice = rng() % 6U;
    switch (choice) {
      case 0U: {
        // In-window sequential data: always accepted.
        const auto size = 64U + (rng() % 128U);
        (void)send_data(expected_offset, size);
        expected_offset += size;
        break;
      }
      case 1U: {
        // Exact duplicate of already-consumed bytes: idempotent.
        if (expected_offset == 0U) break;
        (void)send_data(0U, 64U);
        break;
      }
      case 2U: {
        // Gap / future offset: resets exactly this stream.
        const auto gap_sent = send_data(expected_offset + 100'000U, 64U);
        if (gap_sent) {
          EXPECT_EQ((*stream.value_if())->state(), StreamState::reset);
        }
        // The session survives; open a fresh stream and continue.
        auto fresh = left_service.open_stream(2048U, 4U);
        if (fresh) {
          stream = fresh;
          harness.pump_all();
        }
        expected_offset = 0U;
        break;
      }
      case 3U: {
        // Window overflow: reset, stream only.
        const auto overflow_sent = send_data(expected_offset, 4096U);
        if (overflow_sent) {
          EXPECT_EQ((*stream.value_if())->state(), StreamState::reset);
        }
        auto fresh = left_service.open_stream(2048U, 4U);
        if (fresh) {
          stream = fresh;
          harness.pump_all();
        }
        expected_offset = 0U;
        break;
      }
      case 4U: {
        // Unknown REQUIRED frame on the stream channel: closes that channel,
        // never the session.
        Frame unknown;
        unknown.type = 0xFEU;
        unknown.flags = frame_flag_required;
        unknown.channel_id = 1U;
        unknown.message_id = filled<MessageId>(0x2U);
        unknown.payload.assign(4U, std::byte{0});
        auto accepted = harness.left->send_frame(1U, session::FrameClass::standard,
                                                 std::move(unknown));
        harness.pump_all();
        (void)accepted;
        auto fresh = left_service.open_stream(2048U, 4U);
        if (fresh) {
          stream = fresh;
          harness.pump_all();
        }
        expected_offset = 0U;
        break;
      }
      default: {
        // Declared length mismatch: reset, stream only.
        std::vector<std::byte> payload(28U + 32U, std::byte{0});
        payload[27U] = std::byte{0xFFU};
        Frame broken;
        broken.type = static_cast<std::uint8_t>(FrameType::stream_data);
        broken.channel_id = 1U;
        broken.message_id = filled<MessageId>(0x3U);
        broken.payload = std::move(payload);
        auto accepted = harness.left->send_frame(1U, session::FrameClass::bulk,
                                                 std::move(broken));
        harness.pump_all();
        (void)accepted;
        auto fresh = left_service.open_stream(2048U, 4U);
        if (fresh) {
          stream = fresh;
          harness.pump_all();
        }
        expected_offset = 0U;
        break;
      }
    }
    // Invariants after every round: the session itself stays authorized and
    // bounded; the stream registry never leaks past its cap.
    EXPECT_TRUE(harness.left->authenticated());
    EXPECT_TRUE(harness.right->authenticated());
    EXPECT_LE(right_service.active_streams(), limits.max_concurrent_streams);
  }
}

}  // namespace
}  // namespace heyaki
