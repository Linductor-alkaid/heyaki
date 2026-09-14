// M9-12 compatibility tests: schema N-1/N interop (session-hello negotiation,
// LAN discovery admission, relay login/enrollment handshakes), handshake-time
// rejection of incompatible versions/capabilities, restart frames gated by the
// negotiated capability set, and rolling relay upgrade (v1 database migration
// with login continuity).

#include "m4_support.hpp"
#include "peer_session.hpp"
#include "relay_database.hpp"
#include "relay_enrollment.hpp"
#include "relay_enrollment_service.hpp"
#include "relay_login.hpp"
#include "relay_login_service.hpp"

#include <heyaki/lan_protocol.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/wire.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string_view>

#include <sqlite3.h>

namespace heyaki {
namespace {

constexpr std::uint64_t kNow = 1'700'000'000'000U;

#ifndef HEYAKI_M9_COMPAT_TEST_STATE_DIR
#define HEYAKI_M9_COMPAT_TEST_STATE_DIR "."
#endif

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

class TemporaryDirectory {
 public:
  explicit TemporaryDirectory(std::string_view name) {
    std::error_code error;
    path_ = std::filesystem::path{HEYAKI_M9_COMPAT_TEST_STATE_DIR} / name;
    std::filesystem::remove_all(path_, error);
    error.clear();
    std::filesystem::create_directories(path_, error);
    EXPECT_FALSE(error);
  }
  ~TemporaryDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }
  TemporaryDirectory(const TemporaryDirectory&) = delete;
  TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

 private:
  std::filesystem::path path_;
};

std::uint64_t now_milliseconds() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

RelayId test_relay_id(std::uint8_t seed) {
  RelayId relay_id{};
  relay_id[0] = static_cast<std::byte>(seed);
  relay_id[1] = static_cast<std::byte>(0x9CU);
  return relay_id;
}

ProtocolHello protocol_at(std::uint32_t minor, std::uint64_t supported) {
  return {.version = ProtocolVersion{current_protocol_version.major, minor},
          .supported = CapabilitySet{supported},
          .required = CapabilitySet{static_cast<std::uint64_t>(Capability::session)}};
}

// --- Negotiation semantics -------------------------------------------------

TEST(M9CompatNegotiation, NegotiatesDownToOlderMinorAndIntersectsCapabilities) {
  const ProtocolHello local = protocol_at(2U, protocol_1_2_capability_bits);
  const ProtocolHello remote = protocol_at(1U, protocol_1_1_capability_bits);
  auto negotiated = negotiate_protocol(local, remote);
  ASSERT_TRUE(negotiated) << negotiated.error_if()->safe_detail();
  EXPECT_EQ(negotiated.value_if()->version.major, 1U);
  EXPECT_EQ(negotiated.value_if()->version.minor, 1U);
  EXPECT_EQ(negotiated.value_if()->capabilities.bits, protocol_1_1_capability_bits);

  // Symmetric: the older side observes the same negotiated window.
  auto mirrored = negotiate_protocol(remote, local);
  ASSERT_TRUE(mirrored);
  EXPECT_EQ(mirrored.value_if()->version.minor, 1U);
  EXPECT_EQ(mirrored.value_if()->capabilities.bits, protocol_1_1_capability_bits);
}

TEST(M9CompatNegotiation, CapabilitiesForVersionMapsMinorsAndForeignMajors) {
  EXPECT_EQ(capabilities_for_version({1U, 0U}), protocol_1_0_capability_bits);
  EXPECT_EQ(capabilities_for_version({1U, 1U}), protocol_1_1_capability_bits);
  EXPECT_EQ(capabilities_for_version({1U, 2U}), protocol_1_2_capability_bits);
  // Foreign majors (including newer ones) define no capability bits.
  EXPECT_EQ(capabilities_for_version({2U, 0U}), 0U);
  EXPECT_EQ(capabilities_for_version({2U, 2U}), 0U);
  EXPECT_EQ(capabilities_for_version({0U, 2U}), 0U);
}

TEST(M9CompatNegotiation, RejectsIncompatibleVersionsAtHandshake) {
  const ProtocolHello local = protocol_at(2U, protocol_1_2_capability_bits);

  // A foreign major never negotiates, even with identical capability bits.
  ProtocolHello foreign_major = local;
  foreign_major.version.major = 2U;
  auto major_mismatch = negotiate_protocol(local, foreign_major);
  ASSERT_FALSE(major_mismatch);
  EXPECT_EQ(major_mismatch.error_if()->safe_detail(), "incompatible_major_version");

  // A device at 1.1 that requires the 1.2-only restart bit cannot negotiate:
  // the required bit is outside the version's defined capability set.
  ProtocolHello overrequires = protocol_at(1U, protocol_1_2_capability_bits);
  overrequires.required.bits |= static_cast<std::uint64_t>(Capability::session_restart_v1);
  auto required_unavailable = negotiate_protocol(local, overrequires);
  ASSERT_FALSE(required_unavailable);
  EXPECT_EQ(required_unavailable.error_if()->safe_detail(),
            "required_capability_unavailable");

  // Unknown required bits are rejected before any version logic.
  ProtocolHello unknown_required = local;
  unknown_required.required.bits |= (1ULL << 40U);
  auto unknown = negotiate_protocol(local, unknown_required);
  ASSERT_FALSE(unknown);
  EXPECT_EQ(unknown.error_if()->safe_detail(), "unknown_required_capability");
}

// --- Session-hello interop over a loopback transport ------------------------

struct CompatSessionPair {
  test::LoopbackTransportPair pair;
  Result<IdentityKeyPair> left_identity{create_identity()};
  Result<IdentityKeyPair> right_identity{create_identity()};
  std::shared_ptr<PeerSession> left;
  std::shared_ptr<PeerSession> right;

  [[nodiscard]] DeviceEndpointKey left_key() const {
    return {left_identity.value_if()->device_id(), filled<EndpointId>(0x20U)};
  }
  [[nodiscard]] DeviceEndpointKey right_key() const {
    return {right_identity.value_if()->device_id(), filled<EndpointId>(0x40U)};
  }

  static Result<SessionAuthorization> trust_everything(std::uint64_t) {
    SessionAuthorization authorization;
    authorization.trusted = true;
    authorization.scopes = {"message.send"};
    authorization.pairing_allowed = true;
    return Result<SessionAuthorization>::success(authorization);
  }

  // left speaks the current protocol; right speaks `minor` with the matching
  // capability set, standing in for an N-1 device.
  void build(std::uint32_t right_minor) {
    const auto session_id = filled<SessionId>(0x60U);
    const auto initiator_nonce = filled_array<signaling_nonce_bytes>(0x10U);
    const auto responder_nonce = filled_array<signaling_nonce_bytes>(0x30U);
    const auto transcript = filled_array<signaling_transcript_sha256_bytes>(0x50U);
    auto left_transport = std::shared_ptr<transport::TransportSession>(
        &pair.left(), [](transport::TransportSession*) {});
    auto right_transport = std::shared_ptr<transport::TransportSession>(
        &pair.right(), [](transport::TransportSession*) {});
    pair.connect();
    // The loopback transport matches inbound delivery by channel kind, so
    // both sides need a registered control channel before the hellos flow
    // (the same setup the M5 session tests use); the responder adopts the
    // inbound channel from its hello.
    transport::ChannelOptions control_options;
    pair.left().async_open_channel(transport::ChannelKind::control, control_options,
                                   [](Result<transport::TransportChannel*>) {});
    pair.right().async_open_channel(transport::ChannelKind::control, control_options,
                                    [](Result<transport::TransportChannel*>) {});
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

    const auto right_supported =
        capabilities_for_version({current_protocol_version.major, right_minor});
    auto left_created = PeerSession::create_verified(
        {left_transport, left_binding, &*left_identity.value_if(),
         right_identity.value_if()->public_key(),
         protocol_at(2U, protocol_1_2_capability_bits),
         kNow + 60'000U,
         kNow,
         {},
         left_timeline,
         {},
         trust_everything});
    ASSERT_TRUE(left_created) << left_created.error_if()->safe_detail();
    left = *left_created.value_if();

    auto right_created = PeerSession::create_verified(
        {right_transport, right_binding, &*right_identity.value_if(),
         left_identity.value_if()->public_key(),
         protocol_at(right_minor, right_supported),
         kNow + 60'000U,
         kNow,
         {},
         right_timeline,
         {},
         trust_everything});
    ASSERT_TRUE(right_created) << right_created.error_if()->safe_detail();
    right = *right_created.value_if();
  }

  void start_and_authenticate(std::uint32_t right_minor) {
    build(right_minor);
    ASSERT_TRUE(left->start());
    ASSERT_TRUE(right->start());
    pump_all();
    if (!left->authenticated()) {
      const auto diagnostics = left->diagnostics();
      ADD_FAILURE() << "left not authenticated; state="
                    << static_cast<int>(diagnostics.state) << " error="
                    << (diagnostics.last_error.has_value()
                            ? diagnostics.last_error->safe_detail()
                            : "<none>");
    }
    if (!right->authenticated()) {
      const auto diagnostics = right->diagnostics();
      ADD_FAILURE() << "right not authenticated; state="
                    << static_cast<int>(diagnostics.state) << " error="
                    << (diagnostics.last_error.has_value()
                            ? diagnostics.last_error->safe_detail()
                            : "<none>");
    }
  }

  // Drives both loopback directions until quiet; bounded to catch livelock.
  void pump_all(int rounds = 8) {
    for (int round = 0; round < rounds; ++round) {
      pair.left().pump();
      pair.right().pump();
    }
  }

  // Delivers `frame` to the LEFT session as if the peer had sent it on the
  // control channel, bypassing the sending PeerSession's own gates.
  Result<void> inject_into_left(const Frame& frame) {
    transport::ChannelOptions options;
    transport::TransportChannel* opened_channel = nullptr;
    Error open_error{ErrorCode::transport, "m9_compat_test", "control_open_failed"};
    pair.right().async_open_channel(
        transport::ChannelKind::control, options,
        [&opened_channel, &open_error](Result<transport::TransportChannel*> result) {
          if (result) {
            opened_channel = *result.value_if();
          } else {
            open_error = *result.error_if();
          }
        });
    if (opened_channel == nullptr) {
      return Result<void>::failure(open_error);
    }
    auto encoded = encode_frame(frame);
    if (!encoded) return Result<void>::failure(*encoded.error_if());
    auto sent = opened_channel->send(*encoded.value_if());
    if (!sent) return sent;
    pump_all(1);
    return Result<void>::success();
  }
};

TEST(M9CompatSession, InteropsWithOlderMinorAndGatesRestartFrames) {
  CompatSessionPair harness;
  ASSERT_NO_FATAL_FAILURE(harness.start_and_authenticate(1U));

  // Negotiated down to 1.1 with the intersection capability set on both sides.
  const auto left_diagnostics = harness.left->diagnostics();
  const auto right_diagnostics = harness.right->diagnostics();
  EXPECT_EQ(left_diagnostics.negotiated_capabilities.bits, protocol_1_1_capability_bits);
  EXPECT_EQ(right_diagnostics.negotiated_capabilities.bits, protocol_1_1_capability_bits);

  bool offer_forwarded = false;
  harness.left->set_restart_handler(PeerSessionRestartHandler{
      .on_restart_offer =
          [&offer_forwarded](std::vector<std::byte>) { offer_forwarded = true; },
  });

  // A 1.1-negotiated session must not send restart frames.
  Frame offer;
  offer.type = static_cast<std::uint8_t>(FrameType::session_restart_offer);
  offer.message_id = filled<MessageId>(0x0AU);
  offer.payload.assign(16U, std::byte{0x5AU});
  auto send_denied = harness.left->send_restart_frame(
      FrameType::session_restart_offer,
      std::span<const std::byte>{offer.payload.data(), offer.payload.size()});
  ASSERT_FALSE(send_denied);
  EXPECT_EQ(send_denied.error_if()->safe_detail(),
            "restart_capability_not_negotiated");

  // ... and must ignore restart frames arriving from the peer without
  // forwarding them: the behavior is not enabled by the negotiated capability.
  auto delivered = harness.inject_into_left(offer);
  ASSERT_TRUE(delivered) << delivered.error_if()->safe_detail();
  EXPECT_FALSE(offer_forwarded);
  EXPECT_EQ(harness.left->diagnostics().restart_frames_received, 1U);
  EXPECT_TRUE(harness.left->authenticated());
  EXPECT_EQ(harness.left->diagnostics().restart_frames_sent, 0U);
}

TEST(M9CompatSession, ForwardsRestartFramesWhenCapabilityIsNegotiated) {
  CompatSessionPair harness;
  ASSERT_NO_FATAL_FAILURE(harness.start_and_authenticate(2U));
  ASSERT_EQ(harness.left->diagnostics().negotiated_capabilities.bits,
            protocol_1_2_capability_bits);

  std::optional<std::vector<std::byte>> forwarded;
  harness.left->set_restart_handler(PeerSessionRestartHandler{
      .on_restart_offer =
          [&forwarded](std::vector<std::byte> payload) { forwarded = std::move(payload); },
  });

  Frame offer;
  offer.type = static_cast<std::uint8_t>(FrameType::session_restart_offer);
  offer.message_id = filled<MessageId>(0x0BU);
  offer.payload.assign(16U, std::byte{0x5BU});
  auto delivered = harness.inject_into_left(offer);
  ASSERT_TRUE(delivered) << delivered.error_if()->safe_detail();
  ASSERT_TRUE(forwarded.has_value());
  EXPECT_EQ(forwarded->size(), offer.payload.size());
  EXPECT_TRUE(harness.left->authenticated());
}

// --- Relay control-plane handshakes ----------------------------------------

RelayLoginRequest make_login_request(const IdentityKeyPair& identity,
                                     const RelayLoginChallenge& challenge,
                                     ProtocolVersion version, std::uint64_t supported,
                                     std::uint64_t required, std::uint64_t generation,
                                     std::uint64_t now, std::uint8_t endpoint_byte) {
  RelayLoginRequest request;
  request.device_id = identity.device_id();
  EndpointId::Storage endpoint{};
  endpoint[0] = static_cast<std::byte>(endpoint_byte);
  request.endpoint_id = EndpointId{endpoint};
  request.identity_public_key = identity.public_key();
  request.challenge_nonce = challenge.nonce;
  request.tenant = "tenant-a";
  request.protocol_version = version;
  request.supported.bits = supported;
  request.required.bits = required;
  request.enrollment_generation = generation;
  request.expires_unix_milliseconds = now + 30U * 1000U;
  auto signature = sign_relay_login_request(request, challenge.relay_id, identity);
  EXPECT_TRUE(signature) << signature.error_if()->safe_detail();
  return request;
}

RelayDeviceRecord make_device_record(const IdentityKeyPair& identity) {
  RelayDeviceRecord record;
  record.device_id = identity.device_id();
  record.public_key = identity.public_key();
  record.tenant = "tenant-a";
  record.display_name = "compat-device";
  record.enrollment_generation = 1U;
  record.status = RelayDeviceStatus::active;
  return record;
}

TEST(M9CompatRelayLogin, AdmitsOlderMinorDeviceWithClampedCapabilities) {
  TemporaryDirectory directory{"m9-compat-relay-login-older"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  ASSERT_TRUE(
      database.value_if()->enroll_device(make_device_record(*identity.value_if()), kNow));

  auto service = RelayLoginService::create(database.value_if(), test_relay_id(3U));
  ASSERT_TRUE(service) << service.error_if()->safe_detail();

  // A 1.1 device that honestly advertises the 1.1 capability set.
  {
    auto challenge_bytes = service.value_if()->begin_challenge(kNow);
    ASSERT_TRUE(challenge_bytes) << challenge_bytes.error_if()->safe_detail();
    auto challenge = parse_enrollment_challenge(*challenge_bytes.value_if());
    ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();
    auto request = make_login_request(
        *identity.value_if(), *challenge.value_if(), ProtocolVersion{1U, 1U},
        protocol_1_1_capability_bits, static_cast<std::uint64_t>(Capability::enrollment),
        1U, kNow, 0x31U);
    auto encoded = encode_relay_login_request(request);
    ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();
    auto authenticated = service.value_if()->authenticate(*encoded.value_if(), kNow + 1U);
    ASSERT_TRUE(authenticated) << authenticated.error_if()->safe_detail();
    EXPECT_EQ(authenticated.value_if()->capabilities.bits, protocol_1_1_capability_bits);
  }

  // A misbehaving "1.1" device claiming the 1.2-only restart bit: the claim
  // survives validation but the granted set is clamped to the negotiated
  // version's capability bits.
  {
    auto challenge_bytes = service.value_if()->begin_challenge(kNow + 10U);
    ASSERT_TRUE(challenge_bytes) << challenge_bytes.error_if()->safe_detail();
    auto challenge = parse_enrollment_challenge(*challenge_bytes.value_if());
    ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();
    auto request = make_login_request(
        *identity.value_if(), *challenge.value_if(), ProtocolVersion{1U, 1U},
        protocol_1_2_capability_bits, static_cast<std::uint64_t>(Capability::enrollment),
        1U, kNow + 10U, 0x32U);
    auto encoded = encode_relay_login_request(request);
    ASSERT_TRUE(encoded);
    auto authenticated = service.value_if()->authenticate(*encoded.value_if(), kNow + 11U);
    ASSERT_TRUE(authenticated) << authenticated.error_if()->safe_detail();
    EXPECT_EQ(authenticated.value_if()->capabilities.bits, protocol_1_1_capability_bits);
  }
  EXPECT_EQ(service.value_if()->diagnostics().logins_succeeded, 2U);
}

TEST(M9CompatRelayLogin, RejectsIncompatibleDevicesAtHandshake) {
  TemporaryDirectory directory{"m9-compat-relay-login-reject"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  ASSERT_TRUE(
      database.value_if()->enroll_device(make_device_record(*identity.value_if()), kNow));

  auto service = RelayLoginService::create(database.value_if(), test_relay_id(4U));
  ASSERT_TRUE(service) << service.error_if()->safe_detail();

  // Foreign major: rejected with an explicit protocol error at the handshake,
  // never admitted into the session state machine.
  {
    auto challenge_bytes = service.value_if()->begin_challenge(kNow);
    ASSERT_TRUE(challenge_bytes);
    auto challenge = parse_enrollment_challenge(*challenge_bytes.value_if());
    ASSERT_TRUE(challenge);
    auto request = make_login_request(
        *identity.value_if(), *challenge.value_if(), ProtocolVersion{2U, 0U},
        protocol_1_2_capability_bits, static_cast<std::uint64_t>(Capability::enrollment),
        1U, kNow, 0x33U);
    auto encoded = encode_relay_login_request(request);
    ASSERT_TRUE(encoded);
    auto rejected = service.value_if()->authenticate(*encoded.value_if(), kNow + 1U);
    ASSERT_FALSE(rejected);
    EXPECT_EQ(rejected.error_if()->code(), ErrorCode::protocol);
    EXPECT_EQ(rejected.error_if()->safe_detail(), "incompatible_major_version");
  }

  // A "1.1" device requiring the 1.2-only restart bit: the required set is not
  // available at the negotiated version.
  {
    auto challenge_bytes = service.value_if()->begin_challenge(kNow + 10U);
    ASSERT_TRUE(challenge_bytes);
    auto challenge = parse_enrollment_challenge(*challenge_bytes.value_if());
    ASSERT_TRUE(challenge);
    const std::uint64_t required = static_cast<std::uint64_t>(Capability::enrollment) |
                                   static_cast<std::uint64_t>(Capability::session_restart_v1);
    auto request = make_login_request(
        *identity.value_if(), *challenge.value_if(), ProtocolVersion{1U, 1U},
        protocol_1_2_capability_bits, required, 1U, kNow + 10U, 0x34U);
    auto encoded = encode_relay_login_request(request);
    ASSERT_TRUE(encoded);
    auto rejected = service.value_if()->authenticate(*encoded.value_if(), kNow + 11U);
    ASSERT_FALSE(rejected);
    EXPECT_EQ(rejected.error_if()->safe_detail(), "required_capability_unavailable");
  }

  // Unknown required bits are refused before anything else. A client cannot
  // even encode them (supported must contain required), so that rejection is
  // covered by the negotiation unit test above; the wire-visible cases are
  // the two above.
  EXPECT_EQ(service.value_if()->diagnostics().logins_succeeded, 0U);
}

TEST(M9CompatRelayEnrollment, AdmitsOlderMinorDevice) {
  TemporaryDirectory directory{"m9-compat-relay-enroll"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  // Bootstrap tokens are wall-clock dated: use the real clock for expiry.
  const auto now = now_milliseconds();
  const std::string token = "TEST-ONLY-compat-token-0123456789";
  ASSERT_TRUE(database.value_if()->create_bootstrap_token("tenant-a", token,
                                                          now + 60U * 1000U, 1U));

  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  auto service = RelayEnrollmentService::create(database.value_if(), test_relay_id(5U));
  ASSERT_TRUE(service) << service.error_if()->safe_detail();

  auto challenge_bytes = service.value_if()->begin_challenge(now);
  ASSERT_TRUE(challenge_bytes) << challenge_bytes.error_if()->safe_detail();
  auto challenge = parse_enrollment_challenge(*challenge_bytes.value_if());
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();

  EnrollmentRequest request;
  request.device_id = identity.value_if()->device_id();
  EndpointId::Storage endpoint{};
  endpoint[0] = static_cast<std::byte>(0x41U);
  request.endpoint_id = EndpointId{endpoint};
  request.identity_public_key = identity.value_if()->public_key();
  request.challenge_nonce = challenge.value_if()->nonce;
  request.tenant = "tenant-a";
  request.bootstrap_token = token;
  // Enroll as a 1.1 device with the 1.1 capability set.
  request.protocol_version = ProtocolVersion{1U, 1U};
  request.supported.bits = protocol_1_1_capability_bits;
  request.required.bits = static_cast<std::uint64_t>(Capability::enrollment);
  request.expires_unix_milliseconds = now + 30U * 1000U;
  auto signature = sign_enrollment_request(request, challenge.value_if()->relay_id,
                                           *identity.value_if());
  ASSERT_TRUE(signature) << signature.error_if()->safe_detail();
  auto encoded = encode_enrollment_request(request);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();

  auto completed = service.value_if()->complete(*encoded.value_if(), now + 1U);
  ASSERT_TRUE(completed) << completed.error_if()->safe_detail();
  EXPECT_EQ(completed.value_if()->enrollment_generation, 1U);
  EXPECT_EQ(database.value_if()->snapshot().device_count, 1U);
}

// --- LAN discovery interop --------------------------------------------------

LanPresence make_presence(const IdentityKeyPair& identity) {
  LanPresence presence;
  EndpointId::Storage endpoint_bytes{};
  endpoint_bytes[0] = std::byte{0x42U};
  presence.endpoint_id = EndpointId{endpoint_bytes};
  for (std::size_t index = 0U; index < presence.boot_nonce.size(); ++index) {
    presence.boot_nonce[index] = static_cast<std::byte>(index + 1U);
  }
  presence.sequence = 9U;
  presence.tls_signaling_port = 49190U;
  presence.lease = std::chrono::milliseconds{15000};
  EXPECT_TRUE(sign_lan_presence(presence, identity));
  return presence;
}

LanHello make_hello(const IdentityKeyPair& sender, const IdentityKeyPair& peer,
                    LanHelloRole role) {
  LanHello hello;
  hello.role = role;
  EndpointId::Storage sender_endpoint{};
  sender_endpoint[0] = std::byte{0x11U};
  EndpointId::Storage peer_endpoint{};
  peer_endpoint[0] = std::byte{0x22U};
  hello.sender_endpoint_id = EndpointId{sender_endpoint};
  hello.peer_device_id = peer.device_id();
  hello.peer_endpoint_id = EndpointId{peer_endpoint};
  hello.initiator_nonce[0] = std::byte{0x31U};
  hello.responder_nonce[0] = std::byte{0x32U};
  hello.sender_tls_certificate_sha256[0] = std::byte{0x41U};
  hello.observed_peer_tls_certificate_sha256[0] = std::byte{0x42U};
  hello.sender_boot_nonce[0] = std::byte{0x51U};
  EXPECT_TRUE(sign_lan_hello(hello, sender));
  return hello;
}

TEST(M9CompatLan, AdmitsOlderMinorPresenceAndHelloFromLanCapablePeers) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  auto peer = create_identity();
  ASSERT_TRUE(peer) << peer.error_if()->safe_detail();

  // A 1.1 device (the minor that introduced the LAN capability bits) stays
  // discoverable to a 1.2 receiver.
  auto older = make_presence(*identity.value_if());
  older.protocol_version = ProtocolVersion{1U, 1U};
  older.supported.bits = protocol_1_1_capability_bits;
  older.required.bits = static_cast<std::uint64_t>(Capability::lan_discovery_v1);
  ASSERT_TRUE(sign_lan_presence(older, *identity.value_if()));
  EXPECT_TRUE(validate_lan_presence(older));

  auto older_hello = make_hello(*identity.value_if(), *peer.value_if(),
                                LanHelloRole::initiator);
  older_hello.protocol_version = ProtocolVersion{1U, 1U};
  older_hello.supported.bits = protocol_1_1_capability_bits;
  older_hello.required.bits = static_cast<std::uint64_t>(Capability::lan_signaling_v1);
  ASSERT_TRUE(sign_lan_hello(older_hello, *identity.value_if()));
  EXPECT_TRUE(validate_lan_hello(older_hello));
}

TEST(M9CompatLan, StillRejectsPreLanAndForeignMajorPeers) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();

  // Minor 0 has no LAN capability bits at all: rejected by the version floor.
  auto pre_lan = make_presence(*identity.value_if());
  pre_lan.protocol_version = ProtocolVersion{1U, 0U};
  pre_lan.supported.bits = protocol_1_0_capability_bits;
  pre_lan.required.bits = static_cast<std::uint64_t>(Capability::session);
  ASSERT_TRUE(sign_lan_presence(pre_lan, *identity.value_if()));
  auto rejected_floor = validate_lan_presence(pre_lan);
  ASSERT_FALSE(rejected_floor);
  EXPECT_EQ(rejected_floor.error_if()->code(), ErrorCode::protocol);

  // A foreign major is rejected even with a matching capability claim.
  auto foreign = make_presence(*identity.value_if());
  foreign.protocol_version = ProtocolVersion{2U, 2U};
  ASSERT_TRUE(sign_lan_presence(foreign, *identity.value_if()));
  EXPECT_FALSE(validate_lan_presence(foreign));

  // Same-minor LAN presence without the LAN bits stays rejected.
  auto no_bits = make_presence(*identity.value_if());
  no_bits.supported.bits = protocol_1_0_capability_bits;
  ASSERT_TRUE(sign_lan_presence(no_bits, *identity.value_if()));
  EXPECT_FALSE(validate_lan_presence(no_bits));
}

// --- Rolling relay upgrade --------------------------------------------------

constexpr std::string_view relay_schema_v1_sql = R"SQL(
CREATE TABLE schema_migrations(
  version INTEGER PRIMARY KEY,
  applied_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE devices(
  device_id BLOB PRIMARY KEY CHECK(length(device_id) = 32),
  public_key BLOB NOT NULL CHECK(length(public_key) = 32),
  tenant TEXT NOT NULL,
  display_name TEXT NOT NULL,
  enrollment_generation INTEGER NOT NULL CHECK(enrollment_generation > 0),
  status INTEGER NOT NULL CHECK(status IN (1, 2)),
  created_unix_milliseconds INTEGER NOT NULL,
  updated_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE bootstrap_tokens(
  token_id BLOB PRIMARY KEY CHECK(length(token_id) = 16),
  token_hash BLOB NOT NULL UNIQUE CHECK(length(token_hash) = 32),
  tenant TEXT NOT NULL,
  expires_unix_milliseconds INTEGER NOT NULL,
  remaining_uses INTEGER NOT NULL CHECK(remaining_uses >= 0),
  created_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE device_audit(
  id INTEGER PRIMARY KEY,
  device_id BLOB CHECK(device_id IS NULL OR length(device_id) = 32),
  action TEXT NOT NULL,
  occurred_unix_milliseconds INTEGER NOT NULL,
  metadata TEXT NOT NULL
);
INSERT INTO schema_migrations(version, applied_unix_milliseconds)
VALUES(1, CAST(unixepoch('subsec') * 1000 AS INTEGER));
PRAGMA application_id=1213808977;
PRAGMA user_version=1;
)SQL";

// Creates a schema-v1 relay database containing one enrolled device whose
// identity is the given key pair — the state a relay binary from before the
// v2 schema left on disk.
void create_v1_database_with_device(const std::filesystem::path& path,
                                    const IdentityKeyPair& identity) {
  sqlite3* database = nullptr;
  ASSERT_EQ(sqlite3_open_v2(path.string().c_str(), &database,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                                SQLITE_OPEN_FULLMUTEX,
                            nullptr),
            SQLITE_OK);
  char* message = nullptr;
  const int result = sqlite3_exec(database, std::string{relay_schema_v1_sql}.c_str(),
                                  nullptr, nullptr, &message);
  ASSERT_EQ(result, SQLITE_OK) << (message == nullptr ? "" : message);
  sqlite3_free(message);

  sqlite3_stmt* insert = nullptr;
  const char* sql =
      "INSERT INTO devices(device_id, public_key, tenant, display_name,"
      " enrollment_generation, status, created_unix_milliseconds,"
      " updated_unix_milliseconds) VALUES(?, ?, 'tenant-a', 'pre-upgrade', 1, 1,"
      " 1700000000000, 1700000000000)";
  ASSERT_EQ(sqlite3_prepare_v2(database, sql, -1, &insert, nullptr), SQLITE_OK);
  const auto device_id = identity.device_id().bytes();
  const auto& public_key = identity.public_key();
  ASSERT_EQ(sqlite3_bind_blob(insert, 1, device_id.data(),
                              static_cast<int>(device_id.size()), SQLITE_TRANSIENT),
            SQLITE_OK);
  ASSERT_EQ(sqlite3_bind_blob(insert, 2, public_key.data(),
                              static_cast<int>(public_key.size()), SQLITE_TRANSIENT),
            SQLITE_OK);
  ASSERT_EQ(sqlite3_step(insert), SQLITE_DONE);
  sqlite3_finalize(insert);
  ASSERT_EQ(sqlite3_close_v2(database), SQLITE_OK);
}

TEST(M9CompatRollingUpgrade, MigratedV1DatabaseKeepsDevicesLoggingIn) {
  TemporaryDirectory directory{"m9-compat-rolling-upgrade"};
  const auto database_path = directory.path() / "relay.sqlite";
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  ASSERT_NO_FATAL_FAILURE(create_v1_database_with_device(database_path,
                                                         *identity.value_if()));

  auto login_once = [&](RelayDatabase& database) {
    auto service = RelayLoginService::create(&database, test_relay_id(6U));
    EXPECT_TRUE(service) << service.error_if()->safe_detail();
    auto challenge_bytes = service.value_if()->begin_challenge(kNow);
    EXPECT_TRUE(challenge_bytes) << challenge_bytes.error_if()->safe_detail();
    auto challenge = parse_enrollment_challenge(*challenge_bytes.value_if());
    EXPECT_TRUE(challenge) << challenge.error_if()->safe_detail();
    auto request =
        make_login_request(*identity.value_if(), *challenge.value_if(),
                           current_protocol_version, protocol_1_2_capability_bits,
                           static_cast<std::uint64_t>(Capability::enrollment), 1U, kNow,
                           0x36U);
    auto encoded = encode_relay_login_request(request);
    EXPECT_TRUE(encoded) << encoded.error_if()->safe_detail();
    return service.value_if()->authenticate(*encoded.value_if(), kNow + 1U);
  };

  // The pre-upgrade enrollment still authenticates after the migration.
  {
    // The upgraded relay binary opens the pre-upgrade database in place.
    auto upgraded = RelayDatabase::open(database_path);
    ASSERT_TRUE(upgraded) << upgraded.error_if()->safe_detail();
    EXPECT_EQ(upgraded.value_if()->snapshot().schema_version,
              relay_database_schema_version);
    EXPECT_EQ(upgraded.value_if()->snapshot().device_count, 1U);
    EXPECT_EQ(upgraded.value_if()->snapshot().device_audit_count, 0U);
    auto& upgraded_database = *upgraded.value_if();
    auto first = login_once(upgraded_database);
    ASSERT_TRUE(first) << first.error_if()->safe_detail();
    EXPECT_EQ(first.value_if()->capabilities.bits, protocol_1_2_capability_bits);
    EXPECT_EQ(upgraded.value_if()->snapshot().device_audit_count, 1U);
  }

  // Relay process restart after the upgrade: same database, logins continue.
  auto restarted = RelayDatabase::open(database_path);
  ASSERT_TRUE(restarted) << restarted.error_if()->safe_detail();
  EXPECT_EQ(restarted.value_if()->snapshot().schema_version, relay_database_schema_version);
  auto& restarted_database = *restarted.value_if();
  auto second = login_once(restarted_database);
  ASSERT_TRUE(second) << second.error_if()->safe_detail();
  EXPECT_EQ(restarted.value_if()->snapshot().device_audit_count, 2U);
}

}  // namespace
}  // namespace heyaki
