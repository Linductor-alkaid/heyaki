#include "m4_support.hpp"
#include "m1_golden_vectors.hpp"
#include "test_bytes.hpp"

#include <heyaki/identity.hpp>
#include <heyaki/signaling_protocol.hpp>
#include <heyaki/signaling_replay_cache.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using heyaki::test::bytes_from_hex;

std::uint64_t hex_to_u64(std::string_view hex) {
  std::uint64_t value = 0U;
  for (const char character : hex) {
    const auto nibble = static_cast<std::uint8_t>(character <= '9' ? character - '0'
                                                                   : character - 'a' + 10);
    value = (value << 4U) | nibble;
  }
  return value;
}

template <typename Id>
Id id_from_hex(std::string_view hex) {
  const auto bytes = bytes_from_hex(hex);
  typename Id::Storage storage{};
  std::memcpy(storage.data(), bytes.data(), storage.size());
  return Id{storage};
}

heyaki::SignalingNonce nonce_from_hex(std::string_view hex) {
  const auto bytes = bytes_from_hex(hex);
  heyaki::SignalingNonce nonce{};
  std::memcpy(nonce.data(), bytes.data(), nonce.size());
  return nonce;
}

heyaki::DtlsFingerprint fingerprint_from_hex(std::string_view hex) {
  const auto bytes = bytes_from_hex(hex);
  heyaki::DtlsFingerprint fingerprint{};
  std::memcpy(fingerprint.data(), bytes.data(), fingerprint.size());
  return fingerprint;
}

heyaki::SignedOffer golden_offer() {
  namespace vectors = heyaki::test_vectors;
  heyaki::SignedOffer offer;
  offer.binding.initiator.device_id =
      id_from_hex<heyaki::DeviceId>(std::string_view{vectors::canonical_field_1_hex});
  offer.binding.initiator.endpoint_id =
      id_from_hex<heyaki::EndpointId>(std::string_view{vectors::canonical_field_2_hex});
  offer.binding.responder.device_id =
      id_from_hex<heyaki::DeviceId>(std::string_view{vectors::canonical_field_3_hex});
  offer.binding.responder.endpoint_id =
      id_from_hex<heyaki::EndpointId>(std::string_view{vectors::canonical_field_4_hex});
  offer.binding.request_id =
      id_from_hex<heyaki::RequestId>(std::string_view{vectors::canonical_field_5_hex});
  offer.binding.session_id =
      id_from_hex<heyaki::SessionId>(std::string_view{vectors::canonical_field_6_hex});
  offer.binding.initiator_nonce =
      nonce_from_hex(std::string_view{vectors::canonical_field_7_hex});
  offer.binding.expires_unix_milliseconds =
      hex_to_u64(std::string_view{vectors::canonical_field_8_hex});
  offer.sdp = bytes_from_hex(std::string_view{vectors::canonical_field_9_hex});
  offer.dtls_fingerprint =
      fingerprint_from_hex(std::string_view{vectors::canonical_field_10_hex});
  return offer;
}

heyaki::SignedAnswer golden_answer() {
  heyaki::SignedAnswer answer;
  answer.binding = golden_offer().binding;
  answer.binding.responder_nonce =
      nonce_from_hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
  answer.sdp = bytes_from_hex("763d300d0a");
  answer.dtls_fingerprint =
      fingerprint_from_hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
  return answer;
}

constexpr std::string_view kSdpA{
    "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\na=ice-ufrag:8hKaFrag\r\na=ice-pwd:password0"
    "1password01\r\n"};
constexpr std::string_view kSdpB{
    "v=0\r\no=- 2 2 IN IP4 192.0.2.2\r\ns=-\r\na=ice-ufrag:Qz9xOther\r\na=ice-pwd:password02"
    "password02\r\n"};

std::vector<std::byte> sdp_bytes(std::string_view sdp) {
  return {reinterpret_cast<const std::byte*>(sdp.data()),
          reinterpret_cast<const std::byte*>(sdp.data()) + sdp.size()};
}

heyaki::DtlsFingerprint test_fingerprint(std::uint8_t seed) {
  heyaki::DtlsFingerprint fingerprint{};
  for (std::size_t index = 0U; index < fingerprint.size(); ++index) {
    fingerprint[index] = static_cast<std::byte>(seed + index);
  }
  return fingerprint;
}

TEST(M4SignalingProtocol, CanonicalOfferMatchesGoldenVector) {
  namespace vectors = heyaki::test_vectors;
  const auto offer = golden_offer();
  const auto canonical = heyaki::canonical_signed_offer(offer);
  ASSERT_TRUE(canonical.has_value());
  EXPECT_EQ(*canonical.value_if(), bytes_from_hex(std::string_view{vectors::canonical_hex}));
}

TEST(M4SignalingProtocol, GoldenOfferSignatureVerifies) {
  namespace vectors = heyaki::test_vectors;
  auto offer = golden_offer();
  const auto public_key = bytes_from_hex(std::string_view{vectors::ed25519_public_key_hex});
  const auto signature = bytes_from_hex(std::string_view{vectors::ed25519_signature_hex});
  std::memcpy(offer.signature.data(), signature.data(), offer.signature.size());
  const auto verified = heyaki::verify_signed_offer(
      offer, public_key, offer.binding.expires_unix_milliseconds);
  EXPECT_TRUE(verified.has_value());

  auto flipped = offer;
  flipped.signature[0] ^= std::byte{1U};
  const auto rejected = heyaki::verify_signed_offer(
      flipped, public_key, flipped.binding.expires_unix_milliseconds);
  ASSERT_FALSE(rejected.has_value());
  EXPECT_EQ(rejected.error_if()->code(), heyaki::ErrorCode::authentication);
}

TEST(M4SignalingProtocol, CanonicalAnswerAndTranscriptMatchGoldenVector) {
  namespace vectors = heyaki::test_vectors;
  const auto answer = golden_answer();
  const auto canonical = heyaki::canonical_signed_answer(answer);
  ASSERT_TRUE(canonical.has_value());
  EXPECT_EQ(*canonical.value_if(),
            bytes_from_hex(std::string_view{vectors::canonical_answer_hex}));

  const auto offer_canonical = bytes_from_hex(std::string_view{vectors::canonical_hex});
  const auto transcript =
      heyaki::hash_signaling_transcript(offer_canonical, *canonical.value_if());
  ASSERT_TRUE(transcript.has_value());
  const auto expected =
      bytes_from_hex(std::string_view{vectors::signaling_transcript_sha256_hex});
  EXPECT_EQ(0, std::memcmp(transcript.value_if()->data(), expected.data(), expected.size()));
}

TEST(M4SignalingProtocol, OfferAnswerCandidateRoundTrip) {
  auto identity = heyaki::create_identity();
  ASSERT_TRUE(identity.has_value());

  auto offer = golden_offer();
  offer.binding.initiator = {identity.value_if()->device_id(),
                             id_from_hex<heyaki::EndpointId>("00112233445566778899aabbccddeeff")};
  ASSERT_TRUE(heyaki::sign_signed_offer(offer, *identity.value_if()).has_value());
  const auto encoded_offer = heyaki::encode_signed_offer(offer);
  ASSERT_TRUE(encoded_offer.has_value());
  const auto parsed_offer = heyaki::parse_signed_offer(*encoded_offer.value_if());
  ASSERT_TRUE(parsed_offer.has_value());
  EXPECT_EQ(parsed_offer.value_if()->binding, offer.binding);
  EXPECT_EQ(parsed_offer.value_if()->sdp, offer.sdp);
  EXPECT_EQ(parsed_offer.value_if()->signature, offer.signature);

  auto answer = golden_answer();
  answer.binding.initiator = offer.binding.initiator;
  answer.binding.responder.device_id = identity.value_if()->device_id();
  ASSERT_TRUE(heyaki::sign_signed_answer(answer, *identity.value_if()).has_value());
  const auto encoded_answer = heyaki::encode_signed_answer(answer);
  ASSERT_TRUE(encoded_answer.has_value());
  const auto parsed_answer = heyaki::parse_signed_answer(*encoded_answer.value_if());
  ASSERT_TRUE(parsed_answer.has_value());
  EXPECT_EQ(parsed_answer.value_if()->binding, answer.binding);

  heyaki::SignedCandidate candidate;
  candidate.binding = answer.binding;
  candidate.sequence = 1U;
  candidate.candidate = bytes_from_hex("616e6469646174653a31");
  const auto transcript = heyaki::hash_signaling_transcript(
      *heyaki::canonical_signed_offer(offer).value_if(),
      *heyaki::canonical_signed_answer(answer).value_if());
  ASSERT_TRUE(transcript.has_value());
  candidate.signaling_transcript_sha256 = *transcript.value_if();
  candidate.owner_ice_ufrag = "8hKa";
  candidate.owner_dtls_fingerprint = answer.dtls_fingerprint;
  ASSERT_TRUE(heyaki::sign_signed_candidate(candidate, *identity.value_if()).has_value());
  const auto encoded_candidate = heyaki::encode_signed_candidate(candidate);
  ASSERT_TRUE(encoded_candidate.has_value());
  const auto parsed_candidate =
      heyaki::parse_signed_candidate(*encoded_candidate.value_if());
  ASSERT_TRUE(parsed_candidate.has_value());
  EXPECT_EQ(parsed_candidate.value_if()->binding, candidate.binding);
  EXPECT_EQ(parsed_candidate.value_if()->owner_ice_ufrag, candidate.owner_ice_ufrag);
  EXPECT_EQ(parsed_candidate.value_if()->sequence, candidate.sequence);
}

TEST(M4SignalingProtocol, ParserRejectsMalformedInput) {
  auto identity = heyaki::create_identity();
  ASSERT_TRUE(identity.has_value());
  auto offer = golden_offer();
  offer.binding.initiator.device_id = identity.value_if()->device_id();
  ASSERT_TRUE(heyaki::sign_signed_offer(offer, *identity.value_if()).has_value());
  const auto encoded = *heyaki::encode_signed_offer(offer).value_if();

  // Truncated buffer.
  EXPECT_FALSE(
      heyaki::parse_signed_offer(std::span{encoded.data(), encoded.size() - 1U}).has_value());
  // Trailing unknown field.
  auto unknown = encoded;
  unknown.push_back(std::byte{0xfa});
  unknown.push_back(std::byte{0x06});
  unknown.push_back(std::byte{1U});
  unknown.push_back(std::byte{0x00});
  EXPECT_FALSE(heyaki::parse_signed_offer(unknown).has_value());
  // Duplicated top-level field bytes.
  auto duplicated = encoded;
  const auto tail = std::vector<std::byte>{encoded.end() - 70U, encoded.end()};
  duplicated.insert(duplicated.end(), tail.begin(), tail.end());
  EXPECT_FALSE(heyaki::parse_signed_offer(duplicated).has_value());
  // Non-canonical varint for the binding expiry.
  std::vector<std::byte> malformed_binding;
  malformed_binding.push_back(std::byte{(6U << 3U) | 0U});
  malformed_binding.push_back(std::byte{0x80U});
  malformed_binding.push_back(std::byte{0x00U});
  std::vector<std::byte> malformed;
  const auto append_bytes_field = [&malformed](std::uint32_t field,
                                               std::span<const std::byte> value) {
    malformed.push_back(static_cast<std::byte>((field << 3U) | 2U));
    malformed.insert(malformed.end(), value.begin(), value.end());
  };
  append_bytes_field(1U, malformed_binding);
  append_bytes_field(2U, offer.sdp);
  append_bytes_field(3U, {offer.dtls_fingerprint.data(), offer.dtls_fingerprint.size()});
  EXPECT_FALSE(heyaki::parse_signed_offer(malformed).has_value());
  // Empty SDP is structurally invalid even when parseable.
  auto empty_sdp = offer;
  empty_sdp.sdp.clear();
  EXPECT_FALSE(heyaki::validate_signed_offer(empty_sdp).has_value());
}

TEST(M4SignalingProtocol, OfferRejectsResponderNonceAndAnswerRequiresIt) {
  const auto answer = golden_answer();
  const auto encoded_answer = heyaki::encode_signed_answer(answer);
  ASSERT_TRUE(encoded_answer.has_value());
  // The answer binding carries field 7; parsing those bytes as an offer must fail.
  EXPECT_FALSE(heyaki::parse_signed_offer(*encoded_answer.value_if()).has_value());

  auto missing_nonce = golden_answer();
  missing_nonce.binding.responder_nonce.reset();
  EXPECT_FALSE(heyaki::validate_signed_answer(missing_nonce).has_value());
}

TEST(M4SignalingProtocol, ExpiryWindowEnforced) {
  auto identity = heyaki::create_identity();
  ASSERT_TRUE(identity.has_value());
  const std::uint64_t now = 1'700'000'000'000ULL;
  const auto make_offer = [&](std::uint64_t expiry) {
    auto offer = golden_offer();
    offer.binding.initiator.device_id = identity.value_if()->device_id();
    offer.binding.expires_unix_milliseconds = expiry;
    (void)heyaki::sign_signed_offer(offer, *identity.value_if());
    return offer;
  };
  const auto public_key = std::vector<std::byte>{
      identity.value_if()->public_key().begin(), identity.value_if()->public_key().end()};
  EXPECT_TRUE(heyaki::verify_signed_offer(make_offer(now + 5U * 60U * 1000U), public_key,
                                          now)
                  .has_value());
  EXPECT_FALSE(heyaki::verify_signed_offer(make_offer(now + 5U * 60U * 1000U + 1U),
                                           public_key, now)
                   .has_value());
  EXPECT_TRUE(
      heyaki::verify_signed_offer(make_offer(now - 30U * 1000U), public_key, now).has_value());
  EXPECT_FALSE(
      heyaki::verify_signed_offer(make_offer(now - 30U * 1000U - 1U), public_key, now)
          .has_value());
}

TEST(M4SignalingProtocol, SdpUfragParser) {
  EXPECT_EQ(*heyaki::parse_sdp_ice_ufrag(sdp_bytes(kSdpA)).value_if(), "8hKaFrag");
  EXPECT_FALSE(heyaki::parse_sdp_ice_ufrag(sdp_bytes("v=0\r\ns=-\r\n")).has_value());
  EXPECT_FALSE(heyaki::parse_sdp_ice_ufrag(sdp_bytes("a=ice-ufrag:ab\r\n")).has_value());
}

TEST(M4ReplayCache, AdmitsDuplicatesCapacityAndTtl) {
  heyaki::ReplayCachePolicy policy;
  policy.ttl_milliseconds = 600'000U;
  policy.capacity = 64U;
  policy.per_peer_capacity = 16U;
  auto cache = heyaki::SignalingReplayCache::create(policy);
  ASSERT_TRUE(cache.has_value());
  const auto t0 = std::chrono::steady_clock::time_point{} + std::chrono::seconds{5};
  const auto signer = id_from_hex<heyaki::DeviceId>(
      "aafe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9");
  const auto other = id_from_hex<heyaki::DeviceId>(
      "bbfe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9");
  const auto request =
      id_from_hex<heyaki::RequestId>("102132435465768798a9bacbdcedfe0f");
  const auto session =
      id_from_hex<heyaki::SessionId>("112233445566778899aabbccddeeff00");
  const auto nonce = nonce_from_hex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

  EXPECT_EQ(*cache.value_if()
                 ->admit(heyaki::SigningDomain::offer, signer, request, session, nonce,
                         std::nullopt, std::nullopt, t0)
                 .value_if(),
            heyaki::SignalingReplayDecision::admitted);
  EXPECT_EQ(*cache.value_if()
                 ->admit(heyaki::SigningDomain::offer, signer, request, session, nonce,
                         std::nullopt, std::nullopt, t0)
                 .value_if(),
            heyaki::SignalingReplayDecision::duplicate);
  EXPECT_EQ(*cache.value_if()
                 ->admit(heyaki::SigningDomain::answer, signer, request, session, nonce,
                         std::nullopt, std::nullopt, t0)
                 .value_if(),
            heyaki::SignalingReplayDecision::admitted);
  // Fill the signer's per-peer budget of 16 with distinct request IDs.
  for (std::uint32_t index = 0U; index < 14U; ++index) {
    auto fill_storage = request.bytes();
    fill_storage[0] = static_cast<std::byte>(index + 1U);
    const auto fill_request = heyaki::RequestId{fill_storage};
    EXPECT_EQ(*cache.value_if()
                   ->admit(heyaki::SigningDomain::offer, signer, fill_request, session,
                           nonce, std::nullopt, std::nullopt, t0)
                   .value_if(),
              heyaki::SignalingReplayDecision::admitted);
  }
  // The per-peer budget is now saturated for this signer.
  EXPECT_EQ(*cache.value_if()
                 ->admit(heyaki::SigningDomain::candidate, signer, request, session, nonce,
                         std::nullopt, 1U, t0)
                 .value_if(),
            heyaki::SignalingReplayDecision::capacity_rejected);
  // A different signer is still admitted.
  EXPECT_EQ(*cache.value_if()
                 ->admit(heyaki::SigningDomain::offer, other, request, session, nonce,
                         std::nullopt, std::nullopt, t0)
                 .value_if(),
            heyaki::SignalingReplayDecision::admitted);

  const auto diagnostics = cache.value_if()->diagnostics();
  EXPECT_EQ(diagnostics.duplicates_rejected, 1U);
  EXPECT_EQ(diagnostics.capacity_rejected, 1U);
  EXPECT_EQ(diagnostics.per_peer_rejected, 1U);
  EXPECT_EQ(diagnostics.current_entries, 17U);
  EXPECT_EQ(diagnostics.peak_entries, 17U);

  // After the TTL passes, the same key is admitted again.
  const auto later = t0 + std::chrono::milliseconds{600'001U};
  cache.value_if()->expire(later);
  EXPECT_EQ(*cache.value_if()
                 ->admit(heyaki::SigningDomain::offer, signer, request, session, nonce,
                         std::nullopt, std::nullopt, later)
                 .value_if(),
            heyaki::SignalingReplayDecision::admitted);
}

struct PeerHarness {
  std::optional<heyaki::IdentityKeyPair> identity;
  heyaki::DeviceEndpointKey self;
  std::optional<heyaki::SignalingCoordinator> coordinator;
  std::shared_ptr<heyaki::SignalingDelegate> delegate =
      std::make_shared<heyaki::SignalingDelegate>();
  std::vector<std::string> events;

  bool init(std::byte endpoint_seed, heyaki::SignalingCoordinatorConfig config) {
    auto created = heyaki::create_identity();
    if (!created.has_value()) {
      return false;
    }
    identity = std::move(*created.value_if());
    self.device_id = identity->device_id();
    heyaki::EndpointId::Storage endpoint{};
    endpoint[0] = endpoint_seed;
    self.endpoint_id = heyaki::EndpointId{endpoint};
    config.local = self;
    config.identity = &*identity;
    auto created_coordinator = heyaki::SignalingCoordinator::create(config, delegate);
    if (!created_coordinator.has_value()) {
      return false;
    }
    coordinator = std::move(*created_coordinator.value_if());
    return true;
  }
};

constexpr auto kSteadyNow =
    std::chrono::steady_clock::time_point{} + std::chrono::seconds{100};
constexpr std::uint64_t kNowUnix = 1'700'000'000'000ULL;

heyaki::SignalingCoordinatorConfig default_config() {
  heyaki::SignalingCoordinatorConfig config;
  config.attempt_ttl = std::chrono::milliseconds{15000};
  return config;
}

// Wires initiator A and responder B over recording routes without automatic forwarding, so
// individual envelopes can be inspected and tampered with before manual delivery.
struct ManualFlow {
  PeerHarness a;
  PeerHarness b;
  heyaki::test::FakeSignalingRoute route_a{heyaki::SignalingRouteKind::lan};
  heyaki::test::FakeSignalingRoute route_b{heyaki::SignalingRouteKind::lan};
  std::optional<heyaki::SignalBinding> a_answer_binding;

  bool init() {
    if (!a.init(std::byte{1U}, default_config()) || !b.init(std::byte{2U}, default_config())) {
      return false;
    }
    a.coordinator->attach_route(&route_a);
    b.coordinator->attach_route(&route_b);
    a.delegate->peer_identity = [&](const heyaki::DeviceEndpointKey& key)
        -> std::optional<heyaki::IdentityPublicKey> {
      return key == b.self ? std::optional{b.identity->public_key()} : std::nullopt;
    };
    b.delegate->peer_identity = [&](const heyaki::DeviceEndpointKey& key)
        -> std::optional<heyaki::IdentityPublicKey> {
      return key == a.self ? std::optional{a.identity->public_key()} : std::nullopt;
    };
    return true;
  }

  // Runs connect_request -> (accepted) -> connect_accept manually and returns the request.
  heyaki::RequestId connect_accepted() {
    auto accepted = false;
    b.delegate->on_inbound_connect = [&](const heyaki::SignalingAttemptSnapshot&) {
      accepted = true;
      return true;
    };
    const auto request = a.coordinator->begin_attempt(
        b.self, heyaki::SignalingRouteKind::lan, kSteadyNow);
    EXPECT_TRUE(request.has_value());
    const auto connect =
        route_a.last_of(heyaki::LanSignalingMessageKind::connect_request);
    EXPECT_TRUE(connect.has_value());
    auto inbound_connect = *connect;
    inbound_connect.peer = a.self;
    EXPECT_TRUE(b.coordinator
                    ->handle_message(inbound_connect, heyaki::SignalingRouteKind::lan,
                                     kSteadyNow, kNowUnix)
                    .has_value());
    EXPECT_TRUE(accepted);
    heyaki::SignalingEnvelope accept;
    accept.peer = b.self;
    accept.kind = heyaki::LanSignalingMessageKind::connect_accept;
    accept.request_id = connect->request_id;
    EXPECT_TRUE(a.coordinator
                    ->handle_message(accept, heyaki::SignalingRouteKind::lan, kSteadyNow,
                                     kNowUnix)
                    .has_value());
    return *request.value_if();
  }

  // Delivers the recorded offer/answer envelopes across both sides and reports the
  // transcript observed by the initiator.
  heyaki::SignalingTranscriptSha256 exchange_offer_answer(
      const heyaki::RequestId& request, const heyaki::DtlsFingerprint& fingerprint_a,
      const heyaki::DtlsFingerprint& fingerprint_b) {
    std::optional<heyaki::SignalingTranscriptSha256> transcript;
    a.delegate->on_verified_answer =
        [&](const heyaki::SignalingAttemptSnapshot&, const heyaki::SignedAnswer& answer,
            const heyaki::SignalingTranscriptSha256& value) {
          transcript = value;
          a_answer_binding = answer.binding;
        };
    EXPECT_TRUE(a.coordinator
                    ->send_local_offer(request, sdp_bytes(kSdpA), fingerprint_a, kSteadyNow,
                                       kNowUnix)
                    .has_value());
    const auto offer_envelope =
        route_a.last_of(heyaki::LanSignalingMessageKind::signed_offer);
    EXPECT_TRUE(offer_envelope.has_value());
    auto inbound_offer = *offer_envelope;
    inbound_offer.peer = a.self;
    EXPECT_TRUE(b.coordinator
                    ->handle_message(inbound_offer, heyaki::SignalingRouteKind::lan,
                                     kSteadyNow, kNowUnix)
                    .has_value());
    EXPECT_TRUE(b.coordinator
                    ->send_local_answer(request, sdp_bytes(kSdpB), fingerprint_b, kSteadyNow,
                                        kNowUnix)
                    .has_value());
    const auto answer_envelope =
        route_b.last_of(heyaki::LanSignalingMessageKind::signed_answer);
    EXPECT_TRUE(answer_envelope.has_value());
    auto inbound_answer = *answer_envelope;
    inbound_answer.peer = b.self;
    EXPECT_TRUE(a.coordinator
                    ->handle_message(inbound_answer, heyaki::SignalingRouteKind::lan,
                                     kSteadyNow, kNowUnix)
                    .has_value());
    EXPECT_TRUE(transcript.has_value());
    return *transcript;
  }
};

TEST(M4Coordinator, VerifiedHandshakeAndTrickleFlow) {
  ManualFlow flow;
  ASSERT_TRUE(flow.init());

  bool transport_opened_on_b = false;
  std::vector<std::uint32_t> b_candidates;
  std::vector<std::uint32_t> a_candidates;
  flow.b.delegate->on_verified_offer = [&](const heyaki::SignalingAttemptSnapshot&,
                                          const heyaki::SignedOffer& offer) {
    flow.b.events.push_back("verified_offer");
    // M4-05: the session layer may only open the transport with verified SDP.
    EXPECT_EQ(offer.sdp, sdp_bytes(kSdpA));
    transport_opened_on_b = true;
  };
  flow.b.delegate->on_verified_candidate = [&](const heyaki::SignalingAttemptSnapshot&,
                                              const heyaki::SignedCandidate& candidate) {
    b_candidates.push_back(candidate.sequence);
  };
  flow.a.delegate->on_verified_candidate = [&](const heyaki::SignalingAttemptSnapshot&,
                                              const heyaki::SignedCandidate& candidate) {
    a_candidates.push_back(candidate.sequence);
  };

  const auto request = flow.connect_accepted();
  auto premature_binding = flow.a.coordinator->verified_session_binding(request, 3U);
  ASSERT_FALSE(premature_binding);
  EXPECT_EQ(premature_binding.error_if()->safe_detail(), "session_binding_not_ready");
  const auto transcript =
      flow.exchange_offer_answer(request, test_fingerprint(0x10U), test_fingerprint(0x70U));
  EXPECT_TRUE(transport_opened_on_b);
  EXPECT_NE(transcript, heyaki::SignalingTranscriptSha256{});
  auto binding = flow.a.coordinator->verified_session_binding(request, 3U);
  ASSERT_TRUE(binding);
  EXPECT_EQ(binding.value_if()->expectation.sender, flow.b.self);
  EXPECT_EQ(binding.value_if()->expectation.peer, flow.a.self);
  EXPECT_TRUE(binding.value_if()->initiator);
  EXPECT_EQ(binding.value_if()->expectation.session_epoch, 3U);
  EXPECT_EQ(binding.value_if()->expectation.signaling_transcript_sha256, transcript);
  EXPECT_EQ(binding.value_if()->peer_fingerprint, test_fingerprint(0x70U));

  EXPECT_TRUE(flow.a.coordinator
                  ->send_local_candidate(request, bytes_from_hex("01000000"), kSteadyNow,
                                         kNowUnix)
                  .has_value());
  const auto candidate_envelope =
      flow.route_a.last_of(heyaki::LanSignalingMessageKind::signed_candidate);
  ASSERT_TRUE(candidate_envelope.has_value());
  auto inbound_candidate = *candidate_envelope;
  inbound_candidate.peer = flow.a.self;
  EXPECT_TRUE(flow.b.coordinator
                  ->handle_message(inbound_candidate, heyaki::SignalingRouteKind::lan,
                                   kSteadyNow, kNowUnix)
                  .has_value());
  EXPECT_EQ(b_candidates, (std::vector<std::uint32_t>{1U}));

  EXPECT_TRUE(flow.b.coordinator
                  ->send_local_candidate(request, bytes_from_hex("02000000"), kSteadyNow,
                                         kNowUnix)
                  .has_value());
  const auto peer_candidate_envelope =
      flow.route_b.last_of(heyaki::LanSignalingMessageKind::signed_candidate);
  ASSERT_TRUE(peer_candidate_envelope.has_value());
  auto inbound_peer_candidate = *peer_candidate_envelope;
  inbound_peer_candidate.peer = flow.b.self;
  EXPECT_TRUE(flow.a.coordinator
                  ->handle_message(inbound_peer_candidate,
                                   heyaki::SignalingRouteKind::lan, kSteadyNow, kNowUnix)
                  .has_value());
  EXPECT_EQ(a_candidates, (std::vector<std::uint32_t>{1U}));

  const auto attempts_a = flow.a.coordinator->attempts();
  ASSERT_EQ(attempts_a.size(), 1U);
  EXPECT_EQ(attempts_a[0].phase, heyaki::SignalingAttemptPhase::candidates);
  EXPECT_FALSE(attempts_a[0].session_id.is_zero());
  const auto attempts_b = flow.b.coordinator->attempts();
  ASSERT_EQ(attempts_b.size(), 1U);
  EXPECT_EQ(attempts_b[0].phase, heyaki::SignalingAttemptPhase::candidates);
  EXPECT_EQ(attempts_b[0].session_id, attempts_a[0].session_id);
  EXPECT_EQ(attempts_b[0].route, heyaki::SignalingRouteKind::lan);
}

TEST(M4Coordinator, TamperedOfferNeverReachesSession) {
  ManualFlow flow;
  ASSERT_TRUE(flow.init());
  bool verified = false;
  flow.b.delegate->on_verified_offer = [&](const heyaki::SignalingAttemptSnapshot&,
                                          const heyaki::SignedOffer&) {
    verified = true;
  };

  const auto request = flow.connect_accepted();
  ASSERT_TRUE(flow.a.coordinator
                  ->send_local_offer(request, sdp_bytes(kSdpA), test_fingerprint(0x10U),
                                     kSteadyNow, kNowUnix)
                  .has_value());
  auto envelope = *flow.route_a.last_of(heyaki::LanSignalingMessageKind::signed_offer);
  envelope.peer = flow.a.self;
  envelope.payload[envelope.payload.size() - 1U] ^= std::byte{1U};
  const auto rejected = flow.b.coordinator->handle_message(
      envelope, heyaki::SignalingRouteKind::lan, kSteadyNow, kNowUnix);
  ASSERT_FALSE(rejected.has_value());
  EXPECT_FALSE(verified);
  EXPECT_GE(flow.b.coordinator->diagnostics().signature_rejected, 1U);
  // The tampered delivery did not consume the pending inbound attempt.
  ASSERT_EQ(flow.b.coordinator->attempts().size(), 1U);
  EXPECT_EQ(flow.b.coordinator->attempts()[0].phase,
            heyaki::SignalingAttemptPhase::responding);
}

TEST(M4Coordinator, DuplicateOfferDeliveryIsRejected) {
  ManualFlow flow;
  ASSERT_TRUE(flow.init());
  int verified_count = 0;
  flow.b.delegate->on_verified_offer = [&](const heyaki::SignalingAttemptSnapshot&,
                                          const heyaki::SignedOffer&) {
    ++verified_count;
  };

  const auto request = flow.connect_accepted();
  ASSERT_TRUE(flow.a.coordinator
                  ->send_local_offer(request, sdp_bytes(kSdpA), test_fingerprint(0x10U),
                                     kSteadyNow, kNowUnix)
                  .has_value());
  auto envelope = *flow.route_a.last_of(heyaki::LanSignalingMessageKind::signed_offer);
  envelope.peer = flow.a.self;
  EXPECT_TRUE(flow.b.coordinator
                  ->handle_message(envelope, heyaki::SignalingRouteKind::lan, kSteadyNow,
                                   kNowUnix)
                  .has_value());
  const auto replay = flow.b.coordinator->handle_message(
      envelope, heyaki::SignalingRouteKind::lan, kSteadyNow, kNowUnix);
  EXPECT_FALSE(replay.has_value());
  EXPECT_EQ(verified_count, 1);
}

TEST(M4Coordinator, CandidateBindingViolationsRejected) {
  ManualFlow flow;
  ASSERT_TRUE(flow.init());
  std::optional<heyaki::SignedOffer> verified_offer;
  std::vector<std::uint32_t> delivered;
  flow.b.delegate->on_verified_offer = [&](const heyaki::SignalingAttemptSnapshot&,
                                          const heyaki::SignedOffer& offer) {
    verified_offer = offer;
  };
  flow.b.delegate->on_verified_candidate = [&](const heyaki::SignalingAttemptSnapshot&,
                                              const heyaki::SignedCandidate& candidate) {
    delivered.push_back(candidate.sequence);
  };

  const auto request = flow.connect_accepted();
  const auto transcript =
      flow.exchange_offer_answer(request, test_fingerprint(0x10U), test_fingerprint(0x70U));
  ASSERT_TRUE(flow.a_answer_binding.has_value());
  ASSERT_TRUE(flow.a.coordinator
                  ->send_local_candidate(request, bytes_from_hex("01020304"), kSteadyNow,
                                         kNowUnix)
                  .has_value());
  auto good = *flow.route_a.last_of(heyaki::LanSignalingMessageKind::signed_candidate);
  good.peer = flow.a.self;
  EXPECT_TRUE(flow.b.coordinator
                  ->handle_message(good, heyaki::SignalingRouteKind::lan, kSteadyNow,
                                   kNowUnix)
                  .has_value());
  ASSERT_EQ(delivered, (std::vector<std::uint32_t>{1U}));

  // Byte-identical replay is idempotent and not re-delivered.
  EXPECT_TRUE(flow.b.coordinator
                  ->handle_message(good, heyaki::SignalingRouteKind::lan, kSteadyNow,
                                   kNowUnix)
                  .has_value());
  ASSERT_EQ(delivered, (std::vector<std::uint32_t>{1U}));

  // Forge candidates with the verified binding recorded from the handshake.
  auto make_candidate = [&](std::uint32_t sequence,
                            const heyaki::SignalingTranscriptSha256& candidate_transcript,
                            std::string_view ufrag) {
    heyaki::SignedCandidate forged;
    forged.binding = verified_offer->binding;
    forged.binding.responder_nonce = flow.a_answer_binding->responder_nonce;
    forged.binding.expires_unix_milliseconds = kNowUnix + 30'000U;
    forged.sequence = sequence;
    forged.candidate = bytes_from_hex("deadbeef");
    forged.signaling_transcript_sha256 = candidate_transcript;
    forged.owner_ice_ufrag = std::string{ufrag};
    forged.owner_dtls_fingerprint = verified_offer->dtls_fingerprint;
    (void)heyaki::sign_signed_candidate(forged, *flow.a.identity);
    return forged;
  };

  // Re-used sequence with different bytes is rejected.
  auto forged_envelope = good;
  forged_envelope.payload =
      *heyaki::encode_signed_candidate(make_candidate(1U, transcript, "8hKaFrag"))
           .value_if();
  EXPECT_FALSE(flow.b.coordinator
                   ->handle_message(forged_envelope, heyaki::SignalingRouteKind::lan,
                                    kSteadyNow, kNowUnix)
                   .has_value());
  EXPECT_EQ(delivered, (std::vector<std::uint32_t>{1U}));

  // Wrong transcript hash is rejected.
  auto wrong_transcript = transcript;
  wrong_transcript[0] ^= std::byte{1U};
  forged_envelope.payload =
      *heyaki::encode_signed_candidate(make_candidate(2U, wrong_transcript, "8hKaFrag"))
           .value_if();
  EXPECT_FALSE(flow.b.coordinator
                   ->handle_message(forged_envelope, heyaki::SignalingRouteKind::lan,
                                    kSteadyNow, kNowUnix)
                   .has_value());
  EXPECT_EQ(delivered, (std::vector<std::uint32_t>{1U}));

  // Wrong owner ufrag is rejected.
  forged_envelope.payload =
      *heyaki::encode_signed_candidate(make_candidate(2U, transcript, "NopeUfrag"))
           .value_if();
  EXPECT_FALSE(flow.b.coordinator
                   ->handle_message(forged_envelope, heyaki::SignalingRouteKind::lan,
                                    kSteadyNow, kNowUnix)
                   .has_value());
  EXPECT_EQ(delivered, (std::vector<std::uint32_t>{1U}));
  EXPECT_GE(flow.b.coordinator->diagnostics().binding_rejected, 1U);
}

TEST(M4Coordinator, UnknownPeerIdentityRejected) {
  ManualFlow flow;
  ASSERT_TRUE(flow.init());
  // The responder resolves no identities.
  flow.b.delegate->peer_identity = nullptr;
  bool verified = false;
  flow.b.delegate->on_verified_offer = [&](const heyaki::SignalingAttemptSnapshot&,
                                          const heyaki::SignedOffer&) {
    verified = true;
  };

  const auto request = flow.connect_accepted();
  ASSERT_TRUE(flow.a.coordinator
                  ->send_local_offer(request, sdp_bytes(kSdpA), test_fingerprint(0x10U),
                                     kSteadyNow, kNowUnix)
                  .has_value());
  auto unknown_envelope = *flow.route_a.last_of(
      heyaki::LanSignalingMessageKind::signed_offer);
  unknown_envelope.peer = flow.a.self;
  const auto rejected = flow.b.coordinator->handle_message(
      unknown_envelope, heyaki::SignalingRouteKind::lan, kSteadyNow, kNowUnix);
  ASSERT_FALSE(rejected.has_value());
  EXPECT_EQ(rejected.error_if()->code(), heyaki::ErrorCode::authentication);
  EXPECT_FALSE(verified);
}

TEST(M4Coordinator, InboundDeniedSendsConnectDeny) {
  ManualFlow flow;
  ASSERT_TRUE(flow.init());
  flow.b.delegate->on_inbound_connect = [&](const heyaki::SignalingAttemptSnapshot&) {
    return false;
  };
  const auto request = flow.a.coordinator->begin_attempt(
      flow.b.self, heyaki::SignalingRouteKind::lan, kSteadyNow);
  ASSERT_TRUE(request.has_value());
  const auto connect = flow.route_a.last_of(heyaki::LanSignalingMessageKind::connect_request);
  ASSERT_TRUE(connect.has_value());
  auto inbound_connect = *connect;
  inbound_connect.peer = flow.a.self;
  const auto denied = flow.b.coordinator->handle_message(
      inbound_connect, heyaki::SignalingRouteKind::lan, kSteadyNow, kNowUnix);
  ASSERT_FALSE(denied.has_value());
  EXPECT_EQ(denied.error_if()->code(), heyaki::ErrorCode::permission);
  const auto deny = flow.route_b.last_of(heyaki::LanSignalingMessageKind::connect_deny);
  ASSERT_TRUE(deny.has_value());
  EXPECT_EQ(deny->request_id, *request.value_if());
  EXPECT_TRUE(flow.b.coordinator->attempts().empty());
}

TEST(M4Coordinator, ConnectDenyClosesOutboundAttempt) {
  ManualFlow flow;
  ASSERT_TRUE(flow.init());
  const auto request = flow.a.coordinator->begin_attempt(
      flow.b.self, heyaki::SignalingRouteKind::lan, kSteadyNow);
  ASSERT_TRUE(request.has_value());
  heyaki::SignalingEnvelope deny;
  deny.peer = flow.b.self;
  deny.kind = heyaki::LanSignalingMessageKind::connect_deny;
  deny.request_id = *request.value_if();
  int errors = 0;
  flow.a.delegate->on_attempt_error = [&](const heyaki::SignalingAttemptSnapshot&,
                                         const heyaki::Error& error) {
    ++errors;
    EXPECT_EQ(error.code(), heyaki::ErrorCode::remote_error);
  };
  EXPECT_TRUE(flow.a.coordinator
                  ->handle_message(deny, heyaki::SignalingRouteKind::lan, kSteadyNow,
                                   kNowUnix)
                  .has_value());
  EXPECT_EQ(errors, 1);
  EXPECT_TRUE(flow.a.coordinator->attempts().empty());
  const auto offer_after_deny = flow.a.coordinator->send_local_offer(
      *request.value_if(), sdp_bytes(kSdpA), test_fingerprint(0x10U), kSteadyNow, kNowUnix);
  EXPECT_FALSE(offer_after_deny.has_value());
}

TEST(M4Coordinator, BoundsTtlAndRateLimits) {
  PeerHarness a;
  auto config = default_config();
  config.max_pending_attempts = 2U;
  config.max_inbound_attempts = 1U;
  config.inbound_rate_limit = 64U;
  config.attempt_ttl = std::chrono::milliseconds{1000};
  ASSERT_TRUE(a.init(std::byte{1U}, config));
  heyaki::test::FakeSignalingRoute route_a{heyaki::SignalingRouteKind::lan};
  a.coordinator->attach_route(&route_a);

  PeerHarness b;
  ASSERT_TRUE(b.init(std::byte{2U}, default_config()));
  PeerHarness c;
  ASSERT_TRUE(c.init(std::byte{3U}, default_config()));
  PeerHarness d;
  ASSERT_TRUE(d.init(std::byte{4U}, default_config()));

  EXPECT_TRUE(a.coordinator
                  ->begin_attempt(b.self, heyaki::SignalingRouteKind::lan, kSteadyNow)
                  .has_value());
  // Duplicate active attempt to the same peer is rejected below capacity.
  const auto duplicate = a.coordinator->begin_attempt(
      b.self, heyaki::SignalingRouteKind::lan, kSteadyNow);
  ASSERT_FALSE(duplicate.has_value());
  EXPECT_EQ(duplicate.error_if()->code(), heyaki::ErrorCode::signaling);
  EXPECT_TRUE(a.coordinator
                  ->begin_attempt(c.self, heyaki::SignalingRouteKind::lan, kSteadyNow)
                  .has_value());
  // Outbound capacity of 2 is now exhausted.
  const auto exhausted = a.coordinator->begin_attempt(
      d.self, heyaki::SignalingRouteKind::lan, kSteadyNow);
  ASSERT_FALSE(exhausted.has_value());
  EXPECT_EQ(exhausted.error_if()->code(), heyaki::ErrorCode::resource_exhausted);
  EXPECT_GE(a.coordinator->diagnostics().outbound_capacity_rejected, 1U);

  // Inbound capacity: the first connect_request is accepted, the second rejected.
  a.delegate->on_inbound_connect = [&](const heyaki::SignalingAttemptSnapshot&) {
    return true;
  };
  heyaki::SignalingEnvelope inbound;
  inbound.peer = d.self;
  inbound.kind = heyaki::LanSignalingMessageKind::connect_request;
  inbound.request_id = id_from_hex<heyaki::RequestId>("00000000000000000000000000000001");
  EXPECT_TRUE(a.coordinator
                  ->handle_message(inbound, heyaki::SignalingRouteKind::lan, kSteadyNow,
                                   kNowUnix)
                  .has_value());
  inbound.request_id = id_from_hex<heyaki::RequestId>("00000000000000000000000000000002");
  const auto inbound_rejected = a.coordinator->handle_message(
      inbound, heyaki::SignalingRouteKind::lan, kSteadyNow, kNowUnix);
  ASSERT_FALSE(inbound_rejected.has_value());
  EXPECT_EQ(inbound_rejected.error_if()->code(), heyaki::ErrorCode::resource_exhausted);
  EXPECT_GE(a.coordinator->diagnostics().inbound_capacity_rejected, 1U);

  // Duplicate active request ID is rejected as a replayed connect.
  inbound.request_id = id_from_hex<heyaki::RequestId>("00000000000000000000000000000001");
  const auto duplicate_request = a.coordinator->handle_message(
      inbound, heyaki::SignalingRouteKind::lan, kSteadyNow, kNowUnix);
  EXPECT_FALSE(duplicate_request.has_value());
  EXPECT_GE(a.coordinator->diagnostics().duplicate_request_rejected, 1U);

  // TTL expiry moves attempts to a terminal state and clears the table.
  int expired_errors = 0;
  a.delegate->on_attempt_error = [&](const heyaki::SignalingAttemptSnapshot& snapshot,
                                    const heyaki::Error& error) {
    if (error.code() == heyaki::ErrorCode::timeout) {
      ++expired_errors;
      const auto cancelled = a.coordinator->cancel_attempt(
          snapshot.request_id, kSteadyNow + std::chrono::milliseconds{1001});
      EXPECT_FALSE(cancelled.has_value());
      EXPECT_EQ(cancelled.error_if()->safe_detail(), "attempt_unknown");
    }
  };
  a.coordinator->expire(kSteadyNow + std::chrono::milliseconds{1001});
  EXPECT_EQ(expired_errors, 3);
  EXPECT_TRUE(a.coordinator->attempts().empty());
  EXPECT_EQ(a.coordinator->diagnostics().attempts_expired, 3U);
  // After expiry, the same peer can start a fresh attempt.
  EXPECT_TRUE(a.coordinator
                  ->begin_attempt(b.self, heyaki::SignalingRouteKind::lan,
                                  kSteadyNow + std::chrono::milliseconds{1002})
                  .has_value());

  // Rate limit: flooding messages from one peer beyond the window limit is rejected.
  char padded[33];
  for (int index = 0; index < 70; ++index) {
    std::snprintf(padded, sizeof(padded), "%032d", index);
    inbound.request_id = id_from_hex<heyaki::RequestId>(padded);
    inbound.kind = heyaki::LanSignalingMessageKind::connect_accept;
    (void)a.coordinator->handle_message(inbound, heyaki::SignalingRouteKind::lan,
                                        kSteadyNow, kNowUnix);
  }
  const auto last = a.coordinator->handle_message(
      inbound, heyaki::SignalingRouteKind::lan, kSteadyNow, kNowUnix);
  ASSERT_FALSE(last.has_value());
  EXPECT_EQ(last.error_if()->code(), heyaki::ErrorCode::resource_exhausted);
  EXPECT_GE(a.coordinator->diagnostics().rate_rejected, 1U);

  // Oversized payloads are rejected before parsing.
  heyaki::SignalingEnvelope oversized;
  oversized.peer = d.self;
  oversized.kind = heyaki::LanSignalingMessageKind::signed_offer;
  oversized.request_id = inbound.request_id;
  oversized.payload.assign(65'537U, std::byte{0U});
  const auto oversized_result = a.coordinator->handle_message(
      oversized, heyaki::SignalingRouteKind::lan, kSteadyNow, kNowUnix);
  ASSERT_FALSE(oversized_result.has_value());
  EXPECT_GE(a.coordinator->diagnostics().payload_rejected, 1U);
}

TEST(M4TransportSpi, LoopbackChannelBoundedSendAndClose) {
  heyaki::test::LoopbackTransportPair pair;
  int state_events = 0;
  std::vector<std::string> received;
  pair.right().set_state_handler(
      [&](const heyaki::transport::TransportSessionSnapshot&) { ++state_events; });
  pair.right().set_message_handler(
      [&](heyaki::transport::TransportChannel& channel, std::vector<std::byte> payload) {
        received.emplace_back(reinterpret_cast<const char*>(payload.data()), payload.size());
        EXPECT_EQ(channel.kind(), heyaki::transport::ChannelKind::control);
      });
  pair.connect();
  EXPECT_GT(state_events, 0);

  heyaki::transport::ChannelOptions options;
  options.send_queue_bytes = 32U;
  options.max_message_bytes = 32U;
  heyaki::transport::TransportChannel* left_channel = nullptr;
  pair.left().async_open_channel(
      heyaki::transport::ChannelKind::control, options,
      [&](heyaki::Result<heyaki::transport::TransportChannel*> result) {
        ASSERT_TRUE(result.has_value());
        left_channel = *result.value_if();
      });
  ASSERT_NE(left_channel, nullptr);
  pair.right().async_open_channel(
      heyaki::transport::ChannelKind::control, options,
      [](heyaki::Result<heyaki::transport::TransportChannel*>) {});

  const auto message = std::vector<std::byte>(16U, std::byte{'x'});
  EXPECT_TRUE(left_channel->send(message).has_value());
  EXPECT_TRUE(left_channel->send(message).has_value());
  EXPECT_EQ(left_channel->buffered_amount(), 32U);
  // The third 16-byte message exceeds the byte budget.
  const auto blocked = left_channel->send(message);
  ASSERT_FALSE(blocked.has_value());
  EXPECT_EQ(blocked.error_if()->code(), heyaki::ErrorCode::would_block);
  // Messages above max_message_bytes are rejected outright.
  const auto too_large = left_channel->send(std::vector<std::byte>(33U, std::byte{'y'}));
  ASSERT_FALSE(too_large.has_value());
  EXPECT_EQ(too_large.error_if()->code(), heyaki::ErrorCode::protocol);

  // The peer session pumps the queued messages out, releasing the sender's budget.
  pair.right().pump();
  EXPECT_EQ(received, (std::vector<std::string>{std::string(16U, 'x'),
                                                std::string(16U, 'x')}));
  EXPECT_EQ(left_channel->buffered_amount(), 0U);

  heyaki::transport::PathInfo path;
  path.signaling_path = heyaki::transport::SignalingPathKind::lan;
  path.data_path = heyaki::transport::DataPathKind::direct_host;
  pair.left().set_path(path);
  EXPECT_EQ(pair.left().snapshot().path.data_path,
            heyaki::transport::DataPathKind::direct_host);
  EXPECT_EQ(pair.left().snapshot().path.signaling_path,
            heyaki::transport::SignalingPathKind::lan);

  pair.left().close(heyaki::transport::CloseReason::local_shutdown);
  EXPECT_EQ(pair.left().last_close_reason(),
            heyaki::transport::CloseReason::local_shutdown);
  EXPECT_EQ(pair.left().snapshot().state, heyaki::transport::TransportState::closed);
  const auto after_close = left_channel->send(message);
  ASSERT_FALSE(after_close.has_value());
  EXPECT_EQ(after_close.error_if()->code(), heyaki::ErrorCode::transport);
  EXPECT_EQ(heyaki::transport::close_reason_name(
                heyaki::transport::CloseReason::local_shutdown),
            "local_shutdown");
  EXPECT_EQ(heyaki::transport::data_path_kind_name(
                heyaki::transport::DataPathKind::turn_tls),
            "turn_tls");
  EXPECT_EQ(heyaki::transport::signaling_path_kind_name(
                heyaki::transport::SignalingPathKind::relay),
            "relay");
  EXPECT_EQ(heyaki::transport::transport_state_name(
                heyaki::transport::TransportState::connected),
            "connected");
}

}  // namespace
