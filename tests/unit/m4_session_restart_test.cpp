// M4-10 session-restart admission tests: the restart renegotiation reuses the
// frozen offer/answer/candidate signing domains over the control channel while
// preserving the SessionId and bumping the epoch.
#include <heyaki/identity.hpp>
#include <heyaki/session_restart.hpp>
#include <heyaki/signing.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

template <typename Value>
Value filled(std::uint8_t seed) {
  typename Value::Storage bytes{};
  for (std::size_t index = 0U; index < bytes.size(); ++index) {
    bytes[index] = static_cast<std::byte>(seed + static_cast<std::uint8_t>(index));
  }
  return Value{bytes};
}

template <std::size_t Size>
std::array<std::byte, Size> filled_array(std::uint8_t seed) {
  std::array<std::byte, Size> bytes{};
  for (std::size_t index = 0U; index < bytes.size(); ++index) {
    bytes[index] = static_cast<std::byte>(seed + static_cast<std::uint8_t>(index));
  }
  return bytes;
}

constexpr std::string_view kRestartOfferSdp{
    "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\na=ice-ufrag:8hKaFrag\r\na=ice-pwd:password0"
    "1password01\r\n"};
constexpr std::string_view kRestartAnswerSdp{
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

struct RestartFixture {
  heyaki::IdentityKeyPair initiator_identity;
  heyaki::IdentityKeyPair responder_identity;
  heyaki::SessionRestartContext initiator_context;
  heyaki::SessionRestartContext responder_context;
  heyaki::RequestId request_id{filled<heyaki::RequestId>(0xA1U)};
  heyaki::SessionId session_id{filled<heyaki::SessionId>(0x51U)};
  heyaki::SignalingNonce initiator_nonce{filled_array<heyaki::signaling_nonce_bytes>(0xB1U)};
  heyaki::SignalingNonce responder_nonce{filled_array<heyaki::signaling_nonce_bytes>(0xC1U)};

  static RestartFixture create() {
    auto initiator = heyaki::create_identity();
    auto responder = heyaki::create_identity();
    EXPECT_TRUE(initiator);
    EXPECT_TRUE(responder);
    auto initiator_identity = std::move(*initiator.value_if());
    auto responder_identity = std::move(*responder.value_if());
    const heyaki::DeviceEndpointKey initiator_key{
        initiator_identity.device_id(), filled<heyaki::EndpointId>(0x31U)};
    const heyaki::DeviceEndpointKey responder_key{
        responder_identity.device_id(), filled<heyaki::EndpointId>(0x41U)};
    heyaki::SessionRestartContext initiator_context{
        .local = initiator_key,
        .peer = responder_key,
        .session_id = filled<heyaki::SessionId>(0x51U),
        .current_epoch = 4U,
        .peer_public_key = responder_identity.public_key(),
    };
    heyaki::SessionRestartContext responder_context{
        .local = responder_key,
        .peer = initiator_key,
        .session_id = filled<heyaki::SessionId>(0x51U),
        .current_epoch = 4U,
        .peer_public_key = initiator_identity.public_key(),
    };
    return {std::move(initiator_identity), std::move(responder_identity),
            std::move(initiator_context), std::move(responder_context),
            filled<heyaki::RequestId>(0xA1U), filled<heyaki::SessionId>(0x51U),
            filled_array<heyaki::signaling_nonce_bytes>(0xB1U),
            filled_array<heyaki::signaling_nonce_bytes>(0xC1U)};
  }

  heyaki::SignedOffer offer_shape(
      std::optional<heyaki::RequestId> request = std::nullopt,
      std::optional<heyaki::SessionId> session = std::nullopt) const {
    heyaki::SignedOffer offer;
    offer.binding.initiator = initiator_context.local;
    offer.binding.responder = initiator_context.peer;
    offer.binding.request_id = request.value_or(request_id);
    offer.binding.session_id = session.value_or(session_id);
    offer.binding.initiator_nonce = initiator_nonce;
    offer.binding.expires_unix_milliseconds = 1'030'000U;
    offer.sdp = sdp_bytes(kRestartOfferSdp);
    offer.dtls_fingerprint = test_fingerprint(0x10U);
    return offer;
  }

  heyaki::SignedAnswer answer_shape() const {
    heyaki::SignedAnswer answer;
    answer.binding.initiator = initiator_context.local;
    answer.binding.responder = initiator_context.peer;
    answer.binding.request_id = request_id;
    answer.binding.session_id = session_id;
    answer.binding.initiator_nonce = initiator_nonce;
    answer.binding.responder_nonce = responder_nonce;
    answer.binding.expires_unix_milliseconds = 1'030'000U;
    answer.sdp = sdp_bytes(kRestartAnswerSdp);
    answer.dtls_fingerprint = test_fingerprint(0x20U);
    return answer;
  }

  std::vector<std::byte> canonical_answer_bytes() const {
    auto canonical = heyaki::canonical_signed_answer(answer_shape());
    EXPECT_TRUE(canonical);
    return std::move(*canonical.value_if());
  }

  heyaki::SignalingTranscriptSha256 transcript() const {
    auto canonical_offer = heyaki::canonical_signed_offer(offer_shape());
    EXPECT_TRUE(canonical_offer);
    auto canonical_answer = heyaki::canonical_signed_answer(answer_shape());
    EXPECT_TRUE(canonical_answer);
    auto transcript = heyaki::hash_signaling_transcript(*canonical_offer.value_if(),
                                                        *canonical_answer.value_if());
    EXPECT_TRUE(transcript);
    return *transcript.value_if();
  }

  std::vector<std::byte> build_offer(
      std::optional<heyaki::RequestId> request = std::nullopt,
      std::optional<heyaki::SessionId> session = std::nullopt) const {
    auto context = initiator_context;
    if (session.has_value()) {
      context.session_id = *session;
    }
    auto offer = heyaki::build_session_restart_offer(
        context, initiator_identity, request.value_or(request_id),
        initiator_nonce, sdp_bytes(kRestartOfferSdp), test_fingerprint(0x10U), 1'000'000U);
    EXPECT_TRUE(offer);
    return std::move(*offer.value_if());
  }

  // A restart offer initiated by the peer endpoint (the responder identity in
  // this fixture), used for admission tests running on the initiator side.
  std::vector<std::byte> build_peer_offer(const heyaki::RequestId& request) const {
    heyaki::SignedOffer offer;
    offer.binding.initiator = responder_context.local;
    offer.binding.responder = responder_context.peer;
    offer.binding.request_id = request;
    offer.binding.session_id = session_id;
    offer.binding.initiator_nonce = initiator_nonce;
    offer.binding.expires_unix_milliseconds = 1'030'000U;
    offer.sdp = sdp_bytes(kRestartAnswerSdp);
    offer.dtls_fingerprint = test_fingerprint(0x20U);
    EXPECT_TRUE(heyaki::sign_signed_offer(offer, responder_identity));
    auto encoded = heyaki::encode_signed_offer(offer);
    EXPECT_TRUE(encoded);
    return std::move(*encoded.value_if());
  }

  std::vector<std::byte> build_answer() const {
    auto answer = heyaki::build_session_restart_answer(
        responder_context, responder_identity, request_id, initiator_nonce,
        responder_nonce, sdp_bytes(kRestartAnswerSdp), test_fingerprint(0x20U), 1'000'000U);
    EXPECT_TRUE(answer);
    return std::move(*answer.value_if());
  }

  std::vector<std::byte> build_candidate(std::uint32_t sequence) const {
    heyaki::SignalBinding binding;
    binding.initiator = initiator_context.local;
    binding.responder = initiator_context.peer;
    binding.request_id = request_id;
    binding.session_id = session_id;
    binding.initiator_nonce = initiator_nonce;
    binding.responder_nonce = responder_nonce;
    auto candidate = heyaki::build_session_restart_candidate(
        initiator_identity, binding, sequence,
        std::vector<std::byte>{std::byte{0x01}, std::byte{0x02}}, transcript(),
        "8hKaFrag", test_fingerprint(0x10U), 1'000'000U);
    EXPECT_TRUE(candidate);
    return std::move(*candidate.value_if());
  }
};

}  // namespace

TEST(M4SessionRestart, AdmitsOfferAnswerAndCandidateRoundTrip) {
  auto fixture = RestartFixture::create();
  auto offer_payload = fixture.build_offer();
  auto answer_payload = fixture.build_answer();

  heyaki::SessionRestartAdmission responder(fixture.responder_context);
  auto offer = responder.admit_offer(offer_payload, 1'000'000U);
  ASSERT_TRUE(offer);
  ASSERT_TRUE(offer.value_if()->has_value());
  EXPECT_EQ((**offer.value_if()).next_epoch, 5U);
  EXPECT_FALSE((**offer.value_if()).supersedes_local_restart);
  EXPECT_TRUE(responder.initiator_nonce().has_value());
  EXPECT_FALSE(responder.answer_admitted());

  ASSERT_TRUE(responder.set_local_restart_answer(fixture.responder_nonce,
                                                 fixture.canonical_answer_bytes()));
  EXPECT_TRUE(responder.answer_admitted());
  EXPECT_EQ(responder.transcript(), fixture.transcript());

  auto candidate = responder.admit_candidate(fixture.build_candidate(1U), 1'000'000U);
  ASSERT_TRUE(candidate);
  ASSERT_TRUE(candidate.value_if()->has_value());
  EXPECT_EQ((**candidate.value_if()).candidate.sequence, 1U);

  heyaki::SessionRestartAdmission initiator(fixture.initiator_context);
  auto canonical_offer = heyaki::canonical_signed_offer(fixture.offer_shape());
  ASSERT_TRUE(canonical_offer);
  initiator.set_local_restart(fixture.request_id, fixture.initiator_nonce,
                              *canonical_offer.value_if());
  auto answer = initiator.admit_answer(answer_payload, 1'000'000U);
  ASSERT_TRUE(answer);
  ASSERT_TRUE(answer.value_if()->has_value());
  EXPECT_EQ((**answer.value_if()).transcript, fixture.transcript());
}

TEST(M4SessionRestart, RejectsTamperedAndMismatchedOffers) {
  auto fixture = RestartFixture::create();
  auto payload = fixture.build_offer();
  heyaki::SessionRestartAdmission responder(fixture.responder_context);

  auto tampered = payload;
  tampered[tampered.size() / 2U] = static_cast<std::byte>(
      std::to_integer<std::uint8_t>(tampered[tampered.size() / 2U]) ^ 0x40U);
  auto rejected = responder.admit_offer(tampered, 1'000'000U);
  ASSERT_FALSE(rejected);

  // A different session id must not restart the live session.
  auto mismatched = responder.admit_offer(
      fixture.build_offer(std::nullopt, filled<heyaki::SessionId>(0x77U)), 1'000'000U);
  ASSERT_FALSE(mismatched);

  auto expired = responder.admit_offer(payload, 10'000'000U);
  ASSERT_FALSE(expired);
  EXPECT_EQ(responder.diagnostics().offers_admitted, 0U);
}

TEST(M4SessionRestart, DuplicateOfferIsIdempotentAndConflictsFail) {
  auto fixture = RestartFixture::create();
  auto payload = fixture.build_offer();
  heyaki::SessionRestartAdmission responder(fixture.responder_context);
  ASSERT_TRUE(responder.admit_offer(payload, 1'000'000U));

  auto duplicate = responder.admit_offer(payload, 1'000'000U);
  ASSERT_TRUE(duplicate);
  EXPECT_FALSE(duplicate.value_if()->has_value());
  EXPECT_EQ(responder.diagnostics().duplicates_ignored, 1U);

  auto conflict = responder.admit_offer(
      fixture.build_offer(filled<heyaki::RequestId>(0xEEU)), 1'000'000U);
  ASSERT_FALSE(conflict);
  EXPECT_EQ(responder.diagnostics().offers_admitted, 1U);
}

TEST(M4SessionRestart, RejectsCandidatesBeforeAnswerAndBindingViolations) {
  auto fixture = RestartFixture::create();
  heyaki::SessionRestartAdmission responder(fixture.responder_context);
  auto premature = responder.admit_candidate(fixture.build_candidate(1U), 1'000'000U);
  ASSERT_FALSE(premature);

  ASSERT_TRUE(responder.admit_offer(fixture.build_offer(), 1'000'000U));
  auto still_premature =
      responder.admit_candidate(fixture.build_candidate(1U), 1'000'000U);
  ASSERT_FALSE(still_premature);

  ASSERT_TRUE(responder.set_local_restart_answer(fixture.responder_nonce,
                                                 fixture.canonical_answer_bytes()));

  auto good = responder.admit_candidate(fixture.build_candidate(1U), 1'000'000U);
  ASSERT_TRUE(good);
  ASSERT_TRUE(good.value_if()->has_value());

  auto replay_identical =
      responder.admit_candidate(fixture.build_candidate(1U), 1'000'000U);
  ASSERT_TRUE(replay_identical);
  EXPECT_FALSE(replay_identical.value_if()->has_value());

  // Same sequence with different signed bytes is a protocol error, not an
  // idempotent duplicate.
  heyaki::SignedCandidate conflicting;
  conflicting.binding.initiator = fixture.initiator_context.local;
  conflicting.binding.responder = fixture.initiator_context.peer;
  conflicting.binding.request_id = fixture.request_id;
  conflicting.binding.session_id = fixture.session_id;
  conflicting.binding.initiator_nonce = fixture.initiator_nonce;
  conflicting.binding.responder_nonce = fixture.responder_nonce;
  conflicting.binding.expires_unix_milliseconds = 1'030'000U;
  conflicting.sequence = 1U;
  conflicting.candidate = {std::byte{0x07}};
  conflicting.signaling_transcript_sha256 = fixture.transcript();
  conflicting.owner_ice_ufrag = "8hKaFrag";
  conflicting.owner_dtls_fingerprint = test_fingerprint(0x10U);
  ASSERT_TRUE(heyaki::sign_signed_candidate(conflicting, fixture.initiator_identity));
  auto encoded_conflict = heyaki::encode_signed_candidate(conflicting);
  ASSERT_TRUE(encoded_conflict);
  auto stale_sequence =
      responder.admit_candidate(*encoded_conflict.value_if(), 1'000'000U);
  ASSERT_FALSE(stale_sequence);
  EXPECT_EQ(stale_sequence.error_if()->safe_detail(),
            "restart_candidate_duplicate_bytes_differ");

  // A candidate bound to the wrong transcript cannot be moved between ICE
  // generations even when correctly signed by the peer.
  heyaki::SignedCandidate moved = conflicting;
  moved.sequence = 2U;
  moved.signaling_transcript_sha256 = filled_array<32U>(0x99U);
  ASSERT_TRUE(heyaki::sign_signed_candidate(moved, fixture.initiator_identity));
  auto encoded_moved = heyaki::encode_signed_candidate(moved);
  ASSERT_TRUE(encoded_moved);
  auto rejected = responder.admit_candidate(*encoded_moved.value_if(), 1'000'000U);
  ASSERT_FALSE(rejected);
}

TEST(M4SessionRestart, GlareRuleIsDeterministicAndAdmissionFollowsIt) {
  const auto bigger = filled<heyaki::RequestId>(0xF0U);
  const auto smaller = filled<heyaki::RequestId>(0x01U);
  EXPECT_TRUE(heyaki::session_restart_offer_wins(bigger, smaller));
  EXPECT_FALSE(heyaki::session_restart_offer_wins(smaller, bigger));
  EXPECT_FALSE(heyaki::session_restart_offer_wins(bigger, bigger));

  auto fixture = RestartFixture::create();
  const auto local_request = filled<heyaki::RequestId>(0xF0U);
  auto local_offer = fixture.offer_shape(local_request);
  auto canonical = heyaki::canonical_signed_offer(local_offer);
  ASSERT_TRUE(canonical);

  // Losing simultaneous peer offer: suppressed without failing the session.
  heyaki::SessionRestartAdmission initiator(fixture.initiator_context);
  initiator.set_local_restart(local_request, fixture.initiator_nonce,
                              *canonical.value_if());
  auto suppressed = initiator.admit_offer(
      fixture.build_peer_offer(filled<heyaki::RequestId>(0x01U)), 1'000'000U);
  ASSERT_TRUE(suppressed);
  EXPECT_FALSE(suppressed.value_if()->has_value());
  EXPECT_EQ(initiator.diagnostics().glare_suppressed, 1U);

  // Winning simultaneous peer offer: admitted and supersedes the local one.
  auto admitted = initiator.admit_offer(
      fixture.build_peer_offer(filled<heyaki::RequestId>(0xFFU)), 1'000'000U);
  ASSERT_TRUE(admitted);
  ASSERT_TRUE(admitted.value_if()->has_value());
  EXPECT_TRUE((**admitted.value_if()).supersedes_local_restart);
}

TEST(M4SessionRestart, InitiatorSideAdmitsPeerCandidates) {
  auto fixture = RestartFixture::create();
  heyaki::SessionRestartAdmission initiator(fixture.initiator_context);
  auto canonical_offer =
      heyaki::canonical_signed_offer(fixture.offer_shape());
  ASSERT_TRUE(canonical_offer);
  initiator.set_local_restart(fixture.request_id, fixture.initiator_nonce,
                              *canonical_offer.value_if());
  auto answer = initiator.admit_answer(fixture.build_answer(), 1'000'000U);
  ASSERT_TRUE(answer);
  ASSERT_TRUE(answer.value_if()->has_value());

  // The peer (restart responder) signs candidates with the same absolute
  // binding; the initiator admission must accept them.
  heyaki::SignalBinding binding;
  binding.initiator = fixture.initiator_context.local;
  binding.responder = fixture.initiator_context.peer;
  binding.request_id = fixture.request_id;
  binding.session_id = fixture.session_id;
  binding.initiator_nonce = fixture.initiator_nonce;
  binding.responder_nonce = fixture.responder_nonce;
  auto candidate = heyaki::build_session_restart_candidate(
      fixture.responder_identity, binding, 1U,
      std::vector<std::byte>{std::byte{0x09}}, fixture.transcript(), "Qz9xOther",
      test_fingerprint(0x20U), 1'000'000U);
  ASSERT_TRUE(candidate);
  auto admitted = initiator.admit_candidate(*candidate.value_if(), 1'000'000U);
  ASSERT_TRUE(admitted);
  ASSERT_TRUE(admitted.value_if()->has_value());
}

TEST(M4SessionRestart, RejectsAnswerWithoutLocalRestart) {
  auto fixture = RestartFixture::create();
  heyaki::SessionRestartAdmission responder(fixture.responder_context);
  auto answer = responder.admit_answer(fixture.build_answer(), 1'000'000U);
  ASSERT_FALSE(answer);
  EXPECT_EQ(answer.error_if()->safe_detail(), "restart_answer_without_local_restart");
}
