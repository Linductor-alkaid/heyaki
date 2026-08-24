#include <heyaki/session_restart.hpp>

#include <heyaki/signing.hpp>

#include <utility>

namespace heyaki {
namespace {

Error restart_error(ErrorCode code, const char* detail) {
  return {code, "session_restart", detail};
}

[[nodiscard]] std::span<const std::byte> public_key_span(
    const IdentityPublicKey& key) noexcept {
  return std::span<const std::byte>{key.data(), key.size()};
}

bool same_binding_endpoints(const SignalBinding& binding,
                            const DeviceEndpointKey& initiator,
                            const DeviceEndpointKey& responder) noexcept {
  return binding.initiator == initiator && binding.responder == responder;
}

}  // namespace

bool session_restart_offer_wins(const RequestId& candidate,
                                const RequestId& other) noexcept {
  return candidate.bytes() > other.bytes();
}

Result<std::vector<std::byte>> build_session_restart_offer(
    const SessionRestartContext& context, const IdentityKeyPair& identity,
    const RequestId& request_id, const SignalingNonce& initiator_nonce,
    std::span<const std::byte> sdp, const DtlsFingerprint& fingerprint,
    std::uint64_t now_unix_milliseconds) {
  SignedOffer offer;
  offer.binding.initiator = context.local;
  offer.binding.responder = context.peer;
  offer.binding.request_id = request_id;
  offer.binding.session_id = context.session_id;
  offer.binding.initiator_nonce = initiator_nonce;
  offer.binding.expires_unix_milliseconds =
      now_unix_milliseconds + session_restart_validity_milliseconds;
  offer.sdp.assign(sdp.begin(), sdp.end());
  offer.dtls_fingerprint = fingerprint;
  auto signed_offer = sign_signed_offer(offer, identity);
  if (!signed_offer) {
    return Result<std::vector<std::byte>>::failure(*signed_offer.error_if());
  }
  return encode_signed_offer(offer);
}

Result<std::vector<std::byte>> build_session_restart_answer(
    const SessionRestartContext& context, const IdentityKeyPair& identity,
    const RequestId& request_id, const SignalingNonce& initiator_nonce,
    const SignalingNonce& responder_nonce, std::span<const std::byte> sdp,
    const DtlsFingerprint& fingerprint, std::uint64_t now_unix_milliseconds) {
  SignedAnswer answer;
  answer.binding.initiator = context.peer;
  answer.binding.responder = context.local;
  answer.binding.request_id = request_id;
  answer.binding.session_id = context.session_id;
  answer.binding.initiator_nonce = initiator_nonce;
  answer.binding.responder_nonce = responder_nonce;
  answer.binding.expires_unix_milliseconds =
      now_unix_milliseconds + session_restart_validity_milliseconds;
  answer.sdp.assign(sdp.begin(), sdp.end());
  answer.dtls_fingerprint = fingerprint;
  auto signed_answer = sign_signed_answer(answer, identity);
  if (!signed_answer) {
    return Result<std::vector<std::byte>>::failure(*signed_answer.error_if());
  }
  return encode_signed_answer(answer);
}

Result<std::vector<std::byte>> build_session_restart_candidate(
    const IdentityKeyPair& identity, const SignalBinding& binding,
    std::uint32_t sequence, std::span<const std::byte> candidate,
    const SignalingTranscriptSha256& transcript, std::string_view owner_ufrag,
    const DtlsFingerprint& owner_fingerprint, std::uint64_t now_unix_milliseconds) {
  SignedCandidate object;
  object.binding = binding;
  object.binding.expires_unix_milliseconds =
      now_unix_milliseconds + session_restart_validity_milliseconds;
  object.sequence = sequence;
  object.candidate.assign(candidate.begin(), candidate.end());
  object.signaling_transcript_sha256 = transcript;
  object.owner_ice_ufrag.assign(owner_ufrag.begin(), owner_ufrag.end());
  object.owner_dtls_fingerprint = owner_fingerprint;
  auto signed_candidate = sign_signed_candidate(object, identity);
  if (!signed_candidate) {
    return Result<std::vector<std::byte>>::failure(*signed_candidate.error_if());
  }
  return encode_signed_candidate(object);
}

SessionRestartAdmission::SessionRestartAdmission(SessionRestartContext context)
    : context_(std::move(context)) {
  auto replay = SignalingReplayCache::create(context_.replay_policy);
  if (replay) {
    replay_.emplace(std::move(*replay.value_if()));
  }
}

void SessionRestartAdmission::set_local_restart(
    const RequestId& request_id, const SignalingNonce& restart_initiator_nonce,
    std::span<const std::byte> canonical_offer) {
  local_restart_ = request_id;
  accepted_request_ = request_id;
  initiator_nonce_ = restart_initiator_nonce;
  canonical_offer_ = std::vector<std::byte>{canonical_offer.begin(),
                                            canonical_offer.end()};
}

Result<void> SessionRestartAdmission::set_local_restart_answer(
    const SignalingNonce& responder_nonce,
    std::span<const std::byte> canonical_answer) {
  if (!canonical_offer_.has_value()) {
    return Result<void>::failure(
        restart_error(ErrorCode::internal, "restart_answer_without_offer"));
  }
  auto transcript = hash_signaling_transcript(*canonical_offer_, canonical_answer);
  if (!transcript) return Result<void>::failure(*transcript.error_if());
  responder_nonce_ = responder_nonce;
  transcript_ = *transcript.value_if();
  return Result<void>::success();
}

Result<std::optional<AdmittedSessionRestartOffer>> SessionRestartAdmission::admit_offer(
    std::span<const std::byte> payload, std::uint64_t now_unix_milliseconds) {
  if (!replay_.has_value()) {
    return Result<std::optional<AdmittedSessionRestartOffer>>::failure(
        restart_error(ErrorCode::internal, "restart_replay_cache_unavailable"));
  }
  auto parsed = parse_signed_offer(payload);
  if (!parsed) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartOffer>>::failure(
        *parsed.error_if());
  }
  const auto& offer = *parsed.value_if();
  // A restart offer must come from the authenticated peer, present itself as
  // the initiator, address this endpoint as the responder, and preserve the
  // session id of the live session.
  if (!same_binding_endpoints(offer.binding, context_.peer, context_.local) ||
      offer.binding.session_id != context_.session_id ||
      offer.binding.responder_nonce.has_value()) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartOffer>>::failure(
        restart_error(ErrorCode::protocol, "restart_offer_binding_mismatch"));
  }
  auto verified = verify_signed_offer(offer, public_key_span(context_.peer_public_key),
                                      now_unix_milliseconds);
  if (!verified) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartOffer>>::failure(
        *verified.error_if());
  }
  auto ufrag = parse_sdp_ice_ufrag(offer.sdp);
  if (!ufrag) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartOffer>>::failure(
        *ufrag.error_if());
  }
  auto canonical = canonical_signed_offer(offer);
  if (!canonical) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartOffer>>::failure(
        *canonical.error_if());
  }
  const bool glare_candidate =
      local_restart_.has_value() && offer.binding.request_id != *local_restart_;
  if (glare_candidate &&
      !session_restart_offer_wins(offer.binding.request_id, *local_restart_)) {
    // The simultaneous local restart wins the deterministic glare rule; the
    // peer aborts its losing attempt by the same rule, so this offer is
    // dropped without failing the session.
    ++diagnostics_.glare_suppressed;
    return Result<std::optional<AdmittedSessionRestartOffer>>::success(std::nullopt);
  }
  if (accepted_request_.has_value()) {
    if (*accepted_request_ == offer.binding.request_id) {
      // Byte-identical retransmission of the offer this side already knows.
      ++diagnostics_.duplicates_ignored;
      return Result<std::optional<AdmittedSessionRestartOffer>>::success(std::nullopt);
    }
    if (!glare_candidate) {
      ++diagnostics_.rejected;
      return Result<std::optional<AdmittedSessionRestartOffer>>::failure(
          restart_error(ErrorCode::protocol, "restart_offer_conflict"));
    }
  }
  auto replay = replay_->admit(SigningDomain::offer, context_.peer.device_id,
                               offer.binding.request_id, offer.binding.session_id,
                               offer.binding.initiator_nonce, std::nullopt, std::nullopt);
  if (!replay) {
    ++diagnostics_.replay_rejected;
    return Result<std::optional<AdmittedSessionRestartOffer>>::failure(*replay.error_if());
  }
  if (*replay.value_if() == SignalingReplayDecision::duplicate) {
    ++diagnostics_.replay_rejected;
    return Result<std::optional<AdmittedSessionRestartOffer>>::failure(
        restart_error(ErrorCode::protocol, "restart_offer_replayed"));
  }
  if (*replay.value_if() == SignalingReplayDecision::capacity_rejected) {
    ++diagnostics_.replay_rejected;
    return Result<std::optional<AdmittedSessionRestartOffer>>::failure(
        restart_error(ErrorCode::resource_exhausted, "replay_cache_saturated"));
  }
  accepted_request_ = offer.binding.request_id;
  canonical_offer_ = std::move(*canonical.value_if());
  initiator_nonce_ = offer.binding.initiator_nonce;
  peer_fingerprint_ = offer.dtls_fingerprint;
  peer_ufrag_ = *ufrag.value_if();
  ++diagnostics_.offers_admitted;
  return Result<std::optional<AdmittedSessionRestartOffer>>::success(
      AdmittedSessionRestartOffer{
          .offer = offer,
          .canonical_offer = *canonical_offer_,
          .next_epoch = context_.current_epoch + 1U,
          .supersedes_local_restart = glare_candidate,
      });
}

Result<std::optional<AdmittedSessionRestartAnswer>> SessionRestartAdmission::admit_answer(
    std::span<const std::byte> payload, std::uint64_t now_unix_milliseconds) {
  if (!replay_.has_value()) {
    return Result<std::optional<AdmittedSessionRestartAnswer>>::failure(
        restart_error(ErrorCode::internal, "restart_replay_cache_unavailable"));
  }
  auto parsed = parse_signed_answer(payload);
  if (!parsed) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartAnswer>>::failure(
        *parsed.error_if());
  }
  const auto& answer = *parsed.value_if();
  if (!accepted_request_.has_value() || !initiator_nonce_.has_value() ||
      !canonical_offer_.has_value() || !local_restart_.has_value()) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartAnswer>>::failure(
        restart_error(ErrorCode::protocol, "restart_answer_without_local_restart"));
  }
  // The local side initiated this restart, so the answer's binding keeps the
  // local endpoint as the initiator and the authenticated peer as responder.
  if (!same_binding_endpoints(answer.binding, context_.local, context_.peer) ||
      answer.binding.request_id != *accepted_request_ ||
      answer.binding.session_id != context_.session_id ||
      answer.binding.initiator_nonce != *initiator_nonce_ ||
      !answer.binding.responder_nonce.has_value()) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartAnswer>>::failure(
        restart_error(ErrorCode::protocol, "restart_answer_binding_mismatch"));
  }
  auto verified = verify_signed_answer(answer,
                                       public_key_span(context_.peer_public_key),
                                       now_unix_milliseconds);
  if (!verified) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartAnswer>>::failure(
        *verified.error_if());
  }
  auto ufrag = parse_sdp_ice_ufrag(answer.sdp);
  if (!ufrag) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartAnswer>>::failure(
        *ufrag.error_if());
  }
  auto canonical = canonical_signed_answer(answer);
  if (!canonical) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartAnswer>>::failure(
        *canonical.error_if());
  }
  if (responder_nonce_.has_value()) {
    if (*responder_nonce_ == answer.binding.responder_nonce) {
      ++diagnostics_.duplicates_ignored;
      return Result<std::optional<AdmittedSessionRestartAnswer>>::success(std::nullopt);
    }
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartAnswer>>::failure(
        restart_error(ErrorCode::protocol, "restart_answer_conflict"));
  }
  auto transcript = hash_signaling_transcript(*canonical_offer_, *canonical.value_if());
  if (!transcript) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartAnswer>>::failure(
        *transcript.error_if());
  }
  auto replay = replay_->admit(
      SigningDomain::answer, context_.peer.device_id, answer.binding.request_id,
      answer.binding.session_id, answer.binding.initiator_nonce,
      answer.binding.responder_nonce, std::nullopt);
  if (!replay) {
    ++diagnostics_.replay_rejected;
    return Result<std::optional<AdmittedSessionRestartAnswer>>::failure(*replay.error_if());
  }
  if (*replay.value_if() == SignalingReplayDecision::duplicate) {
    ++diagnostics_.replay_rejected;
    return Result<std::optional<AdmittedSessionRestartAnswer>>::failure(
        restart_error(ErrorCode::protocol, "restart_answer_replayed"));
  }
  if (*replay.value_if() == SignalingReplayDecision::capacity_rejected) {
    ++diagnostics_.replay_rejected;
    return Result<std::optional<AdmittedSessionRestartAnswer>>::failure(
        restart_error(ErrorCode::resource_exhausted, "replay_cache_saturated"));
  }
  responder_nonce_ = answer.binding.responder_nonce;
  transcript_ = *transcript.value_if();
  peer_fingerprint_ = answer.dtls_fingerprint;
  peer_ufrag_ = *ufrag.value_if();
  ++diagnostics_.answers_admitted;
  return Result<std::optional<AdmittedSessionRestartAnswer>>::success(
      AdmittedSessionRestartAnswer{
          .answer = answer,
          .canonical_answer = std::move(*canonical.value_if()),
          .transcript = *transcript.value_if(),
      });
}

Result<std::optional<AdmittedSessionRestartCandidate>>
SessionRestartAdmission::admit_candidate(std::span<const std::byte> payload,
                                         std::uint64_t now_unix_milliseconds) {
  if (!replay_.has_value()) {
    return Result<std::optional<AdmittedSessionRestartCandidate>>::failure(
        restart_error(ErrorCode::internal, "restart_replay_cache_unavailable"));
  }
  auto parsed = parse_signed_candidate(payload);
  if (!parsed) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartCandidate>>::failure(
        *parsed.error_if());
  }
  const auto& candidate = *parsed.value_if();
  if (!accepted_request_.has_value() || !initiator_nonce_.has_value() ||
      !responder_nonce_.has_value() || !transcript_.has_value()) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartCandidate>>::failure(
        restart_error(ErrorCode::protocol, "restart_candidate_before_answer"));
  }
  // The binding endpoints are absolute: the restart initiator endpoint stays
  // the initiator in every object. This side is the initiator exactly when it
  // registered its own restart offer.
  const bool local_is_initiator = local_restart_.has_value();
  const DeviceEndpointKey& expected_initiator =
      local_is_initiator ? context_.local : context_.peer;
  const DeviceEndpointKey& expected_responder =
      local_is_initiator ? context_.peer : context_.local;
  if (candidate.binding.initiator != expected_initiator ||
      candidate.binding.responder != expected_responder ||
      candidate.binding.request_id != *accepted_request_ ||
      candidate.binding.session_id != context_.session_id ||
      candidate.binding.initiator_nonce != *initiator_nonce_ ||
      candidate.binding.responder_nonce != *responder_nonce_) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartCandidate>>::failure(
        restart_error(ErrorCode::protocol, "restart_candidate_binding_mismatch"));
  }
  auto owner = verify_signed_candidate(candidate,
                                       public_key_span(context_.peer_public_key),
                                       now_unix_milliseconds);
  if (!owner) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartCandidate>>::failure(
        *owner.error_if());
  }
  // Every inbound candidate is signed by the peer, whichever restart role the
  // peer holds; the signed owner fields must match the verified peer facts.
  if (candidate.signaling_transcript_sha256 != *transcript_ ||
      candidate.owner_dtls_fingerprint != peer_fingerprint_ ||
      candidate.owner_ice_ufrag != peer_ufrag_) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartCandidate>>::failure(
        restart_error(ErrorCode::protocol, "restart_candidate_transcript_mismatch"));
  }
  if (admitted_candidates_ >= max_session_restart_candidates) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartCandidate>>::failure(
        restart_error(ErrorCode::resource_exhausted, "restart_candidate_budget_exhausted"));
  }
  auto replay = replay_->admit(SigningDomain::candidate, context_.peer.device_id,
                               candidate.binding.request_id,
                               candidate.binding.session_id,
                               candidate.binding.initiator_nonce,
                               candidate.binding.responder_nonce, candidate.sequence);
  if (!replay) {
    ++diagnostics_.replay_rejected;
    return Result<std::optional<AdmittedSessionRestartCandidate>>::failure(
        *replay.error_if());
  }
  if (*replay.value_if() == SignalingReplayDecision::duplicate) {
    const auto stored = accepted_candidates_.find(candidate.sequence);
    if (stored != accepted_candidates_.end() &&
        stored->second == std::vector<std::byte>{payload.begin(), payload.end()}) {
      ++diagnostics_.duplicates_ignored;
      return Result<std::optional<AdmittedSessionRestartCandidate>>::success(std::nullopt);
    }
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartCandidate>>::failure(
        restart_error(ErrorCode::protocol, "restart_candidate_duplicate_bytes_differ"));
  }
  if (*replay.value_if() == SignalingReplayDecision::capacity_rejected) {
    ++diagnostics_.replay_rejected;
    return Result<std::optional<AdmittedSessionRestartCandidate>>::failure(
        restart_error(ErrorCode::resource_exhausted, "replay_cache_saturated"));
  }
  if (candidate.sequence <= peer_candidate_sequence_) {
    ++diagnostics_.rejected;
    return Result<std::optional<AdmittedSessionRestartCandidate>>::failure(
        restart_error(ErrorCode::protocol, "restart_candidate_sequence_not_increasing"));
  }
  peer_candidate_sequence_ = candidate.sequence;
  accepted_candidates_.emplace(
      candidate.sequence, std::vector<std::byte>{payload.begin(), payload.end()});
  ++admitted_candidates_;
  ++diagnostics_.candidates_admitted;
  return Result<std::optional<AdmittedSessionRestartCandidate>>::success(
      AdmittedSessionRestartCandidate{.candidate = candidate});
}

std::optional<SignalingNonce> SessionRestartAdmission::initiator_nonce() const noexcept {
  return initiator_nonce_;
}

std::optional<SignalingNonce> SessionRestartAdmission::responder_nonce() const noexcept {
  return responder_nonce_;
}

std::optional<SignalingTranscriptSha256> SessionRestartAdmission::transcript() const
    noexcept {
  return transcript_;
}

std::optional<DtlsFingerprint> SessionRestartAdmission::peer_fingerprint() const noexcept {
  return peer_fingerprint_;
}

std::optional<std::string> SessionRestartAdmission::peer_ufrag() const noexcept {
  return peer_ufrag_;
}

bool SessionRestartAdmission::answer_admitted() const noexcept {
  return responder_nonce_.has_value();
}

const SessionRestartDiagnostics& SessionRestartAdmission::diagnostics() const noexcept {
  return diagnostics_;
}

}  // namespace heyaki
