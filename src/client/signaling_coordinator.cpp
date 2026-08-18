#include "signaling_coordinator.hpp"

#include <heyaki/security.hpp>

#include <sodium/randombytes.h>

#include <algorithm>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <utility>

#include <cstddef>
#include <cstdint>

namespace heyaki {
namespace {

Error coordinator_error(ErrorCode code, const char* detail) {
  return Error{code, "signaling_coordinator", detail};
}

template <std::size_t Size>
void fill_random(std::array<std::byte, Size>& value) {
  randombytes_buf(value.data(), value.size());
}

template <typename Id>
Id random_id() {
  typename Id::Storage bytes{};
  randombytes_buf(bytes.data(), bytes.size());
  Id id{bytes};
  while (id.is_zero()) {
    randombytes_buf(bytes.data(), bytes.size());
    id = Id{bytes};
  }
  return id;
}

struct Attempt {
  RequestId request_id;
  SessionId session_id;
  DeviceEndpointKey peer;
  bool inbound{false};
  SignalingRouteKind route{SignalingRouteKind::lan};
  SignalingAttemptPhase phase{SignalingAttemptPhase::requesting};
  std::chrono::steady_clock::time_point created_at{};
  SignalingNonce initiator_nonce{};
  std::optional<SignalingNonce> responder_nonce;
  std::optional<SignedOffer> verified_offer;
  std::optional<std::vector<std::byte>> canonical_offer;
  std::optional<std::vector<std::byte>> canonical_answer;
  std::optional<SignalingTranscriptSha256> transcript;
  std::string peer_ufrag;
  std::string local_ufrag;
  DtlsFingerprint peer_fingerprint{};
  DtlsFingerprint local_fingerprint{};
  std::uint32_t local_sequence{};
  std::uint32_t peer_sequence{};
  std::uint32_t sent_candidates{};
  std::uint32_t received_candidates{};
  // Bounded by max_candidates_per_attempt; keyed by sequence for byte-identity replay.
  std::map<std::uint32_t, std::vector<std::byte>> accepted_candidate_payloads;
};

struct RateEntry {
  std::chrono::steady_clock::time_point window_start{};
  std::size_t count{};
};

SignalingAttemptSnapshot snapshot_of(const Attempt& attempt,
                                     std::chrono::milliseconds ttl) {
  SignalingAttemptSnapshot snapshot;
  snapshot.request_id = attempt.request_id;
  snapshot.session_id = attempt.session_id;
  snapshot.peer = attempt.peer;
  snapshot.inbound = attempt.inbound;
  snapshot.route = attempt.route;
  snapshot.phase = attempt.phase;
  snapshot.created_at = attempt.created_at;
  snapshot.ttl = ttl;
  snapshot.sent_candidates = attempt.sent_candidates;
  snapshot.received_candidates = attempt.received_candidates;
  return snapshot;
}

}  // namespace

class SignalingCoordinator::Impl {
 public:
  Impl(SignalingCoordinatorConfig config, std::shared_ptr<SignalingDelegate> delegate,
       SignalingReplayCache replay)
      : config_(std::move(config)),
        delegate_(std::move(delegate)),
        replay_(std::move(replay)) {}

  void attach_route(SignalingRoute* route) {
    if (route == nullptr) {
      return;
    }
    routes_[route->kind()] = route;
  }

  Result<RequestId> begin_attempt(DeviceEndpointKey peer, SignalingRouteKind route,
                                  std::chrono::steady_clock::time_point now) {
    if (peer.device_id.is_zero() || peer.endpoint_id.is_zero()) {
      return Result<RequestId>::failure(coordinator_error(ErrorCode::protocol,
                                                          "peer_endpoint_zero"));
    }
    const auto outbound = std::count_if(attempts_.begin(), attempts_.end(),
                                        [](const auto& pair) {
                                          return !pair.second.inbound;
                                        });
    if (static_cast<std::size_t>(outbound) >= config_.max_pending_attempts) {
      ++diagnostics_.outbound_capacity_rejected;
      return Result<RequestId>::failure(
          coordinator_error(ErrorCode::resource_exhausted, "pending_attempts_exhausted"));
    }
    for (const auto& [id, attempt] : attempts_) {
      if (!attempt.inbound && attempt.peer == peer &&
          attempt.phase != SignalingAttemptPhase::closed) {
        return Result<RequestId>::failure(
            coordinator_error(ErrorCode::signaling, "attempt_already_active"));
      }
    }
    Attempt attempt;
    attempt.request_id = random_id<RequestId>();
    attempt.session_id = random_id<SessionId>();
    fill_random(attempt.initiator_nonce);
    attempt.peer = peer;
    attempt.inbound = false;
    attempt.route = route;
    attempt.phase = SignalingAttemptPhase::requesting;
    attempt.created_at = now;

    SignalingEnvelope envelope;
    envelope.peer = peer;
    envelope.kind = LanSignalingMessageKind::connect_request;
    envelope.request_id = attempt.request_id;
    auto sent = send_via_route(route, envelope);
    if (!sent) {
      return Result<RequestId>::failure(*sent.error_if());
    }
    const auto request_id = attempt.request_id;
    attempts_.emplace(request_id, std::move(attempt));
    ++diagnostics_.attempts_begun;
    update_attempt_peak();
    return Result<RequestId>::success(request_id);
  }

  Result<void> send_local_offer(RequestId request_id, std::span<const std::byte> sdp,
                                const DtlsFingerprint& fingerprint,
                                std::chrono::steady_clock::time_point /*now*/,
                                std::uint64_t now_unix_ms) {
    auto* attempt = find(request_id);
    if (attempt == nullptr) {
      return Result<void>::failure(coordinator_error(ErrorCode::signaling,
                                                     "attempt_unknown"));
    }
    if (attempt->inbound || attempt->phase != SignalingAttemptPhase::accepted) {
      return Result<void>::failure(
          coordinator_error(ErrorCode::signaling, "attempt_not_ready_for_offer"));
    }
    SignedOffer offer;
    offer.binding.initiator = config_.local;
    offer.binding.responder = attempt->peer;
    offer.binding.request_id = attempt->request_id;
    offer.binding.session_id = attempt->session_id;
    offer.binding.initiator_nonce = attempt->initiator_nonce;
    offer.binding.expires_unix_milliseconds =
        now_unix_ms + config_.signaling_validity_milliseconds;
    offer.sdp.assign(sdp.begin(), sdp.end());
    offer.dtls_fingerprint = fingerprint;
    auto ufrag = parse_sdp_ice_ufrag(sdp);
    if (!ufrag) {
      return Result<void>::failure(*ufrag.error_if());
    }
    auto signed_offer = sign_signed_offer(offer, *config_.identity);
    if (!signed_offer) {
      return Result<void>::failure(*signed_offer.error_if());
    }
    auto canonical = canonical_signed_offer(offer);
    if (!canonical) {
      return Result<void>::failure(*canonical.error_if());
    }
    auto payload = encode_signed_offer(offer);
    if (!payload) {
      return Result<void>::failure(*payload.error_if());
    }
    auto sent = send_payload(*attempt, LanSignalingMessageKind::signed_offer,
                             *payload.value_if());
    if (!sent) {
      return Result<void>::failure(*sent.error_if());
    }
    attempt->canonical_offer = *canonical.value_if();
    attempt->local_fingerprint = fingerprint;
    attempt->local_ufrag = *ufrag.value_if();
    attempt->phase = SignalingAttemptPhase::offered;
    return Result<void>::success();
  }

  Result<void> send_local_answer(RequestId request_id, std::span<const std::byte> sdp,
                                 const DtlsFingerprint& fingerprint,
                                 std::chrono::steady_clock::time_point /*now*/,
                                 std::uint64_t now_unix_ms) {
    auto* attempt = find(request_id);
    if (attempt == nullptr) {
      return Result<void>::failure(coordinator_error(ErrorCode::signaling,
                                                     "attempt_unknown"));
    }
    if (!attempt->inbound || attempt->phase != SignalingAttemptPhase::offered ||
        !attempt->verified_offer.has_value() ||
        !attempt->canonical_offer.has_value()) {
      return Result<void>::failure(
          coordinator_error(ErrorCode::signaling, "attempt_not_ready_for_answer"));
    }
    SignedAnswer answer;
    answer.binding = attempt->verified_offer->binding;
    SignalingNonce responder_nonce{};
    fill_random(responder_nonce);
    answer.binding.responder_nonce = responder_nonce;
    answer.binding.expires_unix_milliseconds =
        now_unix_ms + config_.signaling_validity_milliseconds;
    answer.sdp.assign(sdp.begin(), sdp.end());
    answer.dtls_fingerprint = fingerprint;
    auto ufrag = parse_sdp_ice_ufrag(sdp);
    if (!ufrag) {
      return Result<void>::failure(*ufrag.error_if());
    }
    auto signed_answer = sign_signed_answer(answer, *config_.identity);
    if (!signed_answer) {
      return Result<void>::failure(*signed_answer.error_if());
    }
    auto canonical = canonical_signed_answer(answer);
    if (!canonical) {
      return Result<void>::failure(*canonical.error_if());
    }
    auto transcript =
        hash_signaling_transcript(*attempt->canonical_offer, *canonical.value_if());
    if (!transcript) {
      return Result<void>::failure(*transcript.error_if());
    }
    auto payload = encode_signed_answer(answer);
    if (!payload) {
      return Result<void>::failure(*payload.error_if());
    }
    auto sent = send_payload(*attempt, LanSignalingMessageKind::signed_answer,
                             *payload.value_if());
    if (!sent) {
      return Result<void>::failure(*sent.error_if());
    }
    attempt->responder_nonce = responder_nonce;
    attempt->canonical_answer = *canonical.value_if();
    attempt->transcript = *transcript.value_if();
    attempt->local_fingerprint = fingerprint;
    attempt->local_ufrag = *ufrag.value_if();
    attempt->phase = SignalingAttemptPhase::answered;
    return Result<void>::success();
  }

  Result<void> send_local_candidate(RequestId request_id,
                                    std::span<const std::byte> candidate,
                                    std::chrono::steady_clock::time_point /*now*/,
                                    std::uint64_t now_unix_ms) {
    auto* attempt = find(request_id);
    if (attempt == nullptr) {
      return Result<void>::failure(coordinator_error(ErrorCode::signaling,
                                                     "attempt_unknown"));
    }
    if (attempt->phase != SignalingAttemptPhase::answered &&
        attempt->phase != SignalingAttemptPhase::candidates) {
      return Result<void>::failure(
          coordinator_error(ErrorCode::signaling, "attempt_not_ready_for_candidate"));
    }
    if (attempt->sent_candidates + 1U > config_.max_candidates_per_attempt) {
      ++diagnostics_.candidate_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::resource_exhausted, "candidate_budget_exhausted"));
    }
    if (attempt->local_sequence == std::numeric_limits<std::uint32_t>::max()) {
      return Result<void>::failure(
          coordinator_error(ErrorCode::resource_exhausted, "candidate_sequence_exhausted"));
    }
    SignedCandidate object;
    object.binding.initiator = attempt->inbound ? attempt->peer : config_.local;
    object.binding.responder = attempt->inbound ? config_.local : attempt->peer;
    object.binding.request_id = attempt->request_id;
    object.binding.session_id = attempt->session_id;
    object.binding.initiator_nonce = attempt->initiator_nonce;
    object.binding.responder_nonce = attempt->responder_nonce;
    object.binding.expires_unix_milliseconds =
        now_unix_ms + config_.signaling_validity_milliseconds;
    object.sequence = attempt->local_sequence + 1U;
    object.candidate.assign(candidate.begin(), candidate.end());
    object.signaling_transcript_sha256 = *attempt->transcript;
    object.owner_ice_ufrag = attempt->local_ufrag;
    object.owner_dtls_fingerprint = attempt->local_fingerprint;
    auto signed_candidate = sign_signed_candidate(object, *config_.identity);
    if (!signed_candidate) {
      return Result<void>::failure(*signed_candidate.error_if());
    }
    auto payload = encode_signed_candidate(object);
    if (!payload) {
      return Result<void>::failure(*payload.error_if());
    }
    auto sent = send_payload(*attempt, LanSignalingMessageKind::signed_candidate,
                             *payload.value_if());
    if (!sent) {
      return Result<void>::failure(*sent.error_if());
    }
    attempt->local_sequence = object.sequence;
    ++attempt->sent_candidates;
    attempt->phase = SignalingAttemptPhase::candidates;
    return Result<void>::success();
  }

  Result<void> handle_message(const SignalingEnvelope& message, SignalingRouteKind source,
                              std::chrono::steady_clock::time_point now,
                              std::uint64_t now_unix_ms) {
    ++diagnostics_.messages_received;
    if (message.payload.size() > config_.max_signaling_payload_bytes) {
      ++diagnostics_.payload_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::protocol, "signaling_payload_too_large"));
    }
    if (message.request_id.is_zero()) {
      ++diagnostics_.parse_rejected;
      return Result<void>::failure(coordinator_error(ErrorCode::protocol,
                                                     "signaling_request_id_zero"));
    }
    if (!admit_rate(message.peer, now)) {
      ++diagnostics_.rate_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::resource_exhausted, "signaling_rate_exceeded"));
    }
    switch (message.kind) {
      case LanSignalingMessageKind::connect_request:
        return handle_connect_request(message, source, now);
      case LanSignalingMessageKind::connect_accept:
        return handle_connect_accept(message, source);
      case LanSignalingMessageKind::connect_deny:
        return handle_connect_deny(message, source);
      case LanSignalingMessageKind::signed_offer:
        return handle_signed_offer(message, source, now_unix_ms);
      case LanSignalingMessageKind::signed_answer:
        return handle_signed_answer(message, source, now_unix_ms);
      case LanSignalingMessageKind::signed_candidate:
        return handle_signed_candidate(message, source, now_unix_ms);
    }
    ++diagnostics_.parse_rejected;
    return Result<void>::failure(coordinator_error(ErrorCode::protocol,
                                                   "signaling_kind_unknown"));
  }

  Result<void> cancel_attempt(RequestId request_id,
                              std::chrono::steady_clock::time_point /*now*/) {
    const auto erased = attempts_.erase(request_id);
    if (erased == 0U) {
      return Result<void>::failure(coordinator_error(ErrorCode::signaling,
                                                     "attempt_unknown"));
    }
    ++diagnostics_.attempts_closed;
    update_current_attempts();
    return Result<void>::success();
  }

  void expire(std::chrono::steady_clock::time_point now) {
    for (auto it = attempts_.begin(); it != attempts_.end();) {
      const auto deadline = it->second.created_at + config_.attempt_ttl;
      if (now >= deadline) {
        if (delegate_->on_attempt_error) {
          delegate_->on_attempt_error(snapshot_of(it->second, config_.attempt_ttl),
                                     coordinator_error(ErrorCode::timeout,
                                                       "attempt_expired"));
        }
        it = attempts_.erase(it);
        ++diagnostics_.attempts_expired;
      } else {
        ++it;
      }
    }
    update_current_attempts();
  }

  std::vector<SignalingAttemptSnapshot> attempts() const {
    std::vector<SignalingAttemptSnapshot> snapshots;
    snapshots.reserve(attempts_.size());
    for (const auto& [id, attempt] : attempts_) {
      snapshots.push_back(snapshot_of(attempt, config_.attempt_ttl));
    }
    return snapshots;
  }

  Result<VerifiedSessionBinding> verified_session_binding(RequestId request_id,
                                                          std::uint64_t epoch) const {
    const auto* attempt = find(request_id);
    if (attempt == nullptr || !attempt->canonical_offer || !attempt->canonical_answer ||
        !attempt->transcript || !attempt->responder_nonce || attempt->session_id.is_zero()) {
      return Result<VerifiedSessionBinding>::failure(
          coordinator_error(ErrorCode::signaling, "session_binding_not_ready"));
    }
    const auto initiator = attempt->inbound ? attempt->peer : config_.local;
    const auto responder = attempt->inbound ? config_.local : attempt->peer;
    return Result<VerifiedSessionBinding>::success({
        .expectation = {.sender = initiator,
                        .peer = responder,
                        .session_id = attempt->session_id,
                        .session_epoch = epoch,
                        .initiator_nonce = attempt->initiator_nonce,
                        .responder_nonce = *attempt->responder_nonce,
                        .signaling_transcript_sha256 = *attempt->transcript},
        .peer_fingerprint = attempt->peer_fingerprint,
        .peer_ufrag = attempt->peer_ufrag});
  }

  SignalingCoordinatorDiagnostics diagnostics() const noexcept { return diagnostics_; }

  Result<void> check_create() {
    if (config_.identity == nullptr) {
      return Result<void>::failure(coordinator_error(ErrorCode::configuration,
                                                     "identity_missing"));
    }
    auto derived = derive_device_id(config_.identity->public_key());
    if (!derived || *derived.value_if() != config_.local.device_id) {
      return Result<void>::failure(coordinator_error(ErrorCode::identity,
                                                     "local_identity_mismatch"));
    }
    if (config_.local.device_id.is_zero() || config_.local.endpoint_id.is_zero()) {
      return Result<void>::failure(coordinator_error(ErrorCode::configuration,
                                                     "local_endpoint_zero"));
    }
    if (config_.max_pending_attempts == 0U || config_.max_inbound_attempts == 0U ||
        config_.max_candidates_per_attempt == 0U || config_.inbound_rate_limit == 0U ||
        config_.rate_key_capacity == 0U || config_.attempt_ttl.count() <= 0 ||
        config_.inbound_rate_window.count() <= 0) {
      return Result<void>::failure(coordinator_error(ErrorCode::configuration,
                                                     "signaling_bounds_invalid"));
    }
    if (config_.signaling_validity_milliseconds < 1000U ||
        config_.signaling_validity_milliseconds > maximum_signed_validity_milliseconds) {
      return Result<void>::failure(coordinator_error(ErrorCode::configuration,
                                                     "signaling_validity_invalid"));
    }
    return Result<void>::success();
  }

 private:
  Attempt* find(const RequestId& request_id) {
    const auto it = attempts_.find(request_id);
    return it == attempts_.end() ? nullptr : &it->second;
  }

  const Attempt* find(const RequestId& request_id) const {
    const auto it = attempts_.find(request_id);
    return it == attempts_.end() ? nullptr : &it->second;
  }

  void update_attempt_peak() {
    diagnostics_.current_attempts = attempts_.size();
    diagnostics_.peak_attempts = std::max(diagnostics_.peak_attempts, attempts_.size());
  }

  void update_current_attempts() {
    diagnostics_.current_attempts = attempts_.size();
  }

  bool admit_rate(const DeviceEndpointKey& peer,
                  std::chrono::steady_clock::time_point now) {
    auto it = rate_entries_.find(peer);
    if (it == rate_entries_.end()) {
      if (rate_entries_.size() >= config_.rate_key_capacity) {
        return false;
      }
      it = rate_entries_.emplace(peer, RateEntry{now, 0U}).first;
    }
    if (now - it->second.window_start >= config_.inbound_rate_window) {
      it->second.window_start = now;
      it->second.count = 0U;
    }
    ++it->second.count;
    return it->second.count <= config_.inbound_rate_limit;
  }

  Result<void> send_via_route(SignalingRouteKind kind, const SignalingEnvelope& envelope) {
    const auto it = routes_.find(kind);
    if (it == routes_.end() || it->second == nullptr) {
      ++diagnostics_.route_missing;
      return Result<void>::failure(coordinator_error(
          kind == SignalingRouteKind::relay ? ErrorCode::relay_unavailable
                                            : ErrorCode::signaling,
          "signaling_route_missing"));
    }
    return it->second->send(envelope);
  }

  Result<void> send_payload(const Attempt& attempt, LanSignalingMessageKind kind,
                            std::span<const std::byte> payload) {
    SignalingEnvelope envelope;
    envelope.peer = attempt.peer;
    envelope.kind = kind;
    envelope.request_id = attempt.request_id;
    envelope.payload.assign(payload.begin(), payload.end());
    return send_via_route(attempt.route, envelope);
  }

  Result<void> handle_connect_request(const SignalingEnvelope& message,
                                      SignalingRouteKind source,
                                      std::chrono::steady_clock::time_point now) {
    if (!message.payload.empty()) {
      ++diagnostics_.parse_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::protocol, "connect_request_payload_invalid"));
    }
    if (find(message.request_id) != nullptr) {
      ++diagnostics_.duplicate_request_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::protocol, "connect_request_duplicate"));
    }
    const auto inbound = std::count_if(attempts_.begin(), attempts_.end(),
                                       [](const auto& pair) {
                                         return pair.second.inbound;
                                       });
    if (static_cast<std::size_t>(inbound) >= config_.max_inbound_attempts) {
      ++diagnostics_.inbound_capacity_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::resource_exhausted, "inbound_attempts_exhausted"));
    }
    bool accept = false;
    {
      Attempt probe;
      probe.request_id = message.request_id;
      probe.peer = message.peer;
      probe.inbound = true;
      probe.route = source;
      probe.phase = SignalingAttemptPhase::responding;
      probe.created_at = now;
      const auto snapshot = snapshot_of(probe, config_.attempt_ttl);
      accept = delegate_->on_inbound_connect
                   ? delegate_->on_inbound_connect(snapshot)
                   : false;
    }
    SignalingEnvelope envelope;
    envelope.peer = message.peer;
    envelope.request_id = message.request_id;
    if (!accept) {
      ++diagnostics_.inbound_denied;
      envelope.kind = LanSignalingMessageKind::connect_deny;
      const auto sent = send_via_route(source, envelope);
      if (!sent) {
        return sent;
      }
      return Result<void>::failure(
          coordinator_error(ErrorCode::permission, "connect_request_denied"));
    }
    envelope.kind = LanSignalingMessageKind::connect_accept;
    const auto sent = send_via_route(source, envelope);
    if (!sent) {
      return sent;
    }
    Attempt attempt;
    attempt.request_id = message.request_id;
    attempt.peer = message.peer;
    attempt.inbound = true;
    attempt.route = source;
    attempt.phase = SignalingAttemptPhase::responding;
    attempt.created_at = now;
    attempts_.emplace(attempt.request_id, std::move(attempt));
    ++diagnostics_.inbound_accepted;
    update_attempt_peak();
    return Result<void>::success();
  }

  Result<void> handle_connect_accept(const SignalingEnvelope& message,
                                     SignalingRouteKind source) {
    if (!message.payload.empty()) {
      ++diagnostics_.parse_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::protocol, "connect_accept_payload_invalid"));
    }
    auto* attempt = find(message.request_id);
    if (attempt == nullptr || attempt->inbound ||
        attempt->phase != SignalingAttemptPhase::requesting ||
        attempt->route != source || attempt->peer != message.peer) {
      ++diagnostics_.binding_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::signaling, "connect_accept_unmatched"));
    }
    attempt->phase = SignalingAttemptPhase::accepted;
    if (delegate_->on_outbound_accepted) {
      delegate_->on_outbound_accepted(snapshot_of(*attempt, config_.attempt_ttl));
    }
    return Result<void>::success();
  }

  Result<void> handle_connect_deny(const SignalingEnvelope& message,
                                   SignalingRouteKind source) {
    if (!message.payload.empty()) {
      ++diagnostics_.parse_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::protocol, "connect_deny_payload_invalid"));
    }
    auto* attempt = find(message.request_id);
    if (attempt == nullptr || attempt->inbound || attempt->route != source ||
        attempt->peer != message.peer) {
      ++diagnostics_.binding_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::signaling, "connect_deny_unmatched"));
    }
    const auto snapshot = snapshot_of(*attempt, config_.attempt_ttl);
    attempts_.erase(message.request_id);
    ++diagnostics_.attempts_closed;
    update_current_attempts();
    if (delegate_->on_attempt_error) {
      delegate_->on_attempt_error(
          snapshot, coordinator_error(ErrorCode::remote_error, "connect_denied"));
    }
    return Result<void>::success();
  }

  Result<void> handle_signed_offer(const SignalingEnvelope& message, SignalingRouteKind source,
                                   std::uint64_t now_unix_ms) {
    auto* attempt = find(message.request_id);
    if (attempt == nullptr || !attempt->inbound ||
        attempt->phase != SignalingAttemptPhase::responding ||
        attempt->route != source || attempt->peer != message.peer) {
      ++diagnostics_.binding_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::signaling, "signed_offer_unmatched"));
    }
    auto parsed = parse_signed_offer(message.payload);
    if (!parsed) {
      ++diagnostics_.parse_rejected;
      return Result<void>::failure(*parsed.error_if());
    }
    const auto& offer = *parsed.value_if();
    if (offer.binding.initiator != attempt->peer ||
        offer.binding.responder != config_.local ||
        offer.binding.request_id != attempt->request_id) {
      ++diagnostics_.binding_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::signaling, "signed_offer_binding_mismatch"));
    }
    auto public_key = lookup_peer_identity(offer.binding.initiator);
    if (!public_key) {
      ++diagnostics_.signature_rejected;
      return Result<void>::failure(*public_key.error_if());
    }
    auto verified = verify_signed_offer(
        offer,
        std::span<const std::byte>{public_key.value_if()->data(),
                                   public_key.value_if()->size()},
        now_unix_ms);
    if (!verified) {
      ++diagnostics_.signature_rejected;
      return Result<void>::failure(*verified.error_if());
    }
    auto ufrag = parse_sdp_ice_ufrag(offer.sdp);
    if (!ufrag) {
      ++diagnostics_.binding_rejected;
      return Result<void>::failure(*ufrag.error_if());
    }
    auto canonical = canonical_signed_offer(offer);
    if (!canonical) {
      return Result<void>::failure(*canonical.error_if());
    }
    auto replay = replay_.admit(SigningDomain::offer, offer.binding.initiator.device_id,
                                offer.binding.request_id, offer.binding.session_id,
                                offer.binding.initiator_nonce, std::nullopt, std::nullopt);
    if (!replay) {
      return Result<void>::failure(*replay.error_if());
    }
    if (*replay.value_if() == SignalingReplayDecision::duplicate) {
      ++diagnostics_.replay_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::protocol, "signed_offer_replayed"));
    }
    if (*replay.value_if() == SignalingReplayDecision::capacity_rejected) {
      ++diagnostics_.replay_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::resource_exhausted, "replay_cache_saturated"));
    }
    attempt->session_id = offer.binding.session_id;
    attempt->initiator_nonce = offer.binding.initiator_nonce;
    attempt->verified_offer = offer;
    attempt->canonical_offer = *canonical.value_if();
    attempt->peer_fingerprint = offer.dtls_fingerprint;
    attempt->peer_ufrag = *ufrag.value_if();
    attempt->phase = SignalingAttemptPhase::offered;
    if (delegate_->on_verified_offer) {
      delegate_->on_verified_offer(snapshot_of(*attempt, config_.attempt_ttl), offer);
    }
    ++diagnostics_.messages_dispatched;
    return Result<void>::success();
  }

  Result<void> handle_signed_answer(const SignalingEnvelope& message,
                                    SignalingRouteKind source,
                                    std::uint64_t now_unix_ms) {
    auto* attempt = find(message.request_id);
    if (attempt == nullptr || attempt->inbound ||
        attempt->phase != SignalingAttemptPhase::offered ||
        attempt->route != source || attempt->peer != message.peer ||
        !attempt->canonical_offer.has_value()) {
      ++diagnostics_.binding_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::signaling, "signed_answer_unmatched"));
    }
    auto parsed = parse_signed_answer(message.payload);
    if (!parsed) {
      ++diagnostics_.parse_rejected;
      return Result<void>::failure(*parsed.error_if());
    }
    const auto& answer = *parsed.value_if();
    if (answer.binding.initiator != config_.local ||
        answer.binding.responder != attempt->peer ||
        answer.binding.request_id != attempt->request_id ||
        answer.binding.session_id != attempt->session_id ||
        answer.binding.initiator_nonce != attempt->initiator_nonce) {
      ++diagnostics_.binding_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::signaling, "signed_answer_binding_mismatch"));
    }
    auto public_key = lookup_peer_identity(answer.binding.responder);
    if (!public_key) {
      ++diagnostics_.signature_rejected;
      return Result<void>::failure(*public_key.error_if());
    }
    auto verified = verify_signed_answer(
        answer,
        std::span<const std::byte>{public_key.value_if()->data(),
                                   public_key.value_if()->size()},
        now_unix_ms);
    if (!verified) {
      ++diagnostics_.signature_rejected;
      return Result<void>::failure(*verified.error_if());
    }
    auto ufrag = parse_sdp_ice_ufrag(answer.sdp);
    if (!ufrag) {
      ++diagnostics_.binding_rejected;
      return Result<void>::failure(*ufrag.error_if());
    }
    auto canonical = canonical_signed_answer(answer);
    if (!canonical) {
      return Result<void>::failure(*canonical.error_if());
    }
    auto transcript =
        hash_signaling_transcript(*attempt->canonical_offer, *canonical.value_if());
    if (!transcript) {
      return Result<void>::failure(*transcript.error_if());
    }
    auto replay = replay_.admit(SigningDomain::answer, answer.binding.responder.device_id,
                                answer.binding.request_id, answer.binding.session_id,
                                answer.binding.initiator_nonce,
                                answer.binding.responder_nonce, std::nullopt);
    if (!replay) {
      return Result<void>::failure(*replay.error_if());
    }
    if (*replay.value_if() == SignalingReplayDecision::duplicate) {
      ++diagnostics_.replay_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::protocol, "signed_answer_replayed"));
    }
    if (*replay.value_if() == SignalingReplayDecision::capacity_rejected) {
      ++diagnostics_.replay_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::resource_exhausted, "replay_cache_saturated"));
    }
    attempt->responder_nonce = answer.binding.responder_nonce;
    attempt->canonical_answer = *canonical.value_if();
    attempt->transcript = *transcript.value_if();
    attempt->peer_fingerprint = answer.dtls_fingerprint;
    attempt->peer_ufrag = *ufrag.value_if();
    attempt->phase = SignalingAttemptPhase::answered;
    if (delegate_->on_verified_answer) {
      delegate_->on_verified_answer(snapshot_of(*attempt, config_.attempt_ttl), answer,
                                   *transcript.value_if());
    }
    ++diagnostics_.messages_dispatched;
    return Result<void>::success();
  }

  Result<void> handle_signed_candidate(const SignalingEnvelope& message,
                                       SignalingRouteKind source,
                                       std::uint64_t now_unix_ms) {
    auto* attempt = find(message.request_id);
    if (attempt == nullptr || attempt->route != source || attempt->peer != message.peer ||
        (attempt->phase != SignalingAttemptPhase::answered &&
         attempt->phase != SignalingAttemptPhase::candidates) ||
        !attempt->transcript.has_value() || !attempt->responder_nonce.has_value()) {
      ++diagnostics_.binding_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::signaling, "signed_candidate_unmatched"));
    }
    auto parsed = parse_signed_candidate(message.payload);
    if (!parsed) {
      ++diagnostics_.parse_rejected;
      return Result<void>::failure(*parsed.error_if());
    }
    const auto& candidate = *parsed.value_if();
    if (candidate.binding.initiator != (attempt->inbound ? attempt->peer : config_.local) ||
        candidate.binding.responder != (attempt->inbound ? config_.local : attempt->peer) ||
        candidate.binding.request_id != attempt->request_id ||
        candidate.binding.session_id != attempt->session_id ||
        candidate.binding.initiator_nonce != attempt->initiator_nonce ||
        candidate.binding.responder_nonce != attempt->responder_nonce) {
      ++diagnostics_.binding_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::signaling, "signed_candidate_binding_mismatch"));
    }
    auto public_key = lookup_peer_identity(attempt->peer);
    if (!public_key) {
      ++diagnostics_.signature_rejected;
      return Result<void>::failure(*public_key.error_if());
    }
    auto owner = verify_signed_candidate(
        candidate,
        std::span<const std::byte>{public_key.value_if()->data(),
                                   public_key.value_if()->size()},
        now_unix_ms);
    if (!owner) {
      ++diagnostics_.signature_rejected;
      return Result<void>::failure(*owner.error_if());
    }
    const auto expected_owner = attempt->inbound ? SignalingCandidateOwner::initiator
                                                 : SignalingCandidateOwner::responder;
    if (*owner.value_if() != expected_owner) {
      ++diagnostics_.binding_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::authentication, "candidate_owner_not_peer"));
    }
    if (candidate.signaling_transcript_sha256 != *attempt->transcript ||
        candidate.owner_ice_ufrag != attempt->peer_ufrag ||
        candidate.owner_dtls_fingerprint != attempt->peer_fingerprint) {
      ++diagnostics_.binding_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::signaling, "signed_candidate_transcript_mismatch"));
    }
    if (attempt->received_candidates + 1U > config_.max_candidates_per_attempt) {
      ++diagnostics_.candidate_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::resource_exhausted, "candidate_budget_exhausted"));
    }
    auto replay = replay_.admit(SigningDomain::candidate, attempt->peer.device_id,
                                candidate.binding.request_id, candidate.binding.session_id,
                                candidate.binding.initiator_nonce,
                                candidate.binding.responder_nonce, candidate.sequence);
    if (!replay) {
      return Result<void>::failure(*replay.error_if());
    }
    if (*replay.value_if() == SignalingReplayDecision::duplicate) {
      // Sequence duplicates are idempotent only when the entire signed object is
      // byte-identical to the previously accepted one.
      const auto stored = attempt->accepted_candidate_payloads.find(candidate.sequence);
      if (stored != attempt->accepted_candidate_payloads.end() &&
          stored->second == message.payload) {
        ++diagnostics_.replay_rejected;
        return Result<void>::success();
      }
      ++diagnostics_.candidate_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::protocol, "candidate_duplicate_bytes_differ"));
    }
    if (*replay.value_if() == SignalingReplayDecision::capacity_rejected) {
      ++diagnostics_.replay_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::resource_exhausted, "replay_cache_saturated"));
    }
    if (candidate.sequence <= attempt->peer_sequence) {
      ++diagnostics_.candidate_rejected;
      return Result<void>::failure(
          coordinator_error(ErrorCode::protocol, "candidate_sequence_not_increasing"));
    }
    attempt->peer_sequence = candidate.sequence;
    attempt->accepted_candidate_payloads.emplace(
        candidate.sequence,
        std::vector<std::byte>{message.payload.begin(), message.payload.end()});
    ++attempt->received_candidates;
    attempt->phase = SignalingAttemptPhase::candidates;
    if (delegate_->on_verified_candidate) {
      delegate_->on_verified_candidate(snapshot_of(*attempt, config_.attempt_ttl),
                                      candidate);
    }
    ++diagnostics_.messages_dispatched;
    return Result<void>::success();
  }

  Result<std::vector<std::byte>> lookup_peer_identity(const DeviceEndpointKey& peer) {
    if (!delegate_->peer_identity) {
      return Result<std::vector<std::byte>>::failure(
          coordinator_error(ErrorCode::authentication, "peer_identity_lookup_missing"));
    }
    auto key = delegate_->peer_identity(peer);
    if (!key.has_value()) {
      return Result<std::vector<std::byte>>::failure(
          coordinator_error(ErrorCode::authentication, "peer_identity_unknown"));
    }
    return Result<std::vector<std::byte>>::success(
        std::vector<std::byte>{key->begin(), key->end()});
  }

  SignalingCoordinatorConfig config_;
  std::shared_ptr<SignalingDelegate> delegate_;
  SignalingReplayCache replay_;
  std::map<SignalingRouteKind, SignalingRoute*> routes_;
  std::map<RequestId, Attempt> attempts_;
  std::map<DeviceEndpointKey, RateEntry> rate_entries_;
  SignalingCoordinatorDiagnostics diagnostics_;
};

std::string_view signaling_attempt_phase_name(SignalingAttemptPhase phase) noexcept {
  switch (phase) {
    case SignalingAttemptPhase::requesting:
      return "requesting";
    case SignalingAttemptPhase::accepted:
      return "accepted";
    case SignalingAttemptPhase::responding:
      return "responding";
    case SignalingAttemptPhase::offered:
      return "offered";
    case SignalingAttemptPhase::answered:
      return "answered";
    case SignalingAttemptPhase::candidates:
      return "candidates";
    case SignalingAttemptPhase::closed:
      return "closed";
  }
  return "unknown";
}

SignalingCoordinator::SignalingCoordinator(SignalingCoordinator&& other) noexcept = default;
SignalingCoordinator& SignalingCoordinator::operator=(SignalingCoordinator&&) noexcept =
    default;
SignalingCoordinator::~SignalingCoordinator() = default;

Result<SignalingCoordinator> SignalingCoordinator::create(
    SignalingCoordinatorConfig config, std::shared_ptr<SignalingDelegate> delegate) {
  if (delegate == nullptr) {
    return Result<SignalingCoordinator>::failure(
        coordinator_error(ErrorCode::configuration, "delegate_missing"));
  }
  auto replay = SignalingReplayCache::create(config.replay_policy);
  if (!replay) {
    return Result<SignalingCoordinator>::failure(*replay.error_if());
  }
  auto impl = std::make_unique<Impl>(std::move(config), std::move(delegate),
                                     std::move(*replay.value_if()));
  auto checked = impl->check_create();
  if (!checked) {
    return Result<SignalingCoordinator>::failure(*checked.error_if());
  }
  return Result<SignalingCoordinator>::success(SignalingCoordinator(std::move(impl)));
}

void SignalingCoordinator::attach_route(SignalingRoute* route) { impl_->attach_route(route); }

Result<RequestId> SignalingCoordinator::begin_attempt(
    DeviceEndpointKey peer, SignalingRouteKind route,
    std::chrono::steady_clock::time_point now) {
  return impl_->begin_attempt(peer, route, now);
}

Result<void> SignalingCoordinator::send_local_offer(
    RequestId request_id, std::span<const std::byte> sdp,
    const DtlsFingerprint& fingerprint, std::chrono::steady_clock::time_point now,
    std::uint64_t now_unix_milliseconds) {
  return impl_->send_local_offer(request_id, sdp, fingerprint, now, now_unix_milliseconds);
}

Result<void> SignalingCoordinator::send_local_answer(
    RequestId request_id, std::span<const std::byte> sdp,
    const DtlsFingerprint& fingerprint, std::chrono::steady_clock::time_point now,
    std::uint64_t now_unix_milliseconds) {
  return impl_->send_local_answer(request_id, sdp, fingerprint, now, now_unix_milliseconds);
}

Result<void> SignalingCoordinator::send_local_candidate(
    RequestId request_id, std::span<const std::byte> candidate,
    std::chrono::steady_clock::time_point now, std::uint64_t now_unix_milliseconds) {
  return impl_->send_local_candidate(request_id, candidate, now, now_unix_milliseconds);
}

Result<void> SignalingCoordinator::handle_message(
    const SignalingEnvelope& message, SignalingRouteKind source,
    std::chrono::steady_clock::time_point now, std::uint64_t now_unix_milliseconds) {
  return impl_->handle_message(message, source, now, now_unix_milliseconds);
}

Result<void> SignalingCoordinator::cancel_attempt(
    RequestId request_id, std::chrono::steady_clock::time_point now) {
  return impl_->cancel_attempt(request_id, now);
}

void SignalingCoordinator::expire(std::chrono::steady_clock::time_point now) {
  impl_->expire(now);
}

std::vector<SignalingAttemptSnapshot> SignalingCoordinator::attempts() const {
  return impl_->attempts();
}

SignalingCoordinatorDiagnostics SignalingCoordinator::diagnostics() const noexcept {
  return impl_->diagnostics();
}

Result<VerifiedSessionBinding> SignalingCoordinator::verified_session_binding(
    RequestId request_id, std::uint64_t session_epoch) const {
  return impl_->verified_session_binding(request_id, session_epoch);
}

SignalingCoordinator::SignalingCoordinator(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

}  // namespace heyaki
