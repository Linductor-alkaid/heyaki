#pragma once

#include <heyaki/identity.hpp>
#include <heyaki/lan_directory.hpp>
#include <heyaki/signaling_protocol.hpp>
#include <heyaki/signaling_replay_cache.hpp>
#include <heyaki/session_protocol.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

namespace heyaki {

// Protocol 1.2 session restart: an authenticated session renegotiates a
// replacement ICE/DTLS transport by exchanging fresh signed offer/answer and
// candidate objects over the session's own control channel. The SessionId is
// preserved and the successor session runs at current_epoch + 1. The pinned
// libjuice backend cannot change ICE credentials on a live association, so the
// "restart" deliberately negotiates a NEW transport while the old control
// channel authenticates the renegotiation; it is not a lossless migration.
inline constexpr std::size_t max_session_restart_candidates = 128U;
inline constexpr std::uint64_t session_restart_validity_milliseconds = 30000U;

struct SessionRestartDiagnostics {
  std::uint64_t offers_admitted{};
  std::uint64_t answers_admitted{};
  std::uint64_t candidates_admitted{};
  std::uint64_t duplicates_ignored{};
  std::uint64_t replay_rejected{};
  std::uint64_t glare_suppressed{};
  std::uint64_t rejected{};
};

// Facts of the authenticated session that every restart object is bound to.
struct SessionRestartContext {
  DeviceEndpointKey local;
  DeviceEndpointKey peer;
  SessionId session_id;
  std::uint64_t current_epoch{1U};
  IdentityPublicKey peer_public_key{};
  ReplayCachePolicy replay_policy{};
};

// Deterministic glare resolution when both peers spontaneously initiate a
// restart: the offer whose request id compares greater in big-endian byte
// order wins; both peers reach the same verdict without extra round trips.
[[nodiscard]] bool session_restart_offer_wins(const RequestId& candidate,
                                              const RequestId& other) noexcept;

// Signs the restart objects. They reuse the frozen heyaki.offer.v1,
// heyaki.answer.v1, and heyaki.candidate.v1 canonical domains verbatim; the
// restart identity comes from the preserved SessionId plus the fresh request id
// and nonces, not from a new signing domain.
[[nodiscard]] Result<std::vector<std::byte>> build_session_restart_offer(
    const SessionRestartContext& context, const IdentityKeyPair& identity,
    const RequestId& request_id, const SignalingNonce& initiator_nonce,
    std::span<const std::byte> sdp, const DtlsFingerprint& fingerprint,
    std::uint64_t now_unix_milliseconds);
[[nodiscard]] Result<std::vector<std::byte>> build_session_restart_answer(
    const SessionRestartContext& context, const IdentityKeyPair& identity,
    const RequestId& request_id, const SignalingNonce& initiator_nonce,
    const SignalingNonce& responder_nonce, std::span<const std::byte> sdp,
    const DtlsFingerprint& fingerprint, std::uint64_t now_unix_milliseconds);
[[nodiscard]] Result<std::vector<std::byte>> build_session_restart_candidate(
    const IdentityKeyPair& identity, const SignalBinding& binding,
    std::uint32_t sequence, std::span<const std::byte> candidate,
    const SignalingTranscriptSha256& transcript, std::string_view owner_ufrag,
    const DtlsFingerprint& owner_fingerprint, std::uint64_t now_unix_milliseconds);

struct AdmittedSessionRestartOffer {
  SignedOffer offer;
  std::vector<std::byte> canonical_offer;
  std::uint64_t next_epoch{};
  // True when the local side had its own restart in flight and this offer lost
  // the glare comparison; the caller must abort its own attempt first and then
  // answer this offer as the responder.
  bool supersedes_local_restart{};
};

struct AdmittedSessionRestartAnswer {
  SignedAnswer answer;
  std::vector<std::byte> canonical_answer;
  SignalingTranscriptSha256 transcript{};
};

struct AdmittedSessionRestartCandidate {
  SignedCandidate candidate;
};

// Admission for inbound restart objects on one side of an authenticated
// session. A failure Result is a protocol error and must close the session;
// a successful Result with no value means the payload was a byte-identical
// duplicate or a glare-suppressed offer and is ignored without state change.
class SessionRestartAdmission {
 public:
  SessionRestartAdmission(SessionRestartContext context);

  // Marks a locally initiated restart (with its initiator nonce and the
  // canonical bytes of the signed offer this side produced) so simultaneous
  // peer offers resolve through the deterministic glare rule and the answer
  // transcript can be computed.
  void set_local_restart(const RequestId& request_id,
                         const SignalingNonce& restart_initiator_nonce,
                         std::span<const std::byte> canonical_offer);

  // Responder completion: records the locally generated responder nonce and
  // the canonical answer bytes so the transcript and candidate admission are
  // ready before the peer's candidates arrive.
  [[nodiscard]] Result<void> set_local_restart_answer(
      const SignalingNonce& responder_nonce,
      std::span<const std::byte> canonical_answer);

  [[nodiscard]] Result<std::optional<AdmittedSessionRestartOffer>> admit_offer(
      std::span<const std::byte> payload, std::uint64_t now_unix_milliseconds);
  [[nodiscard]] Result<std::optional<AdmittedSessionRestartAnswer>> admit_answer(
      std::span<const std::byte> payload, std::uint64_t now_unix_milliseconds);
  [[nodiscard]] Result<std::optional<AdmittedSessionRestartCandidate>> admit_candidate(
      std::span<const std::byte> payload, std::uint64_t now_unix_milliseconds);

  // Verified facts for the successor session, available once the restart
  // offer/answer pair has been admitted on this side.
  [[nodiscard]] std::optional<SignalingNonce> initiator_nonce() const noexcept;
  [[nodiscard]] std::optional<SignalingNonce> responder_nonce() const noexcept;
  [[nodiscard]] std::optional<SignalingTranscriptSha256> transcript() const noexcept;
  [[nodiscard]] std::optional<DtlsFingerprint> peer_fingerprint() const noexcept;
  [[nodiscard]] std::optional<std::string> peer_ufrag() const noexcept;
  [[nodiscard]] bool answer_admitted() const noexcept;
  [[nodiscard]] const SessionRestartDiagnostics& diagnostics() const noexcept;

 private:
  SessionRestartContext context_;
  std::optional<SignalingReplayCache> replay_;
  SessionRestartDiagnostics diagnostics_{};
  std::optional<RequestId> accepted_request_;
  std::optional<std::vector<std::byte>> canonical_offer_;
  std::optional<SignalingNonce> initiator_nonce_;
  std::optional<SignalingNonce> responder_nonce_;
  std::optional<SignalingTranscriptSha256> transcript_;
  std::optional<DtlsFingerprint> peer_fingerprint_;
  std::optional<std::string> peer_ufrag_;
  std::optional<RequestId> local_restart_;
  std::map<std::uint32_t, std::vector<std::byte>> accepted_candidates_;
  std::uint32_t peer_candidate_sequence_{0U};
  std::uint32_t admitted_candidates_{0U};
};

}  // namespace heyaki
