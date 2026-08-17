#pragma once

#include <heyaki/identity.hpp>
#include <heyaki/lan_directory.hpp>
#include <heyaki/signing.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

inline constexpr std::size_t signaling_nonce_bytes = 32U;
using SignalingNonce = std::array<std::byte, signaling_nonce_bytes>;
inline constexpr std::size_t dtls_fingerprint_bytes = 32U;
using DtlsFingerprint = std::array<std::byte, dtls_fingerprint_bytes>;
inline constexpr std::size_t min_signaling_ice_ufrag_bytes = 4U;
inline constexpr std::size_t max_signaling_ice_ufrag_bytes = 256U;
inline constexpr std::size_t max_signaling_sdp_bytes = 16U * 1024U;
inline constexpr std::size_t max_signaling_candidate_bytes = 1024U;
// Encoded signed signaling objects share the bounded LAN signaling frame payload budget.
inline constexpr std::size_t max_signaling_object_bytes = max_lan_signaling_payload_bytes;

struct SignalBinding {
  DeviceEndpointKey initiator;
  DeviceEndpointKey responder;
  RequestId request_id;
  SessionId session_id;
  SignalingNonce initiator_nonce{};
  std::uint64_t expires_unix_milliseconds{};
  std::optional<SignalingNonce> responder_nonce;

  friend constexpr bool operator==(const SignalBinding&,
                                   const SignalBinding&) noexcept = default;
};

struct SignedOffer {
  SignalBinding binding;
  std::vector<std::byte> sdp;
  DtlsFingerprint dtls_fingerprint{};
  IdentitySignature signature{};
};

struct SignedAnswer {
  SignalBinding binding;
  std::vector<std::byte> sdp;
  DtlsFingerprint dtls_fingerprint{};
  IdentitySignature signature{};
};

struct SignedCandidate {
  SignalBinding binding;
  std::uint32_t sequence{};
  std::vector<std::byte> candidate;
  SignalingTranscriptSha256 signaling_transcript_sha256{};
  std::string owner_ice_ufrag;
  DtlsFingerprint owner_dtls_fingerprint{};
  IdentitySignature signature{};
};

[[nodiscard]] Result<std::vector<std::byte>> canonical_signed_offer(const SignedOffer& offer);
[[nodiscard]] Result<std::vector<std::byte>> canonical_signed_answer(const SignedAnswer& answer);
[[nodiscard]] Result<std::vector<std::byte>> canonical_signed_candidate(
    const SignedCandidate& candidate);

[[nodiscard]] Result<void> validate_signed_offer(const SignedOffer& offer);
[[nodiscard]] Result<void> validate_signed_answer(const SignedAnswer& answer);
[[nodiscard]] Result<void> validate_signed_candidate(const SignedCandidate& candidate);

[[nodiscard]] Result<void> sign_signed_offer(SignedOffer& offer,
                                             const IdentityKeyPair& identity);
[[nodiscard]] Result<void> sign_signed_answer(SignedAnswer& answer,
                                              const IdentityKeyPair& identity);
[[nodiscard]] Result<void> sign_signed_candidate(SignedCandidate& candidate,
                                                 const IdentityKeyPair& identity);

// Verification covers structural validation, the signed expiry window, the Ed25519 signature
// over the canonical bytes, and that the signer's public key derives the bound DeviceId.
// The verifier must supply the peer identity public key it resolved out of band.
[[nodiscard]] Result<void> verify_signed_offer(
    const SignedOffer& offer, std::span<const std::byte> initiator_public_key,
    std::uint64_t now_unix_milliseconds);
[[nodiscard]] Result<void> verify_signed_answer(
    const SignedAnswer& answer, std::span<const std::byte> responder_public_key,
    std::uint64_t now_unix_milliseconds);
// A candidate is signed by its owner, which is either the initiator or the responder of the
// binding; the returned role states which side the verified signing key belongs to.
enum class SignalingCandidateOwner : std::uint8_t {
  initiator,
  responder,
};
[[nodiscard]] Result<SignalingCandidateOwner> verify_signed_candidate(
    const SignedCandidate& candidate, std::span<const std::byte> owner_public_key,
    std::uint64_t now_unix_milliseconds);

[[nodiscard]] Result<std::vector<std::byte>> encode_signed_offer(const SignedOffer& offer);
[[nodiscard]] Result<SignedOffer> parse_signed_offer(std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_signed_answer(const SignedAnswer& answer);
[[nodiscard]] Result<SignedAnswer> parse_signed_answer(std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_signed_candidate(
    const SignedCandidate& candidate);
[[nodiscard]] Result<SignedCandidate> parse_signed_candidate(std::span<const std::byte> payload);

// Extracts the owner's ICE ufrag from an offer/answer SDP. Candidate binding checks compare
// the signed candidate ufrag against this value.
[[nodiscard]] Result<std::string> parse_sdp_ice_ufrag(std::span<const std::byte> sdp);

[[nodiscard]] std::string_view signaling_candidate_owner_name(
    SignalingCandidateOwner owner) noexcept;

}  // namespace heyaki
