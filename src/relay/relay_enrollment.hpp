#pragma once

#include <heyaki/identity.hpp>
#include <heyaki/protocol.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

inline constexpr std::size_t relay_id_bytes = 32U;
inline constexpr std::size_t enrollment_challenge_nonce_bytes = 32U;
inline constexpr std::size_t max_enrollment_request_bytes = 64U * 1024U;
// Password-admission proof: 32 raw Argon2id output bytes carried in the
// optional `EnrollmentRequest.enrollment_password_proof` wire field. The proof
// is a secret the same way `bootstrap_token` is: never logged and never part
// of the signed canonical object.
inline constexpr std::size_t enrollment_password_proof_bytes = 32U;
// Owner enrollment passwords may be any UTF-8 text up to the shared password
// policy ceiling; the minimum-strength side is enforced where the password is
// set (relay --init), not on the wire.
inline constexpr std::size_t enrollment_password_max_bytes = 256U;
// Fixed client-side proof-derivation parameters (wire contract, independent of
// the server verifier calibration). Frozen in docs/operations/parameter-freeze.md.
inline constexpr std::uint32_t enrollment_proof_argon2_operations = 2U;
inline constexpr std::size_t enrollment_proof_argon2_memory_bytes = 64U * 1024U * 1024U;

using RelayId = std::array<std::byte, relay_id_bytes>;
using EnrollmentChallengeNonce =
    std::array<std::byte, enrollment_challenge_nonce_bytes>;
using EnrollmentPasswordProof =
    std::array<std::byte, enrollment_password_proof_bytes>;

struct EnrollmentChallenge {
  RelayId relay_id{};
  EnrollmentChallengeNonce nonce{};
  std::uint64_t expires_unix_milliseconds{};
};

struct EnrollmentRequest {
  DeviceId device_id;
  EndpointId endpoint_id;
  IdentityPublicKey identity_public_key{};
  EnrollmentChallengeNonce challenge_nonce{};
  std::string tenant;
  // Token mode: bootstrap token. Password mode: empty. Exactly one of
  // `bootstrap_token` and `password_proof` is present.
  std::string bootstrap_token;
  // Password mode: challenge-bound Argon2id proof. Token mode: nullopt.
  std::optional<EnrollmentPasswordProof> password_proof;
  ProtocolVersion protocol_version{current_protocol_version};
  CapabilitySet supported{};
  CapabilitySet required{};
  std::uint64_t expires_unix_milliseconds{};
  IdentitySignature signature{};
};

[[nodiscard]] Result<EnrollmentChallenge> create_enrollment_challenge(
    RelayId relay_id, std::uint64_t now_unix_milliseconds,
    std::chrono::milliseconds validity = std::chrono::milliseconds{60U * 1000U});
[[nodiscard]] Result<std::vector<std::byte>> encode_enrollment_challenge(
    const EnrollmentChallenge& challenge);
[[nodiscard]] Result<EnrollmentChallenge> parse_enrollment_challenge(
    std::span<const std::byte> payload);
// Derives the relay-bound password proof for password-mode enrollment:
// `proof = Argon2id(password, BLAKE2b-128(domain_tag || relay_id))` with the
// fixed wire parameters above. The proof is stable per (relay, password), so
// the relay holds a static Argon2id verifier of the proof; it is a bearer
// admission credential in the same class as a bootstrap token (TLS-protected
// in transit, never logged, relay-bound so a captured proof does not transfer
// to other services). Challenge freshness comes from the existing single-use
// challenge + device-signature chain.
[[nodiscard]] Result<EnrollmentPasswordProof> derive_enrollment_password_proof(
    std::string_view password, RelayId relay_id);
[[nodiscard]] Result<std::vector<std::byte>> encode_enrollment_request(
    const EnrollmentRequest& request);
[[nodiscard]] Result<EnrollmentRequest> parse_enrollment_request(
    std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> canonical_enrollment_request(
    const EnrollmentRequest& request, RelayId relay_id);
[[nodiscard]] Result<void> sign_enrollment_request(EnrollmentRequest& request,
                                                   RelayId relay_id,
                                                   const IdentityKeyPair& identity);
[[nodiscard]] Result<void> validate_enrollment_request(
    const EnrollmentRequest& request, const EnrollmentChallenge& challenge,
    std::uint64_t now_unix_milliseconds);

}  // namespace heyaki
