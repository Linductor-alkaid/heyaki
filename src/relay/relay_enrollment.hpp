#pragma once

#include <heyaki/identity.hpp>
#include <heyaki/protocol.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace heyaki {

inline constexpr std::size_t relay_id_bytes = 32U;
inline constexpr std::size_t enrollment_challenge_nonce_bytes = 32U;
inline constexpr std::size_t max_enrollment_request_bytes = 64U * 1024U;

using RelayId = std::array<std::byte, relay_id_bytes>;
using EnrollmentChallengeNonce =
    std::array<std::byte, enrollment_challenge_nonce_bytes>;

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
  std::string bootstrap_token;
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
