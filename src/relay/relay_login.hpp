#pragma once

#include "relay_database.hpp"
#include "relay_enrollment.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace heyaki {

inline constexpr std::size_t max_relay_login_request_bytes = 64U * 1024U;

using RelayLoginChallenge = EnrollmentChallenge;
using RelayLoginNonce = EnrollmentChallengeNonce;

struct RelayLoginRequest {
  DeviceId device_id;
  EndpointId endpoint_id;
  IdentityPublicKey identity_public_key{};
  RelayLoginNonce challenge_nonce{};
  std::string tenant;
  ProtocolVersion protocol_version{current_protocol_version};
  CapabilitySet supported{};
  CapabilitySet required{};
  std::uint64_t enrollment_generation{};
  std::uint64_t expires_unix_milliseconds{};
  IdentitySignature signature{};
};

[[nodiscard]] Result<std::vector<std::byte>> encode_relay_login_request(
    const RelayLoginRequest& request);
[[nodiscard]] Result<RelayLoginRequest> parse_relay_login_request(
    std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> canonical_relay_login_request(
    const RelayLoginRequest& request, RelayId relay_id);
[[nodiscard]] Result<void> sign_relay_login_request(RelayLoginRequest& request,
                                                    RelayId relay_id,
                                                    const IdentityKeyPair& identity);
[[nodiscard]] Result<void> validate_relay_login_request(
    const RelayLoginRequest& request, const RelayLoginChallenge& challenge,
    const RelayDeviceRecord& device, std::uint64_t now_unix_milliseconds);

}  // namespace heyaki
