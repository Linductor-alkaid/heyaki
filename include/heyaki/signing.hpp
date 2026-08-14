#pragma once

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>

#include <cstddef>
#include <cstdint>
#include <array>
#include <span>
#include <string_view>
#include <vector>

namespace heyaki {

enum class SigningDomain : std::uint8_t {
  enrollment,
  enrollment_record,
  endpoint_record,
  service_manifest,
  offer,
  answer,
  candidate,
  session_hello,
  trust_grant,
};

struct CanonicalField {
  std::uint16_t number{};
  std::vector<std::byte> value;
};

inline constexpr std::size_t max_canonical_signing_bytes = 1024U * 1024U;
inline constexpr std::size_t signaling_transcript_sha256_bytes = 32U;
using SignalingTranscriptSha256 = std::array<std::byte, signaling_transcript_sha256_bytes>;

[[nodiscard]] std::string_view signing_domain_separator(SigningDomain domain) noexcept;
[[nodiscard]] Result<std::vector<std::byte>> canonicalize_for_signature(
    SigningDomain domain, std::span<const CanonicalField> fields);
[[nodiscard]] Result<SignalingTranscriptSha256> hash_signaling_transcript(
    std::span<const std::byte> canonical_offer, std::span<const std::byte> canonical_answer);

[[nodiscard]] std::vector<std::byte> canonical_uint16(std::uint16_t value);
[[nodiscard]] std::vector<std::byte> canonical_uint32(std::uint32_t value);
[[nodiscard]] std::vector<std::byte> canonical_uint64(std::uint64_t value);
[[nodiscard]] std::vector<std::byte> canonical_bytes(const DeviceId& value);
[[nodiscard]] std::vector<std::byte> canonical_bytes(const EndpointId& value);
[[nodiscard]] std::vector<std::byte> canonical_bytes(const SessionId& value);
[[nodiscard]] std::vector<std::byte> canonical_bytes(const RequestId& value);
[[nodiscard]] std::vector<std::byte> canonical_bytes(const TransferId& value);

}  // namespace heyaki
