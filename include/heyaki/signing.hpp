#pragma once

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace heyaki {

enum class SigningDomain : std::uint8_t {
  enrollment,
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

[[nodiscard]] std::string_view signing_domain_separator(SigningDomain domain) noexcept;
[[nodiscard]] Result<std::vector<std::byte>> canonicalize_for_signature(
    SigningDomain domain, std::span<const CanonicalField> fields);

[[nodiscard]] std::vector<std::byte> canonical_uint16(std::uint16_t value);
[[nodiscard]] std::vector<std::byte> canonical_uint32(std::uint32_t value);
[[nodiscard]] std::vector<std::byte> canonical_uint64(std::uint64_t value);
[[nodiscard]] std::vector<std::byte> canonical_bytes(const DeviceId& value);
[[nodiscard]] std::vector<std::byte> canonical_bytes(const EndpointId& value);
[[nodiscard]] std::vector<std::byte> canonical_bytes(const SessionId& value);

}  // namespace heyaki
