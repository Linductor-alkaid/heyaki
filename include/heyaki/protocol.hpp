#pragma once

#include <heyaki/error.hpp>

#include <cstdint>

namespace heyaki {

struct ProtocolVersion {
  std::uint16_t major{1U};
  std::uint16_t minor{0U};

  friend constexpr bool operator==(ProtocolVersion, ProtocolVersion) noexcept = default;
};

enum class Capability : std::uint64_t {
  enrollment = 1ULL << 0U,
  signaling = 1ULL << 1U,
  session = 1ULL << 2U,
  pairing = 1ULL << 3U,
  message = 1ULL << 4U,
  unary_rpc = 1ULL << 5U,
  event = 1ULL << 6U,
  byte_stream = 1ULL << 7U,
  file = 1ULL << 8U,
  shell = 1ULL << 9U,
};

struct CapabilitySet {
  std::uint64_t bits{};

  [[nodiscard]] constexpr bool has(Capability capability) const noexcept {
    return (bits & static_cast<std::uint64_t>(capability)) != 0U;
  }
  [[nodiscard]] constexpr bool contains(CapabilitySet required) const noexcept {
    return (bits & required.bits) == required.bits;
  }
};

struct ProtocolHello {
  ProtocolVersion version;
  CapabilitySet supported;
  CapabilitySet required;
};

struct NegotiatedProtocol {
  ProtocolVersion version;
  CapabilitySet capabilities;
};

[[nodiscard]] Result<NegotiatedProtocol> negotiate_protocol(const ProtocolHello& local,
                                                            const ProtocolHello& remote);

}  // namespace heyaki
