#pragma once

#include <heyaki/error.hpp>

#include <cstdint>

namespace heyaki {

struct ProtocolVersion {
  std::uint32_t major{1U};
  std::uint32_t minor{0U};

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

inline constexpr std::uint64_t known_capability_bits =
    static_cast<std::uint64_t>(Capability::enrollment) |
    static_cast<std::uint64_t>(Capability::signaling) |
    static_cast<std::uint64_t>(Capability::session) |
    static_cast<std::uint64_t>(Capability::pairing) |
    static_cast<std::uint64_t>(Capability::message) |
    static_cast<std::uint64_t>(Capability::unary_rpc) |
    static_cast<std::uint64_t>(Capability::event) |
    static_cast<std::uint64_t>(Capability::byte_stream) |
    static_cast<std::uint64_t>(Capability::file) |
    static_cast<std::uint64_t>(Capability::shell);

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
