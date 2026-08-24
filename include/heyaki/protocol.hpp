#pragma once

#include <heyaki/error.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace heyaki {

struct ProtocolVersion {
  std::uint32_t major{1U};
  std::uint32_t minor{1U};

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
  lan_discovery_v1 = 1ULL << 10U,
  lan_signaling_v1 = 1ULL << 11U,
  session_restart_v1 = 1ULL << 12U,
};

inline constexpr std::uint64_t protocol_1_0_capability_bits =
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
inline constexpr std::uint64_t protocol_1_1_capability_bits =
    protocol_1_0_capability_bits |
    static_cast<std::uint64_t>(Capability::lan_discovery_v1) |
    static_cast<std::uint64_t>(Capability::lan_signaling_v1);
// Protocol 1.2 adds the optional session-restart capability: a signed
// renegotiation of a new ICE/DTLS transport over the authenticated control
// channel of an existing session, preserving the SessionId and bumping the
// session epoch. A 1.1 peer ignores the bit and never receives restart frames.
inline constexpr std::uint64_t protocol_1_2_capability_bits =
    protocol_1_1_capability_bits |
    static_cast<std::uint64_t>(Capability::session_restart_v1);
inline constexpr std::uint64_t known_capability_bits = protocol_1_2_capability_bits;

inline constexpr ProtocolVersion current_protocol_version{1U, 2U};

enum class LanDatagramType : std::uint8_t {
  presence = 1U,
};

inline constexpr std::string_view lan_discovery_ipv4_group{"239.192.72.89"};
inline constexpr std::string_view lan_discovery_ipv6_group{"ff12::4845:5941:4b49"};
inline constexpr std::uint16_t lan_discovery_udp_port = 49189U;
inline constexpr std::uint8_t lan_discovery_hop_limit = 1U;
inline constexpr std::array lan_datagram_magic{
    std::byte{'H'}, std::byte{'Y'}, std::byte{'L'}, std::byte{'D'}};
inline constexpr std::uint8_t lan_datagram_envelope_version = 1U;
inline constexpr std::size_t lan_datagram_header_bytes = 8U;
inline constexpr std::size_t max_lan_datagram_bytes = 1200U;
inline constexpr std::size_t max_lan_datagram_payload_bytes =
    max_lan_datagram_bytes - lan_datagram_header_bytes;
inline constexpr std::uint32_t min_lan_presence_lease_milliseconds = 1000U;
inline constexpr std::uint32_t max_lan_presence_lease_milliseconds = 120000U;
inline constexpr std::uint32_t max_lan_hello_expiry_milliseconds = 10000U;

enum class LanDatagramParseStatus : std::uint8_t {
  parsed,
  incomplete,
  malformed,
  unsupported,
};

struct LanDatagramView {
  LanDatagramType type;
  std::span<const std::byte> payload;
};

struct LanDatagramParseResult {
  LanDatagramParseStatus status{LanDatagramParseStatus::incomplete};
  std::optional<LanDatagramView> datagram;
};

[[nodiscard]] LanDatagramParseResult parse_lan_datagram(
    std::span<const std::byte> bytes) noexcept;
[[nodiscard]] Result<std::vector<std::byte>> encode_lan_datagram(
    LanDatagramType type, std::span<const std::byte> payload);

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
