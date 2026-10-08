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
  gateway_v1 = 1ULL << 13U,
  // Optional: the peer understands the passwordless pairing-approval
  // request frame and answers with a pairing_result.
  pairing_approval_v1 = 1ULL << 14U,
  // Optional: the peer understands password-based relay enrollment. A client
  // advertising the bit may put a relay-bound Argon2id proof (32 bytes) into
  // `EnrollmentRequest.enrollment_password_proof` (wire field 10); a relay
  // running `enrollment_mode = password` requires the bit and rejects
  // requests without it. Token-mode exchanges never carry the field, so
  // builds without the bit are unaffected.
  relay_enrollment_password_v1 = 1ULL << 15U,
  // Optional: the peer consumes the relay-issued `ice_config` field of
  // login_result/heartbeat_ack (short-lived TURN REST credentials). The
  // relay includes the field only for sessions whose login advertisement
  // carried the bit, so legacy peers keep byte-identical control traffic.
  relay_ice_config_v1 = 1ULL << 16U,
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
// Protocol 1.3 also carries the passwordless pairing-approval capability:
// peers advertising 1.3 understand the approval request frame. Older peers
// never advertise the bit (their build's known-bit set excludes it) and the
// version mask strips it from every negotiation with them, so hello
// compatibility is unchanged; the receiving side's
// NodeConfig::pairing_approval_enabled still gates actual use.
// Protocol 1.3 additionally carries the relay password-enrollment capability,
// which follows the same optional-bit pattern: only password-mode enrollment
// exchanges put the matching proof field on the wire.
// Protocol 1.3 additionally carries the relay-ice-config capability: peers
// advertising it accept the optional `ice_config` field of relay
// login_result/heartbeat_ack. The relay gates the field on the login
// advertisement, so a mixed-version fleet keeps legacy peers unperturbed.
inline constexpr std::uint64_t protocol_1_3_capability_bits =
    protocol_1_2_capability_bits |
    static_cast<std::uint64_t>(Capability::gateway_v1) |
    static_cast<std::uint64_t>(Capability::pairing_approval_v1) |
    static_cast<std::uint64_t>(Capability::relay_enrollment_password_v1) |
    static_cast<std::uint64_t>(Capability::relay_ice_config_v1);
inline constexpr std::uint64_t known_capability_bits = protocol_1_3_capability_bits;

inline constexpr ProtocolVersion current_protocol_version{1U, 3U};

// Lowest minor whose capability set contains the LAN discovery/signaling
// bits: LAN presence and hello admission accepts same-major peers at or above
// this floor so N-1 devices stay mutually discoverable, while the actual
// version/capability negotiation still happens in SESSION_HELLO.
inline constexpr std::uint32_t lan_supported_minor_floor = 1U;

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

// Capability set defined by a wire protocol version: the bits a peer at that
// version may legitimately advertise. Zero for a foreign major version.
[[nodiscard]] std::uint64_t capabilities_for_version(ProtocolVersion version) noexcept;

}  // namespace heyaki
