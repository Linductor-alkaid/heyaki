#pragma once

#include <heyaki/identity.hpp>
#include <heyaki/protocol.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace heyaki {

inline constexpr std::size_t lan_boot_nonce_bytes = 32U;
inline constexpr std::size_t tls_certificate_fingerprint_bytes = 32U;
using LanBootNonce = std::array<std::byte, lan_boot_nonce_bytes>;
using TlsCertificateFingerprint =
    std::array<std::byte, tls_certificate_fingerprint_bytes>;
using LanHandshakeNonce = std::array<std::byte, 32U>;

enum class LanSignalingMessageKind : std::uint8_t {
  connect_request = 1,
  connect_accept = 2,
  connect_deny = 3,
  signed_offer = 4,
  signed_answer = 5,
  signed_candidate = 6,
};

inline constexpr std::size_t max_lan_signaling_payload_bytes = 64U * 1024U;
inline constexpr std::size_t lan_signaling_frame_header_bytes = 4U;
inline constexpr std::size_t lan_signaling_frame_fixed_body_bytes =
    1U + RequestId::size_bytes;
inline constexpr std::size_t max_lan_signaling_body_bytes =
    lan_signaling_frame_fixed_body_bytes + max_lan_signaling_payload_bytes;
inline constexpr std::size_t max_lan_signaling_frame_bytes =
    lan_signaling_frame_header_bytes + max_lan_signaling_body_bytes;

struct LanSignalingFrame {
  LanSignalingMessageKind kind{LanSignalingMessageKind::connect_request};
  RequestId request_id;
  std::vector<std::byte> payload;
};

struct LanPresence {
  ProtocolVersion protocol_version{current_protocol_version};
  CapabilitySet supported{protocol_1_1_capability_bits};
  CapabilitySet required{
      static_cast<std::uint64_t>(Capability::lan_discovery_v1) |
      static_cast<std::uint64_t>(Capability::lan_signaling_v1)};
  DeviceId device_id;
  IdentityPublicKey identity_public_key{};
  EndpointId endpoint_id;
  LanBootNonce boot_nonce{};
  std::uint64_t sequence{};
  std::uint16_t tls_signaling_port{};
  std::chrono::milliseconds lease{15000};
  IdentitySignature signature{};
};

enum class LanHelloRole : std::uint8_t {
  initiator = 1,
  responder = 2,
};

struct LanHello {
  LanHelloRole role{LanHelloRole::initiator};
  DeviceId sender_device_id;
  EndpointId sender_endpoint_id;
  DeviceId peer_device_id;
  EndpointId peer_endpoint_id;
  IdentityPublicKey sender_identity_public_key{};
  LanHandshakeNonce initiator_nonce{};
  LanHandshakeNonce responder_nonce{};
  TlsCertificateFingerprint sender_tls_certificate_sha256{};
  TlsCertificateFingerprint observed_peer_tls_certificate_sha256{};
  LanBootNonce sender_boot_nonce{};
  ProtocolVersion protocol_version{current_protocol_version};
  CapabilitySet supported{protocol_1_1_capability_bits};
  CapabilitySet required{static_cast<std::uint64_t>(Capability::lan_signaling_v1)};
  std::chrono::milliseconds expiry{5000};
  IdentitySignature signature{};
};

[[nodiscard]] Result<std::vector<std::byte>> canonical_lan_presence(
    const LanPresence& presence);
[[nodiscard]] Result<void> sign_lan_presence(LanPresence& presence,
                                             const IdentityKeyPair& identity);
[[nodiscard]] Result<void> validate_lan_presence(const LanPresence& presence);
[[nodiscard]] Result<std::vector<std::byte>> encode_lan_presence(
    const LanPresence& presence);
[[nodiscard]] Result<LanPresence> parse_lan_presence(std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_lan_presence_datagram(
    const LanPresence& presence);
[[nodiscard]] Result<LanPresence> parse_lan_presence_datagram(
    std::span<const std::byte> datagram);
[[nodiscard]] Result<std::vector<std::byte>> canonical_lan_hello(const LanHello& hello);
[[nodiscard]] Result<void> sign_lan_hello(LanHello& hello,
                                         const IdentityKeyPair& identity);
[[nodiscard]] Result<void> validate_lan_hello(const LanHello& hello);
[[nodiscard]] Result<std::vector<std::byte>> encode_lan_hello(const LanHello& hello);
[[nodiscard]] Result<LanHello> parse_lan_hello(std::span<const std::byte> payload);
[[nodiscard]] Result<void> validate_lan_signaling_frame(
    const LanSignalingFrame& frame);
[[nodiscard]] Result<std::vector<std::byte>> encode_lan_signaling_frame(
    const LanSignalingFrame& frame);
[[nodiscard]] Result<LanSignalingFrame> parse_lan_signaling_frame(
    std::span<const std::byte> input);

}  // namespace heyaki
