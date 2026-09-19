#pragma once

// Gateway proxy protocol surfaces frozen by the protocol 1.3 change sheet
// (M10-01/M10-02; design: docs/design/gateway-service.md §4). A gateway
// stream is an ordinary ByteStream opened by STREAM_OPEN carrying the
// optional `heyaki.protocol.gateway.v1.GatewayConnect gateway = 4` field.
// The capability bit `gateway_v1` (bit 13) must be negotiated first:
//
//   * a session that did NOT negotiate bit 13 and receives a STREAM_OPEN
//     carrying the gateway field rejects it with `protocol` and closes only
//     that logical channel (M10-02);
//   * a 1.2-or-older peer treats the field as an unknown optional field and
//     is never sent one — a 1.3 sender gates emission on the negotiated
//     version/capability;
//   * no new frame types exist: failures ride STREAM_RESET with a mapped
//     StableStatusCode, success is announced by the fixed 2-byte prelude.
//
// The prelude is the first STREAM_DATA frame of the gateway direction
// (offset 0..1), U16 big-endian, `0` = connected. Failures never send a
// prelude; they reset the stream with gateway_refusal_status() instead. A
// receiver MUST treat a nonzero prelude as a protocol violation of the
// stream mapping (there is no legal nonzero value: dial failures reset).
//
// Scope model (M10-03): the initiator's TrustGrant must contain
// `gateway.use`; the serving side must hold `gateway.provide:<profile>`.
// Both default OFF and are excluded from every standard pairing template,
// exactly like Remote Shell.

#include <heyaki/error.hpp>
#include <heyaki/pairing_protocol.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

// ---- Scopes (M10-03) ----
// Checked live on each side: `gateway.use` on the initiator before any
// gateway STREAM_OPEN leaves, `gateway.provide:<profile>` on the serving
// side before any dial. Neither scope appears in a standard pairing
// template; only explicit configuration grants them.
inline constexpr std::string_view gateway_use_scope{"gateway.use"};
[[nodiscard]] std::string gateway_provide_scope(std::string_view profile);

// ---- Wire body: heyaki.protocol.gateway.v1.GatewayConnect ----

// C++ mirror of the frozen GatewayConnect schema. `host` is the
// peer-supplied ASCII hostname (LDH) or IPv4/IPv6 literal, validated by
// valid_gateway_host() before it may enter any log or audit record (the
// gateway threat model forbids free-text targets). `profile` empty means
// the serving side adjudicates against its configured default.
struct GatewayConnect {
  std::string host;
  std::uint16_t port{};
  std::string profile;
};

// ---- Frozen limits (design §8) ----
inline constexpr std::size_t max_gateway_host_bytes = 253U;
inline constexpr std::size_t max_gateway_profile_bytes = 64U;
inline constexpr std::size_t max_gateway_profiles_per_endpoint = 16U;
inline constexpr std::size_t max_gateway_profiles_per_endpoint_hard = 64U;
inline constexpr std::chrono::milliseconds default_gateway_dial_deadline{10000};
inline constexpr std::chrono::milliseconds max_gateway_dial_deadline{30000};
// Protocol 1.3: sessions may carry at most this many concurrent gateway
// streams per side; negotiation can only lower it.
inline constexpr std::size_t default_max_concurrent_gateway_streams = 8U;
inline constexpr std::size_t hard_max_concurrent_gateway_streams = 64U;

// Hostname grammar: ASCII LDH labels (single label allowed) or an IPv4 /
// IPv6 literal, 1..253 bytes, no NUL/control/space/underscore characters
// and no leading or trailing hyphen per label.
[[nodiscard]] bool valid_gateway_host(std::string_view host) noexcept;

// Profile-name grammar: 1..64 bytes of ASCII [a-z0-9_.-].
[[nodiscard]] bool safe_gateway_profile_name(std::string_view name) noexcept;

// Structural validation of one connect request: host grammar, port != 0,
// profile grammar when present. Used on both sides; the result never
// echoes the peer-supplied host.
[[nodiscard]] Result<void> validate_gateway_connect(const GatewayConnect& connect);

// Encodes the GatewayConnect protobuf body (fields 1..3; an empty profile
// is omitted exactly as proto3 prescribes).
[[nodiscard]] Result<std::vector<std::byte>> encode_gateway_connect(
    const GatewayConnect& connect);

// Strict parse of the GatewayConnect body: wire-level malformations
// (bad varints, truncation, unknown fields) are `protocol` failures whose
// caller closes the offending logical channel; grammar problems are NOT
// detected here — validate_gateway_connect() handles them as admissions.
[[nodiscard]] Result<GatewayConnect> parse_gateway_connect(
    std::span<const std::byte> payload);

// ---- Prelude (protocol 1.3, frozen) ----
inline constexpr std::size_t gateway_prelude_bytes = 2U;
// The only legal prelude value: connected. Failures reset instead.
inline constexpr std::uint16_t gateway_prelude_connected = 0U;

[[nodiscard]] std::array<std::byte, gateway_prelude_bytes> encode_gateway_prelude(
    std::uint16_t status) noexcept;
// Reads the two prelude bytes; any nonzero status is a protocol violation
// of the gateway stream mapping.
[[nodiscard]] Result<std::uint16_t> parse_gateway_prelude(
    std::span<const std::byte> payload);

// ---- Dial/refusal mapping table (protocol 1.3, frozen; design §9.2) ----
// Coarse by design: the serving side never distinguishes refused,
// unreachable, or filtered dials on the wire (probing-oracle mitigation).
enum class GatewayRefusal : std::uint8_t {
  // STREAM_OPEN carried the gateway field on a session that did not
  // negotiate gateway_v1; protocol violation, closes the channel.
  capability_not_negotiated,
  // Host/port/profile failed structural validation.
  invalid_target,
  // Serving-side gateway feature disabled or no profile configured.
  not_enabled,
  // gateway.provide:<profile> scope not granted to this session.
  scope_denied,
  // Target outside the profile's CIDR list / port allowlist, or inside the
  // default deny list (loopback, link-local, management ranges, tunnel
  // endpoints).
  policy_denied,
  // Concurrent-stream or profile quota exhausted (fail-closed).
  quota_exhausted,
  // Local dial failed (refused/unreachable/filtered merged).
  dial_failed,
  // Dial deadline expired.
  dial_deadline,
  // Local gateway machinery failed before a dial could be attempted.
  local_failure,
};

// The frozen mapping from refusal categories to the StableStatusCode the
// peer observes in STREAM_RESET.
[[nodiscard]] constexpr StableStatus gateway_refusal_status(
    GatewayRefusal refusal) noexcept {
  switch (refusal) {
    case GatewayRefusal::capability_not_negotiated:
      return StableStatus::protocol_error;
    case GatewayRefusal::invalid_target:
    case GatewayRefusal::scope_denied:
    case GatewayRefusal::policy_denied:
      return StableStatus::permission_denied;
    case GatewayRefusal::quota_exhausted:
      return StableStatus::resource_exhausted;
    case GatewayRefusal::not_enabled:
      return StableStatus::unimplemented;
    case GatewayRefusal::dial_failed:
      return StableStatus::unavailable;
    case GatewayRefusal::dial_deadline:
      return StableStatus::deadline_exceeded;
    case GatewayRefusal::local_failure:
      return StableStatus::internal;
  }
  return StableStatus::internal;
}

// Stable token for audit/metric labels of a refusal category.
[[nodiscard]] std::string_view gateway_refusal_name(
    GatewayRefusal refusal) noexcept;

}  // namespace heyaki
