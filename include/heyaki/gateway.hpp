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
#include <functional>
#include <optional>
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
// Aggregate quota hard caps enforced by validate_gateway_profile (M9-11
// hard-cap discipline; defaults registered in parameter-freeze.md).
inline constexpr std::uint64_t max_gateway_profile_bytes_hard =
    1ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t max_gateway_profile_bytes_per_second_hard =
    256ULL * 1024ULL * 1024ULL;
inline constexpr std::chrono::milliseconds max_gateway_stream_idle_timeout{
    3600000};
inline constexpr std::chrono::milliseconds max_gateway_stream_duration{
    86400000};

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

// ---- IP / CIDR primitives (profile policy inputs, M10-04) ----

// One IP address: 4 bytes (IPv4) or 16 bytes (IPv6), stored host-order in
// `bytes` (IPv4 occupies the first 4 bytes). Comparable, formattable, and
// safe for audit records — unlike a peer-supplied hostname it is either a
// validated literal or a locally resolved address.
struct GatewayIp {
  std::array<std::byte, 16U> bytes{};
  bool v4{true};

  friend constexpr bool operator==(const GatewayIp&, const GatewayIp&) noexcept = default;
};

[[nodiscard]] std::optional<GatewayIp> parse_gateway_ip(
    std::string_view literal) noexcept;
// Canonical text form (dotted quad / compressed IPv6) for validated values.
[[nodiscard]] std::string format_gateway_ip(const GatewayIp& address);

struct GatewayCidr {
  GatewayIp address;
  int prefix_bits{};
};

[[nodiscard]] std::optional<GatewayCidr> parse_gateway_cidr(
    std::string_view text) noexcept;
[[nodiscard]] bool gateway_cidr_contains(const GatewayCidr& cidr,
                                         const GatewayIp& address) noexcept;
// True for 0.0.0.0/0 or ::/0 (design 3.2: effective only with
// allow_internet).
[[nodiscard]] bool gateway_cidr_is_catch_all(const GatewayCidr& cidr) noexcept;

// ---- Profiles (M10-04) ----

// Human confirmation mode for serving-side gateway opens (design 3.3).
enum class GatewayConfirmMode : std::uint8_t {
  never = 0U,
  first_use = 1U,
  always = 2U,
};

// Inclusive TCP port range within 1..65535.
struct GatewayPortRange {
  std::uint16_t low{1U};
  std::uint16_t high{65535U};
};

struct GatewayProfileConfig {
  // Logical profile name exposed through the gateway.provide:<profile>
  // scope (safe_gateway_profile_name grammar).
  std::string name;
  // Explicitly enumerated target ranges. A catch-all entry is a
  // configuration error unless allow_internet is set (no silent wide-open
  // fallback). Empty list is invalid: a profile must state its targets.
  std::vector<GatewayCidr> allowed_cidrs;
  // Extra deny ranges (B's management segments, the relay's address space,
  // …) stacked on the built-in deny list; deny always wins over allow.
  std::vector<GatewayCidr> denied_cidrs;
  // TCP ports this profile may dial. Empty denies everything.
  std::vector<GatewayPortRange> allowed_ports;
  // Explicit opt-in for routing through B's internet egress (design 3.2,
  // default false).
  bool allow_internet{false};
  // Dual concurrency caps (design 3.2): per session and per profile.
  std::size_t max_concurrent_streams_per_session{default_max_concurrent_gateway_streams};
  std::size_t max_concurrent_streams_per_profile{16U};
  // Aggregate byte / rate quotas per profile, enforced fail-closed.
  std::uint64_t max_profile_bytes{2ULL * 1024ULL * 1024ULL * 1024ULL};
  std::uint64_t max_profile_bytes_per_second{16U * 1024U * 1024U};
  // Per-stream idle and absolute duration caps; exceeding resets the stream.
  std::chrono::milliseconds stream_idle_timeout{300000};
  std::chrono::milliseconds stream_max_duration{3600000};
  std::chrono::milliseconds dial_deadline{10000};
  // Serving-side confirmation flow (M10-06 wires the TUI).
  GatewayConfirmMode confirm{GatewayConfirmMode::never};
};

// Validates one profile: name grammar, at least one CIDR, catch-all rule,
// port ranges, quota/timeout bounds against the frozen hard caps. An
// invalid profile fails node startup — never clamped, never ignored.
[[nodiscard]] Result<void> validate_gateway_profile(const GatewayProfileConfig& profile);

// Validates a whole configured set: every profile valid, unique names, and
// the per-endpoint profile count within max_gateway_profiles_per_endpoint_hard.
[[nodiscard]] Result<void> validate_gateway_profiles(
    std::span<const GatewayProfileConfig> profiles);

// ---- Admission engine (M10-05, pure policy) ----
// No I/O, no clock: the caller supplies resolved addresses and live
// counters, the engine adjudicates and returns the dialable subset. The
// live gateway.provide:<profile> scope check stays with the caller (it
// owns the session's authorized scopes).

struct GatewayAdmissionContext {
  // Concurrent gateway streams currently served to this session / under
  // the candidate profile.
  std::size_t streams_active_session{};
  std::size_t streams_active_profile{};
  // Aggregate bytes already metered under the profile's lifetime quota.
  std::uint64_t profile_bytes_used{};
};

struct GatewayAdmission {
  bool allowed{false};
  GatewayRefusal refusal{GatewayRefusal::policy_denied};
  // Set when allowed: the adjudicating profile (caller re-checks the live
  // gateway.provide:<name> scope before dialing).
  const GatewayProfileConfig* profile{nullptr};
  // The resolved-address subset that survived the deny list and the CIDR
  // allowlist, in input order. Empty with allowed=false means refused;
  // the caller dials only these addresses (design 4.3).
  std::vector<GatewayIp> dial_addresses;
};

// Selects the adjudicating profile for a connect request: an explicit name
// must match a configured profile; an empty name resolves only when exactly
// one profile is configured (nullptr otherwise, engine refuses
// not_enabled). Shared by the admission engine and the serving service so
// selection cannot drift between them.
[[nodiscard]] const GatewayProfileConfig* resolve_gateway_profile(
    std::span<const GatewayProfileConfig> profiles,
    std::string_view name) noexcept;

// Adjudicates one inbound GatewayConnect. `resolved` holds every address
// the (B-side) resolution of `connect.host` produced; for an IP literal
// that is the literal itself. All grammar checks are assumed done
// (validate_gateway_connect); the engine decides profile selection, port
// policy, per-address CIDR/deny policy, and quota admission.
[[nodiscard]] GatewayAdmission admit_gateway_connection(
    std::span<const GatewayProfileConfig> profiles, const GatewayConnect& connect,
    std::span<const GatewayIp> resolved, const GatewayAdmissionContext& context);

// ---- Serving-side service stats (M10-11) ----
// Per-profile byte accounting for the metrics export (rates derive from
// the counters via the usual rate() window, not a second family).
struct GatewayProfileUsageSnapshot {
  std::string profile;
  std::size_t active_tunnels{};
  std::uint64_t bytes_from_tunnel{};
  std::uint64_t bytes_to_tunnel{};
};

// Counters/gauges the node aggregates per serving-side gateway service.
// Refusals are indexed by GatewayRefusal (gateway_refusal_name labels).
struct GatewayServiceStats {
  static constexpr std::size_t dial_sample_window = 256U;
  std::array<std::uint64_t,
             static_cast<std::size_t>(GatewayRefusal::local_failure) + 1U>
      refusals{};
  std::uint64_t opens_received{0};
  std::uint64_t dials_succeeded{0};
  std::uint64_t dials_failed{0};
  std::uint64_t bytes_from_tunnel{0};  // A -> target
  std::uint64_t bytes_to_tunnel{0};    // target -> A
  std::uint64_t tunnels_closed_clean{0};
  std::uint64_t idle_timeout_resets{0};
  std::uint64_t duration_timeout_resets{0};
  std::uint64_t byte_quota_resets{0};
  std::uint64_t confirm_denials{0};
  std::uint64_t path_rejected{0};
  std::size_t tunnels_active{0};
  // Recent dial latencies (open received -> prelude written), for the
  // exported P95 approximation over the bounded window.
  std::array<std::uint32_t, dial_sample_window> dial_samples{};
  std::size_t dial_samples_count{0};
  std::size_t dial_samples_next{0};
  std::vector<GatewayProfileUsageSnapshot> profile_usage;
};

// Records one dial latency sample into the bounded ring.
void record_gateway_dial_sample(GatewayServiceStats& stats,
                                std::uint32_t milliseconds) noexcept;
// 95th percentile of the recorded dial window (0 when empty).
[[nodiscard]] std::uint32_t gateway_dial_p95(
    const GatewayServiceStats& stats) noexcept;

// ---- Audit (M10-12) ----
// One record per gateway tunnel that entered admission. `target_host` is
// always the grammar-validated form (wire-malformed opens never reach the
// service; safe_detail discipline keeps unvalidated text out of records).
struct GatewayAuditRecord {
  DeviceId initiator;
  std::string profile;
  std::string target_host;
  std::uint16_t target_port{};
  std::uint64_t started_unix_ms{};
  std::uint64_t ended_unix_ms{};
  std::uint64_t bytes_from_tunnel{};
  std::uint64_t bytes_to_tunnel{};
  StableStatus end_status{StableStatus::unspecified};
};

// ---- Human confirmation (design 3.3, M10-06) ----// One confirmation request shown to the serving-side operator before the
// tunnel dials; `host` has already passed the frozen grammar validation
// (safe-detail discipline). Sinks answer asynchronously through the
// decider, which may be invoked from any thread. Profiles with
// confirm==never never ask; an unanswered request auto-denies after 30s.
struct GatewayConfirmRequest {
  // Requesting peer identity for the operator's prompt (design 3.3).
  DeviceId peer_device;
  std::string profile;
  std::string host;
  std::uint16_t port{};
};
using GatewayConfirmSink =
    std::function<void(const GatewayConfirmRequest&, std::function<void(bool)>)>;
inline constexpr std::chrono::milliseconds gateway_confirm_deadline{30000};

}  // namespace heyaki
