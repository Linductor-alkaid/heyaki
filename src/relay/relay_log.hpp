#pragma once

// Structured relay log records (M9-02). The relay emits one record per
// security-relevant or operational event; high-frequency success events
// (heartbeats, signaling forwards, endpoint queries) are sampled by the
// server while failures and security events are always emitted. Records
// carry only correlation-safe fields: timestamps, stable detail strings,
// connection/device/endpoint ids, tenant, and the signaling request id used
// as correlation id. Secrets, tokens, verifiers, and business payloads never
// enter a record (architecture §13.1/§13.2).

#include <heyaki/ids.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace heyaki {

enum class RelayLogLevel : std::uint8_t {
  info = 0U,
  warn = 1U,
};

enum class RelayLogEventKind : std::uint8_t {
  server_state_changed = 0U,
  server_error,
  connection_capacity_rejected,
  handshake_timeout,
  handshake_failed,
  policy_rejected,
  rate_limited,
  enrollment_completed,
  enrollment_rejected,
  login_completed,
  login_rejected,
  endpoint_published,
  signaling_forwarded,
  signaling_rejected,
  heartbeat_refreshed,
  endpoint_query_served,
};

struct RelayLogRecord {
  RelayLogEventKind kind{};
  RelayLogLevel level{RelayLogLevel::info};
  std::uint64_t timestamp_unix_milliseconds{};
  // Stable machine-greppable detail (usually an Error safe_detail); never a
  // free-form dump of remote input. Owned copy: the producing handler's
  // Error/locals die as soon as log_event returns, so sinks may store records.
  std::string detail;
  std::string connection_id;
  std::optional<DeviceId> device_id;
  std::optional<EndpointId> endpoint_id;
  std::string tenant;
  // Signaling request id when the event belongs to a forwarded request;
  // joins relay logs with the M9-03 correlation id space.
  std::optional<RequestId> request_id;
};

// Invoked synchronously on the relay's execution context after each emitted
// record. Sinks must return promptly and must not throw; exceptions are
// swallowed by the server.
using RelayLogSink = std::function<void(const RelayLogRecord&)>;

[[nodiscard]] std::string_view relay_log_event_name(
    RelayLogEventKind kind) noexcept;
[[nodiscard]] std::string_view relay_log_level_name(
    RelayLogLevel level) noexcept;

// Renders one JSON object per line. Absent fields (empty connection id /
// tenant / detail, missing device, endpoint, or request id) are omitted
// entirely; strings are JSON-escaped.
[[nodiscard]] std::string format_relay_log_json(const RelayLogRecord& record);

}  // namespace heyaki
