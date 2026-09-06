// JSON Lines rendering for RelayLogRecord (M9-02). Hand-rolled escaping on
// purpose: the log surface stays dependency-free, and every field is either
// a server-generated identifier or a stable detail string, so the escaper
// only has to guarantee JSON-valid output for arbitrary bytes.

#include "relay_log.hpp"

#include <string>

namespace heyaki {
namespace {

void append_json_string(std::string& out, std::string_view value) {
  out.push_back('"');
  for (const char character : value) {
    switch (character) {
      case '"':
        out.append("\\\"");
        break;
      case '\\':
        out.append("\\\\");
        break;
      case '\n':
        out.append("\\n");
        break;
      case '\r':
        out.append("\\r");
        break;
      case '\t':
        out.append("\\t");
        break;
      default:
        if (static_cast<unsigned char>(character) < 0x20U) {
          static constexpr char hex[] = "0123456789abcdef";
          out.append("\\u00");
          out.push_back(hex[static_cast<unsigned char>(character) >> 4U]);
          out.push_back(hex[static_cast<unsigned char>(character) & 0x0fU]);
        } else {
          out.push_back(character);
        }
        break;
    }
  }
  out.push_back('"');
}

void append_field_separator(std::string& out, bool& first) {
  if (!first) {
    out.push_back(',');
  }
  first = false;
}

}  // namespace

std::string_view relay_log_event_name(RelayLogEventKind kind) noexcept {
  switch (kind) {
    case RelayLogEventKind::server_state_changed:
      return "server_state_changed";
    case RelayLogEventKind::server_error:
      return "server_error";
    case RelayLogEventKind::connection_capacity_rejected:
      return "connection_capacity_rejected";
    case RelayLogEventKind::handshake_timeout:
      return "handshake_timeout";
    case RelayLogEventKind::handshake_failed:
      return "handshake_failed";
    case RelayLogEventKind::policy_rejected:
      return "policy_rejected";
    case RelayLogEventKind::rate_limited:
      return "rate_limited";
    case RelayLogEventKind::enrollment_completed:
      return "enrollment_completed";
    case RelayLogEventKind::enrollment_rejected:
      return "enrollment_rejected";
    case RelayLogEventKind::login_completed:
      return "login_completed";
    case RelayLogEventKind::login_rejected:
      return "login_rejected";
    case RelayLogEventKind::endpoint_published:
      return "endpoint_published";
    case RelayLogEventKind::signaling_forwarded:
      return "signaling_forwarded";
    case RelayLogEventKind::signaling_rejected:
      return "signaling_rejected";
    case RelayLogEventKind::heartbeat_refreshed:
      return "heartbeat_refreshed";
    case RelayLogEventKind::endpoint_query_served:
      return "endpoint_query_served";
  }
  return "unknown";
}

std::string_view relay_log_level_name(RelayLogLevel level) noexcept {
  switch (level) {
    case RelayLogLevel::info:
      return "info";
    case RelayLogLevel::warn:
      return "warn";
  }
  return "info";
}

std::string format_relay_log_json(const RelayLogRecord& record) {
  std::string out;
  out.reserve(160U);
  out.push_back('{');

  bool first = true;
  append_field_separator(out, first);
  out.append("\"ts\":");
  out.append(std::to_string(record.timestamp_unix_milliseconds));

  append_field_separator(out, first);
  out.append("\"level\":");
  append_json_string(out, relay_log_level_name(record.level));

  append_field_separator(out, first);
  out.append("\"event\":");
  append_json_string(out, relay_log_event_name(record.kind));

  if (!record.connection_id.empty()) {
    append_field_separator(out, first);
    out.append("\"conn\":");
    append_json_string(out, record.connection_id);
  }
  if (record.device_id) {
    append_field_separator(out, first);
    out.append("\"device\":");
    append_json_string(out, to_string(*record.device_id));
  }
  if (record.endpoint_id) {
    append_field_separator(out, first);
    out.append("\"endpoint\":");
    append_json_string(out, to_string(*record.endpoint_id));
  }
  if (!record.tenant.empty()) {
    append_field_separator(out, first);
    out.append("\"tenant\":");
    append_json_string(out, record.tenant);
  }
  if (record.request_id) {
    append_field_separator(out, first);
    out.append("\"request_id\":");
    append_json_string(out, to_string(*record.request_id));
  }
  if (!record.detail.empty()) {
    append_field_separator(out, first);
    out.append("\"detail\":");
    append_json_string(out, record.detail);
  }

  out.append("}\n");
  return out;
}

}  // namespace heyaki
