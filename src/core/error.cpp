#include <heyaki/error.hpp>

namespace heyaki {

Error::Error(ErrorCode code, std::string component, std::string safe_detail,
             std::optional<std::int64_t> underlying_code, std::optional<DeviceId> peer_id,
             std::optional<OperationId> operation_id)
    : code_(code),
      underlying_code_(underlying_code),
      peer_id_(peer_id),
      operation_id_(operation_id),
      component_(is_safe_detail_token(component) ? std::move(component) : "invalid_component"),
      safe_detail_(is_safe_detail_token(safe_detail) ? std::move(safe_detail)
                                                     : "invalid_safe_detail") {}

bool is_safe_detail_token(std::string_view value) noexcept {
  if (value.empty() || value.size() > max_safe_detail_bytes) {
    return false;
  }
  for (const char character : value) {
    const bool is_lower = character >= 'a' && character <= 'z';
    const bool is_digit = character >= '0' && character <= '9';
    if (!is_lower && !is_digit && character != '_' && character != '-' && character != '.') {
      return false;
    }
  }
  return true;
}

std::string_view error_code_name(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::configuration:
      return "configuration";
    case ErrorCode::identity:
      return "identity";
    case ErrorCode::authentication:
      return "authentication";
    case ErrorCode::permission:
      return "permission";
    case ErrorCode::not_registered:
      return "not_registered";
    case ErrorCode::enrollment_revoked:
      return "enrollment_revoked";
    case ErrorCode::profile_locked:
      return "profile_locked";
    case ErrorCode::pairing_required:
      return "pairing_required";
    case ErrorCode::pairing_denied:
      return "pairing_denied";
    case ErrorCode::pairing_rate_limited:
      return "pairing_rate_limited";
    case ErrorCode::peer_offline:
      return "peer_offline";
    case ErrorCode::endpoint_offline:
      return "endpoint_offline";
    case ErrorCode::signaling:
      return "signaling";
    case ErrorCode::nat_traversal:
      return "nat_traversal";
    case ErrorCode::relay_unavailable:
      return "relay_unavailable";
    case ErrorCode::transport:
      return "transport";
    case ErrorCode::protocol:
      return "protocol";
    case ErrorCode::timeout:
      return "timeout";
    case ErrorCode::cancelled:
      return "cancelled";
    case ErrorCode::would_block:
      return "would_block";
    case ErrorCode::resource_exhausted:
      return "resource_exhausted";
    case ErrorCode::remote_error:
      return "remote_error";
    case ErrorCode::outcome_unknown:
      return "outcome_unknown";
    case ErrorCode::internal:
      return "internal";
  }
  return "internal";
}

}  // namespace heyaki
