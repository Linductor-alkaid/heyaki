#include <heyaki/gateway.hpp>

#include "proto_codec.hpp"

#include <algorithm>
#include <utility>

namespace heyaki {
namespace {

Error gateway_error(ErrorCode code, const char* detail) {
  return {code, "gateway", detail};
}

// One ASCII LDH label: 1..63 bytes of [A-Za-z0-9-], no leading/trailing
// hyphen (RFC 1123 label; single-letter labels are legal for LAN names).
bool valid_ldh_label(std::string_view label) noexcept {
  if (label.empty() || label.size() > 63U) {
    return false;
  }
  if (label.front() == '-' || label.back() == '-') {
    return false;
  }
  return std::all_of(label.begin(), label.end(), [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-';
  });
}

// Dotted-quad IPv4 literal: four 0..255 groups, no leading zeros beyond the
// single-digit form, no embedded spaces.
bool valid_ipv4_literal(std::string_view text) noexcept {
  std::uint32_t groups = 0U;
  std::string_view rest = text;
  while (!rest.empty()) {
    const auto dot = rest.find('.');
    const auto group = rest.substr(0U, dot == std::string_view::npos
                                           ? std::string_view::npos
                                           : dot);
    rest = dot == std::string_view::npos ? std::string_view{}
                                         : rest.substr(dot + 1U);
    if (group.empty() || group.size() > 3U) {
      return false;
    }
    if (group.size() > 1U && group.front() == '0') {
      return false;
    }
    std::uint32_t value = 0U;
    for (char c : group) {
      if (c < '0' || c > '9') {
        return false;
      }
      value = value * 10U + static_cast<std::uint32_t>(c - '0');
    }
    if (value > 255U) {
      return false;
    }
    ++groups;
    if (groups > 4U) {
      return false;
    }
  }
  return groups == 4U;
}

// IPv6 literal: 2..8 hex groups separated by ':', at most one "::"
// compression (not leading a group list that then has 8 groups), optional
// embedded dotted-quad tail after exactly the last groups. Zone indices
// ("%eth0") are rejected: they name a local interface, not a target.
bool valid_ipv6_literal(std::string_view text) noexcept {
  if (text.size() < 2U) {
    return false;
  }
  bool compressed = false;
  std::uint32_t groups = 0U;
  std::string_view rest = text;
  if (rest.starts_with("::")) {
    compressed = true;
    rest.remove_prefix(2U);
  } else if (rest.front() == ':' || rest.back() == ':') {
    return false;
  }
  while (!rest.empty()) {
    auto colon = rest.find(':');
    auto group = rest.substr(0U, colon == std::string_view::npos
                                     ? std::string_view::npos
                                     : colon);
    // Embedded IPv4 tail: only legal as the last group.
    if (group.find('.') != std::string_view::npos) {
      if (colon != std::string_view::npos) {
        return false;
      }
      if (!valid_ipv4_literal(group)) {
        return false;
      }
      groups += 2U;
      rest = std::string_view{};
      break;
    }
    if (group.empty()) {
      // "::" in the middle.
      if (compressed || colon == std::string_view::npos) {
        return false;
      }
      compressed = true;
      rest = rest.substr(colon + 1U);
      if (rest.empty()) {
        break;
      }
      continue;
    }
    if (group.size() > 4U) {
      return false;
    }
    for (char c : group) {
      const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                       (c >= 'A' && c <= 'F');
      if (!hex) {
        return false;
      }
    }
    ++groups;
    rest = colon == std::string_view::npos ? std::string_view{}
                                           : rest.substr(colon + 1U);
  }
  if (compressed) {
    return groups <= 7U;
  }
  return groups == 8U;
}

}  // namespace

std::string gateway_provide_scope(std::string_view profile) {
  std::string scope;
  scope.reserve(gateway_use_scope.size() + 1U + profile.size());
  scope.append("gateway.provide:").append(profile);
  return scope;
}

bool valid_gateway_host(std::string_view host) noexcept {
  if (host.empty() || host.size() > max_gateway_host_bytes) {
    return false;
  }
  // All bytes must be printable ASCII without spaces; this rejects NUL,
  // control characters, underscores, and any non-ASCII byte up front.
  const bool printable =
      std::all_of(host.begin(), host.end(), [](char c) {
        return c >= 0x21 && c <= 0x7e && c != ' ';
      });
  if (!printable) {
    return false;
  }
  if (host.find(':') != std::string_view::npos) {
    return valid_ipv6_literal(host);
  }
  // A leading or trailing dot encodes an empty label in every form.
  if (host.front() == '.' || host.back() == '.') {
    return false;
  }
  if (std::all_of(host.begin(), host.end(), [](char c) {
        return (c >= '0' && c <= '9') || c == '.';
      })) {
    return valid_ipv4_literal(host);
  }
  // LDH hostname: dot-separated labels; a single label is acceptable.
  std::string_view rest = host;
  while (!rest.empty()) {
    const auto dot = rest.find('.');
    const auto label = rest.substr(0U, dot == std::string_view::npos
                                           ? std::string_view::npos
                                           : dot);
    if (dot == std::string_view::npos) {
      return valid_ldh_label(label);
    }
    if (!valid_ldh_label(label)) {
      return false;
    }
    rest = rest.substr(dot + 1U);
  }
  return true;
}

bool safe_gateway_profile_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > max_gateway_profile_bytes) {
    return false;
  }
  return std::all_of(name.begin(), name.end(), [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' ||
           c == '.' || c == '-';
  });
}

Result<void> validate_gateway_connect(const GatewayConnect& connect) {
  if (!valid_gateway_host(connect.host)) {
    return Result<void>::failure(
        gateway_error(ErrorCode::permission, "gateway_host_invalid"));
  }
  if (connect.port == 0U) {
    return Result<void>::failure(
        gateway_error(ErrorCode::permission, "gateway_port_invalid"));
  }
  if (!connect.profile.empty() && !safe_gateway_profile_name(connect.profile)) {
    return Result<void>::failure(
        gateway_error(ErrorCode::permission, "gateway_profile_invalid"));
  }
  return Result<void>::success();
}

Result<std::vector<std::byte>> encode_gateway_connect(const GatewayConnect& connect) {
  if (!valid_gateway_host(connect.host)) {
    return Result<std::vector<std::byte>>::failure(
        gateway_error(ErrorCode::protocol, "gateway_host_invalid"));
  }
  if (connect.port == 0U) {
    return Result<std::vector<std::byte>>::failure(
        gateway_error(ErrorCode::protocol, "gateway_port_invalid"));
  }
  if (!connect.profile.empty() && !safe_gateway_profile_name(connect.profile)) {
    return Result<std::vector<std::byte>>::failure(
        gateway_error(ErrorCode::protocol, "gateway_profile_invalid"));
  }
  std::vector<std::byte> payload;
  payload.reserve(connect.host.size() + connect.profile.size() + 8U);
  proto_codec::append_text(payload, 1U, connect.host);
  proto_codec::append_uint(payload, 2U, connect.port);
  if (!connect.profile.empty()) {
    proto_codec::append_text(payload, 3U, connect.profile);
  }
  return Result<std::vector<std::byte>>::success(std::move(payload));
}

Result<GatewayConnect> parse_gateway_connect(std::span<const std::byte> payload) {
  GatewayConnect connect;
  proto_codec::ProtoReader reader(payload);
  bool have_host = false;
  bool have_port = false;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<GatewayConnect>::failure(*field.error_if());
    }
    const auto& parsed = *field.value_if();
    if (parsed.number == 1U && parsed.wire_type == 2U) {
      if (have_host) {
        return Result<GatewayConnect>::failure(
            gateway_error(ErrorCode::protocol, "gateway_field_conflict"));
      }
      have_host = true;
      connect.host.assign(reinterpret_cast<const char*>(parsed.bytes.data()),
                          parsed.bytes.size());
    } else if (parsed.number == 2U && parsed.wire_type == 0U) {
      if (have_port) {
        return Result<GatewayConnect>::failure(
            gateway_error(ErrorCode::protocol, "gateway_field_conflict"));
      }
      have_port = true;
      if (parsed.integer == 0U || parsed.integer > 65535U) {
        return Result<GatewayConnect>::failure(
            gateway_error(ErrorCode::protocol, "gateway_port_invalid"));
      }
      connect.port = static_cast<std::uint16_t>(parsed.integer);
    } else if (parsed.number == 3U && parsed.wire_type == 2U) {
      if (!connect.profile.empty()) {
        return Result<GatewayConnect>::failure(
            gateway_error(ErrorCode::protocol, "gateway_field_conflict"));
      }
      connect.profile.assign(reinterpret_cast<const char*>(parsed.bytes.data()),
                             parsed.bytes.size());
    } else {
      // Strict from birth: GatewayConnect has no unknown optional fields
      // at 1.3; a future field number must come through a new minor sheet.
      return Result<GatewayConnect>::failure(
          gateway_error(ErrorCode::protocol, "gateway_unknown_field"));
    }
  }
  if (!have_host || !have_port) {
    return Result<GatewayConnect>::failure(
        gateway_error(ErrorCode::protocol, "gateway_field_missing"));
  }
  return Result<GatewayConnect>::success(std::move(connect));
}

std::array<std::byte, gateway_prelude_bytes> encode_gateway_prelude(
    std::uint16_t status) noexcept {
  return {static_cast<std::byte>(status >> 8U), static_cast<std::byte>(status)};
}

Result<std::uint16_t> parse_gateway_prelude(std::span<const std::byte> payload) {
  if (payload.size() != gateway_prelude_bytes) {
    return Result<std::uint16_t>::failure(
        gateway_error(ErrorCode::protocol, "gateway_prelude_length"));
  }
  const auto high = std::to_integer<std::uint16_t>(payload[0U]);
  const auto low = std::to_integer<std::uint16_t>(payload[1U]);
  const std::uint16_t status = static_cast<std::uint16_t>((high << 8U) | low);
  if (status != gateway_prelude_connected) {
    return Result<std::uint16_t>::failure(
        gateway_error(ErrorCode::protocol, "gateway_prelude_status_invalid"));
  }
  return Result<std::uint16_t>::success(status);
}

std::string_view gateway_refusal_name(GatewayRefusal refusal) noexcept {
  switch (refusal) {
    case GatewayRefusal::capability_not_negotiated:
      return "capability_not_negotiated";
    case GatewayRefusal::invalid_target:
      return "invalid_target";
    case GatewayRefusal::not_enabled:
      return "not_enabled";
    case GatewayRefusal::scope_denied:
      return "scope_denied";
    case GatewayRefusal::policy_denied:
      return "policy_denied";
    case GatewayRefusal::quota_exhausted:
      return "quota_exhausted";
    case GatewayRefusal::dial_failed:
      return "dial_failed";
    case GatewayRefusal::dial_deadline:
      return "dial_deadline";
    case GatewayRefusal::local_failure:
      return "local_failure";
  }
  return "unknown";
}

}  // namespace heyaki
