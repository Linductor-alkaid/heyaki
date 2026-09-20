#include <heyaki/gateway.hpp>

#include "proto_codec.hpp"

#include <algorithm>
#include <array>
#include <optional>
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

// Dotted-quad IPv4 literal into four octet values: four 0..255 groups, no
// leading zeros beyond the single-digit form, no empty or >3-digit group,
// and no leading/trailing dot (an empty label is not a group).
std::optional<std::array<std::uint8_t, 4U>> ipv4_octets(
    std::string_view text) noexcept {
  if (text.empty() || text.front() == '.' || text.back() == '.') {
    return std::nullopt;
  }
  std::array<std::uint8_t, 4U> octets{};
  std::uint32_t groups = 0U;
  std::string_view rest = text;
  while (!rest.empty()) {
    const auto dot = rest.find('.');
    const auto group =
        rest.substr(0U, dot == std::string_view::npos ? std::string_view::npos : dot);
    rest = dot == std::string_view::npos ? std::string_view{} : rest.substr(dot + 1U);
    if (group.empty() || group.size() > 3U || groups >= 4U) {
      return std::nullopt;
    }
    if (group.size() > 1U && group.front() == '0') {
      return std::nullopt;
    }
    std::uint32_t value = 0U;
    for (char c : group) {
      if (c < '0' || c > '9') {
        return std::nullopt;
      }
      value = value * 10U + static_cast<std::uint32_t>(c - '0');
    }
    if (value > 255U) {
      return std::nullopt;
    }
    octets[groups] = static_cast<std::uint8_t>(value);
    ++groups;
  }
  if (groups != 4U) {
    return std::nullopt;
  }
  return octets;
}

// IPv6 literal into its eight 16-bit groups, expanding at most one "::"
// (which must stand for at least one zero group) and an embedded
// dotted-quad tail (last group only). Rejects zone indices.
struct Ipv6Part {
  std::array<std::uint16_t, 8U> groups{};
  std::uint32_t count{};
};

std::optional<Ipv6Part> parse_ipv6_part(std::string_view part,
                                        bool allow_v4_tail) noexcept {
  if (part.empty()) {
    return Ipv6Part{};
  }
  if (part.front() == ':' || part.back() == ':') {
    return std::nullopt;
  }
  Ipv6Part parsed;
  std::string_view rest = part;
  while (!rest.empty()) {
    const auto colon = rest.find(':');
    const auto group =
        rest.substr(0U, colon == std::string_view::npos ? std::string_view::npos : colon);
    const bool last = colon == std::string_view::npos;
    std::array<std::uint16_t, 2U> values{};
    std::uint32_t expands = 1U;
    if (group.find('.') != std::string_view::npos) {
      // Embedded IPv4 tail: only legal as the very last group of the whole
      // address and expands into two groups.
      if (!allow_v4_tail || !last) {
        return std::nullopt;
      }
      auto octets = ipv4_octets(group);
      if (!octets.has_value()) {
        return std::nullopt;
      }
      values[0] = static_cast<std::uint16_t>(((*octets)[0] << 8U) | (*octets)[1]);
      values[1] = static_cast<std::uint16_t>(((*octets)[2] << 8U) | (*octets)[3]);
      expands = 2U;
    } else {
      if (group.empty() || group.size() > 4U) {
        return std::nullopt;
      }
      std::uint16_t value = 0U;
      for (char c : group) {
        std::uint16_t digit = 0xFFFFU;
        if (c >= '0' && c <= '9') {
          digit = static_cast<std::uint16_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
          digit = static_cast<std::uint16_t>((c - 'a') + 10);
        } else if (c >= 'A' && c <= 'F') {
          digit = static_cast<std::uint16_t>((c - 'A') + 10);
        } else {
          return std::nullopt;
        }
        value = static_cast<std::uint16_t>((value << 4U) | digit);
      }
      values[0] = value;
    }
    for (std::uint32_t index = 0U; index < expands; ++index) {
      if (parsed.count >= 8U) {
        return std::nullopt;
      }
      parsed.groups[parsed.count++] = values[index];
    }
    rest = last ? std::string_view{} : rest.substr(colon + 1U);
  }
  return parsed;
}

std::optional<std::array<std::uint16_t, 8U>> ipv6_groups(
    std::string_view text) noexcept {
  if (text.size() < 2U) {
    return std::nullopt;
  }
  const auto compression = text.find("::");
  const bool compressed = compression != std::string_view::npos;
  if (compressed && text.find("::", compression + 2U) != std::string_view::npos) {
    return std::nullopt;
  }
  const auto head_part = compressed ? text.substr(0U, compression) : text;
  const auto tail_part =
      compressed ? text.substr(compression + 2U) : std::string_view{};
  auto head = parse_ipv6_part(head_part, !compressed);
  if (!head.has_value()) {
    return std::nullopt;
  }
  std::optional<Ipv6Part> tail = Ipv6Part{};
  if (compressed) {
    tail = parse_ipv6_part(tail_part, true);
    if (!tail.has_value()) {
      return std::nullopt;
    }
  }
  const std::uint32_t total = head->count + tail->count;
  if (compressed ? total > 7U : total != 8U) {
    // "::" stands for at least one zero group (RFC 5952).
    return std::nullopt;
  }
  // The compressed gap is the middle: head groups first, then zeros, then
  // the tail groups at the END of the address ("::1" is 00..00 01, not
  // 01 00..00 — the deny list compares these bytes, so a misplacement
  // silently disables loopback denials).
  std::array<std::uint16_t, 8U> groups{};
  for (std::uint32_t index = 0U; index < head->count; ++index) {
    groups[index] = head->groups[index];
  }
  const std::uint32_t tail_offset = 8U - tail->count;
  for (std::uint32_t index = 0U; index < tail->count; ++index) {
    groups[tail_offset + index] = tail->groups[index];
  }
  return groups;
}

bool valid_ipv6_literal(std::string_view text) noexcept {
  return ipv6_groups(text).has_value();
}

// The always-on serving-side deny list (design 9.2): loopback, link-local,
// unspecified, multicast/broadcast, CGNAT infrastructure, and the IPv4-
// mapped IPv6 range (gateway_cidr_contains is family-isolated, so without
// this entry a mapped "::ffff:127.0.0.1" would dodge the IPv4 loopback
// deny — an SSRF-shaped hole once the dialer resolves hostnames).
// Configured denied_cidrs stack on top; deny always wins over the allowlist.
constexpr std::string_view builtin_gateway_deny_ranges[] = {
    "0.0.0.0/8",          "127.0.0.0/8",      "169.254.0.0/16", "224.0.0.0/4",
    "255.255.255.255/32", "100.64.0.0/10",    "::/128",         "::1/128",
    "fe80::/10",          "ff00::/8",         "::ffff:0:0/96",
};

bool cidr_list_contains(const std::vector<GatewayCidr>& ranges,
                        const GatewayIp& address) noexcept {
  return std::any_of(ranges.begin(), ranges.end(), [&](const GatewayCidr& cidr) {
    return gateway_cidr_contains(cidr, address);
  });
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
    return ipv4_octets(host).has_value();
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

std::optional<GatewayIp> parse_gateway_ip(std::string_view literal) noexcept {
  if (literal.find(':') == std::string_view::npos) {
    auto octets = ipv4_octets(literal);
    if (!octets.has_value()) {
      return std::nullopt;
    }
    GatewayIp address;
    address.v4 = true;
    for (std::size_t index = 0U; index < 4U; ++index) {
      address.bytes[index] = static_cast<std::byte>((*octets)[index]);
    }
    return address;
  }
  auto groups = ipv6_groups(literal);
  if (!groups.has_value()) {
    return std::nullopt;
  }
  GatewayIp address;
  address.v4 = false;
  for (std::size_t group = 0U; group < 8U; ++group) {
    const auto value = (*groups)[group];
    address.bytes[group * 2U] = static_cast<std::byte>(value >> 8U);
    address.bytes[group * 2U + 1U] = static_cast<std::byte>(value);
  }
  return address;
}

std::string format_gateway_ip(const GatewayIp& address) {
  if (address.v4) {
    std::string text;
    text.reserve(15U);
    for (std::size_t index = 0U; index < 4U; ++index) {
      if (index != 0U) {
        text.push_back('.');
      }
      text += std::to_string(
          std::to_integer<unsigned>(address.bytes[index]));
    }
    return text;
  }
  std::array<std::uint16_t, 8U> groups{};
  for (std::size_t group = 0U; group < 8U; ++group) {
    groups[group] = static_cast<std::uint16_t>(
        (std::to_integer<std::uint16_t>(address.bytes[group * 2U]) << 8U) |
        std::to_integer<std::uint16_t>(address.bytes[group * 2U + 1U]));
  }
  // RFC 5952 compression: lowercase hex, no leading zeros, the single
  // longest run of 2+ zero groups becomes "::" (ties keep the first).
  std::size_t best_start = 8U;
  std::size_t best_length = 0U;
  std::size_t index = 0U;
  while (index < 8U) {
    if (groups[index] != 0U) {
      ++index;
      continue;
    }
    std::size_t run = index;
    while (run < 8U && groups[run] == 0U) {
      ++run;
    }
    if (run - index > best_length && run - index >= 2U) {
      best_start = index;
      best_length = run - index;
    }
    index = run;
  }
  // RFC 5952 5: an IPv4-mapped address (::ffff:0:0/96) prints its last 32
  // bits as a dotted quad ("::ffff:192.0.2.1", not "::ffff:c000:201").
  const bool v4_mapped = std::all_of(groups.begin(), groups.begin() + 5U,
                                     [](std::uint16_t group) { return group == 0U; }) &&
                         groups[5] == 0xFFFFU;
  if (v4_mapped) {
    const std::array<std::uint16_t, 2U> tail{groups[6], groups[7]};
    std::string text = "::ffff:";
    for (std::size_t group = 0U; group < 2U; ++group) {
      for (int half = 0; half < 2; ++half) {
        const auto octet = static_cast<unsigned>((tail[group] >> (half == 0 ? 8U : 0U)) & 0xFFU);
        text += std::to_string(octet);
        if (group == 0U || half == 0U) {
          text.push_back('.');
        }
      }
    }
    return text;
  }
  static constexpr char hex[] = "0123456789abcdef";
  std::string text;
  text.reserve(39U);
  for (std::size_t group = 0U; group < 8U; ++group) {
    if (best_length != 0U && group == best_start) {
      // "::" opens the zero run wherever it sits: the first colon separates
      // from the preceding group (or begins the address), the second
      // separates the following group from the run.
      text += "::";
      group += best_length - 1U;
      continue;
    }
    // The group right after the run needs no separator — the second colon
    // of "::" already provided it.
    if (group != 0U && !(best_length != 0U && group == best_start + best_length)) {
      text.push_back(':');
    }
    bool significant = false;
    for (int shift = 12; shift >= 0; shift -= 4) {
      const auto nibble = static_cast<char>((groups[group] >> shift) & 0xFU);
      if (nibble != 0 || significant || shift == 0) {
        text.push_back(hex[static_cast<std::size_t>(nibble)]);
        significant = true;
      }
    }
  }
  return text;
}

std::optional<GatewayCidr> parse_gateway_cidr(std::string_view text) noexcept {
  const auto slash = text.find('/');
  if (slash == std::string_view::npos) {
    return std::nullopt;
  }
  auto address = parse_gateway_ip(text.substr(0U, slash));
  if (!address.has_value()) {
    return std::nullopt;
  }
  const auto bits_text = text.substr(slash + 1U);
  if (bits_text.empty() || bits_text.size() > 3U) {
    return std::nullopt;
  }
  int bits = 0;
  for (char c : bits_text) {
    if (c < '0' || c > '9') {
      return std::nullopt;
    }
    bits = bits * 10 + (c - '0');
  }
  const int max_bits = address->v4 ? 32 : 128;
  if (bits > max_bits) {
    return std::nullopt;
  }
  return GatewayCidr{.address = *address, .prefix_bits = bits};
}

bool gateway_cidr_contains(const GatewayCidr& cidr,
                           const GatewayIp& address) noexcept {
  if (cidr.address.v4 != address.v4) {
    return false;
  }
  const std::size_t width = cidr.address.v4 ? 4U : 16U;
  auto bit_at = [width](const GatewayIp& value,
                        std::size_t bit) noexcept -> int {
    // Bits beyond the family width read as zero so family mismatch is the
    // only cross-family outcome (checked above).
    if (bit >= width * 8U) {
      return 0;
    }
    const auto byte = std::to_integer<std::uint8_t>(value.bytes[bit / 8U]);
    return (byte >> (7U - (bit % 8U))) & 1U;
  };
  for (int bit = 0; bit < cidr.prefix_bits; ++bit) {
    if (bit_at(cidr.address, static_cast<std::size_t>(bit)) !=
        bit_at(address, static_cast<std::size_t>(bit))) {
      return false;
    }
  }
  return true;
}

bool gateway_cidr_is_catch_all(const GatewayCidr& cidr) noexcept {
  return cidr.prefix_bits == 0;
}

Result<void> validate_gateway_profile(const GatewayProfileConfig& profile) {
  if (!safe_gateway_profile_name(profile.name)) {
    return Result<void>::failure(
        gateway_error(ErrorCode::configuration, "gateway_profile_name_invalid"));
  }
  if (profile.allowed_cidrs.empty()) {
    return Result<void>::failure(
        gateway_error(ErrorCode::configuration, "gateway_profile_targets_empty"));
  }
  for (const auto& cidr : profile.allowed_cidrs) {
    if (gateway_cidr_is_catch_all(cidr) && !profile.allow_internet) {
      return Result<void>::failure(gateway_error(
          ErrorCode::configuration, "gateway_profile_catch_all_without_internet"));
    }
  }
  for (const auto& range : profile.allowed_ports) {
    if (range.low == 0U || range.low > range.high) {
      return Result<void>::failure(
          gateway_error(ErrorCode::configuration, "gateway_profile_ports_invalid"));
    }
  }
  if (profile.max_concurrent_streams_per_session == 0U ||
      profile.max_concurrent_streams_per_session > hard_max_concurrent_gateway_streams ||
      profile.max_concurrent_streams_per_profile == 0U ||
      profile.max_concurrent_streams_per_profile > hard_max_concurrent_gateway_streams) {
    return Result<void>::failure(
        gateway_error(ErrorCode::configuration, "gateway_profile_concurrency_invalid"));
  }
  if (profile.max_profile_bytes == 0U ||
      profile.max_profile_bytes > max_gateway_profile_bytes_hard ||
      profile.max_profile_bytes_per_second == 0U ||
      profile.max_profile_bytes_per_second > max_gateway_profile_bytes_per_second_hard) {
    return Result<void>::failure(
        gateway_error(ErrorCode::configuration, "gateway_profile_quota_invalid"));
  }
  if (profile.stream_idle_timeout < std::chrono::milliseconds{1000} ||
      profile.stream_idle_timeout > max_gateway_stream_idle_timeout ||
      profile.stream_max_duration < std::chrono::milliseconds{1000} ||
      profile.stream_max_duration > max_gateway_stream_duration ||
      profile.dial_deadline < std::chrono::milliseconds{1000} ||
      profile.dial_deadline > max_gateway_dial_deadline) {
    return Result<void>::failure(
        gateway_error(ErrorCode::configuration, "gateway_profile_timeout_invalid"));
  }
  return Result<void>::success();
}

Result<void> validate_gateway_profiles(std::span<const GatewayProfileConfig> profiles) {
  if (profiles.size() > max_gateway_profiles_per_endpoint_hard) {
    return Result<void>::failure(
        gateway_error(ErrorCode::configuration, "gateway_profile_count_invalid"));
  }
  for (const auto& profile : profiles) {
    auto valid = validate_gateway_profile(profile);
    if (!valid) {
      return valid;
    }
  }
  for (std::size_t left = 0U; left < profiles.size(); ++left) {
    for (std::size_t right = left + 1U; right < profiles.size(); ++right) {
      if (profiles[left].name == profiles[right].name) {
        return Result<void>::failure(gateway_error(
            ErrorCode::configuration, "gateway_profile_name_duplicate"));
      }
    }
  }
  return Result<void>::success();
}

const GatewayProfileConfig* resolve_gateway_profile(
    std::span<const GatewayProfileConfig> profiles, std::string_view name) noexcept {
  if (name.empty()) {
    return profiles.size() == 1U ? &profiles.front() : nullptr;
  }
  for (const auto& candidate : profiles) {
    if (candidate.name == name) {
      return &candidate;
    }
  }
  return nullptr;
}

GatewayAdmission admit_gateway_connection(
    std::span<const GatewayProfileConfig> profiles, const GatewayConnect& connect,
    std::span<const GatewayIp> resolved, const GatewayAdmissionContext& context) {
  GatewayAdmission admission;
  const GatewayProfileConfig* profile = resolve_gateway_profile(profiles, connect.profile);
  if (profile == nullptr) {
    admission.refusal = connect.profile.empty() ? GatewayRefusal::not_enabled
                                                : GatewayRefusal::policy_denied;
    return admission;
  }
  const bool port_allowed =
      std::any_of(profile->allowed_ports.begin(), profile->allowed_ports.end(),
                  [&](const GatewayPortRange& range) {
                    return connect.port >= range.low && connect.port <= range.high;
                  });
  if (!port_allowed) {
    admission.refusal = GatewayRefusal::policy_denied;
    return admission;
  }
  // Per-address policy after B-side resolution (design 4.3): the built-in
  // deny list and the profile's denied ranges win; the remainder must fall
  // inside the allowlist. Only surviving addresses may be dialed.
  for (const auto& address : resolved) {
    bool denied = false;
    for (std::string_view range : builtin_gateway_deny_ranges) {
      auto cidr = parse_gateway_cidr(range);
      if (cidr.has_value() && gateway_cidr_contains(*cidr, address)) {
        denied = true;
        break;
      }
    }
    if (!denied && cidr_list_contains(profile->denied_cidrs, address)) {
      denied = true;
    }
    if (denied) {
      continue;
    }
    if (cidr_list_contains(profile->allowed_cidrs, address)) {
      admission.dial_addresses.push_back(address);
    }
  }
  if (admission.dial_addresses.empty()) {
    admission.refusal = GatewayRefusal::policy_denied;
    return admission;
  }
  if (context.streams_active_session >= profile->max_concurrent_streams_per_session ||
      context.streams_active_profile >= profile->max_concurrent_streams_per_profile) {
    admission.refusal = GatewayRefusal::quota_exhausted;
    admission.dial_addresses.clear();
    return admission;
  }
  if (context.profile_bytes_used >= profile->max_profile_bytes) {
    admission.refusal = GatewayRefusal::quota_exhausted;
    admission.dial_addresses.clear();
    return admission;
  }
  admission.allowed = true;
  admission.profile = profile;
  return admission;
}

}  // namespace heyaki
