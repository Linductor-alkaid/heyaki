// M10 Round 2 independent verification: gateway profile configuration
// (M10-04) and the B-side admission engine (M10-05), plus the M10-03
// scope/template exclusion regression. Covers the IP/CIDR primitives
// (parse/format/contains), validate_gateway_profile(s) axis failures with
// their frozen detail tokens, the admit_gateway_connection matrix (profile
// selection, port policy, per-address deny/allow filtering, quotas), the
// NodeConfig gateway_profiles wiring into Node::create, and the TUI default
// pairing templates staying free of every gateway.* scope.

#include <heyaki/error.hpp>
#include <heyaki/gateway.hpp>
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <gtest/gtest.h>

// Platform RFC 5952 oracle: the resolver's own inet_pton/inet_ntop are used
// as an independent second opinion on parse bytes and canonical text, so a
// shared bug cannot hide on both sides of a comparison. The oracle needs
// POSIX <arpa/inet.h>, which MSVC does not provide: on Windows (and whenever
// HEYAKI_TEST_NO_POSIX_INET is defined, which lets any platform compile the
// oracle-off configuration for verification) the oracle-backed comparisons
// are skipped while every pure grammar and policy assertion still runs.
#if !defined(_WIN32) && !defined(HEYAKI_TEST_NO_POSIX_INET)
#define HEYAKI_TEST_POSIX_INET 1
#include <arpa/inet.h>
#endif

#include <array>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {
namespace {

using namespace std::chrono_literals;

// ---- Fixtures / helpers ------------------------------------------------------

GatewayCidr make_cidr(std::string_view text) {
  auto parsed = parse_gateway_cidr(text);
  EXPECT_TRUE(parsed.has_value()) << "cidr literal: " << text;
  return parsed.value_or(GatewayCidr{});
}

GatewayIp make_ip(std::string_view literal) {
  auto parsed = parse_gateway_ip(literal);
  EXPECT_TRUE(parsed.has_value()) << "ip literal: " << literal;
  return parsed.value_or(GatewayIp{});
}

// Legal baseline profile: office LAN segment, two port ranges, every other
// knob left at its frozen default.
GatewayProfileConfig base_profile() {
  GatewayProfileConfig profile;
  profile.name = "office";
  profile.allowed_cidrs = {make_cidr("10.0.0.0/8")};
  profile.allowed_ports = {{.low = 443U, .high = 443U},
                           {.low = 8080U, .high = 8090U}};
  return profile;
}

// Wide-open profile used to prove the built-in deny list cannot be
// configured away: dual-family catch-all with allow_internet.
GatewayProfileConfig internet_profile() {
  GatewayProfileConfig profile;
  profile.name = "internet";
  profile.allow_internet = true;
  profile.allowed_cidrs = {make_cidr("0.0.0.0/0"), make_cidr("::/0")};
  profile.allowed_ports = {{.low = 1U, .high = 65535U}};
  return profile;
}

GatewayAdmissionContext idle_context() { return {}; }

GatewayConnect connect_request(std::string_view host, std::uint16_t port,
                               std::string_view profile_name) {
  return GatewayConnect{.host = std::string{host},
                        .port = port,
                        .profile = std::string{profile_name}};
}

void expect_refused(const GatewayAdmission& admission, GatewayRefusal refusal) {
  EXPECT_FALSE(admission.allowed);
  EXPECT_EQ(admission.refusal, refusal);
  EXPECT_TRUE(admission.dial_addresses.empty());
  EXPECT_EQ(admission.profile, nullptr);
}

// Quota refusals happen after per-address filtering, so dial_addresses may
// already hold the filtered subset; the caller-visible contract is that
// nothing dials (allowed=false) and no profile is handed out.
void expect_quota_refused(const GatewayAdmission& admission) {
  EXPECT_FALSE(admission.allowed);
  EXPECT_EQ(admission.refusal, GatewayRefusal::quota_exhausted);
  EXPECT_EQ(admission.profile, nullptr);
}

// ---- 1. IP literal grammar / parse ------------------------------------------

TEST(M10GatewayIp, ParsesValidLiterals) {
  const std::vector<std::pair<std::string_view, bool>> valid{
      {"0.0.0.0", true},          {"192.0.2.1", true},   {"255.255.255.255", true},
      {"::", false},              {"::1", false},        {"fe80::", false},
      {"1::", false},             {"2001:db8::", false}, {"2001:db8::192.0.2.1", false},
      {"::ffff:192.0.2.1", false}, {"1:2:3:4:5:6:7:8", false},
  };
  for (const auto& [literal, expect_v4] : valid) {
    const auto parsed = parse_gateway_ip(literal);
    ASSERT_TRUE(parsed.has_value()) << "literal=" << literal;
    EXPECT_EQ(parsed->v4, expect_v4) << "literal=" << literal;
  }
}

TEST(M10GatewayIp, ByteLayoutOfParsedLiterals) {
  const auto v4 = parse_gateway_ip("192.0.2.1");
  ASSERT_TRUE(v4.has_value());
  EXPECT_TRUE(v4->v4);
  EXPECT_EQ(v4->bytes[0], std::byte{0xc0U});
  EXPECT_EQ(v4->bytes[1], std::byte{0x00U});
  EXPECT_EQ(v4->bytes[2], std::byte{0x02U});
  EXPECT_EQ(v4->bytes[3], std::byte{0x01U});

  // ::1 is all-zero except the final byte (RFC 4291 loopback).
  const auto loopback = parse_gateway_ip("::1");
  ASSERT_TRUE(loopback.has_value());
  EXPECT_FALSE(loopback->v4);
  EXPECT_EQ(loopback->bytes.front(), std::byte{0x00U});
  EXPECT_EQ(loopback->bytes.back(), std::byte{0x01U});
  for (std::size_t index = 0U; index + 1U < loopback->bytes.size(); ++index) {
    EXPECT_EQ(loopback->bytes[index], std::byte{0x00U}) << "index=" << index;
  }

  // fe80::1 keeps the link-local first group 0xfe80.
  const auto link_local = parse_gateway_ip("fe80::1");
  ASSERT_TRUE(link_local.has_value());
  EXPECT_EQ(link_local->bytes[0], std::byte{0xfeU});
  EXPECT_EQ(link_local->bytes[1], std::byte{0x80U});
  EXPECT_EQ(link_local->bytes.back(), std::byte{0x01U});

  // IPv4-mapped tail: ::ffff:192.0.2.1 = groups [0,0,0,0,0,ffff,c000,0201].
  const auto mapped = parse_gateway_ip("::ffff:192.0.2.1");
  ASSERT_TRUE(mapped.has_value());
  EXPECT_EQ(mapped->bytes[10], std::byte{0xffU});
  EXPECT_EQ(mapped->bytes[11], std::byte{0xffU});
  EXPECT_EQ(mapped->bytes[12], std::byte{0xc0U});
  EXPECT_EQ(mapped->bytes[13], std::byte{0x00U});
  EXPECT_EQ(mapped->bytes[14], std::byte{0x02U});
  EXPECT_EQ(mapped->bytes[15], std::byte{0x01U});
}

TEST(M10GatewayIp, RejectsInvalidLiterals) {
  const std::vector<std::pair<std::string, std::string_view>> invalid{
      {"01.2.3.4", "IPv4 leading zero"},
      {"1.2.3", "IPv4 three groups"},
      {"1.2.3.4.5", "IPv4 five groups"},
      {"1.2.3.256", "IPv4 group overflow"},
      {"1.2.3.4.", "IPv4 trailing dot"},
      {".1.2.3.4", "IPv4 leading dot"},
      {":::1", "triple colon head"},
      {"1:::2", "triple colon middle"},
      {"1::2::3", "two ::"},
      {"fe80::1%eth0", "zone suffix"},
      {"1:2:3:4:5:6:7:8:9", "nine groups"},
      {"1:2:3:4:5:6:7:8::", "compressed with eight groups"},
      {"1:2:3:4:5:6:7", "seven groups uncompressed"},
      {"12345", "pure numeric non-IPv4"},
      {"", "empty"},
  };
  for (const auto& [literal, label] : invalid) {
    EXPECT_FALSE(parse_gateway_ip(literal).has_value())
        << label << " literal=" << literal;
  }
}

// ---- 2. Canonical formatting (RFC 5952) --------------------------------------

TEST(M10GatewayIp, FormatsIPv4AsDottedQuad) {
  const auto address = make_ip("192.0.2.1");
  EXPECT_EQ(format_gateway_ip(address), "192.0.2.1");
  const auto zero = make_ip("0.0.0.0");
  EXPECT_EQ(format_gateway_ip(zero), "0.0.0.0");
}

TEST(M10GatewayIp, FormatCompressionRuleOnExplicitGroups) {
  // Hand-built group arrays pin the formatter independently of the parser:
  // longest zero run wins, ties keep the first, runs of one stay expanded.
  struct Case {
    std::array<std::uint16_t, 8U> groups;
    std::string_view expected;
  };
  const std::vector<Case> cases{
      {{0x1U, 0x2U, 0x3U, 0x4U, 0x5U, 0x6U, 0x7U, 0x8U}, "1:2:3:4:5:6:7:8"},
      {{0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, "::"},
      {{0U, 0U, 0U, 0U, 0U, 0U, 0U, 0x1U}, "::1"},
      {{0x1U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, "1::"},
      // Longest run wins: front run of 3 beats the middle run of 2.
      {{0U, 0U, 0U, 0x1U, 0U, 0U, 0x2U, 0x3U}, "::1:0:0:2:3"},
      // Longest run wins from the other side: middle run of 3 beats front 2.
      {{0U, 0U, 0x1U, 0U, 0U, 0U, 0x2U, 0x3U}, "0:0:1::2:3"},
      // Equal-length runs (2 vs 2): the first is compressed.
      {{0x1U, 0U, 0U, 0x2U, 0U, 0U, 0x3U, 0x4U}, "1::2:0:0:3:4"},
      // Only length-1 zero runs: no compression at all.
      {{0x1U, 0U, 0x2U, 0U, 0x3U, 0U, 0x4U, 0U}, "1:0:2:0:3:0:4:0"},
      // Tail run of 2 after real groups.
      {{0x2001U, 0x0db8U, 0x1U, 0x1U, 0x1U, 0U, 0U, 0x1U},
       "2001:db8:1:1:1::1"},
  };
  for (const auto& item : cases) {
    GatewayIp address;
    address.v4 = false;
    for (std::size_t group = 0U; group < 8U; ++group) {
      address.bytes[group * 2U] = static_cast<std::byte>(item.groups[group] >> 8U);
      address.bytes[group * 2U + 1U] =
          static_cast<std::byte>(item.groups[group]);
    }
    EXPECT_EQ(format_gateway_ip(address), item.expected);
  }
}

TEST(M10GatewayIp, ParseFormatRoundTrip) {
  const std::vector<std::pair<std::string_view, std::string_view>> round_trip{
      {"192.0.2.1", "192.0.2.1"},
      {"::", "::"},
      {"::1", "::1"},
      {"1::", "1::"},
      {"fe80::1", "fe80::1"},
      {"2001:0db8:0000:0000:0000:0000:0002:0001", "2001:db8::2:1"},
      {"::ffff:192.0.2.1", "::ffff:192.0.2.1"},
      {"1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"},
      {"0:0:1:0:0:0:2:3", "0:0:1::2:3"},
      {"1:0:0:2:0:0:3:4", "1::2:0:0:3:4"},
      {"1:0:2:0:3:0:4:0", "1:0:2:0:3:0:4:0"},
  };
  for (const auto& [literal, canonical] : round_trip) {
    const auto parsed = parse_gateway_ip(literal);
    ASSERT_TRUE(parsed.has_value()) << "literal=" << literal;
    EXPECT_EQ(format_gateway_ip(*parsed), canonical)
        << "literal=" << literal;
  }
}

// ---- 3. CIDR primitives -------------------------------------------------------

TEST(M10GatewayCidr, ParsesPrefixRanges) {
  EXPECT_TRUE(parse_gateway_cidr("10.0.0.0/8").has_value());
  EXPECT_TRUE(parse_gateway_cidr("fe80::/10").has_value());
  EXPECT_TRUE(parse_gateway_cidr("::/0").has_value());
  EXPECT_TRUE(parse_gateway_cidr("0.0.0.0/0").has_value());

  // No slash, empty address part, empty prefix, oversized prefix, non-digits.
  EXPECT_FALSE(parse_gateway_cidr("10.0.0.0").has_value());
  EXPECT_FALSE(parse_gateway_cidr("/8").has_value());
  EXPECT_FALSE(parse_gateway_cidr("10.0.0.0/").has_value());
  EXPECT_FALSE(parse_gateway_cidr("10.0.0.0/33").has_value());
  EXPECT_FALSE(parse_gateway_cidr("fe80::/129").has_value());
  EXPECT_FALSE(parse_gateway_cidr("10.0.0.0/abc").has_value());
  EXPECT_FALSE(parse_gateway_cidr("10.0.0.0/1234").has_value());

  const auto bits = parse_gateway_cidr("10.0.0.0/8");
  ASSERT_TRUE(bits.has_value());
  EXPECT_EQ(bits->prefix_bits, 8);
  EXPECT_TRUE(bits->address.v4);
}

TEST(M10GatewayCidr, CatchAllDetection) {
  EXPECT_TRUE(gateway_cidr_is_catch_all(make_cidr("0.0.0.0/0")));
  EXPECT_TRUE(gateway_cidr_is_catch_all(make_cidr("::/0")));
  EXPECT_FALSE(gateway_cidr_is_catch_all(make_cidr("0.0.0.0/8")));
  EXPECT_FALSE(gateway_cidr_is_catch_all(make_cidr("10.0.0.0/1")));
  EXPECT_FALSE(gateway_cidr_is_catch_all(make_cidr("::/1")));
}

TEST(M10GatewayCidr, ContainsMatchesPrefixBits) {
  const auto ten_eighth = make_cidr("10.0.0.0/8");
  EXPECT_TRUE(gateway_cidr_contains(ten_eighth, make_ip("10.0.0.1")));
  EXPECT_TRUE(gateway_cidr_contains(ten_eighth, make_ip("10.255.0.1")));
  EXPECT_FALSE(gateway_cidr_contains(ten_eighth, make_ip("11.0.0.1")));
  EXPECT_FALSE(gateway_cidr_contains(ten_eighth, make_ip("9.255.255.255")));

  const auto host_route = make_cidr("10.1.2.3/32");
  EXPECT_TRUE(gateway_cidr_contains(host_route, make_ip("10.1.2.3")));
  EXPECT_FALSE(gateway_cidr_contains(host_route, make_ip("10.1.2.4")));

  const auto doc = make_cidr("192.0.2.0/24");
  EXPECT_TRUE(gateway_cidr_contains(doc, make_ip("192.0.2.0")));
  EXPECT_TRUE(gateway_cidr_contains(doc, make_ip("192.0.2.255")));
  EXPECT_FALSE(gateway_cidr_contains(doc, make_ip("192.0.3.0")));

  // fe80::/10 covers the whole first-group range fe80..febf (top ten bits
  // 1111111010), including fe81:: and fe80:ffff::; fec0:: falls outside.
  const auto link_local = make_cidr("fe80::/10");
  EXPECT_TRUE(gateway_cidr_contains(link_local, make_ip("fe80::1")));
  EXPECT_TRUE(gateway_cidr_contains(link_local, make_ip("fe80:ffff::1")));
  EXPECT_TRUE(gateway_cidr_contains(link_local, make_ip("fe81::1")));
  EXPECT_TRUE(gateway_cidr_contains(link_local, make_ip("febf::1")));
  EXPECT_FALSE(gateway_cidr_contains(link_local, make_ip("fe7f::1")));
  EXPECT_FALSE(gateway_cidr_contains(link_local, make_ip("fec0::1")));

  const auto v6_all = make_cidr("::/0");
  EXPECT_TRUE(gateway_cidr_contains(v6_all, make_ip("2001:db8::1")));
  EXPECT_TRUE(gateway_cidr_contains(v6_all, make_ip("::")));

  // Family isolation: a v4 CIDR never matches a v6 address and vice versa,
  // even with prefix 0.
  EXPECT_FALSE(gateway_cidr_contains(make_cidr("0.0.0.0/0"), make_ip("::1")));
  EXPECT_FALSE(gateway_cidr_contains(make_cidr("::/0"), make_ip("10.0.0.1")));
  EXPECT_FALSE(gateway_cidr_contains(ten_eighth, make_ip("::a00:1")));
}

// ---- 4. Host grammar regression (this round's tail-compression fix) ----------

TEST(M10GatewayHost, TailCompressionLiteralsAreLegal) {
  EXPECT_TRUE(valid_gateway_host("fe80::"));
  EXPECT_TRUE(valid_gateway_host("1::"));
  EXPECT_TRUE(valid_gateway_host("2001:db8::"));
  EXPECT_TRUE(valid_gateway_host("::"));
  EXPECT_FALSE(valid_gateway_host("1::2::3"));
  EXPECT_FALSE(valid_gateway_host(":::1"));
  EXPECT_FALSE(valid_gateway_host("1:2:3:4:5:6:7:8::"));
  EXPECT_FALSE(valid_gateway_host("1:2:3:4:5:6:7"));
}

// ---- 5. validate_gateway_profile axes ----------------------------------------

void expect_profile_error(const GatewayProfileConfig& profile,
                          std::string_view detail) {
  const auto result = validate_gateway_profile(profile);
  ASSERT_FALSE(result);
  ASSERT_NE(result.error_if(), nullptr) << detail;
  EXPECT_EQ(result.error_if()->code(), ErrorCode::configuration) << detail;
  EXPECT_EQ(result.error_if()->component(), "gateway") << detail;
  EXPECT_EQ(result.error_if()->safe_detail(), detail) << detail;
}

TEST(M10GatewayProfile, BaselineProfileValidates) {
  const auto result = validate_gateway_profile(base_profile());
  EXPECT_TRUE(result);
}

TEST(M10GatewayProfile, RejectsBadName) {
  auto profile = base_profile();
  profile.name = "Office";
  expect_profile_error(profile, "gateway_profile_name_invalid");
  profile = base_profile();
  profile.name = "";
  expect_profile_error(profile, "gateway_profile_name_invalid");
  profile = base_profile();
  profile.name = std::string(65U, 'p');
  expect_profile_error(profile, "gateway_profile_name_invalid");
}

TEST(M10GatewayProfile, RejectsEmptyTargetList) {
  auto profile = base_profile();
  profile.allowed_cidrs = {};
  expect_profile_error(profile, "gateway_profile_targets_empty");
}

TEST(M10GatewayProfile, RejectsCatchAllWithoutInternet) {
  auto profile = base_profile();
  profile.allowed_cidrs = {make_cidr("0.0.0.0/0")};
  profile.allow_internet = false;
  expect_profile_error(profile, "gateway_profile_catch_all_without_internet");

  profile = base_profile();
  profile.allowed_cidrs = {make_cidr("::/0")};
  expect_profile_error(profile, "gateway_profile_catch_all_without_internet");

  // Non-catch-all /0-like-but-not prefixes stay legal without the flag.
  profile = base_profile();
  profile.allowed_cidrs = {make_cidr("128.0.0.0/1")};
  EXPECT_TRUE(validate_gateway_profile(profile));
}

TEST(M10GatewayProfile, AcceptsCatchAllWithInternet) {
  auto profile = base_profile();
  profile.allow_internet = true;
  profile.allowed_cidrs = {make_cidr("0.0.0.0/0"), make_cidr("::/0")};
  EXPECT_TRUE(validate_gateway_profile(profile));
}

TEST(M10GatewayProfile, RejectsInvalidPortRanges) {
  auto profile = base_profile();
  profile.allowed_ports = {{.low = 0U, .high = 1024U}};
  expect_profile_error(profile, "gateway_profile_ports_invalid");

  profile = base_profile();
  profile.allowed_ports = {{.low = 8090U, .high = 8080U}};
  expect_profile_error(profile, "gateway_profile_ports_invalid");

  // Empty port list is structurally legal (it denies every port at admission).
  profile = base_profile();
  profile.allowed_ports = {};
  EXPECT_TRUE(validate_gateway_profile(profile));
}

TEST(M10GatewayProfile, RejectsConcurrencyOutOfRange) {
  auto profile = base_profile();
  profile.max_concurrent_streams_per_session = 0U;
  expect_profile_error(profile, "gateway_profile_concurrency_invalid");

  profile = base_profile();
  profile.max_concurrent_streams_per_session = 65U;
  expect_profile_error(profile, "gateway_profile_concurrency_invalid");

  profile = base_profile();
  profile.max_concurrent_streams_per_profile = 0U;
  expect_profile_error(profile, "gateway_profile_concurrency_invalid");

  profile = base_profile();
  profile.max_concurrent_streams_per_profile = 65U;
  expect_profile_error(profile, "gateway_profile_concurrency_invalid");

  profile = base_profile();
  profile.max_concurrent_streams_per_session = hard_max_concurrent_gateway_streams;
  profile.max_concurrent_streams_per_profile = hard_max_concurrent_gateway_streams;
  EXPECT_TRUE(validate_gateway_profile(profile));
}

TEST(M10GatewayProfile, RejectsQuotaOutOfRange) {
  auto profile = base_profile();
  profile.max_profile_bytes = 0U;
  expect_profile_error(profile, "gateway_profile_quota_invalid");

  profile = base_profile();
  profile.max_profile_bytes = max_gateway_profile_bytes_hard + 1U;
  expect_profile_error(profile, "gateway_profile_quota_invalid");

  profile = base_profile();
  profile.max_profile_bytes_per_second = 0U;
  expect_profile_error(profile, "gateway_profile_quota_invalid");

  profile = base_profile();
  profile.max_profile_bytes_per_second =
      max_gateway_profile_bytes_per_second_hard + 1U;
  expect_profile_error(profile, "gateway_profile_quota_invalid");

  profile = base_profile();
  profile.max_profile_bytes = max_gateway_profile_bytes_hard;
  profile.max_profile_bytes_per_second =
      max_gateway_profile_bytes_per_second_hard;
  EXPECT_TRUE(validate_gateway_profile(profile));
}

TEST(M10GatewayProfile, RejectsTimeoutsOutOfRange) {
  auto profile = base_profile();
  profile.stream_idle_timeout = 500ms;
  expect_profile_error(profile, "gateway_profile_timeout_invalid");

  profile = base_profile();
  profile.stream_idle_timeout = 2h;
  expect_profile_error(profile, "gateway_profile_timeout_invalid");

  profile = base_profile();
  profile.stream_max_duration = max_gateway_stream_duration + 1ms;
  expect_profile_error(profile, "gateway_profile_timeout_invalid");

  profile = base_profile();
  profile.dial_deadline = max_gateway_dial_deadline + 1ms;
  expect_profile_error(profile, "gateway_profile_timeout_invalid");

  profile = base_profile();
  profile.dial_deadline = 500ms;
  expect_profile_error(profile, "gateway_profile_timeout_invalid");

  // Boundary values are exactly the frozen caps.
  profile = base_profile();
  profile.stream_idle_timeout = 1000ms;
  profile.stream_max_duration = max_gateway_stream_duration;
  profile.dial_deadline = max_gateway_dial_deadline;
  EXPECT_TRUE(validate_gateway_profile(profile));
}

// ---- 6. validate_gateway_profiles (set rules) --------------------------------

TEST(M10GatewayProfileSet, RejectsDuplicateNames) {
  std::vector<GatewayProfileConfig> profiles{base_profile(), base_profile()};
  profiles[1].allowed_cidrs = {make_cidr("192.0.2.0/24")};
  const auto result = validate_gateway_profiles(profiles);
  ASSERT_FALSE(result);
  ASSERT_NE(result.error_if(), nullptr);
  EXPECT_EQ(result.error_if()->code(), ErrorCode::configuration);
  EXPECT_EQ(result.error_if()->component(), "gateway");
  EXPECT_EQ(result.error_if()->safe_detail(), "gateway_profile_name_duplicate");
}

TEST(M10GatewayProfileSet, RejectsMoreThanHardCapProfiles) {
  std::vector<GatewayProfileConfig> profiles;
  profiles.reserve(max_gateway_profiles_per_endpoint_hard + 1U);
  for (std::size_t index = 0U;
       index <= max_gateway_profiles_per_endpoint_hard; ++index) {
    auto profile = base_profile();
    profile.name = "p" + std::to_string(index);
    profiles.push_back(std::move(profile));
  }
  const auto result = validate_gateway_profiles(profiles);
  ASSERT_FALSE(result);
  ASSERT_NE(result.error_if(), nullptr);
  EXPECT_EQ(result.error_if()->safe_detail(), "gateway_profile_count_invalid");
  EXPECT_EQ(result.error_if()->code(), ErrorCode::configuration);
  EXPECT_EQ(result.error_if()->component(), "gateway");
}

TEST(M10GatewayProfileSet, AcceptsSixteenDistinctProfiles) {
  std::vector<GatewayProfileConfig> profiles;
  for (std::size_t index = 0U; index < max_gateway_profiles_per_endpoint;
       ++index) {
    auto profile = base_profile();
    profile.name = "office-" + std::to_string(index);
    profiles.push_back(std::move(profile));
  }
  EXPECT_TRUE(validate_gateway_profiles(profiles));
}

TEST(M10GatewayProfileSet, EmptySetIsValid) {
  const std::vector<GatewayProfileConfig> profiles;
  EXPECT_TRUE(validate_gateway_profiles(profiles));
}

// ---- 7. Admission matrix (M10-05) ---------------------------------------------

TEST(M10GatewayAdmission, NamedProfileNotFoundPolicyDenied) {
  const std::vector<GatewayProfileConfig> profiles{base_profile()};
  const auto admission = admit_gateway_connection(
      profiles, connect_request("10.1.2.3", 443U, "datacenter"),
      std::vector<GatewayIp>{make_ip("10.1.2.3")}, idle_context());
  expect_refused(admission, GatewayRefusal::policy_denied);
}

TEST(M10GatewayAdmission, EmptyProfileNameUsesSoleProfile) {
  const std::vector<GatewayProfileConfig> profiles{base_profile()};
  const auto admission = admit_gateway_connection(
      profiles, connect_request("10.1.2.3", 443U, ""),
      std::vector<GatewayIp>{make_ip("10.1.2.3")}, idle_context());
  ASSERT_TRUE(admission.allowed);
  ASSERT_NE(admission.profile, nullptr);
  EXPECT_EQ(admission.profile->name, "office");
  ASSERT_EQ(admission.dial_addresses.size(), 1U);
  EXPECT_EQ(admission.dial_addresses[0], make_ip("10.1.2.3"));
}

TEST(M10GatewayAdmission, EmptyProfileNameAmbiguousIsNotEnabled) {
  std::vector<GatewayProfileConfig> profiles{base_profile(), base_profile()};
  profiles[1].name = "home";
  profiles[1].allowed_cidrs = {make_cidr("192.168.0.0/16")};
  const auto admission = admit_gateway_connection(
      profiles, connect_request("10.1.2.3", 443U, ""),
      std::vector<GatewayIp>{make_ip("10.1.2.3")}, idle_context());
  expect_refused(admission, GatewayRefusal::not_enabled);
}

TEST(M10GatewayAdmission, EmptyProfileSetWithEmptyNameIsNotEnabled) {
  const std::vector<GatewayProfileConfig> profiles;
  const auto admission = admit_gateway_connection(
      profiles, connect_request("10.1.2.3", 443U, ""),
      std::vector<GatewayIp>{make_ip("10.1.2.3")}, idle_context());
  expect_refused(admission, GatewayRefusal::not_enabled);
}

TEST(M10GatewayAdmission, NamedProfileSelectionByExactName) {
  std::vector<GatewayProfileConfig> profiles{base_profile(), base_profile()};
  profiles[1].name = "home";
  profiles[1].allowed_cidrs = {make_cidr("192.168.0.0/16")};
  const auto home = admit_gateway_connection(
      profiles, connect_request("192.168.1.10", 443U, "home"),
      std::vector<GatewayIp>{make_ip("192.168.1.10")}, idle_context());
  ASSERT_TRUE(home.allowed);
  ASSERT_NE(home.profile, nullptr);
  EXPECT_EQ(home.profile->name, "home");
  // The other profile's policy does not leak into the named selection.
  const auto office = admit_gateway_connection(
      profiles, connect_request("192.168.1.10", 443U, "office"),
      std::vector<GatewayIp>{make_ip("192.168.1.10")}, idle_context());
  expect_refused(office, GatewayRefusal::policy_denied);
}

TEST(M10GatewayAdmission, PortOutsideAllowlistDenied) {
  const std::vector<GatewayProfileConfig> profiles{base_profile()};
  const auto denied = admit_gateway_connection(
      profiles, connect_request("10.1.2.3", 80U, "office"),
      std::vector<GatewayIp>{make_ip("10.1.2.3")}, idle_context());
  expect_refused(denied, GatewayRefusal::policy_denied);

  // Range upper edge 8090 is inside {{443,443},{8080,8090}}.
  const auto edge = admit_gateway_connection(
      profiles, connect_request("10.1.2.3", 8090U, "office"),
      std::vector<GatewayIp>{make_ip("10.1.2.3")}, idle_context());
  ASSERT_TRUE(edge.allowed);
  EXPECT_EQ(edge.profile->name, "office");

  // Just past the range (8091) is outside.
  const auto past = admit_gateway_connection(
      profiles, connect_request("10.1.2.3", 8091U, "office"),
      std::vector<GatewayIp>{make_ip("10.1.2.3")}, idle_context());
  expect_refused(past, GatewayRefusal::policy_denied);
}

TEST(M10GatewayAdmission, EmptyPortListDeniesEverything) {
  auto profile = base_profile();
  profile.allowed_ports = {};
  const std::vector<GatewayProfileConfig> profiles{profile};
  const auto admission = admit_gateway_connection(
      profiles, connect_request("10.1.2.3", 443U, "office"),
      std::vector<GatewayIp>{make_ip("10.1.2.3")}, idle_context());
  expect_refused(admission, GatewayRefusal::policy_denied);
}

TEST(M10GatewayAdmission, TargetInsideAllowlistIsDialable) {
  const std::vector<GatewayProfileConfig> profiles{base_profile()};
  const auto admission = admit_gateway_connection(
      profiles, connect_request("10.1.2.3", 443U, "office"),
      std::vector<GatewayIp>{make_ip("10.1.2.3")}, idle_context());
  ASSERT_TRUE(admission.allowed);
  ASSERT_NE(admission.profile, nullptr);
  ASSERT_EQ(admission.dial_addresses.size(), 1U);
  EXPECT_EQ(admission.dial_addresses[0], make_ip("10.1.2.3"));
}

TEST(M10GatewayAdmission, TargetOutsideAllowlistWithoutInternetDenied) {
  const std::vector<GatewayProfileConfig> profiles{base_profile()};
  const auto admission = admit_gateway_connection(
      profiles, connect_request("203.0.113.5", 443U, "office"),
      std::vector<GatewayIp>{make_ip("203.0.113.5")}, idle_context());
  expect_refused(admission, GatewayRefusal::policy_denied);
}

// The built-in deny list (loopback, unspecified, link-local, multicast,
// broadcast, CGNAT) must survive a fully permissive profile: the CIDR
// allowlist cannot re-admit a denied address, and deny beats allow.
TEST(M10GatewayAdmission, BuiltinDenyListFiltersEveryRange) {
  const std::vector<GatewayProfileConfig> profiles{internet_profile()};
  const std::vector<std::pair<std::string, std::string_view>> targets{
      {"127.0.0.1", "IPv4 loopback"},
      {"127.255.255.254", "IPv4 loopback end"},
      {"0.0.0.1", "this-network"},
      {"169.254.1.1", "IPv4 link-local"},
      {"224.0.0.1", "IPv4 multicast"},
      {"255.255.255.255", "IPv4 broadcast"},
      {"100.64.0.1", "CGNAT"},
      {"::", "IPv6 unspecified"},
      {"::1", "IPv6 loopback"},
      {"fe80::1", "IPv6 link-local"},
      {"ff02::1", "IPv6 multicast"},
  };
  for (const auto& [literal, label] : targets) {
    const auto admission = admit_gateway_connection(
        profiles, connect_request(literal, 443U, "internet"),
        std::vector<GatewayIp>{make_ip(literal)}, idle_context());
    EXPECT_FALSE(admission.allowed) << label << " target=" << literal;
    EXPECT_EQ(admission.refusal, GatewayRefusal::policy_denied)
        << label << " target=" << literal;
    EXPECT_TRUE(admission.dial_addresses.empty()) << label;
  }
}

// End-to-end security property behind the matrix above: the compressed
// loopback literal "::1" must be denied. The engine receives B-side
// resolution output, so this exercises parse_gateway_ip + admission the way
// the serving side will (IP literal resolves to itself).
TEST(M10GatewayAdmission, CompressedLoopbackLiteralIsDeniedEndToEnd) {
  const std::vector<GatewayProfileConfig> profiles{internet_profile()};
  for (const auto* literal : {"::1", "fe80::1", "ff02::1"}) {
    const auto resolved = parse_gateway_ip(literal);
    ASSERT_TRUE(resolved.has_value()) << literal;
    const auto admission = admit_gateway_connection(
        profiles, connect_request(literal, 443U, "internet"),
        std::vector<GatewayIp>{*resolved}, idle_context());
    EXPECT_FALSE(admission.allowed) << "literal=" << literal;
    EXPECT_EQ(admission.refusal, GatewayRefusal::policy_denied)
        << "literal=" << literal;
  }
}

// The deny list is a table of *byte ranges*: it must hold for the canonical
// byte layout a real B-side resolver returns (all-zero groups with the final
// byte 0x01 for ::1), independent of the compressed-literal text form.
TEST(M10GatewayAdmission, BuiltinDenyListCoversCanonicalResolverBytes) {
  const std::vector<GatewayProfileConfig> profiles{internet_profile()};
  const auto canonical = [](std::array<std::uint16_t, 8U> groups) {
    GatewayIp address;
    address.v4 = false;
    for (std::size_t group = 0U; group < 8U; ++group) {
      address.bytes[group * 2U] = static_cast<std::byte>(groups[group] >> 8U);
      address.bytes[group * 2U + 1U] = static_cast<std::byte>(groups[group]);
    }
    return address;
  };
  const std::vector<std::pair<std::array<std::uint16_t, 8U>, const char*>> targets{
      {{{0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U}}, "::1"},
      {{{0xfe80U, 0U, 0U, 0U, 0U, 0U, 0U, 1U}}, "fe80::1"},
      {{{0xff02U, 0U, 0U, 0U, 0U, 0U, 0U, 1U}}, "ff02::1"},
      {{{0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}}, "::"},
  };
  for (const auto& [groups, label] : targets) {
    const auto admission = admit_gateway_connection(
        profiles, connect_request("example.invalid", 443U, "internet"),
        std::vector<GatewayIp>{canonical(groups)}, idle_context());
    EXPECT_FALSE(admission.allowed) << "canonical " << label;
    EXPECT_EQ(admission.refusal, GatewayRefusal::policy_denied)
        << "canonical " << label;
    EXPECT_TRUE(admission.dial_addresses.empty()) << "canonical " << label;
  }
}

TEST(M10GatewayAdmission, ProfileDeniedCidrsWinOverAllowlist) {
  auto profile = internet_profile();
  profile.name = "office";
  profile.denied_cidrs = {make_cidr("192.0.2.0/24")};  // management segment
  const std::vector<GatewayProfileConfig> profiles{profile};

  const auto alone = admit_gateway_connection(
      profiles, connect_request("192.0.2.7", 443U, "office"),
      std::vector<GatewayIp>{make_ip("192.0.2.7")}, idle_context());
  expect_refused(alone, GatewayRefusal::policy_denied);

  // Mixed resolution: the denied address is filtered, the survivor dials and
  // the input order of survivors is preserved.
  const auto mixed = admit_gateway_connection(
      profiles, connect_request("mgmt.example", 443U, "office"),
      std::vector<GatewayIp>{make_ip("192.0.2.7"), make_ip("203.0.113.5")},
      idle_context());
  ASSERT_TRUE(mixed.allowed);
  ASSERT_EQ(mixed.dial_addresses.size(), 1U);
  EXPECT_EQ(mixed.dial_addresses[0], make_ip("203.0.113.5"));

  const auto reversed = admit_gateway_connection(
      profiles, connect_request("mgmt.example", 443U, "office"),
      std::vector<GatewayIp>{make_ip("203.0.113.5"), make_ip("192.0.2.7")},
      idle_context());
  ASSERT_TRUE(reversed.allowed);
  ASSERT_EQ(reversed.dial_addresses.size(), 1U);
  EXPECT_EQ(reversed.dial_addresses[0], make_ip("203.0.113.5"));
}

TEST(M10GatewayAdmission, AllAddressesFilteredPolicyDenied) {
  // Both resolved addresses fall in the (single) denied range.
  auto profile = internet_profile();
  profile.name = "office";
  profile.denied_cidrs = {make_cidr("192.0.2.0/24")};
  const std::vector<GatewayProfileConfig> profiles{profile};
  const auto admission = admit_gateway_connection(
      profiles, connect_request("mgmt.example", 443U, "office"),
      std::vector<GatewayIp>{make_ip("192.0.2.7"), make_ip("192.0.2.9")},
      idle_context());
  expect_refused(admission, GatewayRefusal::policy_denied);
}

TEST(M10GatewayAdmission, SessionConcurrencyExhausted) {
  auto profile = base_profile();
  profile.max_concurrent_streams_per_session = 8U;
  profile.max_concurrent_streams_per_profile = 16U;
  const std::vector<GatewayProfileConfig> profiles{profile};
  GatewayAdmissionContext context;
  context.streams_active_session = 8U;
  context.streams_active_profile = 0U;
  const auto admission = admit_gateway_connection(
      profiles, connect_request("10.1.2.3", 443U, "office"),
      std::vector<GatewayIp>{make_ip("10.1.2.3")}, context);
  expect_quota_refused(admission);

  // One below the cap still admits.
  context.streams_active_session = 7U;
  const auto below = admit_gateway_connection(
      profiles, connect_request("10.1.2.3", 443U, "office"),
      std::vector<GatewayIp>{make_ip("10.1.2.3")}, context);
  EXPECT_TRUE(below.allowed);
}

TEST(M10GatewayAdmission, ProfileConcurrencyExhausted) {
  auto profile = base_profile();
  profile.max_concurrent_streams_per_session = 8U;
  profile.max_concurrent_streams_per_profile = 16U;
  const std::vector<GatewayProfileConfig> profiles{profile};
  GatewayAdmissionContext context;
  context.streams_active_session = 0U;
  context.streams_active_profile = 16U;
  const auto admission = admit_gateway_connection(
      profiles, connect_request("10.1.2.3", 443U, "office"),
      std::vector<GatewayIp>{make_ip("10.1.2.3")}, context);
  expect_quota_refused(admission);
}

TEST(M10GatewayAdmission, ProfileByteQuotaExhausted) {
  auto profile = base_profile();
  profile.max_profile_bytes = 1024U;
  const std::vector<GatewayProfileConfig> profiles{profile};
  GatewayAdmissionContext context;
  context.profile_bytes_used = 1024U;
  const auto admission = admit_gateway_connection(
      profiles, connect_request("10.1.2.3", 443U, "office"),
      std::vector<GatewayIp>{make_ip("10.1.2.3")}, context);
  expect_quota_refused(admission);

  context.profile_bytes_used = 1023U;
  const auto below = admit_gateway_connection(
      profiles, connect_request("10.1.2.3", 443U, "office"),
      std::vector<GatewayIp>{make_ip("10.1.2.3")}, context);
  EXPECT_TRUE(below.allowed);
}

TEST(M10GatewayAdmission, PositiveInternetPath) {
  auto profile = internet_profile();
  profile.name = "office";
  const std::vector<GatewayProfileConfig> profiles{profile};
  const auto admission = admit_gateway_connection(
      profiles, connect_request("8.8.8.8", 443U, "office"),
      std::vector<GatewayIp>{make_ip("8.8.8.8")}, idle_context());
  ASSERT_TRUE(admission.allowed);
  ASSERT_NE(admission.profile, nullptr);
  EXPECT_EQ(admission.profile->name, "office");
  ASSERT_EQ(admission.dial_addresses.size(), 1U);
  EXPECT_EQ(admission.dial_addresses[0], make_ip("8.8.8.8"));
}

// ---- 8. NodeConfig / Node::create wiring -------------------------------------

class M10GatewayNodeTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root = std::filesystem::path{HEYAKI_M10_GATEWAY_TEST_STATE_DIR} /
           ("node-" + std::to_string(::testing::UnitTest::GetInstance()
                                          ->random_seed()));
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root);
    // The profile store rejects world/group-readable state directories, and
    // the intermediate m10-gateway dir is created by this suite too.
    std::filesystem::permissions(root.parent_path(), std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    std::filesystem::permissions(root, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
  }

  void TearDown() override {
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
  }

  Result<Node> make_node(std::vector<GatewayProfileConfig> gateway_profiles) {
    ProfileOpenOptions options;
    options.secret_backend.prefer_os_backend = false;
    auto profile = ProfileStore::create(root / "profile.sqlite", options);
    if (!profile) {
      return Result<Node>::failure(*profile.error_if());
    }
    PasswordVerifier verifier{.format_version = 1U,
                              .parameters = PasswordHashParameters{},
                              .encoded = "$argon2id$v=19$m=65536,t=2,p=1$test$test"};
    LocalProfileInitialization initialization{
        .application_id = "com.example.m10-gateway",
        .password_verifier = std::move(verifier),
        .password_generation = 1U,
        .pairing_policy = PairingPolicy{},
        .lan = LanConfiguration{}};
    auto initialized = profile.value_if()->initialize_local(initialization);
    if (!initialized) {
      return Result<Node>::failure(*initialized.error_if());
    }
    store.emplace(std::move(*profile.value_if()));
    LanConfiguration lan;
    lan.enabled = false;
    NodeConfig config{.profile = &*store,
                      .runtime = nullptr,
                      .application_id = "com.example.m10-gateway",
                      .lan_override = lan,
                      .runtime_config = RuntimeConfig{},
                      .signaling_validator = {},
                      .signaling_handler = {},
                      .relay_override = std::nullopt,
                      .path_policy_override = std::nullopt,
                      .pairing_failure_threshold = 0U,
                      .pairing_backoff_base = std::chrono::milliseconds{0},
                      .pairing_backoff_max = std::chrono::milliseconds{0},
                      .pairing_grant_ttl_milliseconds = 0U,
                      .event_subscriber_queue_items = 0U,
                      .event_max_subscriptions_per_peer = 0U,
                      .file_receive_roots = {},
                      .file_max_peer_receive_bytes = 0U,
                      .shell_profiles = {},
                      .gateway_profiles = std::move(gateway_profiles),
                      .gateway_confirm_sink = {}};
    return Node::create(std::move(config));
  }

  std::filesystem::path root;
  std::optional<ProfileStore> store;
};

TEST_F(M10GatewayNodeTest, CreateFailsOnInvalidGatewayProfile) {
  auto invalid = base_profile();
  invalid.allowed_cidrs = {};
  auto node = make_node({invalid});
  ASSERT_FALSE(node);
  ASSERT_NE(node.error_if(), nullptr);
  EXPECT_EQ(node.error_if()->code(), ErrorCode::configuration);
  EXPECT_EQ(node.error_if()->component(), "gateway");
  EXPECT_EQ(node.error_if()->safe_detail(), "gateway_profile_targets_empty");
}

TEST_F(M10GatewayNodeTest, CreateFailsOnDuplicateGatewayProfileNames) {
  auto node = make_node({base_profile(), base_profile()});
  ASSERT_FALSE(node);
  ASSERT_NE(node.error_if(), nullptr);
  EXPECT_EQ(node.error_if()->code(), ErrorCode::configuration);
  EXPECT_EQ(node.error_if()->safe_detail(), "gateway_profile_name_duplicate");
}

TEST_F(M10GatewayNodeTest, CreateSucceedsWithValidGatewayProfile) {
  auto node = make_node({base_profile()});
  ASSERT_TRUE(node) << node.error_if()->safe_detail();
  auto shutdown = node.value_if()->shutdown();
  EXPECT_TRUE(shutdown.stopped);
}

TEST_F(M10GatewayNodeTest, CreateSucceedsWithEmptyGatewayProfiles) {
  auto node = make_node({});
  ASSERT_TRUE(node) << node.error_if()->safe_detail();
  auto shutdown = node.value_if()->shutdown();
  EXPECT_TRUE(shutdown.stopped);
}

// ---- 9. M10-03 template exclusion regression ---------------------------------

// Collapses every whitespace run to a single space so brace lists split
// across source lines compare stably.
std::string normalize_ws(std::string_view text) {
  std::string out;
  bool pending_space = false;
  for (const char c : text) {
    if (std::isspace(static_cast<unsigned char>(c))) {
      pending_space = !out.empty();
      continue;
    }
    if (pending_space) {
      out.push_back(' ');
      pending_space = false;
    }
    out.push_back(c);
  }
  return out;
}

// Extracts the brace-initializer scope list that follows `anchor` in the TUI
// source (the default pairing templates), so the regression can assert the
// frozen read-only scope set with no gateway.* entries.
std::optional<std::string> scope_list_after(const std::string& source,
                                            std::string_view anchor,
                                            bool after_return) {
  auto position = source.find(std::string{anchor});
  if (position == std::string::npos) {
    return std::nullopt;
  }
  if (after_return) {
    const auto returned = source.find("return", position);
    if (returned == std::string::npos) {
      return std::nullopt;
    }
    position = returned;
  }
  const auto open = source.find('{', position);
  const auto close = source.find('}', position);
  if (open == std::string::npos || close == std::string::npos || close < open) {
    return std::nullopt;
  }
  return normalize_ws(source.substr(open, close - open + 1U));
}

std::optional<std::string> read_file(const std::filesystem::path& path) {
  std::ifstream input(path);
  if (!input) {
    return std::nullopt;
  }
  return std::string{std::istreambuf_iterator<char>(input),
                     std::istreambuf_iterator<char>()};
}

TEST(M10GatewayScopeExclusion, TuiDefaultTemplatesContainNoGatewayScopes) {
  const std::filesystem::path tui_dir{HEYAKI_M10_TUI_DIR};

  const auto local_setup = read_file(tui_dir / "local_setup.cpp");
  ASSERT_TRUE(local_setup.has_value()) << "local_setup.cpp unreadable";
  const auto policy_list =
      scope_list_after(*local_setup, "policy.default_scopes", false);
  ASSERT_TRUE(policy_list.has_value())
      << "PairingPolicy.default_scopes initializer not found";

  const auto main_source = read_file(tui_dir / "main.cpp");
  ASSERT_TRUE(main_source.has_value()) << "main.cpp unreadable";
  // The definition (line ~566) precedes the call site, so the first anchor
  // hit is the function body whose returned list is the template.
  const auto requested_list = scope_list_after(
      *main_source, "std::vector<std::string> default_pairing_scopes()", true);
  ASSERT_TRUE(requested_list.has_value())
      << "default_pairing_scopes() body not found";

  // The frozen DEC-04 read-only template, identical on both sides.
  const std::string frozen = normalize_ws(
      "{\"message.send\", \"rpc.device.read\", \"event.telemetry.subscribe\", "
      "\"file.push:inbox\", \"stream.open\"}");
  EXPECT_EQ(*policy_list, frozen) << "local_setup.cpp default template drifted";
  EXPECT_EQ(*requested_list, frozen) << "main.cpp default template drifted";

  for (const auto* list : {&*policy_list, &*requested_list}) {
    EXPECT_EQ(list->find("gateway."), std::string::npos)
        << "gateway.* scope leaked into a default pairing template";
    EXPECT_EQ(list->find(gateway_use_scope), std::string::npos);
    EXPECT_EQ(list->find("gateway.provide:"), std::string::npos);
  }
}

// ---- 10. M10 Round 2 fix verification against an independent oracle --------
//
// The three production defects fixed this round are re-verified here with
// hand-built canonical byte layouts and the platform resolver (inet_pton /
// inet_ntop) instead of the production parser, so the checks cannot pass
// vacuously through a bug shared with the code under test. The resolver
// oracle is POSIX-only (HEYAKI_TEST_POSIX_INET, see the include guard at
// the top of this file): on Windows the oracle comparisons are skipped and
// the pure-oracle test GTEST_SKIPs, while every hand-built byte layout,
// grammar, and admission assertion below still runs.

GatewayIp v6_from_groups(const std::array<std::uint16_t, 8U>& groups) {
  GatewayIp address;
  address.v4 = false;
  for (std::size_t group = 0U; group < 8U; ++group) {
    address.bytes[group * 2U] = static_cast<std::byte>(groups[group] >> 8U);
    address.bytes[group * 2U + 1U] = static_cast<std::byte>(groups[group]);
  }
  return address;
}

// Bytes a real B-side resolver would hand the admission engine for an IPv6
// literal; false means the platform itself rejects the literal.
#ifdef HEYAKI_TEST_POSIX_INET
bool system_v6_bytes(std::string_view literal,
                     std::array<std::uint8_t, 16U>& out) {
  const std::string text{literal};
  std::array<unsigned char, 16U> raw{};
  if (::inet_pton(AF_INET6, text.c_str(), raw.data()) != 1) {
    return false;
  }
  for (std::size_t index = 0U; index < 16U; ++index) {
    out[index] = static_cast<std::uint8_t>(raw[index]);
  }
  return true;
}

std::string system_v6_text(const GatewayIp& address) {
  char buffer[INET6_ADDRSTRLEN] = {};
  const void* raw = static_cast<const void*>(address.bytes.data());
  const char* result = ::inet_ntop(AF_INET6, raw, buffer, sizeof buffer);
  if (result == nullptr) {
    return "<inet_ntop-failed>";
  }
  return std::string{result};
}
#endif  // HEYAKI_TEST_POSIX_INET

std::string groups_to_text(const std::array<std::uint16_t, 8U>& groups) {
  static constexpr char hex[] = "0123456789abcdef";
  std::string out;
  for (std::uint16_t value : groups) {
    if (!out.empty()) {
      out.push_back(':');
    }
    for (int shift = 12; shift >= 0; shift -= 4) {
      out.push_back(hex[(value >> shift) & 0xFU]);
    }
  }
  return out;
}

// D1 positive control: canonical resolver bytes for a global address must be
// admitted by the fully permissive profile, so the canonical-byte deny
// checks cannot pass merely by refusing everything IPv6.
TEST(M10GatewayD1Fix, CanonicalGlobalV6BytesAreAdmitted) {
  const std::vector<GatewayProfileConfig> profiles{internet_profile()};
  // 2001:db8::1 exactly as getaddrinfo-style resolution returns it:
  // 20 01 0d b8 followed by ten zero bytes and a final 01.
  std::array<std::uint16_t, 8U> groups{};
  groups[0] = 0x2001U;
  groups[1] = 0x0db8U;
  groups[7] = 0x0001U;
  const GatewayIp address = v6_from_groups(groups);
  EXPECT_EQ(address.bytes[0], std::byte{0x20U});
  EXPECT_EQ(address.bytes[1], std::byte{0x01U});
  EXPECT_EQ(address.bytes[2], std::byte{0x0dU});
  EXPECT_EQ(address.bytes[3], std::byte{0xb8U});
  EXPECT_EQ(address.bytes[15], std::byte{0x01U});

  const auto admission = admit_gateway_connection(
      profiles, connect_request("example.invalid", 443U, "internet"),
      std::vector<GatewayIp>{address}, idle_context());
  ASSERT_TRUE(admission.allowed);
  ASSERT_EQ(admission.dial_addresses.size(), 1U);
  EXPECT_EQ(admission.dial_addresses.front(), address);
}

// D1: the full 16-byte layout of the IPv4-mapped literal, pinning the ten
// leading zero bytes (not just the ffff/c000/0201 tail) so a head/tail
// placement slip cannot hide behind a partial check.
TEST(M10GatewayD1Fix, MappedLiteralBytesAreTenZerosThenTail) {
  const auto mapped = parse_gateway_ip("::ffff:192.0.2.1");
  ASSERT_TRUE(mapped.has_value());
  ASSERT_FALSE(mapped->v4);
  std::array<std::byte, 16U> expected{};
  expected[10] = std::byte{0xffU};
  expected[11] = std::byte{0xffU};
  expected[12] = std::byte{0xc0U};
  expected[13] = std::byte{0x00U};
  expected[14] = std::byte{0x02U};
  expected[15] = std::byte{0x01U};
  EXPECT_EQ(mapped->bytes, expected);

#ifdef HEYAKI_TEST_POSIX_INET
  // The deny literals themselves must byte-match the platform oracle.
  for (const auto* literal : {"::", "::1", "fe80::1", "ff02::1"}) {
    std::array<std::uint8_t, 16U> system_bytes{};
    ASSERT_TRUE(system_v6_bytes(literal, system_bytes)) << literal;
    const auto parsed = parse_gateway_ip(literal);
    ASSERT_TRUE(parsed.has_value()) << literal;
    for (std::size_t index = 0U; index < 16U; ++index) {
      EXPECT_EQ(parsed->bytes[index],
                static_cast<std::byte>(system_bytes[index]))
          << "byte " << index << " of " << literal;
    }
  }
#endif  // HEYAKI_TEST_POSIX_INET
}

// D1/D3 cross-check: accept/reject agreement plus byte equality with
// inet_pton over the deny-list literals and adversarial compression forms.
TEST(M10GatewayParseOracle, AgreesWithInetPtonOnV6Literals) {
#ifndef HEYAKI_TEST_POSIX_INET
  GTEST_SKIP() << "inet_pton oracle unavailable (MSVC has no arpa/inet.h)";
#else
  const std::vector<std::string_view> literals{
      "::",       "::1",           "::2",            "fe80::",
      "fe80::1",  "fe80::1%eth0",  "ff00::",         "ff02::1",
      "ff02::1:2", "2001:db8::1",  "2001:db8::192.0.2.1",
      "64:ff9b::192.0.2.33", "::ffff:192.0.2.1", "::ffff:0.0.0.0",
      "::ffff:1.2.3.4.", "::ffff:.1.2.3.4", "1:2::3:4", "1::2", "::abcd:1",
      "0:0:1:0:0:0:2:3", "1:0:0:2:0:0:3:4", "1:2:3:4:5:6:0:0",
      "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7",
      ":::1", "1:::2", "1::2::3", "1:2:3:4:5:6:7", "",
      "2001:DB8::1", "::FFFF:192.0.2.1",
  };
  for (const auto literal : literals) {
    std::array<std::uint8_t, 16U> system_bytes{};
    const bool system_ok = system_v6_bytes(literal, system_bytes);
    const auto parsed = parse_gateway_ip(literal);
    EXPECT_EQ(parsed.has_value(), system_ok)
        << "accept/reject disagreement for \"" << literal << "\"";
    if (system_ok && parsed.has_value()) {
      EXPECT_FALSE(parsed->v4) << literal;
      for (std::size_t index = 0U; index < 16U; ++index) {
        EXPECT_EQ(parsed->bytes[index],
                  static_cast<std::byte>(system_bytes[index]))
            << "byte " << index << " of " << literal;
      }
    }
  }
#endif  // HEYAKI_TEST_POSIX_INET
}

// D4 (Round 2 supplement): IPv4-mapped IPv6 targets must not dodge the
// built-in deny list through gateway_cidr_contains family isolation. Before
// the "::ffff:0:0/96" entry existed, a B-side resolver returning mapped
// bytes for "::ffff:127.0.0.1" skipped every IPv4 deny range (mapped bytes
// are v6-family) and sailed through an allow-internet profile — an
// SSRF-shaped hole. FROZEN SEMANTICS: "::ffff:0:0/96" is itself a deny-table
// entry, and deny wins over any allowlist, so the ENTIRE mapped segment is
// policy_denied — including a mapped global address such as
// "::ffff:8.8.8.8". Public destinations reach the gateway in their native
// v4/v6 form; the mapped spelling is precisely the resolver artifact the
// deny entry exists to neutralize, and blanket-denying it is the deliberate
// deny-wins decision recorded in the parameter-freeze table (docs/
// operations/parameter-freeze.md section 6a). Probe-confirmed against the
// actual binary before this assertion was written.
TEST(M10GatewayAdmission, BuiltinDenyListCoversIpv4MappedTargets) {
  const std::vector<GatewayProfileConfig> profiles{internet_profile()};

  // The bypass shapes this entry closes: mapped spellings of the IPv4 deny
  // ranges (loopback, link-local, this-network, broadcast).
  const std::vector<std::pair<std::string_view, const char*>> bypass{
      {"::ffff:127.0.0.1", "mapped IPv4 loopback"},
      {"::ffff:169.254.1.1", "mapped IPv4 link-local"},
      {"::ffff:0.0.0.1", "mapped this-network"},
      {"::ffff:255.255.255.255", "mapped IPv4 broadcast"},
  };
  for (const auto& [literal, label] : bypass) {
    const auto resolved = parse_gateway_ip(literal);
    ASSERT_TRUE(resolved.has_value()) << label << " literal=" << literal;
    ASSERT_FALSE(resolved->v4) << label << " must be v6-family bytes";
#ifdef HEYAKI_TEST_POSIX_INET
    // Tie the parsed bytes to the platform oracle so the check cannot pass
    // through a parser bug shared with production.
    std::array<std::uint8_t, 16U> system_bytes{};
    ASSERT_TRUE(system_v6_bytes(literal, system_bytes)) << literal;
    for (std::size_t index = 0U; index < 16U; ++index) {
      ASSERT_EQ(resolved->bytes[index],
                static_cast<std::byte>(system_bytes[index]))
          << "byte " << index << " of " << literal;
    }
#endif  // HEYAKI_TEST_POSIX_INET
    const auto admission = admit_gateway_connection(
        profiles, connect_request(literal, 443U, "internet"),
        std::vector<GatewayIp>{*resolved}, idle_context());
    EXPECT_FALSE(admission.allowed) << label << " target=" << literal;
    EXPECT_EQ(admission.refusal, GatewayRefusal::policy_denied)
        << label << " target=" << literal;
    EXPECT_TRUE(admission.dial_addresses.empty()) << label;
  }

  // Canonical resolver bytes (hand-built groups, not the parser) for
  // ::ffff:127.0.0.1 = [0,0,0,0,0,ffff,7f00,0001]: the deny must hold for
  // the byte layout getaddrinfo-style resolution actually returns.
  {
    const GatewayIp mapped_loopback =
        v6_from_groups({{0U, 0U, 0U, 0U, 0U, 0xffffU, 0x7f00U, 0x0001U}});
    EXPECT_EQ(mapped_loopback.bytes[10], std::byte{0xffU});
    EXPECT_EQ(mapped_loopback.bytes[11], std::byte{0xffU});
    const auto admission = admit_gateway_connection(
        profiles, connect_request("loopback.mapped", 443U, "internet"),
        std::vector<GatewayIp>{mapped_loopback}, idle_context());
    EXPECT_FALSE(admission.allowed);
    EXPECT_EQ(admission.refusal, GatewayRefusal::policy_denied);
    EXPECT_TRUE(admission.dial_addresses.empty());
  }

  // FROZEN whole-segment semantics: every address inside ::ffff:0:0/96 is
  // denied, mapped globals included (the deny entry covers the whole /96;
  // there is no per-mapped-v4-target fallthrough to the v4 deny table).
  for (const auto* literal :
       {"::ffff:8.8.8.8", "::ffff:1.1.1.1", "::ffff:0a0b:0c0d"}) {
    const auto resolved = parse_gateway_ip(literal);
    ASSERT_TRUE(resolved.has_value()) << literal;
    const auto admission = admit_gateway_connection(
        profiles, connect_request(literal, 443U, "internet"),
        std::vector<GatewayIp>{*resolved}, idle_context());
    EXPECT_FALSE(admission.allowed)
        << "mapped segment is wholly denied, target=" << literal;
    EXPECT_EQ(admission.refusal, GatewayRefusal::policy_denied)
        << "mapped segment is wholly denied, target=" << literal;
    EXPECT_TRUE(admission.dial_addresses.empty()) << literal;
  }

  // Positive controls: the same public destinations in NATIVE form are
  // admitted by the same profile, so the mapped-segment denials above are
  // the deny entry working, not a blanket refusal of everything.
  const auto native_v4 = admit_gateway_connection(
      profiles, connect_request("8.8.8.8", 443U, "internet"),
      std::vector<GatewayIp>{make_ip("8.8.8.8")}, idle_context());
  ASSERT_TRUE(native_v4.allowed);
  ASSERT_EQ(native_v4.dial_addresses.size(), 1U);
  EXPECT_EQ(native_v4.dial_addresses[0], make_ip("8.8.8.8"));

  const auto native_v6 = admit_gateway_connection(
      profiles, connect_request("2001:4860:4860::8888", 443U, "internet"),
      std::vector<GatewayIp>{make_ip("2001:4860:4860::8888")}, idle_context());
  ASSERT_TRUE(native_v6.allowed);
  ASSERT_EQ(native_v6.dial_addresses.size(), 1U);

  // Mixed dual-family resolution with one mapped address: only the native
  // survivor dials, in input order.
  const auto mixed = admit_gateway_connection(
      profiles, connect_request("dual.mapped", 443U, "internet"),
      std::vector<GatewayIp>{make_ip("::ffff:8.8.8.8"), make_ip("8.8.8.8")},
      idle_context());
  ASSERT_TRUE(mixed.allowed);
  ASSERT_EQ(mixed.dial_addresses.size(), 1U);
  EXPECT_EQ(mixed.dial_addresses[0], make_ip("8.8.8.8"));
}

// D2: the exact compression cases this round's formatter fix targeted.
TEST(M10GatewayD2Fix, TailRunCompressionAndMappedPrinting) {
  // Tail run of zero groups compresses with "::" at the end.
  EXPECT_EQ(format_gateway_ip(make_ip("1:2:3:4:5:6:0:0")), "1:2:3:4:5:6::");
  // IPv4-mapped range prints the RFC 5952 5 dotted tail, in both spellings.
  EXPECT_EQ(format_gateway_ip(make_ip("::ffff:0.0.0.0")), "::ffff:0.0.0.0");
  EXPECT_EQ(format_gateway_ip(make_ip("::ffff:10.11.12.13")),
            "::ffff:10.11.12.13");
  EXPECT_EQ(format_gateway_ip(make_ip("::ffff:0a0b:0c0d")),
            "::ffff:10.11.12.13");
  // Mid-address compression stays free of ":::" artifacts.
  EXPECT_EQ(format_gateway_ip(make_ip("2001:db8::2:1")), "2001:db8::2:1");
  EXPECT_EQ(format_gateway_ip(make_ip("1:0:0:2:0:0:3:4")), "1::2:0:0:3:4");
  EXPECT_EQ(format_gateway_ip(make_ip("0:0:1:0:0:0:2:3")), "0:0:1::2:3");
  EXPECT_EQ(format_gateway_ip(make_ip("::2")), "::2");
  for (const auto* literal : {"2001:db8::2:1", "1::2:0:0:3:4", "::ffff:0.0.0.0",
                              "1:2:3:4:5:6::", "::", "::1"}) {
    const std::string text = format_gateway_ip(make_ip(literal));
    EXPECT_EQ(text.find(":::"), std::string::npos) << literal << " -> " << text;
  }
}

// D2 exhaustive sweep: every group pattern over {0,1,2,db8,ffff}^8 (390625
// addresses) must (a) match the platform's canonical text, except this
// glibc's deprecated IPv4-compatible "::a.b.c.d" quirk where heyaki must
// instead keep the pure IPv6 form, (b) round-trip through both parsers to
// the same bytes, (c) never emit ":::", more than one "::", an overlong
// string, or a character outside [0-9a-f.:].
TEST(M10GatewayFormatOracle, SweepMatchesSystemNtopAndRoundTrips) {
  constexpr std::array<std::uint16_t, 5U> alphabet{0U, 1U, 2U, 0x0db8U,
                                                   0xffffU};
  constexpr std::uint64_t total = 390625ULL;  // 5^8
  std::array<std::size_t, 8U> digits{};
  std::size_t failures = 0U;
  for (std::uint64_t step = 0ULL; step < total && failures < 5U; ++step) {
    std::array<std::uint16_t, 8U> groups{};
    for (std::size_t group = 0U; group < 8U; ++group) {
      groups[group] = alphabet[digits[group]];
    }
    const GatewayIp address = v6_from_groups(groups);
    const std::string text = format_gateway_ip(address);
#if defined(HEYAKI_TEST_POSIX_INET)
    const std::string system_text = system_v6_text(address);
#else
    // No platform oracle: only the structural and round-trip checks below
    // run (they are all oracle-independent).
    const std::string system_text;
#endif
    std::string reason;

    if (text.size() > 39U) {
      reason = "longer than 39 characters";
    }
    if (reason.empty() && text.find(":::") != std::string::npos) {
      reason = "contains a ::: artifact";
    }
    if (reason.empty()) {
      std::size_t compressions = 0U;
      for (std::size_t at = text.find("::"); at != std::string::npos;
           at = text.find("::", at + 2U)) {
        ++compressions;
      }
      if (compressions > 1U) {
        reason = "more than one :: compression";
      }
    }
    if (reason.empty()) {
      for (char c : text) {
        const bool legal = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                           c == ':' || c == '.';
        if (!legal) {
          reason = std::string{"illegal character "} + c;
          break;
        }
      }
    }
    const auto reparsed = parse_gateway_ip(text);
    if (reason.empty() && (!reparsed.has_value() || *reparsed != address)) {
      reason = "production parser round-trip mismatch";
    }
#if defined(HEYAKI_TEST_POSIX_INET)
    if (reason.empty()) {
      std::array<std::uint8_t, 16U> system_bytes{};
      if (!system_v6_bytes(text, system_bytes)) {
        reason = "system parser rejects the formatted text";
      } else {
        for (std::size_t index = 0U; index < 16U; ++index) {
          if (address.bytes[index] !=
              static_cast<std::byte>(system_bytes[index])) {
            reason = "system parser round-trip mismatch";
            break;
          }
        }
      }
    }
#endif  // HEYAKI_TEST_POSIX_INET
    // glibc prints the deprecated IPv4-compatible range (words[0..5] all
    // zero, words[6] nonzero) as "::a.b.c.d"; RFC 5952 discourages that
    // form, heyaki keeps pure IPv6 notation there, so that range is exempt
    // from the exact-text comparison but must not contain a dot.
    bool ipv4_compatible = groups[6] != 0U;
    for (std::size_t group = 0U; group < 6U; ++group) {
      ipv4_compatible = ipv4_compatible && groups[group] == 0U;
    }
    if (ipv4_compatible) {
      if (reason.empty() && text.find('.') != std::string::npos) {
        reason = "used the deprecated IPv4-compatible dotted form";
      }
    }
#if defined(HEYAKI_TEST_POSIX_INET)
    else if (reason.empty() && text != system_text) {
      reason = "canonical text differs from inet_ntop";
    }
#endif  // HEYAKI_TEST_POSIX_INET
    if (!reason.empty()) {
      ++failures;
      ADD_FAILURE() << groups_to_text(groups) << ": text=\"" << text
                    << "\" system=\"" << system_text << "\": " << reason;
    }
    for (std::size_t digit = 0U; digit < digits.size(); ++digit) {
      digits[digit] = (digits[digit] + 1U) % alphabet.size();
      if (digits[digit] != 0U) {
        break;
      }
    }
  }
  EXPECT_EQ(failures, 0U) << "sweep produced " << failures << " failures";
}

// D2 IPv4 counterpart over {0,1,10,199,255}^4 (625 addresses).
TEST(M10GatewayFormatOracle, IPv4SweepMatchesSystemNtopAndRoundTrips) {
  constexpr std::array<unsigned, 5U> alphabet{0U, 1U, 10U, 199U, 255U};
  std::array<std::size_t, 4U> digits{};
  for (std::uint64_t step = 0ULL; step < 625ULL; ++step) {
    GatewayIp address;
    address.v4 = true;
    for (std::size_t octet = 0U; octet < 4U; ++octet) {
      address.bytes[octet] = static_cast<std::byte>(alphabet[digits[octet]]);
    }
    const std::string text = format_gateway_ip(address);
#if defined(HEYAKI_TEST_POSIX_INET)
    char system_text[INET_ADDRSTRLEN] = {};
    const void* raw = static_cast<const void*>(address.bytes.data());
    ASSERT_NE(::inet_ntop(AF_INET, raw, system_text, sizeof system_text),
              nullptr);
    EXPECT_EQ(text, std::string{system_text});
#endif  // HEYAKI_TEST_POSIX_INET
    const auto reparsed = parse_gateway_ip(text);
    ASSERT_TRUE(reparsed.has_value()) << text;
    EXPECT_TRUE(*reparsed == address) << text;
    EXPECT_EQ(reparsed->bytes[4], std::byte{0}) << "v4 must occupy 4 bytes";
    for (std::size_t digit = 0U; digit < digits.size(); ++digit) {
      digits[digit] = (digits[digit] + 1U) % alphabet.size();
      if (digits[digit] != 0U) {
        break;
      }
    }
  }
}

// D3: a leading or trailing dot is rejected by every gateway entry point,
// in agreement with the platform resolver.
TEST(M10GatewayD3Fix, LeadingAndTrailingDotsRejectedEverywhere) {
  EXPECT_FALSE(parse_gateway_ip("1.2.3.4.").has_value());
  EXPECT_FALSE(parse_gateway_ip(".1.2.3.4").has_value());
  EXPECT_FALSE(parse_gateway_cidr("1.2.3.4./32").has_value());
  EXPECT_FALSE(parse_gateway_cidr(".1.2.3.4/32").has_value());
  EXPECT_FALSE(valid_gateway_host("1.2.3.4."));
  EXPECT_FALSE(valid_gateway_host(".1.2.3.4"));
  // The embedded IPv4 tail inside an IPv6 literal shares the octet grammar.
  EXPECT_FALSE(parse_gateway_ip("::ffff:1.2.3.4.").has_value());
  EXPECT_FALSE(parse_gateway_ip("::ffff:.1.2.3.4").has_value());
  EXPECT_FALSE(valid_gateway_host("::ffff:1.2.3.4."));
  // The well-formed counterpart still parses.
  EXPECT_TRUE(parse_gateway_cidr("1.2.3.4/32").has_value());
  EXPECT_TRUE(valid_gateway_host("1.2.3.4"));
#if defined(HEYAKI_TEST_POSIX_INET)
  // Platform oracle agreement on the dot-edged forms.
  unsigned char scratch[4] = {};
  EXPECT_NE(::inet_pton(AF_INET, "1.2.3.4.", scratch), 1);
  EXPECT_NE(::inet_pton(AF_INET, ".1.2.3.4", scratch), 1);
#endif  // HEYAKI_TEST_POSIX_INET
}

// Incidental fix: the two quota refusal branches must clear dial_addresses
// so a refused connection can never leak a partially filtered dial list.
TEST(M10GatewayAdmissionQuotaClear, QuotaRefusalsLeaveNoDialAddresses) {
  auto profile = internet_profile();
  profile.name = "internet";
  profile.max_concurrent_streams_per_session = 4U;
  profile.max_concurrent_streams_per_profile = 8U;
  profile.max_profile_bytes = 1024U;
  const std::vector<GatewayProfileConfig> profiles{profile};
  const std::vector<GatewayIp> resolved{make_ip("8.8.8.8"),
                                        make_ip("2001:db8::1")};

  GatewayAdmissionContext session_cap;
  session_cap.streams_active_session = 4U;
  const auto session_refusal = admit_gateway_connection(
      profiles, connect_request("dual.example", 443U, "internet"), resolved,
      session_cap);
  expect_quota_refused(session_refusal);
  EXPECT_TRUE(session_refusal.dial_addresses.empty());

  GatewayAdmissionContext profile_cap;
  profile_cap.streams_active_profile = 8U;
  const auto profile_refusal = admit_gateway_connection(
      profiles, connect_request("dual.example", 443U, "internet"), resolved,
      profile_cap);
  expect_quota_refused(profile_refusal);
  EXPECT_TRUE(profile_refusal.dial_addresses.empty());

  GatewayAdmissionContext byte_cap;
  byte_cap.profile_bytes_used = 1024U;
  const auto byte_refusal = admit_gateway_connection(
      profiles, connect_request("dual.example", 443U, "internet"), resolved,
      byte_cap);
  expect_quota_refused(byte_refusal);
  EXPECT_TRUE(byte_refusal.dial_addresses.empty());

  // Control: with an idle context the same resolution admits both family
  // addresses, so the refusals above really are the quota branches clearing
  // an otherwise non-empty list.
  const auto admitted = admit_gateway_connection(
      profiles, connect_request("dual.example", 443U, "internet"), resolved,
      idle_context());
  ASSERT_TRUE(admitted.allowed);
  EXPECT_EQ(admitted.dial_addresses.size(), 2U);
}

}  // namespace
}  // namespace heyaki
