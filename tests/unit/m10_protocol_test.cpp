// M10 protocol 1.3 gateway change sheet (M10-01/M10-02) independent
// verification: GatewayConnect grammar/codec, the 2-byte prelude, the frozen
// refusal->StableStatus mapping, capability negotiation for gateway_v1,
// frozen golden vectors, and the ByteStream gateway send/receive gates over
// the in-memory loopback session harness.

#include "byte_stream.hpp"
#include "m4_support.hpp"
#include "m10_golden_vectors.hpp"
#include "peer_session.hpp"
#include "test_bytes.hpp"

#include "core/proto_codec.hpp"

#include <heyaki/error.hpp>
#include <heyaki/gateway.hpp>
#include <heyaki/identity.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/signaling_protocol.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

constexpr std::uint64_t kNow = 1'700'000'000'000U;

template <typename Storage, std::size_t Size = sizeof(Storage)>
Storage filled(std::uint8_t seed) {
  Storage storage{};
  auto* bytes = reinterpret_cast<std::uint8_t*>(&storage);
  for (std::size_t index = 0U; index < Size; ++index) {
    bytes[index] = static_cast<std::uint8_t>(seed + index);
  }
  return storage;
}

template <std::size_t Size>
std::array<std::byte, Size> filled_array(std::uint8_t seed) {
  std::array<std::byte, Size> value{};
  for (std::size_t index = 0U; index < Size; ++index) {
    value[index] = static_cast<std::byte>(seed + index);
  }
  return value;
}

// ---- Grammar tables -------------------------------------------------------

bool is_name_token(std::string_view value) {
  if (value.empty()) return false;
  for (const char c : value) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '_' || c == '.' || c == '-';
    if (!ok) return false;
  }
  return true;
}

TEST(M10GatewayGrammar, AcceptsLegalHosts) {
  const std::vector<std::string> valid{
      "nas",                     // single LDH label
      "intranode.lan",           // multi label
      "a-b.example.com",         // intra-label hyphen
      "192.0.2.1",               // IPv4 literal
      "::1",                     // IPv6 loopback
      "fe80::1",                 // IPv6 compressed
      "2001:db8::192.0.2.1",     // IPv6 with embedded IPv4 tail
      "::",                      // unspecified address
      "::ffff:192.0.2.1",        // IPv4-mapped
  };
  for (const auto& host : valid) {
    EXPECT_TRUE(valid_gateway_host(host)) << "host=" << host;
  }
}

TEST(M10GatewayGrammar, RejectsIllegalHosts) {
  const std::string host_nul{"a\0b", 3U};
  const std::string host_control{"a\x01b", 3U};
  const std::vector<std::pair<std::string, std::string_view>> invalid{
      {"", "empty"},
      {std::string(254U, 'a'), "254 bytes"},
      {"intranode.lan.", "trailing dot"},
      {".leading", "leading dot"},
      {"-lead", "leading hyphen"},
      {"trail-", "trailing hyphen"},
      {"under_score", "underscore"},
      {"with space", "space"},
      {host_nul, "embedded NUL"},
      {host_control, "control byte"},
      {"01.2.3.4", "IPv4 leading zero"},
      {"1.2.3.256", "IPv4 group > 255"},
      {"1.2.3.4.5", "five dotted groups"},
      {"1.2.3", "IPv4 short"},
      {":::%", "zone suffix only"},
      {"fe80::1%eth0", "zone suffix"},
      {"::::1", "double compression"},
      {"12345", "pure numeric non-IPv4"},
      {"a::b::c", "two ::"},
  };
  for (const auto& [host, label] : invalid) {
    EXPECT_FALSE(valid_gateway_host(host)) << label << " host=" << host;
  }
}

TEST(M10GatewayGrammar, HostLengthBoundaryIs253Bytes) {
  const std::string host_253 = std::string(63U, 'a') + "." + std::string(63U, 'b') +
                               "." + std::string(63U, 'c') + "." +
                               std::string(61U, 'd');
  ASSERT_EQ(host_253.size(), max_gateway_host_bytes);
  EXPECT_TRUE(valid_gateway_host(host_253));
  const std::string host_254 = std::string(63U, 'a') + "." + std::string(63U, 'b') +
                               "." + std::string(63U, 'c') + "." +
                               std::string(62U, 'd');
  ASSERT_EQ(host_254.size(), max_gateway_host_bytes + 1U);
  EXPECT_FALSE(valid_gateway_host(host_254));
}

TEST(M10GatewayGrammar, ProfileNameGrammar) {
  EXPECT_TRUE(safe_gateway_profile_name("office"));
  EXPECT_TRUE(safe_gateway_profile_name("a.b-c_d"));
  EXPECT_TRUE(safe_gateway_profile_name(std::string(64U, 'p')));
  EXPECT_FALSE(safe_gateway_profile_name(""));
  EXPECT_FALSE(safe_gateway_profile_name(std::string(65U, 'p')));
  EXPECT_FALSE(safe_gateway_profile_name("Office"));
  EXPECT_FALSE(safe_gateway_profile_name("sp ace"));
}

TEST(M10GatewayGrammar, ValidateConnectRejectsWithPermission) {
  const GatewayConnect ok{.host = "intranode.lan", .port = 443U, .profile = "office"};
  EXPECT_TRUE(validate_gateway_connect(ok));
  EXPECT_TRUE(validate_gateway_connect(
      GatewayConnect{.host = "nas", .port = 1U, .profile = ""}));

  const std::vector<std::pair<GatewayConnect, std::string_view>> invalid{
      {GatewayConnect{.host = "bad_host", .port = 443U, .profile = ""},
       "gateway_host_invalid"},
      {GatewayConnect{.host = "nas", .port = 0U, .profile = ""},
       "gateway_port_invalid"},
      {GatewayConnect{.host = "nas", .port = 443U, .profile = "Office"},
       "gateway_profile_invalid"},
  };
  for (const auto& [connect, detail] : invalid) {
    const auto result = validate_gateway_connect(connect);
    ASSERT_FALSE(result);
    ASSERT_NE(result.error_if(), nullptr);
    EXPECT_EQ(result.error_if()->code(), ErrorCode::permission) << detail;
    EXPECT_EQ(result.error_if()->component(), "gateway");
    EXPECT_EQ(result.error_if()->safe_detail(), detail);
  }
}

// ---- Codec ----------------------------------------------------------------

TEST(M10GatewayCodec, EncodeParseRoundTrip) {
  const GatewayConnect profiled{.host = "intranode.lan", .port = 443U,
                                .profile = "office"};
  const auto encoded = encode_gateway_connect(profiled);
  ASSERT_TRUE(encoded);
  // Deterministic encoding: two runs produce identical bytes.
  const auto again = encode_gateway_connect(profiled);
  ASSERT_TRUE(again);
  EXPECT_EQ(*encoded.value_if(), *again.value_if());

  const auto parsed = parse_gateway_connect(std::span<const std::byte>{
      encoded.value_if()->data(), encoded.value_if()->size()});
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->host, "intranode.lan");
  EXPECT_EQ(parsed.value_if()->port, 443U);
  EXPECT_EQ(parsed.value_if()->profile, "office");

  // Empty profile: field 3 omitted; parse yields the empty default.
  const GatewayConnect bare{.host = "10.20.30.40", .port = 8080U, .profile = ""};
  const auto encoded_bare = encode_gateway_connect(bare);
  ASSERT_TRUE(encoded_bare);
  const auto parsed_bare = parse_gateway_connect(std::span<const std::byte>{
      encoded_bare.value_if()->data(), encoded_bare.value_if()->size()});
  ASSERT_TRUE(parsed_bare);
  EXPECT_EQ(parsed_bare.value_if()->host, "10.20.30.40");
  EXPECT_EQ(parsed_bare.value_if()->port, 8080U);
  EXPECT_EQ(parsed_bare.value_if()->profile, "");
}

TEST(M10GatewayCodec, EncodeRejectsInvalidInput) {
  const std::vector<std::pair<GatewayConnect, std::string_view>> invalid{
      {GatewayConnect{.host = "bad_host", .port = 443U, .profile = ""},
       "gateway_host_invalid"},
      {GatewayConnect{.host = "nas", .port = 0U, .profile = ""},
       "gateway_port_invalid"},
      {GatewayConnect{.host = "nas", .port = 443U, .profile = "sp ace"},
       "gateway_profile_invalid"},
  };
  for (const auto& [connect, detail] : invalid) {
    const auto encoded = encode_gateway_connect(connect);
    ASSERT_FALSE(encoded);
    ASSERT_NE(encoded.error_if(), nullptr);
    EXPECT_EQ(encoded.error_if()->code(), ErrorCode::protocol) << detail;
    EXPECT_EQ(encoded.error_if()->component(), "gateway");
    EXPECT_EQ(encoded.error_if()->safe_detail(), detail);
  }
}

TEST(M10GatewayCodec, ParseStrictlyRejectsWireMalformations) {
  std::vector<std::byte> valid;
  proto_codec::append_text(valid, 1U, "nas");
  proto_codec::append_uint(valid, 2U, 443U);
  proto_codec::append_text(valid, 3U, "office");

  auto with_unknown_field = valid;
  const std::vector<std::byte> one_byte{std::byte{0x00U}};
  proto_codec::append_bytes(with_unknown_field, 4U,
                            std::span<const std::byte>{one_byte.data(), 1U});
  auto with_duplicate_host = valid;
  proto_codec::append_text(with_duplicate_host, 1U, "other");
  auto with_duplicate_port = valid;
  proto_codec::append_uint(with_duplicate_port, 2U, 8443U);
  std::vector<std::byte> missing_host;
  proto_codec::append_uint(missing_host, 2U, 443U);
  std::vector<std::byte> missing_port;
  proto_codec::append_text(missing_port, 1U, "nas");
  std::vector<std::byte> port_zero;
  proto_codec::append_text(port_zero, 1U, "nas");
  proto_codec::append_uint(port_zero, 2U, 0U);
  std::vector<std::byte> port_too_big;
  proto_codec::append_text(port_too_big, 1U, "nas");
  proto_codec::append_uint(port_too_big, 2U, 65536U);
  const std::vector<std::byte> truncated_varint{std::byte{0x0aU}};
  const std::vector<std::byte> truncated_body =
      [&valid] { auto copy = valid; copy.pop_back(); return copy; }();
  const std::vector<std::byte> length_overrun{std::byte{0x0aU}, std::byte{0x40U},
                                              std::byte{'n'}};

  const std::vector<std::pair<std::vector<std::byte>, std::string_view>> rejects{
      {with_unknown_field, "gateway_unknown_field"},
      {with_duplicate_host, "gateway_field_conflict"},
      {with_duplicate_port, "gateway_field_conflict"},
      {missing_host, "gateway_field_missing"},
      {missing_port, "gateway_field_missing"},
      {port_zero, "gateway_port_invalid"},
      {port_too_big, "gateway_port_invalid"},
  };
  for (const auto& [payload, detail] : rejects) {
    const auto parsed = parse_gateway_connect(
        std::span<const std::byte>{payload.data(), payload.size()});
    ASSERT_FALSE(parsed) << detail;
    ASSERT_NE(parsed.error_if(), nullptr) << detail;
    EXPECT_EQ(parsed.error_if()->code(), ErrorCode::protocol) << detail;
    EXPECT_EQ(parsed.error_if()->component(), "gateway") << detail;
    EXPECT_EQ(parsed.error_if()->safe_detail(), detail) << detail;
  }

  // Codec-level malformations propagate as `protocol` failures from the
  // shared proto reader (component "proto").
  for (const auto* payload : {&truncated_varint, &truncated_body, &length_overrun}) {
    const auto parsed = parse_gateway_connect(
        std::span<const std::byte>{payload->data(), payload->size()});
    EXPECT_FALSE(parsed);
    ASSERT_NE(parsed.error_if(), nullptr);
    EXPECT_EQ(parsed.error_if()->code(), ErrorCode::protocol);
  }
}

TEST(M10GatewayCodec, PreludeIsTwoByteBigEndianConnectedOnly) {
  EXPECT_EQ(gateway_prelude_bytes, 2U);
  EXPECT_EQ(gateway_prelude_connected, 0U);

  const auto connected = encode_gateway_prelude(0U);
  EXPECT_EQ(connected[0U], std::byte{0x00U});
  EXPECT_EQ(connected[1U], std::byte{0x00U});
  const auto big_endian = encode_gateway_prelude(0x1234U);
  EXPECT_EQ(big_endian[0U], std::byte{0x12U});
  EXPECT_EQ(big_endian[1U], std::byte{0x34U});

  const std::vector<std::byte> good{std::byte{0x00U}, std::byte{0x00U}};
  const auto parsed_good = parse_gateway_prelude(good);
  ASSERT_TRUE(parsed_good);
  EXPECT_EQ(*parsed_good.value_if(), 0U);

  const std::vector<std::byte> nonzero{std::byte{0x00U}, std::byte{0x01U}};
  const auto parsed_nonzero = parse_gateway_prelude(nonzero);
  ASSERT_FALSE(parsed_nonzero);
  ASSERT_NE(parsed_nonzero.error_if(), nullptr);
  EXPECT_EQ(parsed_nonzero.error_if()->code(), ErrorCode::protocol);
  EXPECT_EQ(parsed_nonzero.error_if()->safe_detail(), "gateway_prelude_status_invalid");

  const std::vector<std::byte> short_input{std::byte{0x00U}};
  const auto parsed_short = parse_gateway_prelude(short_input);
  ASSERT_FALSE(parsed_short);
  EXPECT_EQ(parsed_short.error_if()->safe_detail(), "gateway_prelude_length");

  const std::vector<std::byte> long_input{std::byte{0x00U}, std::byte{0x00U},
                                          std::byte{0x00U}};
  const auto parsed_long = parse_gateway_prelude(long_input);
  ASSERT_FALSE(parsed_long);
  EXPECT_EQ(parsed_long.error_if()->safe_detail(), "gateway_prelude_length");
}

// ---- Frozen refusal mapping ------------------------------------------------

TEST(M10GatewayMapping, RefusalStatusTableIsFrozen) {
  const std::vector<std::pair<GatewayRefusal, StableStatus>> frozen{
      {GatewayRefusal::capability_not_negotiated, StableStatus::protocol_error},
      {GatewayRefusal::invalid_target, StableStatus::permission_denied},
      {GatewayRefusal::scope_denied, StableStatus::permission_denied},
      {GatewayRefusal::policy_denied, StableStatus::permission_denied},
      {GatewayRefusal::quota_exhausted, StableStatus::resource_exhausted},
      {GatewayRefusal::not_enabled, StableStatus::unimplemented},
      {GatewayRefusal::dial_failed, StableStatus::unavailable},
      {GatewayRefusal::dial_deadline, StableStatus::deadline_exceeded},
      {GatewayRefusal::local_failure, StableStatus::internal},
  };
  for (const auto& [refusal, status] : frozen) {
    EXPECT_EQ(gateway_refusal_status(refusal), status)
        << "refusal=" << gateway_refusal_name(refusal);
    const auto name = gateway_refusal_name(refusal);
    EXPECT_TRUE(is_name_token(name)) << "name=" << name;
    EXPECT_TRUE(is_safe_detail_token(name)) << "name=" << name;
  }
  // All nine categories are covered by the table above.
  EXPECT_EQ(frozen.size(), 9U);
}

TEST(M10GatewayMapping, ScopesAndFrozenLimits) {
  EXPECT_EQ(gateway_use_scope, "gateway.use");
  EXPECT_EQ(gateway_provide_scope("office"), "gateway.provide:office");
  EXPECT_EQ(gateway_provide_scope(""), "gateway.provide:");

  EXPECT_EQ(max_gateway_host_bytes, 253U);
  EXPECT_EQ(max_gateway_profile_bytes, 64U);
  EXPECT_EQ(max_gateway_profiles_per_endpoint, 16U);
  EXPECT_EQ(max_gateway_profiles_per_endpoint_hard, 64U);
  EXPECT_EQ(default_gateway_dial_deadline, std::chrono::milliseconds(10000));
  EXPECT_EQ(max_gateway_dial_deadline, std::chrono::milliseconds(30000));
  EXPECT_EQ(default_max_concurrent_gateway_streams, 8U);
  EXPECT_EQ(hard_max_concurrent_gateway_streams, 64U);
}

// ---- Version / capabilities ------------------------------------------------

TEST(M10ProtocolVersion, CurrentVersionIs13AndBitsMapByMinor) {
  EXPECT_EQ(current_protocol_version, (ProtocolVersion{1U, 3U}));
  EXPECT_EQ(static_cast<std::uint64_t>(Capability::gateway_v1), 1ULL << 13U);

  EXPECT_EQ(capabilities_for_version(ProtocolVersion{1U, 0U}),
            protocol_1_0_capability_bits);
  EXPECT_EQ(capabilities_for_version(ProtocolVersion{1U, 1U}),
            protocol_1_1_capability_bits);
  EXPECT_EQ(capabilities_for_version(ProtocolVersion{1U, 2U}),
            protocol_1_2_capability_bits);
  EXPECT_EQ(capabilities_for_version(ProtocolVersion{1U, 3U}),
            protocol_1_3_capability_bits);
  // Any minor >= 3 clamps to the 1.3 set.
  EXPECT_EQ(capabilities_for_version(ProtocolVersion{1U, 9U}),
            protocol_1_3_capability_bits);
  EXPECT_EQ(capabilities_for_version(ProtocolVersion{2U, 3U}), 0U);

  EXPECT_TRUE(CapabilitySet{protocol_1_3_capability_bits}.has(Capability::gateway_v1));
  EXPECT_FALSE(CapabilitySet{protocol_1_2_capability_bits}.has(Capability::gateway_v1));
  EXPECT_EQ(known_capability_bits, protocol_1_3_capability_bits);
  EXPECT_TRUE(CapabilitySet{known_capability_bits}.has(Capability::gateway_v1));
}

ProtocolHello hello_13(std::uint64_t required) {
  return {.version = ProtocolVersion{1U, 3U},
          .supported = {protocol_1_3_capability_bits},
          .required = {required}};
}

TEST(M10ProtocolNegotiation, BothSides13NegotiateGatewayBit) {
  const auto session_required = static_cast<std::uint64_t>(Capability::session);
  const auto both_required =
      session_required | static_cast<std::uint64_t>(Capability::gateway_v1);
  const auto negotiated =
      negotiate_protocol(hello_13(both_required), hello_13(both_required));
  ASSERT_TRUE(negotiated);
  EXPECT_EQ(negotiated.value_if()->version, (ProtocolVersion{1U, 3U}));
  EXPECT_EQ(negotiated.value_if()->capabilities.bits, protocol_1_3_capability_bits);
  EXPECT_TRUE(negotiated.value_if()->capabilities.has(Capability::gateway_v1));
}

TEST(M10ProtocolNegotiation, VersionClampStripsGatewayBitAgainst12Peer) {
  // Both advertise the bit in `supported`, but the remote version is 1.2:
  // the negotiated minor is 2, so the capability clamp drops bit 13.
  const auto session_required = static_cast<std::uint64_t>(Capability::session);
  const ProtocolHello local = hello_13(session_required);
  const ProtocolHello remote{.version = ProtocolVersion{1U, 2U},
                             .supported = {protocol_1_3_capability_bits},
                             .required = {session_required}};
  const auto negotiated = negotiate_protocol(local, remote);
  ASSERT_TRUE(negotiated);
  EXPECT_EQ(negotiated.value_if()->version, (ProtocolVersion{1U, 2U}));
  EXPECT_EQ(negotiated.value_if()->capabilities.bits, protocol_1_2_capability_bits);
  EXPECT_FALSE(negotiated.value_if()->capabilities.has(Capability::gateway_v1));
}

TEST(M10ProtocolNegotiation, RequiredGatewayAgainst12PeerFails) {
  const auto session_required = static_cast<std::uint64_t>(Capability::session);
  const auto with_gateway_required =
      session_required | static_cast<std::uint64_t>(Capability::gateway_v1);
  const ProtocolHello remote{.version = ProtocolVersion{1U, 2U},
                             .supported = {protocol_1_2_capability_bits},
                             .required = {session_required}};
  const auto negotiated = negotiate_protocol(hello_13(with_gateway_required), remote);
  ASSERT_FALSE(negotiated);
  ASSERT_NE(negotiated.error_if(), nullptr);
  EXPECT_EQ(negotiated.error_if()->safe_detail(), "required_capability_unavailable");
}

TEST(M10ProtocolNegotiation, RequiredGatewayUnsupportedLocallyIsInvalid) {
  const auto session_required = static_cast<std::uint64_t>(Capability::session);
  const auto with_gateway_required =
      session_required | static_cast<std::uint64_t>(Capability::gateway_v1);
  const ProtocolHello local{.version = ProtocolVersion{1U, 3U},
                            .supported = {protocol_1_2_capability_bits},
                            .required = {with_gateway_required}};
  const auto negotiated = negotiate_protocol(local, hello_13(session_required));
  ASSERT_FALSE(negotiated);
  ASSERT_NE(negotiated.error_if(), nullptr);
  EXPECT_EQ(negotiated.error_if()->safe_detail(), "invalid_required_capabilities");
}

// ---- Frozen golden vectors ---------------------------------------------------

std::vector<std::byte> stream_open_payload(const StreamId& id,
                                           std::uint64_t window_bytes,
                                           std::uint32_t window_frames,
                                           const std::vector<std::byte>* gateway_body) {
  std::vector<std::byte> payload;
  proto_codec::append_bytes(payload, 1U,
                            std::span<const std::byte>{id.data(), id.size()});
  proto_codec::append_uint(payload, 2U, window_bytes);
  proto_codec::append_uint(payload, 3U, window_frames);
  if (gateway_body != nullptr) {
    proto_codec::append_bytes(payload, 4U,
                              std::span<const std::byte>{gateway_body->data(),
                                                         gateway_body->size()});
  }
  return payload;
}

TEST(M10GoldenVectors, FrozenEncodingBytesAreExact) {
  namespace vectors = test_vectors::m10;
  ASSERT_EQ(vectors::protocol_major, 1U);
  ASSERT_EQ(vectors::protocol_minor, 3U);

  // GatewayConnect body with profile.
  const GatewayConnect profiled{.host = "intranode.lan", .port = 443U,
                                .profile = "office"};
  const auto encoded_profiled = encode_gateway_connect(profiled);
  ASSERT_TRUE(encoded_profiled);
  EXPECT_EQ(*encoded_profiled.value_if(),
            test::bytes_from_hex(vectors::gateway_connect_hex))
      << "gateway_connect encoding drift";

  // GatewayConnect body without profile (field 3 omitted).
  const GatewayConnect bare{.host = "10.20.30.40", .port = 8080U, .profile = ""};
  const auto encoded_bare = encode_gateway_connect(bare);
  ASSERT_TRUE(encoded_bare);
  EXPECT_EQ(*encoded_bare.value_if(),
            test::bytes_from_hex(vectors::gateway_connect_no_profile_hex))
      << "gateway_connect_no_profile encoding drift";

  // STREAM_OPEN payloads with the frozen id and dual window.
  StreamId id{};
  const auto id_bytes = test::bytes_from_hex(vectors::stream_open_id_hex);
  ASSERT_EQ(id_bytes.size(), id.size());
  std::copy_n(id_bytes.begin(), id.size(), id.begin());
  ASSERT_EQ(vectors::stream_open_window_bytes, 262144U);
  ASSERT_EQ(vectors::stream_open_window_frames, 64U);

  const auto plain = stream_open_payload(id, vectors::stream_open_window_bytes,
                                         vectors::stream_open_window_frames, nullptr);
  EXPECT_EQ(plain, test::bytes_from_hex(vectors::stream_open_plain_hex))
      << "stream_open_plain encoding drift";

  const auto gateway = stream_open_payload(id, vectors::stream_open_window_bytes,
                                           vectors::stream_open_window_frames,
                                           encoded_profiled.value_if());
  EXPECT_EQ(gateway, test::bytes_from_hex(vectors::stream_open_gateway_hex))
      << "stream_open_gateway encoding drift";

  // The golden gateway body parses back to the exact frozen request.
  const auto reparsed = parse_gateway_connect(std::span<const std::byte>{
      encoded_profiled.value_if()->data(), encoded_profiled.value_if()->size()});
  ASSERT_TRUE(reparsed);
  EXPECT_EQ(reparsed.value_if()->host, "intranode.lan");
  EXPECT_EQ(reparsed.value_if()->port, 443U);
  EXPECT_EQ(reparsed.value_if()->profile, "office");

  // Prelude: encode(connected) is the frozen 0000.
  const auto prelude = encode_gateway_prelude(gateway_prelude_connected);
  EXPECT_EQ(std::vector<std::byte>(prelude.begin(), prelude.end()),
            test::bytes_from_hex(vectors::prelude_connected_hex));
}

TEST(M10GoldenVectors, GatewayOpenFieldLayoutIsFrozen) {
  namespace vectors = test_vectors::m10;
  const auto golden = test::bytes_from_hex(vectors::stream_open_gateway_hex);
  proto_codec::ProtoReader reader(
      std::span<const std::byte>{golden.data(), golden.size()});
  std::optional<std::vector<std::byte>> field1;
  std::optional<std::uint64_t> field2;
  std::optional<std::uint64_t> field3;
  std::optional<std::vector<std::byte>> field4;
  while (!reader.done()) {
    auto field = reader.next();
    ASSERT_TRUE(field);
    const auto& parsed = *field.value_if();
    if (parsed.number == 1U && parsed.wire_type == 2U) {
      field1 = std::vector<std::byte>{parsed.bytes.begin(), parsed.bytes.end()};
    } else if (parsed.number == 2U && parsed.wire_type == 0U) {
      field2 = parsed.integer;
    } else if (parsed.number == 3U && parsed.wire_type == 0U) {
      field3 = parsed.integer;
    } else if (parsed.number == 4U && parsed.wire_type == 2U) {
      field4 = std::vector<std::byte>{parsed.bytes.begin(), parsed.bytes.end()};
    } else {
      FAIL() << "unexpected field " << parsed.number;
    }
  }
  ASSERT_TRUE(field1.has_value() && field2.has_value() && field3.has_value() &&
              field4.has_value());
  EXPECT_EQ(*field1, test::bytes_from_hex(vectors::stream_open_id_hex));
  EXPECT_EQ(*field2, 262144U);
  EXPECT_EQ(*field3, 64U);
  // Field 4 is exactly the frozen GatewayConnect body.
  EXPECT_EQ(*field4, test::bytes_from_hex(vectors::gateway_connect_hex));
}

// ---- ByteStream integration over the loopback session harness ---------------

// Both sides of one loopback session with full wiring: pre-seeded mutual
// trust (no pairing path), protocol hellos fixed at construction so tests
// can pin either peer at 1.2 or 1.3. LEFT is the session initiator.
struct GatewaySessionPair {
  test::LoopbackTransportPair pair;
  Result<IdentityKeyPair> left_identity{create_identity()};
  Result<IdentityKeyPair> right_identity{create_identity()};
  std::map<DeviceId, std::vector<std::string>> left_trust;
  std::map<DeviceId, std::vector<std::string>> right_trust;
  std::shared_ptr<PeerSession> left;
  std::shared_ptr<PeerSession> right;

  GatewaySessionPair(ProtocolHello left_protocol, ProtocolHello right_protocol) {
    EXPECT_TRUE(left_identity && right_identity);
    pair.connect();
    transport::ChannelOptions control_options;
    pair.left().async_open_channel(transport::ChannelKind::control, control_options,
                                   [](Result<transport::TransportChannel*>) {});
    pair.right().async_open_channel(transport::ChannelKind::control, control_options,
                                    [](Result<transport::TransportChannel*>) {});
    build_sessions(left_protocol, right_protocol);
  }

  [[nodiscard]] DeviceEndpointKey left_key() const {
    return {left_identity.value_if()->device_id(), filled<EndpointId>(0x20U)};
  }
  [[nodiscard]] DeviceEndpointKey right_key() const {
    return {right_identity.value_if()->device_id(), filled<EndpointId>(0x40U)};
  }

  void build_sessions(ProtocolHello left_protocol, ProtocolHello right_protocol) {
    const auto session_id = filled<SessionId>(0x60U);
    const auto initiator_nonce = filled_array<signaling_nonce_bytes>(0x10U);
    const auto responder_nonce = filled_array<signaling_nonce_bytes>(0x30U);
    const auto transcript = filled_array<signaling_transcript_sha256_bytes>(0x50U);
    auto left_transport = std::shared_ptr<transport::TransportSession>(
        &pair.left(), [](transport::TransportSession*) {});
    auto right_transport = std::shared_ptr<transport::TransportSession>(
        &pair.right(), [](transport::TransportSession*) {});
    VerifiedSessionBinding left_binding{
        {right_key(), left_key(), session_id, 1U, initiator_nonce, responder_nonce,
         transcript},
        {},
        "peer-ufrag",
        true};
    VerifiedSessionBinding right_binding{
        {left_key(), right_key(), session_id, 1U, initiator_nonce, responder_nonce,
         transcript},
        {},
        "peer-ufrag",
        false};

    auto left_timeline = std::make_shared<ConnectionAttemptTimeline>();
    EXPECT_TRUE(left_timeline->transition(ConnectionStage::resolving_endpoint, "test",
                                          "endpoint_selected"));
    EXPECT_TRUE(left_timeline->transition(ConnectionStage::signaling, "test",
                                          "attempt_accepted"));
    auto right_timeline = std::make_shared<ConnectionAttemptTimeline>();
    EXPECT_TRUE(right_timeline->transition(ConnectionStage::resolving_endpoint, "test",
                                           "endpoint_selected"));
    EXPECT_TRUE(right_timeline->transition(ConnectionStage::signaling, "test",
                                           "attempt_accepted"));

    auto build = [&](VerifiedSessionBinding binding,
                     const IdentityKeyPair& identity, const IdentityKeyPair& peer,
                     ProtocolHello protocol,
                     std::map<DeviceId, std::vector<std::string>>& trust,
                     const std::shared_ptr<ConnectionAttemptTimeline>& timeline,
                     std::shared_ptr<transport::TransportSession> transport)
        -> Result<std::shared_ptr<PeerSession>> {
      return PeerSession::create_verified(
          {.transport = std::move(transport),
           .binding = binding,
           .local_identity = &identity,
           .peer_public_key = peer.public_key(),
           .local_protocol = protocol,
           .expires_unix_milliseconds = kNow + 60'000U,
           .now_unix_milliseconds = kNow,
           .observer = {},
           .timeline = timeline,
           .clock = {},
           .trust_authorizer = [&trust, peer_id = peer.device_id()](std::uint64_t now) {
             SessionAuthorization authorization;
             auto found = trust.find(peer_id);
             if (found != trust.end()) {
               authorization.trusted = true;
               authorization.scopes = found->second;
             }
             authorization.pairing_allowed = false;
             (void)now;
             return Result<SessionAuthorization>::success(authorization);
           },
           .wall_clock = [] { return kNow; }});
    };

    auto left_created = build(left_binding, *left_identity.value_if(),
                              *right_identity.value_if(), left_protocol, left_trust,
                              left_timeline, left_transport);
    ASSERT_TRUE(left_created);
    left = *left_created.value_if();
    auto right_created = build(right_binding, *right_identity.value_if(),
                               *left_identity.value_if(), right_protocol, right_trust,
                               right_timeline, right_transport);
    ASSERT_TRUE(right_created);
    right = *right_created.value_if();
  }

  // Drives both loopback directions until quiet; bounded to catch livelock.
  void pump_all(int rounds = 8) {
    for (int round = 0; round < rounds; ++round) {
      pair.left().pump();
      pair.right().pump();
    }
  }

  void start_authenticated(const std::vector<std::string>& scopes = {"stream.open"}) {
    left_trust[right_identity.value_if()->device_id()] = scopes;
    right_trust[left_identity.value_if()->device_id()] = scopes;
    ASSERT_TRUE(left->start());
    ASSERT_TRUE(right->start());
    pump_all();
    ASSERT_TRUE(left->authenticated() && right->authenticated());
  }
};

ProtocolHello protocol_13_hello() {
  return {.version = ProtocolVersion{1U, 3U},
          .supported = {protocol_1_3_capability_bits},
          .required = {static_cast<std::uint64_t>(Capability::session)}};
}

ProtocolHello protocol_12_hello() {
  return {.version = ProtocolVersion{1U, 2U},
          .supported = {protocol_1_2_capability_bits},
          .required = {static_cast<std::uint64_t>(Capability::session)}};
}

struct CapturedFrame {
  std::uint8_t type{};
  std::vector<std::byte> payload;
};

// Opens a fresh stream-domain logical channel on `side` whose inbound frames
// land in `inbox`; returns the channel id. Used to inject hand-built frames.
Result<std::uint32_t> open_capture_channel(PeerSession& side,
                                           std::vector<CapturedFrame>& inbox) {
  return side.open_business_channel(
      session::ChannelDomain::stream, session::QueueFullPolicy::reject, 16U,
      64U * 1024U,
      [&inbox](const FrameView& frame) {
        inbox.push_back(CapturedFrame{
            frame.type,
            std::vector<std::byte>{frame.payload.begin(), frame.payload.end()}});
      });
}

Result<void> inject_open(PeerSession& side, std::uint32_t channel_id,
                         const std::vector<std::byte>& payload) {
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::stream_open);
  frame.channel_id = channel_id;
  frame.message_id = filled<MessageId>(0x9U);
  frame.payload = payload;
  return side.send_frame(channel_id, session::FrameClass::standard, std::move(frame));
}

std::optional<std::uint64_t> reset_status_of(const std::vector<std::byte>& payload) {
  proto_codec::ProtoReader reader(
      std::span<const std::byte>{payload.data(), payload.size()});
  std::optional<std::uint64_t> status;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) return std::nullopt;
    if (field.value_if()->number == 2U && field.value_if()->wire_type == 0U) {
      status = field.value_if()->integer;
    }
  }
  return status;
}

StreamId fixed_stream_id(std::uint8_t seed) {
  StreamId id{};
  for (std::size_t index = 0U; index < id.size(); ++index) {
    id[index] = static_cast<std::byte>(seed + index);
  }
  return id;
}

std::vector<std::byte> open_payload(const StreamId& id, std::uint64_t window_bytes,
                                    std::uint32_t window_frames,
                                    const std::vector<std::byte>* gateway_body,
                                    const std::vector<std::byte>* unknown_field5) {
  std::vector<std::byte> payload;
  proto_codec::append_bytes(payload, 1U,
                            std::span<const std::byte>{id.data(), id.size()});
  proto_codec::append_uint(payload, 2U, window_bytes);
  proto_codec::append_uint(payload, 3U, window_frames);
  if (gateway_body != nullptr) {
    proto_codec::append_bytes(payload, 4U,
                              std::span<const std::byte>{gateway_body->data(),
                                                         gateway_body->size()});
  }
  if (unknown_field5 != nullptr) {
    proto_codec::append_bytes(payload, 5U,
                              std::span<const std::byte>{unknown_field5->data(),
                                                         unknown_field5->size()});
  }
  return payload;
}

TEST(M10ByteStream, GatewayStreamEndToEndOnNegotiated13) {
  GatewaySessionPair harness{protocol_13_hello(), protocol_13_hello()};
  harness.start_authenticated();
  ASSERT_TRUE(harness.left->diagnostics().negotiated_capabilities.has(
      Capability::gateway_v1));
  ASSERT_TRUE(harness.right->diagnostics().negotiated_capabilities.has(
      Capability::gateway_v1));

  std::vector<std::pair<std::shared_ptr<ByteStreamHandle>, GatewayConnect>> inbound;
  ByteStreamLimits limits;
  limits.default_receive_window_bytes = 4096U;
  limits.default_receive_window_frames = 4U;
  limits.max_data_chunk_bytes = 1024U;
  ByteStreamService right_service(*harness.right, limits);
  ByteStreamService left_service(*harness.left, limits);
  ASSERT_TRUE(right_service.attach() && left_service.attach());
  harness.pump_all();

  right_service.set_gateway_inbound_handler(
      [&](const std::shared_ptr<ByteStreamHandle>& stream, const GatewayConnect& c) {
        inbound.emplace_back(stream, c);
      });

  const GatewayConnect request{.host = "intranode.lan", .port = 443U,
                               .profile = "office"};
  auto stream = left_service.open_gateway_stream(request, 4096U, 4U);
  ASSERT_TRUE(stream) << "error: " << stream.error_if()->safe_detail();
  harness.pump_all();

  ASSERT_EQ(inbound.size(), 1U);
  EXPECT_EQ(inbound[0].second.host, "intranode.lan");
  EXPECT_EQ(inbound[0].second.port, 443U);
  EXPECT_EQ(inbound[0].second.profile, "office");
  EXPECT_TRUE(inbound[0].first->is_gateway());
  EXPECT_EQ(inbound[0].first->state(), StreamState::open);
  // The opener's local handle is flagged gateway too, and — until the
  // serving side's 2-byte prelude lands — stays `opening` (M10-08: open
  // means connected, not merely "STREAM_OPEN sent").
  EXPECT_TRUE((*stream.value_if())->is_gateway());
  EXPECT_EQ((*stream.value_if())->state(), StreamState::opening);

  // The prelude is the only thing that promotes the initiator: deliver it
  // from the serving side and the stream must reach `open` (and stay there
  // for further payload).
  const auto prelude = encode_gateway_prelude(gateway_prelude_connected);
  bool prelude_written = false;
  inbound[0].first->async_write(
      std::span<const std::byte>{prelude.data(), prelude.size()},
      [&prelude_written](StreamIoResult result) {
        if (!result.error.has_value()) prelude_written = true;
      });
  harness.pump_all();
  ASSERT_TRUE(prelude_written);
  EXPECT_EQ((*stream.value_if())->state(), StreamState::open);
}

TEST(M10ByteStream, GatewayStreamGatedLocallyAgainst12Peer) {
  GatewaySessionPair harness{protocol_13_hello(), protocol_12_hello()};
  harness.start_authenticated();
  ASSERT_FALSE(harness.left->diagnostics().negotiated_capabilities.has(
      Capability::gateway_v1));
  ASSERT_FALSE(harness.right->diagnostics().negotiated_capabilities.has(
      Capability::gateway_v1));

  ByteStreamLimits limits;
  ByteStreamService right_service(*harness.right, limits);
  ByteStreamService left_service(*harness.left, limits);
  ASSERT_TRUE(right_service.attach() && left_service.attach());
  harness.pump_all();

  std::size_t gateway_opens_seen = 0U;
  std::size_t plain_opens_seen = 0U;
  right_service.set_gateway_inbound_handler(
      [&](const std::shared_ptr<ByteStreamHandle>&, const GatewayConnect&) {
        ++gateway_opens_seen;
      });
  right_service.set_inbound_handler(
      [&](const std::shared_ptr<ByteStreamHandle>&) { ++plain_opens_seen; });

  const auto rejected_before = harness.right->diagnostics().business_frames_rejected;
  auto stream = left_service.open_gateway_stream(
      GatewayConnect{.host = "intranode.lan", .port = 443U, .profile = "office"},
      4096U, 4U);
  ASSERT_FALSE(stream);
  ASSERT_NE(stream.error_if(), nullptr);
  EXPECT_EQ(stream.error_if()->code(), ErrorCode::protocol);
  EXPECT_EQ(stream.error_if()->component(), "byte_stream");
  EXPECT_EQ(stream.error_if()->safe_detail(), "gateway_not_negotiated");
  harness.pump_all();

  // M10-02: nothing was emitted, so the peer saw no frame at all.
  EXPECT_EQ(gateway_opens_seen, 0U);
  EXPECT_EQ(plain_opens_seen, 0U);
  EXPECT_EQ(right_service.active_streams(), 0U);
  EXPECT_EQ(harness.right->diagnostics().business_frames_rejected, rejected_before);
  // Both sessions remain healthy.
  EXPECT_TRUE(harness.left->authenticated() && harness.right->authenticated());
}

TEST(M10ByteStream, GatewayStreamRefusedUnimplementedWithoutHandler) {
  GatewaySessionPair harness{protocol_13_hello(), protocol_13_hello()};
  harness.start_authenticated();

  ByteStreamLimits limits;
  ByteStreamService right_service(*harness.right, limits);
  ByteStreamService left_service(*harness.left, limits);
  ASSERT_TRUE(right_service.attach() && left_service.attach());
  harness.pump_all();
  // No gateway inbound handler installed: the feature is default OFF.

  auto stream = left_service.open_gateway_stream(
      GatewayConnect{.host = "intranode.lan", .port = 443U, .profile = "office"},
      4096U, 4U);
  ASSERT_TRUE(stream);
  harness.pump_all();

  // The opener observes the stream-level refusal as a reset.
  EXPECT_EQ((*stream.value_if())->state(), StreamState::reset);
  std::optional<Error> read_error;
  std::array<std::byte, 8U> sink{};
  (*stream.value_if())->async_read_some(
      sink, [&](StreamIoResult result) { read_error = result.error; });
  ASSERT_TRUE(read_error.has_value());
  EXPECT_EQ(read_error->code(), ErrorCode::cancelled);
  EXPECT_EQ(read_error->safe_detail(), "stream_reset");
  EXPECT_EQ(right_service.active_streams(), 0U);
  EXPECT_TRUE(harness.left->authenticated() && harness.right->authenticated());
}

TEST(M10ByteStream, LocalAdmissionRejectsBadGatewayOpenParameters) {
  GatewaySessionPair harness{protocol_13_hello(), protocol_13_hello()};
  harness.start_authenticated();

  ByteStreamLimits limits;
  ByteStreamService left_service(*harness.left, limits);

  // Not attached.
  auto unattached = left_service.open_gateway_stream(
      GatewayConnect{.host = "nas", .port = 443U, .profile = ""}, 1024U, 4U);
  ASSERT_FALSE(unattached);
  EXPECT_EQ(unattached.error_if()->code(), ErrorCode::configuration);
  EXPECT_EQ(unattached.error_if()->safe_detail(), "service_not_attached");

  ASSERT_TRUE(left_service.attach());

  // Zero receive window.
  auto zero_window = left_service.open_gateway_stream(
      GatewayConnect{.host = "nas", .port = 443U, .profile = ""}, 0U, 0U);
  ASSERT_FALSE(zero_window);
  EXPECT_EQ(zero_window.error_if()->code(), ErrorCode::configuration);
  EXPECT_EQ(zero_window.error_if()->safe_detail(), "receive_window_invalid");

  // Structurally invalid target: validate_gateway_connect failure surfaces.
  auto bad_target = left_service.open_gateway_stream(
      GatewayConnect{.host = "bad_host", .port = 443U, .profile = ""}, 1024U, 4U);
  ASSERT_FALSE(bad_target);
  EXPECT_EQ(bad_target.error_if()->code(), ErrorCode::permission);
  EXPECT_EQ(bad_target.error_if()->component(), "gateway");
  EXPECT_EQ(bad_target.error_if()->safe_detail(), "gateway_host_invalid");

  // Concurrency cap shared with plain streams.
  ByteStreamLimits tiny_limits = limits;
  tiny_limits.max_concurrent_streams = 1U;
  ByteStreamService tiny_service(*harness.left, tiny_limits);
  ASSERT_TRUE(tiny_service.attach());
  auto first = tiny_service.open_stream(1024U, 4U);
  ASSERT_TRUE(first);
  auto second = tiny_service.open_gateway_stream(
      GatewayConnect{.host = "nas", .port = 443U, .profile = ""}, 1024U, 4U);
  ASSERT_FALSE(second);
  EXPECT_EQ(second.error_if()->code(), ErrorCode::resource_exhausted);
  EXPECT_EQ(second.error_if()->safe_detail(), "stream_limit");
}

// M10-02 interop core: a 1.2-negotiated session that receives a
// gateway-carrying STREAM_OPEN must close ONLY that logical channel.
TEST(M10ByteStream, GatewayOpenOn12SessionClosesChannelOnly) {
  GatewaySessionPair harness{protocol_12_hello(), protocol_12_hello()};
  harness.start_authenticated();
  ASSERT_FALSE(harness.right->diagnostics().negotiated_capabilities.has(
      Capability::gateway_v1));

  std::vector<CapturedFrame> inbox;
  ByteStreamLimits limits;
  ByteStreamService right_service(*harness.right, limits);
  ByteStreamService left_service(*harness.left, limits);
  ASSERT_TRUE(right_service.attach() && left_service.attach());
  harness.pump_all();

  std::size_t gateway_opens_seen = 0U;
  right_service.set_gateway_inbound_handler(
      [&](const std::shared_ptr<ByteStreamHandle>&, const GatewayConnect&) {
        ++gateway_opens_seen;
      });

  const auto channel = open_capture_channel(*harness.left, inbox);
  ASSERT_TRUE(channel);

  // Wire-valid OPEN whose field 4 is a wire-valid GatewayConnect body; the
  // session negotiated 1.2 so the capability gate must fire.
  auto body = encode_gateway_connect(
      GatewayConnect{.host = "intranode.lan", .port = 443U, .profile = "office"});
  ASSERT_TRUE(body);
  const auto payload =
      open_payload(fixed_stream_id(0x21U), 4096U, 4U, body.value_if(), nullptr);
  const auto rejected_before = harness.right->diagnostics().business_frames_rejected;
  auto sent = inject_open(*harness.left, *channel.value_if(), payload);
  ASSERT_TRUE(sent);
  harness.pump_all();

  EXPECT_EQ(gateway_opens_seen, 0U);
  EXPECT_EQ(right_service.active_streams(), 0U);
  EXPECT_FALSE(harness.right->has_business_channel(*channel.value_if()));
  EXPECT_EQ(harness.right->diagnostics().business_frames_rejected,
            rejected_before + 1U);
  // The session itself survives: control-plane ping still round-trips.
  EXPECT_TRUE(harness.right->authenticated());
  ASSERT_TRUE(harness.right->send_ping(0x77U));
  harness.pump_all();
  EXPECT_EQ(harness.right->diagnostics().pongs_received, 1U);
  EXPECT_NE(harness.right->diagnostics().state, PeerSessionState::closed);
}

TEST(M10ByteStream, MalformedGatewayBodyOn13SessionClosesChannelOnly) {
  GatewaySessionPair harness{protocol_13_hello(), protocol_13_hello()};
  harness.start_authenticated();
  ASSERT_TRUE(harness.right->diagnostics().negotiated_capabilities.has(
      Capability::gateway_v1));

  std::vector<CapturedFrame> inbox;
  ByteStreamLimits limits;
  ByteStreamService right_service(*harness.right, limits);
  ByteStreamService left_service(*harness.left, limits);
  ASSERT_TRUE(right_service.attach() && left_service.attach());
  harness.pump_all();

  std::size_t gateway_opens_seen = 0U;
  right_service.set_gateway_inbound_handler(
      [&](const std::shared_ptr<ByteStreamHandle>&, const GatewayConnect&) {
        ++gateway_opens_seen;
      });

  const auto channel = open_capture_channel(*harness.left, inbox);
  ASSERT_TRUE(channel);

  // Field 4 present and length-delimited, but its body is wire-malformed
  // (field 1 tag with the length varint truncated).
  const std::vector<std::byte> malformed_body{std::byte{0x0aU}};
  const auto payload =
      open_payload(fixed_stream_id(0x31U), 4096U, 4U, &malformed_body, nullptr);
  const auto rejected_before = harness.right->diagnostics().business_frames_rejected;
  auto sent = inject_open(*harness.left, *channel.value_if(), payload);
  ASSERT_TRUE(sent);
  harness.pump_all();

  EXPECT_EQ(gateway_opens_seen, 0U);
  EXPECT_EQ(right_service.active_streams(), 0U);
  EXPECT_EQ(harness.right->diagnostics().business_frames_rejected,
            rejected_before + 1U);
  EXPECT_TRUE(harness.right->authenticated());
  EXPECT_NE(harness.right->diagnostics().state, PeerSessionState::closed);
}

TEST(M10ByteStream, GrammarInvalidGatewayTargetResetsStreamWithPermissionDenied) {
  GatewaySessionPair harness{protocol_13_hello(), protocol_13_hello()};
  harness.start_authenticated();

  std::vector<CapturedFrame> inbox;
  ByteStreamLimits limits;
  ByteStreamService right_service(*harness.right, limits);
  ByteStreamService left_service(*harness.left, limits);
  ASSERT_TRUE(right_service.attach() && left_service.attach());
  harness.pump_all();

  std::size_t gateway_opens_seen = 0U;
  right_service.set_gateway_inbound_handler(
      [&](const std::shared_ptr<ByteStreamHandle>&, const GatewayConnect&) {
        ++gateway_opens_seen;
      });

  const auto channel = open_capture_channel(*harness.left, inbox);
  ASSERT_TRUE(channel);

  // Wire-valid body whose host fails the grammar (underscore): an admission
  // refusal, so the stream is RESET while the channel and session stay up.
  std::vector<std::byte> body;
  proto_codec::append_text(body, 1U, "bad_host");
  proto_codec::append_uint(body, 2U, 443U);
  const auto payload = open_payload(fixed_stream_id(0x41U), 4096U, 4U, &body, nullptr);
  const auto rejected_before = harness.right->diagnostics().business_frames_rejected;
  auto sent = inject_open(*harness.left, *channel.value_if(), payload);
  ASSERT_TRUE(sent);
  harness.pump_all();

  EXPECT_EQ(gateway_opens_seen, 0U);
  EXPECT_EQ(right_service.active_streams(), 0U);
  // Grammar refusals are stream-level, not channel failures.
  EXPECT_EQ(harness.right->diagnostics().business_frames_rejected, rejected_before);
  ASSERT_EQ(inbox.size(), 1U);
  EXPECT_EQ(inbox[0].type, static_cast<std::uint8_t>(FrameType::stream_reset));
  const auto status = reset_status_of(inbox[0].payload);
  ASSERT_TRUE(status.has_value());
  EXPECT_EQ(*status, static_cast<std::uint64_t>(StableStatus::permission_denied));
  EXPECT_TRUE(harness.right->authenticated());
}

// 1.2-compatibility regression: unknown OPTIONAL open fields are skipped.
TEST(M10ByteStream, UnknownOptionalOpenFieldSkippedOn12Session) {
  GatewaySessionPair harness{protocol_12_hello(), protocol_12_hello()};
  harness.start_authenticated();

  std::vector<CapturedFrame> inbox;
  std::vector<std::shared_ptr<ByteStreamHandle>> inbound;
  ByteStreamLimits limits;
  ByteStreamService right_service(*harness.right, limits);
  ByteStreamService left_service(*harness.left, limits);
  ASSERT_TRUE(right_service.attach() && left_service.attach());
  harness.pump_all();

  right_service.set_inbound_handler(
      [&](const std::shared_ptr<ByteStreamHandle>& stream) {
        inbound.push_back(stream);
      });

  const auto channel = open_capture_channel(*harness.left, inbox);
  ASSERT_TRUE(channel);

  const std::vector<std::byte> future_field{std::byte{0xDEU}, std::byte{0xADU}};
  const auto payload =
      open_payload(fixed_stream_id(0x51U), 4096U, 4U, nullptr, &future_field);
  auto sent = inject_open(*harness.left, *channel.value_if(), payload);
  ASSERT_TRUE(sent);
  harness.pump_all();

  ASSERT_EQ(inbound.size(), 1U);
  EXPECT_EQ(inbound[0]->state(), StreamState::open);
  EXPECT_FALSE(inbound[0]->is_gateway());
  EXPECT_TRUE(harness.right->has_business_channel(*channel.value_if()));
  EXPECT_TRUE(harness.left->authenticated() && harness.right->authenticated());
}

// Regression: plain streams are unaffected by the 1.3 gateway surfaces.
TEST(M10ByteStream, PlainStreamsStillRoundTripOn13) {
  GatewaySessionPair harness{protocol_13_hello(), protocol_13_hello()};
  harness.start_authenticated();

  std::vector<std::shared_ptr<ByteStreamHandle>> inbound;
  ByteStreamLimits limits;
  limits.default_receive_window_bytes = 4096U;
  limits.default_receive_window_frames = 4U;
  limits.max_data_chunk_bytes = 1024U;
  ByteStreamService right_service(*harness.right, limits);
  ByteStreamService left_service(*harness.left, limits);
  ASSERT_TRUE(right_service.attach() && left_service.attach());
  harness.pump_all();

  right_service.set_inbound_handler(
      [&](const std::shared_ptr<ByteStreamHandle>& stream) {
        inbound.push_back(stream);
      });

  auto stream = left_service.open_stream(4096U, 4U);
  ASSERT_TRUE(stream);
  harness.pump_all();
  ASSERT_EQ(inbound.size(), 1U);
  EXPECT_FALSE((*stream.value_if())->is_gateway());
  EXPECT_FALSE(inbound[0]->is_gateway());

  const std::string payload(512U, 'x');
  std::size_t completed = 0U;
  std::optional<Error> write_error;
  (*stream.value_if())
      ->async_write(std::span{reinterpret_cast<const std::byte*>(payload.data()),
                              payload.size()},
                    [&](StreamIoResult result) {
                      completed = result.bytes;
                      write_error = result.error;
                    });
  EXPECT_EQ(completed, payload.size());
  EXPECT_FALSE(write_error.has_value());
  harness.pump_all();

  std::vector<std::byte> received(payload.size(), std::byte{0});
  std::size_t total_read = 0U;
  while (total_read < received.size()) {
    bool progressed = false;
    inbound[0]->async_read_some(
        std::span<std::byte>{received.data() + total_read,
                             received.size() - total_read},
        [&](StreamIoResult result) {
          ASSERT_FALSE(result.error.has_value());
          if (result.bytes > 0U) progressed = true;
          total_read += result.bytes;
        });
    if (total_read == received.size()) break;
    ASSERT_TRUE(progressed);
  }
  EXPECT_EQ(std::memcmp(received.data(), payload.data(), payload.size()), 0);

  EXPECT_TRUE((*stream.value_if())->shutdown_write());
  harness.pump_all();
  bool eof_seen = false;
  std::array<std::byte, 8U> tail{};
  inbound[0]->async_read_some(tail, [&](StreamIoResult result) {
    if (result.bytes == 0U && !result.error.has_value()) eof_seen = true;
  });
  EXPECT_TRUE(eof_seen);
}

}  // namespace
}  // namespace heyaki
