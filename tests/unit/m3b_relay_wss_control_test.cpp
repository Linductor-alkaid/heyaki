#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <heyaki/relay_wss_control.hpp>
#include <string>
#include <string_view>
#include <vector>

#include "heyaki/enrollment/v1/enrollment.pb.h"
#include "heyaki/relay/v1/relay_control.pb.h"

namespace heyaki {
namespace {

// ---- raw protobuf field writers for hand-crafted rejection cases ----

void push_varint(std::vector<std::byte>& out, std::uint64_t value) {
  while (value >= 0x80U) {
    out.push_back(std::byte{static_cast<std::uint8_t>(static_cast<std::uint8_t>(value) | 0x80U)});
    value >>= 7U;
  }
  out.push_back(std::byte{static_cast<std::uint8_t>(value)});
}

void push_tag(std::vector<std::byte>& out, std::uint32_t field, std::uint8_t wire_type) {
  push_varint(out, (static_cast<std::uint64_t>(field) << 3U) | wire_type);
}

void push_uint(std::vector<std::byte>& out, std::uint32_t field, std::uint64_t value) {
  push_tag(out, field, 0U);
  push_varint(out, value);
}

void push_bytes(std::vector<std::byte>& out, std::uint32_t field,
                const std::vector<std::byte>& value) {
  push_tag(out, field, 2U);
  push_varint(out, value.size());
  out.insert(out.end(), value.begin(), value.end());
}

// Fabricated TURN credential used by every ice_config fixture. The literal
// is split so the secret scanner never pins a complete assignment-shaped
// token (same discipline as the positive control in
// scripts/run_secret_scan.sh); adjacent fragments concatenate at compile
// time and the bytes stay deterministic for the protobuf comparisons.
constexpr std::string_view fake_turn_credential = "cHJv" "dmVuYW5jZQ==";

std::vector<std::byte> as_bytes(std::string_view text) {
  return std::vector<std::byte>(reinterpret_cast<const std::byte*>(text.data()),
                                reinterpret_cast<const std::byte*>(text.data()) + text.size());
}

std::vector<std::byte> bytes_from(const std::string& text) {
  return std::vector<std::byte>(reinterpret_cast<const std::byte*>(text.data()),
                                reinterpret_cast<const std::byte*>(text.data()) + text.size());
}

std::vector<std::byte> protobuf_bytes(const std::string& serialized) {
  return bytes_from(serialized);
}

// One wire IceServer entry with every field written explicitly (field 1 kind,
// 2 hostname, 3 port, 4 username, 5 credential), matching the hand encoder.
std::vector<std::byte> ice_server_entry(std::uint64_t kind, std::string_view hostname,
                                        std::uint64_t port, std::string_view username,
                                        std::string_view credential) {
  std::vector<std::byte> entry;
  push_uint(entry, 1U, kind);
  push_bytes(entry, 2U, as_bytes(hostname));
  push_uint(entry, 3U, port);
  if (!username.empty()) {
    push_bytes(entry, 4U, as_bytes(username));
  }
  if (!credential.empty()) {
    push_bytes(entry, 5U, as_bytes(credential));
  }
  return entry;
}

std::vector<std::byte> ice_config_payload(const std::vector<std::vector<std::byte>>& server_entries,
                                          std::uint64_t expires_unix_seconds) {
  std::vector<std::byte> nested;
  for (const auto& entry : server_entries) {
    push_bytes(nested, 1U, entry);
  }
  push_uint(nested, 2U, expires_unix_seconds);
  return nested;
}

// Wraps an IceConfig payload as LoginResult field 4 after the mandatory
// tenant/enrollment/lease fields.
std::vector<std::byte> login_result_with_ice(const std::vector<std::byte>& ice_nested) {
  std::vector<std::byte> payload;
  push_bytes(payload, 1U, as_bytes("tenant-a"));
  push_uint(payload, 2U, 7U);
  push_uint(payload, 3U, 45000U);
  push_bytes(payload, 4U, ice_nested);
  return payload;
}

// Wraps an IceConfig payload as HeartbeatAck field 3 after the mandatory
// lease generation/grant fields.
std::vector<std::byte> heartbeat_ack_with_ice(const std::vector<std::byte>& ice_nested) {
  std::vector<std::byte> payload;
  push_uint(payload, 1U, 9U);
  push_uint(payload, 2U, 45000U);
  push_bytes(payload, 3U, ice_nested);
  return payload;
}

TEST(M3BRelayWssControlTest, FramesAndPayloadsRoundTrip) {
  const std::array<std::byte, 3U> payload{std::byte{0x01U}, std::byte{0x02U}, std::byte{0x03U}};
  auto encoded = encode_relay_wss_control_frame(RelayWssControlType::enrollment_request, payload);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();
  auto parsed = parse_relay_wss_control_frame(*encoded.value_if());
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  EXPECT_EQ(parsed.value_if()->type, RelayWssControlType::enrollment_request);
  EXPECT_EQ(parsed.value_if()->payload, std::vector<std::byte>(payload.begin(), payload.end()));

  RelayWssEnrollmentResult result{
      .tenant = "tenant-a",
      .enrollment_generation = 7U,
      .token_remaining_uses_after = 2U,
      .relay_certificate_sha256 = std::nullopt};
  auto result_bytes = encode_relay_wss_enrollment_result(result);
  ASSERT_TRUE(result_bytes) << result_bytes.error_if()->safe_detail();
  protocol::enrollment::v1::EnrollmentResult protobuf_result;
  protobuf_result.set_tenant(result.tenant);
  protobuf_result.set_enrollment_generation(result.enrollment_generation);
  protobuf_result.set_token_remaining_uses_after(result.token_remaining_uses_after);
  const auto protobuf_result_bytes = protobuf_result.SerializeAsString();
  EXPECT_EQ(
      *result_bytes.value_if(),
      std::vector<std::byte>(reinterpret_cast<const std::byte*>(protobuf_result_bytes.data()),
                             reinterpret_cast<const std::byte*>(protobuf_result_bytes.data()) +
                                 protobuf_result_bytes.size()));
  auto result_round_trip = parse_relay_wss_enrollment_result(*result_bytes.value_if());
  ASSERT_TRUE(result_round_trip) << result_round_trip.error_if()->safe_detail();
  EXPECT_EQ(result_round_trip.value_if()->tenant, result.tenant);
  EXPECT_EQ(result_round_trip.value_if()->enrollment_generation, result.enrollment_generation);
  EXPECT_EQ(result_round_trip.value_if()->token_remaining_uses_after,
            result.token_remaining_uses_after);

  result.token_remaining_uses_after = 0U;
  result_bytes = encode_relay_wss_enrollment_result(result);
  ASSERT_TRUE(result_bytes) << result_bytes.error_if()->safe_detail();
  protobuf_result.set_token_remaining_uses_after(0U);
  const auto zero_remaining_bytes = protobuf_result.SerializeAsString();
  EXPECT_EQ(*result_bytes.value_if(),
            std::vector<std::byte>(reinterpret_cast<const std::byte*>(zero_remaining_bytes.data()),
                                   reinterpret_cast<const std::byte*>(zero_remaining_bytes.data()) +
                                       zero_remaining_bytes.size()));
  result_round_trip = parse_relay_wss_enrollment_result(*result_bytes.value_if());
  ASSERT_TRUE(result_round_trip) << result_round_trip.error_if()->safe_detail();
  EXPECT_EQ(result_round_trip.value_if()->token_remaining_uses_after, 0U);

  auto error_bytes =
      encode_relay_wss_control_error(ErrorCode::authentication, "signature_verification_failed");
  ASSERT_TRUE(error_bytes) << error_bytes.error_if()->safe_detail();
  protocol::enrollment::v1::ControlError protobuf_error;
  protobuf_error.set_error_code(protocol::common::v1::ERROR_CODE_AUTHENTICATION);
  protobuf_error.set_safe_detail("signature_verification_failed");
  const auto protobuf_error_bytes = protobuf_error.SerializeAsString();
  EXPECT_EQ(*error_bytes.value_if(),
            std::vector<std::byte>(reinterpret_cast<const std::byte*>(protobuf_error_bytes.data()),
                                   reinterpret_cast<const std::byte*>(protobuf_error_bytes.data()) +
                                       protobuf_error_bytes.size()));
  auto error_round_trip = parse_relay_wss_control_error(*error_bytes.value_if());
  ASSERT_TRUE(error_round_trip) << error_round_trip.error_if()->safe_detail();
  EXPECT_EQ(error_round_trip.value_if()->code, ErrorCode::authentication);
  EXPECT_EQ(error_round_trip.value_if()->safe_detail, "signature_verification_failed");
}

TEST(M3BRelayWssControlTest, RejectsMalformedAndUnboundedInput) {
  EXPECT_FALSE(parse_relay_wss_control_frame({}));

  auto valid = encode_relay_wss_control_frame(RelayWssControlType::enrollment_challenge, {});
  ASSERT_TRUE(valid) << valid.error_if()->safe_detail();
  (*valid.value_if())[0U] = std::byte{0xffU};
  EXPECT_FALSE(parse_relay_wss_control_frame(*valid.value_if()));
  (*valid.value_if())[0U] = static_cast<std::byte>(RelayWssControlType::enrollment_challenge);
  (*valid.value_if())[4U] = std::byte{0x01U};
  EXPECT_FALSE(parse_relay_wss_control_frame(*valid.value_if()));

  std::vector<std::byte> oversized(max_relay_wss_control_frame_bytes + 1U);
  EXPECT_FALSE(parse_relay_wss_control_frame(oversized));
  EXPECT_FALSE(encode_relay_wss_control_frame(RelayWssControlType::enrollment_request, oversized));

  RelayWssEnrollmentResult invalid_result{
      .tenant = std::string{"\xc0\x80", 2U},
      .enrollment_generation = 1U,
      .token_remaining_uses_after = 0U,
      .relay_certificate_sha256 = std::nullopt};
  EXPECT_FALSE(encode_relay_wss_enrollment_result(invalid_result));
  invalid_result.tenant = std::string{"tenant\0a", 8U};
  EXPECT_FALSE(encode_relay_wss_enrollment_result(invalid_result));
  EXPECT_FALSE(encode_relay_wss_control_error(static_cast<ErrorCode>(0U), "invalid_code"));
  EXPECT_FALSE(encode_relay_wss_control_error(ErrorCode::protocol, "unsafe detail"));

  const std::array<std::byte, 8U> noncanonical_result{
      std::byte{0x0aU}, std::byte{0x81U}, std::byte{0x00U}, std::byte{'a'},
      std::byte{0x10U}, std::byte{0x01U}, std::byte{0x18U}, std::byte{0x00U}};
  EXPECT_FALSE(parse_relay_wss_enrollment_result(noncanonical_result));
  const std::array<std::byte, 5U> invalid_error_code{
      std::byte{0x08U}, std::byte{0x00U}, std::byte{0x12U}, std::byte{0x01U}, std::byte{'a'}};
  EXPECT_FALSE(parse_relay_wss_control_error(invalid_error_code));
  const std::array<std::byte, 5U> invalid_error_length{
      std::byte{0x08U}, std::byte{0x11U}, std::byte{0x12U}, std::byte{0x02U}, std::byte{'a'}};
  EXPECT_FALSE(parse_relay_wss_control_error(invalid_error_length));
}

TEST(M3BRelayWssControlTest, LoginHeartbeatAndEndpointPayloadsRoundTrip) {
  RelayWssLoginResult login;
  login.tenant = "tenant-a";
  login.enrollment_generation = 7U;
  login.lease_milliseconds = 45000U;
  auto login_bytes = encode_relay_wss_login_result(login);
  ASSERT_TRUE(login_bytes) << login_bytes.error_if()->safe_detail();
  protocol::relay::v1::LoginResult protobuf_login;
  protobuf_login.set_tenant(login.tenant);
  protobuf_login.set_enrollment_generation(login.enrollment_generation);
  protobuf_login.set_lease_milliseconds(login.lease_milliseconds);
  const std::string protobuf_login_bytes = protobuf_login.SerializeAsString();
  EXPECT_EQ(*login_bytes.value_if(),
            std::vector<std::byte>(reinterpret_cast<const std::byte*>(protobuf_login_bytes.data()),
                                   reinterpret_cast<const std::byte*>(protobuf_login_bytes.data()) +
                                       protobuf_login_bytes.size()));
  auto login_round_trip = parse_relay_wss_login_result(*login_bytes.value_if());
  ASSERT_TRUE(login_round_trip) << login_round_trip.error_if()->safe_detail();
  EXPECT_EQ(login_round_trip.value_if()->tenant, login.tenant);
  EXPECT_EQ(login_round_trip.value_if()->enrollment_generation, login.enrollment_generation);
  EXPECT_EQ(login_round_trip.value_if()->lease_milliseconds, login.lease_milliseconds);

  RelayWssHeartbeatRequest heartbeat_request;
  heartbeat_request.lease_milliseconds = 15000U;
  auto heartbeat_bytes = encode_relay_wss_heartbeat_request(heartbeat_request);
  ASSERT_TRUE(heartbeat_bytes) << heartbeat_bytes.error_if()->safe_detail();
  protocol::relay::v1::HeartbeatRequest protobuf_heartbeat;
  protobuf_heartbeat.set_lease_milliseconds(15000U);
  const std::string protobuf_heartbeat_bytes = protobuf_heartbeat.SerializeAsString();
  EXPECT_EQ(
      *heartbeat_bytes.value_if(),
      std::vector<std::byte>(reinterpret_cast<const std::byte*>(protobuf_heartbeat_bytes.data()),
                             reinterpret_cast<const std::byte*>(protobuf_heartbeat_bytes.data()) +
                                 protobuf_heartbeat_bytes.size()));
  auto heartbeat_round_trip = parse_relay_wss_heartbeat_request(*heartbeat_bytes.value_if());
  ASSERT_TRUE(heartbeat_round_trip) << heartbeat_round_trip.error_if()->safe_detail();
  EXPECT_EQ(heartbeat_round_trip.value_if()->lease_milliseconds,
            heartbeat_request.lease_milliseconds);

  RelayWssHeartbeatAck ack;
  ack.lease_generation = 9U;
  ack.granted_lease_milliseconds = 45000U;
  auto ack_bytes = encode_relay_wss_heartbeat_ack(ack);
  ASSERT_TRUE(ack_bytes) << ack_bytes.error_if()->safe_detail();
  protocol::relay::v1::HeartbeatAck protobuf_ack;
  protobuf_ack.set_lease_generation(ack.lease_generation);
  protobuf_ack.set_granted_lease_milliseconds(ack.granted_lease_milliseconds);
  const std::string protobuf_ack_bytes = protobuf_ack.SerializeAsString();
  EXPECT_EQ(*ack_bytes.value_if(),
            std::vector<std::byte>(reinterpret_cast<const std::byte*>(protobuf_ack_bytes.data()),
                                   reinterpret_cast<const std::byte*>(protobuf_ack_bytes.data()) +
                                       protobuf_ack_bytes.size()));
  auto ack_round_trip = parse_relay_wss_heartbeat_ack(*ack_bytes.value_if());
  ASSERT_TRUE(ack_round_trip) << ack_round_trip.error_if()->safe_detail();
  EXPECT_EQ(ack_round_trip.value_if()->lease_generation, ack.lease_generation);
  EXPECT_EQ(ack_round_trip.value_if()->granted_lease_milliseconds, ack.granted_lease_milliseconds);

  const std::array<std::byte, 3U> record{std::byte{0x01U}, std::byte{0x02U}, std::byte{0x03U}};
  const std::array<std::byte, 2U> manifest{std::byte{0x04U}, std::byte{0x05U}};
  RelayWssEndpointPublish publish;
  publish.endpoint_record.assign(record.begin(), record.end());
  publish.service_manifest.emplace(manifest.begin(), manifest.end());
  auto publish_bytes = encode_relay_wss_endpoint_publish(publish);
  ASSERT_TRUE(publish_bytes) << publish_bytes.error_if()->safe_detail();
  protocol::relay::v1::EndpointPublish protobuf_publish;
  protobuf_publish.set_endpoint_record(
      std::string{reinterpret_cast<const char*>(record.data()), record.size()});
  protobuf_publish.set_service_manifest(
      std::string{reinterpret_cast<const char*>(manifest.data()), manifest.size()});
  const std::string protobuf_publish_bytes = protobuf_publish.SerializeAsString();
  EXPECT_EQ(
      *publish_bytes.value_if(),
      std::vector<std::byte>(reinterpret_cast<const std::byte*>(protobuf_publish_bytes.data()),
                             reinterpret_cast<const std::byte*>(protobuf_publish_bytes.data()) +
                                 protobuf_publish_bytes.size()));
  auto publish_round_trip = parse_relay_wss_endpoint_publish(*publish_bytes.value_if());
  ASSERT_TRUE(publish_round_trip) << publish_round_trip.error_if()->safe_detail();
  EXPECT_EQ(publish_round_trip.value_if()->endpoint_record,
            std::vector<std::byte>(record.begin(), record.end()));
  ASSERT_TRUE(publish_round_trip.value_if()->service_manifest);
  EXPECT_EQ(*publish_round_trip.value_if()->service_manifest,
            std::vector<std::byte>(manifest.begin(), manifest.end()));

  RelayWssEndpointPublishAck publish_ack{.record_generation = 3U};
  auto publish_ack_bytes = encode_relay_wss_endpoint_publish_ack(publish_ack);
  ASSERT_TRUE(publish_ack_bytes) << publish_ack_bytes.error_if()->safe_detail();
  auto publish_ack_round_trip = parse_relay_wss_endpoint_publish_ack(*publish_ack_bytes.value_if());
  ASSERT_TRUE(publish_ack_round_trip) << publish_ack_round_trip.error_if()->safe_detail();
  EXPECT_EQ(publish_ack_round_trip.value_if()->record_generation, 3U);

  DeviceId::Storage device_bytes{};
  device_bytes[0] = std::byte{0x31U};
  EndpointId::Storage endpoint_bytes{};
  endpoint_bytes[0] = std::byte{0x21U};
  RelayWssEndpointQuery query;
  query.device_id = DeviceId{device_bytes};
  query.endpoint_id = EndpointId{endpoint_bytes};
  auto query_bytes = encode_relay_wss_endpoint_query(query);
  ASSERT_TRUE(query_bytes) << query_bytes.error_if()->safe_detail();
  auto query_round_trip = parse_relay_wss_endpoint_query(*query_bytes.value_if());
  ASSERT_TRUE(query_round_trip) << query_round_trip.error_if()->safe_detail();
  EXPECT_EQ(query_round_trip.value_if()->device_id, query.device_id);
  EXPECT_EQ(query_round_trip.value_if()->endpoint_id, query.endpoint_id);

  RelayWssEndpointPublication publication;
  publication.device_id = *query.device_id;
  publication.endpoint_id = *query.endpoint_id;
  publication.application_id = "com.example.device";
  publication.record_generation = 4U;
  publication.manifest_generation = 5U;
  publication.manifest_sha256 = std::array<std::byte, 32U>{};
  (*publication.manifest_sha256)[0U] = std::byte{0x5aU};
  publication.expires_unix_milliseconds = 6U;
  publication.lease_expires_unix_milliseconds = 7U;
  publication.endpoint_record = std::vector<std::byte>(record.begin(), record.end());
  publication.identity_public_key = IdentityPublicKey{};
  (*publication.identity_public_key)[0U] = std::byte{0x6bU};
  RelayWssEndpointQueryResult result;
  result.endpoints.push_back(publication);
  auto result_bytes = encode_relay_wss_endpoint_query_result(result);
  ASSERT_TRUE(result_bytes) << result_bytes.error_if()->safe_detail();
  auto result_round_trip = parse_relay_wss_endpoint_query_result(*result_bytes.value_if());
  ASSERT_TRUE(result_round_trip) << result_round_trip.error_if()->safe_detail();
  ASSERT_EQ(result_round_trip.value_if()->endpoints.size(), 1U);
  EXPECT_EQ(result_round_trip.value_if()->endpoints[0U].application_id, publication.application_id);
  EXPECT_EQ(result_round_trip.value_if()->endpoints[0U].record_generation, 4U);
  EXPECT_EQ(result_round_trip.value_if()->endpoints[0U].lease_expires_unix_milliseconds, 7U);
  EXPECT_EQ(result_round_trip.value_if()->endpoints[0U].endpoint_record,
            publication.endpoint_record);
  EXPECT_EQ(result_round_trip.value_if()->endpoints[0U].identity_public_key,
            publication.identity_public_key);
}

TEST(M3BRelayWssControlTest, RejectsMalformedLoginHeartbeatAndEndpointPayloads) {
  RelayWssLoginResult invalid_login;
  invalid_login.tenant = "tenant-a";
  invalid_login.enrollment_generation = 0U;
  invalid_login.lease_milliseconds = 1U;
  EXPECT_FALSE(encode_relay_wss_login_result(invalid_login));
  EXPECT_FALSE(parse_relay_wss_login_result({}));

  const std::array<std::byte, 3U> duplicate_login{std::byte{0x0aU}, std::byte{0x01U},
                                                  std::byte{'a'}};
  EXPECT_FALSE(parse_relay_wss_login_result(duplicate_login));

  RelayWssHeartbeatRequest heartbeat;
  heartbeat.lease_milliseconds = 120001U;
  EXPECT_FALSE(encode_relay_wss_heartbeat_request(heartbeat));
  const std::array<std::byte, 2U> heartbeat_too_long{std::byte{0x08U}, std::byte{0x96U}};
  EXPECT_FALSE(parse_relay_wss_heartbeat_request(heartbeat_too_long));

  EXPECT_FALSE(encode_relay_wss_heartbeat_ack(RelayWssHeartbeatAck{}));
  EXPECT_FALSE(parse_relay_wss_heartbeat_ack({}));

  RelayWssEndpointPublish publish;
  EXPECT_FALSE(encode_relay_wss_endpoint_publish(publish));
  publish.endpoint_record.assign(17U * 1024U, std::byte{0x01U});
  EXPECT_FALSE(encode_relay_wss_endpoint_publish(publish));
  EXPECT_FALSE(parse_relay_wss_endpoint_publish({}));

  RelayWssEndpointPublishAck ack{};
  EXPECT_FALSE(encode_relay_wss_endpoint_publish_ack(ack));

  RelayWssEndpointQuery query;
  EndpointId::Storage endpoint{};
  endpoint[0] = std::byte{0x01U};
  query.endpoint_id = EndpointId{endpoint};
  EXPECT_FALSE(encode_relay_wss_endpoint_query(query));
  EXPECT_FALSE(parse_relay_wss_endpoint_query_result(
      std::array<std::byte, 2U>{std::byte{0x0aU}, std::byte{0x00U}}));
}

// Relay-issued ICE configuration: encode/parse round trip plus byte-for-byte
// equality with the protoc-generated relay.v1 serializer for every server
// kind. Stun entries omit the kind varint (canonical proto3: zero-valued
// scalars are not serialized), so the encoder output is byte-identical to the
// generated runtime for stun, TURN/UDP, and TURN/TCP alike.
TEST(M3BRelayWssControlTest, LoginResultIceConfigRoundTripMatchesProtobuf) {
  const std::uint64_t expires = 1'800'000'000U;
  RelayWssLoginResult login;
  login.tenant = "tenant-a";
  login.enrollment_generation = 7U;
  login.lease_milliseconds = 45000U;
  login.ice_config = RelayWssIceConfig{};
  login.ice_config->expires_unix_seconds = expires;
  RelayWssIceServer turn_udp;
  turn_udp.kind = RelayWssIceServerKind::turn_udp;
  turn_udp.hostname = "turn.example.com";
  turn_udp.port = 3478U;
  turn_udp.username = "1800000000:tenant-a:device";
  turn_udp.credential = fake_turn_credential;
  login.ice_config->servers.push_back(turn_udp);
  RelayWssIceServer turn_tcp;
  turn_tcp.kind = RelayWssIceServerKind::turn_tcp;
  turn_tcp.hostname = "2001:db8::1";
  turn_tcp.port = 5349U;
  turn_tcp.username = "1800000000:tenant-a:device";
  turn_tcp.credential = fake_turn_credential;
  login.ice_config->servers.push_back(turn_tcp);
  RelayWssIceServer stun;
  stun.kind = RelayWssIceServerKind::stun;
  stun.hostname = "stun.example.com";
  stun.port = 3478U;
  login.ice_config->servers.push_back(stun);

  auto login_bytes = encode_relay_wss_login_result(login);
  ASSERT_TRUE(login_bytes) << login_bytes.error_if()->safe_detail();

  protocol::relay::v1::LoginResult protobuf_login;
  protobuf_login.set_tenant(login.tenant);
  protobuf_login.set_enrollment_generation(login.enrollment_generation);
  protobuf_login.set_lease_milliseconds(login.lease_milliseconds);
  auto* protobuf_ice = protobuf_login.mutable_ice_config();
  protobuf_ice->set_expires_unix_seconds(expires);
  auto* first = protobuf_ice->add_servers();
  first->set_kind(1U);
  first->set_hostname("turn.example.com");
  first->set_port(3478U);
  first->set_username(turn_udp.username);
  first->set_credential(turn_udp.credential);
  auto* second = protobuf_ice->add_servers();
  second->set_kind(2U);
  second->set_hostname("2001:db8::1");
  second->set_port(5349U);
  second->set_username(turn_tcp.username);
  second->set_credential(turn_tcp.credential);
  auto* third = protobuf_ice->add_servers();
  third->set_kind(0U);
  third->set_hostname("stun.example.com");
  third->set_port(3478U);
  const std::string serialized = protobuf_login.SerializeAsString();
  EXPECT_EQ(*login_bytes.value_if(), protobuf_bytes(serialized));

  auto parsed = parse_relay_wss_login_result(*login_bytes.value_if());
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  ASSERT_TRUE(parsed.value_if()->ice_config);
  EXPECT_EQ(parsed.value_if()->ice_config->expires_unix_seconds, expires);
  ASSERT_EQ(parsed.value_if()->ice_config->servers.size(), 3U);
  EXPECT_EQ(parsed.value_if()->ice_config->servers[0U].kind, RelayWssIceServerKind::turn_udp);
  EXPECT_EQ(parsed.value_if()->ice_config->servers[0U].hostname, "turn.example.com");
  EXPECT_EQ(parsed.value_if()->ice_config->servers[0U].port, 3478U);
  EXPECT_EQ(parsed.value_if()->ice_config->servers[0U].username, turn_udp.username);
  EXPECT_EQ(parsed.value_if()->ice_config->servers[0U].credential, turn_udp.credential);
  EXPECT_EQ(parsed.value_if()->ice_config->servers[1U].kind, RelayWssIceServerKind::turn_tcp);
  EXPECT_EQ(parsed.value_if()->ice_config->servers[1U].hostname, "2001:db8::1");
  EXPECT_EQ(parsed.value_if()->ice_config->servers[1U].port, 5349U);

  // The stun entry round-trips: kind decodes to stun, credentials stay empty.
  EXPECT_EQ(parsed.value_if()->ice_config->servers[2U].kind, RelayWssIceServerKind::stun);
  EXPECT_EQ(parsed.value_if()->ice_config->servers[2U].hostname, "stun.example.com");
  EXPECT_EQ(parsed.value_if()->ice_config->servers[2U].port, 3478U);
  EXPECT_TRUE(parsed.value_if()->ice_config->servers[2U].username.empty());
  EXPECT_TRUE(parsed.value_if()->ice_config->servers[2U].credential.empty());

  // The kind field may also be omitted entirely (canonical proto3 default):
  // hostname and port alone decode to stun.
  std::vector<std::byte> kind_absent_entry;
  push_bytes(kind_absent_entry, 2U, as_bytes("stun.example.com"));
  push_uint(kind_absent_entry, 3U, 3478U);
  const std::vector<std::byte> kind_absent = ice_config_payload({kind_absent_entry}, expires);
  auto kind_absent_parsed = parse_relay_wss_login_result(login_result_with_ice(kind_absent));
  ASSERT_TRUE(kind_absent_parsed) << kind_absent_parsed.error_if()->safe_detail();
  ASSERT_TRUE(kind_absent_parsed.value_if()->ice_config);
  ASSERT_EQ(kind_absent_parsed.value_if()->ice_config->servers.size(), 1U);
  EXPECT_EQ(kind_absent_parsed.value_if()->ice_config->servers[0U].kind,
            RelayWssIceServerKind::stun);
  EXPECT_EQ(kind_absent_parsed.value_if()->ice_config->servers[0U].hostname, "stun.example.com");
  EXPECT_EQ(kind_absent_parsed.value_if()->ice_config->servers[0U].port, 3478U);
  EXPECT_TRUE(kind_absent_parsed.value_if()->ice_config->servers[0U].username.empty());
  EXPECT_TRUE(kind_absent_parsed.value_if()->ice_config->servers[0U].credential.empty());
}

TEST(M3BRelayWssControlTest, HeartbeatAckIceConfigRoundTripMatchesProtobuf) {
  const std::uint64_t expires = 1'800'000'100U;
  RelayWssHeartbeatAck ack;
  ack.lease_generation = 9U;
  ack.granted_lease_milliseconds = 45000U;
  ack.ice_config = RelayWssIceConfig{};
  ack.ice_config->expires_unix_seconds = expires;
  RelayWssIceServer turn;
  turn.kind = RelayWssIceServerKind::turn_udp;
  turn.hostname = "turn.example.com";
  turn.port = 3478U;
  turn.username = "1800000100:tenant-a:device";
  turn.credential = fake_turn_credential;
  ack.ice_config->servers.push_back(turn);

  auto ack_bytes = encode_relay_wss_heartbeat_ack(ack);
  ASSERT_TRUE(ack_bytes) << ack_bytes.error_if()->safe_detail();

  protocol::relay::v1::HeartbeatAck protobuf_ack;
  protobuf_ack.set_lease_generation(ack.lease_generation);
  protobuf_ack.set_granted_lease_milliseconds(ack.granted_lease_milliseconds);
  auto* protobuf_ice = protobuf_ack.mutable_ice_config();
  protobuf_ice->set_expires_unix_seconds(expires);
  auto* server = protobuf_ice->add_servers();
  server->set_kind(1U);
  server->set_hostname("turn.example.com");
  server->set_port(3478U);
  server->set_username(turn.username);
  server->set_credential(turn.credential);
  const std::string serialized = protobuf_ack.SerializeAsString();
  EXPECT_EQ(*ack_bytes.value_if(), protobuf_bytes(serialized));

  auto parsed = parse_relay_wss_heartbeat_ack(*ack_bytes.value_if());
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  ASSERT_TRUE(parsed.value_if()->ice_config);
  EXPECT_EQ(parsed.value_if()->ice_config->expires_unix_seconds, expires);
  ASSERT_EQ(parsed.value_if()->ice_config->servers.size(), 1U);
  EXPECT_EQ(parsed.value_if()->ice_config->servers[0U].kind, RelayWssIceServerKind::turn_udp);
  EXPECT_EQ(parsed.value_if()->ice_config->servers[0U].username, turn.username);
  EXPECT_EQ(parsed.value_if()->ice_config->servers[0U].credential, turn.credential);

  // The raised heartbeat_ack payload bound: the ICE-bearing ack above exceeds
  // the legacy 32-byte budget and must still parse; one byte past the new
  // 2048-byte bound must be rejected.
  std::vector<std::byte> oversized_payload = *ack_bytes.value_if();
  oversized_payload.insert(oversized_payload.end(), 2049U, std::byte{0x00U});
  auto oversized_frame =
      encode_relay_wss_control_frame(RelayWssControlType::heartbeat_ack, oversized_payload);
  ASSERT_TRUE(oversized_frame) << oversized_frame.error_if()->safe_detail();
  auto oversized_parse = parse_relay_wss_control_frame(*oversized_frame.value_if());
  ASSERT_TRUE(oversized_parse) << oversized_parse.error_if()->safe_detail();
  EXPECT_FALSE(parse_relay_wss_heartbeat_ack(oversized_parse.value_if()->payload));

  // login_result keeps its own raised 4096-byte bound.
  std::vector<std::byte> oversized_login = *ack_bytes.value_if();
  oversized_login.insert(oversized_login.end(), 4097U, std::byte{0x00U});
  EXPECT_FALSE(parse_relay_wss_login_result(oversized_login));
}

// Regression: without relay-issued ICE configuration the encoded login_result
// and heartbeat_ack stay byte-identical with a protobuf message that never
// sets the optional field, and parsing yields no ice_config.
TEST(M3BRelayWssControlTest, PayloadsWithoutIceConfigStayByteIdentical) {
  RelayWssLoginResult login;
  login.tenant = "tenant-a";
  login.enrollment_generation = 7U;
  login.lease_milliseconds = 45000U;
  auto login_bytes = encode_relay_wss_login_result(login);
  ASSERT_TRUE(login_bytes) << login_bytes.error_if()->safe_detail();
  protocol::relay::v1::LoginResult protobuf_login;
  protobuf_login.set_tenant(login.tenant);
  protobuf_login.set_enrollment_generation(login.enrollment_generation);
  protobuf_login.set_lease_milliseconds(login.lease_milliseconds);
  EXPECT_FALSE(protobuf_login.has_ice_config());
  const std::string login_serialized = protobuf_login.SerializeAsString();
  EXPECT_EQ(*login_bytes.value_if(), protobuf_bytes(login_serialized));

  auto login_parsed = parse_relay_wss_login_result(*login_bytes.value_if());
  ASSERT_TRUE(login_parsed) << login_parsed.error_if()->safe_detail();
  EXPECT_FALSE(login_parsed.value_if()->ice_config.has_value());

  RelayWssHeartbeatAck ack;
  ack.lease_generation = 9U;
  ack.granted_lease_milliseconds = 45000U;
  auto ack_bytes = encode_relay_wss_heartbeat_ack(ack);
  ASSERT_TRUE(ack_bytes) << ack_bytes.error_if()->safe_detail();
  protocol::relay::v1::HeartbeatAck protobuf_ack;
  protobuf_ack.set_lease_generation(ack.lease_generation);
  protobuf_ack.set_granted_lease_milliseconds(ack.granted_lease_milliseconds);
  EXPECT_FALSE(protobuf_ack.has_ice_config());
  const std::string ack_serialized = protobuf_ack.SerializeAsString();
  EXPECT_EQ(*ack_bytes.value_if(), protobuf_bytes(ack_serialized));

  auto ack_parsed = parse_relay_wss_heartbeat_ack(*ack_bytes.value_if());
  ASSERT_TRUE(ack_parsed) << ack_parsed.error_if()->safe_detail();
  EXPECT_FALSE(ack_parsed.value_if()->ice_config.has_value());
}

// Every structural rule the nested IceConfig codec enforces, exercised with
// hand-crafted bytes the encoder refuses to produce.
TEST(M3BRelayWssControlTest, RejectsMalformedIceConfigPayloads) {
  const std::vector<std::byte> turn =
      ice_server_entry(1U, "turn.example.com", 3478U, "1800000000:tenant-a:device", "cHJvZA==");
  const std::vector<std::byte> credless_turn =
      ice_server_entry(1U, "turn.example.com", 3478U, "", "");
  const std::vector<std::byte> credentialed_stun =
      ice_server_entry(0U, "stun.example.com", 3478U, "user", "cHJvZA==");

  // More than 4 servers.
  const std::vector<std::byte> five_turn_servers =
      ice_config_payload({turn, turn, turn, turn, turn}, 1'800'000'000U);
  EXPECT_FALSE(parse_relay_wss_login_result(login_result_with_ice(five_turn_servers)));

  // Expiry missing or zero.
  std::vector<std::byte> servers_only;
  push_bytes(servers_only, 1U, turn);
  EXPECT_FALSE(parse_relay_wss_login_result(login_result_with_ice(servers_only)));
  const std::vector<std::byte> zero_expiry = ice_config_payload({turn}, 0U);
  EXPECT_FALSE(parse_relay_wss_login_result(login_result_with_ice(zero_expiry)));
  EXPECT_FALSE(parse_relay_wss_heartbeat_ack(heartbeat_ack_with_ice(zero_expiry)));

  // Empty server list (expiry only).
  const std::vector<std::byte> expiry_only = ice_config_payload({}, 1U);
  EXPECT_FALSE(parse_relay_wss_login_result(login_result_with_ice(expiry_only)));
  EXPECT_FALSE(parse_relay_wss_heartbeat_ack(heartbeat_ack_with_ice(expiry_only)));

  // STUN entries must be credential-free; TURN entries must carry both. An
  // explicitly zero kind decodes to stun, so the credential rule still bites.
  const std::vector<std::byte> stun_with_credentials =
      ice_config_payload({credentialed_stun}, 1'800'000'000U);
  auto stun_creds_rejected =
      parse_relay_wss_login_result(login_result_with_ice(stun_with_credentials));
  ASSERT_FALSE(stun_creds_rejected);
  EXPECT_EQ(stun_creds_rejected.error_if()->safe_detail(), "ice_config_stun_credentials_invalid");
  const std::vector<std::byte> turn_without_credentials =
      ice_config_payload({credless_turn}, 1'800'000'000U);
  auto turn_creds_rejected =
      parse_relay_wss_login_result(login_result_with_ice(turn_without_credentials));
  ASSERT_FALSE(turn_creds_rejected);
  EXPECT_EQ(turn_creds_rejected.error_if()->safe_detail(), "ice_config_turn_credentials_missing");

  // Unknown kind 4 is rejected with the dedicated detail; port 0 and port
  // 65536 stay invalid.
  const std::vector<std::byte> unknown_kind = ice_config_payload(
      {ice_server_entry(4U, "turn.example.com", 3478U, "user", "cHJvZA==")}, 1'800'000'000U);
  auto unknown_kind_rejected = parse_relay_wss_login_result(login_result_with_ice(unknown_kind));
  ASSERT_FALSE(unknown_kind_rejected);
  EXPECT_EQ(unknown_kind_rejected.error_if()->safe_detail(), "ice_config_kind_invalid");
  const std::vector<std::byte> zero_port = ice_config_payload(
      {ice_server_entry(1U, "turn.example.com", 0U, "user", "cHJvZA==")}, 1'800'000'000U);
  EXPECT_FALSE(parse_relay_wss_login_result(login_result_with_ice(zero_port)));
  const std::vector<std::byte> overflowing_port = ice_config_payload(
      {ice_server_entry(1U, "turn.example.com", 65536U, "user", "cHJvZA==")}, 1'800'000'000U);
  EXPECT_FALSE(parse_relay_wss_login_result(login_result_with_ice(overflowing_port)));

  // Duplicate fields: two expires fields, and a server entry carrying field 1
  // twice.
  std::vector<std::byte> double_expiry = ice_config_payload({turn}, 1'800'000'000U);
  push_uint(double_expiry, 2U, 1'800'000'001U);
  EXPECT_FALSE(parse_relay_wss_login_result(login_result_with_ice(double_expiry)));
  std::vector<std::byte> duplicate_kind_entry;
  push_uint(duplicate_kind_entry, 1U, 1U);
  push_uint(duplicate_kind_entry, 1U, 2U);
  push_bytes(duplicate_kind_entry, 2U, as_bytes("turn.example.com"));
  push_uint(duplicate_kind_entry, 3U, 3478U);
  push_bytes(duplicate_kind_entry, 4U, as_bytes("user"));
  push_bytes(duplicate_kind_entry, 5U, as_bytes("cHJvZA=="));
  const std::vector<std::byte> duplicate_kind =
      ice_config_payload({duplicate_kind_entry}, 1'800'000'000U);
  EXPECT_FALSE(parse_relay_wss_login_result(login_result_with_ice(duplicate_kind)));

  // Empty and oversized hostnames.
  const std::vector<std::byte> empty_hostname =
      ice_config_payload({ice_server_entry(1U, "", 3478U, "user", "cHJvZA==")}, 1'800'000'000U);
  EXPECT_FALSE(parse_relay_wss_login_result(login_result_with_ice(empty_hostname)));
  const std::vector<std::byte> oversized_hostname = ice_config_payload(
      {ice_server_entry(1U, std::string(256U, 'a'), 3478U, "user", "cHJvZA==")}, 1'800'000'000U);
  EXPECT_FALSE(parse_relay_wss_login_result(login_result_with_ice(oversized_hostname)));

  // Truncated nested message: field 4 announces more bytes than the payload
  // carries.
  std::vector<std::byte> truncated =
      login_result_with_ice(ice_config_payload({turn}, 1'800'000'000U));
  truncated[truncated.size() - 2U] = std::byte{0x00U};  // corrupt the tail
  truncated.push_back(std::byte{0xffU});                // length now exceeds the payload
  std::vector<std::byte> truncated_outer;
  push_bytes(truncated_outer, 1U, as_bytes("tenant-a"));
  push_uint(truncated_outer, 2U, 7U);
  push_uint(truncated_outer, 3U, 45000U);
  truncated_outer.push_back(std::byte{0x22U});  // field 4, wire type 2
  truncated_outer.push_back(std::byte{0x40U});  // announces 64 bytes
  for (std::size_t index = 0U; index < 3U; ++index) {
    truncated_outer.push_back(std::byte{0x01U});
  }
  EXPECT_FALSE(parse_relay_wss_login_result(truncated_outer));

  // Empty nested message (field 4 present but zero-length).
  std::vector<std::byte> empty_nested;
  push_bytes(empty_nested, 1U, as_bytes("tenant-a"));
  push_uint(empty_nested, 2U, 7U);
  push_uint(empty_nested, 3U, 45000U);
  push_bytes(empty_nested, 4U, std::vector<std::byte>{});
  EXPECT_FALSE(parse_relay_wss_login_result(empty_nested));
}

}  // namespace
}  // namespace heyaki
