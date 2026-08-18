#include <heyaki/relay_wss_control.hpp>

#include "heyaki/enrollment/v1/enrollment.pb.h"
#include "heyaki/relay/v1/relay_control.pb.h"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace heyaki {
namespace {

TEST(M3BRelayWssControlTest, FramesAndPayloadsRoundTrip) {
  const std::array<std::byte, 3U> payload{
      std::byte{0x01U}, std::byte{0x02U}, std::byte{0x03U}};
  auto encoded = encode_relay_wss_control_frame(
      RelayWssControlType::enrollment_request, payload);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();
  auto parsed = parse_relay_wss_control_frame(*encoded.value_if());
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  EXPECT_EQ(parsed.value_if()->type, RelayWssControlType::enrollment_request);
  EXPECT_EQ(parsed.value_if()->payload,
            std::vector<std::byte>(payload.begin(), payload.end()));

  RelayWssEnrollmentResult result{
      .tenant = "tenant-a",
      .enrollment_generation = 7U,
      .token_remaining_uses_after = 2U};
  auto result_bytes = encode_relay_wss_enrollment_result(result);
  ASSERT_TRUE(result_bytes) << result_bytes.error_if()->safe_detail();
  protocol::enrollment::v1::EnrollmentResult protobuf_result;
  protobuf_result.set_tenant(result.tenant);
  protobuf_result.set_enrollment_generation(result.enrollment_generation);
  protobuf_result.set_token_remaining_uses_after(
      result.token_remaining_uses_after);
  const auto protobuf_result_bytes = protobuf_result.SerializeAsString();
  EXPECT_EQ(*result_bytes.value_if(),
            std::vector<std::byte>(
                reinterpret_cast<const std::byte*>(protobuf_result_bytes.data()),
                reinterpret_cast<const std::byte*>(protobuf_result_bytes.data()) +
                    protobuf_result_bytes.size()));
  auto result_round_trip =
      parse_relay_wss_enrollment_result(*result_bytes.value_if());
  ASSERT_TRUE(result_round_trip) << result_round_trip.error_if()->safe_detail();
  EXPECT_EQ(result_round_trip.value_if()->tenant, result.tenant);
  EXPECT_EQ(result_round_trip.value_if()->enrollment_generation,
            result.enrollment_generation);
  EXPECT_EQ(result_round_trip.value_if()->token_remaining_uses_after,
            result.token_remaining_uses_after);

  result.token_remaining_uses_after = 0U;
  result_bytes = encode_relay_wss_enrollment_result(result);
  ASSERT_TRUE(result_bytes) << result_bytes.error_if()->safe_detail();
  protobuf_result.set_token_remaining_uses_after(0U);
  const auto zero_remaining_bytes = protobuf_result.SerializeAsString();
  EXPECT_EQ(*result_bytes.value_if(),
            std::vector<std::byte>(
                reinterpret_cast<const std::byte*>(zero_remaining_bytes.data()),
                reinterpret_cast<const std::byte*>(zero_remaining_bytes.data()) +
                    zero_remaining_bytes.size()));
  result_round_trip =
      parse_relay_wss_enrollment_result(*result_bytes.value_if());
  ASSERT_TRUE(result_round_trip) << result_round_trip.error_if()->safe_detail();
  EXPECT_EQ(result_round_trip.value_if()->token_remaining_uses_after, 0U);

  auto error_bytes = encode_relay_wss_control_error(
      ErrorCode::authentication, "signature_verification_failed");
  ASSERT_TRUE(error_bytes) << error_bytes.error_if()->safe_detail();
  protocol::enrollment::v1::ControlError protobuf_error;
  protobuf_error.set_error_code(
      protocol::common::v1::ERROR_CODE_AUTHENTICATION);
  protobuf_error.set_safe_detail("signature_verification_failed");
  const auto protobuf_error_bytes = protobuf_error.SerializeAsString();
  EXPECT_EQ(*error_bytes.value_if(),
            std::vector<std::byte>(
                reinterpret_cast<const std::byte*>(protobuf_error_bytes.data()),
                reinterpret_cast<const std::byte*>(protobuf_error_bytes.data()) +
                    protobuf_error_bytes.size()));
  auto error_round_trip = parse_relay_wss_control_error(*error_bytes.value_if());
  ASSERT_TRUE(error_round_trip) << error_round_trip.error_if()->safe_detail();
  EXPECT_EQ(error_round_trip.value_if()->code, ErrorCode::authentication);
  EXPECT_EQ(error_round_trip.value_if()->safe_detail,
            "signature_verification_failed");
}

TEST(M3BRelayWssControlTest, RejectsMalformedAndUnboundedInput) {
  EXPECT_FALSE(parse_relay_wss_control_frame({}));

  auto valid = encode_relay_wss_control_frame(
      RelayWssControlType::enrollment_challenge, {});
  ASSERT_TRUE(valid) << valid.error_if()->safe_detail();
  (*valid.value_if())[0U] = std::byte{0xffU};
  EXPECT_FALSE(parse_relay_wss_control_frame(*valid.value_if()));
  (*valid.value_if())[0U] =
      static_cast<std::byte>(RelayWssControlType::enrollment_challenge);
  (*valid.value_if())[4U] = std::byte{0x01U};
  EXPECT_FALSE(parse_relay_wss_control_frame(*valid.value_if()));

  std::vector<std::byte> oversized(max_relay_wss_control_frame_bytes + 1U);
  EXPECT_FALSE(parse_relay_wss_control_frame(oversized));
  EXPECT_FALSE(encode_relay_wss_control_frame(
      RelayWssControlType::enrollment_request, oversized));

  RelayWssEnrollmentResult invalid_result{
      .tenant = std::string{"\xc0\x80", 2U},
      .enrollment_generation = 1U,
      .token_remaining_uses_after = 0U};
  EXPECT_FALSE(encode_relay_wss_enrollment_result(invalid_result));
  invalid_result.tenant = std::string{"tenant\0a", 8U};
  EXPECT_FALSE(encode_relay_wss_enrollment_result(invalid_result));
  EXPECT_FALSE(encode_relay_wss_control_error(
      static_cast<ErrorCode>(0U), "invalid_code"));
  EXPECT_FALSE(encode_relay_wss_control_error(
      ErrorCode::protocol, "unsafe detail"));

  const std::array<std::byte, 8U> noncanonical_result{
      std::byte{0x0aU}, std::byte{0x81U}, std::byte{0x00U}, std::byte{'a'},
      std::byte{0x10U}, std::byte{0x01U}, std::byte{0x18U}, std::byte{0x00U}};
  EXPECT_FALSE(parse_relay_wss_enrollment_result(noncanonical_result));
  const std::array<std::byte, 5U> invalid_error_code{
      std::byte{0x08U}, std::byte{0x00U}, std::byte{0x12U}, std::byte{0x01U},
      std::byte{'a'}};
  EXPECT_FALSE(parse_relay_wss_control_error(invalid_error_code));
  const std::array<std::byte, 5U> invalid_error_length{
      std::byte{0x08U}, std::byte{0x11U}, std::byte{0x12U}, std::byte{0x02U},
      std::byte{'a'}};
  EXPECT_FALSE(parse_relay_wss_control_error(invalid_error_length));
}

TEST(M3BRelayWssControlTest, LoginHeartbeatAndEndpointPayloadsRoundTrip) {
  RelayWssLoginResult login{
      .tenant = "tenant-a",
      .enrollment_generation = 7U,
      .lease_milliseconds = 45000U};
  auto login_bytes = encode_relay_wss_login_result(login);
  ASSERT_TRUE(login_bytes) << login_bytes.error_if()->safe_detail();
  protocol::relay::v1::LoginResult protobuf_login;
  protobuf_login.set_tenant(login.tenant);
  protobuf_login.set_enrollment_generation(login.enrollment_generation);
  protobuf_login.set_lease_milliseconds(login.lease_milliseconds);
  const std::string protobuf_login_bytes = protobuf_login.SerializeAsString();
  EXPECT_EQ(*login_bytes.value_if(),
            std::vector<std::byte>(
                reinterpret_cast<const std::byte*>(protobuf_login_bytes.data()),
                reinterpret_cast<const std::byte*>(protobuf_login_bytes.data()) +
                    protobuf_login_bytes.size()));
  auto login_round_trip = parse_relay_wss_login_result(*login_bytes.value_if());
  ASSERT_TRUE(login_round_trip) << login_round_trip.error_if()->safe_detail();
  EXPECT_EQ(login_round_trip.value_if()->tenant, login.tenant);
  EXPECT_EQ(login_round_trip.value_if()->enrollment_generation,
            login.enrollment_generation);
  EXPECT_EQ(login_round_trip.value_if()->lease_milliseconds,
            login.lease_milliseconds);

  RelayWssHeartbeatRequest heartbeat_request;
  heartbeat_request.lease_milliseconds = 15000U;
  auto heartbeat_bytes = encode_relay_wss_heartbeat_request(heartbeat_request);
  ASSERT_TRUE(heartbeat_bytes) << heartbeat_bytes.error_if()->safe_detail();
  protocol::relay::v1::HeartbeatRequest protobuf_heartbeat;
  protobuf_heartbeat.set_lease_milliseconds(15000U);
  const std::string protobuf_heartbeat_bytes = protobuf_heartbeat.SerializeAsString();
  EXPECT_EQ(*heartbeat_bytes.value_if(),
            std::vector<std::byte>(
                reinterpret_cast<const std::byte*>(protobuf_heartbeat_bytes.data()),
                reinterpret_cast<const std::byte*>(protobuf_heartbeat_bytes.data()) +
                    protobuf_heartbeat_bytes.size()));
  auto heartbeat_round_trip =
      parse_relay_wss_heartbeat_request(*heartbeat_bytes.value_if());
  ASSERT_TRUE(heartbeat_round_trip) << heartbeat_round_trip.error_if()->safe_detail();
  EXPECT_EQ(heartbeat_round_trip.value_if()->lease_milliseconds,
            heartbeat_request.lease_milliseconds);

  RelayWssHeartbeatAck ack{
      .lease_generation = 9U,
      .granted_lease_milliseconds = 45000U};
  auto ack_bytes = encode_relay_wss_heartbeat_ack(ack);
  ASSERT_TRUE(ack_bytes) << ack_bytes.error_if()->safe_detail();
  protocol::relay::v1::HeartbeatAck protobuf_ack;
  protobuf_ack.set_lease_generation(ack.lease_generation);
  protobuf_ack.set_granted_lease_milliseconds(ack.granted_lease_milliseconds);
  const std::string protobuf_ack_bytes = protobuf_ack.SerializeAsString();
  EXPECT_EQ(*ack_bytes.value_if(),
            std::vector<std::byte>(
                reinterpret_cast<const std::byte*>(protobuf_ack_bytes.data()),
                reinterpret_cast<const std::byte*>(protobuf_ack_bytes.data()) +
                    protobuf_ack_bytes.size()));
  auto ack_round_trip = parse_relay_wss_heartbeat_ack(*ack_bytes.value_if());
  ASSERT_TRUE(ack_round_trip) << ack_round_trip.error_if()->safe_detail();
  EXPECT_EQ(ack_round_trip.value_if()->lease_generation, ack.lease_generation);
  EXPECT_EQ(ack_round_trip.value_if()->granted_lease_milliseconds,
            ack.granted_lease_milliseconds);

  const std::array<std::byte, 3U> record{std::byte{0x01U}, std::byte{0x02U},
                                         std::byte{0x03U}};
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
  EXPECT_EQ(*publish_bytes.value_if(),
            std::vector<std::byte>(
                reinterpret_cast<const std::byte*>(protobuf_publish_bytes.data()),
                reinterpret_cast<const std::byte*>(protobuf_publish_bytes.data()) +
                    protobuf_publish_bytes.size()));
  auto publish_round_trip =
      parse_relay_wss_endpoint_publish(*publish_bytes.value_if());
  ASSERT_TRUE(publish_round_trip) << publish_round_trip.error_if()->safe_detail();
  EXPECT_EQ(publish_round_trip.value_if()->endpoint_record,
            std::vector<std::byte>(record.begin(), record.end()));
  ASSERT_TRUE(publish_round_trip.value_if()->service_manifest);
  EXPECT_EQ(*publish_round_trip.value_if()->service_manifest,
            std::vector<std::byte>(manifest.begin(), manifest.end()));

  RelayWssEndpointPublishAck publish_ack{.record_generation = 3U};
  auto publish_ack_bytes = encode_relay_wss_endpoint_publish_ack(publish_ack);
  ASSERT_TRUE(publish_ack_bytes) << publish_ack_bytes.error_if()->safe_detail();
  auto publish_ack_round_trip =
      parse_relay_wss_endpoint_publish_ack(*publish_ack_bytes.value_if());
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
  auto result_round_trip =
      parse_relay_wss_endpoint_query_result(*result_bytes.value_if());
  ASSERT_TRUE(result_round_trip) << result_round_trip.error_if()->safe_detail();
  ASSERT_EQ(result_round_trip.value_if()->endpoints.size(), 1U);
  EXPECT_EQ(result_round_trip.value_if()->endpoints[0U].application_id,
            publication.application_id);
  EXPECT_EQ(result_round_trip.value_if()->endpoints[0U].record_generation, 4U);
  EXPECT_EQ(result_round_trip.value_if()->endpoints[0U].lease_expires_unix_milliseconds, 7U);
  EXPECT_EQ(result_round_trip.value_if()->endpoints[0U].endpoint_record,
            publication.endpoint_record);
  EXPECT_EQ(result_round_trip.value_if()->endpoints[0U].identity_public_key,
            publication.identity_public_key);
}

TEST(M3BRelayWssControlTest, RejectsMalformedLoginHeartbeatAndEndpointPayloads) {
  RelayWssLoginResult invalid_login{
      .tenant = "tenant-a", .enrollment_generation = 0U, .lease_milliseconds = 1U};
  EXPECT_FALSE(encode_relay_wss_login_result(invalid_login));
  EXPECT_FALSE(parse_relay_wss_login_result({}));

  const std::array<std::byte, 3U> duplicate_login{
      std::byte{0x0aU}, std::byte{0x01U}, std::byte{'a'}};
  EXPECT_FALSE(parse_relay_wss_login_result(duplicate_login));

  RelayWssHeartbeatRequest heartbeat;
  heartbeat.lease_milliseconds = 120001U;
  EXPECT_FALSE(encode_relay_wss_heartbeat_request(heartbeat));
  const std::array<std::byte, 2U> heartbeat_too_long{
      std::byte{0x08U}, std::byte{0x96U}};
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

}  // namespace
}  // namespace heyaki
