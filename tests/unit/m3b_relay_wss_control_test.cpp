#include <heyaki/relay_wss_control.hpp>

#include "heyaki/enrollment/v1/enrollment.pb.h"

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

}  // namespace
}  // namespace heyaki
