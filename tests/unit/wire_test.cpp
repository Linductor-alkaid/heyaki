#include <heyaki/wire.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace {

constexpr std::array<std::pair<heyaki::FrameType, std::uint8_t>, 34U> frozen_frame_types{{
    {heyaki::FrameType::session_hello, 0x01U},
    {heyaki::FrameType::protocol_close, 0x02U},
    {heyaki::FrameType::ping, 0x03U},
    {heyaki::FrameType::pong, 0x04U},
    {heyaki::FrameType::cancel, 0x05U},
    {heyaki::FrameType::pairing_request, 0x10U},
    {heyaki::FrameType::pairing_result, 0x11U},
    {heyaki::FrameType::message, 0x20U},
    {heyaki::FrameType::message_ack, 0x21U},
    {heyaki::FrameType::rpc_request, 0x30U},
    {heyaki::FrameType::rpc_response, 0x31U},
    {heyaki::FrameType::rpc_cancel, 0x32U},
    {heyaki::FrameType::event_subscribe, 0x40U},
    {heyaki::FrameType::event_item, 0x41U},
    {heyaki::FrameType::event_unsubscribe, 0x42U},
    {heyaki::FrameType::stream_open, 0x50U},
    {heyaki::FrameType::stream_data, 0x51U},
    {heyaki::FrameType::stream_window_update, 0x52U},
    {heyaki::FrameType::stream_fin, 0x53U},
    {heyaki::FrameType::stream_reset, 0x54U},
    {heyaki::FrameType::file_manifest, 0x60U},
    {heyaki::FrameType::file_accept, 0x61U},
    {heyaki::FrameType::file_chunk, 0x62U},
    {heyaki::FrameType::file_complete, 0x63U},
    {heyaki::FrameType::file_reject, 0x64U},
    {heyaki::FrameType::shell_open, 0x70U},
    {heyaki::FrameType::shell_input, 0x71U},
    {heyaki::FrameType::shell_output, 0x72U},
    {heyaki::FrameType::shell_resize, 0x73U},
    {heyaki::FrameType::shell_signal, 0x74U},
    {heyaki::FrameType::shell_exit, 0x75U},
    {heyaki::FrameType::shell_eof, 0x76U},
    {heyaki::FrameType::shell_error, 0x77U},
    {heyaki::FrameType::shell_close, 0x78U},
}};

static_assert([] {
  for (const auto& [type, value] : frozen_frame_types) {
    if (static_cast<std::uint8_t>(type) != value) {
      return false;
    }
  }
  return true;
}());

heyaki::Frame sample_frame() {
  heyaki::MessageId::Storage message_id{};
  message_id.front() = std::byte{0x42U};
  return {.type = static_cast<std::uint8_t>(heyaki::FrameType::rpc_request),
          .flags = heyaki::frame_flag_required,
          .channel_id = 300U,
          .message_id = heyaki::MessageId{message_id},
          .payload = {std::byte{0x01U}, std::byte{0x02U}}};
}

TEST(Wire, RoundTripsCanonicalMultiByteVarint) {
  const auto encoded = heyaki::encode_frame(sample_frame());
  ASSERT_TRUE(encoded);
  const auto parsed = heyaki::parse_frame(*encoded.value_if());
  ASSERT_EQ(parsed.status, heyaki::FrameParseStatus::parsed);
  EXPECT_EQ(parsed.frame->channel_id, 300U);
  EXPECT_EQ(parsed.frame->payload.size(), 2U);
}

TEST(Wire, RejectsLengthBeforePayloadAllocation) {
  const std::vector<std::byte> over_limit{std::byte{0x81U}, std::byte{0x80U},
                                          std::byte{0x80U}, std::byte{0x01U}};
  const auto parsed = heyaki::parse_frame(over_limit);
  EXPECT_EQ(parsed.status, heyaki::FrameParseStatus::invalid);
  ASSERT_TRUE(parsed.error.has_value());
  EXPECT_EQ(parsed.error->safe_detail(), "varint_limit");

  const std::vector<std::byte> oversized_control{std::byte{0x81U}, std::byte{0x80U},
                                                 std::byte{0x04U}, std::byte{0x01U}};
  const auto control = heyaki::parse_frame(oversized_control);
  EXPECT_EQ(control.status, heyaki::FrameParseStatus::invalid);
  ASSERT_TRUE(control.error.has_value());
  EXPECT_EQ(control.error->safe_detail(), "control_frame_limit");
}

TEST(Wire, RejectsNonCanonicalVarintsAndReservedFlags) {
  const std::vector<std::byte> non_canonical{std::byte{0x80U}, std::byte{0x00U}};
  EXPECT_EQ(heyaki::parse_frame(non_canonical).status, heyaki::FrameParseStatus::invalid);

  auto frame = sample_frame();
  frame.flags = 0x80U;
  const auto encoded = heyaki::encode_frame(frame);
  ASSERT_FALSE(encoded);
  EXPECT_EQ(encoded.error_if()->safe_detail(), "reserved_frame_flags");
}

TEST(Wire, EnforcesCorrelationIdAndChannelClass) {
  auto zero_id = sample_frame();
  zero_id.message_id = heyaki::MessageId{};
  EXPECT_FALSE(heyaki::encode_frame(zero_id));

  auto business_on_control = sample_frame();
  business_on_control.channel_id = 0U;
  EXPECT_FALSE(heyaki::encode_frame(business_on_control));

  auto control_on_business = sample_frame();
  control_on_business.type = static_cast<std::uint8_t>(heyaki::FrameType::session_hello);
  EXPECT_FALSE(heyaki::encode_frame(control_on_business));
}

TEST(Wire, DistinguishesTruncatedInputFromInvalidInput) {
  const auto encoded = heyaki::encode_frame(sample_frame());
  ASSERT_TRUE(encoded);
  for (std::size_t size = 0U; size < encoded.value_if()->size(); ++size) {
    EXPECT_EQ(heyaki::parse_frame(
                  std::span<const std::byte>{encoded.value_if()->data(), size})
                  .status,
              heyaki::FrameParseStatus::need_more);
  }
}

TEST(Wire, UnknownRequiredFrameClosesOnlyTheChannel) {
  auto frame = sample_frame();
  frame.type = 0x7fU;
  frame.flags = 0U;
  const auto optional = heyaki::encode_frame(frame);
  ASSERT_TRUE(optional);
  const auto optional_view = heyaki::parse_frame(*optional.value_if());
  ASSERT_TRUE(optional_view.frame.has_value());
  EXPECT_EQ(heyaki::unknown_frame_action(*optional_view.frame), heyaki::UnknownFrameAction::skip);

  frame.flags = heyaki::frame_flag_required;
  const auto required = heyaki::encode_frame(frame);
  ASSERT_TRUE(required);
  const auto required_view = heyaki::parse_frame(*required.value_if());
  ASSERT_TRUE(required_view.frame.has_value());
  EXPECT_EQ(heyaki::unknown_frame_action(*required_view.frame),
            heyaki::UnknownFrameAction::close_channel);
}

TEST(Wire, FileRejectAndShellTerminalFramesAreKnown) {
  for (const auto type : {heyaki::FrameType::file_reject, heyaki::FrameType::shell_eof,
                          heyaki::FrameType::shell_error, heyaki::FrameType::shell_close}) {
    EXPECT_TRUE(heyaki::is_known_frame_type(static_cast<std::uint8_t>(type)));
  }
}

TEST(Wire, FileChunkLimitCountsDataRatherThanRawHeader) {
  constexpr std::size_t file_chunk_header_bytes = 60U;
  const heyaki::Limits limits;
  auto frame = sample_frame();
  frame.type = static_cast<std::uint8_t>(heyaki::FrameType::file_chunk);
  frame.payload.resize(file_chunk_header_bytes + limits.max_file_chunk_bytes);

  const auto boundary = heyaki::encode_frame(frame, limits);
  ASSERT_TRUE(boundary);
  EXPECT_EQ(heyaki::parse_frame(*boundary.value_if(), limits).status,
            heyaki::FrameParseStatus::parsed);

  frame.payload.push_back(std::byte{0});
  const auto oversized = heyaki::encode_frame(frame, limits);
  ASSERT_FALSE(oversized);
  EXPECT_EQ(oversized.error_if()->safe_detail(), "file_chunk_limit");
}

}  // namespace
