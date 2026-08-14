#include <heyaki/wire.hpp>

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

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
  EXPECT_EQ(parsed.error->safe_detail, "varint_limit");

  const std::vector<std::byte> oversized_control{std::byte{0x81U}, std::byte{0x80U},
                                                 std::byte{0x04U}, std::byte{0x01U}};
  const auto control = heyaki::parse_frame(oversized_control);
  EXPECT_EQ(control.status, heyaki::FrameParseStatus::invalid);
  ASSERT_TRUE(control.error.has_value());
  EXPECT_EQ(control.error->safe_detail, "control_frame_limit");
}

TEST(Wire, RejectsNonCanonicalVarintsAndReservedFlags) {
  const std::vector<std::byte> non_canonical{std::byte{0x80U}, std::byte{0x00U}};
  EXPECT_EQ(heyaki::parse_frame(non_canonical).status, heyaki::FrameParseStatus::invalid);

  auto frame = sample_frame();
  frame.flags = 0x80U;
  const auto encoded = heyaki::encode_frame(frame);
  ASSERT_FALSE(encoded);
  EXPECT_EQ(encoded.error_if()->safe_detail, "reserved_frame_flags");
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

}  // namespace
