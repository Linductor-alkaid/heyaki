#pragma once

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/limits.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace heyaki {

enum class FrameType : std::uint8_t {
  session_hello = 0x01,
  protocol_close = 0x02,
  ping = 0x03,
  pong = 0x04,
  cancel = 0x05,
  pairing_request = 0x10,
  pairing_result = 0x11,
  message = 0x20,
  message_ack = 0x21,
  rpc_request = 0x30,
  rpc_response = 0x31,
  rpc_cancel = 0x32,
  event_subscribe = 0x40,
  event_item = 0x41,
  event_unsubscribe = 0x42,
  stream_open = 0x50,
  stream_data = 0x51,
  stream_window_update = 0x52,
  stream_fin = 0x53,
  stream_reset = 0x54,
  file_manifest = 0x60,
  file_accept = 0x61,
  file_chunk = 0x62,
  file_complete = 0x63,
  shell_open = 0x70,
  shell_input = 0x71,
  shell_output = 0x72,
  shell_resize = 0x73,
  shell_signal = 0x74,
  shell_exit = 0x75,
};

inline constexpr std::uint8_t frame_flag_required = 0x01U;
inline constexpr std::uint8_t frame_known_flags = frame_flag_required;

struct Frame {
  std::uint8_t type{};
  std::uint8_t flags{};
  std::uint32_t channel_id{};
  MessageId message_id;
  std::vector<std::byte> payload;
};

struct FrameView {
  std::uint8_t type{};
  std::uint8_t flags{};
  std::uint32_t channel_id{};
  MessageId message_id;
  std::span<const std::byte> payload;
};

enum class FrameParseStatus : std::uint8_t { parsed, need_more, invalid };
enum class UnknownFrameAction : std::uint8_t { process, skip, close_channel };

struct FrameParseResult {
  FrameParseStatus status{FrameParseStatus::need_more};
  std::size_t consumed{};
  std::optional<FrameView> frame;
  std::optional<Error> error;
};

[[nodiscard]] bool is_known_frame_type(std::uint8_t type) noexcept;
[[nodiscard]] UnknownFrameAction unknown_frame_action(const FrameView& frame) noexcept;
[[nodiscard]] Result<std::vector<std::byte>> encode_frame(const Frame& frame,
                                                         const Limits& limits = {});
[[nodiscard]] FrameParseResult parse_frame(std::span<const std::byte> input,
                                           const Limits& limits = {});

}  // namespace heyaki
