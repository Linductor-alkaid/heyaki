#include <heyaki/wire.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

enum class VarintStatus : std::uint8_t { parsed, need_more, invalid };

struct VarintResult {
  VarintStatus status{VarintStatus::need_more};
  std::uint32_t value{};
  std::size_t bytes{};
  const char* detail{"truncated_varint"};
};

VarintResult decode_varint(std::span<const std::byte> input, std::uint32_t maximum) noexcept {
  std::uint32_t value = 0U;
  constexpr std::size_t max_varint_bytes = 5U;
  const auto available = std::min(input.size(), max_varint_bytes);
  for (std::size_t index = 0U; index < available; ++index) {
    const auto byte = std::to_integer<std::uint8_t>(input[index]);
    if (index == 4U && (byte & 0xf0U) != 0U) {
      return {.status = VarintStatus::invalid, .detail = "varint_overflow"};
    }
    value |= static_cast<std::uint32_t>(byte & 0x7fU) << (7U * index);
    if ((byte & 0x80U) == 0U) {
      if (index > 0U && (byte & 0x7fU) == 0U) {
        return {.status = VarintStatus::invalid, .detail = "non_canonical_varint"};
      }
      if (value > maximum) {
        return {.status = VarintStatus::invalid, .detail = "varint_limit"};
      }
      return {.status = VarintStatus::parsed, .value = value, .bytes = index + 1U};
    }
  }
  if (input.size() >= max_varint_bytes) {
    return {.status = VarintStatus::invalid, .detail = "varint_overflow"};
  }
  return {};
}

void append_varint(std::vector<std::byte>& output, std::uint32_t value) {
  do {
    auto byte = static_cast<std::uint8_t>(value & 0x7fU);
    value >>= 7U;
    if (value != 0U) {
      byte |= 0x80U;
    }
    output.push_back(static_cast<std::byte>(byte));
  } while (value != 0U);
}

std::size_t varint_size(std::uint32_t value) noexcept {
  std::size_t size = 1U;
  while (value >= 0x80U) {
    value >>= 7U;
    ++size;
  }
  return size;
}

Error wire_error(const char* detail) {
  return {ErrorCode::protocol, "wire", detail};
}

FrameParseResult invalid_frame(const char* detail) {
  return {.status = FrameParseStatus::invalid,
          .consumed = 0U,
          .frame = std::nullopt,
          .error = wire_error(detail)};
}

bool is_control_type(std::uint8_t type) noexcept { return type < 0x20U; }

bool requires_control_channel(std::uint8_t type) noexcept {
  return (type >= static_cast<std::uint8_t>(FrameType::session_hello) &&
          type <= static_cast<std::uint8_t>(FrameType::pong)) ||
         type == static_cast<std::uint8_t>(FrameType::pairing_request) ||
         type == static_cast<std::uint8_t>(FrameType::pairing_result);
}

bool requires_business_channel(std::uint8_t type) noexcept {
  return type >= static_cast<std::uint8_t>(FrameType::message) && is_known_frame_type(type);
}

const char* channel_error(std::uint8_t type, std::uint32_t channel_id) noexcept {
  if (requires_control_channel(type) && channel_id != 0U) {
    return "control_channel_required";
  }
  if (requires_business_channel(type) && channel_id == 0U) {
    return "business_channel_required";
  }
  return nullptr;
}

const char* payload_limit_error(std::uint8_t type, std::size_t payload_size,
                                const Limits& limits) noexcept {
  if ((type == static_cast<std::uint8_t>(FrameType::message) ||
       type == static_cast<std::uint8_t>(FrameType::message_ack)) &&
      payload_size > limits.max_message_bytes) {
    return "message_payload_limit";
  }
  if (type >= static_cast<std::uint8_t>(FrameType::rpc_request) &&
      type <= static_cast<std::uint8_t>(FrameType::rpc_cancel) &&
      payload_size > limits.max_rpc_payload_bytes) {
    return "rpc_payload_limit";
  }
  if (type >= static_cast<std::uint8_t>(FrameType::pairing_request) &&
      type <= static_cast<std::uint8_t>(FrameType::pairing_result) &&
      payload_size > limits.max_pairing_payload_bytes) {
    return "pairing_payload_limit";
  }
  constexpr std::size_t file_chunk_header_bytes = 60U;
  if (type == static_cast<std::uint8_t>(FrameType::file_chunk) &&
      payload_size > file_chunk_header_bytes &&
      payload_size - file_chunk_header_bytes > limits.max_file_chunk_bytes) {
    return "file_chunk_limit";
  }
  return nullptr;
}

}  // namespace

bool is_known_frame_type(std::uint8_t type) noexcept {
  switch (static_cast<FrameType>(type)) {
    case FrameType::session_hello:
    case FrameType::protocol_close:
    case FrameType::ping:
    case FrameType::pong:
    case FrameType::cancel:
    case FrameType::pairing_request:
    case FrameType::pairing_result:
    case FrameType::message:
    case FrameType::message_ack:
    case FrameType::rpc_request:
    case FrameType::rpc_response:
    case FrameType::rpc_cancel:
    case FrameType::event_subscribe:
    case FrameType::event_item:
    case FrameType::event_unsubscribe:
    case FrameType::stream_open:
    case FrameType::stream_data:
    case FrameType::stream_window_update:
    case FrameType::stream_fin:
    case FrameType::stream_reset:
    case FrameType::file_manifest:
    case FrameType::file_accept:
    case FrameType::file_chunk:
    case FrameType::file_complete:
    case FrameType::file_reject:
    case FrameType::shell_open:
    case FrameType::shell_input:
    case FrameType::shell_output:
    case FrameType::shell_resize:
    case FrameType::shell_signal:
    case FrameType::shell_exit:
    case FrameType::shell_eof:
    case FrameType::shell_error:
    case FrameType::shell_close:
      return true;
  }
  return false;
}

UnknownFrameAction unknown_frame_action(const FrameView& frame) noexcept {
  if (is_known_frame_type(frame.type)) {
    return UnknownFrameAction::process;
  }
  return (frame.flags & frame_flag_required) == 0U ? UnknownFrameAction::skip
                                                   : UnknownFrameAction::close_channel;
}

Result<std::vector<std::byte>> encode_frame(const Frame& frame, const Limits& limits) {
  const auto valid_limits = validate_limits(limits);
  if (!valid_limits) {
    return Result<std::vector<std::byte>>::failure(*valid_limits.error_if());
  }
  if ((frame.flags & ~frame_known_flags) != 0U) {
    return Result<std::vector<std::byte>>::failure(wire_error("reserved_frame_flags"));
  }
  if (frame.message_id.is_zero()) {
    return Result<std::vector<std::byte>>::failure(wire_error("zero_message_id"));
  }
  if (const auto* detail = channel_error(frame.type, frame.channel_id)) {
    return Result<std::vector<std::byte>>::failure(wire_error(detail));
  }

  constexpr std::size_t fixed_body_size = 1U + 1U + MessageId::size_bytes;
  const std::size_t channel_size = varint_size(frame.channel_id);
  if (frame.payload.size() > limits.max_frame_bytes ||
      fixed_body_size + channel_size > limits.max_frame_bytes - frame.payload.size()) {
    return Result<std::vector<std::byte>>::failure(wire_error("frame_length_limit"));
  }
  if (const auto* detail = payload_limit_error(frame.type, frame.payload.size(), limits)) {
    return Result<std::vector<std::byte>>::failure(wire_error(detail));
  }

  const auto body_size = fixed_body_size + channel_size + frame.payload.size();
  if (body_size > std::numeric_limits<std::uint32_t>::max()) {
    return Result<std::vector<std::byte>>::failure(wire_error("frame_length_overflow"));
  }
  if (is_control_type(frame.type) && body_size > limits.max_control_frame_bytes) {
    return Result<std::vector<std::byte>>::failure(wire_error("control_frame_limit"));
  }

  std::vector<std::byte> output;
  output.reserve(varint_size(static_cast<std::uint32_t>(body_size)) + body_size);
  append_varint(output, static_cast<std::uint32_t>(body_size));
  output.push_back(static_cast<std::byte>(frame.type));
  output.push_back(static_cast<std::byte>(frame.flags));
  append_varint(output, frame.channel_id);
  output.insert(output.end(), frame.message_id.bytes().begin(), frame.message_id.bytes().end());
  output.insert(output.end(), frame.payload.begin(), frame.payload.end());
  return Result<std::vector<std::byte>>::success(std::move(output));
}

FrameParseResult parse_frame(std::span<const std::byte> input, const Limits& limits) {
  const auto valid_limits = validate_limits(limits);
  if (!valid_limits) {
    return {.status = FrameParseStatus::invalid,
            .consumed = 0U,
            .frame = std::nullopt,
            .error = *valid_limits.error_if()};
  }

  const auto length = decode_varint(
      input, static_cast<std::uint32_t>(std::min<std::size_t>(
                 limits.max_frame_bytes, std::numeric_limits<std::uint32_t>::max())));
  if (length.status == VarintStatus::need_more) {
    return {};
  }
  if (length.status == VarintStatus::invalid) {
    return invalid_frame(length.detail);
  }

  constexpr std::size_t minimum_body_size = 1U + 1U + 1U + MessageId::size_bytes;
  if (length.value < minimum_body_size) {
    return invalid_frame("frame_header_truncated");
  }
  if (input.size() > length.bytes &&
      is_control_type(std::to_integer<std::uint8_t>(input[length.bytes])) &&
      length.value > limits.max_control_frame_bytes) {
    return invalid_frame("control_frame_limit");
  }
  const std::size_t total_size = length.bytes + length.value;
  if (input.size() < total_size) {
    return {.status = FrameParseStatus::need_more,
            .consumed = 0U,
            .frame = std::nullopt,
            .error = std::nullopt};
  }

  const auto body = input.subspan(length.bytes, length.value);
  const auto type = std::to_integer<std::uint8_t>(body[0]);
  const auto flags = std::to_integer<std::uint8_t>(body[1]);
  if ((flags & ~frame_known_flags) != 0U) {
    return invalid_frame("reserved_frame_flags");
  }

  const auto channel = decode_varint(body.subspan(2U), std::numeric_limits<std::uint32_t>::max());
  if (channel.status != VarintStatus::parsed) {
    return invalid_frame(channel.status == VarintStatus::invalid ? channel.detail
                                                                 : "channel_varint_truncated");
  }
  const std::size_t message_offset = 2U + channel.bytes;
  if (message_offset + MessageId::size_bytes > body.size()) {
    return invalid_frame("frame_header_truncated");
  }

  MessageId::Storage message_bytes{};
  std::copy_n(body.begin() + static_cast<std::ptrdiff_t>(message_offset),
              MessageId::size_bytes, message_bytes.begin());
  if (MessageId{message_bytes}.is_zero()) {
    return invalid_frame("zero_message_id");
  }
  if (const auto* detail = channel_error(type, channel.value)) {
    return invalid_frame(detail);
  }
  const std::size_t payload_offset = message_offset + MessageId::size_bytes;
  const auto payload = body.subspan(payload_offset);
  if (const auto* detail = payload_limit_error(type, payload.size(), limits)) {
    return invalid_frame(detail);
  }

  return {.status = FrameParseStatus::parsed,
          .consumed = total_size,
          .frame = FrameView{.type = type,
                             .flags = flags,
                             .channel_id = channel.value,
                             .message_id = MessageId{message_bytes},
                             .payload = payload},
          .error = std::nullopt};
}

}  // namespace heyaki
