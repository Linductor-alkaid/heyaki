#include <heyaki/frame_stream.hpp>

#include <algorithm>
#include <limits>
#include <utility>

namespace heyaki {
namespace {

Error frame_stream_error(ErrorCode code, const char* detail) {
  return {code, "frame_stream", detail};
}

std::size_t varint_size(std::uint32_t value) noexcept {
  std::size_t size = 1U;
  while (value >= 0x80U) {
    value >>= 7U;
    ++size;
  }
  return size;
}

// Decodes the canonical length varint at the start of `input`, bounded by
// `maximum`. need_more means the varint itself is still incomplete.
struct LengthVarint {
  enum class Status : std::uint8_t { parsed, need_more, invalid };
  Status status{Status::need_more};
  std::uint32_t value{};
  std::size_t bytes{};
  const char* detail{"truncated_varint"};
};

LengthVarint decode_length_varint(std::span<const std::byte> input,
                                  std::uint32_t maximum) noexcept {
  std::uint32_t value = 0U;
  const auto available = std::min(input.size(), max_frame_length_varint_bytes);
  for (std::size_t index = 0U; index < available; ++index) {
    const auto byte = std::to_integer<std::uint8_t>(input[index]);
    if (index == 4U && (byte & 0xf0U) != 0U) {
      return {.status = LengthVarint::Status::invalid, .detail = "varint_overflow"};
    }
    value |= static_cast<std::uint32_t>(byte & 0x7fU) << (7U * index);
    if ((byte & 0x80U) == 0U) {
      if (index > 0U && (byte & 0x7fU) == 0U) {
        return {.status = LengthVarint::Status::invalid,
                .detail = "non_canonical_varint"};
      }
      if (value > maximum) {
        return {.status = LengthVarint::Status::invalid, .detail = "varint_limit"};
      }
      return {.status = LengthVarint::Status::parsed,
              .value = value,
              .bytes = index + 1U};
    }
  }
  if (input.size() >= max_frame_length_varint_bytes) {
    return {.status = LengthVarint::Status::invalid, .detail = "varint_overflow"};
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

constexpr std::size_t minimum_frame_body_bytes = 1U + 1U + 1U + MessageId::size_bytes;

bool is_control_type(std::uint8_t type) noexcept { return type < 0x20U; }

}  // namespace

FrameStreamDecoder::FrameStreamDecoder(Limits limits) : limits_(limits) {
  const auto valid = validate_limits(limits);
  // Limits are validated on every use; a non-default instance keeps its
  // configured values and each operation re-checks them.
  (void)valid;
}

Result<void> FrameStreamDecoder::append(std::span<const std::byte> bytes) {
  if (poisoned_) {
    return Result<void>::failure(frame_stream_error(ErrorCode::protocol, "decoder_poisoned"));
  }
  const auto valid_limits = validate_limits(limits_);
  if (!valid_limits) {
    poisoned_ = true;
    return Result<void>::failure(*valid_limits.error_if());
  }
  if (offset_ > 0U && offset_ == buffer_.size()) {
    buffer_.clear();
    offset_ = 0U;
  } else if (offset_ > 0U) {
    buffer_.erase(buffer_.begin(),
                  buffer_.begin() + static_cast<std::ptrdiff_t>(offset_));
    offset_ = 0U;
  }
  last_view_end_.reset();
  buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
  return Result<void>::success();
}

FrameStreamStep FrameStreamDecoder::next_view() {
  if (poisoned_) {
    return {.status = FrameStreamStatus::invalid,
            .frame = std::nullopt,
            .error = frame_stream_error(ErrorCode::protocol, "decoder_poisoned")};
  }
  const auto valid_limits = validate_limits(limits_);
  if (!valid_limits) {
    poisoned_ = true;
    return {.status = FrameStreamStatus::invalid, .frame = std::nullopt,
            .error = *valid_limits.error_if()};
  }
  const auto pending = std::span<const std::byte>{buffer_}.subspan(offset_);
  const auto maximum = static_cast<std::uint32_t>(std::min<std::size_t>(
      limits_.max_frame_bytes, std::numeric_limits<std::uint32_t>::max()));
  const auto length =
      decode_length_varint(pending, maximum);
  if (length.status == LengthVarint::Status::need_more) {
    return {};
  }
  if (length.status == LengthVarint::Status::invalid) {
    poisoned_ = true;
    return {.status = FrameStreamStatus::invalid, .frame = std::nullopt,
            .error = frame_stream_error(ErrorCode::protocol, length.detail)};
  }
  if (length.value < minimum_frame_body_bytes) {
    poisoned_ = true;
    return {.status = FrameStreamStatus::invalid, .frame = std::nullopt,
            .error = frame_stream_error(ErrorCode::protocol, "frame_header_truncated")};
  }
  if (is_control_type(std::to_integer<std::uint8_t>(pending[length.bytes])) &&
      length.value > limits_.max_control_frame_bytes) {
    poisoned_ = true;
    return {.status = FrameStreamStatus::invalid, .frame = std::nullopt,
            .error = frame_stream_error(ErrorCode::protocol, "control_frame_limit")};
  }
  const std::size_t total = length.bytes + length.value;
  if (pending.size() < total) {
    // Retention is bounded by one maximum frame: a legal incomplete frame
    // never exceeds its declared length plus the varint prefix, so pending
    // bytes beyond the ceiling cannot become a legal frame.
    const auto retention_ceiling =
        max_frame_length_varint_bytes +
        std::min<std::size_t>(limits_.max_frame_bytes,
                              std::numeric_limits<std::uint32_t>::max());
    if (pending.size() > retention_ceiling) {
      poisoned_ = true;
      return {.status = FrameStreamStatus::invalid, .frame = std::nullopt,
              .error = frame_stream_error(ErrorCode::protocol, "frame_length_limit")};
    }
    return {};
  }
  const auto body = pending.subspan(length.bytes, length.value);
  const auto type = std::to_integer<std::uint8_t>(body[0]);
  const auto flags = std::to_integer<std::uint8_t>(body[1]);
  if ((flags & ~frame_known_flags) != 0U) {
    poisoned_ = true;
    return {.status = FrameStreamStatus::invalid, .frame = std::nullopt,
            .error = frame_stream_error(ErrorCode::protocol, "reserved_frame_flags")};
  }
  // Channel varint spans at most five bytes; a body this short cannot hold it.
  const auto channel = decode_length_varint(body.subspan(2U),
                                            std::numeric_limits<std::uint32_t>::max());
  if (channel.status != LengthVarint::Status::parsed) {
    poisoned_ = true;
    return {.status = FrameStreamStatus::invalid, .frame = std::nullopt,
            .error = frame_stream_error(
                ErrorCode::protocol,
                channel.status == LengthVarint::Status::invalid ? channel.detail
                                                                : "channel_varint_truncated")};
  }
  const std::size_t message_offset = 2U + channel.bytes;
  if (message_offset + MessageId::size_bytes > body.size()) {
    poisoned_ = true;
    return {.status = FrameStreamStatus::invalid, .frame = std::nullopt,
            .error = frame_stream_error(ErrorCode::protocol, "frame_header_truncated")};
  }
  MessageId::Storage message_bytes{};
  std::copy_n(body.begin() + static_cast<std::ptrdiff_t>(message_offset),
              MessageId::size_bytes, message_bytes.begin());
  if (MessageId{message_bytes}.is_zero()) {
    poisoned_ = true;
    return {.status = FrameStreamStatus::invalid, .frame = std::nullopt,
            .error = frame_stream_error(ErrorCode::protocol, "zero_message_id")};
  }
  const std::size_t payload_offset = message_offset + MessageId::size_bytes;
  const auto payload = body.subspan(payload_offset);
  // Reuse the frozen one-shot parser's domain checks (channel binding and
  // per-domain payload ceilings) so both paths accept identical bytes.
  FrameView view{.type = type,
                 .flags = flags,
                 .channel_id = channel.value,
                 .message_id = MessageId{message_bytes},
                 .payload = payload};
  const auto action = unknown_frame_action(view);
  if (action == UnknownFrameAction::process) {
    const bool requires_control =
        (type >= static_cast<std::uint8_t>(FrameType::session_hello) &&
         type <= static_cast<std::uint8_t>(FrameType::pong)) ||
        type == static_cast<std::uint8_t>(FrameType::pairing_request) ||
        type == static_cast<std::uint8_t>(FrameType::pairing_result);
    const bool requires_business = type >= static_cast<std::uint8_t>(FrameType::message);
    if (requires_control && channel.value != 0U) {
      poisoned_ = true;
      return {.status = FrameStreamStatus::invalid, .frame = std::nullopt,
              .error = frame_stream_error(ErrorCode::protocol,
                                          "control_channel_required")};
    }
    if (requires_business && channel.value == 0U) {
      poisoned_ = true;
      return {.status = FrameStreamStatus::invalid, .frame = std::nullopt,
              .error = frame_stream_error(ErrorCode::protocol,
                                          "business_channel_required")};
    }
    if (const auto* detail =
            frame_payload_limit_error(type, payload.size(), limits_)) {
      poisoned_ = true;
      return {.status = FrameStreamStatus::invalid, .frame = std::nullopt,
              .error = frame_stream_error(ErrorCode::protocol, detail)};
    }
  }
  last_view_end_ = offset_ + total;
  return {.status = FrameStreamStatus::parsed, .frame = view, .error = std::nullopt};
}

Result<void> FrameStreamDecoder::consume_view() {
  if (!last_view_end_.has_value()) {
    return Result<void>::failure(
        frame_stream_error(ErrorCode::configuration, "no_frame_to_consume"));
  }
  offset_ = *last_view_end_;
  last_view_end_.reset();
  if (offset_ == buffer_.size()) {
    buffer_.clear();
    offset_ = 0U;
  }
  return Result<void>::success();
}

Result<std::optional<Frame>> FrameStreamDecoder::take_frame() {
  auto step = next_view();
  if (step.status == FrameStreamStatus::need_more) {
    return Result<std::optional<Frame>>::success(std::nullopt);
  }
  if (step.status == FrameStreamStatus::invalid) {
    return Result<std::optional<Frame>>::failure(*step.error);
  }
  const auto& view = *step.frame;
  Frame frame{.type = view.type,
              .flags = view.flags,
              .channel_id = view.channel_id,
              .message_id = view.message_id,
              .payload = std::vector<std::byte>{view.payload.begin(),
                                                view.payload.end()}};
  const auto consumed = consume_view();
  if (!consumed) {
    return Result<std::optional<Frame>>::failure(*consumed.error_if());
  }
  return Result<std::optional<Frame>>::success(std::move(frame));
}

std::size_t FrameStreamDecoder::buffered_bytes() const noexcept {
  return buffer_.size() - offset_;
}

bool FrameStreamDecoder::poisoned() const noexcept { return poisoned_; }

const Limits& FrameStreamDecoder::limits() const noexcept { return limits_; }

void FrameStreamDecoder::reset() noexcept {
  buffer_.clear();
  offset_ = 0U;
  last_view_end_.reset();
  poisoned_ = false;
}

FrameStreamEncoder::FrameStreamEncoder(Limits limits) : limits_(limits) {}

Result<std::size_t> FrameStreamEncoder::encode(std::vector<std::byte>& output,
                                               const FrameView& view) {
  auto header = encode_header(output, view.type, view.flags, view.channel_id,
                              view.message_id, view.payload.size());
  if (!header) {
    return Result<std::size_t>::failure(*header.error_if());
  }
  output.insert(output.end(), view.payload.begin(), view.payload.end());
  return Result<std::size_t>::success(*header.value_if() + view.payload.size());
}

Result<std::size_t> FrameStreamEncoder::encode_header(std::vector<std::byte>& output,
                                                      std::uint8_t type,
                                                      std::uint8_t flags,
                                                      std::uint32_t channel_id,
                                                      MessageId message_id,
                                                      std::size_t payload_size) {
  const auto valid_limits = validate_limits(limits_);
  if (!valid_limits) {
    return Result<std::size_t>::failure(*valid_limits.error_if());
  }
  if ((flags & ~frame_known_flags) != 0U) {
    return Result<std::size_t>::failure(
        frame_stream_error(ErrorCode::protocol, "reserved_frame_flags"));
  }
  if (message_id.is_zero()) {
    return Result<std::size_t>::failure(
        frame_stream_error(ErrorCode::protocol, "zero_message_id"));
  }
  const bool requires_control =
      (type >= static_cast<std::uint8_t>(FrameType::session_hello) &&
       type <= static_cast<std::uint8_t>(FrameType::pong)) ||
      type == static_cast<std::uint8_t>(FrameType::pairing_request) ||
      type == static_cast<std::uint8_t>(FrameType::pairing_result);
  const bool requires_business =
      type >= static_cast<std::uint8_t>(FrameType::message) && is_known_frame_type(type);
  if (requires_control && channel_id != 0U) {
    return Result<std::size_t>::failure(
        frame_stream_error(ErrorCode::protocol, "control_channel_required"));
  }
  if (requires_business && channel_id == 0U) {
    return Result<std::size_t>::failure(
        frame_stream_error(ErrorCode::protocol, "business_channel_required"));
  }
  const auto size = encoded_size(type, flags, channel_id, payload_size);
  if (!size) {
    return Result<std::size_t>::failure(*size.error_if());
  }
  if (is_control_type(type) &&
      *size.value_if() > limits_.max_control_frame_bytes) {
    return Result<std::size_t>::failure(
        frame_stream_error(ErrorCode::protocol, "control_frame_limit"));
  }
  constexpr std::size_t fixed_body_size = 1U + 1U + MessageId::size_bytes;
  const std::size_t body_size = fixed_body_size + varint_size(channel_id) + payload_size;
  append_varint(output, static_cast<std::uint32_t>(body_size));
  const auto payload_offset = output.size();
  output.push_back(static_cast<std::byte>(type));
  output.push_back(static_cast<std::byte>(flags));
  append_varint(output, channel_id);
  output.insert(output.end(), message_id.bytes().begin(), message_id.bytes().end());
  return Result<std::size_t>::success(payload_offset);
}

Result<std::size_t> FrameStreamEncoder::encoded_size(std::uint8_t type,
                                                     std::uint8_t flags,
                                                     std::uint32_t channel_id,
                                                     std::size_t payload_size) const {
  (void)type;
  (void)flags;
  constexpr std::size_t fixed_body_size = 1U + 1U + MessageId::size_bytes;
  const std::size_t body_size = fixed_body_size + varint_size(channel_id) + payload_size;
  if (payload_size > limits_.max_frame_bytes ||
      body_size > limits_.max_frame_bytes ||
      body_size > std::numeric_limits<std::uint32_t>::max()) {
    return Result<std::size_t>::failure(
        frame_stream_error(ErrorCode::protocol, "frame_length_limit"));
  }
  const auto body32 = static_cast<std::uint32_t>(body_size);
  return Result<std::size_t>::success(varint_size(body32) + body_size);
}

const Limits& FrameStreamEncoder::limits() const noexcept { return limits_; }

}  // namespace heyaki
