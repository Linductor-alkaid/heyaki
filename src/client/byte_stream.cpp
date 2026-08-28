#include "byte_stream.hpp"

#include "../core/proto_codec.hpp"

#include <heyaki/pairing_protocol.hpp>

#include <sodium/randombytes.h>

#include <algorithm>
#include <cstring>
#include <iterator>
#include <limits>
#include <utility>

namespace heyaki {
namespace {

Error stream_error(ErrorCode code, const char* detail) {
  return {code, "byte_stream", detail};
}

StreamId random_stream_id() {
  StreamId id{};
  do {
    randombytes_buf(id.data(), id.size());
  } while (std::all_of(id.begin(), id.end(), [](std::byte byte) {
    return byte == std::byte{0};
  }));
  return id;
}

void append_u64(std::vector<std::byte>& out, std::uint64_t value) {
  for (std::size_t index = 0U; index < 8U; ++index) {
    out.push_back(static_cast<std::byte>(value >> (56U - index * 8U)));
  }
}

void append_u32(std::vector<std::byte>& out, std::uint32_t value) {
  for (std::size_t index = 0U; index < 4U; ++index) {
    out.push_back(static_cast<std::byte>(value >> (24U - index * 8U)));
  }
}

std::uint64_t read_u64(std::span<const std::byte> in, std::size_t offset) {
  std::uint64_t value = 0U;
  for (std::size_t index = 0U; index < 8U; ++index) {
    value = (value << 8U) |
            static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(in[offset + index]));
  }
  return value;
}

std::uint32_t read_u32(std::span<const std::byte> in, std::size_t offset) {
  std::uint32_t value = 0U;
  for (std::size_t index = 0U; index < 4U; ++index) {
    value = (value << 8U) |
            static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[offset + index]));
  }
  return value;
}

Result<StreamId> parse_stream_id(std::span<const std::byte> payload) {
  if (payload.size() < 16U) {
    return Result<StreamId>::failure(stream_error(ErrorCode::protocol, "stream_id_truncated"));
  }
  StreamId id{};
  std::copy_n(payload.begin(), 16U, id.begin());
  if (std::all_of(id.begin(), id.end(), [](std::byte byte) { return byte == std::byte{0}; })) {
    return Result<StreamId>::failure(stream_error(ErrorCode::protocol, "stream_id_zero"));
  }
  return Result<StreamId>::success(id);
}

// Protobuf payloads (OPEN/WINDOW_UPDATE/FIN/RESET) carry the stream id as
// field 1 (tag 0x0A, length 16); only the RAW STREAM_DATA layout puts the id
// at offset zero.
Result<StreamId> parse_pb_stream_id(std::span<const std::byte> payload) {
  if (payload.size() < 18U) {
    return Result<StreamId>::failure(
        stream_error(ErrorCode::protocol, "stream_id_field_truncated"));
  }
  if (std::to_integer<std::uint8_t>(payload[0]) != 0x0AU ||
      std::to_integer<std::uint8_t>(payload[1]) != 16U) {
    return Result<StreamId>::failure(
        stream_error(ErrorCode::protocol, "stream_id_field_invalid"));
  }
  StreamId id{};
  std::copy_n(payload.begin() + 2, 16U, id.begin());
  if (std::all_of(id.begin(), id.end(), [](std::byte byte) { return byte == std::byte{0}; })) {
    return Result<StreamId>::failure(stream_error(ErrorCode::protocol, "stream_id_zero"));
  }
  return Result<StreamId>::success(id);
}

constexpr std::size_t stream_channel_frame_capacity = 1024U;
constexpr std::size_t stream_channel_byte_capacity = 8U * 1024U * 1024U;

}  // namespace

std::string_view stream_state_name(StreamState state) noexcept {
  switch (state) {
    case StreamState::opening:
      return "opening";
    case StreamState::open:
      return "open";
    case StreamState::half_closed_local:
      return "half_closed_local";
    case StreamState::half_closed_remote:
      return "half_closed_remote";
    case StreamState::closed:
      return "closed";
    case StreamState::reset:
      return "reset";
  }
  return "unknown";
}

Result<void> validate_byte_stream_limits(const ByteStreamLimits& limits) {
  if (limits.max_data_chunk_bytes == 0U ||
      limits.max_data_chunk_bytes > 1024U * 1024U) {
    return Result<void>::failure(
        stream_error(ErrorCode::configuration, "data_chunk_limit_invalid"));
  }
  if (limits.default_receive_window_bytes == 0U ||
      limits.default_receive_window_bytes > 64U * 1024U * 1024U) {
    return Result<void>::failure(
        stream_error(ErrorCode::configuration, "receive_window_limit_invalid"));
  }
  if (limits.default_receive_window_frames == 0U) {
    return Result<void>::failure(
        stream_error(ErrorCode::configuration, "receive_window_frames_invalid"));
  }
  if (limits.max_concurrent_streams == 0U) {
    return Result<void>::failure(
        stream_error(ErrorCode::configuration, "concurrent_stream_limit_invalid"));
  }
  if (limits.pending_write_bytes == 0U || limits.max_pending_reads == 0U ||
      limits.max_pending_writes == 0U) {
    return Result<void>::failure(
        stream_error(ErrorCode::configuration, "pending_limit_invalid"));
  }
  return Result<void>::success();
}

ByteStreamHandle::ByteStreamHandle(ByteStreamService& service, StreamId id,
                                   std::uint32_t channel_id,
                                   std::uint64_t receive_window_bytes,
                                   std::uint32_t receive_window_frames)
    : service_(&service),
      id_(id),
      channel_id_(channel_id),
      max_pending_reads_(service.limits().max_pending_reads),
      max_pending_writes_(service.limits().max_pending_writes),
      max_pending_write_bytes_(service.limits().pending_write_bytes),
      receive_window_bytes_(receive_window_bytes),
      receive_window_frames_(receive_window_frames),
      receive_window_remaining_bytes_(receive_window_bytes),
      receive_window_remaining_frames_(receive_window_frames) {}

ByteStreamHandle::~ByteStreamHandle() = default;

StreamState ByteStreamHandle::state() const noexcept { return state_; }

const StreamId& ByteStreamHandle::stream_id() const noexcept { return id_; }

std::uint32_t ByteStreamHandle::channel_id() const noexcept { return channel_id_; }

std::size_t ByteStreamHandle::pending_writes() const noexcept { return writes_.size(); }

std::size_t ByteStreamHandle::pending_reads() const noexcept { return reads_.size(); }

StreamWindowSnapshot ByteStreamHandle::window() const noexcept {
  StreamWindowSnapshot snapshot;
  snapshot.next_send_offset = next_send_offset_;
  snapshot.send_credit_bytes = send_credit_bytes_;
  snapshot.send_credit_frames = send_credit_frames_;
  snapshot.next_receive_offset = next_receive_offset_;
  snapshot.receive_window_bytes = receive_window_bytes_;
  snapshot.receive_window_frames = receive_window_frames_;
  snapshot.receive_buffered_bytes = receive_buffered_bytes_;
  snapshot.receive_buffered_frames = static_cast<std::uint32_t>(receive_chunks_.size());
  snapshot.consumed_through_offset = consumed_through_offset_;
  return snapshot;
}

void ByteStreamHandle::async_read_some(std::span<std::byte> out, ReadHandler handler,
                                       std::optional<std::uint64_t> deadline) {
  if (out.empty()) {
    handler(StreamIoResult{0U, stream_error(ErrorCode::configuration, "read_buffer_empty")});
    return;
  }
  if (state_ == StreamState::reset) {
    handler(StreamIoResult{0U, stream_error(ErrorCode::cancelled, "stream_reset")});
    return;
  }
  if (reads_.size() >= max_pending_reads_) {
    handler(StreamIoResult{0U, stream_error(ErrorCode::resource_exhausted, "read_limit")});
    return;
  }
  reads_.push_back(std::make_shared<PendingRead>(
      PendingRead{out, std::move(handler), deadline}));
  try_dispatch_reads();
}

void ByteStreamHandle::async_write(std::span<const std::byte> data, WriteHandler handler,
                                   std::optional<std::uint64_t> deadline) {
  if (state_ == StreamState::reset || state_ == StreamState::closed) {
    handler(StreamIoResult{0U, stream_error(ErrorCode::cancelled, "stream_not_writable")});
    return;
  }
  if (fin_sent_ || state_ == StreamState::half_closed_local) {
    handler(StreamIoResult{0U, stream_error(ErrorCode::protocol, "write_after_fin")});
    return;
  }
  if (data.empty()) {
    handler(StreamIoResult{0U, std::nullopt});
    return;
  }
  std::size_t pending_bytes = 0U;
  for (const auto& write : writes_) pending_bytes += write->data.size() - write->offset;
  if (pending_bytes + data.size() > max_pending_write_bytes_) {
    handler(StreamIoResult{0U, stream_error(ErrorCode::would_block, "write_backlog_full")});
    return;
  }
  if (writes_.size() >= max_pending_writes_) {
    handler(StreamIoResult{0U, stream_error(ErrorCode::resource_exhausted, "write_limit")});
    return;
  }
  writes_.push_back(std::make_shared<PendingWrite>(PendingWrite{
      std::vector<std::byte>{data.begin(), data.end()}, 0U, std::move(handler), deadline,
      false}));
  service_->pump_writes(*this);
  service_->check_deadlines();
}

Result<void> ByteStreamHandle::shutdown_write() {
  if (fin_sent_ || state_ == StreamState::reset || state_ == StreamState::closed) {
    return Result<void>::failure(stream_error(ErrorCode::protocol, "fin_not_sendable"));
  }
  if (!writes_.empty()) {
    // FIN follows the last queued write once it fully entered the window.
    writes_.back()->fin_after = true;
    fin_sent_ = true;
    return Result<void>::success();
  }
  fin_sent_ = true;
  std::vector<std::byte> payload;
  proto_codec::append_bytes(payload, 1U,
                            std::span<const std::byte>{id_.data(), id_.size()});
  proto_codec::append_uint(payload, 2U, next_send_offset_);
  auto sent = service_->send_stream_frame(
      channel_id_, static_cast<std::uint8_t>(FrameType::stream_fin), std::move(payload),
      session::FrameClass::control);
  if (!sent) {
    return sent;
  }
  service_->finish_stream(
      *this, fin_received_ ? StreamState::closed : StreamState::half_closed_local);
  return Result<void>::success();
}

void ByteStreamHandle::reset(StableStatus reason) {
  if (state_ == StreamState::reset || state_ == StreamState::closed) return;
  service_->handle_reset_frame_for(*this, reason);
}

void ByteStreamHandle::complete_read(StreamIoResult result) {
  if (reads_.empty()) return;
  auto read = std::move(reads_.front());
  reads_.erase(reads_.begin());
  if (read->handler) read->handler(std::move(result));
}

void ByteStreamHandle::complete_write(PendingWrite& write, StreamIoResult result) {
  if (write.handler) {
    auto handler = std::move(write.handler);
    write.handler = nullptr;
    handler(std::move(result));
  }
}

void ByteStreamHandle::try_dispatch_reads() {
  while (!reads_.empty()) {
    auto& read = *reads_.front();
    if (receive_chunks_.empty()) {
      if (fin_received_ && next_receive_offset_ == final_receive_offset_) {
        // Clean EOF: zero bytes, no error.
        complete_read(StreamIoResult{0U, std::nullopt});
        if (fin_sent_ && receive_chunks_.empty()) {
          service_->finish_stream(*this, StreamState::closed);
        }
        continue;
      }
      return;
    }
    auto& chunk = receive_chunks_.front();
    const auto count = std::min(read.out.size(), chunk.size());
    std::copy_n(chunk.begin(), static_cast<std::ptrdiff_t>(count), read.out.begin());
    consumed_through_offset_ += count;
    receive_buffered_bytes_ -= count;
    if (count == chunk.size()) {
      receive_chunks_.pop_front();
      receive_window_remaining_frames_ =
          std::min<std::uint32_t>(receive_window_remaining_frames_ + 1U,
                                  receive_window_frames_);
    } else {
      chunk.erase(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(count));
    }
    complete_read(StreamIoResult{count, std::nullopt});
    maybe_send_window_update();
  }
}

void ByteStreamHandle::maybe_send_window_update() {
  const auto consumed_bytes = consumed_through_offset_ - update_reported_consumed_bytes_;
  const auto consumed_frames = receive_window_remaining_frames_ -
                               update_reported_consumed_frames_;
  const bool window_drained = receive_window_remaining_bytes_ == 0U;
  const bool enough_credit = consumed_bytes >= receive_window_bytes_ / 4U;
  if (!window_drained && !enough_credit) return;
  std::vector<std::byte> payload;
  proto_codec::append_bytes(payload, 1U,
                            std::span<const std::byte>{id_.data(), id_.size()});
  proto_codec::append_uint(payload, 2U, consumed_through_offset_);
  proto_codec::append_uint(payload, 3U, consumed_bytes);
  proto_codec::append_uint(payload, 4U, consumed_frames);
  auto sent = service_->send_stream_frame(
      channel_id_, static_cast<std::uint8_t>(FrameType::stream_window_update),
      std::move(payload), session::FrameClass::control);
  if (!sent) return;
  update_reported_consumed_bytes_ = consumed_through_offset_;
  update_reported_consumed_frames_ = receive_window_remaining_frames_;
  receive_window_remaining_bytes_ =
      std::min<std::uint64_t>(receive_window_remaining_bytes_ + consumed_bytes,
                              receive_window_bytes_);
}

ByteStreamService::ByteStreamService(PeerSession& session, ByteStreamLimits limits,
                                     std::function<std::uint64_t()> wall_clock)
    : session_(session), limits_(limits), wall_clock_(std::move(wall_clock)) {}

ByteStreamService::~ByteStreamService() {
  fail_all(stream_error(ErrorCode::cancelled, "service_closed"));
  session_.set_domain_handler(session::ChannelDomain::stream, DomainFrameHandler{});
  for (auto channel : owned_channels_) {
    session_.close_business_channel(channel);
  }
}

const ByteStreamLimits& ByteStreamService::limits() const noexcept { return limits_; }

std::uint64_t ByteStreamService::now() const {
  if (wall_clock_) return wall_clock_();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

Result<void> ByteStreamService::attach() {
  auto valid = validate_byte_stream_limits(limits_);
  if (!valid) return valid;
  auto weak_service = std::make_shared<ByteStreamService*>(this);
  auto opened = session_.open_business_channel(
      session::ChannelDomain::stream, session::QueueFullPolicy::reject,
      stream_channel_frame_capacity, stream_channel_byte_capacity,
      [weak_service](const FrameView& frame) {
        if (*weak_service != nullptr) (*weak_service)->handle_frame(frame);
      });
  if (!opened) return Result<void>::failure(*opened.error_if());
  channel_id_ = *opened.value_if();
  owned_channels_.push_back(*channel_id_);
  session_.set_domain_handler(
      session::ChannelDomain::stream,
      [weak_service](const FrameView& frame) -> Result<void> {
        if (*weak_service == nullptr) {
          return Result<void>::failure(
              stream_error(ErrorCode::cancelled, "service_detached"));
        }
        return (*weak_service)->admit_frame(frame);
      });
  attached_ = true;
  return Result<void>::success();
}

Result<std::shared_ptr<ByteStreamHandle>> ByteStreamService::open_stream(
    std::uint64_t receive_window_bytes, std::uint32_t receive_window_frames) {
  if (!attached_) {
    return Result<std::shared_ptr<ByteStreamHandle>>::failure(
        stream_error(ErrorCode::configuration, "service_not_attached"));
  }
  if (receive_window_bytes == 0U || receive_window_frames == 0U) {
    return Result<std::shared_ptr<ByteStreamHandle>>::failure(
        stream_error(ErrorCode::configuration, "receive_window_invalid"));
  }
  if (streams_.size() >= limits_.max_concurrent_streams) {
    return Result<std::shared_ptr<ByteStreamHandle>>::failure(
        stream_error(ErrorCode::resource_exhausted, "stream_limit"));
  }
  auto stream = std::make_shared<ByteStreamHandle>(*this, random_stream_id(),
                                                   *channel_id_, receive_window_bytes,
                                                   receive_window_frames);
  auto sent = send_stream_open(*stream);
  if (!sent) {
    return Result<std::shared_ptr<ByteStreamHandle>>::failure(*sent.error_if());
  }
  stream->state_ = StreamState::open;
  streams_.emplace(stream->stream_id(), stream);
  return Result<std::shared_ptr<ByteStreamHandle>>::success(std::move(stream));
}

void ByteStreamService::set_inbound_handler(InboundHandler handler) {
  inbound_handler_ = std::move(handler);
}

std::size_t ByteStreamService::active_streams() const noexcept { return streams_.size(); }

std::vector<StreamId> ByteStreamService::stream_ids() const {
  std::vector<StreamId> ids;
  ids.reserve(streams_.size());
  for (const auto& [id, stream] : streams_) ids.push_back(id);
  return ids;
}

std::shared_ptr<ByteStreamHandle> ByteStreamService::stream(const StreamId& id) const {
  auto found = streams_.find(id);
  if (found == streams_.end()) return nullptr;
  return found->second;
}

void ByteStreamService::fail_all(const Error& error) {
  for (auto& [id, stream] : streams_) {
    for (auto& read : stream->reads_) {
      if (read->handler) {
        auto handler = std::move(read->handler);
        read->handler = nullptr;
        handler(StreamIoResult{0U, error});
      }
    }
    stream->reads_.clear();
    for (auto& write : stream->writes_) {
      stream->complete_write(*write, StreamIoResult{write->offset, error});
    }
    stream->writes_.clear();
    stream->state_ = StreamState::reset;
  }
  streams_.clear();
}

void ByteStreamService::check_deadlines() {
  const auto now_value = now();
  for (auto& [id, stream] : streams_) {
    for (auto it = stream->reads_.begin(); it != stream->reads_.end();) {
      if ((*it)->deadline.has_value() && now_value > *(*it)->deadline) {
        auto read = *it;
        it = stream->reads_.erase(it);
        if (read->handler) {
          auto handler = std::move(read->handler);
          read->handler = nullptr;
          handler(StreamIoResult{0U, stream_error(ErrorCode::timeout, "read_deadline")});
        }
        continue;
      }
      ++it;
    }
    for (auto it = stream->writes_.begin(); it != stream->writes_.end();) {
      if ((*it)->deadline.has_value() && now_value > *(*it)->deadline) {
        auto write = *it;
        it = stream->writes_.erase(it);
        stream->complete_write(
            *write, StreamIoResult{write->offset,
                                   stream_error(ErrorCode::timeout, "write_deadline")});
        continue;
      }
      ++it;
    }
  }
}

Result<void> ByteStreamService::send_stream_frame(std::uint32_t channel_id,
                                                  std::uint8_t type,
                                                  std::vector<std::byte> payload,
                                                  session::FrameClass klass) {
  Frame frame{.type = type, .channel_id = channel_id, .payload = std::move(payload)};
  return session_.send_frame(channel_id, klass, std::move(frame));
}

Result<void> ByteStreamService::send_stream_open(ByteStreamHandle& stream) {
  std::vector<std::byte> payload;
  proto_codec::append_bytes(payload, 1U,
                            std::span<const std::byte>{stream.id_.data(), stream.id_.size()});
  proto_codec::append_uint(payload, 2U, stream.receive_window_bytes_);
  proto_codec::append_uint(payload, 3U, stream.receive_window_frames_);
  return send_stream_frame(stream.channel_id_,
                           static_cast<std::uint8_t>(FrameType::stream_open),
                           std::move(payload), session::FrameClass::standard);
}

void ByteStreamService::handle_frame(const FrameView& frame) { (void)admit_frame(frame); }

Result<void> ByteStreamService::admit_frame(const FrameView& frame) {
  check_deadlines();
  switch (static_cast<FrameType>(frame.type)) {
    case FrameType::stream_open:
      handle_open(frame, frame.channel_id);
      return Result<void>::success();
    case FrameType::stream_data:
      handle_data(frame);
      return Result<void>::success();
    case FrameType::stream_window_update:
      handle_window_update(frame);
      return Result<void>::success();
    case FrameType::stream_fin:
      handle_fin(frame);
      return Result<void>::success();
    case FrameType::stream_reset:
      handle_reset(frame);
      return Result<void>::success();
    default:
      return Result<void>::failure(
          stream_error(ErrorCode::protocol, "frame_not_stream_domain"));
  }
}

void ByteStreamService::handle_open(const FrameView& frame, std::uint32_t channel_id) {
  auto id = parse_pb_stream_id(frame.payload);
  if (!id) return;
  if (streams_.contains(*id.value_if())) {
    auto existing = streams_.at(*id.value_if());
    if (existing->state_ != StreamState::reset) {
      handle_reset_frame_for(*existing, StableStatus::already_exists);
    }
    return;
  }
  proto_codec::ProtoReader reader(frame.payload);
  std::optional<std::uint64_t> window_bytes;
  std::optional<std::uint64_t> window_frames;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) return;
    if (field.value_if()->number == 2U && field.value_if()->wire_type == 0U) {
      window_bytes = field.value_if()->integer;
    } else if (field.value_if()->number == 3U && field.value_if()->wire_type == 0U) {
      window_frames = field.value_if()->integer;
    }
  }
  if (!window_bytes.has_value() || !window_frames.has_value() || *window_bytes == 0U ||
      *window_frames == 0U || *window_frames > std::numeric_limits<std::uint32_t>::max() ||
      *window_bytes > 64U * 1024U * 1024U) {
    return;
  }
  auto refuse = [&](StableStatus status) {
    std::vector<std::byte> payload;
    proto_codec::append_bytes(payload, 1U,
                              std::span<const std::byte>{id.value_if()->data(),
                                                         id.value_if()->size()});
    proto_codec::append_uint(payload, 2U, static_cast<std::uint64_t>(status));
    (void)send_stream_frame(channel_id,
                            static_cast<std::uint8_t>(FrameType::stream_reset),
                            std::move(payload), session::FrameClass::control);
  };
  if (streams_.size() >= limits_.max_concurrent_streams) {
    refuse(StableStatus::resource_exhausted);
    return;
  }
  if (!session_.has_business_channel(channel_id)) {
    auto weak_service = std::make_shared<ByteStreamService*>(this);
    auto adopted = session_.adopt_business_channel(
        channel_id, session::ChannelDomain::stream, session::QueueFullPolicy::reject,
        stream_channel_frame_capacity, stream_channel_byte_capacity,
        [weak_service](const FrameView& inbound) {
          if (*weak_service != nullptr) (*weak_service)->handle_frame(inbound);
        });
    if (!adopted) {
      return;
    }
    owned_channels_.push_back(channel_id);
  }
  auto stream = std::make_shared<ByteStreamHandle>(
      *this, *id.value_if(), channel_id, limits_.default_receive_window_bytes,
      limits_.default_receive_window_frames);
  stream->state_ = StreamState::open;
  // The peer's open grants our send credit for this stream (M5-16).
  stream->send_credit_bytes_ = *window_bytes;
  stream->send_credit_frames_ = static_cast<std::uint32_t>(*window_frames);
  streams_.emplace(stream->stream_id(), stream);
  // Grant the opener its initial send credit: our receive window for this
  // stream. The OPEN only carried the opener's own receive window, so
  // without this grant the opener could never send DATA (M5-16).
  {
    std::vector<std::byte> credit;
    proto_codec::append_bytes(credit, 1U,
                              std::span<const std::byte>{stream->id_.data(),
                                                         stream->id_.size()});
    proto_codec::append_uint(credit, 2U, 0U);
    proto_codec::append_uint(credit, 3U, stream->receive_window_bytes_);
    proto_codec::append_uint(credit, 4U, stream->receive_window_frames_);
    (void)send_stream_frame(
        channel_id, static_cast<std::uint8_t>(FrameType::stream_window_update),
        std::move(credit), session::FrameClass::control);
  }
  if (inbound_handler_) {
    inbound_handler_(stream);
    return;
  }
  // No consumer for inbound streams: refuse explicitly instead of dropping.
  stream->state_ = StreamState::reset;
  streams_.erase(stream->stream_id());
  refuse(StableStatus::permission_denied);
}

void ByteStreamService::handle_data(const FrameView& frame) {
  if (frame.payload.size() < stream_data_header_bytes) return;
  StreamId id{};
  std::copy_n(frame.payload.begin(), 16U, id.begin());
  auto found = streams_.find(id);
  if (found == streams_.end()) return;
  auto& stream = *found->second;
  if (stream.state_ == StreamState::reset || stream.state_ == StreamState::closed) return;
  const auto offset = read_u64(frame.payload, 16U);
  const auto length = read_u32(frame.payload, 24U);
  if (static_cast<std::uint64_t>(stream_data_header_bytes) + length !=
      frame.payload.size()) {
    handle_reset_frame_for(stream, StableStatus::protocol_error);
    return;
  }
  const auto data = frame.payload.subspan(stream_data_header_bytes);
  if (offset < stream.next_receive_offset_) {
    // Exact already-consumed bytes are duplicates: idempotent, no charge.
    return;
  }
  if (offset > stream.next_receive_offset_) {
    handle_reset_frame_for(stream, StableStatus::protocol_error);
    return;
  }
  if (data.size() > stream.receive_window_remaining_bytes_ ||
      stream.receive_window_remaining_frames_ == 0U) {
    // Dual-window violation (M5-16): the receiver's bound was exceeded.
    handle_reset_frame_for(stream, StableStatus::resource_exhausted);
    return;
  }
  stream.receive_window_remaining_bytes_ -= data.size();
  stream.receive_window_remaining_frames_ -= 1U;
  stream.next_receive_offset_ += data.size();
  stream.receive_buffered_bytes_ += data.size();
  stream.receive_chunks_.emplace_back(data.begin(), data.end());
  stream.try_dispatch_reads();
  if (stream.fin_received_ && stream.next_receive_offset_ == stream.final_receive_offset_ &&
      stream.receive_chunks_.empty()) {
    finish_stream(stream, stream.fin_sent_ ? StreamState::closed
                                           : StreamState::half_closed_remote);
  }
}

void ByteStreamService::handle_window_update(const FrameView& frame) {
  auto id = parse_pb_stream_id(frame.payload);
  if (!id) return;
  auto found = streams_.find(*id.value_if());
  if (found == streams_.end()) return;
  auto& stream = *found->second;
  proto_codec::ProtoReader reader(frame.payload);
  std::optional<std::uint64_t> consumed;
  std::optional<std::uint64_t> additional_bytes;
  std::optional<std::uint64_t> additional_frames;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) return;
    switch (field.value_if()->number) {
      case 2U:
        consumed = field.value_if()->integer;
        break;
      case 3U:
        additional_bytes = field.value_if()->integer;
        break;
      case 4U:
        additional_frames = field.value_if()->integer;
        break;
      default:
        break;
    }
  }
  if (!consumed.has_value() || !additional_bytes.has_value() ||
      !additional_frames.has_value()) {
    return;
  }
  // Stale (regressing) updates are ignored; credit never decreases
  // (wire 6.3). A consumed offset beyond what we ever sent is protocol.
  if (*consumed < stream.send_consumed_by_peer_) return;
  if (*consumed > stream.next_send_offset_) {
    handle_reset_frame_for(stream, StableStatus::protocol_error);
    return;
  }
  stream.send_consumed_by_peer_ = *consumed;
  if (*additional_bytes > std::numeric_limits<std::uint64_t>::max() -
                              stream.send_credit_bytes_) {
    handle_reset_frame_for(stream, StableStatus::resource_exhausted);
    return;
  }
  stream.send_credit_bytes_ += *additional_bytes;
  stream.send_credit_frames_ = static_cast<std::uint32_t>(
      std::min<std::uint64_t>(*additional_frames + stream.send_credit_frames_,
                             std::numeric_limits<std::uint32_t>::max()));
  pump_writes(stream);
}

void ByteStreamService::handle_fin(const FrameView& frame) {
  auto id = parse_pb_stream_id(frame.payload);
  if (!id) return;
  auto found = streams_.find(*id.value_if());
  if (found == streams_.end()) return;
  auto& stream = *found->second;
  if (stream.state_ == StreamState::reset || stream.state_ == StreamState::closed) return;
  proto_codec::ProtoReader reader(frame.payload);
  std::optional<std::uint64_t> final_offset;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) return;
    if (field.value_if()->number == 2U) final_offset = field.value_if()->integer;
  }
  if (!final_offset.has_value()) return;
  stream.fin_received_ = true;
  stream.final_receive_offset_ = *final_offset;
  if (*final_offset != stream.next_receive_offset_) {
    handle_reset_frame_for(stream, StableStatus::protocol_error);
    return;
  }
  stream.try_dispatch_reads();
  if (stream.receive_chunks_.empty()) {
    finish_stream(stream,
                  stream.fin_sent_ ? StreamState::closed : StreamState::half_closed_remote);
  }
}

void ByteStreamService::handle_reset(const FrameView& frame) {
  auto id = parse_pb_stream_id(frame.payload);
  if (!id) return;
  auto found = streams_.find(*id.value_if());
  if (found == streams_.end()) return;
  auto& stream = *found->second;
  if (stream.state_ == StreamState::reset) return;
  // An exact repeated RESET is idempotent (wire 6.3).
  finish_stream(stream, StreamState::reset);
}

void ByteStreamService::handle_reset_frame_for(ByteStreamHandle& stream,
                                               StableStatus reason) {
  if (stream.state_ != StreamState::reset) {
    std::vector<std::byte> payload;
    proto_codec::append_bytes(payload, 1U,
                              std::span<const std::byte>{stream.id_.data(),
                                                         stream.id_.size()});
    proto_codec::append_uint(payload, 2U, static_cast<std::uint64_t>(reason));
    (void)send_stream_frame(stream.channel_id_,
                            static_cast<std::uint8_t>(FrameType::stream_reset),
                            std::move(payload), session::FrameClass::control);
  }
  finish_stream(stream, StreamState::reset);
}

void ByteStreamService::finish_stream(ByteStreamHandle& stream, StreamState terminal) {
  stream.state_ = terminal;
  const bool clean_end =
      terminal == StreamState::closed || terminal == StreamState::half_closed_remote;
  for (auto& read : stream.reads_) {
    if (read->handler) {
      auto handler = std::move(read->handler);
      read->handler = nullptr;
      handler(StreamIoResult{
          0U, clean_end ? std::optional<Error>{} : std::optional<Error>{stream_error(
                                                       ErrorCode::cancelled,
                                                       "stream_reset")}});
    }
  }
  stream.reads_.clear();
  for (auto& write : stream.writes_) {
    stream.complete_write(
        *write, StreamIoResult{write->offset,
                               stream_error(ErrorCode::cancelled, "stream_reset")});
  }
  stream.writes_.clear();
  if (terminal == StreamState::reset || terminal == StreamState::closed) {
    streams_.erase(stream.id_);
  }
}

void ByteStreamService::pump_writes(ByteStreamHandle& stream) {
  if (stream.state_ == StreamState::reset || stream.state_ == StreamState::closed) return;
  while (!stream.writes_.empty()) {
    auto write = stream.writes_.front();
    while (write->offset < write->data.size()) {
      if (stream.send_credit_bytes_ == 0U || stream.send_credit_frames_ == 0U) {
        // M5-16: window exhausted — stop producing DATA; the peer's next
        // WINDOW_UPDATE resumes this pump. Never lean on transport buffering.
        return;
      }
      const auto chunk = std::min<std::size_t>(
          {limits_.max_data_chunk_bytes, write->data.size() - write->offset,
           static_cast<std::size_t>(
               std::min<std::uint64_t>(stream.send_credit_bytes_,
                                       std::numeric_limits<std::size_t>::max()))});
      std::vector<std::byte> payload;
      payload.reserve(stream_data_header_bytes + chunk);
      payload.insert(payload.end(), stream.id_.begin(), stream.id_.end());
      append_u64(payload, stream.next_send_offset_);
      append_u32(payload, static_cast<std::uint32_t>(chunk));
      payload.insert(payload.end(),
                     write->data.begin() + static_cast<std::ptrdiff_t>(write->offset),
                     write->data.begin() +
                         static_cast<std::ptrdiff_t>(write->offset + chunk));
      auto sent = send_stream_frame(stream.channel_id_,
                                    static_cast<std::uint8_t>(FrameType::stream_data),
                                    std::move(payload), session::FrameClass::bulk);
      if (!sent) {
        if (sent.error_if()->code() == ErrorCode::would_block) {
          // Channel queue full: keep the write; the next event retries.
          return;
        }
        stream.complete_write(*write, StreamIoResult{write->offset, *sent.error_if()});
        stream.writes_.erase(stream.writes_.begin());
        handle_reset_frame_for(stream, StableStatus::unavailable);
        return;
      }
      stream.send_credit_bytes_ -= chunk;
      stream.send_credit_frames_ -= 1U;
      stream.next_send_offset_ += chunk;
      write->offset += chunk;
    }
    // Whole write admitted: completion means "entered the controlled send
    // window", not "peer read" (M5-18).
    const bool fin_after = write->fin_after;
    stream.complete_write(*write, StreamIoResult{write->data.size(), std::nullopt});
    stream.writes_.erase(stream.writes_.begin());
    if (fin_after) {
      std::vector<std::byte> payload;
      proto_codec::append_bytes(payload, 1U,
                                std::span<const std::byte>{stream.id_.data(),
                                                           stream.id_.size()});
      proto_codec::append_uint(payload, 2U, stream.next_send_offset_);
      (void)send_stream_frame(stream.channel_id_,
                              static_cast<std::uint8_t>(FrameType::stream_fin),
                              std::move(payload), session::FrameClass::control);
      finish_stream(stream,
                    stream.fin_received_ ? StreamState::closed
                                         : StreamState::half_closed_local);
      return;
    }
  }
}

}  // namespace heyaki
