// Public ByteStream façade implementation. The public heyaki::ByteStream
// wraps the internal ByteStreamHandle; no session or transport type leaks
// through the public header (RULE-01).

#include <heyaki/byte_stream.hpp>

#include "byte_stream.hpp"

#include <utility>

namespace heyaki {

std::string_view byte_stream_state_name(ByteStreamState state) noexcept {
  switch (state) {
    case ByteStreamState::opening:
      return "opening";
    case ByteStreamState::open:
      return "open";
    case ByteStreamState::half_closed_local:
      return "half_closed_local";
    case ByteStreamState::half_closed_remote:
      return "half_closed_remote";
    case ByteStreamState::closed:
      return "closed";
    case ByteStreamState::reset:
      return "reset";
  }
  return "unknown";
}

class ByteStream::Impl {
 public:
  explicit Impl(std::shared_ptr<void> erased_handle)
      : erased(std::move(erased_handle)) {}

  std::shared_ptr<void> erased;
};

ByteStream::ByteStream(std::shared_ptr<Impl> impl) : impl_(std::move(impl)) {}

ByteStream::ByteStream(ByteStream&&) noexcept = default;

ByteStream& ByteStream::operator=(ByteStream&&) noexcept = default;

ByteStream::~ByteStream() = default;

namespace {

ByteStreamState public_state(StreamState state) noexcept {
  switch (state) {
    case StreamState::opening:
      return ByteStreamState::opening;
    case StreamState::open:
      return ByteStreamState::open;
    case StreamState::half_closed_local:
      return ByteStreamState::half_closed_local;
    case StreamState::half_closed_remote:
      return ByteStreamState::half_closed_remote;
    case StreamState::closed:
      return ByteStreamState::closed;
    case StreamState::reset:
      return ByteStreamState::reset;
  }
  return ByteStreamState::reset;
}

ByteStreamIoResult public_result(StreamIoResult result) {
  return ByteStreamIoResult{result.bytes, std::move(result.error)};
}

ByteStreamHandle* handle_of(const std::shared_ptr<ByteStream::Impl>& impl) {
  if (impl == nullptr || impl->erased == nullptr) return nullptr;
  return static_cast<ByteStreamHandle*>(impl->erased.get());
}

}  // namespace

void ByteStream::async_read_some(std::span<std::byte> out, ReadHandler handler,
                                 std::optional<std::uint64_t> deadline_unix_milliseconds) {
  auto* handle = handle_of(impl_);
  if (handle == nullptr) {
    handler(ByteStreamIoResult{0U, Error{ErrorCode::cancelled, "byte_stream",
                                          "stream_released"}});
    return;
  }
  handle->async_read_some(
      out,
      [handler = std::move(handler)](StreamIoResult result) {
        handler(public_result(std::move(result)));
      },
      deadline_unix_milliseconds);
}

void ByteStream::async_write(std::span<const std::byte> data, WriteHandler handler,
                             std::optional<std::uint64_t> deadline_unix_milliseconds) {
  auto* handle = handle_of(impl_);
  if (handle == nullptr) {
    handler(ByteStreamIoResult{0U, Error{ErrorCode::cancelled, "byte_stream",
                                          "stream_released"}});
    return;
  }
  handle->async_write(
      data,
      [handler = std::move(handler)](StreamIoResult result) {
        handler(public_result(std::move(result)));
      },
      deadline_unix_milliseconds);
}

Result<void> ByteStream::shutdown_write() {
  auto* handle = handle_of(impl_);
  if (handle == nullptr) {
    return Result<void>::failure(
        Error{ErrorCode::cancelled, "byte_stream", "stream_released"});
  }
  return handle->shutdown_write();
}

void ByteStream::reset(StableStatus reason) {
  auto* handle = handle_of(impl_);
  if (handle == nullptr) return;
  handle->reset(reason);
}

ByteStreamState ByteStream::state() const noexcept {
  auto* handle = handle_of(impl_);
  if (handle == nullptr) return ByteStreamState::reset;
  return public_state(handle->state());
}

ByteStreamWindow ByteStream::window() const noexcept {
  ByteStreamWindow window;
  auto* handle = handle_of(impl_);
  if (handle == nullptr) return window;
  const auto snapshot = handle->window();
  window.next_send_offset = snapshot.next_send_offset;
  window.send_credit_bytes = snapshot.send_credit_bytes;
  window.send_credit_frames = snapshot.send_credit_frames;
  window.next_receive_offset = snapshot.next_receive_offset;
  window.receive_window_bytes = snapshot.receive_window_bytes;
  window.receive_window_frames = snapshot.receive_window_frames;
  window.receive_buffered_bytes = snapshot.receive_buffered_bytes;
  window.consumed_through_offset = snapshot.consumed_through_offset;
  return window;
}

ByteStream ByteStream::adopt(std::shared_ptr<void> erased_handle) {
  return ByteStream(std::make_shared<Impl>(std::move(erased_handle)));
}

std::size_t ByteStream::pending_writes() const noexcept {
  auto* handle = handle_of(impl_);
  return handle == nullptr ? 0U : handle->pending_writes();
}

std::size_t ByteStream::pending_reads() const noexcept {
  auto* handle = handle_of(impl_);
  return handle == nullptr ? 0U : handle->pending_reads();
}

ByteStream make_public_byte_stream(std::shared_ptr<ByteStreamHandle> handle) {
  return ByteStream::adopt(std::shared_ptr<void>{std::move(handle)});
}

}  // namespace heyaki
