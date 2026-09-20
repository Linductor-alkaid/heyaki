// Public ByteStream façade implementation. The public heyaki::ByteStream
// wraps the internal ByteStreamHandle; no session or transport type leaks
// through the public header (RULE-01).
//
// Threading (M10 fix of an M5-era race caught by TSan): the handle's state
// lives on the execution context that owns its ByteStreamService (the node
// strand — transport callbacks and the maintenance tick both run there).
// When a poster is attached, every public operation is marshaled onto that
// context; a null poster keeps the historical single-context inline
// behavior (unit-test harnesses that pump everything on one thread).
// `out`/`data` spans follow the existing completion contract: buffers
// stay valid until the handler fires.

#include <heyaki/byte_stream.hpp>

#include "byte_stream.hpp"

#include <chrono>
#include <future>
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
  Impl(std::shared_ptr<void> erased_handle, ByteStreamOpPoster op_poster)
      : erased(std::move(erased_handle)), poster(std::move(op_poster)) {}

  std::shared_ptr<void> erased;
  ByteStreamOpPoster poster;
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

std::shared_ptr<ByteStreamHandle> shared_handle_of(
    const std::shared_ptr<ByteStream::Impl>& impl) {
  if (impl == nullptr) return nullptr;
  return std::static_pointer_cast<ByteStreamHandle>(impl->erased);
}

Error poster_error(const char* detail) {
  return Error{ErrorCode::cancelled, "byte_stream", detail};
}

}  // namespace

void ByteStream::async_read_some(std::span<std::byte> out, ReadHandler handler,
                                 std::optional<std::uint64_t> deadline_unix_milliseconds) {
  auto* handle = handle_of(impl_);
  if (handle == nullptr) {
    handler(ByteStreamIoResult{0U, poster_error("stream_released")});
    return;
  }
  auto call = [handle = shared_handle_of(impl_), out, handler = std::move(handler),
               deadline_unix_milliseconds]() mutable {
    handle->async_read_some(
        out,
        [handler = std::move(handler)](StreamIoResult result) {
          handler(public_result(std::move(result)));
        },
        deadline_unix_milliseconds);
  };
  if (!impl_->poster) {
    call();
    return;
  }
  if (!impl_->poster(std::move(call))) {
    handler(ByteStreamIoResult{0U, poster_error("stream_context_gone")});
  }
}

void ByteStream::async_write(std::span<const std::byte> data, WriteHandler handler,
                             std::optional<std::uint64_t> deadline_unix_milliseconds) {
  auto* handle = handle_of(impl_);
  if (handle == nullptr) {
    handler(ByteStreamIoResult{0U, poster_error("stream_released")});
    return;
  }
  auto call = [handle = shared_handle_of(impl_), data, handler = std::move(handler),
               deadline_unix_milliseconds]() mutable {
    handle->async_write(
        data,
        [handler = std::move(handler)](StreamIoResult result) {
          handler(public_result(std::move(result)));
        },
        deadline_unix_milliseconds);
  };
  if (!impl_->poster) {
    call();
    return;
  }
  if (!impl_->poster(std::move(call))) {
    handler(ByteStreamIoResult{0U, poster_error("stream_context_gone")});
  }
}

Result<void> ByteStream::shutdown_write() {
  auto* handle = handle_of(impl_);
  if (handle == nullptr) {
    return Result<void>::failure(poster_error("stream_released"));
  }
  if (!impl_->poster) {
    return handle->shutdown_write();
  }
  auto promise = std::make_shared<std::promise<Result<void>>>();
  auto future = promise->get_future();
  const bool dispatched = impl_->poster(
      [handle = shared_handle_of(impl_), promise] {
        promise->set_value(handle->shutdown_write());
      });
  if (!dispatched) {
    return Result<void>::failure(poster_error("stream_context_gone"));
  }
  // The poster runs inline on the owning context, so this only blocks
  // cross-context callers; the bound wait mirrors run_on_strandAndWait.
  if (future.wait_for(std::chrono::seconds{5}) != std::future_status::ready) {
    return Result<void>::failure(poster_error("stream_context_timeout"));
  }
  return future.get();
}

void ByteStream::reset(StableStatus reason) {
  auto* handle = handle_of(impl_);
  if (handle == nullptr) return;
  if (!impl_->poster) {
    handle->reset(reason);
    return;
  }
  // Fire-and-forget: strand FIFO preserves ordering with queued I/O ops.
  (void)impl_->poster([handle = shared_handle_of(impl_), reason] {
    handle->reset(reason);
  });
}

ByteStreamState ByteStream::state() const {
  auto* handle = handle_of(impl_);
  if (handle == nullptr) return ByteStreamState::reset;
  if (!impl_->poster) return public_state(handle->state());
  auto promise = std::make_shared<std::promise<ByteStreamState>>();
  auto future = promise->get_future();
  const bool dispatched = impl_->poster(
      [handle = shared_handle_of(impl_), promise] {
        promise->set_value(public_state(handle->state()));
      });
  if (!dispatched ||
      future.wait_for(std::chrono::seconds{5}) != std::future_status::ready) {
    return ByteStreamState::reset;
  }
  return future.get();
}

ByteStreamWindow ByteStream::window() const {
  ByteStreamWindow window;
  auto* handle = handle_of(impl_);
  if (handle == nullptr) return window;
  const auto adopt_snapshot = [&window](const StreamWindowSnapshot& snapshot) {
    window.next_send_offset = snapshot.next_send_offset;
    window.send_credit_bytes = snapshot.send_credit_bytes;
    window.send_credit_frames = snapshot.send_credit_frames;
    window.next_receive_offset = snapshot.next_receive_offset;
    window.receive_window_bytes = snapshot.receive_window_bytes;
    window.receive_window_frames = snapshot.receive_window_frames;
    window.receive_buffered_bytes = snapshot.receive_buffered_bytes;
    window.consumed_through_offset = snapshot.consumed_through_offset;
  };
  if (!impl_->poster) {
    adopt_snapshot(handle->window());
    return window;
  }
  auto promise = std::make_shared<std::promise<StreamWindowSnapshot>>();
  auto future = promise->get_future();
  const bool dispatched = impl_->poster(
      [handle = shared_handle_of(impl_), promise] {
        promise->set_value(handle->window());
      });
  if (dispatched &&
      future.wait_for(std::chrono::seconds{5}) == std::future_status::ready) {
    adopt_snapshot(future.get());
  }
  return window;
}

ByteStream ByteStream::adopt(std::shared_ptr<void> erased_handle,
                             std::function<bool(std::function<void()>)> op_poster) {
  return ByteStream(std::make_shared<Impl>(std::move(erased_handle),
                                           ByteStreamOpPoster{std::move(op_poster)}));
}

std::size_t ByteStream::pending_writes() const {
  auto* handle = handle_of(impl_);
  if (handle == nullptr) return 0U;
  if (!impl_->poster) return handle->pending_writes();
  auto promise = std::make_shared<std::promise<std::size_t>>();
  auto future = promise->get_future();
  const bool dispatched = impl_->poster(
      [handle = shared_handle_of(impl_), promise] {
        promise->set_value(handle->pending_writes());
      });
  if (!dispatched ||
      future.wait_for(std::chrono::seconds{5}) != std::future_status::ready) {
    return 0U;
  }
  return future.get();
}

std::size_t ByteStream::pending_reads() const {
  auto* handle = handle_of(impl_);
  if (handle == nullptr) return 0U;
  if (!impl_->poster) return handle->pending_reads();
  auto promise = std::make_shared<std::promise<std::size_t>>();
  auto future = promise->get_future();
  const bool dispatched = impl_->poster(
      [handle = shared_handle_of(impl_), promise] {
        promise->set_value(handle->pending_reads());
      });
  if (!dispatched ||
      future.wait_for(std::chrono::seconds{5}) != std::future_status::ready) {
    return 0U;
  }
  return future.get();
}

ByteStream make_public_byte_stream(std::shared_ptr<ByteStreamHandle> handle,
                                   ByteStreamOpPoster poster) {
  return ByteStream::adopt(std::shared_ptr<void>{std::move(handle)}, std::move(poster));
}

}  // namespace heyaki
