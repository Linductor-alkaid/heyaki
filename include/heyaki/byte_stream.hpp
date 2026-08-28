#pragma once

// Public ByteStream façade (architecture 7.5, M5-15..M5-18). A ByteStream is
// an ordered, reliable bidirectional byte stream over an authorized peer
// session, usable by applications after local authorization. The public type
// deliberately exposes no transport or session internals.

#include <heyaki/error.hpp>
#include <heyaki/pairing_protocol.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace heyaki {

class Node;

enum class ByteStreamState : std::uint8_t {
  opening,
  open,
  half_closed_local,
  half_closed_remote,
  closed,
  reset,
};

[[nodiscard]] std::string_view byte_stream_state_name(ByteStreamState state) noexcept;

// Completion for stream I/O: `bytes` counts what actually happened, so a
// deadline or cancellation still reports a partial result.
struct ByteStreamIoResult {
  std::size_t bytes{};
  std::optional<Error> error;
};

struct ByteStreamWindow {
  std::uint64_t next_send_offset{};
  std::uint64_t send_credit_bytes{};
  std::uint32_t send_credit_frames{};
  std::uint64_t next_receive_offset{};
  std::uint64_t receive_window_bytes{};
  std::uint32_t receive_window_frames{};
  std::uint64_t receive_buffered_bytes{};
  std::uint64_t consumed_through_offset{};
};

// One stream bound to the lifetime of its session: streams never survive a
// session loss (M5-18); recovery belongs to higher-level protocols.
class ByteStream {
 public:
  using ReadHandler = std::function<void(ByteStreamIoResult)>;
  using WriteHandler = std::function<void(ByteStreamIoResult)>;

  ByteStream(ByteStream&&) noexcept;
  ByteStream& operator=(ByteStream&&) noexcept;
  ~ByteStream();

  ByteStream(const ByteStream&) = delete;
  ByteStream& operator=(const ByteStream&) = delete;

  // Reads up to out.size() buffered bytes; may complete short; a clean
  // end-of-stream completes with zero bytes and no error. `deadline` is a
  // wall-clock millisecond timestamp; expired reads complete with a timeout
  // error.
  void async_read_some(std::span<std::byte> out, ReadHandler handler,
                       std::optional<std::uint64_t> deadline_unix_milliseconds = {});
  // Writes bytes; the handler fires once every byte entered the controlled
  // send window (credit consumed, frames admitted to the bounded queue) —
  // NOT once the peer application read them (M5-18).
  void async_write(std::span<const std::byte> data, WriteHandler handler,
                   std::optional<std::uint64_t> deadline_unix_milliseconds = {});
  // Half-close the write direction after pending bytes.
  [[nodiscard]] Result<void> shutdown_write();
  // Fail this stream only; the session keeps running.
  void reset(StableStatus reason);

  [[nodiscard]] ByteStreamState state() const noexcept;
  [[nodiscard]] ByteStreamWindow window() const noexcept;
  [[nodiscard]] std::size_t pending_writes() const noexcept;
  [[nodiscard]] std::size_t pending_reads() const noexcept;

  // Internal: wraps a type-erased stream handle owned by the session layer.
  // Applications receive streams from Node, never construct them.
  [[nodiscard]] static ByteStream adopt(std::shared_ptr<void> erased_handle);

  // Opaque implementation type, defined inside the library.
  class Impl;

 private:
  explicit ByteStream(std::shared_ptr<Impl> impl);

  std::shared_ptr<Impl> impl_;
};

}  // namespace heyaki
