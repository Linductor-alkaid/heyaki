#pragma once

// ByteStream over the frozen STREAM_* frames (M5-15..M5-18). Streams ride
// reliable ordered logical `stream` channels of an authorized PeerSession.
// The protocol is exactly wire protocol 2.1/6.3: STREAM_OPEN fixes the stream
// id and the receiver's dual (byte + frame) window; STREAM_DATA carries one
// offset; WINDOW_UPDATE grants credit from a monotonic consumed offset; FIN
// half-closes with the final offset; RESET fails exactly one stream.
//
// Semantics (architecture 7.5):
//   * a completed async_write means the bytes entered the controlled send
//     window (credit consumed and frames admitted to the bounded channel
//     queue), NOT that the peer application read them;
//   * the sender stops producing DATA once the peer-granted window is
//     exhausted instead of relying on transport buffering;
//   * ordinary streams never survive a session loss: closing the session
//     fails every stream (recovery belongs to the file protocol).

#include "peer_session.hpp"
#include "session_channels.hpp"

#include <heyaki/byte_stream.hpp>
#include <heyaki/error.hpp>
#include <heyaki/pairing_protocol.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace heyaki {

class ByteStreamService;

using StreamId = std::array<std::byte, 16U>;

inline constexpr std::size_t stream_data_header_bytes = 28U;

enum class StreamState : std::uint8_t {
  // Local open sent/being sent; peer window not yet known for initiated
  // streams before the first window arrives with the peer's OPEN answer —
  // v1 open frames carry the opener's receive window, and the peer's data
  // uses the credit we granted.
  opening,
  open,
  half_closed_local,
  half_closed_remote,
  closed,
  reset,
};

[[nodiscard]] std::string_view stream_state_name(StreamState state) noexcept;

// Completion for stream I/O: `bytes` counts what actually happened, so a
// deadline or cancellation can still report a partial result (M5-17).
struct StreamIoResult {
  std::size_t bytes{};
  std::optional<Error> error;
};

struct StreamWindowSnapshot {
  std::uint64_t next_send_offset{};
  std::uint64_t send_credit_bytes{};
  std::uint32_t send_credit_frames{};
  std::uint64_t next_receive_offset{};
  std::uint64_t receive_window_bytes{};
  std::uint32_t receive_window_frames{};
  std::uint64_t receive_buffered_bytes{};
  std::uint32_t receive_buffered_frames{};
  std::uint64_t consumed_through_offset{};
};

struct ByteStreamLimits {
  std::size_t max_data_chunk_bytes{16U * 1024U};
  std::size_t default_receive_window_bytes{256U * 1024U};
  std::uint32_t default_receive_window_frames{64U};
  std::size_t max_concurrent_streams{16U};
  // Bounded per-stream pending write bytes before async_write reports
  // would_block to the caller.
  std::size_t pending_write_bytes{512U * 1024U};
  std::size_t max_pending_reads{16U};
  std::size_t max_pending_writes{16U};
};

[[nodiscard]] Result<void> validate_byte_stream_limits(const ByteStreamLimits& limits);

// One bidirectional byte stream. All methods must be called on the session's
// execution context; handlers run on it as well.
class ByteStreamHandle {
 public:
  using ReadHandler = std::function<void(StreamIoResult)>;
  using WriteHandler = std::function<void(StreamIoResult)>;

  ~ByteStreamHandle();

  ByteStreamHandle(const ByteStreamHandle&) = delete;
  ByteStreamHandle& operator=(const ByteStreamHandle&) = delete;

  // Reads up to out.size() buffered bytes; completes immediately when data or
  // end-of-stream state exists, otherwise pends (bounded) until DATA/FIN/
  // RESET or its deadline. May complete short.
  void async_read_some(std::span<std::byte> out, ReadHandler handler,
                       std::optional<std::uint64_t> deadline_unix_milliseconds = {});
  // Writes bytes into the stream, splitting into bounded DATA chunks. The
  // handler fires once every byte entered the send window (or the partial
  // count on deadline/cancellation). Never blocks the caller.
  void async_write(std::span<const std::byte> data, WriteHandler handler,
                   std::optional<std::uint64_t> deadline_unix_milliseconds = {});
  // Half-close: after all pending bytes, send FIN with the final offset.
  [[nodiscard]] Result<void> shutdown_write();
  // Fail this stream only; idempotent.
  void reset(StableStatus reason);

  [[nodiscard]] StreamState state() const noexcept;
  [[nodiscard]] const StreamId& stream_id() const noexcept;
  [[nodiscard]] std::uint32_t channel_id() const noexcept;
  [[nodiscard]] StreamWindowSnapshot window() const noexcept;
  [[nodiscard]] std::size_t pending_writes() const noexcept;
  [[nodiscard]] std::size_t pending_reads() const noexcept;

 private:
  friend class ByteStreamService;
  struct PendingWrite {
    std::vector<std::byte> data;
    std::size_t offset{};
    WriteHandler handler;
    std::optional<std::uint64_t> deadline;
    bool fin_after{false};
  };
  struct PendingRead {
    std::span<std::byte> out;
    ReadHandler handler;
    std::optional<std::uint64_t> deadline;
  };

 public:
  // Internal: only ByteStreamService constructs streams (public because
  // make_shared cannot use the private constructor through library internals).
  ByteStreamHandle(ByteStreamService& service, StreamId id, std::uint32_t channel_id,
                   std::uint64_t receive_window_bytes,
                   std::uint32_t receive_window_frames);

 private:
  void complete_read(StreamIoResult result);
  void complete_write(PendingWrite& write, StreamIoResult result);
  void try_dispatch_reads();
  // Sends a WINDOW_UPDATE once enough consumed credit accumulated (or the
  // window drained), reporting the monotonic consumed offset (M5-16).
  void maybe_send_window_update();

  ByteStreamService* service_{nullptr};
  StreamId id_{};
  std::uint32_t channel_id_{};
  StreamState state_{StreamState::opening};
  std::size_t max_pending_reads_{16U};
  std::size_t max_pending_writes_{16U};
  std::size_t max_pending_write_bytes_{512U * 1024U};
  // Receive side: strict next-offset acceptance and dual-window accounting.
  std::uint64_t next_receive_offset_{};
  std::uint64_t receive_window_bytes_{};
  std::uint32_t receive_window_frames_{};
  std::uint64_t receive_window_remaining_bytes_{};
  std::uint32_t receive_window_remaining_frames_{};
  std::deque<std::vector<std::byte>> receive_chunks_;
  std::uint64_t receive_buffered_bytes_{};
  std::uint64_t consumed_through_offset_{};
  std::uint64_t update_reported_consumed_bytes_{};
  std::uint32_t update_reported_consumed_frames_{};
  bool fin_received_{false};
  std::uint64_t final_receive_offset_{};
  // Send side: credit granted by the peer and the peer's reported consumed
  // offset (our send-side mirror, distinct from our receive-side counter).
  std::uint64_t next_send_offset_{};
  std::uint64_t send_consumed_by_peer_{};
  std::uint64_t send_credit_bytes_{};
  std::uint32_t send_credit_frames_{};
  bool fin_sent_{false};
  std::optional<StableStatus> reset_reason_;
  std::vector<std::shared_ptr<PendingWrite>> writes_;
  std::vector<std::shared_ptr<PendingRead>> reads_;
};

// Per-session stream multiplexer (M5-15/M5-16).
class ByteStreamService {
 public:
  using InboundHandler =
      std::function<void(const std::shared_ptr<ByteStreamHandle>&)>;

  ByteStreamService(PeerSession& session, ByteStreamLimits limits = {},
                    std::function<std::uint64_t()> wall_clock = {});
  // Detaches the stream domain handler and closes this service's logical
  // channels before the raw references into the session dangle.
  ~ByteStreamService();

  ByteStreamService(const ByteStreamService&) = delete;
  ByteStreamService& operator=(const ByteStreamService&) = delete;

  // Opens this side's logical stream channel and installs dispatching.
  [[nodiscard]] Result<void> attach();
  // Initiates a stream on the session's channel (STREAM_OPEN carries our
  // receive window). The peer's inbound callback fires on its side.
  [[nodiscard]] Result<std::shared_ptr<ByteStreamHandle>> open_stream(
      std::uint64_t receive_window_bytes, std::uint32_t receive_window_frames);
  // Streams the peer initiated land here when set; unset inbound streams are
  // reset with permission_denied.
  void set_inbound_handler(InboundHandler handler);

  [[nodiscard]] std::size_t active_streams() const noexcept;
  [[nodiscard]] std::vector<StreamId> stream_ids() const;
  [[nodiscard]] std::shared_ptr<ByteStreamHandle> stream(const StreamId& id) const;
  // Fails every stream (session lost); M5-18: no automatic recovery.
  void fail_all(const Error& error);
  // Deadline sweep; also called on every inbound frame and write.
  void check_deadlines();

  [[nodiscard]] const ByteStreamLimits& limits() const noexcept;

 private:
  friend class ByteStreamHandle;

  [[nodiscard]] std::uint64_t now() const;
  [[nodiscard]] Result<void> send_stream_open(ByteStreamHandle& stream);
  void handle_frame(const FrameView& frame);
  [[nodiscard]] Result<void> admit_frame(const FrameView& frame);
  void handle_open(const FrameView& frame, std::uint32_t channel_id);
  void handle_data(const FrameView& frame);
  void handle_window_update(const FrameView& frame);
  void handle_fin(const FrameView& frame);
  void handle_reset(const FrameView& frame);
  void handle_reset_frame_for(ByteStreamHandle& stream, StableStatus reason);
  [[nodiscard]] Result<void> send_stream_frame(std::uint32_t channel_id,
                                               std::uint8_t type,
                                               std::vector<std::byte> payload,
                                               session::FrameClass klass);
  void pump_writes(ByteStreamHandle& stream);
  void complete_all_reads(ByteStreamHandle& stream, StreamIoResult result);
  void finish_stream(ByteStreamHandle& stream, StreamState terminal);

  PeerSession& session_;
  ByteStreamLimits limits_;
  std::function<std::uint64_t()> wall_clock_;
  std::optional<std::uint32_t> channel_id_;
  std::vector<std::uint32_t> owned_channels_;
  std::map<StreamId, std::shared_ptr<ByteStreamHandle>> streams_;
  InboundHandler inbound_handler_;
  bool attached_{false};
};

// Internal factory used by Node to wrap a stream handle in the public
// facade type (defined in byte_stream_facade.cpp).
[[nodiscard]] ByteStream make_public_byte_stream(
    std::shared_ptr<ByteStreamHandle> handle);

}  // namespace heyaki
