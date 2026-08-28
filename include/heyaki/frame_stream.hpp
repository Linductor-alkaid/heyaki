#pragma once

// Incremental framing codec (M5-01). The one-shot parse_frame/encode_frame in
// wire.hpp assume a caller-owned contiguous buffer that already holds whole
// frames. Transport backends deliver arbitrary byte chunks instead: a frame
// may be split across deliveries and several frames may arrive coalesced.
// FrameStreamDecoder/Encoder keep the frozen wire frame layout but make no
// assumption about message boundaries, so a future byte-stream transport
// (for example the WSS cipher-frame backend) can reuse them unchanged.
//
// Bounds are enforced before retention: the decoder never buffers more than
// one declared frame (plus its length varint) and rejects a declared length
// above the configured ceiling before any payload allocation.

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/limits.hpp>
#include <heyaki/wire.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace heyaki {

inline constexpr std::size_t max_frame_length_varint_bytes = 5U;

enum class FrameStreamStatus : std::uint8_t {
  // A complete frame is available.
  parsed,
  // More bytes are required; nothing was consumed.
  need_more,
  // Protocol violation; the decoder is poisoned until reset().
  invalid,
};

struct FrameStreamStep {
  FrameStreamStatus status{FrameStreamStatus::need_more};
  std::optional<FrameView> frame;
  std::optional<Error> error;
};

class FrameStreamDecoder {
 public:
  explicit FrameStreamDecoder(Limits limits = {});

  FrameStreamDecoder(const FrameStreamDecoder&) = delete;
  FrameStreamDecoder& operator=(const FrameStreamDecoder&) = delete;

  // Feeds received bytes. The retained buffer is bounded by one maximum
  // frame; appending past that without completing a frame is a protocol
  // error, not an unbounded accumulation.
  [[nodiscard]] Result<void> append(std::span<const std::byte> bytes);

  // Returns the next complete frame as a view into the internal buffer. The
  // view (including its payload span) remains valid until the next append,
  // take_frame, or consume_view call. need_more keeps pending bytes buffered.
  [[nodiscard]] FrameStreamStep next_view();

  // Consumes the frame last returned by next_view.
  [[nodiscard]] Result<void> consume_view();

  // Owning variant of next_view + consume_view. When the frame is the only
  // buffered content the payload is moved out without a copy; otherwise it is
  // copied out of the retained prefix. This is the common path for
  // one-frame-per-transport-message deliveries.
  [[nodiscard]] Result<std::optional<Frame>> take_frame();

  [[nodiscard]] std::size_t buffered_bytes() const noexcept;
  [[nodiscard]] bool poisoned() const noexcept;
  [[nodiscard]] const Limits& limits() const noexcept;
  void reset() noexcept;

 private:
  Limits limits_;
  std::vector<std::byte> buffer_;
  std::size_t offset_{};
  std::optional<std::size_t> last_view_end_;
  bool poisoned_{false};
};

// Incremental encoder. encode_header writes the frozen frame header for a
// payload the caller has not materialized yet, so a sender can reserve the
// exact output size once and append payload bytes (possibly from a file or
// stream buffer) without re-copying through a Frame object.
class FrameStreamEncoder {
 public:
  explicit FrameStreamEncoder(Limits limits = {});

  // Appends the encoded frame for `view` to `output`.
  [[nodiscard]] Result<std::size_t> encode(std::vector<std::byte>& output,
                                           const FrameView& view);

  // Appends the frame header and returns the payload offset. The caller must
  // append exactly payload_size bytes to `output` afterwards.
  [[nodiscard]] Result<std::size_t> encode_header(std::vector<std::byte>& output,
                                                  std::uint8_t type, std::uint8_t flags,
                                                  std::uint32_t channel_id, MessageId message_id,
                                                  std::size_t payload_size);

  // Exact encoded size of a frame with this header and payload length.
  [[nodiscard]] Result<std::size_t> encoded_size(std::uint8_t type, std::uint8_t flags,
                                                 std::uint32_t channel_id,
                                                 std::size_t payload_size) const;

  [[nodiscard]] const Limits& limits() const noexcept;

 private:
  Limits limits_;
};

}  // namespace heyaki
