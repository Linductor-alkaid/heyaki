// Internal transport SPI for Heyaki session establishment. This header is deliberately not
// installed and is not a stable third-party plugin ABI: v1 ships exactly one implementation
// (WebRtcTransportSession over libdatachannel) plus in-tree test fakes. Public business APIs
// must keep depending only on transport-neutral session contracts.
#pragma once

#include <heyaki/error.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki::transport {

enum class SignalingPathKind : std::uint8_t {
  none,
  lan,
  relay,
};

enum class DataPathKind : std::uint8_t {
  unknown,
  direct_host,
  direct_srflx,
  turn_udp,
  turn_tcp,
  turn_tls,
};

// PathInfo keeps the control-plane route and the data-plane path separate: the signaling
// route that carried offer/answer never implies which ICE candidate ended up selected.
struct PathInfo {
  SignalingPathKind signaling_path{SignalingPathKind::none};
  DataPathKind data_path{DataPathKind::unknown};
  std::string selected_candidate;
  std::chrono::milliseconds rtt{};

  friend bool operator==(const PathInfo&, const PathInfo&) = default;
};

[[nodiscard]] std::string_view signaling_path_kind_name(SignalingPathKind kind) noexcept;
[[nodiscard]] std::string_view data_path_kind_name(DataPathKind kind) noexcept;

enum class ChannelKind : std::uint8_t {
  control,
  pairing,
  message,
  rpc,
  event,
  file,
  shell,
};

enum class Reliability : std::uint8_t {
  reliable,
  unreliable,
};

enum class Ordering : std::uint8_t {
  ordered,
  unordered,
};

// Weighted scheduling classes: control and interactive traffic preempt standard traffic,
// bulk transfers only consume the remaining budget.
enum class ChannelPriority : std::uint8_t {
  control,
  interactive,
  standard,
  bulk,
};

struct ChannelOptions {
  Reliability reliability{Reliability::reliable};
  Ordering ordering{Ordering::ordered};
  ChannelPriority priority{ChannelPriority::standard};
  std::size_t send_queue_bytes{64U * 1024U};
  std::size_t max_message_bytes{64U * 1024U};
};

enum class CloseReason : std::uint8_t {
  local_shutdown,
  peer_closed,
  transport_failed,
  signaling_lost,
  timeout,
  cancelled,
  protocol_error,
};

[[nodiscard]] std::string_view close_reason_name(CloseReason reason) noexcept;

enum class TransportState : std::uint8_t {
  new_session,
  gathering,
  checking,
  connected,
  failed,
  closed,
};

[[nodiscard]] std::string_view transport_state_name(TransportState state) noexcept;

struct TransportSessionSnapshot {
  TransportState state{TransportState::new_session};
  PathInfo path;
  std::optional<Error> error;
  std::size_t buffered_amount{};
};

// One logical channel inside a transport session. Implementations must bound the send queue
// by both bytes and messages and surface backpressure as would_block instead of buffering
// without limit.
class TransportChannel {
 public:
  virtual ~TransportChannel() = default;

  [[nodiscard]] virtual ChannelKind kind() const noexcept = 0;
  [[nodiscard]] virtual const ChannelOptions& options() const noexcept = 0;
  [[nodiscard]] virtual Result<void> send(std::span<const std::byte> payload) = 0;
  [[nodiscard]] virtual std::size_t buffered_amount() const noexcept = 0;
  virtual void close(CloseReason reason) = 0;
};

class TransportSession {
 public:
  using OpenCompletion = std::function<void(Result<TransportChannel*>)>;
  using MessageHandler = std::function<void(TransportChannel&, std::vector<std::byte>)>;
  using StateHandler = std::function<void(const TransportSessionSnapshot&)>;

  virtual ~TransportSession() = default;

  virtual void async_open_channel(ChannelKind kind, ChannelOptions options,
                                  OpenCompletion completion) = 0;
  virtual void set_message_handler(MessageHandler handler) = 0;
  virtual void set_state_handler(StateHandler handler) = 0;
  [[nodiscard]] virtual TransportSessionSnapshot snapshot() const noexcept = 0;
  virtual void close(CloseReason reason) = 0;
};

inline std::string_view signaling_path_kind_name(SignalingPathKind kind) noexcept {
  switch (kind) {
    case SignalingPathKind::none:
      return "none";
    case SignalingPathKind::lan:
      return "lan";
    case SignalingPathKind::relay:
      return "relay";
  }
  return "unknown";
}

inline std::string_view data_path_kind_name(DataPathKind kind) noexcept {
  switch (kind) {
    case DataPathKind::unknown:
      return "unknown";
    case DataPathKind::direct_host:
      return "direct_host";
    case DataPathKind::direct_srflx:
      return "direct_srflx";
    case DataPathKind::turn_udp:
      return "turn_udp";
    case DataPathKind::turn_tcp:
      return "turn_tcp";
    case DataPathKind::turn_tls:
      return "turn_tls";
  }
  return "unknown";
}

inline std::string_view close_reason_name(CloseReason reason) noexcept {
  switch (reason) {
    case CloseReason::local_shutdown:
      return "local_shutdown";
    case CloseReason::peer_closed:
      return "peer_closed";
    case CloseReason::transport_failed:
      return "transport_failed";
    case CloseReason::signaling_lost:
      return "signaling_lost";
    case CloseReason::timeout:
      return "timeout";
    case CloseReason::cancelled:
      return "cancelled";
    case CloseReason::protocol_error:
      return "protocol_error";
  }
  return "unknown";
}

inline std::string_view transport_state_name(TransportState state) noexcept {
  switch (state) {
    case TransportState::new_session:
      return "new";
    case TransportState::gathering:
      return "gathering";
    case TransportState::checking:
      return "checking";
    case TransportState::connected:
      return "connected";
    case TransportState::failed:
      return "failed";
    case TransportState::closed:
      return "closed";
  }
  return "unknown";
}

}  // namespace heyaki::transport
