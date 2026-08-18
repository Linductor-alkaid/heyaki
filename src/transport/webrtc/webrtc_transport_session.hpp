#pragma once

#include "transport_session.hpp"

#include <heyaki/error.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki::transport::webrtc {

enum class IceServerKind : std::uint8_t {
  stun,
  turn_udp,
  turn_tcp,
  turn_tls,
};

struct IceServerConfig {
  IceServerKind kind{IceServerKind::stun};
  std::string hostname;
  std::uint16_t port{};
  std::string username;
  std::string credential;
};

struct CandidatePolicy {
  bool allow_ipv4_host{true};
  bool allow_ipv6_host{true};
  bool allow_server_reflexive{true};
  bool allow_turn_udp{true};
  bool allow_turn_tcp{false};
  bool allow_turn_tls{false};
  bool relay_only{false};
};

struct WebRtcTransportConfig {
  bool offerer{false};
  SignalingPathKind signaling_path{SignalingPathKind::none};
  CandidatePolicy candidates;
  std::vector<IceServerConfig> ice_servers;
  std::size_t callback_capacity{256U};
  std::size_t channel_capacity{32U};
  std::size_t channel_message_capacity{256U};
  std::size_t maximum_message_bytes{1024U * 1024U};
  std::size_t buffered_amount_high_water{512U * 1024U};
  std::size_t buffered_amount_low_water{256U * 1024U};
  // The default pinned libjuice backend does not implement TURN/TCP or TURN/TLS.
  bool tcp_turn_backend_verified{false};
};

struct WebRtcTransportDiagnostics {
  std::uint64_t callbacks_enqueued{};
  std::uint64_t callbacks_dispatched{};
  std::uint64_t callbacks_rejected{};
  std::uint64_t callback_dispatch_rejected{};
  std::uint64_t messages_rejected{};
  std::uint64_t sends_would_block{};
  std::uint64_t channels_opened{};
  std::uint64_t channels_rejected{};
  std::uint64_t ice_restarts{};
  std::size_t callback_depth{};
  std::size_t callback_peak_depth{};
};

using RuntimeDispatcher =
    std::function<Result<void>(std::string_view, std::function<Result<void>()>)>;

struct WebRtcSignalingHandler {
  std::function<void(std::vector<std::byte>, std::string)> on_local_description;
  std::function<void(std::vector<std::byte>)> on_local_candidate;
};

class WebRtcTransportSession final
    : public TransportSession,
      public std::enable_shared_from_this<WebRtcTransportSession> {
 public:
  [[nodiscard]] static Result<std::shared_ptr<WebRtcTransportSession>> create(
      WebRtcTransportConfig config, RuntimeDispatcher dispatcher,
      WebRtcSignalingHandler signaling = {});

  ~WebRtcTransportSession() override;

  WebRtcTransportSession(const WebRtcTransportSession&) = delete;
  WebRtcTransportSession& operator=(const WebRtcTransportSession&) = delete;

  [[nodiscard]] Result<void> start();
  [[nodiscard]] Result<void> set_remote_description(std::span<const std::byte> sdp,
                                                    std::string_view type);
  [[nodiscard]] Result<void> add_remote_candidate(std::span<const std::byte> candidate);
  [[nodiscard]] Result<void> restart_ice();
  [[nodiscard]] WebRtcTransportDiagnostics diagnostics() const noexcept;

  void async_open_channel(ChannelKind kind, ChannelOptions options,
                          OpenCompletion completion) override;
  void set_message_handler(MessageHandler handler) override;
  void set_state_handler(StateHandler handler) override;
  [[nodiscard]] TransportSessionSnapshot snapshot() const noexcept override;
  void close(CloseReason reason) override;

 private:
  class Impl;
  explicit WebRtcTransportSession(std::shared_ptr<Impl> impl) noexcept;
  std::shared_ptr<Impl> impl_;
};

}  // namespace heyaki::transport::webrtc
