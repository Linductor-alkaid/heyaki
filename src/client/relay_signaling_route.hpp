// SignalingRoute adapter that carries the unified coordinator envelopes over the relay
// WSS control plane. Outbound envelopes are wrapped in SignalingSend frames and handed to
// the WSS sender; inbound SignalingDeliver frames are decoded back into envelopes so the
// owning Node can dispatch them into its SignalingCoordinator. The relay stays payload
// opaque; all signed-object verification runs on the devices.
#pragma once

#include "signaling_coordinator.hpp"

#include <heyaki/lan_protocol.hpp>
#include <heyaki/relay_wss_control.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <utility>

namespace heyaki {

class RelaySignalingRoute : public SignalingRoute {
 public:
  using FrameSender = std::function<Result<void>(std::span<const std::byte> frame)>;

  RelaySignalingRoute(DeviceEndpointKey local, FrameSender sender)
      : local_(local), sender_(std::move(sender)) {}

  [[nodiscard]] SignalingRouteKind kind() const noexcept override {
    return SignalingRouteKind::relay;
  }

  [[nodiscard]] Result<void> send(const SignalingEnvelope& message) override {
    if (message.peer.device_id.is_zero() || message.peer.endpoint_id.is_zero() ||
        message.request_id.is_zero() || sender_ == nullptr) {
      return Result<void>::failure(
          Error{ErrorCode::signaling, "relay_signaling_route", "route_not_ready"});
    }
    if (message.payload.size() > max_signaling_object_bytes) {
      return Result<void>::failure(
          Error{ErrorCode::protocol, "relay_signaling_route", "payload_too_large"});
    }
    RelayWssSignalingSend send_frame;
    send_frame.target_device_id = message.peer.device_id;
    send_frame.target_endpoint_id = message.peer.endpoint_id;
    send_frame.kind = static_cast<std::uint8_t>(message.kind);
    send_frame.request_id = message.request_id;
    send_frame.payload = message.payload;
    auto payload = encode_relay_wss_signaling_send(send_frame);
    if (!payload) {
      return Result<void>::failure(*payload.error_if());
    }
    auto frame = encode_relay_wss_control_frame(RelayWssControlType::signaling_send,
                                                *payload.value_if());
    if (!frame) {
      return Result<void>::failure(*frame.error_if());
    }
    return sender_(*frame.value_if());
  }

  // Decodes one SignalingDeliver payload into the coordinator envelope form. The peer
  // field is the authenticated source endpoint, matching the coordinator's inbound
  // convention.
  [[nodiscard]] static Result<SignalingEnvelope> decode_delivery(
      std::span<const std::byte> payload) {
    auto deliver = parse_relay_wss_signaling_deliver(payload);
    if (!deliver) {
      return Result<SignalingEnvelope>::failure(*deliver.error_if());
    }
    SignalingEnvelope envelope;
    envelope.peer.device_id = deliver.value_if()->source_device_id;
    envelope.peer.endpoint_id = deliver.value_if()->source_endpoint_id;
    envelope.kind = static_cast<LanSignalingMessageKind>(deliver.value_if()->kind);
    envelope.request_id = deliver.value_if()->request_id;
    envelope.payload = std::move(deliver.value_if()->payload);
    return Result<SignalingEnvelope>::success(std::move(envelope));
  }

 private:
  DeviceEndpointKey local_;
  FrameSender sender_;
};

}  // namespace heyaki
