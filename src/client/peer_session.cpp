#include "peer_session.hpp"

#include <heyaki/wire.hpp>

#include <sodium/randombytes.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <span>
#include <utility>

namespace heyaki {
namespace {

Error session_error(ErrorCode code, const char* detail) {
  return {code, "peer_session", detail};
}

MessageId random_message_id() {
  MessageId::Storage bytes{};
  do {
    randombytes_buf(bytes.data(), bytes.size());
  } while (MessageId{bytes}.is_zero());
  return MessageId{bytes};
}

std::vector<std::byte> encode_ping_payload(std::uint64_t value) {
  std::vector<std::byte> payload(8U);
  for (std::size_t index = 0U; index < payload.size(); ++index) {
    payload[index] = static_cast<std::byte>(value >> (index * 8U));
  }
  return payload;
}

std::uint64_t decode_ping_payload(std::span<const std::byte> payload) {
  std::uint64_t value = 0U;
  for (std::size_t index = 0U; index < payload.size(); ++index) {
    value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(payload[index]))
             << (index * 8U);
  }
  return value;
}

}  // namespace

PeerSession::PeerSession(PeerSessionConfig config) : config_(std::move(config)) {
  admission_ = std::make_unique<SessionHelloAdmission>(
      config_.expectation, config_.peer_public_key, config_.local_protocol);
}

PeerSession::~PeerSession() { close(transport::CloseReason::local_shutdown); }

Result<std::shared_ptr<PeerSession>> PeerSession::create(PeerSessionConfig config) {
  if (!config.transport || config.local_hello.sender.device_id.is_zero() ||
      config.local_hello.peer.device_id.is_zero() ||
      config.peer_public_key == IdentityPublicKey{}) {
    return Result<std::shared_ptr<PeerSession>>::failure(
        session_error(ErrorCode::configuration, "peer_session_config_invalid"));
  }
  auto valid = validate_signed_session_hello(config.local_hello);
  if (!valid) {
    return Result<std::shared_ptr<PeerSession>>::failure(*valid.error_if());
  }
  if (config.local_hello.sender != config.expectation.peer ||
      config.local_hello.peer != config.expectation.sender ||
      config.local_hello.session_id != config.expectation.session_id ||
      config.local_hello.session_epoch != config.expectation.session_epoch ||
      config.local_hello.initiator_nonce != config.expectation.initiator_nonce ||
      config.local_hello.responder_nonce != config.expectation.responder_nonce ||
      config.local_hello.signaling_transcript_sha256 !=
          config.expectation.signaling_transcript_sha256) {
    return Result<std::shared_ptr<PeerSession>>::failure(
        session_error(ErrorCode::authentication, "local_hello_binding_mismatch"));
  }
  return Result<std::shared_ptr<PeerSession>>::success(
      std::shared_ptr<PeerSession>(new PeerSession(std::move(config))));
}

Result<void> PeerSession::start() {
  if (started_ || diagnostics_.state == PeerSessionState::closed) {
    return Result<void>::failure(session_error(ErrorCode::cancelled, "peer_session_closed"));
  }
  started_ = true;
  diagnostics_.state = PeerSessionState::authenticating;
  auto weak = weak_from_this();
  config_.transport->set_message_handler(
      [weak](transport::TransportChannel& channel, std::vector<std::byte> payload) {
        if (auto self = weak.lock()) self->handle_message(channel, std::move(payload));
      });
  config_.transport->set_state_handler([weak](const transport::TransportSessionSnapshot& snapshot) {
    if (auto self = weak.lock(); self && snapshot.state == transport::TransportState::closed) {
      self->diagnostics_.state = PeerSessionState::closed;
    }
  });
  if (!config_.initiator) return Result<void>::success();
  transport::ChannelOptions options;
  options.priority = transport::ChannelPriority::control;
  options.send_queue_bytes = 64U * 1024U;
  options.max_message_bytes = 64U * 1024U;
  config_.transport->async_open_channel(
      transport::ChannelKind::control, options,
      [weak](Result<transport::TransportChannel*> result) {
        auto self = weak.lock();
        if (!self) return;
        if (!result) {
          self->fail(*result.error_if());
          return;
        }
        self->control_ = *result.value_if();
        auto sent = self->send_hello(*self->control_);
        if (!sent) self->fail(*sent.error_if());
      });
  return Result<void>::success();
}

Result<void> PeerSession::send_hello(transport::TransportChannel& channel) {
  auto payload = encode_signed_session_hello(config_.local_hello);
  if (!payload) return Result<void>::failure(*payload.error_if());
  Frame frame{.type = static_cast<std::uint8_t>(FrameType::session_hello),
              .channel_id = 0U,
              .message_id = random_message_id(),
              .payload = std::move(*payload.value_if())};
  auto encoded = encode_frame(frame);
  if (!encoded) return Result<void>::failure(*encoded.error_if());
  auto sent = channel.send(*encoded.value_if());
  if (!sent) return Result<void>::failure(*sent.error_if());
  ++diagnostics_.hellos_sent;
  return Result<void>::success();
}

Result<void> PeerSession::send_ping(std::uint64_t ping_id) {
  if (!authenticated() || control_ == nullptr || pending_ping_.has_value()) {
    return Result<void>::failure(
        session_error(ErrorCode::permission, "control_ping_not_available"));
  }
  Frame ping{.type = static_cast<std::uint8_t>(FrameType::ping),
             .channel_id = 0U,
             .message_id = random_message_id(),
             .payload = encode_ping_payload(ping_id)};
  auto encoded = encode_frame(ping);
  if (!encoded) return Result<void>::failure(*encoded.error_if());
  auto sent = control_->send(*encoded.value_if());
  if (!sent) return Result<void>::failure(*sent.error_if());
  pending_ping_ = ping_id;
  ++diagnostics_.pings_sent;
  return Result<void>::success();
}

void PeerSession::handle_message(transport::TransportChannel& channel,
                                 std::vector<std::byte> payload) {
  if (channel.kind() != transport::ChannelKind::control) {
    ++diagnostics_.business_frames_rejected;
    channel.close(transport::CloseReason::protocol_error);
    return;
  }
  auto parsed = parse_frame(payload);
  if (parsed.status != FrameParseStatus::parsed || !parsed.frame ||
      parsed.consumed != payload.size()) {
    fail(session_error(ErrorCode::protocol, "control_frame_invalid"));
    return;
  }
  const auto& frame = *parsed.frame;
  if (frame.type == static_cast<std::uint8_t>(FrameType::session_hello)) {
    control_ = &channel;
    auto admitted = admission_->admit(frame.payload, config_.now_unix_milliseconds);
    if (!admitted) {
      fail(*admitted.error_if());
      return;
    }
    ++diagnostics_.hellos_received;
    if (admitted.value_if()->action == SessionHelloAdmissionAction::accepted) {
      if (diagnostics_.hellos_sent == 0U) {
        auto sent = send_hello(channel);
        if (!sent) {
          fail(*sent.error_if());
          return;
        }
      }
      diagnostics_.state = PeerSessionState::authenticated;
    }
    return;
  }
  if (frame.type == static_cast<std::uint8_t>(FrameType::ping) &&
      diagnostics_.state == PeerSessionState::authenticated && frame.payload.size() == 8U) {
    Frame pong{.type = static_cast<std::uint8_t>(FrameType::pong),
               .channel_id = 0U,
               .message_id = random_message_id(),
               .payload = {frame.payload.begin(), frame.payload.end()}};
    auto encoded = encode_frame(pong);
    if (!encoded || !control_->send(*encoded.value_if())) {
      fail(session_error(ErrorCode::transport, "pong_send_failed"));
      return;
    }
    ++diagnostics_.pings_received;
    ++diagnostics_.pongs_sent;
    return;
  }
  if (frame.type == static_cast<std::uint8_t>(FrameType::pong) &&
      diagnostics_.state == PeerSessionState::authenticated && frame.payload.size() == 8U &&
      pending_ping_ == decode_ping_payload(frame.payload)) {
    pending_ping_.reset();
    ++diagnostics_.pongs_received;
    return;
  }
  if (diagnostics_.state != PeerSessionState::authenticated) {
    fail(session_error(ErrorCode::authentication, "control_frame_before_hello"));
  }
}

void PeerSession::fail(Error error) {
  diagnostics_.last_error = error;
  diagnostics_.state = PeerSessionState::closed;
  if (config_.transport) config_.transport->close(transport::CloseReason::protocol_error);
}

PeerSessionDiagnostics PeerSession::diagnostics() const noexcept { return diagnostics_; }

bool PeerSession::authenticated() const noexcept {
  return diagnostics_.state == PeerSessionState::authenticated;
}

void PeerSession::close(transport::CloseReason reason) {
  if (diagnostics_.state == PeerSessionState::closed) return;
  diagnostics_.state = PeerSessionState::closed;
  if (config_.transport) config_.transport->close(reason);
}

}  // namespace heyaki
