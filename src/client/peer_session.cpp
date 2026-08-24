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

Result<void> validate_timeline_for_peer_session(
    const std::shared_ptr<ConnectionAttemptTimeline>& timeline) {
  if (!timeline) return Result<void>::success();
  std::size_t required_capacity = 0U;
  switch (timeline->stage()) {
    case ConnectionStage::signaling:
      required_capacity = 6U;
      break;
    case ConnectionStage::gathering:
      required_capacity = 5U;
      break;
    case ConnectionStage::checking:
      required_capacity = 4U;
      break;
    case ConnectionStage::transport_connected:
      required_capacity = 3U;
      break;
    default:
      return Result<void>::failure(
          session_error(ErrorCode::configuration, "connection_timeline_not_ready"));
  }
  if (timeline->capacity() - timeline->transitions().size() < required_capacity) {
    return Result<void>::failure(
        session_error(ErrorCode::configuration, "connection_timeline_capacity_insufficient"));
  }
  return Result<void>::success();
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
  auto timeline_valid = validate_timeline_for_peer_session(config.timeline);
  if (!timeline_valid) {
    return Result<std::shared_ptr<PeerSession>>::failure(*timeline_valid.error_if());
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

Result<std::shared_ptr<PeerSession>> PeerSession::create_verified(
    VerifiedPeerSessionConfig config) {
  if (config.local_identity == nullptr) {
    return Result<std::shared_ptr<PeerSession>>::failure(
        session_error(ErrorCode::configuration, "local_identity_missing"));
  }
  SignedSessionHello local;
  local.sender = config.binding.expectation.peer;
  local.peer = config.binding.expectation.sender;
  local.session_id = config.binding.expectation.session_id;
  local.session_epoch = config.binding.expectation.session_epoch;
  local.initiator_nonce = config.binding.expectation.initiator_nonce;
  local.responder_nonce = config.binding.expectation.responder_nonce;
  local.signaling_transcript_sha256 =
      config.binding.expectation.signaling_transcript_sha256;
  local.protocol_version = config.local_protocol.version;
  local.supported = config.local_protocol.supported;
  local.required = config.local_protocol.required;
  local.expires_unix_milliseconds = config.expires_unix_milliseconds;
  auto signed_hello = sign_signed_session_hello(local, *config.local_identity);
  if (!signed_hello) {
    return Result<std::shared_ptr<PeerSession>>::failure(*signed_hello.error_if());
  }
  return create({.transport = std::move(config.transport),
                 .local_hello = std::move(local),
                 .expectation = config.binding.expectation,
                 .peer_public_key = config.peer_public_key,
                 .local_protocol = config.local_protocol,
                 .now_unix_milliseconds = config.now_unix_milliseconds,
                 .initiator = config.binding.initiator,
                 .observer = std::move(config.observer),
                 .timeline = std::move(config.timeline),
                 .clock = std::move(config.clock)});
}

Result<void> PeerSession::start() {
  if (started_ || diagnostics_.state == PeerSessionState::closed) {
    return Result<void>::failure(session_error(ErrorCode::cancelled, "peer_session_closed"));
  }
  started_ = true;
  diagnostics_.state = PeerSessionState::authenticating;
  notify();
  auto weak = weak_from_this();
  config_.transport->set_message_handler(
      [weak](transport::TransportChannel& channel, std::vector<std::byte> payload) {
        if (auto self = weak.lock()) self->handle_message(channel, std::move(payload));
      });
  config_.transport->set_state_handler(
      [weak](const transport::TransportSessionSnapshot& snapshot) {
        auto self = weak.lock();
        if (!self) return;
        bool timeline_changed = false;
        if (snapshot.state == transport::TransportState::gathering && self->config_.timeline &&
            self->config_.timeline->stage() == ConnectionStage::signaling) {
          auto recorded =
              self->record(ConnectionStage::gathering, "transport", "ice_gathering");
          if (!recorded) {
            self->fail(*recorded.error_if());
            return;
          }
          timeline_changed = true;
        } else if (snapshot.state == transport::TransportState::checking &&
                   self->config_.timeline &&
                   (self->config_.timeline->stage() == ConnectionStage::signaling ||
                    self->config_.timeline->stage() == ConnectionStage::gathering)) {
          auto recorded =
              self->record(ConnectionStage::checking, "transport", "ice_checking");
          if (!recorded) {
            self->fail(*recorded.error_if());
            return;
          }
          timeline_changed = true;
        } else if (snapshot.state == transport::TransportState::connected &&
                   self->config_.timeline &&
                   (self->config_.timeline->stage() == ConnectionStage::signaling ||
                    self->config_.timeline->stage() == ConnectionStage::gathering ||
                    self->config_.timeline->stage() == ConnectionStage::checking)) {
          auto recorded = self->record(ConnectionStage::transport_connected, "transport",
                                       "data_channel_transport_ready");
          if (!recorded) {
            self->fail(*recorded.error_if());
            return;
          }
          timeline_changed = true;
        } else if (snapshot.state == transport::TransportState::failed) {
          // A failed transport must keep its real failure reason (for example
          // ice_failed) instead of letting the follow-up closed notification
          // masquerade as a clean close.
          self->diagnostics_.state = PeerSessionState::closed;
          if (snapshot.error) {
            self->diagnostics_.last_error = *snapshot.error;
          }
          const std::string_view reason =
              snapshot.error ? snapshot.error->safe_detail() : "transport_failed";
          auto recorded = self->record(ConnectionStage::closed, "transport", reason);
          if (!recorded) self->diagnostics_.last_error = *recorded.error_if();
          self->notify();
          return;
        } else if (snapshot.state == transport::TransportState::closed) {
          self->diagnostics_.state = PeerSessionState::closed;
          auto recorded =
              self->record(ConnectionStage::closed, "transport", "transport_closed");
          if (!recorded) self->diagnostics_.last_error = *recorded.error_if();
          self->notify();
          return;
        }
        if (timeline_changed) self->notify();
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
        if (self->config_.timeline &&
            self->config_.timeline->stage() != ConnectionStage::transport_connected) {
          auto recorded = self->record(ConnectionStage::transport_connected, "peer_session",
                                       "control_channel_open");
          if (!recorded) {
            self->fail(*recorded.error_if());
            return;
          }
        }
        auto recorded = self->record(ConnectionStage::authenticating, "peer_session",
                                     "session_hello_sent");
        if (!recorded) {
          self->fail(*recorded.error_if());
          return;
        }
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
  notify();
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
  notify();
  return Result<void>::success();
}

void PeerSession::set_restart_handler(PeerSessionRestartHandler handler) {
  restart_handler_ = std::move(handler);
}

const SignedSessionHello& PeerSession::local_hello() const noexcept {
  return config_.local_hello;
}

Result<void> PeerSession::send_restart_frame(FrameType type,
                                             std::span<const std::byte> payload) {
  if (type != FrameType::session_restart_offer &&
      type != FrameType::session_restart_answer &&
      type != FrameType::session_restart_candidate) {
    return Result<void>::failure(
        session_error(ErrorCode::configuration, "restart_frame_type_invalid"));
  }
  if (!authenticated() || control_ == nullptr) {
    return Result<void>::failure(
        session_error(ErrorCode::permission, "restart_frame_not_available"));
  }
  if (payload.empty() || payload.size() > max_signaling_object_bytes) {
    return Result<void>::failure(
        session_error(ErrorCode::protocol, "restart_frame_payload_invalid"));
  }
  Frame frame{.type = static_cast<std::uint8_t>(type),
              .channel_id = 0U,
              .message_id = random_message_id(),
              .payload = std::vector<std::byte>{payload.begin(), payload.end()}};
  auto encoded = encode_frame(frame);
  if (!encoded) return Result<void>::failure(*encoded.error_if());
  auto sent = control_->send(*encoded.value_if());
  if (!sent) return Result<void>::failure(*sent.error_if());
  ++diagnostics_.restart_frames_sent;
  notify();
  return Result<void>::success();
}

void PeerSession::handle_message(transport::TransportChannel& channel,
                                 std::vector<std::byte> payload) {
  if (channel.kind() != transport::ChannelKind::control) {
    ++diagnostics_.business_frames_rejected;
    notify();
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
    if (config_.timeline &&
        config_.timeline->stage() != ConnectionStage::authenticating) {
      if (config_.timeline->stage() != ConnectionStage::transport_connected) {
        auto recorded = record(ConnectionStage::transport_connected, "peer_session",
                               "inbound_control_channel_ready");
        if (!recorded) {
          fail(*recorded.error_if());
          return;
        }
      }
      auto recorded = record(ConnectionStage::authenticating, "peer_session",
                             "session_hello_received");
      if (!recorded) {
        fail(*recorded.error_if());
        return;
      }
    }
    auto admitted = admission_->admit(frame.payload, config_.now_unix_milliseconds);
    if (!admitted) {
      fail(*admitted.error_if());
      return;
    }
    ++diagnostics_.hellos_received;
    if (admitted.value_if()->action == SessionHelloAdmissionAction::accepted) {
      diagnostics_.negotiated_capabilities =
          admitted.value_if()->negotiated_protocol.value_or(NegotiatedProtocol{})
              .capabilities;
      if (diagnostics_.hellos_sent == 0U) {
        auto sent = send_hello(channel);
        if (!sent) {
          fail(*sent.error_if());
          return;
        }
      }
      auto recorded = record(ConnectionStage::authenticated, "peer_session",
                             "session_hello_verified");
      if (!recorded) {
        fail(*recorded.error_if());
        return;
      }
      diagnostics_.state = PeerSessionState::authenticated;
      notify();
    }
    return;
  }
  if (frame.type == static_cast<std::uint8_t>(FrameType::session_restart_offer) ||
      frame.type == static_cast<std::uint8_t>(FrameType::session_restart_answer) ||
      frame.type == static_cast<std::uint8_t>(FrameType::session_restart_candidate)) {
    // Restart frames are optional protocol-1.2 control frames: without a
    // handler they are skipped like any unknown optional frame; with one the
    // Node's restart admission owns verification.
    ++diagnostics_.restart_frames_received;
    if (diagnostics_.state != PeerSessionState::authenticated) {
      fail(session_error(ErrorCode::authentication, "restart_frame_before_hello"));
      return;
    }
    if (frame.type == static_cast<std::uint8_t>(FrameType::session_restart_offer) &&
        restart_handler_.on_restart_offer) {
      restart_handler_.on_restart_offer(
          std::vector<std::byte>{frame.payload.begin(), frame.payload.end()});
    } else if (frame.type == static_cast<std::uint8_t>(FrameType::session_restart_answer) &&
               restart_handler_.on_restart_answer) {
      restart_handler_.on_restart_answer(
          std::vector<std::byte>{frame.payload.begin(), frame.payload.end()});
    } else if (frame.type ==
                   static_cast<std::uint8_t>(FrameType::session_restart_candidate) &&
               restart_handler_.on_restart_candidate) {
      restart_handler_.on_restart_candidate(
          std::vector<std::byte>{frame.payload.begin(), frame.payload.end()});
    }
    notify();
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
    notify();
    return;
  }
  if (frame.type == static_cast<std::uint8_t>(FrameType::pong) &&
      diagnostics_.state == PeerSessionState::authenticated && frame.payload.size() == 8U &&
      pending_ping_ == decode_ping_payload(frame.payload)) {
    pending_ping_.reset();
    ++diagnostics_.pongs_received;
    notify();
    return;
  }
  if (diagnostics_.state != PeerSessionState::authenticated) {
    fail(session_error(ErrorCode::authentication, "control_frame_before_hello"));
  }
}

void PeerSession::fail(Error error) {
  diagnostics_.last_error = error;
  diagnostics_.state = PeerSessionState::closed;
  (void)record(ConnectionStage::closed, "peer_session", error.safe_detail());
  notify();
  if (config_.transport) config_.transport->close(transport::CloseReason::protocol_error);
}

PeerSessionDiagnostics PeerSession::diagnostics() const noexcept { return diagnostics_; }

bool PeerSession::authenticated() const noexcept {
  return diagnostics_.state == PeerSessionState::authenticated;
}

void PeerSession::close(transport::CloseReason reason) {
  if (diagnostics_.state == PeerSessionState::closed) return;
  diagnostics_.state = PeerSessionState::closed;
  auto recorded =
      record(ConnectionStage::closed, "peer_session", transport::close_reason_name(reason));
  if (!recorded) diagnostics_.last_error = *recorded.error_if();
  notify();
  if (config_.transport) config_.transport->close(reason);
}

void PeerSession::notify() const {
  if (config_.observer) config_.observer(diagnostics_);
}

Result<void> PeerSession::record(ConnectionStage stage, std::string_view source,
                                 std::string_view reason) {
  if (!config_.timeline || config_.timeline->stage() == stage ||
      config_.timeline->stage() == ConnectionStage::closed) {
    return Result<void>::success();
  }
  const auto timestamp = config_.clock ? config_.clock() : std::chrono::steady_clock::now();
  return config_.timeline->transition(stage, source, reason, timestamp);
}

}  // namespace heyaki
