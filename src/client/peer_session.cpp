#include "peer_session.hpp"

#include <heyaki/wire.hpp>

#include <sodium/randombytes.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <map>
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

RequestId random_request_id() {
  RequestId::Storage bytes{};
  do {
    randombytes_buf(bytes.data(), bytes.size());
  } while (RequestId{bytes}.is_zero());
  return RequestId{bytes};
}

PairingNonce random_pairing_nonce() {
  PairingNonce nonce{};
  do {
    randombytes_buf(nonce.data(), nonce.size());
  } while (std::all_of(nonce.begin(), nonce.end(),
                       [](std::byte byte) { return byte == std::byte{0}; }));
  return nonce;
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

transport::ChannelKind physical_kind_for_domain(session::ChannelDomain domain) {
  switch (domain) {
    case session::ChannelDomain::control:
      return transport::ChannelKind::control;
    case session::ChannelDomain::message:
      return transport::ChannelKind::message;
    case session::ChannelDomain::rpc:
      return transport::ChannelKind::rpc;
    case session::ChannelDomain::event:
      return transport::ChannelKind::event;
    case session::ChannelDomain::file:
      return transport::ChannelKind::file;
    case session::ChannelDomain::shell:
      return transport::ChannelKind::shell;
    case session::ChannelDomain::stream:
      return transport::ChannelKind::stream;
  }
  return transport::ChannelKind::message;
}

// The negotiated capability bit a business domain requires before its frames
// may flow (M5-06): a parseable schema alone never enables behavior.
std::optional<Capability> capability_for_domain(session::ChannelDomain domain) {
  switch (domain) {
    case session::ChannelDomain::control:
      return Capability::session;
    case session::ChannelDomain::message:
      return Capability::message;
    case session::ChannelDomain::rpc:
      return Capability::unary_rpc;
    case session::ChannelDomain::event:
      return Capability::event;
    case session::ChannelDomain::file:
      return Capability::file;
    case session::ChannelDomain::shell:
      return Capability::shell;
    case session::ChannelDomain::stream:
      return Capability::byte_stream;
  }
  return std::nullopt;
}

}  // namespace

PeerSession::PeerSession(PeerSessionConfig config) : config_(std::move(config)) {
  admission_ = std::make_unique<SessionHelloAdmission>(
      config_.expectation, config_.peer_public_key, config_.local_protocol);
  auto budgets = config_.channel_budgets;
  channels_ =
      std::make_unique<session::SessionChannelManager>(budgets, config_.limits);
  pairing_admission_ = std::make_unique<PairingRequestAdmission>(config_.limits);
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
  auto budgets_valid = session::validate_channel_budget_config(config.channel_budgets);
  if (!budgets_valid) {
    return Result<std::shared_ptr<PeerSession>>::failure(*budgets_valid.error_if());
  }
  if (config.pairing_deadline <= std::chrono::milliseconds::zero()) {
    return Result<std::shared_ptr<PeerSession>>::failure(
        session_error(ErrorCode::configuration, "pairing_deadline_invalid"));
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
                 .clock = std::move(config.clock),
                 .trust_authorizer = std::move(config.trust_authorizer),
                 .pairing_evaluator = std::move(config.pairing_evaluator),
                 .pairing_result_sink = std::move(config.pairing_result_sink),
                 .limits = config.limits,
                 .channel_budgets = config.channel_budgets,
                 .pairing_deadline = config.pairing_deadline,
                 .wall_clock = std::move(config.wall_clock)});
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
        self->physical_channels_[session::ChannelDomain::control] = self->control_;
        self->control_->set_writable_handler([weak] {
          if (auto self = weak.lock()) self->pump();
        });
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
  auto sent = enqueue_control_frame(static_cast<std::uint8_t>(FrameType::session_hello),
                                    0U, std::move(*payload.value_if()));
  if (!sent) return sent;
  (void)channel;
  ++diagnostics_.hellos_sent;
  notify();
  return Result<void>::success();
}

Result<void> PeerSession::enqueue_control_frame(std::uint8_t type, std::uint8_t flags,
                                                std::vector<std::byte> payload) {
  if (control_ == nullptr) {
    return Result<void>::failure(
        session_error(ErrorCode::permission, "control_channel_not_ready"));
  }
  Frame frame{.type = type,
              .flags = flags,
              .channel_id = 0U,
              .message_id = random_message_id(),
              .payload = std::move(payload)};
  auto valid_limits = encode_frame(frame, config_.limits);
  if (!valid_limits) return Result<void>::failure(*valid_limits.error_if());
  auto enqueued =
      channels_->enqueue(0U, session::FrameClass::control, std::move(frame));
  if (!enqueued) return Result<void>::failure(*enqueued.error_if());
  pump();
  return Result<void>::success();
}

Result<void> PeerSession::send_ping(std::uint64_t ping_id) {  // Observer reentrancy guard: a send can fail the session synchronously,
  // and the Node observer may drop the last external reference (retiring the
  // attempt) while this call is still on the stack. Holding a strong
  // reference for the duration of every public entry point keeps the object
  // alive until the call returns. These methods are never invoked from the
  // destructor.
  const auto self_guard = shared_from_this();

  if (!authenticated() || control_ == nullptr || pending_ping_.has_value()) {
    return Result<void>::failure(
        session_error(ErrorCode::permission, "control_ping_not_available"));
  }
  auto sent = enqueue_control_frame(static_cast<std::uint8_t>(FrameType::ping), 0U,
                                    encode_ping_payload(ping_id));
  if (!sent) return sent;
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
                                             std::span<const std::byte> payload) {  // Observer reentrancy guard: a send can fail the session synchronously,
  // and the Node observer may drop the last external reference (retiring the
  // attempt) while this call is still on the stack. Holding a strong
  // reference for the duration of every public entry point keeps the object
  // alive until the call returns. These methods are never invoked from the
  // destructor.
  const auto self_guard = shared_from_this();

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
  auto sent = enqueue_control_frame(static_cast<std::uint8_t>(type), 0U,
                                    std::vector<std::byte>{payload.begin(), payload.end()});
  if (!sent) return sent;
  ++diagnostics_.restart_frames_sent;
  notify();
  return Result<void>::success();
}

bool PeerSession::authenticated() const noexcept {
  return diagnostics_.state == PeerSessionState::authenticated ||
         diagnostics_.state == PeerSessionState::active;
}

bool PeerSession::pairing_restricted() const noexcept {
  return diagnostics_.state == PeerSessionState::pairing_restricted;
}

const std::vector<std::string>& PeerSession::authorized_scopes() const noexcept {
  return diagnostics_.authorized_scopes;
}

const session::SessionChannelManager& PeerSession::channels() const noexcept {
  return *channels_;
}

std::uint64_t PeerSession::wall_clock_now() const {
  if (config_.wall_clock) return config_.wall_clock();
  return config_.now_unix_milliseconds;
}

Result<void> PeerSession::enforce_pairing_deadline() {
  if (!restricted_since_.has_value()) return Result<void>::success();
  const auto now = wall_clock_now();
  if (now < *restricted_since_) return Result<void>::success();
  if (now - *restricted_since_ >
      static_cast<std::uint64_t>(config_.pairing_deadline.count())) {
    return Result<void>::failure(
        session_error(ErrorCode::timeout, "pairing_deadline_exceeded"));
  }
  return Result<void>::success();
}

void PeerSession::upgrade_to_authorized(std::vector<std::string> scopes,
                                        std::string_view reason) {
  diagnostics_.authorized_scopes = std::move(scopes);
  diagnostics_.pairing_restricted = false;
  restricted_since_.reset();
  auto recorded = record(ConnectionStage::authenticated, "peer_session", reason);
  if (!recorded) diagnostics_.last_error = *recorded.error_if();
  diagnostics_.state = PeerSessionState::authenticated;
  notify();
}

void PeerSession::handle_message(transport::TransportChannel& channel,
                                 std::vector<std::byte> payload) {  // Observer reentrancy guard: a send can fail the session synchronously,
  // and the Node observer may drop the last external reference (retiring the
  // attempt) while this call is still on the stack. Holding a strong
  // reference for the duration of every public entry point keeps the object
  // alive until the call returns. These methods are never invoked from the
  // destructor.
  const auto self_guard = shared_from_this();

  auto parsed = parse_frame(payload, config_.limits);
  if (parsed.status != FrameParseStatus::parsed || !parsed.frame ||
      parsed.consumed != payload.size()) {
    if (channel.kind() == transport::ChannelKind::control) {
      fail(session_error(ErrorCode::protocol, "control_frame_invalid"));
    } else {
      note_business_violation(channel);
    }
    return;
  }
  if (channel.kind() == transport::ChannelKind::control) {
    handle_control_frame(channel, *parsed.frame);
  } else {
    handle_business_frame(channel, *parsed.frame);
  }
}

void PeerSession::note_business_violation(transport::TransportChannel& channel) {
  ++diagnostics_.business_frames_rejected;
  ++business_violations_;
  notify();
  // First violation closes only the offending channel (M5-06: one bad
  // optional protocol must not kill the session); repeats close the session
  // (wire protocol 6.1).
  if (business_violations_ >= 2U) {
    fail(session_error(ErrorCode::permission, "business_frames_not_authorized"));
    return;
  }
  channel.close(transport::CloseReason::protocol_error);
}

void PeerSession::handle_control_frame(transport::TransportChannel& channel,
                                       FrameView frame) {
  const auto type = static_cast<FrameType>(frame.type);
  if (type == FrameType::session_hello) {
    control_ = &channel;
    physical_channels_[session::ChannelDomain::control] = control_;
    control_->set_writable_handler([weak = weak_from_this()] {
      if (auto self = weak.lock()) self->pump();
    });
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
      if (config_.trust_authorizer) {
        auto authorization = config_.trust_authorizer(wall_clock_now());
        if (!authorization) {
          fail(*authorization.error_if());
          return;
        }
        const auto& trust = *authorization.value_if();
        if (trust.trusted) {
          upgrade_to_authorized(trust.scopes, "session_authorized");
        } else {
          // RULE-03: an untrusted peer may only pair, within strict caps.
          if (!diagnostics_.negotiated_capabilities.has(Capability::pairing)) {
            fail(session_error(ErrorCode::pairing_denied, "pairing_capability_absent"));
            return;
          }
          diagnostics_.state = PeerSessionState::pairing_restricted;
          diagnostics_.pairing_restricted = true;
          diagnostics_.authorized_scopes.clear();
          restricted_since_ = wall_clock_now();
          notify();
        }
      } else {
        // Legacy M4 semantics: hello-verified equals authorized.
        upgrade_to_authorized({}, "session_hello_verified");
      }
    }
    return;
  }
  if (type == FrameType::pairing_request) {
    handle_pairing_request(frame);
    return;
  }
  if (type == FrameType::pairing_result) {
    handle_pairing_result(frame);
    return;
  }
  if (type == FrameType::session_restart_offer ||
      type == FrameType::session_restart_answer ||
      type == FrameType::session_restart_candidate) {
    // Restart frames are optional protocol-1.2 control frames: without a
    // handler they are skipped like any unknown optional frame; with one the
    // Node's restart admission owns verification.
    ++diagnostics_.restart_frames_received;
    if (!authenticated()) {
      fail(session_error(ErrorCode::authentication, "restart_frame_before_hello"));
      return;
    }
    if (type == FrameType::session_restart_offer && restart_handler_.on_restart_offer) {
      restart_handler_.on_restart_offer(
          std::vector<std::byte>{frame.payload.begin(), frame.payload.end()});
    } else if (type == FrameType::session_restart_answer &&
               restart_handler_.on_restart_answer) {
      restart_handler_.on_restart_answer(
          std::vector<std::byte>{frame.payload.begin(), frame.payload.end()});
    } else if (type == FrameType::session_restart_candidate &&
               restart_handler_.on_restart_candidate) {
      restart_handler_.on_restart_candidate(
          std::vector<std::byte>{frame.payload.begin(), frame.payload.end()});
    }
    notify();
    return;
  }
  if (type == FrameType::ping && authenticated() && frame.payload.size() == 8U) {
    auto sent = enqueue_control_frame(static_cast<std::uint8_t>(FrameType::pong), 0U,
                                      std::vector<std::byte>{frame.payload.begin(),
                                                             frame.payload.end()});
    if (!sent) {
      fail(session_error(ErrorCode::transport, "pong_send_failed"));
      return;
    }
    ++diagnostics_.pings_received;
    ++diagnostics_.pongs_sent;
    notify();
    return;
  }
  if (type == FrameType::pong && authenticated() && frame.payload.size() == 8U &&
      pending_ping_ == decode_ping_payload(frame.payload)) {
    pending_ping_.reset();
    ++diagnostics_.pongs_received;
    notify();
    return;
  }
  if (type == FrameType::ping || type == FrameType::pong) {
    // Liveness frames outside an authenticated session are counted and
    // ignored; they carry no state.
    notify();
    return;
  }
  if (type == FrameType::protocol_close) {
    close(transport::CloseReason::peer_closed);
    return;
  }
  if (diagnostics_.state != PeerSessionState::authenticated &&
      diagnostics_.state != PeerSessionState::active &&
      diagnostics_.state != PeerSessionState::pairing_restricted) {
    fail(session_error(ErrorCode::authentication, "control_frame_before_hello"));
  }
}

void PeerSession::handle_pairing_request(FrameView frame) {
  // M5-07/M5-08: pairing frames only exist inside an identity-verified,
  // fingerprint-bound session that is still untrusted.
  if (!authenticated() && diagnostics_.state != PeerSessionState::pairing_restricted) {
    fail(session_error(ErrorCode::authentication, "pairing_frame_before_hello"));
    return;
  }
  if (authenticated()) {
    // Already authorized peers have no business pairing; count and ignore.
    ++diagnostics_.pairing_requests_received;
    notify();
    return;
  }
  ++diagnostics_.pairing_requests_received;
  auto deny_and_close = [this](RequestId request_id, StableStatus status,
                               ErrorCode close_code, const char* close_detail) {
    PairingResultBody denied;
    denied.request_id = request_id;
    denied.status = status;
    auto encoded = encode_pairing_result(denied);
    if (encoded) {
      (void)enqueue_control_frame(static_cast<std::uint8_t>(FrameType::pairing_result),
                                  0U, std::move(*encoded.value_if()));
    }
    fail(Error{close_code, "peer_session", close_detail});
  };
  if (frame.payload.size() > config_.limits.max_pairing_payload_bytes) {
    fail(session_error(ErrorCode::protocol, "pairing_payload_limit"));
    return;
  }
  auto parsed = parse_pairing_request(frame.payload);
  if (!parsed) {
    fail(*parsed.error_if());
    return;
  }
  const auto& request = *parsed.value_if();
  auto deadline = enforce_pairing_deadline();
  if (!deadline) {
    deny_and_close(request.request_id, StableStatus::deadline_exceeded,
                   ErrorCode::pairing_denied, "pairing_deadline_exceeded");
    return;
  }
  auto admission = pairing_admission_->admit_request(request);
  if (!admission) {
    // Attempts exhausted or a conflicting duplicate: stable rate-limited
    // denial, then close (M5-14).
    deny_and_close(request.request_id, StableStatus::resource_exhausted,
                   admission.error_if()->code(), "pairing_rate_limited");
    return;
  }
  if (admission.value_if()->action == PairingAdmissionAction::duplicate &&
      admission.value_if()->cached_result.has_value()) {
    // Byte-identical retransmission replays the terminal result.
    auto encoded = encode_pairing_result(*admission.value_if()->cached_result);
    if (!encoded) {
      fail(*encoded.error_if());
      return;
    }
    auto sent = enqueue_control_frame(
        static_cast<std::uint8_t>(FrameType::pairing_result), 0U,
        std::move(*encoded.value_if()));
    if (!sent) fail(*sent.error_if());
    return;
  }
  if (!config_.pairing_evaluator) {
    // Pairing disabled on this target: stable denial and close (M5-14).
    deny_and_close(request.request_id, StableStatus::permission_denied,
                   ErrorCode::pairing_denied, "pairing_disabled");
    return;
  }
  auto evaluated = config_.pairing_evaluator(request);
  PairingResultBody result;
  result.request_id = request.request_id;
  if (!evaluated) {
    result.status = status_for_error(*evaluated.error_if());
    if (result.status == StableStatus::ok) {
      result.status = StableStatus::internal;
    }
  } else {
    result = std::move(*evaluated.value_if());
    result.request_id = request.request_id;
  }
  auto recorded = pairing_admission_->record_result(result);
  if (!recorded) {
    fail(*recorded.error_if());
    return;
  }
  auto encoded = encode_pairing_result(result);
  if (!encoded) {
    fail(*encoded.error_if());
    return;
  }
  auto sent = enqueue_control_frame(static_cast<std::uint8_t>(FrameType::pairing_result),
                                    0U, std::move(*encoded.value_if()));
  if (!sent) {
    fail(*sent.error_if());
    return;
  }
  ++diagnostics_.pairing_results_sent;
  if (result.status == StableStatus::ok && result.grant.has_value()) {
    // Target side upgrade: the peer now holds a signed grant for the
    // intersection scopes.
    upgrade_to_authorized(result.grant->granted_scopes, "session_authorized");
    return;
  }
  // Terminal denial: wrong password, policy refusal, or rate limit close the
  // restricted session with a stable AUTH_DENIED code (M5-14).
  notify();
  fail(Error{ErrorCode::pairing_denied, "peer_session", "pairing_denied"});
}

void PeerSession::handle_pairing_result(FrameView frame) {
  if (!pending_pairing_.has_value()) {
    fail(session_error(ErrorCode::protocol, "pairing_result_unexpected"));
    return;
  }
  if (diagnostics_.state != PeerSessionState::pairing_restricted) {
    fail(session_error(ErrorCode::protocol, "pairing_result_outside_restricted"));
    return;
  }
  auto parsed = parse_pairing_result(frame.payload);
  if (!parsed) {
    fail(*parsed.error_if());
    return;
  }
  auto& result = *parsed.value_if();
  if (result.request_id != pending_pairing_->first) {
    fail(session_error(ErrorCode::protocol, "pairing_result_request_mismatch"));
    return;
  }
  ++diagnostics_.pairing_results_received;
  if (result.status == StableStatus::ok && result.grant.has_value()) {
    if (!config_.pairing_result_sink) {
      fail(session_error(ErrorCode::configuration, "pairing_result_sink_missing"));
      return;
    }
    auto accepted = config_.pairing_result_sink(
        result, pending_pairing_->first, pending_pairing_->second,
        pending_pairing_scopes_);
    if (!accepted) {
      fail(*accepted.error_if());
      return;
    }
    auto scopes = result.grant->granted_scopes;
    pending_pairing_.reset();
    upgrade_to_authorized(std::move(scopes), "session_authorized");
    return;
  }
  pending_pairing_.reset();
  notify();
  // Stable AUTH_DENIED close for denied / rate-limited / expired attempts.
  fail(Error{ErrorCode::pairing_denied, "peer_session", "pairing_denied"});
}

StableStatus PeerSession::status_for_error(const Error& error) const noexcept {
  switch (error.code()) {
    case ErrorCode::pairing_rate_limited:
    case ErrorCode::resource_exhausted:
      return StableStatus::resource_exhausted;
    case ErrorCode::pairing_denied:
    case ErrorCode::permission:
      return StableStatus::permission_denied;
    case ErrorCode::authentication:
    case ErrorCode::pairing_required:
      return StableStatus::unauthenticated;
    case ErrorCode::timeout:
      return StableStatus::deadline_exceeded;
    case ErrorCode::cancelled:
      return StableStatus::cancelled;
    default:
      return StableStatus::internal;
  }
}

Result<void> PeerSession::submit_pairing_request(
    std::string_view password_utf8, std::vector<std::string> requested_scopes) {  // Observer reentrancy guard: a send can fail the session synchronously,
  // and the Node observer may drop the last external reference (retiring the
  // attempt) while this call is still on the stack. Holding a strong
  // reference for the duration of every public entry point keeps the object
  // alive until the call returns. These methods are never invoked from the
  // destructor.
  const auto self_guard = shared_from_this();

  if (diagnostics_.state != PeerSessionState::pairing_restricted) {
    return Result<void>::failure(
        session_error(ErrorCode::pairing_required, "session_not_pairing_restricted"));
  }
  if (pending_pairing_.has_value()) {
    return Result<void>::failure(
        session_error(ErrorCode::pairing_required, "pairing_request_in_flight"));
  }
  auto deadline = enforce_pairing_deadline();
  if (!deadline) return deadline;
  if (!diagnostics_.negotiated_capabilities.has(Capability::pairing)) {
    return Result<void>::failure(
        session_error(ErrorCode::pairing_denied, "pairing_capability_absent"));
  }
  PairingRequestBody request;
  request.request_id = random_request_id();
  request.nonce = random_pairing_nonce();
  request.password_utf8 = std::string{password_utf8};
  request.requested_scopes = std::move(requested_scopes);
  auto encoded = encode_pairing_request(request);
  if (!encoded) return Result<void>::failure(*encoded.error_if());
  auto sent = enqueue_control_frame(static_cast<std::uint8_t>(FrameType::pairing_request),
                                    0U, std::move(*encoded.value_if()));
  if (!sent) return sent;
  pending_pairing_ = std::make_pair(request.request_id, request.nonce);
  pending_pairing_scopes_ = request.requested_scopes;
  ++diagnostics_.pairing_requests_sent;
  notify();
  return Result<void>::success();
}

Result<std::uint32_t> PeerSession::open_business_channel(
    session::ChannelDomain domain, session::QueueFullPolicy policy,
    std::size_t queued_frame_capacity, std::size_t queued_byte_capacity,
    BusinessFrameHandler handler) {
  // M5-14: business channels exist only after session authorization.
  if (!authenticated()) {
    return Result<std::uint32_t>::failure(
        session_error(ErrorCode::pairing_required, "session_not_authorized"));
  }
  if (diagnostics_.state == PeerSessionState::pairing_restricted) {
    return Result<std::uint32_t>::failure(
        session_error(ErrorCode::pairing_required, "session_not_authorized"));
  }
  const auto required_capability = capability_for_domain(domain);
  if (required_capability.has_value() &&
      !diagnostics_.negotiated_capabilities.has(*required_capability)) {
    return Result<std::uint32_t>::failure(
        session_error(ErrorCode::protocol, "domain_capability_not_negotiated"));
  }
  auto allocated = channels_->allocate_channel(config_.initiator, domain, policy,
                                               queued_frame_capacity,
                                               queued_byte_capacity);
  if (!allocated) {
    return Result<std::uint32_t>::failure(*allocated.error_if());
  }
  channel_handlers_.emplace(*allocated.value_if(), std::move(handler));
  ensure_physical_channel(domain);
  if (diagnostics_.state == PeerSessionState::authenticated) {
    diagnostics_.state = PeerSessionState::active;
    notify();
  }
  return allocated;
}

void PeerSession::close_business_channel(std::uint32_t channel_id) {
  channels_->close_channel(channel_id);
  channel_handlers_.erase(channel_id);
}

Result<std::uint32_t> PeerSession::adopt_business_channel(
    std::uint32_t channel_id, session::ChannelDomain domain,
    session::QueueFullPolicy policy, std::size_t queued_frame_capacity,
    std::size_t queued_byte_capacity, BusinessFrameHandler handler) {
  if (!authenticated()) {
    return Result<std::uint32_t>::failure(
        session_error(ErrorCode::pairing_required, "session_not_authorized"));
  }
  auto opened = channels_->open_channel(channel_id, domain, policy,
                                        queued_frame_capacity, queued_byte_capacity);
  if (!opened) {
    return Result<std::uint32_t>::failure(*opened.error_if());
  }
  channel_handlers_.emplace(channel_id, std::move(handler));
  ensure_physical_channel(domain);
  return Result<std::uint32_t>::success(channel_id);
}

void PeerSession::set_domain_handler(session::ChannelDomain domain,
                                     DomainFrameHandler handler) {
  if (handler) {
    domain_handlers_[domain] = std::move(handler);
  } else {
    domain_handlers_.erase(domain);
  }
}

bool PeerSession::has_business_channel(std::uint32_t channel_id) const noexcept {
  return channels_->has_channel(channel_id);
}

Result<void> PeerSession::send_frame(std::uint32_t channel_id,
                                     session::FrameClass klass, Frame frame) {  // Observer reentrancy guard: a send can fail the session synchronously,
  // and the Node observer may drop the last external reference (retiring the
  // attempt) while this call is still on the stack. Holding a strong
  // reference for the duration of every public entry point keeps the object
  // alive until the call returns. These methods are never invoked from the
  // destructor.
  const auto self_guard = shared_from_this();

  if (!authenticated()) {
    return Result<void>::failure(
        session_error(ErrorCode::pairing_required, "session_not_authorized"));
  }
  if (frame.message_id.is_zero()) frame.message_id = random_message_id();
  if (frame.channel_id == 0U) frame.channel_id = channel_id;
  ensure_physical_channel(session::frame_type_domain(frame.type).value_or(
      session::ChannelDomain::message));
  auto enqueued = channels_->enqueue(channel_id, klass, std::move(frame));
  if (!enqueued) return Result<void>::failure(*enqueued.error_if());
  pump();
  return Result<void>::success();
}

transport::TransportChannel* PeerSession::physical_channel_for_domain(
    session::ChannelDomain domain) {
  auto found = physical_channels_.find(domain);
  if (found == physical_channels_.end()) return nullptr;
  return found->second;
}

void PeerSession::ensure_physical_channel(session::ChannelDomain domain) {
  if (domain == session::ChannelDomain::control || physical_channels_.contains(domain)) {
    return;
  }
  transport::ChannelOptions options;
  switch (domain) {
    case session::ChannelDomain::file:
    case session::ChannelDomain::stream:
      options.priority = transport::ChannelPriority::bulk;
      options.send_queue_bytes = 1024U * 1024U;
      options.max_message_bytes = 1024U * 1024U;
      break;
    case session::ChannelDomain::shell:
      options.priority = transport::ChannelPriority::interactive;
      options.send_queue_bytes = 128U * 1024U;
      options.max_message_bytes = 256U * 1024U;
      break;
    default:
      options.priority = transport::ChannelPriority::standard;
      options.send_queue_bytes = 256U * 1024U;
      options.max_message_bytes = 1024U * 1024U;
      break;
  }
  auto weak = weak_from_this();
  config_.transport->async_open_channel(
      physical_kind_for_domain(domain), options,
      [weak, domain](Result<transport::TransportChannel*> result) {
        auto self = weak.lock();
        if (!self) return;
        if (!result) {
          self->fail(*result.error_if());
          return;
        }
        self->physical_channels_[domain] = *result.value_if();
        (*result.value_if())->set_writable_handler([weak] {
          if (auto self = weak.lock()) self->pump();
        });
        self->pump();
      });
}

void PeerSession::handle_business_frame(transport::TransportChannel& channel,
                                        FrameView frame) {
  if (!authenticated()) {
    note_business_violation(channel);
    return;
  }
  const auto action = unknown_frame_action(frame);
  if (action == UnknownFrameAction::close_channel) {
    // Unknown REQUIRED frame: close its logical channel only.
    channels_->close_channel(frame.channel_id);
    channel_handlers_.erase(frame.channel_id);
    ++diagnostics_.business_frames_rejected;
    notify();
    channel.close(transport::CloseReason::protocol_error);
    return;
  }
  if (action == UnknownFrameAction::skip) {
    // Unknown optional frames never change state.
    notify();
    return;
  }
  auto handler = channel_handlers_.find(frame.channel_id);
  if (handler == channel_handlers_.end()) {
    // Unknown logical channel: give the domain handler a chance to admit a
    // peer-initiated channel before treating the frame as stray.
    const auto domain = session::frame_type_domain(frame.type);
    if (domain.has_value()) {
      auto domain_handler = domain_handlers_.find(*domain);
      if (domain_handler != domain_handlers_.end()) {
        auto admitted = domain_handler->second(frame);
        if (!admitted) {
          ++diagnostics_.business_frames_rejected;
          notify();
          channel.close(transport::CloseReason::protocol_error);
          return;
        }
        if (diagnostics_.state == PeerSessionState::authenticated) {
          diagnostics_.state = PeerSessionState::active;
        }
        notify();
        return;
      }
    }
    // No logical channel registered for this id: drop and count without
    // touching session state (M5-06).
    ++diagnostics_.business_frames_rejected;
    notify();
    return;
  }
  if (diagnostics_.state == PeerSessionState::authenticated) {
    diagnostics_.state = PeerSessionState::active;
  }
  handler->second(frame);
  notify();
}

void PeerSession::pump() {  // Observer reentrancy guard: a send can fail the session synchronously,
  // and the Node observer may drop the last external reference (retiring the
  // attempt) while this call is still on the stack. Holding a strong
  // reference for the duration of every public entry point keeps the object
  // alive until the call returns. These methods are never invoked from the
  // destructor.
  const auto self_guard = shared_from_this();

  while (channels_->has_sendable_frames()) {
    auto next = channels_->next_to_send();
    if (!next.has_value()) return;
    auto& queued = *next;
    transport::TransportChannel* physical = nullptr;
    if (queued.frame_class == session::FrameClass::control &&
        session::is_control_domain_frame_type(queued.frame.type)) {
      physical = control_;
    } else {
      const auto domain = session::frame_type_domain(queued.frame.type);
      if (!domain.has_value()) {
        channels_->close_channel(queued.channel_id);
        continue;
      }
      physical = physical_channel_for_domain(*domain);
    }
    if (physical == nullptr) {
      // Physical channel still opening; wait for its completion to pump.
      channels_->return_to_send(std::move(queued));
      return;
    }
    auto encoded = encode_frame(queued.frame, config_.limits);
    if (!encoded) {
      channels_->close_channel(queued.channel_id);
      fail(*encoded.error_if());
      return;
    }
    auto sent = physical->send(*encoded.value_if());
    if (!sent) {
      if (sent.error_if()->code() == ErrorCode::would_block) {
        // Backpressure: keep the frame queued in its class with budgets
        // intact; the transport's writable callback re-triggers the pump.
        channels_->return_to_send(std::move(queued));
        return;
      }
      channels_->close_channel(queued.channel_id);
      fail(*sent.error_if());
      return;
    }
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
