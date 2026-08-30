#include "message_service.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <utility>

namespace heyaki {
namespace {

constexpr std::size_t envelope_digest_bytes = 32U;

MessageId random_message_id() {
  MessageId::Storage bytes{};
  do {
    randombytes_buf(bytes.data(), bytes.size());
  } while (MessageId{bytes}.is_zero());
  return MessageId{bytes};
}

std::vector<std::byte> envelope_digest(std::span<const std::byte> encoded) {
  std::array<unsigned char, envelope_digest_bytes> digest{};
  crypto_hash_sha256(digest.data(), reinterpret_cast<const unsigned char*>(encoded.data()),
                     encoded.size());
  std::vector<std::byte> output(digest.size());
  for (std::size_t index = 0U; index < digest.size(); ++index) {
    output[index] = static_cast<std::byte>(digest[index]);
  }
  return output;
}

Error message_service_error(ErrorCode code, std::string_view detail) {
  return Error{code, "message", std::string{detail}};
}

}  // namespace

MessageService::MessageService(PeerSession& session, DeviceEndpointKey peer,
                               MessageServiceConfig config,
                               ServiceDispatch dispatch, ScopeCheck scope_check,
                               std::function<std::uint64_t()> wall_clock)
    : session_(session),
      peer_(std::move(peer)),
      config_(config),
      dispatch_(std::move(dispatch)),
      scope_check_(std::move(scope_check)),
      wall_clock_(std::move(wall_clock)) {}

MessageService::~MessageService() {
  session_.set_domain_handler(session::ChannelDomain::message, DomainFrameHandler{});
  for (const auto channel : owned_channels_) {
    session_.close_business_channel(channel);
  }
  // In-flight handler tasks finish on their own DispatchRecord copies; their
  // deltas are dropped because the service and its counters are gone.
}

std::uint64_t MessageService::now() const {
  if (wall_clock_) return wall_clock_();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

Result<void> MessageService::attach() {
  if (attached_) {
    return Result<void>::success();
  }
  if (config_.dedup_capacity == 0U || config_.pending_ack_capacity == 0U ||
      config_.channel_frame_capacity == 0U || config_.channel_byte_capacity == 0U) {
    return Result<void>::failure(
        message_service_error(ErrorCode::configuration, "message_config_invalid"));
  }
  if (!dispatch_) {
    return Result<void>::failure(
        message_service_error(ErrorCode::configuration, "dispatch_missing"));
  }
  auto weak = weak_from_this();
  auto opened = session_.open_business_channel(
      session::ChannelDomain::message, session::QueueFullPolicy::reject,
      config_.channel_frame_capacity, config_.channel_byte_capacity,
      [weak](const FrameView& frame) {
        if (auto self = weak.lock()) self->handle_frame(frame);
      });
  if (!opened) return Result<void>::failure(*opened.error_if());
  channel_id_ = *opened.value_if();
  owned_channels_.push_back(channel_id_);
  session_.set_domain_handler(
      session::ChannelDomain::message,
      [weak](const FrameView& frame) -> Result<void> {
        auto self = weak.lock();
        if (!self) {
          return Result<void>::failure(
              message_service_error(ErrorCode::cancelled, "service_detached"));
        }
        return self->admit_frame(frame);
      });
  attached_ = true;
  return Result<void>::success();
}

Result<MessageId> MessageService::send(MessageEnvelope envelope) {
  if (!attached_) {
    return Result<MessageId>::failure(
        message_service_error(ErrorCode::configuration, "service_not_attached"));
  }
  if (envelope.message_id.is_zero()) {
    envelope.message_id = random_message_id();
  }
  const auto id = envelope.message_id;
  auto encoded = encode_message_envelope(envelope, session_.channels().limits());
  if (!encoded) {
    ++stats_.send_rejected;
    observe_ack(id, MessageDeliveryEvent::send_failed, *encoded.error_if());
    return Result<MessageId>::failure(*encoded.error_if());
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::message);
  frame.channel_id = channel_id_;
  frame.payload = std::move(*encoded.value_if());
  const auto sent = session_.send_frame(channel_id_, session::FrameClass::standard,
                                        std::move(frame));
  if (!sent) {
    // Admission failure: the frame never entered the bounded queue, so the
    // outcome is deterministic and no ACK tracking is registered.
    ++stats_.send_rejected;
    observe_ack(id, MessageDeliveryEvent::send_failed, *sent.error_if());
    return Result<MessageId>::failure(*sent.error_if());
  }
  if (envelope.delivery_mode == MessageDeliveryMode::peer_acked) {
    ++stats_.sent_peer_acked;
    prune_expired();
    if (pending_acks_.size() >= config_.pending_ack_capacity && !pending_acks_.empty()) {
      // Bounded tracking: the oldest pending entry ages out as a timeout.
      const auto oldest = pending_acks_.begin()->first;
      ++stats_.ack_timed_out;
      observe_ack(oldest, MessageDeliveryEvent::ack_timeout,
                  message_service_error(ErrorCode::timeout, "ack_tracking_capacity"));
      pending_acks_.erase(oldest);
    }
    pending_acks_[id] = PendingAck{now() + envelope.ttl_milliseconds};
    observe_ack(id, MessageDeliveryEvent::queued, std::nullopt);
  } else {
    ++stats_.sent_best_effort;
  }
  return Result<MessageId>::success(id);
}

void MessageService::set_inbound_sink(InboundSink sink, void* context) {
  inbound_sink_ = sink;
  inbound_context_ = context;
}

void MessageService::set_ack_sink(AckSink sink, void* context) {
  ack_sink_ = sink;
  ack_context_ = context;
}

void MessageService::prune() {
  merge_dispatch_records();
  prune_expired();
}

void MessageService::handle_session_closed() {
  for (const auto& [id, pending] : pending_acks_) {
    ++stats_.acks_on_closed;
    observe_ack(id, MessageDeliveryEvent::session_closed,
                message_service_error(ErrorCode::transport, "session_closed"));
  }
  pending_acks_.clear();
}

void MessageService::handle_frame(const FrameView& frame) {
  (void)admit_frame(frame);
}

Result<void> MessageService::admit_frame(const FrameView& frame) {
  if (!attached_) {
    return Result<void>::failure(
        message_service_error(ErrorCode::configuration, "service_not_attached"));
  }
  if (frame.type == static_cast<std::uint8_t>(FrameType::message)) {
    // Peer-initiated logical channel: adopt it so later frames have a
    // per-channel handler (the M5-14 domain-admission pattern).
    if (!session_.has_business_channel(frame.channel_id)) {
      auto weak = weak_from_this();
      auto adopted = session_.adopt_business_channel(
          frame.channel_id, session::ChannelDomain::message,
          session::QueueFullPolicy::reject, config_.channel_frame_capacity,
          config_.channel_byte_capacity,
          [weak](const FrameView& inbound) {
            if (auto self = weak.lock()) self->handle_frame(inbound);
          });
      if (!adopted) return Result<void>::failure(*adopted.error_if());
      owned_channels_.push_back(*adopted.value_if());
    }
    handle_inbound_message(frame);
    return Result<void>::success();
  }
  if (frame.type == static_cast<std::uint8_t>(FrameType::message_ack)) {
    handle_inbound_ack(frame);
    return Result<void>::success();
  }
  return Result<void>::failure(
      message_service_error(ErrorCode::protocol, "message_domain_frame_unknown"));
}

void MessageService::handle_inbound_message(const FrameView& frame) {
  prune_expired();
  auto parsed = parse_message_envelope(frame.payload, session_.channels().limits());
  if (!parsed) {
    // Structurally invalid: no ACK (the sender's ack wait times out), no
    // handler, and no state change beyond the counter.
    ++stats_.invalid_envelopes;
    return;
  }
  auto& envelope = *parsed.value_if();
  const auto digest = envelope_digest(frame.payload);
  const auto existing = dedup_.find(envelope.message_id);
  if (existing != dedup_.end() &&
      existing->second.expires_at_unix_milliseconds > now()) {
    if (existing->second.envelope_digest == digest) {
      // Exact duplicate: never redeliver; replay the cached ACK verdict.
      ++stats_.duplicates;
      if (envelope.delivery_mode == MessageDeliveryMode::peer_acked) {
        send_ack_for(envelope, frame.channel_id);
      }
      return;
    }
    // Same message id with different bytes violates the immutable-envelope
    // rule (wire protocol 6.2): close only the message channel.
    session_.fail_business_channel(frame.channel_id,
                                   transport::CloseReason::protocol_error);
    return;
  }
  if (existing != dedup_.end()) {
    ++stats_.dedup_expired;
    dedup_.erase(existing);
  }
  if (dedup_.size() >= config_.dedup_capacity) {
    // Bounded cache: drop expired entries first, then the oldest entry.
    for (auto entry = dedup_.begin(); entry != dedup_.end();) {
      if (entry->second.expires_at_unix_milliseconds <= now()) {
        ++stats_.dedup_expired;
        entry = dedup_.erase(entry);
        if (dedup_.size() < config_.dedup_capacity) break;
      } else {
        ++entry;
      }
    }
    while (dedup_.size() >= config_.dedup_capacity && !dedup_.empty()) {
      ++stats_.dedup_evictions;
      dedup_.erase(dedup_.begin());
    }
  }
  DedupEntry entry;
  entry.expires_at_unix_milliseconds = now() + envelope.ttl_milliseconds;
  entry.envelope_digest = digest;
  dedup_[envelope.message_id] = std::move(entry);

  // Scope gate before any ACK or handler (M6-05): the sender's session must
  // cover message.send. Unauthorized frames get no protocol-level service.
  if (!scope_check_ || !scope_check_(message_send_scope)) {
    ++stats_.scope_rejected;
    return;
  }

  if (envelope.delivery_mode == MessageDeliveryMode::peer_acked) {
    send_ack_for(envelope, frame.channel_id);
  }
  ++stats_.received;
  deliver_to_handler(std::move(envelope));
}

void MessageService::send_ack_for(const MessageEnvelope& envelope,
                                  std::uint32_t channel_id) {
  // Protocol-level ACK: the envelope passed basic validation only (M6-03);
  // it never claims the handler ran or anything was persisted.
  Frame ack_frame;
  ack_frame.type = static_cast<std::uint8_t>(FrameType::message_ack);
  ack_frame.channel_id = channel_id;
  auto encoded = encode_message_ack(MessageAckBody{envelope.message_id, true});
  if (!encoded) {
    ++stats_.ack_send_failures;
    return;
  }
  ack_frame.payload = std::move(*encoded.value_if());
  if (session_.send_frame(channel_id, session::FrameClass::control,
                          std::move(ack_frame))) {
    ++stats_.acks_sent;
  } else {
    ++stats_.ack_send_failures;
  }
}

void MessageService::deliver_to_handler(MessageEnvelope envelope) {
  if (inbound_sink_ == nullptr) {
    return;
  }
  const auto sink = inbound_sink_;
  const auto context = inbound_context_;
  auto record = std::make_shared<DispatchRecord>();
  const std::uint64_t record_id = next_dispatch_id_++;
  dispatch_records_[record_id] = record;
  ++stats_.dispatched;
  auto dispatched = dispatch_(
      "heyaki-message-handler",
      [record, sink, context, peer = peer_,
       envelope = std::move(envelope)]() mutable {
        try {
          sink(context, peer, envelope);
          record->completed.fetch_add(1U, std::memory_order_relaxed);
        } catch (...) {
          // Handler failures are contained: any ACK already went out at
          // protocol level; only the local failure is recorded.
          record->exceptions.fetch_add(1U, std::memory_order_relaxed);
        }
        record->done.store(true, std::memory_order_release);
      });
  if (!dispatched) {
    // Admission rejected before execution: observable, never silent.
    dispatch_records_.erase(record_id);
    ++stats_.dispatch_rejected;
  }
}

void MessageService::handle_inbound_ack(const FrameView& frame) {
  auto parsed = parse_message_ack(frame.payload);
  if (!parsed) {
    ++stats_.invalid_envelopes;
    return;
  }
  const auto pending = pending_acks_.find(parsed.value_if()->message_id);
  if (pending == pending_acks_.end()) {
    // Unknown or late ACK: ignored and counted (wire protocol 6.2).
    ++stats_.unknown_acks;
    return;
  }
  pending_acks_.erase(pending);
  if (parsed.value_if()->protocol_accepted) {
    ++stats_.acked;
    observe_ack(parsed.value_if()->message_id, MessageDeliveryEvent::acked, std::nullopt);
  } else {
    ++stats_.ack_rejected;
    observe_ack(parsed.value_if()->message_id, MessageDeliveryEvent::peer_rejected,
                message_service_error(ErrorCode::protocol, "peer_rejected_envelope"));
  }
}

void MessageService::observe_ack(const MessageId& id, MessageDeliveryEvent event,
                                 std::optional<Error> error) {
  if (ack_sink_ != nullptr) {
    ack_sink_(ack_context_, peer_, id, event, std::move(error));
  }
}

void MessageService::merge_dispatch_records() {
  for (auto entry = dispatch_records_.begin(); entry != dispatch_records_.end();) {
    if (entry->second->done.load(std::memory_order_acquire)) {
      stats_.handler_completed += entry->second->completed.load(std::memory_order_relaxed);
      stats_.handler_exceptions += entry->second->exceptions.load(std::memory_order_relaxed);
      entry = dispatch_records_.erase(entry);
    } else {
      ++entry;
    }
  }
}

void MessageService::prune_expired() {
  const auto current = now();
  for (auto entry = dedup_.begin(); entry != dedup_.end();) {
    if (entry->second.expires_at_unix_milliseconds <= current) {
      ++stats_.dedup_expired;
      entry = dedup_.erase(entry);
    } else {
      ++entry;
    }
  }
  for (auto entry = pending_acks_.begin(); entry != pending_acks_.end();) {
    if (entry->second.expires_at_unix_milliseconds <= current) {
      ++stats_.ack_timed_out;
      const auto id = entry->first;
      entry = pending_acks_.erase(entry);
      observe_ack(id, MessageDeliveryEvent::ack_timeout,
                  message_service_error(ErrorCode::timeout, "ack_ttl_expired"));
    } else {
      ++entry;
    }
  }
}

MessageServiceStats MessageService::stats() {
  merge_dispatch_records();
  return stats_;
}

}  // namespace heyaki
