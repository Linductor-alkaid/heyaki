#include "event_service.hpp"

#include <sodium.h>

#include <algorithm>
#include <utility>

namespace heyaki {
namespace {

Error event_service_error(ErrorCode code, std::string_view detail) {
  return Error{code, "event", std::string{detail}};
}

bool subscription_id_zero(const EventSubscriptionId& id) noexcept {
  return std::all_of(id.begin(), id.end(),
                     [](std::byte value) { return value == std::byte{0}; });
}

EventSubscriptionId random_subscription_id() {
  EventSubscriptionId id{};
  do {
    randombytes_buf(id.data(), id.size());
  } while (subscription_id_zero(id));
  return id;
}

EventId random_event_id() {
  EventId id{};
  randombytes_buf(id.data(), id.size());
  return id;
}

std::string_view first_topic_segment(std::string_view topic) noexcept {
  const auto dot = topic.find('.');
  return dot == std::string_view::npos ? topic : topic.substr(0U, dot);
}

}  // namespace

std::string event_subscription_scope(std::string_view pattern) {
  std::string scope{"event.subscribe:"};
  scope.append(first_topic_segment(pattern));
  return scope;
}

EventService::EventService(PeerSession& session, DeviceEndpointKey peer,
                           DeviceId local_device, EventServiceConfig config,
                           ServiceDispatch dispatch, ScopeCheck scope_check,
                           LocalTopic& local_topic,
                           std::function<std::uint64_t()> wall_clock)
    : session_(session),
      peer_(std::move(peer)),
      local_device_(local_device),
      config_(config),
      dispatch_(std::move(dispatch)),
      scope_check_(std::move(scope_check)),
      local_topic_(local_topic),
      wall_clock_(std::move(wall_clock)) {}

EventService::~EventService() {
  session_.set_domain_handler(session::ChannelDomain::event, DomainFrameHandler{});
  for (const auto channel : owned_channels_) {
    session_.close_business_channel(channel);
  }
  // In-flight handler tasks finish on their own DispatchRecord copies; their
  // deltas are dropped because the service and its counters are gone.
}

std::uint64_t EventService::now() const {
  if (wall_clock_) return wall_clock_();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

Result<void> EventService::attach() {
  if (attached_) {
    return Result<void>::success();
  }
  if (config_.subscriber_queue_items == 0U ||
      config_.max_subscriptions_per_peer == 0U ||
      config_.channel_frame_capacity == 0U || config_.channel_byte_capacity == 0U) {
    return Result<void>::failure(
        event_service_error(ErrorCode::configuration, "event_config_invalid"));
  }
  if (!dispatch_) {
    return Result<void>::failure(
        event_service_error(ErrorCode::configuration, "dispatch_missing"));
  }
  auto weak = weak_from_this();
  auto opened = session_.open_business_channel(
      session::ChannelDomain::event, session::QueueFullPolicy::reject,
      config_.channel_frame_capacity, config_.channel_byte_capacity,
      [weak](const FrameView& frame) {
        if (auto self = weak.lock()) self->handle_frame(frame);
      });
  if (!opened) return Result<void>::failure(*opened.error_if());
  channel_id_ = *opened.value_if();
  owned_channels_.push_back(channel_id_);
  session_.set_domain_handler(
      session::ChannelDomain::event,
      [weak](const FrameView& frame) -> Result<void> {
        auto self = weak.lock();
        if (!self) {
          return Result<void>::failure(
              event_service_error(ErrorCode::cancelled, "service_detached"));
        }
        return self->admit_frame(frame);
      });
  attached_ = true;
  return Result<void>::success();
}

Result<EventSubscriptionId> EventService::subscribe(std::string pattern, bool prefix_match,
                                                    EventQos qos) {
  (void)qos;  // carried into the wire body below
  if (!attached_) {
    return Result<EventSubscriptionId>::failure(
        event_service_error(ErrorCode::configuration, "service_not_attached"));
  }
  if (!valid_event_topic(pattern)) {
    return Result<EventSubscriptionId>::failure(
        event_service_error(ErrorCode::protocol, "topic_invalid"));
  }
  EventSubscribeBody body;
  body.subscription_id = random_subscription_id();
  body.topic = std::move(pattern);
  body.prefix_match = prefix_match;
  body.qos = qos;
  auto encoded = encode_event_subscribe(body, session_.channels().limits());
  if (!encoded) {
    return Result<EventSubscriptionId>::failure(*encoded.error_if());
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::event_subscribe);
  frame.channel_id = channel_id_;
  frame.payload = std::move(*encoded.value_if());
  const auto sent = session_.send_frame(channel_id_, session::FrameClass::standard,
                                        std::move(frame));
  if (!sent) {
    return Result<EventSubscriptionId>::failure(*sent.error_if());
  }
  LocalSubscription subscription;
  subscription.id = body.subscription_id;
  subscription.pattern = body.topic;
  subscription.prefix_match = body.prefix_match;
  subscription.qos = qos;
  local_subscriptions_[body.subscription_id] = std::move(subscription);
  ++stats_.subscribe_requests_sent;
  return Result<EventSubscriptionId>::success(body.subscription_id);
}

std::size_t EventService::unsubscribe(std::string_view pattern) {
  std::size_t removed = 0U;
  for (auto entry = local_subscriptions_.begin(); entry != local_subscriptions_.end();) {
    if (entry->second.pattern == pattern && entry->second.active) {
      send_unsubscribe(entry->first);
      entry = local_subscriptions_.erase(entry);
      ++removed;
    } else {
      ++entry;
    }
  }
  return removed;
}

Result<void> EventService::unsubscribe_id(const EventSubscriptionId& id) {
  const auto entry = local_subscriptions_.find(id);
  if (entry == local_subscriptions_.end() || !entry->second.active) {
    return Result<void>::failure(
        event_service_error(ErrorCode::peer_offline, "subscription_unknown"));
  }
  send_unsubscribe(id);
  local_subscriptions_.erase(entry);
  return Result<void>::success();
}

std::vector<EventService::LocalSubscriptionSummary>
EventService::local_subscriptions() const {
  std::vector<LocalSubscriptionSummary> summaries;
  summaries.reserve(local_subscriptions_.size());
  for (const auto& [id, subscription] : local_subscriptions_) {
    summaries.push_back(LocalSubscriptionSummary{
        id, subscription.pattern, subscription.prefix_match, subscription.qos,
        subscription.active, subscription.newest_sequence, subscription.has_sequence});
  }
  return summaries;
}

Result<EventService::PublishOutcome> EventService::publish(
    std::string topic, std::vector<std::byte> payload, std::uint32_t schema_version,
    std::optional<std::int64_t> wall_time_unix_milliseconds) {
  if (!attached_) {
    return Result<PublishOutcome>::failure(
        event_service_error(ErrorCode::configuration, "service_not_attached"));
  }
  if (!valid_event_topic(topic)) {
    return Result<PublishOutcome>::failure(
        event_service_error(ErrorCode::protocol, "topic_invalid"));
  }
  const auto limits = session_.channels().limits();
  if (payload.size() > limits.max_event_payload_bytes) {
    return Result<PublishOutcome>::failure(
        event_service_error(ErrorCode::resource_exhausted, "payload_oversized"));
  }
  ++stats_.published;
  // Per-topic locally increasing sequence (M7-01).
  const std::uint64_t sequence = ++topic_sequences_[topic];
  const EventId event_id = random_event_id();

  PublishOutcome outcome;
  std::vector<EventSubscriptionId> overflowed;
  for (auto& [id, subscription] : remote_subscriptions_) {
    if (!event_topic_matches(subscription.pattern, subscription.prefix_match, topic)) {
      continue;
    }
    ++outcome.matched;
    EventItemBody item;
    item.subscription_id = id;
    item.event_id = event_id;
    item.publisher_device_id = local_device_;
    item.publisher_sequence = sequence;
    item.schema_version = schema_version;
    item.wall_time_unix_milliseconds = wall_time_unix_milliseconds;
    item.qos = subscription.qos;
    item.payload = payload;  // copied per subscription (per-subscription encoding)
    auto encoded = encode_event_item(item, limits);
    if (!encoded) {
      ++stats_.item_send_failures;
      continue;
    }
    if (subscription.qos == EventQos::best_effort_latest) {
      if (!subscription.staged.empty()) {
        // Keep-latest: the still-unsent older value is superseded (M7-02).
        ++stats_.subscriber_overwrites;
        ++stats_.subscriber_drops;
        subscription.staged.pop_front();
      }
      subscription.staged.push_back(std::move(*encoded.value_if()));
      ++outcome.staged;
    } else {
      if (subscription.staged.size() >= config_.subscriber_queue_items) {
        // Reliable-live overflow terminates only this subscription with an
        // observable error (wire protocol 6.2); the publisher keeps going.
        ++stats_.subscriber_overflows;
        ++outcome.terminated;
        overflowed.push_back(id);
        continue;
      }
      subscription.staged.push_back(std::move(*encoded.value_if()));
      ++outcome.staged;
    }
    subscription.last_staged_sequence = sequence;
    subscription.staged_valid = true;
  }
  for (const auto& id : overflowed) {
    terminate_remote_subscription(id, true);
  }
  ++stats_.published_items;
  // Try immediate delivery so the fast path needs no timer tick.
  for (auto& [id, subscription] : remote_subscriptions_) {
    drain_staged(subscription);
  }
  return Result<PublishOutcome>::success(outcome);
}

Result<EventService::PublishOutcome> EventService::bridge_local_message(
    const LocalEventMessage& message) {
  return publish(message.topic, message.payload, message.schema_version);
}

void EventService::set_inbound_sink(InboundSink sink, void* context) {
  inbound_sink_ = sink;
  inbound_context_ = context;
}

void EventService::prune() {
  merge_dispatch_records();
  for (auto& [id, subscription] : remote_subscriptions_) {
    drain_staged(subscription);
  }
}

void EventService::handle_session_closed() {
  // Subscriber role: every local subscription stops. reliable_live never
  // replays history, so re-subscription is the application's choice on the
  // next session, not an automatic resend trigger.
  local_subscriptions_.clear();
  // Source role: the peer's subscriptions were connection-scoped.
  for (auto& [id, subscription] : remote_subscriptions_) {
    subscription.staged.clear();
  }
  remote_subscriptions_.clear();
}

void EventService::handle_frame(const FrameView& frame) {
  (void)admit_frame(frame);
}

Result<void> EventService::admit_frame(const FrameView& frame) {
  if (!attached_) {
    return Result<void>::failure(
        event_service_error(ErrorCode::configuration, "service_not_attached"));
  }
  const auto known_channel = session_.has_business_channel(frame.channel_id);
  if (frame.type == static_cast<std::uint8_t>(FrameType::event_subscribe) ||
      frame.type == static_cast<std::uint8_t>(FrameType::event_item)) {
    if (!known_channel) {
      auto weak = weak_from_this();
      auto adopted = session_.adopt_business_channel(
          frame.channel_id, session::ChannelDomain::event,
          session::QueueFullPolicy::reject, config_.channel_frame_capacity,
          config_.channel_byte_capacity,
          [weak](const FrameView& inbound) {
            if (auto self = weak.lock()) self->handle_frame(inbound);
          });
      if (!adopted) return Result<void>::failure(*adopted.error_if());
      owned_channels_.push_back(*adopted.value_if());
    }
  }
  if (frame.type == static_cast<std::uint8_t>(FrameType::event_subscribe)) {
    handle_inbound_subscribe(frame);
    return Result<void>::success();
  }
  if (frame.type == static_cast<std::uint8_t>(FrameType::event_item)) {
    handle_inbound_item(frame);
    return Result<void>::success();
  }
  if (frame.type == static_cast<std::uint8_t>(FrameType::event_unsubscribe)) {
    handle_inbound_unsubscribe(frame);
    return Result<void>::success();
  }
  return Result<void>::failure(
      event_service_error(ErrorCode::protocol, "event_domain_frame_unknown"));
}

void EventService::handle_inbound_subscribe(const FrameView& frame) {
  auto parsed = parse_event_subscribe(frame.payload, session_.channels().limits());
  if (!parsed) {
    ++stats_.subscriptions_rejected;
    session_.fail_business_channel(frame.channel_id,
                                   transport::CloseReason::protocol_error);
    return;
  }
  const auto& body = *parsed.value_if();
  const auto existing = remote_subscriptions_.find(body.subscription_id);
  if (existing != remote_subscriptions_.end()) {
    if (existing->second.pattern == body.topic &&
        existing->second.prefix_match == body.prefix_match &&
        existing->second.qos == body.qos) {
      // Byte-stable replay of a live subscription: idempotent.
      ++stats_.duplicate_subscriptions;
      return;
    }
    // Subscription id binds topic/match/QoS immutably (wire protocol 6.2).
    session_.fail_business_channel(frame.channel_id,
                                   transport::CloseReason::protocol_error);
    return;
  }
  // Scope gate before any state is kept (M7-04): the subscriber's session
  // must cover event.subscribe:<root>.
  if (!scope_check_ || !scope_check_(event_subscription_scope(body.topic))) {
    ++stats_.subscriptions_rejected;
    ++stats_.scope_rejected;
    // Explicit refusal: answer with unsubscribe so the peer observes it.
    send_unsubscribe(body.subscription_id);
    return;
  }
  if (remote_subscriptions_.size() >= config_.max_subscriptions_per_peer) {
    ++stats_.subscriptions_rejected;
    ++stats_.subscription_limit_hits;
    send_unsubscribe(body.subscription_id);
    return;
  }
  RemoteSubscription subscription;
  subscription.id = body.subscription_id;
  subscription.pattern = body.topic;
  subscription.prefix_match = body.prefix_match;
  subscription.qos = body.qos;
  remote_subscriptions_[body.subscription_id] = std::move(subscription);
  ++stats_.subscriptions_accepted;
}

void EventService::handle_inbound_unsubscribe(const FrameView& frame) {
  ++stats_.unsubscribes_received;
  auto parsed = parse_event_unsubscribe(frame.payload);
  if (!parsed) {
    return;
  }
  const auto entry = remote_subscriptions_.find(parsed.value_if()->subscription_id);
  if (entry == remote_subscriptions_.end()) {
    // Late unsubscribe after termination: ignored and counted.
    ++stats_.terminated_subscriptions;
    return;
  }
  remote_subscriptions_.erase(entry);
}

void EventService::handle_inbound_item(const FrameView& frame) {
  auto parsed = parse_event_item(frame.payload, session_.channels().limits());
  if (!parsed) {
    session_.fail_business_channel(frame.channel_id,
                                   transport::CloseReason::protocol_error);
    return;
  }
  auto item = std::move(*parsed.value_if());
  const auto entry = local_subscriptions_.find(item.subscription_id);
  if (entry == local_subscriptions_.end() || !entry->second.active) {
    ++stats_.unknown_subscription_items;
    return;
  }
  auto& subscription = entry->second;
  const std::uint64_t sequence = item.publisher_sequence;
  if (!subscription.has_sequence) {
    subscription.has_sequence = true;
  } else if (sequence == subscription.newest_sequence) {
    if (item.event_id == subscription.last_event_id) {
      // Exact duplicate: ignored (wire protocol 6.2).
      ++stats_.duplicate_items;
      return;
    }
    // Same sequence, different event: the publisher sequence is immutable.
    ++stats_.conflicting_items;
    subscription.active = false;
    send_unsubscribe(subscription.id);
    local_subscriptions_.erase(entry);
    return;
  } else if (sequence < subscription.newest_sequence) {
    // Non-increasing sequence that is not an exact duplicate conflicts with
    // the locally increasing per-publisher sequence rule (wire protocol 6.2).
    ++stats_.conflicting_items;
    subscription.active = false;
    send_unsubscribe(subscription.id);
    local_subscriptions_.erase(entry);
    return;
  } else {
    const std::uint64_t gap = sequence - subscription.newest_sequence - 1U;
    if (gap > 0U) {
      ++stats_.lag_events;
      stats_.lag_total_sequences += gap;
      if (subscription.qos == EventQos::best_effort_latest) {
        // The skipped intermediates went stale upstream (keep-latest).
        ++stats_.stale_items;
      }
    }
  }
  subscription.newest_sequence = sequence;
  subscription.last_event_id = item.event_id;
  ++stats_.items_received;
  deliver_locally(subscription, std::move(item));
}

void EventService::deliver_locally(const LocalSubscription& subscription,
                                   EventItemBody item) {
  // Inbound half of the M7-05 bridge: remote items become local
  // executor::comm fan-out messages under the subscription's pattern.
  LocalEventMessage message;
  message.topic = subscription.pattern;
  message.schema_version = item.schema_version;
  message.payload = item.payload;
  (void)local_topic_.publish(std::move(message));

  if (inbound_sink_ == nullptr) {
    return;
  }
  const auto sink = inbound_sink_;
  const auto context = inbound_context_;
  auto record = std::make_shared<DispatchRecord>();
  const std::uint64_t record_id = next_dispatch_id_++;
  dispatch_records_[record_id] = record;
  ++stats_.handler_dispatched;
  auto dispatched = dispatch_(
      "heyaki-event-handler",
      [record, sink, context, peer = peer_, pattern = subscription.pattern,
       item = std::move(item)]() mutable {
        try {
          sink(context, peer, pattern, item);
          record->completed.fetch_add(1U, std::memory_order_relaxed);
        } catch (...) {
          // Handler failures are contained; only the local failure is
          // recorded.
          record->exceptions.fetch_add(1U, std::memory_order_relaxed);
        }
        record->done.store(true, std::memory_order_release);
      });
  if (!dispatched) {
    dispatch_records_.erase(record_id);
    ++stats_.handler_dispatch_rejected;
  }
}

void EventService::send_unsubscribe(const EventSubscriptionId& id) {
  EventUnsubscribeBody body;
  body.subscription_id = id;
  auto encoded = encode_event_unsubscribe(body);
  if (!encoded) {
    return;
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::event_unsubscribe);
  frame.channel_id = channel_id_;
  frame.payload = std::move(*encoded.value_if());
  if (session_.send_frame(channel_id_, session::FrameClass::standard, std::move(frame))) {
    ++stats_.unsubscribes_sent;
  }
}

void EventService::terminate_remote_subscription(const EventSubscriptionId& id,
                                                 bool notify_peer) {
  remote_subscriptions_.erase(id);
  ++stats_.terminated_subscriptions;
  if (notify_peer) {
    // The overflowed subscription is over for the peer too.
    send_unsubscribe(id);
  }
}

void EventService::drain_staged(RemoteSubscription& subscription) {
  while (!subscription.staged.empty()) {
    Frame frame;
    frame.type = static_cast<std::uint8_t>(FrameType::event_item);
    frame.channel_id = channel_id_;
    frame.payload = subscription.staged.front();  // copied until admission
    const auto sent = session_.send_frame(channel_id_, session::FrameClass::bulk,
                                          std::move(frame));
    if (!sent) {
      // Channel admission failed (would_block): the item stays staged. A
      // best_effort_latest item may still be superseded by a newer publish;
      // a reliable_live item retries on the next prune. Either way the
      // publisher is never blocked (M7-04).
      return;
    }
    subscription.staged.pop_front();
    ++stats_.items_sent;
  }
}

void EventService::merge_dispatch_records() {
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

EventServiceStats EventService::stats() {
  merge_dispatch_records();
  return stats_;
}

}  // namespace heyaki
