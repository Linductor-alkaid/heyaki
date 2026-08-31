#pragma once

// Remote event bus service (M7-01..M7-06), one instance per authorized
// PeerSession. The model is publisher-direct: the peer subscribes with
// EVENT_SUBSCRIBE, this side (the event source) checks the session's
// event.subscribe:<root> scope, then fans publisher items out through one
// bounded staging queue per subscription — best_effort_latest keeps only the
// newest unsent item (overwrites observable), reliable_live keeps a bounded
// FIFO and terminates only its own subscription on overflow. A slow
// subscriber never blocks the publisher or another subscriber (M7-04).
//
// The service is also the explicit bridge to local executor::comm fan-out
// (M7-05): received remote items are re-published into a local
// executor::comm::Topic<LocalEventMessage>, and publish() forwards locally
// authored messages to matching remote subscriptions. LocalEventMessage and
// EventItemBody stay distinct types with distinct names so local Topic
// lifecycle and remote delivery guarantees never blur.
//
// Threading: every public method runs on the owning Node's strand. Dispatched
// handler tasks run on executor threads and only touch self-contained
// DispatchRecord state, merged back through the shared anchor nulled by the
// destructor (the MessageService pattern).

#include "peer_session.hpp"
#include "service_dispatch.hpp"

#include <executor/comm/topic.hpp>

#include <heyaki/event.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

// Scope the subscribing peer's session must cover on the event source,
// qualified by the subscription pattern's first topic segment (for example
// event.subscribe:telemetry); a grant of event.subscribe:* admits every
// topic root.
[[nodiscard]] std::string event_subscription_scope(std::string_view pattern);

// Local fan-out unit bridged at the device boundary (M7-05).
struct LocalEventMessage {
  std::string topic;
  std::uint32_t schema_version{1U};
  std::vector<std::byte> payload;
};

struct EventServiceConfig {
  // Per-remote-subscription staging bound in items (M7-04): reliable_live
  // terminates the subscription when publishing beyond it;
  // best_effort_latest keeps at most one unsent item regardless.
  std::size_t subscriber_queue_items{256U};
  // Max simultaneous subscriptions this peer may hold (M7-06); extra
  // EVENT_SUBSCRIBE requests are answered with EVENT_UNSUBSCRIBE.
  std::size_t max_subscriptions_per_peer{64U};
  std::size_t channel_frame_capacity{256U};
  std::size_t channel_byte_capacity{2U * 1024U * 1024U};
};

class EventService : public std::enable_shared_from_this<EventService> {
 public:
  // Delivery notification leaves through a function-pointer sink (the M6
  // closure-free notification pattern). `pattern` is the local subscription
  // pattern the item matched.
  using InboundSink = void (*)(void* context, const DeviceEndpointKey& peer,
                               std::string_view pattern, const EventItemBody& item);
  using ScopeCheck = std::function<bool(std::string_view scope)>;
  using LocalTopic = executor::comm::Topic<LocalEventMessage>;

  // `local_topic` fans received remote events out to local consumers; it
  // outlives every service (owned by the Node).
  EventService(PeerSession& session, DeviceEndpointKey peer, DeviceId local_device,
               EventServiceConfig config, ServiceDispatch dispatch, ScopeCheck scope_check,
               LocalTopic& local_topic,
               std::function<std::uint64_t()> wall_clock = {});
  ~EventService();

  EventService(const EventService&) = delete;
  EventService& operator=(const EventService&) = delete;

  // Opens the logical event channel and installs the domain handler so
  // peer-initiated event channels are admitted (the M5-14 pattern).
  [[nodiscard]] Result<void> attach();

  // ---- Subscriber role ----
  // Sends EVENT_SUBSCRIBE for `pattern` (exact match, or segment-boundary
  // prefix when prefix_match). The subscription starts on the next item.
  [[nodiscard]] Result<EventSubscriptionId> subscribe(std::string pattern,
                                                      bool prefix_match, EventQos qos);
  // Unsubscribes every local subscription whose pattern equals `pattern`.
  [[nodiscard]] std::size_t unsubscribe(std::string_view pattern);
  [[nodiscard]] Result<void> unsubscribe_id(const EventSubscriptionId& id);

  struct LocalSubscriptionSummary {
    EventSubscriptionId id;
    std::string pattern;
    bool prefix_match{false};
    EventQos qos{EventQos::best_effort_latest};
    bool active{true};
    std::uint64_t newest_sequence{0U};
    bool has_sequence{false};
  };
  [[nodiscard]] std::vector<LocalSubscriptionSummary> local_subscriptions() const;

  // ---- Publisher role ----
  struct PublishOutcome {
    std::size_t matched{0U};   // active remote subscriptions whose pattern matched
    std::size_t staged{0U};    // items admitted into a staging queue
    std::size_t terminated{0U};  // subscriptions terminated by this publish
  };
  // Publishes one event under `topic` to every matching remote subscription.
  // The publisher sequence increases per topic; the event id is fresh. QoS is
  // per subscription (the subscriber chose it), so publish takes none.
  [[nodiscard]] Result<PublishOutcome> publish(
      std::string topic, std::vector<std::byte> payload, std::uint32_t schema_version,
      std::optional<std::int64_t> wall_time_unix_milliseconds = std::nullopt);

  // ---- Local bridge (M7-05) ----
  // Forwards one locally authored message to matching remote subscriptions
  // and returns the publish outcome (the remote half of the bridge).
  [[nodiscard]] Result<PublishOutcome> bridge_local_message(const LocalEventMessage& message);

  void set_inbound_sink(InboundSink sink, void* context);

  // Drains staged items while the channel admits them and merges finished
  // dispatch records. Called on publish/receive paths and safe from a
  // periodic timer.
  void prune();

  // Session loss is terminal for both roles: local subscriptions stop
  // (reliable_live never replays history) and remote subscriptions are
  // released (their guarantee was connection-scoped).
  void handle_session_closed();

  [[nodiscard]] EventServiceStats stats();
  [[nodiscard]] bool attached() const noexcept { return attached_; }
  [[nodiscard]] std::size_t remote_subscription_count() const noexcept {
    return remote_subscriptions_.size();
  }
  // Frame entry point (also used by tests for direct injection).
  void handle_frame(const FrameView& frame);

 private:
  // Written only by the owning executor task; read by the strand after the
  // relaxed `done` store (the MessageService handoff pattern).
  struct DispatchRecord {
    std::atomic<bool> done{false};
    std::atomic<std::uint64_t> completed{0U};
    std::atomic<std::uint64_t> exceptions{0U};
  };

  struct RemoteSubscription {
    EventSubscriptionId id{};
    std::string pattern;
    bool prefix_match{false};
    EventQos qos{EventQos::best_effort_latest};
    // Encoded EventItem payloads staged between publish and channel
    // admission; best_effort_latest holds at most one entry (keep-latest).
    std::deque<std::vector<std::byte>> staged;
    std::uint64_t last_staged_sequence{0U};
    bool staged_valid{false};
  };

  struct LocalSubscription {
    EventSubscriptionId id{};
    std::string pattern;
    bool prefix_match{false};
    EventQos qos{EventQos::best_effort_latest};
    bool active{true};
    bool has_sequence{false};
    std::uint64_t newest_sequence{0U};
    EventId last_event_id{};
  };

  [[nodiscard]] std::uint64_t now() const;
  [[nodiscard]] Result<void> admit_frame(const FrameView& frame);
  void handle_inbound_subscribe(const FrameView& frame);
  void handle_inbound_unsubscribe(const FrameView& frame);
  void handle_inbound_item(const FrameView& frame);
  void send_unsubscribe(const EventSubscriptionId& id);
  void terminate_remote_subscription(const EventSubscriptionId& id, bool notify_peer);
  void drain_staged(RemoteSubscription& subscription);
  void deliver_locally(const LocalSubscription& subscription, EventItemBody item);
  void merge_dispatch_records();

  PeerSession& session_;
  DeviceEndpointKey peer_;
  DeviceId local_device_;
  EventServiceConfig config_;
  ServiceDispatch dispatch_;
  ScopeCheck scope_check_;
  LocalTopic& local_topic_;
  std::function<std::uint64_t()> wall_clock_;
  InboundSink inbound_sink_{};
  void* inbound_context_{};
  // Peer-held subscriptions (this side is the event source).
  std::map<EventSubscriptionId, RemoteSubscription> remote_subscriptions_;
  // Locally held subscriptions (this side consumes the peer's events).
  std::map<EventSubscriptionId, LocalSubscription> local_subscriptions_;
  // Publisher sequence per topic (M7-01: locally increasing, no global order).
  std::map<std::string, std::uint64_t> topic_sequences_;
  std::map<std::uint64_t, std::shared_ptr<DispatchRecord>> dispatch_records_;
  std::uint64_t next_dispatch_id_{1U};
  EventServiceStats stats_;
  std::uint32_t channel_id_{};
  std::vector<std::uint32_t> owned_channels_;
  bool attached_{false};
};

}  // namespace heyaki
