#pragma once

// Remote event bus wire bodies (M7-01..M7-03). EventSubscribe/EventItem/
// EventUnsubscribe follow the frozen heyaki.protocol.event.v1 schemas and ride
// the non-zero logical event channel of an authorized session. The model is
// publisher-direct: a subscriber sends EVENT_SUBSCRIBE to the event source,
// the source matches the topic locally and fans items out per subscription
// (RULE: the relay never sees topics and never brokers events).
//
// QoS semantics (architecture 8.3, wire protocol 6.2):
//   * best_effort_latest keeps only the newest unsent item per subscription;
//     overwritten and stale deliveries are observable, never silent.
//   * reliable_live is reliable inside the current connection only; overflow
//     terminates that one subscription with an observable error and never
//     closes unrelated channels. History is NOT replayed after reconnect.
// Each publisher/topic carries a locally increasing sequence; there is no
// cross-device global order.

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/limits.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

// Mirrors heyaki.protocol.event.v1.EventQos. Wire-stable.
enum class EventQos : std::uint32_t {
  best_effort_latest = 1U,
  reliable_live = 2U,
};

[[nodiscard]] std::string_view event_qos_name(EventQos qos) noexcept;

// Subscription and event identifiers: 16 non-zero bytes on the wire.
using EventSubscriptionId = std::array<std::byte, 16U>;
using EventId = std::array<std::byte, 16U>;

inline constexpr std::size_t max_event_topic_bytes = 256U;
inline constexpr std::size_t max_event_topic_segments = 16U;
inline constexpr std::size_t max_event_topic_segment_bytes = 64U;

// True when `topic` is a structurally valid topic name: dot-separated
// non-empty segments of name tokens (letters, digits, '_', '-').
[[nodiscard]] bool valid_event_topic(std::string_view topic) noexcept;

// True when a published `topic` matches a subscription pattern: exact match,
// or prefix match on a segment boundary ("telemetry.cpu" prefix-matches
// "telemetry.cpu.load" but not "telemetry.cpux"). No regex in v1.
[[nodiscard]] bool event_topic_matches(std::string_view pattern, bool prefix_match,
                                       std::string_view topic) noexcept;

struct EventSubscribeBody {
  EventSubscriptionId subscription_id{};
  std::string topic;
  bool prefix_match{false};
  EventQos qos{EventQos::best_effort_latest};
};

[[nodiscard]] Result<std::vector<std::byte>> encode_event_subscribe(
    const EventSubscribeBody& subscribe, const Limits& limits = {});
[[nodiscard]] Result<EventSubscribeBody> parse_event_subscribe(
    std::span<const std::byte> payload, const Limits& limits = {});

struct EventItemBody {
  EventSubscriptionId subscription_id{};
  EventId event_id{};
  DeviceId publisher_device_id;
  std::uint64_t publisher_sequence{};
  std::uint32_t schema_version{1U};
  std::optional<std::int64_t> wall_time_unix_milliseconds;
  EventQos qos{EventQos::best_effort_latest};
  std::vector<std::byte> payload;
};

[[nodiscard]] Result<std::vector<std::byte>> encode_event_item(
    const EventItemBody& item, const Limits& limits = {});
[[nodiscard]] Result<EventItemBody> parse_event_item(std::span<const std::byte> payload,
                                                     const Limits& limits = {});

struct EventUnsubscribeBody {
  EventSubscriptionId subscription_id{};
};

[[nodiscard]] Result<std::vector<std::byte>> encode_event_unsubscribe(
    const EventUnsubscribeBody& unsubscribe);
[[nodiscard]] Result<EventUnsubscribeBody> parse_event_unsubscribe(
    std::span<const std::byte> payload);

// Counters for one event service (M7-02..M7-06): every overwrite, drop, gap,
// rejection, and termination is observable; nothing fails silently.
struct EventServiceStats {
  // Publisher side (event source).
  std::uint64_t published{};                 // publish() calls with >= 0 matches
  std::uint64_t published_items{};           // items matched to subscriptions
  std::uint64_t subscriber_overwrites{};     // best_effort_latest pending item replaced
  std::uint64_t subscriber_drops{};          // best_effort_latest item dropped at a full channel
  std::uint64_t subscriber_overflows{};      // reliable_live queue overflow: subscription terminated
  std::uint64_t items_sent{};
  std::uint64_t item_send_failures{};
  std::uint64_t subscriptions_accepted{};
  std::uint64_t subscriptions_rejected{};    // scope/limit/invalid-topic denials
  std::uint64_t duplicate_subscriptions{};   // byte-stable replay of a live subscription
  std::uint64_t subscription_limit_hits{};   // per-peer subscription cap reached
  std::uint64_t scope_rejected{};            // event.subscribe:<root> not granted
  std::uint64_t unsubscribes_received{};
  std::uint64_t terminated_subscriptions{};  // sender-side terminal count
  // Subscriber side (event consumer).
  std::uint64_t subscribe_requests_sent{};
  std::uint64_t items_received{};
  std::uint64_t stale_items{};               // delivered sequence below the newest seen
  std::uint64_t lag_events{};                // deliveries that skipped >= 1 sequence
  std::uint64_t lag_total_sequences{};
  std::uint64_t duplicate_items{};           // exact duplicate (same event id + sequence)
  std::uint64_t conflicting_items{};         // sequence conflict: subscription closed
  std::uint64_t unknown_subscription_items{}; // items after unsubscribe/termination
  std::uint64_t unsubscribes_sent{};
  std::uint64_t handler_dispatched{};
  std::uint64_t handler_dispatch_rejected{};
  std::uint64_t handler_completed{};
  std::uint64_t handler_exceptions{};
};

// Sums every counter (used by NodeServiceDiagnostics aggregation).
inline void accumulate(EventServiceStats& total, const EventServiceStats& delta) {
  total.published += delta.published;
  total.published_items += delta.published_items;
  total.subscriber_overwrites += delta.subscriber_overwrites;
  total.subscriber_drops += delta.subscriber_drops;
  total.subscriber_overflows += delta.subscriber_overflows;
  total.items_sent += delta.items_sent;
  total.item_send_failures += delta.item_send_failures;
  total.subscriptions_accepted += delta.subscriptions_accepted;
  total.subscriptions_rejected += delta.subscriptions_rejected;
  total.duplicate_subscriptions += delta.duplicate_subscriptions;
  total.subscription_limit_hits += delta.subscription_limit_hits;
  total.scope_rejected += delta.scope_rejected;
  total.unsubscribes_received += delta.unsubscribes_received;
  total.terminated_subscriptions += delta.terminated_subscriptions;
  total.subscribe_requests_sent += delta.subscribe_requests_sent;
  total.items_received += delta.items_received;
  total.stale_items += delta.stale_items;
  total.lag_events += delta.lag_events;
  total.lag_total_sequences += delta.lag_total_sequences;
  total.duplicate_items += delta.duplicate_items;
  total.conflicting_items += delta.conflicting_items;
  total.unknown_subscription_items += delta.unknown_subscription_items;
  total.unsubscribes_sent += delta.unsubscribes_sent;
  total.handler_dispatched += delta.handler_dispatched;
  total.handler_dispatch_rejected += delta.handler_dispatch_rejected;
  total.handler_completed += delta.handler_completed;
  total.handler_exceptions += delta.handler_exceptions;
}

}  // namespace heyaki
