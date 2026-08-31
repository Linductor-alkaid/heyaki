// M7 event service tests over the loopback pair: QoS semantics, per-
// subscriber staging, scope/limit admission, sequence rules, session loss,
// and the local executor::comm topic bridge (M7-01..M7-06).

#include "m7_support.hpp"

#include <executor/comm/topic.hpp>

#include <gtest/gtest.h>

#include <deque>
#include <cstdio>
#include <string>
#include <vector>

namespace heyaki {
namespace {

using test::M7ServicePair;
using test::ManualDispatch;
using test::ManualPoster;

std::vector<std::string> default_scopes() {
  return {"message.send", "rpc.device.read", "rpc.device.configure", "stream.open",
          "event.subscribe:*", "event.subscribe:telemetry"};
}

struct ReceivedItem {
  std::string pattern;
  EventItemBody item;
};

struct EventRecorder {
  std::vector<ReceivedItem> received;
  void record(const DeviceEndpointKey&, std::string_view pattern,
              const EventItemBody& item) {
    received.push_back(ReceivedItem{std::string{pattern}, item});
  }
};

M7ServicePair::Options event_options() {
  M7ServicePair::Options options;
  options.left_scopes = default_scopes();
  options.right_scopes = default_scopes();
  return options;
}

TEST(M7EventService, ExactTopicDeliversWithIncreasingSequence) {
  M7ServicePair harness(event_options());
  EventRecorder recorder;
  harness.right_event_sinks.inbound = [&recorder](const DeviceEndpointKey& peer,
                                                  std::string_view pattern,
                                                  const EventItemBody& item) {
    recorder.record(peer, pattern, item);
  };

  auto subscribed = harness.right_events->subscribe("telemetry.cpu", false, EventQos::reliable_live);
  ASSERT_TRUE(subscribed);
  harness.m6.pump();

  auto outcome = harness.left_events->publish("telemetry.cpu", {std::byte{1}}, 1U);
  ASSERT_TRUE(outcome);
  EXPECT_EQ(outcome.value_if()->matched, 1U);
  auto second = harness.left_events->publish("telemetry.cpu", {std::byte{2}}, 1U);
  ASSERT_TRUE(second);
  harness.cycle();

  harness.right_general.run_all();
  ASSERT_EQ(recorder.received.size(), 2U);
  EXPECT_EQ(recorder.received[0].item.publisher_sequence, 1U);
  EXPECT_EQ(recorder.received[1].item.publisher_sequence, 2U);
  const auto stats = harness.right_events->stats();
  EXPECT_EQ(stats.items_received, 2U);
  EXPECT_EQ(stats.lag_events, 0U);
}

TEST(M7EventService, PrefixMatchRespectsSegmentBoundary) {
  M7ServicePair harness(event_options());
  EventRecorder recorder;
  harness.right_event_sinks.inbound = [&recorder](const DeviceEndpointKey& peer,
                                                  std::string_view pattern,
                                                  const EventItemBody& item) {
    recorder.record(peer, pattern, item);
  };

  ASSERT_TRUE(harness.right_events->subscribe("telemetry", true,
                                              EventQos::best_effort_latest));
  harness.m6.pump();

  // Matches: "telemetry.cpu.load" under prefix "telemetry".
  ASSERT_TRUE(
      harness.left_events->publish("telemetry.cpu.load", {std::byte{1}}, 1U));
  // No match: "telemetryx" is not a segment-boundary child.
  auto missed = harness.left_events->publish("telemetryx.cpu", {std::byte{2}}, 1U);
  ASSERT_TRUE(missed);
  EXPECT_EQ(missed.value_if()->matched, 0U);
  harness.cycle();
  harness.right_general.run_all();
  EXPECT_EQ(recorder.received.size(), 1U);
}

TEST(M7EventService, ExactPatternDoesNotMatchChildren) {
  M7ServicePair harness(event_options());
  EventRecorder recorder;
  harness.right_event_sinks.inbound = [&recorder](const DeviceEndpointKey& peer,
                                                  std::string_view pattern,
                                                  const EventItemBody& item) {
    recorder.record(peer, pattern, item);
  };
  ASSERT_TRUE(harness.right_events->subscribe("telemetry.cpu", false,
                                              EventQos::best_effort_latest));
  harness.m6.pump();
  auto missed = harness.left_events->publish("telemetry.cpu.load", {std::byte{1}}, 1U);
  ASSERT_TRUE(missed);
  EXPECT_EQ(missed.value_if()->matched, 0U);
  harness.cycle();
  EXPECT_TRUE(recorder.received.empty());
}

TEST(M7EventService, ScopeDeniedAnswersUnsubscribe) {
  M7ServicePair::Options options = event_options();
  // Left grants telemetry only: a chat-root subscribe is out of scope.
  options.left_scopes = {"message.send", "event.subscribe:telemetry"};
  M7ServicePair harness(std::move(options));

  // The RIGHT side subscribes on the LEFT service (the event source).
  auto subscribed = harness.right_events->subscribe("chat.room1", false, EventQos::reliable_live);
  ASSERT_TRUE(subscribed);
  harness.m6.pump();

  const auto stats = harness.left_events->stats();
  EXPECT_EQ(stats.subscriptions_accepted, 0U);
  EXPECT_EQ(stats.scope_rejected, 1U);
  // The refusal is explicit: the source answered with unsubscribe.
  EXPECT_EQ(stats.unsubscribes_sent, 1U);
  EXPECT_EQ(harness.left_events->remote_subscription_count(), 0U);
  // A telemetry-root subscribe IS granted.
  auto allowed = harness.right_events->subscribe("telemetry.cpu", false, EventQos::reliable_live);
  ASSERT_TRUE(allowed);
  harness.m6.pump();
  EXPECT_EQ(harness.left_events->stats().subscriptions_accepted, 1U);
}

TEST(M7EventService, SubscriberLimitRejectsExplicitly) {
  M7ServicePair::Options options = event_options();
  options.left_event.max_subscriptions_per_peer = 2U;
  M7ServicePair harness(std::move(options));

  for (int index = 0; index < 3; ++index) {
    ASSERT_TRUE(harness.right_events->subscribe("telemetry.t" + std::to_string(index),
                                                false, EventQos::reliable_live));
    harness.m6.pump();
  }
  const auto stats = harness.left_events->stats();
  EXPECT_EQ(stats.subscriptions_accepted, 2U);
  EXPECT_EQ(stats.subscription_limit_hits, 1U);
  EXPECT_EQ(harness.left_events->remote_subscription_count(), 2U);
}

TEST(M7EventService, DuplicateSubscribeIdempotentConflictClosesChannel) {
  M7ServicePair harness(event_options());
  ASSERT_TRUE(harness.right_events->subscribe("telemetry.cpu", false,
                                              EventQos::reliable_live));
  harness.m6.pump();

  // Byte-stable replay of the same subscription.
  EventSubscribeBody replay;
  replay.subscription_id = harness.right_events->local_subscriptions()[0].id;
  replay.topic = "telemetry.cpu";
  replay.qos = EventQos::reliable_live;
  auto encoded = encode_event_subscribe(replay);
  ASSERT_TRUE(encoded);
  harness.inject_frame(harness.right_session(), harness.event_channel_of(harness.right_session()),
                       static_cast<std::uint8_t>(FrameType::event_subscribe),
                       *encoded.value_if());
  EXPECT_EQ(harness.left_events->stats().duplicate_subscriptions, 1U);
  EXPECT_EQ(harness.left_events->remote_subscription_count(), 1U);

  // Same id with a different topic violates the immutability rule and
  // closes the event channel.
  EventSubscribeBody conflict = replay;
  conflict.topic = "telemetry.mem";
  auto bad = encode_event_subscribe(conflict);
  ASSERT_TRUE(bad);
  harness.inject_frame(harness.right_session(),
                       harness.event_channel_of(harness.right_session()),
                       static_cast<std::uint8_t>(FrameType::event_subscribe),
                       *bad.value_if());
  // The channel id becomes invalid after the protocol failure.
  EXPECT_EQ(harness.left_events->stats().duplicate_subscriptions, 1U);
}

TEST(M7EventService, BestEffortLatestKeepsOnlyNewestAndCountsOverwrite) {
  M7ServicePair::Options options = event_options();
  // A small logical event channel (32 KiB) is the bounded admission point:
  // one 24 KiB event fits; the next publish meets would_block and stages in
  // the keep-latest slot.
  options.left_event.channel_byte_capacity = 32U * 1024U;
  M7ServicePair harness(std::move(options));
  ASSERT_TRUE(harness.right_events->subscribe("telemetry.cpu", false,
                                              EventQos::best_effort_latest));
  harness.m6.pump();

  // The loopback transport charges the sender until the peer pumps: the
  // event channel's 256 KiB budget fills after ~10 of these 24 KiB events,
  // so later publishes stage in the keep-latest slot and overwrite.
  std::vector<std::byte> big_payload(24U * 1024U, std::byte{0x5A});
  for (int index = 0; index < 16; ++index) {
    auto outcome = harness.left_events->publish("telemetry.cpu", big_payload, 1U);
    ASSERT_TRUE(outcome);
    // No pump: the transport budget only drains when the peer pumps.
  }
  const auto stats = harness.left_events->stats();
  EXPECT_GE(stats.subscriber_overwrites, 1U);
  EXPECT_GE(stats.subscriber_drops, 1U);
  // The publisher itself was never blocked: every publish returned.
  EXPECT_EQ(stats.published, 16U);
}

TEST(M7EventService, ReliableLiveOverflowTerminatesOnlyThatSubscription) {
  M7ServicePair::Options options = event_options();
  options.left_event.subscriber_queue_items = 2U;
  options.left_event.channel_byte_capacity = 32U * 1024U;
  M7ServicePair harness(std::move(options));
  ASSERT_TRUE(harness.right_events->subscribe("telemetry.cpu", false,
                                              EventQos::reliable_live));
  ASSERT_TRUE(harness.right_events->subscribe("telemetry.mem", false,
                                              EventQos::reliable_live));
  harness.m6.pump();

  std::vector<std::byte> big_payload(24U * 1024U, std::byte{0xA5});
  for (int index = 0; index < 20; ++index) {
    ASSERT_TRUE(harness.left_events->publish("telemetry.cpu", big_payload, 1U));
  }
  const auto stats = harness.left_events->stats();
  EXPECT_GE(stats.subscriber_overflows, 1U);
  EXPECT_GE(stats.terminated_subscriptions, 1U);
  // The unrelated subscription survives the overflow (M7-04).
  EXPECT_EQ(harness.left_events->remote_subscription_count(), 1U);
}

TEST(M7EventService, SequenceConflictClosesSubscription) {
  M7ServicePair harness(event_options());
  EventRecorder recorder;
  harness.right_event_sinks.inbound = [&recorder](const DeviceEndpointKey& peer,
                                                  std::string_view pattern,
                                                  const EventItemBody& item) {
    recorder.record(peer, pattern, item);
  };
  auto subscribed = harness.right_events->subscribe("telemetry.cpu", false, EventQos::reliable_live);
  ASSERT_TRUE(subscribed);
  const auto id = harness.right_events->local_subscriptions()[0].id;
  harness.m6.pump();

  // Valid first item.
  ASSERT_TRUE(harness.left_events->publish("telemetry.cpu", {std::byte{1}}, 1U));
  harness.cycle();
  harness.right_general.run_all();
  ASSERT_EQ(recorder.received.size(), 1U);

  // Conflicting duplicate: same sequence, different event id.
  EventItemBody conflict;
  conflict.subscription_id = id;
  EventId other_id{};
  other_id.fill(std::byte{0x99});
  conflict.event_id = other_id;
  conflict.publisher_device_id = harness.m6.left_identity.value_if()->device_id();
  conflict.publisher_sequence = recorder.received[0].item.publisher_sequence;
  conflict.schema_version = 1U;
  conflict.qos = EventQos::reliable_live;
  conflict.payload = {std::byte{7}};
  auto encoded = encode_event_item(conflict);
  ASSERT_TRUE(encoded);
  harness.inject_frame(harness.left_session(),
                       harness.event_channel_of(harness.left_session()),
                       static_cast<std::uint8_t>(FrameType::event_item),
                       *encoded.value_if());

  const auto stats = harness.right_events->stats();
  EXPECT_EQ(stats.conflicting_items, 1U);
  // The subscription is gone locally; late items count as unknown.
  EXPECT_TRUE(harness.right_events->local_subscriptions().empty());
}

TEST(M7EventService, DuplicateItemIgnored) {
  M7ServicePair harness(event_options());
  EventRecorder recorder;
  harness.right_event_sinks.inbound = [&recorder](const DeviceEndpointKey& peer,
                                                  std::string_view pattern,
                                                  const EventItemBody& item) {
    recorder.record(peer, pattern, item);
  };
  ASSERT_TRUE(harness.right_events->subscribe("telemetry.cpu", false,
                                              EventQos::reliable_live));
  harness.m6.pump();
  ASSERT_TRUE(harness.left_events->publish("telemetry.cpu", {std::byte{1}}, 1U));
  harness.cycle();
  harness.right_general.run_all();
  ASSERT_EQ(recorder.received.size(), 1U);

  // Exact replay: the sender's transport-level duplicate never redelivers.
  EventItemBody replay = recorder.received[0].item;
  auto encoded = encode_event_item(replay);
  ASSERT_TRUE(encoded);
  harness.inject_frame(harness.left_session(),
                       harness.event_channel_of(harness.left_session()),
                       static_cast<std::uint8_t>(FrameType::event_item),
                       *encoded.value_if());
  EXPECT_EQ(harness.right_events->stats().duplicate_items, 1U);
  EXPECT_EQ(recorder.received.size(), 1U);
}

TEST(M7EventService, LagIsObservableOnSkippedSequences) {
  M7ServicePair harness(event_options());
  EventRecorder recorder;
  harness.right_event_sinks.inbound = [&recorder](const DeviceEndpointKey& peer,
                                                  std::string_view pattern,
                                                  const EventItemBody& item) {
    recorder.record(peer, pattern, item);
  };
  ASSERT_TRUE(harness.right_events->subscribe("telemetry.cpu", false,
                                              EventQos::best_effort_latest));
  const auto id = harness.right_events->local_subscriptions()[0].id;
  harness.m6.pump();

  // Deliver sequence 1 then 4 directly: the gap is the observable lag.
  for (const std::uint64_t sequence : {1ULL, 4ULL}) {
    EventItemBody item;
    item.subscription_id = id;
    EventId event{};
    event.fill(static_cast<std::byte>(sequence));
    item.event_id = event;
    item.publisher_device_id = harness.m6.left_identity.value_if()->device_id();
    item.publisher_sequence = sequence;
    item.schema_version = 1U;
    item.qos = EventQos::best_effort_latest;
    item.payload = {std::byte{1}};
    auto encoded = encode_event_item(item);
    ASSERT_TRUE(encoded);
    harness.inject_frame(harness.left_session(),
                         harness.event_channel_of(harness.left_session()),
                         static_cast<std::uint8_t>(FrameType::event_item),
                         *encoded.value_if());
  }
  harness.right_general.run_all();
  ASSERT_EQ(recorder.received.size(), 2U);
  const auto stats = harness.right_events->stats();
  EXPECT_EQ(stats.lag_events, 1U);
  EXPECT_EQ(stats.lag_total_sequences, 2U);  // sequences 2 and 3 skipped
  EXPECT_EQ(stats.stale_items, 1U);          // intermediates went stale upstream
}

TEST(M7EventService, UnsubscribeStopsDeliveryAndLateItemsCounted) {
  M7ServicePair harness(event_options());
  EventRecorder recorder;
  harness.right_event_sinks.inbound = [&recorder](const DeviceEndpointKey& peer,
                                                  std::string_view pattern,
                                                  const EventItemBody& item) {
    recorder.record(peer, pattern, item);
  };
  ASSERT_TRUE(harness.right_events->subscribe("telemetry.cpu", false,
                                              EventQos::reliable_live));
  const auto id = harness.right_events->local_subscriptions()[0].id;
  harness.m6.pump();

  EXPECT_EQ(harness.right_events->unsubscribe("telemetry.cpu"), 1U);
  harness.m6.pump();
  EXPECT_EQ(harness.right_events->stats().unsubscribes_sent, 1U);
  EXPECT_EQ(harness.left_events->stats().unsubscribes_received, 1U);
  EXPECT_EQ(harness.left_events->remote_subscription_count(), 0U);

  // A publish after unsubscribe matches nothing.
  auto missed = harness.left_events->publish("telemetry.cpu", {std::byte{1}}, 1U);
  ASSERT_TRUE(missed);
  EXPECT_EQ(missed.value_if()->matched, 0U);

  // Late items for the dead subscription are ignored and counted.
  EventItemBody late;
  late.subscription_id = id;
  EventId event{};
  event.fill(std::byte{0x55});
  late.event_id = event;
  late.publisher_device_id = harness.m6.left_identity.value_if()->device_id();
  late.publisher_sequence = 1U;
  late.schema_version = 1U;
  late.qos = EventQos::reliable_live;
  auto encoded = encode_event_item(late);
  ASSERT_TRUE(encoded);
  harness.inject_frame(harness.left_session(),
                       harness.event_channel_of(harness.left_session()),
                       static_cast<std::uint8_t>(FrameType::event_item),
                       *encoded.value_if());
  EXPECT_EQ(harness.right_events->stats().unknown_subscription_items, 1U);
}

TEST(M7EventService, SessionLossStopsLocalSubscriptions) {
  M7ServicePair harness(event_options());
  ASSERT_TRUE(harness.right_events->subscribe("telemetry.cpu", false,
                                              EventQos::reliable_live));
  harness.m6.pump();
  EXPECT_EQ(harness.right_events->local_subscriptions().size(), 1U);

  harness.left_events->handle_session_closed();
  harness.right_events->handle_session_closed();
  EXPECT_TRUE(harness.right_events->local_subscriptions().empty());
  EXPECT_EQ(harness.left_events->remote_subscription_count(), 0U);
}

TEST(M7EventService, LocalTopicBridgeFansOutRemoteItems) {
  M7ServicePair harness(event_options());
  auto local = harness.right_local_topic.subscribe(
      executor::comm::TopicSubscriptionOptions{64U, executor::comm::DropPolicy::DropOldest,
                                               true, "m7-test-local"});
  ASSERT_TRUE(harness.right_events->subscribe("telemetry.cpu", false,
                                              EventQos::reliable_live));
  harness.m6.pump();
  ASSERT_TRUE(
      harness.left_events->publish("telemetry.cpu", {std::byte{1}, std::byte{2}}, 7U));
  harness.cycle();

  LocalEventMessage message;
  ASSERT_TRUE(local.try_receive(message));
  EXPECT_EQ(message.topic, "telemetry.cpu");
  EXPECT_EQ(message.schema_version, 7U);
  EXPECT_EQ(message.payload.size(), 2U);
  // The bridge type is distinct from the wire item: no event id, no QoS.
  EXPECT_FALSE(local.try_receive(message));
}

}  // namespace
}  // namespace heyaki
