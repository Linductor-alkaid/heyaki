// M6 message service tests: envelope contract (M6-01), best_effort and
// peer_acked semantics (M6-02/M6-03), bounded TTL deduplication (M6-04),
// scope gating and executor dispatch (M6-05), and offline behavior (M6-06).
// All races (duplicate frames, late ACKs, TTL expiry) are driven
// deterministically through the manual dispatch/poster queues.

#include "m6_support.hpp"

#include <heyaki/message.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <optional>
#include <vector>

namespace heyaki {
namespace {

TEST(M6MessageProtocolTest, EnvelopeValidationRejectsInvalidShapes) {
  const Limits limits;
  MessageEnvelope envelope;
  envelope.type = "test.ping";
  envelope.ttl_milliseconds = 1000U;
  envelope.message_id = MessageId{MessageId::Storage{std::byte{1}}};

  EXPECT_TRUE(validate_message_envelope(envelope, limits));

  auto invalid = envelope;
  invalid.type.clear();
  EXPECT_FALSE(validate_message_envelope(invalid, limits));

  invalid = envelope;
  invalid.type = std::string(max_message_type_bytes + 1U, 'a');
  EXPECT_FALSE(validate_message_envelope(invalid, limits));

  invalid = envelope;
  invalid.ttl_milliseconds = 0U;
  EXPECT_FALSE(validate_message_envelope(invalid, limits));

  invalid = envelope;
  invalid.ttl_milliseconds = max_message_ttl_milliseconds + 1U;
  EXPECT_FALSE(validate_message_envelope(invalid, limits));

  invalid = envelope;
  invalid.schema_version = 0U;
  EXPECT_FALSE(validate_message_envelope(invalid, limits));

  invalid = envelope;
  invalid.payload = std::vector<std::byte>(limits.max_message_bytes + 1U);
  EXPECT_FALSE(validate_message_envelope(invalid, limits));

  invalid = envelope;
  invalid.headers.resize(max_message_headers + 1U);
  EXPECT_FALSE(validate_message_envelope(invalid, limits));

  invalid = envelope;
  invalid.headers.push_back({"bad name!", {}});
  EXPECT_FALSE(validate_message_envelope(invalid, limits));

  invalid = envelope;
  invalid.headers.push_back({"ok", std::vector<std::byte>(max_message_header_value_bytes + 1U)});
  EXPECT_FALSE(validate_message_envelope(invalid, limits));
}

TEST(M6MessageProtocolTest, EnvelopeCodecRoundTripsAndFreezesWireBytes) {
  MessageEnvelope envelope;
  MessageId::Storage id{};
  id[0] = std::byte{0xAB};
  envelope.message_id = MessageId{id};
  envelope.type = "demo.tick";
  envelope.schema_version = 2U;
  envelope.ttl_milliseconds = 5000U;
  envelope.delivery_mode = MessageDeliveryMode::peer_acked;
  envelope.headers.push_back({"unit", {std::byte{9}}});
  envelope.payload = {std::byte{0xDE}, std::byte{0xAD}};
  envelope.wall_time_unix_milliseconds = 1'700'000'000'123U;

  auto encoded = encode_message_envelope(envelope);
  ASSERT_TRUE(encoded);
  auto parsed = parse_message_envelope(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->message_id, envelope.message_id);
  EXPECT_EQ(parsed.value_if()->type, envelope.type);
  EXPECT_EQ(parsed.value_if()->schema_version, 2U);
  EXPECT_EQ(parsed.value_if()->ttl_milliseconds, 5000U);
  EXPECT_EQ(parsed.value_if()->delivery_mode, MessageDeliveryMode::peer_acked);
  ASSERT_EQ(parsed.value_if()->headers.size(), 1U);
  EXPECT_EQ(parsed.value_if()->headers[0].name, "unit");
  EXPECT_EQ(parsed.value_if()->headers[0].value,
            std::vector<std::byte>{std::byte{9}});
  EXPECT_EQ(parsed.value_if()->payload, envelope.payload);
  EXPECT_EQ(parsed.value_if()->wall_time_unix_milliseconds,
            envelope.wall_time_unix_milliseconds);

  // Golden bytes: field 1 (id), 2 (type), 3 (schema), 4 (ttl), 5 (mode),
  // 8 (wall time) are deterministic; regenerating changes wire compatibility.
  // 0A 10 <16 id bytes> 12 08 "demo.tick" 18 02 20 A0 1F 28 02 40 ...
  ASSERT_GE(encoded.value_if()->size(), 10U);
  EXPECT_EQ((*encoded.value_if())[0], std::byte{0x0A});
  EXPECT_EQ((*encoded.value_if())[1], std::byte{0x10});
  EXPECT_EQ((*encoded.value_if())[2], std::byte{0xAB});
  EXPECT_EQ((*encoded.value_if())[3], std::byte{0x00});

  // Truncated and garbage payloads never parse.
  EXPECT_FALSE(parse_message_envelope({}));
  const std::vector<std::byte> garbage(8U, std::byte{0xFF});
  EXPECT_FALSE(parse_message_envelope(garbage));
}

TEST(M6MessageProtocolTest, AckCodecRoundTrip) {
  MessageId::Storage id{};
  id[15] = std::byte{0x07};
  auto encoded = encode_message_ack(MessageAckBody{MessageId{id}, true});
  ASSERT_TRUE(encoded);
  auto parsed = parse_message_ack(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->message_id, MessageId{id});
  EXPECT_TRUE(parsed.value_if()->protocol_accepted);

  const std::vector<std::byte> garbage(6U, std::byte{0x01});
  EXPECT_FALSE(parse_message_ack(garbage));
}

TEST(M6MessageServiceTest, BestEffortCompletesAtQueueAdmission) {
  test::M6ServicePair harness;
  std::vector<MessageEnvelope> received;
  harness.right_messages->set_inbound_handler(
      [&received](const MessageEnvelope& envelope) { received.push_back(envelope); });

  auto envelope = harness.make_envelope("test.best", MessageDeliveryMode::best_effort);
  auto sent = harness.left_messages->send(envelope);
  ASSERT_TRUE(sent);
  // Completion point: the frame entered the bounded queue (send returned);
  // no lifecycle event exists for best_effort.
  harness.pump();
  harness.right_dispatch.run_all();
  ASSERT_EQ(received.size(), 1U);
  EXPECT_EQ(received[0].type, "test.best");
  const auto stats = harness.left_messages->stats();
  EXPECT_EQ(stats.sent_best_effort, 1U);
  EXPECT_EQ(stats.sent_peer_acked, 0U);
  EXPECT_EQ(harness.right_messages->stats().received, 1U);
  EXPECT_EQ(harness.right_messages->stats().acks_sent, 0U);
}

TEST(M6MessageServiceTest, PeerAckedAcksAfterBasicValidationOnly) {
  test::M6ServicePair harness;
  std::vector<MessageEnvelope> received;
  harness.right_messages->set_inbound_handler(
      [&received](const MessageEnvelope& envelope) { received.push_back(envelope); });

  std::vector<std::pair<MessageId, MessageDeliveryEvent>> events;
  harness.left_messages->set_ack_observer(
      [&events](const MessageId& id, MessageDeliveryEvent event, std::optional<Error>) {
        events.emplace_back(id, event);
      });

  auto envelope =
      harness.make_envelope("test.acked", MessageDeliveryMode::peer_acked);
  auto sent = harness.left_messages->send(envelope);
  ASSERT_TRUE(sent);
  EXPECT_EQ(events.size(), 1U);
  EXPECT_EQ(events[0].second, MessageDeliveryEvent::queued);

  harness.pump();
  // Handler has NOT run yet (task still queued): the ACK already went out at
  // protocol level — an ACK never claims handler execution (M6-03).
  EXPECT_EQ(harness.right_messages->stats().acks_sent, 1U);
  EXPECT_TRUE(received.empty());
  EXPECT_TRUE(harness.right_dispatch.has_pending());

  harness.pair.left().pump();  // deliver the ACK back
  EXPECT_EQ(harness.left_messages->stats().acked, 1U);
  ASSERT_EQ(events.size(), 2U);
  EXPECT_EQ(events[1].first, *sent.value_if());
  EXPECT_EQ(events[1].second, MessageDeliveryEvent::acked);

  harness.right_dispatch.run_all();
  ASSERT_EQ(received.size(), 1U);
}

TEST(M6MessageServiceTest, AckLossSurfacesAsTtlTimeout) {
  test::M6ServicePair harness;
  // No inbound handler on the right and no ACK path: simulate a lost ACK by
  // detaching the right service before the frame arrives.
  harness.right_messages.reset();

  std::vector<MessageDeliveryEvent> events;
  harness.left_messages->set_ack_observer(
      [&events](const MessageId&, MessageDeliveryEvent event, std::optional<Error>) {
        events.push_back(event);
      });

  auto envelope = harness.make_envelope("test.lost", MessageDeliveryMode::peer_acked,
                                        {std::byte{5}}, 1000U);
  ASSERT_TRUE(harness.left_messages->send(envelope));
  harness.pump();
  EXPECT_EQ(events.size(), 1U);  // queued only

  // TTL has not expired yet.
  harness.left_messages->prune();
  EXPECT_EQ(events.size(), 1U);

  harness.left_clock += 1001U;
  harness.left_messages->prune();
  ASSERT_EQ(events.size(), 2U);
  EXPECT_EQ(events[1], MessageDeliveryEvent::ack_timeout);
  EXPECT_EQ(harness.left_messages->stats().ack_timed_out, 1U);
  EXPECT_EQ(harness.left_messages->pending_acks(), 0U);
}

TEST(M6MessageServiceTest, DuplicateEnvelopeDeliveredOnceAndAckReplayed) {
  test::M6ServicePair harness;
  std::vector<MessageEnvelope> received;
  harness.right_messages->set_inbound_handler(
      [&received](const MessageEnvelope& envelope) { received.push_back(envelope); });

  const auto envelope =
      harness.make_envelope("test.dup", MessageDeliveryMode::peer_acked);
  ASSERT_TRUE(harness.left_messages->send(envelope));
  harness.pump();
  harness.right_dispatch.run_all();
  EXPECT_EQ(received.size(), 1U);

  // Re-send the identical envelope (send keeps a non-zero id): duplicate,
  // no redelivery, ACK replayed.
  auto sent_again = harness.left_messages->send(envelope);
  ASSERT_TRUE(sent_again);
  EXPECT_EQ(*sent_again.value_if(), envelope.message_id);
  harness.pump();
  harness.right_dispatch.run_all();

  EXPECT_EQ(received.size(), 1U);
  EXPECT_EQ(harness.right_messages->stats().duplicates, 1U);
  EXPECT_EQ(harness.right_messages->stats().acks_sent, 2U);  // original + replay
}

TEST(M6MessageServiceTest, SameIdDifferentBytesIsProtocolViolation) {
  test::M6ServicePair harness;
  std::vector<MessageEnvelope> received;
  harness.right_messages->set_inbound_handler(
      [&received](const MessageEnvelope& envelope) { received.push_back(envelope); });

  auto first = harness.make_envelope("test.conflict", MessageDeliveryMode::best_effort);
  ASSERT_TRUE(harness.left_messages->send(first));
  harness.pump();
  harness.right_dispatch.run_all();
  ASSERT_EQ(received.size(), 1U);

  // Same message id, changed payload: the immutable-envelope rule is broken
  // (wire protocol 6.2) and the message channel closes — the frame is never
  // delivered and the session keeps the other channels.
  auto second = first;
  second.payload = {std::byte{0x99}};
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::message);
  auto encoded = encode_message_envelope(second);
  ASSERT_TRUE(encoded);
  frame.payload = *encoded.value_if();
  const auto snapshots = harness.left->channels().channel_snapshots();
  ASSERT_FALSE(snapshots.empty());
  const auto message_channel = snapshots.front().channel_id;
  ASSERT_EQ(harness.left->channels().channel_domain(message_channel),
            session::ChannelDomain::message);
  ASSERT_TRUE(harness.left->send_frame(message_channel, session::FrameClass::standard,
                                       std::move(frame)));
  harness.pump();

  EXPECT_EQ(received.size(), 1U);  // conflicting frame not delivered
  EXPECT_EQ(harness.right_messages->stats().received, 1U);
}

TEST(M6MessageServiceTest, DedupEntryExpiresAfterTtl) {
  test::M6ServicePair harness;
  std::vector<MessageEnvelope> received;
  harness.right_messages->set_inbound_handler(
      [&received](const MessageEnvelope& envelope) { received.push_back(envelope); });

  const auto envelope = harness.make_envelope("test.ttl", MessageDeliveryMode::best_effort,
                                              {std::byte{7}}, 500U);
  ASSERT_TRUE(harness.left_messages->send(envelope));
  harness.pump();
  harness.right_dispatch.run_all();
  ASSERT_EQ(received.size(), 1U);
  EXPECT_EQ(harness.right_messages->dedup_entries(), 1U);

  harness.right_clock += 501U;
  harness.right_messages->prune();
  EXPECT_EQ(harness.right_messages->dedup_entries(), 0U);
  EXPECT_EQ(harness.right_messages->stats().dedup_expired, 1U);

  // After expiry the same id may deliver again (documented duplicate risk;
  // handlers must be idempotent past the TTL window).
  ASSERT_TRUE(harness.left_messages->send(envelope));
  harness.pump();
  harness.right_dispatch.run_all();
  EXPECT_EQ(received.size(), 2U);
}

TEST(M6MessageServiceTest, DedupCapacityEvictsBounded) {
  test::M6ServicePair::Options options;
  options.right_message.dedup_capacity = 2U;
  test::M6ServicePair harness{options};
  std::vector<MessageEnvelope> received;
  harness.right_messages->set_inbound_handler(
      [&received](const MessageEnvelope& envelope) { received.push_back(envelope); });

  for (int index = 0; index < 3; ++index) {
    auto envelope = harness.make_envelope("test.cap");
    envelope.ttl_milliseconds = 60'000U;
    ASSERT_TRUE(harness.left_messages->send(envelope));
    harness.pump();
  }
  harness.right_dispatch.run_all();
  EXPECT_EQ(received.size(), 3U);
  EXPECT_EQ(harness.right_messages->dedup_entries(), 2U);
  EXPECT_GE(harness.right_messages->stats().dedup_evictions, 1U);
}

TEST(M6MessageServiceTest, ScopeMissingBlocksHandlerAndAck) {
  // The right side's session has no message.send scope: inbound frames are
  // rejected before any ACK or handler runs (M6-05).
  test::M6ServicePair::Options options;
  options.right_scopes = {"rpc.device.read"};
  test::M6ServicePair harness{options};
  std::vector<MessageEnvelope> received;
  harness.right_messages->set_inbound_handler(
      [&received](const MessageEnvelope& envelope) { received.push_back(envelope); });

  const auto envelope =
      harness.make_envelope("test.scope", MessageDeliveryMode::peer_acked);
  ASSERT_TRUE(harness.left_messages->send(envelope));
  harness.pump();

  EXPECT_TRUE(received.empty());
  const auto stats = harness.right_messages->stats();
  EXPECT_EQ(stats.scope_rejected, 1U);
  EXPECT_EQ(stats.acks_sent, 0U);  // unauthorized: no protocol service
  EXPECT_EQ(stats.received, 0U);
}

TEST(M6MessageServiceTest, InvalidEnvelopeCountedWithoutAck) {
  test::M6ServicePair harness;
  // Inject a malformed MESSAGE frame directly at the right service on an
  // existing message channel.
  static constexpr std::array<std::byte, 1> kTruncated = {std::byte{0x01}};
  FrameView view;
  view.type = static_cast<std::uint8_t>(FrameType::message);
  view.channel_id = harness.message_channel_of(*harness.right);
  view.payload = kTruncated;  // invalid tag/id field
  harness.right_messages->handle_frame(view);
  EXPECT_EQ(harness.right_messages->stats().invalid_envelopes, 1U);
  EXPECT_EQ(harness.right_messages->stats().received, 0U);
}

TEST(M6MessageServiceTest, HandlerExceptionIsContained) {
  test::M6ServicePair harness;
  harness.right_messages->set_inbound_handler([](const MessageEnvelope&) {
    throw std::runtime_error("handler exploded");
  });

  const auto envelope = harness.make_envelope("test.throw");
  ASSERT_TRUE(harness.left_messages->send(envelope));
  harness.pump();
  harness.right_dispatch.run_all();
  harness.right_messages->prune();  // merge dispatch records

  const auto stats = harness.right_messages->stats();
  EXPECT_EQ(stats.received, 1U);
  EXPECT_EQ(stats.dispatched, 1U);
  EXPECT_EQ(stats.handler_exceptions, 1U);
  EXPECT_EQ(stats.handler_completed, 0U);
}

TEST(M6MessageServiceTest, DispatchRejectionIsObservable) {
  test::M6ServicePair harness;
  harness.right_dispatch.admit = false;

  std::vector<MessageEnvelope> received;
  harness.right_messages->set_inbound_handler(
      [&received](const MessageEnvelope& envelope) { received.push_back(envelope); });

  const auto envelope = harness.make_envelope("test.full");
  ASSERT_TRUE(harness.left_messages->send(envelope));
  harness.pump();

  EXPECT_TRUE(received.empty());
  const auto stats = harness.right_messages->stats();
  EXPECT_EQ(stats.dispatch_rejected, 1U);
  EXPECT_EQ(stats.dispatched, 1U);
  EXPECT_EQ(stats.handler_completed, 0U);
}

TEST(M6MessageServiceTest, SessionClosedFailsPendingAcks) {
  test::M6ServicePair harness;
  std::vector<MessageDeliveryEvent> events;
  harness.left_messages->set_ack_observer(
      [&events](const MessageId&, MessageDeliveryEvent event, std::optional<Error>) {
        events.push_back(event);
      });

  const auto envelope =
      harness.make_envelope("test.close", MessageDeliveryMode::peer_acked,
                            {std::byte{3}}, 60'000U);
  ASSERT_TRUE(harness.left_messages->send(envelope));
  // Deliberately NOT pumped: the ACK is still in flight when the session dies.

  harness.left->close(transport::CloseReason::transport_failed);
  harness.left_messages->handle_session_closed();
  ASSERT_EQ(events.size(), 2U);
  EXPECT_EQ(events[1], MessageDeliveryEvent::session_closed);
  EXPECT_EQ(harness.left_messages->stats().acks_on_closed, 1U);
}

TEST(M6MessageServiceTest, UnknownAckCountedAndIgnored) {
  test::M6ServicePair harness;
  // An ACK for an id we never sent must not disturb state.
  FrameView view;
  MessageId::Storage id{};
  id[3] = std::byte{0x2A};
  auto encoded = encode_message_ack(MessageAckBody{MessageId{id}, true});
  ASSERT_TRUE(encoded);
  view.type = static_cast<std::uint8_t>(FrameType::message_ack);
  view.payload = *encoded.value_if();
  harness.left_messages->handle_frame(view);
  EXPECT_EQ(harness.left_messages->stats().unknown_acks, 1U);
  EXPECT_EQ(harness.left_messages->stats().acked, 0U);
}

}  // namespace
}  // namespace heyaki
