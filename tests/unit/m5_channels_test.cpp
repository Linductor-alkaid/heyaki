// M5 channel manager tests: budgets with control reservation (M5-03),
// weighted scheduling without starvation (M5-04), and queue policies with
// cancellable capacity waits (M5-05).

#include "session_channels.hpp"

#include <heyaki/wire.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <random>

namespace heyaki::session {
namespace {

Frame make_frame(std::uint8_t type, std::uint32_t channel, std::size_t payload) {
  Frame frame;
  frame.type = type;
  frame.channel_id = channel;
  MessageId::Storage id{};
  id[0] = static_cast<std::byte>(payload & 0xFFU);
  id[1] = static_cast<std::byte>((payload >> 8U) & 0xFFU);
  id[2] = std::byte{1U};
  frame.message_id = MessageId{id};
  frame.payload.assign(payload, std::byte{0x5A});
  return frame;
}

TEST(M5ChannelBudgetConfig, InvalidConfigurationsFail) {
  ChannelBudgetConfig zero_channels;
  zero_channels.max_open_channels = 0U;
  EXPECT_FALSE(validate_channel_budget_config(zero_channels));
  ChannelBudgetConfig zero_budget;
  zero_budget.per_peer_queued_bytes = 0U;
  EXPECT_FALSE(validate_channel_budget_config(zero_budget));
  ChannelBudgetConfig zero_reservation;
  zero_reservation.control_reserved_frames = 0U;
  EXPECT_FALSE(validate_channel_budget_config(zero_reservation));
  ChannelBudgetConfig inverted;
  inverted.control_reserved_bytes = inverted.per_peer_queued_bytes + 1U;
  EXPECT_FALSE(validate_channel_budget_config(inverted));
  EXPECT_TRUE(validate_channel_budget_config(ChannelBudgetConfig{}));
}

TEST(M5ChannelManager, AllocatesParityIdsAndBoundsOpenChannels) {
  SessionChannelManager manager(ChannelBudgetConfig{});
  auto initiator_channel = manager.allocate_channel(true, ChannelDomain::message,
                                                    QueueFullPolicy::reject, 8U, 8192U);
  auto responder_channel = manager.allocate_channel(false, ChannelDomain::message,
                                                    QueueFullPolicy::reject, 8U, 8192U);
  ASSERT_TRUE(initiator_channel && responder_channel);
  EXPECT_EQ(*initiator_channel.value_if() % 2U, 1U);
  EXPECT_EQ(*responder_channel.value_if() % 2U, 0U);
  EXPECT_NE(*initiator_channel.value_if(), *responder_channel.value_if());
  EXPECT_EQ(manager.open_channel_count(), 2U);

  ChannelBudgetConfig single;
  single.max_open_channels = 1U;
  SessionChannelManager capped(single);
  ASSERT_TRUE(capped.allocate_channel(true, ChannelDomain::message,
                                      QueueFullPolicy::reject, 8U, 8192U));
  auto overflow = capped.allocate_channel(true, ChannelDomain::message,
                                          QueueFullPolicy::reject, 8U, 8192U);
  ASSERT_FALSE(overflow);
  EXPECT_EQ(overflow.error_if()->code(), ErrorCode::resource_exhausted);
}

TEST(M5ChannelManager, RejectPolicyReturnsWouldBlockAndCapacityWaitFires) {
  SessionChannelManager manager(ChannelBudgetConfig{});
  auto channel = manager.allocate_channel(true, ChannelDomain::message,
                                          QueueFullPolicy::reject, 2U, 1U << 20U);
  ASSERT_TRUE(channel);
  const auto id = *channel.value_if();
  ASSERT_TRUE(manager.enqueue(id, FrameClass::standard, make_frame(0x20U, id, 16U)));
  ASSERT_TRUE(manager.enqueue(id, FrameClass::standard, make_frame(0x20U, id, 16U)));
  auto third = manager.enqueue(id, FrameClass::standard, make_frame(0x20U, id, 16U));
  ASSERT_FALSE(third);
  EXPECT_EQ(third.error_if()->code(), ErrorCode::would_block);

  bool completed = false;
  auto ticket_result = manager.wait_for_capacity(
      id, [&completed](Result<void> result) {
        completed = true;
        EXPECT_TRUE(result);
      });
  ASSERT_TRUE(ticket_result);

  // Draining one frame frees exactly one slot: the waiter completes.
  auto drained = manager.next_to_send();
  ASSERT_TRUE(drained.has_value());
  EXPECT_TRUE(completed);
  EXPECT_EQ(manager.total_queued_frames(), 1U);

  // A wait registered while the queue is full stays pending until capacity
  // appears or the ticket is cancelled; cancellation reports it exactly once.
  ASSERT_TRUE(manager.enqueue(id, FrameClass::standard, make_frame(0x20U, id, 16U)));
  bool cancelled = false;
  auto pending = manager.wait_for_capacity(
      id, [&cancelled](Result<void> result) {
        cancelled = true;
        ASSERT_FALSE(result);
        EXPECT_EQ(result.error_if()->code(), ErrorCode::cancelled);
      });
  ASSERT_TRUE(pending);
  pending.value_if()->cancel();
  EXPECT_TRUE(cancelled);
  EXPECT_EQ(manager.total_queued_frames(), 2U);
}

TEST(M5ChannelManager, DropOldestAndKeepLatestPoliciesStayObservable) {
  {
    SessionChannelManager manager(ChannelBudgetConfig{});
    auto channel = manager.allocate_channel(true, ChannelDomain::event,
                                            QueueFullPolicy::drop_oldest, 2U, 1U << 20U);
    ASSERT_TRUE(channel);
    const auto id = *channel.value_if();
    for (int round = 0; round < 6; ++round) {
      auto enqueued =
          manager.enqueue(id, FrameClass::bulk, make_frame(0x41U, id, 16U));
      ASSERT_TRUE(enqueued);
    }
    EXPECT_EQ(manager.total_queued_frames(), 2U);
    const auto stats = manager.channel_snapshots();
    ASSERT_EQ(stats.size(), 1U);
    EXPECT_EQ(stats[0].stats.dropped_frames, 4U);
  }
  {
    SessionChannelManager manager(ChannelBudgetConfig{});
    auto channel = manager.allocate_channel(true, ChannelDomain::event,
                                            QueueFullPolicy::keep_latest, 4U, 1U << 20U);
    ASSERT_TRUE(channel);
    const auto id = *channel.value_if();
    for (int round = 0; round < 6; ++round) {
      auto enqueued =
          manager.enqueue(id, FrameClass::bulk, make_frame(0x41U, id, 16U));
      ASSERT_TRUE(enqueued);
    }
    // keep_latest drops all superseded frames: exactly one stays queued.
    EXPECT_EQ(manager.total_queued_frames(), 1U);
    const auto stats = manager.channel_snapshots();
    EXPECT_EQ(stats[0].stats.dropped_frames, 5U);
  }
}

TEST(M5ChannelManager, PeerBudgetExhaustionAlwaysRejects) {
  ChannelBudgetConfig config;
  config.per_peer_queued_bytes = 4096U;
  SessionChannelManager manager(config);
  auto first = manager.allocate_channel(true, ChannelDomain::file,
                                        QueueFullPolicy::drop_oldest, 64U, 1U << 20U);
  auto second = manager.allocate_channel(true, ChannelDomain::file,
                                         QueueFullPolicy::drop_oldest, 64U, 1U << 20U);
  ASSERT_TRUE(first && second);
  // Fill the peer budget across both channels.
  while (manager.enqueue(*first.value_if(), FrameClass::bulk,
                         make_frame(0x62U, *first.value_if(), 512U))) {
  }
  const auto queued_at_limit = manager.total_queued_bytes();
  EXPECT_LE(queued_at_limit, config.per_peer_queued_bytes);
  auto overflow = manager.enqueue(*second.value_if(), FrameClass::bulk,
                                  make_frame(0x62U, *second.value_if(), 512U));
  ASSERT_FALSE(overflow);
  EXPECT_EQ(overflow.error_if()->code(), ErrorCode::would_block);
  EXPECT_EQ(overflow.error_if()->safe_detail(), "per_peer_budget_full");
}

TEST(M5ChannelManager, ControlFramesFlowWhileBulkBacksUp) {
  SessionChannelManager manager(ChannelBudgetConfig{});
  auto bulk = manager.allocate_channel(true, ChannelDomain::file,
                                       QueueFullPolicy::drop_oldest, 1024U, 1U << 20U);
  ASSERT_TRUE(bulk);
  const auto bulk_id = *bulk.value_if();
  // Fill the bulk channel with a large backlog.
  for (int round = 0; round < 64; ++round) {
    auto enqueued =
        manager.enqueue(bulk_id, FrameClass::bulk, make_frame(0x62U, bulk_id, 1024U));
    ASSERT_TRUE(enqueued);
  }
  // A control frame joins the queue after all the bulk traffic.
  ASSERT_TRUE(manager.enqueue(bulk_id, FrameClass::control,
                              make_frame(0x52U, bulk_id, 16U)));
  std::size_t bulk_sent = 0U;
  std::size_t control_sent = 0U;
  std::size_t position_of_control = 0U;
  std::size_t position = 0U;
  while (manager.has_sendable_frames()) {
    auto next = manager.next_to_send();
    ASSERT_TRUE(next.has_value());
    ++position;
    if (next->frame_class == FrameClass::control) {
      ++control_sent;
      if (position_of_control == 0U) position_of_control = position;
    } else {
      ++bulk_sent;
    }
  }
  EXPECT_EQ(control_sent, 1U);
  EXPECT_EQ(bulk_sent, 64U);
  // Control preempts: the window update is transmitted long before the bulk
  // backlog drains despite being enqueued last.
  EXPECT_LT(position_of_control, 20U);
  EXPECT_EQ(manager.control_queued_frames(), 0U);
}

TEST(M5ChannelManager, BulkIsNotStarvedUnderContinuousControlLoad) {
  // Exit-condition property: neither class starves. Under continuous control
  // load bulk still transmits a bounded share of slots.
  SessionChannelManager manager(ChannelBudgetConfig{});
  auto control_channel = manager.allocate_channel(true, ChannelDomain::message,
                                                  QueueFullPolicy::drop_oldest, 1024U,
                                                  1U << 20U);
  auto bulk_channel = manager.allocate_channel(true, ChannelDomain::file,
                                               QueueFullPolicy::drop_oldest, 1024U,
                                               1U << 20U);
  ASSERT_TRUE(control_channel && bulk_channel);
  std::mt19937 rng{42U};
  std::size_t control_sent = 0U;
  std::size_t bulk_sent = 0U;
  // Interleave: always keep control saturated; add one bulk frame per round.
  for (int round = 0; round < 200; ++round) {
    (void)manager.enqueue(*control_channel.value_if(), FrameClass::control,
                          make_frame(0x05U, 0U, 16U));
    (void)manager.enqueue(*bulk_channel.value_if(), FrameClass::bulk,
                          make_frame(0x62U, *bulk_channel.value_if(), 256U));
    for (int slot = 0; slot < 2; ++slot) {
      if (!manager.has_sendable_frames()) break;
      auto next = manager.next_to_send();
      if (!next.has_value()) break;
      if (next->frame_class == FrameClass::control) {
        ++control_sent;
      } else {
        ++bulk_sent;
      }
    }
  }
  EXPECT_GT(control_sent, 0U);
  EXPECT_GT(bulk_sent, 0U);
  // Weights 8:1 — bulk must keep a nonzero bounded share (no starvation).
  EXPECT_GE(bulk_sent * 8U, control_sent / 4U);
}

TEST(M5ChannelManager, LocalChannelCloseDropsOnlyItsFrames) {
  SessionChannelManager manager(ChannelBudgetConfig{});
  auto first = manager.allocate_channel(true, ChannelDomain::message,
                                        QueueFullPolicy::reject, 8U, 1U << 20U);
  auto second = manager.allocate_channel(true, ChannelDomain::message,
                                         QueueFullPolicy::reject, 8U, 1U << 20U);
  ASSERT_TRUE(first && second);
  ASSERT_TRUE(
      manager.enqueue(*first.value_if(), FrameClass::standard,
                      make_frame(0x20U, *first.value_if(), 16U)));
  ASSERT_TRUE(
      manager.enqueue(*second.value_if(), FrameClass::standard,
                      make_frame(0x20U, *second.value_if(), 16U)));
  manager.close_channel(*first.value_if());
  EXPECT_FALSE(manager.has_channel(*first.value_if()));
  EXPECT_TRUE(manager.has_channel(*second.value_if()));
  EXPECT_EQ(manager.total_queued_frames(), 1U);
  auto next = manager.next_to_send();
  ASSERT_TRUE(next.has_value());
  EXPECT_EQ(next->channel_id, *second.value_if());
}

}  // namespace
}  // namespace heyaki::session
