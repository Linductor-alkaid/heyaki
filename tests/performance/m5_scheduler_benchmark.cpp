// M5-04 repeatable scheduling benchmark: under a sustained mixed load the
// weighted scheduler must keep control latency low AND give bulk a bounded
// nonzero share (no starvation in either direction). The scenario is
// deterministic: fixed seed, fixed frame sizes, fixed round counts, so runs
// are comparable across builds.

#include "session_channels.hpp"

#include <heyaki/wire.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <random>

namespace {

using heyaki::Frame;
using heyaki::FrameType;
using heyaki::MessageId;
using heyaki::session::ChannelDomain;
using heyaki::session::FrameClass;
using heyaki::session::QueueFullPolicy;
using heyaki::session::SessionChannelManager;

Frame make_frame(std::uint8_t type, std::uint32_t channel, std::size_t payload_size,
                 std::uint8_t seed) {
  Frame frame;
  frame.type = type;
  frame.channel_id = channel;
  MessageId::Storage id{};
  id[0] = static_cast<std::byte>(seed);
  id[1] = std::byte{1U};
  frame.message_id = MessageId{id};
  frame.payload.assign(payload_size, std::byte{0x42});
  return frame;
}

}  // namespace

int main() {
  heyaki::session::ChannelBudgetConfig config;
  SessionChannelManager manager(config);
  const auto control_channel =
      manager.allocate_channel(true, ChannelDomain::message, QueueFullPolicy::reject,
                               1024U, 8U << 20U);
  const auto bulk_channel = manager.allocate_channel(true, ChannelDomain::file,
                                                     QueueFullPolicy::drop_oldest,
                                                     1024U, 8U << 20U);
  if (!control_channel || !bulk_channel) return 2;
  const auto control_id = *control_channel.value_if();
  const auto bulk_id = *bulk_channel.value_if();

  constexpr std::size_t rounds = 20'000U;
  std::size_t control_sent = 0U;
  std::size_t bulk_sent = 0U;
  std::size_t control_position_sum = 0U;
  std::size_t control_observations = 0U;
  std::size_t max_control_deficit = 0U;  // bulk frames sent between two control frames

  const auto start = std::chrono::steady_clock::now();
  for (std::size_t round = 0U; round < rounds; ++round) {
    // Saturate control (cancels/window updates/close-class frames) and add
    // one bulk file chunk per round: the worst case for bulk starvation.
    (void)manager.enqueue(control_id, FrameClass::control,
                          make_frame(0x05U, control_id, 32U,
                                     static_cast<std::uint8_t>(round & 0xFFU)));
    (void)manager.enqueue(bulk_id, FrameClass::bulk,
                          make_frame(static_cast<std::uint8_t>(FrameType::file_chunk),
                                     bulk_id, 1024U, static_cast<std::uint8_t>(round)));
    std::size_t bulk_before = bulk_sent;
    for (int slot = 0; slot < 2; ++slot) {
      auto next = manager.next_to_send();
      if (!next.has_value()) break;
      if (next->frame_class == FrameClass::control) {
        control_sent += 1U;
        control_position_sum += static_cast<std::size_t>(slot);
        control_observations += 1U;
        max_control_deficit = std::max(max_control_deficit, bulk_sent - bulk_before);
        bulk_before = bulk_sent;
      } else {
        bulk_sent += 1U;
      }
    }
  }
  // Drain the remaining backlog.
  while (manager.has_sendable_frames()) {
    auto next = manager.next_to_send();
    if (!next.has_value()) break;
    if (next->frame_class == FrameClass::control) {
      control_sent += 1U;
    } else {
      bulk_sent += 1U;
    }
  }
  const auto elapsed = std::chrono::steady_clock::now() - start;
  const auto elapsed_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

  std::cout << "m5_scheduler rounds=" << rounds
            << " control_sent=" << control_sent << " bulk_sent=" << bulk_sent
            << " avg_control_slot="
            << (control_observations == 0U
                    ? 0.0
                    : static_cast<double>(control_position_sum) /
                          static_cast<double>(control_observations))
            << " max_bulk_between_control=" << max_control_deficit
            << " elapsed_ms=" << elapsed_ms << '\n';

  // No-starvation exit conditions, both directions:
  //   1. bulk always progresses under saturated control load (8:1 weights);
  //   2. control is never stuck behind a bulk backlog (bounded deficit).
  if (bulk_sent == 0U) {
    std::cerr << "FAIL: bulk starved under control load\n";
    return 1;
  }
  if (control_sent == 0U) {
    std::cerr << "FAIL: control starved under bulk load\n";
    return 1;
  }
  if (max_control_deficit > 16U) {
    std::cerr << "FAIL: control waited behind " << max_control_deficit
              << " bulk frames\n";
    return 1;
  }
  if (manager.total_queued_frames() != 0U) {
    std::cerr << "FAIL: queue did not drain\n";
    return 1;
  }
  std::cout << "M5_SCHEDULER_OK control=" << control_sent << " bulk=" << bulk_sent
            << " max_deficit=" << max_control_deficit << '\n';
  return 0;
}
