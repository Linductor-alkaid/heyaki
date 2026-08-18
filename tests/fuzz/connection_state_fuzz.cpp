#include "fuzz_targets.hpp"

#include "client/connection_attempt.hpp"

#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <string>

namespace heyaki::fuzz {

void connection_attempt_state_machine(std::span<const std::byte> input) {
  const auto byte = [&](std::size_t index) {
    return index < input.size() ? std::to_integer<unsigned int>(input[index]) : 0U;
  };
  const std::size_t capacity = byte(0U) % 12U;
  ConnectionAttemptTimeline timeline(capacity);
  auto timestamp = std::chrono::steady_clock::time_point{};

  for (std::size_t offset = 1U; offset < input.size(); offset += 4U) {
    const auto before_stage = timeline.stage();
    const auto before_size = timeline.transitions().size();
    constexpr auto stage_count = static_cast<unsigned int>(ConnectionStage::closed) + 1U;
    const auto next = static_cast<ConnectionStage>(byte(offset) % stage_count);
    const std::string source((byte(offset + 1U) % 70U), 's');
    const std::string reason((byte(offset + 2U) % 140U), 'r');
    timestamp += std::chrono::milliseconds{byte(offset + 3U)};
    const auto result = timeline.transition(next, source, reason, timestamp);

    if (timeline.transitions().size() > capacity) std::abort();
    if (!result) {
      if (timeline.stage() != before_stage ||
          timeline.transitions().size() != before_size) {
        std::abort();
      }
      continue;
    }
    if (timeline.stage() != next || timeline.transitions().size() != before_size + 1U) {
      std::abort();
    }
    const auto& recorded = timeline.transitions().back();
    if (recorded.from != before_stage || recorded.to != next ||
        recorded.source != source || recorded.reason != reason ||
        recorded.timestamp != timestamp) {
      std::abort();
    }
  }

  const auto& transitions = timeline.transitions();
  for (std::size_t index = 1U; index < transitions.size(); ++index) {
    if (transitions[index - 1U].to != transitions[index].from) std::abort();
  }
  if (transitions.empty()) {
    if (timeline.stage() != ConnectionStage::idle) std::abort();
  } else if (timeline.stage() != transitions.back().to) {
    std::abort();
  }
}

}  // namespace heyaki::fuzz
