#include "fuzz_targets.hpp"

#include <heyaki/operation.hpp>
#include <heyaki/wire.hpp>

#include <algorithm>
#include <cstdlib>
#include <optional>
#include <span>
#include <vector>

namespace heyaki::fuzz {

void frame_parser(std::span<const std::byte> input) {
  const auto parsed = parse_frame(input);
  if (parsed.status != FrameParseStatus::parsed) {
    return;
  }
  if (!parsed.frame.has_value() || parsed.consumed == 0U || parsed.consumed > input.size()) {
    std::abort();
  }

  const auto& view = *parsed.frame;
  Frame owning{.type = view.type,
               .flags = view.flags,
               .channel_id = view.channel_id,
               .message_id = view.message_id,
               .payload = {view.payload.begin(), view.payload.end()}};
  const auto encoded = encode_frame(owning);
  if (!encoded || encoded.value_if()->size() != parsed.consumed ||
      !std::equal(encoded.value_if()->begin(), encoded.value_if()->end(), input.begin())) {
    std::abort();
  }
}

void operation_state_machine(std::span<const std::byte> input) {
  OperationStatus current{};
  for (const auto raw : input) {
    const auto byte = std::to_integer<unsigned int>(raw);
    if (current.state != OperationState::pending) {
      if ((byte & 0x80U) == 0U) {
        const auto repeated = transition_operation(current, OperationState::success);
        const bool same_terminal_state = current.state == OperationState::success;
        if (static_cast<bool>(repeated) != same_terminal_state ||
            current.state == OperationState::pending) {
          std::abort();
        }
        continue;
      }
      const auto next_epoch = current.epoch.next();
      if (!next_epoch.has_value()) {
        return;
      }
      current = OperationStatus{.id = current.id,
                                .epoch = *next_epoch,
                                .state = OperationState::pending,
                                .error = std::nullopt};
    }

    const auto next = static_cast<OperationState>((byte % 4U) + 1U);
    std::optional<Error> error;
    if (next == OperationState::error) {
      error = Error{ErrorCode::remote_error, "fuzz", "remote_error"};
    }
    const auto transitioned = transition_operation(current, next, std::move(error));
    if (!transitioned || transitioned.value_if()->state == OperationState::pending ||
        transitioned.value_if()->epoch != current.epoch) {
      std::abort();
    }
    current = *transitioned.value_if();
  }
}

}  // namespace heyaki::fuzz
