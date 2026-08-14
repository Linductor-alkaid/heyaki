#include "fuzz_targets.hpp"

#include <heyaki/operation.hpp>
#include <heyaki/wire.hpp>

#include "heyaki/message/v1/message.pb.h"

#include <algorithm>
#include <cstdlib>
#include <limits>
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

void protobuf_message_parser(std::span<const std::byte> input) {
  if (input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    return;
  }
  protocol::message::v1::MessageEnvelope message;
  if (!message.ParseFromArray(input.data(), static_cast<int>(input.size()))) {
    return;
  }

  const auto encoded = message.SerializeAsString();
  protocol::message::v1::MessageEnvelope reparsed;
  if (!reparsed.ParseFromString(encoded) || reparsed.message_id() != message.message_id() ||
      reparsed.type() != message.type() || reparsed.schema_version() != message.schema_version() ||
      reparsed.payload() != message.payload()) {
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
