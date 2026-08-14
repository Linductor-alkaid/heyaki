#pragma once

#include <cstddef>
#include <span>

namespace heyaki::fuzz {

void frame_parser(std::span<const std::byte> input);
void protobuf_message_parser(std::span<const std::byte> input);
void operation_state_machine(std::span<const std::byte> input);

}  // namespace heyaki::fuzz
