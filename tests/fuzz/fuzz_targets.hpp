#pragma once

#include <cstddef>
#include <span>

namespace heyaki::fuzz {

void frame_parser(std::span<const std::byte> input);
void lan_datagram_parser(std::span<const std::byte> input);
void protobuf_schema_parser(std::span<const std::byte> input);
void protocol_state_machines(std::span<const std::byte> input);

}  // namespace heyaki::fuzz
