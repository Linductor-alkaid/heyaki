#pragma once

#include <cstddef>
#include <span>

namespace heyaki::fuzz {

void frame_parser(std::span<const std::byte> input);
void lan_datagram_parser(std::span<const std::byte> input);
void lan_hello_parser(std::span<const std::byte> input);
void lan_presence_parser(std::span<const std::byte> input);
void lan_signaling_frame_parser(std::span<const std::byte> input);
void signed_offer_parser(std::span<const std::byte> input);
void signed_answer_parser(std::span<const std::byte> input);
void signed_candidate_parser(std::span<const std::byte> input);
void signed_session_hello_parser(std::span<const std::byte> input);
void lan_directory_state_machine(std::span<const std::byte> input);
void protobuf_schema_parser(std::span<const std::byte> input);
void protocol_state_machines(std::span<const std::byte> input);

}  // namespace heyaki::fuzz
