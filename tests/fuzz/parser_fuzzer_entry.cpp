#include "fuzz_targets.hpp"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span input{reinterpret_cast<const std::byte*>(data), size};
  heyaki::fuzz::frame_parser(input);
  heyaki::fuzz::lan_datagram_parser(input);
  return 0;
}
