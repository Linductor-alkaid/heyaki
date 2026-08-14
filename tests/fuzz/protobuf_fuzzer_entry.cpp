#include "fuzz_targets.hpp"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  heyaki::fuzz::protobuf_schema_parser({reinterpret_cast<const std::byte*>(data), size});
  return 0;
}
