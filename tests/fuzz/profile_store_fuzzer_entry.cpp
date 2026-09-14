#include "fuzz_targets.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  heyaki::fuzz::profile_store_migration({reinterpret_cast<const std::byte*>(data), size});
  return 0;
}
