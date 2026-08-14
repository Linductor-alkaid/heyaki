#include <cstddef>

extern "C" void sodium_memzero(void* const pointer, const std::size_t length) {
  volatile auto* bytes = static_cast<volatile unsigned char*>(pointer);
  for (std::size_t index = 0; index < length; ++index) {
    bytes[index] = 0U;
  }
}
