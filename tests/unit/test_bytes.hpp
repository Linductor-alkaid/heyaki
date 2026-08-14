#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace heyaki::test {

inline std::vector<std::byte> bytes_from_hex(std::string_view hex) {
  std::vector<std::byte> output;
  if (hex.size() % 2U != 0U) {
    return output;
  }
  output.reserve(hex.size() / 2U);
  const auto nibble = [](char value) -> int {
    if (value >= '0' && value <= '9') {
      return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
      return value - 'a' + 10;
    }
    return -1;
  };
  for (std::size_t index = 0U; index < hex.size(); index += 2U) {
    const int high = nibble(hex[index]);
    const int low = nibble(hex[index + 1U]);
    if (high < 0 || low < 0) {
      return {};
    }
    output.push_back(static_cast<std::byte>(static_cast<unsigned int>((high << 4) | low)));
  }
  return output;
}

}  // namespace heyaki::test
