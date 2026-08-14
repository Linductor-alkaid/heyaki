#include <heyaki/version.hpp>

#include <chrono>
#include <cstddef>
#include <iostream>

int main() {
  constexpr std::size_t iterations = 100'000U;
  const auto start = std::chrono::steady_clock::now();
  std::size_t observed_size = 0U;
  for (std::size_t index = 0; index < iterations; ++index) {
    observed_size += heyaki::build_info().version.size();
  }
  const auto elapsed = std::chrono::steady_clock::now() - start;
  const auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
  std::cout << "build_info iterations=" << iterations << " elapsed_us=" << elapsed_us << '\n';
  return observed_size == 0U ? 1 : 0;
}
