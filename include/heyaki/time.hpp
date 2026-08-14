#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>

namespace heyaki {

using MonotonicClock = std::chrono::steady_clock;
using WallClock = std::chrono::system_clock;

class RelativeTimeout {
 public:
  explicit constexpr RelativeTimeout(std::chrono::milliseconds value) noexcept : value_(value) {}

  [[nodiscard]] constexpr std::chrono::milliseconds value() const noexcept { return value_; }

 private:
  std::chrono::milliseconds value_{};
};

class Deadline {
 public:
  explicit constexpr Deadline(MonotonicClock::time_point value) noexcept : value_(value) {}

  [[nodiscard]] static Deadline after(
      RelativeTimeout timeout,
      MonotonicClock::time_point now = MonotonicClock::now()) noexcept {
    return Deadline{now + timeout.value()};
  }

  [[nodiscard]] constexpr MonotonicClock::time_point value() const noexcept { return value_; }
  [[nodiscard]] bool expired(
      MonotonicClock::time_point now = MonotonicClock::now()) const noexcept {
    return now >= value_;
  }
  [[nodiscard]] std::chrono::milliseconds remaining(
      MonotonicClock::time_point now = MonotonicClock::now()) const noexcept {
    if (now >= value_) {
      return std::chrono::milliseconds::zero();
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(value_ - now);
  }

 private:
  MonotonicClock::time_point value_;
};

struct WallClockMetadata {
  std::optional<std::int64_t> unix_milliseconds;
};

[[nodiscard]] inline Deadline deadline_from_wire_timeout(
    std::uint32_t wire_timeout_ms, RelativeTimeout local_maximum,
    MonotonicClock::time_point received_at = MonotonicClock::now()) noexcept {
  const auto received = std::chrono::milliseconds{wire_timeout_ms};
  return Deadline::after(RelativeTimeout{std::min(received, local_maximum.value())}, received_at);
}

}  // namespace heyaki
