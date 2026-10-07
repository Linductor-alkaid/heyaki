#pragma once

#include <heyaki/error.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

namespace heyaki {

// Per-IP admission throttle for enrollment attempts (online password/token
// guessing defense). Failures deepen an exponential backoff; any success
// resets the streak for that IP. Parameters are frozen in
// docs/operations/parameter-freeze.md. All methods must be called on the
// relay strand (the owning server serializes control handling there).
struct RelayEnrollmentThrottleConfig {
  std::size_t max_tracked_ips{4096U};
  std::chrono::milliseconds failure_backoff_base{500};
  std::chrono::milliseconds failure_backoff_maximum{60000};
  // Backoff exponent cap: streak n uses base * 2^min(n-1, 7).
  std::uint32_t maximum_backoff_shift{7U};
  std::chrono::milliseconds entry_ttl{10U * 60U * 1000U};
};

struct RelayEnrollmentThrottleDiagnostics {
  std::uint64_t admitted{};
  std::uint64_t throttled{};
  std::uint64_t capacity_rejected{};
  std::uint64_t failures_recorded{};
  std::uint64_t successes_recorded{};
  std::size_t tracked_ips{};
  std::size_t peak_tracked_ips{};
};

class RelayEnrollmentThrottle {
 public:
  struct Impl;

  RelayEnrollmentThrottle(RelayEnrollmentThrottle&&) noexcept;
  RelayEnrollmentThrottle& operator=(RelayEnrollmentThrottle&&) noexcept;
  ~RelayEnrollmentThrottle();

  RelayEnrollmentThrottle(const RelayEnrollmentThrottle&) = delete;
  RelayEnrollmentThrottle& operator=(const RelayEnrollmentThrottle&) = delete;

  [[nodiscard]] static Result<RelayEnrollmentThrottle> create(
      const RelayEnrollmentThrottleConfig& config = {});
  [[nodiscard]] static Result<void> validate_config(
      const RelayEnrollmentThrottleConfig& config);

  // Admits one enrollment attempt from `ip`. Rejected with
  // resource_exhausted while the IP is serving its failure backoff, or when
  // the tracking table is at capacity.
  [[nodiscard]] Result<void> admit(
      std::string_view ip,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  void record_failure(
      std::string_view ip,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  void record_success(
      std::string_view ip,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  void prune(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  [[nodiscard]] RelayEnrollmentThrottleDiagnostics diagnostics() const noexcept;

 private:
  explicit RelayEnrollmentThrottle(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

}  // namespace heyaki
