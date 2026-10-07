#include "relay_enrollment_throttle.hpp"

#include <heyaki/error.hpp>

#include <algorithm>
#include <map>
#include <string>
#include <utility>

namespace heyaki {
namespace {

Error throttle_error(ErrorCode code, const char* detail) {
  return Error{code, "relay_enrollment_throttle", detail};
}

constexpr std::size_t max_ip_key_bytes = 64U;

struct Entry {
  std::uint32_t failure_streak{};
  std::chrono::steady_clock::time_point backoff_until{};
  std::chrono::steady_clock::time_point last_seen{};
};

}  // namespace

struct RelayEnrollmentThrottle::Impl {
  explicit Impl(RelayEnrollmentThrottleConfig config_value)
      : config(config_value) {}

  RelayEnrollmentThrottleConfig config;
  std::map<std::string, Entry, std::less<>> entries;
  RelayEnrollmentThrottleDiagnostics stats;
};

RelayEnrollmentThrottle::RelayEnrollmentThrottle(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}
RelayEnrollmentThrottle::RelayEnrollmentThrottle(RelayEnrollmentThrottle&&) noexcept = default;
RelayEnrollmentThrottle& RelayEnrollmentThrottle::operator=(
    RelayEnrollmentThrottle&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}
RelayEnrollmentThrottle::~RelayEnrollmentThrottle() = default;

Result<void> RelayEnrollmentThrottle::validate_config(
    const RelayEnrollmentThrottleConfig& config) {
  if (config.max_tracked_ips == 0U || config.max_tracked_ips > 65536U ||
      config.failure_backoff_base.count() <= 0 ||
      config.failure_backoff_maximum < config.failure_backoff_base ||
      config.maximum_backoff_shift == 0U || config.maximum_backoff_shift > 16U ||
      config.entry_ttl.count() <= 0) {
    return Result<void>::failure(
        throttle_error(ErrorCode::configuration, "enrollment_throttle_config_invalid"));
  }
  return Result<void>::success();
}

Result<RelayEnrollmentThrottle> RelayEnrollmentThrottle::create(
    const RelayEnrollmentThrottleConfig& config) {
  auto valid = validate_config(config);
  if (!valid) {
    return Result<RelayEnrollmentThrottle>::failure(*valid.error_if());
  }
  return Result<RelayEnrollmentThrottle>::success(
      RelayEnrollmentThrottle{std::make_unique<Impl>(config)});
}

Result<void> RelayEnrollmentThrottle::admit(std::string_view ip,
                                            std::chrono::steady_clock::time_point now) {
  if (!impl_) {
    return Result<void>::failure(
        throttle_error(ErrorCode::cancelled, "enrollment_throttle_not_initialized"));
  }
  if (ip.empty() || ip.size() > max_ip_key_bytes) {
    return Result<void>::failure(
        throttle_error(ErrorCode::configuration, "enrollment_throttle_ip_invalid"));
  }
  auto& impl = *impl_;
  auto existing = impl.entries.find(ip);
  if (existing != impl.entries.end()) {
    if (existing->second.last_seen + impl.config.entry_ttl <= now) {
      impl.entries.erase(existing);
      impl.stats.tracked_ips = impl.entries.size();
      existing = impl.entries.end();
    } else if (existing->second.backoff_until > now) {
      ++impl.stats.throttled;
      return Result<void>::failure(
          throttle_error(ErrorCode::resource_exhausted, "enrollment_throttled"));
    }
  }
  if (existing == impl.entries.end() && impl.entries.size() >= impl.config.max_tracked_ips) {
    prune(now);
    if (impl.entries.size() >= impl.config.max_tracked_ips) {
      ++impl.stats.capacity_rejected;
      return Result<void>::failure(throttle_error(ErrorCode::resource_exhausted,
                                                  "enrollment_throttle_capacity_exhausted"));
    }
  }
  ++impl.stats.admitted;
  return Result<void>::success();
}

void RelayEnrollmentThrottle::record_failure(std::string_view ip,
                                             std::chrono::steady_clock::time_point now) {
  if (!impl_ || ip.empty() || ip.size() > max_ip_key_bytes) {
    return;
  }
  auto& impl = *impl_;
  auto& entry = impl.entries[std::string{ip}];
  entry.failure_streak = entry.failure_streak >= 32U
                             ? 32U
                             : entry.failure_streak + 1U;
  const auto shift = std::min<std::uint32_t>(entry.failure_streak - 1U,
                                             impl.config.maximum_backoff_shift);
  auto backoff = std::chrono::duration_cast<std::chrono::milliseconds>(
      impl.config.failure_backoff_base * (std::uint64_t{1U} << shift));
  backoff = std::min(backoff, impl.config.failure_backoff_maximum);
  entry.backoff_until = now + backoff;
  entry.last_seen = now;
  ++impl.stats.failures_recorded;
  impl.stats.tracked_ips = impl.entries.size();
  impl.stats.peak_tracked_ips =
      std::max(impl.stats.peak_tracked_ips, impl.entries.size());
}

void RelayEnrollmentThrottle::record_success(std::string_view ip,
                                             std::chrono::steady_clock::time_point now) {
  if (!impl_ || ip.empty() || ip.size() > max_ip_key_bytes) {
    return;
  }
  auto& impl = *impl_;
  impl.entries.erase(std::string{ip});
  ++impl.stats.successes_recorded;
  impl.stats.tracked_ips = impl.entries.size();
  (void)now;
}

void RelayEnrollmentThrottle::prune(std::chrono::steady_clock::time_point now) {
  if (!impl_) {
    return;
  }
  auto& impl = *impl_;
  for (auto iterator = impl.entries.begin(); iterator != impl.entries.end();) {
    if (iterator->second.last_seen + impl.config.entry_ttl <= now &&
        iterator->second.backoff_until <= now) {
      iterator = impl.entries.erase(iterator);
    } else {
      ++iterator;
    }
  }
  impl.stats.tracked_ips = impl.entries.size();
}

RelayEnrollmentThrottleDiagnostics RelayEnrollmentThrottle::diagnostics() const noexcept {
  return impl_ ? impl_->stats : RelayEnrollmentThrottleDiagnostics{};
}

}  // namespace heyaki
