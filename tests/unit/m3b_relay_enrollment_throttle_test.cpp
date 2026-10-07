// Issue #22 verification: RelayEnrollmentThrottle per-IP exponential backoff,
// success reset, capacity, and TTL behavior with an injected steady clock.
#include "relay_enrollment_throttle.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

namespace heyaki {
namespace {

using TimePoint = std::chrono::steady_clock::time_point;

constexpr TimePoint at_milliseconds(std::int64_t milliseconds) {
  return TimePoint{std::chrono::milliseconds{milliseconds}};
}

TEST(M3BRelayEnrollmentThrottleTest, AdmitsCleanIpAndThrottlesAfterFailure) {
  auto throttle = RelayEnrollmentThrottle::create();
  ASSERT_TRUE(throttle) << throttle.error_if()->safe_detail();

  const std::string ip = "203.0.113.10";
  EXPECT_TRUE(throttle.value_if()->admit(ip, at_milliseconds(1'000)));

  // One failure -> base backoff 500 ms.
  throttle.value_if()->record_failure(ip, at_milliseconds(1'000));
  auto during_backoff = throttle.value_if()->admit(ip, at_milliseconds(1'499));
  ASSERT_FALSE(during_backoff);
  EXPECT_EQ(during_backoff.error_if()->code(), ErrorCode::resource_exhausted);
  EXPECT_EQ(during_backoff.error_if()->safe_detail(), "enrollment_throttled");
  EXPECT_TRUE(throttle.value_if()->admit(ip, at_milliseconds(1'500)));

  const auto diagnostics = throttle.value_if()->diagnostics();
  EXPECT_EQ(diagnostics.admitted, 2U);
  EXPECT_EQ(diagnostics.throttled, 1U);
  EXPECT_EQ(diagnostics.failures_recorded, 1U);
  EXPECT_EQ(diagnostics.successes_recorded, 0U);
  EXPECT_EQ(diagnostics.tracked_ips, 1U);
  EXPECT_EQ(diagnostics.peak_tracked_ips, 1U);
}

TEST(M3BRelayEnrollmentThrottleTest, BackoffGrowsExponentiallyAndCapsAt60Seconds) {
  RelayEnrollmentThrottleConfig config;
  config.failure_backoff_base = std::chrono::milliseconds{500};
  config.failure_backoff_maximum = std::chrono::milliseconds{60000};
  config.maximum_backoff_shift = 7U;
  auto throttle = RelayEnrollmentThrottle::create(config);
  ASSERT_TRUE(throttle) << throttle.error_if()->safe_detail();

  const std::string ip = "198.51.100.7";
  const std::int64_t start = 10'000'000;

  // streak 1 -> 500 ms
  throttle.value_if()->record_failure(ip, at_milliseconds(start));
  EXPECT_FALSE(throttle.value_if()->admit(ip, at_milliseconds(start + 499)));
  EXPECT_TRUE(throttle.value_if()->admit(ip, at_milliseconds(start + 500)));

  // streak 2 -> 1 s
  throttle.value_if()->record_failure(ip, at_milliseconds(start + 500));
  EXPECT_FALSE(throttle.value_if()->admit(ip, at_milliseconds(start + 1'499)));
  EXPECT_TRUE(throttle.value_if()->admit(ip, at_milliseconds(start + 1'500)));

  // streak 3 -> 2 s
  throttle.value_if()->record_failure(ip, at_milliseconds(start + 1'500));
  EXPECT_FALSE(throttle.value_if()->admit(ip, at_milliseconds(start + 3'499)));
  EXPECT_TRUE(throttle.value_if()->admit(ip, at_milliseconds(start + 3'500)));

  // streak 4 -> 4 s
  throttle.value_if()->record_failure(ip, at_milliseconds(start + 3'500));
  EXPECT_FALSE(throttle.value_if()->admit(ip, at_milliseconds(start + 7'499)));
  EXPECT_TRUE(throttle.value_if()->admit(ip, at_milliseconds(start + 7'500)));

  // streaks 5..7 keep doubling (8 s, 16 s, 32 s).
  throttle.value_if()->record_failure(ip, at_milliseconds(start + 7'500));
  throttle.value_if()->record_failure(ip, at_milliseconds(start + 7'501));
  throttle.value_if()->record_failure(ip, at_milliseconds(start + 7'502));
  EXPECT_FALSE(throttle.value_if()->admit(ip, at_milliseconds(start + 39'501)));
  EXPECT_TRUE(throttle.value_if()->admit(ip, at_milliseconds(start + 39'502)));

  // streak 8: base * 2^7 = 64 s is capped at the 60 s maximum.
  throttle.value_if()->record_failure(ip, at_milliseconds(start + 39'502));
  EXPECT_FALSE(throttle.value_if()->admit(ip, at_milliseconds(start + 99'501)));
  EXPECT_TRUE(throttle.value_if()->admit(ip, at_milliseconds(start + 99'502)));

  const auto diagnostics = throttle.value_if()->diagnostics();
  EXPECT_EQ(diagnostics.failures_recorded, 8U);
  EXPECT_EQ(diagnostics.tracked_ips, 1U);
}

TEST(M3BRelayEnrollmentThrottleTest, SuccessResetsStreakAndUnknownIpIsHarmless) {
  auto throttle = RelayEnrollmentThrottle::create();
  ASSERT_TRUE(throttle) << throttle.error_if()->safe_detail();

  const std::string ip = "192.0.2.44";
  const std::string unknown = "192.0.2.99";

  // Success for an IP the throttle never saw must not crash or create state.
  throttle.value_if()->record_success(unknown, at_milliseconds(1'000));
  EXPECT_EQ(throttle.value_if()->diagnostics().tracked_ips, 0U);

  throttle.value_if()->record_failure(ip, at_milliseconds(1'000));
  EXPECT_FALSE(throttle.value_if()->admit(ip, at_milliseconds(1'100)));

  throttle.value_if()->record_success(ip, at_milliseconds(1'200));
  EXPECT_TRUE(throttle.value_if()->admit(ip, at_milliseconds(1'201)));
  EXPECT_EQ(throttle.value_if()->diagnostics().tracked_ips, 0U);

  // After a reset the next failure restarts from the base backoff.
  throttle.value_if()->record_failure(ip, at_milliseconds(2'000));
  EXPECT_FALSE(throttle.value_if()->admit(ip, at_milliseconds(2'400)));
  EXPECT_TRUE(throttle.value_if()->admit(ip, at_milliseconds(2'500)));

  const auto diagnostics = throttle.value_if()->diagnostics();
  EXPECT_EQ(diagnostics.successes_recorded, 2U);
  EXPECT_EQ(diagnostics.failures_recorded, 2U);
}

TEST(M3BRelayEnrollmentThrottleTest, CapacityRejectsUnknownIpsWhenFull) {
  RelayEnrollmentThrottleConfig config;
  config.max_tracked_ips = 2U;
  auto throttle = RelayEnrollmentThrottle::create(config);
  ASSERT_TRUE(throttle) << throttle.error_if()->safe_detail();

  throttle.value_if()->record_failure("10.0.0.1", at_milliseconds(1'000));
  throttle.value_if()->record_failure("10.0.0.2", at_milliseconds(1'000));
  EXPECT_EQ(throttle.value_if()->diagnostics().tracked_ips, 2U);

  auto rejected = throttle.value_if()->admit("10.0.0.3", at_milliseconds(1'001));
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->code(), ErrorCode::resource_exhausted);
  EXPECT_EQ(rejected.error_if()->safe_detail(),
            "enrollment_throttle_capacity_exhausted");
  EXPECT_EQ(throttle.value_if()->diagnostics().capacity_rejected, 1U);

  // Beyond the entry TTL the queried entry is dropped on admission and the
  // tracked_ips diagnostic reflects the eviction immediately.
  const std::int64_t after_ttl = 1'000 + 10LL * 60LL * 1000LL + 1LL;
  EXPECT_TRUE(throttle.value_if()->admit("10.0.0.1", at_milliseconds(after_ttl)));
  EXPECT_EQ(throttle.value_if()->diagnostics().tracked_ips, 1U);
  EXPECT_TRUE(throttle.value_if()->admit("10.0.0.3", at_milliseconds(after_ttl)));
  // 10.0.0.2 was never queried, so only prune reclaims it.
  EXPECT_EQ(throttle.value_if()->diagnostics().tracked_ips, 1U);
  throttle.value_if()->prune(at_milliseconds(after_ttl));
  EXPECT_EQ(throttle.value_if()->diagnostics().tracked_ips, 0U);
}

TEST(M3BRelayEnrollmentThrottleTest, EntryTtlExpiresAndPruneReclaims) {
  RelayEnrollmentThrottleConfig config;
  config.entry_ttl = std::chrono::milliseconds{60'000};
  auto throttle = RelayEnrollmentThrottle::create(config);
  ASSERT_TRUE(throttle) << throttle.error_if()->safe_detail();

  const std::string ip = "10.0.0.9";
  throttle.value_if()->record_failure(ip, at_milliseconds(1'000));

  // A backoff-expired but not yet TTL-expired entry keeps throttling.
  EXPECT_FALSE(throttle.value_if()->admit(ip, at_milliseconds(1'499)));
  EXPECT_TRUE(throttle.value_if()->admit(ip, at_milliseconds(1'500)));

  // After the TTL the entry is gone: admission succeeds and the next failure
  // starts from the base backoff again.
  EXPECT_TRUE(throttle.value_if()->admit(ip, at_milliseconds(61'001)));
  throttle.value_if()->record_failure(ip, at_milliseconds(61'002));
  EXPECT_FALSE(throttle.value_if()->admit(ip, at_milliseconds(61'202)));
  EXPECT_TRUE(throttle.value_if()->admit(ip, at_milliseconds(61'502)));

  throttle.value_if()->prune(at_milliseconds(200'000));
  EXPECT_EQ(throttle.value_if()->diagnostics().tracked_ips, 0U);
}

TEST(M3BRelayEnrollmentThrottleTest, RejectsInvalidIpKeys) {
  auto throttle = RelayEnrollmentThrottle::create();
  ASSERT_TRUE(throttle) << throttle.error_if()->safe_detail();

  auto empty_ip = throttle.value_if()->admit("", at_milliseconds(1'000));
  ASSERT_FALSE(empty_ip);
  EXPECT_EQ(empty_ip.error_if()->code(), ErrorCode::configuration);
  EXPECT_EQ(empty_ip.error_if()->safe_detail(), "enrollment_throttle_ip_invalid");

  const std::string oversized(65U, 'a');
  auto long_ip = throttle.value_if()->admit(oversized, at_milliseconds(1'000));
  ASSERT_FALSE(long_ip);
  EXPECT_EQ(long_ip.error_if()->safe_detail(), "enrollment_throttle_ip_invalid");

  // record_failure / record_success ignore invalid keys without crashing.
  throttle.value_if()->record_failure("", at_milliseconds(1'000));
  throttle.value_if()->record_success(oversized, at_milliseconds(1'000));
  EXPECT_EQ(throttle.value_if()->diagnostics().tracked_ips, 0U);
  EXPECT_EQ(throttle.value_if()->diagnostics().failures_recorded, 0U);
  EXPECT_EQ(throttle.value_if()->diagnostics().successes_recorded, 0U);

  const std::string max_length(64U, 'b');
  EXPECT_TRUE(throttle.value_if()->admit(max_length, at_milliseconds(1'000)));
}

TEST(M3BRelayEnrollmentThrottleTest, ValidatesConfigBounds) {
  RelayEnrollmentThrottleConfig zero_capacity;
  zero_capacity.max_tracked_ips = 0U;
  auto zero = RelayEnrollmentThrottle::create(zero_capacity);
  ASSERT_FALSE(zero);
  EXPECT_EQ(zero.error_if()->safe_detail(), "enrollment_throttle_config_invalid");

  RelayEnrollmentThrottleConfig above_bound;
  above_bound.max_tracked_ips = 65537U;
  auto above = RelayEnrollmentThrottle::create(above_bound);
  ASSERT_FALSE(above);

  RelayEnrollmentThrottleConfig zero_base;
  zero_base.failure_backoff_base = std::chrono::milliseconds{0};
  auto zero_backoff = RelayEnrollmentThrottle::create(zero_base);
  ASSERT_FALSE(zero_backoff);

  RelayEnrollmentThrottleConfig inverted;
  inverted.failure_backoff_base = std::chrono::milliseconds{2000};
  inverted.failure_backoff_maximum = std::chrono::milliseconds{1000};
  auto inverted_created = RelayEnrollmentThrottle::create(inverted);
  ASSERT_FALSE(inverted_created);

  RelayEnrollmentThrottleConfig zero_shift;
  zero_shift.maximum_backoff_shift = 0U;
  auto shift = RelayEnrollmentThrottle::create(zero_shift);
  ASSERT_FALSE(shift);

  RelayEnrollmentThrottleConfig zero_ttl;
  zero_ttl.entry_ttl = std::chrono::milliseconds{0};
  auto ttl = RelayEnrollmentThrottle::create(zero_ttl);
  ASSERT_FALSE(ttl);

  RelayEnrollmentThrottleConfig defaults;
  auto valid = RelayEnrollmentThrottle::validate_config(defaults);
  EXPECT_TRUE(valid) << valid.error_if()->safe_detail();
}

}  // namespace
}  // namespace heyaki
