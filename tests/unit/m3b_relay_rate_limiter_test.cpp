#include "relay_rate_limiter.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>

namespace heyaki {
namespace {

using namespace std::chrono_literals;

RelayRateLimitPolicy test_policy() {
  RelayRateLimitPolicy policy;
  policy.connection = RelayRateLimitRule{2U, 1000ms, 8U};
  policy.request = RelayRateLimitRule{3U, 1000ms, 1U};
  policy.tenant = RelayRateLimitRule{2U, 1000ms, 8U};
  policy.ip = RelayRateLimitRule{1U, 1000ms, 8U};
  policy.entry_ttl = 60000ms;
  return policy;
}

TEST(M3BRelayRateLimiterTest, EnforcesConnectionRequestTenantAndIpTokens) {
  auto created = RelayRateLimiter::create(test_policy());
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  auto limiter = std::move(*created.value_if());
  const auto now = std::chrono::steady_clock::now();

  for (int index = 0; index < 3; ++index) {
    EXPECT_TRUE(limiter.check_request(now + std::chrono::milliseconds{index}));
  }
  auto request_rejected = limiter.check_request(now + 3ms);
  ASSERT_FALSE(request_rejected);
  EXPECT_EQ(request_rejected.error_if()->safe_detail(), "rate_limit_exceeded");

  EXPECT_TRUE(limiter.check_connection("conn-a", now));
  EXPECT_TRUE(limiter.check_connection("conn-a", now + 1ms));
  auto connection_rejected = limiter.check_connection("conn-a", now + 2ms);
  ASSERT_FALSE(connection_rejected);
  EXPECT_EQ(connection_rejected.error_if()->safe_detail(), "rate_limit_exceeded");
  EXPECT_TRUE(limiter.check_connection("conn-b", now + 2ms));
  EXPECT_TRUE(limiter.check_connection("conn-a", now + 1001ms));

  EXPECT_TRUE(limiter.check_tenant("tenant-a", now));
  EXPECT_TRUE(limiter.check_tenant("tenant-a", now + 1ms));
  EXPECT_FALSE(limiter.check_tenant("tenant-a", now + 2ms));
  EXPECT_TRUE(limiter.check_tenant("tenant-b", now + 2ms));

  EXPECT_TRUE(limiter.check_ip("192.0.2.1", now));
  EXPECT_FALSE(limiter.check_ip("192.0.2.1", now + 1ms));
  EXPECT_TRUE(limiter.check_ip("192.0.2.2", now + 1ms));

  const auto stats = limiter.diagnostics();
  EXPECT_EQ(stats.request.allowed, 3U);
  EXPECT_EQ(stats.request.rejected, 1U);
  EXPECT_EQ(stats.connection.allowed, 4U);
  EXPECT_EQ(stats.connection.rejected, 1U);
  EXPECT_EQ(stats.tenant.allowed, 3U);
  EXPECT_EQ(stats.tenant.rejected, 1U);
  EXPECT_EQ(stats.ip.allowed, 2U);
  EXPECT_EQ(stats.ip.rejected, 1U);
}

TEST(M3BRelayRateLimiterTest, RejectsNewKeysWhenBoundedKeyTableIsFull) {
  RelayRateLimitPolicy policy;
  policy.tenant = RelayRateLimitRule{4U, 1000ms, 1U};
  policy.entry_ttl = 60000ms;
  auto created = RelayRateLimiter::create(policy);
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  auto limiter = std::move(*created.value_if());
  const auto now = std::chrono::steady_clock::now();

  EXPECT_TRUE(limiter.check_tenant("tenant-a", now));
  auto rejected = limiter.check_tenant("tenant-b", now + 1ms);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "rate_limit_key_capacity_exhausted");
  EXPECT_EQ(limiter.diagnostics().tenant.capacity_rejected, 1U);
  EXPECT_EQ(limiter.diagnostics().tenant.current_keys, 1U);
  EXPECT_EQ(limiter.diagnostics().tenant.peak_keys, 1U);
}

TEST(M3BRelayRateLimiterTest, PruneRemovesIdleKeysAndRestoresAdmission) {
  RelayRateLimitPolicy policy;
  policy.connection = RelayRateLimitRule{4U, 1000ms, 1U};
  policy.entry_ttl = 100ms;
  auto created = RelayRateLimiter::create(policy);
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  auto limiter = std::move(*created.value_if());
  const auto now = std::chrono::steady_clock::now();

  EXPECT_TRUE(limiter.check_connection("conn-a", now));
  EXPECT_EQ(limiter.diagnostics().connection.current_keys, 1U);
  EXPECT_FALSE(limiter.check_connection("conn-b", now + 1ms));

  limiter.prune(now + 101ms);
  EXPECT_EQ(limiter.diagnostics().connection.current_keys, 0U);
  EXPECT_TRUE(limiter.check_connection("conn-b", now + 102ms));
  EXPECT_EQ(limiter.diagnostics().connection.current_keys, 1U);
}

TEST(M3BRelayRateLimiterTest, RejectsInvalidPolicyAndInvalidKeys) {
  EXPECT_FALSE(RelayRateLimiter::validate_policy([] {
    RelayRateLimitPolicy policy;
    policy.request.capacity = 0U;
    return policy;
  }()));
  EXPECT_FALSE(RelayRateLimiter::validate_policy([] {
    RelayRateLimitPolicy policy;
    policy.ip.window = 0ms;
    return policy;
  }()));
  EXPECT_FALSE(RelayRateLimiter::validate_policy([] {
    RelayRateLimitPolicy policy;
    policy.entry_ttl = 0ms;
    return policy;
  }()));

  auto created = RelayRateLimiter::create(test_policy());
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  auto limiter = std::move(*created.value_if());
  EXPECT_FALSE(limiter.check_tenant("", std::chrono::steady_clock::now()));
  EXPECT_FALSE(limiter.check_ip("bad key with spaces", std::chrono::steady_clock::now()));
  EXPECT_FALSE(limiter.check_connection("", std::chrono::steady_clock::now()));
  EXPECT_EQ(relay_rate_limit_scope_name(RelayRateLimitScope::tenant), "tenant");
}

}  // namespace
}  // namespace heyaki
