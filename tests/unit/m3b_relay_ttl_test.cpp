#include "relay_ttl_table.hpp"

#include <heyaki/ids.hpp>
#include <heyaki/lan_directory.hpp>

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

namespace heyaki {
namespace {

using namespace std::chrono_literals;

DeviceEndpointKey make_key(std::uint8_t device_byte, std::uint8_t endpoint_byte) {
  DeviceId::Storage device_bytes{};
  EndpointId::Storage endpoint_bytes{};
  device_bytes[0] = static_cast<std::byte>(device_byte);
  device_bytes[1] = static_cast<std::byte>(0x5aU);
  endpoint_bytes[0] = static_cast<std::byte>(endpoint_byte);
  return DeviceEndpointKey{.device_id = DeviceId{device_bytes},
                           .endpoint_id = EndpointId{endpoint_bytes}};
}

RequestId make_request(std::uint8_t first_byte) {
  RequestId::Storage bytes{};
  bytes[0] = static_cast<std::byte>(first_byte);
  return RequestId{bytes};
}

TEST(M3BRelayTtlTableTest, BoundedUpsertRefreshExpiryAndErase) {
  auto created = RelayTtlTable<RequestId, int>::create(2U);
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  auto table = std::move(*created.value_if());
  const auto now = std::chrono::steady_clock::now();

  auto first = table.upsert(make_request(1U), 10, 1000ms, now);
  ASSERT_TRUE(first) << first.error_if()->safe_detail();
  EXPECT_EQ(*first.value_if(), RelayTtlUpsertOutcome::inserted);

  auto refreshed = table.upsert(make_request(1U), 11, 1000ms, now + 1ms);
  ASSERT_TRUE(refreshed) << refreshed.error_if()->safe_detail();
  EXPECT_EQ(*refreshed.value_if(), RelayTtlUpsertOutcome::updated);
  EXPECT_EQ(table.get(make_request(1U), now + 2ms), 11);

  auto second = table.upsert(make_request(2U), 20, 1000ms, now + 2ms);
  ASSERT_TRUE(second) << second.error_if()->safe_detail();

  auto rejected = table.upsert(make_request(3U), 30, 1000ms, now + 3ms);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->code(), ErrorCode::resource_exhausted);

  auto stats = table.diagnostics();
  EXPECT_EQ(stats.accepted, 2U);
  EXPECT_EQ(stats.updated, 1U);
  EXPECT_EQ(stats.capacity_rejected, 1U);
  EXPECT_EQ(stats.current_entries, 2U);
  EXPECT_EQ(stats.peak_entries, 2U);

  EXPECT_EQ(table.snapshot(now + 500ms).size(), 2U);
  EXPECT_FALSE(table.contains(make_request(1U), now + 1100ms));
  EXPECT_EQ(table.snapshot(now + 1100ms).size(), 0U);

  table.expire(now + 1100ms);
  stats = table.diagnostics();
  EXPECT_EQ(stats.expired, 2U);
  EXPECT_EQ(stats.current_entries, 0U);

  auto after_expiry = table.upsert(make_request(3U), 30, 1000ms, now + 1200ms);
  ASSERT_TRUE(after_expiry) << after_expiry.error_if()->safe_detail();
  EXPECT_EQ(*after_expiry.value_if(), RelayTtlUpsertOutcome::inserted);
  EXPECT_EQ(table.diagnostics().current_entries, 1U);

  auto erased = table.erase(make_request(3U));
  ASSERT_TRUE(erased) << erased.error_if()->safe_detail();
  EXPECT_EQ(table.diagnostics().current_entries, 0U);
}

TEST(M3BRelayTtlTableTest, RejectsZeroCapacityAndNonPositiveTtl) {
  EXPECT_FALSE((RelayTtlTable<DeviceEndpointKey, int>::create(0U)));
  auto table = RelayTtlTable<DeviceEndpointKey, int>::create(4U);
  ASSERT_TRUE(table) << table.error_if()->safe_detail();
  auto rejected = table.value_if()->upsert(make_key(1U, 1U), 7, 0ms);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->code(), ErrorCode::configuration);

  auto negative = table.value_if()->upsert(make_key(1U, 1U), 7, -1ms);
  ASSERT_FALSE(negative);
  EXPECT_EQ(negative.error_if()->code(), ErrorCode::configuration);
}

}  // namespace
}  // namespace heyaki
