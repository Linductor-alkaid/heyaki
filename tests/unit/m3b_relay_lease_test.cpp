#include "relay_lease_table.hpp"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

namespace heyaki {
namespace {

using namespace std::chrono_literals;

RelayLeaseKey make_key(std::uint8_t device_byte, std::uint8_t endpoint_byte) {
  DeviceId::Storage device{};
  EndpointId::Storage endpoint{};
  device[0] = static_cast<std::byte>(device_byte);
  device[1] = static_cast<std::byte>(0x7aU);
  endpoint[0] = static_cast<std::byte>(endpoint_byte);
  return RelayLeaseKey{.device_id = DeviceId{device},
                       .endpoint_id = EndpointId{endpoint}};
}

TEST(M3BRelayLeaseTest, HeartbeatInsertsRefreshesAndQueriesByDeviceAndTenant) {
  auto created = RelayLeaseTable::create();
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  auto table = std::move(*created.value_if());
  const auto now = std::chrono::steady_clock::now();

  auto first = table.heartbeat(make_key(1U, 1U), "tenant-a", 0ms, now);
  ASSERT_TRUE(first) << first.error_if()->safe_detail();
  EXPECT_EQ(first.value_if()->outcome, RelayLeaseHeartbeatOutcome::inserted);
  EXPECT_EQ(first.value_if()->expires_at, now + 45000ms);
  EXPECT_EQ(first.value_if()->lease_generation, 1U);

  auto second = table.heartbeat(make_key(1U, 2U), "tenant-a", 0ms, now + 1ms);
  ASSERT_TRUE(second) << second.error_if()->safe_detail();
  EXPECT_EQ(second.value_if()->outcome, RelayLeaseHeartbeatOutcome::inserted);

  auto other_device = table.heartbeat(make_key(2U, 1U), "tenant-a", 0ms, now + 2ms);
  ASSERT_TRUE(other_device) << other_device.error_if()->safe_detail();

  auto refreshed = table.heartbeat(make_key(1U, 1U), "tenant-a", 60000ms, now + 3ms);
  ASSERT_TRUE(refreshed) << refreshed.error_if()->safe_detail();
  EXPECT_EQ(refreshed.value_if()->outcome, RelayLeaseHeartbeatOutcome::refreshed);
  EXPECT_EQ(refreshed.value_if()->expires_at, now + 3ms + 60000ms);
  EXPECT_GT(refreshed.value_if()->lease_generation, first.value_if()->lease_generation);

  EXPECT_EQ(table.online(now + 4ms).size(), 3U);
  EXPECT_EQ(table.online_device(DeviceId{[] {
              DeviceId::Storage bytes{};
              bytes[0] = std::byte{1U};
              bytes[1] = std::byte{0x7aU};
              return bytes;
            }()},
                                now + 4ms)
                .size(),
            2U);
  EXPECT_EQ(table.online_tenant("tenant-a", now + 4ms).size(), 3U);
  EXPECT_EQ(table.online_tenant("tenant-b", now + 4ms).size(), 0U);

  auto stats = table.diagnostics();
  EXPECT_EQ(stats.accepted, 3U);
  EXPECT_EQ(stats.refreshed, 1U);
  EXPECT_EQ(stats.current_entries, 3U);
  EXPECT_EQ(stats.peak_entries, 3U);
}

TEST(M3BRelayLeaseTest, ExpiryRemoveAndRemoveDeviceMaintainIndexes) {
  auto created = RelayLeaseTable::create();
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  auto table = std::move(*created.value_if());
  const auto now = std::chrono::steady_clock::now();

  ASSERT_TRUE(table.heartbeat(make_key(1U, 1U), "tenant-a", 1000ms, now));
  ASSERT_TRUE(table.heartbeat(make_key(1U, 2U), "tenant-a", 1000ms, now + 1ms));
  ASSERT_TRUE(table.heartbeat(make_key(2U, 1U), "tenant-b", 2000ms, now + 2ms));

  EXPECT_EQ(table.online(now + 100ms).size(), 3U);
  table.expire(now + 1500ms);
  EXPECT_EQ(table.online(now + 1501ms).size(), 1U);
  EXPECT_EQ(table.diagnostics().expired, 2U);

  auto removed = table.remove(make_key(1U, 1U));
  ASSERT_TRUE(removed) << removed.error_if()->safe_detail();
  EXPECT_EQ(table.online_device(DeviceId{[] {
              DeviceId::Storage bytes{};
              bytes[0] = std::byte{1U};
              bytes[1] = std::byte{0x7aU};
              return bytes;
            }()},
                                now + 100ms)
                .size(),
            0U);

  const auto removed_device_count = table.remove_device(DeviceId{[] {
    DeviceId::Storage bytes{};
    bytes[0] = std::byte{2U};
    bytes[1] = std::byte{0x7aU};
    return bytes;
  }()});
  EXPECT_EQ(removed_device_count, 1U);
  EXPECT_EQ(table.diagnostics().removed, 1U);
  EXPECT_EQ(table.online(now + 100ms).size(), 0U);
}

TEST(M3BRelayLeaseTest, EnforcesTotalPerDeviceAndPerTenantCapacity) {
  RelayLeaseConfig config;
  config.capacity = 2U;
  config.per_device_endpoint_capacity = 1U;
  config.per_tenant_device_capacity = 1U;
  auto created = RelayLeaseTable::create(config);
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  auto table = std::move(*created.value_if());
  const auto now = std::chrono::steady_clock::now();

  auto first = table.heartbeat(make_key(1U, 1U), "tenant-a", 0ms, now);
  ASSERT_TRUE(first) << first.error_if()->safe_detail();
  auto per_device = table.heartbeat(make_key(1U, 2U), "tenant-a", 0ms, now + 1ms);
  ASSERT_FALSE(per_device);
  EXPECT_EQ(per_device.error_if()->safe_detail(), "lease_per_device_capacity_exhausted");

  auto per_tenant = table.heartbeat(make_key(2U, 1U), "tenant-a", 0ms, now + 2ms);
  ASSERT_FALSE(per_tenant);
  EXPECT_EQ(per_tenant.error_if()->safe_detail(), "lease_per_tenant_capacity_exhausted");

  auto other_tenant = table.heartbeat(make_key(2U, 1U), "tenant-b", 0ms, now + 3ms);
  ASSERT_TRUE(other_tenant) << other_tenant.error_if()->safe_detail();
  auto total = table.heartbeat(make_key(3U, 1U), "tenant-c", 0ms, now + 4ms);
  ASSERT_FALSE(total);
  EXPECT_EQ(total.error_if()->safe_detail(), "lease_capacity_exhausted");

  const auto stats = table.diagnostics();
  EXPECT_EQ(stats.accepted, 2U);
  EXPECT_EQ(stats.per_device_rejected, 1U);
  EXPECT_EQ(stats.per_tenant_rejected, 1U);
  EXPECT_EQ(stats.capacity_rejected, 1U);
}

TEST(M3BRelayLeaseTest, RejectsTenantConflictAndInvalidConfiguration) {
  auto created = RelayLeaseTable::create();
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  auto table = std::move(*created.value_if());
  const auto now = std::chrono::steady_clock::now();
  ASSERT_TRUE(table.heartbeat(make_key(1U, 1U), "tenant-a", 0ms, now));

  auto conflict = table.heartbeat(make_key(1U, 1U), "tenant-b", 0ms, now + 1ms);
  ASSERT_FALSE(conflict);
  EXPECT_EQ(conflict.error_if()->safe_detail(), "lease_tenant_conflict");
  EXPECT_EQ(table.diagnostics().tenant_conflict_rejected, 1U);

  EXPECT_FALSE((RelayLeaseTable::create([] {
    RelayLeaseConfig invalid;
    invalid.capacity = 0U;
    return invalid;
  }())));
  EXPECT_FALSE(table.heartbeat(RelayLeaseKey{}, "tenant-a", 0ms, now));
  EXPECT_FALSE(table.heartbeat(make_key(1U, 2U), "", 0ms, now));
  EXPECT_FALSE(table.heartbeat(make_key(1U, 2U), "tenant-a", 121000ms, now));
}

}  // namespace
}  // namespace heyaki
