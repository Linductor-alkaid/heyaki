#pragma once

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

struct RelayLeaseKey {
  DeviceId device_id;
  EndpointId endpoint_id;

  friend constexpr bool operator==(const RelayLeaseKey&,
                                   const RelayLeaseKey&) noexcept = default;
  friend constexpr auto operator<=>(const RelayLeaseKey&,
                                    const RelayLeaseKey&) noexcept = default;
};

struct RelayLeaseRecord {
  RelayLeaseKey key;
  std::string tenant;
  std::uint64_t lease_generation{};
  std::chrono::steady_clock::time_point expires_at;
};

struct RelayLeaseConfig {
  std::size_t capacity{4096U};
  std::size_t per_device_endpoint_capacity{64U};
  std::size_t per_tenant_device_capacity{4096U};
  std::chrono::milliseconds default_lease{45000};
  std::chrono::milliseconds maximum_lease{120000};
};

enum class RelayLeaseHeartbeatOutcome : std::uint8_t {
  inserted,
  refreshed,
};

struct RelayLeaseHeartbeatResult {
  RelayLeaseHeartbeatOutcome outcome{RelayLeaseHeartbeatOutcome::inserted};
  std::uint64_t lease_generation{};
  std::chrono::steady_clock::time_point expires_at;
};

struct RelayLeaseDiagnostics {
  std::uint64_t accepted{};
  std::uint64_t refreshed{};
  std::uint64_t expired{};
  std::uint64_t removed{};
  std::uint64_t capacity_rejected{};
  std::uint64_t per_device_rejected{};
  std::uint64_t per_tenant_rejected{};
  std::uint64_t tenant_conflict_rejected{};
  std::size_t current_entries{};
  std::size_t peak_entries{};
};

class RelayLeaseTable {
 public:
  struct Impl;

  RelayLeaseTable(RelayLeaseTable&&) noexcept;
  RelayLeaseTable& operator=(RelayLeaseTable&&) noexcept;
  ~RelayLeaseTable();

  RelayLeaseTable(const RelayLeaseTable&) = delete;
  RelayLeaseTable& operator=(const RelayLeaseTable&) = delete;

  [[nodiscard]] static Result<RelayLeaseTable> create(const RelayLeaseConfig& config = {});

  [[nodiscard]] Result<RelayLeaseHeartbeatResult> heartbeat(
      RelayLeaseKey key, std::string tenant,
      std::chrono::milliseconds lease = std::chrono::milliseconds{0},
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  [[nodiscard]] Result<void> remove(const RelayLeaseKey& key);
  [[nodiscard]] std::size_t remove_device(const DeviceId& device_id);
  void expire(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  [[nodiscard]] std::optional<RelayLeaseRecord> get(
      const RelayLeaseKey& key,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const;
  [[nodiscard]] std::vector<RelayLeaseRecord> online(
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const;
  [[nodiscard]] std::vector<RelayLeaseRecord> online_device(
      const DeviceId& device_id,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const;
  [[nodiscard]] std::vector<RelayLeaseRecord> online_tenant(
      std::string_view tenant,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const;
  [[nodiscard]] RelayLeaseDiagnostics diagnostics() const noexcept;

 private:
  explicit RelayLeaseTable(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

}  // namespace heyaki
