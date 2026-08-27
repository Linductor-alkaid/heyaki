#include "relay_lease_table.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

Error lease_error(ErrorCode code, const char* detail) {
  return Error{code, "relay_lease", detail};
}

bool valid_tenant(std::string_view value) noexcept {
  if (value.empty() || value.size() > 128U) {
    return false;
  }
  for (const char raw : value) {
    if (static_cast<unsigned char>(raw) < 0x20U) {
      return false;
    }
  }
  return true;
}

std::chrono::milliseconds effective_lease(std::chrono::milliseconds requested,
                                          const RelayLeaseConfig& config) {
  if (requested.count() <= 0) {
    return config.default_lease;
  }
  return requested;
}

}  // namespace

struct RelayLeaseTable::Impl {
  explicit Impl(RelayLeaseConfig config_value) : config(std::move(config_value)) {}

  void unlink(const RelayLeaseKey& key) {
    const auto entry = entries.find(key);
    if (entry == entries.end()) {
      return;
    }
    const auto& device = entry->second.key.device_id;
    const auto& endpoint = entry->second.key.endpoint_id;
    const auto& tenant = entry->second.tenant;

    auto by_device = endpoints_by_device.find(device);
    if (by_device != endpoints_by_device.end()) {
      by_device->second.erase(endpoint);
      if (by_device->second.empty()) {
        endpoints_by_device.erase(by_device);
      }
    }
    auto by_tenant = devices_by_tenant.find(tenant);
    if (by_tenant != devices_by_tenant.end()) {
      by_tenant->second.erase(device);
      if (by_tenant->second.empty()) {
        devices_by_tenant.erase(by_tenant);
      }
    }
    entries.erase(entry);
  }

  std::uint64_t next_generation{1U};
  RelayLeaseConfig config;
  std::map<RelayLeaseKey, RelayLeaseRecord, std::less<>> entries;
  std::map<DeviceId, std::set<EndpointId>, std::less<>> endpoints_by_device;
  std::map<std::string, std::set<DeviceId>, std::less<>> devices_by_tenant;
  RelayLeaseDiagnostics stats;
};

RelayLeaseTable::RelayLeaseTable(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}
RelayLeaseTable::RelayLeaseTable(RelayLeaseTable&&) noexcept = default;
RelayLeaseTable& RelayLeaseTable::operator=(RelayLeaseTable&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}
RelayLeaseTable::~RelayLeaseTable() = default;

Result<RelayLeaseTable> RelayLeaseTable::create(const RelayLeaseConfig& config) {
  if (config.capacity == 0U || config.per_device_endpoint_capacity == 0U ||
      config.per_tenant_device_capacity == 0U || config.default_lease.count() <= 0 ||
      config.maximum_lease < config.default_lease) {
    return Result<RelayLeaseTable>::failure(
        lease_error(ErrorCode::configuration, "lease_config_invalid"));
  }
  return Result<RelayLeaseTable>::success(
      RelayLeaseTable{std::make_unique<Impl>(config)});
}

Result<RelayLeaseHeartbeatResult> RelayLeaseTable::heartbeat(
    RelayLeaseKey key, std::string tenant, std::chrono::milliseconds lease,
    std::chrono::steady_clock::time_point now) {
  if (!impl_) {
    return Result<RelayLeaseHeartbeatResult>::failure(
        lease_error(ErrorCode::cancelled, "lease_table_not_initialized"));
  }
  if (key.device_id.is_zero() || key.endpoint_id.is_zero() || !valid_tenant(tenant) ||
      lease > impl_->config.maximum_lease) {
    return Result<RelayLeaseHeartbeatResult>::failure(
        lease_error(ErrorCode::configuration, "lease_heartbeat_invalid"));
  }
  const auto duration = effective_lease(lease, impl_->config);

  auto existing = impl_->entries.find(key);
  if (existing != impl_->entries.end()) {
    if (existing->second.expires_at > now) {
      if (existing->second.tenant != tenant) {
        ++impl_->stats.tenant_conflict_rejected;
        return Result<RelayLeaseHeartbeatResult>::failure(
            lease_error(ErrorCode::permission, "lease_tenant_conflict"));
      }
      existing->second.expires_at = now + duration;
      existing->second.lease_generation = impl_->next_generation++;
      ++impl_->stats.refreshed;
      return Result<RelayLeaseHeartbeatResult>::success(RelayLeaseHeartbeatResult{
          .outcome = RelayLeaseHeartbeatOutcome::refreshed,
          .lease_generation = existing->second.lease_generation,
          .expires_at = existing->second.expires_at});
    }
    impl_->unlink(key);
    ++impl_->stats.expired;
  }

  if (impl_->entries.size() >= impl_->config.capacity) {
    ++impl_->stats.capacity_rejected;
    return Result<RelayLeaseHeartbeatResult>::failure(
        lease_error(ErrorCode::resource_exhausted, "lease_capacity_exhausted"));
  }
  const auto device_it = impl_->endpoints_by_device.find(key.device_id);
  if (device_it != impl_->endpoints_by_device.end() &&
      device_it->second.size() >= impl_->config.per_device_endpoint_capacity) {
    ++impl_->stats.per_device_rejected;
    return Result<RelayLeaseHeartbeatResult>::failure(
        lease_error(ErrorCode::resource_exhausted, "lease_per_device_capacity_exhausted"));
  }
  const auto tenant_it = impl_->devices_by_tenant.find(tenant);
  if (tenant_it != impl_->devices_by_tenant.end() &&
      !tenant_it->second.contains(key.device_id) &&
      tenant_it->second.size() >= impl_->config.per_tenant_device_capacity) {
    ++impl_->stats.per_tenant_rejected;
    return Result<RelayLeaseHeartbeatResult>::failure(
        lease_error(ErrorCode::resource_exhausted, "lease_per_tenant_capacity_exhausted"));
  }

  RelayLeaseRecord record{
      .key = key,
      .tenant = std::move(tenant),
      .lease_generation = impl_->next_generation++,
      .expires_at = now + duration,
  };
  impl_->entries.emplace(key, record);
  impl_->endpoints_by_device[key.device_id].insert(key.endpoint_id);
  impl_->devices_by_tenant[record.tenant].insert(key.device_id);
  ++impl_->stats.accepted;
  impl_->stats.current_entries = impl_->entries.size();
  impl_->stats.peak_entries = std::max(impl_->stats.peak_entries, impl_->entries.size());
  return Result<RelayLeaseHeartbeatResult>::success(RelayLeaseHeartbeatResult{
      .outcome = RelayLeaseHeartbeatOutcome::inserted,
      .lease_generation = record.lease_generation,
      .expires_at = record.expires_at});
}

Result<void> RelayLeaseTable::remove(const RelayLeaseKey& key) {
  if (!impl_) {
    return Result<void>::failure(lease_error(ErrorCode::cancelled, "lease_table_not_initialized"));
  }
  if (impl_->entries.contains(key)) {
    impl_->unlink(key);
    ++impl_->stats.removed;
    impl_->stats.current_entries = impl_->entries.size();
  }
  return Result<void>::success();
}

std::size_t RelayLeaseTable::remove_device(const DeviceId& device_id) {
  if (!impl_) {
    return 0U;
  }
  std::vector<RelayLeaseKey> keys;
  const auto device_it = impl_->endpoints_by_device.find(device_id);
  if (device_it != impl_->endpoints_by_device.end()) {
    for (const auto& endpoint_id : device_it->second) {
      keys.push_back(RelayLeaseKey{.device_id = device_id, .endpoint_id = endpoint_id});
    }
  }
  for (const auto& key : keys) {
    (void)remove(key);
  }
  return keys.size();
}

void RelayLeaseTable::expire(std::chrono::steady_clock::time_point now) {
  if (!impl_) {
    return;
  }
  std::vector<RelayLeaseKey> expired;
  for (const auto& [key, record] : impl_->entries) {
    if (record.expires_at <= now) {
      expired.push_back(key);
    }
  }
  for (const auto& key : expired) {
    impl_->unlink(key);
    ++impl_->stats.expired;
  }
  impl_->stats.current_entries = impl_->entries.size();
}

std::optional<RelayLeaseRecord> RelayLeaseTable::get(const RelayLeaseKey& key,
                                                     std::chrono::steady_clock::time_point now) const {
  if (!impl_) {
    return std::nullopt;
  }
  const auto found = impl_->entries.find(key);
  if (found == impl_->entries.end() || found->second.expires_at <= now) {
    return std::nullopt;
  }
  return found->second;
}

std::vector<RelayLeaseRecord> RelayLeaseTable::online(
    std::chrono::steady_clock::time_point now) const {
  std::vector<RelayLeaseRecord> output;
  if (!impl_) {
    return output;
  }
  for (const auto& [key, record] : impl_->entries) {
    (void)key;
    if (record.expires_at > now) {
      output.push_back(record);
    }
  }
  return output;
}

std::vector<RelayLeaseRecord> RelayLeaseTable::online_device(
    const DeviceId& device_id, std::chrono::steady_clock::time_point now) const {
  std::vector<RelayLeaseRecord> output;
  if (!impl_) {
    return output;
  }
  const auto device_it = impl_->endpoints_by_device.find(device_id);
  if (device_it == impl_->endpoints_by_device.end()) {
    return output;
  }
  for (const auto& endpoint_id : device_it->second) {
    const auto record = get(RelayLeaseKey{.device_id = device_id, .endpoint_id = endpoint_id}, now);
    if (record) {
      output.push_back(*record);
    }
  }
  return output;
}

std::vector<RelayLeaseRecord> RelayLeaseTable::online_tenant(
    std::string_view tenant, std::chrono::steady_clock::time_point now) const {
  std::vector<RelayLeaseRecord> output;
  if (!impl_) {
    return output;
  }
  const auto tenant_it = impl_->devices_by_tenant.find(std::string{tenant});
  if (tenant_it == impl_->devices_by_tenant.end()) {
    return output;
  }
  for (const auto& device_id : tenant_it->second) {
    const auto endpoints = online_device(device_id, now);
    output.insert(output.end(), endpoints.begin(), endpoints.end());
  }
  return output;
}

RelayLeaseDiagnostics RelayLeaseTable::diagnostics() const noexcept {
  return impl_ ? impl_->stats : RelayLeaseDiagnostics{};
}

}  // namespace heyaki
