#pragma once

#include <heyaki/error.hpp>
#include <heyaki/identity.hpp>
#include <heyaki/profile_store.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

struct RelayEnrollmentExchangeResult {
  std::string relay_url;
  std::string tenant;
  std::uint64_t enrollment_generation{};
  std::uint64_t token_remaining_uses_after{};
};

using RelayEnrollmentExchange = std::function<Result<RelayEnrollmentExchangeResult>(
    const IdentityKeyPair& identity, const EndpointId& endpoint_id,
    std::string_view tenant, std::string_view bootstrap_token,
    std::uint64_t now_unix_milliseconds)>;
using RelayEnrollmentRollback = std::function<Result<void>(
    const DeviceId& device_id, std::string_view tenant,
    std::uint64_t enrollment_generation)>;

struct RelayEnrollmentClientConfig {
  ProfileStore* profile{nullptr};
  std::string application_id;
  std::string relay_url;
  std::string tenant;
  std::optional<std::vector<std::byte>> relay_pin;
  bool auto_connect{true};
  RelayEnrollmentExchange exchange;
  RelayEnrollmentRollback rollback;
};

struct RelayEnrollmentClientResult {
  std::string relay_url;
  std::string tenant;
  std::uint64_t enrollment_generation{};
  std::uint64_t token_remaining_uses_after{};
};

[[nodiscard]] Result<RelayEnrollmentClientResult> enroll_relay_profile(
    const RelayEnrollmentClientConfig& config, std::string_view bootstrap_token,
    std::uint64_t now_unix_milliseconds);

}  // namespace heyaki
