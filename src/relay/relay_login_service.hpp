#pragma once

#include "relay_database.hpp"
#include "relay_enrollment.hpp"
#include "relay_login.hpp"
#include "relay_ttl_table.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace heyaki {

struct RelayLoginServiceConfig {
  std::size_t challenge_capacity{256U};
  std::chrono::milliseconds challenge_validity{60U * 1000U};
};

struct RelayLoginCompletion {
  DeviceId device_id;
  EndpointId endpoint_id;
  std::string tenant;
  std::uint64_t enrollment_generation{};
  CapabilitySet capabilities;
};

struct RelayLoginServiceDiagnostics {
  std::uint64_t challenges_issued{};
  std::uint64_t logins_succeeded{};
  std::uint64_t challenges_unknown{};
  std::uint64_t validation_rejected{};
  std::uint64_t device_rejected{};
  std::uint64_t audit_failed{};
  RelayTtlDiagnostics challenge_table;
};

class RelayLoginService {
 public:
  class Impl;

  RelayLoginService(RelayLoginService&&) noexcept;
  RelayLoginService& operator=(RelayLoginService&&) noexcept;
  ~RelayLoginService();

  RelayLoginService(const RelayLoginService&) = delete;
  RelayLoginService& operator=(const RelayLoginService&) = delete;

  [[nodiscard]] static Result<RelayLoginService> create(
      RelayDatabase* database, RelayId relay_id,
      const RelayLoginServiceConfig& config = {});

  [[nodiscard]] Result<std::vector<std::byte>> begin_challenge(
      std::uint64_t now_unix_milliseconds);
  [[nodiscard]] Result<RelayLoginCompletion> authenticate(
      std::span<const std::byte> encoded_request, std::uint64_t now_unix_milliseconds);
  [[nodiscard]] RelayLoginServiceDiagnostics diagnostics() const noexcept;

 private:
  explicit RelayLoginService(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

}  // namespace heyaki
