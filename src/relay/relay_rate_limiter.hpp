#pragma once

#include <heyaki/error.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace heyaki {

enum class RelayRateLimitScope : std::uint8_t {
  connection,
  request,
  tenant,
  ip,
};

struct RelayRateLimitRule {
  std::size_t capacity{16U};
  std::chrono::milliseconds window{1000};
  std::size_t max_keys{4096U};
};

struct RelayRateLimitPolicy {
  RelayRateLimitRule connection{16U, std::chrono::milliseconds{1000}, 4096U};
  RelayRateLimitRule request{256U, std::chrono::milliseconds{1000}, 1U};
  RelayRateLimitRule tenant{64U, std::chrono::milliseconds{1000}, 1024U};
  RelayRateLimitRule ip{32U, std::chrono::milliseconds{1000}, 4096U};
  std::chrono::milliseconds entry_ttl{60000};
};

struct RelayRateLimitCounters {
  std::uint64_t allowed{};
  std::uint64_t rejected{};
  std::uint64_t capacity_rejected{};
  std::size_t current_keys{};
  std::size_t peak_keys{};
};

struct RelayRateLimitDiagnostics {
  RelayRateLimitCounters connection;
  RelayRateLimitCounters request;
  RelayRateLimitCounters tenant;
  RelayRateLimitCounters ip;
};

class RelayRateLimiter {
 public:
  struct Impl;

  RelayRateLimiter(RelayRateLimiter&&) noexcept;
  RelayRateLimiter& operator=(RelayRateLimiter&&) noexcept;
  ~RelayRateLimiter();

  RelayRateLimiter(const RelayRateLimiter&) = delete;
  RelayRateLimiter& operator=(const RelayRateLimiter&) = delete;

  [[nodiscard]] static Result<RelayRateLimiter> create(
      const RelayRateLimitPolicy& policy = {});
  [[nodiscard]] static Result<void> validate_policy(const RelayRateLimitPolicy& policy);

  [[nodiscard]] Result<void> check_connection(
      std::string_view connection_id,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  [[nodiscard]] Result<void> check_request(
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  [[nodiscard]] Result<void> check_tenant(
      std::string_view tenant,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  [[nodiscard]] Result<void> check_ip(
      std::string_view ip,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  void prune(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  [[nodiscard]] RelayRateLimitDiagnostics diagnostics() const noexcept;

 private:
  explicit RelayRateLimiter(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

[[nodiscard]] std::string_view relay_rate_limit_scope_name(
    RelayRateLimitScope scope) noexcept;

}  // namespace heyaki
