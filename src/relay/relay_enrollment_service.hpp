#pragma once

#include "relay_database.hpp"
#include "relay_enrollment.hpp"
#include "relay_ttl_table.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace heyaki {

// Relay admission policy for new enrollments. `token` is the historical
// bootstrap-token flow and stays the default; `password` admits devices with
// the challenge-bound Argon2id proof of the owner password; `closed` refuses
// every new enrollment (existing devices keep logging in).
enum class RelayEnrollmentMode : std::uint8_t {
  token = 1U,
  password = 2U,
  closed = 3U,
};

struct RelayEnrollmentServiceConfig {
  std::size_t challenge_capacity{256U};
  std::chrono::milliseconds challenge_validity{60U * 1000U};
  RelayEnrollmentMode mode{RelayEnrollmentMode::token};
  // Only used by `password` mode: the single tenant password enrollment lands
  // in; requests naming any other tenant are rejected.
  std::string default_tenant{"default"};
};

struct RelayEnrollmentCompletion {
  DeviceId device_id;
  EndpointId endpoint_id;
  std::string tenant;
  std::uint64_t enrollment_generation{};
  std::optional<std::uint64_t> token_remaining_uses_after;
};

struct RelayEnrollmentServiceDiagnostics {
  std::uint64_t challenges_issued{};
  std::uint64_t challenges_completed{};
  std::uint64_t challenges_expired{};
  std::uint64_t challenges_unknown{};
  std::uint64_t validation_rejected{};
  std::uint64_t token_rejected{};
  std::uint64_t database_rejected{};
  // Password mode: wrong-proof verifications and requests rejected by the
  // admission mode itself (closed mode, wrong tenant, missing capability bit
  // or proof).
  std::uint64_t password_rejected{};
  std::uint64_t mode_rejected{};
  RelayTtlDiagnostics challenge_table;
};

class RelayEnrollmentService {
 public:
  struct Impl;

  RelayEnrollmentService(RelayEnrollmentService&&) noexcept;
  RelayEnrollmentService& operator=(RelayEnrollmentService&&) noexcept;
  ~RelayEnrollmentService();

  RelayEnrollmentService(const RelayEnrollmentService&) = delete;
  RelayEnrollmentService& operator=(const RelayEnrollmentService&) = delete;

  [[nodiscard]] static Result<RelayEnrollmentService> create(
      RelayDatabase* database, RelayId relay_id,
      const RelayEnrollmentServiceConfig& config = {});

  [[nodiscard]] Result<std::vector<std::byte>> begin_challenge(
      std::uint64_t now_unix_milliseconds);
  [[nodiscard]] Result<RelayEnrollmentCompletion> complete(
      std::span<const std::byte> encoded_request, std::uint64_t now_unix_milliseconds);
  [[nodiscard]] RelayEnrollmentServiceDiagnostics diagnostics() const noexcept;

 private:
  explicit RelayEnrollmentService(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

}  // namespace heyaki
