#pragma once

#include <heyaki/error.hpp>
#include <heyaki/identity.hpp>
#include <heyaki/ids.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace heyaki {

inline constexpr std::uint32_t relay_database_schema_version = 2U;
inline constexpr std::size_t relay_bootstrap_token_hash_bytes = 32U;
inline constexpr std::size_t relay_bootstrap_token_id_bytes = 16U;
inline constexpr std::size_t relay_bootstrap_token_min_bytes = 16U;
inline constexpr std::size_t relay_bootstrap_token_max_bytes = 256U;
inline constexpr std::uint64_t relay_bootstrap_token_max_uses = 1000000U;

using RelayBootstrapTokenId = std::array<std::byte, relay_bootstrap_token_id_bytes>;
using RelayBootstrapTokenHash = std::array<std::byte, relay_bootstrap_token_hash_bytes>;

struct RelayDatabaseOpenOptions {
  bool create_if_missing{true};
  std::chrono::milliseconds sqlite_busy_timeout{2000};
};

struct RelayBootstrapTokenReceipt {
  RelayBootstrapTokenId token_id{};
  RelayBootstrapTokenHash token_hash{};
  std::string tenant;
  std::uint64_t expires_unix_milliseconds{};
  std::uint64_t remaining_uses{};
};

struct RelayBootstrapConsumption {
  RelayBootstrapTokenId token_id{};
  std::string tenant;
  std::uint64_t expires_unix_milliseconds{};
  std::uint64_t remaining_uses_before{};
  std::uint64_t remaining_uses_after{};
};

enum class RelayDeviceStatus : std::uint8_t {
  active = 1,
  revoked = 2,
};

struct RelayDeviceRecord {
  DeviceId device_id;
  IdentityPublicKey public_key{};
  std::string tenant;
  std::string display_name;
  std::uint64_t enrollment_generation{1U};
  RelayDeviceStatus status{RelayDeviceStatus::active};
  std::uint64_t created_unix_milliseconds{};
  std::uint64_t updated_unix_milliseconds{};
};

struct RelayDatabaseSnapshot {
  std::uint32_t schema_version{};
  std::uint64_t device_count{};
  std::uint64_t bootstrap_token_count{};
  std::uint64_t device_audit_count{};
};

[[nodiscard]] Result<RelayBootstrapTokenHash> hash_relay_bootstrap_token(
    std::string_view bootstrap_token);
[[nodiscard]] Result<void> validate_relay_bootstrap_token(
    std::string_view bootstrap_token);

class RelayDatabase {
 public:
  struct Impl;

  RelayDatabase(RelayDatabase&&) noexcept;
  RelayDatabase& operator=(RelayDatabase&&) noexcept;
  ~RelayDatabase();

  RelayDatabase(const RelayDatabase&) = delete;
  RelayDatabase& operator=(const RelayDatabase&) = delete;

  [[nodiscard]] static Result<RelayDatabase> open(
      const std::filesystem::path& database_path,
      const RelayDatabaseOpenOptions& options = {});
  [[nodiscard]] static Result<void> validate_existing(
      const std::filesystem::path& database_path);

  [[nodiscard]] const std::filesystem::path& path() const noexcept;
  // Live table counts straight from SQLite; reflects other connections.
  [[nodiscard]] RelayDatabaseSnapshot snapshot() const;
  // In-process counters maintained by this connection's mutators. Accurate for
  // the relay server (the sole writer) without per-login COUNT(*) scans.
  [[nodiscard]] RelayDatabaseSnapshot cached_snapshot() const;

  [[nodiscard]] Result<RelayBootstrapTokenReceipt> create_bootstrap_token(
      std::string tenant, std::string_view bootstrap_token,
      std::uint64_t expires_unix_milliseconds, std::uint64_t remaining_uses);
  [[nodiscard]] Result<RelayBootstrapConsumption> consume_bootstrap_token(
      std::string_view bootstrap_token, std::string_view tenant,
      std::optional<DeviceId> device_id, std::uint64_t now_unix_milliseconds);
  [[nodiscard]] Result<void> record_device_audit(
      DeviceId device_id, std::string_view action,
      std::uint64_t occurred_unix_milliseconds, std::string_view metadata);
  [[nodiscard]] Result<void> enroll_device(const RelayDeviceRecord& record,
                                           std::uint64_t now_unix_milliseconds);
  [[nodiscard]] Result<std::optional<RelayDeviceRecord>> device(
      const DeviceId& device_id) const;
  [[nodiscard]] Result<void> revoke_device(DeviceId device_id,
                                           std::uint64_t enrollment_generation,
                                           std::uint64_t revoked_unix_milliseconds);

 private:
  explicit RelayDatabase(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

}  // namespace heyaki
