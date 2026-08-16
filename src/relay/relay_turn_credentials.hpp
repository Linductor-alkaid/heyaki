#pragma once

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace heyaki {

inline constexpr std::size_t turn_secret_min_bytes = 16U;
inline constexpr std::size_t turn_secret_max_bytes = 256U;
inline constexpr std::uint32_t turn_credential_max_ttl_seconds = 86400U;

struct RelayTurnSecretConfig {
  std::size_t max_secrets{4U};
  std::chrono::seconds credential_ttl{600};
};

struct RelayTurnCredential {
  std::string username;
  std::string password;
  std::uint64_t expires_unix_seconds{};
  std::uint64_t secret_generation{};
};

struct RelayTurnCredentialDiagnostics {
  std::uint64_t issued{};
  std::uint64_t validated{};
  std::uint64_t validation_rejected{};
  std::uint64_t latest_secret_generation{};
  std::size_t active_secrets{};
};

class RelayTurnCredentialService {
 public:
  struct Impl;

  RelayTurnCredentialService(RelayTurnCredentialService&&) noexcept;
  RelayTurnCredentialService& operator=(RelayTurnCredentialService&&) noexcept;
  ~RelayTurnCredentialService();

  RelayTurnCredentialService(const RelayTurnCredentialService&) = delete;
  RelayTurnCredentialService& operator=(const RelayTurnCredentialService&) = delete;

  [[nodiscard]] static Result<RelayTurnCredentialService> create(
      const RelayTurnSecretConfig& config = {});
  [[nodiscard]] static Result<void> validate_config(const RelayTurnSecretConfig& config);

  [[nodiscard]] Result<void> set_secret(std::uint64_t generation,
                                        std::string_view secret,
                                        std::uint64_t activated_unix_seconds);
  [[nodiscard]] Result<RelayTurnCredential> issue(
      std::string_view tenant, const DeviceId& device_id,
      std::uint64_t now_unix_seconds);
  [[nodiscard]] Result<std::uint64_t> validate(
      std::string_view username, std::string_view password,
      std::uint64_t now_unix_seconds);
  [[nodiscard]] RelayTurnCredentialDiagnostics diagnostics() const noexcept;

 private:
  explicit RelayTurnCredentialService(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

[[nodiscard]] Result<std::string> turn_rest_password(std::string_view secret,
                                                     std::string_view username);
[[nodiscard]] Result<void> validate_turn_secret(std::string_view secret);

}  // namespace heyaki
