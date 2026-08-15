#pragma once

#include <heyaki/identity.hpp>
#include <heyaki/password.hpp>
#include <heyaki/secret_backend.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

inline constexpr std::uint32_t profile_schema_version = 2U;

struct ProfileOpenOptions {
  std::chrono::milliseconds lock_timeout{2000};
  std::chrono::milliseconds sqlite_busy_timeout{2000};
  SecretBackendOptions secret_backend;
  std::shared_ptr<SecretBackend> secrets;
};

struct ProfileInfo {
  std::string name;
  std::filesystem::path database_path;
};

enum class TrustGrantDirection : std::uint8_t {
  issued = 1,
  received = 2,
};

struct TrustGrantRecord {
  GrantId grant_id;
  TrustGrantDirection direction{TrustGrantDirection::issued};
  DeviceId issuer;
  DeviceId subject;
  std::vector<std::string> scopes;
  std::uint64_t password_generation{1U};
  std::uint64_t issued_unix_milliseconds{};
  std::optional<std::uint64_t> expires_unix_milliseconds;
  std::vector<std::byte> signature;
  bool revoked{false};
};

class ProfileStore {
 public:
  class Impl;

  ProfileStore(ProfileStore&&) noexcept;
  ProfileStore& operator=(ProfileStore&&) noexcept;
  ~ProfileStore();

  ProfileStore(const ProfileStore&) = delete;
  ProfileStore& operator=(const ProfileStore&) = delete;

  [[nodiscard]] static Result<ProfileStore> create(
      const std::filesystem::path& database_path, const ProfileOpenOptions& options = {});
  [[nodiscard]] static Result<ProfileStore> open(
      const std::filesystem::path& database_path, const ProfileOpenOptions& options = {});
  [[nodiscard]] static Result<ProfileStore> create_default(
      std::string_view profile_name, const ProfileOpenOptions& options = {});
  [[nodiscard]] static Result<ProfileStore> open_default(
      std::string_view profile_name = "default", const ProfileOpenOptions& options = {});

  [[nodiscard]] static Result<std::filesystem::path> default_profiles_root();
  [[nodiscard]] static Result<std::vector<ProfileInfo>> enumerate_default();
  [[nodiscard]] static Result<void> rename_default(
      std::string_view current_name, std::string_view new_name,
      std::chrono::milliseconds lock_timeout = std::chrono::milliseconds{2000});
  [[nodiscard]] static Result<void> delete_local(
      const std::filesystem::path& database_path,
      std::chrono::milliseconds lock_timeout = std::chrono::milliseconds{2000});
  [[nodiscard]] static std::filesystem::path migration_backup_path(
      const std::filesystem::path& database_path, std::uint32_t source_version);
  [[nodiscard]] static Result<void> restore_from_backup(
      const std::filesystem::path& database_path,
      const std::filesystem::path& backup_path,
      std::chrono::milliseconds lock_timeout = std::chrono::milliseconds{2000});

  [[nodiscard]] const std::filesystem::path& path() const noexcept;
  [[nodiscard]] const DeviceId& device_id() const noexcept;
  [[nodiscard]] const IdentityPublicKey& identity_public_key() const noexcept;
  [[nodiscard]] SecretBackendSecurity secret_backend_security() const noexcept;
  [[nodiscard]] Result<IdentityKeyPair> load_identity() const;

  [[nodiscard]] Result<EndpointId> endpoint_for(std::string_view application_id);
  [[nodiscard]] Result<void> set_password_verifier(const PasswordVerifier& verifier,
                                                   std::uint64_t password_generation);
  [[nodiscard]] Result<std::optional<PasswordVerifier>> password_verifier() const;
  [[nodiscard]] Result<std::uint64_t> password_generation() const;

  [[nodiscard]] Result<void> put_trust_grant(const TrustGrantRecord& grant);
  [[nodiscard]] Result<std::optional<TrustGrantRecord>> trust_grant(
      const GrantId& grant_id) const;
  [[nodiscard]] Result<void> revoke_trust_grant(const GrantId& grant_id,
                                                std::uint64_t revoked_unix_milliseconds);
  [[nodiscard]] Result<bool> is_scope_authorized(
      const DeviceId& peer, std::string_view scope, std::uint64_t now_unix_milliseconds) const;

  [[nodiscard]] Result<void> mark_relay_revoked(std::string_view relay_url,
                                                std::uint64_t enrollment_generation);
  [[nodiscard]] Result<void> export_to(const std::filesystem::path& destination) const;

 private:
  explicit ProfileStore(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

}  // namespace heyaki
