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

inline constexpr std::uint32_t profile_schema_version = 3U;

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

enum class ConnectivityMode : std::uint8_t {
  automatic = 1,
  lan_only = 2,
  relay_only = 3,
};

struct LanConfiguration {
  ConnectivityMode connectivity_mode{ConnectivityMode::automatic};
  bool enabled{true};
  bool discoverable{true};
  bool auto_connect_trusted{false};
  std::vector<std::string> interface_preferences;
  std::size_t interface_capacity{32U};
  std::size_t directory_capacity{4096U};
  std::size_t trusted_directory_reserve{128U};
  std::size_t per_interface_directory_capacity{1024U};
  std::size_t per_source_presence_capacity{64U};
  std::size_t unknown_identity_capacity{512U};
  std::size_t replay_capacity{8192U};
  std::size_t diagnostic_capacity{1024U};
  std::size_t provisional_connection_capacity{64U};
  std::size_t per_source_provisional_capacity{8U};
  std::size_t provisional_accept_rate_per_second{64U};
  std::size_t per_source_provisional_rate{16U};
  std::size_t pending_signaling_capacity{128U};
  std::size_t auto_connect_capacity{16U};
  std::size_t announcement_rate_per_second{32U};
  std::size_t per_source_announcement_rate{8U};
  std::chrono::milliseconds announcement_interval{5000};
  std::chrono::milliseconds presence_lease{15000};
  std::chrono::milliseconds announcement_jitter{500};
  std::chrono::milliseconds interface_refresh_interval{5000};
  std::chrono::milliseconds handshake_timeout{5000};
  std::chrono::milliseconds hello_timeout{3000};
  std::chrono::milliseconds route_preference_delay{250};
  std::chrono::milliseconds shutdown_timeout{2000};
};

struct PairingPolicy {
  std::uint64_t generation{1U};
  bool password_pairing_enabled{true};
  bool require_manual_approval_unknown{true};
  std::vector<std::string> default_scopes;
};

struct LocalProfileInitialization {
  std::string application_id;
  PasswordVerifier password_verifier;
  std::uint64_t password_generation{1U};
  PairingPolicy pairing_policy;
  LanConfiguration lan;
};

struct LocalProfileReadiness {
  bool identity_ready{false};
  bool endpoint_ready{false};
  bool password_verifier_ready{false};
  bool pairing_policy_ready{false};
  bool lan_configuration_ready{false};

  [[nodiscard]] bool ready() const noexcept {
    return identity_ready && endpoint_ready && password_verifier_ready &&
           pairing_policy_ready && lan_configuration_ready;
  }
};

[[nodiscard]] Result<void> validate_lan_configuration(const LanConfiguration& configuration);
[[nodiscard]] Result<void> validate_pairing_policy(const PairingPolicy& policy);

enum class TrustGrantDirection : std::uint8_t {
  issued = 1,
  received = 2,
};

struct RelayEnrollmentRecord {
  std::string relay_url;
  std::optional<std::vector<std::byte>> relay_pin;
  std::string tenant;
  std::uint64_t enrollment_generation{};
  bool auto_connect{true};
  bool revoked{false};
  std::uint64_t updated_unix_milliseconds{};
};

struct TrustGrantRecord {
  GrantId grant_id;
  TrustGrantDirection direction{TrustGrantDirection::issued};
  DeviceId issuer;
  DeviceId subject;
  std::vector<std::string> scopes;
  std::uint64_t password_generation{1U};
  std::uint64_t issued_unix_milliseconds{};
  std::optional<std::uint64_t> expires_unix_milliseconds{};
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
  [[nodiscard]] Result<EndpointId> initialize_local(
      const LocalProfileInitialization& initialization);
  [[nodiscard]] Result<LocalProfileReadiness> local_readiness(
      std::string_view application_id) const;
  [[nodiscard]] Result<void> set_lan_configuration(const LanConfiguration& configuration);
  [[nodiscard]] Result<LanConfiguration> lan_configuration() const;
  [[nodiscard]] Result<void> set_pairing_policy(const PairingPolicy& policy);
  [[nodiscard]] Result<PairingPolicy> pairing_policy() const;
  [[nodiscard]] Result<void> set_password_verifier(const PasswordVerifier& verifier,
                                                   std::uint64_t password_generation);
  [[nodiscard]] Result<std::optional<PasswordVerifier>> password_verifier() const;
  [[nodiscard]] Result<std::uint64_t> password_generation() const;

  [[nodiscard]] Result<void> put_trust_grant(const TrustGrantRecord& grant);
  [[nodiscard]] Result<std::optional<TrustGrantRecord>> trust_grant(
      const GrantId& grant_id) const;
  // Valid (non-revoked, non-expired) grants of the relationship with `peer`
  // in both directions. Password rotation alone never invalidates a grant;
  // only explicit revocation does.
  [[nodiscard]] Result<std::vector<TrustGrantRecord>> trust_grants_for_peer(
      const DeviceId& peer, std::uint64_t now_unix_milliseconds) const;
  [[nodiscard]] Result<void> revoke_trust_grant(const GrantId& grant_id,
                                                std::uint64_t revoked_unix_milliseconds);
  // Revokes every still-valid grant this device issued with a password
  // generation below `minimum_generation` (M5-13 "rotate and revoke").
  [[nodiscard]] Result<std::size_t> revoke_issued_trust_grants_below_generation(
      std::uint64_t minimum_generation, std::uint64_t revoked_unix_milliseconds);
  [[nodiscard]] Result<bool> is_scope_authorized(
      const DeviceId& peer, std::string_view scope, std::uint64_t now_unix_milliseconds) const;
  [[nodiscard]] Result<bool> is_device_trusted(
      const DeviceId& peer, std::uint64_t now_unix_milliseconds) const;
  [[nodiscard]] Result<std::vector<DeviceId>> trusted_devices(
      std::uint64_t now_unix_milliseconds) const;

  [[nodiscard]] Result<void> put_relay_enrollment(
      const RelayEnrollmentRecord& enrollment);
  [[nodiscard]] Result<std::optional<RelayEnrollmentRecord>> relay_enrollment(
      std::string_view relay_url) const;
  [[nodiscard]] Result<std::vector<RelayEnrollmentRecord>> relay_enrollments() const;
  [[nodiscard]] Result<void> mark_relay_revoked(std::string_view relay_url,
                                                std::uint64_t enrollment_generation);
  [[nodiscard]] Result<void> export_to(const std::filesystem::path& destination) const;

 private:
  explicit ProfileStore(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

}  // namespace heyaki
