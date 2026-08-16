#include <heyaki/identity.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <executor/comm/channel.hpp>
#include <executor/comm/phase_gate.hpp>
#include <executor/executor.hpp>

#include <gtest/gtest.h>
#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <future>
#include <iterator>
#include <string>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <windows.h>
#endif

namespace heyaki {
namespace {

SecretBackendOptions encrypted_file_secret_options() {
  SecretBackendOptions options;
  options.prefer_os_backend = false;
  return options;
}

ProfileOpenOptions encrypted_file_profile_options() {
  ProfileOpenOptions options;
  options.secret_backend = encrypted_file_secret_options();
  return options;
}

bool create_v1_profile_fixture(const std::filesystem::path& database_path,
                               bool remove_trust_grants,
                               DeviceId& created_device_id) {
  std::error_code filesystem_error;
  std::filesystem::create_directories(database_path.parent_path(), filesystem_error);
  if (filesystem_error) {
    return false;
  }
#ifndef _WIN32
  if (::chmod(database_path.parent_path().c_str(), S_IRWXU) != 0) {
    return false;
  }
#endif
  auto secrets = open_default_secret_backend(
      database_path.parent_path() / (database_path.filename().string() + ".secrets"),
      encrypted_file_secret_options());
  auto identity = create_identity();
  if (!secrets || !identity) {
    return false;
  }
  auto handle = (*secrets.value_if())->store("identity-ed25519",
                                             identity.value_if()->secret_key());
  if (!handle) {
    return false;
  }

  std::ifstream fixture(HEYAKI_M2_PROFILE_V1_FIXTURE, std::ios::binary);
  if (!fixture) {
    return false;
  }
  const std::string fixture_sql{std::istreambuf_iterator<char>{fixture},
                                std::istreambuf_iterator<char>{}};
  sqlite3* database = nullptr;
  if (sqlite3_open(database_path.string().c_str(), &database) != SQLITE_OK) {
    if (database != nullptr) {
      sqlite3_close(database);
    }
    return false;
  }
  bool success = sqlite3_exec(database, fixture_sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
  sqlite3_stmt* statement = nullptr;
  if (success) {
    success = sqlite3_prepare_v2(
                  database,
                  "INSERT INTO identity(singleton, device_id, public_key, secret_handle, "
                  "created_unix_milliseconds) VALUES(1, ?, ?, ?, 1)",
                  -1, &statement, nullptr) == SQLITE_OK;
  }
  if (success) {
    success = sqlite3_bind_blob(statement, 1, identity.value_if()->device_id().bytes().data(),
                                static_cast<int>(DeviceId::size_bytes), SQLITE_TRANSIENT) ==
                  SQLITE_OK &&
              sqlite3_bind_blob(statement, 2, identity.value_if()->public_key().data(),
                                static_cast<int>(identity.value_if()->public_key().size()),
                                SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_bind_text(statement, 3, handle.value_if()->value.c_str(), -1,
                                SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_step(statement) == SQLITE_DONE;
  }
  if (statement != nullptr) {
    sqlite3_finalize(statement);
  }
  if (success && remove_trust_grants) {
    success = sqlite3_exec(database, "DROP TABLE trust_grants", nullptr, nullptr, nullptr) ==
              SQLITE_OK;
  }
  success = sqlite3_close(database) == SQLITE_OK && success;
#ifndef _WIN32
  success = ::chmod(database_path.c_str(), S_IRUSR | S_IWUSR) == 0 && success;
#endif
  if (success) {
    created_device_id = identity.value_if()->device_id();
  }
  return success;
}

int read_user_version(const std::filesystem::path& database_path) {
  sqlite3* database = nullptr;
  if (sqlite3_open_v2(database_path.string().c_str(), &database, SQLITE_OPEN_READONLY, nullptr) !=
      SQLITE_OK) {
    if (database != nullptr) {
      sqlite3_close(database);
    }
    return -1;
  }
  sqlite3_stmt* statement = nullptr;
  int version = -1;
  if (sqlite3_prepare_v2(database, "PRAGMA user_version", -1, &statement, nullptr) == SQLITE_OK &&
      sqlite3_step(statement) == SQLITE_ROW) {
    version = sqlite3_column_int(statement, 0);
  }
  if (statement != nullptr) {
    sqlite3_finalize(statement);
  }
  sqlite3_close(database);
  return version;
}

bool sqlite_object_exists(const std::filesystem::path& database_path, std::string_view type,
                          std::string_view name) {
  sqlite3* database = nullptr;
  if (sqlite3_open_v2(database_path.string().c_str(), &database, SQLITE_OPEN_READONLY, nullptr) !=
      SQLITE_OK) {
    if (database != nullptr) {
      sqlite3_close(database);
    }
    return false;
  }
  sqlite3_stmt* statement = nullptr;
  bool exists = false;
  if (sqlite3_prepare_v2(database,
                        "SELECT 1 FROM sqlite_schema WHERE type=? AND name=? LIMIT 1", -1,
                        &statement, nullptr) == SQLITE_OK) {
    sqlite3_bind_text(statement, 1, type.data(), static_cast<int>(type.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, name.data(), static_cast<int>(name.size()), SQLITE_TRANSIENT);
    exists = sqlite3_step(statement) == SQLITE_ROW;
  }
  if (statement != nullptr) {
    sqlite3_finalize(statement);
  }
  sqlite3_close(database);
  return exists;
}

class M2ProfileTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M2_TEST_STATE_DIR} / "profile-store";
    cleanup();
    std::filesystem::create_directories(root_);
  }

  void TearDown() override { cleanup(); }

  void cleanup() {
    std::error_code ignored;
    if (!std::filesystem::exists(root_, ignored)) {
      return;
    }
    std::vector<std::filesystem::path> databases;
    for (std::filesystem::recursive_directory_iterator iterator{root_, ignored}, end;
         !ignored && iterator != end; iterator.increment(ignored)) {
      if (iterator->is_regular_file(ignored) && iterator->path().filename() == "profile.sqlite") {
        databases.push_back(iterator->path());
      }
    }
    for (const auto& database : databases) {
      (void)ProfileStore::delete_local(database);
    }

    ignored.clear();
    std::vector<std::filesystem::path> external_secret_roots;
    for (std::filesystem::recursive_directory_iterator iterator{root_, ignored}, end;
         !ignored && iterator != end; iterator.increment(ignored)) {
      if (iterator->is_regular_file(ignored) && iterator->path().filename() == "store.id") {
        external_secret_roots.push_back(iterator->path().parent_path());
      }
    }
    for (const auto& secret_root : external_secret_roots) {
      SecretBackendOptions options;
      options.create_if_missing = false;
      auto backend = open_default_secret_backend(secret_root, options);
      if (backend) {
        (void)(*backend.value_if())->erase_all();
      }
    }

    ignored.clear();
    std::filesystem::remove_all(root_, ignored);
  }

  [[nodiscard]] std::filesystem::path profile_path() const {
    return root_ / "default" / "profile.sqlite";
  }

  std::filesystem::path root_;
};

TEST(IdentityMaterialTest, CreatesAndValidatesEd25519Identity) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  EXPECT_FALSE(identity.value_if()->device_id().is_zero());

  auto derived = derive_device_id(identity.value_if()->public_key());
  ASSERT_TRUE(derived);
  EXPECT_EQ(*derived.value_if(), identity.value_if()->device_id());

  auto imported = import_identity(identity.value_if()->public_key(),
                                  identity.value_if()->secret_key());
  ASSERT_TRUE(imported) << imported.error_if()->safe_detail();
  EXPECT_EQ(imported.value_if()->device_id(), identity.value_if()->device_id());

  std::array<std::byte, ed25519_secret_key_bytes> tampered{};
  std::copy(identity.value_if()->secret_key().begin(), identity.value_if()->secret_key().end(),
            tampered.begin());
  tampered[0] ^= std::byte{1U};
  auto invalid = import_identity(identity.value_if()->public_key(), tampered);
  ASSERT_FALSE(invalid);
  EXPECT_EQ(invalid.error_if()->code(), ErrorCode::identity);
}

TEST(PasswordVerifierTest, EnforcesPolicyAndVerifiesWithArgon2id) {
  const PasswordHashParameters parameters{};
  auto short_password = create_password_verifier("1234567", parameters);
  ASSERT_FALSE(short_password);
  EXPECT_EQ(short_password.error_if()->safe_detail(), "password_too_short");

  auto minimum_password = create_password_verifier("12345678", parameters);
  ASSERT_TRUE(minimum_password) << minimum_password.error_if()->safe_detail();

  constexpr std::string_view password = "correct horse battery staple";
  auto verifier = create_password_verifier(password, parameters);
  ASSERT_TRUE(verifier) << verifier.error_if()->safe_detail();
  EXPECT_EQ(verifier.value_if()->format_version, 1U);
  EXPECT_TRUE(verifier.value_if()->encoded.starts_with("$argon2id$"));

  auto matches = verify_password(password, *verifier.value_if());
  ASSERT_TRUE(matches);
  EXPECT_TRUE(*matches.value_if());
  auto mismatch = verify_password("wrong password with enough length", *verifier.value_if());
  ASSERT_TRUE(mismatch);
  EXPECT_FALSE(*mismatch.value_if());

  auto needs_upgrade = password_verifier_needs_upgrade(
      *verifier.value_if(), PasswordHashParameters{.operations = 3U,
                                                   .memory_bytes = parameters.memory_bytes});
  ASSERT_TRUE(needs_upgrade);
  EXPECT_TRUE(*needs_upgrade.value_if());
}

TEST_F(M2ProfileTest, MissingProfileDoesNotCreateIdentity) {
  auto profile = ProfileStore::open(profile_path());
  ASSERT_FALSE(profile);
  EXPECT_EQ(profile.error_if()->code(), ErrorCode::not_registered);
  EXPECT_FALSE(std::filesystem::exists(profile_path()));
}

TEST_F(M2ProfileTest, LocalInitializationIsRelayIndependentAndPersistent) {
  auto profile = ProfileStore::create(profile_path());
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();

  auto before = profile.value_if()->local_readiness("com.example.local-node");
  ASSERT_TRUE(before) << before.error_if()->safe_detail();
  EXPECT_TRUE(before.value_if()->identity_ready);
  EXPECT_FALSE(before.value_if()->endpoint_ready);
  EXPECT_FALSE(before.value_if()->password_verifier_ready);
  EXPECT_TRUE(before.value_if()->pairing_policy_ready);
  EXPECT_TRUE(before.value_if()->lan_configuration_ready);
  EXPECT_FALSE(before.value_if()->ready());

  auto verifier = create_password_verifier("correct horse battery staple",
                                           PasswordHashParameters{});
  ASSERT_TRUE(verifier) << verifier.error_if()->safe_detail();
  LanConfiguration lan;
  lan.connectivity_mode = ConnectivityMode::lan_only;
  lan.auto_connect_trusted = true;
  lan.interface_preferences = {"eth0", "wlan0"};
  PairingPolicy policy;
  policy.generation = 7U;
  policy.default_scopes = {"file.exchange", "rpc.device.read"};
  LocalProfileInitialization initialization{
      .application_id = "com.example.local-node",
      .password_verifier = *verifier.value_if(),
      .password_generation = 3U,
      .pairing_policy = policy,
      .lan = lan};
  auto endpoint = profile.value_if()->initialize_local(initialization);
  ASSERT_TRUE(endpoint) << endpoint.error_if()->safe_detail();
  EXPECT_FALSE(endpoint.value_if()->is_zero());

  auto readiness = profile.value_if()->local_readiness(initialization.application_id);
  ASSERT_TRUE(readiness) << readiness.error_if()->safe_detail();
  EXPECT_TRUE(readiness.value_if()->ready());
  auto stored_lan = profile.value_if()->lan_configuration();
  ASSERT_TRUE(stored_lan) << stored_lan.error_if()->safe_detail();
  EXPECT_EQ(stored_lan.value_if()->connectivity_mode, ConnectivityMode::lan_only);
  EXPECT_TRUE(stored_lan.value_if()->auto_connect_trusted);
  EXPECT_EQ(stored_lan.value_if()->interface_preferences, lan.interface_preferences);
  auto stored_policy = profile.value_if()->pairing_policy();
  ASSERT_TRUE(stored_policy) << stored_policy.error_if()->safe_detail();
  EXPECT_EQ(stored_policy.value_if()->generation, 7U);
  EXPECT_EQ(stored_policy.value_if()->default_scopes, policy.default_scopes);

  profile = Result<ProfileStore>::failure(
      Error{ErrorCode::internal, "test", "release_profile"});
  sqlite3* database = nullptr;
  ASSERT_EQ(sqlite3_open(profile_path().string().c_str(), &database), SQLITE_OK);
  ASSERT_EQ(sqlite3_exec(database, "DROP TABLE relay_enrollments", nullptr, nullptr, nullptr),
            SQLITE_OK);
  ASSERT_EQ(sqlite3_close(database), SQLITE_OK);

  auto reopened = ProfileStore::open(profile_path());
  ASSERT_TRUE(reopened) << reopened.error_if()->safe_detail();
  auto relay_free_readiness = reopened.value_if()->local_readiness(initialization.application_id);
  ASSERT_TRUE(relay_free_readiness) << relay_free_readiness.error_if()->safe_detail();
  EXPECT_TRUE(relay_free_readiness.value_if()->ready());
}

TEST_F(M2ProfileTest, RejectsInvalidLanCapacitiesAndDeadlinesBeforePersistence) {
  auto profile = ProfileStore::create(profile_path());
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();

  LanConfiguration invalid_capacity;
  invalid_capacity.pending_signaling_capacity = 0U;
  auto capacity_result = profile.value_if()->set_lan_configuration(invalid_capacity);
  ASSERT_FALSE(capacity_result);
  EXPECT_EQ(capacity_result.error_if()->code(), ErrorCode::configuration);
  EXPECT_EQ(capacity_result.error_if()->safe_detail(), "invalid_lan_configuration");

  LanConfiguration invalid_deadline;
  invalid_deadline.handshake_timeout = std::chrono::milliseconds{0};
  auto deadline_result = profile.value_if()->set_lan_configuration(invalid_deadline);
  ASSERT_FALSE(deadline_result);
  EXPECT_EQ(deadline_result.error_if()->code(), ErrorCode::configuration);

  LanConfiguration invalid_mode;
  invalid_mode.connectivity_mode = ConnectivityMode::lan_only;
  invalid_mode.enabled = false;
  auto mode_result = profile.value_if()->set_lan_configuration(invalid_mode);
  ASSERT_FALSE(mode_result);
  EXPECT_EQ(mode_result.error_if()->code(), ErrorCode::configuration);

  auto stored = profile.value_if()->lan_configuration();
  ASSERT_TRUE(stored) << stored.error_if()->safe_detail();
  EXPECT_EQ(stored.value_if()->pending_signaling_capacity, 128U);
  EXPECT_EQ(stored.value_if()->handshake_timeout, std::chrono::milliseconds{5000});
}

TEST_F(M2ProfileTest, SecretBackendAcceptsMaximumLabelAndRejectsInvalidHandle) {
  auto backend = open_default_secret_backend(root_ / "standalone-secrets");
  ASSERT_TRUE(backend) << backend.error_if()->safe_detail();
  const std::string label(64U, 'a');
  const std::array<std::byte, 4U> secret{
      std::byte{1U}, std::byte{2U}, std::byte{3U}, std::byte{4U}};
  auto handle = (*backend.value_if())->store(label, secret);
  ASSERT_TRUE(handle) << handle.error_if()->safe_detail();
  auto loaded = (*backend.value_if())->load(*handle.value_if());
  ASSERT_TRUE(loaded) << loaded.error_if()->safe_detail();
  EXPECT_TRUE(std::equal(loaded.value_if()->begin(), loaded.value_if()->end(), secret.begin()));

  auto invalid = (*backend.value_if())->load(SecretHandle{"../outside"});
  ASSERT_FALSE(invalid);
  EXPECT_EQ(invalid.error_if()->code(), ErrorCode::secret_unavailable);
  EXPECT_EQ(invalid.error_if()->safe_detail(), "invalid_secret_handle");
  EXPECT_TRUE((*backend.value_if())->erase(*handle.value_if()));
}

TEST_F(M2ProfileTest, CanForceEncryptedFileFallback) {
  const auto secret_root = root_ / "forced-file-secrets";
  auto backend = open_default_secret_backend(secret_root, encrypted_file_secret_options());
  ASSERT_TRUE(backend) << backend.error_if()->safe_detail();
  EXPECT_EQ((*backend.value_if())->security(),
            SecretBackendSecurity::encrypted_file_fallback);
  EXPECT_TRUE(std::filesystem::exists(secret_root / "master.key"));
  EXPECT_FALSE(std::filesystem::exists(secret_root / "store.id"));
  ASSERT_TRUE((*backend.value_if())->erase_all());
  EXPECT_FALSE(std::filesystem::exists(secret_root));
}

TEST_F(M2ProfileTest, ExistingEncryptedFileBackendIsNeverSilentlySwitched) {
  const auto secret_root = root_ / "existing-file-secrets";
  auto created = open_default_secret_backend(secret_root, encrypted_file_secret_options());
  ASSERT_TRUE(created) << created.error_if()->safe_detail();

  SecretBackendOptions reopen_options;
  reopen_options.create_if_missing = false;
  auto reopened = open_default_secret_backend(secret_root, reopen_options);
  ASSERT_TRUE(reopened) << reopened.error_if()->safe_detail();
  EXPECT_EQ((*reopened.value_if())->security(),
            SecretBackendSecurity::encrypted_file_fallback);

  reopen_options.allow_encrypted_file_fallback = false;
  auto forbidden = open_default_secret_backend(secret_root, reopen_options);
  ASSERT_FALSE(forbidden);
  EXPECT_EQ(forbidden.error_if()->code(), ErrorCode::secret_backend_degraded);
  ASSERT_TRUE((*created.value_if())->erase_all());
}

TEST_F(M2ProfileTest, RejectsConfigurationWithoutAnAllowedSecretBackend) {
  SecretBackendOptions options;
  options.prefer_os_backend = false;
  options.allow_encrypted_file_fallback = false;
  auto backend = open_default_secret_backend(root_ / "forbidden-secrets", options);
  ASSERT_FALSE(backend);
  EXPECT_EQ(backend.error_if()->code(), ErrorCode::secret_backend_degraded);
  EXPECT_EQ(backend.error_if()->safe_detail(), "encrypted_file_fallback_forbidden");
}

#ifdef __linux__
TEST_F(M2ProfileTest, UsesSecretServiceWhenAvailable) {
  const auto secret_root = root_ / "secret-service";
  SecretBackendOptions options;
  options.allow_encrypted_file_fallback = false;
  auto backend = open_default_secret_backend(secret_root, options);
  if (!backend && backend.error_if()->code() == ErrorCode::secret_backend_degraded) {
    GTEST_SKIP() << "Secret Service is unavailable";
  }
  ASSERT_TRUE(backend) << backend.error_if()->safe_detail();
  ASSERT_EQ((*backend.value_if())->security(), SecretBackendSecurity::os_protected);
  const std::array<std::byte, 4U> secret{
      std::byte{1U}, std::byte{2U}, std::byte{3U}, std::byte{4U}};
  auto handle = (*backend.value_if())->store("integration", secret);
  ASSERT_TRUE(handle) << handle.error_if()->safe_detail();
  options.prefer_os_backend = false;
  options.allow_encrypted_file_fallback = true;
  options.create_if_missing = false;
  auto reopened = open_default_secret_backend(secret_root, options);
  ASSERT_TRUE(reopened) << reopened.error_if()->safe_detail();
  ASSERT_EQ((*reopened.value_if())->security(), SecretBackendSecurity::os_protected);
  auto loaded = (*reopened.value_if())->load(*handle.value_if());
  ASSERT_TRUE(loaded) << loaded.error_if()->safe_detail();
  EXPECT_TRUE(std::equal(loaded.value_if()->begin(), loaded.value_if()->end(), secret.begin()));
  ASSERT_TRUE((*reopened.value_if())->erase_all());
  auto missing = (*reopened.value_if())->load(*handle.value_if());
  ASSERT_FALSE(missing);
  EXPECT_EQ(missing.error_if()->code(), ErrorCode::secret_unavailable);
}
#endif

TEST_F(M2ProfileTest, PersistsIdentityAndDistinctApplicationEndpoints) {
  auto created = ProfileStore::create(profile_path());
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  const DeviceId device_id = created.value_if()->device_id();
#ifdef _WIN32
  EXPECT_EQ(created.value_if()->secret_backend_security(), SecretBackendSecurity::os_protected);
#else
  const auto secret_root = profile_path().parent_path() / "profile.sqlite.secrets";
  const auto expected_secret_security = std::filesystem::exists(secret_root / "store.id")
                                            ? SecretBackendSecurity::os_protected
                                            : SecretBackendSecurity::encrypted_file_fallback;
  EXPECT_EQ(created.value_if()->secret_backend_security(), expected_secret_security);
#endif

  auto endpoint_a = created.value_if()->endpoint_for("com.example.alpha");
  auto endpoint_a_again = created.value_if()->endpoint_for("com.example.alpha");
  auto endpoint_b = created.value_if()->endpoint_for("com.example.beta");
  ASSERT_TRUE(endpoint_a);
  ASSERT_TRUE(endpoint_a_again);
  ASSERT_TRUE(endpoint_b);
  EXPECT_EQ(*endpoint_a.value_if(), *endpoint_a_again.value_if());
  EXPECT_NE(*endpoint_a.value_if(), *endpoint_b.value_if());

  created = Result<ProfileStore>::failure(
      Error{ErrorCode::internal, "test", "release_profile"});
  auto reopened = ProfileStore::open(profile_path());
  ASSERT_TRUE(reopened) << reopened.error_if()->safe_detail();
  EXPECT_EQ(reopened.value_if()->device_id(), device_id);
  auto endpoint_after_restart = reopened.value_if()->endpoint_for("com.example.alpha");
  ASSERT_TRUE(endpoint_after_restart);
  EXPECT_EQ(*endpoint_after_restart.value_if(), *endpoint_a.value_if());
}

TEST_F(M2ProfileTest, PersistsPasswordAndAppliesTrustGrantFinalDecision) {
  auto profile = ProfileStore::create(profile_path());
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  auto verifier = create_password_verifier("correct horse battery staple", {});
  ASSERT_TRUE(verifier);
  ASSERT_TRUE(profile.value_if()->set_password_verifier(*verifier.value_if(), 3U));

  auto stored = profile.value_if()->password_verifier();
  ASSERT_TRUE(stored);
  ASSERT_TRUE(stored.value_if()->has_value());
  auto matches = verify_password("correct horse battery staple", **stored.value_if());
  ASSERT_TRUE(matches);
  EXPECT_TRUE(*matches.value_if());
  auto generation = profile.value_if()->password_generation();
  ASSERT_TRUE(generation);
  EXPECT_EQ(*generation.value_if(), 3U);

  auto peer_identity = create_identity();
  ASSERT_TRUE(peer_identity);
  GrantId::Storage grant_bytes{};
  grant_bytes[0] = std::byte{1U};
  const GrantId grant_id{grant_bytes};
  const std::uint64_t now = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
  TrustGrantRecord grant{
      .grant_id = grant_id,
      .direction = TrustGrantDirection::issued,
      .issuer = profile.value_if()->device_id(),
      .subject = peer_identity.value_if()->device_id(),
      .scopes = {"rpc.device.read", "message.send"},
      .password_generation = 3U,
      .issued_unix_milliseconds = now,
      .expires_unix_milliseconds = now + 60'000U,
      .signature = std::vector<std::byte>(64U, std::byte{0x5aU})};
  ASSERT_TRUE(profile.value_if()->put_trust_grant(grant));

  auto authorized = profile.value_if()->is_scope_authorized(
      peer_identity.value_if()->device_id(), "rpc.device.read", now);
  ASSERT_TRUE(authorized);
  EXPECT_TRUE(*authorized.value_if());
  auto missing_scope = profile.value_if()->is_scope_authorized(
      peer_identity.value_if()->device_id(), "rpc.device.configure", now);
  ASSERT_TRUE(missing_scope);
  EXPECT_FALSE(*missing_scope.value_if());
  auto expired = profile.value_if()->is_scope_authorized(
      peer_identity.value_if()->device_id(), "rpc.device.read", now + 60'001U);
  ASSERT_TRUE(expired);
  EXPECT_FALSE(*expired.value_if());

  ASSERT_TRUE(profile.value_if()->revoke_trust_grant(grant_id, now + 1U));
  auto revoked = profile.value_if()->is_scope_authorized(
      peer_identity.value_if()->device_id(), "rpc.device.read", now + 2U);
  ASSERT_TRUE(revoked);
  EXPECT_FALSE(*revoked.value_if());
}

#ifndef _WIN32
TEST_F(M2ProfileTest, RejectsProfileWithPermissionsThatAreTooWide) {
  {
    auto profile = ProfileStore::create(profile_path());
    ASSERT_TRUE(profile);
  }
  ASSERT_EQ(::chmod(profile_path().c_str(), S_IRUSR | S_IWUSR | S_IRGRP), 0);
  auto reopened = ProfileStore::open(profile_path());
  ASSERT_FALSE(reopened);
  EXPECT_EQ(reopened.error_if()->code(), ErrorCode::profile_permissions);
}
#endif

TEST_F(M2ProfileTest, ExportAndLocalDeleteAreDistinctFromRelayRevocation) {
  const auto exported_path = root_ / "export" / "profile.sqlite";
  DeviceId original_device_id;
  const auto options = encrypted_file_profile_options();
  {
    auto profile = ProfileStore::create(profile_path(), options);
    ASSERT_TRUE(profile);
    ASSERT_EQ(profile.value_if()->secret_backend_security(),
              SecretBackendSecurity::encrypted_file_fallback);
    original_device_id = profile.value_if()->device_id();
    ASSERT_TRUE(profile.value_if()->mark_relay_revoked("wss://relay.example.invalid", 4U));
    ASSERT_TRUE(profile.value_if()->export_to(exported_path));
  }
  EXPECT_TRUE(std::filesystem::exists(exported_path));
  auto exported = ProfileStore::open(exported_path);
  ASSERT_TRUE(exported) << exported.error_if()->safe_detail();
  EXPECT_EQ(exported.value_if()->device_id(), original_device_id);
  EXPECT_EQ(exported.value_if()->secret_backend_security(),
            SecretBackendSecurity::encrypted_file_fallback);
  ASSERT_TRUE(ProfileStore::delete_local(profile_path()));
  EXPECT_FALSE(std::filesystem::exists(profile_path()));
  EXPECT_TRUE(std::filesystem::exists(exported_path));
}

#ifdef __linux__
TEST_F(M2ProfileTest, SecretServiceProfileExportsAndDeletesWithoutOrphans) {
  const auto exported_path = root_ / "os-export" / "profile.sqlite";
  ProfileOpenOptions options;
  options.secret_backend.allow_encrypted_file_fallback = false;
  auto profile = ProfileStore::create(profile_path(), options);
  if (!profile && profile.error_if()->code() == ErrorCode::secret_backend_degraded) {
    GTEST_SKIP() << "Secret Service is unavailable";
  }
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  ASSERT_EQ(profile.value_if()->secret_backend_security(), SecretBackendSecurity::os_protected);
  const auto original_device_id = profile.value_if()->device_id();
  ASSERT_TRUE(profile.value_if()->export_to(exported_path));
  profile = Result<ProfileStore>::failure(
      Error{ErrorCode::internal, "test", "release_profile"});

  auto exported = ProfileStore::open(exported_path);
  ASSERT_TRUE(exported) << exported.error_if()->safe_detail();
  EXPECT_EQ(exported.value_if()->device_id(), original_device_id);
  EXPECT_EQ(exported.value_if()->secret_backend_security(), SecretBackendSecurity::os_protected);
  exported = Result<ProfileStore>::failure(
      Error{ErrorCode::internal, "test", "release_profile"});

  ASSERT_TRUE(ProfileStore::delete_local(profile_path()));
  ASSERT_TRUE(ProfileStore::delete_local(exported_path));
  EXPECT_FALSE(std::filesystem::exists(profile_path()));
  EXPECT_FALSE(std::filesystem::exists(exported_path));
}
#endif

TEST_F(M2ProfileTest, RejectsSchemaThatIsNewerThanTheLibrary) {
  {
    auto profile = ProfileStore::create(profile_path());
    ASSERT_TRUE(profile);
  }
  sqlite3* database = nullptr;
  ASSERT_EQ(sqlite3_open(profile_path().string().c_str(), &database), SQLITE_OK);
  const std::string newer_schema =
      "PRAGMA user_version=" + std::to_string(profile_schema_version + 1U);
  ASSERT_EQ(sqlite3_exec(database, newer_schema.c_str(), nullptr, nullptr, nullptr), SQLITE_OK);
  ASSERT_EQ(sqlite3_close(database), SQLITE_OK);

  auto reopened = ProfileStore::open(profile_path());
  ASSERT_FALSE(reopened);
  EXPECT_EQ(reopened.error_if()->code(), ErrorCode::schema_too_new);
}

TEST_F(M2ProfileTest, MigratesV1FixtureWithRecoverableBackup) {
  DeviceId expected_device_id;
  ASSERT_TRUE(create_v1_profile_fixture(profile_path(), false, expected_device_id));
  const auto backup_path = ProfileStore::migration_backup_path(profile_path(), 1U);

  auto migrated = ProfileStore::open(profile_path());
  ASSERT_TRUE(migrated) << migrated.error_if()->safe_detail();
  EXPECT_EQ(migrated.value_if()->device_id(), expected_device_id);
  EXPECT_EQ(read_user_version(profile_path()), static_cast<int>(profile_schema_version));
  EXPECT_TRUE(sqlite_object_exists(profile_path(), "index",
                                   "trust_grants_authorization_index"));
  EXPECT_TRUE(sqlite_object_exists(profile_path(), "table", "lan_configuration"));
  EXPECT_TRUE(sqlite_object_exists(profile_path(), "table", "pairing_policy"));
  ASSERT_TRUE(std::filesystem::exists(backup_path));
  EXPECT_EQ(read_user_version(backup_path), 1);
#ifndef _WIN32
  struct stat backup_status {};
  ASSERT_EQ(::stat(backup_path.c_str(), &backup_status), 0);
  EXPECT_EQ(backup_status.st_mode & (S_IRWXG | S_IRWXO), 0U);
#endif

  migrated = Result<ProfileStore>::failure(
      Error{ErrorCode::internal, "test", "release_profile"});
  auto restored = ProfileStore::restore_from_backup(profile_path(), backup_path);
  ASSERT_TRUE(restored) << restored.error_if()->safe_detail();
  EXPECT_EQ(read_user_version(profile_path()), 1);
  EXPECT_FALSE(sqlite_object_exists(profile_path(), "index",
                                    "trust_grants_authorization_index"));

  auto reopened = ProfileStore::open(profile_path());
  ASSERT_TRUE(reopened) << reopened.error_if()->safe_detail();
  EXPECT_EQ(reopened.value_if()->device_id(), expected_device_id);
  EXPECT_EQ(read_user_version(profile_path()), static_cast<int>(profile_schema_version));
}

TEST_F(M2ProfileTest, RollsBackFailedV1MigrationAndPreservesBackup) {
  DeviceId expected_device_id;
  ASSERT_TRUE(create_v1_profile_fixture(profile_path(), true, expected_device_id));
  const auto backup_path = ProfileStore::migration_backup_path(profile_path(), 1U);

  auto migrated = ProfileStore::open(profile_path());
  ASSERT_FALSE(migrated);
  EXPECT_EQ(migrated.error_if()->code(), ErrorCode::storage);
  EXPECT_EQ(read_user_version(profile_path()), 1);
  EXPECT_FALSE(sqlite_object_exists(profile_path(), "index",
                                    "trust_grants_authorization_index"));
  EXPECT_TRUE(std::filesystem::exists(backup_path));
  EXPECT_EQ(read_user_version(backup_path), 1);
}

TEST_F(M2ProfileTest, ReportsUnavailablePrivateKeyWithoutReplacingIdentity) {
  DeviceId original_device_id;
  {
    auto profile = ProfileStore::create(profile_path(), encrypted_file_profile_options());
    ASSERT_TRUE(profile);
    original_device_id = profile.value_if()->device_id();
  }
  std::error_code error;
  std::filesystem::remove_all(
      profile_path().parent_path() / "profile.sqlite.secrets", error);
  ASSERT_FALSE(error);

  auto reopened = ProfileStore::open(profile_path());
  ASSERT_FALSE(reopened);
  EXPECT_EQ(reopened.error_if()->code(), ErrorCode::secret_unavailable);

  sqlite3* database = nullptr;
  ASSERT_EQ(sqlite3_open_v2(profile_path().string().c_str(), &database, SQLITE_OPEN_READONLY,
                            nullptr),
            SQLITE_OK);
  sqlite3_stmt* statement = nullptr;
  ASSERT_EQ(sqlite3_prepare_v2(database, "SELECT device_id FROM identity WHERE singleton=1", -1,
                               &statement, nullptr),
            SQLITE_OK);
  ASSERT_EQ(sqlite3_step(statement), SQLITE_ROW);
  DeviceId::Storage stored_bytes{};
  const auto* bytes = static_cast<const std::byte*>(sqlite3_column_blob(statement, 0));
  ASSERT_NE(bytes, nullptr);
  std::copy_n(bytes, stored_bytes.size(), stored_bytes.begin());
  EXPECT_EQ(DeviceId{stored_bytes}, original_device_id);
  sqlite3_finalize(statement);
  sqlite3_close(database);
}

TEST_F(M2ProfileTest, ReportsCorruptDatabase) {
  {
    auto profile = ProfileStore::create(profile_path());
    ASSERT_TRUE(profile);
  }
  {
    std::ofstream output(profile_path(), std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(output);
    output << "not a sqlite database";
  }
  auto reopened = ProfileStore::open(profile_path());
  ASSERT_FALSE(reopened);
  EXPECT_EQ(reopened.error_if()->code(), ErrorCode::profile_corrupt);
}

#ifndef _WIN32
TEST_F(M2ProfileTest, DiskFullRollsBackTransactionAndPreservesExistingProfile) {
  DeviceId original_device_id;
  EndpointId original_endpoint;
  {
    auto profile = ProfileStore::create(profile_path());
    ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
    original_device_id = profile.value_if()->device_id();
    auto endpoint = profile.value_if()->endpoint_for("com.example.disk-full");
    ASSERT_TRUE(endpoint);
    original_endpoint = *endpoint.value_if();
  }
  auto profile = ProfileStore::open(profile_path());
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  GrantId::Storage grant_bytes{};
  grant_bytes[0] = std::byte{0x44U};
  DeviceId::Storage subject_bytes{};
  subject_bytes[0] = std::byte{0x55U};
  TrustGrantRecord grant{
      .grant_id = GrantId{grant_bytes},
      .direction = TrustGrantDirection::issued,
      .issuer = profile.value_if()->device_id(),
      .subject = DeviceId{subject_bytes},
      .scopes = {},
      .password_generation = 1U,
      .issued_unix_milliseconds = 1000U,
      .expires_unix_milliseconds = std::nullopt,
      .signature = std::vector<std::byte>(4096U, std::byte{0x5aU}),
      .revoked = false};
  grant.scopes.reserve(256U);
  for (std::size_t index = 0U; index < 256U; ++index) {
    grant.scopes.push_back("scope." + std::to_string(index) + "." + std::string(220U, 'x'));
  }

  struct rlimit original_limit {};
  if (::getrlimit(RLIMIT_FSIZE, &original_limit) != 0) {
    GTEST_SKIP() << "RLIMIT_FSIZE unavailable";
  }
  struct sigaction original_signal {};
  struct sigaction ignore_signal {};
  ignore_signal.sa_handler = SIG_IGN;
  sigemptyset(&ignore_signal.sa_mask);
  if (::sigaction(SIGXFSZ, &ignore_signal, &original_signal) != 0) {
    GTEST_SKIP() << "SIGXFSZ control unavailable";
  }
  std::error_code wal_error;
  const auto wal_path = profile_path().string() + "-wal";
  const auto wal_size = std::filesystem::exists(wal_path, wal_error)
                            ? std::filesystem::file_size(wal_path, wal_error)
                            : 0U;
  if (wal_error) {
    (void)::sigaction(SIGXFSZ, &original_signal, nullptr);
    GTEST_SKIP() << "Cannot inspect SQLite WAL size";
  }
  struct rlimit limited = original_limit;
  const auto failure_limit = static_cast<rlim_t>(wal_size + 32U * 1024U);
  limited.rlim_cur = std::min<rlim_t>(original_limit.rlim_max, failure_limit);
  if (::setrlimit(RLIMIT_FSIZE, &limited) != 0) {
    (void)::sigaction(SIGXFSZ, &original_signal, nullptr);
    GTEST_SKIP() << "RLIMIT_FSIZE cannot be lowered";
  }
  const auto written = profile.value_if()->put_trust_grant(grant);
  const int limit_restored = ::setrlimit(RLIMIT_FSIZE, &original_limit);
  const int signal_restored = ::sigaction(SIGXFSZ, &original_signal, nullptr);
  ASSERT_EQ(limit_restored, 0);
  ASSERT_EQ(signal_restored, 0);
  ASSERT_FALSE(written);
  EXPECT_EQ(written.error_if()->code(), ErrorCode::storage);
  EXPECT_EQ(written.error_if()->safe_detail(), "sqlite_statement_failed");

  profile = Result<ProfileStore>::failure(
      Error{ErrorCode::internal, "test", "release_profile"});
  auto reopened = ProfileStore::open(profile_path());
  ASSERT_TRUE(reopened) << reopened.error_if()->safe_detail();
  EXPECT_EQ(reopened.value_if()->device_id(), original_device_id);
  auto endpoint = reopened.value_if()->endpoint_for("com.example.disk-full");
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(*endpoint.value_if(), original_endpoint);
  auto stored_grant = reopened.value_if()->trust_grant(GrantId{grant_bytes});
  ASSERT_TRUE(stored_grant);
  EXPECT_FALSE(stored_grant.value_if()->has_value());
}
#endif

TEST_F(M2ProfileTest, ReportsProfileLockTimeout) {
  {
    auto profile = ProfileStore::create(profile_path());
    ASSERT_TRUE(profile);
  }
  const auto lock_path = profile_path().parent_path() / "profile.sqlite.lock";
#ifdef _WIN32
  HANDLE lock_file = CreateFileW(lock_path.wstring().c_str(), GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                                 FILE_ATTRIBUTE_HIDDEN, nullptr);
  ASSERT_NE(lock_file, INVALID_HANDLE_VALUE);
  OVERLAPPED overlapped{};
  ASSERT_NE(LockFileEx(lock_file, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0,
                       MAXDWORD, MAXDWORD, &overlapped),
            0);
#else
  const int lock_file = ::open(lock_path.c_str(), O_RDWR | O_CLOEXEC);
  ASSERT_GE(lock_file, 0);
  ASSERT_EQ(::flock(lock_file, LOCK_EX | LOCK_NB), 0);
#endif

  ProfileOpenOptions options;
  options.lock_timeout = std::chrono::milliseconds{20};
  auto reopened = ProfileStore::open(profile_path(), options);
  ASSERT_FALSE(reopened);
  EXPECT_EQ(reopened.error_if()->code(), ErrorCode::profile_locked);

#ifdef _WIN32
  UnlockFileEx(lock_file, 0, MAXDWORD, MAXDWORD, &overlapped);
  CloseHandle(lock_file);
#else
  ASSERT_EQ(::flock(lock_file, LOCK_UN), 0);
  ASSERT_EQ(::close(lock_file), 0);
#endif
}

TEST_F(M2ProfileTest, ConcurrentProfileOpensPreserveOneIdentity) {
  const auto options = encrypted_file_profile_options();
  DeviceId expected_device_id;
  {
    auto profile = ProfileStore::create(profile_path(), options);
    ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
    expected_device_id = profile.value_if()->device_id();
  }

  executor::Executor task_executor;
  executor::ExecutorConfig executor_config;
  executor_config.min_threads = 4U;
  executor_config.max_threads = 4U;
  executor_config.queue_capacity = 8U;
  ASSERT_TRUE(task_executor.initialize_ex(executor_config));

  executor::comm::ChannelOptions channel_options;
  channel_options.capacity = 4U;
  channel_options.name = "profile-open-started";
  executor::comm::MpscChannel<std::size_t> started(channel_options);
  executor::comm::PhaseGate release("profile-open-release");
  std::vector<std::future<Result<ProfileStore>>> futures;
  futures.reserve(4U);
  for (std::size_t index = 0U; index < 4U; ++index) {
    futures.push_back(task_executor.submit_auto([&, index, options] {
      if (!started.send_for(index, std::chrono::seconds{2})) {
        return Result<ProfileStore>::failure(
            Error{ErrorCode::timeout, "test", "profile_open_start_timeout"});
      }
      if (!release.wait_for(1U, std::chrono::seconds{2})) {
        return Result<ProfileStore>::failure(
            Error{ErrorCode::timeout, "test", "profile_open_release_timeout"});
      }
      return ProfileStore::open(profile_path(), options);
    }));
  }

  bool all_started = true;
  for (std::size_t index = 0U; index < 4U; ++index) {
    std::size_t started_index = 0U;
    all_started = static_cast<bool>(
                      started.receive_for(started_index, std::chrono::seconds{2})) &&
                  all_started;
  }
  EXPECT_TRUE(all_started);
  EXPECT_TRUE(release.advance_to(1U));

  std::vector<Result<ProfileStore>> opened_profiles;
  opened_profiles.reserve(futures.size());
  for (auto& future : futures) {
    opened_profiles.push_back(future.get());
  }
  (void)task_executor.shutdown(true);

  for (const auto& profile : opened_profiles) {
    ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
    EXPECT_EQ(profile.value_if()->device_id(), expected_device_id);
    EXPECT_EQ(profile.value_if()->secret_backend_security(),
              SecretBackendSecurity::encrypted_file_fallback);
  }
}

}  // namespace
}  // namespace heyaki
