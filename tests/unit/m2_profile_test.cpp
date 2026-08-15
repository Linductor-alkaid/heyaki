#include <heyaki/identity.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <gtest/gtest.h>
#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <windows.h>
#endif

namespace heyaki {
namespace {

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
      database_path.parent_path() / (database_path.filename().string() + ".secrets"));
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
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
    std::filesystem::create_directories(root_);
  }

  void TearDown() override {
    std::error_code ignored;
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
  auto short_password = create_password_verifier("short", parameters);
  ASSERT_FALSE(short_password);
  EXPECT_EQ(short_password.error_if()->safe_detail(), "password_too_short");

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

TEST_F(M2ProfileTest, PersistsIdentityAndDistinctApplicationEndpoints) {
  auto created = ProfileStore::create(profile_path());
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  const DeviceId device_id = created.value_if()->device_id();
#ifdef _WIN32
  constexpr auto expected_secret_security = SecretBackendSecurity::os_protected;
#else
  constexpr auto expected_secret_security = SecretBackendSecurity::encrypted_file_fallback;
#endif
  EXPECT_EQ(created.value_if()->secret_backend_security(), expected_secret_security);

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
  {
    auto profile = ProfileStore::create(profile_path());
    ASSERT_TRUE(profile);
    original_device_id = profile.value_if()->device_id();
    ASSERT_TRUE(profile.value_if()->mark_relay_revoked("wss://relay.example.invalid", 4U));
    ASSERT_TRUE(profile.value_if()->export_to(exported_path));
  }
  EXPECT_TRUE(std::filesystem::exists(exported_path));
  auto exported = ProfileStore::open(exported_path);
  ASSERT_TRUE(exported) << exported.error_if()->safe_detail();
  EXPECT_EQ(exported.value_if()->device_id(), original_device_id);
  ASSERT_TRUE(ProfileStore::delete_local(profile_path()));
  EXPECT_FALSE(std::filesystem::exists(profile_path()));
  EXPECT_TRUE(std::filesystem::exists(exported_path));
}

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
    auto profile = ProfileStore::create(profile_path());
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

}  // namespace
}  // namespace heyaki
