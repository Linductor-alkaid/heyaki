#include <heyaki/profile_store.hpp>

#include <sqlite3.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

int fail(std::string_view detail) {
  std::cerr << detail << '\n';
  return 1;
}

bool execute(sqlite3* database, const char* sql) {
  char* message = nullptr;
  const int result = sqlite3_exec(database, sql, nullptr, nullptr, &message);
  if (result != SQLITE_OK) {
    if (message != nullptr) {
      std::cerr << message << '\n';
      sqlite3_free(message);
    }
    return false;
  }
  return true;
}

int query_int(sqlite3* database, const char* sql, int fallback = -1) {
  sqlite3_stmt* statement = nullptr;
  if (sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) != SQLITE_OK) {
    return fallback;
  }
  int value = fallback;
  if (sqlite3_step(statement) == SQLITE_ROW) {
    value = sqlite3_column_int(statement, 0);
  }
  sqlite3_finalize(statement);
  return value;
}

bool quick_check(sqlite3* database) {
  sqlite3_stmt* statement = nullptr;
  if (sqlite3_prepare_v2(database, "PRAGMA quick_check(1)", -1, &statement, nullptr) !=
      SQLITE_OK) {
    return false;
  }
  bool valid = false;
  if (sqlite3_step(statement) == SQLITE_ROW) {
    const auto* result = reinterpret_cast<const char*>(sqlite3_column_text(statement, 0));
    valid = result != nullptr && std::string_view{result} == "ok";
  }
  sqlite3_finalize(statement);
  return valid;
}

heyaki::GrantId crash_grant_id() {
  heyaki::GrantId::Storage bytes{};
  bytes[0] = std::byte{0x2aU};
  return heyaki::GrantId{bytes};
}

heyaki::DeviceId crash_subject_id() {
  heyaki::DeviceId::Storage bytes{};
  bytes[0] = std::byte{0x07U};
  return heyaki::DeviceId{bytes};
}

heyaki::TrustGrantRecord crash_grant(const heyaki::DeviceId& issuer) {
  return heyaki::TrustGrantRecord{
      .grant_id = crash_grant_id(),
      .direction = heyaki::TrustGrantDirection::issued,
      .issuer = issuer,
      .subject = crash_subject_id(),
      .scopes = {"rpc.device.read", "message.send", "rpc.device.configure"},
      .password_generation = 1U,
      .issued_unix_milliseconds = 1000U,
      .expires_unix_milliseconds = 60000U,
      .signature = std::vector<std::byte>(64U, std::byte{0x5aU}),
      .revoked = false};
}

heyaki::ProfileOpenOptions profile_options() {
  heyaki::ProfileOpenOptions options;
  options.secret_backend.prefer_os_backend = false;
  return options;
}

int create_profile(const std::filesystem::path& path) {
  auto profile = heyaki::ProfileStore::create(path, profile_options());
  if (!profile) {
    std::cerr << profile.error_if()->safe_detail() << '\n';
    return 1;
  }
  return 0;
}

int prepare_migration(const std::filesystem::path& path) {
  if (create_profile(path) != 0) {
    return 1;
  }
  sqlite3* database = nullptr;
  if (sqlite3_open_v2(path.string().c_str(), &database, SQLITE_OPEN_READWRITE, nullptr) !=
      SQLITE_OK) {
    if (database != nullptr) {
      sqlite3_close(database);
    }
    return fail("migration_prepare_open_failed");
  }
  const bool prepared = execute(
      database,
      "BEGIN IMMEDIATE;"
      "DROP TABLE pairing_policy_scopes;"
      "DROP TABLE pairing_policy;"
      "DROP TABLE lan_interface_preferences;"
      "DROP TABLE lan_configuration;"
      "DELETE FROM schema_migrations WHERE version=3;"
      "PRAGMA user_version=2;"
      "COMMIT;"
      "PRAGMA wal_checkpoint(TRUNCATE);");
  const int closed = sqlite3_close(database);
  return prepared && closed == SQLITE_OK ? 0 : fail("migration_prepare_failed");
}

int migrate_profile(const std::filesystem::path& path) {
  auto profile = heyaki::ProfileStore::open(path, profile_options());
  if (!profile) {
    std::cerr << profile.error_if()->safe_detail() << '\n';
    return 1;
  }
  return 0;
}

int verify_migration(const std::filesystem::path& path) {
  sqlite3* database = nullptr;
  if (sqlite3_open_v2(path.string().c_str(), &database, SQLITE_OPEN_READWRITE, nullptr) !=
      SQLITE_OK) {
    if (database != nullptr) {
      sqlite3_close(database);
    }
    return fail("migration_verify_open_failed");
  }
  const int version = query_int(database, "PRAGMA user_version");
  const bool integrity = quick_check(database);
  const int migration_v2 =
      query_int(database, "SELECT COUNT(*) FROM schema_migrations WHERE version=2");
  const int migration_v3 =
      query_int(database, "SELECT COUNT(*) FROM schema_migrations WHERE version=3");
  const int authorization_index = query_int(
      database,
      "SELECT COUNT(*) FROM sqlite_schema WHERE type='index' "
      "AND name='trust_grants_authorization_index'");
  const int lan_configuration = query_int(
      database,
      "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='lan_configuration'");
  const int closed = sqlite3_close(database);
  const bool old_state = version == 2 && migration_v2 == 1 && migration_v3 == 0 &&
                         authorization_index == 1 && lan_configuration == 0;
  const bool new_state = version == 3 && migration_v2 == 1 && migration_v3 == 1 &&
                         authorization_index == 1 && lan_configuration == 1;
  if (!integrity || closed != SQLITE_OK || (!old_state && !new_state)) {
    return fail("migration_partial_state_detected");
  }
  return migrate_profile(path);
}

int write_grant(const std::filesystem::path& path) {
  auto profile = heyaki::ProfileStore::open(path, profile_options());
  if (!profile) {
    std::cerr << profile.error_if()->safe_detail() << '\n';
    return 1;
  }
  const auto written = profile.value_if()->put_trust_grant(
      crash_grant(profile.value_if()->device_id()));
  if (!written) {
    std::cerr << written.error_if()->safe_detail() << '\n';
    return 1;
  }
  return 0;
}

int verify_grant(const std::filesystem::path& path) {
  auto profile = heyaki::ProfileStore::open(path, profile_options());
  if (!profile) {
    std::cerr << profile.error_if()->safe_detail() << '\n';
    return 1;
  }
  auto grant = profile.value_if()->trust_grant(crash_grant_id());
  if (!grant) {
    std::cerr << grant.error_if()->safe_detail() << '\n';
    return 1;
  }
  if (!grant.value_if()->has_value()) {
    return 0;
  }
  const std::vector<std::string> expected_scopes{
      "message.send", "rpc.device.configure", "rpc.device.read"};
  const auto& stored = **grant.value_if();
  if (stored.issuer != profile.value_if()->device_id() ||
      stored.subject != crash_subject_id() || stored.scopes != expected_scopes ||
      stored.signature.size() != 64U) {
    return fail("trust_grant_partial_state_detected");
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    return fail("usage: profile_crash_probe <mode> <profile-path>");
  }
  const std::string_view mode{argv[1]};
  const std::filesystem::path path{argv[2]};
  if (mode == "create") {
    return create_profile(path);
  }
  if (mode == "verify-create") {
    if (!std::filesystem::exists(path)) {
      return 0;
    }
    return migrate_profile(path);
  }
  if (mode == "prepare-migration") {
    return prepare_migration(path);
  }
  if (mode == "migrate") {
    return migrate_profile(path);
  }
  if (mode == "verify-migration") {
    return verify_migration(path);
  }
  if (mode == "prepare-grant") {
    return create_profile(path);
  }
  if (mode == "grant") {
    return write_grant(path);
  }
  if (mode == "verify-grant") {
    return verify_grant(path);
  }
  return fail("unknown_probe_mode");
}
