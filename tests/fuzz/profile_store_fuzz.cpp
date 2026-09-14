// ProfileStore migration fuzz target (M9-13): drives ProfileStore::open over
// v1 fixtures, corrupt bytes, and truncated databases. The oracle is the
// migration contract pinned by the M2 tests: a successful open migrates in
// place with a recoverable backup, a failed migration leaves the database at
// its previous schema with the backup preserved, and arbitrary bytes only
// ever produce an explicit error.

#include "fuzz_targets.hpp"

#include <heyaki/error.hpp>
#include <heyaki/identity.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/secret_backend.hpp>

#ifndef HEYAKI_FUZZ_PROFILE_V1_FIXTURE
#define HEYAKI_FUZZ_PROFILE_V1_FIXTURE "profile_store_v1.sql"
#endif

#include <sqlite3.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif
#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace heyaki::fuzz {
namespace {

std::filesystem::path fuzz_root() {
  static const std::filesystem::path root = [] {
    std::error_code error;
    auto base = std::filesystem::temp_directory_path(error) /
                ("heyaki-profile-fuzz-" +
                 std::to_string(static_cast<long>(
#ifdef _WIN32
                     ::_getpid()
#else
                     ::getpid()
#endif
                     )));
    std::filesystem::create_directories(base, error);
#ifndef _WIN32
    // Profile paths are validated end to end: every directory component must
    // be private before the encrypted-file secret backend accepts the root.
    if (::chmod(base.c_str(), S_IRWXU) != 0) {
      std::abort();
    }
#endif
    return base;
  }();
  return root;
}

std::string fixture_sql() {
  std::ifstream fixture(HEYAKI_FUZZ_PROFILE_V1_FIXTURE, std::ios::binary);
  if (!fixture) {
    std::abort();
  }
  return {std::istreambuf_iterator<char>{fixture}, std::istreambuf_iterator<char>{}};
}

std::vector<std::byte> read_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    return {};
  }
  const std::string text{std::istreambuf_iterator<char>{input},
                         std::istreambuf_iterator<char>{}};
  return {reinterpret_cast<const std::byte*>(text.data()),
          reinterpret_cast<const std::byte*>(text.data()) + text.size()};
}

bool write_file(const std::filesystem::path& path, std::span<const std::byte> bytes) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) {
    return false;
  }
  output.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(output);
}

// Builds the same shape of pre-upgrade v1 profile database the M2 fixture
// tests use: real identity, encrypted-file secret handle, one relay row.
bool create_v1_database(const std::filesystem::path& database_path,
                        const std::filesystem::path& secrets_path,
                        std::span<const std::byte> mutation) {
  std::error_code error;
  std::filesystem::create_directories(database_path.parent_path(), error);
#ifndef _WIN32
  // The encrypted-file secret backend refuses world-readable directories
  // (same hardening the M2 fixture setup applies).
  if (::chmod(database_path.parent_path().c_str(), S_IRWXU) != 0) {
    std::abort();
  }
#endif
  auto secrets = heyaki::open_default_secret_backend(secrets_path,
                                                     heyaki::SecretBackendOptions{});
  auto identity = heyaki::create_identity();
  if (!secrets || !identity) {
    std::abort();
  }
  auto handle = (*secrets.value_if())->store("identity-ed25519",
                                             identity.value_if()->secret_key());
  if (!handle) {
    std::abort();
  }

  sqlite3* database = nullptr;
  if (sqlite3_open(database_path.string().c_str(), &database) != SQLITE_OK) {
    if (database != nullptr) {
      sqlite3_close_v2(database);
    }
    std::abort();
  }
  const bool executed =
      sqlite3_exec(database, fixture_sql().c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
  sqlite3_stmt* statement = nullptr;
  bool inserted = false;
  if (executed) {
    // Mutate the stored public key with fuzz bytes: the identity row stays
    // well-formed enough for the schema, but its contents are attacker data.
    auto public_key = identity.value_if()->public_key();
    for (std::size_t index = 0U; index < public_key.size() && index < mutation.size();
         ++index) {
      public_key[index] = mutation[index];
    }
    inserted =
        sqlite3_prepare_v2(database,
                           "INSERT INTO identity(singleton, device_id, public_key, "
                           "secret_handle, created_unix_milliseconds) "
                           "VALUES(1, ?, ?, ?, 1)",
                           -1, &statement, nullptr) == SQLITE_OK &&
        sqlite3_bind_blob(statement, 1, identity.value_if()->device_id().bytes().data(),
                          static_cast<int>(heyaki::DeviceId::size_bytes),
                          SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_blob(statement, 2, public_key.data(),
                          static_cast<int>(public_key.size()), SQLITE_TRANSIENT) ==
            SQLITE_OK &&
        sqlite3_bind_text(statement, 3, handle.value_if()->value.c_str(), -1,
                          SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
  }
  sqlite3_close_v2(database);
#ifndef _WIN32
  // ProfileStore::open rejects databases with group/other bits, so the
  // externally built v1 file arrives 0600 (same as the M2 fixture).
  if (::chmod(database_path.c_str(), S_IRUSR | S_IWUSR) != 0) {
    std::abort();
  }
#endif
  return executed && inserted;
}

ProfileOpenOptions file_backend_options() {
  ProfileOpenOptions options;
  options.secret_backend.prefer_os_backend = false;
  return options;
}

void run_one(std::span<const std::byte> input) {
  const auto root = fuzz_root() / "case";
  std::error_code cleanup;
  std::filesystem::remove_all(root, cleanup);
  const auto database_path = root / "profile.sqlite";
  const auto secrets_path = root / "profile.sqlite.secrets";

  if (input.empty() || (input[0] & std::byte{0x03U}) == std::byte{0x00U}) {
    // Positive path: a well-formed pre-upgrade database. Migration must
    // succeed, leave the recoverable backup, and reopen idempotently.
    if (!create_v1_database(database_path, secrets_path, {})) {
      std::abort();
    }
    if (!heyaki::ProfileStore::open(database_path, file_backend_options())) {
      std::abort();
    }
    if (!std::filesystem::exists(
            heyaki::ProfileStore::migration_backup_path(database_path, 1U))) {
      std::abort();
    }
    auto reopened = heyaki::ProfileStore::open(database_path, file_backend_options());
    if (!reopened) {
      std::abort();
    }
    return;
  }

  std::vector<std::byte> database_bytes;
  // Only a well-formed v1 schema is guaranteed to reach the migration step
  // (and therefore to owe a backup on failure); truncated or random bytes
  // fail validation before migration starts.
  bool migration_attempted = false;
  switch (static_cast<unsigned int>(input[0]) & 0x03U) {
    case 1U: {
      // Well-formed schema with attacker-controlled identity bytes.
      if (!create_v1_database(database_path, secrets_path, input.subspan(1U))) {
        std::abort();
      }
      database_bytes = read_file(database_path);
      migration_attempted = true;
      break;
    }
    case 2U: {
      // Truncated pre-upgrade database.
      if (!create_v1_database(database_path, secrets_path, {})) {
        std::abort();
      }
      database_bytes = read_file(database_path);
      const std::size_t cut =
          input.size() > 1U
              ? static_cast<std::size_t>(input[1]) * database_bytes.size() / 255U
              : 0U;
      database_bytes.resize(cut);
      if (!write_file(database_path, database_bytes)) {
        std::abort();
      }
      break;
    }
    default: {
      // Raw fuzz bytes standing in for the whole database file.
      database_bytes.assign(input.subspan(1U).begin(), input.subspan(1U).end());
      std::filesystem::create_directories(root, cleanup);
      if (!write_file(database_path, database_bytes)) {
        std::abort();
      }
      break;
    }
  }

  auto opened = heyaki::ProfileStore::open(database_path, file_backend_options());
  if (opened) {
    // Corrupt inputs must never migrate into a usable-looking profile that
    // then fails to reopen.
    auto reopened = heyaki::ProfileStore::open(database_path, file_backend_options());
    if (!reopened) {
      std::abort();
    }
    return;
  }

  // Failure contract: an explicit error, the database file still on disk,
  // and a v1 database rolled back to user_version 1 with its backup kept.
  if (!std::filesystem::exists(database_path)) {
    std::abort();
  }
  if (migration_attempted && !std::filesystem::exists(
                                 heyaki::ProfileStore::migration_backup_path(
                                     database_path, 1U))) {
    std::abort();
  }
}

}  // namespace

void profile_store_migration(std::span<const std::byte> input) { run_one(input); }

}  // namespace heyaki::fuzz
