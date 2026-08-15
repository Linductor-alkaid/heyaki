#include <heyaki/profile_store.hpp>

#include <sqlite3.h>

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace heyaki {
namespace {

constexpr int profile_application_id = 1213808976;
constexpr std::string_view profile_database_name = "profile.sqlite";

void profile_fault_injection_point(std::string_view point) noexcept {
#ifdef HEYAKI_PROFILE_FAULT_INJECTION
  const char* requested = std::getenv("HEYAKI_PROFILE_FAULT_POINT");
  if (requested != nullptr && point == requested) {
    std::_Exit(86);
  }
#else
  (void)point;
#endif
}

void profile_scope_fault_injection_point(std::size_t scope_index) noexcept {
#ifdef HEYAKI_PROFILE_FAULT_INJECTION
  switch (scope_index) {
    case 1U:
      profile_fault_injection_point("trust_grant.after_scope_1");
      break;
    case 2U:
      profile_fault_injection_point("trust_grant.after_scope_2");
      break;
    case 3U:
      profile_fault_injection_point("trust_grant.after_scope_3");
      break;
    default:
      break;
  }
#else
  (void)scope_index;
#endif
}

Error sqlite_error(sqlite3* database, const char* detail, int code = SQLITE_ERROR) {
  if (database != nullptr) {
    code = sqlite3_extended_errcode(database);
  }
  const int primary_code = code & 0xff;
  const ErrorCode error_code =
      primary_code == SQLITE_BUSY || primary_code == SQLITE_LOCKED
          ? ErrorCode::profile_locked
          : (primary_code == SQLITE_CORRUPT || primary_code == SQLITE_NOTADB
                 ? ErrorCode::profile_corrupt
                 : ErrorCode::storage);
  return Error{error_code,
               "profile", detail, code};
}

Error filesystem_error(const char* detail, const std::error_code& error) {
  return Error{ErrorCode::storage, "profile", detail,
               error ? std::optional<std::int64_t>{error.value()} : std::nullopt};
}

Result<void> execute(sqlite3* database, const char* sql) {
  const int result = sqlite3_exec(database, sql, nullptr, nullptr, nullptr);
  if (result != SQLITE_OK) {
    return Result<void>::failure(sqlite_error(database, "sqlite_statement_failed", result));
  }
  return Result<void>::success();
}

class Statement {
 public:
  Statement() = default;
  Statement(sqlite3* database, sqlite3_stmt* statement) noexcept
      : database_(database), statement_(statement) {}
  Statement(Statement&& other) noexcept
      : database_(std::exchange(other.database_, nullptr)),
        statement_(std::exchange(other.statement_, nullptr)) {}
  Statement& operator=(Statement&& other) noexcept {
    if (this != &other) {
      if (statement_ != nullptr) {
        sqlite3_finalize(statement_);
      }
      database_ = std::exchange(other.database_, nullptr);
      statement_ = std::exchange(other.statement_, nullptr);
    }
    return *this;
  }
  ~Statement() {
    if (statement_ != nullptr) {
      sqlite3_finalize(statement_);
    }
  }

  Statement(const Statement&) = delete;
  Statement& operator=(const Statement&) = delete;

  [[nodiscard]] sqlite3_stmt* get() const noexcept { return statement_; }
  [[nodiscard]] sqlite3* database() const noexcept { return database_; }

 private:
  sqlite3* database_{nullptr};
  sqlite3_stmt* statement_{nullptr};
};

Result<Statement> prepare(sqlite3* database, const char* sql) {
  sqlite3_stmt* statement = nullptr;
  const int result = sqlite3_prepare_v2(database, sql, -1, &statement, nullptr);
  if (result != SQLITE_OK) {
    return Result<Statement>::failure(sqlite_error(database, "sqlite_prepare_failed", result));
  }
  return Result<Statement>::success(Statement{database, statement});
}

Result<void> step_done(Statement& statement) {
  const int result = sqlite3_step(statement.get());
  if (result != SQLITE_DONE) {
    return Result<void>::failure(
        sqlite_error(statement.database(), "sqlite_write_failed", result));
  }
  return Result<void>::success();
}

template <typename Id>
int bind_id(sqlite3_stmt* statement, int index, const Id& id) {
  return sqlite3_bind_blob(statement, index, id.bytes().data(),
                           static_cast<int>(id.bytes().size()), SQLITE_TRANSIENT);
}

template <typename Id>
Result<Id> column_id(sqlite3_stmt* statement, int column, const char* detail) {
  const auto* bytes = static_cast<const std::byte*>(sqlite3_column_blob(statement, column));
  const int size = sqlite3_column_bytes(statement, column);
  if (bytes == nullptr || size != static_cast<int>(Id::size_bytes)) {
    return Result<Id>::failure(Error{ErrorCode::profile_corrupt, "profile", detail});
  }
  typename Id::Storage storage{};
  std::copy_n(bytes, storage.size(), storage.begin());
  return Result<Id>::success(Id{storage});
}

std::filesystem::path secret_root_for(const std::filesystem::path& database_path) {
  return database_path.parent_path() / (database_path.filename().string() + ".secrets");
}

std::filesystem::path lock_path_for(const std::filesystem::path& database_path) {
  return database_path.parent_path() / (database_path.filename().string() + ".lock");
}

std::filesystem::path parent_directory_for(const std::filesystem::path& path) {
  return path.parent_path().empty() ? std::filesystem::path{"."} : path.parent_path();
}

Result<void> ensure_private_directory(const std::filesystem::path& path) {
  std::error_code error;
  const bool existed = std::filesystem::exists(path, error);
  if (error) {
    return Result<void>::failure(filesystem_error("profile_directory_stat_failed", error));
  }
  std::filesystem::create_directories(path, error);
  if (error) {
    return Result<void>::failure(filesystem_error("profile_directory_create_failed", error));
  }
#ifndef _WIN32
  struct stat status {};
  if (::stat(path.c_str(), &status) != 0) {
    return Result<void>::failure(Error{ErrorCode::profile_permissions, "profile",
                                       "profile_directory_stat_failed", errno});
  }
  if (existed && (status.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    return Result<void>::failure(Error{ErrorCode::profile_permissions, "profile",
                                       "profile_directory_permissions_too_wide"});
  }
  if (!existed && ::chmod(path.c_str(), S_IRWXU) != 0) {
    return Result<void>::failure(Error{ErrorCode::profile_permissions, "profile",
                                       "profile_directory_permission_failed", errno});
  }
#endif
  return Result<void>::success();
}

Result<void> check_profile_permissions(const std::filesystem::path& database_path) {
#ifndef _WIN32
  struct stat status {};
  if (::stat(database_path.c_str(), &status) != 0) {
    return Result<void>::failure(
        filesystem_error("profile_stat_failed", {errno, std::generic_category()}));
  }
  if ((status.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    return Result<void>::failure(Error{ErrorCode::profile_permissions, "profile",
                                       "profile_permissions_too_wide"});
  }
#else
  (void)database_path;
#endif
  return Result<void>::success();
}

Result<void> set_private_file_permissions(const std::filesystem::path& database_path) {
#ifndef _WIN32
  if (::chmod(database_path.c_str(), S_IRUSR | S_IWUSR) != 0) {
    return Result<void>::failure(Error{ErrorCode::profile_permissions, "profile",
                                       "profile_permission_update_failed", errno});
  }
#else
  (void)database_path;
#endif
  return Result<void>::success();
}

Result<void> atomic_replace_file(const std::filesystem::path& source,
                                 const std::filesystem::path& destination) {
#ifdef _WIN32
  if (MoveFileExW(source.wstring().c_str(), destination.wstring().c_str(),
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
    return Result<void>::failure(
        Error{ErrorCode::storage, "profile", "profile_atomic_replace_failed",
              static_cast<std::int64_t>(GetLastError())});
  }
#else
  if (::rename(source.c_str(), destination.c_str()) != 0) {
    return Result<void>::failure(
        Error{ErrorCode::storage, "profile", "profile_atomic_replace_failed", errno});
  }
  const int directory =
      ::open(parent_directory_for(destination).c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (directory < 0) {
    return Result<void>::failure(
        Error{ErrorCode::storage, "profile", "profile_directory_flush_failed", errno});
  }
  const int flushed = ::fsync(directory);
  const int flush_error = errno;
  (void)::close(directory);
  if (flushed != 0) {
    return Result<void>::failure(
        Error{ErrorCode::storage, "profile", "profile_directory_flush_failed", flush_error});
  }
#endif
  return Result<void>::success();
}

void remove_database_artifacts(const std::filesystem::path& path) noexcept {
  std::error_code ignored;
  std::filesystem::remove(path, ignored);
  std::filesystem::remove(path.string() + "-wal", ignored);
  std::filesystem::remove(path.string() + "-shm", ignored);
}

bool valid_profile_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > 64U || name == "." || name == "..") {
    return false;
  }
  for (const char character : name) {
    const bool lower = character >= 'a' && character <= 'z';
    const bool upper = character >= 'A' && character <= 'Z';
    const bool digit = character >= '0' && character <= '9';
    if (!lower && !upper && !digit && character != '-' && character != '_' && character != '.') {
      return false;
    }
  }
  return true;
}

bool valid_application_id(std::string_view value) noexcept {
  if (value.empty() || value.size() > 255U) {
    return false;
  }
  for (const char value_character : value) {
    const auto character = static_cast<unsigned char>(value_character);
    if (character < 0x21U || character > 0x7eU) {
      return false;
    }
  }
  return true;
}

bool valid_scope(std::string_view value) noexcept {
  if (value.empty() || value.size() > 256U) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](unsigned char character) {
    return character >= 0x21U && character <= 0x7eU;
  });
}

std::string random_suffix() {
  std::array<unsigned char, 8U> bytes{};
  randombytes_buf(bytes.data(), bytes.size());
  constexpr char alphabet[] = "0123456789abcdef";
  std::string output;
  output.reserve(bytes.size() * 2U);
  for (const auto byte : bytes) {
    output.push_back(alphabet[(byte >> 4U) & 0x0fU]);
    output.push_back(alphabet[byte & 0x0fU]);
  }
  return output;
}

class ExclusiveProfileLock {
 public:
  ExclusiveProfileLock() = default;
  ExclusiveProfileLock(ExclusiveProfileLock&& other) noexcept { move_from(other); }
  ExclusiveProfileLock& operator=(ExclusiveProfileLock&& other) noexcept {
    if (this != &other) {
      release();
      move_from(other);
    }
    return *this;
  }
  ~ExclusiveProfileLock() { release(); }

  ExclusiveProfileLock(const ExclusiveProfileLock&) = delete;
  ExclusiveProfileLock& operator=(const ExclusiveProfileLock&) = delete;

  static Result<ExclusiveProfileLock> acquire(const std::filesystem::path& path,
                                               std::chrono::milliseconds timeout) {
    ExclusiveProfileLock lock;
#ifdef _WIN32
    lock.handle_ = CreateFileW(path.wstring().c_str(), GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                               OPEN_ALWAYS,
                               FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (lock.handle_ == INVALID_HANDLE_VALUE) {
      return Result<ExclusiveProfileLock>::failure(
          Error{ErrorCode::storage, "profile", "profile_lock_open_failed",
                static_cast<std::int64_t>(GetLastError())});
    }
#else
    lock.handle_ = ::open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (lock.handle_ < 0) {
      return Result<ExclusiveProfileLock>::failure(
          Error{ErrorCode::storage, "profile", "profile_lock_open_failed", errno});
    }
#endif
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!lock.try_lock()) {
      if (std::chrono::steady_clock::now() >= deadline) {
        return Result<ExclusiveProfileLock>::failure(
            Error{ErrorCode::profile_locked, "profile", "profile_lock_timeout"});
      }
#ifdef _WIN32
      Sleep(10U);
#else
      (void)::poll(nullptr, 0, 10);
#endif
    }
    return Result<ExclusiveProfileLock>::success(std::move(lock));
  }

 private:
  bool try_lock() {
#ifdef _WIN32
    OVERLAPPED overlapped{};
    if (LockFileEx(handle_, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0,
                   MAXDWORD, MAXDWORD, &overlapped) != FALSE) {
      locked_ = true;
      return true;
    }
    return false;
#else
    if (::flock(handle_, LOCK_EX | LOCK_NB) == 0) {
      locked_ = true;
      return true;
    }
    return false;
#endif
  }

  void release() noexcept {
#ifdef _WIN32
    if (handle_ != INVALID_HANDLE_VALUE) {
      if (locked_) {
        OVERLAPPED overlapped{};
        UnlockFileEx(handle_, 0, MAXDWORD, MAXDWORD, &overlapped);
      }
      CloseHandle(handle_);
      handle_ = INVALID_HANDLE_VALUE;
    }
#else
    if (handle_ >= 0) {
      if (locked_) {
        (void)::flock(handle_, LOCK_UN);
      }
      (void)::close(handle_);
      handle_ = -1;
    }
#endif
    locked_ = false;
  }

  void move_from(ExclusiveProfileLock& other) noexcept {
    handle_ = other.handle_;
    locked_ = other.locked_;
#ifdef _WIN32
    other.handle_ = INVALID_HANDLE_VALUE;
#else
    other.handle_ = -1;
#endif
    other.locked_ = false;
  }

#ifdef _WIN32
  HANDLE handle_{INVALID_HANDLE_VALUE};
#else
  int handle_{-1};
#endif
  bool locked_{false};
};

const char* schema_v1 = R"SQL(
CREATE TABLE schema_migrations(
  version INTEGER PRIMARY KEY,
  applied_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE identity(
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  device_id BLOB NOT NULL CHECK(length(device_id) = 32),
  public_key BLOB NOT NULL CHECK(length(public_key) = 32),
  secret_handle TEXT NOT NULL,
  created_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE relay_enrollments(
  relay_url TEXT PRIMARY KEY,
  relay_pin BLOB,
  tenant TEXT NOT NULL DEFAULT '',
  enrollment_generation INTEGER NOT NULL,
  auto_connect INTEGER NOT NULL DEFAULT 1 CHECK(auto_connect IN (0, 1)),
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
  updated_unix_milliseconds INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE password_verifier(
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  format_version INTEGER NOT NULL,
  encoded TEXT NOT NULL,
  operations INTEGER NOT NULL,
  memory_bytes INTEGER NOT NULL,
  password_generation INTEGER NOT NULL
);
CREATE TABLE trust_grants(
  grant_id BLOB PRIMARY KEY CHECK(length(grant_id) = 16),
  direction INTEGER NOT NULL CHECK(direction IN (1, 2)),
  issuer_device_id BLOB NOT NULL CHECK(length(issuer_device_id) = 32),
  subject_device_id BLOB NOT NULL CHECK(length(subject_device_id) = 32),
  password_generation INTEGER NOT NULL,
  issued_unix_milliseconds INTEGER NOT NULL,
  expires_unix_milliseconds INTEGER,
  signature BLOB NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
  revoked_unix_milliseconds INTEGER
);
CREATE TABLE trust_grant_scopes(
  grant_id BLOB NOT NULL REFERENCES trust_grants(grant_id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  PRIMARY KEY(grant_id, scope)
);
CREATE INDEX trust_grants_subject_index
  ON trust_grants(subject_device_id, direction, revoked, expires_unix_milliseconds);
CREATE TABLE endpoint_records(
  application_id TEXT PRIMARY KEY,
  endpoint_id BLOB NOT NULL UNIQUE CHECK(length(endpoint_id) = 16),
  created_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE file_resume(
  transfer_id BLOB PRIMARY KEY CHECK(length(transfer_id) = 16),
  peer_device_id BLOB NOT NULL CHECK(length(peer_device_id) = 32),
  state BLOB NOT NULL,
  updated_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE preferences(
  key TEXT PRIMARY KEY,
  value BLOB NOT NULL,
  updated_unix_milliseconds INTEGER NOT NULL
);
INSERT INTO schema_migrations(version, applied_unix_milliseconds)
VALUES(1, CAST(unixepoch('subsec') * 1000 AS INTEGER));
PRAGMA application_id=1213808976;
PRAGMA user_version=1;
)SQL";

const char* migration_v2 = R"SQL(
CREATE INDEX trust_grants_authorization_index
  ON trust_grants(issuer_device_id, subject_device_id, direction, revoked,
                  password_generation, expires_unix_milliseconds);
INSERT INTO schema_migrations(version, applied_unix_milliseconds)
VALUES(2, CAST(unixepoch('subsec') * 1000 AS INTEGER));
PRAGMA user_version=2;
)SQL";

Result<int> pragma_int(sqlite3* database, const char* pragma) {
  auto statement = prepare(database, pragma);
  if (!statement) {
    return Result<int>::failure(*statement.error_if());
  }
  if (sqlite3_step(statement.value_if()->get()) != SQLITE_ROW) {
    return Result<int>::failure(sqlite_error(database, "sqlite_pragma_failed"));
  }
  return Result<int>::success(sqlite3_column_int(statement.value_if()->get(), 0));
}

Result<void> validate_database(sqlite3* database) {
  auto check = prepare(database, "PRAGMA quick_check(1)");
  if (!check) {
    return Result<void>::failure(*check.error_if());
  }
  if (sqlite3_step(check.value_if()->get()) != SQLITE_ROW) {
    return Result<void>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "profile_integrity_check_failed"});
  }
  const auto* result = reinterpret_cast<const char*>(
      sqlite3_column_text(check.value_if()->get(), 0));
  if (result == nullptr || std::string_view{result} != "ok") {
    return Result<void>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "profile_integrity_check_failed"});
  }
  return Result<void>::success();
}

Result<void> validate_migration_history(sqlite3* database, int version) {
  auto statement = prepare(
      database, "SELECT COUNT(*) FROM schema_migrations WHERE version BETWEEN 1 AND ?");
  if (!statement) {
    return Result<void>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "profile_migration_history_missing"});
  }
  sqlite3_bind_int(statement.value_if()->get(), 1, version);
  if (sqlite3_step(statement.value_if()->get()) != SQLITE_ROW ||
      sqlite3_column_int(statement.value_if()->get(), 0) != version) {
    return Result<void>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "profile_migration_history_invalid"});
  }
  return Result<void>::success();
}

std::filesystem::path migration_backup_path_for(const std::filesystem::path& database_path,
                                                std::uint32_t source_version) {
  return database_path.string() + ".backup-v" + std::to_string(source_version);
}

Result<void> verify_database_file(const std::filesystem::path& path,
                                  std::optional<int> expected_version) {
  sqlite3* database = nullptr;
  const int opened = sqlite3_open_v2(path.string().c_str(), &database,
                                     SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nullptr);
  if (opened != SQLITE_OK) {
    const auto error = sqlite_error(database, "profile_backup_open_failed", opened);
    if (database != nullptr) {
      sqlite3_close_v2(database);
    }
    return Result<void>::failure(error);
  }
  auto application_id = pragma_int(database, "PRAGMA application_id");
  auto version = pragma_int(database, "PRAGMA user_version");
  auto integrity = validate_database(database);
  Result<void> history = Result<void>::success();
  if (version && *version.value_if() > 0) {
    history = validate_migration_history(database, *version.value_if());
  }
  const int closed = sqlite3_close_v2(database);
  if (!application_id || !version || !integrity || !history || closed != SQLITE_OK) {
    if (!application_id || !version) {
      return Result<void>::failure(
          Error{ErrorCode::profile_corrupt, "profile", "profile_backup_header_invalid"});
    }
    if (!integrity) {
      return integrity;
    }
    if (!history) {
      return history;
    }
    return Result<void>::failure(
        Error{ErrorCode::storage, "profile", "profile_backup_close_failed", closed});
  }
  if (*application_id.value_if() != profile_application_id || *version.value_if() <= 0 ||
      *version.value_if() > static_cast<int>(profile_schema_version) ||
      (expected_version && *version.value_if() != *expected_version)) {
    return Result<void>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "profile_backup_header_invalid"});
  }
  return Result<void>::success();
}

Result<void> write_database_copy(sqlite3* source, const std::filesystem::path& destination,
                                 int expected_version) {
  const auto temporary = destination.string() + ".tmp." + random_suffix();
  sqlite3* output = nullptr;
  const int opened = sqlite3_open_v2(temporary.c_str(), &output,
                                     SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
  if (opened != SQLITE_OK) {
    const auto error = sqlite_error(output, "profile_backup_create_failed", opened);
    if (output != nullptr) {
      sqlite3_close_v2(output);
    }
    return Result<void>::failure(error);
  }
  const auto configured = execute(output, "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;");
  if (!configured) {
    sqlite3_close_v2(output);
    remove_database_artifacts(temporary);
    return configured;
  }
  sqlite3_backup* backup = sqlite3_backup_init(output, "main", source, "main");
  if (backup == nullptr) {
    const auto error = sqlite_error(output, "profile_backup_initialize_failed");
    sqlite3_close_v2(output);
    remove_database_artifacts(temporary);
    return Result<void>::failure(error);
  }
  const int copied = sqlite3_backup_step(backup, -1);
  const int finished = sqlite3_backup_finish(backup);
  const int closed = sqlite3_close_v2(output);
  if (copied != SQLITE_DONE || finished != SQLITE_OK || closed != SQLITE_OK) {
    remove_database_artifacts(temporary);
    return Result<void>::failure(
        Error{ErrorCode::storage, "profile", "profile_backup_copy_failed",
              copied != SQLITE_DONE ? copied : (finished != SQLITE_OK ? finished : closed)});
  }
  const auto permissions = set_private_file_permissions(temporary);
  if (!permissions) {
    remove_database_artifacts(temporary);
    return permissions;
  }
  const auto verified = verify_database_file(temporary, expected_version);
  if (!verified) {
    remove_database_artifacts(temporary);
    return verified;
  }
  const auto replaced = atomic_replace_file(temporary, destination);
  if (!replaced) {
    remove_database_artifacts(temporary);
    return replaced;
  }
  remove_database_artifacts(temporary);
  return Result<void>::success();
}

Result<void> migrate_database(sqlite3* database, const std::filesystem::path& database_path,
                              bool initialize) {
  auto application_id = pragma_int(database, "PRAGMA application_id");
  auto version = pragma_int(database, "PRAGMA user_version");
  if (!application_id || !version) {
    return Result<void>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "profile_header_invalid"});
  }
  if (*application_id.value_if() != 0 && *application_id.value_if() != profile_application_id) {
    return Result<void>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "profile_application_id_mismatch"});
  }
  if (*version.value_if() > static_cast<int>(profile_schema_version)) {
    return Result<void>::failure(
        Error{ErrorCode::schema_too_new, "profile", "profile_schema_too_new"});
  }
  if (*version.value_if() == 0) {
    if (!initialize) {
      return Result<void>::failure(
          Error{ErrorCode::profile_corrupt, "profile", "profile_schema_missing"});
    }
    const auto begin = execute(database, "BEGIN EXCLUSIVE");
    if (!begin) {
      return begin;
    }
    profile_fault_injection_point("schema.after_begin");
    const auto schema = execute(database, schema_v1);
    if (!schema) {
      (void)execute(database, "ROLLBACK");
      return schema;
    }
    profile_fault_injection_point("schema.after_apply");
    const auto commit = execute(database, "COMMIT");
    if (!commit) {
      (void)execute(database, "ROLLBACK");
      return commit;
    }
    profile_fault_injection_point("schema.after_commit");
    *version.value_if() = 1;
  } else if (*application_id.value_if() != profile_application_id) {
    return Result<void>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "profile_application_id_mismatch"});
  }

  auto valid = validate_database(database);
  if (!valid) {
    return valid;
  }
  valid = validate_migration_history(database, *version.value_if());
  if (!valid) {
    return valid;
  }

  if (!initialize && *version.value_if() < static_cast<int>(profile_schema_version)) {
    const auto backup = write_database_copy(
        database,
        migration_backup_path_for(database_path,
                                  static_cast<std::uint32_t>(*version.value_if())),
        *version.value_if());
    if (!backup) {
      return backup;
    }
  }

  while (*version.value_if() < static_cast<int>(profile_schema_version)) {
    const int target_version = *version.value_if() + 1;
    const char* migration = target_version == 2 ? migration_v2 : nullptr;
    if (migration == nullptr) {
      return Result<void>::failure(
          Error{ErrorCode::internal, "profile", "profile_migration_not_registered"});
    }
    const auto begin = execute(database, "BEGIN EXCLUSIVE");
    if (!begin) {
      return begin;
    }
    profile_fault_injection_point("migration.after_begin");
    const auto applied = execute(database, migration);
    if (!applied) {
      (void)execute(database, "ROLLBACK");
      return applied;
    }
    profile_fault_injection_point("migration.after_apply");
    const auto commit = execute(database, "COMMIT");
    if (!commit) {
      (void)execute(database, "ROLLBACK");
      return commit;
    }
    profile_fault_injection_point("migration.after_commit");
    *version.value_if() = target_version;
  }
  valid = validate_database(database);
  if (!valid) {
    return valid;
  }
  return validate_migration_history(database, *version.value_if());
}

Result<sqlite3*> open_database(const std::filesystem::path& path, bool create,
                               std::chrono::milliseconds busy_timeout) {
  sqlite3* database = nullptr;
  const int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX |
                    (create ? SQLITE_OPEN_CREATE : 0);
  const int opened = sqlite3_open_v2(path.string().c_str(), &database, flags, nullptr);
  if (opened != SQLITE_OK) {
    const auto error = sqlite_error(database, "profile_open_failed", opened);
    if (database != nullptr) {
      sqlite3_close_v2(database);
    }
    return Result<sqlite3*>::failure(error);
  }
  const auto timeout_count = std::clamp<std::int64_t>(busy_timeout.count(), 0,
                                                       std::numeric_limits<int>::max());
  sqlite3_extended_result_codes(database, 1);
  sqlite3_busy_timeout(database, static_cast<int>(timeout_count));
  const auto configured = execute(
      database, "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;");
  if (!configured) {
    sqlite3_close_v2(database);
    return Result<sqlite3*>::failure(*configured.error_if());
  }
  return Result<sqlite3*>::success(database);
}

Result<std::filesystem::path> default_root_path() {
#ifdef _WIN32
  const char* local_app_data = std::getenv("LOCALAPPDATA");
  if (local_app_data == nullptr || *local_app_data == '\0') {
    return Result<std::filesystem::path>::failure(
        Error{ErrorCode::configuration, "profile", "local_app_data_unavailable"});
  }
  return Result<std::filesystem::path>::success(
      std::filesystem::path{local_app_data} / "Heyaki" / "profiles");
#else
  const char* xdg_state_home = std::getenv("XDG_STATE_HOME");
  if (xdg_state_home != nullptr && *xdg_state_home != '\0') {
    return Result<std::filesystem::path>::success(
        std::filesystem::path{xdg_state_home} / "heyaki" / "profiles");
  }
  const char* home = std::getenv("HOME");
  if (home == nullptr || *home == '\0') {
    return Result<std::filesystem::path>::failure(
        Error{ErrorCode::configuration, "profile", "home_directory_unavailable"});
  }
  return Result<std::filesystem::path>::success(
      std::filesystem::path{home} / ".local" / "state" / "heyaki" / "profiles");
#endif
}

std::uint64_t current_unix_milliseconds() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
}

}  // namespace

class ProfileStore::Impl {
 public:
  Impl(std::filesystem::path path, sqlite3* database, std::shared_ptr<SecretBackend> secrets,
       DeviceId device_id, IdentityPublicKey public_key, std::string secret_handle)
      : path(std::move(path)),
        database(database),
        secrets(std::move(secrets)),
        device_id(device_id),
        public_key(public_key),
        secret_handle(std::move(secret_handle)) {}

  ~Impl() {
    if (database != nullptr) {
      sqlite3_close_v2(database);
    }
  }

  std::filesystem::path path;
  sqlite3* database;
  std::shared_ptr<SecretBackend> secrets;
  DeviceId device_id;
  IdentityPublicKey public_key;
  std::string secret_handle;
};

namespace {

Result<std::unique_ptr<ProfileStore::Impl>> load_profile_impl(
    const std::filesystem::path& path, sqlite3* database,
    std::shared_ptr<SecretBackend> secrets) {
  auto statement = prepare(
      database, "SELECT device_id, public_key, secret_handle FROM identity WHERE singleton=1");
  if (!statement) {
    return Result<std::unique_ptr<ProfileStore::Impl>>::failure(*statement.error_if());
  }
  if (sqlite3_step(statement.value_if()->get()) != SQLITE_ROW) {
    return Result<std::unique_ptr<ProfileStore::Impl>>::failure(
        Error{ErrorCode::not_registered, "profile", "identity_not_initialized"});
  }
  auto device_id = column_id<DeviceId>(statement.value_if()->get(), 0, "device_id_invalid");
  if (!device_id) {
    return Result<std::unique_ptr<ProfileStore::Impl>>::failure(*device_id.error_if());
  }
  const auto* public_bytes = static_cast<const std::byte*>(
      sqlite3_column_blob(statement.value_if()->get(), 1));
  if (public_bytes == nullptr ||
      sqlite3_column_bytes(statement.value_if()->get(), 1) !=
          static_cast<int>(ed25519_public_key_bytes)) {
    return Result<std::unique_ptr<ProfileStore::Impl>>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "identity_public_key_invalid"});
  }
  IdentityPublicKey public_key{};
  std::copy_n(public_bytes, public_key.size(), public_key.begin());
  const auto* handle_text = reinterpret_cast<const char*>(
      sqlite3_column_text(statement.value_if()->get(), 2));
  if (handle_text == nullptr || *handle_text == '\0') {
    return Result<std::unique_ptr<ProfileStore::Impl>>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "identity_secret_handle_invalid"});
  }

  auto secret = secrets->load(SecretHandle{handle_text});
  if (!secret) {
    return Result<std::unique_ptr<ProfileStore::Impl>>::failure(*secret.error_if());
  }
  auto identity = import_identity(public_key, *secret.value_if());
  sodium_memzero(secret.value_if()->data(), secret.value_if()->size());
  if (!identity || identity.value_if()->device_id() != *device_id.value_if()) {
    return Result<std::unique_ptr<ProfileStore::Impl>>::failure(
        Error{ErrorCode::identity, "profile", "stored_identity_mismatch"});
  }

  return Result<std::unique_ptr<ProfileStore::Impl>>::success(
      std::make_unique<ProfileStore::Impl>(path, database, std::move(secrets),
                                           *device_id.value_if(), public_key, handle_text));
}

Result<std::shared_ptr<SecretBackend>> resolve_secret_backend(
    const std::filesystem::path& path, const ProfileOpenOptions& options, bool create_if_missing) {
  if (options.secrets) {
    return Result<std::shared_ptr<SecretBackend>>::success(options.secrets);
  }
  auto secret_options = options.secret_backend;
  secret_options.create_if_missing = create_if_missing;
  return open_default_secret_backend(secret_root_for(path), secret_options);
}

}  // namespace

ProfileStore::ProfileStore(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
ProfileStore::ProfileStore(ProfileStore&&) noexcept = default;
ProfileStore& ProfileStore::operator=(ProfileStore&&) noexcept = default;
ProfileStore::~ProfileStore() = default;

Result<ProfileStore> ProfileStore::create(const std::filesystem::path& database_path,
                                          const ProfileOpenOptions& options) {
  const auto parent_ready = ensure_private_directory(parent_directory_for(database_path));
  if (!parent_ready) {
    return Result<ProfileStore>::failure(*parent_ready.error_if());
  }
  std::error_code exists_error;
  if (std::filesystem::exists(database_path, exists_error)) {
    return Result<ProfileStore>::failure(
        Error{ErrorCode::configuration, "profile", "profile_already_exists"});
  }
  if (exists_error) {
    return Result<ProfileStore>::failure(filesystem_error("profile_stat_failed", exists_error));
  }
  auto lock = ExclusiveProfileLock::acquire(lock_path_for(database_path), options.lock_timeout);
  if (!lock) {
    return Result<ProfileStore>::failure(*lock.error_if());
  }
  auto secrets = resolve_secret_backend(database_path, options, true);
  if (!secrets) {
    return Result<ProfileStore>::failure(*secrets.error_if());
  }
  auto identity = create_identity();
  if (!identity) {
    return Result<ProfileStore>::failure(*identity.error_if());
  }
  auto handle = (*secrets.value_if())->store("identity-ed25519", identity.value_if()->secret_key());
  if (!handle) {
    return Result<ProfileStore>::failure(*handle.error_if());
  }
  const auto temporary_path = database_path.string() + ".tmp." + random_suffix();
  auto database = open_database(temporary_path, true, options.sqlite_busy_timeout);
  if (!database) {
    (void)(*secrets.value_if())->erase(*handle.value_if());
    return Result<ProfileStore>::failure(*database.error_if());
  }
  const auto migrated = migrate_database(*database.value_if(), temporary_path, true);
  if (!migrated) {
    sqlite3_close_v2(*database.value_if());
    remove_database_artifacts(temporary_path);
    (void)(*secrets.value_if())->erase(*handle.value_if());
    return Result<ProfileStore>::failure(*migrated.error_if());
  }
  {
    auto insert = prepare(*database.value_if(),
                          "INSERT INTO identity(singleton, device_id, public_key, secret_handle, "
                          "created_unix_milliseconds) VALUES(1, ?, ?, ?, ?)");
    if (!insert) {
      sqlite3_close_v2(*database.value_if());
      remove_database_artifacts(temporary_path);
      (void)(*secrets.value_if())->erase(*handle.value_if());
      return Result<ProfileStore>::failure(*insert.error_if());
    }
    bind_id(insert.value_if()->get(), 1, identity.value_if()->device_id());
    sqlite3_bind_blob(insert.value_if()->get(), 2, identity.value_if()->public_key().data(),
                      static_cast<int>(identity.value_if()->public_key().size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(insert.value_if()->get(), 3, handle.value_if()->value.c_str(), -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(insert.value_if()->get(), 4,
                       static_cast<sqlite3_int64>(current_unix_milliseconds()));
    const auto inserted = step_done(*insert.value_if());
    if (!inserted) {
      sqlite3_close_v2(*database.value_if());
      remove_database_artifacts(temporary_path);
      (void)(*secrets.value_if())->erase(*handle.value_if());
      return Result<ProfileStore>::failure(*inserted.error_if());
    }
  }
  const auto checkpoint = execute(*database.value_if(), "PRAGMA wal_checkpoint(TRUNCATE)");
  const int closed = sqlite3_close_v2(*database.value_if());
  if (!checkpoint || closed != SQLITE_OK) {
    remove_database_artifacts(temporary_path);
    (void)(*secrets.value_if())->erase(*handle.value_if());
    return Result<ProfileStore>::failure(
        !checkpoint ? *checkpoint.error_if()
                    : Error{ErrorCode::storage, "profile", "profile_close_failed", closed});
  }
  const auto permissions = set_private_file_permissions(temporary_path);
  if (!permissions) {
    remove_database_artifacts(temporary_path);
    (void)(*secrets.value_if())->erase(*handle.value_if());
    return Result<ProfileStore>::failure(*permissions.error_if());
  }
  const auto replaced = atomic_replace_file(temporary_path, database_path);
  if (!replaced) {
    remove_database_artifacts(temporary_path);
    (void)(*secrets.value_if())->erase(*handle.value_if());
    return Result<ProfileStore>::failure(*replaced.error_if());
  }
  database = open_database(database_path, false, options.sqlite_busy_timeout);
  if (!database) {
    return Result<ProfileStore>::failure(*database.error_if());
  }
  auto impl = load_profile_impl(database_path, *database.value_if(), *secrets.value_if());
  if (!impl) {
    sqlite3_close_v2(*database.value_if());
    return Result<ProfileStore>::failure(*impl.error_if());
  }
  return Result<ProfileStore>::success(ProfileStore{std::move(*impl.value_if())});
}

Result<ProfileStore> ProfileStore::open(const std::filesystem::path& database_path,
                                        const ProfileOpenOptions& options) {
  std::error_code exists_error;
  if (!std::filesystem::exists(database_path, exists_error)) {
    return Result<ProfileStore>::failure(
        Error{ErrorCode::not_registered, "profile", "profile_not_found"});
  }
  if (exists_error) {
    return Result<ProfileStore>::failure(filesystem_error("profile_stat_failed", exists_error));
  }
  const auto permissions = check_profile_permissions(database_path);
  if (!permissions) {
    return Result<ProfileStore>::failure(*permissions.error_if());
  }
  auto lock = ExclusiveProfileLock::acquire(lock_path_for(database_path), options.lock_timeout);
  if (!lock) {
    return Result<ProfileStore>::failure(*lock.error_if());
  }
  auto secrets = resolve_secret_backend(database_path, options, false);
  if (!secrets) {
    return Result<ProfileStore>::failure(*secrets.error_if());
  }
  auto database = open_database(database_path, false, options.sqlite_busy_timeout);
  if (!database) {
    return Result<ProfileStore>::failure(*database.error_if());
  }
  const auto migrated = migrate_database(*database.value_if(), database_path, false);
  if (!migrated) {
    sqlite3_close_v2(*database.value_if());
    return Result<ProfileStore>::failure(*migrated.error_if());
  }
  auto impl = load_profile_impl(database_path, *database.value_if(), *secrets.value_if());
  if (!impl) {
    sqlite3_close_v2(*database.value_if());
    return Result<ProfileStore>::failure(*impl.error_if());
  }
  return Result<ProfileStore>::success(ProfileStore{std::move(*impl.value_if())});
}

Result<std::filesystem::path> ProfileStore::default_profiles_root() {
  return default_root_path();
}

Result<ProfileStore> ProfileStore::create_default(std::string_view profile_name,
                                                  const ProfileOpenOptions& options) {
  if (!valid_profile_name(profile_name)) {
    return Result<ProfileStore>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_profile_name"});
  }
  auto root = default_root_path();
  if (!root) {
    return Result<ProfileStore>::failure(*root.error_if());
  }
  const auto directory = *root.value_if() / std::string{profile_name};
  return create(directory / profile_database_name, options);
}

Result<ProfileStore> ProfileStore::open_default(std::string_view profile_name,
                                                const ProfileOpenOptions& options) {
  if (!valid_profile_name(profile_name)) {
    return Result<ProfileStore>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_profile_name"});
  }
  auto root = default_root_path();
  if (!root) {
    return Result<ProfileStore>::failure(*root.error_if());
  }
  return open(*root.value_if() / std::string{profile_name} / profile_database_name, options);
}

Result<std::vector<ProfileInfo>> ProfileStore::enumerate_default() {
  auto root = default_root_path();
  if (!root) {
    return Result<std::vector<ProfileInfo>>::failure(*root.error_if());
  }
  std::vector<ProfileInfo> profiles;
  std::error_code error;
  if (!std::filesystem::exists(*root.value_if(), error)) {
    return Result<std::vector<ProfileInfo>>::success(std::move(profiles));
  }
  for (std::filesystem::directory_iterator iterator(*root.value_if(), error), end;
       !error && iterator != end; iterator.increment(error)) {
    if (!iterator->is_directory(error)) {
      continue;
    }
    const auto database = iterator->path() / profile_database_name;
    if (std::filesystem::is_regular_file(database, error)) {
      profiles.push_back(ProfileInfo{iterator->path().filename().string(), database});
    }
  }
  if (error) {
    return Result<std::vector<ProfileInfo>>::failure(
        filesystem_error("profile_enumeration_failed", error));
  }
  std::sort(profiles.begin(), profiles.end(), [](const ProfileInfo& lhs, const ProfileInfo& rhs) {
    return lhs.name < rhs.name;
  });
  return Result<std::vector<ProfileInfo>>::success(std::move(profiles));
}

Result<void> ProfileStore::rename_default(std::string_view current_name,
                                          std::string_view new_name,
                                          std::chrono::milliseconds lock_timeout) {
  if (!valid_profile_name(current_name) || !valid_profile_name(new_name)) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_profile_name"});
  }
  auto root = default_root_path();
  if (!root) {
    return Result<void>::failure(*root.error_if());
  }
  const auto source = *root.value_if() / std::string{current_name};
  const auto destination = *root.value_if() / std::string{new_name};
  auto lock = ExclusiveProfileLock::acquire(source / "profile.sqlite.lock", lock_timeout);
  if (!lock) {
    return Result<void>::failure(*lock.error_if());
  }
  std::error_code error;
  if (!std::filesystem::exists(source / profile_database_name, error)) {
    return Result<void>::failure(
        Error{ErrorCode::not_registered, "profile", "profile_not_found"});
  }
  if (std::filesystem::exists(destination, error)) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "profile", "profile_already_exists"});
  }
  std::filesystem::rename(source, destination, error);
  if (error) {
    return Result<void>::failure(filesystem_error("profile_rename_failed", error));
  }
  return Result<void>::success();
}

Result<void> ProfileStore::delete_local(const std::filesystem::path& database_path,
                                        std::chrono::milliseconds lock_timeout) {
  auto lock = ExclusiveProfileLock::acquire(lock_path_for(database_path), lock_timeout);
  if (!lock) {
    return Result<void>::failure(*lock.error_if());
  }
  const auto secret_root = secret_root_for(database_path);
  std::error_code error;
  const bool secret_root_exists = std::filesystem::exists(secret_root, error);
  if (error) {
    return Result<void>::failure(filesystem_error("profile_secret_stat_failed", error));
  }
  if (secret_root_exists) {
    SecretBackendOptions options;
    options.create_if_missing = false;
    auto secrets = open_default_secret_backend(secret_root, options);
    if (secrets) {
      const auto erased = (*secrets.value_if())->erase_all();
      if (!erased) {
        return erased;
      }
    } else {
      const bool external_store = std::filesystem::exists(secret_root / "store.id", error);
      if (error) {
        return Result<void>::failure(filesystem_error("profile_secret_stat_failed", error));
      }
      if (external_store) {
        return Result<void>::failure(*secrets.error_if());
      }
    }
  }

  std::filesystem::remove(database_path, error);
  if (error) {
    return Result<void>::failure(filesystem_error("profile_delete_failed", error));
  }
  std::filesystem::remove(database_path.string() + "-wal", error);
  error.clear();
  std::filesystem::remove(database_path.string() + "-shm", error);
  error.clear();
  std::filesystem::remove_all(secret_root, error);
  if (error) {
    return Result<void>::failure(filesystem_error("profile_secret_delete_failed", error));
  }
  return Result<void>::success();
}

std::filesystem::path ProfileStore::migration_backup_path(
    const std::filesystem::path& database_path, std::uint32_t source_version) {
  return migration_backup_path_for(database_path, source_version);
}

Result<void> ProfileStore::restore_from_backup(
    const std::filesystem::path& database_path, const std::filesystem::path& backup_path,
    std::chrono::milliseconds lock_timeout) {
  if (database_path.empty() || backup_path.empty() || database_path == backup_path) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_profile_backup_path"});
  }
  const auto directory = ensure_private_directory(parent_directory_for(database_path));
  if (!directory) {
    return directory;
  }
  const auto backup_permissions = check_profile_permissions(backup_path);
  if (!backup_permissions) {
    return backup_permissions;
  }
  auto lock = ExclusiveProfileLock::acquire(lock_path_for(database_path), lock_timeout);
  if (!lock) {
    return Result<void>::failure(*lock.error_if());
  }
  const auto verified = verify_database_file(backup_path, std::nullopt);
  if (!verified) {
    return verified;
  }
  sqlite3* source = nullptr;
  const int opened = sqlite3_open_v2(backup_path.string().c_str(), &source,
                                     SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nullptr);
  if (opened != SQLITE_OK) {
    const auto error = sqlite_error(source, "profile_backup_open_failed", opened);
    if (source != nullptr) {
      sqlite3_close_v2(source);
    }
    return Result<void>::failure(error);
  }
  auto version = pragma_int(source, "PRAGMA user_version");
  if (!version) {
    sqlite3_close_v2(source);
    return Result<void>::failure(*version.error_if());
  }
  const auto restored = write_database_copy(source, database_path, *version.value_if());
  const int closed = sqlite3_close_v2(source);
  if (!restored) {
    return restored;
  }
  if (closed != SQLITE_OK) {
    return Result<void>::failure(
        Error{ErrorCode::storage, "profile", "profile_backup_close_failed", closed});
  }
  std::error_code ignored;
  std::filesystem::remove(database_path.string() + "-wal", ignored);
  std::filesystem::remove(database_path.string() + "-shm", ignored);
  return Result<void>::success();
}

const std::filesystem::path& ProfileStore::path() const noexcept { return impl_->path; }
const DeviceId& ProfileStore::device_id() const noexcept { return impl_->device_id; }
const IdentityPublicKey& ProfileStore::identity_public_key() const noexcept {
  return impl_->public_key;
}
SecretBackendSecurity ProfileStore::secret_backend_security() const noexcept {
  return impl_->secrets->security();
}

Result<IdentityKeyPair> ProfileStore::load_identity() const {
  auto secret = impl_->secrets->load(SecretHandle{impl_->secret_handle});
  if (!secret) {
    return Result<IdentityKeyPair>::failure(*secret.error_if());
  }
  auto identity = import_identity(impl_->public_key, *secret.value_if());
  sodium_memzero(secret.value_if()->data(), secret.value_if()->size());
  if (!identity || identity.value_if()->device_id() != impl_->device_id) {
    return Result<IdentityKeyPair>::failure(
        Error{ErrorCode::identity, "profile", "stored_identity_mismatch"});
  }
  return identity;
}

Result<EndpointId> ProfileStore::endpoint_for(std::string_view application_id) {
  if (!valid_application_id(application_id)) {
    return Result<EndpointId>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_application_id"});
  }
  auto select = prepare(impl_->database,
                        "SELECT endpoint_id FROM endpoint_records WHERE application_id=?");
  if (!select) {
    return Result<EndpointId>::failure(*select.error_if());
  }
  sqlite3_bind_text(select.value_if()->get(), 1, application_id.data(),
                    static_cast<int>(application_id.size()), SQLITE_TRANSIENT);
  const int selected = sqlite3_step(select.value_if()->get());
  if (selected == SQLITE_ROW) {
    return column_id<EndpointId>(select.value_if()->get(), 0, "endpoint_id_invalid");
  }
  if (selected != SQLITE_DONE) {
    return Result<EndpointId>::failure(sqlite_error(impl_->database, "endpoint_query_failed"));
  }

  EndpointId::Storage bytes{};
  randombytes_buf(bytes.data(), bytes.size());
  const EndpointId endpoint{bytes};
  auto insert = prepare(impl_->database,
                        "INSERT INTO endpoint_records(application_id, endpoint_id, "
                        "created_unix_milliseconds) VALUES(?, ?, ?) "
                        "ON CONFLICT(application_id) DO NOTHING");
  if (!insert) {
    return Result<EndpointId>::failure(*insert.error_if());
  }
  sqlite3_bind_text(insert.value_if()->get(), 1, application_id.data(),
                    static_cast<int>(application_id.size()), SQLITE_TRANSIENT);
  bind_id(insert.value_if()->get(), 2, endpoint);
  sqlite3_bind_int64(insert.value_if()->get(), 3,
                     static_cast<sqlite3_int64>(current_unix_milliseconds()));
  const auto inserted = step_done(*insert.value_if());
  if (!inserted) {
    return Result<EndpointId>::failure(*inserted.error_if());
  }
  return endpoint_for(application_id);
}

Result<void> ProfileStore::set_password_verifier(const PasswordVerifier& verifier,
                                                 std::uint64_t password_generation) {
  if (password_generation == 0U || verifier.encoded.empty()) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_password_verifier"});
  }
  auto statement = prepare(
      impl_->database,
      "INSERT INTO password_verifier(singleton, format_version, encoded, operations, "
      "memory_bytes, password_generation) VALUES(1, ?, ?, ?, ?, ?) "
      "ON CONFLICT(singleton) DO UPDATE SET format_version=excluded.format_version, "
      "encoded=excluded.encoded, operations=excluded.operations, "
      "memory_bytes=excluded.memory_bytes, password_generation=excluded.password_generation");
  if (!statement) {
    return Result<void>::failure(*statement.error_if());
  }
  sqlite3_bind_int(statement.value_if()->get(), 1, verifier.format_version);
  sqlite3_bind_text(statement.value_if()->get(), 2, verifier.encoded.c_str(), -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_int64(statement.value_if()->get(), 3,
                     static_cast<sqlite3_int64>(verifier.parameters.operations));
  sqlite3_bind_int64(statement.value_if()->get(), 4,
                     static_cast<sqlite3_int64>(verifier.parameters.memory_bytes));
  sqlite3_bind_int64(statement.value_if()->get(), 5,
                     static_cast<sqlite3_int64>(password_generation));
  return step_done(*statement.value_if());
}

Result<std::optional<PasswordVerifier>> ProfileStore::password_verifier() const {
  auto statement = prepare(impl_->database,
                           "SELECT format_version, encoded, operations, memory_bytes "
                           "FROM password_verifier WHERE singleton=1");
  if (!statement) {
    return Result<std::optional<PasswordVerifier>>::failure(*statement.error_if());
  }
  const int result = sqlite3_step(statement.value_if()->get());
  if (result == SQLITE_DONE) {
    return Result<std::optional<PasswordVerifier>>::success(std::nullopt);
  }
  if (result != SQLITE_ROW) {
    return Result<std::optional<PasswordVerifier>>::failure(
        sqlite_error(impl_->database, "password_verifier_query_failed"));
  }
  const auto* encoded = reinterpret_cast<const char*>(
      sqlite3_column_text(statement.value_if()->get(), 1));
  if (encoded == nullptr) {
    return Result<std::optional<PasswordVerifier>>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "password_verifier_invalid"});
  }
  PasswordVerifier verifier{
      .format_version = static_cast<std::uint16_t>(
          sqlite3_column_int(statement.value_if()->get(), 0)),
      .parameters = PasswordHashParameters{
          .operations = static_cast<std::uint64_t>(
              sqlite3_column_int64(statement.value_if()->get(), 2)),
          .memory_bytes = static_cast<std::size_t>(
              sqlite3_column_int64(statement.value_if()->get(), 3))},
      .encoded = encoded};
  return Result<std::optional<PasswordVerifier>>::success(std::move(verifier));
}

Result<std::uint64_t> ProfileStore::password_generation() const {
  auto statement = prepare(impl_->database,
                           "SELECT password_generation FROM password_verifier WHERE singleton=1");
  if (!statement) {
    return Result<std::uint64_t>::failure(*statement.error_if());
  }
  const int result = sqlite3_step(statement.value_if()->get());
  if (result == SQLITE_DONE) {
    return Result<std::uint64_t>::success(0U);
  }
  if (result != SQLITE_ROW || sqlite3_column_int64(statement.value_if()->get(), 0) < 0) {
    return Result<std::uint64_t>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "password_generation_invalid"});
  }
  return Result<std::uint64_t>::success(
      static_cast<std::uint64_t>(sqlite3_column_int64(statement.value_if()->get(), 0)));
}

Result<void> ProfileStore::put_trust_grant(const TrustGrantRecord& input_grant) {
  TrustGrantRecord grant = input_grant;
  if (grant.grant_id.is_zero() || grant.issuer.is_zero() || grant.subject.is_zero() ||
      grant.password_generation == 0U || grant.issued_unix_milliseconds == 0U ||
      grant.signature.empty() || grant.signature.size() > 4096U || grant.scopes.empty() ||
      grant.scopes.size() > 256U) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_trust_grant"});
  }
  std::sort(grant.scopes.begin(), grant.scopes.end());
  grant.scopes.erase(std::unique(grant.scopes.begin(), grant.scopes.end()), grant.scopes.end());
  if (!std::all_of(grant.scopes.begin(), grant.scopes.end(), valid_scope)) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_trust_scope"});
  }
  auto begin = execute(impl_->database, "BEGIN IMMEDIATE");
  if (!begin) {
    return begin;
  }
  profile_fault_injection_point("trust_grant.after_begin");
  auto statement = prepare(
      impl_->database,
      "INSERT INTO trust_grants(grant_id, direction, issuer_device_id, subject_device_id, "
      "password_generation, issued_unix_milliseconds, expires_unix_milliseconds, signature, "
      "revoked) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT(grant_id) DO UPDATE SET direction=excluded.direction, "
      "issuer_device_id=excluded.issuer_device_id, subject_device_id=excluded.subject_device_id, "
      "password_generation=excluded.password_generation, "
      "issued_unix_milliseconds=excluded.issued_unix_milliseconds, "
      "expires_unix_milliseconds=excluded.expires_unix_milliseconds, "
      "signature=excluded.signature, revoked=excluded.revoked");
  if (!statement) {
    (void)execute(impl_->database, "ROLLBACK");
    return Result<void>::failure(*statement.error_if());
  }
  bind_id(statement.value_if()->get(), 1, grant.grant_id);
  sqlite3_bind_int(statement.value_if()->get(), 2, static_cast<int>(grant.direction));
  bind_id(statement.value_if()->get(), 3, grant.issuer);
  bind_id(statement.value_if()->get(), 4, grant.subject);
  sqlite3_bind_int64(statement.value_if()->get(), 5,
                     static_cast<sqlite3_int64>(grant.password_generation));
  sqlite3_bind_int64(statement.value_if()->get(), 6,
                     static_cast<sqlite3_int64>(grant.issued_unix_milliseconds));
  if (grant.expires_unix_milliseconds) {
    sqlite3_bind_int64(statement.value_if()->get(), 7,
                       static_cast<sqlite3_int64>(*grant.expires_unix_milliseconds));
  } else {
    sqlite3_bind_null(statement.value_if()->get(), 7);
  }
  sqlite3_bind_blob(statement.value_if()->get(), 8, grant.signature.data(),
                    static_cast<int>(grant.signature.size()), SQLITE_TRANSIENT);
  sqlite3_bind_int(statement.value_if()->get(), 9, grant.revoked ? 1 : 0);
  auto written = step_done(*statement.value_if());
  if (!written) {
    (void)execute(impl_->database, "ROLLBACK");
    return written;
  }
  profile_fault_injection_point("trust_grant.after_grant");
  auto delete_scopes = prepare(impl_->database, "DELETE FROM trust_grant_scopes WHERE grant_id=?");
  if (!delete_scopes) {
    (void)execute(impl_->database, "ROLLBACK");
    return Result<void>::failure(*delete_scopes.error_if());
  }
  bind_id(delete_scopes.value_if()->get(), 1, grant.grant_id);
  written = step_done(*delete_scopes.value_if());
  if (!written) {
    (void)execute(impl_->database, "ROLLBACK");
    return written;
  }
  profile_fault_injection_point("trust_grant.after_scope_delete");
  std::size_t scope_index = 0U;
  for (const auto& scope : grant.scopes) {
    auto insert_scope = prepare(
        impl_->database, "INSERT INTO trust_grant_scopes(grant_id, scope) VALUES(?, ?)");
    if (!insert_scope) {
      (void)execute(impl_->database, "ROLLBACK");
      return Result<void>::failure(*insert_scope.error_if());
    }
    bind_id(insert_scope.value_if()->get(), 1, grant.grant_id);
    sqlite3_bind_text(insert_scope.value_if()->get(), 2, scope.c_str(), -1, SQLITE_TRANSIENT);
    written = step_done(*insert_scope.value_if());
    if (!written) {
      (void)execute(impl_->database, "ROLLBACK");
      return written;
    }
    ++scope_index;
    profile_scope_fault_injection_point(scope_index);
  }
  profile_fault_injection_point("trust_grant.before_commit");
  const auto committed = execute(impl_->database, "COMMIT");
  if (!committed) {
    (void)execute(impl_->database, "ROLLBACK");
  }
  if (committed) {
    profile_fault_injection_point("trust_grant.after_commit");
  }
  return committed;
}

Result<std::optional<TrustGrantRecord>> ProfileStore::trust_grant(
    const GrantId& grant_id) const {
  auto statement = prepare(
      impl_->database,
      "SELECT direction, issuer_device_id, subject_device_id, password_generation, "
      "issued_unix_milliseconds, expires_unix_milliseconds, signature, revoked "
      "FROM trust_grants WHERE grant_id=?");
  if (!statement) {
    return Result<std::optional<TrustGrantRecord>>::failure(*statement.error_if());
  }
  bind_id(statement.value_if()->get(), 1, grant_id);
  const int result = sqlite3_step(statement.value_if()->get());
  if (result == SQLITE_DONE) {
    return Result<std::optional<TrustGrantRecord>>::success(std::nullopt);
  }
  if (result != SQLITE_ROW) {
    return Result<std::optional<TrustGrantRecord>>::failure(
        sqlite_error(impl_->database, "trust_grant_query_failed"));
  }
  auto issuer = column_id<DeviceId>(statement.value_if()->get(), 1, "trust_issuer_invalid");
  auto subject = column_id<DeviceId>(statement.value_if()->get(), 2, "trust_subject_invalid");
  if (!issuer || !subject) {
    return Result<std::optional<TrustGrantRecord>>::failure(
        !issuer ? *issuer.error_if() : *subject.error_if());
  }
  TrustGrantRecord grant;
  grant.grant_id = grant_id;
  grant.direction = static_cast<TrustGrantDirection>(
      sqlite3_column_int(statement.value_if()->get(), 0));
  grant.issuer = *issuer.value_if();
  grant.subject = *subject.value_if();
  grant.password_generation = static_cast<std::uint64_t>(
      sqlite3_column_int64(statement.value_if()->get(), 3));
  grant.issued_unix_milliseconds = static_cast<std::uint64_t>(
      sqlite3_column_int64(statement.value_if()->get(), 4));
  if (sqlite3_column_type(statement.value_if()->get(), 5) != SQLITE_NULL) {
    grant.expires_unix_milliseconds = static_cast<std::uint64_t>(
        sqlite3_column_int64(statement.value_if()->get(), 5));
  }
  const auto* signature = static_cast<const std::byte*>(
      sqlite3_column_blob(statement.value_if()->get(), 6));
  const int signature_size = sqlite3_column_bytes(statement.value_if()->get(), 6);
  if (signature == nullptr || signature_size <= 0) {
    return Result<std::optional<TrustGrantRecord>>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "trust_signature_invalid"});
  }
  grant.signature.assign(signature, signature + signature_size);
  grant.revoked = sqlite3_column_int(statement.value_if()->get(), 7) != 0;

  auto scopes = prepare(
      impl_->database, "SELECT scope FROM trust_grant_scopes WHERE grant_id=? ORDER BY scope");
  if (!scopes) {
    return Result<std::optional<TrustGrantRecord>>::failure(*scopes.error_if());
  }
  bind_id(scopes.value_if()->get(), 1, grant_id);
  while (true) {
    const int scope_result = sqlite3_step(scopes.value_if()->get());
    if (scope_result == SQLITE_DONE) {
      break;
    }
    if (scope_result != SQLITE_ROW) {
      return Result<std::optional<TrustGrantRecord>>::failure(
          sqlite_error(impl_->database, "trust_scope_query_failed"));
    }
    const auto* scope = reinterpret_cast<const char*>(
        sqlite3_column_text(scopes.value_if()->get(), 0));
    if (scope == nullptr || !valid_scope(scope)) {
      return Result<std::optional<TrustGrantRecord>>::failure(
          Error{ErrorCode::profile_corrupt, "profile", "trust_scope_invalid"});
    }
    grant.scopes.emplace_back(scope);
  }
  return Result<std::optional<TrustGrantRecord>>::success(std::move(grant));
}

Result<void> ProfileStore::revoke_trust_grant(const GrantId& grant_id,
                                              std::uint64_t revoked_unix_milliseconds) {
  auto statement = prepare(
      impl_->database,
      "UPDATE trust_grants SET revoked=1, revoked_unix_milliseconds=? WHERE grant_id=?");
  if (!statement) {
    return Result<void>::failure(*statement.error_if());
  }
  sqlite3_bind_int64(statement.value_if()->get(), 1,
                     static_cast<sqlite3_int64>(revoked_unix_milliseconds));
  bind_id(statement.value_if()->get(), 2, grant_id);
  const auto result = step_done(*statement.value_if());
  if (!result) {
    return result;
  }
  if (sqlite3_changes(impl_->database) == 0) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "profile", "trust_grant_not_found"});
  }
  return Result<void>::success();
}

Result<bool> ProfileStore::is_scope_authorized(const DeviceId& peer, std::string_view scope,
                                               std::uint64_t now_unix_milliseconds) const {
  if (!valid_scope(scope)) {
    return Result<bool>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_trust_scope"});
  }
  auto generation = password_generation();
  if (!generation) {
    return Result<bool>::failure(*generation.error_if());
  }
  auto statement = prepare(
      impl_->database,
      "SELECT 1 FROM trust_grants g JOIN trust_grant_scopes s ON s.grant_id=g.grant_id "
      "WHERE g.direction=1 AND g.issuer_device_id=? AND g.subject_device_id=? "
      "AND g.revoked=0 AND g.password_generation=? AND s.scope=? "
      "AND (g.expires_unix_milliseconds IS NULL OR g.expires_unix_milliseconds>?) LIMIT 1");
  if (!statement) {
    return Result<bool>::failure(*statement.error_if());
  }
  bind_id(statement.value_if()->get(), 1, impl_->device_id);
  bind_id(statement.value_if()->get(), 2, peer);
  sqlite3_bind_int64(statement.value_if()->get(), 3,
                     static_cast<sqlite3_int64>(*generation.value_if()));
  sqlite3_bind_text(statement.value_if()->get(), 4, scope.data(),
                    static_cast<int>(scope.size()), SQLITE_TRANSIENT);
  sqlite3_bind_int64(statement.value_if()->get(), 5,
                     static_cast<sqlite3_int64>(now_unix_milliseconds));
  const int result = sqlite3_step(statement.value_if()->get());
  if (result == SQLITE_ROW) {
    return Result<bool>::success(true);
  }
  if (result == SQLITE_DONE) {
    return Result<bool>::success(false);
  }
  return Result<bool>::failure(sqlite_error(impl_->database, "trust_authorization_failed"));
}

Result<void> ProfileStore::mark_relay_revoked(std::string_view relay_url,
                                              std::uint64_t enrollment_generation) {
  if (relay_url.empty() || relay_url.size() > 2048U || enrollment_generation == 0U) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_relay_revocation"});
  }
  auto statement = prepare(
      impl_->database,
      "INSERT INTO relay_enrollments(relay_url, enrollment_generation, revoked, "
      "updated_unix_milliseconds) VALUES(?, ?, 1, ?) "
      "ON CONFLICT(relay_url) DO UPDATE SET enrollment_generation=excluded.enrollment_generation, "
      "revoked=1, updated_unix_milliseconds=excluded.updated_unix_milliseconds");
  if (!statement) {
    return Result<void>::failure(*statement.error_if());
  }
  sqlite3_bind_text(statement.value_if()->get(), 1, relay_url.data(),
                    static_cast<int>(relay_url.size()), SQLITE_TRANSIENT);
  sqlite3_bind_int64(statement.value_if()->get(), 2,
                     static_cast<sqlite3_int64>(enrollment_generation));
  sqlite3_bind_int64(statement.value_if()->get(), 3,
                     static_cast<sqlite3_int64>(current_unix_milliseconds()));
  return step_done(*statement.value_if());
}

Result<void> ProfileStore::export_to(const std::filesystem::path& destination) const {
  const auto directory = ensure_private_directory(parent_directory_for(destination));
  if (!directory) {
    return directory;
  }
  const auto temporary = destination.string() + ".tmp." + random_suffix();
  const auto destination_secrets = secret_root_for(destination);
  std::error_code existence_error;
  const bool destination_exists = std::filesystem::exists(destination, existence_error);
  if (existence_error) {
    return Result<void>::failure(filesystem_error("profile_export_stat_failed", existence_error));
  }
  const bool destination_secrets_exist =
      std::filesystem::exists(destination_secrets, existence_error);
  if (existence_error) {
    return Result<void>::failure(filesystem_error("profile_export_stat_failed", existence_error));
  }
  if (destination_exists || destination_secrets_exist) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "profile", "profile_export_exists"});
  }

  auto identity = load_identity();
  if (!identity) {
    return Result<void>::failure(*identity.error_if());
  }
  SecretBackendOptions secret_options;
  const bool source_uses_os_backend =
      impl_->secrets->security() == SecretBackendSecurity::os_protected;
  secret_options.prefer_os_backend = source_uses_os_backend;
  secret_options.allow_encrypted_file_fallback = !source_uses_os_backend;
  auto destination_backend = open_default_secret_backend(destination_secrets, secret_options);
  if (!destination_backend) {
    return Result<void>::failure(*destination_backend.error_if());
  }
  auto destination_handle =
      (*destination_backend.value_if())->store("identity-ed25519",
                                               identity.value_if()->secret_key());
  if (!destination_handle) {
    (void)(*destination_backend.value_if())->erase_all();
    std::error_code ignored;
    std::filesystem::remove_all(destination_secrets, ignored);
    return Result<void>::failure(*destination_handle.error_if());
  }
  const auto cleanup = [&]() {
    (void)(*destination_backend.value_if())->erase_all();
    std::error_code ignored;
    std::filesystem::remove_all(destination_secrets, ignored);
    remove_database_artifacts(temporary);
  };

  sqlite3* output = nullptr;
  const int opened = sqlite3_open_v2(temporary.c_str(), &output,
                                     SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
  if (opened != SQLITE_OK) {
    const auto error = sqlite_error(output, "profile_export_open_failed", opened);
    if (output != nullptr) {
      sqlite3_close_v2(output);
    }
    cleanup();
    return Result<void>::failure(error);
  }
  const auto configured = execute(output, "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;");
  if (!configured) {
    sqlite3_close_v2(output);
    cleanup();
    return configured;
  }
  sqlite3_backup* backup = sqlite3_backup_init(output, "main", impl_->database, "main");
  if (backup == nullptr) {
    const auto error = sqlite_error(output, "profile_export_backup_failed");
    sqlite3_close_v2(output);
    cleanup();
    return Result<void>::failure(error);
  }
  const int copied = sqlite3_backup_step(backup, -1);
  const int finished = sqlite3_backup_finish(backup);
  if (copied != SQLITE_DONE || finished != SQLITE_OK) {
    sqlite3_close_v2(output);
    cleanup();
    return Result<void>::failure(
        Error{ErrorCode::storage, "profile", "profile_export_backup_failed"});
  }

  std::optional<Error> update_error;
  {
    auto update = prepare(output, "UPDATE identity SET secret_handle=? WHERE singleton=1");
    if (!update) {
      update_error = *update.error_if();
    } else {
      sqlite3_bind_text(update.value_if()->get(), 1,
                        destination_handle.value_if()->value.c_str(), -1, SQLITE_TRANSIENT);
      const auto updated = step_done(*update.value_if());
      if (!updated || sqlite3_changes(output) != 1) {
        update_error =
            updated ? Error{ErrorCode::profile_corrupt, "profile", "identity_not_initialized"}
                    : *updated.error_if();
      }
    }
  }
  if (update_error) {
    sqlite3_close_v2(output);
    cleanup();
    return Result<void>::failure(std::move(*update_error));
  }
  const int closed = sqlite3_close_v2(output);
  if (closed != SQLITE_OK) {
    cleanup();
    return Result<void>::failure(
        Error{ErrorCode::storage, "profile", "profile_export_close_failed", closed});
  }
  const auto permissions = set_private_file_permissions(temporary);
  if (!permissions) {
    cleanup();
    return permissions;
  }
  const auto verified = verify_database_file(temporary, static_cast<int>(profile_schema_version));
  if (!verified) {
    cleanup();
    return verified;
  }
  const auto replaced = atomic_replace_file(temporary, destination);
  if (!replaced) {
    cleanup();
    return replaced;
  }
  remove_database_artifacts(temporary);
  return Result<void>::success();
}

}  // namespace heyaki
