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
  [[maybe_unused]] const bool existed = std::filesystem::exists(path, error);
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

bool valid_relay_enrollment_url(std::string_view value) noexcept {
  if (value.empty() || value.size() > 2048U ||
      (!value.starts_with("wss://") && !value.starts_with("https://"))) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](char raw) {
    const auto character = static_cast<unsigned char>(raw);
    return character >= 0x21U && character <= 0x7eU;
  });
}

bool valid_relay_tenant(std::string_view value) noexcept {
  if (value.empty() || value.size() > 128U) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](char raw) {
    const auto character = static_cast<unsigned char>(raw);
    return character >= 0x21U && character <= 0x7eU;
  });
}

bool valid_scope(std::string_view value) noexcept {
  if (value.empty() || value.size() > 256U) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](unsigned char character) {
    return character >= 0x21U && character <= 0x7eU;
  });
}

bool valid_interface_preference(std::string_view value) noexcept {
  if (value.empty() || value.size() > 128U || value.front() == ' ' || value.back() == ' ') {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](unsigned char character) {
    return character >= 0x20U && character <= 0x7eU;
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

const char* migration_v3 = R"SQL(
CREATE TABLE lan_configuration(
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  connectivity_mode INTEGER NOT NULL CHECK(connectivity_mode IN (1, 2, 3)),
  enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
  discoverable INTEGER NOT NULL CHECK(discoverable IN (0, 1)),
  auto_connect_trusted INTEGER NOT NULL CHECK(auto_connect_trusted IN (0, 1)),
  interface_capacity INTEGER NOT NULL CHECK(interface_capacity > 0),
  directory_capacity INTEGER NOT NULL CHECK(directory_capacity > 0),
  trusted_directory_reserve INTEGER NOT NULL CHECK(trusted_directory_reserve > 0),
  per_interface_directory_capacity INTEGER NOT NULL CHECK(per_interface_directory_capacity > 0),
  per_source_presence_capacity INTEGER NOT NULL CHECK(per_source_presence_capacity > 0),
  unknown_identity_capacity INTEGER NOT NULL CHECK(unknown_identity_capacity > 0),
  replay_capacity INTEGER NOT NULL CHECK(replay_capacity > 0),
  diagnostic_capacity INTEGER NOT NULL CHECK(diagnostic_capacity > 0),
  provisional_connection_capacity INTEGER NOT NULL CHECK(provisional_connection_capacity > 0),
  per_source_provisional_capacity INTEGER NOT NULL CHECK(per_source_provisional_capacity > 0),
  provisional_accept_rate_per_second INTEGER NOT NULL
    CHECK(provisional_accept_rate_per_second > 0),
  per_source_provisional_rate INTEGER NOT NULL CHECK(per_source_provisional_rate > 0),
  pending_signaling_capacity INTEGER NOT NULL CHECK(pending_signaling_capacity > 0),
  auto_connect_capacity INTEGER NOT NULL CHECK(auto_connect_capacity > 0),
  announcement_rate_per_second INTEGER NOT NULL CHECK(announcement_rate_per_second > 0),
  per_source_announcement_rate INTEGER NOT NULL CHECK(per_source_announcement_rate > 0),
  announcement_interval_ms INTEGER NOT NULL CHECK(announcement_interval_ms > 0),
  presence_lease_ms INTEGER NOT NULL CHECK(presence_lease_ms > 0),
  announcement_jitter_ms INTEGER NOT NULL CHECK(announcement_jitter_ms >= 0),
  interface_refresh_interval_ms INTEGER NOT NULL CHECK(interface_refresh_interval_ms > 0),
  handshake_timeout_ms INTEGER NOT NULL CHECK(handshake_timeout_ms > 0),
  hello_timeout_ms INTEGER NOT NULL CHECK(hello_timeout_ms > 0),
  route_preference_delay_ms INTEGER NOT NULL CHECK(route_preference_delay_ms >= 0),
  shutdown_timeout_ms INTEGER NOT NULL CHECK(shutdown_timeout_ms > 0),
  updated_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE lan_interface_preferences(
  ordinal INTEGER PRIMARY KEY CHECK(ordinal >= 0),
  interface_name TEXT NOT NULL UNIQUE
);
CREATE TABLE pairing_policy(
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  generation INTEGER NOT NULL CHECK(generation > 0),
  password_pairing_enabled INTEGER NOT NULL CHECK(password_pairing_enabled IN (0, 1)),
  require_manual_approval_unknown INTEGER NOT NULL
    CHECK(require_manual_approval_unknown IN (0, 1)),
  updated_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE pairing_policy_scopes(
  scope TEXT PRIMARY KEY
);
INSERT INTO lan_configuration(
  singleton, connectivity_mode, enabled, discoverable, auto_connect_trusted,
  interface_capacity, directory_capacity, trusted_directory_reserve,
  per_interface_directory_capacity, per_source_presence_capacity,
  unknown_identity_capacity, replay_capacity, diagnostic_capacity,
  provisional_connection_capacity, per_source_provisional_capacity,
  provisional_accept_rate_per_second, per_source_provisional_rate,
  pending_signaling_capacity, auto_connect_capacity, announcement_rate_per_second,
  per_source_announcement_rate, announcement_interval_ms, presence_lease_ms,
  announcement_jitter_ms, interface_refresh_interval_ms, handshake_timeout_ms,
  hello_timeout_ms, route_preference_delay_ms, shutdown_timeout_ms,
  updated_unix_milliseconds)
VALUES(1, 1, 1, 1, 0, 32, 4096, 128, 1024, 64, 512, 8192, 1024, 64, 8,
       64, 16, 128, 16, 32, 8, 5000, 15000, 500, 5000, 5000, 3000, 250, 2000,
       CAST(unixepoch('subsec') * 1000 AS INTEGER));
INSERT INTO pairing_policy(
  singleton, generation, password_pairing_enabled, require_manual_approval_unknown,
  updated_unix_milliseconds)
VALUES(1, 1, 1, 1, CAST(unixepoch('subsec') * 1000 AS INTEGER));
INSERT INTO schema_migrations(version, applied_unix_milliseconds)
VALUES(3, CAST(unixepoch('subsec') * 1000 AS INTEGER));
PRAGMA user_version=3;
)SQL";

std::uint64_t current_unix_milliseconds();

Result<void> write_lan_configuration(sqlite3* database,
                                     const LanConfiguration& configuration) {
  auto statement = prepare(
      database,
      "INSERT INTO lan_configuration("
      "singleton, connectivity_mode, enabled, discoverable, auto_connect_trusted, "
      "interface_capacity, directory_capacity, trusted_directory_reserve, "
      "per_interface_directory_capacity, per_source_presence_capacity, "
      "unknown_identity_capacity, replay_capacity, diagnostic_capacity, "
      "provisional_connection_capacity, per_source_provisional_capacity, "
      "provisional_accept_rate_per_second, per_source_provisional_rate, "
      "pending_signaling_capacity, auto_connect_capacity, announcement_rate_per_second, "
      "per_source_announcement_rate, announcement_interval_ms, presence_lease_ms, "
      "announcement_jitter_ms, interface_refresh_interval_ms, handshake_timeout_ms, "
      "hello_timeout_ms, route_preference_delay_ms, shutdown_timeout_ms, "
      "updated_unix_milliseconds) "
      "VALUES(1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
      "?, ?, ?, ?, ?) ON CONFLICT(singleton) DO UPDATE SET "
      "connectivity_mode=excluded.connectivity_mode, enabled=excluded.enabled, "
      "discoverable=excluded.discoverable, auto_connect_trusted=excluded.auto_connect_trusted, "
      "interface_capacity=excluded.interface_capacity, "
      "directory_capacity=excluded.directory_capacity, "
      "trusted_directory_reserve=excluded.trusted_directory_reserve, "
      "per_interface_directory_capacity=excluded.per_interface_directory_capacity, "
      "per_source_presence_capacity=excluded.per_source_presence_capacity, "
      "unknown_identity_capacity=excluded.unknown_identity_capacity, "
      "replay_capacity=excluded.replay_capacity, diagnostic_capacity=excluded.diagnostic_capacity, "
      "provisional_connection_capacity=excluded.provisional_connection_capacity, "
      "per_source_provisional_capacity=excluded.per_source_provisional_capacity, "
      "provisional_accept_rate_per_second=excluded.provisional_accept_rate_per_second, "
      "per_source_provisional_rate=excluded.per_source_provisional_rate, "
      "pending_signaling_capacity=excluded.pending_signaling_capacity, "
      "auto_connect_capacity=excluded.auto_connect_capacity, "
      "announcement_rate_per_second=excluded.announcement_rate_per_second, "
      "per_source_announcement_rate=excluded.per_source_announcement_rate, "
      "announcement_interval_ms=excluded.announcement_interval_ms, "
      "presence_lease_ms=excluded.presence_lease_ms, "
      "announcement_jitter_ms=excluded.announcement_jitter_ms, "
      "interface_refresh_interval_ms=excluded.interface_refresh_interval_ms, "
      "handshake_timeout_ms=excluded.handshake_timeout_ms, "
      "hello_timeout_ms=excluded.hello_timeout_ms, "
      "route_preference_delay_ms=excluded.route_preference_delay_ms, "
      "shutdown_timeout_ms=excluded.shutdown_timeout_ms, "
      "updated_unix_milliseconds=excluded.updated_unix_milliseconds");
  if (!statement) {
    return Result<void>::failure(*statement.error_if());
  }
  int index = 1;
  sqlite3_bind_int(statement.value_if()->get(), index++,
                   static_cast<int>(configuration.connectivity_mode));
  sqlite3_bind_int(statement.value_if()->get(), index++, configuration.enabled ? 1 : 0);
  sqlite3_bind_int(statement.value_if()->get(), index++, configuration.discoverable ? 1 : 0);
  sqlite3_bind_int(statement.value_if()->get(), index++,
                   configuration.auto_connect_trusted ? 1 : 0);
  const auto bind_size = [&](std::size_t value) {
    sqlite3_bind_int64(statement.value_if()->get(), index++,
                       static_cast<sqlite3_int64>(value));
  };
  bind_size(configuration.interface_capacity);
  bind_size(configuration.directory_capacity);
  bind_size(configuration.trusted_directory_reserve);
  bind_size(configuration.per_interface_directory_capacity);
  bind_size(configuration.per_source_presence_capacity);
  bind_size(configuration.unknown_identity_capacity);
  bind_size(configuration.replay_capacity);
  bind_size(configuration.diagnostic_capacity);
  bind_size(configuration.provisional_connection_capacity);
  bind_size(configuration.per_source_provisional_capacity);
  bind_size(configuration.provisional_accept_rate_per_second);
  bind_size(configuration.per_source_provisional_rate);
  bind_size(configuration.pending_signaling_capacity);
  bind_size(configuration.auto_connect_capacity);
  bind_size(configuration.announcement_rate_per_second);
  bind_size(configuration.per_source_announcement_rate);
  const auto bind_duration = [&](std::chrono::milliseconds value) {
    sqlite3_bind_int64(statement.value_if()->get(), index++,
                       static_cast<sqlite3_int64>(value.count()));
  };
  bind_duration(configuration.announcement_interval);
  bind_duration(configuration.presence_lease);
  bind_duration(configuration.announcement_jitter);
  bind_duration(configuration.interface_refresh_interval);
  bind_duration(configuration.handshake_timeout);
  bind_duration(configuration.hello_timeout);
  bind_duration(configuration.route_preference_delay);
  bind_duration(configuration.shutdown_timeout);
  sqlite3_bind_int64(statement.value_if()->get(), index,
                     static_cast<sqlite3_int64>(current_unix_milliseconds()));
  auto written = step_done(*statement.value_if());
  if (!written) {
    return written;
  }

  written = execute(database, "DELETE FROM lan_interface_preferences");
  if (!written) {
    return written;
  }
  auto insert = prepare(
      database,
      "INSERT INTO lan_interface_preferences(ordinal, interface_name) VALUES(?, ?)");
  if (!insert) {
    return Result<void>::failure(*insert.error_if());
  }
  for (std::size_t ordinal = 0U; ordinal < configuration.interface_preferences.size(); ++ordinal) {
    sqlite3_reset(insert.value_if()->get());
    sqlite3_clear_bindings(insert.value_if()->get());
    sqlite3_bind_int64(insert.value_if()->get(), 1, static_cast<sqlite3_int64>(ordinal));
    const auto& name = configuration.interface_preferences[ordinal];
    sqlite3_bind_text(insert.value_if()->get(), 2, name.data(), static_cast<int>(name.size()),
                      SQLITE_TRANSIENT);
    written = step_done(*insert.value_if());
    if (!written) {
      return written;
    }
  }
  return Result<void>::success();
}

Result<LanConfiguration> read_lan_configuration(sqlite3* database) {
  auto statement = prepare(
      database,
      "SELECT connectivity_mode, enabled, discoverable, auto_connect_trusted, "
      "interface_capacity, directory_capacity, trusted_directory_reserve, "
      "per_interface_directory_capacity, per_source_presence_capacity, "
      "unknown_identity_capacity, replay_capacity, diagnostic_capacity, "
      "provisional_connection_capacity, per_source_provisional_capacity, "
      "provisional_accept_rate_per_second, per_source_provisional_rate, "
      "pending_signaling_capacity, auto_connect_capacity, announcement_rate_per_second, "
      "per_source_announcement_rate, announcement_interval_ms, presence_lease_ms, "
      "announcement_jitter_ms, interface_refresh_interval_ms, handshake_timeout_ms, "
      "hello_timeout_ms, route_preference_delay_ms, shutdown_timeout_ms "
      "FROM lan_configuration WHERE singleton=1");
  if (!statement) {
    return Result<LanConfiguration>::failure(*statement.error_if());
  }
  if (sqlite3_step(statement.value_if()->get()) != SQLITE_ROW) {
    return Result<LanConfiguration>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "lan_configuration_missing"});
  }
  LanConfiguration configuration;
  configuration.connectivity_mode =
      static_cast<ConnectivityMode>(sqlite3_column_int(statement.value_if()->get(), 0));
  configuration.enabled = sqlite3_column_int(statement.value_if()->get(), 1) != 0;
  configuration.discoverable = sqlite3_column_int(statement.value_if()->get(), 2) != 0;
  configuration.auto_connect_trusted = sqlite3_column_int(statement.value_if()->get(), 3) != 0;
  const auto column_size = [&](int column) {
    return static_cast<std::size_t>(sqlite3_column_int64(statement.value_if()->get(), column));
  };
  configuration.interface_capacity = column_size(4);
  configuration.directory_capacity = column_size(5);
  configuration.trusted_directory_reserve = column_size(6);
  configuration.per_interface_directory_capacity = column_size(7);
  configuration.per_source_presence_capacity = column_size(8);
  configuration.unknown_identity_capacity = column_size(9);
  configuration.replay_capacity = column_size(10);
  configuration.diagnostic_capacity = column_size(11);
  configuration.provisional_connection_capacity = column_size(12);
  configuration.per_source_provisional_capacity = column_size(13);
  configuration.provisional_accept_rate_per_second = column_size(14);
  configuration.per_source_provisional_rate = column_size(15);
  configuration.pending_signaling_capacity = column_size(16);
  configuration.auto_connect_capacity = column_size(17);
  configuration.announcement_rate_per_second = column_size(18);
  configuration.per_source_announcement_rate = column_size(19);
  const auto column_duration = [&](int column) {
    return std::chrono::milliseconds{sqlite3_column_int64(statement.value_if()->get(), column)};
  };
  configuration.announcement_interval = column_duration(20);
  configuration.presence_lease = column_duration(21);
  configuration.announcement_jitter = column_duration(22);
  configuration.interface_refresh_interval = column_duration(23);
  configuration.handshake_timeout = column_duration(24);
  configuration.hello_timeout = column_duration(25);
  configuration.route_preference_delay = column_duration(26);
  configuration.shutdown_timeout = column_duration(27);

  auto interfaces = prepare(
      database,
      "SELECT interface_name FROM lan_interface_preferences ORDER BY ordinal ASC");
  if (!interfaces) {
    return Result<LanConfiguration>::failure(*interfaces.error_if());
  }
  while (true) {
    const int result = sqlite3_step(interfaces.value_if()->get());
    if (result == SQLITE_DONE) {
      break;
    }
    if (result != SQLITE_ROW) {
      return Result<LanConfiguration>::failure(
          sqlite_error(database, "lan_interface_preferences_query_failed"));
    }
    const auto* name = reinterpret_cast<const char*>(
        sqlite3_column_text(interfaces.value_if()->get(), 0));
    if (name == nullptr) {
      return Result<LanConfiguration>::failure(
          Error{ErrorCode::profile_corrupt, "profile", "lan_interface_preference_invalid"});
    }
    configuration.interface_preferences.emplace_back(name);
  }
  auto valid = validate_lan_configuration(configuration);
  if (!valid) {
    return Result<LanConfiguration>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "lan_configuration_invalid"});
  }
  return Result<LanConfiguration>::success(std::move(configuration));
}

Result<void> write_pairing_policy(sqlite3* database, const PairingPolicy& policy) {
  auto statement = prepare(
      database,
      "INSERT INTO pairing_policy(singleton, generation, password_pairing_enabled, "
      "require_manual_approval_unknown, updated_unix_milliseconds) VALUES(1, ?, ?, ?, ?) "
      "ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation, "
      "password_pairing_enabled=excluded.password_pairing_enabled, "
      "require_manual_approval_unknown=excluded.require_manual_approval_unknown, "
      "updated_unix_milliseconds=excluded.updated_unix_milliseconds");
  if (!statement) {
    return Result<void>::failure(*statement.error_if());
  }
  sqlite3_bind_int64(statement.value_if()->get(), 1,
                     static_cast<sqlite3_int64>(policy.generation));
  sqlite3_bind_int(statement.value_if()->get(), 2, policy.password_pairing_enabled ? 1 : 0);
  sqlite3_bind_int(statement.value_if()->get(), 3,
                   policy.require_manual_approval_unknown ? 1 : 0);
  sqlite3_bind_int64(statement.value_if()->get(), 4,
                     static_cast<sqlite3_int64>(current_unix_milliseconds()));
  auto written = step_done(*statement.value_if());
  if (!written) {
    return written;
  }
  written = execute(database, "DELETE FROM pairing_policy_scopes");
  if (!written) {
    return written;
  }
  auto insert = prepare(database, "INSERT INTO pairing_policy_scopes(scope) VALUES(?)");
  if (!insert) {
    return Result<void>::failure(*insert.error_if());
  }
  for (const auto& scope : policy.default_scopes) {
    sqlite3_reset(insert.value_if()->get());
    sqlite3_clear_bindings(insert.value_if()->get());
    sqlite3_bind_text(insert.value_if()->get(), 1, scope.data(), static_cast<int>(scope.size()),
                      SQLITE_TRANSIENT);
    written = step_done(*insert.value_if());
    if (!written) {
      return written;
    }
  }
  return Result<void>::success();
}

Result<PairingPolicy> read_pairing_policy(sqlite3* database) {
  auto statement = prepare(
      database,
      "SELECT generation, password_pairing_enabled, require_manual_approval_unknown "
      "FROM pairing_policy WHERE singleton=1");
  if (!statement) {
    return Result<PairingPolicy>::failure(*statement.error_if());
  }
  if (sqlite3_step(statement.value_if()->get()) != SQLITE_ROW) {
    return Result<PairingPolicy>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "pairing_policy_missing"});
  }
  PairingPolicy policy;
  policy.generation =
      static_cast<std::uint64_t>(sqlite3_column_int64(statement.value_if()->get(), 0));
  policy.password_pairing_enabled = sqlite3_column_int(statement.value_if()->get(), 1) != 0;
  policy.require_manual_approval_unknown =
      sqlite3_column_int(statement.value_if()->get(), 2) != 0;
  auto scopes = prepare(database, "SELECT scope FROM pairing_policy_scopes ORDER BY scope ASC");
  if (!scopes) {
    return Result<PairingPolicy>::failure(*scopes.error_if());
  }
  while (true) {
    const int result = sqlite3_step(scopes.value_if()->get());
    if (result == SQLITE_DONE) {
      break;
    }
    if (result != SQLITE_ROW) {
      return Result<PairingPolicy>::failure(
          sqlite_error(database, "pairing_policy_scopes_query_failed"));
    }
    const auto* scope = reinterpret_cast<const char*>(sqlite3_column_text(scopes.value_if()->get(), 0));
    if (scope == nullptr) {
      return Result<PairingPolicy>::failure(
          Error{ErrorCode::profile_corrupt, "profile", "pairing_policy_scope_invalid"});
    }
    policy.default_scopes.emplace_back(scope);
  }
  auto valid = validate_pairing_policy(policy);
  if (!valid) {
    return Result<PairingPolicy>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "pairing_policy_invalid"});
  }
  return Result<PairingPolicy>::success(std::move(policy));
}

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
    const char* migration = target_version == 2 ? migration_v2
                                                : (target_version == 3 ? migration_v3 : nullptr);
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
                                                       (std::numeric_limits<int>::max)());
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

Result<void> validate_lan_configuration(const LanConfiguration& configuration) {
  const bool valid_mode =
      configuration.connectivity_mode == ConnectivityMode::automatic ||
      configuration.connectivity_mode == ConnectivityMode::lan_only ||
      configuration.connectivity_mode == ConnectivityMode::relay_only;
  constexpr std::size_t maximum_capacity = 1024U * 1024U;
  const std::array capacities{
      configuration.interface_capacity,
      configuration.directory_capacity,
      configuration.trusted_directory_reserve,
      configuration.per_interface_directory_capacity,
      configuration.per_source_presence_capacity,
      configuration.unknown_identity_capacity,
      configuration.replay_capacity,
      configuration.diagnostic_capacity,
      configuration.provisional_connection_capacity,
      configuration.per_source_provisional_capacity,
      configuration.provisional_accept_rate_per_second,
      configuration.per_source_provisional_rate,
      configuration.pending_signaling_capacity,
      configuration.auto_connect_capacity,
      configuration.announcement_rate_per_second,
      configuration.per_source_announcement_rate};
  const bool capacities_valid = std::all_of(
      capacities.begin(), capacities.end(), [](std::size_t value) {
        return value > 0U && value <= maximum_capacity;
      });
  const bool relationships_valid =
      configuration.interface_preferences.size() <= configuration.interface_capacity &&
      configuration.trusted_directory_reserve <= configuration.directory_capacity &&
      configuration.per_interface_directory_capacity <= configuration.directory_capacity &&
      configuration.per_source_presence_capacity <= configuration.directory_capacity &&
      configuration.unknown_identity_capacity <= configuration.directory_capacity &&
      configuration.per_source_provisional_capacity <=
          configuration.provisional_connection_capacity &&
      configuration.per_source_provisional_rate <=
          configuration.provisional_accept_rate_per_second &&
      configuration.auto_connect_capacity <= configuration.pending_signaling_capacity &&
      configuration.per_source_announcement_rate <=
          configuration.announcement_rate_per_second;
  const bool durations_valid =
      configuration.announcement_interval.count() > 0 &&
      configuration.announcement_interval <= std::chrono::milliseconds{120000} &&
      configuration.presence_lease >= std::chrono::milliseconds{1000} &&
      configuration.presence_lease <= std::chrono::milliseconds{120000} &&
      configuration.announcement_interval < configuration.presence_lease &&
      configuration.announcement_jitter.count() >= 0 &&
      configuration.announcement_jitter <= configuration.announcement_interval &&
      configuration.interface_refresh_interval.count() > 0 &&
      configuration.interface_refresh_interval <= std::chrono::milliseconds{120000} &&
      configuration.handshake_timeout.count() > 0 &&
      configuration.handshake_timeout <= std::chrono::milliseconds{60000} &&
      configuration.hello_timeout.count() > 0 &&
      configuration.hello_timeout <= configuration.handshake_timeout &&
      configuration.route_preference_delay.count() >= 0 &&
      configuration.route_preference_delay <= std::chrono::milliseconds{60000} &&
      configuration.shutdown_timeout.count() > 0 &&
      configuration.shutdown_timeout <= std::chrono::milliseconds{60000};
  std::vector<std::string_view> names;
  names.reserve(configuration.interface_preferences.size());
  bool interfaces_valid = true;
  for (const auto& interface_name : configuration.interface_preferences) {
    if (!valid_interface_preference(interface_name)) {
      interfaces_valid = false;
      break;
    }
    names.emplace_back(interface_name);
  }
  std::sort(names.begin(), names.end());
  interfaces_valid = interfaces_valid &&
                     std::adjacent_find(names.begin(), names.end()) == names.end();
  if (!valid_mode || !capacities_valid || !relationships_valid || !durations_valid ||
      !interfaces_valid ||
      (configuration.connectivity_mode == ConnectivityMode::lan_only &&
       !configuration.enabled)) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_lan_configuration"});
  }
  return Result<void>::success();
}

Result<void> validate_pairing_policy(const PairingPolicy& policy) {
  if (policy.generation == 0U || policy.default_scopes.size() > 256U ||
      !std::all_of(policy.default_scopes.begin(), policy.default_scopes.end(), valid_scope)) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_pairing_policy"});
  }
  std::vector<std::string_view> scopes;
  scopes.reserve(policy.default_scopes.size());
  for (const auto& scope : policy.default_scopes) {
    scopes.emplace_back(scope);
  }
  std::sort(scopes.begin(), scopes.end());
  if (std::adjacent_find(scopes.begin(), scopes.end()) != scopes.end()) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_pairing_policy"});
  }
  return Result<void>::success();
}

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

Result<EndpointId> ProfileStore::initialize_local(
    const LocalProfileInitialization& initialization) {
  if (!valid_application_id(initialization.application_id) ||
      initialization.password_generation == 0U ||
      initialization.password_verifier.encoded.empty()) {
    return Result<EndpointId>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_local_initialization"});
  }
  auto valid = validate_lan_configuration(initialization.lan);
  if (!valid) {
    return Result<EndpointId>::failure(*valid.error_if());
  }
  valid = validate_pairing_policy(initialization.pairing_policy);
  if (!valid) {
    return Result<EndpointId>::failure(*valid.error_if());
  }

  auto begin = execute(impl_->database, "BEGIN IMMEDIATE");
  if (!begin) {
    return Result<EndpointId>::failure(*begin.error_if());
  }
  auto endpoint = endpoint_for(initialization.application_id);
  if (!endpoint) {
    (void)execute(impl_->database, "ROLLBACK");
    return endpoint;
  }
  auto written = set_password_verifier(initialization.password_verifier,
                                       initialization.password_generation);
  if (!written) {
    (void)execute(impl_->database, "ROLLBACK");
    return Result<EndpointId>::failure(*written.error_if());
  }
  written = write_pairing_policy(impl_->database, initialization.pairing_policy);
  if (!written) {
    (void)execute(impl_->database, "ROLLBACK");
    return Result<EndpointId>::failure(*written.error_if());
  }
  written = write_lan_configuration(impl_->database, initialization.lan);
  if (!written) {
    (void)execute(impl_->database, "ROLLBACK");
    return Result<EndpointId>::failure(*written.error_if());
  }
  const auto committed = execute(impl_->database, "COMMIT");
  if (!committed) {
    (void)execute(impl_->database, "ROLLBACK");
    return Result<EndpointId>::failure(*committed.error_if());
  }
  return endpoint;
}

Result<LocalProfileReadiness> ProfileStore::local_readiness(
    std::string_view application_id) const {
  if (!valid_application_id(application_id)) {
    return Result<LocalProfileReadiness>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_application_id"});
  }
  LocalProfileReadiness readiness;
  readiness.identity_ready = !impl_->device_id.is_zero();

  auto endpoint = prepare(
      impl_->database,
      "SELECT 1 FROM endpoint_records WHERE application_id=? LIMIT 1");
  if (!endpoint) {
    return Result<LocalProfileReadiness>::failure(*endpoint.error_if());
  }
  sqlite3_bind_text(endpoint.value_if()->get(), 1, application_id.data(),
                    static_cast<int>(application_id.size()), SQLITE_TRANSIENT);
  const int endpoint_result = sqlite3_step(endpoint.value_if()->get());
  if (endpoint_result != SQLITE_ROW && endpoint_result != SQLITE_DONE) {
    return Result<LocalProfileReadiness>::failure(
        sqlite_error(impl_->database, "endpoint_readiness_query_failed"));
  }
  readiness.endpoint_ready = endpoint_result == SQLITE_ROW;

  auto verifier = password_verifier();
  if (!verifier) {
    return Result<LocalProfileReadiness>::failure(*verifier.error_if());
  }
  readiness.password_verifier_ready = verifier.value_if()->has_value();

  auto policy = read_pairing_policy(impl_->database);
  if (!policy) {
    return Result<LocalProfileReadiness>::failure(*policy.error_if());
  }
  readiness.pairing_policy_ready = true;

  auto configuration = read_lan_configuration(impl_->database);
  if (!configuration) {
    return Result<LocalProfileReadiness>::failure(*configuration.error_if());
  }
  readiness.lan_configuration_ready = true;
  return Result<LocalProfileReadiness>::success(readiness);
}

Result<void> ProfileStore::set_lan_configuration(
    const LanConfiguration& configuration) {
  auto valid = validate_lan_configuration(configuration);
  if (!valid) {
    return valid;
  }
  auto begin = execute(impl_->database, "BEGIN IMMEDIATE");
  if (!begin) {
    return begin;
  }
  auto written = write_lan_configuration(impl_->database, configuration);
  if (!written) {
    (void)execute(impl_->database, "ROLLBACK");
    return written;
  }
  const auto committed = execute(impl_->database, "COMMIT");
  if (!committed) {
    (void)execute(impl_->database, "ROLLBACK");
    return committed;
  }
  return Result<void>::success();
}

Result<LanConfiguration> ProfileStore::lan_configuration() const {
  return read_lan_configuration(impl_->database);
}

Result<void> ProfileStore::set_pairing_policy(const PairingPolicy& policy) {
  auto valid = validate_pairing_policy(policy);
  if (!valid) {
    return valid;
  }
  auto begin = execute(impl_->database, "BEGIN IMMEDIATE");
  if (!begin) {
    return begin;
  }
  auto written = write_pairing_policy(impl_->database, policy);
  if (!written) {
    (void)execute(impl_->database, "ROLLBACK");
    return written;
  }
  const auto committed = execute(impl_->database, "COMMIT");
  if (!committed) {
    (void)execute(impl_->database, "ROLLBACK");
    return committed;
  }
  return Result<void>::success();
}

Result<PairingPolicy> ProfileStore::pairing_policy() const {
  return read_pairing_policy(impl_->database);
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

Result<std::size_t> ProfileStore::revoke_issued_trust_grants_below_generation(
    std::uint64_t minimum_generation, std::uint64_t revoked_unix_milliseconds) {
  auto statement = prepare(impl_->database,
                           "UPDATE trust_grants SET revoked=1, revoked_unix_milliseconds=? "
                           "WHERE direction=1 AND issuer_device_id=? AND revoked=0 "
                           "AND password_generation<?");
  if (!statement) {
    return Result<std::size_t>::failure(*statement.error_if());
  }
  sqlite3_bind_int64(statement.value_if()->get(), 1,
                     static_cast<sqlite3_int64>(revoked_unix_milliseconds));
  bind_id(statement.value_if()->get(), 2, impl_->device_id);
  sqlite3_bind_int64(statement.value_if()->get(), 3,
                     static_cast<sqlite3_int64>(minimum_generation));
  const int result = sqlite3_step(statement.value_if()->get());
  if (result != SQLITE_DONE) {
    return Result<std::size_t>::failure(
        sqlite_error(impl_->database, "trust_grant_revocation_failed"));
  }
  return Result<std::size_t>::success(
      static_cast<std::size_t>(sqlite3_changes(impl_->database)));
}

Result<std::vector<TrustGrantRecord>> ProfileStore::trust_grants_for_peer(
    const DeviceId& peer, std::uint64_t now_unix_milliseconds) const {
  if (peer.is_zero() || peer == impl_->device_id) {
    return Result<std::vector<TrustGrantRecord>>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_trust_peer"});
  }
  // Valid grants of the relationship in both directions: grants this device
  // issued to the peer (peer may act on us) and grants received from the peer
  // (we may act on the peer). Revocation, not password rotation, is the trust
  // basis; rotation only revokes when explicitly asked to.
  auto statement = prepare(
      impl_->database,
      "SELECT grant_id, direction, issuer_device_id, subject_device_id, "
      "password_generation, issued_unix_milliseconds, expires_unix_milliseconds, "
      "signature, revoked FROM trust_grants WHERE revoked=0 "
      "AND (expires_unix_milliseconds IS NULL OR expires_unix_milliseconds>?) "
      "AND ((direction=1 AND issuer_device_id=? AND subject_device_id=?) "
      "OR (direction=2 AND issuer_device_id=? AND subject_device_id=?))");
  if (!statement) {
    return Result<std::vector<TrustGrantRecord>>::failure(*statement.error_if());
  }
  sqlite3_bind_int64(statement.value_if()->get(), 1,
                     static_cast<sqlite3_int64>(now_unix_milliseconds));
  bind_id(statement.value_if()->get(), 2, impl_->device_id);
  bind_id(statement.value_if()->get(), 3, peer);
  bind_id(statement.value_if()->get(), 4, peer);
  bind_id(statement.value_if()->get(), 5, impl_->device_id);
  std::vector<TrustGrantRecord> output;
  while (true) {
    const int result = sqlite3_step(statement.value_if()->get());
    if (result == SQLITE_DONE) break;
    if (result != SQLITE_ROW) {
      return Result<std::vector<TrustGrantRecord>>::failure(
          sqlite_error(impl_->database, "trust_grants_for_peer_query_failed"));
    }
    auto grant_id = column_id<GrantId>(statement.value_if()->get(), 0,
                                       "trust_grant_id_invalid");
    auto issuer = column_id<DeviceId>(statement.value_if()->get(), 2,
                                      "trust_issuer_invalid");
    auto subject = column_id<DeviceId>(statement.value_if()->get(), 3,
                                       "trust_subject_invalid");
    if (!grant_id || !issuer || !subject) {
      return Result<std::vector<TrustGrantRecord>>::failure(
          !grant_id ? *grant_id.error_if()
                    : (!issuer ? *issuer.error_if() : *subject.error_if()));
    }
    TrustGrantRecord grant;
    grant.grant_id = *grant_id.value_if();
    grant.direction = static_cast<TrustGrantDirection>(
        sqlite3_column_int(statement.value_if()->get(), 1));
    grant.issuer = *issuer.value_if();
    grant.subject = *subject.value_if();
    grant.password_generation = static_cast<std::uint64_t>(
        sqlite3_column_int64(statement.value_if()->get(), 4));
    grant.issued_unix_milliseconds = static_cast<std::uint64_t>(
        sqlite3_column_int64(statement.value_if()->get(), 5));
    if (sqlite3_column_type(statement.value_if()->get(), 6) != SQLITE_NULL) {
      grant.expires_unix_milliseconds = static_cast<std::uint64_t>(
          sqlite3_column_int64(statement.value_if()->get(), 6));
    }
    const auto* signature = static_cast<const std::byte*>(
        sqlite3_column_blob(statement.value_if()->get(), 7));
    const int signature_size = sqlite3_column_bytes(statement.value_if()->get(), 7);
    if (signature == nullptr || signature_size <= 0) {
      return Result<std::vector<TrustGrantRecord>>::failure(
          Error{ErrorCode::profile_corrupt, "profile", "trust_signature_invalid"});
    }
    grant.signature.assign(signature, signature + signature_size);
    auto scopes = prepare(impl_->database,
                          "SELECT scope FROM trust_grant_scopes WHERE grant_id=? "
                          "ORDER BY scope");
    if (!scopes) {
      return Result<std::vector<TrustGrantRecord>>::failure(*scopes.error_if());
    }
    bind_id(scopes.value_if()->get(), 1, grant.grant_id);
    while (true) {
      const int scope_result = sqlite3_step(scopes.value_if()->get());
      if (scope_result == SQLITE_DONE) break;
      if (scope_result != SQLITE_ROW) {
        return Result<std::vector<TrustGrantRecord>>::failure(
            sqlite_error(impl_->database, "trust_scope_query_failed"));
      }
      const auto* scope = reinterpret_cast<const char*>(
          sqlite3_column_text(scopes.value_if()->get(), 0));
      if (scope == nullptr || !valid_scope(scope)) {
        return Result<std::vector<TrustGrantRecord>>::failure(
            Error{ErrorCode::profile_corrupt, "profile", "trust_scope_invalid"});
      }
      grant.scopes.emplace_back(scope);
    }
    output.push_back(std::move(grant));
  }
  return Result<std::vector<TrustGrantRecord>>::success(std::move(output));
}

Result<bool> ProfileStore::is_scope_authorized(const DeviceId& peer, std::string_view scope,
                                               std::uint64_t now_unix_milliseconds) const {
  if (!valid_scope(scope)) {
    return Result<bool>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_trust_scope"});
  }
  auto statement = prepare(
      impl_->database,
      "SELECT 1 FROM trust_grants g JOIN trust_grant_scopes s ON s.grant_id=g.grant_id "
      "WHERE g.direction=1 AND g.issuer_device_id=? AND g.subject_device_id=? "
      "AND g.revoked=0 AND s.scope=? "
      "AND (g.expires_unix_milliseconds IS NULL OR g.expires_unix_milliseconds>?) LIMIT 1");
  if (!statement) {
    return Result<bool>::failure(*statement.error_if());
  }
  bind_id(statement.value_if()->get(), 1, impl_->device_id);
  bind_id(statement.value_if()->get(), 2, peer);
  sqlite3_bind_text(statement.value_if()->get(), 3, scope.data(),
                    static_cast<int>(scope.size()), SQLITE_TRANSIENT);
  sqlite3_bind_int64(statement.value_if()->get(), 4,
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

Result<bool> ProfileStore::is_device_trusted(const DeviceId& peer,
                                             std::uint64_t now_unix_milliseconds) const {
  if (peer.is_zero()) {
    return Result<bool>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_trusted_peer"});
  }
  auto statement = prepare(
      impl_->database,
      "SELECT 1 FROM trust_grants WHERE direction=1 AND issuer_device_id=? "
      "AND subject_device_id=? AND revoked=0 "
      "AND (expires_unix_milliseconds IS NULL OR expires_unix_milliseconds>?) LIMIT 1");
  if (!statement) {
    return Result<bool>::failure(*statement.error_if());
  }
  bind_id(statement.value_if()->get(), 1, impl_->device_id);
  bind_id(statement.value_if()->get(), 2, peer);
  sqlite3_bind_int64(statement.value_if()->get(), 3,
                     static_cast<sqlite3_int64>(now_unix_milliseconds));
  const int result = sqlite3_step(statement.value_if()->get());
  if (result == SQLITE_ROW) {
    return Result<bool>::success(true);
  }
  if (result == SQLITE_DONE) {
    return Result<bool>::success(false);
  }
  return Result<bool>::failure(sqlite_error(impl_->database, "trust_status_query_failed"));
}

Result<std::vector<DeviceId>> ProfileStore::trusted_devices(
    std::uint64_t now_unix_milliseconds) const {
  auto statement = prepare(
      impl_->database,
      "SELECT DISTINCT subject_device_id FROM trust_grants WHERE direction=1 "
      "AND issuer_device_id=? AND revoked=0 "
      "AND (expires_unix_milliseconds IS NULL OR expires_unix_milliseconds>?) "
      "ORDER BY subject_device_id");
  if (!statement) {
    return Result<std::vector<DeviceId>>::failure(*statement.error_if());
  }
  bind_id(statement.value_if()->get(), 1, impl_->device_id);
  sqlite3_bind_int64(statement.value_if()->get(), 2,
                     static_cast<sqlite3_int64>(now_unix_milliseconds));
  std::vector<DeviceId> output;
  while (true) {
    const int result = sqlite3_step(statement.value_if()->get());
    if (result == SQLITE_DONE) {
      break;
    }
    if (result != SQLITE_ROW) {
      return Result<std::vector<DeviceId>>::failure(
          sqlite_error(impl_->database, "trusted_devices_query_failed"));
    }
    auto device = column_id<DeviceId>(statement.value_if()->get(), 0,
                                      "trusted_device_id_invalid");
    if (!device) {
      return Result<std::vector<DeviceId>>::failure(*device.error_if());
    }
    output.push_back(*device.value_if());
  }
  return Result<std::vector<DeviceId>>::success(std::move(output));
}

Result<void> ProfileStore::put_relay_enrollment(
    const RelayEnrollmentRecord& enrollment) {
  if (!valid_relay_enrollment_url(enrollment.relay_url) ||
      !valid_relay_tenant(enrollment.tenant) || enrollment.enrollment_generation == 0U ||
      (enrollment.relay_pin &&
       enrollment.relay_pin->size() != 32U)) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_relay_enrollment"});
  }
  auto statement = prepare(
      impl_->database,
      "INSERT INTO relay_enrollments("
      "relay_url, relay_pin, tenant, enrollment_generation, auto_connect, revoked, "
      "updated_unix_milliseconds) VALUES(?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT(relay_url) DO UPDATE SET relay_pin=excluded.relay_pin, "
      "tenant=excluded.tenant, enrollment_generation=excluded.enrollment_generation, "
      "auto_connect=excluded.auto_connect, revoked=excluded.revoked, "
      "updated_unix_milliseconds=excluded.updated_unix_milliseconds");
  if (!statement) {
    return Result<void>::failure(*statement.error_if());
  }
  sqlite3_bind_text(statement.value_if()->get(), 1, enrollment.relay_url.data(),
                    static_cast<int>(enrollment.relay_url.size()), SQLITE_TRANSIENT);
  if (enrollment.relay_pin) {
    sqlite3_bind_blob(statement.value_if()->get(), 2, enrollment.relay_pin->data(),
                      static_cast<int>(enrollment.relay_pin->size()), SQLITE_TRANSIENT);
  } else {
    sqlite3_bind_null(statement.value_if()->get(), 2);
  }
  sqlite3_bind_text(statement.value_if()->get(), 3, enrollment.tenant.data(),
                    static_cast<int>(enrollment.tenant.size()), SQLITE_TRANSIENT);
  sqlite3_bind_int64(statement.value_if()->get(), 4,
                     static_cast<sqlite3_int64>(enrollment.enrollment_generation));
  sqlite3_bind_int(statement.value_if()->get(), 5, enrollment.auto_connect ? 1 : 0);
  sqlite3_bind_int(statement.value_if()->get(), 6, enrollment.revoked ? 1 : 0);
  sqlite3_bind_int64(statement.value_if()->get(), 7,
                     static_cast<sqlite3_int64>(current_unix_milliseconds()));
  return step_done(*statement.value_if());
}

Result<std::optional<RelayEnrollmentRecord>> ProfileStore::relay_enrollment(
    std::string_view relay_url) const {
  if (!valid_relay_enrollment_url(relay_url)) {
    return Result<std::optional<RelayEnrollmentRecord>>::failure(
        Error{ErrorCode::configuration, "profile", "invalid_relay_enrollment_url"});
  }
  auto statement = prepare(
      impl_->database,
      "SELECT relay_url, relay_pin, tenant, enrollment_generation, auto_connect, revoked, "
      "updated_unix_milliseconds FROM relay_enrollments WHERE relay_url = ?");
  if (!statement) {
    return Result<std::optional<RelayEnrollmentRecord>>::failure(*statement.error_if());
  }
  sqlite3_bind_text(statement.value_if()->get(), 1, relay_url.data(),
                    static_cast<int>(relay_url.size()), SQLITE_TRANSIENT);
  const int step = sqlite3_step(statement.value_if()->get());
  if (step == SQLITE_DONE) {
    return Result<std::optional<RelayEnrollmentRecord>>::success(std::nullopt);
  }
  if (step != SQLITE_ROW) {
    return Result<std::optional<RelayEnrollmentRecord>>::failure(
        sqlite_error(impl_->database, "relay_enrollment_query_failed", step));
  }
  RelayEnrollmentRecord record;
  const auto* url = reinterpret_cast<const char*>(sqlite3_column_text(statement.value_if()->get(), 0));
  const int url_size = sqlite3_column_bytes(statement.value_if()->get(), 0);
  if (url == nullptr || url_size <= 0) {
    return Result<std::optional<RelayEnrollmentRecord>>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "relay_enrollment_url_invalid"});
  }
  record.relay_url.assign(url, static_cast<std::size_t>(url_size));
  const auto* pin = static_cast<const std::byte*>(
      sqlite3_column_blob(statement.value_if()->get(), 1));
  const int pin_size = sqlite3_column_bytes(statement.value_if()->get(), 1);
  if (pin != nullptr) {
    if (pin_size != static_cast<int>(32U)) {
      return Result<std::optional<RelayEnrollmentRecord>>::failure(
          Error{ErrorCode::profile_corrupt, "profile", "relay_enrollment_pin_invalid"});
    }
    record.relay_pin = std::vector<std::byte>(pin, pin + pin_size);
  }
  const auto* tenant = reinterpret_cast<const char*>(
      sqlite3_column_text(statement.value_if()->get(), 2));
  const int tenant_size = sqlite3_column_bytes(statement.value_if()->get(), 2);
  if (tenant == nullptr || tenant_size <= 0) {
    return Result<std::optional<RelayEnrollmentRecord>>::failure(
        Error{ErrorCode::profile_corrupt, "profile", "relay_enrollment_tenant_invalid"});
  }
  record.tenant.assign(tenant, static_cast<std::size_t>(tenant_size));
  record.enrollment_generation = static_cast<std::uint64_t>(
      sqlite3_column_int64(statement.value_if()->get(), 3));
  record.auto_connect = sqlite3_column_int(statement.value_if()->get(), 4) != 0;
  record.revoked = sqlite3_column_int(statement.value_if()->get(), 5) != 0;
  record.updated_unix_milliseconds = static_cast<std::uint64_t>(
      sqlite3_column_int64(statement.value_if()->get(), 6));
  return Result<std::optional<RelayEnrollmentRecord>>::success(std::move(record));
}

Result<std::vector<RelayEnrollmentRecord>> ProfileStore::relay_enrollments() const {
  auto statement = prepare(
      impl_->database,
      "SELECT relay_url, relay_pin, tenant, enrollment_generation, auto_connect, revoked, "
      "updated_unix_milliseconds FROM relay_enrollments ORDER BY relay_url");
  if (!statement) {
    return Result<std::vector<RelayEnrollmentRecord>>::failure(*statement.error_if());
  }
  std::vector<RelayEnrollmentRecord> output;
  int step = sqlite3_step(statement.value_if()->get());
  while (step == SQLITE_ROW) {
    RelayEnrollmentRecord record;
    const auto* url = reinterpret_cast<const char*>(
        sqlite3_column_text(statement.value_if()->get(), 0));
    const int url_size = sqlite3_column_bytes(statement.value_if()->get(), 0);
    if (url == nullptr || url_size <= 0) {
      return Result<std::vector<RelayEnrollmentRecord>>::failure(
          Error{ErrorCode::profile_corrupt, "profile", "relay_enrollment_url_invalid"});
    }
    record.relay_url.assign(url, static_cast<std::size_t>(url_size));
    const auto* pin = static_cast<const std::byte*>(
        sqlite3_column_blob(statement.value_if()->get(), 1));
    const int pin_size = sqlite3_column_bytes(statement.value_if()->get(), 1);
    if (pin != nullptr) {
      if (pin_size != static_cast<int>(32U)) {
        return Result<std::vector<RelayEnrollmentRecord>>::failure(
            Error{ErrorCode::profile_corrupt, "profile", "relay_enrollment_pin_invalid"});
      }
      record.relay_pin = std::vector<std::byte>(pin, pin + pin_size);
    }
    const auto* tenant = reinterpret_cast<const char*>(
        sqlite3_column_text(statement.value_if()->get(), 2));
    const int tenant_size = sqlite3_column_bytes(statement.value_if()->get(), 2);
    if (tenant == nullptr || tenant_size <= 0) {
      return Result<std::vector<RelayEnrollmentRecord>>::failure(
          Error{ErrorCode::profile_corrupt, "profile", "relay_enrollment_tenant_invalid"});
    }
    record.tenant.assign(tenant, static_cast<std::size_t>(tenant_size));
    record.enrollment_generation = static_cast<std::uint64_t>(
        sqlite3_column_int64(statement.value_if()->get(), 3));
    record.auto_connect = sqlite3_column_int(statement.value_if()->get(), 4) != 0;
    record.revoked = sqlite3_column_int(statement.value_if()->get(), 5) != 0;
    record.updated_unix_milliseconds = static_cast<std::uint64_t>(
        sqlite3_column_int64(statement.value_if()->get(), 6));
    output.push_back(std::move(record));
    step = sqlite3_step(statement.value_if()->get());
  }
  if (step != SQLITE_DONE) {
    return Result<std::vector<RelayEnrollmentRecord>>::failure(
        sqlite_error(impl_->database, "relay_enrollments_query_failed", step));
  }
  return Result<std::vector<RelayEnrollmentRecord>>::success(std::move(output));
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
