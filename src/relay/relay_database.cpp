#include "relay_database.hpp"

#include <heyaki/error.hpp>
#include <heyaki/identity.hpp>
#include <heyaki/security.hpp>

#include <sqlite3.h>

#include <sodium.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <span>
#include <string_view>
#include <utility>

namespace heyaki {

constexpr int relay_database_application_id = 1213808977;

Error database_error(sqlite3* database, const char* detail, int code = SQLITE_ERROR) {
  if (database != nullptr) {
    code = sqlite3_extended_errcode(database);
  }
  return Error{ErrorCode::storage, "relay_database", detail, code};
}

Error database_corrupt_error(const char* detail) {
  return Error{ErrorCode::storage, "relay_database", detail};
}

std::uint64_t current_unix_milliseconds() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
}

Result<void> execute(sqlite3* database, const char* sql) {
  char* message = nullptr;
  const int result = sqlite3_exec(database, sql, nullptr, nullptr, &message);
  if (result != SQLITE_OK) {
    const auto error = database_error(database, "relay_database_statement_failed", result);
    sqlite3_free(message);
    return Result<void>::failure(error);
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
    return Result<Statement>::failure(database_error(database, "relay_database_prepare_failed",
                                                     result));
  }
  return Result<Statement>::success(Statement{database, statement});
}

Result<void> step_done(Statement& statement) {
  const int result = sqlite3_step(statement.get());
  if (result != SQLITE_DONE) {
    return Result<void>::failure(
        database_error(statement.database(), "relay_database_write_failed", result));
  }
  return Result<void>::success();
}

Result<void> rollback(sqlite3* database) {
  return execute(database, "ROLLBACK");
}

void rollback_best_effort(sqlite3* database) noexcept {
  (void)rollback(database);
}

Result<int> pragma_int(sqlite3* database, const char* pragma) {
  auto statement = prepare(database, pragma);
  if (!statement) {
    return Result<int>::failure(*statement.error_if());
  }
  if (sqlite3_step(statement.value_if()->get()) != SQLITE_ROW) {
    return Result<int>::failure(database_error(database, "relay_database_pragma_failed"));
  }
  return Result<int>::success(sqlite3_column_int(statement.value_if()->get(), 0));
}

Result<std::uint64_t> count_rows(sqlite3* database, const char* table) {
  const std::string sql = "SELECT COUNT(*) FROM " + std::string{table};
  auto statement = prepare(database, sql.c_str());
  if (!statement) {
    return Result<std::uint64_t>::failure(*statement.error_if());
  }
  if (sqlite3_step(statement.value_if()->get()) != SQLITE_ROW) {
    return Result<std::uint64_t>::failure(
        database_error(database, "relay_database_count_failed"));
  }
  return Result<std::uint64_t>::success(
      static_cast<std::uint64_t>(sqlite3_column_int64(statement.value_if()->get(), 0)));
}

Result<void> validate_migration_history(sqlite3* database, int version) {
  auto statement = prepare(
      database, "SELECT COUNT(*) FROM schema_migrations WHERE version BETWEEN 1 AND ?");
  if (!statement) {
    return Result<void>::failure(*statement.error_if());
  }
  sqlite3_bind_int(statement.value_if()->get(), 1, version);
  if (sqlite3_step(statement.value_if()->get()) != SQLITE_ROW ||
      sqlite3_column_int(statement.value_if()->get(), 0) != version) {
    return Result<void>::failure(database_corrupt_error("relay_database_migration_history_invalid"));
  }
  return Result<void>::success();
}

Result<void> validate_integrity(sqlite3* database) {
  auto check = prepare(database, "PRAGMA quick_check(1)");
  if (!check) {
    return Result<void>::failure(*check.error_if());
  }
  if (sqlite3_step(check.value_if()->get()) != SQLITE_ROW) {
    return Result<void>::failure(database_corrupt_error("relay_database_integrity_check_failed"));
  }
  const auto* result = reinterpret_cast<const char*>(
      sqlite3_column_text(check.value_if()->get(), 0));
  if (result == nullptr || std::string_view{result} != "ok") {
    return Result<void>::failure(database_corrupt_error("relay_database_integrity_check_failed"));
  }
  return Result<void>::success();
}

bool valid_tenant(std::string_view value) noexcept {
  if (value.empty() || value.size() > 128U) {
    return false;
  }
  std::size_t index = 0U;
  while (index < value.size()) {
    const auto first = static_cast<unsigned char>(value[index]);
    if (first <= 0x7fU) {
      if (first < 0x20U) {
        return false;
      }
      ++index;
      continue;
    }
    std::size_t continuation_count = 0U;
    std::uint8_t second_minimum = 0x80U;
    std::uint8_t second_maximum = 0xbfU;
    if (first >= 0xc2U && first <= 0xdfU) {
      continuation_count = 1U;
    } else if (first >= 0xe0U && first <= 0xefU) {
      continuation_count = 2U;
      if (first == 0xe0U) {
        second_minimum = 0xa0U;
      } else if (first == 0xedU) {
        second_maximum = 0x9fU;
      }
    } else if (first >= 0xf0U && first <= 0xf4U) {
      continuation_count = 3U;
      if (first == 0xf0U) {
        second_minimum = 0x90U;
      } else if (first == 0xf4U) {
        second_maximum = 0x8fU;
      }
    } else {
      return false;
    }
    if (value.size() - index <= continuation_count) {
      return false;
    }
    const auto second = static_cast<unsigned char>(value[index + 1U]);
    if (second < second_minimum || second > second_maximum) {
      return false;
    }
    for (std::size_t offset = 2U; offset <= continuation_count; ++offset) {
      const auto continuation = static_cast<unsigned char>(value[index + offset]);
      if (continuation < 0x80U || continuation > 0xbfU) {
        return false;
      }
    }
    index += continuation_count + 1U;
  }
  return true;
}

bool valid_audit_action(std::string_view value) noexcept {
  return is_safe_detail_token(value);
}

bool valid_audit_metadata(std::string_view value) noexcept {
  if (value.size() > 256U) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](unsigned char character) {
    return character >= 0x20U && character <= 0x7eU;
  });
}

const char* schema_v1 = R"SQL(
CREATE TABLE schema_migrations(
  version INTEGER PRIMARY KEY,
  applied_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE devices(
  device_id BLOB PRIMARY KEY CHECK(length(device_id) = 32),
  public_key BLOB NOT NULL CHECK(length(public_key) = 32),
  tenant TEXT NOT NULL,
  display_name TEXT NOT NULL,
  enrollment_generation INTEGER NOT NULL CHECK(enrollment_generation > 0),
  status INTEGER NOT NULL CHECK(status IN (1, 2)),
  created_unix_milliseconds INTEGER NOT NULL,
  updated_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE bootstrap_tokens(
  token_id BLOB PRIMARY KEY CHECK(length(token_id) = 16),
  token_hash BLOB NOT NULL UNIQUE CHECK(length(token_hash) = 32),
  tenant TEXT NOT NULL,
  expires_unix_milliseconds INTEGER NOT NULL,
  remaining_uses INTEGER NOT NULL CHECK(remaining_uses >= 0),
  created_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE device_audit(
  id INTEGER PRIMARY KEY,
  device_id BLOB CHECK(device_id IS NULL OR length(device_id) = 32),
  action TEXT NOT NULL,
  occurred_unix_milliseconds INTEGER NOT NULL,
  metadata TEXT NOT NULL
);
INSERT INTO schema_migrations(version, applied_unix_milliseconds)
VALUES(1, CAST(unixepoch('subsec') * 1000 AS INTEGER));
PRAGMA application_id=1213808977;
PRAGMA user_version=1;
)SQL";

const char* migration_v2 = R"SQL(
CREATE INDEX devices_tenant_status_index
  ON devices(tenant, status);
CREATE INDEX bootstrap_tokens_tenant_expiry_index
  ON bootstrap_tokens(tenant, expires_unix_milliseconds);
CREATE INDEX device_audit_device_time_index
  ON device_audit(device_id, occurred_unix_milliseconds);
INSERT INTO schema_migrations(version, applied_unix_milliseconds)
VALUES(2, CAST(unixepoch('subsec') * 1000 AS INTEGER));
PRAGMA user_version=2;
)SQL";

const char* migration_for(int version) noexcept {
  return version == 2 ? migration_v2 : nullptr;
}

Result<void> apply_migration(sqlite3* database, int target_version) {
  const char* migration = migration_for(target_version);
  if (migration == nullptr) {
    return Result<void>::failure(
        database_corrupt_error("relay_database_migration_not_registered"));
  }
  const auto begin = execute(database, "BEGIN EXCLUSIVE");
  if (!begin) {
    return begin;
  }
  const auto applied = execute(database, migration);
  if (!applied) {
    rollback_best_effort(database);
    return applied;
  }
  const auto committed = execute(database, "COMMIT");
  if (!committed) {
    rollback_best_effort(database);
    return committed;
  }
  return Result<void>::success();
}

Result<void> initialize_database(sqlite3* database) {
  const auto begin = execute(database, "BEGIN EXCLUSIVE");
  if (!begin) {
    return begin;
  }
  auto applied = execute(database, schema_v1);
  if (applied) {
    applied = execute(database, migration_v2);
  }
  if (!applied) {
    rollback_best_effort(database);
    return applied;
  }
  const auto committed = execute(database, "COMMIT");
  if (!committed) {
    rollback_best_effort(database);
    return committed;
  }
  return Result<void>::success();
}

Result<void> validate_or_migrate(sqlite3* database, bool create_if_missing) {
  auto application_id = pragma_int(database, "PRAGMA application_id");
  auto version = pragma_int(database, "PRAGMA user_version");
  if (!application_id || !version) {
    return Result<void>::failure(database_corrupt_error("relay_database_header_invalid"));
  }
  if (*application_id.value_if() != 0 &&
      *application_id.value_if() != relay_database_application_id) {
    return Result<void>::failure(database_corrupt_error("relay_database_application_id_mismatch"));
  }
  if (*version.value_if() > static_cast<int>(relay_database_schema_version)) {
    return Result<void>::failure(
        Error{ErrorCode::schema_too_new, "relay_database", "relay_database_schema_too_new"});
  }
  if (*version.value_if() == 0) {
    if (*application_id.value_if() != 0) {
      return Result<void>::failure(database_corrupt_error("relay_database_schema_header_invalid"));
    }
    if (!create_if_missing) {
      return Result<void>::failure(database_corrupt_error("relay_database_schema_missing"));
    }
    const auto initialized = initialize_database(database);
    if (!initialized) {
      return initialized;
    }
    application_id = pragma_int(database, "PRAGMA application_id");
    version = pragma_int(database, "PRAGMA user_version");
    if (!application_id || !version) {
      return Result<void>::failure(database_corrupt_error("relay_database_header_invalid"));
    }
  }
  if (*application_id.value_if() != relay_database_application_id) {
    return Result<void>::failure(database_corrupt_error("relay_database_application_id_mismatch"));
  }
  const auto integrity = validate_integrity(database);
  if (!integrity) {
    return integrity;
  }
  while (*version.value_if() < static_cast<int>(relay_database_schema_version)) {
    const int previous_version = *version.value_if();
    const auto migrated = apply_migration(database, previous_version + 1);
    if (!migrated) {
      return migrated;
    }
    version = pragma_int(database, "PRAGMA user_version");
    if (!version || *version.value_if() <= previous_version) {
      return Result<void>::failure(
          database_corrupt_error("relay_database_migration_version_invalid"));
    }
  }
  return validate_migration_history(database, *version.value_if());
}

int bind_blob(sqlite3_stmt* statement, int index, std::span<const std::byte> bytes) {
  return sqlite3_bind_blob(statement, index, bytes.data(), static_cast<int>(bytes.size()),
                           SQLITE_TRANSIENT);
}

template <std::size_t Size>
int bind_blob(sqlite3_stmt* statement, int index,
              const std::array<std::byte, Size>& bytes) {
  return bind_blob(statement, index, std::span<const std::byte>{bytes});
}

template <std::size_t Size>
Result<std::array<std::byte, Size>> column_blob(sqlite3_stmt* statement, int column,
                                                const char* detail) {
  const auto* bytes = static_cast<const std::byte*>(sqlite3_column_blob(statement, column));
  const int size = sqlite3_column_bytes(statement, column);
  if (bytes == nullptr || size != static_cast<int>(Size)) {
    return Result<std::array<std::byte, Size>>::failure(
        database_corrupt_error(detail));
  }
  std::array<std::byte, Size> output{};
  std::copy_n(bytes, Size, output.begin());
  return Result<std::array<std::byte, Size>>::success(output);
}

std::string_view column_string_view(sqlite3_stmt* statement, int column) {
  const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(statement, column));
  const int size = sqlite3_column_bytes(statement, column);
  return text == nullptr ? std::string_view{} : std::string_view{text, static_cast<std::size_t>(size)};
}

Result<void> bind_id_or_null(sqlite3_stmt* statement, int index,
                             const std::optional<DeviceId>& device_id) {
  if (!device_id) {
    if (sqlite3_bind_null(statement, index) != SQLITE_OK) {
      return Result<void>::failure(database_error(sqlite3_db_handle(statement),
                                                  "relay_database_bind_failed"));
    }
    return Result<void>::success();
  }
  if (device_id->is_zero()) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "relay_database", "relay_database_device_id_invalid"});
  }
  if (bind_blob(statement, index, device_id->bytes()) != SQLITE_OK) {
    return Result<void>::failure(database_error(sqlite3_db_handle(statement),
                                                "relay_database_bind_failed"));
  }
  return Result<void>::success();
}

struct RelayDatabase::Impl {
  explicit Impl(std::filesystem::path database_path, sqlite3* handle) noexcept
      : path(std::move(database_path)), database(handle) {}

  ~Impl() {
    if (database != nullptr) {
      sqlite3_close_v2(database);
    }
  }

  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;

  std::filesystem::path path;
  sqlite3* database{nullptr};
};

Result<RelayBootstrapTokenHash> hash_relay_bootstrap_token(
    std::string_view bootstrap_token) {
  auto valid = validate_relay_bootstrap_token(bootstrap_token);
  if (!valid) {
    return Result<RelayBootstrapTokenHash>::failure(*valid.error_if());
  }
  RelayBootstrapTokenHash hash{};
  static_assert(sizeof(hash) == crypto_hash_sha256_BYTES);
  if (crypto_hash_sha256(reinterpret_cast<unsigned char*>(hash.data()),
                         reinterpret_cast<const unsigned char*>(bootstrap_token.data()),
                         bootstrap_token.size()) != 0) {
    return Result<RelayBootstrapTokenHash>::failure(
        Error{ErrorCode::internal, "relay_database", "relay_database_hash_failed"});
  }
  return Result<RelayBootstrapTokenHash>::success(hash);
}

Result<void> validate_relay_bootstrap_token(std::string_view bootstrap_token) {
  if (bootstrap_token.size() < relay_bootstrap_token_min_bytes ||
      bootstrap_token.size() > relay_bootstrap_token_max_bytes) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "relay_database", "relay_bootstrap_token_length_invalid"});
  }
  for (const char raw_character : bootstrap_token) {
    const auto character = static_cast<unsigned char>(raw_character);
    if (character < 0x21U || character > 0x7eU) {
      return Result<void>::failure(Error{ErrorCode::configuration, "relay_database",
                                         "relay_bootstrap_token_character_invalid"});
    }
  }
  return Result<void>::success();
}

RelayDatabase::RelayDatabase(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
RelayDatabase::RelayDatabase(RelayDatabase&&) noexcept = default;
RelayDatabase& RelayDatabase::operator=(RelayDatabase&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}
RelayDatabase::~RelayDatabase() = default;

Result<RelayDatabase> RelayDatabase::open(const std::filesystem::path& database_path,
                                          const RelayDatabaseOpenOptions& options) {
  if (database_path.empty()) {
    return Result<RelayDatabase>::failure(
        Error{ErrorCode::configuration, "relay_database", "relay_database_path_invalid"});
  }
  const auto crypto = initialize_crypto();
  if (!crypto) {
    return Result<RelayDatabase>::failure(*crypto.error_if());
  }

  int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX;
  if (options.create_if_missing) {
    flags |= SQLITE_OPEN_CREATE;
  }
  sqlite3* database = nullptr;
  const int opened = sqlite3_open_v2(database_path.string().c_str(), &database, flags, nullptr);
  if (opened != SQLITE_OK) {
    const auto error = database_error(database, "relay_database_open_failed", opened);
    if (database != nullptr) {
      sqlite3_close_v2(database);
    }
    return Result<RelayDatabase>::failure(error);
  }
  sqlite3_busy_timeout(database, static_cast<int>(options.sqlite_busy_timeout.count()));
  auto validated = validate_or_migrate(database, options.create_if_missing);
  if (validated) {
    validated = execute(database,
                        "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; "
                        "PRAGMA synchronous=FULL;");
  }
  if (!validated) {
    sqlite3_close_v2(database);
    return Result<RelayDatabase>::failure(*validated.error_if());
  }
  return Result<RelayDatabase>::success(
      RelayDatabase{std::make_unique<Impl>(database_path, database)});
}

Result<void> RelayDatabase::validate_existing(const std::filesystem::path& database_path) {
  RelayDatabaseOpenOptions options;
  options.create_if_missing = false;
  auto opened = RelayDatabase::open(database_path, options);
  if (!opened) {
    return Result<void>::failure(*opened.error_if());
  }
  return Result<void>::success();
}

const std::filesystem::path& RelayDatabase::path() const noexcept {
  static const std::filesystem::path empty;
  return impl_ ? impl_->path : empty;
}

RelayDatabaseSnapshot RelayDatabase::snapshot() const {
  RelayDatabaseSnapshot output;
  if (!impl_) {
    return output;
  }
  auto version = pragma_int(impl_->database, "PRAGMA user_version");
  if (version) {
    output.schema_version = static_cast<std::uint32_t>(*version.value_if());
  }
  auto devices = count_rows(impl_->database, "devices");
  if (devices) {
    output.device_count = *devices.value_if();
  }
  auto tokens = count_rows(impl_->database, "bootstrap_tokens");
  if (tokens) {
    output.bootstrap_token_count = *tokens.value_if();
  }
  auto audits = count_rows(impl_->database, "device_audit");
  if (audits) {
    output.device_audit_count = *audits.value_if();
  }
  return output;
}

Result<RelayBootstrapTokenReceipt> RelayDatabase::create_bootstrap_token(
    std::string tenant, std::string_view bootstrap_token,
    std::uint64_t expires_unix_milliseconds, std::uint64_t remaining_uses) {
  if (!impl_) {
    return Result<RelayBootstrapTokenReceipt>::failure(
        Error{ErrorCode::cancelled, "relay_database", "relay_database_not_open"});
  }
  if (!valid_tenant(tenant)) {
    return Result<RelayBootstrapTokenReceipt>::failure(
        Error{ErrorCode::configuration, "relay_database", "relay_database_tenant_invalid"});
  }
  if (remaining_uses == 0U || remaining_uses > relay_bootstrap_token_max_uses) {
    return Result<RelayBootstrapTokenReceipt>::failure(
        Error{ErrorCode::configuration, "relay_database", "relay_bootstrap_uses_invalid"});
  }
  if (expires_unix_milliseconds <= current_unix_milliseconds()) {
    return Result<RelayBootstrapTokenReceipt>::failure(
        Error{ErrorCode::configuration, "relay_database", "relay_bootstrap_token_expired_at_create"});
  }
  auto hash = hash_relay_bootstrap_token(bootstrap_token);
  if (!hash) {
    return Result<RelayBootstrapTokenReceipt>::failure(*hash.error_if());
  }

  RelayBootstrapTokenId token_id{};
  randombytes_buf(token_id.data(), token_id.size());

  auto begin = execute(impl_->database, "BEGIN IMMEDIATE");
  if (!begin) {
    return Result<RelayBootstrapTokenReceipt>::failure(*begin.error_if());
  }
  auto insert = prepare(
      impl_->database,
      "INSERT INTO bootstrap_tokens("
      "token_id, token_hash, tenant, expires_unix_milliseconds, remaining_uses, "
      "created_unix_milliseconds) VALUES(?, ?, ?, ?, ?, ?)");
  if (!insert) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapTokenReceipt>::failure(*insert.error_if());
  }
  if (bind_blob(insert.value_if()->get(), 1, token_id) != SQLITE_OK ||
      bind_blob(insert.value_if()->get(), 2, *hash.value_if()) != SQLITE_OK ||
      sqlite3_bind_text(insert.value_if()->get(), 3, tenant.c_str(),
                        static_cast<int>(tenant.size()), SQLITE_TRANSIENT) != SQLITE_OK ||
      sqlite3_bind_int64(insert.value_if()->get(), 4,
                         static_cast<sqlite3_int64>(expires_unix_milliseconds)) != SQLITE_OK ||
      sqlite3_bind_int64(insert.value_if()->get(), 5,
                         static_cast<sqlite3_int64>(remaining_uses)) != SQLITE_OK ||
      sqlite3_bind_int64(insert.value_if()->get(), 6,
                         static_cast<sqlite3_int64>(current_unix_milliseconds())) != SQLITE_OK) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapTokenReceipt>::failure(
        database_error(impl_->database, "relay_database_token_bind_failed"));
  }
  const int step = sqlite3_step(insert.value_if()->get());
  if (step != SQLITE_DONE) {
    rollback_best_effort(impl_->database);
    const bool duplicate = (step & 0xff) == SQLITE_CONSTRAINT;
    return Result<RelayBootstrapTokenReceipt>::failure(
        Error{duplicate ? ErrorCode::authentication : ErrorCode::storage, "relay_database",
              duplicate ? "relay_bootstrap_token_already_exists" : "relay_database_token_insert_failed",
              step});
  }
  auto committed = execute(impl_->database, "COMMIT");
  if (!committed) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapTokenReceipt>::failure(*committed.error_if());
  }
  return Result<RelayBootstrapTokenReceipt>::success(RelayBootstrapTokenReceipt{
      .token_id = token_id,
      .token_hash = *hash.value_if(),
      .tenant = std::move(tenant),
      .expires_unix_milliseconds = expires_unix_milliseconds,
      .remaining_uses = remaining_uses});
}

Result<RelayBootstrapConsumption> RelayDatabase::consume_bootstrap_token(
    std::string_view bootstrap_token, std::string_view tenant,
    std::optional<DeviceId> device_id, std::uint64_t now_unix_milliseconds) {
  if (!impl_) {
    return Result<RelayBootstrapConsumption>::failure(
        Error{ErrorCode::cancelled, "relay_database", "relay_database_not_open"});
  }
  if (!valid_tenant(tenant)) {
    return Result<RelayBootstrapConsumption>::failure(
        Error{ErrorCode::configuration, "relay_database", "relay_database_tenant_invalid"});
  }
  auto hash = hash_relay_bootstrap_token(bootstrap_token);
  if (!hash) {
    return Result<RelayBootstrapConsumption>::failure(*hash.error_if());
  }
  auto begin = execute(impl_->database, "BEGIN IMMEDIATE");
  if (!begin) {
    return Result<RelayBootstrapConsumption>::failure(*begin.error_if());
  }

  auto select = prepare(
      impl_->database,
      "SELECT token_id, tenant, expires_unix_milliseconds, remaining_uses "
      "FROM bootstrap_tokens WHERE token_hash = ?");
  if (!select) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapConsumption>::failure(*select.error_if());
  }
  if (bind_blob(select.value_if()->get(), 1, *hash.value_if()) != SQLITE_OK) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapConsumption>::failure(
        database_error(impl_->database, "relay_database_token_lookup_bind_failed"));
  }
  const int step = sqlite3_step(select.value_if()->get());
  if (step != SQLITE_ROW) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapConsumption>::failure(
        Error{ErrorCode::authentication, "relay_database", "relay_bootstrap_token_invalid",
              step});
  }

  const auto* token_id_blob = static_cast<const std::byte*>(
      sqlite3_column_blob(select.value_if()->get(), 0));
  const int token_id_size = sqlite3_column_bytes(select.value_if()->get(), 0);
  const auto* stored_tenant = reinterpret_cast<const char*>(
      sqlite3_column_text(select.value_if()->get(), 1));
  const int stored_tenant_size = sqlite3_column_bytes(select.value_if()->get(), 1);
  const auto expires = static_cast<std::uint64_t>(
      sqlite3_column_int64(select.value_if()->get(), 2));
  const auto remaining_before = static_cast<std::uint64_t>(
      sqlite3_column_int64(select.value_if()->get(), 3));
  if (token_id_blob == nullptr || token_id_size != relay_bootstrap_token_id_bytes ||
      stored_tenant == nullptr ||
      std::string_view{stored_tenant, static_cast<std::size_t>(stored_tenant_size)} != tenant) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapConsumption>::failure(
        Error{ErrorCode::authentication, "relay_database", "relay_bootstrap_token_invalid"});
  }
  RelayBootstrapTokenId token_id{};
  std::copy_n(token_id_blob, token_id.size(), token_id.begin());
  if (now_unix_milliseconds >= expires) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapConsumption>::failure(
        Error{ErrorCode::authentication, "relay_database", "relay_bootstrap_token_expired"});
  }
  if (remaining_before == 0U) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapConsumption>::failure(
        Error{ErrorCode::authentication, "relay_database", "relay_bootstrap_token_exhausted"});
  }

  auto consume = prepare(
      impl_->database,
      "UPDATE bootstrap_tokens SET remaining_uses = remaining_uses - 1 "
      "WHERE token_hash = ? AND tenant = ? AND expires_unix_milliseconds > ? "
      "AND remaining_uses > 0");
  if (!consume) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapConsumption>::failure(*consume.error_if());
  }
  if (bind_blob(consume.value_if()->get(), 1, *hash.value_if()) != SQLITE_OK ||
      sqlite3_bind_text(consume.value_if()->get(), 2, tenant.data(),
                        static_cast<int>(tenant.size()), SQLITE_TRANSIENT) != SQLITE_OK ||
      sqlite3_bind_int64(consume.value_if()->get(), 3,
                         static_cast<sqlite3_int64>(now_unix_milliseconds)) != SQLITE_OK) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapConsumption>::failure(
        database_error(impl_->database, "relay_database_token_consume_bind_failed"));
  }
  auto consumed = step_done(*consume.value_if());
  if (!consumed) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapConsumption>::failure(*consumed.error_if());
  }
  if (sqlite3_changes(impl_->database) != 1) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapConsumption>::failure(
        Error{ErrorCode::authentication, "relay_database", "relay_bootstrap_token_invalid"});
  }

  const std::string metadata = "remaining_uses_before=" + std::to_string(remaining_before);
  auto audit = prepare(
      impl_->database,
      "INSERT INTO device_audit(device_id, action, occurred_unix_milliseconds, metadata) "
      "VALUES(?, 'bootstrap_consumed', ?, ?)");
  if (!audit) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapConsumption>::failure(*audit.error_if());
  }
  auto bound_id = bind_id_or_null(audit.value_if()->get(), 1, device_id);
  if (!bound_id) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapConsumption>::failure(*bound_id.error_if());
  }
  if (sqlite3_bind_int64(audit.value_if()->get(), 2,
                         static_cast<sqlite3_int64>(now_unix_milliseconds)) != SQLITE_OK ||
      sqlite3_bind_text(audit.value_if()->get(), 3, metadata.c_str(),
                        static_cast<int>(metadata.size()), SQLITE_TRANSIENT) != SQLITE_OK) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapConsumption>::failure(
        database_error(impl_->database, "relay_database_audit_bind_failed"));
  }
  auto audit_done = step_done(*audit.value_if());
  if (!audit_done) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapConsumption>::failure(*audit_done.error_if());
  }

  auto committed = execute(impl_->database, "COMMIT");
  if (!committed) {
    rollback_best_effort(impl_->database);
    return Result<RelayBootstrapConsumption>::failure(*committed.error_if());
  }

  return Result<RelayBootstrapConsumption>::success(RelayBootstrapConsumption{
      .token_id = token_id,
      .tenant = std::string{tenant},
      .expires_unix_milliseconds = expires,
      .remaining_uses_before = remaining_before,
      .remaining_uses_after = remaining_before - 1U});
}

Result<void> RelayDatabase::enroll_device(const RelayDeviceRecord& record,
                                           std::uint64_t now_unix_milliseconds) {
  if (!impl_) {
    return Result<void>::failure(
        Error{ErrorCode::cancelled, "relay_database", "relay_database_not_open"});
  }
  if (record.device_id.is_zero() || record.public_key == IdentityPublicKey{} ||
      record.enrollment_generation == 0U || now_unix_milliseconds == 0U ||
      !valid_tenant(record.tenant) || !valid_tenant(record.display_name) ||
      record.status != RelayDeviceStatus::active) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "relay_database", "relay_device_record_invalid"});
  }
  auto derived = derive_device_id(record.public_key);
  if (!derived || *derived.value_if() != record.device_id) {
    return Result<void>::failure(
        Error{ErrorCode::authentication, "relay_database", "relay_device_id_mismatch"});
  }

  auto begin = execute(impl_->database, "BEGIN IMMEDIATE");
  if (!begin) {
    return begin;
  }
  auto select = prepare(
      impl_->database,
      "SELECT enrollment_generation, status, public_key, tenant FROM devices WHERE device_id = ?");
  if (!select) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(*select.error_if());
  }
  if (bind_blob(select.value_if()->get(), 1, record.device_id.bytes()) != SQLITE_OK) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(
        database_error(impl_->database, "relay_device_select_bind_failed"));
  }
  const int step = sqlite3_step(select.value_if()->get());
  if (step != SQLITE_ROW && step != SQLITE_DONE) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(
        database_error(impl_->database, "relay_device_select_failed", step));
  }

  if (step == SQLITE_ROW) {
    const auto existing_generation = static_cast<std::uint64_t>(
        sqlite3_column_int64(select.value_if()->get(), 0));
    const auto existing_status = sqlite3_column_int(select.value_if()->get(), 1);
    auto existing_public_key =
        column_blob<ed25519_public_key_bytes>(select.value_if()->get(), 2,
                                              "relay_device_public_key_corrupt");
    if (!existing_public_key) {
      rollback_best_effort(impl_->database);
      return Result<void>::failure(*existing_public_key.error_if());
    }
    const auto existing_tenant = column_string_view(select.value_if()->get(), 3);
    if (record.enrollment_generation < existing_generation) {
      rollback_best_effort(impl_->database);
      return Result<void>::failure(
          Error{ErrorCode::permission, "relay_database", "relay_device_generation_older"});
    }
    if (record.enrollment_generation == existing_generation) {
      const bool same = IdentityPublicKey{*existing_public_key.value_if()} == record.public_key &&
                        existing_tenant == record.tenant;
      rollback_best_effort(impl_->database);
      if (!same) {
        return Result<void>::failure(
            Error{ErrorCode::permission, "relay_database", "relay_device_enrollment_conflict"});
      }
      if (existing_status == 2) {
        return Result<void>::failure(
            Error{ErrorCode::permission, "relay_database", "relay_device_revoked"});
      }
      return Result<void>::success();
    }
  }

  auto upsert = prepare(
      impl_->database,
      "INSERT INTO devices("
      "device_id, public_key, tenant, display_name, enrollment_generation, status, "
      "created_unix_milliseconds, updated_unix_milliseconds) "
      "VALUES(?, ?, ?, ?, ?, 1, ?, ?) "
      "ON CONFLICT(device_id) DO UPDATE SET "
      "public_key=excluded.public_key, tenant=excluded.tenant, "
      "display_name=excluded.display_name, "
      "enrollment_generation=excluded.enrollment_generation, "
      "status=excluded.status, updated_unix_milliseconds=excluded.updated_unix_milliseconds");
  if (!upsert) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(*upsert.error_if());
  }
  if (bind_blob(upsert.value_if()->get(), 1, record.device_id.bytes()) != SQLITE_OK ||
      bind_blob(upsert.value_if()->get(), 2, record.public_key) != SQLITE_OK ||
      sqlite3_bind_text(upsert.value_if()->get(), 3, record.tenant.c_str(),
                        static_cast<int>(record.tenant.size()), SQLITE_TRANSIENT) != SQLITE_OK ||
      sqlite3_bind_text(upsert.value_if()->get(), 4, record.display_name.c_str(),
                        static_cast<int>(record.display_name.size()), SQLITE_TRANSIENT) !=
          SQLITE_OK ||
      sqlite3_bind_int64(upsert.value_if()->get(), 5,
                         static_cast<sqlite3_int64>(record.enrollment_generation)) != SQLITE_OK ||
      sqlite3_bind_int64(upsert.value_if()->get(), 6,
                         static_cast<sqlite3_int64>(now_unix_milliseconds)) != SQLITE_OK ||
      sqlite3_bind_int64(upsert.value_if()->get(), 7,
                         static_cast<sqlite3_int64>(now_unix_milliseconds)) != SQLITE_OK) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(
        database_error(impl_->database, "relay_device_upsert_bind_failed"));
  }
  auto upserted = step_done(*upsert.value_if());
  if (!upserted) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(*upserted.error_if());
  }

  const std::string metadata = "enrollment_generation=" +
                               std::to_string(record.enrollment_generation);
  auto audit = prepare(
      impl_->database,
      "INSERT INTO device_audit(device_id, action, occurred_unix_milliseconds, metadata) "
      "VALUES(?, 'device_enrolled', ?, ?)");
  if (!audit) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(*audit.error_if());
  }
  if (bind_blob(audit.value_if()->get(), 1, record.device_id.bytes()) != SQLITE_OK ||
      sqlite3_bind_int64(audit.value_if()->get(), 2,
                         static_cast<sqlite3_int64>(now_unix_milliseconds)) != SQLITE_OK ||
      sqlite3_bind_text(audit.value_if()->get(), 3, metadata.c_str(),
                        static_cast<int>(metadata.size()), SQLITE_TRANSIENT) != SQLITE_OK) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(
        database_error(impl_->database, "relay_device_audit_bind_failed"));
  }
  auto audit_done = step_done(*audit.value_if());
  if (!audit_done) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(*audit_done.error_if());
  }

  auto committed = execute(impl_->database, "COMMIT");
  if (!committed) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(*committed.error_if());
  }
  return Result<void>::success();
}

Result<std::optional<RelayDeviceRecord>> RelayDatabase::device(
    const DeviceId& device_id) const {
  if (!impl_) {
    return Result<std::optional<RelayDeviceRecord>>::failure(
        Error{ErrorCode::cancelled, "relay_database", "relay_database_not_open"});
  }
  if (device_id.is_zero()) {
    return Result<std::optional<RelayDeviceRecord>>::failure(
        Error{ErrorCode::configuration, "relay_database", "relay_device_id_invalid"});
  }
  auto select = prepare(
      impl_->database,
      "SELECT device_id, public_key, tenant, display_name, enrollment_generation, "
      "status, created_unix_milliseconds, updated_unix_milliseconds "
      "FROM devices WHERE device_id = ?");
  if (!select) {
    return Result<std::optional<RelayDeviceRecord>>::failure(*select.error_if());
  }
  if (bind_blob(select.value_if()->get(), 1, device_id.bytes()) != SQLITE_OK) {
    return Result<std::optional<RelayDeviceRecord>>::failure(
        database_error(impl_->database, "relay_device_select_bind_failed"));
  }
  const int step = sqlite3_step(select.value_if()->get());
  if (step == SQLITE_DONE) {
    return Result<std::optional<RelayDeviceRecord>>::success(std::nullopt);
  }
  if (step != SQLITE_ROW) {
    return Result<std::optional<RelayDeviceRecord>>::failure(
        database_error(impl_->database, "relay_device_select_failed", step));
  }
  auto device_blob = column_blob<32U>(select.value_if()->get(), 0, "relay_device_id_corrupt");
  auto public_key = column_blob<ed25519_public_key_bytes>(
      select.value_if()->get(), 1, "relay_device_public_key_corrupt");
  if (!device_blob || !public_key) {
    return Result<std::optional<RelayDeviceRecord>>::failure(
        device_blob ? *public_key.error_if() : *device_blob.error_if());
  }
  const auto status_value = sqlite3_column_int(select.value_if()->get(), 5);
  if (status_value != 1 && status_value != 2) {
    return Result<std::optional<RelayDeviceRecord>>::failure(
        database_corrupt_error("relay_device_status_corrupt"));
  }
  RelayDeviceRecord record;
  record.device_id = DeviceId{*device_blob.value_if()};
  record.public_key = *public_key.value_if();
  record.tenant = std::string{column_string_view(select.value_if()->get(), 2)};
  record.display_name = std::string{column_string_view(select.value_if()->get(), 3)};
  record.enrollment_generation = static_cast<std::uint64_t>(
      sqlite3_column_int64(select.value_if()->get(), 4));
  record.status = static_cast<RelayDeviceStatus>(status_value);
  record.created_unix_milliseconds = static_cast<std::uint64_t>(
      sqlite3_column_int64(select.value_if()->get(), 6));
  record.updated_unix_milliseconds = static_cast<std::uint64_t>(
      sqlite3_column_int64(select.value_if()->get(), 7));
  return Result<std::optional<RelayDeviceRecord>>::success(std::move(record));
}

Result<void> RelayDatabase::revoke_device(DeviceId device_id,
                                          std::uint64_t enrollment_generation,
                                          std::uint64_t revoked_unix_milliseconds) {
  if (!impl_) {
    return Result<void>::failure(
        Error{ErrorCode::cancelled, "relay_database", "relay_database_not_open"});
  }
  if (device_id.is_zero() || enrollment_generation == 0U ||
      revoked_unix_milliseconds == 0U) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "relay_database", "relay_revocation_invalid"});
  }
  auto begin = execute(impl_->database, "BEGIN IMMEDIATE");
  if (!begin) {
    return begin;
  }
  auto select = prepare(impl_->database,
                        "SELECT enrollment_generation FROM devices WHERE device_id = ?");
  if (!select) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(*select.error_if());
  }
  if (bind_blob(select.value_if()->get(), 1, device_id.bytes()) != SQLITE_OK) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(
        database_error(impl_->database, "relay_revoke_select_bind_failed"));
  }
  const int step = sqlite3_step(select.value_if()->get());
  if (step == SQLITE_DONE) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(
        Error{ErrorCode::permission, "relay_database", "relay_device_not_found"});
  }
  if (step != SQLITE_ROW) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(
        database_error(impl_->database, "relay_revoke_select_failed", step));
  }
  const auto existing_generation = static_cast<std::uint64_t>(
      sqlite3_column_int64(select.value_if()->get(), 0));
  if (enrollment_generation <= existing_generation) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(
        Error{ErrorCode::permission, "relay_database", "relay_revocation_generation_not_newer"});
  }

  auto update = prepare(
      impl_->database,
      "UPDATE devices SET enrollment_generation = ?, status = 2, "
      "updated_unix_milliseconds = ? WHERE device_id = ?");
  if (!update) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(*update.error_if());
  }
  if (sqlite3_bind_int64(update.value_if()->get(), 1,
                         static_cast<sqlite3_int64>(enrollment_generation)) != SQLITE_OK ||
      sqlite3_bind_int64(update.value_if()->get(), 2,
                         static_cast<sqlite3_int64>(revoked_unix_milliseconds)) != SQLITE_OK ||
      bind_blob(update.value_if()->get(), 3, device_id.bytes()) != SQLITE_OK) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(
        database_error(impl_->database, "relay_revoke_update_bind_failed"));
  }
  auto updated = step_done(*update.value_if());
  if (!updated) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(*updated.error_if());
  }
  const std::string metadata = "enrollment_generation=" +
                               std::to_string(enrollment_generation);
  auto audit = prepare(
      impl_->database,
      "INSERT INTO device_audit(device_id, action, occurred_unix_milliseconds, metadata) "
      "VALUES(?, 'device_revoked', ?, ?)");
  if (!audit) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(*audit.error_if());
  }
  if (bind_blob(audit.value_if()->get(), 1, device_id.bytes()) != SQLITE_OK ||
      sqlite3_bind_int64(audit.value_if()->get(), 2,
                         static_cast<sqlite3_int64>(revoked_unix_milliseconds)) != SQLITE_OK ||
      sqlite3_bind_text(audit.value_if()->get(), 3, metadata.c_str(),
                        static_cast<int>(metadata.size()), SQLITE_TRANSIENT) != SQLITE_OK) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(
        database_error(impl_->database, "relay_revoke_audit_bind_failed"));
  }
  auto audit_done = step_done(*audit.value_if());
  if (!audit_done) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(*audit_done.error_if());
  }
  auto committed = execute(impl_->database, "COMMIT");
  if (!committed) {
    rollback_best_effort(impl_->database);
    return Result<void>::failure(*committed.error_if());
  }
  return Result<void>::success();
}

Result<void> RelayDatabase::record_device_audit(DeviceId device_id, std::string_view action,
                                                std::uint64_t occurred_unix_milliseconds,
                                                std::string_view metadata) {
  if (!impl_) {
    return Result<void>::failure(
        Error{ErrorCode::cancelled, "relay_database", "relay_database_not_open"});
  }
  if (device_id.is_zero() || !valid_audit_action(action) || !valid_audit_metadata(metadata)) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "relay_database", "relay_database_audit_invalid"});
  }
  auto insert = prepare(
      impl_->database,
      "INSERT INTO device_audit(device_id, action, occurred_unix_milliseconds, metadata) "
      "VALUES(?, ?, ?, ?)");
  if (!insert) {
    return Result<void>::failure(*insert.error_if());
  }
  if (bind_blob(insert.value_if()->get(), 1, device_id.bytes()) != SQLITE_OK ||
      sqlite3_bind_text(insert.value_if()->get(), 2, action.data(),
                        static_cast<int>(action.size()), SQLITE_TRANSIENT) != SQLITE_OK ||
      sqlite3_bind_int64(insert.value_if()->get(), 3,
                         static_cast<sqlite3_int64>(occurred_unix_milliseconds)) != SQLITE_OK ||
      sqlite3_bind_text(insert.value_if()->get(), 4, metadata.data(),
                        static_cast<int>(metadata.size()), SQLITE_TRANSIENT) != SQLITE_OK) {
    return Result<void>::failure(
        database_error(impl_->database, "relay_database_audit_bind_failed"));
  }
  return step_done(*insert.value_if());
}

}  // namespace heyaki
