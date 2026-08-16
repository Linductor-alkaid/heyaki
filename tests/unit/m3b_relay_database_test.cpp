#include "relay_database.hpp"

#include <executor/executor.hpp>

#include <gtest/gtest.h>

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

namespace heyaki {
namespace {

using namespace std::chrono_literals;

constexpr std::string_view test_state_dir = HEYAKI_M3B_TEST_STATE_DIR;

class TemporaryDirectory {
 public:
  explicit TemporaryDirectory(std::string_view name) {
    std::error_code error;
    path_ = std::filesystem::path{test_state_dir} / name;
    std::filesystem::remove_all(path_, error);
    error.clear();
    std::filesystem::create_directories(path_, error);
    EXPECT_FALSE(error);
  }
  ~TemporaryDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }
  TemporaryDirectory(const TemporaryDirectory&) = delete;
  TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

 private:
  std::filesystem::path path_;
};

std::uint64_t now_milliseconds() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
}

constexpr std::string_view relay_schema_v1_sql = R"SQL(
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

bool file_contains(const std::filesystem::path& path, std::string_view needle) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    return false;
  }
  std::string contents((std::istreambuf_iterator<char>(input)),
                       std::istreambuf_iterator<char>());
  return contents.find(needle) != std::string::npos;
}

bool sqlite_table_exists(const std::filesystem::path& path, std::string_view table) {
  sqlite3* database = nullptr;
  if (sqlite3_open_v2(path.string().c_str(), &database,
                      SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
    return false;
  }
  const std::string sql = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?";
  sqlite3_stmt* statement = nullptr;
  bool exists = false;
  if (sqlite3_prepare_v2(database, sql.c_str(), -1, &statement, nullptr) == SQLITE_OK) {
    sqlite3_bind_text(statement, 1, table.data(), static_cast<int>(table.size()),
                      SQLITE_TRANSIENT);
    exists = sqlite3_step(statement) == SQLITE_ROW;
  }
  if (statement != nullptr) {
    sqlite3_finalize(statement);
  }
  sqlite3_close_v2(database);
  return exists;
}

bool sqlite_index_exists(const std::filesystem::path& path, std::string_view index) {
  sqlite3* database = nullptr;
  if (sqlite3_open_v2(path.string().c_str(), &database,
                      SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
    return false;
  }
  const std::string sql = "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?";
  sqlite3_stmt* statement = nullptr;
  bool exists = false;
  if (sqlite3_prepare_v2(database, sql.c_str(), -1, &statement, nullptr) == SQLITE_OK) {
    sqlite3_bind_text(statement, 1, index.data(), static_cast<int>(index.size()),
                      SQLITE_TRANSIENT);
    exists = sqlite3_step(statement) == SQLITE_ROW;
  }
  if (statement != nullptr) {
    sqlite3_finalize(statement);
  }
  sqlite3_close_v2(database);
  return exists;
}

void create_v1_fixture(const std::filesystem::path& path) {
  sqlite3* database = nullptr;
  ASSERT_EQ(sqlite3_open_v2(path.string().c_str(), &database,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                            nullptr),
            SQLITE_OK);
  char* message = nullptr;
  const int result =
      sqlite3_exec(database, std::string{relay_schema_v1_sql}.c_str(), nullptr, nullptr, &message);
  ASSERT_EQ(result, SQLITE_OK) << (message == nullptr ? "" : message);
  sqlite3_free(message);
  ASSERT_EQ(sqlite3_close_v2(database), SQLITE_OK);
}

TEST(M3BRelayDatabaseTest, TokenHashValidationAndBoundedInputs) {
  const std::string valid(16U, 'A');
  auto hash = hash_relay_bootstrap_token(valid);
  ASSERT_TRUE(hash) << hash.error_if()->safe_detail();
  EXPECT_NE(*hash.value_if(), RelayBootstrapTokenHash{});

  EXPECT_FALSE(validate_relay_bootstrap_token(std::string(15U, 'A')));
  EXPECT_FALSE(validate_relay_bootstrap_token(std::string(257U, 'A')));
  EXPECT_FALSE(validate_relay_bootstrap_token("token with spaces"));
  EXPECT_FALSE(validate_relay_bootstrap_token("line\nbreak-token"));
}

TEST(M3BRelayDatabaseTest, CreatesCurrentSchemaAndReopensStable) {
  TemporaryDirectory directory{"m3b-relay-db-create"};
  const auto database_path = directory.path() / "relay.sqlite";
  {
    auto database = RelayDatabase::open(database_path);
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    const auto snapshot = database.value_if()->snapshot();
    EXPECT_EQ(snapshot.schema_version, relay_database_schema_version);
    EXPECT_EQ(snapshot.device_count, 0U);
    EXPECT_EQ(snapshot.bootstrap_token_count, 0U);
    EXPECT_EQ(snapshot.device_audit_count, 0U);
    EXPECT_EQ(database.value_if()->path(), database_path);
  }
  EXPECT_TRUE(sqlite_table_exists(database_path, "devices"));
  EXPECT_TRUE(sqlite_table_exists(database_path, "bootstrap_tokens"));
  EXPECT_TRUE(sqlite_table_exists(database_path, "device_audit"));
  EXPECT_TRUE(sqlite_index_exists(database_path, "devices_tenant_status_index"));

  auto reopened = RelayDatabase::open(database_path);
  ASSERT_TRUE(reopened) << reopened.error_if()->safe_detail();
  EXPECT_EQ(reopened.value_if()->snapshot().schema_version, relay_database_schema_version);
  EXPECT_EQ(reopened.value_if()->snapshot().bootstrap_token_count, 0U);
}

TEST(M3BRelayDatabaseTest, MigratesV1FixtureToCurrentSchema) {
  TemporaryDirectory directory{"m3b-relay-db-migrate"};
  const auto database_path = directory.path() / "relay.sqlite";
  create_v1_fixture(database_path);
  EXPECT_TRUE(sqlite_table_exists(database_path, "devices"));
  EXPECT_FALSE(sqlite_index_exists(database_path, "devices_tenant_status_index"));

  auto database = RelayDatabase::open(database_path);
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  EXPECT_EQ(database.value_if()->snapshot().schema_version, relay_database_schema_version);
  EXPECT_TRUE(sqlite_index_exists(database_path, "devices_tenant_status_index"));
  EXPECT_TRUE(sqlite_index_exists(database_path, "bootstrap_tokens_tenant_expiry_index"));
  EXPECT_TRUE(sqlite_index_exists(database_path, "device_audit_device_time_index"));
}

TEST(M3BRelayDatabaseTest, RejectsTooNewAndForeignApplicationIds) {
  TemporaryDirectory directory{"m3b-relay-db-header"};
  const auto too_new = directory.path() / "too-new.sqlite";
  {
    sqlite3* database = nullptr;
    ASSERT_EQ(sqlite3_open_v2(too_new.string().c_str(), &database,
                              SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                              nullptr),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_exec(database, "PRAGMA application_id=1213808977; PRAGMA user_version=99;",
                           nullptr, nullptr, nullptr),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_close_v2(database), SQLITE_OK);
  }
  auto opened_too_new = RelayDatabase::open(too_new);
  ASSERT_FALSE(opened_too_new);
  EXPECT_EQ(opened_too_new.error_if()->code(), ErrorCode::schema_too_new);

  const auto foreign = directory.path() / "foreign.sqlite";
  {
    sqlite3* database = nullptr;
    ASSERT_EQ(sqlite3_open_v2(foreign.string().c_str(), &database,
                              SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                              nullptr),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_exec(database, "PRAGMA application_id=1213808976; PRAGMA user_version=1;",
                           nullptr, nullptr, nullptr),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_close_v2(database), SQLITE_OK);
  }
  auto opened_foreign = RelayDatabase::open(foreign);
  ASSERT_FALSE(opened_foreign);
  EXPECT_EQ(opened_foreign.error_if()->code(), ErrorCode::storage);
  EXPECT_EQ(opened_foreign.error_if()->safe_detail(), "relay_database_application_id_mismatch");
}

TEST(M3BRelayDatabaseTest, BootstrapTokenHashedConsumedAndExhaustedAtomically) {
  TemporaryDirectory directory{"m3b-relay-token"};
  const auto database_path = directory.path() / "relay.sqlite";
  auto database = RelayDatabase::open(database_path);
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  const std::string token = "TEST-ONLY-bootstrap-token-0123456789";
  const auto now = now_milliseconds();
  const auto created = database.value_if()->create_bootstrap_token(
      "tenant-a", token, now + 60U * 1000U, 2U);
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  EXPECT_EQ(database.value_if()->snapshot().bootstrap_token_count, 1U);

  auto first = database.value_if()->consume_bootstrap_token(
      token, "tenant-a", std::nullopt, now + 1U);
  ASSERT_TRUE(first) << first.error_if()->safe_detail();
  EXPECT_EQ(first.value_if()->remaining_uses_before, 2U);
  EXPECT_EQ(first.value_if()->remaining_uses_after, 1U);
  EXPECT_EQ(first.value_if()->token_id, created.value_if()->token_id);

  auto second = database.value_if()->consume_bootstrap_token(
      token, "tenant-a", std::nullopt, now + 2U);
  ASSERT_TRUE(second) << second.error_if()->safe_detail();
  EXPECT_EQ(second.value_if()->remaining_uses_before, 1U);
  EXPECT_EQ(second.value_if()->remaining_uses_after, 0U);
  EXPECT_EQ(database.value_if()->snapshot().device_audit_count, 2U);

  auto exhausted = database.value_if()->consume_bootstrap_token(
      token, "tenant-a", std::nullopt, now + 3U);
  ASSERT_FALSE(exhausted);
  EXPECT_EQ(exhausted.error_if()->code(), ErrorCode::authentication);
  EXPECT_EQ(exhausted.error_if()->safe_detail(), "relay_bootstrap_token_exhausted");
  EXPECT_EQ(database.value_if()->snapshot().bootstrap_token_count, 1U);
  EXPECT_EQ(database.value_if()->snapshot().device_audit_count, 2U);

  auto wrong_tenant = database.value_if()->consume_bootstrap_token(
      token, "tenant-b", std::nullopt, now + 4U);
  ASSERT_FALSE(wrong_tenant);
  EXPECT_EQ(wrong_tenant.error_if()->safe_detail(), "relay_bootstrap_token_invalid");

  auto duplicate = database.value_if()->create_bootstrap_token(
      "tenant-a", token, now + 60U * 1000U, 1U);
  ASSERT_FALSE(duplicate);
  EXPECT_EQ(duplicate.error_if()->safe_detail(), "relay_bootstrap_token_already_exists");
}

TEST(M3BRelayDatabaseTest, ExpiredTokenRejectedWithoutAuditMutation) {
  TemporaryDirectory directory{"m3b-relay-token-expired"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  const std::string token = "TEST-ONLY-expired-token-0123456789";
  const auto now = now_milliseconds();
  auto created = database.value_if()->create_bootstrap_token(
      "tenant-a", token, now + 10U, 3U);
  ASSERT_TRUE(created) << created.error_if()->safe_detail();

  auto consumed = database.value_if()->consume_bootstrap_token(
      token, "tenant-a", std::nullopt, now + 20U);
  ASSERT_FALSE(consumed);
  EXPECT_EQ(consumed.error_if()->safe_detail(), "relay_bootstrap_token_expired");
  EXPECT_EQ(database.value_if()->snapshot().bootstrap_token_count, 1U);
  EXPECT_EQ(database.value_if()->snapshot().device_audit_count, 0U);
}

TEST(M3BRelayDatabaseTest, RawTokenIsNeverStoredInDatabaseFiles) {
  TemporaryDirectory directory{"m3b-relay-token-secret"};
  const auto database_path = directory.path() / "relay.sqlite";
  const std::string token = "TEST-ONLY-secret-token-0123456789ABCDEF";
  {
    auto database = RelayDatabase::open(database_path);
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    auto created = database.value_if()->create_bootstrap_token(
        "tenant-a", token, now_milliseconds() + 60U * 1000U, 1U);
    ASSERT_TRUE(created) << created.error_if()->safe_detail();
    auto consumed = database.value_if()->consume_bootstrap_token(
        token, "tenant-a", std::nullopt, now_milliseconds() + 1U);
    ASSERT_TRUE(consumed) << consumed.error_if()->safe_detail();
  }
  EXPECT_FALSE(file_contains(database_path, token));
  EXPECT_FALSE(file_contains(database_path.string() + "-wal", token));
  EXPECT_FALSE(file_contains(database_path.string() + "-shm", token));
}

TEST(M3BRelayDatabaseTest, ConcurrentConsumptionAllowsExactlyOneWinner) {
  TemporaryDirectory directory{"m3b-relay-token-concurrent"};
  const auto database_path = directory.path() / "relay.sqlite";
  {
    auto creator = RelayDatabase::open(database_path);
    ASSERT_TRUE(creator) << creator.error_if()->safe_detail();
    const std::string token = "TEST-ONLY-concurrent-token-0123456789";
    auto created = creator.value_if()->create_bootstrap_token(
        "tenant-a", token, now_milliseconds() + 60U * 1000U, 1U);
    ASSERT_TRUE(created) << created.error_if()->safe_detail();
  }

  executor::Executor executor;
  executor::ExecutorConfig executor_config;
  executor_config.min_threads = 2U;
  executor_config.max_threads = 2U;
  ASSERT_TRUE(executor.initialize_ex(executor_config));

  auto first_db = RelayDatabase::open(database_path);
  auto second_db = RelayDatabase::open(database_path);
  ASSERT_TRUE(first_db) << first_db.error_if()->safe_detail();
  ASSERT_TRUE(second_db) << second_db.error_if()->safe_detail();
  const std::string token = "TEST-ONLY-concurrent-token-0123456789";
  const auto now = now_milliseconds();
  auto* first = first_db.value_if();
  auto* second = second_db.value_if();

  auto first_future = executor.submit_auto(
      executor::task([first, token, now]() {
        return first->consume_bootstrap_token(token, "tenant-a", std::nullopt, now + 1U);
      }).name("relay-token-consume-1"));
  auto second_future = executor.submit_auto(
      executor::task([second, token, now]() {
        return second->consume_bootstrap_token(token, "tenant-a", std::nullopt, now + 1U);
      }).name("relay-token-consume-2"));
  ASSERT_TRUE(first_future.wait_for(5s) == std::future_status::ready);
  ASSERT_TRUE(second_future.wait_for(5s) == std::future_status::ready);

  const auto first_result = first_future.get();
  const auto second_result = second_future.get();
  const int success_count = (first_result ? 1 : 0) + (second_result ? 1 : 0);
  EXPECT_EQ(success_count, 1);
  EXPECT_EQ(first_db.value_if()->snapshot().device_audit_count, 1U);

  (void)executor.shutdown(true);
}

}  // namespace
}  // namespace heyaki
