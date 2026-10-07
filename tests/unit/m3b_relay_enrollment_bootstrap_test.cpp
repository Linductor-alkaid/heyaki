// Issue #22 verification: schema v3 + enrollment_password table, v2->v3
// migration, enrollment config keys, and the RelayWssEnrollmentResult
// certificate fingerprint field.
#include "relay_config.hpp"
#include "relay_database.hpp"

#include <heyaki/relay_wss_control.hpp>

#include "heyaki/enrollment/v1/enrollment.pb.h"

#include <gtest/gtest.h>

#include <sqlite3.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {
namespace {

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

// Schema v1 + migration v2 exactly as a pre-v3 relay database looks, so
// RelayDatabase::open must migrate it to v3 in place.
constexpr std::string_view relay_schema_v2_sql = R"SQL(
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
CREATE INDEX devices_tenant_status_index
  ON devices(tenant, status);
CREATE INDEX bootstrap_tokens_tenant_expiry_index
  ON bootstrap_tokens(tenant, expires_unix_milliseconds);
CREATE INDEX device_audit_device_time_index
  ON device_audit(device_id, occurred_unix_milliseconds);
INSERT INTO schema_migrations(version, applied_unix_milliseconds)
VALUES(1, CAST(unixepoch('subsec') * 1000 AS INTEGER));
INSERT INTO schema_migrations(version, applied_unix_milliseconds)
VALUES(2, CAST(unixepoch('subsec') * 1000 AS INTEGER));
PRAGMA application_id=1213808977;
PRAGMA user_version=2;
)SQL";

void create_v2_fixture(const std::filesystem::path& path) {
  sqlite3* database = nullptr;
  ASSERT_EQ(sqlite3_open_v2(path.string().c_str(), &database,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                            nullptr),
            SQLITE_OK);
  char* message = nullptr;
  const int result =
      sqlite3_exec(database, std::string{relay_schema_v2_sql}.c_str(), nullptr, nullptr,
                   &message);
  ASSERT_EQ(result, SQLITE_OK) << (message == nullptr ? "" : message);
  sqlite3_free(message);
  ASSERT_EQ(sqlite3_close_v2(database), SQLITE_OK);
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

std::vector<std::uint32_t> migration_versions(const std::filesystem::path& path) {
  sqlite3* database = nullptr;
  EXPECT_EQ(sqlite3_open_v2(path.string().c_str(), &database,
                            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nullptr),
            SQLITE_OK);
  std::vector<std::uint32_t> versions;
  sqlite3_stmt* statement = nullptr;
  if (sqlite3_prepare_v2(database, "SELECT version FROM schema_migrations ORDER BY version",
                         -1, &statement, nullptr) == SQLITE_OK) {
    while (sqlite3_step(statement) == SQLITE_ROW) {
      versions.push_back(static_cast<std::uint32_t>(sqlite3_column_int(statement, 0)));
    }
  }
  if (statement != nullptr) {
    sqlite3_finalize(statement);
  }
  sqlite3_close_v2(database);
  return versions;
}

void write_config(const std::filesystem::path& root, std::string_view contents) {
  std::ofstream output{root / "relay.conf", std::ios::binary | std::ios::trunc};
  ASSERT_TRUE(output);
  output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  output.close();
  ASSERT_TRUE(output);
}

// 32 distinguishable fingerprint bytes.
std::array<std::byte, 32U> test_fingerprint(std::uint8_t seed) {
  std::array<std::byte, 32U> fingerprint{};
  for (std::size_t index = 0U; index < fingerprint.size(); ++index) {
    fingerprint[index] = static_cast<std::byte>(seed + static_cast<std::uint8_t>(index * 3U));
  }
  return fingerprint;
}

// ---------------------------------------------------------------------------
// RelayDatabase: schema v3 and the enrollment_password verifier.
// ---------------------------------------------------------------------------

TEST(M3BRelayEnrollmentBootstrapTest, FreshDatabaseHasV3SchemaAndEmptyVerifier) {
  TemporaryDirectory directory{"m3b-relay-enroll-db-v3-fresh"};
  const auto database_path = directory.path() / "relay.sqlite";
  auto database = RelayDatabase::open(database_path);
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  EXPECT_EQ(database.value_if()->snapshot().schema_version, 3U);
  EXPECT_EQ(relay_database_schema_version, 3U);
  EXPECT_TRUE(sqlite_table_exists(database_path, "enrollment_password"));

  auto verifier = database.value_if()->enrollment_password_verifier();
  ASSERT_TRUE(verifier) << verifier.error_if()->safe_detail();
  EXPECT_EQ(*verifier.value_if(), std::nullopt);
}

TEST(M3BRelayEnrollmentBootstrapTest, PasswordVerifierRoundTripReplaceAndPersist) {
  TemporaryDirectory directory{"m3b-relay-enroll-db-verifier"};
  const auto database_path = directory.path() / "relay.sqlite";
  auto database = RelayDatabase::open(database_path);
  ASSERT_TRUE(database) << database.error_if()->safe_detail();

  RelayEnrollmentPasswordRecord record;
  record.format_version = 1U;
  record.argon2_operations = 3U;
  record.argon2_memory_kib = 131072U;
  record.encoded =
      "$argon2id$v=19$m=131072,t=3,c29tZXNhbHRzb21lc2FsdA$Zkm2p3Fq0Y0vWqfEeQ7PQg";
  record.updated_unix_milliseconds = 1'770'000'000'000U;
  auto stored = database.value_if()->set_enrollment_password_verifier(record);
  ASSERT_TRUE(stored) << stored.error_if()->safe_detail();

  auto loaded = database.value_if()->enrollment_password_verifier();
  ASSERT_TRUE(loaded) << loaded.error_if()->safe_detail();
  ASSERT_TRUE(loaded.value_if()->has_value());
  EXPECT_EQ((*loaded.value_if())->format_version, record.format_version);
  EXPECT_EQ((*loaded.value_if())->argon2_operations, record.argon2_operations);
  EXPECT_EQ((*loaded.value_if())->argon2_memory_kib, record.argon2_memory_kib);
  EXPECT_EQ((*loaded.value_if())->encoded, record.encoded);
  EXPECT_EQ((*loaded.value_if())->updated_unix_milliseconds,
            record.updated_unix_milliseconds);

  // Setting again replaces the single row.
  RelayEnrollmentPasswordRecord replacement;
  replacement.format_version = 1U;
  replacement.argon2_operations = 2U;
  replacement.argon2_memory_kib = 65536U;
  replacement.encoded =
      "$argon2id$v=19$m=65536,t=2,yetFhXRoZXJzYWx0eWV0$Zkm2p3Fq0Y0vWqfEeQ7PQg";
  replacement.updated_unix_milliseconds = 1'770'000'100'000U;
  auto replaced = database.value_if()->set_enrollment_password_verifier(replacement);
  ASSERT_TRUE(replaced) << replaced.error_if()->safe_detail();
  auto reloaded = database.value_if()->enrollment_password_verifier();
  ASSERT_TRUE(reloaded) << reloaded.error_if()->safe_detail();
  ASSERT_TRUE(reloaded.value_if()->has_value());
  EXPECT_EQ((*reloaded.value_if())->encoded, replacement.encoded);
  EXPECT_EQ((*reloaded.value_if())->updated_unix_milliseconds,
            replacement.updated_unix_milliseconds);

  // The verifier survives a reopen.
  auto reopened = RelayDatabase::open(database_path);
  ASSERT_TRUE(reopened) << reopened.error_if()->safe_detail();
  auto persisted = reopened.value_if()->enrollment_password_verifier();
  ASSERT_TRUE(persisted) << persisted.error_if()->safe_detail();
  ASSERT_TRUE(persisted.value_if()->has_value());
  EXPECT_EQ((*persisted.value_if())->encoded, replacement.encoded);
}

TEST(M3BRelayEnrollmentBootstrapTest, RejectsInvalidPasswordVerifierRecords) {
  TemporaryDirectory directory{"m3b-relay-enroll-db-verifier-invalid"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();

  RelayEnrollmentPasswordRecord base;
  base.format_version = 1U;
  base.argon2_operations = 2U;
  base.argon2_memory_kib = 65536U;
  base.encoded = "$argon2id$v=19$m=65536,t=2,c2FsdA$aGFzaA";
  base.updated_unix_milliseconds = 42U;

  auto expect_rejected = [&](RelayEnrollmentPasswordRecord record) {
    auto stored = database.value_if()->set_enrollment_password_verifier(record);
    EXPECT_FALSE(stored);
    if (stored) {
      return;
    }
    EXPECT_EQ(stored.error_if()->code(), ErrorCode::configuration);
    EXPECT_EQ(stored.error_if()->safe_detail(),
              "relay_enrollment_password_record_invalid");
  };

  auto wrong_format = base;
  wrong_format.format_version = 2U;
  expect_rejected(wrong_format);

  auto empty_encoded = base;
  empty_encoded.encoded.clear();
  expect_rejected(empty_encoded);

  auto oversized = base;
  oversized.encoded = std::string(relay_enrollment_password_encoded_max_bytes + 1U, 'a');
  expect_rejected(oversized);

  auto with_whitespace = base;
  with_whitespace.encoded = "$argon2id$v=19 m=65536,t=2,c2FsdA$aGFzaA";
  expect_rejected(with_whitespace);

  auto zero_operations = base;
  zero_operations.argon2_operations = 0U;
  expect_rejected(zero_operations);

  auto too_many_operations = base;
  too_many_operations.argon2_operations = 17U;
  expect_rejected(too_many_operations);

  auto tiny_memory = base;
  tiny_memory.argon2_memory_kib = 8191U;
  expect_rejected(tiny_memory);

  auto zero_updated = base;
  zero_updated.updated_unix_milliseconds = 0U;
  expect_rejected(zero_updated);

  auto loaded = database.value_if()->enrollment_password_verifier();
  ASSERT_TRUE(loaded) << loaded.error_if()->safe_detail();
  EXPECT_EQ(*loaded.value_if(), std::nullopt);
}

TEST(M3BRelayEnrollmentBootstrapTest, MigratesV2DatabaseToV3PreservingData) {
  TemporaryDirectory directory{"m3b-relay-enroll-db-v2-migrate"};
  const auto database_path = directory.path() / "relay.sqlite";
  create_v2_fixture(database_path);

  // Pre-existing device row the migration must preserve.
  constexpr std::string_view device_id_hex =
      "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
  {
    sqlite3* database = nullptr;
    ASSERT_EQ(sqlite3_open_v2(database_path.string().c_str(), &database,
                              SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nullptr),
              SQLITE_OK);
    char* message = nullptr;
    const std::string insert =
        "INSERT INTO devices(device_id, public_key, tenant, display_name, "
        "enrollment_generation, status, created_unix_milliseconds, "
        "updated_unix_milliseconds) VALUES(x'" +
        std::string{device_id_hex} +
        "', x'" + std::string{device_id_hex} +
        "', 'tenant-a', 'legacy-device', 3, 1, 111, 222);";
    const int result =
        sqlite3_exec(database, insert.c_str(), nullptr, nullptr, &message);
    ASSERT_EQ(result, SQLITE_OK) << (message == nullptr ? "" : message);
    sqlite3_free(message);
    ASSERT_EQ(sqlite3_close_v2(database), SQLITE_OK);
  }
  EXPECT_FALSE(sqlite_table_exists(database_path, "enrollment_password"));

  auto database = RelayDatabase::open(database_path);
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  EXPECT_EQ(database.value_if()->snapshot().schema_version, 3U);
  EXPECT_TRUE(sqlite_table_exists(database_path, "enrollment_password"));
  EXPECT_EQ(migration_versions(database_path),
            (std::vector<std::uint32_t>{1U, 2U, 3U}));

  DeviceId::Storage legacy_device_bytes{};
  for (std::size_t index = 0U; index < legacy_device_bytes.size(); ++index) {
    const auto byte =
        std::stoul(std::string{device_id_hex.substr(index * 2U, 2U)}, nullptr, 16U);
    legacy_device_bytes[index] = static_cast<std::byte>(byte);
  }
  const DeviceId legacy_device{legacy_device_bytes};
  auto device = database.value_if()->device(legacy_device);
  ASSERT_TRUE(device) << device.error_if()->safe_detail();
  ASSERT_TRUE(device.value_if()->has_value());
  EXPECT_EQ((*device.value_if())->tenant, "tenant-a");
  EXPECT_EQ((*device.value_if())->display_name, "legacy-device");
  EXPECT_EQ((*device.value_if())->enrollment_generation, 3U);
  EXPECT_EQ((*device.value_if())->status, RelayDeviceStatus::active);

  auto verifier = database.value_if()->enrollment_password_verifier();
  ASSERT_TRUE(verifier) << verifier.error_if()->safe_detail();
  EXPECT_EQ(*verifier.value_if(), std::nullopt);
}

// ---------------------------------------------------------------------------
// relay.conf enrollment keys.
// ---------------------------------------------------------------------------

TEST(M3BRelayEnrollmentBootstrapTest, LoadsEnrollmentModeAndTenantKeys) {
  TemporaryDirectory directory{"m3b-relay-enroll-config"};
  {
    // The loader checks referenced certificate/key existence after parsing.
    std::ofstream cert{directory.path() / "relay-cert.pem", std::ios::binary | std::ios::trunc};
    std::ofstream key{directory.path() / "relay-key.pem", std::ios::binary | std::ios::trunc};
    cert << "test";
    key << "test";
  }
  const std::array<RelayEnrollmentMode, 3U> modes{
      RelayEnrollmentMode::token, RelayEnrollmentMode::password,
      RelayEnrollmentMode::closed};
  const std::array<std::string_view, 3U> mode_texts{"token", "password", "closed"};
  for (std::size_t index = 0U; index < modes.size(); ++index) {
    write_config(directory.path(),
                 std::string{"tls_certificate_file = relay-cert.pem\n"
                             "tls_private_key_file = relay-key.pem\n"
                             "database_file = relay.sqlite\n"
                             "enrollment_mode = "} +
                     std::string{mode_texts[index]} +
                     "\nenrollment_default_tenant = ops\n");
    auto loaded = load_relay_config_file(directory.path() / "relay.conf");
    ASSERT_TRUE(loaded) << loaded.error_if()->safe_detail();
    EXPECT_EQ(loaded.value_if()->enrollment_mode, modes[index]);
    EXPECT_EQ(loaded.value_if()->enrollment_default_tenant, "ops");
  }
}

TEST(M3BRelayEnrollmentBootstrapTest, DefaultsToTokenModeAndDefaultTenant) {
  RelayServerConfig defaults;
  EXPECT_EQ(defaults.enrollment_mode, RelayEnrollmentMode::token);
  EXPECT_EQ(defaults.enrollment_default_tenant, "default");
  EXPECT_EQ(RelayEnrollmentMode{RelayEnrollmentMode::token},
            static_cast<RelayEnrollmentMode>(1U));
  EXPECT_EQ(static_cast<std::uint8_t>(RelayEnrollmentMode::password), 2U);
  EXPECT_EQ(static_cast<std::uint8_t>(RelayEnrollmentMode::closed), 3U);
}

TEST(M3BRelayEnrollmentBootstrapTest, RejectsInvalidEnrollmentKeys) {
  TemporaryDirectory directory{"m3b-relay-enroll-config-invalid"};
  {
    // The loader checks referenced certificate/key existence after parsing.
    std::ofstream cert{directory.path() / "relay-cert.pem", std::ios::binary | std::ios::trunc};
    std::ofstream key{directory.path() / "relay-key.pem", std::ios::binary | std::ios::trunc};
    cert << "test";
    key << "test";
  }
  const std::vector<std::pair<std::string, std::string>> invalid{
      {"enrollment_mode = open\n", "relay_config_enrollment_mode_invalid"},
      {"enrollment_mode = TOKEN\n", "relay_config_enrollment_mode_invalid"},
      // An empty value is caught by the generic line grammar first.
      {"enrollment_mode =\n", "relay_config_line_invalid"},
      {"enrollment_default_tenant = has space\n",
       "relay_config_enrollment_tenant_invalid"},
      {"enrollment_default_tenant =\n", "relay_config_line_invalid"},
      {"enrollment_default_tenant = " + std::string(129, 'a') + "\n",
       "relay_config_enrollment_tenant_invalid"},
      {"enrollment_mode = password\nenrollment_mode = token\n",
       "relay_config_duplicate_key"},
      {"enrollment_default_tenant = ops\nenrollment_default_tenant = ops\n",
       "relay_config_duplicate_key"},
  };
  for (const auto& [key_line, expected_detail] : invalid) {
    write_config(directory.path(), key_line);
    auto loaded = load_relay_config_file(directory.path() / "relay.conf");
    ASSERT_FALSE(loaded) << "expected rejection for: " << key_line;
    EXPECT_EQ(loaded.error_if()->code(), ErrorCode::configuration);
    EXPECT_EQ(loaded.error_if()->safe_detail(), expected_detail) << key_line;
  }

  // validate_relay_server_config enforces the tenant policy independently of
  // the file loader: everything else default-valid, empty tenant rejected.
  RelayServerConfig valid_config;
  valid_config.tls_certificate_file = "relay-cert.pem";
  valid_config.tls_private_key_file = "relay-key.pem";
  auto baseline = validate_relay_server_config(valid_config);
  ASSERT_TRUE(baseline) << baseline.error_if()->safe_detail();
  valid_config.enrollment_default_tenant = "has space";
  auto rejected = validate_relay_server_config(valid_config);
  ASSERT_FALSE(rejected);
}

// ---------------------------------------------------------------------------
// RelayWssEnrollmentResult certificate fingerprint.
// ---------------------------------------------------------------------------

TEST(M3BRelayEnrollmentBootstrapTest, EnrollmentResultWithoutFingerprintKeepsLegacyBytes) {
  RelayWssEnrollmentResult result{.tenant = "tenant-a",
                                  .enrollment_generation = 7U,
                                  .token_remaining_uses_after = 2U,
                                  .relay_certificate_sha256 = std::nullopt};
  auto encoded = encode_relay_wss_enrollment_result(result);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();

  // Legacy wire shape: tenant + generation + token counter, no field 4.
  protocol::enrollment::v1::EnrollmentResult legacy;
  legacy.set_tenant("tenant-a");
  legacy.set_enrollment_generation(7U);
  legacy.set_token_remaining_uses_after(2U);
  const auto legacy_bytes = legacy.SerializeAsString();
  EXPECT_EQ(*encoded.value_if(),
            std::vector<std::byte>(
                reinterpret_cast<const std::byte*>(legacy_bytes.data()),
                reinterpret_cast<const std::byte*>(legacy_bytes.data()) +
                    legacy_bytes.size()));

  auto parsed = parse_relay_wss_enrollment_result(*encoded.value_if());
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  EXPECT_EQ(parsed.value_if()->tenant, "tenant-a");
  EXPECT_EQ(parsed.value_if()->enrollment_generation, 7U);
  EXPECT_EQ(parsed.value_if()->token_remaining_uses_after, 2U);
  EXPECT_FALSE(parsed.value_if()->relay_certificate_sha256.has_value());

  // token_remaining_uses_after == 0 omits field 3 as before.
  result.token_remaining_uses_after = 0U;
  auto zero_encoded = encode_relay_wss_enrollment_result(result);
  ASSERT_TRUE(zero_encoded) << zero_encoded.error_if()->safe_detail();
  legacy.set_token_remaining_uses_after(0U);
  const auto zero_bytes = legacy.SerializeAsString();
  EXPECT_EQ(*zero_encoded.value_if(),
            std::vector<std::byte>(
                reinterpret_cast<const std::byte*>(zero_bytes.data()),
                reinterpret_cast<const std::byte*>(zero_bytes.data()) +
                    zero_bytes.size()));
}

TEST(M3BRelayEnrollmentBootstrapTest, EnrollmentResultFingerprintRoundTrip) {
  RelayWssEnrollmentResult result{.tenant = "default",
                                  .enrollment_generation = 1U,
                                  .token_remaining_uses_after = 0U,
                                  .relay_certificate_sha256 = test_fingerprint(0x5EU)};
  auto encoded = encode_relay_wss_enrollment_result(result);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();

  protocol::enrollment::v1::EnrollmentResult expected;
  expected.set_tenant("default");
  expected.set_enrollment_generation(1U);
  const auto fingerprint = *result.relay_certificate_sha256;
  expected.set_relay_certificate_sha256(
      reinterpret_cast<const char*>(fingerprint.data()), fingerprint.size());
  const auto expected_bytes = expected.SerializeAsString();
  EXPECT_EQ(*encoded.value_if(),
            std::vector<std::byte>(
                reinterpret_cast<const std::byte*>(expected_bytes.data()),
                reinterpret_cast<const std::byte*>(expected_bytes.data()) +
                    expected_bytes.size()));

  auto parsed = parse_relay_wss_enrollment_result(*encoded.value_if());
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  ASSERT_TRUE(parsed.value_if()->relay_certificate_sha256.has_value());
  EXPECT_EQ(*parsed.value_if()->relay_certificate_sha256, fingerprint);
  EXPECT_EQ(parsed.value_if()->tenant, "default");
  EXPECT_EQ(parsed.value_if()->enrollment_generation, 1U);
  EXPECT_EQ(parsed.value_if()->token_remaining_uses_after, 0U);
}

TEST(M3BRelayEnrollmentBootstrapTest, EnrollmentResultRejectsWrongFingerprintLength) {
  RelayWssEnrollmentResult result{.tenant = "default",
                                  .enrollment_generation = 1U,
                                  .token_remaining_uses_after = 0U,
                                  .relay_certificate_sha256 = std::nullopt};
  auto encoded = encode_relay_wss_enrollment_result(result);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();

  // Field 4 (tag 0x22) with a 31-byte payload is structurally decodable but
  // not a SHA-256 digest: the parser must refuse it.
  std::vector<std::byte> short_fingerprint = *encoded.value_if();
  std::array<std::byte, 31U> truncated{};
  short_fingerprint.push_back(static_cast<std::byte>((4U << 3U) | 2U));
  short_fingerprint.push_back(std::byte{31U});
  short_fingerprint.insert(short_fingerprint.end(), truncated.begin(), truncated.end());
  auto short_parsed = parse_relay_wss_enrollment_result(short_fingerprint);
  ASSERT_FALSE(short_parsed);
  EXPECT_EQ(short_parsed.error_if()->safe_detail(), "enrollment_result_field_invalid");

  std::vector<std::byte> long_fingerprint = *encoded.value_if();
  std::array<std::byte, 33U> oversized{};
  long_fingerprint.push_back(static_cast<std::byte>((4U << 3U) | 2U));
  long_fingerprint.push_back(std::byte{33U});
  long_fingerprint.insert(long_fingerprint.end(), oversized.begin(), oversized.end());
  auto long_parsed = parse_relay_wss_enrollment_result(long_fingerprint);
  ASSERT_FALSE(long_parsed);
  EXPECT_EQ(long_parsed.error_if()->safe_detail(), "enrollment_result_field_invalid");
}

}  // namespace
}  // namespace heyaki
