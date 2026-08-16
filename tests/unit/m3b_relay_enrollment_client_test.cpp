#include <heyaki/password.hpp>
#include <heyaki/relay_enrollment_client.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
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
#ifndef _WIN32
    EXPECT_EQ(::chmod(path_.c_str(), S_IRWXU), 0);
#endif
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

ProfileOpenOptions encrypted_file_options() {
  ProfileOpenOptions options;
  options.secret_backend.prefer_os_backend = false;
  return options;
}

Result<ProfileStore> create_initialized_profile(const std::filesystem::path& path) {
  auto created = ProfileStore::create(path, encrypted_file_options());
  if (!created) {
    return Result<ProfileStore>::failure(*created.error_if());
  }
  auto verifier = create_password_verifier("correct horse battery staple", {});
  if (!verifier) {
    return Result<ProfileStore>::failure(*verifier.error_if());
  }
  LocalProfileInitialization initialization;
  initialization.application_id = "com.example.relay-client";
  initialization.password_verifier = std::move(*verifier.value_if());
  initialization.password_generation = 1U;
  initialization.pairing_policy = PairingPolicy{};
  initialization.lan = LanConfiguration{};
  auto initialized = created.value_if()->initialize_local(initialization);
  if (!initialized) {
    return Result<ProfileStore>::failure(*initialized.error_if());
  }
  return created;
}

std::uint64_t now_milliseconds() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
}

TEST(M3BRelayEnrollmentClientTest, PersistsOnlyAfterSuccessfulExchange) {
  TemporaryDirectory directory{"m3b-relay-enroll-client"};
  auto profile = create_initialized_profile(directory.path() / "profile.sqlite");
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();

  RelayEnrollmentClientConfig config;
  config.profile = profile.value_if();
  config.application_id = "com.example.relay-client";
  config.relay_url = "wss://relay.example/enroll";
  config.tenant = "tenant-a";
  config.exchange = [](const IdentityKeyPair& identity, const EndpointId& endpoint_id,
                       std::string_view tenant, std::string_view /*token*/,
                       std::uint64_t /*now*/) -> Result<RelayEnrollmentExchangeResult> {
    EXPECT_FALSE(identity.device_id().is_zero());
    EXPECT_FALSE(endpoint_id.is_zero());
    EXPECT_EQ(tenant, "tenant-a");
    return Result<RelayEnrollmentExchangeResult>::success(RelayEnrollmentExchangeResult{
        .relay_url = "wss://relay.example/enroll",
        .tenant = "tenant-a",
        .enrollment_generation = 1U,
        .token_remaining_uses_after = 2U});
  };

  auto enrolled = enroll_relay_profile(config, "TEST-ONLY-enrollment-token-012345",
                                       now_milliseconds());
  ASSERT_TRUE(enrolled) << enrolled.error_if()->safe_detail();
  EXPECT_EQ(enrolled.value_if()->enrollment_generation, 1U);

  auto persisted =
      profile.value_if()->relay_enrollment("wss://relay.example/enroll");
  ASSERT_TRUE(persisted) << persisted.error_if()->safe_detail();
  ASSERT_TRUE(persisted.value_if()->has_value());
  EXPECT_EQ(persisted.value_if()->value().tenant, "tenant-a");
  EXPECT_EQ(persisted.value_if()->value().enrollment_generation, 1U);
  EXPECT_TRUE(persisted.value_if()->value().auto_connect);
}

TEST(M3BRelayEnrollmentClientTest, ExchangeFailureDoesNotPersist) {
  TemporaryDirectory directory{"m3b-relay-enroll-client-fail"};
  auto profile = create_initialized_profile(directory.path() / "profile.sqlite");
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();

  RelayEnrollmentClientConfig config;
  config.profile = profile.value_if();
  config.application_id = "com.example.relay-client";
  config.relay_url = "wss://relay.example/enroll";
  config.tenant = "tenant-a";
  config.exchange = [](const IdentityKeyPair&, const EndpointId&, std::string_view,
                       std::string_view, std::uint64_t) -> Result<RelayEnrollmentExchangeResult> {
    return Result<RelayEnrollmentExchangeResult>::failure(
        Error{ErrorCode::relay_unavailable, "test", "relay_down"});
  };

  auto enrolled = enroll_relay_profile(config, "TEST-ONLY-enrollment-token-012345",
                                       now_milliseconds());
  ASSERT_FALSE(enrolled);
  EXPECT_EQ(enrolled.error_if()->safe_detail(), "relay_down");

  auto persisted =
      profile.value_if()->relay_enrollment("wss://relay.example/enroll");
  ASSERT_TRUE(persisted) << persisted.error_if()->safe_detail();
  EXPECT_FALSE(persisted.value_if()->has_value());
}

TEST(M3BRelayEnrollmentClientTest, MismatchedExchangeResultRollsBackAndDoesNotPersist) {
  TemporaryDirectory directory{"m3b-relay-enroll-client-rollback"};
  auto profile = create_initialized_profile(directory.path() / "profile.sqlite");
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  bool rollback_called = false;

  RelayEnrollmentClientConfig config;
  config.profile = profile.value_if();
  config.application_id = "com.example.relay-client";
  config.relay_url = "wss://relay.example/enroll";
  config.tenant = "tenant-a";
  config.exchange = [](const IdentityKeyPair&, const EndpointId&, std::string_view,
                       std::string_view, std::uint64_t) -> Result<RelayEnrollmentExchangeResult> {
    return Result<RelayEnrollmentExchangeResult>::success(RelayEnrollmentExchangeResult{
        .relay_url = "wss://other.example/enroll",
        .tenant = "tenant-a",
        .enrollment_generation = 1U,
        .token_remaining_uses_after = 0U});
  };
  config.rollback = [&](const DeviceId& device_id, std::string_view tenant,
                        std::uint64_t generation) -> Result<void> {
    rollback_called = true;
    EXPECT_FALSE(device_id.is_zero());
    EXPECT_EQ(tenant, "tenant-a");
    EXPECT_EQ(generation, 1U);
    return Result<void>::success();
  };

  auto enrolled = enroll_relay_profile(config, "TEST-ONLY-enrollment-token-012345",
                                       now_milliseconds());
  ASSERT_FALSE(enrolled);
  EXPECT_EQ(enrolled.error_if()->code(), ErrorCode::outcome_unknown);
  EXPECT_TRUE(rollback_called);
  auto persisted = profile.value_if()->relay_enrollment("wss://relay.example/enroll");
  ASSERT_TRUE(persisted) << persisted.error_if()->safe_detail();
  EXPECT_FALSE(persisted.value_if()->has_value());
}

TEST(M3BRelayEnrollmentClientTest, UninitializedProfileIsNotCreatedImplicitly) {
  TemporaryDirectory directory{"m3b-relay-enroll-client-uninitialized"};
  auto profile = ProfileStore::create(directory.path() / "profile.sqlite",
                                      encrypted_file_options());
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  bool exchange_called = false;

  RelayEnrollmentClientConfig config;
  config.profile = profile.value_if();
  config.application_id = "com.example.relay-client";
  config.relay_url = "wss://relay.example/enroll";
  config.tenant = "tenant-a";
  config.exchange = [&](const IdentityKeyPair&, const EndpointId&, std::string_view,
                        std::string_view, std::uint64_t) -> Result<RelayEnrollmentExchangeResult> {
    exchange_called = true;
    return Result<RelayEnrollmentExchangeResult>::success(RelayEnrollmentExchangeResult{
        .relay_url = "wss://relay.example/enroll",
        .tenant = "tenant-a",
        .enrollment_generation = 1U});
  };

  auto enrolled = enroll_relay_profile(config, "TEST-ONLY-enrollment-token-012345",
                                       now_milliseconds());
  ASSERT_FALSE(enrolled);
  EXPECT_EQ(enrolled.error_if()->code(), ErrorCode::not_registered);
  EXPECT_FALSE(exchange_called);
}

}  // namespace
}  // namespace heyaki
