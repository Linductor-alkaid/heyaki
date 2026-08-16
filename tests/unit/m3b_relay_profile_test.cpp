#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#ifndef _WIN32
#include <sys/stat.h>
#endif
#include <vector>

namespace heyaki {
namespace {

constexpr std::string_view test_state_dir = HEYAKI_M2_TEST_STATE_DIR;

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
  initialization.application_id = "com.example.relay-profile";
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

RelayEnrollmentRecord make_record(std::uint64_t generation, bool revoked = false) {
  RelayEnrollmentRecord record;
  record.relay_url = "wss://relay.example/enroll";
  record.relay_pin = std::vector<std::byte>(32U, std::byte{0x5aU});
  record.tenant = "tenant-a";
  record.enrollment_generation = generation;
  record.auto_connect = true;
  record.revoked = revoked;
  return record;
}

TEST(M3BRelayProfileTest, PutsQueriesAndReopensRelayEnrollment) {
  TemporaryDirectory directory{"m3b-relay-profile"};
  const auto path = directory.path() / "profile.sqlite";
  {
    auto profile = create_initialized_profile(path);
    ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
    auto record = make_record(1U);
    ASSERT_TRUE(profile.value_if()->put_relay_enrollment(record));

    auto loaded = profile.value_if()->relay_enrollment(record.relay_url);
    ASSERT_TRUE(loaded) << loaded.error_if()->safe_detail();
    ASSERT_TRUE(loaded.value_if()->has_value());
    EXPECT_EQ(loaded.value_if()->value().relay_url, record.relay_url);
    EXPECT_EQ(loaded.value_if()->value().tenant, "tenant-a");
    EXPECT_EQ(loaded.value_if()->value().enrollment_generation, 1U);
    EXPECT_EQ(loaded.value_if()->value().relay_pin, record.relay_pin);
    EXPECT_TRUE(loaded.value_if()->value().auto_connect);
    EXPECT_FALSE(loaded.value_if()->value().revoked);

    auto updated = make_record(2U);
    updated.auto_connect = false;
    ASSERT_TRUE(profile.value_if()->put_relay_enrollment(updated));
    auto all = profile.value_if()->relay_enrollments();
    ASSERT_TRUE(all) << all.error_if()->safe_detail();
    EXPECT_EQ(all.value_if()->size(), 1U);
    EXPECT_EQ(all.value_if()->front().enrollment_generation, 2U);
    EXPECT_FALSE(all.value_if()->front().auto_connect);
  }

  auto reopened = ProfileStore::open(path, encrypted_file_options());
  ASSERT_TRUE(reopened) << reopened.error_if()->safe_detail();
  auto loaded = reopened.value_if()->relay_enrollment("wss://relay.example/enroll");
  ASSERT_TRUE(loaded) << loaded.error_if()->safe_detail();
  ASSERT_TRUE(loaded.value_if()->has_value());
  EXPECT_EQ(loaded.value_if()->value().enrollment_generation, 2U);

  auto missing = reopened.value_if()->relay_enrollment("wss://other.example/enroll");
  ASSERT_TRUE(missing) << missing.error_if()->safe_detail();
  EXPECT_FALSE(missing.value_if()->has_value());
}

TEST(M3BRelayProfileTest, MarkRevokedUpdatesGenerationAndStatus) {
  TemporaryDirectory directory{"m3b-relay-profile-revoke"};
  auto profile = create_initialized_profile(directory.path() / "profile.sqlite");
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  ASSERT_TRUE(profile.value_if()->put_relay_enrollment(make_record(2U)));

  auto revoked = profile.value_if()->mark_relay_revoked("wss://relay.example/enroll", 3U);
  ASSERT_TRUE(revoked) << revoked.error_if()->safe_detail();
  auto loaded = profile.value_if()->relay_enrollment("wss://relay.example/enroll");
  ASSERT_TRUE(loaded) << loaded.error_if()->safe_detail();
  ASSERT_TRUE(loaded.value_if()->has_value());
  EXPECT_TRUE(loaded.value_if()->value().revoked);
  EXPECT_EQ(loaded.value_if()->value().enrollment_generation, 3U);
}

TEST(M3BRelayProfileTest, RejectsInvalidRelayEnrollmentRecords) {
  TemporaryDirectory directory{"m3b-relay-profile-invalid"};
  auto profile = create_initialized_profile(directory.path() / "profile.sqlite");
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();

  auto invalid_url = make_record(1U);
  invalid_url.relay_url = "http://relay.example";
  EXPECT_FALSE(profile.value_if()->put_relay_enrollment(invalid_url));

  auto invalid_tenant = make_record(1U);
  invalid_tenant.tenant.clear();
  EXPECT_FALSE(profile.value_if()->put_relay_enrollment(invalid_tenant));

  auto invalid_pin = make_record(1U);
  invalid_pin.relay_pin = std::vector<std::byte>(16U);
  EXPECT_FALSE(profile.value_if()->put_relay_enrollment(invalid_pin));

  auto invalid_generation = make_record(0U);
  EXPECT_FALSE(profile.value_if()->put_relay_enrollment(invalid_generation));
}

}  // namespace
}  // namespace heyaki
