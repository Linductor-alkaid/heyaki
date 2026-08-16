#include "relay_turn_credentials.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

namespace heyaki {
namespace {

std::uint64_t now_unix_seconds() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
}

DeviceId test_device_id() {
  DeviceId::Storage bytes{};
  bytes[0] = std::byte{0x11U};
  bytes[1] = std::byte{0x22U};
  return DeviceId{bytes};
}

TEST(M3BRelayTurnCredentialsTest, KnownTurnRestVector) {
  auto password = turn_rest_password("mysecret", "1433893416:user");
  ASSERT_TRUE(password) << password.error_if()->safe_detail();
  EXPECT_EQ(*password.value_if(), "Z1QE/XybgiUxPAGPb142ynMtqps=");
}

TEST(M3BRelayTurnCredentialsTest, IssuesAndValidatesRotatedSecrets) {
  auto created = RelayTurnCredentialService::create();
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  auto service = std::move(*created.value_if());
  const auto now = now_unix_seconds();

  ASSERT_TRUE(service.set_secret(1U, "0123456789abcdef", now));
  auto issued = service.issue("tenant-a", test_device_id(), now);
  ASSERT_TRUE(issued) << issued.error_if()->safe_detail();
  EXPECT_EQ(issued.value_if()->expires_unix_seconds, now + 600U);
  EXPECT_EQ(issued.value_if()->secret_generation, 1U);
  EXPECT_NE(issued.value_if()->username.find(":tenant-a:"), std::string::npos);
  EXPECT_FALSE(issued.value_if()->password.empty());

  auto valid = service.validate(issued.value_if()->username,
                                issued.value_if()->password, now + 1U);
  ASSERT_TRUE(valid) << valid.error_if()->safe_detail();
  EXPECT_EQ(*valid.value_if(), 1U);

  ASSERT_TRUE(service.set_secret(2U, "fedcba9876543210", now));
  auto old_valid = service.validate(issued.value_if()->username,
                                    issued.value_if()->password, now + 2U);
  ASSERT_TRUE(old_valid) << old_valid.error_if()->safe_detail();
  EXPECT_EQ(*old_valid.value_if(), 1U);

  auto rotated = service.issue("tenant-a", test_device_id(), now + 3U);
  ASSERT_TRUE(rotated) << rotated.error_if()->safe_detail();
  EXPECT_EQ(rotated.value_if()->secret_generation, 2U);
  EXPECT_NE(rotated.value_if()->password, issued.value_if()->password);
  auto rotated_valid = service.validate(rotated.value_if()->username,
                                        rotated.value_if()->password, now + 4U);
  ASSERT_TRUE(rotated_valid) << rotated_valid.error_if()->safe_detail();
  EXPECT_EQ(*rotated_valid.value_if(), 2U);
}

TEST(M3BRelayTurnCredentialsTest, RejectsExpiredTamperedAndUnavailable) {
  auto created = RelayTurnCredentialService::create();
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  auto service = std::move(*created.value_if());
  const auto now = now_unix_seconds();

  EXPECT_FALSE(service.issue("tenant-a", test_device_id(), now));
  ASSERT_TRUE(service.set_secret(1U, "0123456789abcdef", now));
  auto issued = service.issue("tenant-a", test_device_id(), now);
  ASSERT_TRUE(issued) << issued.error_if()->safe_detail();

  auto expired = service.validate(issued.value_if()->username,
                                  issued.value_if()->password,
                                  issued.value_if()->expires_unix_seconds);
  ASSERT_FALSE(expired);
  EXPECT_EQ(expired.error_if()->safe_detail(), "turn_credential_expired");

  auto tampered = service.validate(issued.value_if()->username,
                                   issued.value_if()->password + "x", now + 1U);
  ASSERT_FALSE(tampered);
  EXPECT_EQ(tampered.error_if()->safe_detail(), "turn_credential_invalid");

  EXPECT_FALSE(service.set_secret(0U, "0123456789abcdef", now));
  EXPECT_FALSE(service.set_secret(1U, "short", now));
  EXPECT_FALSE(service.issue("bad tenant", test_device_id(), now));
}

TEST(M3BRelayTurnCredentialsTest, ReplacesAndEvictsBoundedSecrets) {
  RelayTurnSecretConfig config;
  config.max_secrets = 2U;
  auto created = RelayTurnCredentialService::create(config);
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  auto service = std::move(*created.value_if());
  const auto now = now_unix_seconds();

  ASSERT_TRUE(service.set_secret(1U, "1111111111111111", now));
  auto first = service.issue("tenant-a", test_device_id(), now);
  ASSERT_TRUE(first) << first.error_if()->safe_detail();
  ASSERT_TRUE(service.set_secret(2U, "2222222222222222", now));
  ASSERT_TRUE(service.set_secret(3U, "3333333333333333", now));
  EXPECT_EQ(service.diagnostics().active_secrets, 2U);
  EXPECT_EQ(service.diagnostics().latest_secret_generation, 3U);

  auto evicted = service.validate(first.value_if()->username,
                                  first.value_if()->password, now + 1U);
  EXPECT_FALSE(evicted);

  auto latest = service.issue("tenant-a", test_device_id(), now + 1U);
  ASSERT_TRUE(latest) << latest.error_if()->safe_detail();
  EXPECT_EQ(latest.value_if()->secret_generation, 3U);

  ASSERT_TRUE(service.set_secret(2U, "4444444444444444", now + 1U));
  auto second = service.issue("tenant-a", test_device_id(), now + 2U);
  ASSERT_TRUE(second) << second.error_if()->safe_detail();
  EXPECT_EQ(second.value_if()->secret_generation, 3U);
  auto replaced_old = service.validate(first.value_if()->username,
                                       first.value_if()->password, now + 3U);
  EXPECT_FALSE(replaced_old);
}

TEST(M3BRelayTurnCredentialsTest, RejectsInvalidPolicy) {
  EXPECT_FALSE(RelayTurnCredentialService::validate_config([] {
    RelayTurnSecretConfig config;
    config.max_secrets = 0U;
    return config;
  }()));
  EXPECT_FALSE(RelayTurnCredentialService::validate_config([] {
    RelayTurnSecretConfig config;
    config.credential_ttl = std::chrono::seconds{0};
    return config;
  }()));
}

}  // namespace
}  // namespace heyaki
