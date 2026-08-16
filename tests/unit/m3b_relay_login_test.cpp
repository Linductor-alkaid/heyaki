#include "relay_database.hpp"
#include "relay_enrollment.hpp"
#include "relay_login.hpp"
#include "relay_login_service.hpp"

#include <gtest/gtest.h>

#include <array>
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

RelayId test_relay_id(std::uint8_t seed) {
  RelayId relay_id{};
  relay_id[0] = static_cast<std::byte>(seed);
  relay_id[1] = static_cast<std::byte>(0x33U);
  return relay_id;
}

RelayLoginRequest make_login_request(const IdentityKeyPair& identity,
                                     const RelayLoginChallenge& challenge,
                                     std::uint64_t generation, std::uint64_t now,
                                     std::uint8_t endpoint_byte,
                                     std::string_view tenant = "tenant-a") {
  RelayLoginRequest request;
  request.device_id = identity.device_id();
  EndpointId::Storage endpoint{};
  endpoint[0] = static_cast<std::byte>(endpoint_byte);
  request.endpoint_id = EndpointId{endpoint};
  request.identity_public_key = identity.public_key();
  request.challenge_nonce = challenge.nonce;
  request.tenant = std::string{tenant};
  request.protocol_version = current_protocol_version;
  request.supported.bits = known_capability_bits;
  request.required.bits = static_cast<std::uint64_t>(Capability::enrollment);
  request.enrollment_generation = generation;
  request.expires_unix_milliseconds = now + 30U * 1000U;
  auto signature = sign_relay_login_request(request, challenge.relay_id, identity);
  EXPECT_TRUE(signature) << signature.error_if()->safe_detail();
  return request;
}

TEST(M3BRelayLoginTest, ChallengeAndRequestRoundTrip) {
  const auto now = now_milliseconds();
  auto challenge = create_enrollment_challenge(test_relay_id(1U), now);
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();
  auto challenge_bytes = encode_enrollment_challenge(*challenge.value_if());
  ASSERT_TRUE(challenge_bytes) << challenge_bytes.error_if()->safe_detail();
  auto parsed_challenge = parse_enrollment_challenge(*challenge_bytes.value_if());
  ASSERT_TRUE(parsed_challenge) << parsed_challenge.error_if()->safe_detail();

  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  auto request = make_login_request(*identity.value_if(), *parsed_challenge.value_if(), 1U,
                                    now, 0x21U);
  auto encoded = encode_relay_login_request(request);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();
  auto parsed = parse_relay_login_request(*encoded.value_if());
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  EXPECT_EQ(parsed.value_if()->device_id, identity.value_if()->device_id());
  EXPECT_EQ(parsed.value_if()->enrollment_generation, 1U);
  EXPECT_EQ(parsed.value_if()->tenant, "tenant-a");
}

TEST(M3BRelayLoginTest, AuthenticatesActiveGenerationAndAudits) {
  TemporaryDirectory directory{"m3b-relay-login"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();

  RelayDeviceRecord record;
  record.device_id = identity.value_if()->device_id();
  record.public_key = identity.value_if()->public_key();
  record.tenant = "tenant-a";
  record.display_name = "device";
  record.enrollment_generation = 1U;
  record.status = RelayDeviceStatus::active;
  const auto now = now_milliseconds();
  ASSERT_TRUE(database.value_if()->enroll_device(record, now));

  auto service = RelayLoginService::create(database.value_if(), test_relay_id(2U));
  ASSERT_TRUE(service) << service.error_if()->safe_detail();
  auto challenge_bytes = service.value_if()->begin_challenge(now);
  ASSERT_TRUE(challenge_bytes) << challenge_bytes.error_if()->safe_detail();
  auto challenge = parse_enrollment_challenge(*challenge_bytes.value_if());
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();
  auto request = make_login_request(*identity.value_if(), *challenge.value_if(), 1U,
                                    now, 0x22U);
  auto encoded = encode_relay_login_request(request);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();

  auto authenticated = service.value_if()->authenticate(*encoded.value_if(), now + 1U);
  ASSERT_TRUE(authenticated) << authenticated.error_if()->safe_detail();
  EXPECT_EQ(authenticated.value_if()->enrollment_generation, 1U);
  EXPECT_EQ(database.value_if()->snapshot().device_audit_count, 2U);
  EXPECT_EQ(service.value_if()->diagnostics().logins_succeeded, 1U);

  auto replay = service.value_if()->authenticate(*encoded.value_if(), now + 2U);
  ASSERT_FALSE(replay);
  EXPECT_EQ(replay.error_if()->safe_detail(), "login_challenge_unknown_or_expired");
}

TEST(M3BRelayLoginTest, RejectsWrongGenerationRevokedTenantAndSignature) {
  TemporaryDirectory directory{"m3b-relay-login-reject"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();

  RelayDeviceRecord record;
  record.device_id = identity.value_if()->device_id();
  record.public_key = identity.value_if()->public_key();
  record.tenant = "tenant-a";
  record.display_name = "device";
  record.enrollment_generation = 2U;
  record.status = RelayDeviceStatus::active;
  const auto now = now_milliseconds();
  ASSERT_TRUE(database.value_if()->enroll_device(record, now));

  auto service = RelayLoginService::create(database.value_if(), test_relay_id(3U));
  ASSERT_TRUE(service) << service.error_if()->safe_detail();
  const auto authenticate_variant = [&](RelayLoginRequest request,
                                        std::uint64_t when) {
    auto encoded = encode_relay_login_request(request);
    EXPECT_TRUE(encoded) << encoded.error_if()->safe_detail();
    return service.value_if()->authenticate(*encoded.value_if(), when);
  };

  auto wrong_generation_bytes = service.value_if()->begin_challenge(now);
  ASSERT_TRUE(wrong_generation_bytes) << wrong_generation_bytes.error_if()->safe_detail();
  auto wrong_challenge = parse_enrollment_challenge(*wrong_generation_bytes.value_if());
  ASSERT_TRUE(wrong_challenge) << wrong_challenge.error_if()->safe_detail();
  auto wrong_generation = make_login_request(*identity.value_if(), *wrong_challenge.value_if(),
                                             1U, now, 0x31U);
  auto wrong_generation_result = authenticate_variant(wrong_generation, now + 1U);
  ASSERT_FALSE(wrong_generation_result);
  EXPECT_EQ(wrong_generation_result.error_if()->safe_detail(), "login_generation_mismatch");

  auto wrong_tenant_bytes = service.value_if()->begin_challenge(now + 1U);
  ASSERT_TRUE(wrong_tenant_bytes) << wrong_tenant_bytes.error_if()->safe_detail();
  auto wrong_tenant_challenge = parse_enrollment_challenge(*wrong_tenant_bytes.value_if());
  ASSERT_TRUE(wrong_tenant_challenge) << wrong_tenant_challenge.error_if()->safe_detail();
  auto wrong_tenant = make_login_request(*identity.value_if(), *wrong_tenant_challenge.value_if(),
                                         2U, now + 1U, 0x32U, "tenant-b");
  auto wrong_tenant_result = authenticate_variant(wrong_tenant, now + 2U);
  ASSERT_FALSE(wrong_tenant_result);
  EXPECT_EQ(wrong_tenant_result.error_if()->safe_detail(), "login_device_record_mismatch");

  auto revoked = database.value_if()->revoke_device(record.device_id, 3U, now + 2U);
  ASSERT_TRUE(revoked) << revoked.error_if()->safe_detail();
  auto revoked_bytes = service.value_if()->begin_challenge(now + 3U);
  ASSERT_TRUE(revoked_bytes) << revoked_bytes.error_if()->safe_detail();
  auto revoked_challenge = parse_enrollment_challenge(*revoked_bytes.value_if());
  ASSERT_TRUE(revoked_challenge) << revoked_challenge.error_if()->safe_detail();
  auto revoked_request = make_login_request(*identity.value_if(), *revoked_challenge.value_if(),
                                            3U, now + 3U, 0x33U);
  auto revoked_result = authenticate_variant(revoked_request, now + 4U);
  ASSERT_FALSE(revoked_result);
  EXPECT_EQ(revoked_result.error_if()->code(), ErrorCode::enrollment_revoked);

  record.enrollment_generation = 4U;
  record.status = RelayDeviceStatus::active;
  ASSERT_TRUE(database.value_if()->enroll_device(record, now + 5U));
  auto bad_signature_bytes = service.value_if()->begin_challenge(now + 6U);
  ASSERT_TRUE(bad_signature_bytes) << bad_signature_bytes.error_if()->safe_detail();
  auto bad_challenge = parse_enrollment_challenge(*bad_signature_bytes.value_if());
  ASSERT_TRUE(bad_challenge) << bad_challenge.error_if()->safe_detail();
  auto bad_signature = make_login_request(*identity.value_if(), *bad_challenge.value_if(),
                                          4U, now + 6U, 0x34U);
  bad_signature.signature[0] ^= std::byte{0x01U};
  auto bad_signature_result = authenticate_variant(bad_signature, now + 7U);
  ASSERT_FALSE(bad_signature_result);
  EXPECT_EQ(bad_signature_result.error_if()->safe_detail(), "signature_verification_failed");
}

TEST(M3BRelayLoginTest, ParserRejectsUnknownDuplicateAndTruncatedFields) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  auto challenge = create_enrollment_challenge(test_relay_id(4U), now);
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();
  auto request = make_login_request(*identity.value_if(), *challenge.value_if(), 1U,
                                    now, 0x41U);
  auto encoded = encode_relay_login_request(request);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();

  std::vector<std::byte> duplicate = *encoded.value_if();
  duplicate.push_back(static_cast<std::byte>((4U << 3U) | 2U));
  duplicate.push_back(std::byte{1U});
  duplicate.push_back(std::byte{'x'});
  EXPECT_FALSE(parse_relay_login_request(duplicate));

  std::vector<std::byte> unknown = *encoded.value_if();
  unknown.push_back(static_cast<std::byte>(static_cast<std::uint8_t>((99U << 3U) | 0U)));
  unknown.push_back(std::byte{1U});
  EXPECT_FALSE(parse_relay_login_request(unknown));

  EXPECT_FALSE(parse_relay_login_request(
      std::span<const std::byte>{encoded.value_if()->data(), encoded.value_if()->size() - 2U}));
}

}  // namespace
}  // namespace heyaki
