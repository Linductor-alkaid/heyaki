#include "relay_database.hpp"
#include "relay_enrollment.hpp"
#include "relay_enrollment_service.hpp"

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
  relay_id[1] = static_cast<std::byte>(0x5aU);
  return relay_id;
}

Result<EnrollmentRequest> make_request(const IdentityKeyPair& identity,
                                       const EnrollmentChallenge& challenge,
                                       std::string_view token, std::uint64_t now,
                                       std::uint8_t endpoint_byte) {
  EnrollmentRequest request;
  request.device_id = identity.device_id();
  EndpointId::Storage endpoint{};
  endpoint[0] = static_cast<std::byte>(endpoint_byte);
  request.endpoint_id = EndpointId{endpoint};
  request.identity_public_key = identity.public_key();
  request.challenge_nonce = challenge.nonce;
  request.tenant = "tenant-a";
  request.bootstrap_token = std::string{token};
  request.protocol_version = current_protocol_version;
  request.supported.bits = known_capability_bits;
  request.required.bits = static_cast<std::uint64_t>(Capability::enrollment);
  request.expires_unix_milliseconds = now + 30U * 1000U;
  auto signature = sign_enrollment_request(request, challenge.relay_id, identity);
  if (!signature) {
    return Result<EnrollmentRequest>::failure(*signature.error_if());
  }
  return Result<EnrollmentRequest>::success(std::move(request));
}

TEST(M3BRelayEnrollmentServiceTest, ChallengeTokenAndPersistenceFlow) {
  TemporaryDirectory directory{"m3b-relay-enrollment-service"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  const std::string token = "TEST-ONLY-service-token-0123456789";
  const auto now = now_milliseconds();
  auto created = database.value_if()->create_bootstrap_token(
      "tenant-a", token, now + 60U * 1000U, 2U);
  ASSERT_TRUE(created) << created.error_if()->safe_detail();

  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  auto service = RelayEnrollmentService::create(database.value_if(), test_relay_id(7U));
  ASSERT_TRUE(service) << service.error_if()->safe_detail();

  auto challenge_bytes = service.value_if()->begin_challenge(now);
  ASSERT_TRUE(challenge_bytes) << challenge_bytes.error_if()->safe_detail();
  auto challenge = parse_enrollment_challenge(*challenge_bytes.value_if());
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();
  auto request = make_request(*identity.value_if(), *challenge.value_if(), token, now, 0x11U);
  ASSERT_TRUE(request) << request.error_if()->safe_detail();
  auto encoded = encode_enrollment_request(*request.value_if());
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();

  auto completed = service.value_if()->complete(*encoded.value_if(), now + 1U);
  ASSERT_TRUE(completed) << completed.error_if()->safe_detail();
  EXPECT_EQ(completed.value_if()->enrollment_generation, 1U);
  EXPECT_EQ(completed.value_if()->token_remaining_uses_after, 1U);
  EXPECT_EQ(database.value_if()->snapshot().device_count, 1U);
  EXPECT_EQ(database.value_if()->snapshot().device_audit_count, 2U);

  auto replay = service.value_if()->complete(*encoded.value_if(), now + 2U);
  ASSERT_FALSE(replay);
  EXPECT_EQ(replay.error_if()->safe_detail(), "enrollment_challenge_unknown_or_expired");

  auto second_challenge_bytes = service.value_if()->begin_challenge(now + 3U);
  ASSERT_TRUE(second_challenge_bytes) << second_challenge_bytes.error_if()->safe_detail();
  auto second_challenge = parse_enrollment_challenge(*second_challenge_bytes.value_if());
  ASSERT_TRUE(second_challenge) << second_challenge.error_if()->safe_detail();
  auto second_identity = create_identity();
  ASSERT_TRUE(second_identity) << second_identity.error_if()->safe_detail();
  auto second_request = make_request(*second_identity.value_if(), *second_challenge.value_if(),
                                     token, now + 3U, 0x22U);
  ASSERT_TRUE(second_request) << second_request.error_if()->safe_detail();
  auto second_encoded = encode_enrollment_request(*second_request.value_if());
  ASSERT_TRUE(second_encoded) << second_encoded.error_if()->safe_detail();
  auto second_completed = service.value_if()->complete(*second_encoded.value_if(), now + 4U);
  ASSERT_TRUE(second_completed) << second_completed.error_if()->safe_detail();
  EXPECT_EQ(second_completed.value_if()->enrollment_generation, 1U);
  EXPECT_EQ(second_completed.value_if()->token_remaining_uses_after, 0U);
  EXPECT_EQ(database.value_if()->snapshot().device_count, 2U);

  auto third_challenge_bytes = service.value_if()->begin_challenge(now + 5U);
  ASSERT_TRUE(third_challenge_bytes) << third_challenge_bytes.error_if()->safe_detail();
  auto third_challenge = parse_enrollment_challenge(*third_challenge_bytes.value_if());
  ASSERT_TRUE(third_challenge) << third_challenge.error_if()->safe_detail();
  auto third_identity = create_identity();
  ASSERT_TRUE(third_identity) << third_identity.error_if()->safe_detail();
  auto third_request = make_request(*third_identity.value_if(), *third_challenge.value_if(),
                                    token, now + 5U, 0x33U);
  ASSERT_TRUE(third_request) << third_request.error_if()->safe_detail();
  auto third_encoded = encode_enrollment_request(*third_request.value_if());
  ASSERT_TRUE(third_encoded) << third_encoded.error_if()->safe_detail();
  auto exhausted = service.value_if()->complete(*third_encoded.value_if(), now + 6U);
  ASSERT_FALSE(exhausted);
  EXPECT_EQ(exhausted.error_if()->safe_detail(), "relay_bootstrap_token_exhausted");

  const auto diagnostics = service.value_if()->diagnostics();
  EXPECT_EQ(diagnostics.challenges_issued, 3U);
  EXPECT_EQ(diagnostics.challenges_completed, 2U);
  EXPECT_EQ(diagnostics.token_rejected, 1U);
}

TEST(M3BRelayEnrollmentServiceTest, RejectsWrongTokenAndSignatureAndCapacity) {
  TemporaryDirectory directory{"m3b-relay-enrollment-service-reject"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  const auto now = now_milliseconds();
  auto created = database.value_if()->create_bootstrap_token(
      "tenant-a", "TEST-ONLY-valid-token-0123456789", now + 60U * 1000U, 1U);
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();

  RelayEnrollmentServiceConfig config;
  config.challenge_capacity = 1U;
  auto service = RelayEnrollmentService::create(database.value_if(), test_relay_id(8U), config);
  ASSERT_TRUE(service) << service.error_if()->safe_detail();

  auto first_bytes = service.value_if()->begin_challenge(now);
  ASSERT_TRUE(first_bytes) << first_bytes.error_if()->safe_detail();
  auto second_bytes = service.value_if()->begin_challenge(now + 1U);
  ASSERT_FALSE(second_bytes);
  EXPECT_EQ(second_bytes.error_if()->code(), ErrorCode::resource_exhausted);

  auto challenge = parse_enrollment_challenge(*first_bytes.value_if());
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();
  auto wrong_token = make_request(*identity.value_if(), *challenge.value_if(),
                                  "TEST-ONLY-wrong-token-012345678", now, 0x44U);
  ASSERT_TRUE(wrong_token) << wrong_token.error_if()->safe_detail();
  auto wrong_encoded = encode_enrollment_request(*wrong_token.value_if());
  ASSERT_TRUE(wrong_encoded) << wrong_encoded.error_if()->safe_detail();
  auto rejected = service.value_if()->complete(*wrong_encoded.value_if(), now + 1U);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "relay_bootstrap_token_invalid");

  auto fresh_bytes = service.value_if()->begin_challenge(now + 2U);
  ASSERT_TRUE(fresh_bytes) << fresh_bytes.error_if()->safe_detail();
  auto fresh = parse_enrollment_challenge(*fresh_bytes.value_if());
  ASSERT_TRUE(fresh) << fresh.error_if()->safe_detail();
  auto tampered = make_request(*identity.value_if(), *fresh.value_if(),
                               "TEST-ONLY-valid-token-0123456789", now + 2U, 0x55U);
  ASSERT_TRUE(tampered) << tampered.error_if()->safe_detail();
  tampered.value_if()->signature[0] ^= std::byte{0x01U};
  auto tampered_encoded = encode_enrollment_request(*tampered.value_if());
  ASSERT_TRUE(tampered_encoded) << tampered_encoded.error_if()->safe_detail();
  auto bad_signature = service.value_if()->complete(*tampered_encoded.value_if(), now + 3U);
  ASSERT_FALSE(bad_signature);
  EXPECT_EQ(bad_signature.error_if()->safe_detail(), "signature_verification_failed");
}

}  // namespace
}  // namespace heyaki
