#include "relay_database.hpp"
#include "relay_enrollment.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
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

void append_varint(std::vector<std::byte>& output, std::uint64_t value) {
  do {
    auto byte = static_cast<std::uint8_t>(value & 0x7fU);
    value >>= 7U;
    if (value != 0U) {
      byte |= 0x80U;
    }
    output.push_back(static_cast<std::byte>(byte));
  } while (value != 0U);
}

void append_unknown_varint(std::vector<std::byte>& output, std::uint32_t field,
                           std::uint64_t value) {
  append_varint(output, (static_cast<std::uint64_t>(field) << 3U));
  append_varint(output, value);
}

RelayId test_relay_id(std::uint8_t seed) {
  RelayId relay_id{};
  relay_id[0] = static_cast<std::byte>(seed);
  relay_id[1] = static_cast<std::byte>(0x41U);
  return relay_id;
}

EnrollmentRequest signed_request(const IdentityKeyPair& identity, RelayId relay_id,
                                 EnrollmentChallenge challenge, std::uint64_t now) {
  EnrollmentRequest request;
  request.device_id = identity.device_id();
  request.endpoint_id = EndpointId{[] {
    EndpointId::Storage bytes{};
    bytes[0] = std::byte{0x11U};
    bytes[1] = std::byte{0x22U};
    return bytes;
  }()};
  request.identity_public_key = identity.public_key();
  request.challenge_nonce = challenge.nonce;
  request.tenant = "tenant-a";
  request.bootstrap_token = "TEST-ONLY-bootstrap-token-0123456789";
  request.protocol_version = current_protocol_version;
  request.supported.bits = known_capability_bits;
  request.required.bits = static_cast<std::uint64_t>(Capability::enrollment);
  request.expires_unix_milliseconds = now + 30U * 1000U;
  auto signed_result = sign_enrollment_request(request, relay_id, identity);
  EXPECT_TRUE(signed_result) << signed_result.error_if()->safe_detail();
  return request;
}

TEST(M3BRelayEnrollmentTest, ChallengeRoundTripAndBounds) {
  const auto now = now_milliseconds();
  auto challenge = create_enrollment_challenge(test_relay_id(9U), now);
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();
  EXPECT_EQ(challenge.value_if()->expires_unix_milliseconds, now + 60U * 1000U);
  EXPECT_NE(challenge.value_if()->nonce, EnrollmentChallengeNonce{});

  auto encoded = encode_enrollment_challenge(*challenge.value_if());
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();
  auto parsed = parse_enrollment_challenge(*encoded.value_if());
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  EXPECT_EQ(parsed.value_if()->relay_id, challenge.value_if()->relay_id);
  EXPECT_EQ(parsed.value_if()->nonce, challenge.value_if()->nonce);
  EXPECT_EQ(parsed.value_if()->expires_unix_milliseconds,
            challenge.value_if()->expires_unix_milliseconds);

  EXPECT_FALSE(create_enrollment_challenge(RelayId{}, now));
  EXPECT_FALSE(create_enrollment_challenge(test_relay_id(1U), now,
                                           std::chrono::milliseconds{0}));
  EXPECT_FALSE(parse_enrollment_challenge({}));
  EXPECT_FALSE(parse_enrollment_challenge(std::span<const std::byte>{
      encoded.value_if()->data(), encoded.value_if()->size() - 1U}));
}

TEST(M3BRelayEnrollmentTest, SignedRequestRoundTripAndValidation) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  auto challenge = create_enrollment_challenge(test_relay_id(2U), now);
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();

  auto request = signed_request(*identity.value_if(), challenge.value_if()->relay_id,
                                *challenge.value_if(), now);
  auto encoded = encode_enrollment_request(request);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();
  auto parsed = parse_enrollment_request(*encoded.value_if());
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  EXPECT_EQ(parsed.value_if()->device_id, identity.value_if()->device_id());
  EXPECT_EQ(parsed.value_if()->endpoint_id, request.endpoint_id);
  EXPECT_EQ(parsed.value_if()->tenant, "tenant-a");
  EXPECT_EQ(parsed.value_if()->bootstrap_token, request.bootstrap_token);
  EXPECT_EQ(parsed.value_if()->required.bits,
            static_cast<std::uint64_t>(Capability::enrollment));

  auto valid = validate_enrollment_request(*parsed.value_if(), *challenge.value_if(), now + 1U);
  EXPECT_TRUE(valid) << valid.error_if()->safe_detail();
}

TEST(M3BRelayEnrollmentTest, RejectsTamperedIdentityChallengeExpiryAndSignature) {
  auto identity = create_identity();
  auto other_identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  ASSERT_TRUE(other_identity) << other_identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  auto challenge = create_enrollment_challenge(test_relay_id(3U), now);
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();
  auto request = signed_request(*identity.value_if(), challenge.value_if()->relay_id,
                                *challenge.value_if(), now);

  auto tampered_device = request;
  tampered_device.device_id = other_identity.value_if()->device_id();
  EXPECT_EQ(validate_enrollment_request(tampered_device, *challenge.value_if(), now + 1U)
                .error_if()
                ->safe_detail(),
            "enrollment_device_id_mismatch");

  auto tampered_nonce = request;
  tampered_nonce.challenge_nonce[0] ^= std::byte{0xffU};
  EXPECT_EQ(validate_enrollment_request(tampered_nonce, *challenge.value_if(), now + 1U)
                .error_if()
                ->safe_detail(),
            "enrollment_challenge_nonce_mismatch");

  auto sign_variant = [&](EnrollmentRequest variant) {
    auto signed_result = sign_enrollment_request(variant, challenge.value_if()->relay_id,
                                                 *identity.value_if());
    EXPECT_TRUE(signed_result) << signed_result.error_if()->safe_detail();
    return variant;
  };

  auto expired = sign_variant([&] {
    auto variant = request;
    variant.expires_unix_milliseconds = now - 1U;
    return variant;
  }());
  EXPECT_EQ(validate_enrollment_request(expired, *challenge.value_if(), now + 31U * 1000U)
                .error_if()
                ->safe_detail(),
            "signed_object_expired");

  auto beyond_challenge = sign_variant([&] {
    auto variant = request;
    variant.expires_unix_milliseconds = challenge.value_if()->expires_unix_milliseconds + 1U;
    return variant;
  }());
  EXPECT_EQ(validate_enrollment_request(beyond_challenge, *challenge.value_if(), now + 1U)
                .error_if()
                ->safe_detail(),
            "enrollment_expiry_exceeds_challenge");

  auto wrong_signature = request;
  wrong_signature.signature[0] ^= std::byte{0x01U};
  EXPECT_EQ(validate_enrollment_request(wrong_signature, *challenge.value_if(), now + 1U)
                .error_if()
                ->safe_detail(),
            "signature_verification_failed");

  auto expired_challenge = *challenge.value_if();
  expired_challenge.expires_unix_milliseconds = now - 1U;
  auto request_for_expired_challenge = sign_variant([&] {
    auto variant = request;
    variant.expires_unix_milliseconds = expired_challenge.expires_unix_milliseconds;
    return variant;
  }());
  EXPECT_EQ(validate_enrollment_request(request_for_expired_challenge, expired_challenge,
                                        now + 61U * 1000U)
                .error_if()
                ->safe_detail(),
            "signed_object_expired");
}

TEST(M3BRelayEnrollmentTest, RejectsUnknownRequiredCapabilityAndShortToken) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  auto challenge = create_enrollment_challenge(test_relay_id(4U), now);
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();

  auto unknown_required = signed_request(*identity.value_if(), challenge.value_if()->relay_id,
                                         *challenge.value_if(), now);
  unknown_required.required.bits |= 1ULL << 63U;
  auto unknown_sign = sign_enrollment_request(unknown_required, challenge.value_if()->relay_id,
                                              *identity.value_if());
  ASSERT_TRUE(unknown_sign) << unknown_sign.error_if()->safe_detail();
  EXPECT_EQ(validate_enrollment_request(unknown_required, *challenge.value_if(), now + 1U)
                .error_if()
                ->safe_detail(),
            "unknown_required_capability");

  auto short_token = signed_request(*identity.value_if(), challenge.value_if()->relay_id,
                                    *challenge.value_if(), now);
  short_token.bootstrap_token = "short";
  EXPECT_EQ(validate_enrollment_request(short_token, *challenge.value_if(), now + 1U)
                .error_if()
                ->safe_detail(),
            "enrollment_request_invalid");
}

TEST(M3BRelayEnrollmentTest, ParserRejectsDuplicateAndUnknownFields) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  auto challenge = create_enrollment_challenge(test_relay_id(5U), now);
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();
  auto request = signed_request(*identity.value_if(), challenge.value_if()->relay_id,
                                *challenge.value_if(), now);
  auto encoded = encode_enrollment_request(request);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();

  // Duplicate field 4 (tenant) with valid wire bytes.
  std::vector<std::byte> duplicate = *encoded.value_if();
  duplicate.push_back(static_cast<std::byte>((4U << 3U) | 2U));
  duplicate.push_back(std::byte{1U});
  duplicate.push_back(std::byte{'x'});
  EXPECT_FALSE(parse_enrollment_request(duplicate));

  // Truncated nested message.
  std::span<const std::byte> truncated{encoded.value_if()->data(), encoded.value_if()->size() - 2U};
  EXPECT_FALSE(parse_enrollment_request(truncated));

  // Unknown field 99.
  std::vector<std::byte> unknown = *encoded.value_if();
  append_unknown_varint(unknown, 99U, 1U);
  EXPECT_FALSE(parse_enrollment_request(unknown));
}

TEST(M3BRelayEnrollmentTest, DeviceEnrollmentRetryRevocationAndReenrollment) {
  TemporaryDirectory directory{"m3b-relay-enroll-db"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();

  RelayDeviceRecord record;
  record.device_id = identity.value_if()->device_id();
  record.public_key = identity.value_if()->public_key();
  record.tenant = "tenant-a";
  record.display_name = "test-device";
  record.enrollment_generation = 1U;
  record.status = RelayDeviceStatus::active;
  const auto now = now_milliseconds();

  auto enrolled = database.value_if()->enroll_device(record, now);
  ASSERT_TRUE(enrolled) << enrolled.error_if()->safe_detail();
  EXPECT_EQ(database.value_if()->snapshot().device_count, 1U);
  EXPECT_EQ(database.value_if()->snapshot().device_audit_count, 1U);

  auto loaded = database.value_if()->device(record.device_id);
  ASSERT_TRUE(loaded) << loaded.error_if()->safe_detail();
  ASSERT_TRUE(loaded.value_if());
  EXPECT_EQ((*loaded.value_if())->status, RelayDeviceStatus::active);
  EXPECT_EQ((*loaded.value_if())->enrollment_generation, 1U);

  auto retried = database.value_if()->enroll_device(record, now + 1U);
  EXPECT_TRUE(retried) << retried.error_if()->safe_detail();
  EXPECT_EQ(database.value_if()->snapshot().device_audit_count, 1U);

  record.enrollment_generation = 0U;
  EXPECT_FALSE(database.value_if()->enroll_device(record, now + 2U));
  record.enrollment_generation = 1U;
  record.public_key = IdentityPublicKey{};
  EXPECT_FALSE(database.value_if()->enroll_device(record, now + 3U));

  auto revoked = database.value_if()->revoke_device(record.device_id, 2U, now + 4U);
  ASSERT_TRUE(revoked) << revoked.error_if()->safe_detail();
  auto loaded_revoked = database.value_if()->device(record.device_id);
  ASSERT_TRUE(loaded_revoked) << loaded_revoked.error_if()->safe_detail();
  ASSERT_TRUE(loaded_revoked.value_if());
  EXPECT_EQ((*loaded_revoked.value_if())->status, RelayDeviceStatus::revoked);
  EXPECT_EQ((*loaded_revoked.value_if())->enrollment_generation, 2U);
  EXPECT_EQ(database.value_if()->snapshot().device_audit_count, 2U);

  auto stale_revocation = database.value_if()->revoke_device(record.device_id, 1U, now + 5U);
  ASSERT_FALSE(stale_revocation);
  EXPECT_EQ(stale_revocation.error_if()->safe_detail(),
            "relay_revocation_generation_not_newer");

  record.public_key = identity.value_if()->public_key();
  RelayDeviceRecord reenrollment = record;
  reenrollment.enrollment_generation = 3U;
  auto reenrolled = database.value_if()->enroll_device(reenrollment, now + 6U);
  EXPECT_TRUE(reenrolled) << reenrolled.error_if()->safe_detail();
  auto loaded_active = database.value_if()->device(record.device_id);
  ASSERT_TRUE(loaded_active) << loaded_active.error_if()->safe_detail();
  EXPECT_EQ((*loaded_active.value_if())->status, RelayDeviceStatus::active);
  EXPECT_EQ((*loaded_active.value_if())->enrollment_generation, 3U);
}

}  // namespace
}  // namespace heyaki
