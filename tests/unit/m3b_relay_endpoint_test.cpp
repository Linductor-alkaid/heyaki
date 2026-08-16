#include "relay_database.hpp"
#include "relay_endpoint.hpp"

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

RelayManifestSha256 make_hash(std::uint8_t seed) {
  RelayManifestSha256 hash{};
  hash[0] = static_cast<std::byte>(seed);
  hash[1] = static_cast<std::byte>(0x5aU);
  return hash;
}

RelayEndpointRecord make_record(const IdentityKeyPair& identity, std::uint64_t now,
                                std::string_view application_id = "com.example.device") {
  RelayEndpointRecord record;
  EndpointId::Storage endpoint{};
  endpoint[0] = std::byte{0x21U};
  record.endpoint = RelayEndpointKey{.device_id = identity.device_id(),
                                     .endpoint_id = EndpointId{endpoint}};
  record.application_id = std::string{application_id};
  record.record_generation = 1U;
  record.manifest_sha256 = make_hash(1U);
  record.expires_unix_milliseconds = now + 60U * 1000U;
  auto signed_record = sign_relay_endpoint_record(record, identity);
  EXPECT_TRUE(signed_record) << signed_record.error_if()->safe_detail();
  return record;
}

RelayServiceManifest make_manifest(const IdentityKeyPair& identity,
                                   const RelayEndpointRecord& record, std::uint64_t now) {
  RelayServiceManifest manifest;
  manifest.endpoint = record.endpoint;
  manifest.manifest_generation = 1U;
  manifest.canonical_manifest_sha256 = record.manifest_sha256;
  manifest.expires_unix_milliseconds = now + 60U * 1000U;
  auto signed_manifest = sign_relay_service_manifest(manifest, identity);
  EXPECT_TRUE(signed_manifest) << signed_manifest.error_if()->safe_detail();
  return manifest;
}

TEST(M3BRelayEndpointTest, RecordRoundTripAndValidation) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  auto record = make_record(*identity.value_if(), now);
  auto encoded = encode_relay_endpoint_record(record);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();
  auto parsed = parse_relay_endpoint_record(*encoded.value_if());
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  EXPECT_EQ(parsed.value_if()->endpoint, record.endpoint);
  EXPECT_EQ(parsed.value_if()->application_id, "com.example.device");
  EXPECT_EQ(parsed.value_if()->record_generation, 1U);

  RelayDeviceRecord device;
  device.device_id = identity.value_if()->device_id();
  device.public_key = identity.value_if()->public_key();
  device.tenant = "tenant-a";
  device.display_name = "device";
  device.enrollment_generation = 1U;
  device.status = RelayDeviceStatus::active;

  EXPECT_TRUE(validate_relay_endpoint_record(*parsed.value_if(), device, now + 1U));
  device.status = RelayDeviceStatus::revoked;
  EXPECT_EQ(validate_relay_endpoint_record(*parsed.value_if(), device, now + 1U)
                .error_if()
                ->code(),
            ErrorCode::enrollment_revoked);
  device.status = RelayDeviceStatus::active;
  device.public_key[0] ^= std::byte{0x01U};
  EXPECT_EQ(validate_relay_endpoint_record(*parsed.value_if(), device, now + 1U)
                .error_if()
                ->safe_detail(),
            "signature_verification_failed");
}

TEST(M3BRelayEndpointTest, ManifestRoundTripValidationAndBinding) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  auto record = make_record(*identity.value_if(), now);
  auto manifest = make_manifest(*identity.value_if(), record, now);

  auto encoded = encode_relay_service_manifest(manifest);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();
  auto parsed = parse_relay_service_manifest(*encoded.value_if());
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  EXPECT_EQ(parsed.value_if()->manifest_generation, 1U);

  RelayDeviceRecord device;
  device.device_id = identity.value_if()->device_id();
  device.public_key = identity.value_if()->public_key();
  device.tenant = "tenant-a";
  device.display_name = "device";
  device.enrollment_generation = 1U;
  device.status = RelayDeviceStatus::active;

  EXPECT_TRUE(validate_relay_service_manifest(*parsed.value_if(), device, now + 1U, record));

  auto mismatch = record;
  mismatch.manifest_sha256 = make_hash(2U);
  auto mismatch_signed = sign_relay_endpoint_record(mismatch, *identity.value_if());
  ASSERT_TRUE(mismatch_signed) << mismatch_signed.error_if()->safe_detail();
  EXPECT_EQ(validate_relay_service_manifest(*parsed.value_if(), device, now + 1U, mismatch)
                .error_if()
                ->safe_detail(),
            "service_manifest_record_mismatch");

  auto tampered = manifest;
  tampered.signature[0] ^= std::byte{0x01U};
  EXPECT_EQ(validate_relay_service_manifest(tampered, device, now + 1U, record)
                .error_if()
                ->safe_detail(),
            "signature_verification_failed");
}

TEST(M3BRelayEndpointTest, TenantExposurePolicyOnlyPublishesAllowedFields) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  auto record = make_record(*identity.value_if(), now);
  auto manifest = make_manifest(*identity.value_if(), record, now);

  RelayTenantExposurePolicy minimal;
  minimal.expose_application_id = false;
  minimal.expose_record_generation = false;
  minimal.expose_manifest_sha256 = false;
  minimal.expose_manifest_generation = false;
  minimal.expose_expiry = true;
  auto publication = publish_relay_endpoint(record, manifest, minimal, now + 1U);
  ASSERT_TRUE(publication) << publication.error_if()->safe_detail();
  EXPECT_EQ(publication.value_if()->endpoint, record.endpoint);
  EXPECT_FALSE(publication.value_if()->application_id);
  EXPECT_FALSE(publication.value_if()->record_generation);
  EXPECT_FALSE(publication.value_if()->manifest_sha256);
  EXPECT_FALSE(publication.value_if()->manifest_generation);
  EXPECT_EQ(publication.value_if()->expires_unix_milliseconds,
            record.expires_unix_milliseconds);

  RelayTenantExposurePolicy full;
  full.expose_application_id = true;
  full.expose_record_generation = true;
  full.expose_manifest_sha256 = true;
  full.expose_manifest_generation = true;
  full.expose_expiry = true;
  auto full_publication = publish_relay_endpoint(record, manifest, full, now + 1U);
  ASSERT_TRUE(full_publication) << full_publication.error_if()->safe_detail();
  EXPECT_EQ(full_publication.value_if()->application_id, "com.example.device");
  EXPECT_EQ(full_publication.value_if()->record_generation, 1U);
  EXPECT_EQ(full_publication.value_if()->manifest_generation, 1U);
  EXPECT_EQ(full_publication.value_if()->manifest_sha256, make_hash(1U));

  auto mismatched_manifest = manifest;
  mismatched_manifest.canonical_manifest_sha256 = make_hash(3U);
  auto mismatched_signed =
      sign_relay_service_manifest(mismatched_manifest, *identity.value_if());
  ASSERT_TRUE(mismatched_signed) << mismatched_signed.error_if()->safe_detail();
  EXPECT_FALSE(publish_relay_endpoint(record, mismatched_manifest, full, now + 1U));

  auto expired = record;
  expired.expires_unix_milliseconds = now - 31U * 1000U;
  auto expired_signed = sign_relay_endpoint_record(expired, *identity.value_if());
  ASSERT_TRUE(expired_signed) << expired_signed.error_if()->safe_detail();
  EXPECT_FALSE(publish_relay_endpoint(expired, std::nullopt, minimal, now + 1U));
}

TEST(M3BRelayEndpointTest, ParserRejectsDuplicateUnknownAndTruncatedFields) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  auto record = make_record(*identity.value_if(), now);
  auto manifest = make_manifest(*identity.value_if(), record, now);

  auto record_bytes = encode_relay_endpoint_record(record);
  ASSERT_TRUE(record_bytes) << record_bytes.error_if()->safe_detail();
  std::vector<std::byte> duplicate = *record_bytes.value_if();
  duplicate.push_back(static_cast<std::byte>((2U << 3U) | 2U));
  duplicate.push_back(std::byte{1U});
  duplicate.push_back(std::byte{'x'});
  EXPECT_FALSE(parse_relay_endpoint_record(duplicate));

  std::vector<std::byte> unknown = *record_bytes.value_if();
  unknown.push_back(static_cast<std::byte>(static_cast<std::uint8_t>((99U << 3U) | 0U)));
  unknown.push_back(std::byte{1U});
  EXPECT_FALSE(parse_relay_endpoint_record(unknown));

  auto manifest_bytes = encode_relay_service_manifest(manifest);
  ASSERT_TRUE(manifest_bytes) << manifest_bytes.error_if()->safe_detail();
  std::vector<std::byte> manifest_duplicate = *manifest_bytes.value_if();
  manifest_duplicate.push_back(static_cast<std::byte>((2U << 3U) | 0U));
  manifest_duplicate.push_back(std::byte{1U});
  EXPECT_FALSE(parse_relay_service_manifest(manifest_duplicate));
  EXPECT_FALSE(parse_relay_service_manifest(
      std::span<const std::byte>{manifest_bytes.value_if()->data(),
                                 manifest_bytes.value_if()->size() - 2U}));
}

}  // namespace
}  // namespace heyaki
