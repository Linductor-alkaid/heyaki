// Issue #22 verification: relay password-admission enrollment.
// Protocol layer (relay-bound proof derivation, credential XOR on the wire,
// token-mode byte compatibility) plus RelayEnrollmentService password /
// closed mode behavior on top of a real RelayDatabase.
//
// Design under test (post DEC-15): the proof is relay-bound —
// Argon2id(password, BLAKE2b-128("heyaki/relay-enrollment-password/v1" ||
// relay_id)) — so it is stable per (relay, password) across challenges and
// the relay holds a static Argon2id verifier over the LOWERCASE HEX of the
// proof. Reusing the same proof for a later challenge on the same relay is
// legal (multi-device enrollment), not a replay.
#include "relay_database.hpp"
#include "relay_enrollment.hpp"
#include "relay_enrollment_service.hpp"

#include <heyaki/error.hpp>
#include <heyaki/password.hpp>
#include <heyaki/security.hpp>

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace heyaki {
namespace {

constexpr std::string_view test_state_dir = HEYAKI_M3B_TEST_STATE_DIR;
constexpr std::string_view owner_password = "test-only-owner-password";

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

EnrollmentPasswordProof nonzero_proof(std::uint8_t seed) {
  EnrollmentPasswordProof proof{};
  for (std::size_t index = 0U; index < proof.size(); ++index) {
    proof[index] = static_cast<std::byte>(seed + static_cast<std::uint8_t>(index));
  }
  return proof;
}

// Lowercase hex, byte-for-byte the encoding the service's hex_proof helper
// and `relay --init` use as the verifier input.
std::string hex_encode(const EnrollmentPasswordProof& proof) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string output;
  output.reserve(proof.size() * 2U);
  for (const auto byte : proof) {
    const auto value = std::to_integer<unsigned char>(byte);
    output.push_back(digits[value >> 4U]);
    output.push_back(digits[value & 0x0fU]);
  }
  return output;
}

struct TestRequest {
  EnrollmentRequest request;
  std::vector<std::byte> encoded;
};

Result<TestRequest> build_request(const IdentityKeyPair& identity,
                                  const EnrollmentChallenge& challenge,
                                  std::optional<EnrollmentPasswordProof> proof,
                                  std::string_view tenant, std::uint64_t now,
                                  bool advertise_password_capability,
                                  std::uint8_t endpoint_byte,
                                  std::string_view token =
                                      "TEST-ONLY-bootstrap-token-0123456789",
                                  std::uint64_t expires_in_milliseconds = 30U * 1000U) {
  EnrollmentRequest request;
  request.device_id = identity.device_id();
  EndpointId::Storage endpoint{};
  endpoint[0] = static_cast<std::byte>(endpoint_byte);
  request.endpoint_id = EndpointId{endpoint};
  request.identity_public_key = identity.public_key();
  request.challenge_nonce = challenge.nonce;
  request.tenant = std::string{tenant};
  if (proof.has_value()) {
    request.password_proof = proof;
  } else {
    request.bootstrap_token = std::string{token};
  }
  request.protocol_version = current_protocol_version;
  request.supported.bits =
      advertise_password_capability
          ? known_capability_bits
          : (known_capability_bits &
             ~static_cast<std::uint64_t>(Capability::relay_enrollment_password_v1));
  request.required.bits = static_cast<std::uint64_t>(Capability::enrollment);
  request.expires_unix_milliseconds = now + expires_in_milliseconds;
  auto signed_result = sign_enrollment_request(request, challenge.relay_id, identity);
  if (!signed_result) {
    return Result<TestRequest>::failure(*signed_result.error_if());
  }
  auto encoded = encode_enrollment_request(request);
  if (!encoded) {
    return Result<TestRequest>::failure(*encoded.error_if());
  }
  return Result<TestRequest>::success(
      TestRequest{.request = std::move(request), .encoded = std::move(*encoded.value_if())});
}

// --init-style provisioning: the verifier is computed over the lowercase hex
// of the relay-bound proof (what enrolling clients present), with the fixed
// wire parameters {2, 64 MiB} standing in for calibration.
Result<EnrollmentPasswordProof> provision_verifier(RelayDatabase& database,
                                                   RelayId relay_id,
                                                   std::string_view password) {
  auto proof = derive_enrollment_password_proof(password, relay_id);
  if (!proof) {
    return proof;
  }
  auto verifier =
      create_password_verifier(hex_encode(*proof.value_if()),
                               PasswordHashParameters{2U, 64U * 1024U * 1024U});
  if (!verifier) {
    return Result<EnrollmentPasswordProof>::failure(*verifier.error_if());
  }
  RelayEnrollmentPasswordRecord record;
  record.format_version = verifier.value_if()->format_version;
  record.kdf_operations =
      static_cast<std::uint32_t>(verifier.value_if()->parameters.operations);
  record.kdf_memory_kib = static_cast<std::uint32_t>(
      verifier.value_if()->parameters.memory_bytes / 1024U);
  record.encoded = verifier.value_if()->encoded;
  record.updated_unix_milliseconds = now_milliseconds();
  auto stored = database.set_enrollment_password_verifier(record);
  if (!stored) {
    return Result<EnrollmentPasswordProof>::failure(*stored.error_if());
  }
  return proof;
}

// ---------------------------------------------------------------------------
// Wire helpers for the pre-change (token-only) EnrollmentRequest golden bytes.
// ---------------------------------------------------------------------------

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

void append_tag(std::vector<std::byte>& output, std::uint32_t field, std::uint8_t wire_type) {
  append_varint(output, (static_cast<std::uint64_t>(field) << 3U) | wire_type);
}

void append_uint(std::vector<std::byte>& output, std::uint32_t field, std::uint64_t value) {
  append_tag(output, field, 0U);
  append_varint(output, value);
}

void append_bytes(std::vector<std::byte>& output, std::uint32_t field,
                  std::span<const std::byte> value) {
  append_tag(output, field, 2U);
  append_varint(output, value.size());
  output.insert(output.end(), value.begin(), value.end());
}

void append_string(std::vector<std::byte>& output, std::uint32_t field,
                   std::string_view value) {
  append_bytes(output, field,
               std::span<const std::byte>{
                   reinterpret_cast<const std::byte*>(value.data()), value.size()});
}

// Hand-built pre-change encoding: fields 1..9, field 5 always present for a
// token request, no field 10. Field order and nesting mirror the production
// encoder before the password-proof field existed.
std::vector<std::byte> legacy_token_bytes(const EnrollmentRequest& request) {
  std::vector<std::byte> endpoint_message;
  append_bytes(endpoint_message, 1U, request.device_id.bytes());
  append_bytes(endpoint_message, 2U, request.endpoint_id.bytes());

  std::vector<std::byte> version_message;
  append_uint(version_message, 1U, request.protocol_version.major);
  append_uint(version_message, 2U, request.protocol_version.minor);

  std::vector<std::byte> capabilities_message;
  append_uint(capabilities_message, 1U, request.supported.bits);
  append_uint(capabilities_message, 2U, request.required.bits);

  std::vector<std::byte> signature_message;
  append_bytes(signature_message, 1U, request.signature);

  std::vector<std::byte> output;
  append_bytes(output, 1U, endpoint_message);
  append_bytes(output, 2U, request.identity_public_key);
  append_bytes(output, 3U, request.challenge_nonce);
  append_string(output, 4U, request.tenant);
  append_string(output, 5U, request.bootstrap_token);
  append_bytes(output, 6U, version_message);
  append_bytes(output, 7U, capabilities_message);
  append_uint(output, 8U, request.expires_unix_milliseconds);
  append_bytes(output, 9U, signature_message);
  return output;
}

// ---------------------------------------------------------------------------
// derive_enrollment_password_proof: relay-bound semantics.
// ---------------------------------------------------------------------------

TEST(M3BRelayEnrollmentPasswordTest, DeriveProofIsDeterministicAndRelayBound) {
  const RelayId relay_id = test_relay_id(11U);

  auto first = derive_enrollment_password_proof(owner_password, relay_id);
  ASSERT_TRUE(first) << first.error_if()->safe_detail();
  auto second = derive_enrollment_password_proof(owner_password, relay_id);
  ASSERT_TRUE(second) << second.error_if()->safe_detail();
  EXPECT_EQ(*first.value_if(), *second.value_if());

  auto other_relay =
      derive_enrollment_password_proof(owner_password, test_relay_id(12U));
  ASSERT_TRUE(other_relay) << other_relay.error_if()->safe_detail();
  EXPECT_NE(*first.value_if(), *other_relay.value_if());

  auto other_password = derive_enrollment_password_proof(
      std::string_view{"a-different-password"}, relay_id);
  ASSERT_TRUE(other_password) << other_password.error_if()->safe_detail();
  EXPECT_NE(*first.value_if(), *other_password.value_if());
}

TEST(M3BRelayEnrollmentPasswordTest, DeriveProofRejectsInvalidInputs) {
  const RelayId relay_id = test_relay_id(13U);

  auto empty = derive_enrollment_password_proof(std::string_view{}, relay_id);
  ASSERT_FALSE(empty);
  EXPECT_EQ(empty.error_if()->safe_detail(), "enrollment_proof_input_invalid");

  const std::string too_long(enrollment_password_max_bytes + 1U, 'x');
  auto oversized = derive_enrollment_password_proof(too_long, relay_id);
  ASSERT_FALSE(oversized);
  EXPECT_EQ(oversized.error_if()->safe_detail(), "enrollment_proof_input_invalid");

  auto zero_relay = derive_enrollment_password_proof(owner_password, RelayId{});
  ASSERT_FALSE(zero_relay);
  EXPECT_EQ(zero_relay.error_if()->safe_detail(), "enrollment_proof_input_invalid");

  const std::string max_length(enrollment_password_max_bytes, 'x');
  auto at_limit = derive_enrollment_password_proof(max_length, relay_id);
  ASSERT_TRUE(at_limit) << at_limit.error_if()->safe_detail();
}

// ---------------------------------------------------------------------------
// EnrollmentRequest wire format: token compatibility and password mode.
// ---------------------------------------------------------------------------

TEST(M3BRelayEnrollmentPasswordTest, LegacyTokenWireBytesStillParseIdentically) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  auto challenge = create_enrollment_challenge(test_relay_id(14U), now);
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();

  auto built = build_request(*identity.value_if(), *challenge.value_if(), std::nullopt,
                             "tenant-a", now, false, 0x21U);
  ASSERT_TRUE(built) << built.error_if()->safe_detail();

  // New encoder output for a token request must be byte-identical to the
  // hand-built pre-change encoding (fields 1..9, no field 10).
  const auto legacy = legacy_token_bytes(built.value_if()->request);
  EXPECT_EQ(built.value_if()->encoded, legacy);

  auto parsed = parse_enrollment_request(legacy);
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  EXPECT_EQ(parsed.value_if()->device_id, built.value_if()->request.device_id);
  EXPECT_EQ(parsed.value_if()->endpoint_id, built.value_if()->request.endpoint_id);
  EXPECT_EQ(parsed.value_if()->identity_public_key,
            built.value_if()->request.identity_public_key);
  EXPECT_EQ(parsed.value_if()->challenge_nonce,
            built.value_if()->request.challenge_nonce);
  EXPECT_EQ(parsed.value_if()->tenant, "tenant-a");
  EXPECT_EQ(parsed.value_if()->bootstrap_token,
            built.value_if()->request.bootstrap_token);
  EXPECT_FALSE(parsed.value_if()->password_proof.has_value());
  EXPECT_EQ(parsed.value_if()->protocol_version.major,
            current_protocol_version.major);
  EXPECT_EQ(parsed.value_if()->supported.bits, built.value_if()->request.supported.bits);
  EXPECT_EQ(parsed.value_if()->required.bits, built.value_if()->request.required.bits);
  EXPECT_EQ(parsed.value_if()->expires_unix_milliseconds,
            built.value_if()->request.expires_unix_milliseconds);
  EXPECT_EQ(parsed.value_if()->signature, built.value_if()->request.signature);

  // Re-encoding the parsed request reproduces the legacy bytes exactly.
  auto reencoded = encode_enrollment_request(*parsed.value_if());
  ASSERT_TRUE(reencoded) << reencoded.error_if()->safe_detail();
  EXPECT_EQ(*reencoded.value_if(), legacy);

  auto valid = validate_enrollment_request(*parsed.value_if(), *challenge.value_if(),
                                           now + 1U);
  EXPECT_TRUE(valid) << valid.error_if()->safe_detail();
}

TEST(M3BRelayEnrollmentPasswordTest, PasswordModeWireRoundTrip) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  auto challenge = create_enrollment_challenge(test_relay_id(15U), now);
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();

  auto built = build_request(*identity.value_if(), *challenge.value_if(),
                             nonzero_proof(0xA0U), "default", now, true, 0x31U);
  ASSERT_TRUE(built) << built.error_if()->safe_detail();
  EXPECT_TRUE(built.value_if()->request.bootstrap_token.empty());

  auto parsed = parse_enrollment_request(built.value_if()->encoded);
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  EXPECT_TRUE(parsed.value_if()->bootstrap_token.empty());
  ASSERT_TRUE(parsed.value_if()->password_proof.has_value());
  EXPECT_EQ(*parsed.value_if()->password_proof, nonzero_proof(0xA0U));
  EXPECT_EQ(parsed.value_if()->tenant, "default");

  auto valid = validate_enrollment_request(*parsed.value_if(), *challenge.value_if(),
                                           now + 1U);
  EXPECT_TRUE(valid) << valid.error_if()->safe_detail();
}

TEST(M3BRelayEnrollmentPasswordTest, ValidateLeavesCapabilityAdvertisingToServiceLayer) {
  // The capability gate lives in RelayEnrollmentService, not in
  // validate_enrollment_request: a proof-mode request that does not advertise
  // relay_enrollment_password_v1 still passes protocol validation.
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  auto challenge = create_enrollment_challenge(test_relay_id(16U), now);
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();

  auto built = build_request(*identity.value_if(), *challenge.value_if(),
                             nonzero_proof(0xB0U), "default", now, false, 0x32U);
  ASSERT_TRUE(built) << built.error_if()->safe_detail();
  EXPECT_EQ(built.value_if()->request.supported.bits &
                static_cast<std::uint64_t>(Capability::relay_enrollment_password_v1),
            0U);
  auto valid = validate_enrollment_request(built.value_if()->request,
                                           *challenge.value_if(), now + 1U);
  EXPECT_TRUE(valid) << valid.error_if()->safe_detail();
}

TEST(M3BRelayEnrollmentPasswordTest, ParseEnforcesCredentialExclusivity) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  auto challenge = create_enrollment_challenge(test_relay_id(17U), now);
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();

  auto token_built = build_request(*identity.value_if(), *challenge.value_if(),
                                   std::nullopt, "tenant-a", now, true, 0x41U);
  ASSERT_TRUE(token_built) << token_built.error_if()->safe_detail();

  // Both credentials present: structurally valid fields, XOR violated.
  std::vector<std::byte> both = token_built.value_if()->encoded;
  append_bytes(both, 10U, nonzero_proof(0xC0U));
  auto both_parsed = parse_enrollment_request(both);
  ASSERT_FALSE(both_parsed);
  EXPECT_EQ(both_parsed.error_if()->safe_detail(), "enrollment_credential_invalid");

  // Neither credential present: drop field 5 from the legacy encoding.
  const auto& token_request = token_built.value_if()->request;
  std::vector<std::byte> version_message;
  append_uint(version_message, 1U, token_request.protocol_version.major);
  append_uint(version_message, 2U, token_request.protocol_version.minor);
  std::vector<std::byte> capabilities_message;
  append_uint(capabilities_message, 1U, token_request.supported.bits);
  append_uint(capabilities_message, 2U, token_request.required.bits);
  std::vector<std::byte> signature_message;
  append_bytes(signature_message, 1U, token_request.signature);

  std::vector<std::byte> neither;
  std::vector<std::byte> endpoint_message;
  append_bytes(endpoint_message, 1U, token_request.device_id.bytes());
  append_bytes(endpoint_message, 2U, token_request.endpoint_id.bytes());
  append_bytes(neither, 1U, endpoint_message);
  append_bytes(neither, 2U, token_request.identity_public_key);
  append_bytes(neither, 3U, token_request.challenge_nonce);
  append_string(neither, 4U, token_request.tenant);
  append_bytes(neither, 6U, version_message);
  append_bytes(neither, 7U, capabilities_message);
  append_uint(neither, 8U, token_request.expires_unix_milliseconds);
  append_bytes(neither, 9U, signature_message);
  auto neither_parsed = parse_enrollment_request(neither);
  ASSERT_FALSE(neither_parsed);
  EXPECT_EQ(neither_parsed.error_if()->safe_detail(), "enrollment_credential_invalid");

  // Field 10 with a length other than 32 bytes is rejected outright.
  std::vector<std::byte> short_proof = token_built.value_if()->encoded;
  const std::array<std::byte, 31U> truncated{};
  append_bytes(short_proof, 10U, truncated);
  auto short_parsed = parse_enrollment_request(short_proof);
  ASSERT_FALSE(short_parsed);
  EXPECT_EQ(short_parsed.error_if()->safe_detail(), "enrollment_proof_invalid");

  std::vector<std::byte> long_proof = token_built.value_if()->encoded;
  const std::array<std::byte, 33U> oversized{};
  append_bytes(long_proof, 10U, oversized);
  auto long_parsed = parse_enrollment_request(long_proof);
  ASSERT_FALSE(long_parsed);
  EXPECT_EQ(long_parsed.error_if()->safe_detail(), "enrollment_proof_invalid");
}

// ---------------------------------------------------------------------------
// RelayEnrollmentService password / closed modes.
// ---------------------------------------------------------------------------

TEST(M3BRelayEnrollmentPasswordTest, PasswordModeHappyPathCompletesWithoutTokenUse) {
  TemporaryDirectory directory{"m3b-relay-enroll-password-happy"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  const RelayId relay_id = test_relay_id(18U);

  RelayEnrollmentServiceConfig config;
  config.mode = RelayEnrollmentMode::password;
  config.default_tenant = "default";
  auto service = RelayEnrollmentService::create(database.value_if(), relay_id, config);
  ASSERT_TRUE(service) << service.error_if()->safe_detail();

  const auto now = now_milliseconds();
  auto challenge_bytes = service.value_if()->begin_challenge(now);
  ASSERT_TRUE(challenge_bytes) << challenge_bytes.error_if()->safe_detail();
  auto challenge = parse_enrollment_challenge(*challenge_bytes.value_if());
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();

  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  auto proof = provision_verifier(*database.value_if(), relay_id, owner_password);
  ASSERT_TRUE(proof) << proof.error_if()->safe_detail();

  auto built = build_request(*identity.value_if(), *challenge.value_if(),
                             *proof.value_if(), "default", now, true, 0x51U);
  ASSERT_TRUE(built) << built.error_if()->safe_detail();

  auto completed = service.value_if()->complete(built.value_if()->encoded, now + 1U);
  ASSERT_TRUE(completed) << completed.error_if()->safe_detail();
  EXPECT_EQ(completed.value_if()->device_id, identity.value_if()->device_id());
  EXPECT_EQ(completed.value_if()->tenant, "default");
  EXPECT_EQ(completed.value_if()->enrollment_generation, 1U);
  EXPECT_EQ(completed.value_if()->token_remaining_uses_after, std::nullopt);
  EXPECT_EQ(database.value_if()->snapshot().device_count, 1U);

  const auto diagnostics = service.value_if()->diagnostics();
  EXPECT_EQ(diagnostics.challenges_issued, 1U);
  EXPECT_EQ(diagnostics.challenges_completed, 1U);
  EXPECT_EQ(diagnostics.password_rejected, 0U);
  EXPECT_EQ(diagnostics.mode_rejected, 0U);
  EXPECT_EQ(diagnostics.token_rejected, 0U);
}

TEST(M3BRelayEnrollmentPasswordTest, PasswordModeRejectsWrongPassword) {
  TemporaryDirectory directory{"m3b-relay-enroll-password-wrong"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  const RelayId relay_id = test_relay_id(19U);

  RelayEnrollmentServiceConfig config;
  config.mode = RelayEnrollmentMode::password;
  auto service = RelayEnrollmentService::create(database.value_if(), relay_id, config);
  ASSERT_TRUE(service) << service.error_if()->safe_detail();

  const auto now = now_milliseconds();
  auto challenge_bytes = service.value_if()->begin_challenge(now);
  ASSERT_TRUE(challenge_bytes) << challenge_bytes.error_if()->safe_detail();
  auto challenge = parse_enrollment_challenge(*challenge_bytes.value_if());
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();

  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  auto proof = provision_verifier(*database.value_if(), relay_id, owner_password);
  ASSERT_TRUE(proof) << proof.error_if()->safe_detail();

  auto wrong_proof = derive_enrollment_password_proof(
      std::string_view{"a-different-password"}, relay_id);
  ASSERT_TRUE(wrong_proof) << wrong_proof.error_if()->safe_detail();
  EXPECT_NE(*wrong_proof.value_if(), *proof.value_if());

  auto built = build_request(*identity.value_if(), *challenge.value_if(),
                             *wrong_proof.value_if(), "default", now, true, 0x52U);
  ASSERT_TRUE(built) << built.error_if()->safe_detail();

  auto rejected = service.value_if()->complete(built.value_if()->encoded, now + 1U);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->code(), ErrorCode::authentication);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "enrollment_password_rejected");

  const auto diagnostics = service.value_if()->diagnostics();
  EXPECT_EQ(diagnostics.password_rejected, 1U);
  EXPECT_EQ(diagnostics.challenges_completed, 0U);
  EXPECT_EQ(database.value_if()->snapshot().device_count, 0U);
}

TEST(M3BRelayEnrollmentPasswordTest, PasswordModeIdempotentReenrollmentKeepsGeneration) {
  TemporaryDirectory directory{"m3b-relay-enroll-password-idempotent"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  const RelayId relay_id = test_relay_id(20U);

  RelayEnrollmentServiceConfig config;
  config.mode = RelayEnrollmentMode::password;
  auto service = RelayEnrollmentService::create(database.value_if(), relay_id, config);
  ASSERT_TRUE(service) << service.error_if()->safe_detail();

  const auto now = now_milliseconds();
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();

  auto first_bytes = service.value_if()->begin_challenge(now);
  ASSERT_TRUE(first_bytes) << first_bytes.error_if()->safe_detail();
  auto first_challenge = parse_enrollment_challenge(*first_bytes.value_if());
  ASSERT_TRUE(first_challenge) << first_challenge.error_if()->safe_detail();
  auto proof = provision_verifier(*database.value_if(), relay_id, owner_password);
  ASSERT_TRUE(proof) << proof.error_if()->safe_detail();
  auto first_built = build_request(*identity.value_if(), *first_challenge.value_if(),
                                   *proof.value_if(), "default", now, true, 0x54U);
  ASSERT_TRUE(first_built) << first_built.error_if()->safe_detail();
  auto first_completed =
      service.value_if()->complete(first_built.value_if()->encoded, now + 1U);
  ASSERT_TRUE(first_completed) << first_completed.error_if()->safe_detail();
  ASSERT_EQ(first_completed.value_if()->enrollment_generation, 1U);

  // The proof is relay-bound: the same proof verifies again on a fresh
  // challenge without re-provisioning, and the active device keeps its
  // generation instead of consuming anything.
  auto second_bytes = service.value_if()->begin_challenge(now + 2U);
  ASSERT_TRUE(second_bytes) << second_bytes.error_if()->safe_detail();
  auto second_challenge = parse_enrollment_challenge(*second_bytes.value_if());
  ASSERT_TRUE(second_challenge) << second_challenge.error_if()->safe_detail();
  EXPECT_NE(second_challenge.value_if()->nonce, first_challenge.value_if()->nonce);
  auto rederved = derive_enrollment_password_proof(owner_password, relay_id);
  ASSERT_TRUE(rederved) << rederved.error_if()->safe_detail();
  EXPECT_EQ(*rederved.value_if(), *proof.value_if());
  auto second_built = build_request(*identity.value_if(), *second_challenge.value_if(),
                                    *rederved.value_if(), "default", now + 2U, true,
                                    0x54U);
  ASSERT_TRUE(second_built) << second_built.error_if()->safe_detail();
  auto second_completed =
      service.value_if()->complete(second_built.value_if()->encoded, now + 3U);
  ASSERT_TRUE(second_completed) << second_completed.error_if()->safe_detail();
  EXPECT_EQ(second_completed.value_if()->enrollment_generation, 1U);
  EXPECT_EQ(second_completed.value_if()->token_remaining_uses_after, std::nullopt);
  EXPECT_EQ(database.value_if()->snapshot().device_count, 1U);
}

// Issue #22 end-to-end acceptance (service level): one --init-style provision
// admits device after device with the same password on fresh challenges, and
// a wrong password is rejected with the counter incremented.
TEST(M3BRelayEnrollmentPasswordTest,
     OneProvisionAdmitsMultipleDevicesAndRejectsWrongPassword) {
  TemporaryDirectory directory{"m3b-relay-enroll-password-multidevice"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  const RelayId relay_id = test_relay_id(25U);

  RelayEnrollmentServiceConfig config;
  config.mode = RelayEnrollmentMode::password;
  auto service = RelayEnrollmentService::create(database.value_if(), relay_id, config);
  ASSERT_TRUE(service) << service.error_if()->safe_detail();

  const auto now = now_milliseconds();
  auto proof = provision_verifier(*database.value_if(), relay_id, owner_password);
  ASSERT_TRUE(proof) << proof.error_if()->safe_detail();

  auto enroll = [&](const IdentityKeyPair& identity, std::uint8_t endpoint_byte,
                    std::uint64_t at) -> Result<RelayEnrollmentCompletion> {
    auto challenge_bytes = service.value_if()->begin_challenge(at);
    if (!challenge_bytes) {
      return Result<RelayEnrollmentCompletion>::failure(*challenge_bytes.error_if());
    }
    auto challenge = parse_enrollment_challenge(*challenge_bytes.value_if());
    if (!challenge) {
      return Result<RelayEnrollmentCompletion>::failure(*challenge.error_if());
    }
    auto built = build_request(identity, *challenge.value_if(), *proof.value_if(),
                               "default", at, true, endpoint_byte);
    if (!built) {
      return Result<RelayEnrollmentCompletion>::failure(*built.error_if());
    }
    return service.value_if()->complete(built.value_if()->encoded, at + 1U);
  };

  auto first_identity = create_identity();
  ASSERT_TRUE(first_identity) << first_identity.error_if()->safe_detail();
  auto first = enroll(*first_identity.value_if(), 0x61U, now);
  ASSERT_TRUE(first) << first.error_if()->safe_detail();
  EXPECT_EQ(first.value_if()->enrollment_generation, 1U);

  // A second device key enrolls with the SAME password (hence the same
  // relay-bound proof) and a fresh challenge: legal, not a replay.
  auto second_identity = create_identity();
  ASSERT_TRUE(second_identity) << second_identity.error_if()->safe_detail();
  auto second = enroll(*second_identity.value_if(), 0x62U, now + 10U);
  ASSERT_TRUE(second) << second.error_if()->safe_detail();
  EXPECT_EQ(second.value_if()->enrollment_generation, 1U);
  EXPECT_NE(second.value_if()->device_id, first.value_if()->device_id);
  EXPECT_EQ(database.value_if()->snapshot().device_count, 2U);

  // A wrong password derives a different proof and is rejected.
  auto wrong_identity = create_identity();
  ASSERT_TRUE(wrong_identity) << wrong_identity.error_if()->safe_detail();
  auto wrong_challenge_bytes = service.value_if()->begin_challenge(now + 20U);
  ASSERT_TRUE(wrong_challenge_bytes) << wrong_challenge_bytes.error_if()->safe_detail();
  auto wrong_challenge = parse_enrollment_challenge(*wrong_challenge_bytes.value_if());
  ASSERT_TRUE(wrong_challenge) << wrong_challenge.error_if()->safe_detail();
  auto wrong_proof = derive_enrollment_password_proof(
      std::string_view{"a-different-password"}, relay_id);
  ASSERT_TRUE(wrong_proof) << wrong_proof.error_if()->safe_detail();
  auto wrong_built = build_request(*wrong_identity.value_if(),
                                   *wrong_challenge.value_if(), *wrong_proof.value_if(),
                                   "default", now + 20U, true, 0x63U);
  ASSERT_TRUE(wrong_built) << wrong_built.error_if()->safe_detail();
  auto rejected =
      service.value_if()->complete(wrong_built.value_if()->encoded, now + 21U);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "enrollment_password_rejected");
  EXPECT_EQ(database.value_if()->snapshot().device_count, 2U);

  const auto diagnostics = service.value_if()->diagnostics();
  EXPECT_EQ(diagnostics.challenges_completed, 2U);
  EXPECT_EQ(diagnostics.password_rejected, 1U);
}

TEST(M3BRelayEnrollmentPasswordTest, PasswordModeStructuralGatesRejectEarly) {
  TemporaryDirectory directory{"m3b-relay-enroll-password-gates"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();

  RelayEnrollmentServiceConfig config;
  config.mode = RelayEnrollmentMode::password;
  auto service = RelayEnrollmentService::create(database.value_if(), test_relay_id(21U),
                                                config);
  ASSERT_TRUE(service) << service.error_if()->safe_detail();

  const auto now = now_milliseconds();
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();

  // Missing relay_enrollment_password_v1 capability.
  auto capability_bytes = service.value_if()->begin_challenge(now);
  ASSERT_TRUE(capability_bytes) << capability_bytes.error_if()->safe_detail();
  auto capability_challenge = parse_enrollment_challenge(*capability_bytes.value_if());
  ASSERT_TRUE(capability_challenge) << capability_challenge.error_if()->safe_detail();
  auto no_capability =
      build_request(*identity.value_if(), *capability_challenge.value_if(),
                    nonzero_proof(0xD0U), "default", now, false, 0x55U);
  ASSERT_TRUE(no_capability) << no_capability.error_if()->safe_detail();
  auto capability_rejected =
      service.value_if()->complete(no_capability.value_if()->encoded, now + 1U);
  ASSERT_FALSE(capability_rejected);
  EXPECT_EQ(capability_rejected.error_if()->safe_detail(),
            "enrollment_password_capability_missing");

  // Unknown tenant.
  auto tenant_bytes = service.value_if()->begin_challenge(now + 2U);
  ASSERT_TRUE(tenant_bytes) << tenant_bytes.error_if()->safe_detail();
  auto tenant_challenge = parse_enrollment_challenge(*tenant_bytes.value_if());
  ASSERT_TRUE(tenant_challenge) << tenant_challenge.error_if()->safe_detail();
  auto other_tenant = build_request(*identity.value_if(), *tenant_challenge.value_if(),
                                    nonzero_proof(0xD1U), "tenant-b", now + 2U, true,
                                    0x56U);
  ASSERT_TRUE(other_tenant) << other_tenant.error_if()->safe_detail();
  auto tenant_rejected =
      service.value_if()->complete(other_tenant.value_if()->encoded, now + 3U);
  ASSERT_FALSE(tenant_rejected);
  EXPECT_EQ(tenant_rejected.error_if()->safe_detail(), "enrollment_tenant_unknown");

  // Token credential instead of a proof.
  auto token_bytes = service.value_if()->begin_challenge(now + 4U);
  ASSERT_TRUE(token_bytes) << token_bytes.error_if()->safe_detail();
  auto token_challenge = parse_enrollment_challenge(*token_bytes.value_if());
  ASSERT_TRUE(token_challenge) << token_challenge.error_if()->safe_detail();
  auto token_request = build_request(*identity.value_if(), *token_challenge.value_if(),
                                     std::nullopt, "default", now + 4U, true, 0x57U);
  ASSERT_TRUE(token_request) << token_request.error_if()->safe_detail();
  auto proof_required =
      service.value_if()->complete(token_request.value_if()->encoded, now + 5U);
  ASSERT_FALSE(proof_required);
  EXPECT_EQ(proof_required.error_if()->safe_detail(),
            "enrollment_password_proof_required");

  // No verifier provisioned in the database.
  auto fresh = create_identity();
  ASSERT_TRUE(fresh) << fresh.error_if()->safe_detail();
  auto unprovisioned_bytes = service.value_if()->begin_challenge(now + 6U);
  ASSERT_TRUE(unprovisioned_bytes) << unprovisioned_bytes.error_if()->safe_detail();
  auto unprovisioned_challenge =
      parse_enrollment_challenge(*unprovisioned_bytes.value_if());
  ASSERT_TRUE(unprovisioned_challenge)
      << unprovisioned_challenge.error_if()->safe_detail();
  auto unprovisioned =
      build_request(*fresh.value_if(), *unprovisioned_challenge.value_if(),
                    nonzero_proof(0xD2U), "default", now + 6U, true, 0x58U);
  ASSERT_TRUE(unprovisioned) << unprovisioned.error_if()->safe_detail();
  auto not_provisioned =
      service.value_if()->complete(unprovisioned.value_if()->encoded, now + 7U);
  ASSERT_FALSE(not_provisioned);
  EXPECT_EQ(not_provisioned.error_if()->code(), ErrorCode::configuration);
  EXPECT_EQ(not_provisioned.error_if()->safe_detail(),
            "enrollment_password_not_provisioned");

  const auto diagnostics = service.value_if()->diagnostics();
  EXPECT_EQ(diagnostics.mode_rejected, 4U);
  EXPECT_EQ(diagnostics.password_rejected, 0U);
  EXPECT_EQ(diagnostics.challenges_completed, 0U);
}

TEST(M3BRelayEnrollmentPasswordTest, PasswordModeRejectsExpiredChallenge) {
  TemporaryDirectory directory{"m3b-relay-enroll-password-expired"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();

  RelayEnrollmentServiceConfig config;
  config.mode = RelayEnrollmentMode::password;
  config.challenge_validity = std::chrono::milliseconds{1000U};
  auto service = RelayEnrollmentService::create(database.value_if(), test_relay_id(22U),
                                                config);
  ASSERT_TRUE(service) << service.error_if()->safe_detail();

  const auto now = now_milliseconds();
  auto challenge_bytes = service.value_if()->begin_challenge(now);
  ASSERT_TRUE(challenge_bytes) << challenge_bytes.error_if()->safe_detail();
  auto challenge = parse_enrollment_challenge(*challenge_bytes.value_if());
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();

  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  // The request expiry must stay within the short challenge validity; the
  // challenge itself is expired by REALLY waiting out the TTL table (the
  // service tracks challenges on the steady clock, not on the mocked unix
  // timestamps).
  auto built = build_request(*identity.value_if(), *challenge.value_if(),
                             nonzero_proof(0xE0U), "default", now, true, 0x59U,
                             "TEST-ONLY-unused-token-0123456789", 900U);
  ASSERT_TRUE(built) << built.error_if()->safe_detail();

  std::this_thread::sleep_for(std::chrono::milliseconds{1200});
  auto expired =
      service.value_if()->complete(built.value_if()->encoded, now + 2000U);
  ASSERT_FALSE(expired);
  EXPECT_EQ(expired.error_if()->code(), ErrorCode::authentication);
  EXPECT_EQ(expired.error_if()->safe_detail(), "enrollment_challenge_unknown_or_expired");
  EXPECT_EQ(database.value_if()->snapshot().device_count, 0U);
}

TEST(M3BRelayEnrollmentPasswordTest, ClosedModeRefusesChallengesAndTokenModeUnchanged) {
  TemporaryDirectory directory{"m3b-relay-enroll-mode-closed-token"};
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();

  RelayEnrollmentServiceConfig closed_config;
  closed_config.mode = RelayEnrollmentMode::closed;
  auto closed_service = RelayEnrollmentService::create(database.value_if(),
                                                       test_relay_id(23U), closed_config);
  ASSERT_TRUE(closed_service) << closed_service.error_if()->safe_detail();

  const auto now = now_milliseconds();
  auto closed_challenge = closed_service.value_if()->begin_challenge(now);
  ASSERT_FALSE(closed_challenge);
  EXPECT_EQ(closed_challenge.error_if()->code(), ErrorCode::permission);
  EXPECT_EQ(closed_challenge.error_if()->safe_detail(), "enrollment_closed");
  EXPECT_EQ(closed_service.value_if()->diagnostics().mode_rejected, 1U);

  // Token mode regression: the complete historical flow still works and the
  // consumption result carries the remaining-use count.
  const std::string token = "TEST-ONLY-mode-regression-token-001";
  auto created = database.value_if()->create_bootstrap_token("tenant-a", token,
                                                             now + 60U * 1000U, 1U);
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  RelayEnrollmentServiceConfig token_config;
  token_config.mode = RelayEnrollmentMode::token;
  auto token_service = RelayEnrollmentService::create(database.value_if(),
                                                      test_relay_id(24U), token_config);
  ASSERT_TRUE(token_service) << token_service.error_if()->safe_detail();

  auto challenge_bytes = token_service.value_if()->begin_challenge(now);
  ASSERT_TRUE(challenge_bytes) << challenge_bytes.error_if()->safe_detail();
  auto challenge = parse_enrollment_challenge(*challenge_bytes.value_if());
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  auto built = build_request(*identity.value_if(), *challenge.value_if(), std::nullopt,
                             "tenant-a", now, false, 0x5AU, token);
  ASSERT_TRUE(built) << built.error_if()->safe_detail();
  auto completed = token_service.value_if()->complete(built.value_if()->encoded, now + 1U);
  ASSERT_TRUE(completed) << completed.error_if()->safe_detail();
  EXPECT_EQ(completed.value_if()->token_remaining_uses_after, 0U);
  EXPECT_EQ(completed.value_if()->enrollment_generation, 1U);
  EXPECT_EQ(database.value_if()->snapshot().device_count, 1U);
}

}  // namespace
}  // namespace heyaki
