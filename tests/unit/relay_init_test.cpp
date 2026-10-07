// Issue #22 verification: `heyaki-relay --init` first-run bootstrap.
// Covers the individual primitives (certificate generation, SAN discovery,
// TURN secret, password file reading) and the full run_relay_init flow
// including idempotence and the provisioned-verifier enrollment contract.
#include "relay_init.hpp"

#include "relay_config.hpp"
#include "relay_database.hpp"
#include "relay_enrollment.hpp"
#include "relay_enrollment_service.hpp"
#include "relay_turn_credentials.hpp"

#include <heyaki/password.hpp>
#include <heyaki/security.hpp>

#include <gtest/gtest.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
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

// run_relay_init prints the access card on stdout; keep test output clean.
class CoutCapture {
 public:
  CoutCapture() : old_(std::cout.rdbuf(buffer_.rdbuf())) {}
  ~CoutCapture() { std::cout.rdbuf(old_); }
  CoutCapture(const CoutCapture&) = delete;
  CoutCapture& operator=(const CoutCapture&) = delete;

  [[nodiscard]] std::string str() const { return buffer_.str(); }

 private:
  std::ostringstream buffer_;
  std::streambuf* old_;
};

void write_password_file(const std::filesystem::path& path, std::string_view content) {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  ASSERT_TRUE(output);
  output.write(content.data(), static_cast<std::streamsize>(content.size()));
  output.close();
  ASSERT_TRUE(output);
}

std::filesystem::perms key_permissions(const std::filesystem::path& path) {
  std::error_code error;
  const auto status = std::filesystem::status(path, error);
  EXPECT_FALSE(error);
  return status.permissions();
}

std::uint64_t now_milliseconds() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
}

// Same translation the enrollment service performs on the stored record
// before verify_password.
PasswordVerifier to_verifier(const RelayEnrollmentPasswordRecord& record) {
  PasswordVerifier verifier;
  verifier.format_version = record.format_version;
  verifier.parameters.operations = record.argon2_operations;
  verifier.parameters.memory_bytes =
      static_cast<std::size_t>(record.argon2_memory_kib) * 1024U;
  verifier.encoded = record.encoded;
  return verifier;
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

// SHA-256 of a PEM certificate — the relay id `relay --init` provisions
// against and the running relay derives for itself.
Result<RelayId> certificate_digest(const std::filesystem::path& certificate_file) {
  std::FILE* file = std::fopen(certificate_file.string().c_str(), "rb");
  if (file == nullptr) {
    return Result<RelayId>::failure(
        Error{ErrorCode::configuration, "test", "certificate_unreadable"});
  }
  X509* certificate = PEM_read_X509(file, nullptr, nullptr, nullptr);
  std::fclose(file);
  if (certificate == nullptr) {
    return Result<RelayId>::failure(
        Error{ErrorCode::configuration, "test", "certificate_unparseable"});
  }
  RelayId relay_id{};
  const int matched = X509_digest(certificate, EVP_sha256(),
                                  reinterpret_cast<unsigned char*>(relay_id.data()),
                                  nullptr);
  X509_free(certificate);
  if (matched != 1) {
    return Result<RelayId>::failure(
        Error{ErrorCode::configuration, "test", "certificate_digest_failed"});
  }
  return Result<RelayId>::success(relay_id);
}

std::string file_contents(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary};
  EXPECT_TRUE(input);
  return std::string{std::istreambuf_iterator<char>(input),
                     std::istreambuf_iterator<char>()};
}

// ---------------------------------------------------------------------------
// Primitives.
// ---------------------------------------------------------------------------

TEST(RelayInitTest, CollectLocalSanEntriesContainsLoopbackAnchors) {
  auto entries = collect_local_san_entries();
  ASSERT_TRUE(entries) << entries.error_if()->safe_detail();
  const auto& list = *entries.value_if();
  ASSERT_GE(list.size(), 3U);
  EXPECT_EQ(list[list.size() - 3U], "localhost");
  EXPECT_EQ(list[list.size() - 2U], "127.0.0.1");
  EXPECT_EQ(list[list.size() - 1U], "::1");
  // No duplicates.
  for (std::size_t outer = 0U; outer < list.size(); ++outer) {
    for (std::size_t inner = outer + 1U; inner < list.size(); ++inner) {
      EXPECT_NE(list[outer], list[inner]) << "duplicate SAN entry";
    }
  }
  // When the hostname resolves to a non-loopback address, it leads the list
  // (the advertised host for the access card).
  if (list.size() > 3U) {
    EXPECT_NE(list.front(), "localhost");
    EXPECT_NE(list.front(), "127.0.0.1");
    EXPECT_NE(list.front(), "::1");
  }
}

TEST(RelayInitTest, GeneratesSelfSignedCertificateWithDigestAndOwnerOnlyKey) {
  TemporaryDirectory directory{"relay-init-cert"};
  const auto certificate = directory.path() / "relay.crt";
  const auto private_key = directory.path() / "relay.key";
  const std::vector<std::string> sans{"relay.test.example", "localhost", "127.0.0.1",
                                      "::1"};

  auto generated =
      generate_self_signed_relay_certificate(certificate, private_key, sans);
  ASSERT_TRUE(generated) << generated.error_if()->safe_detail();
  ASSERT_TRUE(std::filesystem::is_regular_file(certificate));
  ASSERT_TRUE(std::filesystem::is_regular_file(private_key));

  // The key file is owner-only (0600).
  const auto permissions = key_permissions(private_key);
  EXPECT_EQ(permissions & std::filesystem::perms::mask,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);

  // The certificate is parseable PEM and the returned digest is its SHA-256.
  std::FILE* file = std::fopen(certificate.string().c_str(), "rb");
  ASSERT_NE(file, nullptr);
  X509* parsed = PEM_read_X509(file, nullptr, nullptr, nullptr);
  std::fclose(file);
  ASSERT_NE(parsed, nullptr);
  std::array<unsigned char, 32U> digest{};
  const int matched = X509_digest(parsed, EVP_sha256(), digest.data(), nullptr);
  X509_free(parsed);
  ASSERT_EQ(matched, 1);
  for (std::size_t index = 0U; index < digest.size(); ++index) {
    EXPECT_EQ((*generated.value_if())[index], static_cast<std::byte>(digest[index]))
        << "digest byte " << index;
  }

  // Regenerating over the same paths must fail (never overwrite).
  auto again = generate_self_signed_relay_certificate(certificate, private_key, sans);
  EXPECT_FALSE(again);

  auto empty_sans =
      generate_self_signed_relay_certificate(directory.path() / "empty.crt",
                                             directory.path() / "empty.key", {});
  EXPECT_FALSE(empty_sans);
}

TEST(RelayInitTest, GeneratesDistinctValidTurnSecrets) {
  auto first = generate_turn_secret();
  ASSERT_TRUE(first) << first.error_if()->safe_detail();
  EXPECT_EQ(first.value_if()->size(), 40U);
  EXPECT_TRUE(std::all_of(first.value_if()->begin(), first.value_if()->end(),
                          [](char character) {
                            const auto raw = static_cast<unsigned char>(character);
                            return (raw >= 'A' && raw <= 'Z') ||
                                   (raw >= 'a' && raw <= 'z') ||
                                   (raw >= '0' && raw <= '9');
                          }));
  auto validated = validate_turn_secret(*first.value_if());
  EXPECT_TRUE(validated) << validated.error_if()->safe_detail();

  auto second = generate_turn_secret();
  ASSERT_TRUE(second) << second.error_if()->safe_detail();
  EXPECT_NE(*first.value_if(), *second.value_if());
}

TEST(RelayInitTest, ReadsOwnerPasswordFileFirstLine) {
  TemporaryDirectory directory{"relay-init-password-file"};

  const auto plain = directory.path() / "plain.txt";
  write_password_file(plain, "correct horse battery staple\n");
  auto plain_password = read_owner_password_file(plain);
  ASSERT_TRUE(plain_password) << plain_password.error_if()->safe_detail();
  EXPECT_EQ(*plain_password.value_if(), "correct horse battery staple");

  // Trailing CR (CRLF files) is stripped; only the first line is read.
  const auto crlf = directory.path() / "crlf.txt";
  write_password_file(crlf, "windows-password\r\nsecond line ignored\n");
  auto crlf_password = read_owner_password_file(crlf);
  ASSERT_TRUE(crlf_password) << crlf_password.error_if()->safe_detail();
  EXPECT_EQ(*crlf_password.value_if(), "windows-password");

  const auto empty = directory.path() / "empty.txt";
  write_password_file(empty, "");
  auto empty_password = read_owner_password_file(empty);
  ASSERT_FALSE(empty_password);
  EXPECT_EQ(empty_password.error_if()->code(), ErrorCode::configuration);

  const auto too_long = directory.path() / "too-long.txt";
  write_password_file(too_long, std::string(enrollment_password_max_bytes + 1U, 'x'));
  auto long_password = read_owner_password_file(too_long);
  ASSERT_FALSE(long_password);

  auto missing = read_owner_password_file(directory.path() / "missing.txt");
  ASSERT_FALSE(missing);
}

// ---------------------------------------------------------------------------
// run_relay_init full flow.
// ---------------------------------------------------------------------------

RelayInitOptions init_options(const std::filesystem::path& directory) {
  RelayInitOptions options;
  options.config_file = directory / "relay.conf";
  options.listen_port = 18443U;
  options.password_file = directory / "owner-password.txt";
  return options;
}

TEST(RelayInitTest, RunInitProvisionsConfigCertificateDatabaseAndTurnSecret) {
  TemporaryDirectory directory{"relay-init-flow"};
  auto options = init_options(directory.path());
  write_password_file(*options.password_file, std::string{owner_password} + "\n");

  std::string output;
  {
    CoutCapture capture;
    auto initialized = run_relay_init(options);
    ASSERT_TRUE(initialized) << initialized.error_if()->safe_detail();
    output = capture.str();
  }
  EXPECT_NE(output.find("URL:"), std::string::npos);
  EXPECT_NE(output.find("PIN:"), std::string::npos);
  EXPECT_NE(output.find("Tenant:"), std::string::npos);
  EXPECT_NE(output.find("wss://"), std::string::npos);

  // Generated baseline config loads and selects password enrollment.
  auto config = load_relay_config_file(options.config_file);
  ASSERT_TRUE(config) << config.error_if()->safe_detail();
  EXPECT_EQ(config.value_if()->enrollment_mode, RelayEnrollmentMode::password);
  EXPECT_EQ(config.value_if()->enrollment_default_tenant, "default");
  EXPECT_EQ(config.value_if()->listen_port, 18443U);
  EXPECT_TRUE(std::filesystem::is_regular_file(config.value_if()->tls_certificate_file));
  EXPECT_TRUE(std::filesystem::is_regular_file(config.value_if()->tls_private_key_file));

  // Owner password verifier provisioned in the relay database: the verifier
  // input is the lowercase hex of the relay-bound proof for the owner
  // password against the generated certificate digest (the relay id).
  auto relay_id = certificate_digest(config.value_if()->tls_certificate_file);
  ASSERT_TRUE(relay_id) << relay_id.error_if()->safe_detail();
  auto proof = derive_enrollment_password_proof(owner_password, *relay_id.value_if());
  ASSERT_TRUE(proof) << proof.error_if()->safe_detail();
  auto database = RelayDatabase::open(config.value_if()->database_file);
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  auto verifier = database.value_if()->enrollment_password_verifier();
  ASSERT_TRUE(verifier) << verifier.error_if()->safe_detail();
  ASSERT_TRUE(verifier.value_if()->has_value());
  EXPECT_EQ((*verifier.value_if())->format_version, 1U);
  auto proof_verified =
      verify_password(hex_encode(*proof.value_if()), to_verifier(**verifier.value_if()));
  ASSERT_TRUE(proof_verified) << proof_verified.error_if()->safe_detail();
  EXPECT_TRUE(*proof_verified.value_if());

  // TURN env file with a random secret, owner-only permissions.
  const auto turn_env = directory.path() / "heyaki-turn.env";
  ASSERT_TRUE(std::filesystem::is_regular_file(turn_env));
  const auto turn_contents = file_contents(turn_env);
  EXPECT_TRUE(turn_contents.starts_with("HEYAKI_TURN_SECRET="));
  EXPECT_EQ(turn_contents.find("HEYAKI_TURN_SECRET=" + std::string(40U, 'x')),
            std::string::npos)
      << "the TURN secret must be random";
  EXPECT_EQ(key_permissions(turn_env) & std::filesystem::perms::mask,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
}

TEST(RelayInitTest, RunInitIsIdempotentWithoutNewPasswordInput) {
  TemporaryDirectory directory{"relay-init-idempotent"};
  auto options = init_options(directory.path());
  write_password_file(*options.password_file, std::string{owner_password} + "\n");
  {
    CoutCapture capture;
    ASSERT_TRUE(run_relay_init(options)) << "first init must succeed";
  }

  // Freeze what exists: file contents and the provisioned verifier.
  const auto config_before = file_contents(options.config_file);
  const auto certificate_before = file_contents(directory.path() / "certs" / "relay.crt");
  const auto key_before = file_contents(directory.path() / "certs" / "relay.key");
  const auto turn_before = file_contents(directory.path() / "heyaki-turn.env");
  std::string verifier_encoded_before;
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    auto verifier_before = database.value_if()->enrollment_password_verifier();
    ASSERT_TRUE(verifier_before) << verifier_before.error_if()->safe_detail();
    ASSERT_TRUE(verifier_before.value_if()->has_value());
    verifier_encoded_before = (*verifier_before.value_if())->encoded;
  }  // Release the database handle before the second init run.

  // Second run with no password source (the password file option is dropped
  // and stdin (/dev/null) makes the interactive prompt fail fast), so the
  // existing verifier is kept and no artifact is rewritten.
  options.password_file.reset();
#if defined(_WIN32)
  std::FILE* null_stdin = std::freopen("NUL", "r", stdin);
#else
  std::FILE* null_stdin = std::freopen("/dev/null", "r", stdin);
#endif
  ASSERT_NE(null_stdin, nullptr);
  std::string output;
  {
    CoutCapture capture;
    auto second = run_relay_init(options);
    ASSERT_TRUE(second) << second.error_if()->safe_detail();
    output = capture.str();
  }
  EXPECT_NE(output.find("using existing"), std::string::npos);
  EXPECT_NE(output.find("already provisioned"), std::string::npos);

  EXPECT_EQ(file_contents(options.config_file), config_before);
  EXPECT_EQ(file_contents(directory.path() / "certs" / "relay.crt"), certificate_before);
  EXPECT_EQ(file_contents(directory.path() / "certs" / "relay.key"), key_before);
  EXPECT_EQ(file_contents(directory.path() / "heyaki-turn.env"), turn_before);

  auto reopened = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(reopened) << reopened.error_if()->safe_detail();
  auto verifier_after = reopened.value_if()->enrollment_password_verifier();
  ASSERT_TRUE(verifier_after) << verifier_after.error_if()->safe_detail();
  ASSERT_TRUE(verifier_after.value_if()->has_value());
  EXPECT_EQ((*verifier_after.value_if())->encoded, verifier_encoded_before);
}

TEST(RelayInitTest, RunInitFailsWithoutAnyPasswordSourceOnFreshDatabase) {
  TemporaryDirectory directory{"relay-init-no-password"};
  auto options = init_options(directory.path());
  options.password_file.reset();

  const char* saved_environment = std::getenv("HEYAKI_INIT_PASSWORD");
  const bool had_environment = saved_environment != nullptr;
  const std::string saved_value = had_environment ? saved_environment : "";
#if defined(_WIN32)
  _putenv_s("HEYAKI_INIT_PASSWORD", "");
#else
  unsetenv("HEYAKI_INIT_PASSWORD");
#endif

#if defined(_WIN32)
  std::FILE* null_stdin = std::freopen("NUL", "r", stdin);
#else
  std::FILE* null_stdin = std::freopen("/dev/null", "r", stdin);
#endif
  ASSERT_NE(null_stdin, nullptr);

  std::string failure_detail;
  {
    CoutCapture capture;
    auto initialized = run_relay_init(options);
    ASSERT_FALSE(initialized);
    failure_detail = initialized.error_if()->safe_detail();
    EXPECT_FALSE(failure_detail.empty());
  }

  // Restore the caller's environment.
#if defined(_WIN32)
  if (had_environment) {
    _putenv_s("HEYAKI_INIT_PASSWORD", saved_value.c_str());
  } else {
    _putenv_s("HEYAKI_INIT_PASSWORD", "");
  }
#else
  if (had_environment) {
    setenv("HEYAKI_INIT_PASSWORD", saved_value.c_str(), 1);
  } else {
    unsetenv("HEYAKI_INIT_PASSWORD");
  }
#endif

  // The config and certificate may exist, but no verifier may have been
  // provisioned without a password.
  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  auto verifier = database.value_if()->enrollment_password_verifier();
  ASSERT_TRUE(verifier) << verifier.error_if()->safe_detail();
  EXPECT_EQ(*verifier.value_if(), std::nullopt);
}

// ---------------------------------------------------------------------------
// End-to-end admission contract of the --init-provisioned verifier.
// ---------------------------------------------------------------------------

// Issue #22 acceptance: against the database --init provisioned, a device
// holding only the URL and the owner password derives the relay-bound proof,
// and the password-mode enrollment service admits it. The service's relay id
// is the leaf certificate digest — exactly what --init derived against.
TEST(RelayInitTest, InitProvisionedVerifierAdmitsDerivedProofEnrollment) {
  TemporaryDirectory directory{"relay-init-verifier-contract"};
  auto options = init_options(directory.path());
  write_password_file(*options.password_file, std::string{owner_password} + "\n");
  {
    CoutCapture capture;
    ASSERT_TRUE(run_relay_init(options)) << "init must succeed";
  }

  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  auto stored = database.value_if()->enrollment_password_verifier();
  ASSERT_TRUE(stored) << stored.error_if()->safe_detail();
  ASSERT_TRUE(stored.value_if()->has_value());
  PasswordVerifier verifier = to_verifier(**stored.value_if());

  // The provisioned verifier accepts the hex of the relay-bound proof.
  const RelayId relay_id =
      *certificate_digest(directory.path() / "certs" / "relay.crt").value_if();
  auto proof = derive_enrollment_password_proof(owner_password, relay_id);
  ASSERT_TRUE(proof) << proof.error_if()->safe_detail();
  auto proof_matches = verify_password(hex_encode(*proof.value_if()), verifier);
  ASSERT_TRUE(proof_matches) << proof_matches.error_if()->safe_detail();
  EXPECT_TRUE(*proof_matches.value_if());
  // The plaintext password itself is never a verifier input (the relay never
  // stores or hashes the owner password).
  auto password_matches = verify_password(owner_password, verifier);
  ASSERT_TRUE(password_matches) << password_matches.error_if()->safe_detail();
  EXPECT_FALSE(*password_matches.value_if());

  // Service-level acceptance: full begin/derive/complete flow with the
  // certificate digest as the relay id.
  RelayEnrollmentServiceConfig config;
  config.mode = RelayEnrollmentMode::password;
  auto service = RelayEnrollmentService::create(database.value_if(), relay_id, config);
  ASSERT_TRUE(service) << service.error_if()->safe_detail();
  const auto now = now_milliseconds();
  auto challenge_bytes = service.value_if()->begin_challenge(now);
  ASSERT_TRUE(challenge_bytes) << challenge_bytes.error_if()->safe_detail();
  auto service_challenge = parse_enrollment_challenge(*challenge_bytes.value_if());
  ASSERT_TRUE(service_challenge) << service_challenge.error_if()->safe_detail();
  auto service_proof = derive_enrollment_password_proof(owner_password, relay_id);
  ASSERT_TRUE(service_proof) << service_proof.error_if()->safe_detail();
  EXPECT_EQ(*service_proof.value_if(), *proof.value_if());

  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  EnrollmentRequest request;
  request.device_id = identity.value_if()->device_id();
  EndpointId::Storage endpoint{};
  endpoint[0] = std::byte{0x61U};
  request.endpoint_id = EndpointId{endpoint};
  request.identity_public_key = identity.value_if()->public_key();
  request.challenge_nonce = service_challenge.value_if()->nonce;
  request.tenant = "default";
  request.password_proof = *service_proof.value_if();
  request.protocol_version = current_protocol_version;
  request.supported.bits = known_capability_bits;
  request.required.bits = static_cast<std::uint64_t>(Capability::enrollment);
  request.expires_unix_milliseconds = now + 30U * 1000U;
  auto signed_result =
      sign_enrollment_request(request, relay_id, *identity.value_if());
  ASSERT_TRUE(signed_result) << signed_result.error_if()->safe_detail();
  auto encoded = encode_enrollment_request(request);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();

  auto completed = service.value_if()->complete(*encoded.value_if(), now + 1U);
  ASSERT_TRUE(completed) << completed.error_if()->safe_detail();
  EXPECT_EQ(completed.value_if()->enrollment_generation, 1U);
  EXPECT_EQ(completed.value_if()->tenant, "default");
  EXPECT_EQ(completed.value_if()->token_remaining_uses_after, std::nullopt);
  EXPECT_EQ(database.value_if()->snapshot().device_count, 1U);
}

// The owner password must satisfy the shared password policy before any
// verifier is provisioned.
TEST(RelayInitTest, RunInitRejectsWeakPasswordBeforeProvisioning) {
  TemporaryDirectory directory{"relay-init-weak-password"};
  auto options = init_options(directory.path());
  write_password_file(*options.password_file, "short\n");

  CoutCapture capture;
  auto initialized = run_relay_init(options);
  ASSERT_FALSE(initialized);
  EXPECT_EQ(initialized.error_if()->safe_detail(), "password_too_short");

  auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  auto verifier = database.value_if()->enrollment_password_verifier();
  ASSERT_TRUE(verifier) << verifier.error_if()->safe_detail();
  EXPECT_EQ(*verifier.value_if(), std::nullopt);
}

}  // namespace
}  // namespace heyaki
