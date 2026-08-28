#include "relay_server.hpp"
#include "relay_database.hpp"
#include "relay_enrollment.hpp"
#include "relay_endpoint.hpp"
#include "relay_login.hpp"
#include "relay_wss_client.hpp"

#include <heyaki/identity.hpp>
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/relay_enrollment_client.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/relay_wss_control.hpp>

#include <gtest/gtest.h>

#include "m5_support.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <string_view>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace heyaki {
namespace {

using namespace std::chrono_literals;

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

bool write_test_certificate(const std::filesystem::path& directory) {
  const auto certificate_path = directory / "test-only-cert.pem";
  const auto key_path = directory / "test-only-key.pem";
  EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1");
  if (key == nullptr) {
    return false;
  }
  X509* certificate = X509_new();
  if (certificate == nullptr) {
    EVP_PKEY_free(key);
    return false;
  }
  std::array<unsigned char, 8U> serial_bytes{};
  std::uint64_t serial = 1U;
  if (RAND_bytes(serial_bytes.data(), static_cast<int>(serial_bytes.size())) == 1) {
    std::memcpy(&serial, serial_bytes.data(), serial_bytes.size());
    serial &= (std::numeric_limits<std::uint64_t>::max)() >> 1U;
    serial = std::max<std::uint64_t>(serial, 1U);
  }
  bool configured =
      X509_set_version(certificate, 2L) == 1 &&
      ASN1_INTEGER_set_uint64(X509_get_serialNumber(certificate), serial) == 1 &&
      X509_gmtime_adj(X509_getm_notBefore(certificate), -60L) != nullptr &&
      X509_gmtime_adj(X509_getm_notAfter(certificate), 24L * 60L * 60L) != nullptr &&
      X509_set_pubkey(certificate, key) == 1;
  X509_NAME* name = X509_get_subject_name(certificate);
  configured = configured && name != nullptr &&
               X509_NAME_add_entry_by_txt(
                   name, "CN", MBSTRING_ASC,
                   reinterpret_cast<const unsigned char*>("127.0.0.1"), -1, -1, 0) == 1 &&
               X509_set_issuer_name(certificate, name) == 1;
  configured = configured && X509_sign(certificate, key, EVP_sha256()) > 0;
  BIO* certificate_output = BIO_new_file(certificate_path.string().c_str(), "wb");
  BIO* key_output = BIO_new_file(key_path.string().c_str(), "wb");
  configured = configured && certificate_output != nullptr && key_output != nullptr &&
               PEM_write_bio_X509(certificate_output, certificate) == 1 &&
               PEM_write_bio_PrivateKey(key_output, key, nullptr, nullptr, 0, nullptr, nullptr) == 1;
  if (certificate_output != nullptr) {
    BIO_free(certificate_output);
  }
  if (key_output != nullptr) {
    BIO_free(key_output);
  }
  X509_free(certificate);
  EVP_PKEY_free(key);
  return configured;
}

std::optional<RelayTlsPin> certificate_pin(const std::filesystem::path& path) {
  BIO* input = BIO_new_file(path.string().c_str(), "rb");
  if (input == nullptr) {
    return std::nullopt;
  }
  X509* certificate = PEM_read_bio_X509(input, nullptr, nullptr, nullptr);
  BIO_free(input);
  if (certificate == nullptr) {
    return std::nullopt;
  }
  RelayTlsPin pin{};
  unsigned int size = 0U;
  const bool ok = X509_digest(certificate, EVP_sha256(),
                              reinterpret_cast<unsigned char*>(pin.data()), &size) == 1 &&
                  size == pin.size();
  X509_free(certificate);
  return ok ? std::optional<RelayTlsPin>{pin} : std::nullopt;
}

RelayServerConfig server_config(const std::filesystem::path& root) {
  RelayServerConfig config;
  config.listen_address = "127.0.0.1";
  config.listen_port = 0U;
  config.tls_certificate_file = root / "test-only-cert.pem";
  config.tls_private_key_file = root / "test-only-key.pem";
  config.database_file = root / "relay.sqlite";
  config.health_path = "/health";
  config.install_signal_handlers = false;
  config.runtime.worker_name = "heyaki-m3b-wss-client-test";
  return config;
}

bool wait_until(const std::function<bool()>& predicate, std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    std::this_thread::yield();
  }
  return predicate();
}

std::uint64_t now_milliseconds() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
}

Result<RelayWssControlFrame> receive_control(RelayWssClient& client) {
  auto received = client.receive(3s);
  if (!received) {
    return Result<RelayWssControlFrame>::failure(*received.error_if());
  }
  if (received.value_if()->text) {
    return Result<RelayWssControlFrame>::failure(
        Error{ErrorCode::protocol, "test", "control_response_not_binary"});
  }
  return parse_relay_wss_control_frame(received.value_if()->payload);
}

Result<void> send_control(RelayWssClient& client, RelayWssControlType type,
                          std::span<const std::byte> payload = {}) {
  auto frame = encode_relay_wss_control_frame(type, payload);
  if (!frame) {
    return Result<void>::failure(*frame.error_if());
  }
  return client.send(*frame.value_if());
}

Result<EnrollmentRequest> make_enrollment_request(
    const IdentityKeyPair& identity, const EnrollmentChallenge& challenge,
    std::string_view token, std::string_view tenant = "tenant-a",
    bool tamper_signature = false) {
  EnrollmentRequest request;
  request.device_id = identity.device_id();
  EndpointId::Storage endpoint_bytes{};
  endpoint_bytes[0U] = std::byte{0x42U};
  request.endpoint_id = EndpointId{endpoint_bytes};
  request.identity_public_key = identity.public_key();
  request.challenge_nonce = challenge.nonce;
  request.tenant = std::string{tenant};
  request.bootstrap_token = std::string{token};
  request.protocol_version = current_protocol_version;
  request.supported.bits = known_capability_bits;
  request.required.bits = static_cast<std::uint64_t>(Capability::enrollment);
  request.expires_unix_milliseconds = challenge.expires_unix_milliseconds - 1U;
  auto signed_request = sign_enrollment_request(request, challenge.relay_id, identity);
  if (!signed_request) {
    return Result<EnrollmentRequest>::failure(*signed_request.error_if());
  }
  if (tamper_signature) {
    request.signature[0U] ^= std::byte{0x01U};
  }
  return Result<EnrollmentRequest>::success(std::move(request));
}

Result<RelayLoginRequest> make_login_request(
    const IdentityKeyPair& identity, const EnrollmentChallenge& challenge,
    std::uint64_t generation, std::uint64_t now, std::uint8_t endpoint_byte,
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
  if (!signature) {
    return Result<RelayLoginRequest>::failure(*signature.error_if());
  }
  return Result<RelayLoginRequest>::success(std::move(request));
}

Result<RelayEndpointRecord> make_endpoint_record(
    const IdentityKeyPair& identity, std::uint8_t endpoint_byte,
    std::uint64_t now, std::uint64_t generation = 1U) {
  RelayEndpointRecord record;
  EndpointId::Storage endpoint{};
  endpoint[0] = static_cast<std::byte>(endpoint_byte);
  record.endpoint = RelayEndpointKey{.device_id = identity.device_id(),
                                     .endpoint_id = EndpointId{endpoint}};
  record.application_id = "com.example.device";
  record.record_generation = generation;
  record.manifest_sha256[0] = std::byte{0x5aU};
  record.expires_unix_milliseconds = now + 60U * 1000U;
  auto signature = sign_relay_endpoint_record(record, identity);
  if (!signature) {
    return Result<RelayEndpointRecord>::failure(*signature.error_if());
  }
  return Result<RelayEndpointRecord>::success(std::move(record));
}

Result<RelayWssClient> connect_control_client(const std::filesystem::path& root,
                                              std::uint16_t port) {
  auto pin = certificate_pin(root / "test-only-cert.pem");
  if (!pin) {
    return Result<RelayWssClient>::failure(
        Error{ErrorCode::internal, "test", "certificate_pin_failed"});
  }
  RelayWssClientConfig config;
  config.url = "wss://127.0.0.1:" + std::to_string(port) +
               std::string{relay_wss_control_path};
  config.relay_pin = pin;
  config.tls_verify_peer = false;
  config.runtime.worker_name = "heyaki-m3b-wss-control-client";
  auto client = RelayWssClient::create(std::move(config));
  if (!client) {
    return client;
  }
  auto connected = client.value_if()->connect(3s);
  if (!connected) {
    return Result<RelayWssClient>::failure(*connected.error_if());
  }
  return client;
}

TEST(M3BRelayWssClientTest, ConnectsWithTlsPinAndReceivesHealth) {
  TemporaryDirectory directory{"m3b-wss-client"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  const auto port = server.value_if()->snapshot().listen_port;

  auto pin = certificate_pin(directory.path() / "test-only-cert.pem");
  ASSERT_TRUE(pin);
  RelayWssClientConfig config;
  config.url = "wss://127.0.0.1:" + std::to_string(port) + "/health";
  config.relay_pin = pin;
  config.tls_verify_peer = false;
  config.runtime.worker_name = "heyaki-m3b-wss-client";
  auto client = RelayWssClient::create(std::move(config));
  ASSERT_TRUE(client) << client.error_if()->safe_detail();

  auto connected = client.value_if()->connect(3s);
  ASSERT_TRUE(connected) << connected.error_if()->safe_detail();
  EXPECT_EQ(client.value_if()->snapshot().state, RelayWssState::ready);

  auto message = client.value_if()->receive(3s);
  ASSERT_TRUE(message) << message.error_if()->safe_detail();
  EXPECT_EQ(message.value_if()->text, true);
  const std::string text(reinterpret_cast<const char*>(message.value_if()->payload.data()),
                         message.value_if()->payload.size());
  EXPECT_EQ(text, "ok\n");

  auto closed = client.value_if()->close(3s);
  ASSERT_TRUE(closed) << closed.error_if()->safe_detail();
  EXPECT_EQ(client.value_if()->snapshot().state, RelayWssState::disconnected);
  (void)server.value_if()->shutdown();
}

TEST(M3BRelayWssClientTest, WrongPinFailsAuthentication) {
  TemporaryDirectory directory{"m3b-wss-client-pin"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  const auto port = server.value_if()->snapshot().listen_port;

  RelayWssClientConfig config;
  config.url = "wss://127.0.0.1:" + std::to_string(port) + "/health";
  RelayTlsPin wrong_pin{};
  wrong_pin[0] = std::byte{0x7fU};
  config.relay_pin = wrong_pin;
  config.tls_verify_peer = false;
  auto client = RelayWssClient::create(std::move(config));
  ASSERT_TRUE(client) << client.error_if()->safe_detail();
  auto connected = client.value_if()->connect(3s);
  ASSERT_FALSE(connected);
  EXPECT_EQ(connected.error_if()->safe_detail(), "wss_tls_pin_mismatch");
  EXPECT_EQ(client.value_if()->snapshot().state, RelayWssState::failed);
  (void)server.value_if()->shutdown();
}

TEST(M3BRelayWssClientTest, VerifyPeerWithoutTrustedCaFails) {
  TemporaryDirectory directory{"m3b-wss-client-ca"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  const auto port = server.value_if()->snapshot().listen_port;

  RelayWssClientConfig config;
  config.url = "wss://127.0.0.1:" + std::to_string(port) + "/health";
  config.tls_verify_peer = true;
  const auto other_ca_directory = directory.path() / "other-ca";
  std::error_code error;
  std::filesystem::create_directories(other_ca_directory, error);
  ASSERT_FALSE(error);
  ASSERT_TRUE(write_test_certificate(other_ca_directory));
  config.tls_ca_file = other_ca_directory / "test-only-cert.pem";
  auto client = RelayWssClient::create(std::move(config));
  ASSERT_TRUE(client) << client.error_if()->safe_detail();
  auto connected = client.value_if()->connect(3s);
  ASSERT_FALSE(connected);
  EXPECT_EQ(connected.error_if()->code(), ErrorCode::authentication);
  (void)server.value_if()->shutdown();
}

TEST(M3BRelayWssClientTest, RejectsInvalidUrlsAndPayloads) {
  RelayWssClientConfig config;
  config.url = "http://127.0.0.1/health";
  EXPECT_FALSE(RelayWssClient::create(config));
  config.url = "wss://";
  EXPECT_FALSE(RelayWssClient::create(config));
  config.url = "wss://127.0.0.1:notaport/health";
  EXPECT_FALSE(RelayWssClient::create(config));

  TemporaryDirectory directory{"m3b-wss-client-invalid"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  config.url = "wss://127.0.0.1:" +
               std::to_string(server.value_if()->snapshot().listen_port) + "/health";
  config.tls_verify_peer = false;
  auto client = RelayWssClient::create(config);
  ASSERT_TRUE(client) << client.error_if()->safe_detail();
  EXPECT_FALSE(client.value_if()->send(std::vector<std::byte>{}));
  const std::vector<std::byte> large(70000U);
  EXPECT_FALSE(client.value_if()->send(large));
  (void)server.value_if()->shutdown();
}

TEST(M3BRelayWssClientTest, EnrollsThroughBinaryControlPath) {
  TemporaryDirectory directory{"m3b-wss-control-enrollment"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  const std::string token = "TEST-ONLY-wss-enrollment-token-0123456789";
  const std::string tenant = "\xe7\xa7\x9f\xe6\x88\xb7-a";
  const auto now = now_milliseconds();
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    auto created = database.value_if()->create_bootstrap_token(
        tenant, token, now + 60U * 1000U, 1U);
    ASSERT_TRUE(created) << created.error_if()->safe_detail();
  }

  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  auto client = connect_control_client(
      directory.path(), server.value_if()->snapshot().listen_port);
  ASSERT_TRUE(client) << client.error_if()->safe_detail();

  auto challenge_request = send_control(
      *client.value_if(), RelayWssControlType::enrollment_challenge);
  ASSERT_TRUE(challenge_request) << challenge_request.error_if()->safe_detail();
  auto challenge_frame = receive_control(*client.value_if());
  ASSERT_TRUE(challenge_frame) << challenge_frame.error_if()->safe_detail();
  ASSERT_EQ(challenge_frame.value_if()->type,
            RelayWssControlType::enrollment_challenge_response);
  auto challenge = parse_enrollment_challenge(challenge_frame.value_if()->payload);
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();
  const auto pin = certificate_pin(directory.path() / "test-only-cert.pem");
  ASSERT_TRUE(pin);
  EXPECT_EQ(challenge.value_if()->relay_id, *pin);

  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  auto request = make_enrollment_request(
      *identity.value_if(), *challenge.value_if(), token, tenant);
  ASSERT_TRUE(request) << request.error_if()->safe_detail();
  auto request_bytes = encode_enrollment_request(*request.value_if());
  ASSERT_TRUE(request_bytes) << request_bytes.error_if()->safe_detail();
  auto sent = send_control(*client.value_if(),
                           RelayWssControlType::enrollment_request,
                           *request_bytes.value_if());
  ASSERT_TRUE(sent) << sent.error_if()->safe_detail();

  auto result_frame = receive_control(*client.value_if());
  ASSERT_TRUE(result_frame) << result_frame.error_if()->safe_detail();
  ASSERT_EQ(result_frame.value_if()->type,
            RelayWssControlType::enrollment_result);
  auto result = parse_relay_wss_enrollment_result(result_frame.value_if()->payload);
  ASSERT_TRUE(result) << result.error_if()->safe_detail();
  EXPECT_EQ(result.value_if()->tenant, tenant);
  EXPECT_EQ(result.value_if()->enrollment_generation, 1U);
  EXPECT_EQ(result.value_if()->token_remaining_uses_after, 0U);

  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = server.value_if()->snapshot();
        return snapshot.enrollments_completed == 1U &&
               snapshot.database.device_count == 1U &&
               snapshot.database.device_audit_count == 2U;
      },
      2s));
  const auto snapshot = server.value_if()->snapshot();
  EXPECT_EQ(snapshot.control_sessions, 1U);
  EXPECT_EQ(snapshot.enrollment_challenges, 1U);
  EXPECT_EQ(snapshot.control_rejected, 0U);
  EXPECT_EQ(snapshot.rate_limits.connection.allowed, 2U);
  EXPECT_EQ(snapshot.rate_limits.request.allowed, 2U);
  EXPECT_EQ(snapshot.rate_limits.tenant.allowed, 1U);
  EXPECT_EQ(snapshot.rate_limits.ip.allowed, 2U);

  EXPECT_TRUE(client.value_if()->close(3s));
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST(M3BRelayWssClientTest, RejectsTamperedEnrollmentOverControlPath) {
  TemporaryDirectory directory{"m3b-wss-control-reject"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  const std::string token = "TEST-ONLY-wss-reject-token-0123456789";
  const auto now = now_milliseconds();
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    ASSERT_TRUE(database.value_if()->create_bootstrap_token(
        "tenant-a", token, now + 60U * 1000U, 1U));
  }
  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  auto client = connect_control_client(
      directory.path(), server.value_if()->snapshot().listen_port);
  ASSERT_TRUE(client) << client.error_if()->safe_detail();

  ASSERT_TRUE(send_control(*client.value_if(),
                           RelayWssControlType::enrollment_challenge));
  auto challenge_frame = receive_control(*client.value_if());
  ASSERT_TRUE(challenge_frame) << challenge_frame.error_if()->safe_detail();
  auto challenge = parse_enrollment_challenge(challenge_frame.value_if()->payload);
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  auto request = make_enrollment_request(
      *identity.value_if(), *challenge.value_if(), token, "tenant-a", true);
  ASSERT_TRUE(request) << request.error_if()->safe_detail();
  auto request_bytes = encode_enrollment_request(*request.value_if());
  ASSERT_TRUE(request_bytes) << request_bytes.error_if()->safe_detail();
  ASSERT_TRUE(send_control(*client.value_if(),
                           RelayWssControlType::enrollment_request,
                           *request_bytes.value_if()));

  auto error_frame = receive_control(*client.value_if());
  ASSERT_TRUE(error_frame) << error_frame.error_if()->safe_detail();
  ASSERT_EQ(error_frame.value_if()->type, RelayWssControlType::control_error);
  auto remote_error = parse_relay_wss_control_error(error_frame.value_if()->payload);
  ASSERT_TRUE(remote_error) << remote_error.error_if()->safe_detail();
  EXPECT_EQ(remote_error.value_if()->code, ErrorCode::authentication);
  EXPECT_EQ(remote_error.value_if()->safe_detail,
            "signature_verification_failed");
  ASSERT_TRUE(wait_until(
      [&] {
        return server.value_if()->snapshot().control_rejected == 1U &&
               client.value_if()->snapshot().state == RelayWssState::disconnected;
      },
      2s));
  EXPECT_EQ(server.value_if()->snapshot().database.device_count, 0U);
  EXPECT_EQ(server.value_if()->snapshot().database.device_audit_count, 0U);

  EXPECT_TRUE(client.value_if()->close(3s));
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST(M3BRelayWssClientTest, ChargesEveryBaseRateLimitBeforeRejecting) {
  TemporaryDirectory directory{"m3b-wss-control-rate-limit"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  auto config = server_config(directory.path());
  config.rate_limits.connection.capacity = 1U;
  config.rate_limits.connection.window = 60s;
  auto server = RelayServer::create(std::move(config));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  auto client = connect_control_client(
      directory.path(), server.value_if()->snapshot().listen_port);
  ASSERT_TRUE(client) << client.error_if()->safe_detail();

  ASSERT_TRUE(send_control(*client.value_if(),
                           RelayWssControlType::enrollment_challenge));
  auto challenge = receive_control(*client.value_if());
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();
  ASSERT_TRUE(send_control(*client.value_if(),
                           RelayWssControlType::enrollment_challenge));
  auto rejected = receive_control(*client.value_if());
  ASSERT_TRUE(rejected) << rejected.error_if()->safe_detail();
  ASSERT_EQ(rejected.value_if()->type, RelayWssControlType::control_error);
  auto remote_error = parse_relay_wss_control_error(rejected.value_if()->payload);
  ASSERT_TRUE(remote_error) << remote_error.error_if()->safe_detail();
  EXPECT_EQ(remote_error.value_if()->code, ErrorCode::resource_exhausted);

  ASSERT_TRUE(wait_until(
      [&] {
        return client.value_if()->snapshot().state ==
               RelayWssState::disconnected;
      },
      2s));
  const auto limits = server.value_if()->snapshot().rate_limits;
  EXPECT_EQ(limits.connection.allowed, 1U);
  EXPECT_EQ(limits.connection.rejected, 1U);
  EXPECT_EQ(limits.request.allowed, 2U);
  EXPECT_EQ(limits.ip.allowed, 2U);

  EXPECT_TRUE(client.value_if()->close(3s));
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST(M3BRelayWssClientTest, BindsEnrollmentChallengeToControlSession) {
  TemporaryDirectory directory{"m3b-wss-control-session-binding"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  const std::string token = "TEST-ONLY-wss-session-token-0123456789";
  const auto now = now_milliseconds();
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    ASSERT_TRUE(database.value_if()->create_bootstrap_token(
        "tenant-a", token, now + 60U * 1000U, 1U));
  }
  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  const auto port = server.value_if()->snapshot().listen_port;
  auto first_client = connect_control_client(directory.path(), port);
  auto second_client = connect_control_client(directory.path(), port);
  ASSERT_TRUE(first_client) << first_client.error_if()->safe_detail();
  ASSERT_TRUE(second_client) << second_client.error_if()->safe_detail();

  ASSERT_TRUE(send_control(*first_client.value_if(),
                           RelayWssControlType::enrollment_challenge));
  ASSERT_TRUE(receive_control(*first_client.value_if()));
  ASSERT_TRUE(send_control(*second_client.value_if(),
                           RelayWssControlType::enrollment_challenge));
  auto second_challenge_frame = receive_control(*second_client.value_if());
  ASSERT_TRUE(second_challenge_frame)
      << second_challenge_frame.error_if()->safe_detail();
  auto second_challenge =
      parse_enrollment_challenge(second_challenge_frame.value_if()->payload);
  ASSERT_TRUE(second_challenge) << second_challenge.error_if()->safe_detail();
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  auto request = make_enrollment_request(
      *identity.value_if(), *second_challenge.value_if(), token, "tenant-a");
  ASSERT_TRUE(request) << request.error_if()->safe_detail();
  auto request_bytes = encode_enrollment_request(*request.value_if());
  ASSERT_TRUE(request_bytes) << request_bytes.error_if()->safe_detail();

  ASSERT_TRUE(send_control(*first_client.value_if(),
                           RelayWssControlType::enrollment_request,
                           *request_bytes.value_if()));
  auto rejected = receive_control(*first_client.value_if());
  ASSERT_TRUE(rejected) << rejected.error_if()->safe_detail();
  ASSERT_EQ(rejected.value_if()->type, RelayWssControlType::control_error);
  auto remote_error = parse_relay_wss_control_error(rejected.value_if()->payload);
  ASSERT_TRUE(remote_error) << remote_error.error_if()->safe_detail();
  EXPECT_EQ(remote_error.value_if()->code, ErrorCode::authentication);
  EXPECT_EQ(remote_error.value_if()->safe_detail,
            "enrollment_challenge_session_mismatch");

  ASSERT_TRUE(send_control(*second_client.value_if(),
                           RelayWssControlType::enrollment_request,
                           *request_bytes.value_if()));
  auto completed = receive_control(*second_client.value_if());
  ASSERT_TRUE(completed) << completed.error_if()->safe_detail();
  ASSERT_EQ(completed.value_if()->type, RelayWssControlType::enrollment_result);
  EXPECT_TRUE(parse_relay_wss_enrollment_result(completed.value_if()->payload));

  EXPECT_TRUE(first_client.value_if()->close(3s));
  EXPECT_TRUE(second_client.value_if()->close(3s));
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST(M3BRelayWssClientTest, LogsInHeartbeatsPublishesAndQueriesEndpoint) {
  TemporaryDirectory directory{"m3b-wss-control-login"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    RelayDeviceRecord device;
    device.device_id = identity.value_if()->device_id();
    device.public_key = identity.value_if()->public_key();
    device.tenant = "tenant-a";
    device.display_name = "device";
    device.enrollment_generation = 1U;
    device.status = RelayDeviceStatus::active;
    ASSERT_TRUE(database.value_if()->enroll_device(device, now));
  }

  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  const auto port = server.value_if()->snapshot().listen_port;
  auto client = connect_control_client(directory.path(), port);
  ASSERT_TRUE(client) << client.error_if()->safe_detail();

  ASSERT_TRUE(send_control(*client.value_if(),
                           RelayWssControlType::login_challenge));
  auto challenge_frame = receive_control(*client.value_if());
  ASSERT_TRUE(challenge_frame) << challenge_frame.error_if()->safe_detail();
  ASSERT_EQ(challenge_frame.value_if()->type,
            RelayWssControlType::login_challenge_response);
  auto challenge = parse_enrollment_challenge(challenge_frame.value_if()->payload);
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();

  auto login = make_login_request(*identity.value_if(), *challenge.value_if(),
                                  1U, now, 0x61U);
  ASSERT_TRUE(login) << login.error_if()->safe_detail();
  auto login_bytes = encode_relay_login_request(*login.value_if());
  ASSERT_TRUE(login_bytes) << login_bytes.error_if()->safe_detail();
  ASSERT_TRUE(send_control(*client.value_if(),
                           RelayWssControlType::login_request,
                           *login_bytes.value_if()));
  auto login_frame = receive_control(*client.value_if());
  ASSERT_TRUE(login_frame) << login_frame.error_if()->safe_detail();
  ASSERT_EQ(login_frame.value_if()->type, RelayWssControlType::login_result);
  auto login_result = parse_relay_wss_login_result(login_frame.value_if()->payload);
  ASSERT_TRUE(login_result) << login_result.error_if()->safe_detail();
  EXPECT_EQ(login_result.value_if()->tenant, "tenant-a");
  EXPECT_EQ(login_result.value_if()->enrollment_generation, 1U);
  EXPECT_GE(login_result.value_if()->lease_milliseconds, 1000U);

  RelayWssHeartbeatRequest heartbeat_request;
  heartbeat_request.lease_milliseconds = 15000U;
  auto heartbeat_bytes =
      encode_relay_wss_heartbeat_request(heartbeat_request);
  ASSERT_TRUE(heartbeat_bytes) << heartbeat_bytes.error_if()->safe_detail();
  ASSERT_TRUE(send_control(*client.value_if(),
                           RelayWssControlType::heartbeat,
                           *heartbeat_bytes.value_if()));
  auto heartbeat_frame = receive_control(*client.value_if());
  ASSERT_TRUE(heartbeat_frame) << heartbeat_frame.error_if()->safe_detail();
  ASSERT_EQ(heartbeat_frame.value_if()->type, RelayWssControlType::heartbeat_ack);
  auto heartbeat_ack =
      parse_relay_wss_heartbeat_ack(heartbeat_frame.value_if()->payload);
  ASSERT_TRUE(heartbeat_ack) << heartbeat_ack.error_if()->safe_detail();
  EXPECT_NE(heartbeat_ack.value_if()->lease_generation, 0U);
  EXPECT_GE(heartbeat_ack.value_if()->granted_lease_milliseconds, 15000U);

  auto record = make_endpoint_record(*identity.value_if(), 0x61U, now);
  ASSERT_TRUE(record) << record.error_if()->safe_detail();
  auto record_bytes = encode_relay_endpoint_record(*record.value_if());
  ASSERT_TRUE(record_bytes) << record_bytes.error_if()->safe_detail();
  RelayWssEndpointPublish publish;
  publish.endpoint_record = std::move(*record_bytes.value_if());
  auto publish_bytes = encode_relay_wss_endpoint_publish(publish);
  ASSERT_TRUE(publish_bytes) << publish_bytes.error_if()->safe_detail();
  ASSERT_TRUE(send_control(*client.value_if(),
                           RelayWssControlType::endpoint_publish,
                           *publish_bytes.value_if()));
  auto publish_frame = receive_control(*client.value_if());
  ASSERT_TRUE(publish_frame) << publish_frame.error_if()->safe_detail();
  ASSERT_EQ(publish_frame.value_if()->type,
            RelayWssControlType::endpoint_publish_ack);
  auto publish_ack =
      parse_relay_wss_endpoint_publish_ack(publish_frame.value_if()->payload);
  ASSERT_TRUE(publish_ack) << publish_ack.error_if()->safe_detail();
  EXPECT_EQ(publish_ack.value_if()->record_generation, 1U);

  RelayWssEndpointQuery query;
  auto query_bytes = encode_relay_wss_endpoint_query(query);
  ASSERT_TRUE(query_bytes) << query_bytes.error_if()->safe_detail();
  ASSERT_TRUE(send_control(*client.value_if(),
                           RelayWssControlType::endpoint_query,
                           *query_bytes.value_if()));
  auto query_frame = receive_control(*client.value_if());
  ASSERT_TRUE(query_frame) << query_frame.error_if()->safe_detail();
  ASSERT_EQ(query_frame.value_if()->type,
            RelayWssControlType::endpoint_query_result);
  auto query_result =
      parse_relay_wss_endpoint_query_result(query_frame.value_if()->payload);
  ASSERT_TRUE(query_result) << query_result.error_if()->safe_detail();
  ASSERT_EQ(query_result.value_if()->endpoints.size(), 1U);
  const auto& published = query_result.value_if()->endpoints[0U];
  EXPECT_EQ(published.device_id, identity.value_if()->device_id());
  EXPECT_EQ(published.endpoint_id, record.value_if()->endpoint.endpoint_id);
  EXPECT_FALSE(published.application_id) << "default exposure policy is minimal";
  EXPECT_FALSE(published.record_generation);
  EXPECT_TRUE(published.expires_unix_milliseconds);
  EXPECT_TRUE(published.lease_expires_unix_milliseconds);
  ASSERT_TRUE(published.endpoint_record);
  ASSERT_TRUE(published.identity_public_key);
  auto published_record = parse_relay_endpoint_record(*published.endpoint_record);
  ASSERT_TRUE(published_record) << published_record.error_if()->safe_detail();
  RelayDeviceRecord published_device;
  published_device.device_id = published.device_id;
  published_device.public_key = *published.identity_public_key;
  published_device.tenant = "tenant-a";
  published_device.display_name = "device";
  published_device.status = RelayDeviceStatus::active;
  EXPECT_TRUE(validate_relay_endpoint_record(*published_record.value_if(),
                                             published_device, now_milliseconds()));

  const auto snapshot = server.value_if()->snapshot();
  EXPECT_GE(snapshot.login_challenges, 1U);
  EXPECT_GE(snapshot.logins_completed, 1U);
  EXPECT_GE(snapshot.heartbeats, 1U);
  EXPECT_GE(snapshot.endpoint_publications, 1U);
  EXPECT_GE(snapshot.endpoint_queries, 1U);
  EXPECT_GE(snapshot.leases.current_entries, 1U);

  ASSERT_TRUE(client.value_if()->close(3s));
  ASSERT_TRUE(wait_until(
      [&] {
        const auto current = server.value_if()->snapshot();
        return current.active_sessions == 0U &&
               current.leases.current_entries == 0U;
      },
      2s));
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST(M3BRelayWssClientTest, RejectsRevokedLoginAndClosesExistingControlSession) {
  TemporaryDirectory directory{"m3b-wss-control-revoked"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    RelayDeviceRecord device;
    device.device_id = identity.value_if()->device_id();
    device.public_key = identity.value_if()->public_key();
    device.tenant = "tenant-a";
    device.display_name = "device";
    device.enrollment_generation = 1U;
    device.status = RelayDeviceStatus::active;
    ASSERT_TRUE(database.value_if()->enroll_device(device, now));
  }
  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  const auto port = server.value_if()->snapshot().listen_port;
  auto client = connect_control_client(directory.path(), port);
  ASSERT_TRUE(client) << client.error_if()->safe_detail();
  ASSERT_TRUE(send_control(*client.value_if(),
                           RelayWssControlType::login_challenge));
  auto challenge_frame = receive_control(*client.value_if());
  ASSERT_TRUE(challenge_frame) << challenge_frame.error_if()->safe_detail();
  auto challenge = parse_enrollment_challenge(challenge_frame.value_if()->payload);
  ASSERT_TRUE(challenge) << challenge.error_if()->safe_detail();
  auto login = make_login_request(*identity.value_if(), *challenge.value_if(),
                                  1U, now, 0x62U);
  ASSERT_TRUE(login) << login.error_if()->safe_detail();
  auto login_bytes = encode_relay_login_request(*login.value_if());
  ASSERT_TRUE(login_bytes) << login_bytes.error_if()->safe_detail();
  ASSERT_TRUE(send_control(*client.value_if(),
                           RelayWssControlType::login_request,
                           *login_bytes.value_if()));
  auto login_frame = receive_control(*client.value_if());
  ASSERT_TRUE(login_frame) << login_frame.error_if()->safe_detail();
  ASSERT_EQ(login_frame.value_if()->type, RelayWssControlType::login_result);
  ASSERT_TRUE(send_control(*client.value_if(),
                           RelayWssControlType::heartbeat));
  auto heartbeat_frame = receive_control(*client.value_if());
  ASSERT_TRUE(heartbeat_frame) << heartbeat_frame.error_if()->safe_detail();
  ASSERT_EQ(heartbeat_frame.value_if()->type, RelayWssControlType::heartbeat_ack);

  {
    auto revoker = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(revoker) << revoker.error_if()->safe_detail();
    ASSERT_TRUE(revoker.value_if()->revoke_device(
        identity.value_if()->device_id(), 2U, now + 60U * 1000U));
  }

  ASSERT_TRUE(send_control(*client.value_if(),
                           RelayWssControlType::heartbeat));
  auto revoked_frame = receive_control(*client.value_if());
  ASSERT_TRUE(revoked_frame) << revoked_frame.error_if()->safe_detail();
  ASSERT_EQ(revoked_frame.value_if()->type, RelayWssControlType::control_error);
  auto revoked_error =
      parse_relay_wss_control_error(revoked_frame.value_if()->payload);
  ASSERT_TRUE(revoked_error) << revoked_error.error_if()->safe_detail();
  EXPECT_EQ(revoked_error.value_if()->code, ErrorCode::enrollment_revoked);

  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().active_sessions == 0U; }, 2s));
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST(M3BRelayWssClientTest, SameDeviceMultipleEndpointsShareTenantDirectory) {
  TemporaryDirectory directory{"m3b-wss-control-multi-endpoint"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto now = now_milliseconds();
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    RelayDeviceRecord device;
    device.device_id = identity.value_if()->device_id();
    device.public_key = identity.value_if()->public_key();
    device.tenant = "tenant-a";
    device.display_name = "device";
    device.enrollment_generation = 1U;
    device.status = RelayDeviceStatus::active;
    ASSERT_TRUE(database.value_if()->enroll_device(device, now));
  }
  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  const auto port = server.value_if()->snapshot().listen_port;
  auto first = connect_control_client(directory.path(), port);
  auto second = connect_control_client(directory.path(), port);
  ASSERT_TRUE(first) << first.error_if()->safe_detail();
  ASSERT_TRUE(second) << second.error_if()->safe_detail();

  const auto login_endpoint = [&](RelayWssClient& client,
                                  std::uint8_t endpoint_byte) {
    EXPECT_TRUE(send_control(client, RelayWssControlType::login_challenge));
    auto challenge_frame = receive_control(client);
    EXPECT_TRUE(challenge_frame);
    if (!challenge_frame) {
      return Result<RelayWssLoginResult>::failure(*challenge_frame.error_if());
    }
    auto challenge = parse_enrollment_challenge(challenge_frame.value_if()->payload);
    if (!challenge) {
      return Result<RelayWssLoginResult>::failure(*challenge.error_if());
    }
    auto login = make_login_request(*identity.value_if(), *challenge.value_if(),
                                    1U, now, endpoint_byte);
    if (!login) {
      return Result<RelayWssLoginResult>::failure(*login.error_if());
    }
    auto login_bytes = encode_relay_login_request(*login.value_if());
    if (!login_bytes) {
      return Result<RelayWssLoginResult>::failure(*login_bytes.error_if());
    }
    if (!send_control(client, RelayWssControlType::login_request,
                      *login_bytes.value_if())) {
      return Result<RelayWssLoginResult>::failure(
          Error{ErrorCode::internal, "test", "login_send_failed"});
    }
    auto result_frame = receive_control(client);
    if (!result_frame ||
        result_frame.value_if()->type != RelayWssControlType::login_result) {
      return Result<RelayWssLoginResult>::failure(
          result_frame ? Error{ErrorCode::protocol, "test",
                               "login_result_not_received"}
                       : *result_frame.error_if());
    }
    return parse_relay_wss_login_result(result_frame.value_if()->payload);
  };

  auto first_login = login_endpoint(*first.value_if(), 0x71U);
  auto second_login = login_endpoint(*second.value_if(), 0x72U);
  ASSERT_TRUE(first_login) << first_login.error_if()->safe_detail();
  ASSERT_TRUE(second_login) << second_login.error_if()->safe_detail();
  ASSERT_TRUE(send_control(*first.value_if(), RelayWssControlType::heartbeat));
  ASSERT_EQ(receive_control(*first.value_if()).value_if()->type,
            RelayWssControlType::heartbeat_ack);
  ASSERT_TRUE(send_control(*second.value_if(), RelayWssControlType::heartbeat));
  ASSERT_EQ(receive_control(*second.value_if()).value_if()->type,
            RelayWssControlType::heartbeat_ack);

  auto first_record = make_endpoint_record(*identity.value_if(), 0x71U, now);
  auto second_record = make_endpoint_record(*identity.value_if(), 0x72U, now);
  ASSERT_TRUE(first_record) << first_record.error_if()->safe_detail();
  ASSERT_TRUE(second_record) << second_record.error_if()->safe_detail();
  const auto publish_endpoint = [&](RelayWssClient& client,
                                    const RelayEndpointRecord& record) {
    auto record_bytes = encode_relay_endpoint_record(record);
    EXPECT_TRUE(record_bytes);
    if (!record_bytes) {
      return Result<void>::failure(*record_bytes.error_if());
    }
    RelayWssEndpointPublish publish;
    publish.endpoint_record = std::move(*record_bytes.value_if());
    auto publish_bytes = encode_relay_wss_endpoint_publish(publish);
    if (!publish_bytes) {
      return Result<void>::failure(*publish_bytes.error_if());
    }
    if (!send_control(client, RelayWssControlType::endpoint_publish,
                      *publish_bytes.value_if())) {
      return Result<void>::failure(
          Error{ErrorCode::internal, "test", "publish_send_failed"});
    }
    auto ack = receive_control(client);
    if (!ack ||
        ack.value_if()->type != RelayWssControlType::endpoint_publish_ack) {
      return Result<void>::failure(
          ack ? Error{ErrorCode::protocol, "test",
                      "endpoint_publish_ack_not_received"}
              : *ack.error_if());
    }
    return Result<void>::success();
  };
  ASSERT_TRUE(publish_endpoint(*first.value_if(), *first_record.value_if()));
  ASSERT_TRUE(publish_endpoint(*second.value_if(), *second_record.value_if()));

  ASSERT_TRUE(send_control(*first.value_if(),
                           RelayWssControlType::endpoint_query));
  auto query_frame = receive_control(*first.value_if());
  ASSERT_TRUE(query_frame) << query_frame.error_if()->safe_detail();
  auto all = parse_relay_wss_endpoint_query_result(query_frame.value_if()->payload);
  ASSERT_TRUE(all) << all.error_if()->safe_detail();
  ASSERT_EQ(all.value_if()->endpoints.size(), 2U);

  RelayWssEndpointQuery filtered;
  filtered.device_id = identity.value_if()->device_id();
  filtered.endpoint_id = second_record.value_if()->endpoint.endpoint_id;
  auto filtered_bytes = encode_relay_wss_endpoint_query(filtered);
  ASSERT_TRUE(filtered_bytes) << filtered_bytes.error_if()->safe_detail();
  ASSERT_TRUE(send_control(*first.value_if(),
                           RelayWssControlType::endpoint_query,
                           *filtered_bytes.value_if()));
  auto filtered_frame = receive_control(*first.value_if());
  ASSERT_TRUE(filtered_frame) << filtered_frame.error_if()->safe_detail();
  auto filtered_result =
      parse_relay_wss_endpoint_query_result(filtered_frame.value_if()->payload);
  ASSERT_TRUE(filtered_result) << filtered_result.error_if()->safe_detail();
  ASSERT_EQ(filtered_result.value_if()->endpoints.size(), 1U);
  EXPECT_EQ(filtered_result.value_if()->endpoints[0U].endpoint_id,
            second_record.value_if()->endpoint.endpoint_id);

  ASSERT_TRUE(first.value_if()->close(3s));
  ASSERT_TRUE(second.value_if()->close(3s));
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().leases.current_entries == 0U; },
      2s));
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST(M3BRelayWssClientTest, PersistsRealWssEnrollmentAndRetriesIdempotently) {
  TemporaryDirectory directory{"m3b-wss-control-profile-enrollment"};
#ifndef _WIN32
  ASSERT_EQ(::chmod(directory.path().c_str(), S_IRWXU), 0);
#endif
  ASSERT_TRUE(write_test_certificate(directory.path()));
  const std::string token = "TEST-ONLY-real-profile-enrollment-token-0123456789";
  const auto now = now_milliseconds();
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    ASSERT_TRUE(database.value_if()->create_bootstrap_token(
        "tenant-a", token, now + 60U * 1000U, 1U));
  }
  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  const auto port = server.value_if()->snapshot().listen_port;
  const std::string relay_url =
      "wss://127.0.0.1:" + std::to_string(port);
  auto pin = certificate_pin(directory.path() / "test-only-cert.pem");
  ASSERT_TRUE(pin);
  const std::vector<std::byte> pin_vector(pin->begin(), pin->end());

  ProfileOpenOptions profile_options;
  profile_options.secret_backend.prefer_os_backend = false;
  auto profile =
      ProfileStore::create(directory.path() / "profile.sqlite", profile_options);
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  auto verifier = create_password_verifier("correct horse battery staple", {});
  ASSERT_TRUE(verifier) << verifier.error_if()->safe_detail();
  LocalProfileInitialization initialization;
  initialization.application_id = "com.example.relay-client";
  initialization.password_verifier = std::move(*verifier.value_if());
  initialization.password_generation = 1U;
  initialization.pairing_policy = PairingPolicy{};
  initialization.lan = LanConfiguration{};
  ASSERT_TRUE(profile.value_if()->initialize_local(initialization));

  RelayEnrollmentClientConfig enrollment;
  enrollment.profile = profile.value_if();
  enrollment.application_id = "com.example.relay-client";
  enrollment.relay_url = relay_url;
  enrollment.tenant = "tenant-a";
  enrollment.relay_pin = pin_vector;
  enrollment.auto_connect = true;
  enrollment.wss_transport = RelayEnrollmentWssTransportConfig{
      .relay_url = relay_url,
      .relay_pin = pin_vector,
      .tls_ca_file = std::nullopt,
      .tls_verify_peer = false,
      .connect_timeout = 3s,
      .handshake_timeout = 3s,
      .close_timeout = 2s,
      .runtime = RuntimeConfig{}};

  auto first = enroll_relay_profile(enrollment, token, now);
  ASSERT_TRUE(first) << first.error_if()->safe_detail();
  EXPECT_EQ(first.value_if()->enrollment_generation, 1U);
  auto persisted = profile.value_if()->relay_enrollment(relay_url);
  ASSERT_TRUE(persisted) << persisted.error_if()->safe_detail();
  ASSERT_TRUE(persisted.value_if()->has_value());
  EXPECT_TRUE(persisted.value_if()->value().auto_connect);

  auto second = enroll_relay_profile(enrollment, token, now + 1U);
  ASSERT_TRUE(second) << second.error_if()->safe_detail();
  EXPECT_EQ(second.value_if()->enrollment_generation, 1U);

  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST(M3BRelayWssClientTest, NodeAutoLoginHeartbeatsAndRelayFailureKeepsLanDisabledPath) {
  TemporaryDirectory directory{"m3b-node-relay-auto-login"};
#ifndef _WIN32
  ASSERT_EQ(::chmod(directory.path().c_str(), S_IRWXU), 0);
#endif
  ASSERT_TRUE(write_test_certificate(directory.path()));

  ProfileOpenOptions profile_options;
  profile_options.secret_backend.prefer_os_backend = false;
  auto profile =
      ProfileStore::create(directory.path() / "profile.sqlite", profile_options);
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  auto verifier = create_password_verifier("correct horse battery staple", {});
  ASSERT_TRUE(verifier) << verifier.error_if()->safe_detail();
  LocalProfileInitialization initialization;
  initialization.application_id = "com.example.relay-node";
  initialization.password_verifier = std::move(*verifier.value_if());
  initialization.password_generation = 1U;
  initialization.pairing_policy = PairingPolicy{};
  initialization.lan = LanConfiguration{};
  ASSERT_TRUE(profile.value_if()->initialize_local(initialization));
  auto identity = profile.value_if()->load_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  auto endpoint = profile.value_if()->endpoint_for("com.example.relay-node");
  ASSERT_TRUE(endpoint) << endpoint.error_if()->safe_detail();

  const auto now = now_milliseconds();
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    RelayDeviceRecord device;
    device.device_id = identity.value_if()->device_id();
    device.public_key = identity.value_if()->public_key();
    device.tenant = "tenant-a";
    device.display_name = "device";
    device.enrollment_generation = 1U;
    device.status = RelayDeviceStatus::active;
    ASSERT_TRUE(database.value_if()->enroll_device(device, now));
  }
  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  const auto port = server.value_if()->snapshot().listen_port;
  const std::string relay_url = "wss://127.0.0.1:" + std::to_string(port);
  auto pin = certificate_pin(directory.path() / "test-only-cert.pem");
  ASSERT_TRUE(pin);
  const std::vector<std::byte> pin_vector(pin->begin(), pin->end());

  RelayNodeConfig relay_config;
  relay_config.enabled = true;
  relay_config.relay_url = relay_url;
  relay_config.relay_pin = pin_vector;
  relay_config.tenant = "tenant-a";
  relay_config.tls_ca_file = std::nullopt;
  relay_config.tls_verify_peer = false;
  relay_config.connect_timeout = 2s;
  relay_config.handshake_timeout = 2s;
  relay_config.close_timeout = 1s;
  relay_config.heartbeat_interval = 1000ms;
  relay_config.lease_duration = 3000ms;
  relay_config.missed_heartbeat_limit = 3U;
  relay_config.minimum_backoff = 100ms;
  relay_config.maximum_backoff = 500ms;
  relay_config.poll_interval = 25ms;
  relay_config.receive_capacity = 16U;
  relay_config.send_capacity = 16U;

  LanConfiguration lan;
  lan.enabled = false;
  NodeConfig node_config;
  node_config.profile = profile.value_if();
  node_config.application_id = "com.example.relay-node";
  node_config.lan_override = lan;
  node_config.relay_override = relay_config;
  auto node = Node::create(std::move(node_config));
  ASSERT_TRUE(node) << node.error_if()->safe_detail();

  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = node.value_if()->snapshot();
        return snapshot.relay.state == RelayNodeState::ready;
      },
      3s));
  const auto ready = node.value_if()->snapshot();
  EXPECT_EQ(ready.relay.tenant, "tenant-a");
  EXPECT_EQ(ready.relay.enrollment_generation, 1U);
  EXPECT_EQ(ready.relay.relay_url, relay_url);

  ASSERT_TRUE(wait_until(
      [&] { return node.value_if()->snapshot().relay.heartbeats_sent >= 1U; },
      3s));
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().heartbeats >= 1U; }, 2s));
  EXPECT_GE(server.value_if()->snapshot().leases.current_entries, 1U);

  EXPECT_TRUE(node.value_if()->shutdown().stopped);
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().active_sessions == 0U; }, 2s));
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST(M3BRelayWssClientTest, NodeAutoLogsInFromPersistedRelayEnrollment) {
  TemporaryDirectory directory{"m3b-node-relay-profile-auto-login"};
#ifndef _WIN32
  ASSERT_EQ(::chmod(directory.path().c_str(), S_IRWXU), 0);
#endif
  ASSERT_TRUE(write_test_certificate(directory.path()));

  ProfileOpenOptions profile_options;
  profile_options.secret_backend.prefer_os_backend = false;
  auto profile =
      ProfileStore::create(directory.path() / "profile.sqlite", profile_options);
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  auto verifier = create_password_verifier("correct horse battery staple", {});
  ASSERT_TRUE(verifier) << verifier.error_if()->safe_detail();
  LocalProfileInitialization initialization;
  initialization.application_id = "com.example.relay-node-profile";
  initialization.password_verifier = std::move(*verifier.value_if());
  initialization.password_generation = 1U;
  initialization.pairing_policy = PairingPolicy{};
  initialization.lan = LanConfiguration{};
  ASSERT_TRUE(profile.value_if()->initialize_local(initialization));
  auto identity = profile.value_if()->load_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  ASSERT_TRUE(profile.value_if()->endpoint_for("com.example.relay-node-profile"));

  const auto now = now_milliseconds();
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    RelayDeviceRecord device;
    device.device_id = identity.value_if()->device_id();
    device.public_key = identity.value_if()->public_key();
    device.tenant = "tenant-a";
    device.display_name = "device";
    device.enrollment_generation = 1U;
    device.status = RelayDeviceStatus::active;
    ASSERT_TRUE(database.value_if()->enroll_device(device, now));
  }
  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  const auto port = server.value_if()->snapshot().listen_port;
  const std::string relay_url = "wss://127.0.0.1:" + std::to_string(port);
  auto pin = certificate_pin(directory.path() / "test-only-cert.pem");
  ASSERT_TRUE(pin);
  const std::vector<std::byte> pin_vector(pin->begin(), pin->end());
  RelayEnrollmentRecord enrollment;
  enrollment.relay_url = relay_url;
  enrollment.relay_pin = pin_vector;
  enrollment.tenant = "tenant-a";
  enrollment.enrollment_generation = 1U;
  enrollment.auto_connect = true;
  enrollment.revoked = false;
  ASSERT_TRUE(profile.value_if()->put_relay_enrollment(enrollment));

  LanConfiguration lan;
  lan.enabled = false;
  NodeConfig node_config;
  node_config.profile = profile.value_if();
  node_config.application_id = "com.example.relay-node-profile";
  node_config.lan_override = lan;
  auto node = Node::create(std::move(node_config));
  ASSERT_TRUE(node) << node.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = node.value_if()->snapshot();
        return snapshot.relay.state == RelayNodeState::ready;
      },
      3s));
  const auto ready = node.value_if()->snapshot();
  EXPECT_EQ(ready.relay.enrollment_generation, 1U);
  EXPECT_EQ(ready.relay.relay_url, relay_url);
  EXPECT_TRUE(node.value_if()->shutdown().stopped);
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST(M3BRelayWssClientTest, NodeReconnectsWithBoundedBackoffAfterRelayOutage) {
  TemporaryDirectory directory{"m3b-node-relay-reconnect"};
#ifndef _WIN32
  ASSERT_EQ(::chmod(directory.path().c_str(), S_IRWXU), 0);
#endif
  ASSERT_TRUE(write_test_certificate(directory.path()));

  ProfileOpenOptions profile_options;
  profile_options.secret_backend.prefer_os_backend = false;
  auto profile =
      ProfileStore::create(directory.path() / "profile.sqlite", profile_options);
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  auto verifier = create_password_verifier("correct horse battery staple", {});
  ASSERT_TRUE(verifier) << verifier.error_if()->safe_detail();
  LocalProfileInitialization initialization;
  initialization.application_id = "com.example.relay-reconnect";
  initialization.password_verifier = std::move(*verifier.value_if());
  initialization.password_generation = 1U;
  initialization.pairing_policy = PairingPolicy{};
  initialization.lan = LanConfiguration{};
  ASSERT_TRUE(profile.value_if()->initialize_local(initialization));
  auto identity = profile.value_if()->load_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  ASSERT_TRUE(profile.value_if()->endpoint_for("com.example.relay-reconnect"));

  const auto now = now_milliseconds();
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    RelayDeviceRecord device;
    device.device_id = identity.value_if()->device_id();
    device.public_key = identity.value_if()->public_key();
    device.tenant = "tenant-a";
    device.display_name = "device";
    device.enrollment_generation = 1U;
    device.status = RelayDeviceStatus::active;
    ASSERT_TRUE(database.value_if()->enroll_device(device, now));
  }

  boost::asio::io_context io;
  boost::asio::ip::tcp::acceptor port_probe{
      io, boost::asio::ip::tcp::endpoint{boost::asio::ip::tcp::v4(), 0U}};
  const auto port = port_probe.local_endpoint().port();
  port_probe.close();
  ASSERT_NE(port, 0U);
  const std::string relay_url = "wss://127.0.0.1:" + std::to_string(port);
  auto pin = certificate_pin(directory.path() / "test-only-cert.pem");
  ASSERT_TRUE(pin);
  const std::vector<std::byte> pin_vector(pin->begin(), pin->end());

  RelayNodeConfig relay_config;
  relay_config.enabled = true;
  relay_config.relay_url = relay_url;
  relay_config.relay_pin = pin_vector;
  relay_config.tenant = "tenant-a";
  relay_config.enrollment_generation = 1U;
  relay_config.tls_ca_file = std::nullopt;
  relay_config.tls_verify_peer = false;
  relay_config.connect_timeout = 300ms;
  relay_config.handshake_timeout = 300ms;
  relay_config.close_timeout = 500ms;
  relay_config.heartbeat_interval = 1000ms;
  relay_config.lease_duration = 3000ms;
  relay_config.missed_heartbeat_limit = 3U;
  relay_config.minimum_backoff = 100ms;
  relay_config.maximum_backoff = 400ms;
  relay_config.poll_interval = 25ms;
  relay_config.receive_capacity = 8U;
  relay_config.send_capacity = 8U;

  LanConfiguration lan;
  lan.enabled = false;
  NodeConfig node_config;
  node_config.profile = profile.value_if();
  node_config.application_id = "com.example.relay-reconnect";
  node_config.lan_override = lan;
  node_config.relay_override = relay_config;
  auto node = Node::create(std::move(node_config));
  ASSERT_TRUE(node) << node.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = node.value_if()->snapshot();
        return snapshot.relay.state == RelayNodeState::degraded &&
               snapshot.relay.reconnect_count > 0U;
      },
      2s));
  const auto degraded = node.value_if()->snapshot().relay;
  EXPECT_GE(degraded.backoff.count(), 100);
  EXPECT_LE(degraded.backoff.count(), 400);

  auto config = server_config(directory.path());
  config.listen_port = port;
  auto server = RelayServer::create(std::move(config));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return node.value_if()->snapshot().relay.state == RelayNodeState::ready; },
      3s));
  EXPECT_TRUE(node.value_if()->shutdown().stopped);
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST(M3BRelayWssClientTest, NodeReconnectsAfterRelayRestart) {
  TemporaryDirectory directory{"m3b-node-relay-restart"};
#ifndef _WIN32
  ASSERT_EQ(::chmod(directory.path().c_str(), S_IRWXU), 0);
#endif
  ASSERT_TRUE(write_test_certificate(directory.path()));

  ProfileOpenOptions profile_options;
  profile_options.secret_backend.prefer_os_backend = false;
  auto profile =
      ProfileStore::create(directory.path() / "profile.sqlite", profile_options);
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  auto verifier = create_password_verifier("correct horse battery staple", {});
  ASSERT_TRUE(verifier) << verifier.error_if()->safe_detail();
  LocalProfileInitialization initialization;
  initialization.application_id = "com.example.relay-restart";
  initialization.password_verifier = std::move(*verifier.value_if());
  initialization.password_generation = 1U;
  initialization.pairing_policy = PairingPolicy{};
  initialization.lan = LanConfiguration{};
  ASSERT_TRUE(profile.value_if()->initialize_local(initialization));
  auto identity = profile.value_if()->load_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  ASSERT_TRUE(profile.value_if()->endpoint_for("com.example.relay-restart"));

  const auto now = now_milliseconds();
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    RelayDeviceRecord device;
    device.device_id = identity.value_if()->device_id();
    device.public_key = identity.value_if()->public_key();
    device.tenant = "tenant-a";
    device.display_name = "device";
    device.enrollment_generation = 1U;
    device.status = RelayDeviceStatus::active;
    ASSERT_TRUE(database.value_if()->enroll_device(device, now));
  }

  auto first_server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(first_server) << first_server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return first_server.value_if()->snapshot().listen_port != 0U; }, 2s));
  const auto port = first_server.value_if()->snapshot().listen_port;
  const std::string relay_url = "wss://127.0.0.1:" + std::to_string(port);
  auto pin = certificate_pin(directory.path() / "test-only-cert.pem");
  ASSERT_TRUE(pin);
  const std::vector<std::byte> pin_vector(pin->begin(), pin->end());

  RelayNodeConfig relay_config;
  relay_config.enabled = true;
  relay_config.relay_url = relay_url;
  relay_config.relay_pin = pin_vector;
  relay_config.tenant = "tenant-a";
  relay_config.enrollment_generation = 1U;
  relay_config.tls_ca_file = std::nullopt;
  relay_config.tls_verify_peer = false;
  relay_config.connect_timeout = 300ms;
  relay_config.handshake_timeout = 300ms;
  relay_config.close_timeout = 500ms;
  relay_config.heartbeat_interval = 1000ms;
  relay_config.lease_duration = 3000ms;
  relay_config.missed_heartbeat_limit = 3U;
  relay_config.minimum_backoff = 100ms;
  relay_config.maximum_backoff = 400ms;
  relay_config.poll_interval = 25ms;
  relay_config.receive_capacity = 8U;
  relay_config.send_capacity = 8U;

  LanConfiguration lan;
  lan.enabled = false;
  NodeConfig node_config;
  node_config.profile = profile.value_if();
  node_config.application_id = "com.example.relay-restart";
  node_config.lan_override = lan;
  node_config.relay_override = relay_config;
  auto node = Node::create(std::move(node_config));
  ASSERT_TRUE(node) << node.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return node.value_if()->snapshot().relay.state == RelayNodeState::ready; },
      3s));
  ASSERT_TRUE(wait_until(
      [&] {
        return first_server.value_if()->snapshot().logins_completed >= 1U;
      },
      3s));
  ASSERT_TRUE(first_server.value_if()->shutdown().stopped);

  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = node.value_if()->snapshot();
        return snapshot.relay.state == RelayNodeState::degraded &&
               snapshot.relay.reconnect_count > 0U;
      },
      3s));

  auto restarted_config = server_config(directory.path());
  restarted_config.listen_port = port;
  auto restarted_server = RelayServer::create(std::move(restarted_config));
  ASSERT_TRUE(restarted_server) << restarted_server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return node.value_if()->snapshot().relay.state == RelayNodeState::ready; },
      5s));
  // Node readiness only proves the login response reached the client; the
  // server publishes its snapshot counters through the coalescing flush, so
  // poll instead of asserting immediate visibility.
  ASSERT_TRUE(wait_until(
      [&] {
        return restarted_server.value_if()->snapshot().logins_completed >= 1U;
      },
      3s));
  EXPECT_TRUE(node.value_if()->shutdown().stopped);
  EXPECT_TRUE(restarted_server.value_if()->shutdown().stopped);
}

TEST(M3BRelayWssClientTest, NodesAssembleAuthenticatedSessionOverRelayOnlyRoute) {
  TemporaryDirectory directory{"m4-node-relay-session"};
#ifndef _WIN32
  ASSERT_EQ(::chmod(directory.path().c_str(), S_IRWXU), 0);
#endif
  ASSERT_TRUE(write_test_certificate(directory.path()));
  const auto create_profile = [&](std::string_view name, std::string application_id) {
    ProfileOpenOptions options;
    options.secret_backend.prefer_os_backend = false;
    auto profile = ProfileStore::create(
        directory.path() / (std::string{name} + ".sqlite"), options);
    if (!profile) return profile;
    auto verifier = create_password_verifier("correct horse battery staple", {});
    if (!verifier) return Result<ProfileStore>::failure(*verifier.error_if());
    LocalProfileInitialization initialization;
    initialization.application_id = std::move(application_id);
    initialization.password_verifier = std::move(*verifier.value_if());
    initialization.password_generation = 1U;
    initialization.pairing_policy = PairingPolicy{};
    initialization.lan = LanConfiguration{};
    auto initialized = profile.value_if()->initialize_local(initialization);
    if (!initialized) return Result<ProfileStore>::failure(*initialized.error_if());
    return profile;
  };
  auto first_profile = create_profile("first-profile", "com.example.relay.first");
  auto second_profile = create_profile("second-profile", "com.example.relay.second");
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));
  auto first_identity = first_profile.value_if()->load_identity();
  auto second_identity = second_profile.value_if()->load_identity();
  ASSERT_TRUE(first_identity && second_identity);
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    for (const auto* identity : {first_identity.value_if(), second_identity.value_if()}) {
      RelayDeviceRecord device;
      device.device_id = identity->device_id();
      device.public_key = identity->public_key();
      device.tenant = "tenant-a";
      device.display_name = "device";
      device.enrollment_generation = 1U;
      device.status = RelayDeviceStatus::active;
      ASSERT_TRUE(database.value_if()->enroll_device(device, now_milliseconds()));
    }
  }
  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  const std::string relay_url = "wss://127.0.0.1:" +
                                std::to_string(server.value_if()->snapshot().listen_port);
  auto pin = certificate_pin(directory.path() / "test-only-cert.pem");
  ASSERT_TRUE(pin);
  RelayNodeConfig relay_config;
  relay_config.relay_url = relay_url;
  relay_config.relay_pin = std::vector<std::byte>(pin->begin(), pin->end());
  relay_config.tenant = "tenant-a";
  relay_config.tls_verify_peer = false;
  relay_config.connect_timeout = 2s;
  relay_config.handshake_timeout = 2s;
  relay_config.close_timeout = 1s;
  relay_config.heartbeat_interval = 1000ms;
  relay_config.lease_duration = 3000ms;
  relay_config.minimum_backoff = 100ms;
  relay_config.maximum_backoff = 500ms;
  relay_config.poll_interval = 10ms;
  relay_config.receive_capacity = 64U;
  relay_config.send_capacity = 64U;
  LanConfiguration lan;
  lan.enabled = false;
  lan.connectivity_mode = ConnectivityMode::relay_only;
  NodeConfig first_config;
  first_config.profile = first_profile.value_if();
  first_config.application_id = "com.example.relay.first";
  first_config.lan_override = lan;
  first_config.relay_override = relay_config;
  NodeConfig second_config;
  second_config.profile = second_profile.value_if();
  second_config.application_id = "com.example.relay.second";
  second_config.lan_override = lan;
  second_config.relay_override = relay_config;
  auto first = Node::create(std::move(first_config));
  auto second = Node::create(std::move(second_config));
  ASSERT_TRUE(first && second)
      << "first=" << (first ? "ok" : first.error_if()->safe_detail())
      << " second=" << (second ? "ok" : second.error_if()->safe_detail());
  ASSERT_TRUE(wait_until(
      [&] {
        return first.value_if()->endpoints().size() == 1U &&
               second.value_if()->endpoints().size() == 1U;
      }, 5s));
  const auto peer = first.value_if()->endpoints().front().key;
  ASSERT_TRUE(first.value_if()->connect(peer));
  const bool authenticated = wait_until(
      [&] {
        const auto left = first.value_if()->peer_sessions();
        const auto right = second.value_if()->peer_sessions();
        return left.size() == 1U && right.size() == 1U &&
               left.front().state == NodePeerSessionState::authenticated &&
               right.front().state == NodePeerSessionState::authenticated;
      }, 10s);
  ASSERT_TRUE(authenticated)
      << "first_error="
      << (first.value_if()->snapshot().last_error
              ? first.value_if()->snapshot().last_error->safe_detail() : "none")
      << " second_error="
      << (second.value_if()->snapshot().last_error
              ? second.value_if()->snapshot().last_error->safe_detail() : "none");
  const auto left = first.value_if()->peer_sessions().front();
  const auto right = second.value_if()->peer_sessions().front();
  EXPECT_EQ(left.signaling_route, SignalingRouteKind::relay);
  EXPECT_EQ(right.signaling_route, SignalingRouteKind::relay);
  EXPECT_EQ(left.connection_stage, NodeConnectionStage::authenticated);
  EXPECT_EQ(right.connection_stage, NodeConnectionStage::authenticated);
  EXPECT_EQ(left.data_path, NodeDataPathKind::direct_host);
  EXPECT_EQ(right.data_path, NodeDataPathKind::direct_host);
  EXPECT_FALSE(left.selected_candidate.empty());
  EXPECT_FALSE(right.selected_candidate.empty());
  EXPECT_EQ(left.session_id, right.session_id);
  EXPECT_EQ(left.request_id, right.request_id);
  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST(M3BRelayWssClientTest, DualRouteNodesDedupEndpointsAndPreferLanByPolicy) {
  // M4 exit condition: with LAN and relay both available the peer appears as
  // ONE merged directory entry, automatic policy prefers the LAN signaling
  // route, and each side ends up with exactly one authenticated session.
  TemporaryDirectory directory{"m3b-wss-dual-route"};
#ifndef _WIN32
  ASSERT_EQ(::chmod(directory.path().c_str(), S_IRWXU), 0);
#endif
  ASSERT_TRUE(write_test_certificate(directory.path()));
  const auto create_profile = [&](std::string_view name, std::string application_id) {
    ProfileOpenOptions options;
    options.secret_backend.prefer_os_backend = false;
    auto profile = ProfileStore::create(
        directory.path() / (std::string{name} + ".sqlite"), options);
    if (!profile) return profile;
    auto verifier = create_password_verifier("correct horse battery staple", {});
    if (!verifier) return Result<ProfileStore>::failure(*verifier.error_if());
    LocalProfileInitialization initialization;
    initialization.application_id = std::move(application_id);
    initialization.password_verifier = std::move(*verifier.value_if());
    initialization.password_generation = 1U;
    initialization.pairing_policy = PairingPolicy{};
    initialization.lan = LanConfiguration{};
    auto initialized = profile.value_if()->initialize_local(initialization);
    if (!initialized) return Result<ProfileStore>::failure(*initialized.error_if());
    return profile;
  };
  auto first_profile = create_profile("dual-first", "com.example.dual.first");
  auto second_profile = create_profile("dual-second", "com.example.dual.second");
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));
  auto first_identity = first_profile.value_if()->load_identity();
  auto second_identity = second_profile.value_if()->load_identity();
  ASSERT_TRUE(first_identity && second_identity);
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    for (const auto* identity : {first_identity.value_if(), second_identity.value_if()}) {
      RelayDeviceRecord device;
      device.device_id = identity->device_id();
      device.public_key = identity->public_key();
      device.tenant = "tenant-a";
      device.display_name = "device";
      device.enrollment_generation = 1U;
      device.status = RelayDeviceStatus::active;
      ASSERT_TRUE(database.value_if()->enroll_device(device, now_milliseconds()));
    }
  }
  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  const std::string relay_url = "wss://127.0.0.1:" +
                                std::to_string(server.value_if()->snapshot().listen_port);
  auto pin = certificate_pin(directory.path() / "test-only-cert.pem");
  ASSERT_TRUE(pin);
  RelayNodeConfig relay_config;
  relay_config.relay_url = relay_url;
  relay_config.relay_pin = std::vector<std::byte>(pin->begin(), pin->end());
  relay_config.tenant = "tenant-a";
  relay_config.tls_verify_peer = false;
  relay_config.connect_timeout = 2s;
  relay_config.handshake_timeout = 2s;
  relay_config.close_timeout = 1s;
  relay_config.heartbeat_interval = 1000ms;
  relay_config.lease_duration = 3000ms;
  relay_config.minimum_backoff = 100ms;
  relay_config.maximum_backoff = 500ms;
  relay_config.poll_interval = 10ms;
  relay_config.receive_capacity = 64U;
  relay_config.send_capacity = 64U;

  LanConfiguration lan;
  lan.enabled = true;
  lan.connectivity_mode = ConnectivityMode::automatic;
  lan.announcement_interval = 100ms;
  lan.announcement_jitter = 0ms;
  lan.presence_lease = 1000ms;
  lan.interface_refresh_interval = 2s;
  lan.announcement_rate_per_second = 100U;
  lan.per_source_announcement_rate = 100U;

  NodeConfig first_config;
  first_config.profile = first_profile.value_if();
  first_config.application_id = "com.example.dual.first";
  first_config.lan_override = lan;
  first_config.relay_override = relay_config;
  NodeConfig second_config;
  second_config.profile = second_profile.value_if();
  second_config.application_id = "com.example.dual.second";
  second_config.lan_override = lan;
  second_config.relay_override = relay_config;
  auto first = Node::create(std::move(first_config));
  auto second = Node::create(std::move(second_config));
  ASSERT_TRUE(first && second)
      << "first=" << (first ? "ok" : first.error_if()->safe_detail())
      << " second=" << (second ? "ok" : second.error_if()->safe_detail());
  const auto first_state = first.value_if()->snapshot();
  const auto second_state = second.value_if()->snapshot();
  if (first_state.interfaces.empty() || second_state.interfaces.empty()) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    (void)server.value_if()->shutdown();
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  const auto second_key = DeviceEndpointKey{second_state.device_id,
                                            second_state.endpoint_id};
  const auto first_key =
      DeviceEndpointKey{first_state.device_id, first_state.endpoint_id};

  // Both sources must merge into a single directory entry carrying both hints.
  const auto entry_with_both_hints = [&](const Node& node,
                                         const DeviceEndpointKey& peer) {
    const auto entries = node.endpoints();
    std::size_t matches = 0U;
    const EndpointDirectoryEntrySnapshot* merged = nullptr;
    for (const auto& entry : entries) {
      if (entry.key != peer) continue;
      ++matches;
      if (entry.lan.has_value() && entry.relay.has_value()) merged = &entry;
    }
    return matches == 1U && merged != nullptr;
  };
  ASSERT_TRUE(wait_until(
      [&] {
        return entry_with_both_hints(*first.value_if(), second_key) &&
               entry_with_both_hints(*second.value_if(), first_key);
      }, 15s))
      << "dual-source endpoint merge did not complete";

  ASSERT_TRUE(first.value_if()->connect(second_key));
  const bool authenticated = wait_until(
      [&] {
        const auto left = first.value_if()->peer_sessions();
        const auto right = second.value_if()->peer_sessions();
        return left.size() == 1U && right.size() == 1U &&
               left.front().state == NodePeerSessionState::authenticated &&
               right.front().state == NodePeerSessionState::authenticated;
      }, 25s);
  ASSERT_TRUE(authenticated)
      << "first_error="
      << (first.value_if()->snapshot().last_error
              ? first.value_if()->snapshot().last_error->safe_detail() : "none")
      << " second_error="
      << (second.value_if()->snapshot().last_error
              ? second.value_if()->snapshot().last_error->safe_detail() : "none");
  const auto left = first.value_if()->peer_sessions().front();
  const auto right = second.value_if()->peer_sessions().front();
  // Automatic policy preferred the LAN route even though relay was also ready.
  EXPECT_EQ(left.signaling_route, SignalingRouteKind::lan);
  EXPECT_EQ(right.signaling_route, SignalingRouteKind::lan);
  EXPECT_EQ(left.connection_stage, NodeConnectionStage::authenticated);
  EXPECT_EQ(right.connection_stage, NodeConnectionStage::authenticated);
  EXPECT_EQ(left.data_path, NodeDataPathKind::direct_host);
  EXPECT_EQ(right.data_path, NodeDataPathKind::direct_host);
  // One logical attempt produced exactly one transport winner on each side.
  EXPECT_EQ(first.value_if()->peer_sessions().size(), 1U);
  EXPECT_EQ(second.value_if()->peer_sessions().size(), 1U);
  EXPECT_EQ(left.session_id, right.session_id);
  EXPECT_EQ(left.request_id, right.request_id);
  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST(M3BRelayWssClientTest, AutomaticFallsBackToRelayWhenLanHintAbsent) {
  // M4 exit condition: the automatic policy's relay fallback — with no LAN
  // hint for the peer, connect() must use the relay route and still produce
  // exactly one authenticated session per side.
  TemporaryDirectory directory{"m3b-wss-relay-preferred"};
#ifndef _WIN32
  ASSERT_EQ(::chmod(directory.path().c_str(), S_IRWXU), 0);
#endif
  ASSERT_TRUE(write_test_certificate(directory.path()));
  const auto create_profile = [&](std::string_view name, std::string application_id) {
    ProfileOpenOptions options;
    options.secret_backend.prefer_os_backend = false;
    auto profile = ProfileStore::create(
        directory.path() / (std::string{name} + ".sqlite"), options);
    if (!profile) return profile;
    auto verifier = create_password_verifier("correct horse battery staple", {});
    if (!verifier) return Result<ProfileStore>::failure(*verifier.error_if());
    LocalProfileInitialization initialization;
    initialization.application_id = std::move(application_id);
    initialization.password_verifier = std::move(*verifier.value_if());
    initialization.password_generation = 1U;
    initialization.pairing_policy = PairingPolicy{};
    initialization.lan = LanConfiguration{};
    auto initialized = profile.value_if()->initialize_local(initialization);
    if (!initialized) return Result<ProfileStore>::failure(*initialized.error_if());
    return profile;
  };
  auto first_profile = create_profile("pref-first", "com.example.pref.first");
  auto second_profile = create_profile("pref-second", "com.example.pref.second");
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));
  auto first_identity = first_profile.value_if()->load_identity();
  auto second_identity = second_profile.value_if()->load_identity();
  ASSERT_TRUE(first_identity && second_identity);
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    for (const auto* identity : {first_identity.value_if(), second_identity.value_if()}) {
      RelayDeviceRecord device;
      device.device_id = identity->device_id();
      device.public_key = identity->public_key();
      device.tenant = "tenant-a";
      device.display_name = "device";
      device.enrollment_generation = 1U;
      device.status = RelayDeviceStatus::active;
      ASSERT_TRUE(database.value_if()->enroll_device(device, now_milliseconds()));
    }
  }
  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  const std::string relay_url = "wss://127.0.0.1:" +
                                std::to_string(server.value_if()->snapshot().listen_port);
  auto pin = certificate_pin(directory.path() / "test-only-cert.pem");
  ASSERT_TRUE(pin);
  RelayNodeConfig relay_config;
  relay_config.relay_url = relay_url;
  relay_config.relay_pin = std::vector<std::byte>(pin->begin(), pin->end());
  relay_config.tenant = "tenant-a";
  relay_config.tls_verify_peer = false;
  relay_config.connect_timeout = 2s;
  relay_config.handshake_timeout = 2s;
  relay_config.close_timeout = 1s;
  relay_config.heartbeat_interval = 1000ms;
  relay_config.lease_duration = 3000ms;
  relay_config.minimum_backoff = 100ms;
  relay_config.maximum_backoff = 500ms;
  relay_config.poll_interval = 10ms;
  relay_config.receive_capacity = 64U;
  relay_config.send_capacity = 64U;

  LanConfiguration lan;
  lan.enabled = false;
  lan.connectivity_mode = ConnectivityMode::automatic;
  lan.announcement_interval = 100ms;
  lan.announcement_jitter = 0ms;
  lan.presence_lease = 1000ms;
  lan.interface_refresh_interval = 2s;
  lan.announcement_rate_per_second = 100U;
  lan.per_source_announcement_rate = 100U;

  NodeConfig first_config;
  first_config.profile = first_profile.value_if();
  first_config.application_id = "com.example.pref.first";
  first_config.lan_override = lan;
  first_config.relay_override = relay_config;
  NodeConfig second_config;
  second_config.profile = second_profile.value_if();
  second_config.application_id = "com.example.pref.second";
  second_config.lan_override = lan;
  second_config.relay_override = relay_config;
  auto first = Node::create(std::move(first_config));
  auto second = Node::create(std::move(second_config));
  ASSERT_TRUE(first && second)
      << "first=" << (first ? "ok" : first.error_if()->safe_detail())
      << " second=" << (second ? "ok" : second.error_if()->safe_detail());
  const auto second_state = second.value_if()->snapshot();
  const auto second_key = DeviceEndpointKey{second_state.device_id,
                                            second_state.endpoint_id};

  // The peer must be present via relay with no LAN hint.
  ASSERT_TRUE(wait_until(
      [&] {
        const auto entries = first.value_if()->endpoints();
        return std::any_of(entries.begin(), entries.end(),
                           [&](const auto& entry) {
                             return entry.key == second_key &&
                                    entry.relay.has_value() && !entry.lan.has_value();
                           });
      }, 10s));
  ASSERT_TRUE(first.value_if()->connect(second_key));
  const bool authenticated = wait_until(
      [&] {
        const auto left = first.value_if()->peer_sessions();
        const auto right = second.value_if()->peer_sessions();
        return left.size() == 1U && right.size() == 1U &&
               left.front().state == NodePeerSessionState::authenticated &&
               right.front().state == NodePeerSessionState::authenticated;
      }, 60s);
  ASSERT_TRUE(authenticated);
  const auto left = first.value_if()->peer_sessions().front();
  const auto right = second.value_if()->peer_sessions().front();
  EXPECT_EQ(left.signaling_route, SignalingRouteKind::relay);
  EXPECT_EQ(right.signaling_route, SignalingRouteKind::relay);
  EXPECT_EQ(left.connection_stage, NodeConnectionStage::authenticated);
  EXPECT_EQ(left.data_path, NodeDataPathKind::direct_host);
  EXPECT_EQ(first.value_if()->peer_sessions().size(), 1U);
  EXPECT_EQ(second.value_if()->peer_sessions().size(), 1U);
  EXPECT_EQ(left.session_id, right.session_id);
  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST(M3BRelayWssClientTest, EnrollmentLatencyP95UnderTwoSeconds) {
  TemporaryDirectory directory{"m3b-wss-enrollment-latency"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  const std::string token = "TEST-ONLY-enrollment-latency-token-0123456789";
  const auto now = now_milliseconds();
  {
    auto database = RelayDatabase::open(directory.path() / "relay.sqlite");
    ASSERT_TRUE(database) << database.error_if()->safe_detail();
    ASSERT_TRUE(database.value_if()->create_bootstrap_token(
        "tenant-a", token, now + 120U * 1000U, 100U));
  }
  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));
  const auto port = server.value_if()->snapshot().listen_port;
  const std::string relay_url = "wss://127.0.0.1:" + std::to_string(port);
  auto pin = certificate_pin(directory.path() / "test-only-cert.pem");
  ASSERT_TRUE(pin);
  const std::vector<std::byte> pin_vector(pin->begin(), pin->end());
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  EndpointId::Storage endpoint_bytes{};
  endpoint_bytes[0] = std::byte{0x5aU};
  const EndpointId endpoint_id{endpoint_bytes};

  RelayEnrollmentWssTransportConfig transport;
  transport.relay_url = relay_url;
  transport.relay_pin = pin_vector;
  transport.tls_ca_file = std::nullopt;
  transport.tls_verify_peer = false;
  transport.connect_timeout = 3s;
  transport.handshake_timeout = 3s;
  transport.close_timeout = 2s;
  transport.runtime = RuntimeConfig{};

  std::vector<double> samples;
  samples.reserve(12U);
  for (std::size_t index = 0U; index < 12U; ++index) {
    const auto begin = std::chrono::steady_clock::now();
    auto enrolled = enroll_relay_over_wss(
        transport, *identity.value_if(), endpoint_id, "tenant-a", token,
        now + index);
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    ASSERT_TRUE(enrolled) << enrolled.error_if()->safe_detail();
    EXPECT_EQ(enrolled.value_if()->enrollment_generation, 1U);
    samples.push_back(std::chrono::duration<double, std::milli>(elapsed).count());
  }
  std::sort(samples.begin(), samples.end());
  const auto p95_index = std::min(samples.size() - 1U, samples.size() * 95U / 100U);
  const auto p95 = samples[p95_index];
  std::cout << "M3B enrollment latency ms p95=" << p95
            << " min=" << samples.front() << " max=" << samples.back() << "\n";
  EXPECT_LT(p95, 2000.0);
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

}  // namespace
}  // namespace heyaki
