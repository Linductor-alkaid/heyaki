#pragma once

// Shared harness for the relay control-plane suites (m3b / m4 / m9): a
// throwaway state directory, a self-signed test certificate, relay server /
// control-client wiring, and the request builders for enrollment, login, and
// endpoint records. Test-only; no production code may include this header.
// Everything is header-only so each test target keeps linking only what it
// already links.

#include "relay_enrollment.hpp"
#include "relay_endpoint.hpp"
#include "relay_login.hpp"
#include "relay_server.hpp"
#include "relay_wss_client.hpp"

#include <heyaki/identity.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/relay_wss_control.hpp>

#include <gtest/gtest.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <functional>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>

namespace heyaki::test {
inline namespace relay_support {

inline bool wait_until(const std::function<bool()>& predicate,
                       std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    std::this_thread::yield();
  }
  return predicate();
}

inline std::uint64_t now_milliseconds() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

// Directory under the target's state root, wiped on entry and on scope exit.
// The root is a runtime parameter: every test target owns its state dir via a
// per-target compile definition (see tests/CMakeLists.txt).
class TemporaryDirectory {
 public:
  explicit TemporaryDirectory(std::filesystem::path root, std::string_view name) {
    std::error_code error;
    path_ = std::move(root) / name;
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

inline bool write_test_certificate(const std::filesystem::path& directory,
                                   std::string_view common_name = "127.0.0.1") {
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
                   reinterpret_cast<const unsigned char*>(common_name.data()),
                   static_cast<int>(common_name.size()), -1, 0) == 1 &&
               X509_set_issuer_name(certificate, name) == 1;
  configured = configured && X509_sign(certificate, key, EVP_sha256()) > 0;
  BIO* certificate_output = BIO_new_file(certificate_path.string().c_str(), "wb");
  BIO* key_output = BIO_new_file(key_path.string().c_str(), "wb");
  configured =
      configured && certificate_output != nullptr && key_output != nullptr &&
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

inline std::optional<RelayTlsPin> certificate_pin(const std::filesystem::path& path) {
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

// Loopback relay configuration. `health_path` may be empty to leave the
// health endpoint disabled (some suites assert on the HTTP surface).
inline RelayServerConfig relay_test_server_config(const std::filesystem::path& root,
                                                  std::string_view worker_name,
                                                  std::string_view health_path = "/health") {
  RelayServerConfig config;
  config.listen_address = "127.0.0.1";
  config.listen_port = 0U;
  config.tls_certificate_file = root / "test-only-cert.pem";
  config.tls_private_key_file = root / "test-only-key.pem";
  config.database_file = root / "relay.sqlite";
  if (!health_path.empty()) {
    config.health_path = std::string{health_path};
  }
  config.install_signal_handlers = false;
  config.runtime.worker_name = std::string{worker_name};
  return config;
}

inline Result<RelayWssControlFrame> receive_control(
    RelayWssClient& client, std::chrono::milliseconds timeout = std::chrono::milliseconds{3000}) {
  auto received = client.receive(timeout);
  if (!received) {
    return Result<RelayWssControlFrame>::failure(*received.error_if());
  }
  if (received.value_if()->text) {
    return Result<RelayWssControlFrame>::failure(
        Error{ErrorCode::protocol, "test", "control_response_not_binary"});
  }
  return parse_relay_wss_control_frame(received.value_if()->payload);
}

inline Result<void> send_control(RelayWssClient& client, RelayWssControlType type,
                                 std::span<const std::byte> payload = {}) {
  auto frame = encode_relay_wss_control_frame(type, payload);
  if (!frame) {
    return Result<void>::failure(*frame.error_if());
  }
  return client.send(*frame.value_if());
}

inline Result<RelayWssClient> connect_control_client(const std::filesystem::path& root,
                                                     std::uint16_t port,
                                                     std::string_view worker_name) {
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
  config.runtime.worker_name = std::string{worker_name};
  auto client = RelayWssClient::create(std::move(config));
  if (!client) {
    return client;
  }
  auto connected = client.value_if()->connect(std::chrono::milliseconds{3000});
  if (!connected) {
    return Result<RelayWssClient>::failure(*connected.error_if());
  }
  return client;
}

inline Result<EnrollmentRequest> make_enrollment_request(
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

inline Result<RelayLoginRequest> make_login_request(
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

inline Result<RelayEndpointRecord> make_endpoint_record(
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

}  // inline namespace relay_support
}  // namespace heyaki::test
