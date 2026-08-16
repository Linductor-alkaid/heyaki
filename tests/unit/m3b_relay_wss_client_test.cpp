#include "relay_server.hpp"
#include "relay_wss_client.hpp"

#include <gtest/gtest.h>

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
  EXPECT_FALSE(client.value_if()->send({}));
  const std::vector<std::byte> large(70000U);
  EXPECT_FALSE(client.value_if()->send(large));
  (void)server.value_if()->shutdown();
}

}  // namespace
}  // namespace heyaki
