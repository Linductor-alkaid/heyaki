#include "relay_server.hpp"

#include <heyaki/error.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core/buffers_to_string.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

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
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace heyaki {
namespace {

using namespace std::chrono_literals;

constexpr std::string_view test_state_dir = HEYAKI_M3B_TEST_STATE_DIR;

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

void write_config(const std::filesystem::path& root, std::string_view contents) {
  std::ofstream output{root / "relay.conf", std::ios::binary | std::ios::trunc};
  ASSERT_TRUE(output);
  output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  output.close();
  ASSERT_TRUE(output);
}

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
  configured =
      configured && name != nullptr &&
      X509_NAME_add_entry_by_txt(
          name, "CN", MBSTRING_ASC,
          reinterpret_cast<const unsigned char*>("heyaki-relay-test"), -1, -1, 0) == 1 &&
      X509_set_issuer_name(certificate, name) == 1;
  X509_EXTENSION* constraints = X509V3_EXT_conf_nid(
      nullptr, nullptr, NID_basic_constraints, const_cast<char*>("critical,CA:FALSE"));
  if (constraints != nullptr) {
    configured = configured && X509_add_ext(certificate, constraints, -1) == 1;
    X509_EXTENSION_free(constraints);
  } else {
    configured = false;
  }
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

RelayServerConfig test_config(const std::filesystem::path& root) {
  RelayServerConfig config;
  config.listen_address = "127.0.0.1";
  config.listen_port = 0U;
  config.tls_certificate_file = root / "test-only-cert.pem";
  config.tls_private_key_file = root / "test-only-key.pem";
  config.database_file = root / "relay.sqlite";
  config.health_path = "/health";
  config.max_connections = 8U;
  config.handshake_timeout = 2000ms;
  config.shutdown_timeout = 2000ms;
  config.install_signal_handlers = false;
  config.runtime.worker_name = "heyaki-m3b-relay-test";
  return config;
}

TEST(M3BRelayConfigTest, LoadsAndValidatesFile) {
  TemporaryDirectory directory{"m3b-relay-config"};
  {
    std::ofstream cert{directory.path() / "relay-cert.pem", std::ios::binary | std::ios::trunc};
    std::ofstream key{directory.path() / "relay-key.pem", std::ios::binary | std::ios::trunc};
    cert << "test";
    key << "test";
  }
  write_config(directory.path(),
               "# bounded WSS skeleton\n"
               "listen_address = 127.0.0.1\n"
               "listen_port = 8443\n"
               "tls_certificate_file = relay-cert.pem\n"
               "tls_private_key_file = relay-key.pem\n"
               "database_file = relay.sqlite\n"
               "health_path = /health\n"
               "max_connections = 2048\n"
               "handshake_timeout_milliseconds = 4500\n"
               "shutdown_timeout_milliseconds = 1500\n");

  auto loaded = load_relay_config_file(directory.path() / "relay.conf");
  ASSERT_TRUE(loaded) << loaded.error_if()->safe_detail();
  EXPECT_EQ(loaded.value_if()->listen_address, "127.0.0.1");
  EXPECT_EQ(loaded.value_if()->listen_port, 8443U);
  EXPECT_EQ(loaded.value_if()->tls_certificate_file, directory.path() / "relay-cert.pem");
  EXPECT_EQ(loaded.value_if()->tls_private_key_file, directory.path() / "relay-key.pem");
  EXPECT_EQ(loaded.value_if()->database_file, directory.path() / "relay.sqlite");
  EXPECT_EQ(loaded.value_if()->health_path, "/health");
  EXPECT_EQ(loaded.value_if()->max_connections, 2048U);
  EXPECT_EQ(loaded.value_if()->handshake_timeout, 4500ms);
  EXPECT_EQ(loaded.value_if()->shutdown_timeout, 1500ms);
  EXPECT_TRUE(validate_relay_server_config(*loaded.value_if()));
}

TEST(M3BRelayConfigTest, RejectsDuplicateUnknownAndOutOfRangeKeys) {
  TemporaryDirectory directory{"m3b-relay-config-invalid"};
  const std::array contents{
      std::string_view{"listen_port = 0\n"},
      std::string_view{"listen_address = 127.0.0.1\nlisten_address = ::1\n"},
      std::string_view{"unknown_option = 1\n"},
      std::string_view{"max_connections = 0\n"},
      std::string_view{"handshake_timeout_milliseconds = 99\n"},
      std::string_view{"health_path = no-leading-slash\n"},
      std::string_view{"health_path = /control\n"},
  };
  for (std::size_t index = 0U; index < contents.size(); ++index) {
    write_config(directory.path(), contents[index]);
    auto loaded = load_relay_config_file(directory.path() / "relay.conf");
    EXPECT_FALSE(loaded);
    if (loaded) {
      continue;
    }
    EXPECT_EQ(loaded.error_if()->code(), ErrorCode::configuration);
    EXPECT_FALSE(std::string_view{loaded.error_if()->safe_detail()}.empty());
  }
}

TEST(M3BRelayServerTest, WssHealthCheckAndBoundedShutdown) {
  TemporaryDirectory directory{"m3b-relay-server"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  auto config = test_config(directory.path());
  auto server = RelayServer::create(std::move(config));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();

  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = server.value_if()->snapshot();
        return snapshot.state == RelayServerState::running && snapshot.listen_port != 0U;
      },
      2s));
  const auto ready = server.value_if()->snapshot();
  ASSERT_EQ(ready.state, RelayServerState::running);
  ASSERT_NE(ready.listen_port, 0U);

  {
    boost::asio::io_context io;
    boost::asio::ssl::context client_context{boost::asio::ssl::context::tls_client};
    client_context.set_verify_mode(boost::asio::ssl::verify_none);
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::asio::ip::tcp::socket>>
        websocket{io, client_context};
    boost::asio::ip::tcp::resolver resolver{io};
    auto endpoints = resolver.resolve(ready.listen_address,
                                      std::to_string(ready.listen_port));
    ASSERT_NO_THROW(boost::asio::connect(boost::beast::get_lowest_layer(websocket),
                                         endpoints));
    ASSERT_NO_THROW(websocket.next_layer().handshake(
        boost::asio::ssl::stream_base::client));
    ASSERT_NO_THROW(websocket.handshake("127.0.0.1", "/health"));
    boost::beast::flat_buffer buffer;
    ASSERT_NO_THROW(websocket.read(buffer));
    EXPECT_EQ(boost::beast::buffers_to_string(buffer.data()), "ok\n");
    ASSERT_NO_THROW(websocket.close(boost::beast::websocket::close_code::normal));
  }

  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = server.value_if()->snapshot();
        return snapshot.health_checks == 1U && snapshot.active_sessions == 0U;
      },
      2s));
  const auto healthy = server.value_if()->snapshot();
  EXPECT_EQ(healthy.database.schema_version, relay_database_schema_version);
  EXPECT_EQ(healthy.tcp_accepted, 1U);
  EXPECT_EQ(healthy.websocket_accepted, 1U);
  EXPECT_EQ(healthy.health_checks, 1U);

  const auto report = server.value_if()->shutdown();
  EXPECT_TRUE(report.stopped);
  EXPECT_FALSE(report.timed_out);
  EXPECT_EQ(report.final_snapshot.state, RelayServerState::stopped);
  EXPECT_EQ(report.final_snapshot.active_sessions, 0U);
  EXPECT_EQ(report.runtime.final_phase, RuntimePhase::stopped);
  EXPECT_TRUE(report.runtime.executor_shutdown_performed);
}

TEST(M3BRelayServerTest, HandshakeDeadlineExpiresAndReleasesSlot) {
  TemporaryDirectory directory{"m3b-relay-handshake-timeout"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  auto config = test_config(directory.path());
  config.handshake_timeout = 200ms;
  auto server = RelayServer::create(std::move(config));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = server.value_if()->snapshot();
        return snapshot.state == RelayServerState::running && snapshot.listen_port != 0U;
      },
      2s));
  const auto ready = server.value_if()->snapshot();

  {
    boost::asio::io_context io;
    boost::asio::ip::tcp::socket socket{io};
    boost::asio::ip::tcp::resolver resolver{io};
    auto endpoints = resolver.resolve(ready.listen_address,
                                      std::to_string(ready.listen_port));
    ASSERT_NO_THROW(boost::asio::connect(socket, endpoints));
    ASSERT_TRUE(wait_until(
        [&] { return server.value_if()->snapshot().active_sessions == 1U; }, 2s));
    ASSERT_TRUE(wait_until(
        [&] {
          const auto snapshot = server.value_if()->snapshot();
          return snapshot.active_sessions == 0U && snapshot.handshake_timeouts == 1U;
        },
        2s));
  }
  const auto report = server.value_if()->shutdown();
  EXPECT_TRUE(report.stopped);
  EXPECT_EQ(report.final_snapshot.handshake_timeouts, 1U);
}

TEST(M3BRelayServerTest, ConnectionCapacityRejectsAboveBound) {
  TemporaryDirectory directory{"m3b-relay-capacity"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  auto config = test_config(directory.path());
  config.max_connections = 1U;
  config.handshake_timeout = 4000ms;
  auto server = RelayServer::create(std::move(config));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = server.value_if()->snapshot();
        return snapshot.state == RelayServerState::running && snapshot.listen_port != 0U;
      },
      2s));
  const auto ready = server.value_if()->snapshot();

  {
    boost::asio::io_context io;
    boost::asio::ssl::context client_context{boost::asio::ssl::context::tls_client};
    client_context.set_verify_mode(boost::asio::ssl::verify_none);
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> first{io, client_context};
    boost::asio::ip::tcp::resolver resolver{io};
    auto endpoints = resolver.resolve(ready.listen_address,
                                      std::to_string(ready.listen_port));
    ASSERT_NO_THROW(boost::asio::connect(first.lowest_layer(), endpoints));
    ASSERT_NO_THROW(first.handshake(boost::asio::ssl::stream_base::client));
    ASSERT_TRUE(wait_until(
        [&] { return server.value_if()->snapshot().active_sessions == 1U; }, 2s));

    boost::asio::io_context second_io;
    boost::asio::ssl::context second_context{boost::asio::ssl::context::tls_client};
    second_context.set_verify_mode(boost::asio::ssl::verify_none);
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> second{second_io,
                                                                  second_context};
    boost::system::error_code error;
    boost::asio::connect(second.lowest_layer(), endpoints, error);
    EXPECT_FALSE(error);
    second.handshake(boost::asio::ssl::stream_base::client, error);
    EXPECT_TRUE(error) << "capacity-closed socket should not complete a TLS handshake";
  }

  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = server.value_if()->snapshot();
        return snapshot.capacity_rejected == 1U && snapshot.active_sessions == 0U;
      },
      2s));
  const auto report = server.value_if()->shutdown();
  EXPECT_TRUE(report.stopped);
  EXPECT_EQ(report.final_snapshot.capacity_rejected, 1U);
}

}  // namespace
}  // namespace heyaki
