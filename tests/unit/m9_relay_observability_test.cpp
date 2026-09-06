// M9-02 relay observability tests: the RelayServerSnapshot Prometheus export,
// the structured JSON log records with success-event sampling, the plain-HTTP
// /metrics endpoint, and the end-to-end login/heartbeat/query audit funnel.

#include "relay_database.hpp"
#include "relay_log.hpp"
#include "relay_login.hpp"
#include "relay_metrics.hpp"
#include "relay_server.hpp"
#include "relay_wss_client.hpp"

#include <heyaki/identity.hpp>
#include <heyaki/lan_protocol.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/relay_wss_control.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>

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
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace heyaki {
namespace {

using namespace std::chrono_literals;

constexpr std::string_view test_state_dir = HEYAKI_M9_RELAY_TEST_STATE_DIR;

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
               X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                          reinterpret_cast<const unsigned char*>("127.0.0.1"),
                                          -1, -1, 1) == 1 &&
               X509_sign(certificate, key, EVP_sha256()) > 0;
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
  config.install_signal_handlers = false;
  config.runtime.worker_name = "heyaki-m9-relay-observability-test";
  return config;
}

bool wait_until(const std::function<bool()>& predicate,
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

std::uint64_t now_milliseconds() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
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
  config.runtime.worker_name = "heyaki-m9-relay-observability-client";
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

// One plain-HTTPS request/response round trip against the relay listener.
boost::beast::http::response<boost::beast::http::string_body> https_request(
    std::uint16_t port, boost::beast::http::verb verb, std::string_view target) {
  boost::asio::io_context io;
  boost::asio::ssl::context client_context{boost::asio::ssl::context::tls_client};
  client_context.set_verify_mode(boost::asio::ssl::verify_none);
  boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream{io, client_context};
  boost::asio::ip::tcp::resolver resolver{io};
  auto endpoints = resolver.resolve("127.0.0.1", std::to_string(port));
  boost::asio::connect(stream.lowest_layer(), endpoints);
  stream.handshake(boost::asio::ssl::stream_base::client);
  boost::beast::http::request<boost::beast::http::empty_body> request{
      verb, target, 11};
  request.set(boost::beast::http::field::host, "127.0.0.1");
  boost::beast::http::write(stream, request);
  boost::beast::flat_buffer buffer;
  boost::beast::http::response<boost::beast::http::string_body> response;
  boost::beast::http::read(stream, buffer, response);
  boost::system::error_code ignored;
  stream.shutdown(ignored);
  return response;
}

RelayServerSnapshot representative_snapshot() {
  RelayServerSnapshot snapshot;
  snapshot.state = RelayServerState::running;
  snapshot.listen_address = "127.0.0.1";
  snapshot.listen_port = 8443U;
  snapshot.active_sessions = 3U;
  snapshot.connection_capacity = 16U;
  snapshot.tcp_accepted = 10U;
  snapshot.websocket_accepted = 8U;
  snapshot.health_checks = 2U;
  snapshot.metrics_scrapes = 5U;
  snapshot.control_sessions = 4U;
  snapshot.enrollment_challenges = 1U;
  snapshot.enrollments_completed = 1U;
  snapshot.control_rejected = 2U;
  snapshot.capacity_rejected = 1U;
  snapshot.handshake_timeouts = 1U;
  snapshot.handshake_failed = 1U;
  snapshot.protocol_rejected = 1U;
  snapshot.login_challenges = 3U;
  snapshot.logins_completed = 2U;
  snapshot.heartbeats = 40U;
  snapshot.endpoint_publications = 2U;
  snapshot.endpoint_queries = 6U;
  snapshot.signaling_forwarded = 12U;
  snapshot.signaling_rejected = 3U;
  snapshot.signaling_backpressure_dropped = 1U;
  snapshot.log_events_emitted = 9U;
  snapshot.log_events_sampled_out = 33U;
  snapshot.database.schema_version = relay_database_schema_version;
  snapshot.database.device_count = 2U;
  snapshot.database.bootstrap_token_count = 1U;
  snapshot.database.device_audit_count = 4U;
  snapshot.rate_limits.connection = {11U, 1U, 0U, 2U, 2U};
  snapshot.rate_limits.request = {20U, 0U, 0U, 1U, 1U};
  snapshot.rate_limits.tenant = {30U, 2U, 1U, 3U, 3U};
  snapshot.rate_limits.ip = {25U, 1U, 0U, 1U, 1U};
  snapshot.leases = {7U, 30U, 2U, 1U, 0U, 0U, 0U, 0U, 2U, 3U};
  snapshot.endpoints.published = 2U;
  snapshot.endpoints.updated = 5U;
  snapshot.endpoints.expired = 1U;
  snapshot.endpoints.removed = 1U;
  snapshot.endpoints.capacity_rejected = 0U;
  snapshot.endpoints.validation_rejected = 1U;
  snapshot.endpoints.tenant_conflict_rejected = 0U;
  snapshot.endpoints.table = {2U, 5U, 0U, 1U, 2U, 3U};
  snapshot.login.challenges_issued = 3U;
  snapshot.login.logins_succeeded = 2U;
  snapshot.login.challenges_unknown = 0U;
  snapshot.login.validation_rejected = 1U;
  snapshot.login.device_rejected = 1U;
  snapshot.login.audit_failed = 0U;
  snapshot.login.challenge_table = {3U, 0U, 0U, 1U, 1U, 3U};
  snapshot.enrollment.challenges_issued = 1U;
  snapshot.enrollment.challenges_completed = 1U;
  snapshot.enrollment.challenges_expired = 0U;
  snapshot.enrollment.challenges_unknown = 0U;
  snapshot.enrollment.validation_rejected = 0U;
  snapshot.enrollment.token_rejected = 0U;
  snapshot.enrollment.database_rejected = 0U;
  snapshot.enrollment.challenge_table = {1U, 0U, 0U, 0U, 1U, 1U};
  return snapshot;
}

// Same contract as the device-side exporter: every line is a comment or a
// `name[labels] value` sample, HELP/TYPE appear exactly once per family, and
// unlabelled counters carry the _total suffix.
bool exposition_is_well_formed(const std::string& text,
                               std::size_t minimum_families) {
  std::set<std::string> families;
  std::set<std::string> helps;
  std::set<std::string> types;
  std::size_t samples = 0U;
  std::size_t offset = 0U;
  while (offset < text.size()) {
    const auto end = text.find('\n', offset);
    const std::string_view line =
        std::string_view{text}.substr(offset, end == std::string::npos
                                                  ? std::string_view::npos
                                                  : end - offset);
    offset = end == std::string::npos ? text.size() : end + 1U;
    if (line.empty()) {
      return false;
    }
    if (line.starts_with("# HELP ")) {
      const auto name = line.substr(7U, line.find(' ', 7U) - 7U);
      if (!helps.insert(std::string{name}).second) {
        return false;
      }
      continue;
    }
    if (line.starts_with("# TYPE ")) {
      const auto tail = line.substr(7U);
      const auto name = tail.substr(0U, tail.find(' '));
      const auto kind = tail.substr(tail.rfind(' ') + 1U);
      if (kind != "counter" && kind != "gauge") {
        return false;
      }
      if (!types.insert(std::string{name}).second) {
        return false;
      }
      continue;
    }
    if (line.starts_with("#")) {
      return false;
    }
    const auto label_start = line.find('{');
    const auto value_start = line.rfind(' ');
    if (value_start == std::string_view::npos || value_start == 0U) {
      return false;
    }
    const auto value = line.substr(value_start + 1U);
    if (value.empty() ||
        !std::all_of(value.begin(), value.end(), [](char character) {
          return character >= '0' && character <= '9';
        })) {
      return false;
    }
    const auto name = line.substr(0U, label_start == std::string_view::npos
                                          ? value_start
                                          : label_start);
    if (name.empty() || !name.starts_with("heyaki_relay_")) {
      return false;
    }
    families.insert(std::string{name});
    ++samples;
  }
  return helps == types && families.size() >= minimum_families &&
         samples >= minimum_families;
}

// Exact-line sample lookup (labels included when present).
bool has_sample(const std::string& text, std::string_view expected_line) {
  std::size_t offset = 0U;
  while (offset < text.size()) {
    const auto end = text.find('\n', offset);
    const auto line = std::string_view{text}.substr(
        offset, end == std::string::npos ? std::string_view::npos : end - offset);
    offset = end == std::string::npos ? text.size() : end + 1U;
    if (line == expected_line) {
      return true;
    }
  }
  return false;
}

TEST(M9RelayMetricsTest, PrometheusExportIsWellFormedAndPinsFamilies) {
  const auto snapshot = representative_snapshot();
  const auto text = format_relay_metrics_prometheus(snapshot);
  EXPECT_TRUE(exposition_is_well_formed(text, 70U));

  // Server surface.
  EXPECT_TRUE(has_sample(text, "heyaki_relay_state 2"));
  EXPECT_TRUE(has_sample(text, "heyaki_relay_active_sessions 3"));
  EXPECT_TRUE(has_sample(text, "heyaki_relay_tcp_accepted_total 10"));
  EXPECT_TRUE(has_sample(text, "heyaki_relay_metrics_scrapes_total 5"));
  EXPECT_TRUE(has_sample(text, "heyaki_relay_signaling_backpressure_dropped_total 1"));
  EXPECT_TRUE(has_sample(text, "heyaki_relay_log_events_emitted_total 9"));
  EXPECT_TRUE(has_sample(text, "heyaki_relay_log_events_sampled_out_total 33"));
  // Sub-tables.
  EXPECT_TRUE(has_sample(text, "heyaki_relay_database_devices 2"));
  EXPECT_TRUE(has_sample(text, "heyaki_relay_rate_limit_tenant_rejected_total 2"));
  EXPECT_TRUE(has_sample(text, "heyaki_relay_rate_limit_ip_peak_keys 1"));
  EXPECT_TRUE(has_sample(text, "heyaki_relay_lease_refreshed_total 30"));
  EXPECT_TRUE(has_sample(text, "heyaki_relay_endpoints_validation_rejected_total 1"));
  EXPECT_TRUE(has_sample(text, "heyaki_relay_login_device_rejected_total 1"));
  EXPECT_TRUE(has_sample(text, "heyaki_relay_enrollment_token_rejected_total 0"));
  // HELP text is attached to a representative family.
  EXPECT_NE(text.find("# HELP heyaki_relay_active_sessions "), std::string::npos);
  EXPECT_NE(text.find("# TYPE heyaki_relay_tcp_accepted_total counter"),
            std::string::npos);
}

TEST(M9RelayMetricsTest, InstanceLabelInjectsAndEscapes) {
  const auto snapshot = representative_snapshot();
  const auto text =
      format_relay_metrics_prometheus(snapshot, "relay \"alpha\"\\nz");
  EXPECT_TRUE(has_sample(text, "heyaki_relay_active_sessions{instance=\"relay \\\"alpha\\\"\\\\nz\"} 3"));
}

TEST(M9RelayMetricsTest, RelayIdHexIsLowercaseAndStable) {
  RelayId relay_id{};
  relay_id[0U] = std::byte{0x0aU};
  relay_id[31U] = std::byte{0xffU};
  const auto hex = relay_id_to_hex(relay_id);
  EXPECT_EQ(hex.size(), 64U);
  EXPECT_EQ(hex.substr(0U, 4U), "0a00");
  EXPECT_EQ(hex.substr(60U), "00ff");
  EXPECT_EQ(hex, relay_id_to_hex(relay_id));
  EXPECT_EQ(relay_id_to_hex(RelayId{}).size(), 64U);
}

TEST(M9RelayLogTest, JsonEscapesStringsAndOmitsAbsentFields) {
  RelayLogRecord record;
  record.kind = RelayLogEventKind::login_rejected;
  record.level = RelayLogLevel::warn;
  record.timestamp_unix_milliseconds = 1725500000123U;
  record.detail = "quote\" back\\slash \n\tctrl\x01";
  const auto json = format_relay_log_json(record);
  EXPECT_EQ(json,
            "{\"ts\":1725500000123,\"level\":\"warn\","
            "\"event\":\"login_rejected\","
            "\"detail\":\"quote\\\" back\\\\slash \\n\\tctrl\\u0001\"}\n");

  RelayLogRecord full;
  full.kind = RelayLogEventKind::signaling_forwarded;
  full.level = RelayLogLevel::info;
  full.timestamp_unix_milliseconds = 1U;
  full.connection_id = "7";
  EndpointId::Storage endpoint_bytes{};
  endpoint_bytes[0U] = std::byte{0x42U};
  full.endpoint_id = EndpointId{endpoint_bytes};
  full.tenant = "tenant-a";
  RequestId::Storage request_bytes{};
  request_bytes[0U] = std::byte{0x99U};
  full.request_id = RequestId{request_bytes};
  const auto full_json = format_relay_log_json(full);
  EXPECT_NE(full_json.find("\"conn\":\"7\""), std::string::npos);
  EXPECT_NE(full_json.find("\"endpoint\":\"hye1_"), std::string::npos);
  EXPECT_NE(full_json.find("\"tenant\":\"tenant-a\""), std::string::npos);
  EXPECT_NE(full_json.find("\"request_id\":\"hyr1_"), std::string::npos);
  EXPECT_EQ(full_json.find("\"device\""), std::string::npos);
  EXPECT_EQ(full_json.find("\"detail\""), std::string::npos);
}

TEST(M9RelayLogTest, EventNamesAreStableAndUnique) {
  std::set<std::string_view> names;
  for (std::uint8_t raw = 0U;
       raw <= static_cast<std::uint8_t>(RelayLogEventKind::endpoint_query_served);
       ++raw) {
    const auto kind = static_cast<RelayLogEventKind>(raw);
    const auto name = relay_log_event_name(kind);
    EXPECT_FALSE(name.empty());
    EXPECT_NE(name, "unknown");
    EXPECT_TRUE(names.insert(name).second) << name;
  }
}

TEST(M9RelayConfigTest, LoadsObservabilityKeysAndRejectsCollisions) {
  TemporaryDirectory directory{"m9-relay-config"};
  {
    std::ofstream cert{directory.path() / "relay-cert.pem", std::ios::binary | std::ios::trunc};
    cert << "test";
    std::ofstream key{directory.path() / "relay-key.pem", std::ios::binary | std::ios::trunc};
    key << "test";
    std::ofstream config{directory.path() / "relay.conf", std::ios::binary | std::ios::trunc};
    config << "listen_address = 127.0.0.1\n"
              "listen_port = 9443\n"
              "tls_certificate_file = relay-cert.pem\n"
              "tls_private_key_file = relay-key.pem\n"
              "database_file = :memory:\n"
              "metrics_path = /prometheus\n"
              "success_log_period = 25\n";
  }
  auto loaded =
      load_relay_config_file(directory.path() / "relay.conf");
  ASSERT_TRUE(loaded) << loaded.error_if()->safe_detail();
  EXPECT_EQ(loaded.value_if()->metrics_path, "/prometheus");
  EXPECT_EQ(loaded.value_if()->success_log_period, 25U);

  const std::string_view invalid[] = {
      "metrics_path = /health\n",                 // collides with health path
      "metrics_path = /control\n",                // collides with control path
      "metrics_path = no-leading-slash\n",
      "metrics_path = /metrics\nmetrics_path = /metrics2\n",
      "success_log_period = 1000001\n",
      "success_log_period = notanumber\n",
      "success_log_period = 5\nsuccess_log_period = 6\n",
  };
  for (const auto replacement : invalid) {
    std::ofstream config{directory.path() / "bad.conf", std::ios::binary | std::ios::trunc};
    config << "listen_address = 127.0.0.1\n"
              "tls_certificate_file = relay-cert.pem\n"
              "tls_private_key_file = relay-key.pem\n"
              "database_file = :memory:\n"
           << replacement;
    auto rejected = load_relay_config_file(directory.path() / "bad.conf");
    EXPECT_FALSE(rejected) << replacement;
  }
}

TEST(M9RelayConfigTest, DefaultsSeparateMetricsAndHealthPaths) {
  RelayServerConfig config;
  config.tls_certificate_file = "a.pem";
  config.tls_private_key_file = "b.pem";
  EXPECT_TRUE(validate_relay_server_config(config));
  EXPECT_EQ(config.metrics_path, "/metrics");
  EXPECT_EQ(config.health_path, "/health");
  EXPECT_EQ(config.success_log_period, 100U);

  config.metrics_path = config.health_path;
  EXPECT_FALSE(validate_relay_server_config(config));
  config.metrics_path = relay_wss_control_path;
  EXPECT_FALSE(validate_relay_server_config(config));
  config.metrics_path = "/metrics";
  config.success_log_period = 1000001U;
  EXPECT_FALSE(validate_relay_server_config(config));
}

TEST(M9RelayServerTest, MetricsEndpointServesPrometheusOverHttps) {
  TemporaryDirectory directory{"m9-relay-metrics-endpoint"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  auto config = server_config(directory.path());
  auto server = RelayServer::create(std::move(config));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = server.value_if()->snapshot();
        return snapshot.state == RelayServerState::running &&
               snapshot.listen_port != 0U;
      },
      2s));
  const auto port = server.value_if()->snapshot().listen_port;
  // The scrape body labels every sample with the public relay id.
  const std::string label =
      "{instance=\"" +
      relay_id_to_hex(server.value_if()->snapshot().relay_id) + "\"}";

  const auto response =
      https_request(port, boost::beast::http::verb::get, "/metrics");
  EXPECT_EQ(response.result(), boost::beast::http::status::ok);
  EXPECT_NE(response[boost::beast::http::field::content_type].find("text/plain"),
            std::string::npos);
  EXPECT_TRUE(
      exposition_is_well_formed(response.body(), 70U));
  // The scrape connection itself is the only accepted TCP session so far.
  EXPECT_TRUE(has_sample(response.body(),
                         "heyaki_relay_tcp_accepted_total" + label + " 1"));
  EXPECT_TRUE(has_sample(response.body(),
                         "heyaki_relay_active_sessions" + label + " 1"));
  EXPECT_TRUE(has_sample(response.body(), "heyaki_relay_state" + label + " 2"));
  EXPECT_EQ(relay_id_to_hex(server.value_if()->snapshot().relay_id).size(), 64U);

  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().metrics_scrapes == 1U; }, 2s));

  const auto rejected =
      https_request(port, boost::beast::http::verb::post, "/metrics");
  EXPECT_EQ(rejected.result(), boost::beast::http::status::method_not_allowed);
  EXPECT_EQ(rejected[boost::beast::http::field::allow], "GET");

  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().metrics_scrapes == 2U; }, 2s));
  // Scrapes are WebSocket-free: no upgrade was attempted or counted.
  const auto final_snapshot = server.value_if()->snapshot();
  EXPECT_EQ(final_snapshot.websocket_accepted, 0U);
  EXPECT_EQ(final_snapshot.protocol_rejected, 0U);

  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

// Collects sink records under a mutex: the sink fires on the relay's
// execution context while assertions run on the test thread.
class LogCollector {
 public:
  RelayLogSink sink() {
    return [this](const RelayLogRecord& record) {
      std::lock_guard<std::mutex> guard{mutex_};
      records_.push_back(record);
    };
  }

  std::vector<RelayLogRecord> copies() const {
    std::lock_guard<std::mutex> guard{mutex_};
    return records_;
  }

  std::size_t count(RelayLogEventKind kind) const {
    std::lock_guard<std::mutex> guard{mutex_};
    return static_cast<std::size_t>(std::count_if(
        records_.begin(), records_.end(),
        [kind](const RelayLogRecord& record) { return record.kind == kind; }));
  }

 private:
  mutable std::mutex mutex_;
  std::vector<RelayLogRecord> records_;
};

class M9RelayObservabilityTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(write_test_certificate(directory_.path()));
    identity_ = create_identity();
    ASSERT_TRUE(identity_) << identity_.error_if()->safe_detail();
    const auto now = now_milliseconds();
    {
      auto database = RelayDatabase::open(directory_.path() / "relay.sqlite");
      ASSERT_TRUE(database) << database.error_if()->safe_detail();
      RelayDeviceRecord device;
      device.device_id = identity_.value_if()->device_id();
      device.public_key = identity_.value_if()->public_key();
      device.tenant = "tenant-a";
      device.display_name = "device";
      device.enrollment_generation = 1U;
      device.status = RelayDeviceStatus::active;
      ASSERT_TRUE(database.value_if()->enroll_device(device, now));
    }
  }

  // Connects, logs in with the enrolled identity, and leaves the session
  // ready for heartbeats/publishes/queries.
  Result<RelayWssClient> logged_in_client(std::uint16_t port,
                                          std::uint64_t generation = 1U) {
    auto client = connect_control_client(directory_.path(), port);
    if (!client) {
      return client;
    }
    auto challenge_sent =
        send_control(*client.value_if(), RelayWssControlType::login_challenge);
    if (!challenge_sent) {
      return Result<RelayWssClient>::failure(*challenge_sent.error_if());
    }
    auto challenge_frame = receive_control(*client.value_if());
    if (!challenge_frame) {
      return Result<RelayWssClient>::failure(*challenge_frame.error_if());
    }
    auto challenge =
        parse_enrollment_challenge(challenge_frame.value_if()->payload);
    if (!challenge) {
      return Result<RelayWssClient>::failure(*challenge.error_if());
    }
    auto login = make_login_request(*identity_.value_if(), *challenge.value_if(),
                                    generation, now_milliseconds(), 0x71U);
    if (!login) {
      return Result<RelayWssClient>::failure(*login.error_if());
    }
    auto login_bytes = encode_relay_login_request(*login.value_if());
    if (!login_bytes) {
      return Result<RelayWssClient>::failure(*login_bytes.error_if());
    }
    auto sent = send_control(*client.value_if(),
                             RelayWssControlType::login_request,
                             *login_bytes.value_if());
    if (!sent) {
      return Result<RelayWssClient>::failure(*sent.error_if());
    }
    auto login_frame = receive_control(*client.value_if());
    if (!login_frame) {
      return Result<RelayWssClient>::failure(*login_frame.error_if());
    }
    if (login_frame.value_if()->type == RelayWssControlType::control_error) {
      auto remote_error =
          parse_relay_wss_control_error(login_frame.value_if()->payload);
      return Result<RelayWssClient>::failure(
          remote_error
              ? Error{remote_error.value_if()->code, "test",
                      remote_error.value_if()->safe_detail}
              : Error{ErrorCode::protocol, "test", "control_error"});
    }
    if (login_frame.value_if()->type != RelayWssControlType::login_result) {
      return Result<RelayWssClient>::failure(
          Error{ErrorCode::protocol, "test", "login_result_expected"});
    }
    return client;
  }

  Result<void> heartbeat(RelayWssClient& client) {
    RelayWssHeartbeatRequest request;
    request.lease_milliseconds = 15000U;
    auto bytes = encode_relay_wss_heartbeat_request(request);
    if (!bytes) {
      return Result<void>::failure(*bytes.error_if());
    }
    auto sent =
        send_control(client, RelayWssControlType::heartbeat, *bytes.value_if());
    if (!sent) {
      return Result<void>::failure(*sent.error_if());
    }
    auto ack = receive_control(client);
    if (!ack) {
      return Result<void>::failure(*ack.error_if());
    }
    if (ack.value_if()->type != RelayWssControlType::heartbeat_ack) {
      return Result<void>::failure(
          Error{ErrorCode::protocol, "test", "heartbeat_ack_expected"});
    }
    return Result<void>::success();
  }

  TemporaryDirectory directory_{"m9-relay-structured-log"};
  Result<IdentityKeyPair> identity_ = Result<IdentityKeyPair>::failure(
      Error{ErrorCode::internal, "test", "unset"});
};

TEST_F(M9RelayObservabilityTest, AuditsLoginsAndSamplesSuccessEvents) {
  LogCollector collector;
  auto config = server_config(directory_.path());
  config.log_sink = collector.sink();
  config.success_log_period = 2U;
  auto server = RelayServer::create(std::move(config));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = server.value_if()->snapshot();
        return snapshot.state == RelayServerState::running &&
               snapshot.listen_port != 0U;
      },
      2s));
  const auto port = server.value_if()->snapshot().listen_port;

  // Lifecycle events are always logged.
  ASSERT_TRUE(wait_until(
      [&] { return collector.count(RelayLogEventKind::server_state_changed) >= 1U; },
      2s));

  RequestId::Storage correlation_bytes{};
  correlation_bytes[0U] = std::byte{0x5bU};
  const RequestId correlation_request_id{correlation_bytes};

  {
    auto client = logged_in_client(port);
    ASSERT_TRUE(client) << client.error_if()->safe_detail();

    // Heartbeats 1 and 3 pass the period-2 sampler; the 2nd is suppressed.
    for (int index = 0; index < 3; ++index) {
      ASSERT_TRUE(heartbeat(*client.value_if()))
          << client.error_if()->safe_detail();
    }
    ASSERT_TRUE(wait_until(
        [&] { return server.value_if()->snapshot().heartbeats == 3U; }, 2s));

    // Rejected signaling (offline target) is always logged and carries the
    // request id for correlation.
    RelayWssSignalingSend send;
    DeviceId::Storage target_device{};
    target_device[0U] = std::byte{0xaaU};
    send.target_device_id = DeviceId{target_device};
    EndpointId::Storage target_endpoint{};
    target_endpoint[0U] = std::byte{0xbbU};
    send.target_endpoint_id = EndpointId{target_endpoint};
    send.kind = static_cast<std::uint8_t>(LanSignalingMessageKind::connect_request);
    send.request_id = correlation_request_id;
    auto send_bytes = encode_relay_wss_signaling_send(send);
    ASSERT_TRUE(send_bytes) << send_bytes.error_if()->safe_detail();
    ASSERT_TRUE(send_control(*client.value_if(),
                             RelayWssControlType::signaling_send,
                             *send_bytes.value_if()));
    auto answer = receive_control(*client.value_if());
    ASSERT_TRUE(answer) << answer.error_if()->safe_detail();
    EXPECT_EQ(answer.value_if()->type, RelayWssControlType::control_error);
    ASSERT_TRUE(wait_until(
        [&] { return server.value_if()->snapshot().signaling_rejected == 1U; },
        2s));

    ASSERT_TRUE(client.value_if()->close(3s));
  }

  // A second login with a stale generation is rejected and always logged
  // with the claimed identity.
  {
    auto client = logged_in_client(port, 9U);
    ASSERT_FALSE(client);
    EXPECT_EQ(client.error_if()->code(), ErrorCode::authentication);
  }

  ASSERT_TRUE(wait_until(
      [&] { return collector.count(RelayLogEventKind::login_rejected) == 1U; },
      2s));

  const auto records = collector.copies();
  const auto logins = std::count_if(
      records.begin(), records.end(), [](const RelayLogRecord& record) {
        return record.kind == RelayLogEventKind::login_completed;
      });
  ASSERT_EQ(logins, 1U);
  const auto heartbeats_logged = std::count_if(
      records.begin(), records.end(), [](const RelayLogRecord& record) {
        return record.kind == RelayLogEventKind::heartbeat_refreshed;
      });
  EXPECT_EQ(heartbeats_logged, 2U);

  // Login audit record fields.
  const auto login_record = std::find_if(
      records.begin(), records.end(), [](const RelayLogRecord& record) {
        return record.kind == RelayLogEventKind::login_completed;
      });
  ASSERT_NE(login_record, records.end());
  EXPECT_EQ(login_record->level, RelayLogLevel::info);
  EXPECT_EQ(login_record->tenant, "tenant-a");
  ASSERT_TRUE(login_record->device_id);
  EXPECT_EQ(*login_record->device_id, identity_.value_if()->device_id());
  ASSERT_TRUE(login_record->endpoint_id);
  EXPECT_FALSE(login_record->connection_id.empty());
  EXPECT_GT(login_record->timestamp_unix_milliseconds, 0U);

  // Rejected login names the claimed (unverified) identity.
  const auto rejected = std::find_if(
      records.begin(), records.end(), [](const RelayLogRecord& record) {
        return record.kind == RelayLogEventKind::login_rejected;
      });
  ASSERT_NE(rejected, records.end());
  EXPECT_EQ(rejected->level, RelayLogLevel::warn);
  ASSERT_TRUE(rejected->device_id);
  EXPECT_EQ(*rejected->device_id, identity_.value_if()->device_id());

  // Rejected signaling carries the request id.
  const auto signaling = std::find_if(
      records.begin(), records.end(), [](const RelayLogRecord& record) {
        return record.kind == RelayLogEventKind::signaling_rejected;
      });
  ASSERT_NE(signaling, records.end());
  ASSERT_TRUE(signaling->request_id);
  EXPECT_EQ(*signaling->request_id, correlation_request_id);
  EXPECT_FALSE(signaling->detail.empty());

  // Every rendered line is a single-line JSON object.
  for (const auto& record : records) {
    const auto json = format_relay_log_json(record);
    EXPECT_TRUE(json.starts_with("{\"ts\":"));
    EXPECT_EQ(json.find('\n'), json.size() - 1U);
  }

  // Snapshot log counters: 3 heartbeats -> 1 suppressed; scrape-exported.
  const auto snapshot = server.value_if()->snapshot();
  EXPECT_GE(snapshot.log_events_emitted,
            collector.copies().size());
  EXPECT_EQ(snapshot.log_events_sampled_out, 1U);
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST_F(M9RelayObservabilityTest, ZeroPeriodDisablesSampledSuccessEvents) {
  LogCollector collector;
  auto config = server_config(directory_.path());
  config.log_sink = collector.sink();
  config.success_log_period = 0U;
  auto server = RelayServer::create(std::move(config));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = server.value_if()->snapshot();
        return snapshot.state == RelayServerState::running &&
               snapshot.listen_port != 0U;
      },
      2s));

  {
    auto client = logged_in_client(server.value_if()->snapshot().listen_port);
    ASSERT_TRUE(client) << client.error_if()->safe_detail();
    for (int index = 0; index < 3; ++index) {
      ASSERT_TRUE(heartbeat(*client.value_if()))
          << client.error_if()->safe_detail();
    }
    ASSERT_TRUE(wait_until(
        [&] { return server.value_if()->snapshot().heartbeats == 3U; }, 2s));
    ASSERT_TRUE(client.value_if()->close(3s));
  }

  EXPECT_EQ(collector.count(RelayLogEventKind::heartbeat_refreshed), 0U);
  // Security and lifecycle events still flow.
  EXPECT_GE(collector.count(RelayLogEventKind::login_completed), 1U);
  EXPECT_GE(collector.count(RelayLogEventKind::server_state_changed), 1U);
  const auto snapshot = server.value_if()->snapshot();
  EXPECT_EQ(snapshot.log_events_sampled_out, 3U);
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

TEST_F(M9RelayObservabilityTest, LogsFlowWithoutSinkAndPublishViaMetrics) {
  // No sink configured: counters still advance and the metrics endpoint
  // exposes the audit funnel after a real login.
  auto config = server_config(directory_.path());
  auto server = RelayServer::create(std::move(config));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = server.value_if()->snapshot();
        return snapshot.state == RelayServerState::running &&
               snapshot.listen_port != 0U;
      },
      2s));
  const auto port = server.value_if()->snapshot().listen_port;
  const std::string label =
      "{instance=\"" +
      relay_id_to_hex(server.value_if()->snapshot().relay_id) + "\"}";

  {
    auto client = logged_in_client(port);
    ASSERT_TRUE(client) << client.error_if()->safe_detail();
    ASSERT_TRUE(heartbeat(*client.value_if()))
        << client.error_if()->safe_detail();
    ASSERT_TRUE(client.value_if()->close(3s));
  }
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().heartbeats == 1U; }, 2s));

  const auto response =
      https_request(port, boost::beast::http::verb::get, "/metrics");
  EXPECT_EQ(response.result(), boost::beast::http::status::ok);
  EXPECT_TRUE(has_sample(response.body(),
                         "heyaki_relay_logins_completed_total" + label + " 1"));
  EXPECT_TRUE(has_sample(response.body(),
                         "heyaki_relay_heartbeats_total" + label + " 1"));
  // Default period 100 suppressed heartbeats 2..; only the 1st emitted.
  EXPECT_TRUE(has_sample(response.body(),
                         "heyaki_relay_log_events_sampled_out_total" + label +
                             " 0"));
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

}  // namespace
}  // namespace heyaki
