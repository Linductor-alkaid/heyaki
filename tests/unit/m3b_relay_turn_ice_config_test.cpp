// Relay-issued TURN/ICE configuration (relay_ice_config_v1): configuration
// parsing, shared-secret resolution, and the server-side control-plane
// behavior end to end against a real in-process relay server.
//
//  1. turn_servers URI parsing through load_relay_config_file (accepts the
//     documented forms, rejects malformed ones and stray keys while disabled);
//  2. load_relay_turn_secret sources (file with trailing newline, environment
//     variable, precedence) and its safeguards (bounds, invalid secrets, no
//     secret material in error details);
//  3. validate_relay_server_config turn bounds;
//  4. enabled relay issues REST credentials on login_result and refreshes
//     them on every heartbeat_ack, verifiable with an independent
//     RelayTurnCredentialService seeded with the same secret;
//  5. disabled relay and legacy (capability-masked) clients never see the
//     ice_config field;
//  6. RelayServer::create fails fast when enabled without a resolvable
//     secret;
//  7. issued credentials never surface in structured logs or the Prometheus
//     export.
//
// Threading discipline (AGENTS.md): the relay server and the WSS client run
// on their own executor-backed runtimes; the test thread only performs
// bounded snapshot polling and synchronous request/response exchanges.

#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <heyaki/identity.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/relay_wss_control.hpp>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "relay_config.hpp"
#include "relay_database.hpp"
#include "relay_enrollment.hpp"
#include "relay_login.hpp"
#include "relay_metrics.hpp"
#include "relay_server.hpp"
#include "relay_turn_credentials.hpp"
#include "relay_wss_client.hpp"

namespace heyaki {
namespace {

using namespace std::chrono_literals;

constexpr std::string_view test_state_dir = HEYAKI_M3B_TEST_STATE_DIR;
constexpr std::string_view test_turn_secret = "test-turn-secret-0123456789ab";

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

// RAII guard around one process environment variable: every test that touches
// HEYAKI_TURN_SECRET restores the inherited value on scope exit so test order
// can never leak configuration between cases.
class EnvironmentVariableGuard {
 public:
  explicit EnvironmentVariableGuard(std::string name) : name_(std::move(name)) {
    const char* current = std::getenv(name_.c_str());
    if (current != nullptr) {
      previous_ = current;
    }
  }
  ~EnvironmentVariableGuard() { restore(); }
  EnvironmentVariableGuard(const EnvironmentVariableGuard&) = delete;
  EnvironmentVariableGuard& operator=(const EnvironmentVariableGuard&) = delete;

  void set(const std::string& value) { ::setenv(name_.c_str(), value.c_str(), 1); }
  void clear() { ::unsetenv(name_.c_str()); }

 private:
  void restore() {
    if (previous_) {
      ::setenv(name_.c_str(), previous_->c_str(), 1);
    } else {
      ::unsetenv(name_.c_str());
    }
  }

  std::string name_;
  std::optional<std::string> previous_;
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
  bool configured = X509_set_version(certificate, 2L) == 1 &&
                    ASN1_INTEGER_set_uint64(X509_get_serialNumber(certificate), serial) == 1 &&
                    X509_gmtime_adj(X509_getm_notBefore(certificate), -60L) != nullptr &&
                    X509_gmtime_adj(X509_getm_notAfter(certificate), 24L * 60L * 60L) != nullptr &&
                    X509_set_pubkey(certificate, key) == 1;
  X509_NAME* name = X509_get_subject_name(certificate);
  configured = configured && name != nullptr &&
               X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                          reinterpret_cast<const unsigned char*>("127.0.0.1"), -1,
                                          -1, 0) == 1 &&
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

std::uint64_t now_unix_seconds() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
}

std::uint64_t now_milliseconds() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
}

void write_file(const std::filesystem::path& path, std::string_view contents) {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  ASSERT_TRUE(output);
  output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  output.close();
  ASSERT_TRUE(output);
}

void write_relay_config(const std::filesystem::path& root, const std::string& extra_lines) {
  // listen_port=0 is rejected by the file parser (only the in-memory struct
  // accepts an ephemeral port), so config-file tests bind a fixed port.
  std::string contents =
      "listen_port=18443\n"
      "tls_certificate_file=test-only-cert.pem\n"
      "tls_private_key_file=test-only-key.pem\n"
      "database_file=:memory:\n";
  contents.append(extra_lines);
  write_file(root / "relay.conf", contents);
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
  config.runtime.worker_name = "heyaki-m3b-turn-ice-test";
  return config;
}

// Enables relay-issued TURN credentials on a test server config: one TURN/UDP
// advertisement plus the shared-secret file under the test root.
void enable_turn_credentials(RelayServerConfig& config, const std::filesystem::path& root,
                             std::uint32_t ttl_seconds = 600U) {
  RelayTurnAdvertisedServer advertised;
  advertised.kind = RelayWssIceServerKind::turn_udp;
  advertised.hostname = "127.0.0.1";
  advertised.port = 3478U;
  config.turn_credentials_enabled = true;
  config.turn_credential_ttl = std::chrono::seconds{ttl_seconds};
  config.turn_servers.push_back(advertised);
  const auto secret_file = root / "turn-secret";
  write_file(secret_file, test_turn_secret);
  config.turn_secret_file = secret_file;
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
  config.url = "wss://127.0.0.1:" + std::to_string(port) + std::string{relay_wss_control_path};
  config.relay_pin = pin;
  config.tls_verify_peer = false;
  config.runtime.worker_name = "heyaki-m3b-turn-ice-client";
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

Result<RelayLoginRequest> make_login_request(const IdentityKeyPair& identity,
                                             const EnrollmentChallenge& challenge,
                                             std::uint64_t generation, std::uint64_t now,
                                             std::uint8_t endpoint_byte,
                                             std::uint64_t supported_bits = known_capability_bits,
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
  request.supported.bits = supported_bits;
  request.required.bits = static_cast<std::uint64_t>(Capability::enrollment);
  request.enrollment_generation = generation;
  request.expires_unix_milliseconds = now + 30U * 1000U;
  auto signed_request = sign_relay_login_request(request, challenge.relay_id, identity);
  if (!signed_request) {
    return Result<RelayLoginRequest>::failure(*signed_request.error_if());
  }
  return Result<RelayLoginRequest>::success(std::move(request));
}

// Enrolls the identity so the in-process server accepts its login.
void enroll_device_for_login(const std::filesystem::path& root, const IdentityKeyPair& identity) {
  auto database = RelayDatabase::open(root / "relay.sqlite");
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  RelayDeviceRecord device;
  device.device_id = identity.device_id();
  device.public_key = identity.public_key();
  device.tenant = "tenant-a";
  device.display_name = "turn-ice-test";
  device.enrollment_generation = 1U;
  device.status = RelayDeviceStatus::active;
  ASSERT_TRUE(database.value_if()->enroll_device(device, now_milliseconds()));
}

// One login exchange: the raw wire payload plus the parsed login_result. The
// result is populated only when the payload passes the device-side wire
// codec; a nullopt with parse_detail records a relay payload the device
// rejects.
struct LoginExchange {
  std::optional<RelayWssLoginResult> result;
  std::string parse_detail;
  std::vector<std::byte> payload;
};

Result<LoginExchange> login_new_client(RelayServer& server, const std::filesystem::path& root,
                                       const IdentityKeyPair& identity,
                                       std::uint64_t supported_bits) {
  auto client = connect_control_client(root, server.snapshot().listen_port);
  if (!client) {
    return Result<LoginExchange>::failure(*client.error_if());
  }
  auto exchange = Result<LoginExchange>::failure(Error{ErrorCode::internal, "test", "unset"});
  auto finish = [&](Result<LoginExchange> outcome) {
    (void)client.value_if()->close(3s);
    return outcome;
  };
  if (!send_control(*client.value_if(), RelayWssControlType::login_challenge)) {
    return finish(Result<LoginExchange>::failure(
        Error{ErrorCode::internal, "test", "login_challenge_send_failed"}));
  }
  auto challenge_frame = receive_control(*client.value_if());
  if (!challenge_frame) {
    return finish(Result<LoginExchange>::failure(*challenge_frame.error_if()));
  }
  if (challenge_frame.value_if()->type != RelayWssControlType::login_challenge_response) {
    return finish(Result<LoginExchange>::failure(
        Error{ErrorCode::protocol, "test", "login_challenge_expected"}));
  }
  auto challenge = parse_enrollment_challenge(challenge_frame.value_if()->payload);
  if (!challenge) {
    return finish(Result<LoginExchange>::failure(*challenge.error_if()));
  }
  auto request = make_login_request(identity, *challenge.value_if(), 1U, now_milliseconds(), 0x61U,
                                    supported_bits);
  if (!request) {
    return finish(Result<LoginExchange>::failure(*request.error_if()));
  }
  auto request_bytes = encode_relay_login_request(*request.value_if());
  if (!request_bytes) {
    return finish(Result<LoginExchange>::failure(*request_bytes.error_if()));
  }
  if (!send_control(*client.value_if(), RelayWssControlType::login_request,
                    *request_bytes.value_if())) {
    return finish(Result<LoginExchange>::failure(
        Error{ErrorCode::internal, "test", "login_request_send_failed"}));
  }
  auto login_frame = receive_control(*client.value_if());
  if (!login_frame) {
    return finish(Result<LoginExchange>::failure(*login_frame.error_if()));
  }
  if (login_frame.value_if()->type != RelayWssControlType::login_result) {
    return finish(Result<LoginExchange>::failure(
        Error{ErrorCode::protocol, "test", "login_result_expected"}));
  }
  LoginExchange output;
  output.payload = login_frame.value_if()->payload;
  auto parsed = parse_relay_wss_login_result(login_frame.value_if()->payload);
  if (!parsed) {
    output.parse_detail = std::string{parsed.error_if()->safe_detail()};
  } else {
    output.result = std::move(*parsed.value_if());
  }
  return finish(Result<LoginExchange>::success(std::move(output)));
}

// Logs in on an already-connected client, then sends one heartbeat and
// returns the parsed ack (with the login_result payload retained for callers
// that need it).
struct HeartbeatExchange {
  RelayWssLoginResult login;
  RelayWssHeartbeatAck ack;
};

Result<HeartbeatExchange> login_then_heartbeat(RelayWssClient& client,
                                               const IdentityKeyPair& identity,
                                               std::uint64_t supported_bits) {
  if (!send_control(client, RelayWssControlType::login_challenge)) {
    return Result<HeartbeatExchange>::failure(
        Error{ErrorCode::internal, "test", "login_challenge_send_failed"});
  }
  auto challenge_frame = receive_control(client);
  if (!challenge_frame) {
    return Result<HeartbeatExchange>::failure(*challenge_frame.error_if());
  }
  if (challenge_frame.value_if()->type != RelayWssControlType::login_challenge_response) {
    return Result<HeartbeatExchange>::failure(
        Error{ErrorCode::protocol, "test", "login_challenge_expected"});
  }
  auto challenge = parse_enrollment_challenge(challenge_frame.value_if()->payload);
  if (!challenge) {
    return Result<HeartbeatExchange>::failure(*challenge.error_if());
  }
  auto request = make_login_request(identity, *challenge.value_if(), 1U, now_milliseconds(), 0x61U,
                                    supported_bits);
  if (!request) {
    return Result<HeartbeatExchange>::failure(*request.error_if());
  }
  auto request_bytes = encode_relay_login_request(*request.value_if());
  if (!request_bytes) {
    return Result<HeartbeatExchange>::failure(*request_bytes.error_if());
  }
  if (!send_control(client, RelayWssControlType::login_request, *request_bytes.value_if())) {
    return Result<HeartbeatExchange>::failure(
        Error{ErrorCode::internal, "test", "login_request_send_failed"});
  }
  auto login_frame = receive_control(client);
  if (!login_frame) {
    return Result<HeartbeatExchange>::failure(*login_frame.error_if());
  }
  if (login_frame.value_if()->type != RelayWssControlType::login_result) {
    return Result<HeartbeatExchange>::failure(
        Error{ErrorCode::protocol, "test", "login_result_expected"});
  }
  auto login = parse_relay_wss_login_result(login_frame.value_if()->payload);
  if (!login) {
    return Result<HeartbeatExchange>::failure(*login.error_if());
  }
  HeartbeatExchange output;
  output.login = std::move(*login.value_if());

  RelayWssHeartbeatRequest heartbeat;
  heartbeat.lease_milliseconds = 15000U;
  auto heartbeat_bytes = encode_relay_wss_heartbeat_request(heartbeat);
  if (!heartbeat_bytes) {
    return Result<HeartbeatExchange>::failure(*heartbeat_bytes.error_if());
  }
  auto sent = send_control(client, RelayWssControlType::heartbeat, *heartbeat_bytes.value_if());
  if (!sent) {
    return Result<HeartbeatExchange>::failure(*sent.error_if());
  }
  auto ack_frame = receive_control(client);
  if (!ack_frame) {
    return Result<HeartbeatExchange>::failure(*ack_frame.error_if());
  }
  if (ack_frame.value_if()->type != RelayWssControlType::heartbeat_ack) {
    return Result<HeartbeatExchange>::failure(
        Error{ErrorCode::protocol, "test", "heartbeat_ack_expected"});
  }
  auto ack = parse_relay_wss_heartbeat_ack(ack_frame.value_if()->payload);
  if (!ack) {
    return Result<HeartbeatExchange>::failure(*ack.error_if());
  }
  output.ack = std::move(*ack.value_if());
  return Result<HeartbeatExchange>::success(std::move(output));
}

// Mutex-guarded structured-log collector for the leak assertions.
class LogCollector {
 public:
  LogCollector() = default;

  void append(const RelayLogRecord& record) {
    const std::lock_guard<std::mutex> lock(mutex_);
    records_.push_back(record);
  }

  [[nodiscard]] std::vector<RelayLogRecord> records() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return records_;
  }

 private:
  mutable std::mutex mutex_;
  std::vector<RelayLogRecord> records_;
};

// ---- B1: turn_servers URI parsing through the config file ----

TEST(M3BRelayTurnIceConfigTest, ParsesTurnServerUriForms) {
  TemporaryDirectory directory{"m3b-turn-ice-uri-valid"};
  ASSERT_TRUE(write_test_certificate(directory.path()));

  struct Expected {
    RelayWssIceServerKind kind;
    std::string hostname;
    std::uint16_t port;
  };

  // Accepted forms: plain turn (UDP default), explicit transports, stun.
  write_relay_config(directory.path(),
                     "turn_credentials_enabled=true\n"
                     "turn_servers=turn:turn.example.com:3478?transport=udp,"
                     "turn:turn.example.com:3479?transport=tcp,"
                     "turn:turn.example.com:3480,"
                     "stun:stun.example.com:3478\n");
  auto loaded = load_relay_config_file(directory.path() / "relay.conf");
  ASSERT_TRUE(loaded) << loaded.error_if()->safe_detail();
  ASSERT_EQ(loaded.value_if()->turn_servers.size(), 4U);
  const std::vector<Expected> expected{
      {RelayWssIceServerKind::turn_udp, "turn.example.com", 3478U},
      {RelayWssIceServerKind::turn_tcp, "turn.example.com", 3479U},
      {RelayWssIceServerKind::turn_udp, "turn.example.com", 3480U},
      {RelayWssIceServerKind::stun, "stun.example.com", 3478U},
  };
  for (std::size_t index = 0U; index < expected.size(); ++index) {
    EXPECT_EQ(loaded.value_if()->turn_servers[index].kind, expected[index].kind);
    EXPECT_EQ(loaded.value_if()->turn_servers[index].hostname, expected[index].hostname);
    EXPECT_EQ(loaded.value_if()->turn_servers[index].port, expected[index].port);
  }
  EXPECT_TRUE(loaded.value_if()->turn_credentials_enabled);
  EXPECT_EQ(loaded.value_if()->turn_credential_ttl, std::chrono::seconds{600});

  // Bracketed IPv6 literal.
  TemporaryDirectory ipv6_directory{"m3b-turn-ice-uri-ipv6"};
  ASSERT_TRUE(write_test_certificate(ipv6_directory.path()));
  write_relay_config(ipv6_directory.path(),
                     "turn_credentials_enabled=true\n"
                     "turn_servers=turn:[2001:db8::1]:3478\n");
  auto ipv6 = load_relay_config_file(ipv6_directory.path() / "relay.conf");
  ASSERT_TRUE(ipv6) << ipv6.error_if()->safe_detail();
  ASSERT_EQ(ipv6.value_if()->turn_servers.size(), 1U);
  EXPECT_EQ(ipv6.value_if()->turn_servers[0U].kind, RelayWssIceServerKind::turn_udp);
  EXPECT_EQ(ipv6.value_if()->turn_servers[0U].hostname, "2001:db8::1");
  EXPECT_EQ(ipv6.value_if()->turn_servers[0U].port, 3478U);
}

TEST(M3BRelayTurnIceConfigTest, RejectsMalformedTurnServerUris) {
  struct InvalidCase {
    std::string name;
    std::string servers;
  };
  const std::vector<InvalidCase> cases{
      {"missing_scheme", "turn.example.com:3478"},
      {"turns_rejected", "turns:turn.example.com:3478"},
      {"stun_with_query", "stun:stun.example.com:3478?transport=udp"},
      {"missing_port", "turn:turn.example.com"},
      {"zero_port", "turn:turn.example.com:0"},
      {"empty_host", "turn::3478"},
      {"oversized_host", std::string("turn:") + std::string(254U, 'a') + ":3478"},
      {"unknown_transport", "turn:turn.example.com:3478?transport=tls"},
      {"unknown_query_parameter", "turn:turn.example.com:3478?foo=bar"},
  };
  for (const auto& item : cases) {
    SCOPED_TRACE(item.name);
    TemporaryDirectory directory{"m3b-turn-ice-uri-bad"};
    ASSERT_TRUE(write_test_certificate(directory.path()));
    write_relay_config(directory.path(),
                       "turn_credentials_enabled=true\nturn_servers=" + item.servers + "\n");
    auto loaded = load_relay_config_file(directory.path() / "relay.conf");
    ASSERT_FALSE(loaded) << "unexpectedly loaded: " << item.servers;
    EXPECT_EQ(loaded.error_if()->code(), ErrorCode::configuration);
    EXPECT_EQ(loaded.error_if()->safe_detail(), "relay_config_turn_server_uri_invalid");
  }

  // More than four advertised servers.
  TemporaryDirectory capacity_directory{"m3b-turn-ice-uri-capacity"};
  ASSERT_TRUE(write_test_certificate(capacity_directory.path()));
  write_relay_config(capacity_directory.path(),
                     "turn_credentials_enabled=true\n"
                     "turn_servers=turn:a.example:3478,turn:b.example:3478,"
                     "turn:c.example:3478,turn:d.example:3478,"
                     "turn:e.example:3478\n");
  auto capacity = load_relay_config_file(capacity_directory.path() / "relay.conf");
  ASSERT_FALSE(capacity) << capacity.error_if()->safe_detail();
  EXPECT_EQ(capacity.error_if()->safe_detail(), "relay_config_turn_server_capacity");

  // Stray TURN keys while the feature is disabled.
  const std::vector<std::string> disabled_conflicts{
      "turn_credentials_enabled=false\nturn_servers=turn:a.example:3478\n",
      "turn_credentials_enabled=false\nturn_secret_file=turn-secret\n",
      "turn_credentials_enabled=false\nturn_credential_ttl_seconds=900\n",
      "turn_servers=turn:a.example:3478\n",
  };
  for (const auto& extra : disabled_conflicts) {
    SCOPED_TRACE(extra);
    TemporaryDirectory directory{"m3b-turn-ice-disabled-conflict"};
    ASSERT_TRUE(write_test_certificate(directory.path()));
    write_relay_config(directory.path(), extra);
    auto loaded = load_relay_config_file(directory.path() / "relay.conf");
    ASSERT_FALSE(loaded) << "config loaded: " << extra;
    EXPECT_EQ(loaded.error_if()->safe_detail(), "turn_config_disabled_conflict");
  }
}

// ---- B2: load_relay_turn_secret sources and safeguards ----

TEST(M3BRelayTurnIceConfigTest, LoadsTurnSecretFromEnvironmentAndFile) {
  EnvironmentVariableGuard guard{std::string{relay_turn_secret_env}};
  guard.clear();

  RelayServerConfig config;

  // No file and no environment variable: unavailable.
  auto missing = load_relay_turn_secret(config);
  ASSERT_FALSE(missing);
  EXPECT_EQ(missing.error_if()->safe_detail(), "turn_secret_unavailable");

  // Environment variable source.
  guard.set(std::string{test_turn_secret});
  auto from_environment = load_relay_turn_secret(config);
  ASSERT_TRUE(from_environment) << from_environment.error_if()->safe_detail();
  EXPECT_EQ(*from_environment.value_if(), test_turn_secret);

  // File source wins over the environment variable, and trailing CR/LF is
  // stripped.
  TemporaryDirectory directory{"m3b-turn-ice-secret"};
  const auto secret_file = directory.path() / "turn-secret";
  write_file(secret_file, std::string{test_turn_secret} + "\r\n");
  config.turn_secret_file = secret_file;
  auto from_file = load_relay_turn_secret(config);
  ASSERT_TRUE(from_file) << from_file.error_if()->safe_detail();
  EXPECT_EQ(*from_file.value_if(), test_turn_secret);

  // Interior CR/LF bytes make the secret invalid (only the trailing newline
  // artifact is tolerated); the detail never carries the secret itself.
  const std::string multiline_secret = "line-one\r\nline-two";
  write_file(secret_file, multiline_secret + "\r\n");
  auto multiline = load_relay_turn_secret(config);
  ASSERT_FALSE(multiline);
  EXPECT_EQ(multiline.error_if()->safe_detail(), "turn_secret_invalid");
  EXPECT_EQ(multiline.error_if()->safe_detail().find("line-one"), std::string::npos);

  // Too-short secret from the file.
  const std::string short_secret = "short";
  write_file(secret_file, short_secret);
  auto short_from_file = load_relay_turn_secret(config);
  ASSERT_FALSE(short_from_file);
  EXPECT_EQ(short_from_file.error_if()->safe_detail(), "turn_secret_invalid");
  EXPECT_EQ(short_from_file.error_if()->safe_detail().find(short_secret), std::string::npos);

  // Whitespace-bearing and too-short secrets from the environment.
  config.turn_secret_file.reset();
  guard.set(short_secret);
  auto short_from_environment = load_relay_turn_secret(config);
  ASSERT_FALSE(short_from_environment);
  EXPECT_EQ(short_from_environment.error_if()->safe_detail(), "turn_secret_invalid");
  EXPECT_EQ(short_from_environment.error_if()->safe_detail().find(short_secret), std::string::npos);

  const std::string spaced_secret = "has a space inside";
  guard.set(spaced_secret);
  auto spaced = load_relay_turn_secret(config);
  ASSERT_FALSE(spaced);
  EXPECT_EQ(spaced.error_if()->safe_detail(), "turn_secret_invalid");
  EXPECT_EQ(spaced.error_if()->safe_detail().find(spaced_secret), std::string::npos);

  // A secret file above the 4 KiB bound is unreadable, never truncated into
  // a usable secret.
  TemporaryDirectory oversized{"m3b-turn-ice-secret-oversized"};
  const auto big_file = oversized.path() / "turn-secret-big";
  write_file(big_file, std::string(4097U, 'x'));
  config.turn_secret_file = big_file;
  auto oversized_result = load_relay_turn_secret(config);
  ASSERT_FALSE(oversized_result);
  EXPECT_EQ(oversized_result.error_if()->safe_detail(), "turn_secret_file_unreadable");
  EXPECT_EQ(oversized_result.error_if()->safe_detail().find("xxxx"), std::string::npos);
}

// ---- B3: validate_relay_server_config turn bounds ----

TEST(M3BRelayTurnIceConfigTest, ValidatesTurnConfigurationBounds) {
  RelayServerConfig enabled;
  enabled.listen_address = "127.0.0.1";
  enabled.tls_certificate_file = std::filesystem::path{"cert.pem"};
  enabled.tls_private_key_file = std::filesystem::path{"key.pem"};

  RelayTurnAdvertisedServer advertised;
  advertised.kind = RelayWssIceServerKind::turn_udp;
  advertised.hostname = "turn.example.com";
  advertised.port = 3478U;

  // Enabled without any advertised server.
  enabled.turn_credentials_enabled = true;
  enabled.turn_credential_ttl = std::chrono::seconds{600};
  EXPECT_FALSE(validate_relay_server_config(enabled));

  // TTL bounds.
  enabled.turn_servers.push_back(advertised);
  enabled.turn_credential_ttl = std::chrono::seconds{0};
  EXPECT_FALSE(validate_relay_server_config(enabled));
  enabled.turn_credential_ttl = std::chrono::seconds{86401};
  EXPECT_FALSE(validate_relay_server_config(enabled));
  enabled.turn_credential_ttl = std::chrono::seconds{86400};
  auto valid = validate_relay_server_config(enabled);
  ASSERT_TRUE(valid) << valid.error_if()->safe_detail();

  // TURN/TLS is rejected: no pinned backend implements it.
  RelayServerConfig tls;
  tls.listen_address = enabled.listen_address;
  tls.tls_certificate_file = enabled.tls_certificate_file;
  tls.tls_private_key_file = enabled.tls_private_key_file;
  tls.turn_credentials_enabled = true;
  tls.turn_credential_ttl = std::chrono::seconds{600};
  RelayTurnAdvertisedServer turn_tls;
  turn_tls.kind = RelayWssIceServerKind::turn_tls;
  turn_tls.hostname = "turn.example.com";
  turn_tls.port = 5349U;
  tls.turn_servers.push_back(turn_tls);
  EXPECT_FALSE(validate_relay_server_config(tls));
}

// ---- C1/C2: enabled relay issues and refreshes REST credentials ----

TEST(M3BRelayTurnIceConfigTest, EnabledRelayIssuesAndRefreshesTurnCredentials) {
  TemporaryDirectory directory{"m3b-turn-ice-e2e"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  EnvironmentVariableGuard guard{std::string{relay_turn_secret_env}};
  guard.clear();

  auto config = server_config(directory.path());
  const std::uint32_t ttl_seconds = 600U;
  enable_turn_credentials(config, directory.path(), ttl_seconds);
  auto server = RelayServer::create(std::move(config));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until([&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));

  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  enroll_device_for_login(directory.path(), *identity.value_if());

  const auto login_started = now_unix_seconds();
  auto login = login_new_client(*server.value_if(), directory.path(), *identity.value_if(),
                                known_capability_bits);
  ASSERT_TRUE(login) << login.error_if()->safe_detail();
  ASSERT_TRUE(login.value_if()->result.has_value())
      << "login parse failed: " << login.value_if()->parse_detail;
  ASSERT_TRUE(login.value_if()->result->ice_config)
      << "login_result must carry ice_config for a modern client";
  const RelayWssIceConfig& issued = *login.value_if()->result->ice_config;

  // One entry per configured turn_servers URI.
  ASSERT_EQ(issued.servers.size(), 1U);
  EXPECT_EQ(issued.servers[0U].kind, RelayWssIceServerKind::turn_udp);
  EXPECT_EQ(issued.servers[0U].hostname, "127.0.0.1");
  EXPECT_EQ(issued.servers[0U].port, 3478U);

  // Username shape: <expiry>:<tenant>:<device-hex>, expiry strictly in the
  // future and within one TTL of now.
  const std::string& username = issued.servers[0U].username;
  const auto first_separator = username.find(':');
  const auto second_separator = first_separator == std::string::npos
                                    ? std::string::npos
                                    : username.find(':', first_separator + 1U);
  ASSERT_NE(first_separator, std::string::npos);
  ASSERT_NE(second_separator, std::string::npos);
  const std::string expiry_text = username.substr(0U, first_separator);
  const std::string tenant =
      username.substr(first_separator + 1U, second_separator - first_separator - 1U);
  const std::string device = username.substr(second_separator + 1U);
  ASSERT_FALSE(expiry_text.empty());
  EXPECT_TRUE(std::all_of(expiry_text.begin(), expiry_text.end(), [](unsigned char character) {
    return character >= '0' && character <= '9';
  }));
  const std::uint64_t expiry = std::stoull(expiry_text);
  EXPECT_EQ(tenant, "tenant-a");
  EXPECT_EQ(device, to_string(identity.value_if()->device_id()));
  EXPECT_GT(expiry, login_started);
  // The server's issue instant may tick one second past the captured
  // login_started, so the bound allows that skew.
  EXPECT_LE(expiry, login_started + ttl_seconds + 1U);
  EXPECT_EQ(issued.expires_unix_seconds, expiry);

  // The password verifies against an independent service seeded with the
  // same secret (coturn REST algorithm).
  auto validator = RelayTurnCredentialService::create(RelayTurnSecretConfig{
      .max_secrets = 4U, .credential_ttl = std::chrono::seconds{ttl_seconds}});
  ASSERT_TRUE(validator) << validator.error_if()->safe_detail();
  ASSERT_TRUE(validator.value_if()->set_secret(1U, test_turn_secret, login_started));
  const auto validated =
      validator.value_if()->validate(username, issued.servers[0U].credential, now_unix_seconds());
  ASSERT_TRUE(validated) << validated.error_if()->safe_detail();
  EXPECT_EQ(*validated.value_if(), 1U);

  // Heartbeat refresh: ice_config present again, same URI, expiry not earlier
  // than the login issuance.
  auto client = connect_control_client(directory.path(), server.value_if()->snapshot().listen_port);
  ASSERT_TRUE(client) << client.error_if()->safe_detail();
  auto exchange =
      login_then_heartbeat(*client.value_if(), *identity.value_if(), known_capability_bits);
  ASSERT_TRUE(exchange) << exchange.error_if()->safe_detail();
  ASSERT_TRUE(exchange.value_if()->login.ice_config);
  ASSERT_TRUE(exchange.value_if()->ack.ice_config)
      << "heartbeat_ack must refresh the relay-issued ICE configuration";
  EXPECT_EQ(exchange.value_if()->ack.ice_config->servers.size(), 1U);
  EXPECT_EQ(exchange.value_if()->ack.ice_config->servers[0U].kind, RelayWssIceServerKind::turn_udp);
  EXPECT_EQ(exchange.value_if()->ack.ice_config->servers[0U].hostname, "127.0.0.1");
  EXPECT_EQ(exchange.value_if()->ack.ice_config->servers[0U].port, 3478U);
  EXPECT_GE(exchange.value_if()->ack.ice_config->expires_unix_seconds,
            exchange.value_if()->login.ice_config->expires_unix_seconds);
  EXPECT_GT(exchange.value_if()->ack.ice_config->expires_unix_seconds, now_unix_seconds());
  EXPECT_TRUE(client.value_if()->close(3s));

  // Server-side accounting: three issues (helper login, heartbeat login,
  // heartbeat), zero failures.
  const auto snapshot = server.value_if()->snapshot();
  EXPECT_EQ(snapshot.turn.issued, 3U);
  EXPECT_EQ(snapshot.turn_issue_failures, 0U);

  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

// Mixed turn/stun turn_servers: the TURN entry carries the REST credential,
// the stun entry stays anonymous, and the whole login_result passes the
// device-side wire codec. Regression pin for the 2026-10-07 verification
// defect (issuance used to attach the credential to stun entries, producing a
// payload the client parser rejected and failing every login cycle).
TEST(M3BRelayTurnIceConfigTest, StunAdvertisedEntryIsIssuedWithoutCredentials) {
  TemporaryDirectory directory{"m3b-turn-ice-stun-mixed"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  EnvironmentVariableGuard guard{std::string{relay_turn_secret_env}};
  guard.clear();

  auto config = server_config(directory.path());
  enable_turn_credentials(config, directory.path());
  RelayTurnAdvertisedServer advertised_stun;
  advertised_stun.kind = RelayWssIceServerKind::stun;
  advertised_stun.hostname = "stun.example.com";
  advertised_stun.port = 3479U;
  config.turn_servers.push_back(advertised_stun);
  auto server = RelayServer::create(std::move(config));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until([&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));

  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  enroll_device_for_login(directory.path(), *identity.value_if());
  auto login = login_new_client(*server.value_if(), directory.path(), *identity.value_if(),
                                known_capability_bits);
  ASSERT_TRUE(login) << login.error_if()->safe_detail();
  ASSERT_TRUE(login.value_if()->result.has_value())
      << "the device-side codec rejected the login_result: " << login.value_if()->parse_detail;
  ASSERT_TRUE(login.value_if()->result->ice_config);
  ASSERT_EQ(login.value_if()->result->ice_config->servers.size(), 2U);

  // TURN entry: credential-bearing and verifiable against the shared secret.
  const RelayWssIceServer& turn_entry = login.value_if()->result->ice_config->servers[0U];
  EXPECT_EQ(turn_entry.kind, RelayWssIceServerKind::turn_udp);
  EXPECT_EQ(turn_entry.hostname, "127.0.0.1");
  EXPECT_EQ(turn_entry.port, 3478U);
  EXPECT_FALSE(turn_entry.username.empty());
  EXPECT_FALSE(turn_entry.credential.empty());
  auto validator = RelayTurnCredentialService::create(
      RelayTurnSecretConfig{.max_secrets = 4U, .credential_ttl = std::chrono::seconds{600}});
  ASSERT_TRUE(validator) << validator.error_if()->safe_detail();
  ASSERT_TRUE(validator.value_if()->set_secret(1U, test_turn_secret, now_unix_seconds()));
  const auto validated = validator.value_if()->validate(turn_entry.username, turn_entry.credential,
                                                        now_unix_seconds());
  ASSERT_TRUE(validated) << validated.error_if()->safe_detail();

  // STUN entry: anonymous, per the wire contract.
  const RelayWssIceServer& stun_entry = login.value_if()->result->ice_config->servers[1U];
  EXPECT_EQ(stun_entry.kind, RelayWssIceServerKind::stun);
  EXPECT_EQ(stun_entry.hostname, "stun.example.com");
  EXPECT_EQ(stun_entry.port, 3479U);
  EXPECT_TRUE(stun_entry.username.empty());
  EXPECT_TRUE(stun_entry.credential.empty());

  // End to end: the client-side codec parses the exact payload the relay
  // sent.
  auto reparsed = parse_relay_wss_login_result(login.value_if()->payload);
  ASSERT_TRUE(reparsed) << reparsed.error_if()->safe_detail();
  ASSERT_TRUE(reparsed.value_if()->ice_config);
  ASSERT_EQ(reparsed.value_if()->ice_config->servers.size(), 2U);
  EXPECT_FALSE(reparsed.value_if()->ice_config->servers[0U].username.empty());
  EXPECT_TRUE(reparsed.value_if()->ice_config->servers[1U].username.empty());

  // The heartbeat refresh keeps the same shape.
  auto client = connect_control_client(directory.path(), server.value_if()->snapshot().listen_port);
  ASSERT_TRUE(client) << client.error_if()->safe_detail();
  auto exchange =
      login_then_heartbeat(*client.value_if(), *identity.value_if(), known_capability_bits);
  ASSERT_TRUE(exchange) << exchange.error_if()->safe_detail();
  ASSERT_TRUE(exchange.value_if()->ack.ice_config);
  ASSERT_EQ(exchange.value_if()->ack.ice_config->servers.size(), 2U);
  EXPECT_EQ(exchange.value_if()->ack.ice_config->servers[1U].kind, RelayWssIceServerKind::stun);
  EXPECT_TRUE(exchange.value_if()->ack.ice_config->servers[1U].username.empty());
  EXPECT_TRUE(exchange.value_if()->ack.ice_config->servers[1U].credential.empty());
  EXPECT_FALSE(exchange.value_if()->ack.ice_config->servers[0U].username.empty());
  EXPECT_TRUE(client.value_if()->close(3s));

  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

// ---- C3: disabled relay keeps the payload ice_config-free ----

TEST(M3BRelayTurnIceConfigTest, DisabledRelayOmitsIceConfig) {
  TemporaryDirectory directory{"m3b-turn-ice-disabled"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  enroll_device_for_login(directory.path(), *identity.value_if());

  auto server = RelayServer::create(server_config(directory.path()));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until([&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));

  auto login = login_new_client(*server.value_if(), directory.path(), *identity.value_if(),
                                known_capability_bits);
  ASSERT_TRUE(login) << login.error_if()->safe_detail();
  EXPECT_FALSE(login.value_if()->result->ice_config.has_value());

  auto client = connect_control_client(directory.path(), server.value_if()->snapshot().listen_port);
  ASSERT_TRUE(client) << client.error_if()->safe_detail();
  auto exchange =
      login_then_heartbeat(*client.value_if(), *identity.value_if(), known_capability_bits);
  ASSERT_TRUE(exchange) << exchange.error_if()->safe_detail();
  EXPECT_FALSE(exchange.value_if()->login.ice_config.has_value());
  EXPECT_FALSE(exchange.value_if()->ack.ice_config.has_value());
  EXPECT_TRUE(client.value_if()->close(3s));
  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

// ---- C4: legacy clients without the capability bit never see ice_config ----

TEST(M3BRelayTurnIceConfigTest, LegacyClientReceivesNoIceConfig) {
  TemporaryDirectory directory{"m3b-turn-ice-legacy"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  EnvironmentVariableGuard guard{std::string{relay_turn_secret_env}};
  guard.clear();

  auto config = server_config(directory.path());
  enable_turn_credentials(config, directory.path());
  auto server = RelayServer::create(std::move(config));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until([&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));

  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  enroll_device_for_login(directory.path(), *identity.value_if());

  const std::uint64_t legacy_bits =
      known_capability_bits & ~static_cast<std::uint64_t>(Capability::relay_ice_config_v1);
  auto login =
      login_new_client(*server.value_if(), directory.path(), *identity.value_if(), legacy_bits);
  ASSERT_TRUE(login) << login.error_if()->safe_detail();
  EXPECT_FALSE(login.value_if()->result->ice_config.has_value());

  const auto snapshot = server.value_if()->snapshot();
  EXPECT_EQ(snapshot.turn_issue_failures, 0U);

  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

// ---- C5: create fails fast when enabled without a resolvable secret ----

TEST(M3BRelayTurnIceConfigTest, CreateFailsFastWithoutTurnSecret) {
  TemporaryDirectory directory{"m3b-turn-ice-no-secret"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  EnvironmentVariableGuard guard{std::string{relay_turn_secret_env}};
  guard.clear();

  auto config = server_config(directory.path());
  RelayTurnAdvertisedServer advertised;
  advertised.kind = RelayWssIceServerKind::turn_udp;
  advertised.hostname = "127.0.0.1";
  advertised.port = 3478U;
  config.turn_credentials_enabled = true;
  config.turn_credential_ttl = std::chrono::seconds{600};
  config.turn_servers.push_back(advertised);
  ASSERT_FALSE(config.turn_secret_file.has_value());

  auto created = RelayServer::create(std::move(config));
  ASSERT_FALSE(created);
  EXPECT_EQ(created.error_if()->safe_detail(), "turn_secret_unavailable");
}

// ---- C6: issued credentials never reach logs or the Prometheus export ----

TEST(M3BRelayTurnIceConfigTest, IssuedCredentialsNeverLeakIntoLogsOrMetrics) {
  TemporaryDirectory directory{"m3b-turn-ice-leak"};
  ASSERT_TRUE(write_test_certificate(directory.path()));
  EnvironmentVariableGuard guard{std::string{relay_turn_secret_env}};
  guard.clear();

  auto collector = std::make_shared<LogCollector>();
  auto config = server_config(directory.path());
  enable_turn_credentials(config, directory.path());
  config.log_sink = [collector](const RelayLogRecord& record) { collector->append(record); };
  auto server = RelayServer::create(std::move(config));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until([&] { return server.value_if()->snapshot().listen_port != 0U; }, 2s));

  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  enroll_device_for_login(directory.path(), *identity.value_if());

  auto login = login_new_client(*server.value_if(), directory.path(), *identity.value_if(),
                                known_capability_bits);
  ASSERT_TRUE(login) << login.error_if()->safe_detail();
  ASSERT_TRUE(login.value_if()->result->ice_config);
  std::vector<std::string> secrets;
  secrets.push_back(login.value_if()->result->ice_config->servers[0U].username);
  secrets.push_back(login.value_if()->result->ice_config->servers[0U].credential);
  secrets.push_back(std::string{test_turn_secret});

  auto client = connect_control_client(directory.path(), server.value_if()->snapshot().listen_port);
  ASSERT_TRUE(client) << client.error_if()->safe_detail();
  auto exchange =
      login_then_heartbeat(*client.value_if(), *identity.value_if(), known_capability_bits);
  ASSERT_TRUE(exchange) << exchange.error_if()->safe_detail();
  ASSERT_TRUE(exchange.value_if()->ack.ice_config);
  secrets.push_back(exchange.value_if()->ack.ice_config->servers[0U].username);
  secrets.push_back(exchange.value_if()->ack.ice_config->servers[0U].credential);
  EXPECT_TRUE(client.value_if()->close(3s));

  const auto snapshot = server.value_if()->snapshot();
  const auto prometheus = format_relay_metrics_prometheus(snapshot);
  EXPECT_NE(prometheus.find("heyaki_relay_turn_credentials_issued_total"), std::string::npos);

  for (const auto& record : collector->records()) {
    for (const auto& secret : secrets) {
      EXPECT_EQ(record.detail.find(secret), std::string::npos)
          << "credential material leaked into log detail";
      EXPECT_EQ(record.tenant.find(secret), std::string::npos)
          << "credential material leaked into log tenant";
    }
  }
  for (const auto& secret : secrets) {
    EXPECT_EQ(prometheus.find(secret), std::string::npos)
        << "credential material leaked into the Prometheus export";
  }

  EXPECT_TRUE(server.value_if()->shutdown().stopped);
}

}  // namespace
}  // namespace heyaki
