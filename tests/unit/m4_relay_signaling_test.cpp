// M4 round 2: relay signaling forwarding over the real TLS/WSS control plane and the
// unified SignalingCoordinator running end to end through RelaySignalingRoute.

#include "relay_database.hpp"
#include "relay_enrollment.hpp"
#include "relay_login.hpp"
#include "relay_server.hpp"
#include "relay_signaling_route.hpp"
#include "relay_wss_client.hpp"
#include "signaling_coordinator.hpp"

#include <heyaki/identity.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/relay_wss_control.hpp>
#include <heyaki/signaling_protocol.hpp>

#include <heyaki/relay/v1/relay_control.pb.h>

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
#include <cstring>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
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

constexpr std::string_view test_state_dir = HEYAKI_M4_TEST_STATE_DIR;

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
               PEM_write_bio_PrivateKey(
                   key_output, key, nullptr, nullptr, 0, nullptr, nullptr) == 1;
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
  config.runtime.worker_name = "heyaki-m4-relay-signaling-test";
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
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

Result<RelayWssControlFrame> receive_control(RelayWssClient& client,
                                             std::chrono::milliseconds timeout = 3s) {
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

Result<void> send_control(RelayWssClient& client, RelayWssControlType type,
                          std::span<const std::byte> payload = {}) {
  auto frame = encode_relay_wss_control_frame(type, payload);
  if (!frame) {
    return Result<void>::failure(*frame.error_if());
  }
  return client.send(*frame.value_if());
}

Result<RelayWssClient> connect_control_client(const std::filesystem::path& root,
                                              std::uint16_t port,
                                              std::string_view worker_name) {
  auto pin = certificate_pin(root / "test-only-cert.pem");
  if (!pin) {
    return Result<RelayWssClient>::failure(
        Error{ErrorCode::internal, "test", "certificate_pin_failed"});
  }
  RelayWssClientConfig config;
  config.url =
      "wss://127.0.0.1:" + std::to_string(port) + std::string{relay_wss_control_path};
  config.relay_pin = pin;
  config.tls_verify_peer = false;
  config.runtime.worker_name = worker_name;
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

// Runs the full auto-login challenge round on an open control client.
Result<void> login_client(RelayWssClient& client, const IdentityKeyPair& identity,
                          std::uint64_t generation, std::uint64_t now,
                          std::uint8_t endpoint_byte,
                          std::string_view tenant = "tenant-a") {
  auto sent = send_control(client, RelayWssControlType::login_challenge);
  if (!sent) {
    return sent;
  }
  auto challenge_frame = receive_control(client);
  if (!challenge_frame ||
      challenge_frame.value_if()->type != RelayWssControlType::login_challenge_response) {
    return Result<void>::failure(
        challenge_frame ? Error{ErrorCode::protocol, "test", "login_challenge_unexpected"}
                        : *challenge_frame.error_if());
  }
  auto challenge = parse_enrollment_challenge(challenge_frame.value_if()->payload);
  if (!challenge) {
    return Result<void>::failure(*challenge.error_if());
  }
  auto login = make_login_request(identity, *challenge.value_if(), generation, now,
                                  endpoint_byte, tenant);
  if (!login) {
    return Result<void>::failure(*login.error_if());
  }
  auto login_bytes = encode_relay_login_request(*login.value_if());
  if (!login_bytes) {
    return Result<void>::failure(*login_bytes.error_if());
  }
  sent = send_control(client, RelayWssControlType::login_request, *login_bytes.value_if());
  if (!sent) {
    return sent;
  }
  auto login_frame = receive_control(client);
  if (!login_frame || login_frame.value_if()->type != RelayWssControlType::login_result) {
    return Result<void>::failure(
        login_frame ? Error{ErrorCode::protocol, "test", "login_result_unexpected"}
                    : *login_frame.error_if());
  }
  return Result<void>::success();
}

void enroll_device_record(const std::filesystem::path& database_path,
                          const IdentityKeyPair& identity, std::string_view tenant) {
  auto database = RelayDatabase::open(database_path);
  ASSERT_TRUE(database) << database.error_if()->safe_detail();
  RelayDeviceRecord device;
  device.device_id = identity.device_id();
  device.public_key = identity.public_key();
  device.tenant = std::string{tenant};
  device.display_name = "device";
  device.enrollment_generation = 1U;
  device.status = RelayDeviceStatus::active;
  ASSERT_TRUE(database.value_if()->enroll_device(device, now_milliseconds()));
}

RelayWssSignalingSend sample_send() {
  DeviceId::Storage target_device{};
  target_device[0] = std::byte{0x21U};
  EndpointId::Storage target_endpoint{};
  target_endpoint[0] = std::byte{0x22U};
  RequestId::Storage request{};
  request[0] = std::byte{0x23U};
  RelayWssSignalingSend send;
  send.target_device_id = DeviceId{target_device};
  send.target_endpoint_id = EndpointId{target_endpoint};
  send.kind = static_cast<std::uint8_t>(LanSignalingMessageKind::connect_request);
  send.request_id = RequestId{request};
  return send;
}

TEST(M4RelaySignaling, CodecRoundTripAndRejections) {
  auto send = sample_send();
  auto encoded = encode_relay_wss_signaling_send(send);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();
  auto parsed = parse_relay_wss_signaling_send(*encoded.value_if());
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  EXPECT_EQ(parsed.value_if()->target_device_id, send.target_device_id);
  EXPECT_EQ(parsed.value_if()->kind, send.kind);
  EXPECT_EQ(parsed.value_if()->request_id, send.request_id);
  EXPECT_TRUE(parsed.value_if()->payload.empty());

  // Hand-rolled bytes match the normative Protobuf Lite encoding.
  protocol::relay::v1::SignalingSend protobuf;
  protobuf.set_target_device_id(send.target_device_id.bytes().data(),
                                send.target_device_id.bytes().size());
  protobuf.set_target_endpoint_id(send.target_endpoint_id.bytes().data(),
                                  send.target_endpoint_id.bytes().size());
  protobuf.set_kind(send.kind);
  protobuf.set_request_id(send.request_id.bytes().data(),
                          send.request_id.bytes().size());
  const std::string protobuf_bytes = protobuf.SerializeAsString();
  const std::vector<std::byte> protobuf_encoded{
      reinterpret_cast<const std::byte*>(protobuf_bytes.data()),
      reinterpret_cast<const std::byte*>(protobuf_bytes.data()) + protobuf_bytes.size()};
  EXPECT_EQ(*encoded.value_if(), protobuf_encoded);

  RelayWssSignalingDeliver deliver;
  deliver.source_device_id = send.target_device_id;
  deliver.source_endpoint_id = send.target_endpoint_id;
  deliver.kind = static_cast<std::uint8_t>(LanSignalingMessageKind::signed_offer);
  deliver.request_id = send.request_id;
  deliver.payload = {std::byte{1U}, std::byte{2U}, std::byte{3U}};
  auto deliver_encoded = encode_relay_wss_signaling_deliver(deliver);
  ASSERT_TRUE(deliver_encoded) << deliver_encoded.error_if()->safe_detail();
  auto deliver_parsed = parse_relay_wss_signaling_deliver(*deliver_encoded.value_if());
  ASSERT_TRUE(deliver_parsed) << deliver_parsed.error_if()->safe_detail();
  EXPECT_EQ(deliver_parsed.value_if()->payload, deliver.payload);

  // Rejections: truncation, trailing bytes, zero identities, zero kind, oversized payload.
  auto truncated = *encoded.value_if();
  truncated.pop_back();
  EXPECT_FALSE(parse_relay_wss_signaling_send(truncated));
  auto trailing = *encoded.value_if();
  trailing.push_back(std::byte{0U});
  EXPECT_FALSE(parse_relay_wss_signaling_send(trailing));
  auto zero_request = send;
  zero_request.request_id = RequestId{};
  EXPECT_FALSE(encode_relay_wss_signaling_send(zero_request));
  auto zero_kind = send;
  zero_kind.kind = 0U;
  EXPECT_FALSE(encode_relay_wss_signaling_send(zero_kind));
  auto oversized = sample_send();
  oversized.kind = static_cast<std::uint8_t>(LanSignalingMessageKind::signed_candidate);
  oversized.payload.assign(max_signaling_object_bytes + 1U, std::byte{0U});
  EXPECT_FALSE(encode_relay_wss_signaling_send(oversized));
  EXPECT_FALSE(parse_relay_wss_signaling_send({}));
}

struct RelayFixture {
  TemporaryDirectory directory;
  std::optional<Result<RelayServer>> server;
  std::uint16_t port{};
  bool ready{false};

  explicit RelayFixture(std::string_view name, std::size_t signaling_rate = 32U)
      : directory{name} {
    if (!write_test_certificate(directory.path())) {
      return;
    }
    auto config = server_config(directory.path());
    config.signaling_rate_per_second = signaling_rate;
    server = RelayServer::create(std::move(config));
    if (!server->has_value()) {
      return;
    }
    ready = wait_until(
        [&] { return (*server).value_if()->snapshot().listen_port != 0U; }, 2s);
    port = (*server).value_if()->snapshot().listen_port;
  }

  ~RelayFixture() {
    if (ready) {
      (void)(*server).value_if()->shutdown();
    }
  }
};

#define ASSERT_RELAY_READY(fixture)                         \
  ASSERT_TRUE((fixture).ready) << "relay fixture not ready"

TEST(M4RelaySignaling, ForwardsBetweenLoggedInEndpoints) {
  RelayFixture relay{"m4-relay-forward"};
  ASSERT_RELAY_READY(relay);
  auto identity_a = create_identity();
  auto identity_b = create_identity();
  ASSERT_TRUE(identity_a && identity_b);
  enroll_device_record(relay.directory.path() / "relay.sqlite", *identity_a.value_if(),
                       "tenant-a");
  enroll_device_record(relay.directory.path() / "relay.sqlite", *identity_b.value_if(),
                       "tenant-a");
  const auto now = now_milliseconds();

  auto client_a = connect_control_client(relay.directory.path(), relay.port,
                                         "heyaki-m4-relay-client-a");
  auto client_b = connect_control_client(relay.directory.path(), relay.port,
                                         "heyaki-m4-relay-client-b");
  ASSERT_TRUE(client_a && client_b);
  ASSERT_TRUE(login_client(*client_a.value_if(), *identity_a.value_if(), 1U, now, 0x31U));
  ASSERT_TRUE(login_client(*client_b.value_if(), *identity_b.value_if(), 1U, now, 0x32U));

  auto send = sample_send();
  send.target_device_id = identity_b.value_if()->device_id();
  EndpointId::Storage target_endpoint{};
  target_endpoint[0] = std::byte{0x32U};
  send.target_endpoint_id = EndpointId{target_endpoint};
  auto payload = encode_relay_wss_signaling_send(send);
  ASSERT_TRUE(payload);
  ASSERT_TRUE(send_control(*client_a.value_if(), RelayWssControlType::signaling_send,
                           *payload.value_if()));

  auto delivered = receive_control(*client_b.value_if());
  ASSERT_TRUE(delivered) << delivered.error_if()->safe_detail();
  ASSERT_EQ(delivered.value_if()->type, RelayWssControlType::signaling_deliver);
  auto envelope =
      RelaySignalingRoute::decode_delivery(delivered.value_if()->payload);
  ASSERT_TRUE(envelope) << envelope.error_if()->safe_detail();
  EXPECT_EQ(envelope.value_if()->peer.device_id, identity_a.value_if()->device_id());
  EndpointId::Storage source_endpoint{};
  source_endpoint[0] = std::byte{0x31U};
  EXPECT_EQ(envelope.value_if()->peer.endpoint_id, EndpointId{source_endpoint});
  EXPECT_EQ(envelope.value_if()->kind, LanSignalingMessageKind::connect_request);
  EXPECT_EQ(envelope.value_if()->request_id, send.request_id);
  EXPECT_TRUE(envelope.value_if()->payload.empty());

  const auto snapshot = (*relay.server).value_if()->snapshot();
  EXPECT_GE(snapshot.signaling_forwarded, 1U);

  ASSERT_TRUE(client_a.value_if()->close(3s));
  ASSERT_TRUE(client_b.value_if()->close(3s));
}

TEST(M4RelaySignaling, OfflineTargetReturnsEndpointOffline) {
  RelayFixture relay{"m4-relay-offline"};
  ASSERT_RELAY_READY(relay);
  auto identity_a = create_identity();
  ASSERT_TRUE(identity_a);
  enroll_device_record(relay.directory.path() / "relay.sqlite", *identity_a.value_if(),
                       "tenant-a");
  const auto now = now_milliseconds();
  auto client_a = connect_control_client(relay.directory.path(), relay.port,
                                         "heyaki-m4-relay-client-a");
  ASSERT_TRUE(client_a);
  ASSERT_TRUE(login_client(*client_a.value_if(), *identity_a.value_if(), 1U, now, 0x31U));

  auto send = sample_send();
  send.target_device_id = identity_a.value_if()->device_id();
  EndpointId::Storage missing_endpoint{};
  missing_endpoint[0] = std::byte{0x99U};
  send.target_endpoint_id = EndpointId{missing_endpoint};
  auto payload = encode_relay_wss_signaling_send(send);
  ASSERT_TRUE(payload);
  ASSERT_TRUE(send_control(*client_a.value_if(), RelayWssControlType::signaling_send,
                           *payload.value_if()));
  auto error_frame = receive_control(*client_a.value_if());
  ASSERT_TRUE(error_frame) << error_frame.error_if()->safe_detail();
  ASSERT_EQ(error_frame.value_if()->type, RelayWssControlType::control_error);
  auto error = parse_relay_wss_control_error(error_frame.value_if()->payload);
  ASSERT_TRUE(error);
  EXPECT_EQ(error.value_if()->code, ErrorCode::endpoint_offline);
  EXPECT_GE((*relay.server).value_if()->snapshot().signaling_rejected, 1U);
  ASSERT_TRUE(client_a.value_if()->close(3s));
}

TEST(M4RelaySignaling, RejectsUnknownKindAndPayloadPolicyViolations) {
  RelayFixture relay{"m4-relay-policy"};
  ASSERT_RELAY_READY(relay);
  auto identity = create_identity();
  ASSERT_TRUE(identity);
  enroll_device_record(relay.directory.path() / "relay.sqlite", *identity.value_if(),
                       "tenant-a");

  // Protocol-misuse errors close the control session, so each case uses a fresh client.
  const auto expect_close_error = [&](RelayWssSignalingSend send, ErrorCode expected) {
    auto client = connect_control_client(relay.directory.path(), relay.port,
                                         "heyaki-m4-relay-policy-client");
    ASSERT_TRUE(client);
    ASSERT_TRUE(login_client(*client.value_if(), *identity.value_if(), 1U,
                             now_milliseconds(), 0x41U));
    auto payload = encode_relay_wss_signaling_send(send);
    ASSERT_TRUE(payload);
    auto sent_ok = send_control(*client.value_if(), RelayWssControlType::signaling_send,
                                *payload.value_if());
    EXPECT_TRUE(sent_ok);
    auto frame = receive_control(*client.value_if());
    ASSERT_TRUE(frame) << frame.error_if()->safe_detail();
    ASSERT_EQ(frame.value_if()->type, RelayWssControlType::control_error);
    auto error = parse_relay_wss_control_error(frame.value_if()->payload);
    ASSERT_TRUE(error);
    EXPECT_EQ(error.value_if()->code, expected);
    // The server closes the session after the protocol error.
    auto after_close = client.value_if()->receive(2s);
    EXPECT_FALSE(after_close.has_value());
  };

  EndpointId::Storage self_endpoint{};
  self_endpoint[0] = std::byte{0x41U};
  auto target = identity.value_if()->device_id();

  auto unknown_kind = sample_send();
  unknown_kind.target_device_id = target;
  unknown_kind.target_endpoint_id = EndpointId{self_endpoint};
  unknown_kind.kind = 9U;
  expect_close_error(unknown_kind, ErrorCode::protocol);

  auto control_with_payload = sample_send();
  control_with_payload.target_device_id = target;
  control_with_payload.target_endpoint_id = EndpointId{self_endpoint};
  control_with_payload.payload = {std::byte{1U}};
  expect_close_error(control_with_payload, ErrorCode::protocol);

  auto empty_signed = sample_send();
  empty_signed.target_device_id = target;
  empty_signed.target_endpoint_id = EndpointId{self_endpoint};
  empty_signed.kind = static_cast<std::uint8_t>(LanSignalingMessageKind::signed_offer);
  expect_close_error(empty_signed, ErrorCode::protocol);
}

TEST(M4RelaySignaling, TenantIsolationAndRateLimit) {
  RelayFixture relay{"m4-relay-tenant-rate", /*signaling_rate=*/2U};
  ASSERT_RELAY_READY(relay);
  auto identity_a = create_identity();
  auto identity_b = create_identity();
  ASSERT_TRUE(identity_a && identity_b);
  enroll_device_record(relay.directory.path() / "relay.sqlite", *identity_a.value_if(),
                       "tenant-a");
  enroll_device_record(relay.directory.path() / "relay.sqlite", *identity_b.value_if(),
                       "tenant-b");
  const auto now = now_milliseconds();
  auto client_a = connect_control_client(relay.directory.path(), relay.port,
                                         "heyaki-m4-relay-tenant-a");
  auto client_b = connect_control_client(relay.directory.path(), relay.port,
                                         "heyaki-m4-relay-tenant-b");
  ASSERT_TRUE(client_a && client_b);
  ASSERT_TRUE(login_client(*client_a.value_if(), *identity_a.value_if(), 1U, now, 0x51U,
                          "tenant-a"));
  ASSERT_TRUE(login_client(*client_b.value_if(), *identity_b.value_if(), 1U, now, 0x52U,
                          "tenant-b"));

  auto cross_tenant = sample_send();
  cross_tenant.target_device_id = identity_b.value_if()->device_id();
  EndpointId::Storage endpoint_b{};
  endpoint_b[0] = std::byte{0x52U};
  cross_tenant.target_endpoint_id = EndpointId{endpoint_b};
  auto payload = encode_relay_wss_signaling_send(cross_tenant);
  ASSERT_TRUE(payload);
  ASSERT_TRUE(send_control(*client_a.value_if(), RelayWssControlType::signaling_send,
                           *payload.value_if()));
  auto denied = receive_control(*client_a.value_if());
  ASSERT_TRUE(denied);
  ASSERT_EQ(denied.value_if()->type, RelayWssControlType::control_error);
  auto denial = parse_relay_wss_control_error(denied.value_if()->payload);
  ASSERT_TRUE(denial);
  EXPECT_EQ(denial.value_if()->code, ErrorCode::permission);

  // Same-tenant flood: the third send within one second hits the rate limit.
  auto self = sample_send();
  self.target_device_id = identity_a.value_if()->device_id();
  EndpointId::Storage endpoint_a{};
  endpoint_a[0] = std::byte{0x51U};
  self.target_endpoint_id = EndpointId{endpoint_a};
  auto self_payload = encode_relay_wss_signaling_send(self);
  ASSERT_TRUE(self_payload);
  // The cross-tenant denial already consumed one slot of the per-second window, so one
  // self-send is delivered and the next is rate limited.
  ASSERT_TRUE(send_control(*client_a.value_if(), RelayWssControlType::signaling_send,
                           *self_payload.value_if()));
  auto delivered = receive_control(*client_a.value_if());
  ASSERT_TRUE(delivered);
  ASSERT_EQ(delivered.value_if()->type, RelayWssControlType::signaling_deliver);
  ASSERT_TRUE(send_control(*client_a.value_if(), RelayWssControlType::signaling_send,
                           *self_payload.value_if()));
  auto limited = receive_control(*client_a.value_if());
  ASSERT_TRUE(limited);
  ASSERT_EQ(limited.value_if()->type, RelayWssControlType::control_error);
  auto rate_error = parse_relay_wss_control_error(limited.value_if()->payload);
  ASSERT_TRUE(rate_error);
  EXPECT_EQ(rate_error.value_if()->code, ErrorCode::resource_exhausted);
  // The server coalesces snapshot publication to handler exit: the error
  // frame can reach this client before the counter flush lands, so poll the
  // bounded window instead of racing one read.
  const auto counter_deadline = std::chrono::steady_clock::now() + 2s;
  while ((*relay.server).value_if()->snapshot().signaling_rejected < 2U ||
         (*relay.server).value_if()->snapshot().signaling_forwarded < 1U) {
    if (std::chrono::steady_clock::now() > counter_deadline) {
      break;
    }
    std::this_thread::sleep_for(2ms);
  }
  EXPECT_GE((*relay.server).value_if()->snapshot().signaling_rejected, 2U);
  EXPECT_GE((*relay.server).value_if()->snapshot().signaling_forwarded, 1U);

  ASSERT_TRUE(client_a.value_if()->close(3s));
  ASSERT_TRUE(client_b.value_if()->close(3s));
}

TEST(M4RelaySignaling, CoordinatorHandshakeOverRelayRoute) {
  RelayFixture relay{"m4-relay-coordinator"};
  ASSERT_RELAY_READY(relay);
  auto identity_a = create_identity();
  auto identity_b = create_identity();
  ASSERT_TRUE(identity_a && identity_b);
  enroll_device_record(relay.directory.path() / "relay.sqlite", *identity_a.value_if(),
                       "tenant-a");
  enroll_device_record(relay.directory.path() / "relay.sqlite", *identity_b.value_if(),
                       "tenant-a");
  const auto now = now_milliseconds();
  auto client_a = connect_control_client(relay.directory.path(), relay.port,
                                         "heyaki-m4-coord-a");
  auto client_b = connect_control_client(relay.directory.path(), relay.port,
                                         "heyaki-m4-coord-b");
  ASSERT_TRUE(client_a && client_b);
  ASSERT_TRUE(login_client(*client_a.value_if(), *identity_a.value_if(), 1U, now, 0x61U));
  ASSERT_TRUE(login_client(*client_b.value_if(), *identity_b.value_if(), 1U, now, 0x62U));

  struct CoordinatorPeer {
    std::optional<IdentityKeyPair> identity;
    DeviceEndpointKey self;
    std::shared_ptr<SignalingDelegate> delegate = std::make_shared<SignalingDelegate>();
    std::optional<SignalingCoordinator> coordinator;
    RelaySignalingRoute route{DeviceEndpointKey{}, nullptr};
    bool accepted = false;
    bool offer_verified = false;
    bool answer_verified = false;
    bool candidate_received = false;
    std::optional<RequestId> request;

    void init(std::uint8_t endpoint_byte) {
      self.device_id = identity->device_id();
      EndpointId::Storage endpoint{};
      endpoint[0] = static_cast<std::byte>(endpoint_byte);
      self.endpoint_id = EndpointId{endpoint};
      SignalingCoordinatorConfig config;
      config.local = self;
      config.identity = &*identity;
      auto created = SignalingCoordinator::create(config, delegate);
      ASSERT_TRUE(created.has_value());
      coordinator = std::move(*created.value_if());
    }
  };

  CoordinatorPeer peer_a;
  CoordinatorPeer peer_b;
  peer_a.identity = std::move(*identity_a.value_if());
  peer_b.identity = std::move(*identity_b.value_if());
  peer_a.init(0x61U);
  peer_b.init(0x62U);

  peer_a.delegate->peer_identity = [&](const DeviceEndpointKey& key) {
    return key == peer_b.self ? std::optional{peer_b.identity->public_key()}
                              : std::nullopt;
  };
  peer_b.delegate->peer_identity = [&](const DeviceEndpointKey& key) {
    return key == peer_a.self ? std::optional{peer_a.identity->public_key()}
                              : std::nullopt;
  };
  peer_b.delegate->on_inbound_connect = [&](const SignalingAttemptSnapshot&) {
    return true;
  };
  peer_a.delegate->on_outbound_accepted = [&](const SignalingAttemptSnapshot&) {
    peer_a.accepted = true;
  };
  peer_b.delegate->on_verified_offer = [&](const SignalingAttemptSnapshot&,
                                           const SignedOffer&) {
    peer_b.offer_verified = true;
  };
  peer_a.delegate->on_verified_answer = [&](const SignalingAttemptSnapshot&,
                                            const SignedAnswer&,
                                            const SignalingTranscriptSha256&) {
    peer_a.answer_verified = true;
  };
  peer_a.delegate->on_verified_candidate = [&](const SignalingAttemptSnapshot&,
                                               const SignedCandidate&) {
    peer_a.candidate_received = true;
  };
  peer_b.delegate->on_verified_candidate = [&](const SignalingAttemptSnapshot&,
                                               const SignedCandidate&) {
    peer_b.candidate_received = true;
  };

  RelayWssClient* a_client = client_a.value_if();
  RelayWssClient* b_client = client_b.value_if();
  peer_a.route = RelaySignalingRoute{
      peer_a.self, [a_client](std::span<const std::byte> frame) {
        return a_client->send(frame);
      }};
  peer_b.route = RelaySignalingRoute{
      peer_b.self, [b_client](std::span<const std::byte> frame) {
        return b_client->send(frame);
      }};
  peer_a.coordinator->attach_route(&peer_a.route);
  peer_b.coordinator->attach_route(&peer_b.route);

  constexpr std::string_view sdp_a{
      "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\na=ice-ufrag:RelayFrag\r\n"};
  constexpr std::string_view sdp_b{
      "v=0\r\no=- 2 2 IN IP4 192.0.2.11\r\ns=-\r\na=ice-ufrag:OtherFrag\r\n"};
  const auto sdp_bytes = [](std::string_view sdp) {
    return std::vector<std::byte>{reinterpret_cast<const std::byte*>(sdp.data()),
                                  reinterpret_cast<const std::byte*>(sdp.data()) +
                                      sdp.size()};
  };
  DtlsFingerprint fingerprint_a{};
  fingerprint_a[0] = std::byte{0xa0U};
  DtlsFingerprint fingerprint_b{};
  fingerprint_b[0] = std::byte{0xb0U};

  auto request = peer_a.coordinator->begin_attempt(
      peer_b.self, SignalingRouteKind::relay, std::chrono::steady_clock::now());
  ASSERT_TRUE(request.has_value());
  peer_a.request = *request.value_if();

  bool offer_sent = false;
  bool answer_sent = false;
  bool candidate_a_sent = false;
  bool candidate_b_sent = false;
  const auto deadline = std::chrono::steady_clock::now() + 10s;
  while (std::chrono::steady_clock::now() < deadline) {
    // Drive next local steps.
    if (peer_a.accepted && !offer_sent) {
      auto sent = peer_a.coordinator->send_local_offer(
          *peer_a.request, sdp_bytes(sdp_a), fingerprint_a,
          std::chrono::steady_clock::now(), now_milliseconds());
      ASSERT_TRUE(sent.has_value()) << sent.error_if()->safe_detail();
      offer_sent = true;
    }
    if (peer_b.offer_verified && !answer_sent) {
      auto sent = peer_b.coordinator->send_local_answer(
          *peer_a.request, sdp_bytes(sdp_b), fingerprint_b,
          std::chrono::steady_clock::now(), now_milliseconds());
      ASSERT_TRUE(sent.has_value()) << sent.error_if()->safe_detail();
      answer_sent = true;
    }
    if (peer_a.answer_verified && !candidate_a_sent) {
      const std::vector<std::byte> candidate_a{std::byte{1U}, std::byte{2U}};
      auto sent = peer_a.coordinator->send_local_candidate(
          *peer_a.request, candidate_a, std::chrono::steady_clock::now(),
          now_milliseconds());
      ASSERT_TRUE(sent.has_value()) << sent.error_if()->safe_detail();
      candidate_a_sent = true;
    }
    if (peer_b.candidate_received && !candidate_b_sent) {
      const std::vector<std::byte> candidate_b{std::byte{3U}, std::byte{4U}};
      auto sent = peer_b.coordinator->send_local_candidate(
          *peer_a.request, candidate_b, std::chrono::steady_clock::now(),
          now_milliseconds());
      ASSERT_TRUE(sent.has_value()) << sent.error_if()->safe_detail();
      candidate_b_sent = true;
    }
    if (peer_a.candidate_received && peer_b.candidate_received) {
      break;
    }

    // Pump both sides' inbound deliveries without blocking.
    for (RelayWssClient* pump_client : {a_client, b_client}) {
      RelayWssMessage frame;
      auto status = pump_client->try_receive(frame);
      ASSERT_TRUE(status.has_value()) << status.error_if()->safe_detail();
      if (*status.value_if() != RelayWssReceiveStatus::message || frame.text) {
        continue;
      }
      auto control = parse_relay_wss_control_frame(frame.payload);
      ASSERT_TRUE(control) << control.error_if()->safe_detail();
      ASSERT_EQ(control.value_if()->type, RelayWssControlType::signaling_deliver)
          << "unexpected control frame type "
          << static_cast<int>(control.value_if()->type);
      auto envelope =
          RelaySignalingRoute::decode_delivery(control.value_if()->payload);
      ASSERT_TRUE(envelope) << envelope.error_if()->safe_detail();
      auto& coordinator =
          pump_client == a_client ? peer_a.coordinator : peer_b.coordinator;
      auto handled = coordinator->handle_message(
          *envelope.value_if(), SignalingRouteKind::relay,
          std::chrono::steady_clock::now(), now_milliseconds());
      // Every envelope in this handshake is addressed to the pumping side and must pass
      // the verification chain.
      ASSERT_TRUE(handled.has_value()) << handled.error_if()->safe_detail();
    }
    std::this_thread::sleep_for(2ms);
  }

  ASSERT_TRUE(peer_a.candidate_received);
  ASSERT_TRUE(peer_b.candidate_received);
  const auto attempts_a = peer_a.coordinator->attempts();
  ASSERT_EQ(attempts_a.size(), 1U);
  EXPECT_EQ(attempts_a[0].phase, SignalingAttemptPhase::candidates);
  EXPECT_EQ(attempts_a[0].route, SignalingRouteKind::relay);
  const auto attempts_b = peer_b.coordinator->attempts();
  ASSERT_EQ(attempts_b.size(), 1U);
  EXPECT_EQ(attempts_b[0].phase, SignalingAttemptPhase::candidates);
  EXPECT_GE((*relay.server).value_if()->snapshot().signaling_forwarded, 5U);

  ASSERT_TRUE(client_a.value_if()->close(3s));
  ASSERT_TRUE(client_b.value_if()->close(3s));
}

}  // namespace
}  // namespace heyaki
