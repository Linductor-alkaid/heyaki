// Local reproduction for the coturn-matrix cycle-4+ stall: repeated relay-only
// node pairs against ONE RelayServer instance. Not a permanent test; used to
// localize the signaling-delivery degradation before the final fix.
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include "../../src/relay/relay_server.hpp"
#include "../../src/relay/relay_database.hpp"
#include "../../src/relay/relay_config.hpp"
#include "../../src/client/relay_wss_client.hpp"

#include <executor/comm.hpp>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <gtest/gtest.h>

#include "m5_support.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace heyaki {
namespace {

using namespace std::chrono_literals;

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

bool wait_until(const std::function<bool()>& predicate,
                std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  executor::comm::PhaseGate poll{"m4-cycle-repro-poll"};
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    (void)poll.wait_for(1U, std::chrono::milliseconds{1});
  }
  return predicate();
}

std::uint64_t now_milliseconds() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

TEST(M4RelayCycleRepro, SequentialFreshPairsAuthenticateAcrossSixCycles) {
  std::filesystem::path root = std::filesystem::path{HEYAKI_M4_REPRO_STATE_DIR};
  std::error_code ignored;
  std::filesystem::remove_all(root, ignored);
  std::filesystem::create_directories(root);
#ifndef _WIN32
  ::chmod(root.c_str(), S_IRWXU);
#endif
  ASSERT_TRUE(write_test_certificate(root));
  auto server_config = RelayServerConfig{};
  server_config.listen_address = "127.0.0.1";
  server_config.listen_port = 0U;
  server_config.tls_certificate_file = root / "test-only-cert.pem";
  server_config.tls_private_key_file = root / "test-only-key.pem";
  server_config.database_file = root / "relay.sqlite";
  server_config.install_signal_handlers = false;
  server_config.runtime.worker_name = "m4-cycle-repro-relay";
  auto server = RelayServer::create(std::move(server_config));
  ASSERT_TRUE(server) << server.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] { return server.value_if()->snapshot().listen_port != 0U; }, 5s));
  const std::string relay_url =
      "wss://127.0.0.1:" + std::to_string(server.value_if()->snapshot().listen_port);
  auto pin = certificate_pin(root / "test-only-cert.pem");
  ASSERT_TRUE(pin);

  for (std::size_t cycle = 0U; cycle < 6U; ++cycle) {
    auto make_profile = [&](const char* side) {
      ProfileOpenOptions options;
      options.secret_backend.prefer_os_backend = false;
      auto profile = ProfileStore::create(
          root / ("cycle-" + std::to_string(cycle) + "-" + side + ".sqlite"), options);
      if (!profile) return profile;
      auto verifier = create_password_verifier("correct horse battery staple", {});
      if (!verifier) return Result<ProfileStore>::failure(*verifier.error_if());
      LocalProfileInitialization initialization;
      initialization.application_id = "com.example.repro." + std::string{side};
      initialization.password_verifier = std::move(*verifier.value_if());
      initialization.password_generation = 1U;
      initialization.pairing_policy = PairingPolicy{};
      initialization.lan = LanConfiguration{};
      auto initialized = profile.value_if()->initialize_local(initialization);
      if (!initialized) return Result<ProfileStore>::failure(*initialized.error_if());
      return profile;
    };
    auto first_profile = make_profile("first");
    auto second_profile = make_profile("second");
    ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));
    auto first_identity = first_profile.value_if()->load_identity();
    auto second_identity = second_profile.value_if()->load_identity();
    ASSERT_TRUE(first_identity && second_identity);
    {
      auto database = RelayDatabase::open(root / "relay.sqlite");
      ASSERT_TRUE(database);
      for (const auto* identity :
           {first_identity.value_if(), second_identity.value_if()}) {
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
    relay_config.poll_interval = 100ms;
    LanConfiguration lan;
    lan.enabled = false;
    lan.connectivity_mode = ConnectivityMode::relay_only;
    NodeConfig first_node_config;
    first_node_config.profile = first_profile.value_if();
    first_node_config.application_id = "com.example.repro.first";
    first_node_config.lan_override = lan;
    first_node_config.relay_override = relay_config;
    NodeConfig second_node_config;
    second_node_config.profile = second_profile.value_if();
    second_node_config.application_id = "com.example.repro.second";
    second_node_config.lan_override = lan;
    second_node_config.relay_override = relay_config;
    auto first = Node::create(std::move(first_node_config));
    auto second = Node::create(std::move(second_node_config));
    ASSERT_TRUE(first && second)
        << "cycle " << cycle << " node create failed";
    const auto ready = wait_until(
        [&] {
          return first.value_if()->snapshot().relay.state == RelayNodeState::ready &&
                 second.value_if()->snapshot().relay.state == RelayNodeState::ready;
        },
        8s);
    ASSERT_TRUE(ready) << "cycle " << cycle << " relay login failed";
    const auto found_peer = wait_until(
        [&] {
          const auto endpoints = first.value_if()->endpoints();
          return std::any_of(endpoints.begin(), endpoints.end(),
                             [&](const auto& entry) {
                               return entry.key.device_id !=
                                      first.value_if()->snapshot().device_id;
                             });
        },
        8s);
    ASSERT_TRUE(found_peer) << "cycle " << cycle << " peer not discovered";
    const auto endpoints = first.value_if()->endpoints();
    const auto peer = std::find_if(endpoints.begin(), endpoints.end(),
                                   [&](const auto& entry) {
                                     return entry.key.device_id !=
                                            first.value_if()->snapshot().device_id;
                                   })
                           ->key;
    const auto begin = std::chrono::steady_clock::now();
    ASSERT_TRUE(first.value_if()->connect(peer)) << "cycle " << cycle;
    const bool authenticated = wait_until(
        [&] {
          const auto left = first.value_if()->peer_sessions();
          return std::any_of(left.begin(), left.end(), [](const auto& session) {
            return session.state == NodePeerSessionState::authenticated;
          });
        },
        15s);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - begin)
                             .count();
    if (!authenticated) {
      const auto snapshot = first.value_if()->snapshot();
      const auto sessions = first.value_if()->peer_sessions();
      ADD_FAILURE() << "cycle " << cycle << " stalled after " << elapsed
                    << "ms; coordinator_attempts="
                    << snapshot.session_coordinator.current_attempts
                    << " reconnects=" << snapshot.relay.reconnect_count
                    << " missed=" << snapshot.relay.heartbeats_missed
                    << " endpoints=" << first.value_if()->endpoints().size();
      for (const auto& session : sessions) {
        ADD_FAILURE() << "  session state=" << (int)session.state << " stage="
                      << (int)session.connection_stage << " err="
                      << (session.error ? std::string{session.error->safe_detail()}
                                        : std::string{"-"});
      }
    }
    EXPECT_TRUE(first.value_if()->shutdown().stopped) << "cycle " << cycle;
    EXPECT_TRUE(second.value_if()->shutdown().stopped) << "cycle " << cycle;
    if (!authenticated) {
      break;
    }
  }
  (void)server.value_if()->shutdown();
}

}  // namespace
}  // namespace heyaki
