// Issue #19 regression: the Node runtime relay reconfiguration entry point
// (Node::update_relay_config). The call posts to the node strand and returns
// immediately, so every outcome is observed by polling node->snapshot().relay
// with a bounded wait_until:
//
//  1. a runtime profile enrollment followed by update_relay_config(nullopt)
//     connects and reaches `ready` with fresh registration counters;
//  2. a configuration that fails validation keeps the running control plane
//     and surfaces the error through RelayNodeSnapshot.last_error;
//  3. an explicit RelayNodeConfig replacement tears down and re-logins (the
//     relay server's logins_completed counter proves the fresh cycle);
//  4. an update racing node shutdown is a no-op and shutdown stays bounded; a
//     moved-from Node reports node_not_running;
//  5. revoking the only enrollment followed by update_relay_config(nullopt)
//     tears the control plane down and reports `disabled` (declared last: it
//     exercises the profile-without-active-enrollment reload path).
//
// Threading discipline (AGENTS.md): every concurrent path runs through the
// pinned executor via the Node's and RelayServer's own runtimes. The test
// thread only performs bounded snapshot polling; no std::thread/std::async is
// used for concurrent work.

#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include "../../src/client/relay_wss_client.hpp"
#include "../../src/relay/relay_config.hpp"
#include "../../src/relay/relay_database.hpp"
#include "../../src/relay/relay_server.hpp"

#include <kairo/comm.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <functional>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace heyaki {
namespace {

using namespace std::chrono_literals;

constexpr auto site_start_timeout = 5s;
constexpr auto relay_state_timeout = 10s;
constexpr auto error_surface_timeout = 5s;

// ---- relay test site (certificate + server), following the
// m4_relay_cycle_repro_test.cpp in-process server pattern ----

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

// Bounded poll of node/server snapshots. The predicate is re-evaluated after
// the timeout so a just-missed transition still reads as success.
bool wait_until(const std::function<bool()>& predicate,
                std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  kairo::comm::PhaseGate poll{"m4-node-relay-update-poll"};
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    (void)poll.wait_for(1U, std::chrono::milliseconds{2});
  }
  return predicate();
}

std::uint64_t now_milliseconds() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::string describe_relay(const RelayNodeSnapshot& relay) {
  std::string text = "relay{state=";
  text += std::string{relay_node_state_name(relay.state)};
  text += " enabled=";
  text += relay.enabled ? "true" : "false";
  text += " url=";
  text += relay.relay_url.empty() ? "-" : relay.relay_url;
  text += " tenant=";
  text += relay.tenant.empty() ? "-" : relay.tenant;
  text += " attempts=";
  text += std::to_string(relay.registration_attempts);
  text += " successes=";
  text += std::to_string(relay.registration_successes);
  text += " failures=";
  text += std::to_string(relay.registration_failures);
  text += " reconnects=";
  text += std::to_string(relay.reconnect_count);
  text += " backoff_ms=";
  text += std::to_string(relay.backoff.count());
  if (relay.last_error) {
    text += " last_error=";
    text += relay.last_error->safe_detail();
  }
  text += "}";
  return text;
}

struct RelaySite {
  std::filesystem::path root;
  std::optional<RelayServer> server;
  std::string relay_url;
  RelayTlsPin pin{};
  std::vector<std::byte> pin_bytes;

  void shutdown_server() {
    if (server) {
      (void)server->shutdown();
    }
  }
};

bool start_relay_site(const std::filesystem::path& root, RelaySite& site) {
  std::error_code ignored;
  std::filesystem::remove_all(root, ignored);
  std::filesystem::create_directories(root);
#ifndef _WIN32
  ::chmod(root.c_str(), S_IRWXU);
#endif
  site.root = root;
  if (!write_test_certificate(root)) {
    ADD_FAILURE() << "test relay certificate generation failed";
    return false;
  }
  auto server_config = RelayServerConfig{};
  server_config.listen_address = "127.0.0.1";
  server_config.listen_port = 0U;
  server_config.tls_certificate_file = root / "test-only-cert.pem";
  server_config.tls_private_key_file = root / "test-only-key.pem";
  server_config.database_file = root / "relay.sqlite";
  server_config.install_signal_handlers = false;
  server_config.runtime.worker_name = "m4-relay-update-relay";
  auto server = RelayServer::create(std::move(server_config));
  if (!server) {
    ADD_FAILURE() << "relay server create failed: "
                  << server.error_if()->safe_detail();
    return false;
  }
  site.server.emplace(std::move(*server.value_if()));
  if (!wait_until([&] { return site.server->snapshot().listen_port != 0U; },
                  site_start_timeout)) {
    ADD_FAILURE() << "relay server did not start listening";
    return false;
  }
  site.relay_url =
      "wss://127.0.0.1:" + std::to_string(site.server->snapshot().listen_port);
  auto pin = certificate_pin(root / "test-only-cert.pem");
  if (!pin) {
    ADD_FAILURE() << "relay certificate pin derivation failed";
    return false;
  }
  site.pin = *pin;
  site.pin_bytes.assign(pin->begin(), pin->end());
  return true;
}

// Enrolls the profile's device identity in the relay database so a login
// against the in-process server can succeed.
bool enroll_relay_device(const RelaySite& site, ProfileStore& profile) {
  auto database = RelayDatabase::open(site.root / "relay.sqlite");
  if (!database) {
    ADD_FAILURE() << "relay database open failed: "
                  << database.error_if()->safe_detail();
    return false;
  }
  auto identity = profile.load_identity();
  if (!identity) {
    ADD_FAILURE() << "identity load failed: "
                  << identity.error_if()->safe_detail();
    return false;
  }
  RelayDeviceRecord device;
  device.device_id = identity.value_if()->device_id();
  device.public_key = identity.value_if()->public_key();
  device.tenant = "tenant-a";
  device.display_name = "relay-update-test";
  device.enrollment_generation = 1U;
  device.status = RelayDeviceStatus::active;
  auto enrolled = database.value_if()->enroll_device(device, now_milliseconds());
  if (!enrolled) {
    ADD_FAILURE() << "relay device enrollment failed: "
                  << enrolled.error_if()->safe_detail();
    return false;
  }
  return true;
}

Result<ProfileStore> make_profile(const std::filesystem::path& root,
                                  const std::string& name) {
  ProfileOpenOptions options;
  options.secret_backend.prefer_os_backend = false;
  auto profile = ProfileStore::create(root / (name + ".sqlite"), options);
  if (!profile) {
    return profile;
  }
  auto verifier = create_password_verifier("correct horse battery staple", {});
  if (!verifier) {
    return Result<ProfileStore>::failure(*verifier.error_if());
  }
  LocalProfileInitialization initialization;
  initialization.application_id = "com.example.relayupdate";
  initialization.password_verifier = std::move(*verifier.value_if());
  initialization.password_generation = 1U;
  initialization.pairing_policy = PairingPolicy{};
  initialization.lan = LanConfiguration{};
  auto initialized = profile.value_if()->initialize_local(initialization);
  if (!initialized) {
    return Result<ProfileStore>::failure(*initialized.error_if());
  }
  return profile;
}

LanConfiguration relay_only_lan() {
  LanConfiguration lan;
  lan.enabled = false;
  lan.connectivity_mode = ConnectivityMode::relay_only;
  return lan;
}

// The active-enrollment record the settings UI would write (issue #19 user
// story): same relay site as the device enrollment, auto-connect on.
RelayEnrollmentRecord active_enrollment(const RelaySite& site) {
  RelayEnrollmentRecord enrollment;
  enrollment.relay_url = site.relay_url;
  enrollment.relay_pin = site.pin_bytes;
  enrollment.tenant = "tenant-a";
  enrollment.enrollment_generation = 1U;
  enrollment.auto_connect = true;
  enrollment.revoked = false;
  enrollment.updated_unix_milliseconds = now_milliseconds();
  return enrollment;
}

// Explicit replacement configuration (issue #19 explicit-value path). Field
// values differ from a profile-derived configuration (which keeps the frozen
// defaults, heartbeat_interval = 15000 ms), so a replacement is never a no-op.
RelayNodeConfig explicit_relay_config(const RelaySite& site) {
  RelayNodeConfig config;
  config.relay_url = site.relay_url;
  config.relay_pin = site.pin_bytes;
  config.tenant = "tenant-a";
  config.enrollment_generation = 1U;
  config.tls_verify_peer = false;
  config.connect_timeout = 2s;
  config.handshake_timeout = 2s;
  config.close_timeout = 1s;
  config.heartbeat_interval = 2000ms;
  config.lease_duration = 6000ms;
  config.minimum_backoff = 100ms;
  config.maximum_backoff = 500ms;
  config.poll_interval = 100ms;
  return config;
}

NodeConfig node_config_for(ProfileStore& profile) {
  NodeConfig config;
  config.profile = &profile;
  config.application_id = "com.example.relayupdate";
  config.lan_override = relay_only_lan();
  return config;
}

// Site + enrolled profile + node that auto-connected at create() and reached
// `ready`. Used by the tests that mutate an already-running relay control
// plane.
struct ConnectedSetup {
  RelaySite site;
  std::optional<ProfileStore> profile;
  std::optional<Node> node;
};

bool wait_relay_ready(const ConnectedSetup& setup) {
  const bool ready = wait_until(
      [&] { return setup.node->snapshot().relay.state == RelayNodeState::ready; },
      relay_state_timeout);
  if (!ready) {
    ADD_FAILURE() << "relay control plane did not reach ready: "
                  << describe_relay(setup.node->snapshot().relay);
  }
  return ready;
}

bool make_connected_setup(const std::filesystem::path& root, ConnectedSetup& setup) {
  if (!start_relay_site(root, setup.site)) {
    return false;
  }
  auto profile = make_profile(root, "device");
  if (!profile) {
    ADD_FAILURE() << "profile create failed: "
                  << profile.error_if()->safe_detail();
    return false;
  }
  setup.profile.emplace(std::move(*profile.value_if()));
  if (!enroll_relay_device(setup.site, *setup.profile)) {
    return false;
  }
  if (!setup.profile->put_relay_enrollment(active_enrollment(setup.site))) {
    ADD_FAILURE() << "profile relay enrollment write failed";
    return false;
  }
  auto node = Node::create(node_config_for(*setup.profile));
  if (!node) {
    ADD_FAILURE() << "node create failed: " << node.error_if()->safe_detail();
    return false;
  }
  setup.node.emplace(std::move(*node.value_if()));
  return wait_relay_ready(setup);
}

// ---- 1. runtime enrollment then profile-driven update connects ----

TEST(M4NodeRelayUpdate, RuntimeEnrollmentThenUpdateConnects) {
  std::filesystem::path root =
      std::filesystem::path{HEYAKI_M4_RELAY_UPDATE_STATE_DIR} /
      ::testing::UnitTest::GetInstance()->current_test_info()->name();
  RelaySite site;
  ASSERT_TRUE(start_relay_site(root, site));
  auto profile = make_profile(root, "device");
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  // The device must be enrolled server-side for the later login to succeed,
  // but the PROFILE has no enrollment record yet: the node starts disabled.
  ASSERT_TRUE(enroll_relay_device(site, *profile.value_if()));

  auto node = Node::create(node_config_for(*profile.value_if()));
  ASSERT_TRUE(node) << node.error_if()->safe_detail();
  EXPECT_TRUE(wait_until(
      [&] { return node.value_if()->snapshot().relay.state == RelayNodeState::disabled; },
      error_surface_timeout))
      << describe_relay(node.value_if()->snapshot().relay);

  // Runtime story: the settings UI enrolls against the relay and asks the
  // running node to re-derive its configuration from the profile.
  ASSERT_TRUE(profile.value_if()->put_relay_enrollment(active_enrollment(site)));
  ASSERT_TRUE(node.value_if()->update_relay_config(std::nullopt));
  const bool ready = wait_until(
      [&] { return node.value_if()->snapshot().relay.state == RelayNodeState::ready; },
      relay_state_timeout);
  ASSERT_TRUE(ready) << describe_relay(node.value_if()->snapshot().relay);

  const auto relay = node.value_if()->snapshot().relay;
  EXPECT_GE(relay.registration_attempts, 1U);
  EXPECT_GE(relay.registration_successes, 1U);
  EXPECT_EQ(relay.relay_url, site.relay_url);
  EXPECT_EQ(relay.tenant, "tenant-a");
  EXPECT_FALSE(relay.last_error.has_value())
      << describe_relay(relay);

  EXPECT_TRUE(node.value_if()->shutdown().stopped);
  site.shutdown_server();
}

// ---- 2. validation failure keeps the running control plane ----

TEST(M4NodeRelayUpdate, InvalidUpdateKeepsRunningConnection) {
  std::filesystem::path root =
      std::filesystem::path{HEYAKI_M4_RELAY_UPDATE_STATE_DIR} /
      ::testing::UnitTest::GetInstance()->current_test_info()->name();
  ConnectedSetup setup;
  ASSERT_TRUE(make_connected_setup(root, setup));

  RelayNodeConfig invalid = explicit_relay_config(setup.site);
  invalid.relay_url.clear();  // relay_url.empty() -> relay_node_config_invalid
  ASSERT_TRUE(setup.node->update_relay_config(invalid));

  const bool surfaced = wait_until(
      [&] { return setup.node->snapshot().relay.last_error.has_value(); },
      error_surface_timeout);
  ASSERT_TRUE(surfaced) << describe_relay(setup.node->snapshot().relay);

  const auto relay = setup.node->snapshot().relay;
  EXPECT_EQ(relay.state, RelayNodeState::ready)
      << describe_relay(relay);
  EXPECT_EQ(relay.relay_url, setup.site.relay_url);
  EXPECT_GE(relay.registration_successes, 1U);
  // The old control plane is still served by the relay server.
  EXPECT_GE(setup.site.server->snapshot().active_sessions, 1U);

  EXPECT_TRUE(setup.node->shutdown().stopped);
  setup.site.shutdown_server();
}

// ---- 3. explicit configuration replacement tears down and re-logins ----

TEST(M4NodeRelayUpdate, ExplicitConfigReplacementReconnects) {
  std::filesystem::path root =
      std::filesystem::path{HEYAKI_M4_RELAY_UPDATE_STATE_DIR} /
      ::testing::UnitTest::GetInstance()->current_test_info()->name();
  ConnectedSetup setup;
  ASSERT_TRUE(make_connected_setup(root, setup));

  const auto logins_before = setup.site.server->snapshot().logins_completed;
  ASSERT_TRUE(
      setup.node->update_relay_config(explicit_relay_config(setup.site)));
  // A replacement resets the registration counters and runs one fresh
  // connect+login cycle; the server-side login counter proves the cycle.
  const bool ready = wait_until(
      [&] {
        return setup.node->snapshot().relay.state == RelayNodeState::ready &&
               setup.site.server->snapshot().logins_completed > logins_before;
      },
      relay_state_timeout);
  ASSERT_TRUE(ready) << describe_relay(setup.node->snapshot().relay)
                     << " server_logins_before=" << logins_before
                     << " server_logins_now="
                     << setup.site.server->snapshot().logins_completed;

  const auto relay = setup.node->snapshot().relay;
  EXPECT_GT(setup.site.server->snapshot().logins_completed, logins_before);
  EXPECT_GE(relay.registration_attempts, 1U);
  EXPECT_GE(relay.registration_successes, 1U);
  EXPECT_EQ(relay.relay_url, setup.site.relay_url);

  EXPECT_TRUE(setup.node->shutdown().stopped);
  setup.site.shutdown_server();
}

// ---- 4. shutdown race and moved-from handling ----

TEST(M4NodeRelayUpdate, UpdateRacingShutdownAndMovedFrom) {
  std::filesystem::path root =
      std::filesystem::path{HEYAKI_M4_RELAY_UPDATE_STATE_DIR} /
      ::testing::UnitTest::GetInstance()->current_test_info()->name();
  ConnectedSetup setup;
  ASSERT_TRUE(make_connected_setup(root, setup));

  // Fire a runtime replacement and immediately shut down: the update either
  // applies before the shutdown barrier or is a no-op; either way shutdown
  // must complete in bounded time (the sanitizer gate watches the process
  // for hangs, races, and leaks).
  ASSERT_TRUE(setup.node->update_relay_config(explicit_relay_config(setup.site)));
  const auto report = setup.node->shutdown();
  EXPECT_TRUE(report.stopped);
  EXPECT_FALSE(report.timed_out);

  // A moved-from Node must fail the call instead of scheduling work.
  Node moved_from = std::move(setup.node.value());
  const auto result = setup.node.value().update_relay_config(std::nullopt);
  ASSERT_FALSE(result);
  ASSERT_NE(result.error_if(), nullptr);
  EXPECT_EQ(result.error_if()->code(), ErrorCode::cancelled)
      << result.error_if()->safe_detail();
  EXPECT_NE(std::string_view{result.error_if()->safe_detail()}
                .find("node_not_running"),
            std::string_view::npos);

  setup.site.shutdown_server();
}

// ---- 5. revoking the only enrollment then updating disconnects ----
// Declared last: this is the profile-without-active-enrollment reload path.

TEST(M4NodeRelayUpdate, RevokedEnrollmentThenUpdateDisconnects) {
  std::filesystem::path root =
      std::filesystem::path{HEYAKI_M4_RELAY_UPDATE_STATE_DIR} /
      ::testing::UnitTest::GetInstance()->current_test_info()->name();
  ConnectedSetup setup;
  ASSERT_TRUE(make_connected_setup(root, setup));

  ASSERT_TRUE(setup.profile->mark_relay_revoked(setup.site.relay_url, 1U));
  ASSERT_TRUE(setup.node->update_relay_config(std::nullopt));
  const bool disabled = wait_until(
      [&] {
        const auto relay = setup.node->snapshot().relay;
        return relay.state == RelayNodeState::disabled && !relay.enabled &&
               relay.relay_url.empty() && relay.tenant.empty();
      },
      relay_state_timeout);
  EXPECT_TRUE(disabled) << describe_relay(setup.node->snapshot().relay);

  EXPECT_TRUE(setup.node->shutdown().stopped);
  setup.site.shutdown_server();
}

}  // namespace
}  // namespace heyaki
