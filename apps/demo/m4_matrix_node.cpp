// M4 network-matrix participant: a real Heyaki node used by the coturn
// topology harness. It performs local profile initialization, optional relay
// enrollment, then runs one bounded session attempt against the peer and
// prints a machine-readable MATRIX_RESULT line describing the outcome. The
// binary never talks to coturn itself; the driver script owns the topology.
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/relay_enrollment_client.hpp>
#include <heyaki/runtime.hpp>

#include <executor/comm.hpp>

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

using heyaki::Error;
using heyaki::ErrorCode;

std::uint64_t unix_milliseconds_now() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::uint64_t parse_u64(std::string_view text) {
  std::uint64_t value = 0U;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      return 0U;
    }
    value = value * 10U + static_cast<std::uint64_t>(character - '0');
  }
  return value;
}

bool wait_until(const std::function<bool()>& predicate,
                std::chrono::milliseconds timeout,
                const std::function<bool()>& on_poll = {}) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  executor::comm::PhaseGate poll{"heyaki-m4-matrix-poll"};
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    if (on_poll) {
      (void)on_poll();
    }
    (void)poll.wait_for(1U, std::chrono::milliseconds{1});
  }
  return predicate();
}

heyaki::Result<heyaki::ProfileStore> initialized_profile(
    const std::filesystem::path& database, std::string_view application_id) {
  heyaki::ProfileOpenOptions options;
  options.secret_backend.prefer_os_backend = false;
  auto profile = heyaki::ProfileStore::create(database, options);
  if (!profile) {
    return profile;
  }
  heyaki::PasswordVerifier verifier{
      .format_version = 1U,
      .parameters = heyaki::PasswordHashParameters{},
      .encoded = "$argon2id$v=19$m=65536,t=2,p=1$test$test"};
  heyaki::LanConfiguration lan;
  lan.enabled = false;
  heyaki::LocalProfileInitialization initialization{
      .application_id = std::string{application_id},
      .password_verifier = std::move(verifier),
      .password_generation = 1U,
      .pairing_policy = heyaki::PairingPolicy{},
      .lan = lan};
  auto initialized = profile.value_if()->initialize_local(initialization);
  if (!initialized) {
    return heyaki::Result<heyaki::ProfileStore>::failure(*initialized.error_if());
  }
  return profile;
}

std::string base64(const unsigned char* data, std::size_t size) {
  static const char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string output;
  output.reserve((size + 2U) / 3U * 4U);
  for (std::size_t index = 0U; index < size; index += 3U) {
    const std::uint32_t triple = (static_cast<std::uint32_t>(data[index]) << 16U) |
                                 (index + 1U < size
                                      ? static_cast<std::uint32_t>(data[index + 1U]) << 8U
                                      : 0U) |
                                 (index + 2U < size
                                      ? static_cast<std::uint32_t>(data[index + 2U])
                                      : 0U);
    output.push_back(kAlphabet[(triple >> 18U) & 0x3FU]);
    output.push_back(kAlphabet[(triple >> 12U) & 0x3FU]);
    output.push_back(index + 1U < size ? kAlphabet[(triple >> 6U) & 0x3FU] : '=');
    output.push_back(index + 2U < size ? kAlphabet[triple & 0x3FU] : '=');
  }
  return output;
}

// TURN REST API credential contract pinned by deploy/coturn/README.md:
// username = "<expiry_unix_seconds>:<tenant>:<DeviceId>",
// password = base64(HMAC-SHA1(static-auth-secret, username)).
heyaki::NodeIceServer turn_server(const std::string& host, std::uint16_t port,
                                  const std::string& secret,
                                  const std::string& tenant,
                                  const heyaki::DeviceId& device_id) {
  const auto expiry = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count() +
                      600;
  const std::string username =
      std::to_string(expiry) + ":" + tenant + ":" + heyaki::to_string(device_id);
  unsigned char mac[EVP_MAX_MD_SIZE]{};
  unsigned int mac_size = 0U;
  const auto* computed = ::HMAC(EVP_sha1(), secret.data(),
                                static_cast<int>(secret.size()),
                                reinterpret_cast<const unsigned char*>(username.data()),
                                username.size(), mac, &mac_size);
  heyaki::NodeIceServer server;
  server.kind = heyaki::NodeIceServerKind::turn_udp;
  server.hostname = host;
  server.port = port;
  server.username = username;
  server.credential = computed != nullptr ? base64(mac, mac_size) : std::string{};
  return server;
}

struct RunOptions {
  std::string role{"responder"};
  std::optional<std::string> stun;
  std::optional<std::string> turn;
  std::string turn_secret;
  bool force_turn{false};
  std::chrono::milliseconds hold{500};
  std::chrono::milliseconds authenticate_budget{15000};
  unsigned retries{0U};
};

int run_node(const std::filesystem::path& database, std::string_view application_id,
             const std::string& relay_url, const std::filesystem::path& ca_file,
             const std::string& tenant, std::chrono::milliseconds total_budget,
             const RunOptions& options) {
  auto profile = heyaki::ProfileStore::open(database);
  if (!profile) {
    std::cerr << "profile open failed: "
              << profile.error_if()->safe_detail() << '\n';
    return 1;
  }
  heyaki::LanConfiguration lan;
  lan.enabled = false;
  lan.connectivity_mode = heyaki::ConnectivityMode::relay_only;
  heyaki::RelayNodeConfig relay;
  relay.relay_url = relay_url;
  relay.tls_ca_file = ca_file;
  relay.tenant = tenant;
  relay.heartbeat_interval = std::chrono::milliseconds{1000};
  relay.lease_duration = std::chrono::milliseconds{3000};
  // The matrix exercises the protocol under adverse topologies, not the
  // production reconnect backoff policy: cap the backoff so a lossy relay
  // link recovers its control plane within the scenario budgets. Backoff
  // semantics stay covered by NodeReconnectsWithBoundedBackoffAfterRelayOutage.
  relay.minimum_backoff = std::chrono::milliseconds{1000};
  relay.maximum_backoff = std::chrono::milliseconds{5000};

  auto profiled = profile.value_if();
  const auto device_id = profiled->device_id();
  heyaki::PeerPathPolicy policy;
  policy.allow_ipv6_host = false;
  if (options.stun.has_value()) {
    const auto separator = options.stun->rfind(':');
    heyaki::NodeIceServer server;
    server.kind = heyaki::NodeIceServerKind::stun;
    server.hostname = options.stun->substr(0U, separator);
    server.port = static_cast<std::uint16_t>(
        parse_u64(options.stun->substr(separator + 1U)));
    policy.ice_servers.push_back(std::move(server));
  }
  if (options.turn.has_value()) {
    const auto separator = options.turn->rfind(':');
    heyaki::NodeIceServer server = turn_server(
        options.turn->substr(0U, separator),
        static_cast<std::uint16_t>(parse_u64(options.turn->substr(separator + 1U))),
        options.turn_secret, tenant, device_id);
    policy.ice_servers.push_back(std::move(server));
  }
  policy.force_turn_data_path = options.force_turn;
  if (options.force_turn) {
    policy.allow_server_reflexive = false;
    policy.allow_ipv4_host = false;
  }

  heyaki::NodeConfig config;
  config.profile = profiled;
  config.application_id = std::string{application_id};
  config.lan_override = lan;
  config.relay_override = relay;
  config.path_policy_override = policy;
  auto node = heyaki::Node::create(std::move(config));
  if (!node) {
    std::cerr << "node create failed: " << node.error_if()->safe_detail() << '\n';
    return 1;
  }

  const auto relay_ready = wait_until(
      [&] {
        return node.value_if()->snapshot().relay.state ==
               heyaki::RelayNodeState::ready;
      },
      std::min(total_budget, std::chrono::milliseconds{10000}));
  if (!relay_ready) {
    const auto snapshot = node.value_if()->snapshot();
    std::cout << "MATRIX_RESULT authenticated=0 data_path=none duration_ms=0"
              << " relay_state="
              << heyaki::relay_node_state_name(snapshot.relay.state) << '\n';
    (void)node.value_if()->shutdown();
    return 0;
  }

  const auto local_key = heyaki::DeviceEndpointKey{
      node.value_if()->snapshot().device_id,
      node.value_if()->snapshot().endpoint_id};
  const auto begin = std::chrono::steady_clock::now();
  bool attempted = false;
  if (options.role == "initiator") {
    const auto peer_endpoint = wait_until(
        [&] {
          const auto entries = node.value_if()->endpoints();
          return std::any_of(entries.begin(), entries.end(),
                             [&](const auto& entry) {
                               return entry.key != local_key &&
                                      entry.relay.has_value();
                             });
        },
        std::chrono::milliseconds{10000});
    if (!peer_endpoint) {
      std::cout << "MATRIX_RESULT authenticated=0 data_path=none duration_ms=0"
                << " relay_state=no_peer\n";
      (void)node.value_if()->shutdown();
      return 0;
    }
    const auto entries = node.value_if()->endpoints();
    const auto peer = std::find_if(entries.begin(), entries.end(),
                                   [&](const auto& entry) {
                                     return entry.key != local_key &&
                                            entry.relay.has_value();
                                   });
    const auto connected = node.value_if()->connect(peer->key);
    attempted = (bool)connected;
    if (!connected) {
      std::cout << "MATRIX_RESULT authenticated=0 data_path=none duration_ms=0"
                << " connect_error=" << connected.error_if()->safe_detail() << '\n';
      (void)node.value_if()->shutdown();
      return 0;
    }
  }

  unsigned connect_retries = options.retries;
  const auto authenticated = wait_until(
      [&] {
        const auto sessions = node.value_if()->peer_sessions();
        return std::any_of(sessions.begin(), sessions.end(),
                           [](const auto& session) {
                             return session.state ==
                                    heyaki::NodePeerSessionState::authenticated;
                           });
      },
      options.authenticate_budget,
      [&] {
        // Retry the dial when the previous attempt terminated without a
        // session (for example a first-shot denial while the peer's reverse
        // discovery lags behind on a lossy link).
        if (options.role != "initiator" || connect_retries == 0U) {
          return false;
        }
        const auto sessions = node.value_if()->peer_sessions();
        const bool terminal_without_session = std::all_of(
            sessions.begin(), sessions.end(), [](const auto& session) {
              return session.state == heyaki::NodePeerSessionState::closed;
            });
        if (!terminal_without_session || sessions.empty()) {
          return false;
        }
        const auto entries = node.value_if()->endpoints();
        const auto peer = std::find_if(entries.begin(), entries.end(),
                                       [&](const auto& entry) {
                                         return entry.key != local_key &&
                                                entry.relay.has_value();
                                       });
        if (peer == entries.end()) {
          return false;
        }
        --connect_retries;
        return (bool)node.value_if()->connect(peer->key);
      });
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - begin)
                           .count();
  std::string data_path = "none";
  std::string stage = "none";
  std::string session_error = "-";
  heyaki::NodePeerSessionState final_state = heyaki::NodePeerSessionState::closed;
  const auto sessions = node.value_if()->peer_sessions();
  for (const auto& session : sessions) {
    final_state = session.state;
    stage = std::string{heyaki::node_connection_stage_name(session.connection_stage)};
    session_error =
        session.error ? std::string{session.error->safe_detail()} : std::string{"-"};
    if (session.state == heyaki::NodePeerSessionState::authenticated) {
      data_path = std::string{
          heyaki::node_data_path_kind_name(session.data_path)};
      break;
    }
  }
  if (authenticated) {
    executor::comm::PhaseGate hold{"heyaki-m4-matrix-hold"};
    (void)hold.wait_for(1U, options.hold);
    // A relay restart mid-hold races this exit against the bounded-backoff
    // re-login. Give the recovery a bounded grace to reach ready before
    // sampling, so relay_state reports the recovery outcome instead of the
    // exit instant; a genuinely broken re-login still surfaces as degraded.
    const auto grace_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{8};
    while (node.value_if()->snapshot().relay.state !=
               heyaki::RelayNodeState::ready &&
           std::chrono::steady_clock::now() < grace_deadline) {
      executor::comm::PhaseGate grace{"heyaki-m4-matrix-grace"};
      (void)grace.wait_for(1U, std::chrono::milliseconds{100});
    }
  }
  const auto snapshot = node.value_if()->snapshot();
  std::cout << "MATRIX_RESULT authenticated=" << (authenticated ? 1 : 0)
            << " data_path=" << data_path << " duration_ms=" << elapsed
            << " attempted=" << (attempted ? 1 : 0)
            << " state=" << heyaki::node_peer_session_state_name(final_state)
            << " stage=" << stage
            << " session_error=" << session_error
            << " relay_state=" << heyaki::relay_node_state_name(snapshot.relay.state)
            << " coordinator_attempts="
            << snapshot.session_coordinator.current_attempts
            << " relay_reconnects=" << snapshot.relay.reconnect_count
            << " heartbeats_missed=" << snapshot.relay.heartbeats_missed
            << " endpoints_seen=" << node.value_if()->endpoints().size()
            << '\n';
  const auto shutdown = node.value_if()->shutdown();
  if (!shutdown.stopped) {
    std::cerr << "node shutdown did not drain\n";
    return 1;
  }
  return 0;
}

int usage() {
  std::cerr << "usage:\n"
            << "  heyaki-m4-matrix-node init-profile DB APP_ID\n"
            << "  heyaki-m4-matrix-node enroll DB APP_ID RELAY_URL CA TENANT TOKEN\n"
            << "  heyaki-m4-matrix-node run DB APP_ID RELAY_URL CA TENANT BUDGET_MS\n"
            << "      [--role initiator|responder] [--stun HOST:PORT]\n"
            << "      [--turn HOST:PORT] [--turn-secret SECRET] [--force-turn]\n"
            << "      [--hold-ms N] [--authenticate-budget-ms N] [--connect-retries N]\n";
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    return usage();
  }
  const std::string command = argv[1];
  if (command == "init-profile") {
    if (argc != 4) {
      return usage();
    }
    auto profile = initialized_profile(argv[2], argv[3]);
    if (!profile) {
      std::cerr << profile.error_if()->safe_detail() << '\n';
      return 1;
    }
    return 0;
  }
  if (command == "enroll") {
    if (argc != 8) {
      return usage();
    }
    auto profile = heyaki::ProfileStore::open(argv[2]);
    if (!profile) {
      std::cerr << profile.error_if()->safe_detail() << '\n';
      return 1;
    }
    heyaki::RelayEnrollmentWssTransportConfig transport;
    transport.relay_url = argv[4];
    transport.tls_ca_file = std::filesystem::path{argv[5]};
    heyaki::RelayEnrollmentClientConfig config;
    config.profile = profile.value_if();
    config.application_id = argv[3];
    config.relay_url = argv[4];
    config.tenant = argv[6];
    config.wss_transport = transport;
    config.exchange = heyaki::make_relay_enrollment_wss_exchange(transport);
    auto enrolled =
        heyaki::enroll_relay_profile(config, argv[7], unix_milliseconds_now());
    if (!enrolled) {
      std::cerr << enrolled.error_if()->safe_detail() << '\n';
      return 1;
    }
    return 0;
  }
  if (command == "run") {
    if (argc < 8) {
      return usage();
    }
    RunOptions options;
    for (int index = 8; index < argc; ++index) {
      const std::string_view flag{argv[index]};
      if (flag == "--role" && index + 1 < argc) {
        options.role = argv[++index];
      } else if (flag == "--stun" && index + 1 < argc) {
        options.stun = argv[++index];
      } else if (flag == "--turn" && index + 1 < argc) {
        options.turn = argv[++index];
      } else if (flag == "--turn-secret" && index + 1 < argc) {
        options.turn_secret = argv[++index];
      } else if (flag == "--force-turn") {
        options.force_turn = true;
      } else if (flag == "--hold-ms" && index + 1 < argc) {
        options.hold = std::chrono::milliseconds{parse_u64(argv[++index])};
      } else if (flag == "--authenticate-budget-ms" && index + 1 < argc) {
        options.authenticate_budget = std::chrono::milliseconds{parse_u64(argv[++index])};
      } else if (flag == "--connect-retries" && index + 1 < argc) {
        options.retries = static_cast<unsigned>(parse_u64(argv[++index]));
      } else {
        return usage();
      }
    }
    return run_node(argv[2], argv[3], argv[4], std::filesystem::path{argv[5]},
                    argv[6], std::chrono::milliseconds{parse_u64(argv[7])}, options);
  }
  return usage();
}
