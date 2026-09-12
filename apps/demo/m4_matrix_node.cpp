// M4 network-matrix participant: a real Heyaki node used by the coturn
// topology harness. It performs local profile initialization, optional relay
// enrollment, then runs one bounded session attempt against the peer and
// prints a machine-readable MATRIX_RESULT line describing the outcome. The
// binary never talks to coturn itself; the driver script owns the topology.
#include <heyaki/message.hpp>
#include <heyaki/node.hpp>
#include <heyaki/rpc.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/trust_grant.hpp>
#include <heyaki/relay_enrollment_client.hpp>
#include <heyaki/runtime.hpp>

#include <executor/comm.hpp>

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifndef _WIN32
// Crash-reporter plumbing: POSIX signals plus glibc backtraces. The coturn
// harness runs on Linux only; Windows keeps a no-op installer below.
#include <csignal>
#include <dirent.h>
#include <execinfo.h>
#include <fcntl.h>
#include <limits>
#include <ucontext.h>
#include <unistd.h>
#else
#include <limits>
#endif

namespace {

using heyaki::Error;
using heyaki::ErrorCode;

#ifndef _WIN32
// Crash reporter for the topology harness: SIGBUS/SIGSEGV/SIGABRT/SIGFPE in
// the CI namespaces previously surfaced only as "Bus error" with no context.
// This handler writes the signal, fault address, the ucontext registers at
// the fault (needed to classify SIGBUS/SI_KERNEL events whose si_addr is
// null), the surrounding /proc/self/maps entries, and a best-effort
// backtrace — all through async-signal-safe-enough syscalls so the dumped
// output file pinpoints the faulting frame and mapping.
void crash_report(int signal_number, siginfo_t* info, void* context) {
  char prefix[512];
  const char* name = signal_number == SIGBUS    ? "SIGBUS"
                     : signal_number == SIGSEGV ? "SIGSEGV"
                     : signal_number == SIGABRT ? "SIGABRT"
                                                : "SIGFPE";
  std::size_t total = 0;
  const auto emit = [&total](const char* text, std::size_t length) {
    if (length == 0U) return;
    const auto ignored = write(STDERR_FILENO, text, length);
    (void)ignored;
    total += length;
  };
  (void)total;
  {
    ucontext_t* uc = static_cast<ucontext_t*>(context);
    const int written = std::snprintf(
        prefix, sizeof(prefix),
        "\nMATRIX_CRASH %s code=%d addr=%p rip=%llx rbp=%llx rbx=%llx rdi=%llx "
        "rsp=%llx\n",
        name, info ? info->si_code : -1, info ? info->si_addr : nullptr,
        uc ? static_cast<unsigned long long>(uc->uc_mcontext.gregs[REG_RIP]) : 0ULL,
        uc ? static_cast<unsigned long long>(uc->uc_mcontext.gregs[REG_RBP]) : 0ULL,
        uc ? static_cast<unsigned long long>(uc->uc_mcontext.gregs[REG_RBX]) : 0ULL,
        uc ? static_cast<unsigned long long>(uc->uc_mcontext.gregs[REG_RDI]) : 0ULL,
        uc ? static_cast<unsigned long long>(uc->uc_mcontext.gregs[REG_RSP]) : 0ULL);
    if (written > 0) emit(prefix, static_cast<std::size_t>(written));
  }
  // Backtrace FIRST: a maps read faulting inside the handler would trip
  // SA_RESETHAND and kill the process before the frames print (observed).
  emit("MATRIX_CRASH backtrace:\n", sizeof("MATRIX_CRASH backtrace:\n") - 1U);
  void* frames[64];
  const int depth = backtrace(frames, 64);
  if (depth > 0) {
    backtrace_symbols_fd(frames, depth, STDERR_FILENO);
  }
  // Memory-pressure indicators: a page fault the kernel cannot service
  // (allocation failure under pressure) delivers SIGBUS with a null address.
  {
    emit("MATRIX_CRASH statm:\n", sizeof("MATRIX_CRASH statm:\n") - 1U);
    const int statm = open("/proc/self/statm", O_RDONLY);
    if (statm >= 0) {
      char statm_buffer[256];
      const auto read_bytes = read(statm, statm_buffer, sizeof(statm_buffer) - 1U);
      close(statm);
      if (read_bytes > 0) {
        statm_buffer[read_bytes] = '\0';
        emit(statm_buffer, static_cast<std::size_t>(read_bytes));
      }
    }
  }
  emit("MATRIX_CRASH maps:\n", sizeof("MATRIX_CRASH maps:\n") - 1U);
  const int maps = open("/proc/self/maps", O_RDONLY);
  if (maps >= 0) {
    char chunk[4096];
    for (int rounds = 0; rounds < 64; ++rounds) {
      const auto read_bytes = read(maps, chunk, sizeof(chunk));
      if (read_bytes <= 0) break;
      emit(chunk, static_cast<std::size_t>(read_bytes));
    }
    close(maps);
  }
  _exit(128 + signal_number);
}
#endif  // !_WIN32

void install_crash_reporter() {
#ifndef _WIN32
  struct sigaction action {};
  action.sa_sigaction = crash_report;
  // SA_RESETHAND is an unsigned constant (0x80000000) that does not fit int;
  // the explicit cast keeps -Wsign-conversion quiet.
  action.sa_flags = static_cast<int>(SA_SIGINFO | SA_RESETHAND);
  sigaction(SIGBUS, &action, nullptr);
  sigaction(SIGSEGV, &action, nullptr);
  sigaction(SIGABRT, &action, nullptr);
  sigaction(SIGFPE, &action, nullptr);
#endif  // !_WIN32
}

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

// Signed variant for offset-style flags (negative = in the past).
std::int64_t parse_i64(std::string_view text) {
  const bool negative = !text.empty() && text.front() == '-';
  if (negative) {
    text.remove_prefix(1U);
  }
  const auto magnitude = parse_u64(text);
  const auto signed_value = static_cast<std::int64_t>(magnitude);
  return negative ? -signed_value : signed_value;
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

// M9-09 soak sampling: process-level footprint read from /proc where
// available (the soak harness runs on Linux). Other platforms report zeros
// and the harness treats the fields as informational only. The fd count is
// approximate (the opendir handle itself is included); cross-cycle deltas
// against a slack bound are the leak signal, not the absolute value.
struct ProcessSample {
  std::uint64_t rss_kb{};
  std::size_t open_fds{};
};

ProcessSample sample_process() {
  ProcessSample sample{};
#ifndef _WIN32
  {
    std::ifstream status("/proc/self/status");
    std::string key;
    while (status >> key) {
      if (key == "VmRSS:") {
        status >> sample.rss_kb;
        break;
      }
      status.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
  }
  if (DIR* directory = ::opendir("/proc/self/fd")) {
    struct dirent* entry = nullptr;
    while ((entry = ::readdir(directory)) != nullptr) {
      const std::string_view name{entry->d_name};
      if (name != "." && name != "..") {
        ++sample.open_fds;
      }
    }
    ::closedir(directory);
  }
#endif
  return sample;
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
                                  const heyaki::DeviceId& device_id,
                                  std::chrono::milliseconds expiry_offset = {}) {
  // M9-08: a negative offset derives already-stale REST credentials so the
  // fault matrix can prove coturn rejects expired allocations explicitly.
  const auto expiry = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count() +
                      600 + std::chrono::duration_cast<std::chrono::seconds>(
                                expiry_offset)
                                .count();
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
  // M9-07: explicit TURN credentials bypass the REST API derivation so a
  // libjuice static-credential test TURN server (Windows has no coturn) can
  // serve the turn_udp scenario.
  std::string turn_username;
  std::string turn_credential;
  bool force_turn{false};
  // NAT-matrix mode: keep server-reflexive candidates but exclude host
  // candidates, so the session must hole-punch through the emulated NAT
  // instead of shortcutting over directly routed private addresses.
  bool srflx_only{false};
  // M9-07: run without any relay — discovery and signaling stay on LAN
  // multicast + provisional TLS (the Windows matrix exercises the LAN-only
  // combination without relay infrastructure).
  bool lan_only{false};
  std::chrono::milliseconds hold{500};
  std::chrono::milliseconds authenticate_budget{15000};
  unsigned retries{0U};
  // M9-08 fault-matrix hooks: a sized m7 payload (slow-receiver scenarios),
  // a bounded pause mid-transfer giving the orchestrator a deterministic
  // fault window, a REST-credential expiry offset (negative = stale), and a
  // m7 completion-wait override for shaped links.
  std::uint64_t m7_bytes{0U};
  std::chrono::milliseconds m7_pause_hold{0};
  std::chrono::milliseconds m7_wait{15'000};
  std::chrono::milliseconds turn_expiry_offset{0};
  // M9-09 soak: the initiator loops connect/authenticate/exercise/disconnect
  // cycles in one process so per-cycle resource deltas expose leaks. The
  // harness SIGKILLs the responder after each cycle's work-done marker and
  // respawns it with the same profile (re-login republishes the endpoint).
  unsigned soak_cycles{0U};
};

int run_node(const std::filesystem::path& database, std::string_view application_id,
             const std::string& relay_url, const std::filesystem::path& ca_file,
             const std::string& tenant, std::chrono::milliseconds total_budget,
             const RunOptions& options) {
  // Unbuffered stdout: a crash mid-scenario must still leave its progress
  // markers in the output file the matrix script dumps on failure.
  std::cout << std::unitbuf;
  install_crash_reporter();
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
  if (options.lan_only) {
    // Same cadence the m3a LAN tests use: fast announcements keep the
    // discovery phase well inside the scenario budgets on a quiet link.
    lan.enabled = true;
    lan.discoverable = true;
    lan.connectivity_mode = heyaki::ConnectivityMode::lan_only;
    lan.announcement_interval = std::chrono::milliseconds{200};
    lan.announcement_jitter = std::chrono::milliseconds{0};
    lan.presence_lease = std::chrono::milliseconds{2000};
  }

  auto profiled = profile.value_if();
  const auto device_id = profiled->device_id();
  heyaki::PeerPathPolicy policy;
  policy.allow_ipv6_host = false;
  if (options.lan_only) {
    // lan_only sessions must not carry reflexive candidates, TURN servers,
    // or a forced path (Node rejects such policies); host candidates only.
    policy.allow_server_reflexive = false;
    policy.allow_turn_udp = false;
  }
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
    heyaki::NodeIceServer server;
    if (!options.turn_username.empty() && !options.turn_credential.empty()) {
      server.kind = heyaki::NodeIceServerKind::turn_udp;
      server.hostname = options.turn->substr(0U, separator);
      server.port = static_cast<std::uint16_t>(
          parse_u64(options.turn->substr(separator + 1U)));
      server.username = options.turn_username;
      server.credential = options.turn_credential;
    } else {
      server = turn_server(
          options.turn->substr(0U, separator),
          static_cast<std::uint16_t>(parse_u64(options.turn->substr(separator + 1U))),
          options.turn_secret, tenant, device_id, options.turn_expiry_offset);
    }
    policy.ice_servers.push_back(std::move(server));
  }
  policy.force_turn_data_path = options.force_turn;
  if (options.force_turn) {
    policy.allow_server_reflexive = false;
    policy.allow_ipv4_host = false;
  }
  if (options.srflx_only) {
    policy.allow_ipv4_host = false;
  }

  // M7: both matrix roles host an "inbox" root beside their profile and a
  // small source file the initiator pushes across the topology under test.
  const auto m7_state_dir = database.parent_path() / "m7-files";
  std::error_code m7_dir_ec;
  std::filesystem::create_directories(m7_state_dir, m7_dir_ec);
  const auto m7_source = m7_state_dir / "matrix-source.bin";
  if (options.m7_bytes == 0U) {
    std::ofstream out(m7_source, std::ios::binary | std::ios::trunc);
    for (int index = 0; index < 6000; ++index) {
      out << "m7 matrix payload " << index << '\n';
    }
  } else {
    // Sized deterministic payload for slow-receiver scenarios: the repeating
    // pattern keeps the file compressible in memory but the wire still
    // carries every chunk (no compression on the file channel).
    std::ofstream out(m7_source, std::ios::binary | std::ios::trunc);
    const std::string pattern = "m7 matrix payload 0123456789abcdef\n";
    std::uint64_t written = 0U;
    while (written < options.m7_bytes) {
      const auto chunk = std::min<std::uint64_t>(pattern.size(),
                                                 options.m7_bytes - written);
      out.write(pattern.data(), static_cast<std::streamsize>(chunk));
      written += chunk;
    }
  }
  heyaki::FileRootConfig m7_root;
  m7_root.name = "inbox";
  m7_root.directory = m7_state_dir / "inbox";
  std::filesystem::create_directories(m7_root.directory, m7_dir_ec);
  heyaki::NodeConfig config;
  config.profile = profiled;
  config.application_id = std::string{application_id};
  config.lan_override = lan;
  if (!options.lan_only) {
    config.relay_override = relay;
  }
  config.path_policy_override = policy;
  config.file_receive_roots = {m7_root};
  auto node = heyaki::Node::create(std::move(config));
  if (!node) {
    std::cerr << "node create failed: " << node.error_if()->safe_detail() << '\n';
    return 1;
  }

  std::cout << "MATRIX_PHASE node-created\n";
  if (!options.lan_only) {
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
  }

  const auto local_key = heyaki::DeviceEndpointKey{
      node.value_if()->snapshot().device_id,
      node.value_if()->snapshot().endpoint_id};
  // M6: the same message/RPC exercise runs on every topology (direct and
  // forced-TURN) because it rides the session, never the path (RULE-09).
  // Latest outcomes cross from the node callbacks into this loop through
  // executor comm mailboxes (latest-value semantics, observable stats).
  executor::comm::LatestMailbox<bool> m6_message_acked{"heyaki-m4-matrix-acked"};
  executor::comm::LatestMailbox<int> m6_rpc_status{"heyaki-m4-matrix-rpc-status"};
  executor::comm::LatestMailbox<bool> m7_event_received{"heyaki-m4-matrix-m7-event"};
  executor::comm::LatestMailbox<bool> m7_file_committed{"heyaki-m4-matrix-m7-file"};
  executor::comm::LatestMailbox<bool> m7_transferring{"heyaki-m4-matrix-m7-transferring"};
  (void)m6_message_acked.try_publish(false);
  (void)m6_rpc_status.try_publish(-1);
  (void)m7_event_received.try_publish(false);
  (void)m7_file_committed.try_publish(false);
  (void)m7_transferring.try_publish(false);
  {
    heyaki::RpcMethodDescriptor echo;
    echo.service = "heyaki.matrix";
    echo.method = "echo";
    echo.schema_version = 1U;
    echo.required_scope = "rpc.device.read";
    (void)node.value_if()->register_rpc_method(
        echo, [](const heyaki::RpcCallContext& context) {
          return heyaki::RpcHandlerResult{
              heyaki::StableStatus::ok,
              std::vector<std::byte>(context.payload().begin(), context.payload().end()),
              "ok"};
        });
  }
  node.value_if()->set_message_ack_observer(
      [&m6_message_acked](const heyaki::DeviceEndpointKey&, const heyaki::MessageId&,
                          heyaki::MessageDeliveryEvent event,
                          std::optional<Error>) {
        if (event == heyaki::MessageDeliveryEvent::acked) {
          (void)m6_message_acked.try_publish(true);
        }
      });
  node.value_if()->set_event_inbound_handler(
      [&m7_event_received](const heyaki::DeviceEndpointKey&, std::string_view,
                           const heyaki::EventItemBody&) {
        (void)m7_event_received.try_publish(true);
      });
  node.value_if()->set_file_event_observer(
      [&m7_file_committed, &m7_transferring](
          const heyaki::DeviceEndpointKey&,
          const heyaki::FileTransferEvent& event) {
        if (event.phase == heyaki::FileTransferPhase::committed) {
          (void)m7_file_committed.try_publish(true);
        } else if (event.phase == heyaki::FileTransferPhase::transferring) {
          (void)m7_transferring.try_publish(true);
        }
      });
  const auto begin = std::chrono::steady_clock::now();
  bool attempted = false;
  // LAN-only discovery surfaces the peer through the multicast directory
  // (entry.lan); relay-mode discovery through the relay endpoint directory
  // (entry.relay).
  const auto peer_has_endpoint = [lan_only = options.lan_only](
                                     const auto& entry) {
    return lan_only ? entry.lan.has_value() : entry.relay.has_value();
  };
  const auto find_peer = [&]() -> std::optional<heyaki::DeviceEndpointKey> {
    const auto entries = node.value_if()->endpoints();
    const auto peer = std::find_if(entries.begin(), entries.end(),
                                   [&](const auto& entry) {
                                     return entry.key != local_key &&
                                            peer_has_endpoint(entry);
                                   });
    if (peer == entries.end()) {
      return std::nullopt;
    }
    return peer->key;
  };

  struct ServiceExerciseOutcome {
    bool message_acked{false};
    int rpc_status{-1};
    bool event_received{false};
    bool file_committed{false};
  };
  // M6+M7 service exercise on the authenticated session (initiator side),
  // shared verbatim by the one-shot flow and every soak cycle. The mailbox
  // observers remain the one-shot flow's source of truth; soak callers read
  // the returned fields instead.
  const auto exercise_initiator_services =
      [&](const heyaki::DeviceEndpointKey& peer_key,
          const std::string& m7_destination) -> ServiceExerciseOutcome {
    ServiceExerciseOutcome outcome;
    if (peer_key.device_id.is_zero() ||
        !wait_until(
            [&] {
              const auto services = node.value_if()->service_diagnostics();
              return services.message_sessions > 0U && services.rpc_sessions > 0U;
            },
            std::chrono::milliseconds{5000})) {
      return outcome;
    }
    {
      std::cout << "MATRIX_PHASE m6-exercise-begin\n";
      heyaki::MessageEnvelope envelope;
      envelope.type = "matrix.m6";
      envelope.delivery_mode = heyaki::MessageDeliveryMode::peer_acked;
      envelope.ttl_milliseconds = 20'000U;
      envelope.payload = {std::byte{0x6D}, std::byte{0x36}};
      (void)node.value_if()->send_message(peer_key, std::move(envelope));
      (void)node.value_if()->call_rpc(
          peer_key, "heyaki.matrix", "echo", {std::byte{0x2A}},
          heyaki::RpcCallOptions{},
          [&m6_rpc_status](const heyaki::DeviceEndpointKey&,
                           heyaki::Result<heyaki::RpcCallOutcome> result) {
            if (result) {
              (void)m6_rpc_status.try_publish(
                  static_cast<int>((*result.value_if()).status));
            } else if (result.error_if()->code() == heyaki::ErrorCode::peer_offline) {
              // Session churn under netem: the call was rejected before it
              // left the device — a deterministic, never-executed outcome.
              (void)m6_rpc_status.try_publish(-2);
            } else {
              // Any other local admission failure: encode the error code so
              // the matrix result line names it (e.g. -124 = internal).
              (void)m6_rpc_status.try_publish(
                  -100 - static_cast<int>(result.error_if()->code()));
            }
          });
      (void)wait_until(
          [&] {
            (void)m6_message_acked.try_load(outcome.message_acked);
            (void)m6_rpc_status.try_load(outcome.rpc_status);
            return outcome.message_acked && outcome.rpc_status >= 0;
          },
          std::chrono::milliseconds{8000});
      std::cout << "MATRIX_PHASE m6-exercise-end message="
                << (outcome.message_acked ? 1 : 0)
                << " rpc=" << outcome.rpc_status << "\n";
    }
    if (!wait_until(
            [&] {
              const auto services = node.value_if()->service_diagnostics();
              return services.event_sessions > 0U && services.file_sessions > 0U;
            },
            std::chrono::milliseconds{5000})) {
      return outcome;
    }
    {
      std::cout << "MATRIX_PHASE m7-exercise-begin\n";
      const std::string text = "matrix m7 load";
      std::vector<std::byte> payload;
      for (const char value : text) {
        payload.push_back(static_cast<std::byte>(value));
      }
      (void)node.value_if()->publish_event(peer_key, "telemetry.matrix.load",
                                           std::move(payload), 1U);
      const auto pushed =
          node.value_if()->push_file(peer_key, "inbox", m7_destination, m7_source);
      if (pushed && options.m7_pause_hold.count() > 0) {
        // M9-08 fault window: pause at the first transferring event so the
        // orchestrator can kill a dependency (relay, coturn) at a
        // deterministic mid-transfer point, then resume across the fault.
        bool transferring = false;
        (void)wait_until(
            [&] {
              (void)m7_transferring.try_load(transferring);
              return transferring;
            },
            std::chrono::milliseconds{5000});
        if (transferring) {
          std::cout << "MATRIX_PHASE m7-paused\n";
          const auto paused = node.value_if()->pause_file_transfer(
              peer_key, *pushed.value_if());
          if (!paused) {
            std::cout << "MATRIX_PHASE m7-pause-error="
                      << paused.error_if()->safe_detail() << "\n";
          }
          executor::comm::PhaseGate pause_hold{"heyaki-m4-matrix-m7-pause"};
          (void)pause_hold.wait_for(1U, options.m7_pause_hold);
          const auto resumed = node.value_if()->resume_file_transfer(
              peer_key, *pushed.value_if());
          std::cout << "MATRIX_PHASE m7-resumed"
                    << (resumed
                            ? std::string{}
                            : " resume_error=" +
                                  std::string{resumed.error_if()->safe_detail()})
                    << "\n";
        }
      } else if (!pushed) {
        std::cout << "MATRIX_PHASE m7-push-error="
                  << pushed.error_if()->safe_detail() << "\n";
      }
      (void)wait_until(
          [&] {
            (void)m7_event_received.try_load(outcome.event_received);
            (void)m7_file_committed.try_load(outcome.file_committed);
            return outcome.file_committed;  // events are best-effort: file is the gate
          },
          options.m7_wait);
      std::cout << "MATRIX_PHASE m7-exercise-end event="
                << (outcome.event_received ? 1 : 0)
                << " file=" << (outcome.file_committed ? 1 : 0) << "\n";
    }
    return outcome;
  };

  if (options.soak_cycles > 0U) {
    // M9-09 session-churn soak: bounded cycles of dial/authenticate/exercise
    // in this one process while the harness SIGKills and respawns the peer
    // after every cycle (tests/network/run_m9_soak_harness.sh). Per-cycle
    // RSS/fd/session/replay/worker samples make growth visible; the gates
    // ride SOAK_SUMMARY. Everything below returns; the one-shot flow that
    // follows is untouched.
    const auto soak_begin = std::chrono::steady_clock::now();
    struct CycleOutcome {
      bool work_done{false};
      bool closed_cleanly{false};
      bool message_acked{false};
      int rpc_status{-1};
      bool file_committed{false};
      std::uint64_t work_rss_kb{};
      std::uint64_t closed_rss_kb{};
      std::size_t work_fds{};
      std::size_t closed_fds{};
      std::string data_path{"none"};
    };
    std::vector<CycleOutcome> cycles;
    std::size_t replay_peak = 0U;
    for (unsigned cycle_index = 1U; cycle_index <= options.soak_cycles;
         ++cycle_index) {
      CycleOutcome cycle;
      // The respawned peer republishes its endpoint after re-login. A stale
      // record from the previous cycle can outlive the kill until its lease
      // expires, so the bounded re-dials below (not this wait) absorb a dial
      // against a dead record.
      if (!wait_until([&] { return find_peer().has_value(); },
                      std::chrono::milliseconds{20000})) {
        std::cout << "SOAK_CYCLE idx=" << cycle_index << " state=no-peer\n";
        break;
      }
      const auto peer_key = *find_peer();
      std::cout << "MATRIX_PHASE connecting\n";
      const auto first_dial = options.lan_only
                                  ? node.value_if()->connect_lan(peer_key)
                                  : node.value_if()->connect(peer_key);
      bool dialed = (bool)first_dial;
      if (!dialed) {
        // Synchronous admission failure (for example coordinator capacity):
        // give the respawned peer a moment to republish, then try once more
        // before the bounded authenticated wait.
        executor::comm::PhaseGate redial_gap{"heyaki-m4-matrix-redial"};
        (void)redial_gap.wait_for(1U, std::chrono::milliseconds{500});
        const auto peer_retry = find_peer();
        if (peer_retry.has_value()) {
          dialed = (bool)(options.lan_only
                              ? node.value_if()->connect_lan(*peer_retry)
                              : node.value_if()->connect(*peer_retry));
        }
      }
      unsigned dial_retries = options.retries + 2U;
      const bool authenticated = dialed && wait_until(
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
            // Re-dial when the previous attempt terminated without a
            // session; the respawned peer may not have republished when the
            // first dial landed on its stale directory record.
            if (dial_retries == 0U) {
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
            const auto peer = find_peer();
            if (!peer.has_value()) {
              return false;
            }
            --dial_retries;
            return (bool)(options.lan_only ? node.value_if()->connect_lan(*peer)
                                           : node.value_if()->connect(*peer));
          });
      if (!authenticated) {
        std::cout << "SOAK_CYCLE idx=" << cycle_index
                  << " state=never-authenticated\n";
        break;
      }
      {
        const auto sessions = node.value_if()->peer_sessions();
        const auto session = std::find_if(
            sessions.begin(), sessions.end(), [](const auto& candidate) {
              return candidate.state ==
                     heyaki::NodePeerSessionState::authenticated;
            });
        if (session != sessions.end()) {
          cycle.data_path =
              std::string{heyaki::node_data_path_kind_name(session->data_path)};
        }
      }
      // Fresh latest-value state per cycle (the mailboxes otherwise keep the
      // previous cycle's outcomes).
      (void)m6_message_acked.try_publish(false);
      (void)m6_rpc_status.try_publish(-1);
      (void)m7_event_received.try_publish(false);
      (void)m7_file_committed.try_publish(false);
      const auto outcome = exercise_initiator_services(
          peer_key, "matrix/soak-" + std::to_string(cycle_index) + ".bin");
      cycle.message_acked = outcome.message_acked;
      cycle.rpc_status = outcome.rpc_status;
      cycle.file_committed = outcome.file_committed;
      cycle.work_done =
          cycle.message_acked && cycle.rpc_status >= 0 && cycle.file_committed;
      const auto work_sample = sample_process();
      const auto work_metrics = node.value_if()->metrics();
      cycle.work_rss_kb = work_sample.rss_kb;
      cycle.work_fds = work_sample.open_fds;
      replay_peak = std::max(
          replay_peak, work_metrics.node.session_coordinator.replay_peak_entries);
      std::cout << "SOAK_CYCLE idx=" << cycle_index << " state=work-done"
                << " m6=" << (cycle.message_acked ? 1 : 0)
                << " rpc=" << cycle.rpc_status
                << " m7=" << (cycle.file_committed ? 1 : 0)
                << " rss_kb=" << work_sample.rss_kb
                << " fds=" << work_sample.open_fds
                << " sessions=" << node.value_if()->peer_sessions().size()
                << " replay="
                << work_metrics.node.session_coordinator.replay_current_entries
                << " tasks_active="
                << work_metrics.runtime.executor_active_task_count
                << " tasks_queued="
                << work_metrics.runtime.executor_queued_task_count
                << " data_path=" << cycle.data_path << '\n';
      if (!cycle.work_done) {
        break;
      }
      // The harness kills the responder once the work-done line is out; the
      // authenticated session must reach a terminal state within the ICE
      // consent window (RFC 7675, 30s on the pinned dependency) plus margin.
      const bool closed = wait_until(
          [&] {
            const auto sessions = node.value_if()->peer_sessions();
            return sessions.empty() ||
                   std::all_of(sessions.begin(), sessions.end(),
                               [](const auto& session) {
                                 return session.state ==
                                        heyaki::NodePeerSessionState::closed;
                               });
          },
          std::chrono::milliseconds{45000});
      cycle.closed_cleanly = closed;
      const auto closed_sample = sample_process();
      cycle.closed_rss_kb = closed_sample.rss_kb;
      cycle.closed_fds = closed_sample.open_fds;
      std::cout << "SOAK_CYCLE idx=" << cycle_index << " state=closed"
                << " ok=" << (closed ? 1 : 0)
                << " rss_kb=" << closed_sample.rss_kb
                << " fds=" << closed_sample.open_fds
                << " sessions=" << node.value_if()->peer_sessions().size()
                << '\n';
      cycles.push_back(cycle);
      if (!closed) {
        break;
      }
    }
    // Closed sessions retire into the bounded diagnostic history
    // (finished_peer_sessions, capacity = lan.diagnostic_capacity) by
    // design; the drain gate is "no live session remains", not an empty
    // peer_sessions() listing.
    const auto live_peer_sessions = [&] {
      std::size_t live = 0U;
      for (const auto& session : node.value_if()->peer_sessions()) {
        if (session.state != heyaki::NodePeerSessionState::closed) {
          ++live;
        }
      }
      return live;
    };
    (void)wait_until([&] { return live_peer_sessions() == 0U; },
                     std::chrono::milliseconds{5000});
    std::size_t work_done_count = 0U;
    std::size_t closed_ok_count = 0U;
    std::uint64_t rss_first = 0U;
    std::uint64_t rss_last = 0U;
    std::uint64_t rss_max = 0U;
    std::size_t fds_first = 0U;
    std::size_t fds_last = 0U;
    std::size_t fds_max = 0U;
    bool all_message_acked = !cycles.empty();
    int last_rpc_status = -1;
    bool all_files_committed = !cycles.empty();
    for (const auto& cycle : cycles) {
      work_done_count += cycle.work_done ? 1U : 0U;
      closed_ok_count += cycle.closed_cleanly ? 1U : 0U;
      all_message_acked = all_message_acked && cycle.message_acked;
      last_rpc_status = cycle.rpc_status;
      all_files_committed = all_files_committed && cycle.file_committed;
      if (rss_first == 0U) {
        rss_first = cycle.work_rss_kb;
      }
      if (cycle.closed_rss_kb != 0U) {
        rss_last = cycle.closed_rss_kb;
      }
      rss_max = std::max({rss_max, cycle.work_rss_kb, cycle.closed_rss_kb});
      if (fds_first == 0U) {
        fds_first = cycle.work_fds;
      }
      if (cycle.closed_fds != 0U) {
        fds_last = cycle.closed_fds;
      }
      fds_max = std::max({fds_max, cycle.work_fds, cycle.closed_fds});
    }
    const auto final_metrics = node.value_if()->metrics();
    const auto soak_elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - soak_begin)
            .count();
    std::cout << "SOAK_SUMMARY cycles=" << cycles.size()
              << "/" << options.soak_cycles << " work_done=" << work_done_count
              << " closed_ok=" << closed_ok_count
              << " rss_first_kb=" << rss_first << " rss_last_kb=" << rss_last
              << " rss_max_kb=" << rss_max << " fds_first=" << fds_first
              << " fds_last=" << fds_last << " fds_max=" << fds_max
              << " replay_peak=" << replay_peak
              << " sessions_final=" << node.value_if()->peer_sessions().size()
              << " sessions_live_final=" << live_peer_sessions()
              << " tasks_active_final="
              << final_metrics.runtime.executor_active_task_count
              << " duration_ms=" << soak_elapsed << '\n';
    const bool soak_ok = cycles.size() == options.soak_cycles &&
                         work_done_count == options.soak_cycles &&
                         closed_ok_count == options.soak_cycles &&
                         live_peer_sessions() == 0U;
    std::cout << "MATRIX_RESULT authenticated=" << (soak_ok ? 1 : 0)
              << " data_path="
              << (cycles.empty() ? std::string{"none"} : cycles.back().data_path)
              << " duration_ms=" << soak_elapsed << " attempted=1"
              << " state=closed stage=none session_error=-"
              << " m6_message_acked=" << (all_message_acked ? 1 : 0)
              << " m6_rpc_status=" << last_rpc_status
              << " m7_event=1 m7_file=" << (all_files_committed ? 1 : 0)
              << " relay_state="
              << heyaki::relay_node_state_name(final_metrics.node.relay.state)
              << " coordinator_attempts="
              << final_metrics.node.session_coordinator.current_attempts
              << " relay_reconnects="
              << final_metrics.node.relay.reconnect_count
              << " heartbeats_missed="
              << final_metrics.node.relay.heartbeats_missed
              << " endpoints_seen=" << node.value_if()->endpoints().size()
              << '\n';
    std::cout << "MATRIX_PHASE shutting-down\n";
    const auto soak_shutdown = node.value_if()->shutdown();
    if (!soak_shutdown.stopped) {
      std::cerr << "node shutdown did not drain\n";
      return 1;
    }
    return 0;
  }

  if (options.role == "initiator") {
    const auto peer_endpoint = wait_until(
        [&] {
          const auto entries = node.value_if()->endpoints();
          return std::any_of(entries.begin(), entries.end(),
                             [&](const auto& entry) {
                               return entry.key != local_key &&
                                      peer_has_endpoint(entry);
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
                                            peer_has_endpoint(entry);
                                   });
    const auto connected = options.lan_only
                               ? node.value_if()->connect_lan(peer->key)
                               : node.value_if()->connect(peer->key);
    attempted = (bool)connected;
    if (!connected) {
      std::cout << "MATRIX_RESULT authenticated=0 data_path=none duration_ms=0"
                << " connect_error=" << connected.error_if()->safe_detail() << '\n';
      (void)node.value_if()->shutdown();
      return 0;
    }
  }

  unsigned connect_retries = options.retries;
  std::cout << "MATRIX_PHASE connecting\n";
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
                                                peer_has_endpoint(entry);
                                       });
        if (peer == entries.end()) {
          return false;
        }
        --connect_retries;
        return (bool)(options.lan_only ? node.value_if()->connect_lan(peer->key)
                                       : node.value_if()->connect(peer->key));
      });
  // Responder side: subscribe to the telemetry root so the initiator's
  // event publish has a matching subscription (publisher-direct model).
  if (options.role != "initiator") {
    (void)wait_until(
        [&] {
          for (const auto& session : node.value_if()->peer_sessions()) {
            if (session.state == heyaki::NodePeerSessionState::authenticated) {
              (void)node.value_if()->subscribe_events(
                  session.peer, "telemetry", true, heyaki::EventQos::best_effort_latest);
              return true;
            }
          }
          return false;
        },
        std::chrono::milliseconds{2000});
  }
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
    std::cout << "MATRIX_PHASE authenticated\n";
    // M6 exercise (initiator side): one peer_acked message and one unary RPC
    // through the public API on whatever data path the session negotiated.
    // The services attach asynchronously after authorization, so wait for the
    // service diagnostics to confirm them before exercising; a relay-restart
    // churn scenario may drop the session mid-exercise, which reports as
    // m6=0/-1 rather than a topology failure.
    if (options.role == "initiator") {
      heyaki::DeviceEndpointKey peer_key{};
      for (const auto& session : node.value_if()->peer_sessions()) {
        if (session.state == heyaki::NodePeerSessionState::authenticated) {
          peer_key = session.peer;
          break;
        }
      }
      // M6 message+RPC and the M7 event+file push ride the authenticated
      // session on every topology (the responder subscribes to the telemetry
      // root; both directions carry file scopes). A relay-restart churn
      // scenario may drop the session mid-exercise, which reports as
      // m6=0/-1 rather than a topology failure. The mailbox loads below the
      // block carry the outcomes into the result line.
      (void)exercise_initiator_services(peer_key, "matrix/m7.bin");
    }
    executor::comm::PhaseGate hold{"heyaki-m4-matrix-hold"};
    (void)hold.wait_for(1U, options.hold);
    // A relay restart mid-hold races this exit against the bounded-backoff
    // re-login. Give the recovery a bounded grace to reach ready before
    // sampling, so relay_state reports the recovery outcome instead of the
    // exit instant; a genuinely broken re-login still surfaces as degraded.
    // LAN-only runs have no relay to recover — skip the grace entirely.
    if (!options.lan_only) {
      const auto grace_deadline =
          std::chrono::steady_clock::now() + std::chrono::seconds{8};
      while (node.value_if()->snapshot().relay.state !=
                 heyaki::RelayNodeState::ready &&
             std::chrono::steady_clock::now() < grace_deadline) {
        executor::comm::PhaseGate grace{"heyaki-m4-matrix-grace"};
        (void)grace.wait_for(1U, std::chrono::milliseconds{100});
      }
    }
  }
  const auto snapshot = node.value_if()->snapshot();
  if (!authenticated) {
    std::cerr << "HEYAKI_DEBUG failure_dump\n";
    for (const auto& entry : node.value_if()->endpoints()) {
      std::cerr << "  endpoint device=" << heyaki::to_string(entry.key.device_id)
                << " trusted=" << (entry.trusted ? 1 : 0)
                << " lan=" << (entry.lan.has_value() ? 1 : 0)
                << " addr="
                << (entry.lan.has_value()
                        ? entry.lan->address + ":" +
                              std::to_string(entry.lan->tls_signaling_port)
                        : std::string{"-"})
                << " relay=" << (entry.relay.has_value() ? 1 : 0) << '\n';
    }
    for (const auto& connection : node.value_if()->signaling_connections()) {
      std::cerr << "  signaling state=" << static_cast<int>(connection.state)
                << " inbound=" << (connection.inbound ? 1 : 0)
                << " owner=" << (connection.local_offer_owner ? 1 : 0)
                << " addr=" << connection.address << " error="
                << (connection.error ? connection.error->safe_detail()
                                     : std::string{"-"})
                << '\n';
    }
    std::cerr << "  last_error="
              << (snapshot.last_error ? snapshot.last_error->safe_detail()
                                      : std::string{"-"})
              << " lan_state=" << static_cast<int>(snapshot.lan_state)
              << " tls_ready="
              << (snapshot.tls.listener_ready ? 1 : 0)
              << " tls_port=" << snapshot.tls.listen_port
              << " pending_signaling="
              << snapshot.resources.signaling_callbacks_in_flight << '\n';
  }
  bool final_message_acked = false;
  int final_rpc_status = -1;
  bool final_event_received = false;
  bool final_file_committed = false;
  (void)m6_message_acked.try_load(final_message_acked);
  (void)m6_rpc_status.try_load(final_rpc_status);
  (void)m7_event_received.try_load(final_event_received);
  (void)m7_file_committed.try_load(final_file_committed);
  std::cout << "MATRIX_RESULT authenticated=" << (authenticated ? 1 : 0)
            << " data_path=" << data_path << " duration_ms=" << elapsed
            << " attempted=" << (attempted ? 1 : 0)
            << " state=" << heyaki::node_peer_session_state_name(final_state)
            << " stage=" << stage
            << " session_error=" << session_error
            << " m6_message_acked=" << (final_message_acked ? 1 : 0)
            << " m6_rpc_status=" << final_rpc_status
            << " m7_event=" << (final_event_received ? 1 : 0)
            << " m7_file=" << (final_file_committed ? 1 : 0)
            << " relay_state=" << heyaki::relay_node_state_name(snapshot.relay.state)
            << " coordinator_attempts="
            << snapshot.session_coordinator.current_attempts
            << " relay_reconnects=" << snapshot.relay.reconnect_count
            << " heartbeats_missed=" << snapshot.relay.heartbeats_missed
            << " endpoints_seen=" << node.value_if()->endpoints().size()
            << '\n';
  std::cout << "MATRIX_PHASE shutting-down\n";
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
            << "  heyaki-m4-matrix-node seed-trust FIRST_DB SECOND_DB\n"
            << "  heyaki-m4-matrix-node enroll DB APP_ID RELAY_URL CA TENANT TOKEN\n"
            << "  heyaki-m4-matrix-node run DB APP_ID RELAY_URL CA TENANT BUDGET_MS\n"
            << "      [--role initiator|responder] [--stun HOST:PORT]\n"
            << "      [--turn HOST:PORT] [--turn-secret SECRET] [--force-turn]\n"
            << "      [--turn-username NAME --turn-credential SECRET]\n"
            << "      [--srflx-only] [--lan-only]\n"
            << "      [--hold-ms N] [--authenticate-budget-ms N] [--connect-retries N]\n"
            << "      [--m7-bytes N] [--m7-pause-hold-ms N] [--m7-wait-ms N]\n"
            << "      [--turn-credential-expiry-offset-ms N]\n"
            << "      [--soak-cycles N]  (initiator only; M9-09 soak)\n";
  return 2;
}


// M5 default-deny: connectivity scenarios need pre-seeded mutual trust.
// Signs one directional grant with the issuer's device identity and stores
// it as issued in the issuer's TrustStore and received in the subject's.
heyaki::Result<void> seed_one_way_trust(heyaki::ProfileStore& issuer_store,
                                        heyaki::ProfileStore& subject_store,
                                        const std::vector<std::string>& scopes,
                                        std::uint8_t id_seed) {
  auto issuer_identity = issuer_store.load_identity();
  if (!issuer_identity) {
    return heyaki::Result<void>::failure(*issuer_identity.error_if());
  }
  heyaki::SignedTrustGrant grant;
  heyaki::GrantId::Storage grant_bytes{};
  grant_bytes[0] = static_cast<std::byte>(id_seed);
  for (std::size_t index = 1U; index < grant_bytes.size(); ++index) {
    grant_bytes[index] = static_cast<std::byte>((index * 31U + id_seed) & 0xFFU);
  }
  grant.grant_id = heyaki::GrantId{grant_bytes};
  grant.issuer = issuer_store.device_id();
  grant.subject = subject_store.device_id();
  grant.granted_scopes = scopes;
  grant.password_generation = 1U;
  grant.issued_unix_milliseconds = 1'700'000'000'000U;
  heyaki::PairingNonce nonce{};
  for (std::size_t index = 0U; index < nonce.size(); ++index) {
    nonce[index] = static_cast<std::byte>((index * 17U + id_seed) & 0xFFU);
  }
  grant.nonce = nonce;
  auto signed_grant =
      heyaki::sign_signed_trust_grant(grant, *issuer_identity.value_if());
  if (!signed_grant) {
    return heyaki::Result<void>::failure(*signed_grant.error_if());
  }
  auto as_record = [](const heyaki::SignedTrustGrant& value,
                      heyaki::TrustGrantDirection direction) {
    heyaki::TrustGrantRecord record;
    record.grant_id = value.grant_id;
    record.direction = direction;
    record.issuer = value.issuer;
    record.subject = value.subject;
    record.scopes = value.granted_scopes;
    record.password_generation = value.password_generation;
    record.issued_unix_milliseconds = value.issued_unix_milliseconds;
    record.signature.assign(value.signature.begin(), value.signature.end());
    record.revoked = false;
    return record;
  };
  auto issued =
      issuer_store.put_trust_grant(as_record(grant, heyaki::TrustGrantDirection::issued));
  if (!issued) return issued;
  return subject_store.put_trust_grant(
      as_record(grant, heyaki::TrustGrantDirection::received));
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
  if (command == "seed-trust") {
    if (argc != 4) {
      return usage();
    }
    auto first = heyaki::ProfileStore::open(argv[2]);
    if (!first) {
      std::cerr << first.error_if()->safe_detail() << '\n';
      return 1;
    }
    auto second = heyaki::ProfileStore::open(argv[3]);
    if (!second) {
      std::cerr << second.error_if()->safe_detail() << '\n';
      return 1;
    }
    // Grants canonicalize to a sorted, deduplicated scope list.
  const std::vector<std::string> scopes = {"event.subscribe:*", "file.pull:inbox",
                                        "file.push:inbox",   "matrix.connect",
                                        "message.send",      "rpc.device.read"};
    auto forward = seed_one_way_trust(*first.value_if(), *second.value_if(), scopes, 1U);
    if (!forward) {
      std::cerr << forward.error_if()->safe_detail() << '\n';
      return 1;
    }
    auto backward = seed_one_way_trust(*second.value_if(), *first.value_if(), scopes, 2U);
    if (!backward) {
      std::cerr << backward.error_if()->safe_detail() << '\n';
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
      } else if (flag == "--turn-username" && index + 1 < argc) {
        options.turn_username = argv[++index];
      } else if (flag == "--turn-credential" && index + 1 < argc) {
        options.turn_credential = argv[++index];
      } else if (flag == "--force-turn") {
        options.force_turn = true;
      } else if (flag == "--srflx-only") {
        options.srflx_only = true;
      } else if (flag == "--lan-only") {
        options.lan_only = true;
      } else if (flag == "--hold-ms" && index + 1 < argc) {
        options.hold = std::chrono::milliseconds{parse_u64(argv[++index])};
      } else if (flag == "--authenticate-budget-ms" && index + 1 < argc) {
        options.authenticate_budget = std::chrono::milliseconds{parse_u64(argv[++index])};
      } else if (flag == "--connect-retries" && index + 1 < argc) {
        options.retries = static_cast<unsigned>(parse_u64(argv[++index]));
      } else if (flag == "--m7-bytes" && index + 1 < argc) {
        options.m7_bytes = parse_u64(argv[++index]);
      } else if (flag == "--m7-pause-hold-ms" && index + 1 < argc) {
        options.m7_pause_hold =
            std::chrono::milliseconds{parse_u64(argv[++index])};
      } else if (flag == "--m7-wait-ms" && index + 1 < argc) {
        options.m7_wait = std::chrono::milliseconds{parse_u64(argv[++index])};
      } else if (flag == "--turn-credential-expiry-offset-ms" && index + 1 < argc) {
        options.turn_expiry_offset =
            std::chrono::milliseconds{parse_i64(argv[++index])};
      } else if (flag == "--soak-cycles" && index + 1 < argc) {
        options.soak_cycles = static_cast<unsigned>(parse_u64(argv[++index]));
      } else {
        return usage();
      }
    }
    // The soak loop dials, exercises, and waits for the peer's death per
    // cycle; it has no responder-side variant.
    if (options.soak_cycles > 0U && options.role != "initiator") {
      std::cerr << "--soak-cycles requires --role initiator\n";
      return usage();
    }
    // lan_only sessions carry host candidates only; contradictory transport
    // flags would only surface later as a Node policy rejection.
    if (options.lan_only &&
        (options.stun.has_value() || options.turn.has_value() ||
         options.force_turn || options.srflx_only)) {
      std::cerr << "--lan-only cannot be combined with --stun/--turn/"
                   "--force-turn/--srflx-only\n";
      return usage();
    }
    return run_node(argv[2], argv[3], argv[4], std::filesystem::path{argv[5]},
                    argv[6], std::chrono::milliseconds{parse_u64(argv[7])}, options);
  }
  return usage();
}
