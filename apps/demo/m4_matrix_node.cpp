// M4 network-matrix participant: a real Heyaki node used by the coturn
// topology harness. It performs local profile initialization, optional relay
// enrollment, then runs one bounded session attempt against the peer and
// prints a machine-readable MATRIX_RESULT line describing the outcome. The
// binary never talks to coturn itself; the driver script owns the topology.
#include <heyaki/message.hpp>
#include <heyaki/metrics.hpp>
#include <heyaki/node.hpp>
#include <heyaki/rpc.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/trust_grant.hpp>
#include <heyaki/relay_enrollment_client.hpp>
#include <heyaki/runtime.hpp>

#include "socks_frontend.hpp"

#include <executor/comm.hpp>

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <csignal>

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

// M9-10 bench clock: steady microseconds. Steady-clock epoch is machine-wide
// on the bench platforms (CLOCK_MONOTONIC / QPC), so cross-process deltas
// (fan-out publisher→subscriber) are meaningful inside one harness run.
std::uint64_t steady_micros_now() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

// Process start for the registration-latency marker (BENCH_LOGIN); captured
// at static initialization, before any node work begins. A function-local
// static would initialize at its first evaluation site — inside the marker
// expression itself, whose operand order is unspecified — so this must be a
// namespace-scope constant.
const std::uint64_t g_process_start_micros = steady_micros_now();
std::uint64_t process_start_micros() { return g_process_start_micros; }

struct LatencyReport {
  std::uint64_t p50{};
  std::uint64_t p95{};
  std::uint64_t p99{};
  std::uint64_t max{};
};

LatencyReport summarize_latencies(std::vector<std::uint64_t> samples) {
  LatencyReport report;
  if (samples.empty()) {
    return report;
  }
  std::sort(samples.begin(), samples.end());
  const auto at = [&samples](std::size_t total, double fraction) {
    const std::size_t index = static_cast<std::size_t>(
        fraction * static_cast<double>(total - 1U));
    return samples[std::min(index, total - 1U)];
  };
  const std::size_t total = samples.size();
  report.p50 = at(total, 0.50);
  report.p95 = at(total, 0.95);
  report.p99 = at(total, 0.99);
  report.max = samples.back();
  return report;
}

// One BENCH_METRIC line per latency population; n excludes failures so the
// harness can gate on both shape and completeness.
void print_bench_metric(std::string_view name, const std::vector<std::uint64_t>& samples,
                        std::size_t failures) {
  const auto report = summarize_latencies(samples);
  std::cout << "BENCH_METRIC name=" << name << " n=" << samples.size()
            << " failures=" << failures << " p50_us=" << report.p50
            << " p95_us=" << report.p95 << " p99_us=" << report.p99
            << " max_us=" << report.max << '\n';
}

// Discards anything still queued on a bench channel. The sequential
// single-outstanding sections drain before each send so a straggler from a
// previous (timed-out) operation can never be misattributed to the next one.
template <typename T>
void drain_channel(executor::comm::MpscChannel<T>& channel) {
  T value{};
  while (channel.try_receive(value)) {
  }
}

// Fan-out probe payload: 8 bytes big-endian steady micros + 4 bytes
// big-endian sequence, so each subscriber can timestamp delivery without any
// per-event bookkeeping beyond parsing.
std::vector<std::byte> encode_fanout_payload(std::uint64_t micros, std::uint32_t sequence) {
  std::vector<std::byte> payload(12U, std::byte{0});
  for (int index = 7; index >= 0; --index) {
    payload[static_cast<std::size_t>(7 - index)] =
        static_cast<std::byte>((micros >> (8 * index)) & 0xFFU);
  }
  payload[8] = static_cast<std::byte>((sequence >> 24U) & 0xFFU);
  payload[9] = static_cast<std::byte>((sequence >> 16U) & 0xFFU);
  payload[10] = static_cast<std::byte>((sequence >> 8U) & 0xFFU);
  payload[11] = static_cast<std::byte>(sequence & 0xFFU);
  return payload;
}

bool decode_fanout_payload(const std::vector<std::byte>& payload, std::uint64_t& micros,
                           std::uint32_t& sequence) {
  if (payload.size() != 12U) {
    return false;
  }
  micros = 0U;
  for (std::size_t index = 0U; index < 8U; ++index) {
    micros = (micros << 8U) |
             static_cast<std::uint64_t>(payload[index] & std::byte{0xFFU});
  }
  sequence = 0U;
  for (std::size_t index = 8U; index < 12U; ++index) {
    sequence = (sequence << 8U) |
               static_cast<std::uint32_t>(payload[index] & std::byte{0xFFU});
  }
  return true;
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

// M9-19: the matrix node offers udp and tcp TURN transports. "tls" is
// deliberately absent: no pinned ICE backend implements TURN/TLS, and
// libnice's TURN_TLS relay type silently degrades to plaintext TURN/TCP, so
// the flag rejects at parse time instead of lying about the data path.
heyaki::NodeIceServerKind turn_kind_for_transport(const std::string& transport) {
  if (transport == "tcp") {
    return heyaki::NodeIceServerKind::turn_tcp;
  }
  return heyaki::NodeIceServerKind::turn_udp;
}

// TURN REST API credential contract pinned by deploy/coturn/README.md:
// username = "<expiry_unix_seconds>:<tenant>:<DeviceId>",
// password = base64(HMAC-SHA1(static-auth-secret, username)).
heyaki::NodeIceServer turn_server(const std::string& host, std::uint16_t port,
                                  const std::string& secret,
                                  const std::string& tenant,
                                  const heyaki::DeviceId& device_id,
                                  heyaki::NodeIceServerKind kind,
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
  server.kind = kind;
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
  // M9-19: transport for the configured TURN server. udp keeps the M4/M9-07
  // scenarios; tcp selects the TURN-over-TCP client (libnice builds only; the
  // node rejects the policy on libjuice builds). tls has no backend in v1 and
  // fails at flag parse.
  std::string turn_transport{"udp"};
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
  // M9-10 bench: the initiator runs the latency/throughput suite on the
  // authenticated session(s) instead of the one-shot m6/m7 exercise, and the
  // responder additionally subscribes the bench.fanout topic (reliable QoS)
  // and can serve a PTY shell profile for the contention measurement.
  // --bench-connect-only strips the suite down to dial→authenticate timing
  // for the registration/connect/TURN P95 loops.
  bool bench_initiator{false};
  bool bench_responder{false};
  bool bench_shell{false};
  bool bench_connect_only{false};
  std::size_t bench_peers{1U};
  std::size_t bench_msg_n{200U};
  std::size_t bench_rpc_n{200U};
  std::size_t bench_rpc_concurrent_n{300U};
  std::size_t bench_rpc_window{16U};
  std::size_t bench_fanout_n{0U};
  std::uint64_t bench_file_bytes{0U};
  std::uint64_t bench_file_multi_bytes{8U * 1024U * 1024U};
  std::size_t bench_shell_pings{20U};
  // ---- M10 Round 6 gateway scenarios ----
  // Responder: serve one "lan" gateway profile over these CIDRs (comma
  // separated per flag, flag repeatable; ports fully allowed; confirm never,
  // no confirm sink). The serving side keeps working as a normal responder.
  std::vector<std::string> gateway_serve_cidrs;
  // Initiator: after authentication open one gateway tunnel and require a
  // 64-byte echo round trip (host/port parsed at flag time).
  std::string gateway_echo_host;
  std::uint16_t gateway_echo_port{0U};
  // Initiator: serve a loopback SOCKS5 CONNECT frontend bridging the peer's
  // gateway until SIGTERM/budget expiry.
  std::uint16_t gateway_socks_port{0U};
  // Either role: print the heyaki_gateway_* families from the Prometheus
  // export before exiting (script grep surface).
  bool gateway_metrics{false};
  // Profile name stamped onto gateway opens (must match the responder's
  // --gateway-serve profile, which is always "lan").
  std::string gateway_profile{"lan"};
  // Responder: PeerPathPolicy::GatewayPaths::direct_only — refuse gateway
  // opens while the session rides TURN (path_policy scenario).
  bool gateway_direct_only{false};
};

// ---- M10 Round 6 gateway scenarios -----------------------------------------
// SIGTERM/SIGINT latch for --gateway-socks: the harness kills the process
// once its curl probes are done; the handler only flips a sig_atomic flag
// that the keep-alive loop polls (async-signal-safe, no allocation).
volatile std::sig_atomic_t g_gateway_socks_stop = 0;
void request_gateway_socks_stop(int) { g_gateway_socks_stop = 1; }

// Prints every heyaki_gateway_* line of the Prometheus export so topology
// scripts can assert the family presence and counter values with grep.
void print_gateway_metric_lines(const heyaki::Node& node) {
  const auto text = heyaki::format_node_metrics_prometheus(node.metrics());
  std::string_view remaining = text;
  while (!remaining.empty()) {
    const auto eol = remaining.find('\n');
    const auto line = remaining.substr(0, eol == std::string_view::npos
                                             ? remaining.size()
                                             : eol);
    if (line.find("heyaki_gateway_") != std::string_view::npos) {
      std::cout << line << '\n';
    }
    if (eol == std::string_view::npos) break;
    remaining.remove_prefix(eol + 1U);
  }
}

// One gateway echo round trip (initiator side): open_gateway_stream to the
// flag target, wait for the one-shot on_connected (the dial->prelude
// latency), push 64 deterministic bytes, and require them echoed back
// verbatim. GATEWAY_METRIC carries the verdict; failure detail tokens are
// stable (addresses and free text never enter them) so scripts can gate.
void run_gateway_echo(heyaki::Node& node, const heyaki::DeviceEndpointKey& peer,
                      const RunOptions& options) {
  // Completion events cross the node strand into this loop through one
  // bounded channel (copies only — a late completion after an early return
  // must never touch a dead stack). One outstanding read at a time.
  struct GatewayEchoEvent {
    int kind{0};  // 0=connected 1=write-done 2=read-done
    int code{0};
    std::size_t bytes{0};
    std::array<std::byte, 256U> data{};
  };
  executor::comm::ChannelOptions event_options;
  event_options.capacity = 64U;
  event_options.name = "heyaki-m4-matrix-gateway-events";
  const auto events =
      std::make_shared<executor::comm::MpscChannel<GatewayEchoEvent>>(
          std::move(event_options));
  const auto fail = [](const char* detail, int code) {
    std::cout << "GATEWAY_METRIC name=echo_roundtrip_ms value=0 ok=0 detail="
              << detail << " code=" << code << '\n';
  };
  std::cout << "MATRIX_PHASE gateway-echo-begin\n";
  const auto begin_us = steady_micros_now();
  std::uint64_t connected_us = 0U;
  heyaki::NodeGatewayStreamOptions stream_options;
  stream_options.on_connected =
      [events](heyaki::Result<void> result) {
        GatewayEchoEvent event;
        event.kind = 0;
        event.code =
            result ? 0 : static_cast<int>(result.error_if()->code());
        event.bytes = steady_micros_now();
        (void)events->try_send(std::move(event));
      };
  auto opened = node.open_gateway_stream(
      peer,
      heyaki::GatewayConnect{.host = options.gateway_echo_host,
                             .port = options.gateway_echo_port,
                             .profile = options.gateway_profile},
      stream_options);
  if (!opened) {
    fail("open_failed", static_cast<int>(opened.error_if()->code()));
    return;
  }
  heyaki::ByteStream stream{std::move(*opened.value_if())};
  // Dial deadline default is now+10s; the wait covers it with margin.
  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds{25000};
  int connect_code = 0;
  bool connected = false;
  bool connect_failed = false;
  while (std::chrono::steady_clock::now() < deadline) {
    GatewayEchoEvent event;
    while (events->try_receive(event)) {
      if (event.kind == 0) {
        connected_us = event.bytes;
        connect_code = event.code;
        connected = event.code == 0;
        connect_failed = event.code != 0;
      }
    }
    if (connected || connect_failed) break;
    executor::comm::PhaseGate poll{"heyaki-m4-matrix-gateway-connect"};
    (void)poll.wait_for(1U, std::chrono::milliseconds{5});
  }
  if (connect_failed) {
    fail("connect_failed", connect_code);
    stream.reset(heyaki::StableStatus::cancelled);
    return;
  }
  if (!connected) {
    fail("connect_timeout", 0);
    stream.reset(heyaki::StableStatus::cancelled);
    return;
  }
  // 64 deterministic bytes; the serving side's echo must return them all.
  const auto payload = std::make_shared<std::vector<std::byte>>(64U);
  for (std::size_t index = 0U; index < payload->size(); ++index) {
    (*payload)[index] = static_cast<std::byte>((0x40U + index * 7U) & 0x7FU);
  }
  stream.async_write(
      std::span<const std::byte>{payload->data(), payload->size()},
      [events](heyaki::ByteStreamIoResult result) {
        GatewayEchoEvent event;
        event.kind = 1;
        event.code =
            result.error.has_value()
                ? static_cast<int>(result.error->code())
                : 0;
        (void)events->try_send(std::move(event));
      });
  bool write_ok = false;
  bool write_failed = false;
  int write_code = 0;
  while (std::chrono::steady_clock::now() < deadline &&
         !write_ok && !write_failed) {
    GatewayEchoEvent event;
    while (events->try_receive(event)) {
      if (event.kind == 1) {
        write_ok = event.code == 0;
        write_failed = event.code != 0;
        write_code = event.code;
      }
    }
    if (write_ok || write_failed) break;
    executor::comm::PhaseGate poll{"heyaki-m4-matrix-gateway-write"};
    (void)poll.wait_for(1U, std::chrono::milliseconds{5});
  }
  if (write_failed || !write_ok) {
    fail(write_failed ? "write_failed" : "write_timeout", write_code);
    stream.reset(heyaki::StableStatus::cancelled);
    return;
  }
  // Echo read-back: keep exactly one read outstanding until 64 bytes land.
  std::vector<std::byte> echoed;
  const auto read_buffer =
      std::make_shared<std::array<std::byte, 256U>>();
  const auto post_read = [&]() {
    stream.async_read_some(
        std::span<std::byte>{read_buffer->data(), read_buffer->size()},
        [events, read_buffer](heyaki::ByteStreamIoResult result) {
          GatewayEchoEvent event;
          event.kind = 2;
          event.code =
              result.error.has_value()
                  ? static_cast<int>(result.error->code())
                  : 0;
          event.bytes = result.bytes;
          if (result.bytes > 0U && result.bytes <= read_buffer->size()) {
            std::copy_n(read_buffer->begin(),
                        static_cast<std::ptrdiff_t>(result.bytes),
                        event.data.begin());
          }
          (void)events->try_send(std::move(event));
        });
  };
  post_read();
  bool read_failed = false;
  int read_code = 0;
  while (std::chrono::steady_clock::now() < deadline && echoed.size() < 64U &&
         !read_failed) {
    GatewayEchoEvent event;
    bool rearm = false;
    while (events->try_receive(event)) {
      if (event.kind == 2) {
        if (event.code != 0) {
          read_failed = true;
          read_code = event.code;
        } else if (event.bytes == 0U) {
          read_failed = true;  // clean EOF before the echo completed
          read_code = -1;
        } else {
          echoed.insert(echoed.end(), event.data.begin(),
                        event.data.begin() +
                            static_cast<std::ptrdiff_t>(
                                std::min(event.bytes, event.data.size())));
          rearm = echoed.size() < 64U;
        }
      }
    }
    if (read_failed) break;
    if (rearm) post_read();
    executor::comm::PhaseGate poll{"heyaki-m4-matrix-gateway-read"};
    (void)poll.wait_for(1U, std::chrono::milliseconds{5});
  }
  if (read_failed) {
    fail(read_code < 0 ? "stream_closed_early" : "read_failed", read_code);
    stream.reset(heyaki::StableStatus::cancelled);
    return;
  }
  if (echoed.size() < 64U) {
    fail("read_timeout", 0);
    stream.reset(heyaki::StableStatus::cancelled);
    return;
  }
  if (echoed != *payload) {
    fail("echo_mismatch", 0);
    stream.reset(heyaki::StableStatus::cancelled);
    return;
  }
  stream.reset(heyaki::StableStatus::cancelled);
  std::cout << "GATEWAY_METRIC name=echo_roundtrip_ms value="
            << (connected_us > begin_us ? (connected_us - begin_us) / 1000U
                                        : 0U)
            << " ok=1 bytes=64\n";
  std::cout << "MATRIX_PHASE gateway-echo-end\n";
}

// Loopback SOCKS5 CONNECT frontend (initiator side): bridges the peer's
// gateway through 127.0.0.1:<port> until SIGTERM/SIGINT, peer-session loss,
// or the run budget expires; GATEWAY_SOCKS_SUMMARY carries the frontend
// counters the harness gates on (connects_succeeded and byte totals).
void run_gateway_socks(heyaki::Node& node, heyaki::Runtime& runtime,
                       const heyaki::DeviceEndpointKey& peer,
                       const RunOptions& options,
                       std::chrono::steady_clock::time_point budget_deadline) {
#ifndef _WIN32
  struct sigaction stop_action {};
  stop_action.sa_handler = request_gateway_socks_stop;
  sigaction(SIGTERM, &stop_action, nullptr);
  sigaction(SIGINT, &stop_action, nullptr);
#endif
  heyaki::socks::SocksFrontendConfig config;
  config.bind_address = "127.0.0.1";
  config.port = options.gateway_socks_port;
  config.max_concurrent_connections = 16U;
  config.profile = options.gateway_profile;
  config.connect_deadline = std::chrono::milliseconds{15000};
  auto frontend =
      heyaki::socks::SocksFrontend::create(node, runtime, peer, config);
  if (!frontend) {
    std::cout << "GATEWAY_SOCKS_ERROR detail=create_failed code="
              << static_cast<int>(frontend.error_if()->code()) << '\n';
    return;
  }
  const auto started = (*frontend.value_if())->start();
  if (!started) {
    std::cout << "GATEWAY_SOCKS_ERROR detail=start_failed code="
              << static_cast<int>(started.error_if()->code()) << '\n';
    return;
  }
  const auto bound = (*frontend.value_if())->stats().bound_port;
  std::cout << "GATEWAY_SOCKS_READY port=" << bound << '\n';
  const auto peer_session_alive = [&node, &peer] {
    const auto sessions = node.peer_sessions();
    return std::any_of(sessions.begin(), sessions.end(),
                       [&peer](const auto& session) {
                         return session.peer == peer &&
                                session.state ==
                                    heyaki::NodePeerSessionState::authenticated;
                       });
  };
  while (g_gateway_socks_stop == 0) {
    if (std::chrono::steady_clock::now() >= budget_deadline) {
      std::cout << "MATRIX_PHASE gateway-socks-budget-expired\n";
      break;
    }
    if (!peer_session_alive()) {
      std::cout << "MATRIX_PHASE gateway-socks-peer-session-lost\n";
      break;
    }
    executor::comm::PhaseGate poll{"heyaki-m4-matrix-gateway-socks"};
    (void)poll.wait_for(1U, std::chrono::milliseconds{100});
  }
  executor::comm::PhaseGate settle{"heyaki-m4-matrix-gateway-socks-stats"};
  (void)settle.wait_for(1U, std::chrono::milliseconds{50});
  const auto stats = (*frontend.value_if())->stats();
  std::cout << "GATEWAY_SOCKS_SUMMARY"
            << " accepted=" << stats.accepted
            << " handshakes_failed=" << stats.handshakes_failed
            << " connects_succeeded=" << stats.connects_succeeded
            << " connects_failed=" << stats.connects_failed
            << " bytes_from_clients=" << stats.bytes_from_clients
            << " bytes_to_clients=" << stats.bytes_to_clients
            << " connections_active=" << stats.connections_active
            << " listening=" << (stats.listening ? 1 : 0) << '\n';
  (*frontend.value_if())->stop();
}

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
      server.kind = turn_kind_for_transport(options.turn_transport);
      server.hostname = options.turn->substr(0U, separator);
      server.port = static_cast<std::uint16_t>(
          parse_u64(options.turn->substr(separator + 1U)));
      server.username = options.turn_username;
      server.credential = options.turn_credential;
    } else {
      server = turn_server(
          options.turn->substr(0U, separator),
          static_cast<std::uint16_t>(parse_u64(options.turn->substr(separator + 1U))),
          options.turn_secret, tenant, device_id,
          turn_kind_for_transport(options.turn_transport), options.turn_expiry_offset);
    }
    policy.ice_servers.push_back(std::move(server));
  }
  // M9-19: a TURN/TCP server implies the matching candidate class; the
  // relayed candidates ride the TCP control connection.
  if (options.turn_transport == "tcp") {
    policy.allow_turn_tcp = true;
  }
  policy.force_turn_data_path = options.force_turn;
  if (options.force_turn) {
    policy.allow_server_reflexive = false;
    policy.allow_ipv4_host = false;
  }
  if (options.srflx_only) {
    policy.allow_ipv4_host = false;
  }
  if (options.gateway_direct_only) {
    // M10-11 path policy: refuse gateway opens while the session rides TURN.
    policy.gateway_paths = heyaki::PeerPathPolicy::GatewayPaths::direct_only;
  }

  // M7: both matrix roles host an "inbox" root beside their profile and a
  // small source file the initiator pushes across the topology under test.
  const auto m7_state_dir = database.parent_path() / "m7-files";
  std::error_code m7_dir_ec;
  std::filesystem::create_directories(m7_state_dir, m7_dir_ec);
  const auto m7_source = m7_state_dir / "matrix-source.bin";
  // M9-10: bench file sections reuse the m7 source pipeline — a sized bench
  // payload is just a sized m7 source.
  const auto m7_source_bytes =
      options.bench_initiator && options.bench_file_bytes > 0U && options.m7_bytes == 0U
          ? options.bench_file_bytes
          : options.m7_bytes;
  if (m7_source_bytes == 0U) {
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
    while (written < m7_source_bytes) {
      const auto chunk =
          std::min<std::uint64_t>(pattern.size(), m7_source_bytes - written);
      out.write(pattern.data(), static_cast<std::streamsize>(chunk));
      written += chunk;
    }
  }
  heyaki::FileRootConfig m7_root;
  m7_root.name = "inbox";
  m7_root.directory = m7_state_dir / "inbox";
  std::filesystem::create_directories(m7_root.directory, m7_dir_ec);
  // M10 Round 6: --gateway-socks lends the node an executor-owned runtime so
  // the SOCKS frontend shares the node's Asio context (the TUI's
  // owned-runtime pattern; no second worker). Every other mode keeps the
  // node-internal runtime, so existing scenarios are untouched.
  std::optional<heyaki::Runtime> gateway_runtime_host;
  if (options.gateway_socks_port != 0U) {
    auto runtime_created = heyaki::Runtime::create_owned(heyaki::RuntimeConfig{});
    if (!runtime_created) {
      std::cerr << "runtime create failed: "
                << runtime_created.error_if()->safe_detail() << '\n';
      return 1;
    }
    gateway_runtime_host.emplace(std::move(*runtime_created.value_if()));
  }
  heyaki::NodeConfig config;
  config.profile = profiled;
  config.application_id = std::string{application_id};
  config.lan_override = lan;
  if (!options.lan_only) {
    config.relay_override = relay;
  }
  config.path_policy_override = policy;
  config.file_receive_roots = {m7_root};
  if (options.gateway_socks_port != 0U) {
    config.runtime = &*gateway_runtime_host;
  }
  if (!options.gateway_serve_cidrs.empty()) {
    // One "lan" profile: the given CIDRs, all TCP ports, confirm=never (no
    // confirm sink). The profile is validated at Node::create — an invalid
    // CIDR list fails startup instead of degrading the policy.
    heyaki::GatewayProfileConfig gateway_profile;
    gateway_profile.name = options.gateway_profile.empty()
                               ? std::string{"lan"}
                               : options.gateway_profile;
    gateway_profile.allowed_ports = {heyaki::GatewayPortRange{1U, 65535U}};
    for (const auto& cidr_text : options.gateway_serve_cidrs) {
      const auto cidr = heyaki::parse_gateway_cidr(cidr_text);
      if (!cidr.has_value()) {
        std::cerr << "--gateway-serve CIDR rejected by policy parser\n";
        return 1;
      }
      gateway_profile.allowed_cidrs.push_back(*cidr);
    }
    config.gateway_profiles = {std::move(gateway_profile)};
  }
  if (options.bench_shell) {
    // M9-10 shell contention: the serving side exposes one fixed interactive
    // shell profile; the wire carries no executable override (M8-01), so the
    // program choice here is the whole attack surface.
    heyaki::ShellProfileConfig bench_shell;
    bench_shell.name = "bench";
#if defined(_WIN32)
    bench_shell.argv = {"C:\\Windows\\System32\\cmd.exe"};
#else
    bench_shell.argv = {"/bin/sh"};
#endif
    bench_shell.working_directory = "/tmp";
    bench_shell.environment = {
        {"PATH", std::nullopt}, {"HOME", std::string{"/tmp"}}, {"TERM", std::string{"dumb"}}};
    bench_shell.max_concurrent_sessions = 2U;
    bench_shell.idle_timeout = std::chrono::milliseconds{600000};
    bench_shell.absolute_timeout = std::chrono::milliseconds{3600000};
    config.shell_profiles = {std::move(bench_shell)};
  }
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
    if (relay_ready) {
      // M9-10 registration marker: process start → relay login accepted. The
      // steady-clock duration covers TLS connect + challenge/login only;
      // enrollment is a separate one-time command.
      std::cout << "MATRIX_PHASE relay-ready"
                << " login_ms="
                << (steady_micros_now() - process_start_micros()) / 1000U << '\n';
    }
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
      [&m7_event_received, bench_responder = options.bench_responder](
          const heyaki::DeviceEndpointKey&, std::string_view pattern,
          const heyaki::EventItemBody& item) {
        (void)m7_event_received.try_publish(true);
        if (bench_responder && pattern.find("bench.fanout") != std::string_view::npos) {
          std::uint64_t sent_micros = 0U;
          std::uint32_t sequence = 0U;
          if (decode_fanout_payload(item.payload, sent_micros, sequence)) {
            const auto now = steady_micros_now();
            std::cout << "BENCH_FANOUT_RX seq=" << sequence << " rtt_us="
                      << (now > sent_micros ? now - sent_micros : 0U) << '\n';
          }
        }
      });
  node.value_if()->set_file_event_observer(
      [&m7_file_committed, &m7_transferring,
       bench_responder = options.bench_responder](
          const heyaki::DeviceEndpointKey&,
          const heyaki::FileTransferEvent& event) {
        if (bench_responder) {
          const auto phase = static_cast<int>(event.phase);
          if (phase >= static_cast<int>(heyaki::FileTransferPhase::verifying)) {
            std::cout << "BENCH_FILE_EVENT_RX phase=" << phase
                      << " name=" << event.logical_name
                      << " done=" << event.bytes_done << " total=" << event.bytes_total
                      << " err="
                      << (event.error ? event.error->safe_detail() : std::string{"-"})
                      << '\n';
          }
        }
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

  // M9-10 bench suite (initiator only): latency and throughput populations on
  // the authenticated session(s). Sections are independently sized by their
  // counters (--bench-connect-only skips them all) and every population
  // prints one BENCH_METRIC/BENCH_THROUGHPUT line; BENCH_SUMMARY carries the
  // headline numbers the harness gates on. Completion callbacks run on the
  // node's strand and cross into this loop through executor comm components
  // (bounded channel for id-matched populations, latest-value for
  // single-outstanding waits) — no ad hoc shared state.
  // M9-10 dial anchor: set by the initiator dial block below, read by the
  // bench suite for the dial→authenticated duration (BENCH_CONNECT).
  std::uint64_t bench_dial_begin_us = 0U;
  struct BenchOutcome {
    bool connect_ok{false};
    std::uint64_t connect_ms{0U};
    std::string data_path{"none"};
    std::size_t message_failures{0U};
    std::size_t rpc_failures{0U};
    std::size_t rpc_admission_rejects{0U};
    std::size_t fanout_publish_failures{0U};
    std::size_t fanout_matched_min{0U};
    std::size_t fanout_matched_max{0U};
    bool file_single_ok{false};
    bool file_multi_ok{false};
    bool shell_ok{false};
    std::uint64_t message_p95{0U};
    std::uint64_t rpc_p95{0U};
    std::uint64_t rpc_concurrent_p95{0U};
    std::uint64_t shell_idle_p95{0U};
    std::uint64_t shell_contended_p95{0U};
    double file_single_mib_s{0.0};
    double file_multi_mib_s{0.0};
  };
  const auto channel_options = [](std::string name) {
    executor::comm::ChannelOptions options;
    options.capacity = 64U;
    options.name = std::move(name);
    return options;
  };
  // Bench comm endpoints live at run_node scope deliberately: node shutdown
  // drains pending completions, and those late callbacks may still publish
  // into these endpoints after the suite has returned. Per-section locals
  // caused a use-after-free in the first local run (a late RPC completion
  // fired after its section's channel had been destroyed). The endpoints are
  // torn down only after shutdown() has returned.
  executor::comm::MpscChannel<std::int64_t> bench_ack_channel{
      channel_options("heyaki-bench-msg-ack")};
  executor::comm::MpscChannel<std::int64_t> bench_rpc_channel{
      channel_options("heyaki-bench-rpc-done")};
  struct BenchRpcDone {
    heyaki::RequestId request;
    std::uint64_t done_micros{};
    bool ok{};
  };
  executor::comm::MpscChannel<BenchRpcDone> bench_rpc_concurrent_channel{
      channel_options("heyaki-bench-rpc-concurrent-done")};
  struct BenchFileEvent {
    heyaki::TransferId transfer;
    int phase{0};
    std::uint64_t done_micros{};
  };
  executor::comm::ChannelOptions bench_file_channel_options;
  bench_file_channel_options.capacity = 1024U;  // never drop a committed event
  bench_file_channel_options.name = "heyaki-bench-file-events";
  executor::comm::MpscChannel<BenchFileEvent> bench_file_channel{
      bench_file_channel_options};
  executor::comm::LatestMailbox<std::string> bench_shell_output{
      "heyaki-bench-shell-output"};
  executor::comm::LatestMailbox<int> bench_shell_phase{"heyaki-bench-shell-phase"};
  // Appended on the node strand only (shell observer); published as copies
  // through bench_shell_output for the caller thread.
  std::string bench_shell_accumulated;
  const auto run_bench_suite = [&]() -> BenchOutcome {
    BenchOutcome bench;
    std::vector<heyaki::DeviceEndpointKey> bench_peer_keys;
    // Wait for every expected peer: staggered dials mean the last session
    // can authenticate more than a second after the first; sampling on the
    // first authentication silently drops fan-out subscribers.
    (void)wait_until(
        [&] {
          bench_peer_keys.clear();
          for (const auto& session : node.value_if()->peer_sessions()) {
            if (session.state == heyaki::NodePeerSessionState::authenticated) {
              bench_peer_keys.push_back(session.peer);
            }
          }
          return bench_peer_keys.size() >= options.bench_peers;
        },
        std::chrono::milliseconds{20000});
    bench.connect_ok = !bench_peer_keys.empty();
    for (const auto& session : node.value_if()->peer_sessions()) {
      if (session.state == heyaki::NodePeerSessionState::authenticated) {
        bench.data_path =
            std::string{heyaki::node_data_path_kind_name(session.data_path)};
        break;
      }
    }
    if (bench_dial_begin_us != 0U) {
      bench.connect_ms = (steady_micros_now() - bench_dial_begin_us) / 1000U;
    }
    std::cout << "BENCH_CONNECT duration_ms=" << bench.connect_ms
              << " data_path=" << bench.data_path
              << " peers=" << bench_peer_keys.size() << '\n';
    if (!bench.connect_ok || options.bench_connect_only) {
      std::cout << "BENCH_SUMMARY ok=" << (bench.connect_ok ? 1 : 0)
                << " connect_ms=" << bench.connect_ms
                << " data_path=" << bench.data_path << '\n';
      return bench;
    }
    const auto peer_key0 = bench_peer_keys.front();
    // Services attach asynchronously after authorization (same contract as
    // the one-shot exercise); the latency sections need them in place.
    if (!wait_until(
            [&] {
              const auto services = node.value_if()->service_diagnostics();
              return services.message_sessions > 0U && services.rpc_sessions > 0U;
            },
            std::chrono::milliseconds{5000})) {
      std::cout << "BENCH_SUMMARY ok=0 error=services-not-attached message_sessions="
                << node.value_if()->service_diagnostics().message_sessions
                << " rpc_sessions="
                << node.value_if()->service_diagnostics().rpc_sessions << '\n';
      return bench;
    }

    // ---- message latency: sequential peer_acked messages, one outstanding,
    // so each sample is a clean device-to-device round trip. The observer
    // publishes terminal events only (`queued` is an intermediate state) and
    // each send is preceded by a drain so stragglers cannot be misattributed.
    // ----
    if (options.bench_msg_n > 0U) {
      node.value_if()->set_message_ack_observer(
          [&bench_ack_channel](const heyaki::DeviceEndpointKey&, const heyaki::MessageId&,
                              heyaki::MessageDeliveryEvent event, std::optional<Error>) {
            if (event == heyaki::MessageDeliveryEvent::queued) {
              return;  // intermediate: the frame merely entered the queue
            }
            // Positive = ack monotonic micros; negative = terminal non-ack.
            (void)bench_ack_channel.try_send(
                event == heyaki::MessageDeliveryEvent::acked
                    ? static_cast<std::int64_t>(steady_micros_now())
                    : std::int64_t{-1});
          });
      std::vector<std::byte> payload(1024U, std::byte{0x5A});
      std::vector<std::uint64_t> samples;
      for (std::size_t index = 0U; index < options.bench_msg_n; ++index) {
        drain_channel(bench_ack_channel);
        const auto t0 = steady_micros_now();
        heyaki::MessageEnvelope envelope;
        envelope.type = "bench.message";
        envelope.delivery_mode = heyaki::MessageDeliveryMode::peer_acked;
        envelope.ttl_milliseconds = 20'000U;
        envelope.payload = payload;
        const auto sent = node.value_if()->send_message(peer_key0, std::move(envelope));
        if (!sent) {
          ++bench.message_failures;
          continue;
        }
        std::int64_t done = 0;
        // The wait covers the 20s TTL so a terminal event is never split
        // from its sample by the receive timeout.
        const auto received =
            bench_ack_channel.receive_for(done, std::chrono::seconds{25});
        if (!received || done < 0) {
          ++bench.message_failures;
          continue;
        }
        samples.push_back(static_cast<std::uint64_t>(done) - t0);
      }
      bench.message_p95 = summarize_latencies(samples).p95;
      print_bench_metric("message_rtt", samples, bench.message_failures);
    }

    // ---- RPC latency: sequential echo calls, one outstanding, drain before
    // each call. ----
    if (options.bench_rpc_n > 0U) {
      const auto publish_done =
          [&bench_rpc_channel](const heyaki::Result<heyaki::RpcCallOutcome>& result) {
            std::int64_t value = -1;
            if (result && (*result.value_if()).status == heyaki::StableStatus::ok) {
              value = static_cast<std::int64_t>(steady_micros_now());
            }
            (void)bench_rpc_channel.try_send(value);
          };
      std::vector<std::byte> payload(1024U, std::byte{0x2A});
      std::vector<std::uint64_t> samples;
      for (std::size_t index = 0U; index < options.bench_rpc_n; ++index) {
        drain_channel(bench_rpc_channel);
        const auto t0 = steady_micros_now();
        const auto started = node.value_if()->call_rpc(
            peer_key0, "heyaki.matrix", "echo", payload, heyaki::RpcCallOptions{},
            [&publish_done](const heyaki::DeviceEndpointKey&,
                            heyaki::Result<heyaki::RpcCallOutcome> result) {
              publish_done(result);
            });
        if (!started) {
          ++bench.rpc_failures;
          continue;
        }
        std::int64_t done = 0;
        const auto received =
            bench_rpc_channel.receive_for(done, std::chrono::seconds{35});
        if (!received || done < 0) {
          ++bench.rpc_failures;
          continue;
        }
        samples.push_back(static_cast<std::uint64_t>(done) - t0);
      }
      bench.rpc_p95 = summarize_latencies(samples).p95;
      print_bench_metric("rpc_latency", samples, bench.rpc_failures);
    }

    // ---- concurrent RPC: fixed in-flight window over N completions; the
    // per-request completion record crosses via bounded channel and matches
    // the caller-side send timestamp by wire request id. ----
    if (options.bench_rpc_concurrent_n > 0U) {
      std::map<heyaki::RequestId, std::uint64_t> in_flight;  // caller thread only
      std::vector<std::byte> payload(1024U, std::byte{0x2B});
      std::vector<std::uint64_t> samples;
      const auto fire_one = [&]() {
        const auto started = node.value_if()->call_rpc(
            peer_key0, "heyaki.matrix", "echo", payload, heyaki::RpcCallOptions{},
            [&bench_rpc_concurrent_channel](
                const heyaki::DeviceEndpointKey&,
                heyaki::Result<heyaki::RpcCallOutcome> result) {
              BenchRpcDone record;
              record.done_micros = steady_micros_now();
              if (result) {
                record.request = (*result.value_if()).request_id;
                record.ok = (*result.value_if()).status == heyaki::StableStatus::ok;
              }
              (void)bench_rpc_concurrent_channel.try_send(std::move(record));
            });
        if (!started) {
          ++bench.rpc_admission_rejects;
          return false;
        }
        in_flight[*started.value_if()] = steady_micros_now();
        return true;
      };
      const auto suite_begin = steady_micros_now();
      while (samples.size() + bench.rpc_failures < options.bench_rpc_concurrent_n) {
        while (in_flight.size() < options.bench_rpc_window &&
               samples.size() + bench.rpc_failures + in_flight.size() <
                   options.bench_rpc_concurrent_n) {
          if (!fire_one()) {
            // Admission is closed (queue/capacity): stop pressing and let the
            // outstanding window drain so the population stays bounded.
            break;
          }
        }
        if (in_flight.empty()) {
          break;
        }
        BenchRpcDone record;
        if (!bench_rpc_concurrent_channel.receive_for(record, std::chrono::seconds{15})) {
          bench.rpc_failures += in_flight.size();
          break;
        }
        const auto pending = in_flight.find(record.request);
        if (pending == in_flight.end()) {
          continue;  // stale completion for a request already accounted
        }
        const auto sent_micros = pending->second;
        in_flight.erase(pending);
        if (record.ok) {
          samples.push_back(record.done_micros - sent_micros);
        } else {
          ++bench.rpc_failures;
        }
      }
      const auto suite_duration = steady_micros_now() - suite_begin;
      bench.rpc_concurrent_p95 = summarize_latencies(samples).p95;
      print_bench_metric("rpc_concurrent_latency", samples, bench.rpc_failures);
      const double ops_per_s = suite_duration == 0U
                                   ? 0.0
                                   : static_cast<double>(samples.size()) * 1'000'000.0 /
                                         static_cast<double>(suite_duration);
      std::cout << "BENCH_THROUGHPUT name=rpc_concurrent ops_per_s=" << ops_per_s
                << " window=" << options.bench_rpc_window
                << " admission_rejects=" << bench.rpc_admission_rejects << '\n';
    }

    // ---- event fan-out: publish to every authenticated subscriber's
    // bench.fanout subscription; subscribers print their own delivery RTT
    // (BENCH_FANOUT_RX) which the harness aggregates per subscriber. ----
    if (options.bench_fanout_n > 0U) {
      const auto subscriptions_attached = [&] {
        const auto services = node.value_if()->service_diagnostics();
        return services.event_sessions >= bench_peer_keys.size();
      };
      if (wait_until(subscriptions_attached, std::chrono::milliseconds{8000})) {
        std::size_t matched_min = std::numeric_limits<std::size_t>::max();
        std::size_t matched_max = 0U;
        for (std::size_t sequence = 0U; sequence < options.bench_fanout_n;
             ++sequence) {
          const auto payload =
              encode_fanout_payload(steady_micros_now(),
                                    static_cast<std::uint32_t>(sequence));
          for (const auto& peer : bench_peer_keys) {
            const auto published = node.value_if()->publish_event(
                peer, "bench.fanout", payload, 1U);
            if (!published) {
              ++bench.fanout_publish_failures;
              continue;
            }
            matched_min = std::min(matched_min, *published.value_if());
            matched_max = std::max(matched_max, *published.value_if());
          }
          executor::comm::PhaseGate pace{"heyaki-bench-fanout-pace"};
          (void)pace.wait_for(1U, std::chrono::milliseconds{20});
        }
        if (matched_min == std::numeric_limits<std::size_t>::max()) {
          matched_min = 0U;
        }
        bench.fanout_matched_min = matched_min;
        bench.fanout_matched_max = matched_max;
        std::cout << "BENCH_METRIC name=fanout_publish events="
                  << options.bench_fanout_n << " peers=" << bench_peer_keys.size()
                  << " matched_min=" << matched_min
                  << " matched_max=" << matched_max
                  << " publish_failures=" << bench.fanout_publish_failures << '\n';
      } else {
        bench.fanout_publish_failures += options.bench_fanout_n;
        std::cout << "BENCH_METRIC name=fanout_publish error=subscriptions-not-attached"
                  << " event_sessions="
                  << node.value_if()->service_diagnostics().event_sessions << '\n';
      }
    }

    // ---- file sections: single push, two concurrent pushes (the default
    // per-session send cap), and one push under shell contention. ----
    node.value_if()->set_file_event_observer(
        [&bench_file_channel](const heyaki::DeviceEndpointKey&,
                              const heyaki::FileTransferEvent& event) {
          const auto phase = static_cast<int>(event.phase);
          // Progress events are far too chatty for CI logs; boundaries and
          // terminals carry the diagnostic value.
          if (phase >= static_cast<int>(heyaki::FileTransferPhase::verifying)) {
            std::cout << "BENCH_FILE_EVENT phase=" << phase
                      << " name=" << event.logical_name
                      << " done=" << event.bytes_done << " total=" << event.bytes_total
                      << " err="
                      << (event.error ? event.error->safe_detail() : std::string{"-"})
                      << '\n';
          }
          (void)bench_file_channel.try_send(BenchFileEvent{
              event.transfer_id, static_cast<int>(event.phase),
              steady_micros_now()});
        });
    // Terminal states observed for any transfer while polling, so a commit
    // that lands while another transfer's wait is active is not lost.
    std::map<heyaki::TransferId, std::pair<int, std::uint64_t>> file_terminal;
    const auto poll_file_events = [&]() {
      BenchFileEvent record;
      while (bench_file_channel.try_receive(record)) {
        if (record.phase == static_cast<int>(heyaki::FileTransferPhase::committed) ||
            record.phase == static_cast<int>(heyaki::FileTransferPhase::failed) ||
            record.phase == static_cast<int>(heyaki::FileTransferPhase::cancelled)) {
          file_terminal[record.transfer] = {record.phase, record.done_micros};
        }
      }
    };
    const auto wait_file_terminal = [&](const heyaki::TransferId& transfer,
                                        bool& committed) {
      committed = false;
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{90};
      while (std::chrono::steady_clock::now() < deadline) {
        poll_file_events();
        const auto found = file_terminal.find(transfer);
        if (found != file_terminal.end()) {
          committed = found->second.first ==
                      static_cast<int>(heyaki::FileTransferPhase::committed);
          return steady_micros_now();
        }
        executor::comm::PhaseGate poll{"heyaki-bench-file-poll"};
        (void)poll.wait_for(1U, std::chrono::milliseconds{2});
      }
      // Timeout forensics: the public transfer summaries plus channel stats
      // pinpoint which side of a stalled transfer stopped moving.
      std::cout << "BENCH_FILE_STALL transfer_wait_timed_out";
      for (const auto& summary : node.value_if()->file_transfers(peer_key0)) {
        std::cout << " tx=" << heyaki::to_string(summary.transfer_id)
                  << ",name=" << summary.logical_name << ",phase="
                  << static_cast<int>(summary.phase) << ",done=" << summary.bytes_done
                  << ",total=" << summary.bytes_total;
      }
      std::cout << '\n';
      return steady_micros_now();
    };
    if (options.bench_file_bytes > 0U) {
      // Single push.
      {
        const auto t0 = steady_micros_now();
        const auto pushed = node.value_if()->push_file(
            peer_key0, "inbox", "bench/single.bin", m7_source);
        bool committed = false;
        std::uint64_t done = 0U;
        if (pushed) {
          done = wait_file_terminal(*pushed.value_if(), committed);
        }
        bench.file_single_ok = committed;
        const auto duration_ms = (done - t0) / 1000U;
        bench.file_single_mib_s =
            duration_ms == 0U
                ? 0.0
                : static_cast<double>(options.bench_file_bytes) / 1.048576e6 /
                      (static_cast<double>(duration_ms) / 1000.0);
        std::cout << "BENCH_THROUGHPUT name=file_single"
                  << " bytes=" << options.bench_file_bytes
                  << " duration_ms=" << duration_ms
                  << " mib_per_s=" << bench.file_single_mib_s
                  << " ok=" << (committed ? 1 : 0) << '\n';
      }
      // Two concurrent pushes (default per-session send cap is 2).
      if (options.bench_file_multi_bytes > 0U) {
        const auto multi_source = m7_state_dir / "bench-multi.bin";
        {
          std::ofstream out(multi_source, std::ios::binary | std::ios::trunc);
          const std::string pattern = "m9 bench multi payload 0123456789abcdef\n";
          std::uint64_t written = 0U;
          while (written < options.bench_file_multi_bytes) {
            const auto chunk = std::min<std::uint64_t>(pattern.size(),
                                                       options.bench_file_multi_bytes -
                                                           written);
            out.write(pattern.data(), static_cast<std::streamsize>(chunk));
            written += chunk;
          }
        }
        const auto t0 = steady_micros_now();
        const auto first = node.value_if()->push_file(
            peer_key0, "inbox", "bench/multi-a.bin", multi_source);
        const auto second = node.value_if()->push_file(
            peer_key0, "inbox", "bench/multi-b.bin", multi_source);
        bool first_committed = false;
        bool second_committed = false;
        std::uint64_t done = steady_micros_now();
        if (first) {
          done = wait_file_terminal(*first.value_if(), first_committed);
        }
        if (second) {
          done = std::max(done, wait_file_terminal(*second.value_if(), second_committed));
        }
        bench.file_multi_ok = first_committed && second_committed;
        const auto duration_ms = (done - t0) / 1000U;
        const std::uint64_t total_bytes =
            ((first ? 1U : 0U) + (second ? 1U : 0U)) * options.bench_file_multi_bytes;
        bench.file_multi_mib_s =
            duration_ms == 0U
                ? 0.0
                : static_cast<double>(total_bytes) / 1.048576e6 /
                      (static_cast<double>(duration_ms) / 1000.0);
        std::cout << "BENCH_THROUGHPUT name=file_multi_concurrent"
                  << " bytes=" << total_bytes
                  << " transfers=" << (first ? 1 : 0) + (second ? 1 : 0)
                  << " duration_ms=" << duration_ms
                  << " mib_per_s=" << bench.file_multi_mib_s
                  << " ok=" << (bench.file_multi_ok ? 1 : 0) << '\n';
      }
    }

    // ---- shell contention: keystroke→output round trip idle, then while a
    // bulk push occupies the same session. The PTY echoes the command line,
    // so the token round trip measures input frame → PTY → output frame —
    // exactly the interactivity the file transfer competes with. ----
    if (options.bench_shell) {
      node.value_if()->set_shell_event_observer(
          [&](const heyaki::DeviceEndpointKey&,
              const heyaki::ShellServiceEvent& event) {
            if (!event.output.empty()) {
              bench_shell_accumulated.append(
                  reinterpret_cast<const char*>(event.output.data()),
                  event.output.size());
              (void)bench_shell_output.try_publish(bench_shell_accumulated);
            }
            (void)bench_shell_phase.try_publish(static_cast<int>(event.phase));
          });
      const auto shell = node.value_if()->open_shell(peer_key0, "bench",
                                                     heyaki::ShellOpenOptions{});
      if (shell) {
        int phase = -1;
        const auto active = wait_until(
            [&] {
              (void)bench_shell_phase.try_load(phase);
              return phase == static_cast<int>(heyaki::ShellPhase::active);
            },
            std::chrono::milliseconds{10000});
        if (active) {
          const auto ping_shell = [&](const std::string& token) {
            const auto t0 = steady_micros_now();
            const std::string line = "echo " + token + "\r";
            std::vector<std::byte> bytes;
            bytes.reserve(line.size());
            for (const char value : line) {
              bytes.push_back(static_cast<std::byte>(value));
            }
            const auto sent = node.value_if()->shell_send_input(
                peer_key0, *shell.value_if(), bytes);
            if (!sent) {
              return std::numeric_limits<std::uint64_t>::max();
            }
            const auto seen = wait_until(
                [&] {
                  std::string copy;
                  if (!bench_shell_output.try_load(copy)) {
                    return false;
                  }
                  return copy.find(token) != std::string::npos;
                },
                std::chrono::milliseconds{10000});
            if (!seen) {
              return std::numeric_limits<std::uint64_t>::max();
            }
            return steady_micros_now() - t0;
          };
          std::vector<std::uint64_t> idle_samples;
          for (std::size_t index = 0U; index < options.bench_shell_pings; ++index) {
            const auto rtt = ping_shell("benchidle" + std::to_string(index));
            if (rtt != std::numeric_limits<std::uint64_t>::max()) {
              idle_samples.push_back(rtt);
            }
            executor::comm::PhaseGate pace{"heyaki-bench-shell-pace"};
            (void)pace.wait_for(1U, std::chrono::milliseconds{200});
          }
          bench.shell_idle_p95 = summarize_latencies(idle_samples).p95;
          print_bench_metric("shell_ping_idle", idle_samples,
                             options.bench_shell_pings - idle_samples.size());
          if (options.bench_file_bytes > 0U) {
            const auto push_begin = steady_micros_now();
            const auto pushed = node.value_if()->push_file(
                peer_key0, "inbox", "bench/under-shell.bin", m7_source);
            std::vector<std::uint64_t> contended_samples;
            for (std::size_t index = 0U; index < options.bench_shell_pings * 3U &&
                                          contended_samples.size() <
                                              options.bench_shell_pings;
                 ++index) {
              const auto rtt = ping_shell("benchbusy" + std::to_string(index));
              if (rtt != std::numeric_limits<std::uint64_t>::max()) {
                contended_samples.push_back(rtt);
              }
              executor::comm::PhaseGate pace{"heyaki-bench-shell-pace"};
              (void)pace.wait_for(1U, std::chrono::milliseconds{100});
            }
            bench.shell_contended_p95 = summarize_latencies(contended_samples).p95;
            print_bench_metric("shell_ping_contended", contended_samples,
                               options.bench_shell_pings - contended_samples.size());
            bool committed = false;
            const auto commit_done =
                pushed ? wait_file_terminal(*pushed.value_if(), committed)
                       : steady_micros_now();
            const auto duration_ms = (commit_done - push_begin) / 1000U;
            const double mib_per_s =
                duration_ms == 0U
                    ? 0.0
                    : static_cast<double>(options.bench_file_bytes) / 1.048576e6 /
                          (static_cast<double>(duration_ms) / 1000.0);
            std::cout << "BENCH_THROUGHPUT name=file_under_shell"
                      << " bytes=" << options.bench_file_bytes
                      << " duration_ms=" << duration_ms
                      << " mib_per_s=" << mib_per_s
                      << " ok=" << (committed ? 1 : 0)
                      << " shell_p95_us=" << bench.shell_contended_p95 << '\n';
          }
          bench.shell_ok = true;
        }
        (void)node.value_if()->close_shell(peer_key0, *shell.value_if());
        (void)wait_until(
            [&] {
              int latest = -1;
              (void)bench_shell_phase.try_load(latest);
              return latest == static_cast<int>(heyaki::ShellPhase::closed);
            },
            std::chrono::milliseconds{8000});
      } else {
        std::cout << "BENCH_METRIC name=shell_ping_idle error=open-failed"
                  << " detail=" << shell.error_if()->safe_detail() << '\n';
      }
    }

    // Feed the shared result-line mailboxes so the existing MATRIX_RESULT
    // machinery stays the single source for the harness.
    (void)m6_message_acked.try_publish(bench.message_failures == 0U);
    (void)m6_rpc_status.try_publish(bench.rpc_failures == 0U &&
                                            bench.rpc_admission_rejects == 0U
                                        ? 0
                                        : -1);
    (void)m7_event_received.try_publish(bench.fanout_publish_failures == 0U);
    (void)m7_file_committed.try_publish(
        bench.file_single_ok &&
        (options.bench_file_multi_bytes == 0U || bench.file_multi_ok));
    std::cout << "BENCH_SUMMARY ok=1"
              << " connect_ms=" << bench.connect_ms
              << " data_path=" << bench.data_path
              << " message_p95_us=" << bench.message_p95
              << " rpc_p95_us=" << bench.rpc_p95
              << " rpc_concurrent_p95_us=" << bench.rpc_concurrent_p95
              << " fanout_matched_min=" << bench.fanout_matched_min
              << " fanout_matched_max=" << bench.fanout_matched_max
              << " file_single_mib_per_s=" << bench.file_single_mib_s
              << " file_multi_mib_per_s=" << bench.file_multi_mib_s
              << " shell_idle_p95_us=" << bench.shell_idle_p95
              << " shell_contended_p95_us=" << bench.shell_contended_p95
              << " message_failures=" << bench.message_failures
              << " rpc_failures=" << bench.rpc_failures
              << " rpc_admission_rejects=" << bench.rpc_admission_rejects
              << " fanout_publish_failures=" << bench.fanout_publish_failures
              << '\n';
    return bench;
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
      // authenticated session must reach a terminal state after the unclean
      // peer death. Backend detection windows differ: libjuice rides RFC 7675
      // consent freshness (~30s); libnice's consent-freshness is a
      // construct-only property that libdatachannel v0.23.2 sets after
      // construction (rejected with a GLib CRITICAL, upstream defect), so
      // detection falls back to libnice's plain keepalive timeout (50s). The
      // wait covers the slower window plus margin; re-evaluate at the next
      // libdatachannel pin upgrade.
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
          std::chrono::milliseconds{120000});
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
    const auto discovered_peer_count = [&]() {
      std::size_t count = 0U;
      for (const auto& entry : node.value_if()->endpoints()) {
        if (entry.key != local_key && peer_has_endpoint(entry)) {
          ++count;
        }
      }
      return count;
    };
    const auto peer_endpoint = wait_until(
        [&] {
          return options.bench_initiator
                     ? discovered_peer_count() >= options.bench_peers
                     : discovered_peer_count() >= 1U;
        },
        options.bench_initiator ? std::chrono::milliseconds{20000}
                                : std::chrono::milliseconds{10000});
    if (!peer_endpoint) {
      std::cout << "MATRIX_RESULT authenticated=0 data_path=none duration_ms=0"
                << " relay_state=no_peer\n";
      (void)node.value_if()->shutdown();
      return 0;
    }
    const auto dial_peer = [&](const heyaki::DeviceEndpointKey& key) {
      return options.lan_only ? node.value_if()->connect_lan(key)
                              : node.value_if()->connect(key);
    };
    if (options.bench_initiator) {
      // M9-10: dial every discovered peer (fan-out subscribers count as
      // peers); sections beyond connect timing use the first authenticated
      // session. The dial timestamp anchors BENCH_CONNECT. Dials are
      // staggered: each one bursts offer+candidates through the relay, and
      // the relay's per-IP rate scope (32/s) is shared by every identity on
      // a loopback host — a simultaneous fan-out dial trips it and the
      // rejected control traffic churns the relay connections.
      bench_dial_begin_us = steady_micros_now();
      unsigned dialed = 0U;
      const auto entries = node.value_if()->endpoints();
      for (const auto& entry : entries) {
        if (entry.key != local_key && peer_has_endpoint(entry)) {
          const auto connected = dial_peer(entry.key);
          attempted = attempted || (bool)connected;
          if ((bool)connected) {
            ++dialed;
          }
          executor::comm::PhaseGate dial_gap{"heyaki-bench-dial-gap"};
          (void)dial_gap.wait_for(1U, std::chrono::milliseconds{300});
        }
      }
      if (dialed == 0U) {
        std::cout << "MATRIX_RESULT authenticated=0 data_path=none duration_ms=0"
                  << " connect_error=no-dial-admitted\n";
        (void)node.value_if()->shutdown();
        return 0;
      }
    } else {
      const auto entries = node.value_if()->endpoints();
      const auto peer = std::find_if(entries.begin(), entries.end(),
                                     [&](const auto& entry) {
                                       return entry.key != local_key &&
                                              peer_has_endpoint(entry);
                                     });
      const auto connected = dial_peer(peer->key);
      attempted = (bool)connected;
      if (!connected) {
        std::cout << "MATRIX_RESULT authenticated=0 data_path=none duration_ms=0"
                  << " connect_error=" << connected.error_if()->safe_detail() << '\n';
        (void)node.value_if()->shutdown();
        return 0;
      }
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
              if (options.bench_responder) {
                // M9-10 fan-out: reliable QoS so the delivered-count gate is
                // meaningful (drops would be a finding, not a pacing artifact).
                (void)node.value_if()->subscribe_events(
                    session.peer, "bench.fanout", true, heyaki::EventQos::reliable_live);
              }
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
    // M10 Round 6 gateway scenarios (initiator side): echo rides the
    // authenticated session and then falls through to the regular m6/m7
    // exercise; socks consumes the rest of the budget and skips it.
    const bool gateway_socks_mode =
        options.role == "initiator" && options.gateway_socks_port != 0U;
    if (options.role == "initiator" &&
        (options.gateway_echo_port != 0U || gateway_socks_mode)) {
      heyaki::DeviceEndpointKey gateway_peer{};
      for (const auto& session : node.value_if()->peer_sessions()) {
        if (session.state == heyaki::NodePeerSessionState::authenticated) {
          gateway_peer = session.peer;
          break;
        }
      }
      if (options.gateway_echo_port != 0U) {
        run_gateway_echo(*node.value_if(), gateway_peer, options);
      } else {
        run_gateway_socks(*node.value_if(), *gateway_runtime_host, gateway_peer,
                          options, begin + total_budget);
      }
    }
    // M6 exercise (initiator side): one peer_acked message and one unary RPC
    // through the public API on whatever data path the session negotiated.
    // The services attach asynchronously after authorization, so wait for the
    // service diagnostics to confirm them before exercising; a relay-restart
    // churn scenario may drop the session mid-exercise, which reports as
    // m6=0/-1 rather than a topology failure.
    if (options.role == "initiator" && !gateway_socks_mode) {
      if (options.bench_initiator) {
        // M9-10: the bench suite replaces the one-shot m6/m7 exercise and
        // feeds the shared outcome mailboxes itself.
        (void)run_bench_suite();
      } else {
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
    // Deterministic failure path for the gateway echo scenario when the
    // session never authenticated: the script gates on ok=0 + the stable
    // no-session token.
    if (options.role == "initiator" && options.gateway_echo_port != 0U) {
      std::cout << "GATEWAY_METRIC name=echo_roundtrip_ms value=0 ok=0"
                   " detail=no-session\n";
    }
  }
  bool final_message_acked = false;
  int final_rpc_status = -1;
  bool final_event_received = false;
  bool final_file_committed = false;
  (void)m6_message_acked.try_load(final_message_acked);
  (void)m6_rpc_status.try_load(final_rpc_status);
  (void)m7_event_received.try_load(final_event_received);
  (void)m7_file_committed.try_load(final_file_committed);
  if (options.gateway_metrics) {
    // Serving-side counters republish on the node's periodic diagnostics
    // tick; give a just-closed tunnel a bounded settle so the export
    // reflects it before the process exits. The direct_only path-policy
    // scenario expects refusals instead of traffic, so it skips the wait.
    if (options.role == "responder" && !options.gateway_serve_cidrs.empty() &&
        !options.gateway_direct_only) {
      (void)wait_until([&] {
        return node.value_if()->metrics().services.gateway.bytes_from_tunnel >
               0U;
      }, std::chrono::milliseconds{5000});
    }
    print_gateway_metric_lines(*node.value_if());
  }
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
            << "  heyaki-m4-matrix-node seed-trust FIRST_DB SECOND_DB [SEED_BASE]\n"
            << "  heyaki-m4-matrix-node enroll DB APP_ID RELAY_URL CA TENANT TOKEN\n"
            << "  heyaki-m4-matrix-node run DB APP_ID RELAY_URL CA TENANT BUDGET_MS\n"
            << "      [--role initiator|responder] [--stun HOST:PORT]\n"
            << "      [--turn HOST:PORT] [--turn-secret SECRET] [--force-turn]\n"
            << "      [--turn-transport udp|tcp]  (M9-19; tcp needs the libnice backend)\n"
            << "      [--turn-username NAME --turn-credential SECRET]\n"
            << "      [--srflx-only] [--lan-only]\n"
            << "      [--hold-ms N] [--authenticate-budget-ms N] [--connect-retries N]\n"
            << "      [--m7-bytes N] [--m7-pause-hold-ms N] [--m7-wait-ms N]\n"
            << "      [--turn-credential-expiry-offset-ms N]\n"
            << "      [--soak-cycles N]  (initiator only; M9-09 soak)\n"
            << "      [--bench-initiator] [--bench-connect-only] [--bench-peers N]\n"
            << "      [--bench-msg-n N] [--bench-rpc-n N] [--bench-rpc-concurrent-n N]\n"
            << "      [--bench-rpc-window N] [--bench-fanout-n N] [--bench-file-bytes N]\n"
            << "      [--bench-file-multi-bytes N] [--bench-shell-pings N]  (M9-10)\n"
            << "      [--bench-responder] [--bench-shell]  (responder; M9-10)\n"
            << "      [--gateway-serve CIDR[,CIDR...]]  (responder; M10 gateway\n"
            << "            profile \\\"lan\\\" over the given targets; flag repeatable)\n"
            << "      [--gateway-echo HOST:PORT]  (initiator; 64-byte echo tunnel)\n"
            << "      [--gateway-socks PORT]  (initiator; loopback SOCKS5 frontend\n"
            << "            until SIGTERM/budget; needs the heyaki::socks link)\n"
            << "      [--gateway-metrics]  (print heyaki_gateway_* export lines)\n"
            << "      [--gateway-profile NAME]  (default lan; must match the\n"
            << "            responder profile AND the seeded gateway.provide scope)\n"
            << "      [--gateway-direct-only]  (responder; refuse gateway while\n"
            << "            the session rides TURN)  (M10 Round 6)\n";
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
    if (argc != 4 && argc != 5) {
      return usage();
    }
    // M9-10: the id seed derives the GrantIds; a profile trusted with several
    // peers in sequence must use distinct seeds per pair or the later grants
    // upsert over the earlier ones (same GrantId) and the earlier peers fall
    // back to untrusted. Default keeps the historical 1/2 for single-pair
    // seeding; the bench harness passes a distinct even base per subscriber.
    const std::uint8_t seed_base =
        argc == 5 ? static_cast<std::uint8_t>(parse_u64(argv[4]) & 0x7FU) : 1U;
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
    // Grants canonicalize to a sorted, deduplicated scope list. shell.open:bench
    // is inert unless a bench participant calls the M8 shell API (M9-10).
    // The M10 gateway scopes are inert unless a scenario opens a gateway
    // stream: gateway.use gates the initiator's opens, gateway.provide:lan
    // gates the responder's "lan" profile (the --gateway-serve default name).
  const std::vector<std::string> scopes = {"event.subscribe:*", "file.pull:inbox",
                                        "file.push:inbox",   "gateway.provide:lan",
                                        "gateway.use",       "matrix.connect",
                                        "message.send",      "rpc.device.read",
                                        "shell.open:bench"};
    auto forward =
        seed_one_way_trust(*first.value_if(), *second.value_if(), scopes, seed_base);
    if (!forward) {
      std::cerr << forward.error_if()->safe_detail() << '\n';
      return 1;
    }
    auto backward =
        seed_one_way_trust(*second.value_if(), *first.value_if(), scopes,
                           static_cast<std::uint8_t>(seed_base + 1U));
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
      } else if (flag == "--turn-transport" && index + 1 < argc) {
        options.turn_transport = argv[++index];
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
      } else if (flag == "--bench-initiator") {
        options.bench_initiator = true;
      } else if (flag == "--bench-responder") {
        options.bench_responder = true;
      } else if (flag == "--bench-shell") {
        options.bench_shell = true;
      } else if (flag == "--bench-connect-only") {
        options.bench_connect_only = true;
      } else if (flag == "--bench-peers" && index + 1 < argc) {
        options.bench_peers = static_cast<std::size_t>(parse_u64(argv[++index]));
      } else if (flag == "--bench-msg-n" && index + 1 < argc) {
        options.bench_msg_n = static_cast<std::size_t>(parse_u64(argv[++index]));
      } else if (flag == "--bench-rpc-n" && index + 1 < argc) {
        options.bench_rpc_n = static_cast<std::size_t>(parse_u64(argv[++index]));
      } else if (flag == "--bench-rpc-concurrent-n" && index + 1 < argc) {
        options.bench_rpc_concurrent_n =
            static_cast<std::size_t>(parse_u64(argv[++index]));
      } else if (flag == "--bench-rpc-window" && index + 1 < argc) {
        options.bench_rpc_window = static_cast<std::size_t>(parse_u64(argv[++index]));
      } else if (flag == "--bench-fanout-n" && index + 1 < argc) {
        options.bench_fanout_n = static_cast<std::size_t>(parse_u64(argv[++index]));
      } else if (flag == "--bench-file-bytes" && index + 1 < argc) {
        options.bench_file_bytes = parse_u64(argv[++index]);
      } else if (flag == "--bench-file-multi-bytes" && index + 1 < argc) {
        options.bench_file_multi_bytes = parse_u64(argv[++index]);
      } else if (flag == "--bench-shell-pings" && index + 1 < argc) {
        options.bench_shell_pings = static_cast<std::size_t>(parse_u64(argv[++index]));
      } else if (flag == "--gateway-serve" && index + 1 < argc) {
        // Comma-separated CIDR list per flag; the flag repeats.
        std::string_view list{argv[++index]};
        while (!list.empty()) {
          const auto comma = list.find(',');
          const auto item = list.substr(0, comma == std::string_view::npos
                                               ? list.size()
                                               : comma);
          if (!item.empty()) {
            options.gateway_serve_cidrs.emplace_back(item);
          }
          if (comma == std::string_view::npos) break;
          list.remove_prefix(comma + 1U);
        }
      } else if (flag == "--gateway-echo" && index + 1 < argc) {
        const std::string target{argv[++index]};
        const auto separator = target.rfind(':');
        if (separator == std::string::npos) {
          std::cerr << "--gateway-echo requires HOST:PORT\n";
          return usage();
        }
        options.gateway_echo_host = target.substr(0U, separator);
        const auto port = parse_u64(target.substr(separator + 1U));
        if (options.gateway_echo_host.empty() || port == 0U || port > 65535U) {
          std::cerr << "--gateway-echo requires a non-empty host and port 1..65535\n";
          return usage();
        }
        if (!heyaki::valid_gateway_host(options.gateway_echo_host)) {
          std::cerr << "--gateway-echo host failed the gateway host grammar\n";
          return usage();
        }
        options.gateway_echo_port = static_cast<std::uint16_t>(port);
      } else if (flag == "--gateway-socks" && index + 1 < argc) {
        const auto port = parse_u64(argv[++index]);
        if (port == 0U || port > 65535U) {
          std::cerr << "--gateway-socks requires port 1..65535\n";
          return usage();
        }
        options.gateway_socks_port = static_cast<std::uint16_t>(port);
      } else if (flag == "--gateway-metrics") {
        options.gateway_metrics = true;
      } else if (flag == "--gateway-profile" && index + 1 < argc) {
        options.gateway_profile = argv[++index];
        if (!heyaki::safe_gateway_profile_name(options.gateway_profile)) {
          std::cerr << "--gateway-profile failed the profile name grammar\n";
          return usage();
        }
      } else if (flag == "--gateway-direct-only") {
        options.gateway_direct_only = true;
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
    if (options.bench_initiator && options.role != "initiator") {
      std::cerr << "--bench-initiator requires --role initiator\n";
      return usage();
    }
    if (options.bench_responder && options.role != "responder") {
      std::cerr << "--bench-responder requires --role responder\n";
      return usage();
    }
    if (options.bench_connect_only && !options.bench_initiator) {
      std::cerr << "--bench-connect-only requires --bench-initiator\n";
      return usage();
    }
    // The shell contention section needs the serving-side profile; the flag
    // is what exposes it, so pairing it with the initiator-only connect
    // loop would silently skip the section.
    if (options.bench_shell && options.bench_connect_only) {
      std::cerr << "--bench-connect-only skips the shell section; drop --bench-shell\n";
      return usage();
    }
    // The window must stay under the client pending-call cap (64) and the
    // server concurrent-call cap (16); a window above them measures
    // admission rejection, not RPC latency.
    if (options.bench_rpc_window > 16U) {
      std::cerr << "--bench-rpc-window above the default server cap (16) would "
                   "measure admission rejection, not latency\n";
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
    // Validate early: an unknown --turn-transport value must fail usage, not
    // silently degrade to the udp kind. tls names a transport no pinned ICE
    // backend implements (libnice would silently degrade it to plaintext
    // TURN/TCP), so it is not a valid choice in v1.
    if (options.turn_transport == "tls") {
      std::cerr << "--turn-transport tls is unavailable: no pinned ICE backend "
                   "implements TURN/TLS\n";
      return usage();
    }
    if (options.turn_transport != "udp" && options.turn_transport != "tcp") {
      std::cerr << "--turn-transport must be udp or tcp\n";
      return usage();
    }
    // The transport only matters together with a TURN server; catching the
    // dangling flag here keeps scenario scripts honest.
    if (!options.turn.has_value() && options.turn_transport != "udp") {
      std::cerr << "--turn-transport requires --turn\n";
      return usage();
    }
    // ---- M10 Round 6 gateway flag contracts ----
    if (!options.gateway_serve_cidrs.empty() && options.role != "responder") {
      std::cerr << "--gateway-serve requires --role responder\n";
      return usage();
    }
    if ((options.gateway_echo_port != 0U || options.gateway_socks_port != 0U) &&
        options.role != "initiator") {
      std::cerr << "--gateway-echo/--gateway-socks require --role initiator\n";
      return usage();
    }
    if (options.gateway_echo_port != 0U && options.gateway_socks_port != 0U) {
      std::cerr << "--gateway-echo and --gateway-socks are exclusive scenarios\n";
      return usage();
    }
    if (options.gateway_direct_only && options.gateway_serve_cidrs.empty()) {
      std::cerr << "--gateway-direct-only needs --gateway-serve to matter\n";
      return usage();
    }
    if ((options.gateway_echo_port != 0U || options.gateway_socks_port != 0U) &&
        (options.soak_cycles > 0U || options.bench_initiator)) {
      std::cerr << "gateway scenarios cannot ride the soak/bench loops\n";
      return usage();
    }
    return run_node(argv[2], argv[3], argv[4], std::filesystem::path{argv[5]},
                    argv[6], std::chrono::milliseconds{parse_u64(argv[7])}, options);
  }
  return usage();
}
