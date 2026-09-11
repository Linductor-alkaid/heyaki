// heyaki-test-turn-server: minimal TURN/UDP server for host-local matrix
// scenarios (M9-07). Windows CI has no coturn, so the Windows network matrix
// drives the TURN/UDP combination through the TURN server embedded in the
// pinned libjuice — the same stack the client side links — configured with
// static long-term credentials. The harness generates the credential pair and
// passes it both here and to heyaki-m4-matrix-node via
// --turn-username/--turn-credential.
//
// This helper owns no concurrent work: a single libjuice server handle runs
// on the main thread and the process idles in a blocking sleep until the
// harness terminates it, so nothing here needs an executor context.

#include <juice/juice.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

namespace {

int usage() {
  std::cerr << "usage:\n"
            << "  heyaki-test-turn-server --port N --username NAME\n"
            << "      --credential SECRET [--bind ADDRESS] [--external ADDRESS]\n"
            << "      [--relay-port-begin N] [--relay-port-end N]\n";
  return 2;
}

std::uint64_t parse_u64(const std::string& text, const char* flag) {
  const auto value = std::strtoull(text.c_str(), nullptr, 10);
  if (value == 0U) {
    std::cerr << "invalid " << flag << " value: " << text << '\n';
    std::exit(2);
  }
  return value;
}

}  // namespace

int main(int argc, char** argv) {
  std::uint16_t port = 0U;
  std::string username;
  std::string credential;
  std::string bind = "127.0.0.1";
  std::string external;
  std::uint16_t relay_begin = 49200U;
  std::uint16_t relay_end = 49299U;
  for (int index = 1; index < argc; ++index) {
    const std::string flag{argv[index]};
    const bool has_value = index + 1 < argc;
    if (flag == "--port" && has_value) {
      port = static_cast<std::uint16_t>(parse_u64(argv[++index], "--port"));
    } else if (flag == "--username" && has_value) {
      username = argv[++index];
    } else if (flag == "--credential" && has_value) {
      credential = argv[++index];
    } else if (flag == "--bind" && has_value) {
      bind = argv[++index];
    } else if (flag == "--external" && has_value) {
      external = argv[++index];
    } else if (flag == "--relay-port-begin" && has_value) {
      relay_begin =
          static_cast<std::uint16_t>(parse_u64(argv[++index], "--relay-port-begin"));
    } else if (flag == "--relay-port-end" && has_value) {
      relay_end =
          static_cast<std::uint16_t>(parse_u64(argv[++index], "--relay-port-end"));
    } else {
      return usage();
    }
  }
  if (port == 0U || username.empty() || credential.empty()) {
    return usage();
  }
  if (external.empty()) {
    external = bind;
  }

  // libjuice keeps pointers into the credential array for the server's
  // lifetime; the strings must outlive juice_server_destroy.
  juice_server_credentials_t credentials[1];
  credentials[0].username = username.c_str();
  credentials[0].password = credential.c_str();
  // One matrix scenario makes at most a handful of allocations per side; the
  // quota only exists so exhaustion is observable rather than silent.
  credentials[0].allocations_quota = 64;

  juice_server_config_t config{};
  config.credentials = credentials;
  config.credentials_count = 1;
  config.max_allocations = 64;
  config.max_peers = 256;
  config.bind_address = bind.c_str();
  config.external_address = external.c_str();
  config.port = port;
  config.relay_port_range_begin = relay_begin;
  config.relay_port_range_end = relay_end;
  config.realm = "heyaki.test";

  juice_server_t* server = juice_server_create(&config);
  if (server == nullptr) {
    std::cerr << "TURN_SERVER_FAILED port=" << port << " bind=" << bind << '\n';
    return 1;
  }
  std::cout << "TURN_SERVER_READY port=" << port << " bind=" << bind
            << " external=" << external << " relay_range=" << relay_begin << "-"
            << relay_end << std::endl;
  for (;;) {
    std::this_thread::sleep_for(std::chrono::seconds{1});
  }
}
