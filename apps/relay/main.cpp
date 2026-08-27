#include "relay_server.hpp"

#include <heyaki/version.hpp>

#include <executor/comm.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

namespace {

struct CommandLine {
  std::optional<std::filesystem::path> config_file;
  std::optional<std::string> listen_address;
  std::optional<std::uint16_t> listen_port;
  std::optional<std::filesystem::path> tls_certificate_file;
  std::optional<std::filesystem::path> tls_private_key_file;
  std::optional<std::filesystem::path> database_file;
  std::optional<std::string> health_path;
  bool check_config{false};
  bool help{false};
};

void print_usage() {
  std::cout << "Usage: heyaki-relay [--version] [--help]\n"
               "       heyaki-relay --config <path> [--check-config] "
               "[--listen <ip>] [--port <n>]\n"
               "                   [--tls-cert <path>] [--tls-key <path>] "
               "[--database <path>]\n"
               "                   [--health-path <path>]\n";
}

std::optional<std::uint16_t> parse_port(std::string_view text) {
  if (text.empty() || text.size() > 5U) {
    return std::nullopt;
  }
  std::uint32_t value = 0U;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      return std::nullopt;
    }
    value = value * 10U + static_cast<std::uint32_t>(character - '0');
    if (value > 65535U) {
      return std::nullopt;
    }
  }
  if (value == 0U) {
    return std::nullopt;
  }
  return static_cast<std::uint16_t>(value);
}

std::optional<CommandLine> parse_arguments(int argc, char** argv) {
  CommandLine output;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument{argv[index]};
    if (argument == "--version") {
      const auto info = heyaki::build_info();
      std::cout << "heyaki-relay " << info.version << " (" << info.commit << ")\n";
      std::exit(0);
    }
    if (argument == "--help" || argument == "-h") {
      output.help = true;
      return output;
    }
    if (argument == "--check-config") {
      output.check_config = true;
      continue;
    }
    auto require_value = [&](std::string_view option) -> std::optional<std::string_view> {
      if (index + 1 >= argc) {
        std::cerr << "heyaki-relay: missing value for " << option << "\n";
        return std::nullopt;
      }
      ++index;
      return std::string_view{argv[index]};
    };
    if (argument == "--config") {
      auto value = require_value(argument);
      if (!value) {
        return std::nullopt;
      }
      output.config_file = std::filesystem::path{std::string{*value}};
    } else if (argument == "--listen") {
      auto value = require_value(argument);
      if (!value) {
        return std::nullopt;
      }
      output.listen_address = std::string{*value};
    } else if (argument == "--port") {
      auto value = require_value(argument);
      if (!value) {
        return std::nullopt;
      }
      auto port = parse_port(*value);
      if (!port) {
        std::cerr << "heyaki-relay: invalid --port value\n";
        return std::nullopt;
      }
      output.listen_port = port;
    } else if (argument == "--tls-cert") {
      auto value = require_value(argument);
      if (!value) {
        return std::nullopt;
      }
      output.tls_certificate_file = std::filesystem::path{std::string{*value}};
    } else if (argument == "--tls-key") {
      auto value = require_value(argument);
      if (!value) {
        return std::nullopt;
      }
      output.tls_private_key_file = std::filesystem::path{std::string{*value}};
    } else if (argument == "--database") {
      auto value = require_value(argument);
      if (!value) {
        return std::nullopt;
      }
      output.database_file = std::filesystem::path{std::string{*value}};
    } else if (argument == "--health-path") {
      auto value = require_value(argument);
      if (!value) {
        return std::nullopt;
      }
      output.health_path = std::string{*value};
    } else {
      std::cerr << "heyaki-relay: unknown option: " << argument << "\n";
      return std::nullopt;
    }
  }
  return output;
}

int print_error(const heyaki::Error& error) {
  std::cerr << "heyaki-relay: " << heyaki::error_code_name(error.code()) << " "
            << error.component() << " " << error.safe_detail();
  if (error.underlying_code()) {
    std::cerr << " (" << *error.underlying_code() << ")";
  }
  std::cerr << "\n";
  return 1;
}

}  // namespace

int main(int argc, char** argv) {
  const auto parsed = parse_arguments(argc, argv);
  if (!parsed) {
    print_usage();
    return 2;
  }
  if (parsed->help) {
    print_usage();
    return 0;
  }

  heyaki::RelayServerConfig config;
  if (parsed->config_file) {
    auto loaded = heyaki::load_relay_config_file(*parsed->config_file);
    if (!loaded) {
      return print_error(*loaded.error_if());
    }
    config = std::move(*loaded.value_if());
  }
  if (parsed->listen_address) {
    config.listen_address = std::move(*parsed->listen_address);
  }
  if (parsed->listen_port) {
    config.listen_port = *parsed->listen_port;
  }
  if (parsed->tls_certificate_file) {
    config.tls_certificate_file = std::move(*parsed->tls_certificate_file);
  }
  if (parsed->tls_private_key_file) {
    config.tls_private_key_file = std::move(*parsed->tls_private_key_file);
  }
  if (parsed->database_file) {
    config.database_file = std::move(*parsed->database_file);
  }
  if (parsed->health_path) {
    config.health_path = std::move(*parsed->health_path);
  }

  auto valid = heyaki::validate_relay_server_config(config);
  if (!valid) {
    return print_error(*valid.error_if());
  }
  if (parsed->check_config) {
    std::cout << "heyaki-relay configuration OK\n";
    return 0;
  }

  // The server reports observable state changes on its strand; blocking on the
  // gate replaces sleep-polling the snapshot.
  executor::comm::PhaseGate server_events{"heyaki-relay-main"};
  config.on_state_changed = [&server_events] {
    (void)server_events.advance();
  };

  auto server = heyaki::RelayServer::create(std::move(config));
  if (!server) {
    return print_error(*server.error_if());
  }

  bool running_reached = false;
  const auto startup_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds{2};
  while (std::chrono::steady_clock::now() < startup_deadline) {
    const auto snapshot = server.value_if()->snapshot();
    if (snapshot.state == heyaki::RelayServerState::running) {
      std::cout << "heyaki-relay listening on " << snapshot.listen_address << ":"
                << snapshot.listen_port << " (TLS 1.3/WSS)\n";
      running_reached = true;
      break;
    }
    if (snapshot.state == heyaki::RelayServerState::failed ||
        snapshot.state == heyaki::RelayServerState::stopped) {
      std::cerr << "heyaki-relay: server failed to reach running state\n";
      (void)server.value_if()->shutdown();
      return 1;
    }
    (void)server_events.wait_for(server_events.current_phase() + 1U,
                                 std::chrono::milliseconds{100});
  }
  if (!running_reached) {
    std::cerr << "heyaki-relay: server startup timed out\n";
    (void)server.value_if()->shutdown();
    return 1;
  }
  for (;;) {
    if (server.value_if()->stop_requested()) {
      break;
    }
    const auto snapshot = server.value_if()->snapshot();
    if (snapshot.state == heyaki::RelayServerState::failed ||
        snapshot.state == heyaki::RelayServerState::stopped) {
      break;
    }
    (void)server_events.wait_for(server_events.current_phase() + 1U,
                                 std::chrono::milliseconds{500});
  }

  const auto report = server.value_if()->shutdown();
  std::cout << "heyaki-relay stopped; tcp_accepted="
            << report.final_snapshot.tcp_accepted
            << " websocket_accepted=" << report.final_snapshot.websocket_accepted
            << " health_checks=" << report.final_snapshot.health_checks
            << " active_sessions=" << report.final_snapshot.active_sessions << "\n";
  return report.stopped && !report.timed_out ? 0 : 1;
}
