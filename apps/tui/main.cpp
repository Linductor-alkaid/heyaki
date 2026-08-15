#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/version.hpp>

#include <executor/comm.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace {

using namespace std::chrono_literals;

constexpr std::string_view application_id{"org.heyaki.tui"};

struct Options {
  std::string profile_name{"default"};
  bool version{false};
  bool status_only{false};
  bool help{false};
};

struct UiBridge {
  explicit UiBridge(std::size_t capacity)
      : events([capacity] {
          executor::comm::ChannelOptions options;
          options.capacity = capacity;
          options.name = "heyaki-tui-signaling-events";
          return options;
        }()) {}

  executor::comm::MpscChannel<heyaki::LanSignalingMessage> events;
  std::atomic<std::uint64_t> rejected{0U};
};

struct UiState {
  std::deque<heyaki::LanSignalingMessage> signaling_events;
  std::optional<heyaki::Error> command_error;
  std::string command_status;
};

void wipe_string(std::string& value) noexcept {
  volatile char* bytes = value.empty() ? nullptr : value.data();
  for (std::size_t index = 0U; index < value.size(); ++index) {
    bytes[index] = '\0';
  }
  value.clear();
}

std::optional<Options> parse_options(int argc, char** argv) {
  Options options;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument{argv[index]};
    if (argument == "--version") {
      options.version = true;
    } else if (argument == "--status") {
      options.status_only = true;
    } else if (argument == "--help" || argument == "-h") {
      options.help = true;
    } else if (argument == "--profile" && index + 1 < argc) {
      options.profile_name = argv[++index];
    } else {
      return std::nullopt;
    }
  }
  return options;
}

void print_usage() {
  std::cout << "usage: heyaki-tui [--profile NAME] [--status] [--version]\n";
}

heyaki::Result<std::string> read_secret(std::string_view prompt) {
  std::cout << prompt << std::flush;
#ifdef _WIN32
  const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
  DWORD original_mode = 0U;
  if (input == INVALID_HANDLE_VALUE || GetConsoleMode(input, &original_mode) == 0 ||
      SetConsoleMode(input, original_mode & ~ENABLE_ECHO_INPUT) == 0) {
    std::cout << '\n';
    return heyaki::Result<std::string>::failure(
        heyaki::Error{heyaki::ErrorCode::configuration, "tui",
                      "secure_input_unavailable"});
  }
  std::string value;
  std::getline(std::cin, value);
  (void)SetConsoleMode(input, original_mode);
#else
  termios original{};
  if (::tcgetattr(STDIN_FILENO, &original) != 0) {
    std::cout << '\n';
    return heyaki::Result<std::string>::failure(
        heyaki::Error{heyaki::ErrorCode::configuration, "tui",
                      "secure_input_unavailable"});
  }
  termios hidden = original;
  hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
  if (::tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
    std::cout << '\n';
    return heyaki::Result<std::string>::failure(
        heyaki::Error{heyaki::ErrorCode::configuration, "tui",
                      "secure_input_unavailable"});
  }
  std::string value;
  std::getline(std::cin, value);
  (void)::tcsetattr(STDIN_FILENO, TCSANOW, &original);
#endif
  std::cout << '\n';
  if (!std::cin) {
    wipe_string(value);
    return heyaki::Result<std::string>::failure(
        heyaki::Error{heyaki::ErrorCode::cancelled, "tui", "input_closed"});
  }
  return heyaki::Result<std::string>::success(std::move(value));
}

std::string_view connectivity_mode_name(heyaki::ConnectivityMode mode) noexcept {
  switch (mode) {
    case heyaki::ConnectivityMode::automatic:
      return "automatic";
    case heyaki::ConnectivityMode::lan_only:
      return "lan-only";
    case heyaki::ConnectivityMode::relay_only:
      return "relay-only";
  }
  return "unknown";
}

std::string_view signaling_state_name(
    heyaki::LanSignalingConnectionState state) noexcept {
  switch (state) {
    case heyaki::LanSignalingConnectionState::connecting:
      return "connecting";
    case heyaki::LanSignalingConnectionState::provisional_tls:
      return "provisional-tls";
    case heyaki::LanSignalingConnectionState::authenticated:
      return "authenticated";
    case heyaki::LanSignalingConnectionState::closed:
      return "closed";
    case heyaki::LanSignalingConnectionState::failed:
      return "failed";
  }
  return "failed";
}

std::string_view message_kind_name(heyaki::LanSignalingMessageKind kind) noexcept {
  switch (kind) {
    case heyaki::LanSignalingMessageKind::connect_request:
      return "pair-request";
    case heyaki::LanSignalingMessageKind::connect_accept:
      return "pair-accepted";
    case heyaki::LanSignalingMessageKind::connect_deny:
      return "pair-denied";
    case heyaki::LanSignalingMessageKind::signed_offer:
      return "signed-offer";
    case heyaki::LanSignalingMessageKind::signed_answer:
      return "signed-answer";
    case heyaki::LanSignalingMessageKind::signed_candidate:
      return "signed-candidate";
  }
  return "unknown";
}

void print_error(const heyaki::Error& error) {
  std::cout << heyaki::error_code_name(error.code()) << ' ' << error.component() << ' '
            << error.safe_detail();
}

heyaki::Result<void> initialize_local_profile(heyaki::ProfileStore& profile) {
  auto password = read_secret("password: ");
  if (!password) {
    return heyaki::Result<void>::failure(*password.error_if());
  }
  auto confirmation = read_secret("confirm: ");
  if (!confirmation) {
    wipe_string(*password.value_if());
    return heyaki::Result<void>::failure(*confirmation.error_if());
  }
  if (*password.value_if() != *confirmation.value_if()) {
    wipe_string(*password.value_if());
    wipe_string(*confirmation.value_if());
    return heyaki::Result<void>::failure(
        heyaki::Error{heyaki::ErrorCode::authentication, "tui",
                      "password_confirmation_mismatch"});
  }
  auto verifier = heyaki::create_password_verifier(
      *password.value_if(), heyaki::PasswordHashParameters{});
  wipe_string(*password.value_if());
  wipe_string(*confirmation.value_if());
  if (!verifier) {
    return heyaki::Result<void>::failure(*verifier.error_if());
  }
  heyaki::LocalProfileInitialization initialization{
      .application_id = std::string{application_id},
      .password_verifier = std::move(*verifier.value_if()),
      .password_generation = 1U,
      .pairing_policy = heyaki::PairingPolicy{},
      .lan = heyaki::LanConfiguration{}};
  auto initialized = profile.initialize_local(initialization);
  return initialized ? heyaki::Result<void>::success()
                     : heyaki::Result<void>::failure(*initialized.error_if());
}

heyaki::RequestId make_request_id() {
  heyaki::RequestId::Storage bytes{};
  std::random_device random;
  for (auto& byte : bytes) {
    byte = static_cast<std::byte>(random() & 0xffU);
  }
  if (std::all_of(bytes.begin(), bytes.end(),
                  [](std::byte byte) { return byte == std::byte{0}; })) {
    bytes[0] = std::byte{1U};
  }
  return heyaki::RequestId{bytes};
}

void drain_ui_events(UiBridge& bridge, UiState& state, std::size_t capacity) {
  heyaki::LanSignalingMessage message;
  while (bridge.events.try_receive(message)) {
    state.signaling_events.push_back(std::move(message));
    while (state.signaling_events.size() > capacity) {
      state.signaling_events.pop_front();
    }
  }
}

std::optional<heyaki::DeviceEndpointKey> endpoint_at(
    const std::vector<heyaki::EndpointDirectoryEntrySnapshot>& endpoints,
    std::size_t one_based_index) {
  if (one_based_index == 0U || one_based_index > endpoints.size()) {
    return std::nullopt;
  }
  return endpoints[one_based_index - 1U].key;
}

bool connection_authenticated(const heyaki::Node& node,
                              heyaki::DeviceEndpointKey peer) {
  const auto connections = node.signaling_connections();
  return std::any_of(connections.begin(), connections.end(), [&](const auto& connection) {
    return connection.peer == peer &&
           connection.state == heyaki::LanSignalingConnectionState::authenticated;
  });
}

heyaki::Result<void> wait_for_authenticated(heyaki::Node& node,
                                           heyaki::DeviceEndpointKey peer,
                                           std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  executor::comm::PhaseGate poll{"heyaki-tui-authentication-poll"};
  while (std::chrono::steady_clock::now() < deadline) {
    if (connection_authenticated(node, peer)) {
      return heyaki::Result<void>::success();
    }
    const auto connections = node.signaling_connections();
    const auto failed = std::find_if(connections.begin(), connections.end(),
                                     [&](const auto& connection) {
                                       return connection.peer == peer &&
                                              connection.state ==
                                                  heyaki::LanSignalingConnectionState::failed;
                                     });
    if (failed != connections.end() && failed->error) {
      return heyaki::Result<void>::failure(*failed->error);
    }
    (void)poll.wait_for(1U, std::chrono::milliseconds{1});
  }
  return heyaki::Result<void>::failure(
      heyaki::Error{heyaki::ErrorCode::timeout, "tui",
                    "lan_authentication_timeout"});
}

void render_uninitialized(std::string_view profile_name,
                          const std::optional<heyaki::Error>& error = std::nullopt) {
  std::cout << "HEYAKI  profile=" << profile_name << "\n\n";
  std::cout << "LOCAL   not-initialized\n";
  std::cout << "LAN     stopped\n";
  std::cout << "PAIRING unavailable\n";
  if (error) {
    std::cout << "FAILURE ";
    print_error(*error);
    std::cout << '\n';
  }
}

void render_node(std::string_view profile_name, const heyaki::Node& node,
                 UiBridge& bridge, UiState& state, std::size_t event_capacity) {
  drain_ui_events(bridge, state, event_capacity);
  const auto snapshot = node.snapshot();
  const auto endpoints = node.endpoints();
  const auto connections = node.signaling_connections();
  std::cout << "HEYAKI  profile=" << profile_name << "\n\n";
  std::cout << "LOCAL   ready  device=" << heyaki::to_string(snapshot.device_id)
            << "\n        endpoint=" << heyaki::to_string(snapshot.endpoint_id) << '\n';
  std::cout << "LAN     " << heyaki::lan_readiness_state_name(snapshot.lan_state)
            << "  mode=" << connectivity_mode_name(snapshot.connectivity_mode)
            << "  listener=";
  if (snapshot.tls.listener_ready) {
    std::cout << snapshot.tls.listen_port;
  } else {
    std::cout << "closed";
  }
  std::cout << '\n';

  std::cout << "\nINTERFACES\n";
  if (snapshot.interfaces.empty()) {
    std::cout << "  none\n";
  }
  for (const auto& interface : snapshot.interfaces) {
    std::cout << "  " << (interface.joined ? "ready " : "failed") << ' '
              << interface.name << ' ' << interface.address << " if=" << interface.index;
    if (interface.error) {
      std::cout << "  ";
      print_error(*interface.error);
    }
    std::cout << '\n';
  }

  std::cout << "\nENDPOINTS\n";
  if (endpoints.empty()) {
    std::cout << "  none\n";
  }
  for (std::size_t index = 0U; index < endpoints.size(); ++index) {
    const auto& endpoint = endpoints[index];
    std::cout << "  [" << index + 1U << "] "
              << (endpoint.trusted ? "trusted" : "pairing-restricted")
              << "\n      device=" << heyaki::to_string(endpoint.key.device_id)
              << "\n      endpoint=" << heyaki::to_string(endpoint.key.endpoint_id)
              << "\n      discovery=";
    if (endpoint.lan && endpoint.relay) {
      std::cout << "lan+relay";
    } else if (endpoint.lan) {
      std::cout << "lan";
    } else {
      std::cout << "relay";
    }
    const auto connection = std::find_if(
        connections.begin(), connections.end(), [&](const auto& value) {
          return value.peer == endpoint.key;
        });
    std::cout << "  signaling=";
    if (connection == connections.end()) {
      std::cout << "none";
    } else {
      std::cout << "lan/" << signaling_state_name(connection->state);
    }
    std::cout << "  data=none\n";
  }

  std::cout << "\nPAIRING\n";
  std::size_t request_index = 0U;
  for (const auto& event : state.signaling_events) {
    if (event.kind == heyaki::LanSignalingMessageKind::connect_request) {
      ++request_index;
      std::cout << "  [" << request_index << "] pair-request from "
                << heyaki::to_string(event.peer.device_id) << ' '
                << heyaki::to_string(event.peer.endpoint_id) << '\n';
    } else {
      std::cout << "  " << message_kind_name(event.kind) << " from "
                << heyaki::to_string(event.peer.device_id) << '\n';
    }
  }
  if (state.signaling_events.empty()) {
    std::cout << "  none\n";
  }

  if (!state.command_status.empty()) {
    std::cout << "\nSTATUS  " << state.command_status << '\n';
  }
  const auto failure = state.command_error ? state.command_error : snapshot.last_error;
  if (failure) {
    std::cout << "FAILURE ";
    print_error(*failure);
    std::cout << '\n';
  }
  const auto stats = bridge.events.stats();
  std::cout << "QUEUE   depth=" << stats.current_depth << '/' << stats.capacity
            << " rejected=" << bridge.rejected.load(std::memory_order_relaxed) << '\n';
}

std::optional<heyaki::LanSignalingMessage> pairing_request_at(
    const UiState& state, std::size_t one_based_index) {
  std::size_t current = 0U;
  for (const auto& event : state.signaling_events) {
    if (event.kind != heyaki::LanSignalingMessageKind::connect_request) {
      continue;
    }
    if (++current == one_based_index) {
      return event;
    }
  }
  return std::nullopt;
}

void set_command_result(UiState& state, heyaki::Result<void> result,
                        std::string success) {
  if (result) {
    state.command_status = std::move(success);
    state.command_error.reset();
  } else {
    state.command_status.clear();
    state.command_error = *result.error_if();
  }
}

void run_command(std::string line, heyaki::Node& node, UiState& state,
                 bool& running) {
  std::istringstream input(std::move(line));
  std::string command;
  input >> command;
  if (command.empty() || command == "refresh") {
    set_command_result(state, node.refresh_interfaces(), "interfaces-refreshing");
    return;
  }
  if (command == "quit" || command == "exit") {
    running = false;
    return;
  }
  std::size_t index = 0U;
  input >> index;
  if (!input || index == 0U) {
    state.command_status.clear();
    state.command_error = heyaki::Error{heyaki::ErrorCode::configuration, "tui",
                                        "command_index_invalid"};
    return;
  }
  if (command == "accept" || command == "deny") {
    const auto request = pairing_request_at(state, index);
    if (!request) {
      state.command_status.clear();
      state.command_error = heyaki::Error{heyaki::ErrorCode::configuration, "tui",
                                          "pairing_request_not_found"};
      return;
    }
    const auto kind = command == "accept"
                          ? heyaki::LanSignalingMessageKind::connect_accept
                          : heyaki::LanSignalingMessageKind::connect_deny;
    auto result = node.send_lan_signaling(
        heyaki::LanSignalingMessage{.peer = request->peer,
                                    .kind = kind,
                                    .request_id = request->request_id,
                                    .payload = {}});
    set_command_result(state, std::move(result),
                       command == "accept" ? "pair-request-accepted"
                                           : "pair-request-denied");
    return;
  }
  const auto endpoints = node.endpoints();
  const auto peer = endpoint_at(endpoints, index);
  if (!peer) {
    state.command_status.clear();
    state.command_error = heyaki::Error{heyaki::ErrorCode::endpoint_offline, "tui",
                                        "endpoint_index_not_found"};
    return;
  }
  if (command == "connect") {
    set_command_result(state, node.connect_lan(*peer), "lan-connect-admitted");
    return;
  }
  if (command == "close") {
    set_command_result(state, node.close_lan(*peer), "lan-signaling-closed");
    return;
  }
  if (command == "pair") {
    auto connected = connection_authenticated(node, *peer)
                         ? heyaki::Result<void>::success()
                         : node.connect_lan(*peer);
    if (connected && !connection_authenticated(node, *peer)) {
      connected = wait_for_authenticated(node, *peer, 8s);
    }
    if (!connected) {
      set_command_result(state, std::move(connected), {});
      return;
    }
    auto requested = node.send_lan_signaling(
        heyaki::LanSignalingMessage{
            .peer = *peer,
            .kind = heyaki::LanSignalingMessageKind::connect_request,
            .request_id = make_request_id(),
            .payload = {}});
    set_command_result(state, std::move(requested), "pair-request-sent");
    return;
  }
  state.command_status.clear();
  state.command_error = heyaki::Error{heyaki::ErrorCode::configuration, "tui",
                                      "command_unknown"};
}

int run_tui(const Options& options) {
  auto opened = heyaki::ProfileStore::open_default(options.profile_name);
  std::optional<heyaki::ProfileStore> profile;
  if (opened) {
    profile.emplace(std::move(*opened.value_if()));
  }

  if (!profile) {
    if (options.status_only) {
      render_uninitialized(options.profile_name, *opened.error_if());
      return 0;
    }
    render_uninitialized(options.profile_name);
    std::cout << "\ncommand [init|quit]> " << std::flush;
    std::string command;
    if (!std::getline(std::cin, command) || command != "init") {
      return 0;
    }
    auto created = heyaki::ProfileStore::create_default(options.profile_name);
    if (!created) {
      render_uninitialized(options.profile_name, *created.error_if());
      return 1;
    }
    profile.emplace(std::move(*created.value_if()));
  }

  auto readiness = profile->local_readiness(application_id);
  if (!readiness) {
    render_uninitialized(options.profile_name, *readiness.error_if());
    return 1;
  }
  if (!options.status_only && !readiness.value_if()->endpoint_ready &&
      readiness.value_if()->identity_ready &&
      readiness.value_if()->password_verifier_ready &&
      readiness.value_if()->pairing_policy_ready &&
      readiness.value_if()->lan_configuration_ready) {
    auto endpoint = profile->endpoint_for(application_id);
    if (!endpoint) {
      render_uninitialized(options.profile_name, *endpoint.error_if());
      return 1;
    }
    readiness = profile->local_readiness(application_id);
    if (!readiness) {
      render_uninitialized(options.profile_name, *readiness.error_if());
      return 1;
    }
  }
  if (!readiness.value_if()->ready()) {
    if (options.status_only) {
      render_uninitialized(options.profile_name);
      return 0;
    }
    auto initialized = initialize_local_profile(*profile);
    if (!initialized) {
      render_uninitialized(options.profile_name, *initialized.error_if());
      return 1;
    }
  }

  auto lan = profile->lan_configuration();
  if (!lan) {
    render_uninitialized(options.profile_name, *lan.error_if());
    return 1;
  }
  auto bridge = std::make_shared<UiBridge>(lan.value_if()->pending_signaling_capacity);
  auto handler = [bridge](const heyaki::LanSignalingMessage& message) {
    if (!bridge->events.try_send(message)) {
      bridge->rejected.fetch_add(1U, std::memory_order_relaxed);
      return heyaki::Result<void>::failure(
          heyaki::Error{heyaki::ErrorCode::resource_exhausted, "tui",
                        "ui_event_capacity_full"});
    }
    return heyaki::Result<void>::success();
  };
  auto node = heyaki::Node::create(
      heyaki::NodeConfig{.profile = &*profile,
                         .runtime = nullptr,
                         .application_id = std::string{application_id},
                         .lan_override = std::nullopt,
                         .runtime_config = heyaki::RuntimeConfig{},
                         .signaling_validator = {},
                         .signaling_handler = std::move(handler)});
  if (!node) {
    render_uninitialized(options.profile_name, *node.error_if());
    return 1;
  }

  UiState state;
  if (options.status_only) {
    render_node(options.profile_name, *node.value_if(), *bridge, state,
                lan.value_if()->pending_signaling_capacity);
    (void)node.value_if()->shutdown();
    return 0;
  }

  bool running = true;
  while (running) {
    std::cout << "\x1b[2J\x1b[H";
    render_node(options.profile_name, *node.value_if(), *bridge, state,
                lan.value_if()->pending_signaling_capacity);
    std::cout << "\ncommand [refresh|connect N|pair N|accept N|deny N|close N|quit]> "
              << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) {
      break;
    }
    run_command(std::move(line), *node.value_if(), state, running);
  }
  bridge->events.close();
  const auto shutdown = node.value_if()->shutdown();
  return shutdown.stopped ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  const auto options = parse_options(argc, argv);
  if (!options) {
    print_usage();
    return 2;
  }
  const auto info = heyaki::build_info();
  if (options->version) {
    std::cout << "heyaki-tui " << info.version << " (" << info.commit << ")\n";
    return 0;
  }
  if (options->help) {
    print_usage();
    return 0;
  }
  return run_tui(*options);
}
