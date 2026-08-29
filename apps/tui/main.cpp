#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/relay_enrollment_client.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/version.hpp>

#include <executor/comm.hpp>

#include "device_view.hpp"

#include <heyaki/byte_stream.hpp>
#include <heyaki/message.hpp>
#include <heyaki/rpc.hpp>
#include <heyaki/trust_grant.hpp>

#include <atomic>
#include <iomanip>
#include <sstream>
#include "local_setup.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
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
  // Latest terminal pairing outcome (M5-19); written from the node strand,
  // read by the render loop.
  std::mutex pairing_mutex;
  std::string pairing_peer;
  std::optional<heyaki::Error> pairing_error;
  std::string pairing_scopes;
  // ---- M6 message & RPC view state (written from the node strand) ----
  struct InboundMessage {
    heyaki::DeviceEndpointKey peer;
    heyaki::MessageEnvelope envelope;
  };
  struct AckEvent {
    heyaki::DeviceEndpointKey peer;
    heyaki::MessageId message_id;
    heyaki::MessageDeliveryEvent event;
    std::optional<heyaki::Error> error;
  };
  struct RpcResult {
    heyaki::DeviceEndpointKey peer;
    heyaki::Result<heyaki::RpcCallOutcome> outcome;
  };
  std::mutex service_mutex;
  std::deque<InboundMessage> inbound_messages;
  std::deque<AckEvent> ack_events;
  std::deque<RpcResult> rpc_results;
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

std::string_view relay_state_name(heyaki::RelayNodeState state) noexcept {
  return heyaki::relay_node_state_name(state);
}

void print_error(const heyaki::Error& error);

void render_relay(const heyaki::RelayNodeSnapshot& relay) {
  if (!relay.enabled) {
    std::cout << "RELAY   disabled\n";
    return;
  }
  std::cout << "RELAY   " << relay_state_name(relay.state) << "  url=" << relay.relay_url
            << "  tenant=" << relay.tenant
            << "  generation=" << relay.enrollment_generation
            << "  lease=" << relay.lease_generation
            << "  heartbeat=" << relay.heartbeats_sent
            << "  missed=" << relay.heartbeats_missed
            << "  reconnect=" << relay.reconnect_count;
  if (relay.backoff.count() > 0) {
    std::cout << "  backoff=" << relay.backoff.count() << "ms";
  }
  std::cout << '\n';
  if (relay.last_error) {
    std::cout << "        ";
    print_error(*relay.last_error);
    std::cout << '\n';
  }
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

void render_uninitialized(std::string_view profile_name,
                          const std::optional<heyaki::Error>& error = std::nullopt) {
  std::cout << "HEYAKI  profile=" << profile_name << "\n\n";
  std::cout << "LOCAL   not-initialized\n";
  std::cout << "LAN     stopped\n";
  std::cout << "RELAY   disabled\n";
  std::cout << "PAIRING unavailable\n";
  if (error) {
    std::cout << "FAILURE ";
    print_error(*error);
    std::cout << '\n';
  }
}

std::string preview_bytes(const std::vector<std::byte>& payload, std::size_t limit) {
  std::ostringstream output;
  for (std::size_t index = 0U; index < payload.size() && index < limit; ++index) {
    const auto value = std::to_integer<unsigned char>(payload[index]);
    if (value >= 0x20U && value < 0x7FU) {
      output << static_cast<char>(value);
    } else {
      output << "\\x" << std::hex << std::setw(2) << std::setfill('0') << value
             << std::dec;
    }
  }
  if (payload.size() > limit) {
    output << "...(" << payload.size() << " bytes)";
  }
  return output.str();
}

void render_node(std::string_view profile_name, heyaki::Node& node,
                 UiBridge& bridge, UiState& state, std::size_t event_capacity) {
  drain_ui_events(bridge, state, event_capacity);
  const auto snapshot = node.snapshot();
  const auto endpoints = node.endpoints();
  const auto sessions = node.peer_sessions();
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
  render_relay(snapshot.relay);

  std::cout << "\nINTERFACES\n";
  if (snapshot.interfaces.empty()) {
    std::cout << "  none\n";
  }
  for (const auto& interface : snapshot.interfaces) {
    std::string_view status = "failed";
    if (interface.joined && !snapshot.discoverable) {
      status = "joined";
    } else if (interface.multicast_verified) {
      status = "ready ";
    } else if (interface.joined &&
               snapshot.lan_state == heyaki::LanReadinessState::starting) {
      status = "probe ";
    } else if (interface.joined) {
      status = "blocked";
    }
    std::cout << "  " << status << ' ' << interface.name << ' '
              << interface.address << " if=" << interface.index;
    if (interface.error) {
      std::cout << "  ";
      print_error(*interface.error);
    }
    std::cout << '\n';
  }

  heyaki::tui::render_device_view(std::cout, endpoints, sessions);

  // M6: recent inbound messages with their typed payload metadata.
  std::cout << "\nMESSAGES\n";
  {
    std::scoped_lock lock{state.service_mutex};
    if (state.inbound_messages.empty()) {
      std::cout << "  none\n";
    }
    for (const auto& item : state.inbound_messages) {
      std::cout << "  " << item.envelope.type << " schema="
                << item.envelope.schema_version << " ttl="
                << item.envelope.ttl_milliseconds << " mode="
                << heyaki::message_delivery_mode_name(item.envelope.delivery_mode)
                << " payload=" << preview_bytes(item.envelope.payload, 32U) << "\n";
    }
  }

  // M6: aggregate service diagnostics (executor facilities remain the task
  // health source; these cover protocol state).
  const auto services = node.service_diagnostics();
  std::cout << "\nSERVICES\n";
  std::cout << "  message sent_best=" << services.message.sent_best_effort
            << " sent_acked=" << services.message.sent_peer_acked
            << " acked=" << services.message.acked
            << " timeouts=" << services.message.ack_timed_out
            << " recv=" << services.message.received
            << " dup=" << services.message.duplicates
            << " scope_rej=" << services.message.scope_rejected << "\n";
  std::cout << "  rpc calls=" << services.rpc.calls_started
            << " matched=" << services.rpc.responses_matched
            << " unknown=" << services.rpc.responses_unknown
            << " outcome_unknown=" << services.rpc.outcome_unknown_calls
            << " reqs=" << services.rpc.requests_received
            << " replay=" << services.rpc.replayed_responses
            << " late_drop=" << services.rpc.late_results_dropped
            << " retries=" << services.rpc_retry_queue << "\n";

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

// Default requested scopes for the TUI pairing flow: the read-only template
// (DEC-04), matching what local initialization installs as policy.
std::vector<std::string> default_pairing_scopes() {
  return {"message.send", "rpc.device.read", "event.telemetry.subscribe",
          "file.push:inbox", "stream.open"};
}

void render_pairing_status(UiState& state) {
  std::scoped_lock lock{state.pairing_mutex};
  if (state.pairing_peer.empty()) return;
  std::cout << "pairing " << state.pairing_peer << ": ";
  if (state.pairing_error) {
    std::cout << "denied (" << state.pairing_error->safe_detail() << ")\n";
    return;
  }
  std::cout << "granted scopes=" << state.pairing_scopes << "\n";
}

std::string format_stream_bytes(const std::byte* data, std::size_t size,
                                bool hex) {
  std::ostringstream output;
  if (hex) {
    for (std::size_t index = 0U; index < size; ++index) {
      output << std::hex << std::setw(2) << std::setfill('0')
             << static_cast<unsigned>(std::to_integer<std::uint8_t>(data[index]));
    }
    return output.str();
  }
  output.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
  return output.str();
}

// M5-20 stream view: text/hex send, half-close, reset, and live window state.
void run_stream_view(const heyaki::DeviceEndpointKey& peer,
                     heyaki::ByteStream stream) {
  std::cout << "\nSTREAM device=" << heyaki::to_string(peer.device_id)
            << "\ncommands [send <text>|sendhex <hex>|read|readhex|window|fin|reset|exit]\n";
  bool in_stream = true;
  while (in_stream) {
    const auto window = stream.window();
    std::cout << "stream state=" << heyaki::byte_stream_state_name(stream.state())
              << " send_credit=" << window.send_credit_bytes
              << " buffered=" << window.receive_buffered_bytes << "\n";
    std::cout << "stream> " << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) return;
    std::istringstream input{line};
    std::string command;
    input >> command;
    if (command == "exit") {
      in_stream = false;
    } else if (command == "send" || command == "sendhex") {
      std::string payload_text;
      std::getline(input, payload_text);
      if (!payload_text.empty() && payload_text.front() == ' ') {
        payload_text.erase(payload_text.begin());
      }
      std::vector<std::byte> payload;
      if (command == "sendhex") {
        payload.reserve(payload_text.size() / 2U);
        for (std::size_t index = 0U; index + 1U < payload_text.size(); index += 2U) {
          const auto byte = static_cast<unsigned>(
              std::strtoul(payload_text.substr(index, 2U).c_str(), nullptr, 16));
          payload.push_back(static_cast<std::byte>(byte & 0xFFU));
        }
      } else {
        payload.assign(reinterpret_cast<const std::byte*>(payload_text.data()),
                       reinterpret_cast<const std::byte*>(payload_text.data()) +
                           payload_text.size());
      }
      // Completion means the bytes entered the controlled send window
      // (M5-18), not that the peer read them.
      stream.async_write(payload, [](heyaki::ByteStreamIoResult result) {
        if (result.error) {
          std::cout << "stream write failed: " << result.error->safe_detail()
                    << " bytes=" << result.bytes << "\n";
        }
      });
    } else if (command == "read" || command == "readhex") {
      auto buffer = std::make_unique<std::byte[]>(4096U);
      stream.async_read_some(
          std::span<std::byte>{buffer.get(), 4096U},
          [&, buffer = buffer.release()](heyaki::ByteStreamIoResult result) {
            if (result.error) {
              std::cout << "stream read failed: " << result.error->safe_detail()
                        << "\n";
              delete[] buffer;
              return;
            }
            if (result.bytes == 0U) {
              std::cout << "stream end-of-stream\n";
            } else {
              std::cout << (command == "readhex" ? "hex: " : "text: ")
                        << format_stream_bytes(buffer, result.bytes,
                                               command == "readhex")
                        << "\n";
            }
            delete[] buffer;
          });
    } else if (command == "window") {
      std::cout << "next_send_offset=" << window.next_send_offset
                << " send_credit_bytes=" << window.send_credit_bytes
                << " send_credit_frames=" << window.send_credit_frames
                << " receive_window_bytes=" << window.receive_window_bytes
                << " receive_buffered=" << window.receive_buffered_bytes
                << " consumed_through=" << window.consumed_through_offset << "\n";
    } else if (command == "fin") {
      const auto closed = stream.shutdown_write();
      std::cout << (closed ? "stream half-closed\n"
                           : "stream fin failed\n");
    } else if (command == "reset") {
      stream.reset(heyaki::StableStatus::cancelled);
      std::cout << "stream reset\n";
    } else {
      std::cout << "stream command unknown\n";
    }
  }
}

// M6: registers the TUI's built-in acceptance service so two TUI instances
// can exercise message and RPC end to end through the public API. Echo is a
// plain unary round trip; slow-echo deliberately outlives short deadlines
// and cancels so the views can show those outcomes.
heyaki::Result<void> register_tui_services(heyaki::Node& node) {
  heyaki::RpcMethodDescriptor echo;
  echo.service = "heyaki.tui";
  echo.method = "echo";
  echo.schema_version = 1U;
  echo.required_scope = "rpc.device.read";
  auto registered = node.register_rpc_method(
      echo, [](const heyaki::RpcCallContext& context) {
        return heyaki::RpcHandlerResult{
            heyaki::StableStatus::ok,
            std::vector<std::byte>(context.payload().begin(), context.payload().end()),
            "ok"};
      });
  if (!registered) return registered;

  heyaki::RpcMethodDescriptor info;
  info.service = "heyaki.tui";
  info.method = "info";
  info.schema_version = 1U;
  info.required_scope = "rpc.device.read";
  registered = node.register_rpc_method(
      info, [](const heyaki::RpcCallContext& context) {
        if (context.cancelled()) {
          return heyaki::RpcHandlerResult{heyaki::StableStatus::cancelled, {},
                                          "cancelled_before_reply"};
        }
        const std::string text = "heyaki-tui unary rpc v1";
        return heyaki::RpcHandlerResult{
            heyaki::StableStatus::ok,
            std::vector<std::byte>(reinterpret_cast<const std::byte*>(text.data()),
                                   reinterpret_cast<const std::byte*>(text.data()) +
                                       text.size()),
            "ok"};
      });
  if (!registered) return registered;

  heyaki::RpcMethodDescriptor slow;
  slow.service = "heyaki.tui";
  slow.method = "slow-echo";
  slow.schema_version = 1U;
  slow.required_scope = "rpc.device.read";
  registered = node.register_rpc_method(
      slow, [](const heyaki::RpcCallContext& context) {
        // Busy-wait is deliberate: it models a handler that keeps running
        // past its deadline while cooperating with cancellation.
        while (!context.cancelled() &&
               context.deadline_unix_milliseconds() + 60'000U >
                   static_cast<std::uint64_t>(
                       std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count())) {
          std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        if (context.cancelled()) {
          return heyaki::RpcHandlerResult{heyaki::StableStatus::cancelled, {},
                                          "observed_cancel"};
        }
        return heyaki::RpcHandlerResult{heyaki::StableStatus::ok, {}, "slow_ok"};
      });
  return registered;
}

std::string_view delivery_event_name(heyaki::MessageDeliveryEvent event) noexcept {
  return heyaki::message_delivery_event_name(event);
}

void push_service_event(UiState& state, heyaki::DeviceEndpointKey peer,
                        const heyaki::MessageEnvelope& envelope) {
  std::scoped_lock lock{state.service_mutex};
  state.inbound_messages.push_back(UiState::InboundMessage{peer, envelope});
  while (state.inbound_messages.size() > 32U) {
    state.inbound_messages.pop_front();
  }
}

void push_ack_event(UiState& state, const heyaki::DeviceEndpointKey& peer,
                    const heyaki::MessageId& id, heyaki::MessageDeliveryEvent event,
                    std::optional<heyaki::Error> error) {
  std::scoped_lock lock{state.service_mutex};
  state.ack_events.push_back(UiState::AckEvent{peer, id, event, std::move(error)});
  while (state.ack_events.size() > 64U) {
    state.ack_events.pop_front();
  }
}

void push_rpc_result(UiState& state, const heyaki::DeviceEndpointKey& peer,
                     heyaki::Result<heyaki::RpcCallOutcome> outcome) {
  std::scoped_lock lock{state.service_mutex};
  state.rpc_results.push_back(UiState::RpcResult{peer, std::move(outcome)});
  while (state.rpc_results.size() > 32U) {
    state.rpc_results.pop_front();
  }
}

// M6-14: message view with typed payload, TTL, delivery mode, ACK state, and
// structured failures.
void run_message_view(const heyaki::DeviceEndpointKey& peer, heyaki::Node& node,
                      UiState& state) {
  std::string type = "tui.note";
  std::uint32_t ttl_milliseconds = 30'000U;
  heyaki::MessageDeliveryMode mode = heyaki::MessageDeliveryMode::peer_acked;
  std::cout << "\nMESSAGE device=" << heyaki::to_string(peer.device_id)
            << "\ncommands [type NAME|ttl MS|mode best|acked|send <text>|sendhex "
               "<hex>|inbox|acks|exit]\n";
  bool in_view = true;
  while (in_view) {
    std::cout << "message type=" << type << " ttl=" << ttl_milliseconds
              << " mode=" << heyaki::message_delivery_mode_name(mode) << "> "
              << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) return;
    std::istringstream input{line};
    std::string command;
    input >> command;
    if (command == "exit") {
      in_view = false;
    } else if (command == "type") {
      input >> type;
    } else if (command == "ttl") {
      std::uint32_t ttl = 0U;
      input >> ttl;
      if (ttl > 0U) ttl_milliseconds = ttl;
    } else if (command == "mode") {
      std::string which;
      input >> which;
      if (which == "best") {
        mode = heyaki::MessageDeliveryMode::best_effort;
      } else if (which == "acked") {
        mode = heyaki::MessageDeliveryMode::peer_acked;
      }
    } else if (command == "send" || command == "sendhex") {
      std::string payload_text;
      std::getline(input, payload_text);
      if (!payload_text.empty() && payload_text.front() == ' ') {
        payload_text.erase(payload_text.begin());
      }
      std::vector<std::byte> payload;
      if (command == "sendhex") {
        payload.reserve(payload_text.size() / 2U);
        for (std::size_t index = 0U; index + 1U < payload_text.size(); index += 2U) {
          const auto byte = static_cast<unsigned>(
              std::strtoul(payload_text.substr(index, 2U).c_str(), nullptr, 16));
          payload.push_back(static_cast<std::byte>(byte & 0xFFU));
        }
      } else {
        payload.assign(reinterpret_cast<const std::byte*>(payload_text.data()),
                       reinterpret_cast<const std::byte*>(payload_text.data()) +
                           payload_text.size());
      }
      heyaki::MessageEnvelope envelope;
      envelope.type = type;
      envelope.ttl_milliseconds = ttl_milliseconds;
      envelope.delivery_mode = mode;
      envelope.payload = std::move(payload);
      auto sent = node.send_message(peer, std::move(envelope));
      if (!sent) {
        std::cout << "send failed: " << sent.error_if()->safe_detail() << " ("
                  << heyaki::error_code_name(sent.error_if()->code()) << ")\n";
      } else {
        std::cout << "sent id=" << heyaki::to_string(*sent.value_if()) << "\n";
      }
    } else if (command == "inbox") {
      std::scoped_lock lock{state.service_mutex};
      if (state.inbound_messages.empty()) {
        std::cout << "inbox empty\n";
      }
      for (const auto& item : state.inbound_messages) {
        std::cout << "msg type=" << item.envelope.type
                  << " schema=" << item.envelope.schema_version
                  << " ttl=" << item.envelope.ttl_milliseconds
                  << " mode="
                  << heyaki::message_delivery_mode_name(item.envelope.delivery_mode)
                  << " payload=" << preview_bytes(item.envelope.payload, 48U) << "\n";
      }
    } else if (command == "acks") {
      std::scoped_lock lock{state.service_mutex};
      if (state.ack_events.empty()) {
        std::cout << "no delivery events\n";
      }
      for (const auto& event : state.ack_events) {
        std::cout << "delivery id=" << heyaki::to_string(event.message_id) << " "
                  << delivery_event_name(event.event);
        if (event.error) {
          std::cout << " error=" << event.error->safe_detail();
        }
        std::cout << "\n";
      }
    } else {
      std::cout << "message command unknown\n";
    }
  }
}

heyaki::Result<heyaki::RpcCallOutcome> wait_rpc_result(UiState& state,
                                                       std::uint32_t deadline_ms) {
  const auto limit = std::chrono::steady_clock::now() +
                     std::chrono::milliseconds{deadline_ms + 2000U};
  executor::comm::PhaseGate poll{"heyaki-tui-rpc-wait"};
  while (std::chrono::steady_clock::now() < limit) {
    {
      std::scoped_lock lock{state.service_mutex};
      if (!state.rpc_results.empty()) {
        auto outcome = std::move(state.rpc_results.front());
        state.rpc_results.pop_front();
        return std::move(outcome.outcome);
      }
    }
    (void)poll.wait_for(1U, std::chrono::milliseconds{20});
  }
  return heyaki::Result<heyaki::RpcCallOutcome>::failure(
      heyaki::Error{heyaki::ErrorCode::timeout, "tui", "rpc_view_wait_timeout"});
}

// M6-15: RPC view with local descriptors, raw text/hex payloads, deadline,
// cancellation, and structured status; no JSON assumption about payloads.
void run_rpc_view(const heyaki::DeviceEndpointKey& peer, heyaki::Node& node,
                  UiState& state) {
  std::uint32_t deadline = 10'000U;
  std::optional<heyaki::RequestId> pending;
  std::cout << "\nRPC device=" << heyaki::to_string(peer.device_id)
            << "\ncommands [list|deadline MS|call <svc> <m> <text>|callhex <svc> "
               "<m> <hex>|cancel|exit]\n";
  bool in_view = true;
  while (in_view) {
    std::cout << "rpc deadline=" << deadline << "ms"
              << (pending.has_value() ? " pending-cancelable" : "") << "> "
              << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) return;
    std::istringstream input{line};
    std::string command;
    input >> command;
    if (command == "exit") {
      in_view = false;
    } else if (command == "list") {
      for (const auto& method : node.rpc_methods()) {
        std::cout << "method " << method.service << "." << method.method
                  << " schema=" << method.schema_version
                  << " scope=" << method.required_scope
                  << (method.streaming ? " streaming(unimplemented)" : "") << "\n";
      }
    } else if (command == "deadline") {
      std::uint32_t value = 0U;
      input >> value;
      if (value > 0U) deadline = value;
    } else if (command == "cancel") {
      if (pending.has_value()) {
        const auto cancelled = node.cancel_rpc(peer, *pending);
        std::cout << (cancelled ? "cancel sent\n"
                                : "cancel failed (call not pending)\n");
      } else {
        std::cout << "no pending request\n";
      }
    } else if (command == "call" || command == "callhex") {
      std::string service;
      std::string method;
      input >> service >> method;
      std::string payload_text;
      std::getline(input, payload_text);
      if (!payload_text.empty() && payload_text.front() == ' ') {
        payload_text.erase(payload_text.begin());
      }
      std::vector<std::byte> payload;
      if (command == "callhex") {
        payload.reserve(payload_text.size() / 2U);
        for (std::size_t index = 0U; index + 1U < payload_text.size(); index += 2U) {
          const auto byte = static_cast<unsigned>(
              std::strtoul(payload_text.substr(index, 2U).c_str(), nullptr, 16));
          payload.push_back(static_cast<std::byte>(byte & 0xFFU));
        }
      } else {
        payload.assign(reinterpret_cast<const std::byte*>(payload_text.data()),
                       reinterpret_cast<const std::byte*>(payload_text.data()) +
                           payload_text.size());
      }
      {
        std::scoped_lock lock{state.service_mutex};
        state.rpc_results.clear();
      }
      heyaki::RpcCallOptions options;
      options.deadline_remaining_milliseconds = deadline;
      auto started = node.call_rpc(
          peer, service, method, std::move(payload), std::move(options),
          [&state](const heyaki::DeviceEndpointKey& call_peer,
                   heyaki::Result<heyaki::RpcCallOutcome> outcome) {
            push_rpc_result(state, call_peer, std::move(outcome));
          });
      if (!started) {
        std::cout << "call rejected: " << started.error_if()->safe_detail() << " ("
                  << heyaki::error_code_name(started.error_if()->code()) << ")\n";
        continue;
      }
      pending = *started.value_if();
      auto outcome = wait_rpc_result(state, deadline);
      pending.reset();
      if (!outcome) {
        std::cout << "call failed locally: " << outcome.error_if()->safe_detail()
                  << " (" << heyaki::error_code_name(outcome.error_if()->code())
                  << ")\n";
        continue;
      }
      std::cout << "status=" << static_cast<int>((*outcome.value_if()).status)
                << " detail=" << (*outcome.value_if()).safe_detail
                << " payload=" << preview_bytes((*outcome.value_if()).payload, 64U)
                << "\n";
    } else {
      std::cout << "rpc command unknown\n";
    }
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
  const auto endpoints = node.endpoints();
  const auto peer = endpoint_at(endpoints, index);
  if (!peer) {
    state.command_status.clear();
    state.command_error = heyaki::Error{heyaki::ErrorCode::endpoint_offline, "tui",
                                        "endpoint_index_not_found"};
    return;
  }
  if (command == "connect") {
    // Route selection follows the merged LAN/relay directory and connectivity
    // policy; the resulting session reports its actual signaling route and
    // data path in the SESSIONS view.
    set_command_result(state, node.connect(*peer), "connect-admitted");
    return;
  }
  if (command == "close") {
    set_command_result(state, node.close_lan(*peer), "lan-signaling-closed");
    return;
  }
  if (command == "pair") {
    // M5-19: password pairing against this peer's restricted session. The
    // password is read hidden, used once, and never stored or logged.
    const auto peer_index = index;
    auto password = read_secret("target authorization password: ");
    if (!password) {
      state.command_status.clear();
      state.command_error = *password.error_if();
      return;
    }
    {
      std::scoped_lock lock{state.pairing_mutex};
      state.pairing_peer = "endpoint-" + std::to_string(peer_index);
      state.pairing_error.reset();
      state.pairing_scopes.clear();
    }
    auto paired = node.pair_peer(*peer, *password.value_if(),
                                 default_pairing_scopes());
    wipe_string(*password.value_if());
    if (!paired) {
      state.command_status.clear();
      state.command_error = *paired.error_if();
      return;
    }
    set_command_result(state, heyaki::Result<void>::success(),
                       "pairing-submitted");
    return;
  }
  if (command == "trust") {
    // M5-19: grants of the relationship with this peer.
    auto grants = node.trust_grants_for(*peer);
    if (!grants) {
      state.command_status.clear();
      state.command_error = *grants.error_if();
      return;
    }
    std::cout << "\nTRUST device=" << heyaki::to_string(peer->device_id) << "\n";
    if (grants.value_if()->empty()) {
      std::cout << "  none\n";
    }
    for (std::size_t grant_index = 0U; grant_index < grants.value_if()->size();
         ++grant_index) {
      const auto& grant = (*grants.value_if())[grant_index];
      std::cout << "  [" << grant_index + 1U << "] "
                << (grant.direction == heyaki::TrustGrantDirection::issued
                        ? "issued"
                        : "received")
                << " grant=" << heyaki::to_string(grant.grant_id)
                << " generation=" << grant.password_generation
                << (grant.revoked ? " revoked" : "") << "\n      scopes=";
      for (const auto& scope : grant.scopes) std::cout << scope << " ";
      std::cout << "\n";
    }
    state.command_status = "trust-listed";
    state.command_error.reset();
    return;
  }
  if (command == "revoke") {
    std::size_t grant_index = 0U;
    input >> grant_index;
    if (!input || grant_index == 0U) {
      state.command_status.clear();
      state.command_error = heyaki::Error{heyaki::ErrorCode::configuration, "tui",
                                          "grant_index_invalid"};
      return;
    }
    auto grants = node.trust_grants_for(*peer);
    if (!grants || grant_index > grants.value_if()->size()) {
      state.command_status.clear();
      state.command_error = heyaki::Error{heyaki::ErrorCode::not_registered, "tui",
                                          "grant_index_not_found"};
      return;
    }
    const auto& grant = (*grants.value_if())[grant_index - 1U];
    set_command_result(state, node.revoke_trust_grant(grant.grant_id),
                       "grant-revoked");
    return;
  }
  if (command == "rotate-password" || command == "rotate-password-revoke") {
    auto password = read_secret("new authorization password: ");
    if (!password) {
      state.command_status.clear();
      state.command_error = *password.error_if();
      return;
    }
    auto confirmation = read_secret("confirm password: ");
    if (!confirmation || *confirmation.value_if() != *password.value_if()) {
      wipe_string(*password.value_if());
      state.command_status.clear();
      state.command_error = heyaki::Error{heyaki::ErrorCode::authentication, "tui",
                                          "password_confirmation_mismatch"};
      return;
    }
    auto rotated = command == "rotate-password"
                       ? node.rotate_authorization_password(*password.value_if())
                       : node.rotate_authorization_password_and_revoke(
                           *password.value_if());
    wipe_string(*password.value_if());
    wipe_string(*confirmation.value_if());
    if (!rotated) {
      state.command_status.clear();
      state.command_error = *rotated.error_if();
      return;
    }
    state.command_status = "password-rotated generation=" +
                           std::to_string(*rotated.value_if());
    state.command_error.reset();
    return;
  }
  if (command == "stream") {
    // M5-20: open the generic ByteStream view on this peer's session.
    auto stream = node.open_byte_stream(*peer);
    if (!stream) {
      state.command_status.clear();
      state.command_error = *stream.error_if();
      return;
    }
    run_stream_view(*peer, std::move(*stream.value_if()));
    state.command_status = "stream-closed";
    state.command_error.reset();
    return;
  }
  if (command == "msg") {
    // M6-14: message view (typed payload, TTL, delivery mode, ACK state).
    run_message_view(*peer, node, state);
    state.command_status = "message-view-closed";
    state.command_error.reset();
    return;
  }
  if (command == "rpc") {
    // M6-15: unary RPC view (descriptors, raw payloads, deadline, cancel).
    run_rpc_view(*peer, node, state);
    state.command_status = "rpc-view-closed";
    state.command_error.reset();
    return;
  }
  state.command_status.clear();
  state.command_error = heyaki::Error{heyaki::ErrorCode::configuration, "tui",
                                      "command_unknown"};
}

void render_incomplete(std::string_view profile_name) {
  render_uninitialized(profile_name);
  std::cout << "SETUP   incomplete\n";
}

enum class IncompleteProfileAction : std::uint8_t {
  resume,
  reset,
  quit,
};

IncompleteProfileAction prompt_incomplete_profile_action() {
  while (true) {
    std::cout << "\ncommand [resume|reset|quit]> " << std::flush;
    std::string command;
    if (!std::getline(std::cin, command) || command == "quit") {
      return IncompleteProfileAction::quit;
    }
    if (command == "resume") {
      return IncompleteProfileAction::resume;
    }
    if (command != "reset") {
      continue;
    }
    std::cout << "confirm reset [yes|no]> " << std::flush;
    std::string confirmation;
    if (!std::getline(std::cin, confirmation)) {
      return IncompleteProfileAction::quit;
    }
    if (confirmation == "yes") {
      return IncompleteProfileAction::reset;
    }
  }
}

heyaki::Result<heyaki::LocalProfileInitialization> read_local_initialization(
    std::string_view profile_name) {
  return heyaki::tui::read_local_profile_initialization(
      application_id, read_secret, [profile_name](const heyaki::Error& error) {
        render_uninitialized(profile_name, error);
      });
}

heyaki::Result<void> enroll_relay_from_tui(heyaki::ProfileStore& profile,
                                             std::string_view profile_name) {
  auto existing = profile.relay_enrollments();
  if (!existing) {
    return heyaki::Result<void>::failure(*existing.error_if());
  }
  if (!existing.value_if()->empty()) {
    render_uninitialized(profile_name);
    return heyaki::Result<void>::success();
  }
  std::cout << "relay URL [wss://relay.example:8443]> " << std::flush;
  std::string relay_url;
  if (!std::getline(std::cin, relay_url) || relay_url.empty()) {
    return heyaki::Result<void>::failure(
        heyaki::Error{heyaki::ErrorCode::cancelled, "tui", "relay_url_cancelled"});
  }
  std::cout << "tenant [default]> " << std::flush;
  std::string tenant;
  if (!std::getline(std::cin, tenant)) {
    return heyaki::Result<void>::failure(
        heyaki::Error{heyaki::ErrorCode::cancelled, "tui", "relay_tenant_cancelled"});
  }
  if (tenant.empty()) {
    tenant = "default";
  }
  auto token = read_secret("bootstrap token: ");
  if (!token) {
    return heyaki::Result<void>::failure(*token.error_if());
  }
  heyaki::RelayEnrollmentClientConfig config;
  config.profile = &profile;
  config.application_id = std::string{application_id};
  config.relay_url = relay_url;
  config.tenant = tenant;
  config.auto_connect = true;
  config.wss_transport = heyaki::RelayEnrollmentWssTransportConfig{
      .relay_url = relay_url,
      .relay_pin = std::nullopt,
      .tls_ca_file = std::nullopt,
      .tls_verify_peer = true,
      .connect_timeout = 5s,
      .handshake_timeout = 5s,
      .close_timeout = 2s,
      .runtime = heyaki::RuntimeConfig{}};
  auto enrolled = heyaki::enroll_relay_profile(
      config, *token.value_if(), static_cast<std::uint64_t>(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch()).count()));
  wipe_string(*token.value_if());
  if (!enrolled) {
    return heyaki::Result<void>::failure(*enrolled.error_if());
  }
  return heyaki::Result<void>::success();
}

int run_tui(const Options& options) {
  auto opened = heyaki::ProfileStore::open_default(options.profile_name);
  std::optional<heyaki::ProfileStore> profile;
  bool needs_initialization = false;
  if (opened) {
    profile.emplace(std::move(*opened.value_if()));
  } else {
    bool profile_exists = true;
    if (opened.error_if()->code() == heyaki::ErrorCode::not_registered) {
      auto profiles = heyaki::ProfileStore::enumerate_default();
      if (!profiles) {
        render_uninitialized(options.profile_name, *profiles.error_if());
        return options.status_only ? 0 : 1;
      }
      profile_exists = std::any_of(
          profiles.value_if()->begin(), profiles.value_if()->end(),
          [&](const heyaki::ProfileInfo& info) {
            return info.name == options.profile_name;
          });
    }
    if (profile_exists) {
      render_uninitialized(options.profile_name, *opened.error_if());
      return options.status_only ? 0 : 1;
    }
    if (options.status_only) {
      render_uninitialized(options.profile_name);
      return 0;
    }
    render_uninitialized(options.profile_name);
    std::cout << "\ncommand [init|quit]> " << std::flush;
    std::string command;
    if (!std::getline(std::cin, command) || command != "init") {
      return 0;
    }
    needs_initialization = true;
  }

  if (profile) {
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
      render_incomplete(options.profile_name);
      if (options.status_only) {
        return 0;
      }
      const auto action = prompt_incomplete_profile_action();
      if (action == IncompleteProfileAction::quit) {
        return 0;
      }
      if (action == IncompleteProfileAction::reset) {
        const auto database_path = profile->path();
        profile.reset();
        auto deleted = heyaki::ProfileStore::delete_local(database_path);
        if (!deleted) {
          render_uninitialized(options.profile_name, *deleted.error_if());
          return 1;
        }
      }
      needs_initialization = true;
    }
  }

  if (needs_initialization) {
    auto initialization = read_local_initialization(options.profile_name);
    if (!initialization) {
      render_uninitialized(options.profile_name, *initialization.error_if());
      return initialization.error_if()->code() == heyaki::ErrorCode::cancelled ? 0 : 1;
    }
    if (!profile) {
      auto created = heyaki::ProfileStore::create_default(options.profile_name);
      if (!created) {
        render_uninitialized(options.profile_name, *created.error_if());
        return 1;
      }
      profile.emplace(std::move(*created.value_if()));
    }
    auto initialized = profile->initialize_local(*initialization.value_if());
    if (!initialized) {
      render_uninitialized(options.profile_name, *initialized.error_if());
      return 1;
    }
    auto readiness = profile->local_readiness(application_id);
    if (!readiness || !readiness.value_if()->ready()) {
      const auto error = readiness
                             ? heyaki::Error{heyaki::ErrorCode::internal, "tui",
                                             "local_initialization_incomplete"}
                             : *readiness.error_if();
      render_uninitialized(options.profile_name, error);
      return 1;
    }
  }

  auto lan = profile->lan_configuration();
  if (!lan) {
    render_uninitialized(options.profile_name, *lan.error_if());
    return 1;
  }
  auto bridge = std::make_shared<UiBridge>(lan.value_if()->pending_signaling_capacity);
  // No custom signaling handler: the Node assembles signed sessions
  // automatically, and the renderer observes bounded latest-only snapshots.
  auto make_node = [&]() {
    return heyaki::Node::create(
        heyaki::NodeConfig{.profile = &*profile,
                           .runtime = nullptr,
                           .application_id = std::string{application_id},
                           .lan_override = std::nullopt,
                           .runtime_config = heyaki::RuntimeConfig{},
                           .signaling_validator = {},
                           .signaling_handler = {},
                           .relay_override = std::nullopt,
                           .path_policy_override = std::nullopt});
  };
  std::optional<heyaki::Node> node;
  auto created_node = make_node();
  if (!created_node) {
    render_uninitialized(options.profile_name, *created_node.error_if());
    return 1;
  }
  node.emplace(std::move(*created_node.value_if()));

  UiState state;
  if (options.status_only) {
    const auto relay_enabled = node->snapshot().relay.enabled;
    if (relay_enabled) {
      const auto deadline = std::chrono::steady_clock::now() + 3s;
      executor::comm::PhaseGate poll{"heyaki-tui-relay-status"};
      while (std::chrono::steady_clock::now() < deadline) {
        const auto relay_state = node->snapshot().relay.state;
        if (relay_state == heyaki::RelayNodeState::ready ||
            relay_state == heyaki::RelayNodeState::failed ||
            relay_state == heyaki::RelayNodeState::stopped) {
          break;
        }
        (void)poll.wait_for(1U, std::chrono::milliseconds{1});
      }
    }
    render_node(options.profile_name, *node, *bridge, state,
                lan.value_if()->pending_signaling_capacity);
    (void)node->shutdown();
    return 0;
  }

  // M5-19: pairing outcomes surface in the command loop; secrets never do.
  node->set_pairing_observer([&state](const heyaki::DeviceEndpointKey& peer,
                                      const heyaki::NodePairingOutcome& outcome) {
    std::scoped_lock lock{state.pairing_mutex};
    state.pairing_peer = heyaki::to_string(peer.device_id);
    state.pairing_error.reset();
    state.pairing_scopes.clear();
    if (outcome) {
      for (const auto& scope : *outcome.value_if()) {
        state.pairing_scopes += scope;
        state.pairing_scopes += " ";
      }
    } else {
      state.pairing_error = *outcome.error_if();
    }
  });

  // M6: inbound messages and delivery outcomes surface in the views; the
  // built-in acceptance service answers unary RPCs from other TUIs.
  node->set_message_inbound_handler([&state](const heyaki::DeviceEndpointKey& peer,
                                             const heyaki::MessageEnvelope& envelope) {
    push_service_event(state, peer, envelope);
  });
  node->set_message_ack_observer(
      [&state](const heyaki::DeviceEndpointKey& peer, const heyaki::MessageId& id,
               heyaki::MessageDeliveryEvent event, std::optional<heyaki::Error> error) {
        push_ack_event(state, peer, id, event, std::move(error));
      });
  if (auto registered = register_tui_services(*node); !registered) {
    render_uninitialized(options.profile_name, *registered.error_if());
    (void)node->shutdown();
    return 1;
  }

  bool running = true;
  while (running) {
    std::cout << "\x1b[2J\x1b[H";
    render_node(options.profile_name, *node, *bridge, state,
                lan.value_if()->pending_signaling_capacity);
    render_pairing_status(state);
    std::cout << "\ncommand [refresh|relay|connect N|close N|pair N|trust N|"
                 "revoke N M|rotate-password|rotate-password-revoke|stream N|"
                 "msg N|rpc N|quit]> "
              << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) {
      break;
    }
    std::istringstream probe{line};
    std::string first_command;
    probe >> first_command;
    if (first_command == "relay") {
      auto enrolled = enroll_relay_from_tui(*profile, options.profile_name);
      if (!enrolled) {
        state.command_status.clear();
        state.command_error = *enrolled.error_if();
        continue;
      }
      const auto stopped = node->shutdown();
      if (!stopped.stopped) {
        state.command_status.clear();
        state.command_error =
            heyaki::Error{heyaki::ErrorCode::timeout, "tui",
                          "relay_node_restart_timeout"};
        node.reset();
        bridge->events.close();
        return 1;
      }
      node.reset();
      auto recreated = make_node();
      if (!recreated) {
        render_uninitialized(options.profile_name, *recreated.error_if());
        bridge->events.close();
        return 1;
      }
      node.emplace(std::move(*recreated.value_if()));
      // M6: the recreated node needs its service handlers and the built-in
      // acceptance service again.
      node->set_message_inbound_handler([&state](
                                            const heyaki::DeviceEndpointKey& peer,
                                            const heyaki::MessageEnvelope& envelope) {
        push_service_event(state, peer, envelope);
      });
      node->set_message_ack_observer(
          [&state](const heyaki::DeviceEndpointKey& peer, const heyaki::MessageId& id,
                   heyaki::MessageDeliveryEvent event,
                   std::optional<heyaki::Error> error) {
            push_ack_event(state, peer, id, event, std::move(error));
          });
      (void)register_tui_services(*node);
      state.command_status = "relay-enrolled";
      state.command_error.reset();
      continue;
    }
    run_command(std::move(line), *node, state, running);
  }
  bridge->events.close();
  const auto shutdown = node->shutdown();
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
