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
#include <heyaki/shell.hpp>
#include <heyaki/shell_terminal.hpp>
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
  // Latest terminal pairing outcome (M5-19): published from the node strand,
  // loaded by the render loop — latest-value semantics via executor comm.
  struct PairingStatus {
    std::string peer;
    std::optional<heyaki::Error> error;
    std::string scopes;
  };

  // ---- M6 message & RPC view state ----
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
    // Default placeholder so the struct is default-constructible for channel
    // receives; every real entry carries the task's terminal outcome.
    heyaki::Result<heyaki::RpcCallOutcome> outcome =
        heyaki::Result<heyaki::RpcCallOutcome>::failure(
            heyaki::Error{heyaki::ErrorCode::internal, "tui", "rpc_result_unset"});
  };

  // Cross-thread transfer from the node callbacks to the render loop: bounded
  // executor channels with drop-oldest, so admission stays observable through
  // comm stats instead of a mutex-protected deque.
  UiState()
      : inbound_channel(event_channel_options<InboundMessage>(
            32U, "heyaki-tui-inbound-messages")),
        ack_channel(event_channel_options<AckEvent>(64U, "heyaki-tui-ack-events")),
        rpc_channel(event_channel_options<RpcResult>(32U, "heyaki-tui-rpc-results")),
        pairing("heyaki-tui-pairing") {}

  executor::comm::MpscChannel<InboundMessage> inbound_channel;
  executor::comm::MpscChannel<AckEvent> ack_channel;
  executor::comm::MpscChannel<RpcResult> rpc_channel;
  executor::comm::LatestMailbox<PairingStatus> pairing;

  // ---- M7 event & file view state ----
  struct EventItemView {
    heyaki::DeviceEndpointKey peer;
    std::string pattern;
    heyaki::EventItemBody item;
  };
  struct FileEventView {
    heyaki::DeviceEndpointKey peer;
    heyaki::FileTransferEvent event;
  };
  executor::comm::MpscChannel<EventItemView> event_channel{
      event_channel_options<EventItemView>(64U, "heyaki-tui-event-items")};
  executor::comm::MpscChannel<FileEventView> file_channel{
      event_channel_options<FileEventView>(64U, "heyaki-tui-file-events")};
  std::deque<EventItemView> event_items;
  std::deque<FileEventView> file_events;

  // ---- M8 shell view state ----
  struct ShellEventView {
    heyaki::DeviceEndpointKey peer;
    heyaki::ShellServiceEvent event;
  };
  executor::comm::MpscChannel<ShellEventView> shell_channel{
      event_channel_options<ShellEventView>(128U, "heyaki-tui-shell-events")};
  std::deque<ShellEventView> shell_events;

  // Render-loop-owned display buffers; single-threaded after the drain.
  std::deque<InboundMessage> inbound_messages;
  std::deque<AckEvent> ack_events;
  std::deque<RpcResult> rpc_results;

  std::deque<heyaki::LanSignalingMessage> signaling_events;
  std::optional<heyaki::Error> command_error;
  std::string command_status;

  // Moves every queued cross-thread event into the display buffers.
  void drain_service_events() {
    InboundMessage inbound;
    while (inbound_channel.try_receive(inbound)) {
      inbound_messages.push_back(std::move(inbound));
      while (inbound_messages.size() > 32U) {
        inbound_messages.pop_front();
      }
    }
    AckEvent ack;
    while (ack_channel.try_receive(ack)) {
      ack_events.push_back(std::move(ack));
      while (ack_events.size() > 64U) {
        ack_events.pop_front();
      }
    }
    RpcResult rpc;
    while (rpc_channel.try_receive(rpc)) {
      rpc_results.push_back(std::move(rpc));
      while (rpc_results.size() > 32U) {
        rpc_results.pop_front();
      }
    }
    EventItemView item;
    while (event_channel.try_receive(item)) {
      event_items.push_back(std::move(item));
      while (event_items.size() > 64U) {
        event_items.pop_front();
      }
    }
    FileEventView file_event;
    while (file_channel.try_receive(file_event)) {
      file_events.push_back(std::move(file_event));
      while (file_events.size() > 64U) {
        file_events.pop_front();
      }
    }
    ShellEventView shell_event;
    while (shell_channel.try_receive(shell_event)) {
      shell_events.push_back(std::move(shell_event));
      while (shell_events.size() > 128U) {
        shell_events.pop_front();
      }
    }
  }

 private:
  template <typename Event>
  static executor::comm::ChannelOptions event_channel_options(std::size_t capacity,
                                                              std::string_view name) {
    executor::comm::ChannelOptions options;
    options.capacity = capacity;
    options.drop_policy = executor::comm::DropPolicy::DropOldest;
    options.enable_stats = true;
    options.name = std::string{name};
    return options;
  }
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
  state.drain_service_events();
  std::cout << "\nMESSAGES\n";
  {
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
  UiState::PairingStatus status;
  if (!state.pairing.try_load(status) || status.peer.empty()) return;
  std::cout << "pairing " << status.peer << ": ";
  if (status.error) {
    std::cout << "denied (" << status.error->safe_detail() << ")\n";
    return;
  }
  std::cout << "granted scopes=" << status.scopes << "\n";
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
  (void)state.inbound_channel.try_send(UiState::InboundMessage{std::move(peer), envelope});
}

void push_ack_event(UiState& state, const heyaki::DeviceEndpointKey& peer,
                    const heyaki::MessageId& id, heyaki::MessageDeliveryEvent event,
                    std::optional<heyaki::Error> error) {
  (void)state.ack_channel.try_send(
      UiState::AckEvent{peer, id, event, std::move(error)});
}

void push_rpc_result(UiState& state, const heyaki::DeviceEndpointKey& peer,
                     heyaki::Result<heyaki::RpcCallOutcome> outcome) {
  (void)state.rpc_channel.try_send(UiState::RpcResult{peer, std::move(outcome)});
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
      state.drain_service_events();
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
      state.drain_service_events();
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
    state.drain_service_events();
    if (!state.rpc_results.empty()) {
      auto outcome = std::move(state.rpc_results.front());
      state.rpc_results.pop_front();
      return std::move(outcome.outcome);
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
        // Fresh view for the new call: drop stale queued results (bounded by
        // the channel capacity) and clear the display buffer.
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

// M7-07: remote event view. Topic browse/subscribe/unsubscribe, test
// publishing, and sequence/drop/lag visibility for received items.
void run_event_view(const heyaki::DeviceEndpointKey& peer, heyaki::Node& node,
                    UiState& state) {
  std::string topic = "telemetry.cpu";
  heyaki::EventQos qos = heyaki::EventQos::best_effort_latest;
  bool prefix = true;
  std::cout << "\nEVENT device=" << heyaki::to_string(peer.device_id)
            << "\ncommands [topic NAME|qos latest|live|match exact|prefix|sub|unsub|pub "
               "<text>|items|topics|exit]\n";
  bool in_view = true;
  while (in_view) {
    std::cout << "event topic=" << topic << " qos=" << heyaki::event_qos_name(qos)
              << " match=" << (prefix ? "prefix" : "exact") << "> " << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) return;
    std::istringstream input{line};
    std::string command;
    input >> command;
    if (command == "exit") {
      in_view = false;
    } else if (command == "topic") {
      input >> topic;
    } else if (command == "qos") {
      std::string which;
      input >> which;
      if (which == "live") qos = heyaki::EventQos::reliable_live;
      if (which == "latest") qos = heyaki::EventQos::best_effort_latest;
    } else if (command == "match") {
      std::string which;
      input >> which;
      if (which == "exact") prefix = false;
      if (which == "prefix") prefix = true;
    } else if (command == "sub") {
      auto subscribed = node.subscribe_events(peer, topic, prefix, qos);
      if (!subscribed) {
        std::cout << "subscribe failed: " << subscribed.error_if()->safe_detail()
                  << " (" << heyaki::error_code_name(subscribed.error_if()->code())
                  << ")\n";
      } else {
        std::cout << "subscribed topic=" << topic
                  << " qos=" << heyaki::event_qos_name(qos) << "\n";
      }
    } else if (command == "unsub") {
      const auto removed = node.unsubscribe_events(peer, topic);
      std::cout << "unsubscribed entries=" << removed << "\n";
    } else if (command == "pub") {
      std::string text;
      std::getline(input, text);
      if (!text.empty() && text.front() == ' ') text.erase(text.begin());
      std::vector<std::byte> payload;
      payload.reserve(text.size());
      for (const char value : text) {
        payload.push_back(static_cast<std::byte>(value));
      }
      auto published = node.publish_event(peer, topic, std::move(payload), 1U);
      if (!published) {
        std::cout << "publish failed: " << published.error_if()->safe_detail() << "\n";
      } else {
        std::cout << "published matched=" << *published.value_if() << "\n";
      }
    } else if (command == "items") {
      state.drain_service_events();
      if (state.event_items.empty()) {
        std::cout << "no events yet\n";
      }
      for (const auto& entry : state.event_items) {
        std::string payload;
        payload.reserve(entry.item.payload.size());
        for (const auto value : entry.item.payload) {
          payload.push_back(static_cast<char>(value));
        }
        std::cout << "event pattern=" << entry.pattern
                  << " seq=" << entry.item.publisher_sequence
                  << " schema=" << entry.item.schema_version << " qos="
                  << heyaki::event_qos_name(entry.item.qos) << " payload=\"" << payload
                  << "\"\n";
      }
      const auto diagnostics = node.service_diagnostics();
      std::cout << "stats received=" << diagnostics.event.items_received
                << " lag_events=" << diagnostics.event.lag_events
                << " lag_sequences=" << diagnostics.event.lag_total_sequences
                << " stale=" << diagnostics.event.stale_items
                << " duplicates=" << diagnostics.event.duplicate_items
                << " conflicts=" << diagnostics.event.conflicting_items
                << " overwrites=" << diagnostics.event.subscriber_overwrites
                << " drops=" << diagnostics.event.subscriber_drops << "\n";
    } else if (command == "topics") {
      std::cout << "browse: subscribe a pattern under a topic root granted to this "
                   "peer; the source checks event.subscribe:<root>\n"
                << "examples: telemetry.cpu  telemetry  chat.room1\n";
    } else {
      std::cout << "event command unknown\n";
    }
  }
}

// M7-16: file view. Logical root, push/pull, progress/throughput, pause,
// cancel, and failure visibility — never a raw remote filesystem view.
void run_file_view(const heyaki::DeviceEndpointKey& peer, heyaki::Node& node,
                   UiState& state, const std::filesystem::path& inbox_root) {
  std::cout << "\nFILE device=" << heyaki::to_string(peer.device_id)
            << " root=inbox dir=" << inbox_root.string()
            << "\ncommands [push NAME <local-path>|pull NAME|ls|events|pause "
               "<id>|resume <id>|cancel <id>|exit]\n";
  bool in_view = true;
  while (in_view) {
    std::cout << "file> " << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) return;
    std::istringstream input{line};
    std::string command;
    input >> command;
    if (command == "exit") {
      in_view = false;
    } else if (command == "push") {
      std::string name;
      std::string path_text;
      input >> name;
      std::getline(input, path_text);
      if (!path_text.empty() && path_text.front() == ' ') path_text.erase(path_text.begin());
      auto pushed = node.push_file(peer, "inbox", name, std::filesystem::path{path_text});
      if (!pushed) {
        std::cout << "push failed: " << pushed.error_if()->safe_detail()
                  << " (" << heyaki::error_code_name(pushed.error_if()->code()) << ")\n";
      } else {
        std::cout << "push started id=" << heyaki::to_string(*pushed.value_if()) << "\n";
      }
    } else if (command == "pull") {
      std::string name;
      input >> name;
      auto pulled = node.pull_file(peer, "inbox", name);
      if (!pulled) {
        std::cout << "pull failed: " << pulled.error_if()->safe_detail() << "\n";
      } else {
        std::cout << "pull started id=" << heyaki::to_string(*pulled.value_if()) << "\n";
      }
    } else if (command == "ls") {
      const auto transfers = node.file_transfers(peer);
      if (transfers.empty()) {
        std::cout << "no live transfers\n";
      }
      for (const auto& transfer : transfers) {
        const double fraction = transfer.bytes_total == 0U
                                    ? 0.0
                                    : static_cast<double>(transfer.bytes_done) /
                                          static_cast<double>(transfer.bytes_total);
        std::cout << "transfer id=" << heyaki::to_string(transfer.transfer_id)
                  << " dir=" << (transfer.direction == heyaki::FileTransferDirection::push
                                     ? "push"
                                     : "pull")
                  << " phase=" << heyaki::file_transfer_phase_name(transfer.phase)
                  << " name=" << transfer.logical_name << " bytes=" << transfer.bytes_done
                  << "/" << transfer.bytes_total << " (" << static_cast<int>(fraction * 100.0)
                  << "%)\n";
      }
      const auto diagnostics = node.service_diagnostics();
      std::cout << "stats committed=" << diagnostics.file.committed
                << " failed=" << diagnostics.file.commit_failures
                << " resumed=" << diagnostics.file.resumed_transfers
                << " chunks=" << diagnostics.file.chunks_received
                << " dup=" << diagnostics.file.duplicate_chunks
                << " conflict=" << diagnostics.file.conflicting_chunks
                << " paused=" << diagnostics.file_paused_transfers << "\n";
    } else if (command == "events") {
      state.drain_service_events();
      if (state.file_events.empty()) {
        std::cout << "no file events yet\n";
      }
      for (const auto& entry : state.file_events) {
        std::cout << "file phase="
                  << heyaki::file_transfer_phase_name(entry.event.phase)
                  << " name=" << entry.event.logical_name
                  << " bytes=" << entry.event.bytes_done << "/"
                  << entry.event.bytes_total
                  << (entry.event.error.has_value()
                          ? " error=" + std::string{entry.event.error->safe_detail()}
                          : "")
                  << "\n";
      }
    } else if (command == "pause" || command == "resume" || command == "cancel") {
      std::string id_text;
      input >> id_text;
      const auto id = heyaki::parse_transfer_id(id_text);
      if (!id) {
        std::cout << "transfer id invalid\n";
        continue;
      }
      heyaki::Result<void> outcome = heyaki::Result<void>::failure(
          heyaki::Error{heyaki::ErrorCode::internal, "tui", "no_result"});
      if (command == "pause") {
        outcome = node.pause_file_transfer(peer, *id.value);
      } else if (command == "resume") {
        outcome = node.resume_file_transfer(peer, *id.value);
      } else {
        outcome = node.cancel_file_transfer(peer, *id.value);
      }
      if (!outcome) {
        std::cout << command << " failed: " << outcome.error_if()->safe_detail() << "\n";
      } else {
        std::cout << command << " ok\n";
      }
    } else {
      std::cout << "file command unknown\n";
    }
  }
}


// M8-10/M8-11: the Shell view. Remote output is NEVER written raw to the
// host terminal: every byte passes the safe-subset VT renderer, and the view
// prints the model's lines itself (M8-08/09). Profiles offered for selection
// come from the live session grant (shell.open:<profile> / shell.open:*);
// leaving the view or losing the session closes the shell explicitly and
// waits bounded for convergence.
void run_shell_view(const heyaki::DeviceEndpointKey& peer, heyaki::Node& node,
                    UiState& state) {
  std::cout << "\nSHELL device=" << heyaki::to_string(peer.device_id) << "\n";

  // Profile selection: granted shell.open scopes on this session.
  std::vector<std::string> profiles;
  bool wildcard_shell = false;
  for (const auto& session : node.peer_sessions()) {
    if (session.peer != peer ||
        session.state != heyaki::NodePeerSessionState::authenticated) {
      continue;
    }
    for (const auto& scope : session.authorized_scopes) {
      constexpr std::string_view prefix = "shell.open:";
      if (scope == "shell.open:*") {
        wildcard_shell = true;
        continue;
      }
      if (scope.starts_with(prefix)) {
        std::string name = scope.substr(prefix.size());
        if (heyaki::safe_shell_profile_name(name) &&
            std::find(profiles.begin(), profiles.end(), name) == profiles.end()) {
          profiles.push_back(std::move(name));
        }
      }
    }
  }
  if (profiles.empty() && !wildcard_shell) {
    std::cout << "no shell.open grant on this session; pair with a wider grant first\n";
    return;
  }
  std::cout << "profiles:";
  for (const auto& name : profiles) {
    std::cout << " " << name;
  }
  if (wildcard_shell) {
    std::cout << " (wildcard grant: any server-configured profile)";
  }
  std::cout << "\ncommands [open PROFILE [COLS ROWS]|resize C R|signal "
               "int|term|hup|quit|kill|eof|close|stats|view|exit; other text -> stdin]\n";

  heyaki::SafeTerminalModel terminal;
  std::optional<heyaki::ShellId> shell_id;
  bool shell_terminal = false;
  executor::comm::PhaseGate poll{"heyaki-tui-shell-wait"};

  const auto render_output = [&]() {
    const auto lines = terminal.render_tail(20U);
    for (const auto& line : lines) {
      std::cout << "| " << line << "\n";
    }
  };
  const auto drain_events = [&]() {
    state.drain_service_events();
    while (!state.shell_events.empty()) {
      auto entry = std::move(state.shell_events.front());
      state.shell_events.pop_front();
      if (!shell_id.has_value() || entry.event.shell_id != *shell_id) {
        continue;
      }
      if (!entry.event.output.empty()) {
        terminal.feed(entry.event.output);
      }
      if (entry.event.error.has_value()) {
        std::cout << "shell error: " << entry.event.error->safe_detail();
        if (!shell_terminal) {
          std::cout << " (shell stays active)";
        }
        std::cout << "\n";
      }
      if (entry.event.phase == heyaki::ShellPhase::exited ||
          entry.event.phase == heyaki::ShellPhase::closed) {
        shell_terminal = true;
        std::cout << "shell "
                  << heyaki::shell_phase_name(entry.event.phase) << " reason="
                  << heyaki::shell_close_reason_name(entry.event.close_reason);
        if (entry.event.exit_code.has_value()) {
          std::cout << " exit=" << *entry.event.exit_code;
        }
        std::cout << " bytes in=" << entry.event.input_bytes
                  << " out=" << entry.event.output_bytes << "\n";
      }
    }
  };
  const auto settle = [&](std::uint32_t wait_ms) {
    const auto limit =
        std::chrono::steady_clock::now() + std::chrono::milliseconds{wait_ms};
    while (std::chrono::steady_clock::now() < limit) {
      drain_events();
      (void)poll.wait_for(1U, std::chrono::milliseconds{20});
    }
    drain_events();
  };

  bool in_view = true;
  while (in_view) {
    std::cout << "shell> " << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) {
      in_view = false;
      break;
    }
    std::istringstream input{line};
    std::string command;
    input >> command;
    if (command == "exit") {
      in_view = false;
    } else if (command == "open") {
      if (shell_id.has_value() && !shell_terminal) {
        std::cout << "shell already open\n";
        continue;
      }
      std::string profile;
      input >> profile;
      heyaki::ShellOpenOptions options;
      std::uint32_t columns = 0U;
      std::uint32_t rows = 0U;
      input >> columns >> rows;
      if (columns > 0U && rows > 0U) {
        options.columns = columns;
        options.rows = rows;
      }
      auto opened = node.open_shell(peer, profile, options);
      if (!opened) {
        std::cout << "open failed: " << opened.error_if()->safe_detail() << " ("
                  << heyaki::error_code_name(opened.error_if()->code()) << ")\n";
        continue;
      }
      shell_id = *opened.value_if();
      shell_terminal = false;
      terminal.~SafeTerminalModel();
      new (&terminal) heyaki::SafeTerminalModel{};
      if (columns > 0U && rows > 0U) {
        terminal.resize(columns, rows);
      }
      std::cout << "opening shell id=" << heyaki::to_string(*shell_id) << "\n";
      settle(400U);
    } else if (command == "resize") {
      if (!shell_id.has_value() || shell_terminal) {
        std::cout << "no open shell\n";
        continue;
      }
      std::uint32_t columns = 0U;
      std::uint32_t rows = 0U;
      input >> columns >> rows;
      auto resized = node.shell_resize(peer, *shell_id, columns, rows);
      std::cout << (resized ? "resize sent" : "resize failed") << "\n";
      if (resized) {
        terminal.resize(columns, rows);
      }
    } else if (command == "signal") {
      if (!shell_id.has_value() || shell_terminal) {
        std::cout << "no open shell\n";
        continue;
      }
      std::string name;
      input >> name;
      heyaki::ShellPortableSignal signal = heyaki::ShellPortableSignal::interrupt;
      if (name == "term") {
        signal = heyaki::ShellPortableSignal::terminate;
      } else if (name == "hup") {
        signal = heyaki::ShellPortableSignal::hangup;
      } else if (name == "quit") {
        signal = heyaki::ShellPortableSignal::quit;
      } else if (name == "kill") {
        signal = heyaki::ShellPortableSignal::kill;
      } else if (name != "int") {
        std::cout << "signal unknown (int|term|hup|quit|kill)\n";
        continue;
      }
      auto signalled = node.shell_signal(peer, *shell_id, signal);
      std::cout << (signalled ? "signal sent" : "signal failed") << "\n";
      settle(400U);
    } else if (command == "eof") {
      if (!shell_id.has_value() || shell_terminal) {
        std::cout << "no open shell\n";
        continue;
      }
      auto closed = node.shell_send_eof(peer, *shell_id);
      std::cout << (closed ? "eof sent" : "eof failed") << "\n";
      settle(400U);
    } else if (command == "close") {
      if (!shell_id.has_value() || shell_terminal) {
        std::cout << "no open shell\n";
        continue;
      }
      (void)node.close_shell(peer, *shell_id);
      settle(1000U);
      render_output();
    } else if (command == "stats") {
      const auto diagnostics = node.service_diagnostics();
      std::cout << "shell stats opens_sent=" << diagnostics.shell.opens_sent
                << " outputs=" << diagnostics.shell.outputs_received
                << " output_bytes=" << diagnostics.shell.output_bytes_received
                << " errors=" << diagnostics.shell.errors_received << "\n";
      const auto& model = terminal.stats();
      std::cout << "terminal fed=" << model.bytes_fed
                << " osc_dropped=" << model.osc_dropped
                << " csi_dropped=" << model.csi_dropped
                << " sgr_degraded=" << model.sgr_degraded
                << " invalid_utf8=" << model.invalid_utf8_replaced << "\n";
    } else if (command == "view") {
      drain_events();
      render_output();
    } else if (command.empty()) {
      drain_events();
    } else if (shell_id.has_value() && !shell_terminal) {
      // Any other text becomes stdin plus a newline.
      std::string payload = line;
      payload.push_back('\n');
      std::vector<std::byte> bytes;
      bytes.reserve(payload.size());
      for (const char character : payload) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
      }
      auto sent = node.shell_send_input(peer, *shell_id, bytes);
      if (!sent) {
        std::cout << "input failed: " << sent.error_if()->safe_detail() << "\n";
      }
      settle(400U);
      render_output();
    } else {
      std::cout << "open a shell first: open <profile>\n";
    }
  }

  // M8-11: leaving the view closes an open shell explicitly and waits
  // bounded for the executor-managed operation to converge.
  if (shell_id.has_value() && !shell_terminal) {
    (void)node.close_shell(peer, *shell_id);
    settle(2000U);
  }
}

// M7-16: the TUI's logical "inbox" root lives beside the profile store
// (XDG state), one directory per profile.
std::filesystem::path file_inbox_root(std::string_view profile_name) {
  auto root = heyaki::ProfileStore::default_profiles_root();
  const auto base = root ? *root.value_if() : std::filesystem::temp_directory_path();
  return base.parent_path() / "files" / std::string{profile_name} / "inbox";
}

void run_command(std::string line, heyaki::Node& node, UiState& state, bool& running,
                 const std::filesystem::path& file_inbox) {
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
      (void)state.pairing.try_publish(UiState::PairingStatus{
          "endpoint-" + std::to_string(peer_index), std::nullopt, {}});
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
  if (command == "event") {
    // M7-07: remote event view (topics, subscribe/publish, sequence/drop/lag).
    run_event_view(*peer, node, state);
    state.command_status = "event-view-closed";
    state.command_error.reset();
    return;
  }
  if (command == "file") {
    // M7-16: file view (logical root, push/pull, progress, pause/cancel).
    run_file_view(*peer, node, state, file_inbox);
    state.command_status = "file-view-closed";
    state.command_error.reset();
    return;
  }
  if (command == "shell") {
    // M8-10: shell view (profile selection, stdin, resize/signal/EOF/close,
    // safe VT rendering, exit status).
    run_shell_view(*peer, node, state);
    state.command_status = "shell-view-closed";
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
  const auto file_inbox = file_inbox_root(options.profile_name);
  std::error_code inbox_ec;
  std::filesystem::create_directories(file_inbox, inbox_ec);
  auto make_node = [&]() {
    heyaki::FileRootConfig inbox_root;
    inbox_root.name = "inbox";
    inbox_root.directory = file_inbox;
    return heyaki::Node::create(
        heyaki::NodeConfig{.profile = &*profile,
                           .runtime = nullptr,
                           .application_id = std::string{application_id},
                           .lan_override = std::nullopt,
                           .runtime_config = heyaki::RuntimeConfig{},
                           .signaling_validator = {},
                           .signaling_handler = {},
                           .relay_override = std::nullopt,
                           .path_policy_override = std::nullopt,
                           .file_receive_roots = {inbox_root},
                           .shell_profiles = {}});
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
    UiState::PairingStatus status;
    status.peer = heyaki::to_string(peer.device_id);
    if (outcome) {
      for (const auto& scope : *outcome.value_if()) {
        status.scopes += scope;
        status.scopes += " ";
      }
    } else {
      status.error = *outcome.error_if();
    }
    (void)state.pairing.try_publish(std::move(status));
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
  // M7: remote events and file transfer lifecycle feed the views through the
  // same bounded channels (drop-oldest, observable via comm stats).
  node->set_event_inbound_handler([&state](const heyaki::DeviceEndpointKey& peer,
                                           std::string_view pattern,
                                           const heyaki::EventItemBody& item) {
    UiState::EventItemView view;
    view.peer = peer;
    view.pattern = std::string{pattern};
    view.item = item;
    (void)state.event_channel.try_send(std::move(view));
  });
  node->set_file_event_observer(
      [&state](const heyaki::DeviceEndpointKey& peer, const heyaki::FileTransferEvent& event) {
        (void)state.file_channel.try_send(UiState::FileEventView{peer, event});
      });
  // M8: shell lifecycle and output feed the shell view's bounded channel;
  // raw terminal bytes are only ever consumed by the safe VT renderer.
  node->set_shell_event_observer(
      [&state](const heyaki::DeviceEndpointKey& peer, const heyaki::ShellServiceEvent& event) {
        (void)state.shell_channel.try_send(UiState::ShellEventView{peer, event});
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
                 "msg N|rpc N|file N|event N|shell N|quit]> "
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
    run_command(std::move(line), *node, state, running, file_inbox);
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
