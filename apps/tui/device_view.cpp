#include "device_view.hpp"

#include <heyaki/identity.hpp>

#include <ostream>

namespace heyaki::tui {
namespace {

const char* endpoint_source(const EndpointDirectoryEntrySnapshot& endpoint) noexcept {
  if (endpoint.lan && endpoint.relay) return "lan+relay";
  if (endpoint.lan) return "lan";
  if (endpoint.relay) return "relay";
  return "none";
}

void render_error(std::ostream& output, const Error& error) {
  output << error_code_name(error.code()) << ' ' << error.component() << ' '
         << error.safe_detail();
  if (error.underlying_code()) {
    output << " underlying=" << *error.underlying_code();
  }
  if (error.peer_id()) {
    output << " peer=" << to_string(*error.peer_id());
  }
  if (error.operation_id()) {
    output << " operation=" << to_string(*error.operation_id());
  }
}

}  // namespace

void render_device_view(
    std::ostream& output,
    const std::vector<EndpointDirectoryEntrySnapshot>& endpoints,
    const std::vector<NodePeerSessionSnapshot>& sessions) {
  output << "\nENDPOINTS\n";
  if (endpoints.empty()) output << "  none\n";
  for (std::size_t index = 0U; index < endpoints.size(); ++index) {
    const auto& endpoint = endpoints[index];
    output << "  [" << index + 1U << "] "
           << (endpoint.trusted ? "trusted" : "pairing-restricted")
           << "\n      device=" << to_string(endpoint.key.device_id)
           << "\n      endpoint=" << to_string(endpoint.key.endpoint_id)
           << "\n      discovery=" << endpoint_source(endpoint) << '\n';
  }

  output << "\nSESSIONS\n";
  if (sessions.empty()) output << "  none\n";
  for (std::size_t index = 0U; index < sessions.size(); ++index) {
    const auto& session = sessions[index];
    output << "  [" << index + 1U << "] "
           << node_peer_session_state_name(session.state)
           << "  stage=" << node_connection_stage_name(session.connection_stage)
           << "\n      device=" << to_string(session.peer.device_id)
           << "\n      endpoint=" << to_string(session.peer.endpoint_id)
           << "\n      signaling="
           << signaling_route_kind_name(session.signaling_route)
           << "  data=" << node_data_path_kind_name(session.data_path)
           << "  rtt=" << session.rtt.count() << "ms"
           << "  buffered=" << session.buffered_amount << '\n'
           << "      candidate="
           << (session.selected_candidate.empty() ? "none"
                                                  : session.selected_candidate)
           << '\n';
    if (session.error) {
      output << "      failure=";
      render_error(output, *session.error);
      output << '\n';
    }
  }
}

}  // namespace heyaki::tui
