// Prometheus text-format export of NodeMetrics (M9-01). Pure serialization:
// every value comes from the already-published diagnostics surfaces, so this
// file never touches locks, strands, or executor state. Counters carry the
// `_total` suffix per the exposition format; enums and booleans map to
// numeric gauges via their underlying integer values.

#include <heyaki/metrics.hpp>

#include <algorithm>
#include <string>
#include <string_view>

namespace heyaki {
namespace {

void escape_label_value(std::string& out, std::string_view value) {
  for (const char character : value) {
    switch (character) {
      case '\\':
        out.append("\\\\");
        break;
      case '"':
        out.append("\\\"");
        break;
      case '\n':
        out.append("\\n");
        break;
      default:
        out.push_back(character);
        break;
    }
  }
}

class MetricsWriter {
 public:
  explicit MetricsWriter(std::string_view instance) {
    if (!instance.empty()) {
      label_ = R"({instance=")";
      escape_label_value(label_, instance);
      label_.push_back('"');
      label_.push_back('}');
    }
  }

  void counter(std::string_view name, std::uint64_t value,
               std::string_view help) {
    family(name, "counter", help);
    sample(name, value);
  }

  void gauge(std::string_view name, std::uint64_t value, std::string_view help) {
    family(name, "gauge", help);
    sample(name, value);
  }

  const std::string& output() const noexcept { return output_; }

 private:
  void family(std::string_view name, std::string_view type,
              std::string_view help) {
    output_.append("# HELP ");
    output_.append(name);
    output_.push_back(' ');
    output_.append(help);
    output_.push_back('\n');
    output_.append("# TYPE ");
    output_.append(name);
    output_.push_back(' ');
    output_.append(type);
    output_.push_back('\n');
  }

  void sample(std::string_view name, std::uint64_t value) {
    output_.append(name);
    output_.append(label_);
    output_.push_back(' ');
    output_.append(std::to_string(value));
    output_.push_back('\n');
  }

  std::string output_;
  std::string label_;
};

void write_node_section(MetricsWriter& writer, const NodeSnapshot& node) {
  writer.gauge("heyaki_node_local_initialized", node.local_initialized ? 1U : 0U,
               "1 when the local profile is initialized.");
  writer.gauge("heyaki_node_lan_enabled", node.lan_enabled ? 1U : 0U,
               "1 when LAN discovery is enabled.");
  writer.gauge("heyaki_node_discoverable", node.discoverable ? 1U : 0U,
               "1 when the endpoint announces itself on the LAN.");
  writer.gauge("heyaki_node_lan_state", static_cast<std::uint64_t>(node.lan_state),
               "LanReadinessState enum value.");
  writer.gauge("heyaki_node_interfaces", node.interfaces.size(),
               "Tracked network interfaces.");
  std::uint64_t joined = 0U;
  std::uint64_t multicast_verified = 0U;
  for (const auto& interface : node.interfaces) {
    joined += interface.joined ? 1U : 0U;
    multicast_verified += interface.multicast_verified ? 1U : 0U;
  }
  writer.gauge("heyaki_node_interfaces_joined", joined,
               "Interfaces joined to the multicast group.");
  writer.gauge("heyaki_node_interfaces_multicast_verified", multicast_verified,
               "Interfaces with a verified multicast loopback.");

  writer.counter("heyaki_node_announcements_sent_total", node.announcements_sent,
                 "LAN presence announcements sent.");
  writer.counter("heyaki_node_datagrams_received_total", node.datagrams_received,
                 "LAN discovery datagrams received.");
  writer.counter("heyaki_node_datagrams_rejected_total", node.datagrams_rejected,
                 "LAN discovery datagrams rejected before parsing effects.");

  const auto& tls = node.tls;
  writer.gauge("heyaki_node_tls_listener_ready", tls.listener_ready ? 1U : 0U,
               "1 when the LAN TLS listener accepts connections.");
  writer.gauge("heyaki_node_tls_listen_port", tls.listen_port,
               "LAN TLS listener port (0 when closed).");
  writer.gauge("heyaki_node_tls_provisional_connections",
               tls.provisional_connections,
               "Provisional (pre-hello) LAN TLS connections.");
  writer.gauge("heyaki_node_tls_authenticated_connections",
               tls.authenticated_connections, "Authenticated LAN TLS connections.");
  writer.counter("heyaki_node_tls_accepted_total", tls.accepted,
                 "LAN TLS connections accepted.");
  writer.counter("heyaki_node_tls_rejected_total", tls.rejected,
                 "LAN TLS connections rejected.");
  writer.counter("heyaki_node_tls_capacity_rejected_total",
                 tls.capacity_rejected, "LAN TLS rejections from capacity.");
  writer.counter("heyaki_node_tls_rate_limited_total", tls.rate_limited,
                 "LAN TLS rejections from per-source rate limiting.");
  writer.counter("heyaki_node_tls_timed_out_total", tls.timed_out,
                 "LAN TLS handshakes that timed out.");
  writer.counter("heyaki_node_tls_handshake_failed_total", tls.handshake_failed,
                 "LAN TLS handshakes that failed.");
  writer.counter("heyaki_node_tls_hello_rejected_total", tls.hello_rejected,
                 "LAN HELLO messages rejected.");

  const auto& directory = node.directory;
  writer.counter("heyaki_node_directory_accepted_total", directory.accepted,
                 "Presence records accepted.");
  writer.counter("heyaki_node_directory_updated_total", directory.updated,
                 "Presence records updated.");
  writer.counter("heyaki_node_directory_duplicate_total", directory.duplicate,
                 "Duplicate presence records.");
  writer.counter("heyaki_node_directory_replay_rejected_total",
                 directory.replay_rejected, "Presence records rejected as replay.");
  writer.counter("heyaki_node_directory_conflict_rejected_total",
                 directory.conflict_rejected,
                 "Presence records rejected on identity conflict.");
  writer.counter("heyaki_node_directory_capacity_rejected_total",
                 directory.capacity_rejected,
                 "Presence records rejected from directory capacity.");
  writer.counter("heyaki_node_directory_rate_rejected_total",
                 directory.rate_rejected,
                 "Presence records rejected from per-source rate limiting.");
  writer.counter("heyaki_node_directory_expired_total", directory.expired,
                 "Presence records expired.");
  writer.gauge("heyaki_node_directory_entries", directory.current_entries,
               "Live endpoint directory entries.");
  writer.gauge("heyaki_node_directory_peak_entries", directory.peak_entries,
               "Peak endpoint directory entries.");
  writer.gauge("heyaki_node_directory_replay_entries",
               directory.replay_entries, "Replay-guard table entries.");
  writer.gauge("heyaki_node_directory_source_rate_entries",
               directory.source_rate_entries, "Per-source rate table entries.");

  const auto& relay = node.relay;
  writer.gauge("heyaki_node_relay_enabled", relay.enabled ? 1U : 0U,
               "1 when the relay control connection is configured.");
  writer.gauge("heyaki_node_relay_state", static_cast<std::uint64_t>(relay.state),
               "RelayNodeState enum value.");
  writer.counter("heyaki_node_relay_enrollment_generation",
                 relay.enrollment_generation,
                 "Enrollment generation in use (gauge semantics).");
  writer.counter("heyaki_node_relay_lease_generation", relay.lease_generation,
                 "Endpoint lease generation (gauge semantics).");
  writer.counter("heyaki_node_relay_registration_attempts_total",
                 relay.registration_attempts,
                 "Relay WSS connect + login cycles started.");
  writer.counter("heyaki_node_relay_registration_successes_total",
                 relay.registration_successes,
                 "Relay login cycles that reached ready.");
  writer.counter("heyaki_node_relay_registration_failures_total",
                 relay.registration_failures,
                 "Relay login cycles that ended before ready.");
  writer.counter("heyaki_node_relay_lease_refresh_failures_total",
                 relay.lease_refresh_failures,
                 "Heartbeat rounds whose lease ack was still missing at the next tick.");
  writer.counter("heyaki_node_relay_heartbeats_sent_total",
                 relay.heartbeats_sent, "Relay heartbeats sent.");
  writer.counter("heyaki_node_relay_heartbeats_missed_total",
                 relay.heartbeats_missed, "Relay heartbeats missed.");
  writer.counter("heyaki_node_relay_reconnects_total", relay.reconnect_count,
                 "Relay WSS reconnect attempts.");
  writer.gauge("heyaki_node_relay_backoff_milliseconds",
               static_cast<std::uint64_t>(relay.backoff.count()),
               "Current relay reconnect backoff.");

  const auto& coordinator = node.session_coordinator;
  writer.counter("heyaki_node_session_coordinator_replay_rejected_total",
                 coordinator.replay_rejected,
                 "Signaling objects rejected as replay.");
  writer.counter("heyaki_node_session_coordinator_attempts_expired_total",
                 coordinator.attempts_expired,
                 "Connection attempts expired before completion.");
  writer.counter("heyaki_node_session_coordinator_attempts_closed_total",
                 coordinator.attempts_closed, "Connection attempts closed.");
  writer.gauge("heyaki_node_session_coordinator_attempts",
               coordinator.current_attempts, "Live connection attempts.");
  writer.gauge("heyaki_node_session_coordinator_peak_attempts",
               coordinator.peak_attempts, "Peak connection attempts.");
  writer.gauge("heyaki_node_session_coordinator_replay_entries",
               coordinator.replay_current_entries,
               "Live replay-guard entries.");
  writer.gauge("heyaki_node_session_coordinator_peak_replay_entries",
               coordinator.replay_peak_entries, "Peak replay-guard entries.");

  const auto& restarts = node.session_restarts;
  writer.counter("heyaki_node_session_restarts_initiated_total",
                 restarts.restarts_initiated,
                 "Protocol-1.2 session restarts initiated.");
  writer.counter("heyaki_node_session_restarts_completed_total",
                 restarts.restarts_completed, "Session restarts completed.");
  writer.counter("heyaki_node_session_restarts_failed_total",
                 restarts.restarts_failed, "Session restarts failed.");
  writer.counter("heyaki_node_session_restarts_suppressed_total",
                 restarts.restarts_suppressed, "Session restarts suppressed.");
  writer.gauge("heyaki_node_session_restarts_in_flight",
               restarts.current_restarts, "In-flight session restarts.");
  writer.gauge("heyaki_node_session_restarts_peak",
               restarts.peak_restarts, "Peak concurrent session restarts.");

  const auto& resources = node.resources;
  writer.gauge("heyaki_node_resources_discovery_sockets",
               resources.discovery_sockets, "Open discovery sockets.");
  writer.gauge("heyaki_node_resources_peak_discovery_sockets",
               resources.peak_discovery_sockets, "Peak discovery sockets.");
  writer.gauge("heyaki_node_resources_tls_listener_open",
               resources.tls_listener_open ? 1U : 0U,
               "1 while the LAN TLS listener is open.");
  writer.gauge("heyaki_node_resources_active_timers", resources.active_timers,
               "Active LAN timers.");
  writer.gauge("heyaki_node_resources_peak_active_timers",
               resources.peak_active_timers, "Peak LAN timers.");
  writer.gauge("heyaki_node_resources_signaling_connections",
               resources.signaling_connections, "Live LAN signaling connections.");
  writer.gauge("heyaki_node_resources_peak_signaling_connections",
               resources.peak_signaling_connections,
               "Peak LAN signaling connections.");
  writer.gauge("heyaki_node_resources_signaling_callbacks_in_flight",
               resources.signaling_callbacks_in_flight,
               "In-flight signaling callbacks.");
  writer.gauge("heyaki_node_resources_signaling_command_depth",
               resources.signaling_command_depth,
               "Signaling command channel depth.");
  writer.gauge("heyaki_node_resources_signaling_command_peak_depth",
               resources.signaling_command_peak_depth,
               "Signaling command channel peak depth.");
  writer.gauge("heyaki_node_resources_signaling_result_depth",
               resources.signaling_result_depth, "Signaling result channel depth.");
  writer.gauge("heyaki_node_resources_signaling_result_peak_depth",
               resources.signaling_result_peak_depth,
               "Signaling result channel peak depth.");
  writer.gauge("heyaki_node_resources_pending_outbound_messages",
               resources.pending_outbound_messages,
               "Outbound LAN messages waiting for send.");
}

void write_pairing_section(MetricsWriter& writer,
                           const NodePairingMetrics& pairing) {
  writer.counter("heyaki_pairing_attempts_total", pairing.attempts,
                 "Pairing attempts evaluated.");
  writer.counter("heyaki_pairing_granted_total", pairing.granted,
                 "Pairing attempts that issued a TrustGrant.");
  writer.counter("heyaki_pairing_denied_password_total",
                 pairing.denied_password, "Pairing attempts denied by password.");
  writer.counter("heyaki_pairing_denied_policy_total",
                 pairing.denied_policy, "Pairing attempts denied by policy.");
  writer.counter("heyaki_pairing_denied_backoff_total",
                 pairing.denied_backoff,
                 "Pairing attempts denied by failure backoff.");
  writer.counter("heyaki_pairing_grant_accepted_total",
                 pairing.grant_accepted, "Received grants accepted.");
  writer.counter("heyaki_pairing_grant_rejected_total",
                 pairing.grant_rejected, "Received grants rejected.");
  writer.counter("heyaki_pairing_grant_revoked_total",
                 pairing.grant_revoked, "Issued grants revoked.");
  writer.counter("heyaki_pairing_password_rotated_total",
                 pairing.password_rotated, "Password rotations.");
  writer.counter("heyaki_pairing_grants_revoked_total",
                 pairing.grants_revoked,
                 "Bulk grant revocations (rotate-and-revoke).");
}

void write_connectivity_section(MetricsWriter& writer,
                                const NodeConnectivityMetrics& connectivity) {
  writer.counter("heyaki_connectivity_initiated_total",
                 connectivity.connections_initiated,
                 "Connection attempts admitted (both directions).");
  writer.counter("heyaki_connectivity_authenticated_total",
                 connectivity.sessions_authenticated,
                 "Sessions that reached authenticated.");
  writer.counter("heyaki_connectivity_pairing_restricted_total",
                 connectivity.sessions_pairing_restricted,
                 "Sessions that entered pairing-restricted state.");
  writer.counter("heyaki_connectivity_failures_total",
                 connectivity.connection_failures,
                 "Connection attempts that failed before authenticating.");
  writer.counter("heyaki_connectivity_superseded_total",
                 connectivity.sessions_superseded,
                 "Sessions closed because a restart successor superseded them.");
  writer.counter("heyaki_connectivity_signaling_route_selected_lan_total",
                 connectivity.signaling_route_selected_lan,
                 "Admitted attempts that selected LAN signaling.");
  writer.counter("heyaki_connectivity_signaling_route_selected_relay_total",
                 connectivity.signaling_route_selected_relay,
                 "Admitted attempts that selected relay signaling.");
  writer.counter("heyaki_connectivity_signaling_route_fallbacks_total",
                 connectivity.signaling_route_fallbacks,
                 "Automatic-mode relay selections made because no LAN endpoint was reachable.");
  writer.counter("heyaki_connectivity_signaling_route_lan_total",
                 connectivity.signaling_route_lan,
                 "Authenticated sessions signaled over LAN TLS.");
  writer.counter("heyaki_connectivity_signaling_route_relay_total",
                 connectivity.signaling_route_relay,
                 "Authenticated sessions signaled over the relay.");
  writer.counter("heyaki_connectivity_data_path_unknown_total",
                 connectivity.data_path_unknown,
                 "Authenticated sessions with an unknown data path.");
  writer.counter("heyaki_connectivity_data_path_direct_host_total",
                 connectivity.data_path_direct_host,
                 "Authenticated sessions on direct host candidates.");
  writer.counter("heyaki_connectivity_data_path_direct_srflx_total",
                 connectivity.data_path_direct_srflx,
                 "Authenticated sessions on server-reflexive candidates.");
  writer.counter("heyaki_connectivity_data_path_turn_udp_total",
                 connectivity.data_path_turn_udp,
                 "Authenticated sessions relayed over TURN/UDP.");
  writer.counter("heyaki_connectivity_data_path_turn_tcp_total",
                 connectivity.data_path_turn_tcp,
                 "Authenticated sessions relayed over TURN/TCP.");
  writer.counter("heyaki_connectivity_data_path_turn_tls_total",
                 connectivity.data_path_turn_tls,
                 "Authenticated sessions relayed over TURN/TLS.");
  writer.counter("heyaki_connectivity_connect_duration_samples",
                 connectivity.connect_duration_samples,
                 "Samples of connect-to-authenticated duration.");
  writer.counter("heyaki_connectivity_connect_duration_milliseconds_sum",
                 connectivity.connect_duration_milliseconds_sum,
                 "Sum of connect-to-authenticated durations.");
  writer.gauge("heyaki_connectivity_connect_duration_milliseconds_max",
               connectivity.connect_duration_milliseconds_max,
               "Maximum connect-to-authenticated duration.");
}

void write_transport_section(MetricsWriter& writer,
                             const NodeTransportGauges& transport) {
  writer.gauge("heyaki_transport_peer_sessions", transport.peer_sessions,
               "Live peer sessions.");
  writer.gauge("heyaki_transport_authenticated_sessions",
               transport.authenticated_sessions, "Authenticated peer sessions.");
  writer.gauge("heyaki_transport_pairing_restricted_sessions",
               transport.pairing_restricted_sessions,
               "Pairing-restricted peer sessions.");
  writer.gauge("heyaki_transport_rtt_samples", transport.rtt_samples,
               "Peer sessions reporting an RTT.");
  writer.gauge("heyaki_transport_rtt_milliseconds_sum",
               transport.rtt_milliseconds_sum, "Sum of reported peer RTTs.");
  writer.gauge("heyaki_transport_rtt_milliseconds_max",
               transport.rtt_milliseconds_max, "Maximum reported peer RTT.");
  writer.gauge("heyaki_transport_buffered_amount_bytes",
               transport.buffered_amount_sum,
               "Sum of per-session transport send buffers.");
  // Gauge semantics: per-association backend counters summed over live
  // sessions, so the sum shrinks when a long-lived session closes.
  writer.gauge("heyaki_transport_backend_bytes_sent",
               transport.transport_bytes_sent_sum,
               "Backend-level bytes sent, summed over live peer sessions.");
  writer.gauge("heyaki_transport_backend_bytes_received",
               transport.transport_bytes_received_sum,
               "Backend-level bytes received, summed over live peer sessions.");
}

void write_channel_section(MetricsWriter& writer,
                           const NodeChannelMetrics& channels) {
  writer.gauge("heyaki_channel_channels", channels.channels,
               "Open business channels across sessions.");
  writer.gauge("heyaki_channel_queued_frames", channels.queued_frames,
               "Frames waiting in channel queues.");
  writer.gauge("heyaki_channel_queued_bytes", channels.queued_bytes,
               "Bytes waiting in channel queues.");
  writer.counter("heyaki_channel_sent_frames_total", channels.sent_frames,
                 "Frames handed to the transport.");
  writer.counter("heyaki_channel_sent_bytes_total", channels.sent_bytes,
                 "Bytes handed to the transport.");
  writer.counter("heyaki_channel_dropped_frames_total", channels.dropped_frames,
                 "Frames dropped by queue policy.");
  writer.counter("heyaki_channel_dropped_bytes_total", channels.dropped_bytes,
                 "Bytes dropped by queue policy.");
  writer.counter("heyaki_channel_rejected_frames_total",
                 channels.rejected_frames,
                 "Frames rejected at admission (queue full, closed).");
  writer.counter("heyaki_channel_capacity_waits_total",
                 channels.capacity_waits_completed,
                 "Sends that waited for queue capacity and completed.");
}

void write_message_section(MetricsWriter& writer,
                           const MessageServiceStats& message) {
  writer.counter("heyaki_message_sent_best_effort_total",
                 message.sent_best_effort, "Best-effort messages sent.");
  writer.counter("heyaki_message_sent_peer_acked_total",
                 message.sent_peer_acked, "Ack-tracked messages sent.");
  writer.counter("heyaki_message_send_rejected_total", message.send_rejected,
                 "Message sends rejected at admission.");
  writer.counter("heyaki_message_acked_total", message.acked,
                 "Messages acknowledged by the peer.");
  writer.counter("heyaki_message_ack_rejected_total", message.ack_rejected,
                 "Messages rejected by the peer.");
  writer.counter("heyaki_message_ack_timed_out_total", message.ack_timed_out,
                 "Messages whose ack timed out.");
  writer.counter("heyaki_message_unknown_acks_total", message.unknown_acks,
                 "Acks that matched no pending message.");
  writer.counter("heyaki_message_acks_on_closed_total", message.acks_on_closed,
                 "Acks arriving after session close.");
  writer.counter("heyaki_message_received_total", message.received,
                 "Messages received.");
  writer.counter("heyaki_message_invalid_envelopes_total",
                 message.invalid_envelopes, "Invalid message envelopes.");
  writer.counter("heyaki_message_duplicates_total", message.duplicates,
                 "Duplicate messages deduplicated.");
  writer.counter("heyaki_message_dedup_expired_total", message.dedup_expired,
                 "Dedup windows that expired.");
  writer.counter("heyaki_message_dedup_evictions_total", message.dedup_evictions,
                 "Dedup entries evicted for capacity.");
  writer.counter("heyaki_message_scope_rejected_total", message.scope_rejected,
                 "Inbound messages rejected by scope.");
  writer.counter("heyaki_message_acks_sent_total", message.acks_sent,
                 "Acks sent to peers.");
  writer.counter("heyaki_message_ack_send_failures_total",
                 message.ack_send_failures, "Ack sends that failed.");
  writer.counter("heyaki_message_dispatched_total", message.dispatched,
                 "Inbound messages dispatched to handlers.");
  writer.counter("heyaki_message_dispatch_rejected_total",
                 message.dispatch_rejected,
                 "Inbound messages the handler rejected.");
  writer.counter("heyaki_message_handler_completed_total",
                 message.handler_completed, "Handler runs completed.");
  writer.counter("heyaki_message_handler_exceptions_total",
                 message.handler_exceptions, "Handler runs that threw.");
}

void write_rpc_section(MetricsWriter& writer, const RpcServiceStats& rpc) {
  writer.counter("heyaki_rpc_calls_started_total", rpc.calls_started,
                 "RPC calls started.");
  writer.counter("heyaki_rpc_calls_admission_rejected_total",
                 rpc.calls_admission_rejected,
                 "RPC calls rejected at executor admission.");
  writer.counter("heyaki_rpc_responses_matched_total", rpc.responses_matched,
                 "Responses matched to pending calls.");
  writer.counter("heyaki_rpc_responses_unknown_total", rpc.responses_unknown,
                 "Responses that matched no pending call.");
  writer.counter("heyaki_rpc_cancels_sent_total", rpc.cancels_sent,
                 "RPC cancels sent.");
  writer.counter("heyaki_rpc_local_deadline_exceeded_total",
                 rpc.local_deadline_exceeded, "RPC calls that hit their local deadline.");
  writer.counter("heyaki_rpc_outcome_unknown_total", rpc.outcome_unknown_calls,
                 "Non-idempotent calls ending outcome_unknown.");
  writer.counter("heyaki_rpc_retryable_handled_total", rpc.retryable_handled,
                 "Retryable failures handled by the retry queue.");
  writer.counter("heyaki_rpc_requests_received_total", rpc.requests_received,
                 "RPC requests received.");
  writer.counter("heyaki_rpc_invalid_requests_total", rpc.invalid_requests,
                 "Invalid RPC requests.");
  writer.counter("heyaki_rpc_duplicate_requests_total", rpc.duplicate_requests,
                 "Duplicate RPC requests answered from cache.");
  writer.counter("heyaki_rpc_conflicting_requests_total",
                 rpc.conflicting_requests, "Conflicting RPC requests.");
  writer.counter("heyaki_rpc_replayed_responses_total", rpc.replayed_responses,
                 "Cached RPC responses replayed.");
  writer.counter("heyaki_rpc_scope_rejected_total", rpc.scope_rejected,
                 "RPC requests rejected by scope.");
  writer.counter("heyaki_rpc_unimplemented_answers_total",
                 rpc.unimplemented_answers, "RPC requests for unknown methods.");
  writer.counter("heyaki_rpc_schema_rejected_total", rpc.schema_rejected,
                 "RPC requests rejected by schema.");
  writer.counter("heyaki_rpc_oversized_rejected_total", rpc.oversized_rejected,
                 "RPC requests rejected for size.");
  writer.counter("heyaki_rpc_concurrency_rejected_total",
                 rpc.concurrency_rejected,
                 "RPC requests rejected by concurrency limits.");
  writer.counter("heyaki_rpc_deadline_rejected_total", rpc.deadline_rejected,
                 "RPC requests whose deadline already passed.");
  writer.counter("heyaki_rpc_dispatch_rejected_total", rpc.dispatch_rejected,
                 "RPC requests the server handler rejected.");
  writer.counter("heyaki_rpc_handlers_executed_total", rpc.handlers_executed,
                 "Server RPC handler executions.");
  writer.counter("heyaki_rpc_handler_exceptions_total", rpc.handler_exceptions,
                 "Server RPC handler exceptions.");
  writer.counter("heyaki_rpc_handler_cancelled_total", rpc.handler_cancelled,
                 "Server RPC handler cancellations.");
  writer.counter("heyaki_rpc_handler_deadline_exceeded_total",
                 rpc.handler_deadline_exceeded,
                 "Server RPC handlers that hit their deadline.");
  writer.counter("heyaki_rpc_late_results_dropped_total",
                 rpc.late_results_dropped, "Results arriving after cancellation.");
  writer.counter("heyaki_rpc_responses_sent_total", rpc.responses_sent,
                 "RPC responses sent.");
  writer.counter("heyaki_rpc_response_send_failures_total",
                 rpc.response_send_failures, "RPC response sends that failed.");
}

void write_event_section(MetricsWriter& writer, const EventServiceStats& event) {
  writer.counter("heyaki_event_published_total", event.published,
                 "Publish calls with at least one match.");
  writer.counter("heyaki_event_published_items_total", event.published_items,
                 "Event items matched to subscriptions.");
  writer.counter("heyaki_event_subscriber_overwrites_total",
                 event.subscriber_overwrites,
                 "Latest-mailbox items replaced before delivery.");
  writer.counter("heyaki_event_subscriber_drops_total", event.subscriber_drops,
                 "Latest-mailbox items dropped at a full channel.");
  writer.counter("heyaki_event_subscriber_overflows_total",
                 event.subscriber_overflows,
                 "Reliable queue overflows that terminated a subscription.");
  writer.counter("heyaki_event_items_sent_total", event.items_sent,
                 "Event items sent to subscribers.");
  writer.counter("heyaki_event_item_send_failures_total",
                 event.item_send_failures, "Event item sends that failed.");
  writer.counter("heyaki_event_subscriptions_accepted_total",
                 event.subscriptions_accepted, "Subscriptions accepted.");
  writer.counter("heyaki_event_subscriptions_rejected_total",
                 event.subscriptions_rejected, "Subscriptions rejected.");
  writer.counter("heyaki_event_duplicate_subscriptions_total",
                 event.duplicate_subscriptions,
                 "Byte-stable replays of live subscriptions.");
  writer.counter("heyaki_event_subscription_limit_hits_total",
                 event.subscription_limit_hits,
                 "Per-peer subscription caps reached.");
  writer.counter("heyaki_event_scope_rejected_total", event.scope_rejected,
                 "Subscriptions rejected by scope.");
  writer.counter("heyaki_event_unsubscribes_received_total",
                 event.unsubscribes_received, "Unsubscribes received.");
  writer.counter("heyaki_event_terminated_subscriptions_total",
                 event.terminated_subscriptions,
                 "Subscriptions terminated on the sender side.");
  writer.counter("heyaki_event_subscribe_requests_sent_total",
                 event.subscribe_requests_sent, "Subscribe requests sent.");
  writer.counter("heyaki_event_items_received_total", event.items_received,
                 "Event items received.");
  writer.counter("heyaki_event_stale_items_total", event.stale_items,
                 "Deliveries below the newest seen sequence.");
  writer.counter("heyaki_event_lag_events_total", event.lag_events,
                 "Deliveries that skipped at least one sequence.");
  writer.counter("heyaki_event_lag_total_sequences", event.lag_total_sequences,
                 "Total sequences skipped by lag events.");
  writer.counter("heyaki_event_duplicate_items_total", event.duplicate_items,
                 "Duplicate event items.");
  writer.counter("heyaki_event_conflicting_items_total",
                 event.conflicting_items, "Conflicting event items.");
  writer.counter("heyaki_event_unknown_subscription_items_total",
                 event.unknown_subscription_items,
                 "Items arriving after unsubscribe or termination.");
  writer.counter("heyaki_event_unsubscribes_sent_total", event.unsubscribes_sent,
                 "Unsubscribes sent.");
  writer.counter("heyaki_event_handler_dispatched_total",
                 event.handler_dispatched, "Subscriber handler dispatches.");
  writer.counter("heyaki_event_handler_dispatch_rejected_total",
                 event.handler_dispatch_rejected,
                 "Subscriber dispatches the handler rejected.");
  writer.counter("heyaki_event_handler_completed_total",
                 event.handler_completed, "Subscriber handler completions.");
  writer.counter("heyaki_event_handler_exceptions_total",
                 event.handler_exceptions, "Subscriber handler exceptions.");
}

void write_file_section(MetricsWriter& writer, const FileServiceStats& file) {
  writer.counter("heyaki_file_pushes_started_total", file.pushes_started,
                 "File pushes started.");
  writer.counter("heyaki_file_manifests_sent_total", file.manifests_sent,
                 "File manifests sent.");
  writer.counter("heyaki_file_accepts_received_total", file.accepts_received,
                 "File transfer accepts received.");
  writer.counter("heyaki_file_rejects_received_total", file.rejects_received,
                 "File transfer rejects received.");
  writer.counter("heyaki_file_chunks_sent_total", file.chunks_sent,
                 "File chunks sent.");
  writer.counter("heyaki_file_chunk_send_deferred_total",
                 file.chunk_send_deferred,
                 "Chunk sends deferred by transport backpressure.");
  writer.counter("heyaki_file_completes_sent_total", file.completes_sent,
                 "File completion notices sent.");
  writer.counter("heyaki_file_sender_committed_total", file.sender_committed,
                 "Senders that committed successfully.");
  writer.counter("heyaki_file_sender_failed_total", file.sender_failed,
                 "Senders that failed.");
  writer.counter("heyaki_file_sender_cancelled_total", file.sender_cancelled,
                 "Senders cancelled.");
  writer.counter("heyaki_file_sender_paused_total", file.sender_paused,
                 "Senders paused by backpressure.");
  writer.counter("heyaki_file_sender_resumed_total", file.sender_resumed,
                 "Senders resumed.");
  writer.counter("heyaki_file_read_failures_total", file.read_failures,
                 "Source file read failures.");
  writer.counter("heyaki_file_pull_requests_received_total",
                 file.pull_requests_received, "Pull requests received.");
  writer.counter("heyaki_file_pull_requests_rejected_total",
                 file.pull_requests_rejected, "Pull requests rejected.");
  writer.counter("heyaki_file_manifests_received_total",
                 file.manifests_received, "File manifests received.");
  writer.counter("heyaki_file_manifests_rejected_total",
                 file.manifests_rejected, "File manifests rejected.");
  writer.counter("heyaki_file_scope_rejected_total", file.scope_rejected,
                 "File transfers rejected by scope.");
  writer.counter("heyaki_file_quota_rejected_total", file.quota_rejected,
                 "File transfers rejected by byte quota.");
  writer.counter("heyaki_file_path_rejected_total", file.path_rejected,
                 "File transfers rejected by path policy.");
  writer.counter("heyaki_file_policy_rejected_total", file.policy_rejected,
                 "File transfers rejected by transfer policy.");
  writer.counter("heyaki_file_concurrency_rejected_total",
                 file.concurrency_rejected,
                 "File transfers rejected by concurrency limits.");
  writer.counter("heyaki_file_accepts_sent_total", file.accepts_sent,
                 "File transfer accepts sent.");
  writer.counter("heyaki_file_resumed_transfers_total", file.resumed_transfers,
                 "Transfers resumed from confirmed chunks.");
  writer.counter("heyaki_file_chunks_received_total", file.chunks_received,
                 "File chunks received.");
  writer.counter("heyaki_file_duplicate_chunks_total", file.duplicate_chunks,
                 "Duplicate file chunks.");
  writer.counter("heyaki_file_conflicting_chunks_total",
                 file.conflicting_chunks, "Conflicting file chunks.");
  writer.counter("heyaki_file_chunk_hash_failures_total",
                 file.chunk_hash_failures, "Chunk hash verification failures.");
  writer.counter("heyaki_file_write_failures_total", file.write_failures,
                 "Disk write failures.");
  writer.counter("heyaki_file_verifies_started_total", file.verifies_started,
                 "Final BLAKE3 verifications started.");
  writer.counter("heyaki_file_committed_total", file.committed,
                 "Files committed atomically.");
  writer.counter("heyaki_file_commit_failures_total", file.commit_failures,
                 "File commit failures.");
  writer.counter("heyaki_file_receiver_cancelled_total",
                 file.receiver_cancelled, "Receivers cancelled.");
  writer.counter("heyaki_file_partial_cleanups_total", file.partial_cleanups,
                 "Partial temp/state cleanups after failures.");
}

void write_shell_section(MetricsWriter& writer, const ShellServiceStats& shell) {
  writer.counter("heyaki_shell_opens_received_total", shell.opens_received,
                 "Shell open requests received.");
  writer.counter("heyaki_shell_scope_rejected_total", shell.scope_rejected,
                 "Shell opens rejected by scope.");
  writer.counter("heyaki_shell_unknown_profile_rejected_total",
                 shell.unknown_profile_rejected,
                 "Shell opens for unknown profiles.");
  writer.counter("heyaki_shell_concurrency_rejected_total",
                 shell.concurrency_rejected,
                 "Shell opens rejected by concurrency limits.");
  writer.counter("heyaki_shell_spawns_started_total", shell.spawns_started,
                 "Shell spawns started.");
  writer.counter("heyaki_shell_spawn_failures_total", shell.spawn_failures,
                 "Shell spawn failures.");
  writer.counter("heyaki_shell_inputs_received_total", shell.inputs_received,
                 "Shell stdin frames received.");
  writer.counter("heyaki_shell_input_bytes_received_total",
                 shell.input_bytes_received, "Shell stdin bytes received.");
  writer.counter("heyaki_shell_input_backpressure_rejected_total",
                 shell.input_backpressure_rejected,
                 "Shell stdin rejected by pending-input limits.");
  writer.counter("heyaki_shell_duplicate_input_slices_total",
                 shell.duplicate_input_slices, "Duplicate shell stdin slices.");
  writer.counter("heyaki_shell_conflicting_input_slices_total",
                 shell.conflicting_input_slices, "Conflicting shell stdin slices.");
  writer.counter("heyaki_shell_output_frames_sent_total",
                 shell.output_frames_sent, "Shell output frames sent.");
  writer.counter("heyaki_shell_output_send_deferred_total",
                 shell.output_send_deferred,
                 "Shell output sends deferred by backpressure.");
  writer.counter("heyaki_shell_output_flood_terminated_total",
                 shell.output_flood_terminated,
                 "Shells terminated for output flooding.");
  writer.counter("heyaki_shell_idle_timeouts_total", shell.idle_timeouts,
                 "Shells terminated by idle timeout.");
  writer.counter("heyaki_shell_absolute_timeouts_total",
                 shell.absolute_timeouts,
                 "Shells terminated by absolute timeout.");
  writer.counter("heyaki_shell_output_limit_terminations_total",
                 shell.output_limit_terminations,
                 "Shells terminated by total output budget.");
  writer.counter("heyaki_shell_signals_received_total", shell.signals_received,
                 "Shell signals received.");
  writer.counter("heyaki_shell_signals_rejected_total", shell.signals_rejected,
                 "Shell signals rejected by policy.");
  writer.counter("heyaki_shell_resizes_received_total", shell.resizes_received,
                 "Shell resizes received.");
  writer.counter("heyaki_shell_eofs_received_total", shell.eofs_received,
                 "Shell EOFs received.");
  writer.counter("heyaki_shell_exits_sent_total", shell.exits_sent,
                 "Shell exit notices sent.");
  writer.counter("heyaki_shell_closes_received_total", shell.closes_received,
                 "Shell closes received.");
  writer.counter("heyaki_shell_local_terminations_total",
                 shell.local_terminations, "Shells terminated locally.");
  writer.counter("heyaki_shell_session_close_terminations_total",
                 shell.session_close_terminations,
                 "Shells terminated by session close.");
  writer.counter("heyaki_shell_protocol_violations_total",
                 shell.protocol_violations, "Shell protocol violations.");
  writer.counter("heyaki_shell_late_frames_ignored_total",
                 shell.late_frames_ignored, "Late shell frames ignored.");
  writer.counter("heyaki_shell_opens_sent_total", shell.opens_sent,
                 "Shell opens sent.");
  writer.counter("heyaki_shell_opens_accepted_total", shell.opens_accepted,
                 "Shell opens accepted.");
  writer.counter("heyaki_shell_opens_rejected_total", shell.opens_rejected,
                 "Shell opens rejected.");
  writer.counter("heyaki_shell_outputs_received_total", shell.outputs_received,
                 "Shell output frames received.");
  writer.counter("heyaki_shell_output_bytes_received_total",
                 shell.output_bytes_received, "Shell output bytes received.");
  writer.counter("heyaki_shell_inputs_sent_total", shell.inputs_sent,
                 "Shell stdin frames sent.");
  writer.counter("heyaki_shell_exits_received_total", shell.exits_received,
                 "Shell exit notices received.");
  writer.counter("heyaki_shell_errors_received_total", shell.errors_received,
                 "Shell errors received.");
  writer.counter("heyaki_shell_closes_sent_total", shell.closes_sent,
                 "Shell closes sent.");
}

void write_services_section(MetricsWriter& writer,
                            const NodeServiceDiagnostics& services) {
  write_message_section(writer, services.message);
  write_rpc_section(writer, services.rpc);
  write_event_section(writer, services.event);
  write_file_section(writer, services.file);
  write_shell_section(writer, services.shell);
  writer.gauge("heyaki_services_message_pending_acks",
               services.message_pending_acks,
               "Messages awaiting peer acks.");
  writer.gauge("heyaki_services_rpc_pending_calls", services.rpc_pending_calls,
               "RPC calls awaiting responses.");
  writer.gauge("heyaki_services_rpc_retry_queue", services.rpc_retry_queue,
               "RPC calls parked in the retry queue.");
  writer.gauge("heyaki_services_message_sessions", services.message_sessions,
               "Peers with attached message services.");
  writer.gauge("heyaki_services_rpc_sessions", services.rpc_sessions,
               "Peers with attached RPC services.");
  writer.gauge("heyaki_services_event_sessions", services.event_sessions,
               "Peers with attached event services.");
  writer.gauge("heyaki_services_file_sessions", services.file_sessions,
               "Peers with attached file services.");
  writer.gauge("heyaki_services_file_paused_transfers",
               services.file_paused_transfers, "File transfers paused.");
  writer.gauge("heyaki_services_shell_sessions", services.shell_sessions,
               "Peers with attached shell services.");
}

void write_runtime_section(MetricsWriter& writer,
                           const RuntimeSnapshot& runtime) {
  writer.gauge("heyaki_runtime_ownership",
               static_cast<std::uint64_t>(runtime.ownership),
               "RuntimeOwnership enum value.");
  writer.gauge("heyaki_runtime_phase", static_cast<std::uint64_t>(runtime.phase),
               "RuntimePhase enum value.");
  writer.gauge("heyaki_runtime_state_sequence", runtime.state_sequence,
               "Runtime state transition sequence.");
  writer.counter("heyaki_runtime_callbacks_accepted_total",
                 runtime.callbacks_accepted, "Executor callbacks accepted.");
  writer.counter("heyaki_runtime_callbacks_rejected_total",
                 runtime.callbacks_rejected,
                 "Executor callbacks rejected at admission.");
  writer.counter("heyaki_runtime_callbacks_completed_total",
                 runtime.callbacks_completed, "Executor callbacks completed.");
  writer.counter("heyaki_runtime_callback_exceptions_total",
                 runtime.callback_exception_count, "Executor callback exceptions.");
  writer.counter("heyaki_runtime_handler_exceptions_total",
                 runtime.handler_exception_count, "Service handler exceptions.");
  writer.gauge("heyaki_runtime_outstanding_operations",
               runtime.outstanding_operations, "Tracked operations in flight.");
  writer.gauge("heyaki_runtime_callback_queue_depth",
               runtime.callback_queue_depth, "Callback queue depth.");
  writer.gauge("heyaki_runtime_callback_queue_peak_depth",
               runtime.callback_queue_peak_depth, "Callback queue peak depth.");
  writer.counter("heyaki_runtime_callback_queue_dropped_total",
                 runtime.callback_queue_dropped,
                 "Callbacks dropped by the metrics mailbox policy.");
  writer.gauge("heyaki_runtime_metric_sequence", runtime.metric_sequence,
               "Runtime metrics publication sequence.");
  writer.counter("heyaki_runtime_metric_overwritten_total",
                 runtime.metric_overwritten_count,
                 "Metrics mailbox samples overwritten before consumption.");
  writer.counter("heyaki_runtime_metric_stale_read_total",
                 runtime.metric_stale_read_count,
                 "Metrics mailbox reads that returned stale data.");
  writer.gauge("heyaki_runtime_metric_consumer_lag",
               runtime.metric_consumer_lag, "Metrics mailbox consumer lag.");
  writer.counter("heyaki_executor_submit_rejected_total",
                 runtime.executor_submit_rejected_count,
                 "Executor submissions rejected at admission.");
  writer.counter("heyaki_executor_task_exceptions_total",
                 runtime.executor_task_exception_count,
                 "Executor task failures observed.");
  writer.counter("heyaki_executor_wait_timeouts_total",
                 runtime.executor_wait_timeout_count,
                 "Executor waits that timed out during shutdown or drain.");
  writer.gauge("heyaki_executor_running_backends",
               runtime.executor_running_backend_count,
               "Executor backends running.");
  writer.gauge("heyaki_executor_stopping_backends",
               runtime.executor_stopping_backend_count,
               "Executor backends stopping.");
  writer.gauge("heyaki_executor_blocking_io_workers",
               runtime.executor_blocking_io_count,
               "Blocking I/O workers alive.");
  writer.gauge("heyaki_executor_active_tasks",
               runtime.executor_active_task_count, "Executor tasks active.");
  writer.gauge("heyaki_executor_queued_tasks",
               runtime.executor_queued_task_count, "Executor tasks queued.");
  writer.gauge("heyaki_executor_snapshot_partial",
               runtime.executor_snapshot_partial ? 1U : 0U,
               "1 when the executor snapshot was incomplete.");
}

}  // namespace

std::string format_node_metrics_prometheus(const NodeMetrics& metrics,
                                           std::string_view instance) {
  MetricsWriter writer{instance};
  writer.gauge("heyaki_metrics_unix_milliseconds", metrics.unix_milliseconds,
               "Wall-clock time of this metrics snapshot.");
  write_node_section(writer, metrics.node);
  write_pairing_section(writer, metrics.pairing);
  write_connectivity_section(writer, metrics.connectivity);
  write_transport_section(writer, metrics.transport);
  write_channel_section(writer, metrics.channels);
  write_services_section(writer, metrics.services);
  write_runtime_section(writer, metrics.runtime);
  return writer.output();
}

}  // namespace heyaki
