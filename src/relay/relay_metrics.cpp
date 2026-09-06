// Prometheus text-format export of RelayServerSnapshot (M9-02). See
// relay_metrics.hpp for the format contract; the writer is shared with the
// device-side exporter so escaping and family layout stay identical.

#include "relay_metrics.hpp"

#include "core/metrics_text_writer.hpp"

#include <string>
#include <string_view>

namespace heyaki {
namespace {

using MetricsWriter = detail::MetricsTextWriter;

void write_server_section(MetricsWriter& writer,
                          const RelayServerSnapshot& snapshot) {
  writer.gauge("heyaki_relay_state",
               static_cast<std::uint64_t>(snapshot.state),
               "RelayServerState enum value.");
  writer.gauge("heyaki_relay_stop_requested",
               snapshot.stop_requested ? 1U : 0U,
               "1 when a stop has been requested and the server is draining.");
  writer.gauge("heyaki_relay_active_sessions", snapshot.active_sessions,
               "Currently tracked TLS/WSS sessions.");
  writer.gauge("heyaki_relay_connection_capacity", snapshot.connection_capacity,
               "Configured maximum concurrent connections.");
  writer.gauge("heyaki_relay_listen_port", snapshot.listen_port,
               "Bound listen port (0 when closed).");

  writer.counter("heyaki_relay_tcp_accepted_total", snapshot.tcp_accepted,
                 "TCP connections accepted.");
  writer.counter("heyaki_relay_websocket_accepted_total",
                 snapshot.websocket_accepted,
                 "HTTP upgrade requests accepted (any path).");
  writer.counter("heyaki_relay_health_checks_total", snapshot.health_checks,
                 "Health endpoint requests served.");
  writer.counter("heyaki_relay_metrics_scrapes_total", snapshot.metrics_scrapes,
                 "Prometheus metrics endpoint requests served.");
  writer.counter("heyaki_relay_control_sessions_total",
                 snapshot.control_sessions,
                 "Control-plane WebSocket sessions started.");
  writer.counter("heyaki_relay_control_rejected_total",
                 snapshot.control_rejected,
                 "Control messages rejected (policy, rate, or protocol).");
  writer.counter("heyaki_relay_capacity_rejected_total",
                 snapshot.capacity_rejected,
                 "Connections refused because the session capacity was full.");
  writer.counter("heyaki_relay_handshake_timeouts_total",
                 snapshot.handshake_timeouts,
                 "Sessions dropped by the handshake deadline.");
  writer.counter("heyaki_relay_handshake_failed_total",
                 snapshot.handshake_failed,
                 "Sessions that failed handshake or I/O.");
  writer.counter("heyaki_relay_protocol_rejected_total",
                 snapshot.protocol_rejected,
                 "Sessions closed for policy or protocol violations.");
  writer.counter("heyaki_relay_enrollment_challenges_total",
                 snapshot.enrollment_challenges,
                 "Enrollment challenges issued.");
  writer.counter("heyaki_relay_enrollments_completed_total",
                 snapshot.enrollments_completed,
                 "Enrollments completed.");
  writer.counter("heyaki_relay_login_challenges_total",
                 snapshot.login_challenges, "Login challenges issued.");
  writer.counter("heyaki_relay_logins_completed_total",
                 snapshot.logins_completed, "Logins completed.");
  writer.counter("heyaki_relay_heartbeats_total", snapshot.heartbeats,
                 "Endpoint lease heartbeats refreshed.");
  writer.counter("heyaki_relay_endpoint_publications_total",
                 snapshot.endpoint_publications,
                 "Endpoint records published to the directory.");
  writer.counter("heyaki_relay_endpoint_queries_total",
                 snapshot.endpoint_queries,
                 "Endpoint directory queries served.");
  writer.counter("heyaki_relay_signaling_forwarded_total",
                 snapshot.signaling_forwarded,
                 "Signaling messages forwarded to online targets.");
  writer.counter("heyaki_relay_signaling_rejected_total",
                 snapshot.signaling_rejected,
                 "Signaling messages rejected before delivery.");
  writer.counter("heyaki_relay_signaling_backpressure_dropped_total",
                 snapshot.signaling_backpressure_dropped,
                 "Signaling frames dropped because the target write queue was full.");
  writer.counter("heyaki_relay_log_events_emitted_total",
                 snapshot.log_events_emitted,
                 "Structured log events emitted to the sink.");
  writer.counter("heyaki_relay_log_events_sampled_out_total",
                 snapshot.log_events_sampled_out,
                 "High-frequency success events suppressed by sampling.");
}

void write_database_section(MetricsWriter& writer,
                            const RelayDatabaseSnapshot& database) {
  writer.gauge("heyaki_relay_database_schema_version",
               database.schema_version, "Relay database schema version.");
  writer.gauge("heyaki_relay_database_devices", database.device_count,
               "Enrolled devices in the database.");
  writer.gauge("heyaki_relay_database_bootstrap_tokens",
               database.bootstrap_token_count,
               "Bootstrap tokens in the database.");
  writer.gauge("heyaki_relay_database_device_audit_records",
               database.device_audit_count,
               "Device audit rows in the database.");
}

void write_rate_limit_section(MetricsWriter& writer,
                              const RelayRateLimitDiagnostics& limits) {
  const struct {
    std::string_view scope;
    const RelayRateLimitCounters* counters;
  } scopes[] = {{"connection", &limits.connection},
                {"request", &limits.request},
                {"tenant", &limits.tenant},
                {"ip", &limits.ip}};
  for (const auto& entry : scopes) {
    const std::string prefix = std::string{"heyaki_relay_rate_limit_"} +
                               std::string{entry.scope} + "_";
    writer.counter(prefix + "allowed_total", entry.counters->allowed,
                   "Admitted events under this rate-limit scope.");
    writer.counter(prefix + "rejected_total", entry.counters->rejected,
                   "Events rejected by the scope limit.");
    writer.counter(prefix + "capacity_rejected_total",
                   entry.counters->capacity_rejected,
                   "Events rejected because the scope key table was full.");
    writer.gauge(prefix + "keys", entry.counters->current_keys,
                 "Tracked keys under this rate-limit scope.");
    writer.gauge(prefix + "peak_keys", entry.counters->peak_keys,
                 "Peak tracked keys under this rate-limit scope.");
  }
}

void write_lease_section(MetricsWriter& writer,
                         const RelayLeaseDiagnostics& leases) {
  writer.counter("heyaki_relay_lease_accepted_total", leases.accepted,
                 "Endpoint leases inserted.");
  writer.counter("heyaki_relay_lease_refreshed_total", leases.refreshed,
                 "Endpoint leases refreshed by heartbeats.");
  writer.counter("heyaki_relay_lease_expired_total", leases.expired,
                 "Endpoint leases expired.");
  writer.counter("heyaki_relay_lease_removed_total", leases.removed,
                 "Endpoint leases removed on session close.");
  writer.counter("heyaki_relay_lease_capacity_rejected_total",
                 leases.capacity_rejected,
                 "Leases rejected because the table was full.");
  writer.counter("heyaki_relay_lease_per_device_rejected_total",
                 leases.per_device_rejected,
                 "Leases rejected by the per-device endpoint cap.");
  writer.counter("heyaki_relay_lease_per_tenant_rejected_total",
                 leases.per_tenant_rejected,
                 "Leases rejected by the per-tenant device cap.");
  writer.counter("heyaki_relay_lease_tenant_conflict_rejected_total",
                 leases.tenant_conflict_rejected,
                 "Leases rejected because the endpoint changed tenants.");
  writer.gauge("heyaki_relay_lease_entries", leases.current_entries,
               "Live endpoint leases.");
  writer.gauge("heyaki_relay_lease_peak_entries", leases.peak_entries,
               "Peak endpoint leases.");
}

void write_endpoint_directory_section(
    MetricsWriter& writer, const RelayEndpointDirectoryDiagnostics& endpoints) {
  writer.counter("heyaki_relay_endpoints_published_total", endpoints.published,
                 "Endpoint records published.");
  writer.counter("heyaki_relay_endpoints_updated_total", endpoints.updated,
                 "Endpoint records updated.");
  writer.counter("heyaki_relay_endpoints_expired_total", endpoints.expired,
                 "Endpoint records expired.");
  writer.counter("heyaki_relay_endpoints_removed_total", endpoints.removed,
                 "Endpoint records removed.");
  writer.counter("heyaki_relay_endpoints_capacity_rejected_total",
                 endpoints.capacity_rejected,
                 "Endpoint publications rejected because the directory was full.");
  writer.counter("heyaki_relay_endpoints_validation_rejected_total",
                 endpoints.validation_rejected,
                 "Endpoint publications rejected by validation.");
  writer.counter("heyaki_relay_endpoints_tenant_conflict_rejected_total",
                 endpoints.tenant_conflict_rejected,
                 "Endpoint publications rejected on tenant conflict.");
  writer.counter("heyaki_relay_endpoint_table_accepted_total",
                 endpoints.table.accepted, "Directory TTL table inserts.");
  writer.counter("heyaki_relay_endpoint_table_updated_total",
                 endpoints.table.updated, "Directory TTL table updates.");
  writer.counter("heyaki_relay_endpoint_table_capacity_rejected_total",
                 endpoints.table.capacity_rejected,
                 "Directory TTL table inserts rejected from capacity.");
  writer.counter("heyaki_relay_endpoint_table_expired_total",
                 endpoints.table.expired,
                 "Directory TTL table entries expired.");
  writer.gauge("heyaki_relay_endpoint_table_entries",
               endpoints.table.current_entries,
               "Live endpoint directory entries.");
  writer.gauge("heyaki_relay_endpoint_table_peak_entries",
               endpoints.table.peak_entries,
               "Peak endpoint directory entries.");
}

void write_login_section(MetricsWriter& writer,
                         const RelayLoginServiceDiagnostics& login) {
  writer.counter("heyaki_relay_login_challenges_issued_total",
                 login.challenges_issued, "Login challenges issued.");
  writer.counter("heyaki_relay_login_succeeded_total", login.logins_succeeded,
                 "Logins authenticated.");
  writer.counter("heyaki_relay_login_challenges_unknown_total",
                 login.challenges_unknown,
                 "Login requests referencing an unknown challenge.");
  writer.counter("heyaki_relay_login_validation_rejected_total",
                 login.validation_rejected,
                 "Login requests rejected by validation.");
  writer.counter("heyaki_relay_login_device_rejected_total",
                 login.device_rejected,
                 "Login requests rejected by device state.");
  writer.counter("heyaki_relay_login_audit_failed_total", login.audit_failed,
                 "Login attempts whose database audit write failed.");
  writer.counter("heyaki_relay_login_challenge_table_accepted_total",
                 login.challenge_table.accepted,
                 "Login challenge table inserts.");
  writer.counter("heyaki_relay_login_challenge_table_updated_total",
                 login.challenge_table.updated,
                 "Login challenge table updates.");
  writer.counter("heyaki_relay_login_challenge_table_capacity_rejected_total",
                 login.challenge_table.capacity_rejected,
                 "Login challenge table inserts rejected from capacity.");
  writer.counter("heyaki_relay_login_challenge_table_expired_total",
                 login.challenge_table.expired,
                 "Login challenge table entries expired.");
  writer.gauge("heyaki_relay_login_challenge_table_entries",
               login.challenge_table.current_entries,
               "Live login challenges.");
  writer.gauge("heyaki_relay_login_challenge_table_peak_entries",
               login.challenge_table.peak_entries,
               "Peak login challenges.");
}

void write_enrollment_section(
    MetricsWriter& writer, const RelayEnrollmentServiceDiagnostics& enrollment) {
  writer.counter("heyaki_relay_enrollment_challenges_issued_total",
                 enrollment.challenges_issued,
                 "Enrollment challenges issued.");
  writer.counter("heyaki_relay_enrollments_completed_service_total",
                 enrollment.challenges_completed,
                 "Enrollments completed (service diagnostics).");
  writer.counter("heyaki_relay_enrollment_challenges_expired_total",
                 enrollment.challenges_expired,
                 "Enrollment challenges expired unused.");
  writer.counter("heyaki_relay_enrollment_challenges_unknown_total",
                 enrollment.challenges_unknown,
                 "Enrollment requests referencing an unknown challenge.");
  writer.counter("heyaki_relay_enrollment_validation_rejected_total",
                 enrollment.validation_rejected,
                 "Enrollment requests rejected by validation.");
  writer.counter("heyaki_relay_enrollment_token_rejected_total",
                 enrollment.token_rejected,
                 "Enrollment requests rejected by bootstrap token checks.");
  writer.counter("heyaki_relay_enrollment_database_rejected_total",
                 enrollment.database_rejected,
                 "Enrollment requests rejected by the database.");
  writer.counter("heyaki_relay_enrollment_challenge_table_accepted_total",
                 enrollment.challenge_table.accepted,
                 "Enrollment challenge table inserts.");
  writer.counter("heyaki_relay_enrollment_challenge_table_updated_total",
                 enrollment.challenge_table.updated,
                 "Enrollment challenge table updates.");
  writer.counter(
      "heyaki_relay_enrollment_challenge_table_capacity_rejected_total",
      enrollment.challenge_table.capacity_rejected,
      "Enrollment challenge table inserts rejected from capacity.");
  writer.counter("heyaki_relay_enrollment_challenge_table_expired_total",
                 enrollment.challenge_table.expired,
                 "Enrollment challenge table entries expired.");
  writer.gauge("heyaki_relay_enrollment_challenge_table_entries",
               enrollment.challenge_table.current_entries,
               "Live enrollment challenges.");
  writer.gauge("heyaki_relay_enrollment_challenge_table_peak_entries",
               enrollment.challenge_table.peak_entries,
               "Peak enrollment challenges.");
}

}  // namespace

std::string format_relay_metrics_prometheus(const RelayServerSnapshot& snapshot,
                                            std::string_view instance) {
  MetricsWriter writer{instance};
  write_server_section(writer, snapshot);
  write_database_section(writer, snapshot.database);
  write_rate_limit_section(writer, snapshot.rate_limits);
  write_lease_section(writer, snapshot.leases);
  write_endpoint_directory_section(writer, snapshot.endpoints);
  write_login_section(writer, snapshot.login);
  write_enrollment_section(writer, snapshot.enrollment);
  return writer.output();
}

std::string relay_id_to_hex(const RelayId& relay_id) {
  static constexpr char hex[] = "0123456789abcdef";
  std::string output(relay_id.size() * 2U, '0');
  for (std::size_t index = 0U; index < relay_id.size(); ++index) {
    const auto value = static_cast<unsigned char>(relay_id[index]);
    output[index * 2U] = hex[value >> 4U];
    output[index * 2U + 1U] = hex[value & 0x0fU];
  }
  return output;
}

}  // namespace heyaki
