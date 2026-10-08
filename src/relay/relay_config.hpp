#pragma once

#include "relay_endpoint.hpp"
#include "relay_endpoint_directory.hpp"
#include "relay_enrollment_service.hpp"
#include "relay_lease_table.hpp"
#include "relay_log.hpp"
#include "relay_rate_limiter.hpp"

#include <heyaki/relay_wss_control.hpp>
#include <heyaki/runtime.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace heyaki {

// Environment variable carrying the TURN shared secret when no
// `turn_secret_file` is configured. Same variable the coturn deployment
// (deploy/coturn) consumes, so one secret serves both sides.
inline constexpr std::string_view relay_turn_secret_env = "HEYAKI_TURN_SECRET";

// One advertised ICE server handed to devices through the relay-issued
// `ice_config` field. Kind uses the wire enum; `turn_tls` is rejected by
// validate_relay_server_config because no pinned ICE backend implements it.
struct RelayTurnAdvertisedServer {
  RelayWssIceServerKind kind{RelayWssIceServerKind::turn_udp};
  std::string hostname;
  std::uint16_t port{};
};

struct RelayServerConfig {
  std::string listen_address{"0.0.0.0"};
  std::uint16_t listen_port{8443U};
  std::filesystem::path tls_certificate_file;
  std::filesystem::path tls_private_key_file;
  std::filesystem::path database_file{":memory:"};
  std::string health_path{"/health"};
  // Plain-HTTP Prometheus scrape endpoint (M9-02). Unlike health_path it
  // answers with a normal HTTP response instead of a WebSocket upgrade, so
  // off-the-shelf scrapers work against it.
  std::string metrics_path{"/metrics"};
  std::size_t max_connections{1024U};
  std::chrono::milliseconds handshake_timeout{5000};
  std::chrono::milliseconds shutdown_timeout{2000};
  bool install_signal_handlers{true};
  // Per-session watermark for queued outbound control frames (frame count and
  // encoded byte total). Forwarded signaling to a session that stops reading is
  // dropped with an endpoint_offline answer instead of growing without bound.
  std::size_t control_write_queue_frames{64U};
  std::size_t control_write_queue_bytes{1024U * 1024U};
  // Invoked on the server strand whenever the observable snapshot tuple
  // (state, stop_requested) changes. Lets embedders block on a completion
  // notification (e.g. kairo::comm::PhaseGate) instead of polling.
  std::function<void()> on_state_changed;
  // Structured log sink (M9-02). Invoked synchronously on the relay's
  // execution context for every emitted event; must return promptly and
  // must not throw. Failures and security events always reach the sink;
  // high-frequency success events are sampled per `success_log_period`.
  RelayLogSink log_sink;
  // Sampling period for high-frequency success events (heartbeat refreshes,
  // signaling forwards, endpoint queries): the 1st and then every Nth event
  // per kind is emitted. 0 disables sampled events entirely. Failures,
  // security events, and lifecycle changes are never sampled.
  std::uint32_t success_log_period{100U};
  RelayLeaseConfig lease;
  RelayEndpointDirectoryConfig endpoint_directory;
  RelayTenantExposurePolicy endpoint_exposure;
  std::size_t endpoint_query_max_results{256U};
  std::size_t signaling_rate_per_second{32U};
  bool close_revoked_sessions{true};
  RelayRateLimitPolicy rate_limits;
  // Enrollment admission policy (issue: password enrollment + first-run
  // bootstrap). `token` keeps the historical behavior; `password` requires a
  // provisioned owner password verifier in the relay database and admits
  // devices with URL + password only; `closed` refuses all new enrollments.
  RelayEnrollmentMode enrollment_mode{RelayEnrollmentMode::token};
  // Single tenant password-mode enrollments land in. Must stay in sync with
  // what clients send; the access card printed by `heyaki-relay --init`
  // shows it.
  std::string enrollment_default_tenant{"default"};
  // Relay-issued short-lived TURN REST credentials (coturn use-auth-secret).
  // Default off: deployments without the flag keep byte-identical control
  // traffic. The shared secret never enters this struct or the config file;
  // it is loaded at server start from `turn_secret_file` or the
  // HEYAKI_TURN_SECRET environment variable (in that precedence).
  bool turn_credentials_enabled{false};
  std::chrono::seconds turn_credential_ttl{600};
  std::vector<RelayTurnAdvertisedServer> turn_servers;
  std::optional<std::filesystem::path> turn_secret_file;
  RuntimeConfig runtime;
};

[[nodiscard]] Result<RelayServerConfig> load_relay_config_file(
    const std::filesystem::path& config_file);
[[nodiscard]] Result<void> validate_relay_server_config(
    const RelayServerConfig& config);
// Resolves the TURN shared secret for an enabled configuration: reads
// `turn_secret_file` when set (a single trailing newline is stripped),
// otherwise the HEYAKI_TURN_SECRET environment variable. The secret is
// validated with validate_turn_secret (16–256 printable ASCII bytes) and
// never appears in the returned error details.
[[nodiscard]] Result<std::string> load_relay_turn_secret(
    const RelayServerConfig& config);

}  // namespace heyaki
