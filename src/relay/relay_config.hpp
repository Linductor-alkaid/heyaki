#pragma once

#include "relay_endpoint.hpp"
#include "relay_endpoint_directory.hpp"
#include "relay_lease_table.hpp"
#include "relay_log.hpp"
#include "relay_rate_limiter.hpp"

#include <heyaki/runtime.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>

namespace heyaki {

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
  // notification (e.g. executor::comm::PhaseGate) instead of polling.
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
  RuntimeConfig runtime;
};

[[nodiscard]] Result<RelayServerConfig> load_relay_config_file(
    const std::filesystem::path& config_file);
[[nodiscard]] Result<void> validate_relay_server_config(
    const RelayServerConfig& config);

}  // namespace heyaki
