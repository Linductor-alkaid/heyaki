# Heyaki observability baseline (M9-04)

This directory defines the v1 SLO dashboard and alerting for Heyaki, built
entirely on the exporter surfaces delivered in M9-01..M9-03:

- the relay serves Prometheus text on its TLS listener at `GET /metrics`
  (`metrics_path`, default `/metrics`; ~106 `heyaki_relay_*` families);
- the device side renders the same text format through
  `format_node_metrics_prometheus(Node::metrics())` (~200 `heyaki_node_*`
  and service families), exposed interactively by the TUI `metrics` command.

Everything here references only metrics that those exporters actually emit.
`tests/unit/m9_slo_rules_test.cpp` renders both exporters, parses these
files, and fails CI when a rule or panel references a metric that does not
exist, when an alert loses its `for`/`severity`/`summary`/`runbook_url`
structure, or when a `runbook_url` anchor no longer matches a heading in
`docs/operations/runbook.md`.

## Files

| File | Purpose |
| --- | --- |
| `prometheus/heyaki-scrape.yml` | Scrape configuration for the relay `/metrics` endpoint and the device-side ingestion convention. |
| `prometheus/heyaki-recording.yml` | Recording rules (`heyaki:slo:*`) that turn counters into SLO ratios. |
| `prometheus/heyaki-alerts.yml` | Alert rules, two groups: `heyaki-relay-slo` and `heyaki-node-slo`. |
| `grafana/heyaki-overview.json` | Grafana dashboard (24 panels) covering both surfaces. |

## Data sources

**Relay (always scraped).** The relay is the only component with a resident
HTTP endpoint; point Prometheus at it as shown in `heyaki-scrape.yml`. The
scraper must trust the relay certificate (standard TLS verification; the
device-side pinning does not apply to Prometheus). The `instance` label is
the certificate SHA-256 hex (`relay_id_to_hex`), which joins directly with
the structured log stream (`heyaki-relay` prints JSON lines to stdout).

**Devices (opt-in ingestion).** Devices live behind NAT and intentionally
run no resident exporter. The device surfaces are the TUI `metrics` command
for interactive diagnosis and `Node::metrics()` (public API) for embedding
applications. For infrastructure-hosted devices that should appear on the
dashboard, export the text periodically into node_exporter's textfile
collector directory via the public API; device-side recording rules, panels,
and alerts activate automatically once `heyaki_node_*` series appear and stay
empty and dormant until then. This is a deployment-side convention — no code
in this repository writes the textfile.

## SLO signal map

| M9-04 signal | Primary metrics | Alerts | Dashboard panels |
| --- | --- | --- | --- |
| multicast/listener readiness | `heyaki_node_lan_enabled`, `heyaki_node_lan_state`, `heyaki_node_tls_listener_ready`, `heyaki_node_interfaces_joined`, `heyaki_node_interfaces_multicast_verified` | HeyakiLanListenerNotReady, HeyakiLanMulticastUnverified | Device LAN readiness |
| presence/handshake reject | `heyaki_node_tls_{hello_rejected,handshake_failed}_total`, `heyaki_node_directory_*_rejected_total`, `heyaki_node_datagrams_rejected_total`; relay: `heyaki_relay_handshake_{failed,timeouts}_total` | HeyakiLanPresenceRejects, HeyakiRelayHandshakeFailures | Device LAN presence rejects, Relay handshake failure ratio |
| 登录失败 (login failures) | `heyaki_relay_login_audit_failed_total`, `heyaki_relay_login_{device,validation}_rejected_total`, `heyaki_relay_logins_completed_total`; device: `heyaki_node_relay_registration_{attempts,successes,failures}_total` | HeyakiRelayLoginFailureRate, HeyakiNodeRegistrationFailing | Relay login outcomes + ratio, Device relay registration + ratio |
| 租约续期 (lease renewal) | `heyaki_node_relay_lease_refresh_failures_total`, `heyaki_node_relay_heartbeats_missed_total`, `heyaki_relay_lease_{expired,per_device_rejected,capacity_rejected}_total` | HeyakiLeaseRefreshFailures, HeyakiLeaseTablePressure | Lease health |
| 直连率 (direct-connect rate) | `heyaki_connectivity_data_path_direct_{host,srflx}_total` vs `heyaki_connectivity_authenticated_total` (ratio recorded) | — (trend, watch panel) | Data path mix |
| TURN allocation | `heyaki_connectivity_data_path_turn_{udp,tcp,tls}_total` (ratio recorded) | HeyakiTurnFallbackDominant | Data path mix |
| pairing 猜测 (guessing) | `heyaki_pairing_denied_password_total`, `heyaki_pairing_denied_backoff_total`, `heyaki_pairing_attempts_total` | HeyakiPairingPasswordGuessing | Device pairing outcomes |
| 队列拒绝 (queue rejections) | `heyaki_executor_submit_rejected_total`, `heyaki_channel_{rejected,dropped}_frames_total`, `heyaki_event_subscriber_{drops,overflows}_total`, `heyaki_runtime_callback_queue_dropped_total`, `heyaki_relay_signaling_backpressure_dropped_total` | HeyakiQueueRejections, HeyakiRelaySignalingBackpressure | Device queue rejections, Relay signaling decisions |
| RPC overload | `heyaki_rpc_calls_admission_rejected_total`, `heyaki_rpc_concurrency_rejected_total`, `heyaki_rpc_handler_deadline_exceeded_total` (ratio recorded) | HeyakiRpcOverload | Device RPC overload |
| 文件 hash (file integrity) | `heyaki_file_chunk_hash_failures_total`, `heyaki_file_commit_failures_total`, `heyaki_file_{read,write}_failures_total` | HeyakiFileIntegrityFailures | Device file integrity |
| worker failure | `heyaki_executor_task_exceptions_total`, `heyaki_runtime_{handler,callback}_exceptions_total`, `heyaki_{message,rpc,event}_handler_exceptions_total`, `heyaki_shell_spawn_failures_total` | HeyakiExecutorTaskExceptions, HeyakiWorkerFailures | Device worker failures |
| base health | `up`, `heyaki_relay_state`, `heyaki_relay_active_sessions`, `heyaki_relay_log_events_{emitted,sampled_out}_total` | HeyakiRelayDown, HeyakiRelayNotRunning, HeyakiRelayCapacityPressure, HeyakiRelayRateLimited | Relay up/state, sessions, sampling health |

Alert severities: `critical` for reachability, registration collapse, file
integrity, and executor task loss; `warning` for degradation trends
(ratios, rejects, rate limits). Thresholds are v1 defaults — retune per
deployment; the ratios are computed by the recording rules so only the
comparison in `heyaki-alerts.yml` changes.

## Wiring

1. Prometheus: merge `heyaki-scrape.yml`, load both rule files
   (`rule_files` entry), reload.
2. Grafana: import `grafana/heyaki-overview.json`, select the Prometheus
   datasource when prompted (the `prometheus` template variable).
3. Alertmanager or the Grafana alerting stack consumes the alert rules;
   `runbook_url` values are repository-relative — prefix them with your
   internal docs host at delivery time.

## OpenTelemetry decision (M9-02 follow-up)

v1 ships no in-process OpenTelemetry export. The architecture lists trace
correlation as optional; the delivered join keys (wire `RequestId`/`GrantId`
in logs and TUI, certificate-digest `instance` label) already correlate
device and relay views without a collector dependency. Deployments that
want OTLP can run `opentelemetry-collector` with its Prometheus receiver
against the same `/metrics` endpoints — a deployment-side bridge, no Heyaki
code change. Revisit if a v1.x milestone adds distributed tracing.

## Known limitations

- Device-side series require the textfile/ingestion convention above; out
  of the box only the relay fleet reports.
- Loss estimation remains bounded by the pinned libdatachannel stats API
  (bytes/rtt only) — the M9-01 recorded gap; revisit after M9-10.
- coturn exposes no Prometheus surface in the pinned deployment; observe
  TURN health through the device-side path counters and coturn logs (see
  the runbook's TURN sections).
