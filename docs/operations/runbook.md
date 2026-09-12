# Heyaki v1 Operations Runbook (M9-05)

Operational procedures and alert triage for a Heyaki v1 deployment: one
`heyaki-relay` process with its SQLite database, one coturn instance, and a
fleet of devices (TUI or library applications). Metric names below refer to
the exporters delivered in M9-01..M9-03 and the SLO rules shipped under
`deploy/observability/`.

## Quick reference

### Relay process

```sh
heyaki-relay --config /etc/heyaki/relay.conf [--check-config]
```

CLI overrides (applied after the config file): `--listen`, `--port`,
`--tls-cert`, `--tls-key`, `--database`, `--health-path`, `--metrics-path`,
`--success-log-period`. `--check-config` validates and exits 0/1.

Config file keys: `listen_address`, `listen_port`, `tls_certificate_file`,
`tls_private_key_file`, `database_file`, `health_path`, `metrics_path`,
`success_log_period`, `max_connections`, `handshake_timeout_milliseconds`,
`shutdown_timeout_milliseconds`, `lease_default_milliseconds`,
`lease_maximum_milliseconds`, `lease_capacity`,
`lease_per_device_endpoint_capacity`, `lease_per_tenant_device_capacity`,
`endpoint_directory_capacity`, `endpoint_query_max_results`,
`signaling_rate_per_second`, `close_revoked_sessions`,
`endpoint_expose_application_id`, `endpoint_expose_record_generation`,
`endpoint_expose_manifest_sha256`, `endpoint_expose_manifest_generation`.

Signals: SIGINT/SIGTERM trigger a graceful stop (drain within
`shutdown_timeout_milliseconds`, default 2000).

Endpoints (same TLS listener): `GET /health` liveness; `GET /metrics`
Prometheus text (plain HTTP response, no WebSocket upgrade; non-GET → 405).
Both require TLS trust of the relay certificate.

Logs: JSON lines on stdout (one line per event, flushed immediately). 16
event kinds: `server_state_changed`, `server_error`,
`connection_capacity_rejected`, `handshake_timeout`, `handshake_failed`,
`policy_rejected`, `rate_limited`, `enrollment_completed`,
`enrollment_rejected`, `login_completed`, `login_rejected`,
`endpoint_published`, `signaling_forwarded`, `signaling_rejected`,
`heartbeat_refreshed`, `endpoint_query_served`. Failures, security events,
and lifecycle changes are always logged; heartbeat/signaling/query
successes are sampled (first + every Nth per kind, N =
`success_log_period`, 0 disables). The metrics instance label (certificate
SHA-256 hex) joins the log stream; login/enrollment events carry
device/endpoint/tenant; signaling events carry the wire `RequestId` that
also appears in the TUI session view.

### Relay state gauges

`heyaki_relay_state`: 0 stopped, 1 starting, 2 running, 3 draining,
4 failed. Device side `heyaki_node_relay_state`: 0 disabled, 1 starting,
2 ready, 3 degraded, 4 failed, 5 stopped. `heyaki_node_lan_state` uses the
same six-value scale for LAN discovery.

### Relay database

SQLite file (`database_file`; default `:memory:`, which loses all state on
restart — always set a file path in production). Schema `user_version=2`,
`application_id=1213808977`. Tables: `devices` (device_id BLOB(32) primary
key, public_key, tenant, display_name, enrollment_generation, status
1=active/2=revoked, timestamps), `bootstrap_tokens` (hashed tokens with
tenant, expiry, remaining uses), `device_audit` (append-only action log),
`schema_migrations`. The journal mode is the SQLite default (rollback
journal); see backup guidance below.

### coturn

Deployed separately per `deploy/coturn/` (pinned image digest, resource
policy, REST API credential contract). The shared secret
(`HEYAKI_TURN_SECRET`, ≥16 printable ASCII characters) never enters the
repository or relay logs. TURN REST credentials are short-lived (default
600 s) and bound to device, tenant, and expiry.

### Device side

TUI commands used here: `metrics` (full Prometheus text of the local
device), session views (`request=`/`session=` correlation lines), relay
line (`cycle=`/`since=` registration anchors). Device metrics are local
diagnostics; see `deploy/observability/README.md` for fleet ingestion.

## Alert triage

Each entry maps one alert from
`deploy/observability/prometheus/heyaki-alerts.yml`: what it means, the
first action, and where to dig deeper.

### HeyakiRelayDown

Prometheus cannot scrape `/metrics` (TLS unreachable, certificate expired,
process down). First: `curl --cacert <ca> https://<relay>:8443/health`
from the Prometheus host; then check the process and listener
(`ss -ltnp | grep 8443`). If the certificate expired, see
"Rotate the relay TLS certificate" — but note the pinning constraint
below; an expired cert that devices still accept means the cert renewed
out-of-band is not the one devices pinned.

### HeyakiRelayNotRunning

Scrapes succeed but `heyaki_relay_state` is not 2 for 5 minutes (stuck
starting/draining, or failed). Check stdout logs for `server_state_changed`
and `server_error` events; a failed startup is usually a bad config
(`--check-config`), an unreadable certificate/key, or a locked database
file. `state == 3` (draining) that persists means shutdown stalled —
collect logs and restart.

### HeyakiRelayLoginFailureRate

More than 20% of login outcomes are rejections for 10 minutes (with live
login traffic). Grep logs for `login_rejected` (carries claimed device,
endpoint, tenant and a reason in `detail`): `device_revoked`-class rejections
mean a revocation is taking effect; generation mismatches point at stale
enrollment state on devices; bursts across many tenants with
`rate_limited` events suggest credential stuffing or a misbehaving fleet
pushing a bad release.

### HeyakiRelayHandshakeFailures

Over 10% of accepted TCP connections fail the TLS/WSS handshake.
Distinguish `handshake_timeout` (slowloris-style stalls; verify the
`rate_limited` log events and the `ip` rate-limit scope counters) from
`handshake_failed` (protocol/certificate problems — check for a
mid-rotation certificate mismatch between the relay and scrapers/clients).

### HeyakiRelaySignalingBackpressure

The relay drops queued control frames to sessions that stopped reading
(`signaling_backpressure_dropped_total`). One device is connected but not
draining its WSS receive loop (suspended laptop, frozen process). The relay
answers senders with endpoint_offline, so the network impact is bounded;
identify the device from `signaling_rejected` log events (request_id joins
the TUI view) and restart or wake the endpoint.

### HeyakiRelayCapacityPressure

Sustained rejections on `max_connections`, control-session, or lease-table
capacity. Check `heyaki_relay_active_sessions` against
`heyaki_relay_connection_capacity` and `heyaki_relay_lease_entries` trends
on the dashboard. If the fleet legitimately outgrew the limits, raise
`max_connections` / `lease_capacity` / `endpoint_directory_capacity` in the
config (capacity changes need a process restart) — otherwise hunt the
connection storm in the `ip`/`tenant` rate-limit gauges first.

### HeyakiLeaseTablePressure

`lease_capacity_rejected_total` increased in the last hour: the endpoint
lease table hit `lease_capacity`. Same response as capacity pressure; also
check `lease_per_device_rejected` / `lease_per_tenant_rejected` for
per-entity caps that a single misbehaving device might be exhausting.

### HeyakiRelayRateLimited

Rejections under one of the four rate-limit scopes (connection, request,
tenant, ip) persist for 15 minutes. Panel "Relay rate-limit rejections by
scope" identifies which. A dominant `ip` scope points at a single source
(scanner or stuck client); `tenant` scope at one tenant's fleet
(release bug retry-storming). The `rate_limited` log events carry the
identity; coordinate with the tenant instead of raising limits reflexively.

### HeyakiLanListenerNotReady

A device reports LAN enabled but `heyaki_node_tls_listener_ready == 0` for
5 minutes. On the device TUI check the LAN block: listen port conflicts
(another process grabbed the port), interface enumeration failures, or
firewall policy. This blocks all inbound LAN connections for that device —
relay-signaled paths remain available.

### HeyakiLanMulticastUnverified

Joined multicast groups exceed verified joins for 10 minutes: datagrams
are not round-tripping on at least one interface (switch IGMP snooping,
multicast blocked, wrong interface selection). Run the TUI `metrics`
command and compare `heyaki_node_interfaces_joined` vs
`heyaki_node_interfaces_multicast_verified`; the network matrix scripts
under `deploy/coturn/` reproduce the environment classes locally.

### HeyakiLanPresenceRejects

Continuous presence/handshake rejections on one device: hello signature
rejections, TLS handshake failures, datagram parse/policy rejects, or
directory replay/capacity rejections. Small steady counts are normal
background noise (foreign devices, scanners); a sustained climb means
either a hostile LAN neighbor or a fleet-wide identity/protocol mismatch
(check `heyaki_node_directory_conflict_rejected_total` for identity
conflicts from a re-enrolled device).

### HeyakiNodeRegistrationFailing

A device failed relay registration more than 3 times in 15 minutes
(critical: the device is off the control plane). On the device TUI RELAY
line, `cycle=` shows the attempt count and `since=` the anchor; join with
relay `login_rejected` logs by device identity + tenant + time. Common
causes: relay certificate changed (pin mismatch — see rotation), device
revoked (`device_revoked` in logs), network blocking WSS egress, or relay
capacity. Devices retry with backoff; registration recovers automatically
once the cause clears.

### HeyakiLeaseRefreshFailures

The device's heartbeat acks are missing (`lease_refresh_failures_total`,
same increment point as missed heartbeats). The control connection is
degraded while the data plane may still work. Check relay-side
`heartbeat_refreshed` sampling and connection state; sustained loss
converges to session loss and re-registration.

### HeyakiPairingPasswordGuessing

More than 5 wrong pairing passwords in 15 minutes on one device. The
pairing service rate-limits and backs off (`denied_backoff_total`) on its
own; treat sustained guessing as a security event: identify the source
from the device's pairing audit (TUI / `Node::pairing_audit_records()`
carry request IDs; the log path is end-to-end so the relay never sees it),
and rotate the authorization password if compromise is suspected.

### HeyakiQueueRejections

The device rejects or drops queued work for 10 minutes: executor submit
rejections, channel frame rejections/drops, event subscriber drops, or
callback-queue drops. Overload or a stalled consumer. The TUI QUEUES block
shows depth/capacity@peak:drop per channel. If drops concentrate on one
channel type, that service's consumer is stuck — restart the application;
if depths sit at capacity across the board, shed load (the workload
exceeds the device) rather than raising queue limits blindly.

### HeyakiRpcOverload

Over 5% of RPC calls are rejected on admission/concurrency limits (with
live call traffic). The serving device is at its concurrency budget.
`heyaki_rpc_handler_deadline_exceeded_total` climbing together means the
handlers themselves slowed (check HeyakiWorkerFailures co-firing). Callers
receive resource_exhausted errors and may retry; coordinate retries
downward or raise the service concurrency budget on the device.

### HeyakiFileIntegrityFailures

Chunk hash verification or commit failures on a device (critical: possible
data corruption). Stop relying on the affected transfers, preserve the
partial state, and re-transfer from a known-good source. Disk-level causes
(write failures co-climbing) are the common case — see "Respond to
disk-full". The transfer `TransferId` in events/TUI scopes the affected
file.

### HeyakiExecutorTaskExceptions

An executor task died from an exception within 5 minutes (critical: work
was admitted and then lost). This is a defect signal — collect the device
logs and the failing operation's correlation ID (`op <id>` in the TUI rpc
view) and file it with the workload description. The executor surfaces the
exception through its failure facilities; there is no in-process
auto-recovery for the lost task itself.

### HeyakiWorkerFailures

Service handler/callback exceptions or PTY spawn failures persist for 10
minutes. Distinct from executor task loss: handlers failed, were caught,
and were answered as remote_error. Shell spawn failures specifically point
at the restricted profile/low-privilege account setup on that device.
Recurring exceptions with the same operation shape are defect signals.

### HeyakiTurnFallbackDominant

Over half of the device's authenticated sessions ride TURN for 30 minutes.
Either the network changed (symmetric NAT, UDP blocking — legitimately
TURN-bound) or hole punching degraded. Compare with
`heyaki_connectivity_signaling_route_fallbacks_total`; check coturn
allocation load and its logs for allocation quota pressure. Expect an
uptick in relay bandwidth cost; verify the coturn quotas in
`deploy/coturn/turnserver.conf` still fit.

## Procedures

### Rotate the relay TLS certificate

**v1 pinning constraint (read first).** Devices pin the SHA-256 digest of
the relay's *entire leaf certificate* at enrollment time. Any leaf
change — including a renewal with the same key — breaks every device's
pin (`wss_tls_pin_mismatch`, visible as HeyakiNodeRegistrationFailing
fleet-wide). Plan either (a) a maintenance window plus re-enrollment of
all devices (new bootstrap token round), or (b) keep the current
certificate until a pin-migration mechanism ships. Prometheus only needs
its `ca_file` updated if the CA changes; scrapers do not pin.

Steps: place the new cert/key at the configured paths, run
`heyaki-relay --config ... --check-config`, restart the process (there is
no hot reload), verify `/health` and `/metrics`, then re-enroll devices
per the chosen plan.

### Rotate the TURN shared secret

The TURN REST credential contract keeps at most four secret generations,
so old credentials stay valid until their (≤600 s) expiry while new
issues use the latest generation. Rotation: set the new
`HEYAKI_TURN_SECRET` wherever credentials are issued and in the coturn
environment (`deploy/coturn/heyaki-turn.env.example`), restart coturn,
and let the issuer generation window retire the old secret. Never place
the secret in the repository, relay config, or logs.

### Rotate bootstrap tokens

Enrollment bootstrap tokens are stored hashed with expiry and use counts.
To retire a compromised token: stop issuing it, delete or zero its
`remaining_uses` row in `bootstrap_tokens` (relay stopped or via a
writer respecting the schema), and hand out a fresh token. Enrolled
devices are unaffected — tokens only gate new enrollments.

### Revoke a device

Revocation is a database state the relay enforces at login and (by
default) at heartbeat: status 2 rejections with `close_revoked_sessions`
true also close the revoked device's live control sessions. v1 ships no
admin CLI; the supported procedure is a direct SQLite transaction
mirroring the built-in `revoke_device` semantics (generation must
increase):

```sql
BEGIN IMMEDIATE;
UPDATE devices
   SET enrollment_generation = enrollment_generation + 1,
       status = 2,
       updated_unix_milliseconds = CAST(strftime('%s','now') AS INTEGER) * 1000
 WHERE device_id = X'<32-byte device id hex>';
INSERT INTO device_audit(device_id, action, occurred_unix_milliseconds, metadata)
VALUES (X'<same device id>', 'device_revoked',
        CAST(strftime('%s','now') AS INTEGER) * 1000, 'manual revocation');
COMMIT;
```

Take the device id hex from the relay's `login_completed`/`enrollment_completed`
log events or the `devices` table. Effects: new logins rejected
(`login_rejected` with `device_revoked`), existing sessions closed within a
heartbeat, leases reclaimed. Pair with pairing-side action on the peer
devices (revoke the TrustGrant) if the device had been granted one.

### Restart the relay

SIGTERM (or SIGINT) drains within `shutdown_timeout_milliseconds` and the
process exits 0 after printing final counters. Devices detect the loss and
reconnect with backoff (registration counters advance — a clean restart
counts no registration failures; see HeyakiNodeRegistrationFailing for the
failing variant). Verification: `heyaki_relay_state` returns to 2,
`heyaki_relay_logins_completed_total` climbs back as the fleet re-logs-in,
and device-side `cycle=` counters advance on the TUI.

### Restart coturn

Restarting coturn breaks TURN data paths for in-flight sessions; direct
paths are unaffected. Devices re-allocate on their next connection (or
via session restart). Verify with the allocation probe
(`deploy/coturn/run_allocation_probe.sh`) and watch device-side
`heyaki_connectivity_data_path_turn_*` recover. If restarts repeat,
check the total-allocation quota (100) and per-user quota (12) against
the fleet size before assuming a coturn defect.

### Back up and restore the relay database

The database uses SQLite's default rollback journal. Backup options, in
order of preference:

1. Stopped relay: copy the database file after a clean shutdown (the
   rollback journal makes mid-write copies unsafe).
2. Online: `sqlite3 -readonly <db> ".backup '<backup path>'"` — takes a
   brief read lock; login/heartbeat writes retry within the 2 s busy
   timeout. Do not copy the raw file while the relay runs.

Restore: stop the relay, replace the file, run
`sqlite3 <db> "PRAGMA quick_check(1)"` and verify `PRAGMA user_version`
equals 2, then start. Restoring loses enrollments/revocations recorded
after the backup — re-check `devices.status` for anything revoked in the
 interim window and re-apply if needed.

### Respond to disk-full

Symptoms: SQLite write errors surface as `server_error` log events and
failed logins/enrollments; device-side file transfers show
`heyaki_file_write_failures_total` climbing (HeyakiFileIntegrityFailures
co-fires). Relay: free space (rotate/compress stdout logs — they are JSON
lines and compress well), verify with `PRAGMA quick_check(1)`, and restart
if the process wedged mid-write. Devices: the file service writes to its
configured root with quota enforcement; clear space or raise the quota;
failed transfers resume from confirmed chunks after the final BLAKE3
verification. Do not delete the WAL/journal siblings of the relay
database; if a hot backup left `-journal` files, restore from the backup
instead.

### Respond to overload

Identify the layer from the dashboard: relay rate limits (four scopes) →
capacity rejects → device queue rejections → RPC admission rejections.
Short-term: shed or stagger the workload (callers receive
resource_exhausted / backpressure answers — the system fails loudly, not
silently). Configuration levers: relay `max_connections`,
`lease_capacity`, `endpoint_directory_capacity`, `signaling_rate_per_second`;
device-side service concurrency budgets and queue capacities. Change one
lever at a time and confirm against M9-10 benchmarks before making it
permanent; record the new defaults (M9-11 owns the re-freeze).

### Run a soak (long-stability) test

The M9-09 soak harness drives three boundedness proofs on one loopback
machine: session churn (a long-lived initiator cycling
dial/authenticate/message+RPC+file/disconnect against a SIGKILL-respawned
responder), discovery churn (short-lived distinct devices enrolling and
exiting against a long-lived relay), and capacity overload (a second relay
with tight `max_connections`/`endpoint_directory_capacity` limits driven past
them). The CI slice runs it on every push (`heyaki_m9_soak`, gated by
`HEYAKI_REQUIRE_M9_SOAK=1`).

Command form (from a configured build with apps built):

```bash
HEYAKI_REQUIRE_M9_SOAK=1 \
HEYAKI_SOAK_SESSION_CYCLES=<cycles> \
HEYAKI_SOAK_CHURN_PARTICIPANTS=<devices> \
HEYAKI_SOAK_OVERLOAD_PARTICIPANTS=<concurrent> \
HEYAKI_SOAK_WORK_DIR=/var/tmp/heyaki-soak-$(date +%Y%m%d-%H%M) \
tests/network/run_m9_soak_harness.sh \
  --relay-bin build/heyaki-relay \
  --matrix-bin build/heyaki-m4-matrix-node \
  --demo-bin build/heyaki-m3b-relay-demo
```

For the 24/72h acceptance runs, scale cycles so the harness runs the wanted
duration (measure the CI slice's `SOAK_SUMMARY duration_ms` per cycle and
multiply; a cycle is typically 5–20 s) — for example
`HEYAKI_SOAK_SESSION_CYCLES=12000` with `HEYAKI_SOAK_CHURN_PARTICIPANTS=500`
approximates 24 h. Keep `HEYAKI_SOAK_WORK_DIR` on a disk with a few hundred
MiB free (per-cycle inbox files accumulate by design; prune between runs).
Artifacts: the work dir (kept on failure), `SOAK_CYCLE`/`SOAK_SUMMARY` lines
from the initiator log, and the `SOAK_RELAY_SAMPLE` series from the harness
stdout — keep all three with the run record.

Pass criteria (the CI slice enforces the first block; the 24/72h analysis
adds the slopes):

- Every cycle completes its work and reaches a terminal session state;
  `SOAK_SUMMARY sessions_final=0` and `tasks_active_final=0`.
- Initiator: `fds_last ≤ fds_first + 24`, `rss_last ≤ rss_first + 32 MiB`,
  `replay_peak ≤ 256` (the per-peer replay-guard capacity).
- Relay (both instances): `active_sessions`, endpoint/lease/challenge table
  gauges within the harness bounds at every sample; RSS/fd growth gates;
  overload rejections counted (`heyaki_relay_capacity_rejected_total`,
  endpoint directory rejections) and a full drain to zero afterwards.
- 24/72h: split `SOAK_CYCLE rss_kb` and `SOAK_RELAY_SAMPLE relay_rss_kb`
  into first/second half; the median of the second half must stay within the
  same growth gates over the whole run (a leak slower than that is an M9-11
  input, not a pass).

A failing soak is triaged from the failing gate: fd growth → descriptor or
executor-backend leak on the participant; RSS growth → session/transport
book or allocator retention (compare `replay=` and `sessions=` fields);
relay-table growth → lease/endpoint TTL eviction. Re-run the failing phase
with a larger `HEYAKI_SOAK_SESSION_CYCLES` to confirm the slope before
filing.

### Roll back a version

Rollback order: relay binary first (devices tolerate an older relay
better than an older device against a newer relay schema). Before
replacing binaries: back up the database (see above) — a newer binary may
have migrated it. N-1 schema compatibility is the design target that
M9-12 verifies; if `PRAGMA user_version` exceeds what the old binary
knows, it refuses to open — restore the backup taken before the upgrade. Verify after
rollback: `/health`, `heyaki_relay_state == 2`, devices re-register
(`login_completed` events), and a spot-check TUI session. File the
rollback trigger as an M9-12 compatibility finding regardless of cause.

## Known operational gaps (v1)

- No admin CLI: revocation and bootstrap-token rotation are SQL-level
  procedures (above). An operator tool is a v1.x candidate.
- Certificate rotation forces device re-enrollment (pinning constraint);
  no pin-migration mechanism ships in v1.
- Device metrics have no resident exporter; fleet dashboards need the
  textfile/ingestion convention from `deploy/observability/README.md`.
- Loss-rate estimation is bounded by the pinned libdatachannel stats API
  (bytes/rtt only); revisit after M9-10.
