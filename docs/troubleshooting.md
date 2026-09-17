# Troubleshooting

Symptom-first diagnosis for devices, sessions, and relays. For alert-driven
operations (per-Prometheus-alert triage) use the
[runbook](operations/runbook.md#alert-triage); this page is for interactive
debugging.

## Collect diagnostics first

- **Device (TUI)**: the status view (`--status` or in-app) shows relay state
  (`cycle=`/`since=` registration anchors), LAN readiness, and the SESSIONS
  block (`request=`/`session=` correlation ids that join relay logs). The
  `metrics` command prints the full Prometheus text (~200 families); the
  QUEUES block shows per-channel depth/capacity/drop counters.
- **Relay**: `GET /metrics` on the control listener (TLS trust required) and
  the JSON-lines log on stdout. The metrics `instance` label (relay
  certificate SHA-256) joins log lines to series; signaling events carry the
  same `request_id` the TUI shows.
- **State gauges**: `heyaki_relay_state` 0 stopped/1 starting/2 running/3
  draining/4 failed; `heyaki_node_relay_state` 0 disabled/1 starting/2 ready/
  3 degraded/4 failed/5 stopped; `heyaki_node_lan_state` same six-value scale.

## Discovery (LAN)

| Symptom | Likely causes | What to check |
| --- | --- | --- |
| No LAN peers appear at all | Multicast UDP 49189 blocked (firewall/VPN/middlebox); no multicast-capable interface | TUI DEVICE view empty; `heyaki_node_lan_state`; the m3a network harness reproduces blocked-multicast topologies |
| Peers appear one direction only | Asymmetric firewall on the discovery socket; interface binding picked different NICs | `endpoints()` on both sides; interface_preferences in the LAN configuration |
| Peers appear but signaling fails | LAN TLS listener blocked or the announced address is unroutable (multi-NIC) | `signaling_connections()` snapshots carry the per-connection error; `handshake_failed`/`hello_rejected` counters |
| Peers flicker in and out | Wireless roaming/interface changes | Presence lease (default 15 s) vs actual reachability; `restart_session` counters — in-place restart on interface change is automatic (protocol ≥1.2) |

Multicast uses hop limit 1: discovery never crosses routers — that is by
design, not a bug.

## Pairing and trust

| Symptom | Likely causes | What to check |
| --- | --- | --- |
| Correct password still denied | Backoff window active after repeated failures (per-source exponential, capped) | `pairing_audit_records()` shows denied events with the wire RequestId; wait out the window — the target's TUI pairing view shows it |
| Granted fewer scopes than requested | Scope intersection policy — you get `requested ∩ target policy` | Session snapshot `authorized_scopes`; this is the security model, not a failure |
| Peer stuck in PairingRestricted | No successful pairing yet; grant expired (TTL) | Trust grants list (`trust_grants_for`); re-pair or re-issue |
| Grant works for files but not shell | Missing live `shell.open:<profile>` scope | Scopes are per-domain; request the specific shell scope |

Passwords never appear in logs, audit records, or metrics (only attempt
outcomes and ids).

## Sessions and paths

| Symptom | Likely causes | What to check |
| --- | --- | --- |
| Session falls back to TURN (`turn_udp`) in an office LAN | Hole punching blocked — symmetric NAT, VPN, or inter-client forwarding denied | `data_path` in the session snapshot; this is expected behavior, `direct_*` requires an open path |
| Connect fails with `attempt_expired` | Signaling delivered but no usable candidate pair (UDP blocked and no TURN) | Path policy (STUN/TURN servers configured?); with UDP fully blocked you need TURN/TCP (`nice` backend builds) |
| `handshake_failed` immediately | Protocol/capability mismatch (major version), or identity mismatch | Error detail names it; compat suite defines the handshake-time rejections |
| Session drops ~80 s after killing the peer (libnice builds) | libnice consent-freshness upstream defect — dead-peer detection degrades to keepalive (~50 s + margin) | Known limitation (M9-19); libjuice builds close in ~30 s |
| Restart frames ignored on older peers | Session negotiated < 1.2 — restart capability not negotiated | `restart_capability_not_negotiated` on send, counted-and-ignored on receive; by design |

## Relay (device side)

| Symptom | Likely causes | What to check |
| --- | --- | --- |
| `registration_failures` climbing | Relay unreachable (network/TLS), leaf pin mismatch, database issues on the relay | Relay logs `login_rejected`/`handshake_failed` with claimed identity; pin = full SHA-256 of the **leaf** certificate — rotation must follow the runbook |
| Login rejected after re-enrollment confusion | Enrollment generation mismatch | `login_rejected` detail; devices re-enroll per generation |
| Frequent reconnects behind shared NAT | Per-IP rate limit (32/s) shared across all devices behind one egress | `rate_limited` in relay logs; deployment observation item — raise via struct policy on constrained fleets |
| Endpoint queries return nothing | Peer's lease expired (heartbeat missed) | Lease/endpoint gauges on relay `/metrics`; `lease_refresh_failures` on the device |

## Files and shell

| Symptom | Likely causes | What to check |
| --- | --- | --- |
| Push rejected instantly | Logical name failed grammar, root not in the receiver's allowlist, or per-peer quota exceeded | Error detail (`file.*`); receive roots are explicit — senders cannot pick paths |
| Transfer pauses when the session drops | By design: resumable by TransferId when the session returns | `file_transfers()` summaries; resume survives session loss |
| `complete_early` rejection | Peer bug or protocol mismatch on chunk accounting | Should not reproduce on v1 (guarded by regression tests) — capture both sides' logs |
| Shell open refused | Serving side has no profiles configured (default off) or scope missing | `shell.open:<profile>` scope + profile exists on the serving node |
| Shell echo feels slow (~300 ms p50) | PTY output drains on a 500 ms maintenance tick (design) | Not a regression; frozen as a v1 parameter with a v1.x event-driven candidate |

## Relay operations

| Symptom | Likely causes | What to check |
| --- | --- | --- |
| `connection_capacity_rejected` | `max_connections` reached | Capacity gauges; raise within frozen bounds (parameter-freeze) |
| Log/metrics stop after disk fills | SQLite write failures (`storage` errors) | Runbook disk-full procedure; committed transactions are preserved, failures roll back |
| `/metrics` connection refused by scraper | Scrape must trust the relay TLS certificate | Scrape config example in `deploy/observability/`; /metrics has no client auth beyond TLS (known accepted gap) |
| JSON log volume high | Success-event sampling period | `success_log_period` (first + every Nth per kind; 0 disables sampled kinds) |
| Relay exits on start | Config invalid or cert files missing | `--check-config`; error details are stable strings (`relay_config_*`) |

## Platform notes

- **Windows**: WFP exempts loopback — "block UDP" firewall rules on the same
  machine cannot break same-host TURN servers, so UDP-blocked scenarios need
  separate hosts or the Linux CI matrices (see
  [cross-os-matrix.md](operations/cross-os-matrix.md)).
- **TURN/TLS**: `turns:` servers are rejected by every backend — no pinned
  ICE stack implements TURN/TLS (`turn_tls_backend_not_verified`). Use
  TURN/UDP (default builds) or TURN/TCP (`nice` builds).
- **Cross-OS pairs**: GitHub-hosted runners cannot host true cross-machine
  Linux↔Windows pairs; self-hosted fleet procedures are in
  [cross-os-matrix.md](operations/cross-os-matrix.md).
