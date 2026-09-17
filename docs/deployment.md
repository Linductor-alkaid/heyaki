# Deployment

Production topology: devices talk to each other directly (WebRTC DataChannels,
P2P). A relay provides the control plane — enrollment, presence, signaling
forwarding, short-lived TURN credentials — and never sees user payloads.
coturn provides TURN relaying when hole punching fails.

```
        ┌────────────── control plane (TLS/WSS, TCP 8443) ──────────────┐
        │                                                              │
 device ─┤                                                              ├─ heyaki-relay
 device ─┤   data plane: P2P DataChannels; fallback TURN relay         │        │
 device ─┘   (UDP 3478 / TCP 3478 to coturn, allocation ports          │   SQLite DB
             49160-49200)                                               └── coturn (separate process/container)
```

## Relay host

Requirements:

- One TLS server certificate for the control listener. Devices trust the
  issuing CA; the client additionally pins the **leaf certificate** by full
  SHA-256 when configured (`RelayNodeConfig.relay_pin`) — rotation must
  follow the runbook procedure
  ([operations/runbook.md](operations/runbook.md#rotate-the-relay-tls-certificate)).
- TCP port 8443 (or your `listen_port`) reachable from all devices; that one
  listener serves control traffic, `GET /health`, and `GET /metrics`.
- A persistent `database_file` path on a volume with headroom; enrollment and
  audit state live there (default `:memory:` is for tests only).
- Linux is the CI-verified server platform; Windows runs the relay for
  development (see [operations/cross-os-matrix.md](operations/cross-os-matrix.md)).

Minimal systemd unit (`/etc/systemd/system/heyaki-relay.service`):

```ini
[Unit]
Description=Heyaki relay
After=network-online.target
Wants=network-online.target

[Service]
User=heyaki
Group=heyaki
WorkingDirectory=/var/lib/heyaki
ExecStart=/opt/heyaki/bin/heyaki-relay --config /etc/heyaki/relay.conf
ExecStartPre=/opt/heyaki/bin/heyaki-relay --config /etc/heyaki/relay.conf --check-config
Restart=on-failure
RestartSec=2
# Hardening (adjust to your environment)
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/heyaki
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

The relay logs JSON lines to stdout (16 event kinds; successes sampled per
`success_log_period`). Ship stdout with your log collector; the metrics
instance label (relay certificate SHA-256) joins the log stream to the
Prometheus series. Enrollment needs bootstrap tokens: create them through the
relay database API (`RelayDatabase::create_bootstrap_token`, shown in
`apps/demo/m3b_relay_demo.cpp`); tokens are stored hashed with expiry and use
counts, and rotation is a runbook procedure.

## coturn

Deploy per [deploy/coturn/](../deploy/coturn/): a digest-pinned container
image (authoritative) or the recorded distro fallback package, the baseline
`turnserver.conf`, and `HEYAKI_TURN_SECRET` injected by the deployment
environment. Ports: UDP/TCP 3478 (+TLS 5349 for non-heyaki TURN clients),
allocation range 49160-49200. Heyaki clients use TURN/UDP on the default
`juice` ICE backend and TURN/UDP+TCP on `nice` builds; `turns:` is rejected
by all backends (no pinned ICE stack implements TURN/TLS — see
[cross-os-matrix.md](operations/cross-os-matrix.md)). The credential
contract (short-lived REST credentials bound to device+tenant+expiry) and
the four-secret rotation window are documented in
[deploy/coturn/README.md](../deploy/coturn/README.md) and the runbook.

## Observability

[deploy/observability/](../deploy/observability/) ships the reference stack:
Prometheus scrape config for relay `/metrics`, 8 SLO recording rules, 20
alerts (relay-fleet and device groups), and a 24-panel Grafana dashboard.
Rules and panels reference only metric families the exporters actually emit —
CI enforces this. Devices export Prometheus text on demand (TUI `metrics`
command or `format_node_metrics_prometheus`); fleet ingestion is a deployment
convention (textfile collector or push bridge) because devices sit behind
NAT. Alert triage and the per-alert runbook anchors are in
[operations/runbook.md](operations/runbook.md#alert-triage).

## Device fleet

- **Initialize once**: first run of `heyaki-tui` (or `ProfileStore::create`)
  creates the device identity in the per-user profile store.
- **Enroll**: the operator hands a bootstrap token + the relay CA to each
  device; enrollment is one interaction, afterwards devices log in
  automatically per generation.
- **Pairing**: cross-tenant trust is established by password pairing between
  devices (signed TrustGrants, scope-intersection policy). LAN-only fleets
  never need a relay for trust either.
- **Firewall**: LAN discovery needs inbound/outbound UDP 49189 multicast
  (IPv4 group `239.192.72.89`, IPv6 `ff12::4845:5941:4b49`, hop limit 1) plus
  the LAN TLS signaling listener on the announced interfaces; the Windows
  firewall procedure is in the runbook quick reference and
  [operations/cross-os-matrix.md](operations/cross-os-matrix.md).

## Upgrade, backup, rollback

These are operator procedures with CI-verified anchors — do not improvise:

| Task | Procedure |
| --- | --- |
| Upgrade the relay (schema migration) | [Roll a relay upgrade](operations/runbook.md#roll-a-relay-upgrade) |
| Back up / restore the SQLite database | [Back up and restore the relay database](operations/runbook.md#back-up-and-restore-the-relay-database) |
| Roll back a version | [Roll back a version](operations/runbook.md#roll-back-a-version) |
| Rotate relay TLS certificate | [Rotate the relay TLS certificate](operations/runbook.md#rotate-the-relay-tls-certificate) |
| Rotate the TURN shared secret | [Rotate the TURN shared secret](operations/runbook.md#rotate-the-turn-shared-secret) |
| Revoke a device | [Revoke a device](operations/runbook.md#revoke-a-device) |
| Disk-full response | [Respond to disk-full](operations/runbook.md#respond-to-disk-full) |
| Overload response | [Respond to overload](operations/runbook.md#respond-to-overload) |

Compatibility rules that govern upgrades: same protocol major required,
relay schema only moves forward (`schema_too_new` on a downgrade is the
rollback boundary), N-1 devices interoperate (see
[api.md](api.md#protocol-compatibility) and the M9-12 compat suite).

## Packaged artifacts

`cmake --install` produces the layout the packaged release builds on:

```
<prefix>/
├── bin/          heyaki-relay, heyaki-tui, demos, helpers
├── lib/          client libraries + CMake package (heyaki::core/profile/…)
├── include/      public headers
└── share/heyaki/
    ├── proto/                wire schema sources
    ├── coturn/               example turnserver.conf, compose file, env template
    ├── licenses/             third-party license texts (+ LGPL notice on nice builds)
    └── supply-chain/         SBOM, license manifest, notices
```

The release flow (`scripts/package_release.sh`) installs into a clean prefix,
asserts that inventory, splits debug symbols into a companion `-dbg` tarball,
verifies the stripped binaries still run, and verifies the manifest-driven
uninstall leaves the prefix empty; signing the tarball set with
`heyaki-release-sign` is the separate operator procedure in
[operations/release-signing.md](operations/release-signing.md). `cmake
--build <dir> --target uninstall` performs the same removal interactively.
The whole packaging flow runs as the `heyaki_m9_package` CTest (CI
supply-chain job).
