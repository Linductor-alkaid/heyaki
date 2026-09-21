# Relay

The relay is the control plane only: enrollment, presence, and signed
signaling forwarding. Payload never rides it — direct or TURN-relayed
WebRTC DataChannels carry the data plane.

## Device side (registration)

`RelayNodeConfig` — set via `NodeConfig::relay_override` or the profile's
relay settings — selects the relay: URL, optional leaf pin (full SHA-256 of
the relay's leaf certificate), tenant, CA file, and timing / backoff /
queue knobs.

- Enrollment (bootstrap token → device identity registered) happens once
  per generation through the enrollment client; afterwards login is
  automatic.
- TURN/STUN servers are **configured by the application** on the node's
  path policy (`NodeIceServer`: kind, hostname, port, username,
  credential). When the operator runs coturn with `use-auth-secret`, the
  application mints the short-lived REST credential itself from the shared
  secret — `apps/demo/m4_matrix_node.cpp` shows the exact derivation
  (username `expiry:tenant:deviceId`, HMAC-SHA1 password). Login does not
  carry TURN credentials over the control plane in v1.

## Hosting a relay

Downstream, the relay is the shipped `heyaki-relay` executable run with a
validated `key = value` config file — `heyaki-relay --config <file>`. The
`RelayServer`/`RelayDatabase` sources (`heyaki::relay`) build the binary
inside the Heyaki tree but are **not** part of the SDK export set. The
operational surface of a deployed relay:

- `/metrics` Prometheus endpoint and structured JSON Lines logs.
- SQLite database; schema migrations are forward-only — a downgraded relay
  refuses to open a newer schema (`schema_too_new` is the rollback
  boundary).
- Deployment guide (TLS, coturn digest pinning, backups, rotation):
  [deployment.md](../../../deployment.md) and the
  [runbook](../../../operations/runbook.md).

## Pitfalls

- A relay rollback does not strand enrolled devices: N-1 interop is
  guaranteed by the compat suite. Plan roll-forward, not re-enrollment.
- The relay's per-IP rate limit can trip on shared-egress NATs — size
  fleets accordingly.
