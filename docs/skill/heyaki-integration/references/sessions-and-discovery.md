# Sessions And Discovery

## Discovery

- `endpoints()` — merged LAN + relay directory. Each
  `EndpointDirectoryEntrySnapshot` says which plane the entry came from.
  Same-LAN peers appear with no infrastructure at all; remote peers appear
  once both sides are registered with a relay.
- `refresh_interfaces()` — re-scan network interfaces without a restart
  (Wi-Fi ↔ ethernet switches); session restarts are triggered automatically
  on interface changes.

## Connecting

- `connect(peer)` — automatic mode: prefer the LAN endpoint, fall back to
  relay signaling. `connect_lan(peer)` — LAN only.
- Both return after **admission**. The terminal state arrives through the
  session change handler or `peer_sessions()`; do not treat a returned
  handle as a connected session.
- `peer_sessions()` — live snapshots: state, connection stage, negotiated
  `data_path` (`direct_host` / `direct_srflx` / `turn_udp` / `turn_tcp`),
  RTT, buffered amount, authorized scopes, transport byte counters, and the
  wire RequestId/SessionId used for cross-log correlation.
- `restart_session(peer)` — protocol-1.2 in-place transport restart (same
  SessionId, bumped epoch), used for path failover.

## Pitfalls

- Unknown peers always land in `PairingRestricted` first (default-deny);
  they authenticate straight into `Authorized` only after pairing. Read
  [pairing and trust](pairing-and-trust.md) before expecting sessions to
  authorize.
- A relay is control-plane only: presence and signaling. Payload never
  rides it — direct or TURN-relayed WebRTC DataChannels carry the data
  plane.
- TURN/STUN servers are configured by the application (`NodeIceServer` on
  the node's path policy); login does not deliver TURN credentials over
  the control plane. See [relay](relay.md) for the credential derivation
  pattern.

## Next

Once a session is `Authorized`, pick a service card from
[scenarios](scenarios.md).
