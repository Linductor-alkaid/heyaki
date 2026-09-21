# Gateway (TCP Tunneling, Protocol 1.3)

An authorized device A reaches TCP targets inside / behind device B's
network over the authenticated session. Default-off on both sides;
requires the `gateway_v1` capability (negotiated minor ≥ 3).

## Initiator side

```cpp
heyaki::GatewayConnect target{.host = "intranet.lan", .port = 443,
                              .profile = ""};   // empty = serving default
heyaki::NodeGatewayStreamOptions options;
options.on_connected = [](heyaki::Result<void> outcome) { /* ... */ };
auto stream = node.open_gateway_stream(peer, target, options);
```

- The stream is an ordinary `ByteStream`: the 2-byte prelude is consumed
  internally; reads begin with tunnel payload.
- `state()` stays `opening` until the serving side confirms the dial — do
  not treat the handle as connected before `on_connected` fires (exactly
  once: success, or `gateway_connect_failed_<status>` from the frozen
  refusal mapping / `cancelled` on session close).
- Scope: a live `gateway.use` grant on the session.

## Serving side

- Configure `NodeConfig::gateway_profiles` — validated at `Node::create`;
  an invalid set refuses startup. A profile carries CIDR allowlist, port
  allowlist, `allow_internet` (default false), concurrency / byte / rate
  quotas, idle and total-duration caps, dial deadline, and a confirmation
  mode (`first_use` / `always` — no-answer confirmation fails closed after
  30 s).
- A builtin deny list (loopback, link-local, multicast, CGNAT, IPv4-mapped
  ranges, tunnel endpoints) cannot be removed; domains resolve on B and
  every resolved address is checked.
- Grant `gateway.provide:<profile>`; every open re-checks live scope,
  profile allowlists, and quotas. Audit records
  (`gateway_audit_records()`) carry only grammar-validated targets.

## SOCKS5 frontend

The shipped SOCKS5 frontend turns a device into a local SOCKS5 CONNECT
proxy: loopback-only bind by default, no auth, domain targets pass through
verbatim so the serving side resolves them (split-DNS friendly). In the
product it lives in the TUI (`socks` / `socks-stop` / `socks-status`
commands, `heyaki::socks::SocksFrontend` in-tree); it is **not** in the SDK
export set. Downstream applications implement the equivalent on top of
`open_gateway_stream` — accept locally, open a gateway stream to the
requested target, pump bytes both ways.

## Pitfalls

- Path policy may forbid or rate-limit the TURN path for gateway traffic —
  surface path refusals; do not assume direct connectivity.
- A full tunnel quota fails closed: new opens are refused and counted, not
  queued silently.
