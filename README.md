<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/icon/heyaki-transparent.png">
    <img src="docs/icon/heyaki.png" width="220" alt="Heyaki logo">
  </picture>
</p>

# Heyaki

[![CI](https://github.com/Linductor-alkaid/heyaki/actions/workflows/ci.yml/badge.svg)](https://github.com/Linductor-alkaid/heyaki/actions/workflows/ci.yml)

Heyaki is a C++20 device-to-device communication infrastructure. Devices discover each other
on a LAN, exchange signed signaling, and establish mutually authenticated sessions over
WebRTC DataChannels. When peers are on different networks, a relay provides the control plane
— enrollment, presence, signaling forwarding, and short-lived TURN credentials — while user
data stays peer-to-peer. All concurrency is centralized through the pinned
[`executor`](AGENTS.md) dependency.

## Status

The engineering baseline (M0), protocol and crypto layer (M1), runtime and identity (M2),
LAN serverless connectivity (M3A), relay control plane (M3B), and connectivity MVP (M4)
milestones are complete; the CI network matrix — leak enumeration plus coturn topologies
(direct / forced TURN / TURN-fallback P95 / UDP-blocked / lossy / relay restart) — finished
with MATRIX_OK. M5 (Authorization & ByteStream) is closed (2026-08-28): default-deny
session authorization, password pairing with signed TrustGrants, weighted channel
scheduling, and ByteStream delivery. M6 (Message & unary RPC) is closed (2026-08-29):
a message service (`best_effort`/`peer_acked` with bounded TTL dedup), unary RPC
(registry, deadlines, cooperative cancellation, at-most-once result caching,
`outcome_unknown` semantics), Node public APIs, TUI message/RPC views, and a semantics
demo (`apps/demo/m6_message_rpc_demo.cpp`). See the
[implementation plan](docs/todolists/heyaki-implementation-plan.md) for details.
M7 (Remote events & file transfer) is closed (2026-08-31): a publisher-direct event
bus (exact/segment-prefix topics, per-subscriber bounded staging with
keep-latest or reliable-live QoS, observable overwrite/drop/stale/lag), an explicit
executor::comm Topic bridge at the device boundary, and a resumable file protocol
(manifest → accept-with-bitmap → bounded-window chunks → BLAKE3 verify → fsync →
atomic rename) with root mapping, quotas, symlink-race-resistant staging, pause/
cancel/resume by transfer id, and pull riding the frozen unary-RPC surface. Node
public APIs, TUI event/file views, and the semantics demo
(`apps/demo/m7_data_demo.cpp`) ship with it.
M8 (Remote Shell) is code-complete (2026-09-03): a default-off shell service with locally
configured profiles (`ShellProfileConfig`: fixed program, OS user, working directory, env
allowlist, timeouts, caps), live `shell.open:<profile>` scope and per-profile concurrency
checks, the full frozen shell frame family with a per-shell state machine, a third
executor-managed blocking worker owning every child process (POSIX forkpty/process group,
Windows ConPTY/job object) with a TERM→grace→kill escalation ladder, idle/absolute/output
caps and bounded stdin, content-free audit records, a first-party safe-subset VT renderer
(OSC/clipboard/title and unknown sequences dropped, SGR degraded, UTF-8 validated), Node
public APIs, and a TUI `shell` view. Production enablement is gated on the independent
security review sign-off — v1 stays compiled but disabled by default. See the
[M8 milestone file](docs/todolists/m8-remote-shell.md) for the delivery record.


| Milestone | Scope | State |
| --- | --- | --- |
| M0 | Engineering baseline, CI, dependency locks, supply chain | Done |
| M1 | Wire protocol, signing, security primitives | Done |
| M2 | Runtime, ProfileStore, identity, secret backend | Done |
| M3A | LAN serverless discovery and connectivity | Done |
| M3B | Relay control plane, coturn integration | Done |
| M4 | Connectivity MVP (WebRTC sessions, dual routing, session restart, TUI) | Done |
| M5 | Session authorization, pairing/trust, channel scheduling, ByteStream | Done |
| M6 | Message service and unary RPC | Done |
| M7 | Remote events (best_effort_latest / reliable_live) and resumable file transfer | Done |
| M8 | Remote shell (default-off, executor PTY worker, safe VT renderer, TUI shell view) | Done — pending security review for production enable |
| M9 | Production hardening | Planned |
| M10 | Gateway proxy service (scoped L4 gateway over an authorized session, protocol 1.3) | Planned |
| M11 | Android (NDK) port | Planned |

## Features

- LAN UDP multicast discovery with signed presence, plus a TLS LAN signaling route.
- Relay control plane over WebSocket Secure: enrollment, login, leases, endpoint directory,
  and signaling forwarding. The relay never decodes signaling payloads.
- Short-lived TURN REST credentials (HMAC-SHA1, coturn REST API).
- Signed offer/answer/candidate signaling (`heyaki.offer.v1` / `answer.v1` / `candidate.v1`)
  with replay protection.
- WebRTC DataChannel transport via pinned libdatachannel, parallel ICE gathering, and a
  `PeerPathPolicy` supporting `lan_only`, `relay_only`, and automatic routing with endpoint
  deduplication across LAN and relay routes.
- Signed `heyaki.session-hello.v1` mutual authentication binding the session to verified
  signaling, with default-deny per-session authorization, password pairing, and signed
  TrustGrants (`heyaki.trust-grant.v1`).
- Authorized byte streams over negotiated channels with weighted scheduling and initial
  window credit.
- A message service (`MessageEnvelope`, `best_effort`/`peer_acked` delivery, bounded TTL
  dedup) and unary RPC (per-method scope/policy, relative deadlines, cooperative
  cancellation, at-most-once result caching, `outcome_unknown` on interrupted
  non-idempotent calls) exposed through the `heyaki::Node` public API.
- A default-off Remote Shell service: locally configured profiles, live
  `shell.open:<profile>` scope checks, an executor-managed PTY worker per node owning every
  child (process-tree termination escalation, idle/absolute/output caps, bounded stdin), a
  content-free audit trail, and a safe-subset VT renderer so remote bytes never reach the
  host terminal unfiltered.
- Bounded backpressure and lifecycle observability through executor facilities.
- An FTXUI diagnostics TUI showing endpoints by route, session state, RTT, buffered bytes,
  structured failures, pairing/trust management, message/RPC, event/file, and shell views.

## Components

| Target | Kind | Description |
| --- | --- | --- |
| `heyaki-relay` | App | Relay server: config, SQLite persistence, enrollment/login, leases, endpoint directory, rate limiting, TURN credentials, WSS signaling forwarding |
| `heyaki-tui` | App | FTXUI terminal client: profile setup, pairing/trust, device/endpoint/session/stream views, message and RPC views, `connect`/`close` REPL |
| `heyaki-m2-profile-demo`, `heyaki-m3b-relay-demo`, `heyaki-m6-message-rpc-demo` | Apps | Small demos of the profile store, relay enrollment, and message/RPC semantics (admission vs. completion vs. ACK vs. `outcome_unknown`) |
| `heyaki_core` | Library | Public types, wire protocol, canonical signing, signaling/session protocols, replay cache, identity, limits |
| `heyaki_client` | Library | `heyaki::Node` connection assembly: discovery, signaling coordinator, `PeerSession`, LAN directory, relay enrollment, runtime, authorization/byte-stream, message/unary-RPC/event/file services, and the default-off remote shell service with its executor-managed PTY worker |
| `heyaki_profile` | Library | `ProfileStore` (SQLite), Argon2id password hashing, secret backend |
| `heyaki_transport_webrtc` | Library | `WebRtcTransportSession` wrapping pinned libdatachannel |
| `heyaki_relay` | Library | Relay server implementation behind `heyaki-relay` |
| `heyaki_services` | Library | Placeholder for future business services; the M5–M8 pairing, byte-stream, message/RPC, event/file, and shell services live in `heyaki_client` |

## Build

Configure and build with a preset:

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

By default, CMake synchronizes missing or outdated repositories from
`third_party/dependencies.lock` during configuration, verifies their exact commits, and
installs the resulting artifacts into `build/debug/install`. The `heyaki-deploy` target is
part of the normal build, so no separate dependency or install command is required for a
local deployment. To choose another install directory, pass
`-DHEYAKI_INSTALL_PREFIX=/path/to/install` when configuring.

`release`, `asan`, `ubsan`, and `tsan` presets provide the matching build and test entry
points. The build fails with an actionable dependency command when a selected runtime, test,
or optional checkout is absent or no longer matches its locked commit.

For offline or CI builds where dependencies must already be present, configure with
`-DHEYAKI_FETCH_DEPENDENCIES=OFF`; CMake will perform check-only verification. Disable
automatic installation with `-DHEYAKI_AUTO_INSTALL=OFF` when an external packaging step
owns the install tree.

Requirements: CMake ≥ 3.25, a C++20 toolchain, and system OpenSSL ≥ 3.0 (< 4.0). Linux
(GCC 13.3 / Clang) and Windows (MSVC) are supported; all other dependencies (executor,
libdatachannel, libsodium, protobuf, abseil, sqlite, boost subset, FTXUI, …) are pinned in
`third_party/dependencies.lock` and fetched automatically by CMake.

Notable CMake options: `HEYAKI_BUILD_APPS` (default ON), `HEYAKI_FETCH_DEPENDENCIES`
(default ON), `HEYAKI_AUTO_INSTALL` (default ON), `HEYAKI_BUILD_FUZZERS` (Clang),
`HEYAKI_ENABLE_EXCEPTIONS` (a no-exceptions build is supported), `HEYAKI_WARNINGS_AS_ERRORS`,
`HEYAKI_ENABLE_CLANG_TIDY`, and `HEYAKI_REQUIRE_SANITIZER_RUNTIME`.

Generated protocol files, test profiles and credentials, and fuzz corpora are constrained to
the build tree. `cmake --build build/debug --target heyaki-sbom` regenerates the SPDX
inventory and license manifest from the lock files.

## Testing

`ctest --preset <preset>` runs the unit and integration suites (signaling, session hello,
peer session, WebRTC transport, relay route, path policy, TUI setup, per-milestone service
suites including the M8 shell/PTY-lifecycle and VT-renderer tests) plus script harnesses
for network topologies, relay onboarding, TUI session establishment, and the pinned coturn
deployment. coturn-dependent checks are skipped automatically when the required environment
is not present. Performance tests include session-establishment P95 budgets.

## Documentation

- [Architecture](docs/design/heyaki-architecture.md)
- [Wire Protocol v1](docs/design/heyaki-wire-protocol.md)
- [LAN serverless connectivity](docs/design/lan-serverless-connectivity.md)
- [Gateway proxy service](docs/design/gateway-service.md)
- [Concurrency and shutdown](docs/design/concurrency-and-shutdown.md)
- [Threat model](docs/security/threat-model.md)
- [Implementation plan and milestones](docs/todolists/heyaki-implementation-plan.md)
- [Dependency policy and supply chain](docs/supply-chain/dependency-policy.md)
- [libdatachannel v0.23.2 compatibility](docs/compatibility/libdatachannel-v0.23.2.md)
- [Product defaults (decisions)](docs/decisions/m0-product-defaults.md)
- [coturn deployment](deploy/coturn/README.md)
- [Protocol schema policy](proto/README.md)

Logo assets live in [`docs/icon/`](docs/icon/).
