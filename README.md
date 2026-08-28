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
LAN serverless connectivity (M3A), and relay control plane (M3B) milestones are complete.
M4 (Connectivity MVP) is closed (2026-08-27): authenticated WebRTC sessions, LAN/relay
dual-route arbitration, path diagnostics, the TUI selection flow, and protocol-1.2 session
restart (a signed renegotiation of a replacement transport over the authenticated control
channel) are in place. All 17 milestone tasks and exit criteria are complete, and the CI
network matrix — leak enumeration plus coturn topologies (direct / forced TURN /
TURN-fallback P95 / UDP-blocked / lossy / relay restart) — finished with MATRIX_OK. See the [implementation plan](docs/todolists/heyaki-implementation-plan.md)
for details.

| Milestone | Scope | State |
| --- | --- | --- |
| M0 | Engineering baseline, CI, dependency locks, supply chain | Done |
| M1 | Wire protocol, signing, security primitives | Done |
| M2 | Runtime, ProfileStore, identity, secret backend | Done |
| M3A | LAN serverless discovery and connectivity | Done |
| M3B | Relay control plane, coturn integration | Done |
| M4 | Connectivity MVP (WebRTC sessions, dual routing, session restart, TUI) | Done |
| M5–M9 | Authorization/byte-stream, message RPC, event & file transfer, remote shell, production hardening | Planned |
| M10 | Gateway proxy service (scoped L4 gateway over an authorized session, protocol 1.3) | Planned |

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
  signaling.
- Bounded backpressure and lifecycle observability through executor facilities.
- An FTXUI diagnostics TUI showing endpoints by route, session state, RTT, buffered bytes,
  and structured failures.

## Components

| Target | Kind | Description |
| --- | --- | --- |
| `heyaki-relay` | App | Relay server: config, SQLite persistence, enrollment/login, leases, endpoint directory, rate limiting, TURN credentials, WSS signaling forwarding |
| `heyaki-tui` | App | FTXUI terminal client: profile setup, device/endpoint/session views, `connect`/`close` REPL |
| `heyaki-m2-profile-demo`, `heyaki-m3b-relay-demo` | Apps | Small demos of the profile store and relay enrollment flows |
| `heyaki_core` | Library | Public types, wire protocol, canonical signing, signaling/session protocols, replay cache, identity, limits |
| `heyaki_client` | Library | `heyaki::Node` connection assembly: discovery, signaling coordinator, `PeerSession`, LAN directory, relay enrollment, runtime |
| `heyaki_profile` | Library | `ProfileStore` (SQLite), Argon2id password hashing, secret backend |
| `heyaki_transport_webrtc` | Library | `WebRtcTransportSession` wrapping pinned libdatachannel |
| `heyaki_relay` | Library | Relay server implementation behind `heyaki-relay` |
| `heyaki_services` | Library | Placeholder for business services (M5+) |

## Build

Fetch and verify the pinned source dependencies, then use a preset:

```sh
scripts/fetch_third_party.sh --with-tests
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

`release`, `asan`, `ubsan`, and `tsan` presets provide the matching build and test entry
points. The build fails with an actionable dependency command when a selected runtime, test,
or optional checkout is absent or no longer matches its locked commit.

Requirements: CMake ≥ 3.25, a C++20 toolchain, and system OpenSSL ≥ 3.0 (< 4.0). Linux
(GCC 13.3 / Clang) and Windows (MSVC) are supported; all other dependencies (executor,
libdatachannel, libsodium, protobuf, abseil, sqlite, boost subset, FTXUI, …) are pinned in
`third_party/dependencies.lock` and fetched by `scripts/fetch_third_party.sh`.

Notable CMake options: `HEYAKI_BUILD_APPS` (default ON), `HEYAKI_BUILD_FUZZERS` (Clang),
`HEYAKI_ENABLE_EXCEPTIONS` (a no-exceptions build is supported), `HEYAKI_WARNINGS_AS_ERRORS`,
`HEYAKI_ENABLE_CLANG_TIDY`, and `HEYAKI_REQUIRE_SANITIZER_RUNTIME`.

Generated protocol files, test profiles and credentials, and fuzz corpora are constrained to
the build tree. `cmake --build build/debug --target heyaki-sbom` regenerates the SPDX
inventory and license manifest from the lock files.

## Testing

`ctest --preset <preset>` runs the unit and integration suites (signaling, session hello,
peer session, WebRTC transport, relay route, path policy, TUI setup) plus script harnesses
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
