---
name: heyaki-integration
description: Integrate the Heyaki C++20 client library into an application for peer-to-peer device communication. Use when adding LAN or relay peer discovery, mutually authenticated sessions, password pairing and trust grants, messaging, unary RPC, pub-sub events, resumable file transfer, remote shell, TCP gateway tunneling with a SOCKS5 frontend, device-side relay registration or an embedded relay, or consuming the Heyaki SDK from CMake.
---

# Heyaki Integration

Use this skill as an application developer building against the Heyaki client
library. Public headers under `include/heyaki/` and the current user docs
(`docs/api.md`, `docs/client-library.md`) are authoritative. Load one router
and one card only; do not read design documents or implementation sources
unless a card sends you there.

## Route The Request

| Request contains | Read exactly this next |
| --- | --- |
| First integration, SDK install, `find_package(heyaki)`, profile store, or the first program | [Quick start](references/quick-start.md) |
| An application feature: talk to a peer, move files, open a shell, tunnel TCP | [By scenario](references/scenarios.md) |
| A requirement, constraint, or failure concern: security, bounds, platforms, shutdown | [By requirement](references/by-requirement.md) |
| A known API, type, scope, or error term | [By API](references/by-api.md) |

After a router selects a card, implement its minimal usage, preserve its
pitfalls, and build the application. Observe outcomes through the card's
named `Result`, callback, or snapshot API; never infer success from call
admission. Every fallible Heyaki API returns `Result<T>` — check it before
touching the value.

## Downstream Use

Read [adoption](references/adoption.md) only when the AI runs from a
downstream project and cannot already access this skill. Do not load Heyaki
implementation sources unless reproducing a library defect; questions about
the pinned `executor` concurrency layer itself belong to executor's own
`executor-integration` skill, not this one.
