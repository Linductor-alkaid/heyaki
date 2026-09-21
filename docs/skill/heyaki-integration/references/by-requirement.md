# Index By Requirement

| Requirement or concern | Read |
| --- | --- |
| Who may connect and what they may do (default-deny, scopes, grants) | [Pairing and trust](pairing-and-trust.md) |
| Overload behavior: bounded queues, admission errors, backpressure, no silent loss | [Node lifecycle](node-lifecycle.md) |
| Clean shutdown and drain of a running node | [Node lifecycle](node-lifecycle.md) |
| Cross-platform support: Linux/Windows, Ubuntu 20.04 baseline, DLL/lib layout | [Quick start](quick-start.md) and [client-library.md](../../../client-library.md) |
| Protocol compatibility: N-1 interop, version negotiation, upgrade safety | [Public API coverage](public-api-coverage.md) |
| Observability / SLO integration | [Observability](observability.md) |
| Build, configure, link, or runtime failures | [Troubleshooting](troubleshooting.md) |
| Verify downloaded release artifacts (signed manifests) | [Troubleshooting](troubleshooting.md) |
| Harden or audit the trust model beyond pairing | [Pairing and trust](pairing-and-trust.md) and [threat model](../../../security/threat-model.md) |

Each row names the card that owns the concern; do not load adjacent cards
until the first one fails to answer the question.
