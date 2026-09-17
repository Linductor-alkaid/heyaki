# Heyaki Documentation

This index maps each documentation area to its canonical location. Docs in
`operations/` are for people running Heyaki; docs in `design/` and
`security/` record what Heyaki is and why; `todolists/` is the engineering
delivery record.

| Area | Document |
| --- | --- |
| First steps: build, install, run a relay and a device | [getting-started.md](getting-started.md) |
| Configuration: relay config file, CLI flags, device-side config model | [configuration.md](configuration.md) |
| Production deployment: relay host, coturn, observability, fleet | [deployment.md](deployment.md) |
| Client library API reference | [api.md](api.md) |
| Troubleshooting by symptom (devices, relay, TUI) | [troubleshooting.md](troubleshooting.md) |
| Upgrade, backup, rollback, per-alert triage, soak/bench procedures | [operations/runbook.md](operations/runbook.md) |
| Frozen defaults and hard upper bounds for every tunable | [operations/parameter-freeze.md](operations/parameter-freeze.md) |
| Release artifact signing procedure | [operations/release-signing.md](operations/release-signing.md) |
| Linux/Windows test-matrix coverage and cross-OS limits | [operations/cross-os-matrix.md](operations/cross-os-matrix.md) |
| Architecture | [design/heyaki-architecture.md](design/heyaki-architecture.md) |
| Wire protocol (frozen v1 + golden vectors) | [design/heyaki-wire-protocol.md](design/heyaki-wire-protocol.md) |
| LAN serverless connectivity design | [design/lan-serverless-connectivity.md](design/lan-serverless-connectivity.md) |
| Concurrency and shutdown model | [design/concurrency-and-shutdown.md](design/concurrency-and-shutdown.md) |
| Gateway proxy service (v1.x design) | [design/gateway-service.md](design/gateway-service.md) |
| Protocol compatibility policy | [compatibility/](compatibility/) |
| Threat model | [security/threat-model.md](security/threat-model.md) |
| Dependency policy, pins, and audits | [supply-chain/dependency-policy.md](supply-chain/dependency-policy.md) |

## Keeping examples honest

Code and config samples in the user-facing docs are not prose-only:

- Every fenced block tagged `heyaki-cpp` is extracted and compiled against the
  real public headers by the `heyaki_m9_docs_examples` test, and the extracted
  programs are executed. If a sample stops compiling, CI fails.
- Every fenced block tagged `heyaki-relay-config` is loaded through the real
  `heyaki::load_relay_config_file` parser and validator by the same test.
- The `find_package(heyaki)` consumer snippet in
  [getting-started.md](getting-started.md) mirrors `tests/consumer/`, which CI
  builds and runs as `heyaki_installed_consumer`.

When editing samples, keep them inside those fenced tags so the sync tests
keep covering them.
