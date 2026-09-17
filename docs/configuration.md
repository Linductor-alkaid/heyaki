# Configuration

Heyaki has two configuration surfaces:

- **Relay** (`heyaki-relay`): a key/value config file plus CLI overrides.
  This page is the complete reference.
- **Device side** (client library, TUI): configuration is a code-level API —
  plain structs with defaults, validated by `validate_config` and friends.
  The TUI persists only the profile store; it has no extra config file.

Every default and its hard upper bound is frozen in
[operations/parameter-freeze.md](operations/parameter-freeze.md) with the
measurement that justifies it. Changing a default is a coordinated change to
that document, the validators, and the `heyaki_m9_parameter_freeze` test.

## Relay configuration file

Passed with `--config <path>`. Format: UTF-8/ASCII, one `key = value` per
line, `#` starts a comment, keys must be unique, values are plain tokens
(booleans are `true`/`false`, durations are milliseconds as integers). The
file is capped at 64 KiB. Paths are resolved relative to the config file's
directory, so a config under `/etc/heyaki/relay.conf` with
`tls_certificate_file = certs/relay.crt` reads
`/etc/heyaki/certs/relay.crt` — pass absolute paths or place the config
accordingly. The TLS certificate and private key files must exist at load
time (`--check-config` verifies this too).

All keys, defaults, and accepted ranges:

| Key | Default | Constraint | Meaning |
| --- | --- | --- | --- |
| `listen_address` | `0.0.0.0` | printable ASCII, ≤253 chars, no whitespace | TLS control listener bind address |
| `listen_port` | `8443` | 1–65535 (0 is only legal via the struct API for OS-assigned ports) | TLS control listener port |
| `tls_certificate_file` | required | must exist | Leaf certificate PEM (SAN must match what devices connect to) |
| `tls_private_key_file` | required | must exist | Private key PEM for the leaf |
| `database_file` | `:memory:` | non-empty; use a file path in production | SQLite database (`:memory:` loses all state on restart) |
| `health_path` | `/health` | starts with `/`, ≤128 chars, no `?`/`#`/space, ≠ control path, ≠ `metrics_path` | Plain-HTTP liveness path on the TLS listener |
| `metrics_path` | `/metrics` | same shape as `health_path` | Prometheus scrape path (non-GET → 405) |
| `success_log_period` | `100` | 0–1000000 | Sample high-frequency success log events: first + every Nth per kind; 0 disables sampled events |
| `max_connections` | `1024` | 1–65536 | Concurrent control connections |
| `handshake_timeout_milliseconds` | `5000` | 100–60000 | TLS + WSS + login handshake deadline |
| `shutdown_timeout_milliseconds` | `2000` | 100–60000 | Graceful drain window on SIGINT/SIGTERM |
| `lease_default_milliseconds` | `45000` | ≥1000 | Lease granted per heartbeat (relay judges by the heartbeat request value) |
| `lease_maximum_milliseconds` | `120000` | ≥ `lease_default_milliseconds`, ≤120000 | Upper bound on any granted lease |
| `lease_capacity` | `4096` | 1–65536 | Total lease table entries |
| `lease_per_device_endpoint_capacity` | `64` | 1–65536 | Endpoints per device |
| `lease_per_tenant_device_capacity` | `4096` | 1–65536 | Devices per tenant |
| `endpoint_directory_capacity` | `4096` | 1–65536 | Endpoint directory entries |
| `endpoint_query_max_results` | `256` | 1–4096 | Max results per endpoint query |
| `signaling_rate_per_second` | `32` | 1–1024 | Per-peer signaling forwarding rate (per-second sustained) |
| `close_revoked_sessions` | `true` | bool | Close control sessions of revoked devices |
| `endpoint_expose_application_id` | `false` | bool | Publish application ids in endpoint query results |
| `endpoint_expose_record_generation` | `false` | bool | Publish endpoint record generations |
| `endpoint_expose_manifest_sha256` | `false` | bool | Publish service manifest hashes |
| `endpoint_expose_manifest_generation` | `false` | bool | Publish service manifest generations |

Struct-only knobs with no config-file key (embedding callers set them on
`RelayServerConfig`): `control_write_queue_frames` (default 64, 1–65536),
`control_write_queue_bytes` (default 1 MiB, ≥ max WSS control frame,
≤64 MiB), `endpoint_directory.maximum_ttl` (default 5 min, ≤5 min), and the
four-scope `rate_limits` policy (connection 16/s, request 256/s, tenant 64/s,
ip 32/s — see `src/relay/relay_rate_limiter.hpp`). Out-of-range values are
rejected, never clamped.

Sync-tested baseline config (this exact block is loaded through
`heyaki::load_relay_config_file` by the `heyaki_m9_docs_examples` test; the
two cert files are created as empty stubs by the test — real deployments
point them at real PEM files):

```heyaki-relay-config relay-baseline
# Heyaki relay baseline. Paths resolve relative to this file.
listen_address = 0.0.0.0
listen_port = 8443
tls_certificate_file = certs/relay.crt
tls_private_key_file = certs/relay.key
database_file = relay.sqlite
health_path = /health
metrics_path = /metrics
success_log_period = 100
max_connections = 1024
handshake_timeout_milliseconds = 5000
shutdown_timeout_milliseconds = 2000
lease_default_milliseconds = 45000
lease_maximum_milliseconds = 120000
lease_capacity = 4096
lease_per_device_endpoint_capacity = 64
lease_per_tenant_device_capacity = 4096
endpoint_directory_capacity = 4096
endpoint_query_max_results = 256
signaling_rate_per_second = 32
close_revoked_sessions = true
endpoint_expose_application_id = false
endpoint_expose_record_generation = false
endpoint_expose_manifest_sha256 = false
endpoint_expose_manifest_generation = false
```

### CLI overrides

`--listen <ip>`, `--port <n>`, `--tls-cert <path>`, `--tls-key <path>`,
`--database <path>`, `--health-path <path>`, `--metrics-path <path>`,
`--success-log-period <n>` are applied after the config file.
`--check-config` validates everything (including certificate file presence)
and exits 0/1. `--version` prints version + build commit; `--help` prints
usage.

### Validation errors

Config failures are `configuration` errors from component `relay_config`
with stable detail strings (`relay_config_unknown_key`,
`relay_config_duplicate_key`, `relay_config_port_invalid`,
`relay_config_invalid`, `relay_config_certificate_missing`,
`relay_config_private_key_missing`, …), so tooling can match on them.

## Device-side configuration

Device configuration is the client library's struct API (documented in
[api.md](api.md)); there is no device config file. The structures and their
validators:

| Struct | Validated by | Covers |
| --- | --- | --- |
| `RuntimeConfig` | `validate_config` | Executor threads, queue capacities, 11 lifecycle timeouts |
| `NodeConfig` | `Node::create` | Profile, application id, LAN/relay/path-policy overrides, pairing policy, event/file/shell service knobs |
| `RelayNodeConfig` | `validate_relay_node_config` | Relay URL, leaf pin, tenant, connect/handshake/heartbeat/backoff, queue capacities |
| `ChannelBudgetConfig` | `validate_channel_budget_config` | Per-peer/per-channel queue frames + bytes |
| `ByteStreamLimits` | `validate_byte_stream_limits` | Stream windows, concurrent streams, pending I/O |
| `SignalingCoordinatorConfig` | `SignalingCoordinator::create` | Attempt table, candidates, TTLs, inbound rate limits |
| Service attach configs | `attach()` on each service | Per-service queues, fan-out caps, RPC concurrency, shell profiles |

Sync-tested example — construct a `RuntimeConfig`, tighten one bound, and
validate (compiled and executed by `heyaki_m9_docs_examples`):

```heyaki-cpp runtime-config-validation
#include <heyaki/runtime.hpp>

#include <iostream>

int main() {
  heyaki::RuntimeConfig config;
  if (!heyaki::validate_config(config)) {
    std::cerr << "defaults must validate\n";
    return 1;
  }
  // Out-of-range values are rejected, never clamped (M9-11 freeze):
  config.peer_close_timeout = std::chrono::milliseconds{10 * 60 * 1000 + 1};
  if (heyaki::validate_config(config)) {
    std::cerr << "oversized timeout must be rejected\n";
    return 1;
  }
  return 0;
}
```

The TUI stores the device profile under the platform state directory
(`$XDG_STATE_HOME/heyaki/profiles`, defaulting to
`~/.local/state/heyaki/profiles`; `%LOCALAPPDATA%\Heyaki\profiles` on
Windows), one database per `--profile NAME` (default `default`). File
transfers land beside the profile in an `inbox/` directory. Everything else
— discovery, sessions, relay registration — is runtime state, not
configuration.
