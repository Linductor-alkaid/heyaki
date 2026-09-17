# Client Library API

Heyaki ships as C++20 static libraries consumed through CMake:

| Target | Contents |
| --- | --- |
| `heyaki::core` | Wire protocol, identity, signing, errors, ids, time — no I/O |
| `heyaki::profile` | `ProfileStore`, password verifier, secret backends |
| `heyaki::client` | `Node`, sessions, LAN directory, relay control, five services, file store |
| `heyaki::services` | Thin module umbrella over the service layer |
| `heyaki::transport_webrtc` | The v1 data-plane backend (libdatachannel) |
| `heyaki::relay` | `RelayServer` + `RelayDatabase` for embedding a relay |

Headers live under `include/heyaki/`; everything public is in namespace
`heyaki`. Consume via `find_package(heyaki CONFIG REQUIRED)` (see
[getting-started.md](getting-started.md#consume-the-installed-package)).

## Concurrency model

All asynchronous work — timers, socket workers, service pumps, the shell PTY
worker — runs on the pinned `executor` dependency. Application code never
creates threads. Consequences for API use:

- **Node callbacks fire on executor contexts**, not on your thread. Handlers
  must be cheap and non-blocking; hand off via `executor::comm` components
  (bounded channels, `LatestMailbox`, `Topic`) if you need to cross into
  application code.
- **Blocking calls** (`shutdown`, `wait_for`, file reads) belong to executor
  blocking workers; the library routes them there itself.
- **Queues are bounded everywhere.** Overload surfaces as admission failures
  (`Error` with a capacity/admission detail), dropped-with-counter semantics
  for observability mailboxes, or backpressure windows — never silent loss.
  Queue stats are visible through `Node::metrics()` and the TUI QUEUES view.

The full design is in
[design/concurrency-and-shutdown.md](design/concurrency-and-shutdown.md).

## Error model

Every fallible API returns `Result<T>` with an `Error` carrying:

- `code()` — a `ErrorCode` enum value (stable, serialized on the wire),
- `component()` — the producing subsystem (`"node"`, `"profile"`,
  `"relay_config"`, …),
- `safe_detail()` — a bounded, non-sensitive detail token (≤64 bytes,
  identifier-class only; never payload, paths of other users, or secrets).

Sync-tested example — inspecting an error:

```heyaki-cpp error-model
#include <heyaki/error.hpp>
#include <heyaki/runtime.hpp>

#include <chrono>
#include <iostream>

int main() {
  heyaki::RuntimeConfig config;
  config.executor_max_threads = 1U;          // below executor_min_threads
  const auto result = heyaki::validate_config(config);
  if (result) {
    std::cerr << "invalid config must be rejected\n";
    return 1;
  }
  const auto& error = *result.error_if();
  std::cout << heyaki::error_code_name(error.code()) << '/'
            << error.component() << '/' << error.safe_detail() << '\n';
  return 0;
}
```

(If `validate_config` happens to accept that pair in a future version, the
example fails loudly instead of silently rotting — that is the point of
sync-tested samples.)

## Profile store

`ProfileStore` is the per-OS-user identity database: one SQLite file per
profile, device identity + endpoint identities + password verifier + trust
grants + LAN/pairing configuration.

- `ProfileStore::create_default(name)` / `open_default(name)` operate under
  the platform state directory (`$XDG_STATE_HOME/heyaki/profiles`, default
  `~/.local/state/heyaki/profiles`; `%LOCALAPPDATA%\Heyaki\profiles`).
  `open_default` migrates old schemas automatically (a backup file is left
  beside the database whenever a migration is attempted).
- `endpoint_for(application_id)` derives a stable per-application endpoint
  identity; the TUI owns `org.heyaki.tui`, applications use their own id.
- Permissions are enforced (0600 files, 0700 directories); secret material
  goes through the configured `SecretBackend` (encrypted file backend by
  default, OS credential store optional).

`apps/demo/m2_profile_demo.cpp` is the complete worked example.

## Node lifecycle

`Node` is the device: LAN discovery + relay registration + sessions + the
five services. Construction is `NodeConfig` (defaults for everything except
profile + application id) → `Node::create`; destruction is an explicit
`shutdown()` returning a `NodeShutdownReport` (drain outcomes per stage).

Sync-tested minimal lifecycle — create a node on a scratch profile, read its
identity and metrics, shut it down cleanly:

```heyaki-cpp node-lifecycle
#include <heyaki/metrics.hpp>
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <filesystem>
#include <iostream>

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: node-lifecycle <work-directory>\n";
    return 2;
  }
  const auto database = std::filesystem::path{argv[1]} / "profile.sqlite";
  auto profile = heyaki::ProfileStore::create(database);
  if (!profile) {
    const auto* error = profile.error_if();
    std::cerr << "profile create failed: "
              << heyaki::error_code_name(error->code()) << '/'
              << error->safe_detail() << '\n';
    return 1;
  }
  // Local initialization (what the TUI first-run flow does): identity,
  // password verifier, pairing policy, and LAN configuration. Real apps
  // prompt for the password; this example pins one for determinism.
  auto verifier = heyaki::create_password_verifier(
      "correct horse battery staple", heyaki::PasswordHashParameters{},
      heyaki::PasswordSecurityPolicy{});
  if (!verifier) {
    std::cerr << "password verifier failed\n";
    return 1;
  }
  heyaki::LocalProfileInitialization initialization;  // defaults for policy/LAN
  initialization.application_id = "com.example.docs";
  initialization.password_verifier = std::move(*verifier.value_if());
  auto initialized = profile.value_if()->initialize_local(initialization);
  if (!initialized) {
    std::cerr << "local initialization failed\n";
    return 1;
  }
  heyaki::NodeConfig config;   // every field has a default
  config.profile = &*profile.value_if();
  config.application_id = "com.example.docs";
  auto node = heyaki::Node::create(std::move(config));
  if (!node) {
    const auto* error = node.error_if();
    std::cerr << "node create failed: "
              << heyaki::error_code_name(error->code()) << '/'
              << error->safe_detail() << '\n';
    return 1;
  }
  // metrics() aggregates on the node's periodic tick; snapshot() is live.
  const auto snapshot = node.value_if()->snapshot();
  const auto metrics = node.value_if()->metrics();
  std::cout << "device=" << heyaki::to_string(snapshot.device_id)
            << " prometheus_ready="
            << !heyaki::format_node_metrics_prometheus(metrics).empty() << '\n';
  const auto report = node.value_if()->shutdown();
  if (!report.stopped) {
    std::cerr << "shutdown did not stop cleanly\n";
    return 1;
  }
  return 0;
}
```

`shutdown()` is the only teardown path: it runs the staged drain
(stop producers → cancel services → close peers → unregister relay → flush
persistence) and reports whether the node stopped within budget
(`stopped`/`timed_out` plus final resource counters).

## Discovery and sessions

- `endpoints()` — merged LAN + relay directory (`EndpointDirectoryEntrySnapshot`
  says which plane each entry came from).
- `connect(peer)` — automatic mode: prefer LAN endpoint, fall back to relay
  signaling; `connect_lan(peer)` — LAN-only. Both return after admission; the
  terminal state arrives through the session change handler / `peer_sessions()`.
- `peer_sessions()` — live snapshots: state, connection stage, negotiated
  `data_path` (`direct_host` / `direct_srflx` / `turn_udp` / `turn_tcp`),
  RTT, buffered amount, authorized scopes, transport byte counters, and the
  wire RequestId/SessionId used for cross-log correlation.
- `restart_session(peer)` — protocol-1.2 in-place transport restart (same
  SessionId, bumped epoch); triggered automatically on interface changes.
- `refresh_interfaces()` — re-scan network interfaces without restart.

Unknown peers always land in `PairingRestricted` first (default-deny, M5);
after pairing they authenticate straight into `Authorized`.

## Pairing and trust

`pair_peer(peer, password, requested_scopes)` submits one attempt against the
peer's pairing-restricted session. Outcomes surface through a one-time
observer (`set_pairing_observer`) or the session snapshot; grants are signed
TrustGrants stored locally, and the **effective scope is the intersection**
of requested and the target's policy — never more. Supporting APIs:
`trust_grants_for`, `revoke_trust_grant`,
`rotate_authorization_password[_and_revoke]`, and the bounded
`pairing_audit_records()` ring (correlation ids, never the password).

Scope grammar (`trust_scope_covers`, sync-tested):

```heyaki-cpp pairing-scope-grammar
#include <heyaki/trust_grant.hpp>

#include <iostream>

int main() {
  const bool narrow = heyaki::trust_scope_covers("file:read:*", "file:read:inbox");
  const bool not_bare = heyaki::trust_scope_covers("file:read:*", "file:read");
  const bool not_global = heyaki::trust_scope_covers("*", "file:read:inbox");
  std::cout << narrow << not_bare << not_global << '\n';   // 1 0 0
  return narrow && !not_bare && !not_global ? 0 : 1;
}
```

Prefix wildcards cover deeper segments only (`prefix:*` matches `prefix:x`
and `prefix:x:y`); `*` alone is not a global grant.

## The five services

All services ride authenticated sessions and are default-deny: each frame
kind requires a live trust scope covering it (checked per frame on the
serving side).

| Domain | Entry points | Semantics worth knowing |
| --- | --- | --- |
| Message | `send_message`, inbound/ack handlers | `best_effort` or `peer_acked` delivery; `peer_offline` immediately when no authorized session (no offline queue in v1); bounded TTL dedup |
| RPC | `register_rpc_method`, `call_rpc`, `cancel_rpc` | Unary; scope checked before the handler runs; exactly-once completion; **non-idempotent calls that lose their session return `outcome_unknown`**, at-most-once result caching keyed by RequestId |
| Events | `subscribe_events` / `publish_event` (+ local topic bridge) | Publisher-direct fan-out; exact or segment-prefix patterns; per-subscriber QoS `keep_latest` or `reliable_live`; bounded staging with drop/lag counters |
| Files | `push_file` / `pull_file`, pause/resume/cancel | Manifest → bitmap accept → bounded-window chunks → BLAKE3 verify → fsync → atomic rename; resumable by `TransferId`; receive roots are explicit allowlists with per-peer quotas |
| Shell | `open_shell` / input / resize / signal / eof / `close_shell` | Default-off serving side (explicit `ShellProfileConfig` list); live `shell.open:<profile>` scope; content-free audit records; TERM→grace→kill escalation |

File logical names are validated by a strict grammar (sync-tested):

```heyaki-cpp file-name-policy
#include <heyaki/file.hpp>

#include <iostream>

int main() {
  const bool clean = heyaki::safe_logical_file_name("reports/2026/q3.csv");
  const bool traversal = heyaki::safe_logical_file_name("../escape");
  const bool windows_reserved =
      heyaki::safe_logical_file_name("status/CON.txt");
  std::cout << clean << traversal << windows_reserved << '\n';   // 1 0 0
  return clean && !traversal && !windows_reserved ? 0 : 1;
}
```

`apps/demo/m6_message_rpc_demo.cpp` and `apps/demo/m7_data_demo.cpp` are the
complete worked examples (semantics with two live devices).

## Metrics

`Node::metrics()` returns the aggregated `NodeMetrics` (node/pairing/
connectivity/transport/channels/services + embedded executor runtime
snapshot); `format_node_metrics_prometheus()` renders the Prometheus text
(~200 families). The TUI `metrics` command prints exactly this. The relay
counterpart is `format_relay_metrics_prometheus` on the relay snapshot; the
family catalog and alert mappings live in
[deploy/observability/README.md](../deploy/observability/README.md).

## Relay registration (device side)

`RelayNodeConfig` (a `NodeConfig.relay_override` or the profile's relay
settings) selects the relay: URL, optional leaf pin (full SHA-256 of the
leaf certificate), tenant, CA file, and the timing/backoff/queue knobs.
Enrollment (bootstrap token → device identity registered) happens once per
generation through the enrollment client; afterwards login is automatic.
TURN REST credentials are derived per session from the negotiated relay
capabilities — applications never handle TURN secrets.

## Protocol compatibility

- Wire protocol version is `{1, 2}`; negotiation takes the intersection
  (`negotiate_protocol`): same major required, minor = min, capabilities
  intersected, required bits double-checked.
- **Parsers reject unknown fields** (canonical signed objects — skipping a
  field would change the signature input). New optional fields in v1.x must
  be emitted gated on the negotiated minor.
- N-1 devices interoperate: LAN discovery admits same-major peers back to
  the LAN floor (minor 1), relay login clamps granted capabilities to the
  negotiated version, and relay schema migrations are forward-only
  (`schema_too_new` on downgrade is the rollback boundary).
- The compatibility suite (`heyaki_m9_compat`) pins all of the above; the
  policy lives in [compatibility/](compatibility/) and
  [design/heyaki-wire-protocol.md](design/heyaki-wire-protocol.md).
