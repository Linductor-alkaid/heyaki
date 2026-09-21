# Node Lifecycle And The Shared Model

## Result and error model

Every fallible API returns `Result<T>`; an `Error` carries `code()` (a stable
`ErrorCode`, serialized on the wire), `component()` (`"node"`, `"profile"`,
`"relay_config"`, …), and `safe_detail()` — a bounded (≤64 bytes),
non-sensitive identifier-class token. Never log or branch on free-text
details that are not `safe_detail`. `error_code_name()` renders the code.

## Concurrency model

All asynchronous work — timers, socket workers, service pumps, the shell PTY
worker — runs on the pinned `executor` dependency. Application code never
creates threads. Consequences:

- `Node` callbacks fire on executor contexts, not on your thread. Handlers
  must be cheap and non-blocking; hand off via `executor::comm` components
  (bounded channels, `LatestMailbox`, `Topic`) to cross into application
  code.
- Queues are bounded everywhere. Overload surfaces as admission failures
  (`Error` with a capacity/admission detail), dropped-with-counter semantics
  for observability mailboxes, or backpressure windows — never silent loss.
  Queue stats are visible through `Node::metrics()` and the TUI QUEUES view.

## Lifecycle

`NodeConfig` (defaults for everything except `profile` + `application_id`)
→ `Node::create` → work → `shutdown()`. There is no other teardown path:
`shutdown()` runs the staged drain (stop producers → cancel services →
close peers → unregister relay → flush persistence) and returns a
`NodeShutdownReport` whose `stopped` flag says whether the node stopped
within budget. `snapshot()` is live state; `metrics()` aggregates on the
node's periodic tick.

`RuntimeConfig` / `RelayNodeConfig` values can be validated up front with
`validate_config` / `validate_relay_node_config`; defaults and hard upper
bounds are frozen in
[parameter-freeze.md](../../../operations/parameter-freeze.md).

## Pitfalls

- Treating admission as completion: `connect`, `send_message`, `push_file`
  return after admission; terminal states arrive through the documented
  callback or snapshot API.
- Blocking a callback thread: long work must go to executor blocking
  workers or your own executor-managed context, never a raw thread.
- Skipping `Result` checks — a failed `Node::create` leaves nothing to
  call `shutdown()` on.

## Next

Session states and discovery read
[sessions and discovery](sessions-and-discovery.md). Otherwise return to
the entry router.
