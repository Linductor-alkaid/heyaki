# Services: Message, RPC, Events

All services ride authenticated sessions and are default-deny: each frame
kind requires a live trust scope covering it, checked per frame on the
serving side.

## Message

`send_message` with delivery `best_effort` or `peer_acked`; inbound and ack
handlers are installed on the node. Semantics worth knowing:

- `peer_offline` is returned immediately when no authorized session exists
  — there is no offline queue in v1.
- Bounded TTL dedup: duplicates within the TTL window are dropped, not
  redelivered.

## RPC

`register_rpc_method` on the serving side; `call_rpc` / `cancel_rpc` on the
caller. Unary with deadlines. Semantics worth knowing:

- The scope is checked before the handler runs.
- Completion is exactly-once; non-idempotent calls that lose their session
  return `outcome_unknown` — the call may or may not have executed. Handle
  that outcome explicitly; never retry it blindly.
- Result caching is at-most-once, keyed by RequestId.

## Events

`subscribe_events` / `publish_event` (plus a local topic bridge).
Publisher-direct fan-out with exact or segment-prefix patterns and
per-subscriber QoS:

- `EventQos::best_effort_latest` — subscribers see the newest value;
  staging drops older items under pressure (counted).
- `EventQos::reliable_live` — live-ordered delivery with lag accounting; a
  slow subscriber surfaces as lag counters, not silent gaps.

## Pitfalls

- Overload is visible: admission failures on send paths and drop/lag
  counters on events are the designed behavior — surface them to the user
  instead of retrying in a tight loop.
- Handlers run on executor contexts: never block inside them.

The complete two-device worked examples are
`apps/demo/m6_message_rpc_demo.cpp` and (files/events)
`apps/demo/m7_data_demo.cpp`.
