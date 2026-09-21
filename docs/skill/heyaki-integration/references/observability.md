# Observability

## Device side

- `Node::metrics()` returns the aggregated `NodeMetrics` — node, pairing,
  connectivity, transport, channels, services, plus the embedded executor
  runtime snapshot. `snapshot()` is live state; `metrics()` aggregates on
  the node's periodic tick.
- `format_node_metrics_prometheus()` renders the Prometheus text (300+
  families on the device). The TUI `metrics` command prints exactly this —
  use it to see what your exporter will export.
- Queue health is observable: `Node::metrics()` and the TUI QUEUES view
  expose bounded-queue depths, admission rejections, and drop/lag counters.
  Treat those counters as the source of truth for overload, not log
  grepping.

## Correlation

Logs are JSON Lines with correlation ids; sessions carry wire
RequestId/SessionId visible in `peer_sessions()` — thread those ids through
your own logs to correlate an application action with library events.

## Relay side

The deployed relay exposes `/metrics` (the relay formatter is in-tree; the
endpoint is the downstream surface). The metrics family catalog, recording
rules, alert set, and Grafana dashboards live in
[deploy/observability/](../../../../deploy/observability/README.md) — the SLO
alert set references only real metric families (CI-enforced).

## Pitfalls

- Do not poll `snapshot()` in a hot loop to detect change; install the
  documented change handlers and read snapshots on events.
- Metric families are frozen surface: alert on documented families, not on
  incidental internal counters.
