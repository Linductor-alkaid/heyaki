# Heyaki Repository Instructions

These instructions apply to the entire repository.

## Executor Is the Concurrency Boundary

All concurrent or asynchronous work introduced by a development task must use
the repository's pinned `executor` dependency. This includes production code,
tools, examples, and tests.

- Manage the complete lifecycle of ordinary asynchronous work, periodic work,
  realtime work, blocking I/O workers, and other long-lived work through the
  `executor` facade or the appropriate `executor` backend. Creation, admission,
  cancellation, draining, shutdown, completion, and failure must remain visible
  to `executor`.
- Do not introduce `std::thread`, `std::jthread`, `std::async`, a custom thread
  pool, a detached worker, or another independently managed execution loop.
- Use `executor::comm` components for communication across execution contexts.
  Select the component by its documented semantics, such as a bounded typed
  channel, `LatestMailbox`, `DoubleBuffer`, `RealtimeChannel`, `Topic`, or
  `PhaseGate`. Do not build an ad hoc queue or use shared mutable state plus
  mutexes and condition variables as a substitute for executor communication.
- Use executor monitoring, status, failure events, and communication statistics
  as the source of task-health information. New task paths must make admission
  rejection, execution failure, timeout or cancellation, backpressure, and
  lifecycle/shutdown state observable through executor facilities. Do not add a
  parallel task-monitoring subsystem.
- Treat queue capacity, backpressure/drop policy, timeout, cancellation, and
  shutdown behavior as explicit design choices. Do not accept silent task or
  message loss.

Before implementing concurrent behavior, consult the pinned executor API and
communication documentation under `third_party/executor/`; prefer its public
facade and established components over local abstractions.

If executor cannot satisfy a required behavior and correctness appears to
require a new lock, a dedicated thread, or an independently managed execution
mechanism, do not implement that workaround. Report the requirement first,
including:

1. the behavior that executor cannot currently provide;
2. the executor API or semantic limitation that causes the gap;
3. why existing executor lifecycle and `executor::comm` facilities are
   insufficient;
4. the smallest proposed executor capability or approved exception; and
5. the impact of deferring the work.

Wait for explicit direction before implementing the exception or changing the
executor dependency itself.
