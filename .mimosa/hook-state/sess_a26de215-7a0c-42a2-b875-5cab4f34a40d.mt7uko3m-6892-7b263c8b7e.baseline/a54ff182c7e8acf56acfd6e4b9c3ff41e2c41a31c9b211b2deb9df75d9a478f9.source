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

## Executor Skills And Documentation

Use the resources shipped with the pinned executor dependency before designing
or implementing concurrent behavior. Local resources match the dependency
version used by Heyaki and take precedence over documentation for another
executor release.

- For application integration, use
  `third_party/executor/docs/skill/executor-integration/SKILL.md`. Follow its
  routing instructions and load only the relevant router and capability card.
- If explicit direction has been given to change executor itself, use
  `third_party/executor/docs/skill/executor-maintainer/SKILL.md` before editing
  the dependency. Follow its source, invariant, test, and documentation checks.
  Do not use the maintainer skill as implicit permission to modify executor.
- Use the current user-guide website sources under
  `third_party/executor/website/zh/` (or the corresponding `en/` page when
  needed) for lifecycle, submission, communication, monitoring, failure, and
  production-readiness guidance. In particular, consult the relevant guides in
  `guides/`, `realtime-and-communication/`, and `reliability/` rather than
  guessing API semantics.
- Treat executor public headers and the pinned user guide as authoritative for
  application use. Prefer the public facade and documented communication
  components over local abstractions or executor implementation details.

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

## GitHub Commit And Push

Agents may create scoped commits and push the current working branch to the
HTTPS `origin` without additional per-action authorization when needed to
trigger or verify GitHub CI for the user's requested work. This standing
authorization includes follow-up commits that fix CI failures within the same
request. Any other GitHub-changing action still requires explicit user
authorization. Preserve unrelated working-tree changes and never include them
in these commits.

- Use the HTTPS `origin` remote and prefer a normal non-force
  `git push origin <branch>` when Git transport is available.
- The `gh` CLI is installed at `/usr/bin/gh` and authenticated through the
  system keyring. Prefer `gh` for GitHub API and repository operations, and
  verify the active account with `gh auth status` before making changes.
- After a CI-validation push, monitor the relevant workflow with `gh`, inspect
  failures, and report the final result. Do not merge pull requests, create
  releases or tags, or change repository settings under this standing
  authorization.
- Never print authentication tokens, copy them into the repository, put them
  in remote URLs, expose them in process arguments, or include them in command
  output or logs. If `gh` is unavailable or no longer authenticated, fall back
  to authenticated HTTPS without modifying the credential store.
- If normal Git transport is unavailable but the GitHub API is reachable, the
  Git Database API is an acceptable fallback: verify the current remote ref,
  create blobs, a tree, and a commit based on that exact remote commit, then
  update the branch ref with `force: false`.
- After an API fallback, verify the remote SHA and synchronize the local
  tracking and branch refs without a destructive reset. The local commit may
  have a different SHA from the API-created commit when GitHub normalizes
  commit metadata, even when both commits have the same parent and tree.
- Never force-push, set `force: true`, rewrite published history, or embed a PAT
  in Git configuration unless the user explicitly requests that exact action.
