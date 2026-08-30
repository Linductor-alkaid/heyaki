#pragma once

// Service-layer dispatch boundary (M6-05/M6-09): message and RPC handlers run
// as ordinary executor tasks, never inline on the network callback path. The
// Node injects the pinned executor through the Runtime's general dispatch
// (which retains the future and observes admission rejection/exceptions);
// tests may inject a synchronous dispatcher. A failed Result means admission
// was rejected before the task ran — the caller must treat the work as not
// executed and keep the rejection observable.
//
// Cancellable dispatch (EXEC-07 / ledger P1-3 migration, executor C1): RPC
// handler tasks ride submit_cancellable so wire-level cancellation reaches
// the executor's task lifecycle — a queued task is terminated before it runs
// and a running task receives a cooperative stop request through the injected
// StopToken. The handler-facing RpcCallContext keeps its own polling flag as
// the frozen public observation surface; the strand sets that flag while the
// executor token carries the lifecycle event (both writers are part of one
// logical cancel).

#include <heyaki/error.hpp>

#include <executor/stop_token.hpp>
#include <executor/task_cancellation.hpp>

#include <functional>
#include <string_view>
#include <utility>

namespace heyaki {

using ServiceDispatch =
    std::function<Result<void>(std::string_view task_name, std::function<void()> task)>;

// Task body for cancellable dispatch: the executor injects its StopToken as
// the only argument.
using CancellableTask = std::function<void(executor::StopToken)>;

// Handle returned by cancellable dispatch. Idempotent and safe to call after
// the task reached any terminal state; reports the executor's cancellation
// arbitration (queued removal vs cooperative request vs already terminal).
using TaskCancelRequest = std::function<executor::TaskCancellationResponse()>;

using CancellableServiceDispatch =
    std::function<Result<TaskCancelRequest>(std::string_view task_name, CancellableTask task)>;

}  // namespace heyaki
