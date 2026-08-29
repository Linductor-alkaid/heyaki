#pragma once

// Service-layer dispatch boundary (M6-05/M6-09): message and RPC handlers run
// as ordinary executor tasks, never inline on the network callback path. The
// Node injects the pinned executor through the Runtime's general dispatch
// (which retains the future and observes admission rejection/exceptions);
// tests may inject a synchronous dispatcher. A failed Result means admission
// was rejected before the task ran — the caller must treat the work as not
// executed and keep the rejection observable.

#include <heyaki/error.hpp>

#include <functional>
#include <string_view>

namespace heyaki {

using ServiceDispatch =
    std::function<Result<void>(std::string_view task_name, std::function<void()> task)>;

}  // namespace heyaki
