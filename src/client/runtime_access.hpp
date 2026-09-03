#pragma once

#include "service_dispatch.hpp"
#include "shell_pty.hpp"

#include <heyaki/error.hpp>
#include <heyaki/runtime.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <string>
#include <utility>

namespace heyaki::detail {

class RuntimeAccess {
 public:
  [[nodiscard]] static Result<boost::asio::any_io_executor> io_executor(Runtime& runtime);
  [[nodiscard]] static Result<void> dispatch_general(Runtime& runtime, std::string name,
                                                     std::function<void()> task);
  // Cancellable general dispatch: the task receives an executor StopToken and
  // stays in the executor's cancellation registry; the returned cancel request
  // routes through request_task_cancel (queued tasks terminate before running,
  // running tasks observe a cooperative stop request).
  [[nodiscard]] static Result<TaskCancelRequest> dispatch_general_cancellable(
      Runtime& runtime, std::string name, CancellableTask task);
  // Blocking file I/O dispatch (M7-12): the task runs on the runtime's
  // dedicated executor-managed blocking I/O worker.
  [[nodiscard]] static Result<TaskCancelRequest> dispatch_blocking(Runtime& runtime,
                                                                   std::string name,
                                                                   CancellableTask task);
  // ---- M8 Remote Shell PTY worker ----
  // True when the runtime started the dedicated PTY worker.
  [[nodiscard]] static bool shell_pty_enabled(const Runtime& runtime);
  // Bounded admission onto the PTY worker's command queue; wakes the worker's
  // poll so the command is observed without waiting for the tick deadline.
  [[nodiscard]] static Result<void> shell_pty_submit(Runtime& runtime,
                                                     ShellPtyCommand&& command);
  // Pops every available PTY event and hands it to `sink` (node strand).
  static void shell_pty_drain(Runtime& runtime,
                              const std::function<void(const ShellPtyEvent&)>& sink);
};

}  // namespace heyaki::detail
