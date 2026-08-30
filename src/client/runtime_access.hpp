#pragma once

#include "service_dispatch.hpp"

#include <heyaki/error.hpp>
#include <heyaki/runtime.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <string>

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
};

}  // namespace heyaki::detail
