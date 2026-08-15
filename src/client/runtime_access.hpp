#pragma once

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
};

}  // namespace heyaki::detail
