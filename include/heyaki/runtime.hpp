#pragma once

#include <heyaki/operation.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace executor {
class Executor;
}

namespace heyaki {

enum class RuntimeOwnership : std::uint8_t {
  borrowed,
  owned,
};

enum class RuntimeContextKind : std::uint8_t {
  node,
  peer_session,
  relay,
};

enum class RuntimePhase : std::uint8_t {
  running,
  stopping_admission,
  draining,
  stopped,
  failed,
};

struct RuntimeConfig {
  std::size_t callback_capacity{1024U};
  std::size_t executor_queue_capacity{1024U};
  std::size_t executor_min_threads{2U};
  std::size_t executor_max_threads{4U};
  std::chrono::milliseconds worker_start_timeout{1000};
  std::chrono::milliseconds callback_drain_timeout{2000};
  std::chrono::milliseconds operation_drain_timeout{5000};
  std::chrono::milliseconds worker_stop_timeout{2000};
  std::chrono::milliseconds executor_drain_timeout{5000};
  std::string worker_name{"heyaki-asio"};
};

struct RuntimeSecurityContext {
  std::string application_id;
  std::optional<DeviceId> peer_id;
  std::optional<EndpointId> endpoint_id;
  std::string authorization_scope;
  SessionEpoch epoch{1U};
};

struct RuntimeSnapshot {
  RuntimeOwnership ownership{RuntimeOwnership::borrowed};
  RuntimePhase phase{RuntimePhase::stopped};
  std::uint64_t state_sequence{};
  std::uint64_t metric_sequence{};
  std::uint64_t callbacks_accepted{};
  std::uint64_t callbacks_rejected{};
  std::uint64_t callbacks_completed{};
  std::uint64_t callback_exception_count{};
  std::uint64_t handler_exception_count{};
  std::uint64_t outstanding_operations{};
  std::uint64_t callback_queue_depth{};
  std::uint64_t callback_queue_peak_depth{};
  std::uint64_t callback_queue_dropped{};
  std::uint64_t metric_overwritten_count{};
  std::uint64_t metric_stale_read_count{};
  std::uint64_t metric_consumer_lag{};
  std::uint64_t executor_submit_rejected_count{};
  std::uint64_t executor_task_exception_count{};
  std::uint64_t executor_wait_timeout_count{};
  bool worker_ready{false};
  bool worker_running{false};
};

struct RuntimeShutdownReport {
  RuntimePhase final_phase{RuntimePhase::stopped};
  bool callback_drain_timed_out{false};
  bool operation_drain_timed_out{false};
  bool worker_stop_timed_out{false};
  bool executor_drain_timed_out{false};
  bool executor_shutdown_performed{false};
  std::vector<OperationId> incomplete_operations;
};

using RuntimeStateCallback = std::function<Result<void>()>;
using RuntimeUserHandler = std::function<Result<void>(const RuntimeSecurityContext&)>;

namespace detail {
class RuntimeOperationState;
class RuntimeContextState;
class RuntimeState;
}  // namespace detail

class RuntimeOperation {
 public:
  RuntimeOperation() = default;

  [[nodiscard]] OperationId id() const noexcept;
  [[nodiscard]] Result<std::optional<OperationStatus>> try_status() const;
  [[nodiscard]] Result<OperationStatus> wait_for(std::chrono::milliseconds timeout) const;

 private:
  friend class RuntimeContext;
  friend class detail::RuntimeState;
  explicit RuntimeOperation(std::shared_ptr<detail::RuntimeOperationState> state) noexcept;

  std::shared_ptr<detail::RuntimeOperationState> state_;
};

class RuntimeContext {
 public:
  RuntimeContext() = default;

  [[nodiscard]] RuntimeContextKind kind() const noexcept;
  [[nodiscard]] std::string_view name() const noexcept;
  [[nodiscard]] Result<RuntimeOperation> submit(
      RuntimeSecurityContext security, RuntimeStateCallback state_callback,
      RuntimeUserHandler user_handler = {}) const;

 private:
  friend class Runtime;
  friend class detail::RuntimeState;
  explicit RuntimeContext(std::shared_ptr<detail::RuntimeContextState> state) noexcept;

  std::shared_ptr<detail::RuntimeContextState> state_;
};

class Runtime {
 public:
  Runtime(Runtime&&) noexcept;
  Runtime& operator=(Runtime&&) noexcept;
  ~Runtime();

  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;

  [[nodiscard]] static Result<Runtime> create_borrowed(executor::Executor& executor,
                                                       const RuntimeConfig& config = {});
  [[nodiscard]] static Result<Runtime> create_owned(const RuntimeConfig& config = {});

  [[nodiscard]] RuntimeOwnership ownership() const noexcept;
  [[nodiscard]] Result<RuntimeContext> create_context(RuntimeContextKind kind,
                                                      std::string name);
  [[nodiscard]] RuntimeSnapshot snapshot() const;
  [[nodiscard]] RuntimeShutdownReport shutdown();

 private:
  explicit Runtime(std::shared_ptr<detail::RuntimeState> state) noexcept;

  std::shared_ptr<detail::RuntimeState> state_;
};

[[nodiscard]] std::string_view runtime_phase_name(RuntimePhase phase) noexcept;

}  // namespace heyaki
