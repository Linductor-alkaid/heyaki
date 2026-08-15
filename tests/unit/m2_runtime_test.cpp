#include <heyaki/runtime.hpp>

#include <executor/comm/phase_gate.hpp>
#include <executor/executor.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace heyaki {
namespace {

using namespace std::chrono_literals;

RuntimeSecurityContext test_security_context() {
  return RuntimeSecurityContext{.application_id = "org.heyaki.runtime-test",
                                .peer_id = std::nullopt,
                                .endpoint_id = std::nullopt,
                                .authorization_scope = "runtime.test",
                                .epoch = SessionEpoch{1U}};
}

bool wait_until(const std::function<bool()>& predicate, std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    std::this_thread::yield();
  }
  return predicate();
}

TEST(M2RuntimeTest, OwnedRuntimeSerializesContextAndDispatchesHandlers) {
  RuntimeConfig config;
  config.worker_name = "heyaki-owned-test";
  auto runtime = Runtime::create_owned(config);
  ASSERT_TRUE(runtime) << runtime.error_if()->safe_detail();
  EXPECT_EQ(runtime.value_if()->ownership(), RuntimeOwnership::owned);

  auto context = runtime.value_if()->create_context(RuntimeContextKind::node, "node-main");
  ASSERT_TRUE(context) << context.error_if()->safe_detail();
  std::vector<std::size_t> observed_order;
  observed_order.reserve(32U);
  std::thread::id state_thread;
  std::thread::id handler_thread;
  std::vector<RuntimeOperation> operations;
  operations.reserve(32U);

  for (std::size_t index = 0U; index < 32U; ++index) {
    auto operation = context.value_if()->submit(
        test_security_context(),
        [&, index] {
          state_thread = std::this_thread::get_id();
          observed_order.push_back(index);
          return Result<void>::success();
        },
        [&](const RuntimeSecurityContext&) {
          handler_thread = std::this_thread::get_id();
          return Result<void>::success();
        });
    ASSERT_TRUE(operation) << operation.error_if()->safe_detail();
    operations.push_back(std::move(*operation.value_if()));
  }

  for (const auto& operation : operations) {
    auto status = operation.wait_for(2s);
    ASSERT_TRUE(status) << status.error_if()->safe_detail();
    EXPECT_EQ(status.value_if()->state, OperationState::success);
  }
  ASSERT_EQ(observed_order.size(), 32U);
  for (std::size_t index = 0U; index < observed_order.size(); ++index) {
    EXPECT_EQ(observed_order[index], index);
  }
  EXPECT_NE(state_thread, std::thread::id{});
  EXPECT_NE(handler_thread, std::thread::id{});
  EXPECT_NE(state_thread, handler_thread);

  const auto before_shutdown = runtime.value_if()->snapshot();
  EXPECT_EQ(before_shutdown.phase, RuntimePhase::running);
  EXPECT_EQ(before_shutdown.callbacks_accepted, 32U);
  EXPECT_EQ(before_shutdown.callbacks_completed, 32U);
  EXPECT_EQ(before_shutdown.outstanding_operations, 0U);
  EXPECT_TRUE(before_shutdown.worker_ready);
  EXPECT_TRUE(before_shutdown.worker_running);
  const auto stable_snapshot = runtime.value_if()->snapshot();
  EXPECT_GE(stable_snapshot.metric_sequence, before_shutdown.metric_sequence);

  const auto shutdown = runtime.value_if()->shutdown();
  EXPECT_EQ(shutdown.final_phase, RuntimePhase::stopped);
  EXPECT_TRUE(shutdown.executor_shutdown_performed);
  EXPECT_FALSE(shutdown.callback_drain_timed_out);
  EXPECT_FALSE(shutdown.operation_drain_timed_out);
  const auto shutdown_again = runtime.value_if()->shutdown();
  EXPECT_EQ(shutdown_again.final_phase, RuntimePhase::stopped);
  EXPECT_TRUE(shutdown_again.executor_shutdown_performed);
}

TEST(M2RuntimeTest, CallbackQueueRejectsNewestAndShutdownClosesAdmission) {
  RuntimeConfig config;
  config.worker_name = "heyaki-callback-pressure";
  config.callback_capacity = 1U;
  auto runtime = Runtime::create_owned(config);
  ASSERT_TRUE(runtime) << runtime.error_if()->safe_detail();
  auto context = runtime.value_if()->create_context(RuntimeContextKind::peer_session, "peer-one");
  ASSERT_TRUE(context);

  executor::comm::PhaseGate entered("callback-entered");
  executor::comm::PhaseGate release("callback-release");
  auto first = context.value_if()->submit(test_security_context(), [&] {
    (void)entered.advance_to(1U);
    const auto released = release.wait_for(1U, 2s);
    return released ? Result<void>::success()
                    : Result<void>::failure(
                          Error{ErrorCode::timeout, "test", "callback_release_timeout"});
  });
  ASSERT_TRUE(first);
  ASSERT_TRUE(entered.wait_for(1U, 2s));

  auto second = context.value_if()->submit(test_security_context(), [] {
    return Result<void>::success();
  });
  ASSERT_TRUE(second);
  auto rejected = context.value_if()->submit(test_security_context(), [] {
    return Result<void>::success();
  });
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->code(), ErrorCode::resource_exhausted);

  ASSERT_TRUE(release.advance_to(1U));
  ASSERT_TRUE(first.value_if()->wait_for(2s));
  ASSERT_TRUE(second.value_if()->wait_for(2s));
  const auto pressure = runtime.value_if()->snapshot();
  EXPECT_GE(pressure.callbacks_rejected, 1U);
  EXPECT_GE(pressure.callback_queue_dropped, 1U);
  EXPECT_GE(pressure.callback_queue_peak_depth, 1U);

  (void)runtime.value_if()->shutdown();
  auto context_after_shutdown =
      runtime.value_if()->create_context(RuntimeContextKind::node, "late-node");
  ASSERT_FALSE(context_after_shutdown);
  EXPECT_EQ(context_after_shutdown.error_if()->code(), ErrorCode::cancelled);
  auto after_shutdown = context.value_if()->submit(test_security_context(), [] {
    return Result<void>::success();
  });
  ASSERT_FALSE(after_shutdown);
  EXPECT_EQ(after_shutdown.error_if()->code(), ErrorCode::cancelled);
}

TEST(M2RuntimeTest, BorrowedRuntimeLeavesCallerExecutorRunning) {
  executor::Executor executor;
  executor::ExecutorConfig executor_config;
  executor_config.min_threads = 1U;
  executor_config.max_threads = 2U;
  ASSERT_TRUE(executor.initialize_ex(executor_config));

  RuntimeConfig config;
  config.worker_name = "heyaki-borrowed-test";
  auto runtime = Runtime::create_borrowed(executor, config);
  ASSERT_TRUE(runtime) << runtime.error_if()->safe_detail();
  auto context = runtime.value_if()->create_context(RuntimeContextKind::relay, "relay-main");
  ASSERT_TRUE(context);
  auto operation = context.value_if()->submit(test_security_context(), [] {
    return Result<void>::success();
  });
  ASSERT_TRUE(operation);
  ASSERT_TRUE(operation.value_if()->wait_for(2s));

  const auto shutdown = runtime.value_if()->shutdown();
  EXPECT_FALSE(shutdown.executor_shutdown_performed);
  const auto executor_snapshot = executor.get_snapshot();
  EXPECT_EQ(executor_snapshot.lifecycle, executor::ExecutorLifecycleState::Running);
  EXPECT_TRUE(executor_snapshot.async.is_running);
  (void)executor.shutdown(true);
}

#if defined(__cpp_exceptions)
TEST(M2RuntimeTest, CallbackAndHandlerExceptionsRemainObservable) {
  RuntimeConfig config;
  config.worker_name = "heyaki-exception-test";
  auto runtime = Runtime::create_owned(config);
  ASSERT_TRUE(runtime);
  auto context = runtime.value_if()->create_context(RuntimeContextKind::node, "exception-node");
  ASSERT_TRUE(context);

  auto callback_exception = context.value_if()->submit(test_security_context(), []() -> Result<void> {
    throw std::runtime_error("state callback failed");
  });
  ASSERT_TRUE(callback_exception);
  auto callback_status = callback_exception.value_if()->wait_for(2s);
  ASSERT_TRUE(callback_status);
  EXPECT_EQ(callback_status.value_if()->state, OperationState::error);

  auto handler_exception = context.value_if()->submit(
      test_security_context(), [] { return Result<void>::success(); },
      [](const RuntimeSecurityContext&) -> Result<void> {
        throw std::runtime_error("user handler failed");
      });
  ASSERT_TRUE(handler_exception);
  auto handler_status = handler_exception.value_if()->wait_for(2s);
  ASSERT_TRUE(handler_status);
  EXPECT_EQ(handler_status.value_if()->state, OperationState::error);

  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = runtime.value_if()->snapshot();
        return snapshot.callback_exception_count >= 1U &&
               snapshot.handler_exception_count >= 1U &&
               snapshot.executor_task_exception_count >= 1U;
      },
      2s));
  (void)runtime.value_if()->shutdown();
}
#endif

TEST(M2RuntimeTest, BorrowedRuntimeReportsOwnDrainTimeoutWithoutStoppingExecutor) {
  executor::Executor executor;
  executor::ExecutorConfig executor_config;
  executor_config.min_threads = 1U;
  executor_config.max_threads = 1U;
  ASSERT_TRUE(executor.initialize_ex(executor_config));

  RuntimeConfig config;
  config.worker_name = "heyaki-drain-timeout";
  config.operation_drain_timeout = 10ms;
  auto runtime = Runtime::create_borrowed(executor, config);
  ASSERT_TRUE(runtime);
  auto context = runtime.value_if()->create_context(RuntimeContextKind::node, "slow-node");
  ASSERT_TRUE(context);

  executor::comm::PhaseGate entered("handler-entered");
  executor::comm::PhaseGate release("handler-release");
  auto operation = context.value_if()->submit(
      test_security_context(), [] { return Result<void>::success(); },
      [&](const RuntimeSecurityContext&) {
        (void)entered.advance_to(1U);
        const auto released = release.wait_for(1U, 2s);
        return released ? Result<void>::success()
                        : Result<void>::failure(
                              Error{ErrorCode::timeout, "test", "handler_release_timeout"});
      });
  ASSERT_TRUE(operation);
  ASSERT_TRUE(entered.wait_for(1U, 2s));

  const auto shutdown = runtime.value_if()->shutdown();
  EXPECT_TRUE(shutdown.operation_drain_timed_out);
  EXPECT_FALSE(shutdown.executor_shutdown_performed);
  ASSERT_EQ(shutdown.incomplete_operations.size(), 1U);
  EXPECT_EQ(shutdown.incomplete_operations.front(), operation.value_if()->id());
  auto status = operation.value_if()->wait_for(100ms);
  ASSERT_TRUE(status);
  EXPECT_EQ(status.value_if()->state, OperationState::cancelled);
  EXPECT_EQ(status.value_if()->error->code(), ErrorCode::timeout);

  ASSERT_TRUE(release.advance_to(1U));
  EXPECT_TRUE(executor.wait_for_completion_ex(2s).completed);
  EXPECT_TRUE(executor.get_snapshot().async.is_running);
  (void)executor.shutdown(true);
}

TEST(M2RuntimeTest, ExecutorOverloadTimeoutIsVisibleOnOperationAndFailureStatus) {
  executor::Executor executor;
  executor::ExecutorConfig executor_config;
  executor_config.min_threads = 1U;
  executor_config.max_threads = 1U;
  executor_config.queue_capacity = 1U;
  executor_config.task_timeout_ms = 20;
  ASSERT_TRUE(executor.initialize_ex(executor_config));

  RuntimeConfig config;
  config.worker_name = "heyaki-executor-pressure";
  auto runtime = Runtime::create_borrowed(executor, config);
  ASSERT_TRUE(runtime);
  auto context = runtime.value_if()->create_context(RuntimeContextKind::node, "busy-node");
  ASSERT_TRUE(context);

  executor::comm::PhaseGate entered("executor-entered");
  executor::comm::PhaseGate release("executor-release");
  auto blocking_handler = [&](const RuntimeSecurityContext&) {
    (void)entered.advance_to(1U);
    const auto released = release.wait_for(1U, 10s);
    return released ? Result<void>::success()
                    : Result<void>::failure(
                          Error{ErrorCode::timeout, "test", "executor_release_timeout"});
  };
  auto first = context.value_if()->submit(
      test_security_context(), [] { return Result<void>::success(); }, blocking_handler);
  ASSERT_TRUE(first);
  ASSERT_TRUE(entered.wait_for(1U, 2s));

  auto second = context.value_if()->submit(
      test_security_context(), [] { return Result<void>::success(); },
      [](const RuntimeSecurityContext&) { return Result<void>::success(); });
  ASSERT_TRUE(second);
  ASSERT_TRUE(wait_until([&] { return executor.get_snapshot().async.queue_size >= 1U; }, 2s));
  const auto overload_started = std::chrono::steady_clock::now();
  ASSERT_TRUE(wait_until(
      [&] { return std::chrono::steady_clock::now() - overload_started >= 50ms; }, 1s));

  ASSERT_TRUE(release.advance_to(1U));
  ASSERT_TRUE(first.value_if()->wait_for(2s));
  auto second_status = second.value_if()->wait_for(2s);
  ASSERT_TRUE(second_status);
  EXPECT_EQ(second_status.value_if()->state, OperationState::error);
  EXPECT_EQ(second_status.value_if()->error->code(), ErrorCode::timeout);
  EXPECT_TRUE(wait_until([&] { return executor.get_failure_status().timeout_count >= 1U; }, 2s));
  (void)runtime.value_if()->shutdown();
  (void)executor.shutdown(true);
}

}  // namespace
}  // namespace heyaki
