#include <heyaki/runtime.hpp>

#include "runtime_access.hpp"

#include <heyaki/identity.hpp>

#include <executor/comm.hpp>
#include <executor/executor.hpp>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include <sodium.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace heyaki {
namespace detail {
namespace {

bool valid_runtime_text(std::string_view value, std::size_t maximum_size,
                        bool allow_empty) noexcept {
  if ((!allow_empty && value.empty()) || value.size() > maximum_size) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](unsigned char character) {
    return character >= 0x21U && character <= 0x7eU;
  });
}

Result<void> validate_config(const RuntimeConfig& config) {
  if (config.callback_capacity == 0U || config.shutdown_hook_capacity == 0U ||
      config.executor_queue_capacity == 0U ||
      config.executor_min_threads == 0U ||
      config.executor_max_threads < config.executor_min_threads ||
      !valid_runtime_text(config.worker_name, 64U, false) ||
      config.worker_start_timeout.count() < 0 || config.callback_drain_timeout.count() < 0 ||
      config.producer_stop_timeout.count() < 0 ||
      config.service_cancel_timeout.count() < 0 || config.peer_close_timeout.count() < 0 ||
      config.relay_unregister_timeout.count() < 0 ||
      config.operation_drain_timeout.count() < 0 || config.worker_stop_timeout.count() < 0 ||
      config.persistence_flush_timeout.count() < 0 ||
      config.executor_drain_timeout.count() < 0) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "runtime", "invalid_runtime_configuration"});
  }
  return Result<void>::success();
}

bool valid_shutdown_stage(RuntimeShutdownStage stage) noexcept {
  switch (stage) {
    case RuntimeShutdownStage::stop_producers:
    case RuntimeShutdownStage::cancel_services:
    case RuntimeShutdownStage::close_peers:
    case RuntimeShutdownStage::unregister_relay:
    case RuntimeShutdownStage::flush_persistence:
      return true;
  }
  return false;
}

Result<void> validate_security_context(const RuntimeSecurityContext& security) {
  if (!valid_runtime_text(security.application_id, 255U, false) ||
      !valid_runtime_text(security.authorization_scope, 256U, true) ||
      security.epoch.value() == 0U ||
      (security.peer_id && security.peer_id->is_zero()) ||
      (security.endpoint_id && security.endpoint_id->is_zero())) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "runtime", "invalid_security_context"});
  }
  return Result<void>::success();
}

OperationId make_operation_id() {
  OperationId::Storage bytes{};
  randombytes_buf(bytes.data(), bytes.size());
  return OperationId{bytes};
}

Error attach_operation(const Error& error, const OperationId& operation_id) {
  return Error{error.code(), std::string{error.component()}, std::string{error.safe_detail()},
               error.underlying_code(), error.peer_id(), operation_id};
}

executor::comm::ChannelOptions callback_channel_options(std::size_t capacity) {
  executor::comm::ChannelOptions options;
  options.capacity = capacity;
  options.drop_policy = executor::comm::DropPolicy::RejectNewest;
  options.enable_stats = true;
  options.name = "heyaki-runtime-callbacks";
  return options;
}

executor::comm::ChannelOptions shutdown_hook_channel_options(std::size_t capacity) {
  executor::comm::ChannelOptions options;
  options.capacity = capacity;
  options.drop_policy = executor::comm::DropPolicy::RejectNewest;
  options.enable_stats = true;
  options.name = "heyaki-runtime-shutdown-hooks";
  return options;
}

}  // namespace

struct RuntimeMetricSample {
  std::uint64_t callbacks_accepted{};
  std::uint64_t callbacks_rejected{};
  std::uint64_t callbacks_completed{};
  std::uint64_t callback_exception_count{};
  std::uint64_t handler_exception_count{};
  std::uint64_t outstanding_operations{};
};

class RuntimeDiagnostics {
 public:
  RuntimeDiagnostics() : metrics_("heyaki-runtime-metrics") { publish(); }

  void record_accepted() noexcept {
    callbacks_accepted_.fetch_add(1U, std::memory_order_relaxed);
    outstanding_operations_.fetch_add(1U, std::memory_order_relaxed);
    publish();
  }

  void record_rejected() noexcept {
    callbacks_rejected_.fetch_add(1U, std::memory_order_relaxed);
    publish();
  }

  void record_completed() noexcept {
    callbacks_completed_.fetch_add(1U, std::memory_order_relaxed);
    outstanding_operations_.fetch_sub(1U, std::memory_order_relaxed);
    publish();
  }

  void record_callback_exception() noexcept {
    callback_exception_count_.fetch_add(1U, std::memory_order_relaxed);
    publish();
  }

  void record_handler_exception() noexcept {
    handler_exception_count_.fetch_add(1U, std::memory_order_relaxed);
    publish();
  }

  void record_executor_event() noexcept { publish(); }

  bool load_metrics(RuntimeMetricSample& sample, std::uint64_t& sequence) const {
    const std::uint64_t previous = last_read_sequence_.load(std::memory_order_relaxed);
    if (metrics_.try_load_newer_than(previous, sample, sequence)) {
      last_read_sequence_.store(sequence, std::memory_order_relaxed);
      return true;
    }
    if (!metrics_.try_load(sample)) {
      return false;
    }
    sequence = metrics_.sequence();
    last_read_sequence_.store(sequence, std::memory_order_relaxed);
    return true;
  }

  executor::comm::CommStats metric_stats() const noexcept { return metrics_.stats(); }

 private:
  RuntimeMetricSample sample() const noexcept {
    return RuntimeMetricSample{
        .callbacks_accepted = callbacks_accepted_.load(std::memory_order_relaxed),
        .callbacks_rejected = callbacks_rejected_.load(std::memory_order_relaxed),
        .callbacks_completed = callbacks_completed_.load(std::memory_order_relaxed),
        .callback_exception_count =
            callback_exception_count_.load(std::memory_order_relaxed),
        .handler_exception_count = handler_exception_count_.load(std::memory_order_relaxed),
        .outstanding_operations = outstanding_operations_.load(std::memory_order_relaxed)};
  }

  void publish() noexcept { (void)metrics_.try_publish(sample()); }

  std::atomic<std::uint64_t> callbacks_accepted_{0U};
  std::atomic<std::uint64_t> callbacks_rejected_{0U};
  std::atomic<std::uint64_t> callbacks_completed_{0U};
  std::atomic<std::uint64_t> callback_exception_count_{0U};
  std::atomic<std::uint64_t> handler_exception_count_{0U};
  std::atomic<std::uint64_t> outstanding_operations_{0U};
  mutable std::atomic<std::uint64_t> last_read_sequence_{0U};
  mutable executor::comm::LatestMailbox<RuntimeMetricSample> metrics_;
};

class RuntimeOperationState {
 public:
  RuntimeOperationState(OperationId id, SessionEpoch epoch,
                        std::shared_ptr<RuntimeDiagnostics> diagnostics)
      : id_(id), epoch_(epoch), diagnostics_(std::move(diagnostics)),
        completion_(promise_.get_future().share()) {}

  OperationId id() const noexcept { return id_; }
  bool terminal() const noexcept { return terminal_.load(std::memory_order_acquire); }
  const std::shared_future<OperationStatus>& completion() const noexcept { return completion_; }

  bool complete(OperationState state, std::optional<Error> error = std::nullopt) noexcept {
    bool expected = false;
    if (!terminal_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
      return false;
    }
    OperationStatus status{.id = id_, .epoch = epoch_, .state = state, .error = std::move(error)};
    diagnostics_->record_completed();
    try {
      promise_.set_value(std::move(status));
    } catch (...) {
      return false;
    }
    return true;
  }

 private:
  OperationId id_;
  SessionEpoch epoch_;
  std::shared_ptr<RuntimeDiagnostics> diagnostics_;
  std::atomic<bool> terminal_{false};
  std::promise<OperationStatus> promise_;
  std::shared_future<OperationStatus> completion_;
};

class RuntimeState;

class RuntimeContextState {
 public:
  RuntimeContextState(std::weak_ptr<RuntimeState> runtime, RuntimeContextKind kind,
                      std::string name, boost::asio::io_context& io)
      : runtime(std::move(runtime)), kind(kind), name(std::move(name)),
        strand(boost::asio::make_strand(io)) {}

  std::weak_ptr<RuntimeState> runtime;
  RuntimeContextKind kind;
  std::string name;
  boost::asio::strand<boost::asio::io_context::executor_type> strand;
};

struct RuntimeCallbackEvent {
  std::shared_ptr<RuntimeContextState> context;
  std::shared_ptr<RuntimeOperationState> operation;
  RuntimeSecurityContext security;
  RuntimeStateCallback state_callback;
  RuntimeUserHandler user_handler;
};

struct RuntimeCoreState {
  RuntimeOwnership ownership{RuntimeOwnership::borrowed};
  RuntimePhase phase{RuntimePhase::stopped};
};

struct TrackedTask {
  std::shared_ptr<RuntimeOperationState> operation;
  std::future<void> future;
};

struct InternalTask {
  std::string name;
  std::future<void> future;
};

class AsioWorker final : public executor::IBlockingIoWorker {
 public:
  explicit AsioWorker(boost::asio::io_context& io) : io_(io) {}

  void run(std::stop_token stop_token) override {
    if (!stop_token.stop_requested()) {
      io_.run();
    }
  }

  void wakeup() noexcept override { io_.stop(); }

 private:
  boost::asio::io_context& io_;
};

class RuntimeState : public std::enable_shared_from_this<RuntimeState> {
 public:
  RuntimeState(RuntimeOwnership ownership, RuntimeConfig config,
               std::unique_ptr<executor::Executor> owned_executor,
               executor::Executor* borrowed_executor)
      : owned_executor_(std::move(owned_executor)),
        executor_(owned_executor_ ? owned_executor_.get() : borrowed_executor),
        ownership_(ownership), config_(std::move(config)),
        callbacks_(callback_channel_options(config_.callback_capacity)),
        shutdown_hooks_(shutdown_hook_channel_options(config_.shutdown_hook_capacity)),
        diagnostics_(std::make_shared<RuntimeDiagnostics>()),
        core_state_(RuntimeCoreState{.ownership = ownership_, .phase = RuntimePhase::stopped},
                    "heyaki-runtime-state") {}

  ~RuntimeState() {
    admission_open_.store(false, std::memory_order_release);
    callbacks_.close();
    shutdown_hooks_.close();
    work_guard_.reset();
    io_.stop();
    if (!worker_.name().empty()) {
      worker_.stop();
    }
    if (owned_executor_) {
      (void)owned_executor_->shutdown(false);
    }
  }

  Result<void> start() {
    if (ownership_ == RuntimeOwnership::owned) {
      std::weak_ptr<RuntimeDiagnostics> diagnostics = diagnostics_;
      executor_->set_failure_callback([diagnostics](const executor::ExecutorFailureEvent&) {
        if (auto current = diagnostics.lock()) {
          current->record_executor_event();
        }
      });
    }
    work_guard_.emplace(boost::asio::make_work_guard(io_));
    executor::BlockingWorkerSpec spec;
    spec.name = config_.worker_name;
    spec.config.thread_name = config_.worker_name;
    spec.config.startup_timeout = config_.worker_start_timeout;
    spec.worker = std::make_unique<AsioWorker>(io_);
    worker_ = executor_->start_worker(std::move(spec));
    if (!worker_.started()) {
      work_guard_.reset();
      io_.stop();
      return Result<void>::failure(
          Error{ErrorCode::internal, "runtime", "asio_worker_start_failed",
                static_cast<std::int64_t>(worker_.start_result().error_code)});
    }
    admission_open_.store(true, std::memory_order_release);
    publish_phase(RuntimePhase::running);
    return Result<void>::success();
  }

  Result<RuntimeContext> create_context(RuntimeContextKind kind, std::string name) {
    if (!admission_open_.load(std::memory_order_acquire)) {
      return Result<RuntimeContext>::failure(
          Error{ErrorCode::cancelled, "runtime", "runtime_admission_closed"});
    }
    if (!valid_runtime_text(name, 64U, false)) {
      return Result<RuntimeContext>::failure(
          Error{ErrorCode::configuration, "runtime", "invalid_runtime_context"});
    }
    auto context = std::make_shared<RuntimeContextState>(shared_from_this(), kind,
                                                         std::move(name), io_);
    return Result<RuntimeContext>::success(RuntimeContext{std::move(context)});
  }

  Result<void> register_shutdown_hook(RuntimeShutdownHook hook) {
    if (!admission_open_.load(std::memory_order_acquire)) {
      return Result<void>::failure(
          Error{ErrorCode::cancelled, "runtime", "runtime_admission_closed"});
    }
    if (!valid_shutdown_stage(hook.stage) || !valid_runtime_text(hook.name, 64U, false) ||
        !hook.begin) {
      return Result<void>::failure(
          Error{ErrorCode::configuration, "runtime", "invalid_shutdown_hook"});
    }
    if (!shutdown_hooks_.try_send(std::move(hook))) {
      const bool closed = shutdown_hooks_.is_closed() ||
                          !admission_open_.load(std::memory_order_acquire);
      return Result<void>::failure(
          Error{closed ? ErrorCode::cancelled : ErrorCode::resource_exhausted, "runtime",
                closed ? "runtime_admission_closed" : "shutdown_hook_capacity_exhausted"});
    }
    return Result<void>::success();
  }

  Result<RuntimeOperation> enqueue(const std::shared_ptr<RuntimeContextState>& context,
                                   RuntimeSecurityContext security,
                                   RuntimeStateCallback state_callback,
                                   RuntimeUserHandler user_handler) {
    const OperationId operation_id = make_operation_id();
    if (!admission_open_.load(std::memory_order_acquire)) {
      diagnostics_->record_rejected();
      return Result<RuntimeOperation>::failure(
          Error{ErrorCode::cancelled, "runtime", "runtime_admission_closed", std::nullopt,
                std::nullopt, operation_id});
    }
    auto security_valid = validate_security_context(security);
    if (!security_valid || !state_callback) {
      diagnostics_->record_rejected();
      return Result<RuntimeOperation>::failure(
          Error{ErrorCode::configuration, "runtime", "invalid_runtime_submission",
                std::nullopt, security.peer_id, operation_id});
    }

    auto operation = std::make_shared<RuntimeOperationState>(operation_id, security.epoch,
                                                             diagnostics_);
    RuntimeCallbackEvent event{.context = context,
                               .operation = operation,
                               .security = std::move(security),
                               .state_callback = std::move(state_callback),
                               .user_handler = std::move(user_handler)};
    pending_context_callbacks_.fetch_add(1U, std::memory_order_acq_rel);
    if (!callbacks_.try_send(std::move(event))) {
      pending_context_callbacks_.fetch_sub(1U, std::memory_order_acq_rel);
      diagnostics_->record_rejected();
      const bool closed = callbacks_.is_closed() ||
                          !admission_open_.load(std::memory_order_acquire);
      return Result<RuntimeOperation>::failure(
          Error{closed ? ErrorCode::cancelled : ErrorCode::resource_exhausted, "runtime",
                closed ? "runtime_admission_closed" : "callback_queue_full", std::nullopt,
                std::nullopt, operation_id});
    }
    diagnostics_->record_accepted();
    try {
      std::weak_ptr<RuntimeState> weak = weak_from_this();
      boost::asio::post(io_, [weak] {
        if (auto self = weak.lock()) {
          self->drain_one();
        }
      });
    } catch (...) {
      admission_open_.store(false, std::memory_order_release);
      publish_phase(RuntimePhase::failed);
      operation->complete(
          OperationState::error,
          Error{ErrorCode::internal, "runtime", "asio_callback_schedule_failed", std::nullopt,
                std::nullopt, operation_id});
    }
    return Result<RuntimeOperation>::success(RuntimeOperation{std::move(operation)});
  }

  RuntimeSnapshot snapshot() const {
    RuntimeSnapshot output;
    const auto core = core_state_.load();
    output.ownership = core.value.ownership;
    output.phase = core.value.phase;
    output.state_sequence = core.sequence;

    RuntimeMetricSample metrics;
    std::uint64_t metric_sequence = 0U;
    if (diagnostics_->load_metrics(metrics, metric_sequence)) {
      output.metric_sequence = metric_sequence;
      output.callbacks_accepted = metrics.callbacks_accepted;
      output.callbacks_rejected = metrics.callbacks_rejected;
      output.callbacks_completed = metrics.callbacks_completed;
      output.callback_exception_count = metrics.callback_exception_count;
      output.handler_exception_count = metrics.handler_exception_count;
      output.outstanding_operations = metrics.outstanding_operations;
    }
    const auto callback_stats = callbacks_.stats();
    output.callback_queue_depth = callback_stats.current_depth;
    output.callback_queue_peak_depth = callback_stats.peak_depth;
    output.callback_queue_dropped = callback_stats.dropped_count;
    const auto metric_stats = diagnostics_->metric_stats();
    output.metric_overwritten_count = metric_stats.overwritten_count;
    output.metric_stale_read_count = metric_stats.stale_read_count;
    output.metric_consumer_lag = metric_stats.consumer_lag;

    const auto failures = executor_->get_failure_status();
    output.executor_submit_rejected_count = failures.submit_rejected_count;
    output.executor_task_exception_count = failures.task_exception_count;
    output.executor_wait_timeout_count = failures.wait_timeout_count;
    const auto worker_status = worker_.status();
    output.worker_ready = worker_status.ready;
    output.worker_running = worker_status.is_running;
    return output;
  }

  RuntimeShutdownReport shutdown() {
    if (shutdown_started_.exchange(true, std::memory_order_acq_rel)) {
      return last_shutdown_report_;
    }

    RuntimeShutdownReport report;
    admission_open_.store(false, std::memory_order_release);
    publish_phase(RuntimePhase::stopping_admission);
    shutdown_hooks_.close();
    auto shutdown_hooks = collect_shutdown_hooks();
    run_shutdown_stage(RuntimeShutdownStage::stop_producers, shutdown_hooks, report);
    run_shutdown_stage(RuntimeShutdownStage::cancel_services, shutdown_hooks, report);
    run_shutdown_stage(RuntimeShutdownStage::close_peers, shutdown_hooks, report);
    run_shutdown_stage(RuntimeShutdownStage::unregister_relay, shutdown_hooks, report);
    callbacks_.close();
    publish_phase(RuntimePhase::draining);

    auto barrier = std::make_shared<std::promise<void>>();
    auto barrier_future = barrier->get_future();
    try {
      std::weak_ptr<RuntimeState> weak = weak_from_this();
      boost::asio::post(io_, [weak, barrier] {
        if (auto self = weak.lock()) {
          self->drain_for_shutdown(barrier);
        }
      });
    } catch (...) {
      report.callback_drain_timed_out = true;
    }
    if (!report.callback_drain_timed_out &&
        barrier_future.wait_for(config_.callback_drain_timeout) != std::future_status::ready) {
      report.callback_drain_timed_out = true;
    }

    work_guard_.reset();
    worker_.request_stop();
    const auto worker_deadline = std::chrono::steady_clock::now() + config_.worker_stop_timeout;
    while (worker_.status().is_running && std::chrono::steady_clock::now() < worker_deadline) {
      std::this_thread::yield();
    }
    if (worker_.status().is_running) {
      report.worker_stop_timed_out = true;
    }
    worker_.stop();

    cancel_callbacks_left_after_worker_stop(report);
    drain_tracked_tasks(report);
    drain_internal_tasks(report);
    cancel_pending_operations(report);
    run_shutdown_stage(RuntimeShutdownStage::flush_persistence, shutdown_hooks, report);

    if (ownership_ == RuntimeOwnership::owned) {
      const auto waited = executor_->wait_for_completion_ex(config_.executor_drain_timeout);
      report.executor_drain_timed_out = waited.timed_out;
      (void)executor_->shutdown(waited.completed);
      report.executor_shutdown_performed = true;
    }

    publish_phase(RuntimePhase::stopped);
    report.final_phase = RuntimePhase::stopped;
    last_shutdown_report_ = report;
    return report;
  }

  RuntimeOwnership ownership() const noexcept { return ownership_; }
  boost::asio::any_io_executor io_executor() { return io_.get_executor(); }
  Result<void> dispatch_general(std::string name, std::function<void()> task) {
    if (!admission_open_.load(std::memory_order_acquire) || !task) {
      return Result<void>::failure(
          Error{ErrorCode::cancelled, "runtime", "runtime_admission_closed"});
    }
    try {
      auto future = executor_->submit_auto(
          executor::task(std::move(task))
              .name(name)
              .intent(executor::ExecutionIntent::GeneralCpu));
      if (future.wait_for(std::chrono::milliseconds{0}) == std::future_status::ready) {
        future.get();
        return Result<void>::success();
      }
      prune_internal_tasks();
      auto tracked = std::make_shared<InternalTask>(
          InternalTask{.name = std::move(name), .future = std::move(future)});
      internal_tasks_.push_back(tracked);
      watch_internal_task(tracked);
      return Result<void>::success();
    } catch (...) {
      diagnostics_->record_executor_event();
      return Result<void>::failure(
          Error{ErrorCode::resource_exhausted, "runtime", "executor_dispatch_rejected"});
    }
  }

 private:
  struct StartedShutdownHook {
    std::size_t report_index{};
    RuntimeShutdownCompletion completion;
  };

  void publish_phase(RuntimePhase phase) noexcept {
    phase_.store(phase, std::memory_order_release);
    (void)core_state_.try_publish(RuntimeCoreState{.ownership = ownership_, .phase = phase});
  }

  std::chrono::milliseconds shutdown_stage_timeout(RuntimeShutdownStage stage) const noexcept {
    switch (stage) {
      case RuntimeShutdownStage::stop_producers:
        return config_.producer_stop_timeout;
      case RuntimeShutdownStage::cancel_services:
        return config_.service_cancel_timeout;
      case RuntimeShutdownStage::close_peers:
        return config_.peer_close_timeout;
      case RuntimeShutdownStage::unregister_relay:
        return config_.relay_unregister_timeout;
      case RuntimeShutdownStage::flush_persistence:
        return config_.persistence_flush_timeout;
    }
    return std::chrono::milliseconds{0};
  }

  std::vector<RuntimeShutdownHook> collect_shutdown_hooks() {
    std::vector<RuntimeShutdownHook> hooks;
    hooks.reserve(shutdown_hooks_.size_approx());
    RuntimeShutdownHook hook;
    while (shutdown_hooks_.try_receive(hook)) {
      hooks.push_back(std::move(hook));
    }
    return hooks;
  }

  void run_shutdown_stage(RuntimeShutdownStage stage,
                          const std::vector<RuntimeShutdownHook>& hooks,
                          RuntimeShutdownReport& report) {
    std::vector<StartedShutdownHook> started;
    started.reserve(hooks.size());
    for (const auto& hook : hooks) {
      if (hook.stage != stage) {
        continue;
      }
      const std::size_t report_index = report.hooks.size();
      report.hooks.push_back(RuntimeShutdownHookReport{
          .stage = stage,
          .name = hook.name,
          .outcome = RuntimeShutdownHookOutcome::success,
          .error = std::nullopt});
      try {
        auto completion = hook.begin();
        if (!completion) {
          report.hooks[report_index].outcome = RuntimeShutdownHookOutcome::error;
          report.hooks[report_index].error = *completion.error_if();
          continue;
        }
        if (!completion.value_if()->valid()) {
          report.hooks[report_index].outcome = RuntimeShutdownHookOutcome::error;
          report.hooks[report_index].error =
              Error{ErrorCode::internal, "runtime", "shutdown_hook_completion_invalid"};
          continue;
        }
        started.push_back(StartedShutdownHook{
            .report_index = report_index, .completion = std::move(*completion.value_if())});
      } catch (...) {
        report.hooks[report_index].outcome = RuntimeShutdownHookOutcome::error;
        report.hooks[report_index].error =
            Error{ErrorCode::internal, "runtime", "shutdown_hook_begin_exception"};
      }
    }

    const auto deadline = std::chrono::steady_clock::now() + shutdown_stage_timeout(stage);
    for (auto& hook : started) {
      if (hook.completion.wait_until(deadline) != std::future_status::ready) {
        report.hooks[hook.report_index].outcome = RuntimeShutdownHookOutcome::timed_out;
        report.hooks[hook.report_index].error =
            Error{ErrorCode::timeout, "runtime", "shutdown_hook_timeout"};
        continue;
      }
      try {
        const auto& result = hook.completion.get();
        if (!result) {
          report.hooks[hook.report_index].outcome = RuntimeShutdownHookOutcome::error;
          report.hooks[hook.report_index].error = *result.error_if();
        }
      } catch (...) {
        report.hooks[hook.report_index].outcome = RuntimeShutdownHookOutcome::error;
        report.hooks[hook.report_index].error =
            Error{ErrorCode::internal, "runtime", "shutdown_hook_completion_exception"};
      }
    }
  }

  void register_operation(const std::shared_ptr<RuntimeOperationState>& operation) {
    operations_.push_back(operation);
  }

  void drain_one() {
    RuntimeCallbackEvent event;
    if (!callbacks_.try_receive(event)) {
      return;
    }
    register_operation(event.operation);
    post_to_context(std::move(event));
  }

  void post_to_context(RuntimeCallbackEvent event) {
    auto context = event.context;
    try {
      std::weak_ptr<RuntimeState> weak = weak_from_this();
      boost::asio::post(context->strand,
                        [weak, event = std::move(event)]() mutable {
                          if (auto self = weak.lock()) {
                            self->process_event(std::move(event));
                          }
                        });
    } catch (...) {
      event.operation->complete(
          OperationState::error,
          Error{ErrorCode::internal, "runtime", "strand_callback_schedule_failed",
                std::nullopt, std::nullopt, event.operation->id()});
      pending_context_callbacks_.fetch_sub(1U, std::memory_order_acq_rel);
    }
  }

  void process_event(RuntimeCallbackEvent event) {
    if (event.operation->terminal()) {
      pending_context_callbacks_.fetch_sub(1U, std::memory_order_acq_rel);
      return;
    }

    Result<void> state_result = Result<void>::success();
    try {
      state_result = event.state_callback();
    } catch (...) {
      diagnostics_->record_callback_exception();
      state_result = Result<void>::failure(
          Error{ErrorCode::internal, "runtime", "runtime_callback_exception", std::nullopt,
                event.security.peer_id, event.operation->id()});
    }
    if (!state_result) {
      event.operation->complete(OperationState::error,
                                attach_operation(*state_result.error_if(), event.operation->id()));
      pending_context_callbacks_.fetch_sub(1U, std::memory_order_acq_rel);
      return;
    }
    if (!event.user_handler) {
      event.operation->complete(OperationState::success);
      pending_context_callbacks_.fetch_sub(1U, std::memory_order_acq_rel);
      return;
    }

    auto operation = event.operation;
    auto security = std::move(event.security);
    auto handler = std::move(event.user_handler);
    auto diagnostics = diagnostics_;
    try {
      auto submission = executor_->submit_with_handle(
          [operation, security = std::move(security), handler = std::move(handler),
           diagnostics]() mutable {
            try {
              auto result = handler(security);
              if (result) {
                operation->complete(OperationState::success);
              } else {
                operation->complete(OperationState::error,
                                    attach_operation(*result.error_if(), operation->id()));
              }
            } catch (...) {
              diagnostics->record_handler_exception();
              operation->complete(
                  OperationState::error,
                  Error{ErrorCode::internal, "runtime", "runtime_handler_exception",
                        std::nullopt, security.peer_id, operation->id()});
              throw;
            }
          });
      prune_tracked_tasks();
      auto task = std::make_shared<TrackedTask>(
          TrackedTask{.operation = operation, .future = std::move(submission.future)});
      tracked_tasks_.push_back(task);
      watch_task(task);
    } catch (...) {
      operation->complete(
          OperationState::error,
          Error{ErrorCode::would_block, "runtime", "executor_submit_rejected", std::nullopt,
                event.security.peer_id, operation->id()});
    }
    pending_context_callbacks_.fetch_sub(1U, std::memory_order_acq_rel);
  }

  void observe_ready_task(const std::shared_ptr<TrackedTask>& task) {
    if (!task->future.valid() ||
        task->future.wait_for(std::chrono::milliseconds{0}) != std::future_status::ready) {
      return;
    }
    try {
      task->future.get();
    } catch (const executor::TimedOutException&) {
      task->operation->complete(
          OperationState::error,
          Error{ErrorCode::timeout, "runtime", "executor_task_timeout", std::nullopt,
                std::nullopt, task->operation->id()});
    } catch (...) {
      task->operation->complete(
          OperationState::error,
          Error{ErrorCode::would_block, "runtime", "executor_submit_rejected", std::nullopt,
                std::nullopt, task->operation->id()});
    }
  }

  void watch_task(const std::shared_ptr<TrackedTask>& task) {
    if (task->operation->terminal()) {
      return;
    }
    if (task->future.valid() &&
        task->future.wait_for(std::chrono::milliseconds{0}) == std::future_status::ready) {
      observe_ready_task(task);
      return;
    }
    auto timer = std::make_shared<boost::asio::steady_timer>(io_, std::chrono::milliseconds{10});
    std::weak_ptr<RuntimeState> weak = weak_from_this();
    timer->async_wait([weak, task, timer](const boost::system::error_code& error) {
      if (!error) {
        if (auto self = weak.lock()) {
          self->watch_task(task);
        }
      }
    });
  }

  void prune_tracked_tasks() {
    for (const auto& task : tracked_tasks_) {
      observe_ready_task(task);
    }
    std::erase_if(tracked_tasks_, [](const auto& task) { return !task->future.valid(); });
  }

  void observe_internal_task(const std::shared_ptr<InternalTask>& task) {
    if (!task->future.valid() ||
        task->future.wait_for(std::chrono::milliseconds{0}) !=
            std::future_status::ready) {
      return;
    }
    try {
      task->future.get();
    } catch (...) {
      diagnostics_->record_executor_event();
    }
  }

  void watch_internal_task(const std::shared_ptr<InternalTask>& task) {
    if (!task->future.valid()) {
      return;
    }
    if (task->future.wait_for(std::chrono::milliseconds{0}) ==
        std::future_status::ready) {
      observe_internal_task(task);
      return;
    }
    auto timer = std::make_shared<boost::asio::steady_timer>(
        io_, std::chrono::milliseconds{10});
    std::weak_ptr<RuntimeState> weak = weak_from_this();
    timer->async_wait([weak, task, timer](const boost::system::error_code& error) {
      if (!error) {
        if (auto self = weak.lock()) {
          self->watch_internal_task(task);
        }
      }
    });
  }

  void prune_internal_tasks() {
    for (const auto& task : internal_tasks_) {
      observe_internal_task(task);
    }
    std::erase_if(internal_tasks_,
                  [](const auto& task) { return !task->future.valid(); });
  }

  void drain_for_shutdown(const std::shared_ptr<std::promise<void>>& barrier) {
    RuntimeCallbackEvent event;
    while (callbacks_.try_receive(event)) {
      register_operation(event.operation);
      post_to_context(std::move(event));
    }
    if (callbacks_.is_drained() &&
        pending_context_callbacks_.load(std::memory_order_acquire) == 0U) {
      try {
        barrier->set_value();
      } catch (...) {
      }
      return;
    }
    try {
      std::weak_ptr<RuntimeState> weak = weak_from_this();
      boost::asio::post(io_, [weak, barrier] {
        if (auto self = weak.lock()) {
          self->drain_for_shutdown(barrier);
        }
      });
    } catch (...) {
      try {
        barrier->set_exception(std::current_exception());
      } catch (...) {
      }
    }
  }

  void cancel_callbacks_left_after_worker_stop(RuntimeShutdownReport& report) {
    RuntimeCallbackEvent event;
    while (callbacks_.try_receive(event)) {
      register_operation(event.operation);
      if (event.operation->complete(
              OperationState::cancelled,
              Error{ErrorCode::cancelled, "runtime", "callback_cancelled_during_shutdown",
                    std::nullopt, event.security.peer_id, event.operation->id()})) {
        report.incomplete_operations.push_back(event.operation->id());
      }
    }
  }

  void drain_tracked_tasks(RuntimeShutdownReport& report) {
    const auto deadline = std::chrono::steady_clock::now() + config_.operation_drain_timeout;
    for (const auto& task : tracked_tasks_) {
      if (!task->future.valid()) {
        continue;
      }
      if (task->future.wait_until(deadline) == std::future_status::ready) {
        observe_ready_task(task);
        continue;
      }
      report.operation_drain_timed_out = true;
      if (task->operation->complete(
              OperationState::cancelled,
              Error{ErrorCode::timeout, "runtime", "operation_drain_timeout", std::nullopt,
                    std::nullopt, task->operation->id()})) {
        report.incomplete_operations.push_back(task->operation->id());
      }
    }
  }

  void drain_internal_tasks(RuntimeShutdownReport& report) {
    const auto deadline = std::chrono::steady_clock::now() +
                          config_.operation_drain_timeout;
    for (const auto& task : internal_tasks_) {
      if (!task->future.valid()) {
        continue;
      }
      if (task->future.wait_until(deadline) == std::future_status::ready) {
        observe_internal_task(task);
      } else {
        report.operation_drain_timed_out = true;
      }
    }
  }

  void cancel_pending_operations(RuntimeShutdownReport& report) {
    for (const auto& operation : operations_) {
      if (operation->complete(
              OperationState::cancelled,
              Error{ErrorCode::cancelled, "runtime", "operation_cancelled_during_shutdown",
                    std::nullopt, std::nullopt, operation->id()})) {
        report.incomplete_operations.push_back(operation->id());
      }
    }
    pending_context_callbacks_.store(0U, std::memory_order_release);
  }

  std::unique_ptr<executor::Executor> owned_executor_;
  executor::Executor* executor_;
  RuntimeOwnership ownership_;
  RuntimeConfig config_;
  boost::asio::io_context io_;
  std::optional<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>
      work_guard_;
  executor::comm::MpscChannel<RuntimeCallbackEvent> callbacks_;
  executor::comm::MpscChannel<RuntimeShutdownHook> shutdown_hooks_;
  std::shared_ptr<RuntimeDiagnostics> diagnostics_;
  executor::comm::DoubleBuffer<RuntimeCoreState> core_state_;
  executor::WorkerHandle worker_;
  std::vector<std::shared_ptr<RuntimeOperationState>> operations_;
  std::vector<std::shared_ptr<TrackedTask>> tracked_tasks_;
  std::vector<std::shared_ptr<InternalTask>> internal_tasks_;
  std::atomic<bool> admission_open_{false};
  std::atomic<bool> shutdown_started_{false};
  std::atomic<std::uint64_t> pending_context_callbacks_{0U};
  std::atomic<RuntimePhase> phase_{RuntimePhase::stopped};
  RuntimeShutdownReport last_shutdown_report_;
};

}  // namespace detail

RuntimeOperation::RuntimeOperation(std::shared_ptr<detail::RuntimeOperationState> state) noexcept
    : state_(std::move(state)) {}

OperationId RuntimeOperation::id() const noexcept {
  return state_ ? state_->id() : OperationId{};
}

Result<std::optional<OperationStatus>> RuntimeOperation::try_status() const {
  if (!state_) {
    return Result<std::optional<OperationStatus>>::failure(
        Error{ErrorCode::configuration, "runtime", "invalid_runtime_operation"});
  }
  if (state_->completion().wait_for(std::chrono::milliseconds{0}) != std::future_status::ready) {
    return Result<std::optional<OperationStatus>>::success(std::nullopt);
  }
  try {
    return Result<std::optional<OperationStatus>>::success(state_->completion().get());
  } catch (...) {
    return Result<std::optional<OperationStatus>>::failure(
        Error{ErrorCode::internal, "runtime", "operation_completion_unavailable", std::nullopt,
              std::nullopt, state_->id()});
  }
}

Result<OperationStatus> RuntimeOperation::wait_for(std::chrono::milliseconds timeout) const {
  if (!state_ || timeout.count() < 0) {
    return Result<OperationStatus>::failure(
        Error{ErrorCode::configuration, "runtime", "invalid_operation_wait"});
  }
  if (state_->completion().wait_for(timeout) != std::future_status::ready) {
    return Result<OperationStatus>::failure(
        Error{ErrorCode::timeout, "runtime", "operation_wait_timeout", std::nullopt,
              std::nullopt, state_->id()});
  }
  try {
    return Result<OperationStatus>::success(state_->completion().get());
  } catch (...) {
    return Result<OperationStatus>::failure(
        Error{ErrorCode::internal, "runtime", "operation_completion_unavailable", std::nullopt,
              std::nullopt, state_->id()});
  }
}

RuntimeContext::RuntimeContext(std::shared_ptr<detail::RuntimeContextState> state) noexcept
    : state_(std::move(state)) {}

RuntimeContextKind RuntimeContext::kind() const noexcept {
  return state_ ? state_->kind : RuntimeContextKind::node;
}

std::string_view RuntimeContext::name() const noexcept {
  return state_ ? std::string_view{state_->name} : std::string_view{};
}

Result<RuntimeOperation> RuntimeContext::submit(RuntimeSecurityContext security,
                                                RuntimeStateCallback state_callback,
                                                RuntimeUserHandler user_handler) const {
  if (!state_) {
    return Result<RuntimeOperation>::failure(
        Error{ErrorCode::configuration, "runtime", "invalid_runtime_context"});
  }
  auto runtime = state_->runtime.lock();
  if (!runtime) {
    return Result<RuntimeOperation>::failure(
        Error{ErrorCode::cancelled, "runtime", "runtime_not_available"});
  }
  return runtime->enqueue(state_, std::move(security), std::move(state_callback),
                          std::move(user_handler));
}

Runtime::Runtime(std::shared_ptr<detail::RuntimeState> state) noexcept
    : state_(std::move(state)) {}
Runtime::Runtime(Runtime&&) noexcept = default;
Runtime& Runtime::operator=(Runtime&& other) noexcept {
  if (this != &other) {
    if (state_) {
      (void)state_->shutdown();
    }
    state_ = std::move(other.state_);
  }
  return *this;
}
Runtime::~Runtime() {
  if (state_) {
    (void)state_->shutdown();
  }
}

Result<boost::asio::any_io_executor> detail::RuntimeAccess::io_executor(Runtime& runtime) {
  if (!runtime.state_ || runtime.state_->snapshot().phase != RuntimePhase::running) {
    return Result<boost::asio::any_io_executor>::failure(
        Error{ErrorCode::cancelled, "runtime", "runtime_not_running"});
  }
  return Result<boost::asio::any_io_executor>::success(runtime.state_->io_executor());
}

Result<void> detail::RuntimeAccess::dispatch_general(Runtime& runtime, std::string name,
                                                     std::function<void()> task) {
  if (!runtime.state_) {
    return Result<void>::failure(
        Error{ErrorCode::cancelled, "runtime", "runtime_not_running"});
  }
  return runtime.state_->dispatch_general(std::move(name), std::move(task));
}

Result<Runtime> Runtime::create_borrowed(executor::Executor& executor,
                                         const RuntimeConfig& config) {
  auto valid = detail::validate_config(config);
  if (!valid) {
    return Result<Runtime>::failure(*valid.error_if());
  }
  const auto crypto = initialize_crypto();
  if (!crypto) {
    return Result<Runtime>::failure(*crypto.error_if());
  }
  const auto executor_snapshot = executor.get_snapshot();
  if (executor_snapshot.lifecycle != executor::ExecutorLifecycleState::Running ||
      !executor_snapshot.async.is_running) {
    return Result<Runtime>::failure(
        Error{ErrorCode::configuration, "runtime", "borrowed_executor_not_running"});
  }
  auto state = std::make_shared<detail::RuntimeState>(RuntimeOwnership::borrowed, config, nullptr,
                                                      &executor);
  const auto started = state->start();
  if (!started) {
    return Result<Runtime>::failure(*started.error_if());
  }
  return Result<Runtime>::success(Runtime{std::move(state)});
}

Result<Runtime> Runtime::create_owned(const RuntimeConfig& config) {
  auto valid = detail::validate_config(config);
  if (!valid) {
    return Result<Runtime>::failure(*valid.error_if());
  }
  const auto crypto = initialize_crypto();
  if (!crypto) {
    return Result<Runtime>::failure(*crypto.error_if());
  }
  auto owned_executor = std::make_unique<executor::Executor>();
  executor::ExecutorConfig executor_config;
  executor_config.min_threads = config.executor_min_threads;
  executor_config.max_threads = config.executor_max_threads;
  executor_config.queue_capacity = config.executor_queue_capacity;
  executor_config.enable_monitoring = true;
  const auto initialized = owned_executor->initialize_ex(executor_config);
  if (!initialized) {
    return Result<Runtime>::failure(
        Error{ErrorCode::configuration, "runtime", "executor_initialize_failed",
              static_cast<std::int64_t>(initialized.error_code)});
  }
  auto state = std::make_shared<detail::RuntimeState>(
      RuntimeOwnership::owned, config, std::move(owned_executor), nullptr);
  const auto started = state->start();
  if (!started) {
    return Result<Runtime>::failure(*started.error_if());
  }
  return Result<Runtime>::success(Runtime{std::move(state)});
}

RuntimeOwnership Runtime::ownership() const noexcept {
  return state_ ? state_->ownership() : RuntimeOwnership::borrowed;
}

Result<RuntimeContext> Runtime::create_context(RuntimeContextKind kind, std::string name) {
  if (!state_) {
    return Result<RuntimeContext>::failure(
        Error{ErrorCode::configuration, "runtime", "runtime_not_initialized"});
  }
  return state_->create_context(kind, std::move(name));
}

Result<void> Runtime::register_shutdown_hook(RuntimeShutdownHook hook) {
  if (!state_) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "runtime", "runtime_not_initialized"});
  }
  return state_->register_shutdown_hook(std::move(hook));
}

RuntimeSnapshot Runtime::snapshot() const {
  return state_ ? state_->snapshot() : RuntimeSnapshot{};
}

RuntimeShutdownReport Runtime::shutdown() {
  if (!state_) {
    return RuntimeShutdownReport{};
  }
  return state_->shutdown();
}

std::string_view runtime_phase_name(RuntimePhase phase) noexcept {
  switch (phase) {
    case RuntimePhase::running:
      return "running";
    case RuntimePhase::stopping_admission:
      return "stopping_admission";
    case RuntimePhase::draining:
      return "draining";
    case RuntimePhase::stopped:
      return "stopped";
    case RuntimePhase::failed:
      return "failed";
  }
  return "failed";
}

std::string_view runtime_shutdown_stage_name(RuntimeShutdownStage stage) noexcept {
  switch (stage) {
    case RuntimeShutdownStage::stop_producers:
      return "stop_producers";
    case RuntimeShutdownStage::cancel_services:
      return "cancel_services";
    case RuntimeShutdownStage::close_peers:
      return "close_peers";
    case RuntimeShutdownStage::unregister_relay:
      return "unregister_relay";
    case RuntimeShutdownStage::flush_persistence:
      return "flush_persistence";
  }
  return "unknown";
}

std::string_view runtime_shutdown_hook_outcome_name(
    RuntimeShutdownHookOutcome outcome) noexcept {
  switch (outcome) {
    case RuntimeShutdownHookOutcome::success:
      return "success";
    case RuntimeShutdownHookOutcome::error:
      return "error";
    case RuntimeShutdownHookOutcome::timed_out:
      return "timed_out";
  }
  return "unknown";
}

}  // namespace heyaki
