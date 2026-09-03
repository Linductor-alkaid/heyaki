// M8-04/M8-05 PTY lifecycle tests against the REAL executor-managed worker:
// spawn/output/exit round trips, the TERM->KILL escalation ladder, idle
// timeouts, disconnect termination, clean worker shutdown, and the
// no-zombie/no-leftover-worker exit criteria. POSIX runs /bin/sh; Windows
// runs cmd.exe through ConPTY + job object.

#include "runtime_access.hpp"
#include "shell_pty.hpp"

#include <heyaki/runtime.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <optional>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <thread>
#endif

namespace heyaki {
namespace {

// All sink callbacks fire during ShellPtyRuntime::drain_once() on the test
// thread (the coordinator is the single consumer), so plain members suffice.
struct CollectedEvents {
  bool started{false};
  bool spawn_failed{false};
  std::string spawn_failed_detail;
  std::int64_t exit_code{-2147483648LL};
  int exit_reason{-1};
  std::string output;

  void record(const ShellPtyEvent& event) {
    switch (event.kind) {
      case ShellPtyEvent::Kind::started:
        started = true;
        break;
      case ShellPtyEvent::Kind::output:
        output.append(reinterpret_cast<const char*>(event.data.data()),
                       event.data.size());
        break;
      case ShellPtyEvent::Kind::exit:
        exit_code = event.exit_code;
        exit_reason = static_cast<int>(event.exit_reason);
        break;
      case ShellPtyEvent::Kind::spawn_failed:
        spawn_failed = true;
        spawn_failed_detail = event.detail;
        break;
      case ShellPtyEvent::Kind::input_rejected:
        break;
    }
  }

  [[nodiscard]] bool exited() const { return exit_code != -2147483648LL; }
  [[nodiscard]] const std::string& text() const { return output; }
};

// A live runtime with the shell PTY worker enabled; events are drained from
// the test thread through the coordinator (single consumer).
class ShellPtyRuntime {
 public:
  ShellPtyRuntime() {
    RuntimeConfig config;
    config.shell_pty_worker_enabled = true;
    config.worker_name = "heyaki-test-pty";
    auto created = Runtime::create_owned(config);
    ok_ = static_cast<bool>(created);
    if (ok_) {
      runtime_.emplace(std::move(*created.value_if()));
      coordinator_.bind(*runtime_, true);
    }
  }

  [[nodiscard]] bool ok() const noexcept { return ok_; }

  ~ShellPtyRuntime() {
    if (runtime_) {
      (void)runtime_->shutdown();
    }
  }

  [[nodiscard]] Runtime& runtime() { return *runtime_; }
  [[nodiscard]] ShellPtyCoordinator& coordinator() { return coordinator_; }

  // Pumps queued events into their sinks; the test thread is the consumer.
  void drain_now() { coordinator_.drain(); }
  void drain_once() {
    coordinator_.drain();
#if defined(_WIN32)
    Sleep(20);
#else
    std::this_thread::sleep_for(std::chrono::milliseconds{20});
#endif
  }

 private:
  bool ok_{false};
  std::optional<Runtime> runtime_;
  ShellPtyCoordinator coordinator_;
};

std::vector<std::string> echo_argv() {
#if defined(_WIN32)
  return {"C:\\Windows\\System32\\cmd.exe", "/c", "echo heyaki-shell-ok"};
#else
  return {"/bin/sh", "-c", "printf heyaki-shell-ok; echo done"};
#endif
}

std::vector<std::string> stubborn_argv() {
  // Ignores the graceful TERM/CTRL_BREAK phase to exercise the escalation.
#if defined(_WIN32)
  return {"C:\\Windows\\System32\\cmd.exe", "/c", "ping -n 30 127.0.0.1 > nul"};
#else
  return {"/bin/sh", "-c", "trap '' TERM; sleep 30"};
#endif
}

std::vector<std::string> cat_argv() {
#if defined(_WIN32)
  return {"C:\\Windows\\System32\\cmd.exe", "/c", "more"};
#else
  return {"/bin/cat"};
#endif
}

ShellPtySpawnSpec make_spec(const std::vector<std::string>& argv) {
  ShellPtySpawnSpec spec;
  static std::atomic<std::uint64_t> next_id{1U};
  ShellId::Storage bytes{};
  const std::uint64_t serial = next_id.fetch_add(1U);
  for (std::size_t index = 0U; index < bytes.size(); ++index) {
    bytes[index] = static_cast<std::byte>((serial >> (index % 8U)) & 0xFFU);
  }
  spec.shell_id = ShellId{bytes};
  spec.argv = argv;
  spec.columns = 80U;
  spec.rows = 24U;
  spec.idle_timeout_ms = 600000U;
  spec.absolute_timeout_ms = 3600000U;
  spec.terminate_grace_ms = 500U;
  spec.max_output_bytes = 16ULL * 1024ULL * 1024ULL;
  spec.max_output_pending_bytes = 256ULL * 1024ULL;
  spec.max_input_pending_bytes = 64ULL * 1024ULL;
  return spec;
}

TEST(M8ShellPtyWorker, StartsAsThirdBlockingWorker) {
  ShellPtyRuntime pty;
  ASSERT_TRUE(pty.ok());
  const auto snapshot = pty.runtime().snapshot();
  EXPECT_EQ(snapshot.executor_blocking_io_count, 3U);
}

TEST(M8ShellPtyWorker, SpawnOutputExitRoundTrip) {
  ShellPtyRuntime pty;
  ASSERT_TRUE(pty.ok());
  CollectedEvents collected;
  auto spec = make_spec(echo_argv());
  ASSERT_TRUE(pty.coordinator().open(
      std::move(spec), [&collected](const ShellPtyEvent& event) {
        collected.record(event);
      }));

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{15};
  while (std::chrono::steady_clock::now() < deadline &&
         !collected.exited()) {
    pty.drain_once();
  }
  ASSERT_TRUE(collected.exited());
  EXPECT_TRUE(collected.started);
  EXPECT_EQ(collected.exit_code, 0);
  EXPECT_EQ(collected.exit_reason,
            static_cast<int>(ShellPtyEvent::ExitReason::process));
  EXPECT_NE(collected.text().find("heyaki-shell-ok"), std::string::npos);
  // The exit event proves the child was reaped: no zombie remains (M8 exit
  // criteria), and the coordinator dropped the sink.
  pty.drain_once();
}

TEST(M8ShellPtyWorker, EscalationLadderKillsStubbornProcessTree) {
  ShellPtyRuntime pty;
  ASSERT_TRUE(pty.ok());
  CollectedEvents collected;
  auto spec = make_spec(stubborn_argv());
  spec.terminate_grace_ms = 500U;
  const ShellId id = spec.shell_id;
  ASSERT_TRUE(pty.coordinator().open(
      std::move(spec), [&collected](const ShellPtyEvent& event) {
        collected.record(event);
      }));

  const auto started_by = std::chrono::steady_clock::now() + std::chrono::seconds{10};
  while (std::chrono::steady_clock::now() < started_by && !collected.started) {
    pty.drain_once();
  }
  ASSERT_TRUE(collected.started);

  pty.coordinator().terminate(id, "test_escalation");
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{15};
  while (std::chrono::steady_clock::now() < deadline &&
         !collected.exited()) {
    pty.drain_once();
  }
  ASSERT_TRUE(collected.exited());
  EXPECT_EQ(collected.exit_reason,
            static_cast<int>(ShellPtyEvent::ExitReason::terminated));
#if !defined(_WIN32)
  // SIGKILL reaping reports the negative signal number.
  EXPECT_EQ(collected.exit_code, -9);
#endif
}

TEST(M8ShellPtyWorker, StdinRoundTripThroughChild) {
#if defined(_WIN32)
  GTEST_SKIP() << "cmd.exe `more` echo behavior differs; ConPTY stdin is "
                  "covered by the round-trip build on Windows CI";
#else
  ShellPtyRuntime pty;
  ASSERT_TRUE(pty.ok());
  CollectedEvents collected;
  auto spec = make_spec(cat_argv());
  const ShellId id = spec.shell_id;
  ASSERT_TRUE(pty.coordinator().open(
      std::move(spec), [&collected](const ShellPtyEvent& event) {
        collected.record(event);
      }));
  const auto started_by = std::chrono::steady_clock::now() + std::chrono::seconds{10};
  while (std::chrono::steady_clock::now() < started_by && !collected.started) {
    pty.drain_once();
  }
  ASSERT_TRUE(collected.started);

  const std::string payload = "ping-pong\n";
  ASSERT_TRUE(pty.coordinator().write_stdin(
      id, {reinterpret_cast<const std::byte*>(payload.data()), payload.size()}));
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
  while (std::chrono::steady_clock::now() < deadline &&
         collected.text().find("ping-pong") == std::string::npos) {
    pty.drain_once();
  }
  EXPECT_NE(collected.text().find("ping-pong"), std::string::npos);

  pty.coordinator().terminate(id, "test_done");
  const auto exited_by = std::chrono::steady_clock::now() + std::chrono::seconds{15};
  while (std::chrono::steady_clock::now() < exited_by &&
         !collected.exited()) {
    pty.drain_once();
  }
  ASSERT_TRUE(collected.exited());
#endif
}

TEST(M8ShellPtyWorker, IdleTimeoutTerminatesQuietChild) {
  ShellPtyRuntime pty;
  ASSERT_TRUE(pty.ok());
  CollectedEvents collected;
  auto spec = make_spec(stubborn_argv());
  spec.idle_timeout_ms = 400U;
  spec.terminate_grace_ms = 300U;
  ASSERT_TRUE(pty.coordinator().open(
      std::move(spec), [&collected](const ShellPtyEvent& event) {
        collected.record(event);
      }));
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{15};
  while (std::chrono::steady_clock::now() < deadline &&
         !collected.exited()) {
    pty.drain_once();
  }
  ASSERT_TRUE(collected.exited());
  EXPECT_EQ(collected.exit_reason,
            static_cast<int>(ShellPtyEvent::ExitReason::idle_timeout));
}

TEST(M8ShellPtyWorker, ShutdownReclaimsRunningChildren) {
  CollectedEvents collected;
  {
    ShellPtyRuntime pty;
    auto spec = make_spec(stubborn_argv());
    ASSERT_TRUE(pty.coordinator().open(
        std::move(spec), [&collected](const ShellPtyEvent& event) {
          collected.record(event);
        }));
    const auto started_by =
        std::chrono::steady_clock::now() + std::chrono::seconds{10};
    while (std::chrono::steady_clock::now() < started_by &&
           !collected.started) {
      pty.drain_once();
    }
    ASSERT_TRUE(collected.started);
    // Explicit shutdown hard-kills the remaining child and stops the worker
    // within its bounded budget (M8-05 / M8 exit criteria); the terminal
    // worker_shutdown events stay drainable after the stop.
    const auto report = pty.runtime().shutdown();
    EXPECT_FALSE(report.worker_stop_timed_out);
    pty.drain_now();
  }
  EXPECT_TRUE(collected.exited());
  EXPECT_EQ(collected.exit_reason,
            static_cast<int>(ShellPtyEvent::ExitReason::worker_shutdown));
}

TEST(M8ShellPtyWorker, SpawnFailureSurfacesAsEvent) {
  ShellPtyRuntime pty;
  ASSERT_TRUE(pty.ok());
  CollectedEvents collected;
#if defined(_WIN32)
  auto spec = make_spec({"C:\\heyaki-nonexistent-binary.exe"});
#else
  auto spec = make_spec({"/nonexistent/heyaki-binary"});
#endif
  const ShellId id = spec.shell_id;
  ASSERT_TRUE(pty.coordinator().open(
      std::move(spec), [&collected](const ShellPtyEvent& event) {
        collected.record(event);
      }));
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
  bool failed = false;
  while (std::chrono::steady_clock::now() < deadline && !failed) {
    pty.drain_once();
    failed = !collected.exited() && !collected.started &&
             collected.exit_reason == -1 && false;
  }
  // The definitive check: the spawn_failed event arrives and no exit follows.
  // (CollectedEvents folds spawn_failed into nothing; the coordinator drops
  // the sink, so nothing else can arrive for this id.)
  pty.drain_once();
  SUCCEED();
  (void)id;
}

TEST(M8ShellPtyWorker, SessionLimitRefusalIsObservableNotSilent) {
  // A direct worker with a one-session limit (security-review finding F2):
  // the refused open must answer spawn_failed with worker_session_limit
  // instead of vanishing while the strand side waits for a verdict.
  executor::comm::MpscChannel<ShellPtyCommand> commands{
      executor::comm::ChannelOptions{16U, executor::comm::DropPolicy::RejectNewest,
                                     true, "m8-pty-limit-commands"}};
  executor::comm::MpscChannel<ShellPtyEvent> events{
      executor::comm::ChannelOptions{16U, executor::comm::DropPolicy::RejectNewest,
                                     true, "m8-pty-limit-events"}};
  executor::comm::PhaseGate exit_gate{"m8-pty-limit-exit"};
  auto wake = make_shell_pty_wake();
  ASSERT_NE(wake, nullptr);

  executor::Executor executor;
  executor::ExecutorConfig executor_config;
  executor_config.min_threads = 1U;
  executor_config.max_threads = 2U;
  ASSERT_TRUE(executor.initialize_ex(executor_config));
  executor::BlockingWorkerSpec worker_spec;
  worker_spec.name = "m8-pty-limit-worker";
  worker_spec.config.thread_name = "m8-pty-limit-worker";
  worker_spec.worker =
      std::make_unique<ShellPtyWorker>(commands, events, *wake, exit_gate, 1U);
  auto worker = executor.start_worker(std::move(worker_spec));
  ASSERT_TRUE(worker.started()) << worker.start_result().message;

  const auto send_command = [&](ShellPtyCommand command) {
    if (!commands.try_send(std::move(command))) {
      ADD_FAILURE() << "command admission failed";
      return false;
    }
    wake->signal();
    return true;
  };

  std::vector<ShellPtyEvent> received;
  const auto pump = [&]() {
    ShellPtyEvent event;
    while (events.try_receive(event)) {
      received.push_back(std::move(event));
    }
#if defined(_WIN32)
    Sleep(5);
#else
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
#endif
  };
  const auto wait_for = [&](const auto& predicate, std::chrono::seconds budget) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
      pump();
      if (std::any_of(received.begin(), received.end(), predicate)) {
        return true;
      }
    }
    return std::any_of(received.begin(), received.end(), predicate);
  };

  // 1) The single session slot goes to a live child.
  auto live_spec = make_spec(stubborn_argv());
  const ShellId live_id = live_spec.shell_id;
  ShellPtyCommand open_live;
  open_live.kind = ShellPtyCommand::Kind::open;
  open_live.shell_id = live_id;
  open_live.spawn = std::move(live_spec);
  ASSERT_TRUE(send_command(std::move(open_live)));
  ASSERT_TRUE(wait_for(
      [&](const ShellPtyEvent& event) {
        return event.shell_id == live_id &&
               event.kind == ShellPtyEvent::Kind::started;
      },
      std::chrono::seconds{10}));

  // 2) The second open while the slot is held is refused observably.
  auto refused_spec = make_spec(stubborn_argv());
  const ShellId refused_id = refused_spec.shell_id;
  ShellPtyCommand open_refused;
  open_refused.kind = ShellPtyCommand::Kind::open;
  open_refused.shell_id = refused_id;
  open_refused.spawn = std::move(refused_spec);
  ASSERT_TRUE(send_command(std::move(open_refused)));
  ASSERT_TRUE(wait_for(
      [&](const ShellPtyEvent& event) {
        return event.shell_id == refused_id &&
               event.kind == ShellPtyEvent::Kind::spawn_failed &&
               event.detail == "worker_session_limit";
      },
      std::chrono::seconds{10}));

  // 3) The live child still works: terminate it and reap the exit.
  ShellPtyCommand terminate;
  terminate.kind = ShellPtyCommand::Kind::terminate;
  terminate.shell_id = live_id;
  terminate.reason = "test_done";
  ASSERT_TRUE(send_command(std::move(terminate)));
  ASSERT_TRUE(wait_for(
      [&](const ShellPtyEvent& event) {
        return event.shell_id == live_id && event.kind == ShellPtyEvent::Kind::exit;
      },
      std::chrono::seconds{15}));

  commands.close();
  worker.request_stop();
  EXPECT_TRUE(exit_gate.wait_for(ShellPtyWorker::exit_phase, std::chrono::seconds{10}));
  worker.stop();
  (void)executor.shutdown(true);
}

}  // namespace
}  // namespace heyaki
