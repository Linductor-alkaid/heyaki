#pragma once

// PTY process layer for Remote Shell (M8-04/M8-05/M8-06).
//
// One executor-managed blocking I/O worker owns EVERY child process: spawn,
// stdin writes, PTY reads, resize, signal delivery, escalation
// (cooperative/TERM -> grace -> process-tree kill), reaping, and the
// idle/absolute/output caps all run on that worker (M8-04). The strand side
// never touches a process handle; it exchanges bounded commands and events
// through executor::comm channels:
//
//   strand (Node/ShellService) --ShellPtyCommandQueue--> PTY worker
//   PTY worker --ShellPtyEventQueue--> strand (drained on the node tick)
//
// Backpressure (M8-06): when the event queue is full the worker stops reading
// the session's PTY (the kernel buffer then slows the child); output that is
// already read waits in a per-session pending buffer bounded by the profile's
// max_output_pending_bytes, beyond which the shell is terminated for
// flooding. Pending stdin is bounded by max_input_pending_bytes; overflow
// rejects further input with resource_exhausted.
//
// Threading: every method except ShellPtyWorker::run/wakeup runs on the
// owning Node's strand.

#include <heyaki/error.hpp>
#include <heyaki/shell.hpp>

#include <executor/comm/channel.hpp>
#include <executor/comm/phase_gate.hpp>
#include <executor/executor.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace heyaki {

class Runtime;

// Fully resolved spawn parameters; derived server-side from the validated
// ShellProfileConfig. The wire ShellOpen never influences program, user,
// working directory, or environment (M8-02).
struct ShellPtySpawnSpec {
  ShellId shell_id;
  std::vector<std::string> argv;
  std::string os_user;
  std::filesystem::path working_directory;
  std::vector<std::pair<std::string, std::string>> environment;
  std::uint32_t columns{80U};
  std::uint32_t rows{24U};
  // Enforced by the PTY worker (M8-05/M8-06), in milliseconds.
  std::uint64_t idle_timeout_ms{600000U};
  std::uint64_t absolute_timeout_ms{3600000U};
  std::uint64_t terminate_grace_ms{5000U};
  std::uint64_t max_output_bytes{64ULL * 1024ULL * 1024ULL};
  std::uint64_t max_output_pending_bytes{256ULL * 1024ULL};
  std::uint64_t max_input_pending_bytes{64ULL * 1024ULL};
};

struct ShellPtyEvent {
  enum class Kind : std::uint8_t {
    started,         // child spawned; the shell is active
    output,          // one bounded slice of PTY output
    exit,            // child reaped; terminal for this shell
    spawn_failed,    // the child could not be started; terminal
    input_rejected,  // pending stdin exceeded the cap; terminal
  };
  enum class ExitReason : std::uint8_t {
    process,            // exited on its own
    idle_timeout,       // no activity for the idle timeout (M8-06)
    absolute_timeout,   // absolute lifetime reached (M8-06)
    output_limit,       // total or pending output cap exceeded (M8-06)
    input_backpressure, // pending stdin cap exceeded (M8-06)
    terminated,         // cooperative cancel/escalation or explicit close
    worker_shutdown,    // the PTY worker is stopping
  };

  ShellId shell_id;
  Kind kind{Kind::output};
  ExitReason exit_reason{ExitReason::process};
  std::vector<std::byte> data;  // output slice
  std::int32_t exit_code{0};    // exit: positive exit status; negative = signal
  std::string detail;           // safe diagnostics only, never terminal content
};

struct ShellPtyCommand {
  enum class Kind : std::uint8_t {
    open,
    write_stdin,
    resize,
    signal,
    close_stdin,
    terminate,  // escalation ladder owned by the worker (M8-05)
  };

  Kind kind{Kind::open};
  ShellId shell_id;
  ShellPtySpawnSpec spawn;      // open
  std::vector<std::byte> data;  // write_stdin
  std::uint32_t columns{0U};    // resize
  std::uint32_t rows{0U};       // resize
  ShellPortableSignal signal{ShellPortableSignal::terminate};
  bool hard{false};             // terminate: skip the graceful phase
  std::string reason;           // terminate: safe audit reason
};

using ShellPtyCommandQueue = executor::comm::MpscChannel<ShellPtyCommand>;
using ShellPtyEventQueue = executor::comm::MpscChannel<ShellPtyEvent>;

// Thread-safe wake primitive owned by the runtime: the worker's poll wait
// releases on signal() so freshly submitted commands and stop requests are
// observed promptly (a stop token alone cannot interrupt a blocked poll).
class ShellPtyWake {
 public:
  virtual ~ShellPtyWake() = default;
  virtual void signal() noexcept = 0;
};

[[nodiscard]] std::unique_ptr<ShellPtyWake> make_shell_pty_wake();

// The blocking worker loop. Platform process control (POSIX PTY/process
// group, Windows ConPTY/job object) lives in the implementation.
class ShellPtyWorker final : public executor::IBlockingIoWorker {
 public:
  static constexpr std::uint64_t exit_phase = 1U;

  ShellPtyWorker(ShellPtyCommandQueue& commands, ShellPtyEventQueue& events,
                 ShellPtyWake& wake, executor::comm::PhaseGate& exit_gate);
  ~ShellPtyWorker() override;

  void run(executor::StopToken stop_token) override;
  // Wakes a blocked poll so fresh commands/deadlines are observed promptly.
  void wakeup() noexcept override;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Strand-side seam the ShellService drives. Production routes through the
// runtime's executor-managed PTY worker; unit tests install a manual
// dispatcher with a scripted child.
class IShellPtyDispatcher {
 public:
  // Called on the owning strand for every event of one shell.
  using EventSink = std::function<void(const ShellPtyEvent&)>;

  virtual ~IShellPtyDispatcher() = default;

  // False when the node was not configured with the shell PTY worker; a
  // serving-side SHELL_OPEN then answers SHELL_ERROR failed_precondition.
  [[nodiscard]] virtual bool available() const = 0;
  // Asynchronous: spawn success arrives as a `started` event, failure as
  // `spawn_failed`. A failed Result means the command was not admitted.
  [[nodiscard]] virtual Result<void> open(ShellPtySpawnSpec spec, EventSink sink) = 0;
  [[nodiscard]] virtual Result<void> write_stdin(const ShellId& id,
                                                 std::span<const std::byte> data) = 0;
  [[nodiscard]] virtual Result<void> resize(const ShellId& id, std::uint32_t columns,
                                            std::uint32_t rows) = 0;
  [[nodiscard]] virtual Result<void> signal(const ShellId& id,
                                            ShellPortableSignal signal) = 0;
  [[nodiscard]] virtual Result<void> close_stdin(const ShellId& id) = 0;
  // Termination always runs the escalation ladder (M8-05); the terminal
  // `exit` event follows.
  virtual void terminate(const ShellId& id, std::string_view reason) = 0;

  // Drops every sink; late events (if any) are ignored. Called when the
  // owning service detaches.
  virtual void detach_all() = 0;
};

// Production dispatcher: forwards to the runtime's command queue and drains
// the event queue on the node tick. One instance per Node.
class ShellPtyCoordinator final : public IShellPtyDispatcher {
 public:
  ShellPtyCoordinator() = default;
  ~ShellPtyCoordinator() override;

  // Binds the runtime queues; call once while the node starts. `enabled`
  // reflects RuntimeConfig::shell_pty_worker_enabled.
  void bind(Runtime& runtime, bool enabled);

  [[nodiscard]] bool available() const override;
  [[nodiscard]] Result<void> open(ShellPtySpawnSpec spec, EventSink sink) override;
  [[nodiscard]] Result<void> write_stdin(const ShellId& id,
                                         std::span<const std::byte> data) override;
  [[nodiscard]] Result<void> resize(const ShellId& id, std::uint32_t columns,
                                    std::uint32_t rows) override;
  [[nodiscard]] Result<void> signal(const ShellId& id, ShellPortableSignal signal) override;
  [[nodiscard]] Result<void> close_stdin(const ShellId& id) override;
  void terminate(const ShellId& id, std::string_view reason) override;
  void detach_all() override;

  // Pops every available event and invokes its sink. Runs on the node strand
  // (periodic tick) — the ONLY place sinks fire.
  void drain();

 private:
  Runtime* runtime_{};
  bool enabled_{false};
  std::map<ShellId, EventSink> sinks_;
};

}  // namespace heyaki
