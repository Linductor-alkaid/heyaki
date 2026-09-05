// ShellPtyWorker: the single executor-managed blocking worker that owns every
// Remote Shell child process (M8-04), plus ShellPtyCoordinator (strand side).
//
// POSIX backend: forkpty() + controlling-terminal process group. The child is
// a session leader, so kill(-pid) addresses the whole process group tree. A
// CLOEXEC error pipe carries the exec verdict back so spawn failures surface
// as spawn_failed events instead of zombie exit codes. Windows backend:
// ConPTY (dynamically resolved) + job object with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE so the tree dies with the job.
//
// Escalation (M8-05): terminate() first delivers the graceful signal (SIGTERM
// / CTRL_BREAK_EVENT) to the process group, then escalates to a hard
// process-tree kill (SIGKILL / TerminateJobObject) after
// terminate_grace_ms. Disconnects route through the same ladder; flood and
// input-backpressure terminations skip the graceful phase.
//
// Caps (M8-06): idle/absolute deadlines, the total output budget, the
// pending-output bound (flood), and the pending-input bound (backpressure)
// are enforced here, on the only context that owns the process.
//
// PTY merge semantics (M8-03): both backends merge stdout/stderr into the
// pty stream. A POSIX pty master has no half-close, so close_stdin delivers
// EOT (canonical-mode EOF); ConPTY close_stdin closes the input pipe.

#include "shell_pty.hpp"

#include "runtime_access.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <optional>
#include <utility>
#include <vector>

#if !defined(_WIN32)

#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <pty.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#else

#include <windows.h>

#endif

namespace heyaki {
namespace {

constexpr std::size_t kReadChunkBytes = 16U * 1024U;

std::uint64_t steady_ms_now() noexcept {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

Error pty_error(std::string_view detail) {
  return Error{ErrorCode::internal, "shell-pty", std::string{detail}};
}

bool emit_event(ShellPtyEventQueue& events, ShellPtyEvent&& event) {
  return events.try_send(std::move(event));
}

// ---- Worker session record --------------------------------------------------

struct ShellPtySession {
  ShellPtySpawnSpec spec;
  enum class Phase : std::uint8_t { running, graceful } phase{Phase::running};
  std::uint64_t graceful_deadline_ms{0U};
  bool hard_termination{false};
  bool stdin_closed{false};
  bool exit_emitted{false};
  bool input_rejected_emitted{false};
  bool output_flood{false};
  ShellPtyEvent::ExitReason pending_exit_reason{
      ShellPtyEvent::ExitReason::process};
  std::string terminate_reason;

  // Worker-owned pending buffers (M8-06 backpressure bounds).
  std::vector<std::byte> pending_output;
  std::deque<std::vector<std::byte>> pending_input;
  std::size_t pending_input_bytes{0U};

  std::uint64_t input_bytes{0U};
  std::uint64_t output_bytes{0U};
  std::uint64_t last_activity_ms{0U};
  std::uint64_t absolute_deadline_ms{0U};

#if !defined(_WIN32)
  int master_fd{-1};
  pid_t child{-1};
  bool master_eof{false};
#else
  HPCON pseudo_console{nullptr};
  HANDLE process{nullptr};
  HANDLE job{nullptr};
  // Synchronous anonymous-pipe ends (the documented ConPTY pattern,
  // microsoft/terminal#262: overlapped pipe handles must not be handed to
  // CreatePseudoConsole). Reads poll via PeekNamedPipe; stdin writes are
  // bounded by the pending-input cap plus an oversized pipe buffer.
  HANDLE out_read{nullptr};  // our end: child output
  HANDLE in_write{nullptr};  // our end: child stdin
  std::array<std::byte, kReadChunkBytes> read_buffer{};
#endif
};

struct SpawnOutcome {
  bool ok{false};
  std::string detail;
};

// ---- Platform wake primitives --------------------------------------------

#if !defined(_WIN32)

class PosixPipeWake final : public ShellPtyWake {
 public:
  ~PosixPipeWake() override {
    if (read_fd_ >= 0) ::close(read_fd_);
    if (write_fd_ >= 0) ::close(write_fd_);
  }

  bool open() {
    int fds[2];
    if (::pipe(fds) != 0) {
      return false;
    }
    read_fd_ = fds[0];
    write_fd_ = fds[1];
    const int read_flags = ::fcntl(read_fd_, F_GETFL, 0);
    const int write_flags = ::fcntl(write_fd_, F_GETFL, 0);
    if (read_flags >= 0) (void)::fcntl(read_fd_, F_SETFL, read_flags | O_NONBLOCK);
    if (write_flags >= 0) (void)::fcntl(write_fd_, F_SETFL, write_flags | O_NONBLOCK);
    (void)::fcntl(read_fd_, F_SETFD, FD_CLOEXEC);
    (void)::fcntl(write_fd_, F_SETFD, FD_CLOEXEC);
    return true;
  }

  int read_fd() const noexcept { return read_fd_; }

  void signal() noexcept override {
    if (write_fd_ >= 0) {
      const auto byte = static_cast<unsigned char>('w');
      const auto written = ::write(write_fd_, &byte, 1U);
      (void)written;  // EAGAIN: a wake byte is already pending.
    }
  }

  void drain() noexcept {
    unsigned char scratch[64];
    while (::read(read_fd_, scratch, sizeof(scratch)) > 0) {
    }
  }

 private:
  int read_fd_{-1};
  int write_fd_{-1};
};

#else

class WindowsEventWake final : public ShellPtyWake {
 public:
  ~WindowsEventWake() override {
    if (event_) ::CloseHandle(event_);
  }

  bool open() {
    event_ = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
    return event_ != nullptr;
  }

  HANDLE handle() const noexcept { return event_; }

  void signal() noexcept override {
    if (event_) ::SetEvent(event_);
  }

 private:
  HANDLE event_{nullptr};
};

#endif

// ---- POSIX process control ------------------------------------------------

#if !defined(_WIN32)

int portable_to_posix_signal(ShellPortableSignal signal) noexcept {
  switch (signal) {
    case ShellPortableSignal::hangup:
      return SIGHUP;
    case ShellPortableSignal::interrupt:
      return SIGINT;
    case ShellPortableSignal::quit:
      return SIGQUIT;
    case ShellPortableSignal::kill:
      return SIGKILL;
    case ShellPortableSignal::terminate:
      return SIGTERM;
  }
  return SIGTERM;
}

// Everything the child needs, fully materialized BEFORE forkpty: the child
// performs only async-signal-safe syscalls (no malloc — a forked child of a
// multithreaded process can deadlock on an inherited arena lock, which would
// wedge the worker's exec-verdict read forever).
struct ChildPlan {
  std::vector<std::string> env_storage;
  std::vector<std::string> argv_storage;
  std::vector<char*> env;
  std::vector<char*> argv;
  std::filesystem::path working_directory;
  bool switch_user{false};
  uid_t target_uid{0U};
  gid_t target_gid{0U};
};

[[noreturn]] void child_report_failure(int error_fd, int code) noexcept {
  if (error_fd >= 0) {
    const auto byte = static_cast<unsigned char>(code);
    const auto written = ::write(error_fd, &byte, 1U);
    (void)written;
  }
  ::_exit(127);
}

// Runs inside the forked child; never returns; never allocates.
void child_exec(const ChildPlan& plan, int error_fd) noexcept {
  if (error_fd >= 0) {
    // dup2 clears FD_CLOEXEC; restore it so the exec'd program does not
    // inherit the verdict pipe (a long-running child would otherwise hold
    // the write end open and stall the parent's bounded verdict read).
    (void)::dup2(error_fd, 200);
    ::close(error_fd);
    (void)::fcntl(200, F_SETFD, FD_CLOEXEC);
    error_fd = 200;
  }

  if (!plan.working_directory.empty() &&
      ::chdir(plan.working_directory.c_str()) != 0) {
    child_report_failure(error_fd, errno != 0 ? errno : EACCES);
  }

  if (plan.switch_user) {
    // Resolved pre-fork; setgroups(1, gid) avoids allocation in the child.
    if (::setgroups(1U, &plan.target_gid) != 0 ||
        ::setgid(plan.target_gid) != 0 || ::setuid(plan.target_uid) != 0) {
      child_report_failure(error_fd, errno != 0 ? errno : EPERM);
    }
  }

  ::execve(plan.argv_storage.front().c_str(), plan.argv.data(), plan.env.data());
  child_report_failure(error_fd, errno != 0 ? errno : ENOENT);
}

bool posix_signal_tree(pid_t child, int posix_signal) {
  if (::kill(-child, posix_signal) == 0) {
    return true;
  }
  return ::kill(child, posix_signal) == 0;
}

// Builds the fork-safe plan in the parent; a failed Result refuses the
// spawn without forking at all.
Result<ChildPlan> build_child_plan(const ShellPtySpawnSpec& spec) {
  ChildPlan plan;
  plan.argv_storage = spec.argv;
  plan.working_directory = spec.working_directory;
  plan.env_storage.reserve(spec.environment.size());
  for (const auto& [name, value] : spec.environment) {
    plan.env_storage.push_back(name + "=" + value);
  }
  plan.env.reserve(plan.env_storage.size() + 1U);
  for (auto& entry : plan.env_storage) {
    plan.env.push_back(entry.data());
  }
  plan.env.push_back(nullptr);
  plan.argv.reserve(plan.argv_storage.size() + 1U);
  for (auto& argument : plan.argv_storage) {
    plan.argv.push_back(argument.data());
  }
  plan.argv.push_back(nullptr);

  if (!spec.os_user.empty()) {
    // M8-01: run as the configured OS user or refuse pre-fork. Only a
    // privileged parent may switch identities.
    errno = 0;
    struct passwd* entry = ::getpwnam(spec.os_user.c_str());
    if (entry == nullptr) {
      return Result<ChildPlan>::failure(pty_error("pty_os_user_unknown"));
    }
    const uid_t current = ::geteuid();
    if (current != 0U && current != entry->pw_uid) {
      return Result<ChildPlan>::failure(pty_error("pty_os_user_forbidden"));
    }
    if (current == 0U && entry->pw_uid != 0U) {
      plan.switch_user = true;
      plan.target_uid = entry->pw_uid;
      plan.target_gid = entry->pw_gid;
    }
  }
  return Result<ChildPlan>::success(std::move(plan));
}

SpawnOutcome posix_spawn(ShellPtySession& session) {
  auto plan = build_child_plan(session.spec);
  if (!plan) {
    return {false, std::string{plan.error_if()->safe_detail()}};
  }

  int error_fds[2];
  if (::pipe2(error_fds, O_CLOEXEC) != 0) {
    return {false, "pty_error_pipe_failed"};
  }

  winsize size{};
  size.ws_col = static_cast<unsigned short>(
      std::min<std::uint32_t>(session.spec.columns, 0xFFFFU));
  size.ws_row = static_cast<unsigned short>(
      std::min<std::uint32_t>(session.spec.rows, 0xFFFFU));

  const pid_t child = ::forkpty(&session.master_fd, nullptr, nullptr, &size);
  if (child < 0) {
    ::close(error_fds[0]);
    ::close(error_fds[1]);
    return {false, "pty_fork_failed"};
  }
  if (child == 0) {
    ::close(error_fds[0]);
    child_exec(*plan.value_if(), error_fds[1]);
  }
  session.child = child;
  ::close(error_fds[1]);

  // Bounded exec verdict: EOF = clean exec, one byte = errno, timeout = a
  // wedged child (the worker's only thread never blocks indefinitely).
  unsigned char code = 0U;
  ssize_t received = 0U;
  struct pollfd verdict{error_fds[0], POLLIN, 0};
  const int ready = ::poll(&verdict, 1U, 5000);
  if (ready > 0 && (verdict.revents & (POLLIN | POLLHUP)) != 0) {
    do {
      received = ::read(error_fds[0], &code, 1U);
    } while (received < 0 && errno == EINTR);
  }
  ::close(error_fds[0]);
  if (ready <= 0) {
    (void)posix_signal_tree(child, SIGKILL);
    int status = 0;
    (void)::waitpid(child, &status, 0);
    if (session.master_fd >= 0) {
      ::close(session.master_fd);
      session.master_fd = -1;
    }
    session.child = -1;
    return {false, "pty_exec_timeout"};
  }
  if (received > 0) {
    ::close(session.master_fd);
    session.master_fd = -1;
    int status = 0;
    (void)::waitpid(child, &status, 0);
    session.child = -1;
    return {false, "pty_exec_failed"};
  }

  const int flags = ::fcntl(session.master_fd, F_GETFL, 0);
  if (flags >= 0) (void)::fcntl(session.master_fd, F_SETFL, flags | O_NONBLOCK);
  return {true, {}};
}

// nullopt = master closed (EOF), 0 = would block, >0 = bytes read.
std::optional<std::size_t> posix_read_output(int master_fd, std::byte* buffer,
                                             std::size_t capacity) {
  while (true) {
    const ssize_t got = ::read(master_fd, buffer, capacity);
    if (got > 0) {
      return static_cast<std::size_t>(got);
    }
    if (got == 0) {
      return std::nullopt;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0U;
    }
    // EIO on a pty master is the classic "slave fully closed" signal.
    return std::nullopt;
  }
}

std::size_t posix_write_input(int master_fd, const std::byte* data,
                              std::size_t size) {
  std::size_t written = 0U;
  while (written < size) {
    const ssize_t put = ::write(master_fd, data + written, size - written);
    if (put > 0) {
      written += static_cast<std::size_t>(put);
      continue;
    }
    if (put < 0 && errno == EINTR) {
      continue;
    }
    break;  // EAGAIN or failure: retry when writable.
  }
  return written;
}

void posix_resize(int master_fd, std::uint32_t columns, std::uint32_t rows) {
  winsize size{};
  size.ws_col =
      static_cast<unsigned short>(std::min<std::uint32_t>(columns, 0xFFFFU));
  size.ws_row =
      static_cast<unsigned short>(std::min<std::uint32_t>(rows, 0xFFFFU));
  (void)::ioctl(master_fd, TIOCSWINSZ, &size);
}

bool posix_reap(pid_t child, std::int32_t* exit_code) {
  int status = 0;
  const pid_t reaped = ::waitpid(child, &status, WNOHANG);
  if (reaped != child) {
    return false;
  }
  if (WIFEXITED(status)) {
    *exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    *exit_code = -WTERMSIG(status);
  } else {
    *exit_code = 0;
  }
  return true;
}

#endif  // POSIX process control

}  // namespace

std::unique_ptr<ShellPtyWake> make_shell_pty_wake() {
#if !defined(_WIN32)
  auto wake = std::make_unique<PosixPipeWake>();
  if (!wake->open()) {
    return nullptr;
  }
  return wake;
#else
  auto wake = std::make_unique<WindowsEventWake>();
  if (!wake->open()) {
    return nullptr;
  }
  return wake;
#endif
}

// ---- Windows ConPTY control -------------------------------------------------

#if defined(_WIN32)

namespace {

// ---- Windows ConPTY control ----------------------------------------------

using CreatePseudoConsoleFn = HRESULT(WINAPI*)(COORD, HANDLE, HANDLE, DWORD,
                                               HPCON*);
using ResizePseudoConsoleFn = HRESULT(WINAPI*)(HPCON, COORD);
using ClosePseudoConsoleFn = void(WINAPI*)(HPCON);

struct ConPtyApi {
  CreatePseudoConsoleFn create{nullptr};
  ResizePseudoConsoleFn resize{nullptr};
  ClosePseudoConsoleFn close{nullptr};
  bool loaded{false};

  static const ConPtyApi& instance() {
    static const ConPtyApi api = [] {
      ConPtyApi loaded;
      HMODULE kernel = ::GetModuleHandleW(L"kernel32.dll");
      if (kernel != nullptr) {
        loaded.create = reinterpret_cast<CreatePseudoConsoleFn>(
            ::GetProcAddress(kernel, "CreatePseudoConsole"));
        loaded.resize = reinterpret_cast<ResizePseudoConsoleFn>(
            ::GetProcAddress(kernel, "ResizePseudoConsole"));
        loaded.close = reinterpret_cast<ClosePseudoConsoleFn>(
            ::GetProcAddress(kernel, "ClosePseudoConsole"));
        loaded.loaded = loaded.create != nullptr && loaded.resize != nullptr &&
                        loaded.close != nullptr;
      }
      return loaded;
    }();
    return api;
  }
};

std::wstring wide_from_utf8(const std::string& text) {
  if (text.empty()) {
    return std::wstring{};
  }
  const int size = ::MultiByteToWideChar(
      CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
  std::wstring wide(static_cast<std::size_t>(size > 0 ? size : 0), L'\0');
  if (size > 0) {
    ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                          wide.data(), size);
  }
  return wide;
}

// Canonical ConPTY plumbing (Creating a Pseudoconsole session): two
// anonymous pipes; the ConPTY-facing ends go to CreatePseudoConsole, ours
// stay for the worker's polled I/O. The input pipe buffer covers the whole
// pending-input budget so a synchronous WriteFile does not block the worker
// while ConPTY drains continuously; validate_shell_profile enforces the
// matching budget cap (P3-F3).
constexpr std::size_t kInputPipeBytes =
    static_cast<std::size_t>(kShellWindowsInputPendingCap);

bool make_conpty_pipes(HANDLE* in_conpty, HANDLE* in_ours, HANDLE* out_ours,
                       HANDLE* out_conpty) {
  SECURITY_ATTRIBUTES inheritable{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
  return ::CreatePipe(in_conpty, in_ours, &inheritable,
                      static_cast<DWORD>(kInputPipeBytes)) != 0 &&
         ::CreatePipe(out_ours, out_conpty, &inheritable, 0U) != 0;
}

SpawnOutcome conpty_spawn(ShellPtySession& session) {
  const ConPtyApi& api = ConPtyApi::instance();
  if (!api.loaded) {
    return {false, "conpty_unavailable"};
  }

  HANDLE input_ours = nullptr;   // we write child stdin here
  HANDLE input_conpty = nullptr; // ConPTY reads child stdin
  HANDLE output_ours = nullptr;  // we read child output
  HANDLE output_conpty = nullptr;
  if (!make_conpty_pipes(&input_conpty, &input_ours, &output_ours,
                         &output_conpty)) {
    if (input_ours) ::CloseHandle(input_ours);
    if (input_conpty) ::CloseHandle(input_conpty);
    if (output_ours) ::CloseHandle(output_ours);
    if (output_conpty) ::CloseHandle(output_conpty);
    return {false, "conpty_pipe_failed"};
  }

  COORD size{};
  size.X =
      static_cast<SHORT>(std::min<std::uint32_t>(session.spec.columns, 0x7FFFU));
  size.Y =
      static_cast<SHORT>(std::min<std::uint32_t>(session.spec.rows, 0x7FFFU));
  HPCON console = nullptr;
  if (FAILED(api.create(size, input_conpty, output_conpty, 0U, &console))) {
    ::CloseHandle(input_ours);
    ::CloseHandle(input_conpty);
    ::CloseHandle(output_ours);
    ::CloseHandle(output_conpty);
    return {false, "conpty_create_failed"};
  }
  // The pseudo console keeps its pipe ends.
  ::CloseHandle(input_conpty);
  ::CloseHandle(output_conpty);

  HANDLE job = ::CreateJobObjectW(nullptr, nullptr);
  if (job == nullptr) {
    api.close(console);
    ::CloseHandle(input_ours);
    ::CloseHandle(output_ours);
    return {false, "conpty_job_failed"};
  }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!::SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
                                 sizeof(limits))) {
    ::CloseHandle(job);
    api.close(console);
    ::CloseHandle(input_ours);
    ::CloseHandle(output_ours);
    return {false, "conpty_job_config_failed"};
  }

  std::wstring command;
  for (std::size_t index = 0U; index < session.spec.argv.size(); ++index) {
    if (index != 0U) {
      command.push_back(L' ');
    }
    // Canonical MSVCRT quoting (P4-F7): embedded quotes escape, backslash
    // runs double where the rules require, so operator argv with quotes
    // round-trips instead of being merely wrapped.
    command.append(
        wide_from_utf8(quote_windows_argument(session.spec.argv[index])));
  }

  std::wstring environment;
  for (const auto& [name, value] : session.spec.environment) {
    environment.append(wide_from_utf8(name));
    environment.push_back(L'=');
    environment.append(wide_from_utf8(value));
    environment.push_back(L'\0');
  }
  environment.push_back(L'\0');

  STARTUPINFOEXW info{};
  info.StartupInfo.cb = sizeof(info);
  // PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE only reroutes std handles that are
  // console handles; when this host's own std handles are redirected (CI
  // runners capture test output through pipes), the console-subsystem child
  // inherits them verbatim and bypasses the PTY entirely
  // (microsoft/terminal#11276). Explicitly requesting empty std handles makes
  // the child reconnect them to the pseudoconsole regardless of how this
  // process was launched.
  info.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  info.StartupInfo.hStdInput = nullptr;
  info.StartupInfo.hStdOutput = nullptr;
  info.StartupInfo.hStdError = nullptr;
  SIZE_T attribute_size = 0U;
  (void)::InitializeProcThreadAttributeList(nullptr, 1U, 0U, &attribute_size);
  std::vector<std::byte> attribute_storage(
      attribute_size > 0U ? attribute_size : 1U, std::byte{0});
  info.lpAttributeList =
      reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_storage.data());
  bool attribute_ready = attribute_size > 0U;
  if (attribute_ready) {
    attribute_ready = ::InitializeProcThreadAttributeList(
        info.lpAttributeList, 1U, 0U, &attribute_size) != 0;
  }
  if (attribute_ready) {
    attribute_ready = ::UpdateProcThreadAttribute(
        info.lpAttributeList, 0U, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, console,
        sizeof(HPCON), nullptr, nullptr) != 0;
  }
  if (!attribute_ready) {
    if (attribute_size > 0U) {
      ::DeleteProcThreadAttributeList(info.lpAttributeList);
    }
    ::CloseHandle(job);
    api.close(console);
    ::CloseHandle(input_ours);
    ::CloseHandle(output_ours);
    return {false, "conpty_attribute_failed"};
  }

  const std::wstring directory = wide_from_utf8(session.spec.working_directory.string());
  PROCESS_INFORMATION process_info{};
  const BOOL started = ::CreateProcessW(
      nullptr, command.data(), nullptr, nullptr, FALSE,
      EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED,
      environment.size() > 1U ? environment.data() : nullptr,
      directory.empty() ? nullptr : directory.c_str(), &info.StartupInfo,
      &process_info);
  ::DeleteProcThreadAttributeList(info.lpAttributeList);
  if (!started) {
    ::CloseHandle(job);
    api.close(console);
    ::CloseHandle(input_ours);
    ::CloseHandle(output_ours);
    return {false, "conpty_process_failed"};
  }
  (void)::AssignProcessToJobObject(job, process_info.hProcess);
  (void)::ResumeThread(process_info.hThread);
  ::CloseHandle(process_info.hThread);

  session.pseudo_console = console;
  session.process = process_info.hProcess;
  session.job = job;
  session.in_write = input_ours;
  session.out_read = output_ours;
  return {true, {}};
}

void conpty_close(ShellPtySession& session) {
  if (session.out_read) {
    ::CloseHandle(session.out_read);
    session.out_read = nullptr;
  }
  if (session.in_write) {
    ::CloseHandle(session.in_write);
    session.in_write = nullptr;
  }
  if (session.job) {
    ::CloseHandle(session.job);
    session.job = nullptr;
  }
  if (session.process) {
    ::CloseHandle(session.process);
    session.process = nullptr;
  }
  if (session.pseudo_console) {
    const ConPtyApi& api = ConPtyApi::instance();
    if (api.loaded) {
      api.close(session.pseudo_console);
    }
    session.pseudo_console = nullptr;
  }
}

}  // namespace

#endif  // Windows ConPTY control

struct ShellPtyWorker::Impl {
  ShellPtyCommandQueue& commands;
  ShellPtyEventQueue& events;
  ShellPtyWake& wake;
  executor::comm::PhaseGate& exit_gate;
  std::size_t session_limit;
  std::map<ShellId, ShellPtySession> sessions;
};

ShellPtyWorker::ShellPtyWorker(ShellPtyCommandQueue& commands,
                               ShellPtyEventQueue& events, ShellPtyWake& wake,
                               executor::comm::PhaseGate& exit_gate,
                               std::size_t session_limit)
    : impl_(std::make_unique<Impl>(commands, events, wake, exit_gate,
                                   session_limit > 0U
                                       ? session_limit
                                       : ShellPtyWorker::default_session_limit)) {
}

ShellPtyWorker::~ShellPtyWorker() = default;

void ShellPtyWorker::wakeup() noexcept { impl_->wake.signal(); }

void ShellPtyWorker::run(executor::StopToken stop_token) {
  auto& impl = *impl_;
  std::vector<std::byte> read_scratch(kReadChunkBytes);

  const auto start_termination = [&](ShellPtySession& session,
                                     ShellPtyEvent::ExitReason reason,
                                     std::string detail, bool hard) {
    if (session.phase != ShellPtySession::Phase::running) {
      return;
    }
    session.phase = ShellPtySession::Phase::graceful;
    session.pending_exit_reason = reason;
    session.terminate_reason = std::move(detail);
    session.hard_termination = hard;
    session.graceful_deadline_ms =
        steady_ms_now() + session.spec.terminate_grace_ms;
#if !defined(_WIN32)
    (void)posix_signal_tree(session.child,
                            hard ? SIGKILL : SIGTERM);
#else
    if (hard) {
      if (session.job) ::TerminateJobObject(session.job, 1U);
    } else if (session.process != nullptr) {
      (void)::GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT,
                                       ::GetProcessId(session.process));
    }
#endif
  };

  const auto deliver_output = [&](ShellPtySession& session,
                                  const std::byte* data,
                                  std::size_t size) {
    session.output_bytes += size;
    session.last_activity_ms = steady_ms_now();
    if (session.output_bytes > session.spec.max_output_bytes) {
      session.output_flood = true;
      return;
    }
    ShellPtyEvent event;
    event.shell_id = session.spec.shell_id;
    event.kind = ShellPtyEvent::Kind::output;
    event.data.assign(data, data + size);
    if (emit_event(impl.events, std::move(event))) {
      return;
    }
    // Event queue full: stage in the bounded pending buffer and pause reads;
    // overflow terminates the shell for flooding (M8-06).
    session.pending_output.insert(session.pending_output.end(), data,
                                  data + size);
    if (session.pending_output.size() > session.spec.max_output_pending_bytes) {
      session.output_flood = true;
    }
  };

#if defined(_WIN32)
  // Peek-bounded read of the session's output pipe; ReadFile never blocks
  // because it only asks for bytes PeekNamedPipe already counted.
  const auto poll_conpty_output = [&](ShellPtySession& session) {
    if (session.out_read == nullptr || session.exit_emitted ||
        !session.pending_output.empty() || session.output_flood) {
      return;
    }
    for (int rounds = 0; rounds < 4; ++rounds) {
      DWORD available = 0U;
      if (!::PeekNamedPipe(session.out_read, nullptr, 0U, nullptr, &available,
                           nullptr) ||
          available == 0U) {
        return;
      }
      const DWORD want =
          std::min<DWORD>(available, static_cast<DWORD>(kReadChunkBytes));
      DWORD got = 0U;
      if (!::ReadFile(session.out_read, session.read_buffer.data(), want, &got,
                      nullptr) ||
          got == 0U) {
        return;
      }
      deliver_output(session, session.read_buffer.data(), got);
      if (session.output_flood || !session.pending_output.empty()) {
        return;
      }
    }
  };

  // Final drain at reap: conhost renders the child's tail output
  // asynchronously after the process handle signals, so drain-until-empty
  // must tolerate a short quiet window before concluding (bounded overall).
  const auto drain_conpty_final = [&](ShellPtySession& session) {
    if (session.out_read == nullptr) {
      return;
    }
    int quiet_streak = 0;
    for (int attempts = 0; attempts < 120 && quiet_streak < 4; ++attempts) {
      bool progressed = false;
      for (int rounds = 0; rounds < 8; ++rounds) {
        DWORD available = 0U;
        if (!::PeekNamedPipe(session.out_read, nullptr, 0U, nullptr, &available,
                             nullptr)) {
          return;  // pipe broken: conhost is gone, nothing more to read
        }
        if (available == 0U) {
          break;
        }
        progressed = true;
        quiet_streak = 0;
        const DWORD want =
            std::min<DWORD>(available, static_cast<DWORD>(kReadChunkBytes));
        DWORD got = 0U;
        if (!::ReadFile(session.out_read, session.read_buffer.data(), want,
                        &got, nullptr) ||
            got == 0U) {
          return;
        }
        deliver_output(session, session.read_buffer.data(), got);
        if (session.output_flood) {
          return;
        }
      }
      if (!progressed) {
        ++quiet_streak;
        ::Sleep(5);  // bounded wait for conhost's tail flush
      }
    }
  };
#endif

  const auto drain_pending_output = [&](ShellPtySession& session) {
    while (!session.pending_output.empty()) {
      const std::size_t slice =
          std::min<std::size_t>(session.pending_output.size(), kReadChunkBytes);
      ShellPtyEvent event;
      event.shell_id = session.spec.shell_id;
      event.kind = ShellPtyEvent::Kind::output;
      event.data.assign(session.pending_output.begin(),
                        session.pending_output.begin() +
                            static_cast<std::ptrdiff_t>(slice));
      if (!emit_event(impl.events, std::move(event))) {
        if (session.pending_output.size() >
            session.spec.max_output_pending_bytes) {
          session.output_flood = true;
        }
        return;
      }
      session.pending_output.erase(
          session.pending_output.begin(),
          session.pending_output.begin() + static_cast<std::ptrdiff_t>(slice));
    }
  };

#if !defined(_WIN32)
  const auto harvest_output = [&](ShellPtySession& session) {
    if (session.exit_emitted || session.master_eof || session.master_fd < 0) {
      return;
    }
    for (int rounds = 0; rounds < 4; ++rounds) {
      const auto got =
          posix_read_output(session.master_fd, read_scratch.data(),
                            read_scratch.size());
      if (!got.has_value()) {
        session.master_eof = true;
        return;
      }
      if (*got == 0U) {
        return;
      }
      deliver_output(session, read_scratch.data(), *got);
      if (session.output_flood || !session.pending_output.empty()) {
        return;
      }
    }
  };
#endif

  const auto flush_pending_input = [&](ShellPtySession& session) {
#if !defined(_WIN32)
    while (!session.pending_input.empty()) {
      auto& front = session.pending_input.front();
      const std::size_t written =
          posix_write_input(session.master_fd, front.data(), front.size());
      if (written == 0U) {
        return;  // PTY buffer full; retry when writable.
      }
      session.input_bytes += written;
      session.pending_input_bytes -= written;
      if (written < front.size()) {
        front.erase(front.begin(), front.begin() +
                                       static_cast<std::ptrdiff_t>(written));
        return;
      }
      session.pending_input.pop_front();
    }
#else
    // Synchronous write bounded by the pipe buffer (>= the pending-input
    // cap, see make_conpty_pipes) plus ConPTY's continuous drain.
    while (!session.pending_input.empty() && session.in_write != nullptr) {
      auto& front = session.pending_input.front();
      DWORD put = 0U;
      const BOOL ok =
          ::WriteFile(session.in_write, front.data(),
                      static_cast<DWORD>(front.size()), &put, nullptr);
      if (!ok || put == 0U) {
        session.pending_input.clear();
        session.pending_input_bytes = 0U;
        return;
      }
      session.input_bytes += put;
      session.pending_input_bytes -=
          std::min<std::size_t>(session.pending_input_bytes, put);
      if (put < front.size()) {
        front.erase(front.begin(), front.begin() + static_cast<std::ptrdiff_t>(put));
        return;
      }
      session.pending_input.pop_front();
    }
#endif
  };

  while (!stop_token.stop_requested()) {
    // 1) Strand-submitted commands.
    ShellPtyCommand command;
    while (impl.commands.try_receive(command)) {
      auto found = impl.sessions.find(command.shell_id);
      switch (command.kind) {
        case ShellPtyCommand::Kind::open: {
          if (found != impl.sessions.end()) {
            break;
          }
          if (impl.sessions.size() >= impl.session_limit) {
            // The strand side already holds a record awaiting
            // started/spawn_failed; an admission refusal must stay
            // observable instead of vanishing (silent-loss review F2).
            ShellPtyEvent event;
            event.shell_id = command.shell_id;
            event.kind = ShellPtyEvent::Kind::spawn_failed;
            event.detail = "worker_session_limit";
            (void)emit_event(impl.events, std::move(event));
            break;
          }
          ShellPtySession session;
          session.spec = std::move(command.spawn);
          session.last_activity_ms = steady_ms_now();
          session.absolute_deadline_ms =
              steady_ms_now() + session.spec.absolute_timeout_ms;
#if !defined(_WIN32)
          const SpawnOutcome spawned = posix_spawn(session);
#else
          const SpawnOutcome spawned = conpty_spawn(session);
#endif
          if (!spawned.ok) {
            ShellPtyEvent event;
            event.shell_id = session.spec.shell_id;
            event.kind = ShellPtyEvent::Kind::spawn_failed;
            event.detail = spawned.detail;
            (void)emit_event(impl.events, std::move(event));
#if defined(_WIN32)
            conpty_close(session);
#endif
            break;
          }
          const ShellId id = session.spec.shell_id;
          impl.sessions.emplace(id, std::move(session));
          ShellPtyEvent started;
          started.shell_id = id;
          started.kind = ShellPtyEvent::Kind::started;
          (void)emit_event(impl.events, std::move(started));

          break;
        }
        case ShellPtyCommand::Kind::write_stdin: {
          if (found == impl.sessions.end()) {
            break;
          }
          auto& session = found->second;
          if (session.stdin_closed) {
            break;  // input after EOF is rejected at the protocol layer
          }
          if (!command.data.empty() &&
              session.pending_input_bytes + command.data.size() >
                  session.spec.max_input_pending_bytes) {
            if (!session.input_rejected_emitted) {
              session.input_rejected_emitted = true;
              ShellPtyEvent event;
              event.shell_id = command.shell_id;
              event.kind = ShellPtyEvent::Kind::input_rejected;
              event.detail = "input_pending_limit";
              (void)emit_event(impl.events, std::move(event));
              start_termination(session,
                                ShellPtyEvent::ExitReason::input_backpressure,
                                "input_pending_limit", true);
            }
            break;
          }
          if (!command.data.empty()) {
            session.pending_input_bytes += command.data.size();
            session.pending_input.push_back(std::move(command.data));
          }
          flush_pending_input(session);
          session.last_activity_ms = steady_ms_now();
          break;
        }
        case ShellPtyCommand::Kind::resize: {
          if (found == impl.sessions.end()) {
            break;
          }
#if !defined(_WIN32)
          if (found->second.master_fd >= 0) {
            posix_resize(found->second.master_fd, command.columns, command.rows);
          }
#else
          if (found->second.pseudo_console != nullptr) {
            COORD size{};
            size.X = static_cast<SHORT>(
                std::min<std::uint32_t>(command.columns, 0x7FFFU));
            size.Y = static_cast<SHORT>(
                std::min<std::uint32_t>(command.rows, 0x7FFFU));
            const ConPtyApi& api = ConPtyApi::instance();
            if (api.loaded) {
              (void)api.resize(found->second.pseudo_console, size);
            }
          }
#endif
          found->second.last_activity_ms = steady_ms_now();
          break;
        }
        case ShellPtyCommand::Kind::signal: {
          if (found == impl.sessions.end()) {
            break;
          }
#if !defined(_WIN32)
          if (found->second.child > 0) {
            (void)posix_signal_tree(
                found->second.child,
                portable_to_posix_signal(command.signal));
          }
#else
          if (found->second.process != nullptr) {
            const DWORD group = ::GetProcessId(found->second.process);
            switch (command.signal) {
              case ShellPortableSignal::interrupt:
                (void)::GenerateConsoleCtrlEvent(CTRL_C_EVENT, group);
                break;
              case ShellPortableSignal::quit:
              case ShellPortableSignal::hangup:
              case ShellPortableSignal::terminate:
                (void)::GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, group);
                break;
              case ShellPortableSignal::kill:
                if (found->second.job) {
                  ::TerminateJobObject(found->second.job, 1U);
                }
                break;
            }
          }
#endif
          found->second.last_activity_ms = steady_ms_now();
          break;
        }
        case ShellPtyCommand::Kind::close_stdin: {
          if (found == impl.sessions.end() || found->second.stdin_closed) {
            break;  // duplicate EOF stays idempotent (wire protocol 6.3)
          }
          auto& session = found->second;
          session.stdin_closed = true;
#if !defined(_WIN32)
          if (session.master_fd >= 0) {
            const std::byte eot{0x04};
            (void)posix_write_input(session.master_fd, &eot, 1U);
          }
#else
          if (session.in_write) {
            ::CloseHandle(session.in_write);
            session.in_write = nullptr;
          }
#endif
          break;
        }
        case ShellPtyCommand::Kind::terminate: {
          if (found == impl.sessions.end()) {
            break;
          }
          start_termination(found->second,
                            ShellPtyEvent::ExitReason::terminated,
                            command.reason, command.hard);
          break;
        }
      }
    }

    // 2) Deadlines, escalation, then output FIRST and reaping LAST: a
    // child that exits with output still in the PTY buffer must have that
    // output harvested before the exit event, or it would be lost (the
    // session record dies with the exit).
    for (auto it = impl.sessions.begin(); it != impl.sessions.end();) {
      auto& session = it->second;
      const std::uint64_t now = steady_ms_now();

      if (!session.exit_emitted) {
        if (session.output_bytes > session.spec.max_output_bytes) {
          start_termination(session, ShellPtyEvent::ExitReason::output_limit,
                            "output_budget_exhausted", true);
        } else if (session.output_flood) {
          start_termination(session, ShellPtyEvent::ExitReason::output_limit,
                            "output_pending_flood", true);
        } else if (now >= session.absolute_deadline_ms) {
          start_termination(session,
                            ShellPtyEvent::ExitReason::absolute_timeout,
                            "absolute_timeout", false);
        } else if (now - session.last_activity_ms >=
                   session.spec.idle_timeout_ms) {
          start_termination(session, ShellPtyEvent::ExitReason::idle_timeout,
                            "idle_timeout", false);
        }
      }

      if (session.phase == ShellPtySession::Phase::graceful &&
          !session.hard_termination &&
          now >= session.graceful_deadline_ms) {
#if !defined(_WIN32)
        if (session.child > 0) {
          (void)posix_signal_tree(session.child, SIGKILL);
        }
#else
        if (session.job) {
          ::TerminateJobObject(session.job, 1U);
        }
#endif
        session.hard_termination = true;
      }

      drain_pending_output(session);
#if !defined(_WIN32)
      if (!session.output_flood) {
        harvest_output(session);
      }
#endif

      std::int32_t exit_code = 0;
      bool reaped = false;
#if !defined(_WIN32)
      if (session.child > 0) {
        reaped = posix_reap(session.child, &exit_code);
      }
#else
      if (session.process != nullptr) {
        if (::WaitForSingleObject(session.process, 0U) == WAIT_OBJECT_0) {
          reaped = true;
          DWORD code = 0U;
          (void)::GetExitCodeProcess(session.process, &code);
          exit_code = static_cast<std::int32_t>(code);
        }
      }
#endif
      if (reaped && !session.exit_emitted) {
        // Final non-blocking harvest of whatever the child left buffered.
#if !defined(_WIN32)
        if (!session.output_flood) {
          harvest_output(session);
        }
        drain_pending_output(session);
#else
        if (!session.output_flood) {
          drain_conpty_final(session);
        }
        drain_pending_output(session);
#endif
        session.exit_emitted = true;
        ShellPtyEvent event;
        event.shell_id = session.spec.shell_id;
        event.kind = ShellPtyEvent::Kind::exit;
        event.exit_reason = session.pending_exit_reason;
        event.exit_code = exit_code;
        event.detail = session.terminate_reason;
        if (event.detail.empty() &&
            event.exit_reason == ShellPtyEvent::ExitReason::terminated) {
          event.detail = "terminated";
        }
        (void)emit_event(impl.events, std::move(event));
      }

      if (session.exit_emitted) {
#if !defined(_WIN32)
        if (session.master_fd >= 0) {
          ::close(session.master_fd);
          session.master_fd = -1;
        }
#else
        conpty_close(session);
#endif
        it = impl.sessions.erase(it);
        continue;
      }

      flush_pending_input(session);
      ++it;
    }

    // 3) Wait for readiness, bounded by the nearest deadline.
    std::uint64_t next_deadline = steady_ms_now() + 50U;
    for (auto& [id, session] : impl.sessions) {
      (void)id;
      if (session.exit_emitted) {
        continue;
      }
      next_deadline =
          std::min<std::uint64_t>(next_deadline, session.absolute_deadline_ms);
      next_deadline = std::min<std::uint64_t>(
          next_deadline, session.last_activity_ms + session.spec.idle_timeout_ms);
      if (session.phase == ShellPtySession::Phase::graceful) {
        next_deadline = std::min<std::uint64_t>(next_deadline,
                                                session.graceful_deadline_ms);
      }
    }
    std::int64_t wait_ms = static_cast<std::int64_t>(next_deadline) -
                           static_cast<std::int64_t>(steady_ms_now());
    wait_ms = std::min<std::int64_t>(std::max<std::int64_t>(wait_ms, 1), 50);

#if !defined(_WIN32)
    auto* wake = static_cast<PosixPipeWake*>(&impl.wake);
    std::vector<pollfd> fds;
    fds.push_back(pollfd{wake->read_fd(), POLLIN, 0});
    for (auto& [id, session] : impl.sessions) {
      (void)id;
      if (session.master_fd < 0) {
        continue;
      }
      const bool paused = !session.pending_output.empty() ||
                          session.output_flood || session.master_eof;
      if (!paused) {
        fds.push_back(pollfd{session.master_fd, POLLIN, 0});
      }
      if (!session.pending_input.empty()) {
        fds.push_back(pollfd{session.master_fd, POLLOUT, 0});
      }
    }
    (void)::poll(fds.data(), static_cast<nfds_t>(fds.size()),
                 static_cast<int>(wait_ms));
    wake->drain();
#else
    auto* wake = static_cast<WindowsEventWake*>(&impl.wake);
    (void)::WaitForSingleObject(wake->handle(), static_cast<DWORD>(wait_ms));

    // Poll each session's synchronous pipe: PeekNamedPipe bounds the read
    // to what is already buffered, so ReadFile never blocks the worker.
    for (auto& [id, session] : impl.sessions) {
      (void)id;
      poll_conpty_output(session);
    }
#endif
  }

  // Stop: hard-kill every remaining child, reap bounded, report exits.
  for (auto& [id, session] : impl.sessions) {
    (void)id;
#if !defined(_WIN32)
    if (session.child > 0) {
      (void)posix_signal_tree(session.child, SIGKILL);
      int status = 0;
      for (int attempt = 0; attempt < 200; ++attempt) {
        if (::waitpid(session.child, &status, WNOHANG) == session.child) {
          break;
        }
        ::usleep(10'000);
      }
    }
    if (session.master_fd >= 0) {
      ::close(session.master_fd);
      session.master_fd = -1;
    }
#else
    if (session.job) {
      ::TerminateJobObject(session.job, 1U);
    }
    conpty_close(session);
#endif
    if (!session.exit_emitted) {
      session.exit_emitted = true;
      ShellPtyEvent event;
      event.shell_id = session.spec.shell_id;
      event.kind = ShellPtyEvent::Kind::exit;
      event.exit_reason = ShellPtyEvent::ExitReason::worker_shutdown;
      event.detail = "worker_shutdown";
      (void)emit_event(impl.events, std::move(event));
    }
  }
  impl.sessions.clear();
  impl.events.close();
  (void)impl.exit_gate.advance_to(exit_phase);
}

// ---- ShellPtyCoordinator ---------------------------------------------------

ShellPtyCoordinator::~ShellPtyCoordinator() = default;

void ShellPtyCoordinator::bind(Runtime& runtime, bool enabled) {
  runtime_ = &runtime;
  enabled_ = enabled;
}

bool ShellPtyCoordinator::available() const { return enabled_; }

namespace {

Result<void> coordinator_disabled() {
  return Result<void>::failure(pty_error("shell_pty_worker_disabled"));
}

}  // namespace

Result<void> ShellPtyCoordinator::open(ShellPtySpawnSpec spec, EventSink sink) {
  if (!enabled_ || runtime_ == nullptr || !sink) {
    return coordinator_disabled();
  }
  ShellPtyCommand command;
  command.kind = ShellPtyCommand::Kind::open;
  command.shell_id = spec.shell_id;
  command.spawn = std::move(spec);
  const ShellId id = command.shell_id;
  auto submitted =
      detail::RuntimeAccess::shell_pty_submit(*runtime_, std::move(command));
  if (!submitted) {
    return Result<void>::failure(*submitted.error_if());
  }
  sinks_[id] = std::move(sink);
  return Result<void>::success();
}

Result<void> ShellPtyCoordinator::write_stdin(const ShellId& id,
                                              std::span<const std::byte> data) {
  if (!enabled_ || runtime_ == nullptr) {
    return coordinator_disabled();
  }
  ShellPtyCommand command;
  command.kind = ShellPtyCommand::Kind::write_stdin;
  command.shell_id = id;
  command.data.assign(data.begin(), data.end());
  return detail::RuntimeAccess::shell_pty_submit(*runtime_, std::move(command));
}

Result<void> ShellPtyCoordinator::resize(const ShellId& id, std::uint32_t columns,
                                         std::uint32_t rows) {
  if (!enabled_ || runtime_ == nullptr) {
    return coordinator_disabled();
  }
  ShellPtyCommand command;
  command.kind = ShellPtyCommand::Kind::resize;
  command.shell_id = id;
  command.columns = columns;
  command.rows = rows;
  return detail::RuntimeAccess::shell_pty_submit(*runtime_, std::move(command));
}

Result<void> ShellPtyCoordinator::signal(const ShellId& id,
                                         ShellPortableSignal signal_value) {
  if (!enabled_ || runtime_ == nullptr) {
    return coordinator_disabled();
  }
  ShellPtyCommand command;
  command.kind = ShellPtyCommand::Kind::signal;
  command.shell_id = id;
  command.signal = signal_value;
  return detail::RuntimeAccess::shell_pty_submit(*runtime_, std::move(command));
}

Result<void> ShellPtyCoordinator::close_stdin(const ShellId& id) {
  if (!enabled_ || runtime_ == nullptr) {
    return coordinator_disabled();
  }
  ShellPtyCommand command;
  command.kind = ShellPtyCommand::Kind::close_stdin;
  command.shell_id = id;
  return detail::RuntimeAccess::shell_pty_submit(*runtime_, std::move(command));
}

void ShellPtyCoordinator::terminate(const ShellId& id, std::string_view reason) {
  if (!enabled_ || runtime_ == nullptr) {
    return;
  }
  ShellPtyCommand command;
  command.kind = ShellPtyCommand::Kind::terminate;
  command.shell_id = id;
  command.reason = std::string{reason};
  (void)detail::RuntimeAccess::shell_pty_submit(*runtime_, std::move(command));
}

void ShellPtyCoordinator::detach_all() { sinks_.clear(); }

void ShellPtyCoordinator::drain() {
  if (runtime_ == nullptr) {
    return;
  }
  detail::RuntimeAccess::shell_pty_drain(
      *runtime_, [this](const ShellPtyEvent& event) {
        const auto sink = sinks_.find(event.shell_id);
        if (sink == sinks_.end()) {
          return;
        }
        if (event.kind == ShellPtyEvent::Kind::exit ||
            event.kind == ShellPtyEvent::Kind::spawn_failed) {
          EventSink keep = sink->second;
          sinks_.erase(sink);
          keep(event);
          return;
        }
        sink->second(event);
      });
}

}  // namespace heyaki
