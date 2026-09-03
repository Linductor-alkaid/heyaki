#pragma once

// M8 test harness: ShellService pairs over the M7 loopback sessions plus a
// ManualPtyDispatcher standing in for the executor-managed PTY worker. The
// manual dispatcher runs on the test thread exactly like the other manual
// dispatch flavors: open/write/resize/signal/eof/terminate are recorded, and
// the test drives child behavior by emitting started/output/exit events.

#include "m7_support.hpp"
#include "shell_pty.hpp"
#include "shell_service.hpp"

#include <algorithm>
#include <optional>
#include <vector>

namespace heyaki::test {
namespace {

// Records every dispatcher call; tests script child behavior with emit().
class ManualPtyDispatcher final : public IShellPtyDispatcher {
 public:
  struct Call {
    ShellPtyCommand::Kind kind;
    ShellId id;
    std::vector<std::byte> data;
    std::uint32_t columns{};
    std::uint32_t rows{};
    ShellPortableSignal signal{ShellPortableSignal::interrupt};
    std::string reason;
  };

  bool available() const override { return enabled; }

  Result<void> open(ShellPtySpawnSpec spec, EventSink sink) override {
    if (!enabled) {
      return Result<void>::failure(
          Error{ErrorCode::internal, "test", "pty_disabled"});
    }
    if (sinks.contains(spec.shell_id)) {
      return Result<void>::failure(
          Error{ErrorCode::protocol, "test", "shell_id_in_use"});
    }
    last_spec = std::move(spec);
    sinks[spec.shell_id] = std::move(sink);
    opens += 1U;
    return Result<void>::success();
  }

  Result<void> write_stdin(const ShellId& id, std::span<const std::byte> data) override {
    Call call;
    call.kind = ShellPtyCommand::Kind::write_stdin;
    call.id = id;
    call.data.assign(data.begin(), data.end());
    calls.push_back(std::move(call));
    if (reject_writes) {
      return Result<void>::failure(
          Error{ErrorCode::resource_exhausted, "test", "input_pending_limit"});
    }
    return Result<void>::success();
  }

  Result<void> resize(const ShellId& id, std::uint32_t columns,
                      std::uint32_t rows) override {
    Call call;
    call.kind = ShellPtyCommand::Kind::resize;
    call.id = id;
    call.columns = columns;
    call.rows = rows;
    calls.push_back(std::move(call));
    ++resizes;
    return Result<void>::success();
  }

  Result<void> signal(const ShellId& id, ShellPortableSignal signal) override {
    Call call;
    call.kind = ShellPtyCommand::Kind::signal;
    call.id = id;
    call.signal = signal;
    calls.push_back(std::move(call));
    ++signals;
    return Result<void>::success();
  }

  Result<void> close_stdin(const ShellId& id) override {
    Call call;
    call.kind = ShellPtyCommand::Kind::close_stdin;
    call.id = id;
    calls.push_back(std::move(call));
    ++eofs;
    return Result<void>::success();
  }

  void terminate(const ShellId& id, std::string_view reason) override {
    Call call;
    call.kind = ShellPtyCommand::Kind::terminate;
    call.id = id;
    call.reason = std::string{reason};
    calls.push_back(std::move(call));
    ++terminates;
  }

  void detach_all() override { sinks.clear(); }

  // ---- test driving ----

  void emit(const ShellPtyEvent& event) {
    const auto sink = sinks.find(event.shell_id);
    if (sink == sinks.end()) {
      return;
    }
    sink->second(event);
  }

  void emit_started(const ShellId& id) {
    ShellPtyEvent event;
    event.shell_id = id;
    event.kind = ShellPtyEvent::Kind::started;
    emit(event);
  }

  void emit_output(const ShellId& id, std::string_view text) {
    ShellPtyEvent event;
    event.shell_id = id;
    event.kind = ShellPtyEvent::Kind::output;
    const auto* begin = reinterpret_cast<const std::byte*>(text.data());
    event.data.assign(begin, begin + text.size());
    emit(event);
  }

  void emit_exit(const ShellId& id, std::int32_t exit_code,
                 ShellPtyEvent::ExitReason reason = ShellPtyEvent::ExitReason::process) {
    ShellPtyEvent event;
    event.shell_id = id;
    event.kind = ShellPtyEvent::Kind::exit;
    event.exit_code = exit_code;
    event.exit_reason = reason;
    emit(event);
  }

  void emit_spawn_failed(const ShellId& id, std::string detail) {
    ShellPtyEvent event;
    event.shell_id = id;
    event.kind = ShellPtyEvent::Kind::spawn_failed;
    event.detail = std::move(detail);
    emit(event);
  }

  [[nodiscard]] std::size_t calls_of(ShellPtyCommand::Kind kind) const {
    return static_cast<std::size_t>(
        std::count_if(calls.begin(), calls.end(),
                      [kind](const Call& call) { return call.kind == kind; }));
  }

  bool enabled{true};
  bool reject_writes{false};
  std::size_t opens{};
  std::size_t resizes{};
  std::size_t signals{};
  std::size_t eofs{};
  std::size_t terminates{};
  std::optional<ShellPtySpawnSpec> last_spec;
  std::map<ShellId, EventSink> sinks;
  std::vector<Call> calls;
};

// A profile with a fixed program; tests never spawn real children here.
ShellProfileConfig shell_test_profile(std::string name = "maintenance",
                                      std::size_t max_sessions = 2U) {
  ShellProfileConfig profile;
  profile.name = std::move(name);
  profile.argv = {"/bin/echo", "fixed"};
  profile.working_directory = "/";
  profile.environment = {{"PATH", std::nullopt}, {"HOME", std::string{"/tmp"}}};
  profile.max_concurrent_sessions = max_sessions;
  profile.idle_timeout = std::chrono::milliseconds{600000};
  profile.absolute_timeout = std::chrono::milliseconds{3600000};
  profile.terminate_grace = std::chrono::milliseconds{100};
  profile.allowed_signals = {ShellPortableSignal::interrupt,
                             ShellPortableSignal::terminate};
  return profile;
}

struct M8ServicePair {
  struct Options {
    std::vector<std::string> left_scopes;
    std::vector<std::string> right_scopes;
    ShellServiceConfig left_shell;
    ShellServiceConfig right_shell;
    // Served by the RIGHT side unless overridden (left = client).
    bool serve_on_right = true;
    bool serve_on_left = false;
  };

  M7ServicePair m7;
  std::shared_ptr<ManualPtyDispatcher> left_pty =
      std::make_shared<ManualPtyDispatcher>();
  std::shared_ptr<ManualPtyDispatcher> right_pty =
      std::make_shared<ManualPtyDispatcher>();
  std::shared_ptr<ShellService> left_shell;
  std::shared_ptr<ShellService> right_shell;

  struct ShellSinkContext {
    std::function<void(const DeviceEndpointKey&, const ShellServiceEvent&)> events;
    std::function<void(const DeviceEndpointKey&, const ShellAuditRecord&)> audits;
  };
  ShellSinkContext left_sinks;
  ShellSinkContext right_sinks;

  explicit M8ServicePair() : M8ServicePair(Options{}) {}

  explicit M8ServicePair(Options options)
      : m7([&] {
          M7ServicePair::Options m7_options;
          if (!options.left_scopes.empty()) {
            m7_options.left_scopes = options.left_scopes;
          }
          if (!options.right_scopes.empty()) {
            m7_options.right_scopes = options.right_scopes;
          }
          return M7ServicePair(std::move(m7_options));
        }()) {
    attach_m8(std::move(options));
  }

  void attach_m8(const Options& options) {
    auto attach = [&](const std::shared_ptr<PeerSession>& session,
                      const DeviceEndpointKey& key, const ShellServiceConfig& config,
                      const std::shared_ptr<IShellPtyDispatcher>& pty,
                      std::shared_ptr<ShellService>& service,
                      ShellSinkContext& sinks) {
      service = std::make_shared<ShellService>(
          *session, key, config, pty, m7.m6.scope_check(session),
          [this] { return m7.m6.right_clock; });
      service->set_event_sink(&sink_shell_event, &sinks);
      service->set_audit_sink(&sink_shell_audit, &sinks);
      ASSERT_TRUE(service->attach());
    };
    // peer = the REMOTE endpoint (audit initiator, M8-07).
    if (options.serve_on_left) {
      attach(m7.m6.left, m7.right_key(), options.left_shell, left_pty, left_shell,
             left_sinks);
    } else {
      // Client-only side: an empty profile list keeps serving disabled.
      attach(m7.m6.left, m7.right_key(), ShellServiceConfig{}, left_pty, left_shell,
             left_sinks);
    }
    if (options.serve_on_right) {
      attach(m7.m6.right, m7.left_key(), options.right_shell, right_pty,
             right_shell, right_sinks);
    } else {
      attach(m7.m6.right, m7.left_key(), ShellServiceConfig{}, right_pty,
             right_shell, right_sinks);
    }
    m7.m6.pump();
  }

  static void sink_shell_event(void* context, const DeviceEndpointKey& peer,
                               const ShellServiceEvent& event) {
    auto& sinks = *static_cast<ShellSinkContext*>(context);
    if (sinks.events) sinks.events(peer, event);
  }

  static void sink_shell_audit(void* context, const DeviceEndpointKey& peer,
                               const ShellAuditRecord& record) {
    auto& sinks = *static_cast<ShellSinkContext*>(context);
    if (sinks.audits) sinks.audits(peer, record);
  }

  [[nodiscard]] DeviceEndpointKey left_key() const { return m7.left_key(); }
  [[nodiscard]] DeviceEndpointKey right_key() const { return m7.right_key(); }
  [[nodiscard]] PeerSession& left_session() { return m7.left_session(); }
  [[nodiscard]] PeerSession& right_session() { return m7.right_session(); }

  void cycle(int rounds = 64) { m7.cycle(rounds); }

  void inject_frame(PeerSession& from, std::uint32_t channel_id, std::uint8_t type,
                    std::span<const std::byte> payload) {
    m7.inject_frame(from, channel_id, type, payload);
  }
};

}  // namespace
}  // namespace heyaki::test
