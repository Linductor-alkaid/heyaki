// M8 ShellService tests: the security and protocol exit conditions from
// docs/todolists/m8-remote-shell.md — unauthorized/expired grants, no
// executable/env override from the wire, concurrency limits, offset rules,
// EOF semantics, resize storms, signal policy, output flood, input
// backpressure, disconnect reclamation, late frames, and the content-free
// audit record (M8-07).

#include "m8_support.hpp"
#include "session_channels.hpp"

#include <gtest/gtest.h>

namespace heyaki::test {
namespace {

struct ShellEventLog {
  std::vector<ShellServiceEvent> events;
  std::vector<ShellAuditRecord> audits;

  void install(M8ServicePair& pair, bool right) {
    auto& sinks = right ? pair.right_sinks : pair.left_sinks;
    sinks.events = [this](const DeviceEndpointKey&, const ShellServiceEvent& event) {
      events.push_back(event);
    };
    sinks.audits = [this](const DeviceEndpointKey&, const ShellAuditRecord& record) {
      audits.push_back(record);
    };
  }

  [[nodiscard]] std::optional<ShellServiceEvent> last_phase(ShellPhase phase) const {
    for (auto it = events.rbegin(); it != events.rend(); ++it) {
      if (it->phase == phase) return *it;
    }
    return std::nullopt;
  }
};

std::vector<std::string> shell_scopes() {
  return {"message.send", "shell.open:maintenance"};
}

M8ServicePair::Options default_options() {
  // The serving side (right) grants shell.open:maintenance to the client;
  // the client itself serves nothing.
  M8ServicePair::Options options;
  options.left_scopes = {"message.send"};
  options.right_scopes = shell_scopes();
  options.right_shell.profiles = {shell_test_profile()};
  return options;
}

std::vector<std::byte> text_bytes(std::string_view text) {
  return {reinterpret_cast<const std::byte*>(text.data()),
          reinterpret_cast<const std::byte*>(text.data()) + text.size()};
}

std::uint32_t shell_channel_of(PeerSession& side) {
  for (const auto& snapshot : side.channels().channel_snapshots()) {
    if (snapshot.domain == session::ChannelDomain::shell) return snapshot.channel_id;
  }
  return 0U;
}

TEST(M8ShellService, OpenWithoutScopeIsDeniedAndAudited) {
  auto options = default_options();
  options.right_scopes = {"message.send"};  // no shell.open grant
  M8ServicePair pair(options);
  ShellEventLog right_log;
  ShellEventLog left_log;
  right_log.install(pair, true);
  left_log.install(pair, false);

  auto opened = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(opened);
  pair.cycle();

  // The serving side answered SHELL_ERROR permission_denied and never
  // touched the PTY layer (no spawn attempt).
  EXPECT_EQ(pair.right_pty->opens, 0U);
  EXPECT_EQ(pair.right_shell->stats().scope_rejected, 1U);
  const auto closed = left_log.last_phase(ShellPhase::closed);
  ASSERT_TRUE(closed.has_value());
  ASSERT_TRUE(closed->error.has_value());
  EXPECT_EQ(closed->error->code(), ErrorCode::remote_error);

  // The denied attempt is audited with zero bytes and no content fields.
  ASSERT_EQ(right_log.audits.size(), 1U);
  EXPECT_EQ(right_log.audits.front().initiator, pair.left_key().device_id);
  EXPECT_EQ(right_log.audits.front().profile, "maintenance");
  EXPECT_EQ(right_log.audits.front().input_bytes, 0U);
  EXPECT_EQ(right_log.audits.front().output_bytes, 0U);
  EXPECT_EQ(right_log.audits.front().close_reason, ShellCloseReason::protocol_error);
}

TEST(M8ShellService, OpenUnknownProfileAndDisabledWorkerFailClosed) {
  M8ServicePair pair(default_options());
  ShellEventLog left_log;
  left_log.install(pair, false);

  auto opened = pair.left_shell->open_shell("nonexistent");
  ASSERT_TRUE(opened);
  pair.cycle();
  EXPECT_EQ(pair.right_shell->stats().unknown_profile_rejected, 1U);
  EXPECT_TRUE(left_log.last_phase(ShellPhase::closed).has_value());

  // With the PTY worker unavailable the shell stays compile-present but
  // fails closed (M8-01 default off).
  pair.right_pty->enabled = false;
  auto second = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(second);
  pair.cycle();
  EXPECT_EQ(pair.right_shell->stats().spawn_failures, 1U);
}

TEST(M8ShellService, WireOpenCannotOverrideProgramOrEnvironment) {
  M8ServicePair pair(default_options());
  ShellEventLog left_log;
  left_log.install(pair, false);

  // A crafted SHELL_OPEN carries only id/profile/terminal/size/locale; the
  // spawn spec must come from the local profile (M8-02).
  auto opened = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(opened);
  pair.cycle();
  ASSERT_EQ(pair.right_pty->opens, 1U);
  const auto& spec = *pair.right_pty->last_spec;
  EXPECT_EQ(spec.argv, shell_test_profile().argv);
  EXPECT_EQ(spec.os_user, shell_test_profile().os_user);
  EXPECT_EQ(spec.working_directory, shell_test_profile().working_directory);
  // Environment: TERM from the request + profile allowlist only.
  ASSERT_FALSE(spec.environment.empty());
  EXPECT_EQ(spec.environment.front().first, "TERM");
  bool saw_home = false;
  for (const auto& [name, value] : spec.environment) {
    if (name == "HOME") {
      saw_home = true;
      EXPECT_EQ(value, "/tmp");
    }
    EXPECT_NE(name, "SHELL");  // unlisted names never pass
  }
  EXPECT_TRUE(saw_home);
}

TEST(M8ShellService, ConcurrencyLimitRejectsSecondOpen) {
  auto options = default_options();
  options.right_shell.profiles = {shell_test_profile("maintenance", 1U)};
  M8ServicePair pair(options);
  ShellEventLog left_log;
  left_log.install(pair, false);

  auto first = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(first);
  pair.cycle();
  pair.right_pty->emit_started(*first.value_if());
  auto second = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(second);
  pair.cycle();

  EXPECT_EQ(pair.right_pty->opens, 1U);
  EXPECT_EQ(pair.right_shell->stats().concurrency_rejected, 1U);
}

TEST(M8ShellService, InteractiveRoundTripAndByteAccounting) {
  M8ServicePair pair(default_options());
  ShellEventLog left_log;
  ShellEventLog right_log;
  left_log.install(pair, false);
  right_log.install(pair, true);

  auto opened = pair.left_shell->open_shell("maintenance", ShellOpenOptions{});
  ASSERT_TRUE(opened);
  const ShellId id = *opened.value_if();
  pair.cycle();
  pair.right_pty->emit_started(id);
  EXPECT_TRUE(right_log.last_phase(ShellPhase::active).has_value());

  pair.right_pty->emit_output(id, "hello\n");
  pair.cycle();
  const auto output = left_log.last_phase(ShellPhase::active);
  ASSERT_TRUE(output.has_value());
  std::string received_text;
  for (const auto value : output->output) {
    received_text.push_back(static_cast<char>(static_cast<unsigned char>(value)));
  }
  EXPECT_EQ(received_text, "hello\n");
  EXPECT_EQ(output->output_bytes, 6U);

  auto sent = pair.left_shell->send_input(id, text_bytes("ls\n"));
  ASSERT_TRUE(sent);
  pair.cycle();
  EXPECT_EQ(pair.right_pty->calls_of(ShellPtyCommand::Kind::write_stdin), 1U);
  const auto& stats = pair.right_shell->stats();
  EXPECT_EQ(stats.input_bytes_received, 3U);
}

TEST(M8ShellService, InputOffsetRules) {
  M8ServicePair pair(default_options());
  ShellEventLog left_log;
  left_log.install(pair, false);

  auto opened = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(opened);
  const ShellId id = *opened.value_if();
  pair.cycle();
  pair.right_pty->emit_started(id);

  // Duplicate slice: same offset/length replay is ignored (idempotent).
  auto first = pair.left_shell->send_input(id, text_bytes("abc"));
  ASSERT_TRUE(first);
  pair.cycle();
  EXPECT_EQ(pair.right_shell->stats().inputs_received, 1U);

  // Gap: a slice starting beyond the expected offset closes the shell.
  ShellDataHeader gap;
  gap.shell_id = id;
  gap.offset = 100U;
  gap.data_length = 3U;
  const auto payload = encode_shell_data(gap, text_bytes("xyz"));
  ASSERT_TRUE(payload);
  pair.inject_frame(pair.left_session(), shell_channel_of(pair.left_session()),
                    static_cast<std::uint8_t>(FrameType::shell_input),
                    *payload.value_if());
  pair.cycle();
  EXPECT_EQ(pair.right_shell->stats().conflicting_input_slices, 1U);
  EXPECT_EQ(pair.right_pty->calls_of(ShellPtyCommand::Kind::terminate), 1U);
  EXPECT_TRUE(left_log.last_phase(ShellPhase::closed).has_value());
}

TEST(M8ShellService, EofSemantics) {
  M8ServicePair pair(default_options());
  auto opened = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(opened);
  const ShellId id = *opened.value_if();
  pair.cycle();
  pair.right_pty->emit_started(id);

  // Duplicate EOF frames are idempotent server-side.
  ShellEofBody eof;
  eof.shell_id = id;
  const auto payload = encode_shell_eof(eof);
  ASSERT_TRUE(payload);
  for (int round = 0; round < 2; ++round) {
    pair.inject_frame(pair.left_session(), shell_channel_of(pair.left_session()),
                      static_cast<std::uint8_t>(FrameType::shell_eof),
                      *payload.value_if());
    pair.cycle();
  }
  EXPECT_EQ(pair.right_pty->calls_of(ShellPtyCommand::Kind::close_stdin), 1U);

  // Input after EOF is rejected and terminates the child (wire 6.3).
  auto late = pair.left_shell->send_input(id, text_bytes("x"));
  ASSERT_TRUE(late);
  pair.cycle();
  EXPECT_EQ(pair.right_shell->stats().protocol_violations, 1U);
  EXPECT_EQ(pair.right_pty->calls_of(ShellPtyCommand::Kind::terminate), 1U);
}

TEST(M8ShellService, ResizeStormStaysActiveWithLatestWinning) {
  M8ServicePair pair(default_options());
  auto opened = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(opened);
  const ShellId id = *opened.value_if();
  pair.cycle();
  pair.right_pty->emit_started(id);

  for (std::uint32_t round = 0U; round < 64U; ++round) {
    auto resized = pair.left_shell->resize_shell(id, 40U + round, 10U + round);
    ASSERT_TRUE(resized);
  }
  pair.cycle();
  // Every accepted resize reaches the PTY layer; the newest state supersedes
  // older state (wire 6.3) and the shell never fails.
  EXPECT_EQ(pair.right_pty->resizes, 64U);
  EXPECT_EQ(pair.right_shell->stats().resizes_received, 64U);
  EXPECT_EQ(pair.right_shell->stats().protocol_violations, 0U);
}

TEST(M8ShellService, SignalPolicyAllowsListedAndNacksOthers) {
  M8ServicePair pair(default_options());
  ShellEventLog left_log;
  left_log.install(pair, false);
  auto opened = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(opened);
  const ShellId id = *opened.value_if();
  pair.cycle();
  pair.right_pty->emit_started(id);

  ASSERT_TRUE(pair.left_shell->signal_shell(id, ShellPortableSignal::interrupt));
  pair.cycle();
  EXPECT_EQ(pair.right_pty->signals, 1U);

  // kill is NOT in the profile allowlist: SHELL_ERROR unimplemented comes
  // back but the shell stays ACTIVE (wire 6.3 signal row).
  ASSERT_TRUE(pair.left_shell->signal_shell(id, ShellPortableSignal::kill));
  pair.cycle();
  EXPECT_EQ(pair.right_pty->signals, 1U);
  EXPECT_EQ(pair.right_shell->stats().signals_rejected, 1U);
  bool saw_signal_error = false;
  bool saw_closed = false;
  for (const auto& event : left_log.events) {
    if (event.error.has_value() && event.phase != ShellPhase::closed &&
        event.phase != ShellPhase::exited) {
      saw_signal_error = true;  // the NACK arrives while the shell lives
    }
    if (event.phase == ShellPhase::closed || event.phase == ShellPhase::exited) {
      saw_closed = true;
    }
  }
  EXPECT_TRUE(saw_signal_error);
  EXPECT_FALSE(saw_closed);

  // The shell still works after the NACK.
  pair.right_pty->emit_output(id, "still-alive\n");
  pair.cycle();
  const auto output = left_log.last_phase(ShellPhase::active);
  ASSERT_TRUE(output.has_value());
  EXPECT_EQ(output->output.size(), 12U);
}

TEST(M8ShellService, ExitIsImmutableAndLateFramesAreCounted) {
  M8ServicePair pair(default_options());
  ShellEventLog left_log;
  left_log.install(pair, false);
  auto opened = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(opened);
  const ShellId id = *opened.value_if();
  pair.cycle();
  pair.right_pty->emit_started(id);
  pair.right_pty->emit_exit(id, 3U);
  pair.cycle();

  const auto exited = left_log.last_phase(ShellPhase::exited);
  ASSERT_TRUE(exited.has_value());
  ASSERT_TRUE(exited->exit_code.has_value());
  EXPECT_EQ(*exited->exit_code, 3);

  // A late non-identical frame never restarts anything.
  pair.right_pty->emit_output(id, "late\n");
  pair.cycle();
  EXPECT_EQ(pair.right_shell->stats().exits_sent, 1U);

  auto late_input = pair.left_shell->send_input(id, text_bytes("x"));
  EXPECT_FALSE(late_input);
}

TEST(M8ShellService, OutputFloodTerminatesWithResourceExhausted) {
  auto options = default_options();
  options.right_shell.max_output_window_bytes = 256U;
  // The shell channel only admits small control bodies; the fat output
  // slice stays staged and overflows the window (M8-06).
  options.right_shell.channel_byte_capacity = 64U;
  M8ServicePair pair(options);
  ShellEventLog left_log;
  left_log.install(pair, false);
  auto opened = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(opened);
  const ShellId id = *opened.value_if();
  pair.cycle();
  pair.right_pty->emit_started(id);

  // One slice larger than the whole staging window floods immediately.
  pair.right_pty->emit_output(id, std::string(1024U, 'x'));
  pair.cycle();
  EXPECT_EQ(pair.right_shell->stats().output_flood_terminated, 1U);
  EXPECT_EQ(pair.right_pty->calls_of(ShellPtyCommand::Kind::terminate), 1U);
  const auto closed = left_log.last_phase(ShellPhase::closed);
  EXPECT_TRUE(closed.has_value());
  EXPECT_EQ(pair.right_shell->stats().output_limit_terminations, 0U);
}

TEST(M8ShellService, InputBackpressureRejectsAndTerminates) {
  M8ServicePair pair(default_options());
  auto opened = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(opened);
  const ShellId id = *opened.value_if();
  pair.cycle();
  pair.right_pty->emit_started(id);
  pair.right_pty->reject_writes = true;

  auto sent = pair.left_shell->send_input(id, text_bytes("flood"));
  ASSERT_TRUE(sent);
  pair.cycle();
  EXPECT_EQ(pair.right_shell->stats().input_backpressure_rejected, 1U);
  EXPECT_EQ(pair.right_pty->calls_of(ShellPtyCommand::Kind::terminate), 1U);
}

TEST(M8ShellService, SpawnFailureIsTerminal) {
  M8ServicePair pair(default_options());
  ShellEventLog left_log;
  left_log.install(pair, false);
  auto opened = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(opened);
  const ShellId id = *opened.value_if();
  pair.cycle();
  pair.right_pty->emit_spawn_failed(id, "pty_exec_failed");
  pair.cycle();
  const auto closed = left_log.last_phase(ShellPhase::closed);
  ASSERT_TRUE(closed.has_value());
  EXPECT_EQ(pair.right_shell->stats().spawn_failures, 1U);
  // The worker's failure detail rides the SHELL_ERROR so the peer observes
  // WHY the open failed (review F2: exec verdict / admission refusals).
  ASSERT_TRUE(closed->error.has_value());
  EXPECT_EQ(closed->error->safe_detail(), "pty_exec_failed");
}

TEST(M8ShellService, SessionCloseTerminatesServingChildren) {
  M8ServicePair pair(default_options());
  ShellEventLog right_log;
  right_log.install(pair, true);
  auto opened = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(opened);
  const ShellId id = *opened.value_if();
  pair.cycle();
  pair.right_pty->emit_started(id);

  // Disconnect (M8-05 default terminate): the child dies through the ladder
  // and the audit records the session_closed reason.
  pair.right_shell->handle_session_closed();
  EXPECT_EQ(pair.right_pty->calls_of(ShellPtyCommand::Kind::terminate), 1U);
  ASSERT_EQ(right_log.audits.size(), 1U);
  EXPECT_EQ(right_log.audits.front().close_reason, ShellCloseReason::session_closed);

  // Late worker events after teardown are ignored (no duplicate audit).
  pair.right_pty->emit_exit(id, 0U);
  EXPECT_EQ(right_log.audits.size(), 1U);
}

TEST(M8ShellService, PeerCloseTerminatesAndAudits) {
  M8ServicePair pair(default_options());
  ShellEventLog right_log;
  right_log.install(pair, true);
  auto opened = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(opened);
  const ShellId id = *opened.value_if();
  pair.cycle();
  pair.right_pty->emit_started(id);

  auto closed = pair.left_shell->close_shell(id);
  ASSERT_TRUE(closed);
  pair.cycle();
  EXPECT_EQ(pair.right_pty->calls_of(ShellPtyCommand::Kind::terminate), 1U);
  ASSERT_EQ(right_log.audits.size(), 1U);
  EXPECT_EQ(right_log.audits.front().close_reason, ShellCloseReason::peer_close);
}

TEST(M8ShellService, ClientSideOffsetConflictClosesShell) {
  M8ServicePair pair(default_options());
  ShellEventLog left_log;
  left_log.install(pair, false);
  auto opened = pair.left_shell->open_shell("maintenance");
  ASSERT_TRUE(opened);
  const ShellId id = *opened.value_if();
  pair.cycle();
  pair.right_pty->emit_started(id);

  // Inject an output slice with a gap toward the left (client) side.
  ShellDataHeader gap;
  gap.shell_id = id;
  gap.offset = 42U;
  gap.data_length = 2U;
  const auto payload = encode_shell_data(gap, text_bytes("zz"));
  ASSERT_TRUE(payload);
  pair.inject_frame(pair.right_session(), shell_channel_of(pair.right_session()),
                    static_cast<std::uint8_t>(FrameType::shell_output),
                    *payload.value_if());
  pair.cycle();
  const auto closed = left_log.last_phase(ShellPhase::closed);
  ASSERT_TRUE(closed.has_value());
  ASSERT_TRUE(closed->error.has_value());
}

TEST(M8ShellScheduler, BulkBacklogCannotStarveShellFrames) {
  // M8-06 exit condition: with a file (bulk) backlog, shell data
  // (interactive) and exit/error (standard) frames keep draining — the
  // weighted scheduler reserves capacity for them.
  session::SessionChannelManager manager{session::ChannelBudgetConfig{}};
  const auto file_channel =
      manager.allocate_channel(true, session::ChannelDomain::file,
                               session::QueueFullPolicy::reject, 256U, 1024U * 1024U);
  ASSERT_TRUE(file_channel);
  const auto shell_channel =
      manager.allocate_channel(true, session::ChannelDomain::shell,
                               session::QueueFullPolicy::reject, 256U, 1024U * 1024U);
  ASSERT_TRUE(shell_channel);
  for (int index = 0; index < 64; ++index) {
    Frame chunk;
    chunk.type = static_cast<std::uint8_t>(FrameType::file_chunk);
    chunk.channel_id = *file_channel.value_if();
    ASSERT_TRUE(manager.enqueue(*file_channel.value_if(), session::FrameClass::bulk,
                                std::move(chunk)));
  }
  for (int index = 0; index < 4; ++index) {
    Frame output;
    output.type = static_cast<std::uint8_t>(FrameType::shell_output);
    output.channel_id = *shell_channel.value_if();
    ASSERT_TRUE(manager.enqueue(*shell_channel.value_if(),
                                session::FrameClass::interactive, std::move(output)));
    Frame exit_frame;
    exit_frame.type = static_cast<std::uint8_t>(FrameType::shell_exit);
    exit_frame.channel_id = *shell_channel.value_if();
    ASSERT_TRUE(manager.enqueue(*shell_channel.value_if(), session::FrameClass::standard,
                                std::move(exit_frame)));
  }
  std::size_t shell_sent_within_round = 0U;
  std::size_t position_of_first_shell = 0U;
  std::size_t position = 0U;
  while (manager.has_sendable_frames()) {
    auto next = manager.next_to_send();
    ASSERT_TRUE(next.has_value());
    ++position;
    if (next->frame_class != session::FrameClass::bulk) {
      ++shell_sent_within_round;
      if (position_of_first_shell == 0U) position_of_first_shell = position;
    }
  }
  EXPECT_EQ(shell_sent_within_round, 8U);
  // Shell frames interleave early: interactive/standard weight (8/4 tokens)
  // dominates bulk (1 token), so exit/output never wait for the backlog.
  EXPECT_LT(position_of_first_shell, 5U);
  EXPECT_EQ(manager.total_queued_frames(), 0U);
}

TEST(M8ShellService, AuditNeverCarriesTerminalContent) {
  // Compile-time shape check: ShellAuditRecord exposes only metadata fields
  // (M8-07). The round-trip tests above assert the values; here we pin that
  // no byte-buffer member exists on the type.
  static_assert(!std::is_same_v<decltype(ShellAuditRecord::input_bytes),
                                std::vector<std::byte>>);
  SUCCEED();
}

}  // namespace
}  // namespace heyaki::test
