#pragma once

// Remote Shell service (M8), one instance per authorized PeerSession, both
// roles in one class:
//
//   * Serving side: SHELL_OPEN checks the live shell.open:<profile> scope,
//     the locally configured profile set, and the per-profile concurrency
//     limit BEFORE any child exists (M8-02). Program/user/cwd/env come only
//     from the local ShellProfileConfig — the wire ShellOpen structurally
//     cannot override them. The child is spawned on the executor-managed PTY
//     worker through IShellPtyDispatcher; PTY output drains into a bounded
//     staging window and rides SHELL_OUTPUT frames (interactive class), so
//     SHELL_EXIT/ERROR/CLOSE never queue behind stdout floods (M8-06).
//   * Client side: open_shell() sends SHELL_OPEN; peer OUTPUT/EXIT events
//     surface through the event sink with the same offset discipline.
//
// State machine per wire protocol 6.3: offsets are accepted exactly in
// order per direction; duplicate slices are ignored, gaps/conflicts close
// the shell; a newer resize supersedes older state; EOF is idempotent and
// input after EOF is rejected; exit status is immutable; late frames after
// a terminal state are ignored and counted.
//
// Audit (M8-07): terminal serving-side shells emit one ShellAuditRecord
// (initiator, profile, times, exit code, byte counts, close reason) — never
// terminal content.
//
// Threading: every public method runs on the owning Node's strand. PTY
// events arrive through the dispatcher's sink on the same strand.

#include "peer_session.hpp"
#include "service_dispatch.hpp"
#include "shell_pty.hpp"

#include <heyaki/shell.hpp>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace heyaki {

struct ShellServiceConfig {
  // Serving-side profiles; EMPTY keeps Remote Shell off by default (M8-01).
  std::vector<ShellProfileConfig> profiles;
  std::size_t channel_frame_capacity{128U};
  std::size_t channel_byte_capacity{512U * 1024U};
  // Bounded staging window for PTY output waiting on channel capacity; a
  // shell exceeding it is terminated for flooding (M8-06).
  std::size_t max_output_window_bytes{256U * 1024U};
  // Terminal records retained so late frames are counted, not replayed.
  std::size_t max_retained_terminal{64U};
};

class ShellService : public std::enable_shared_from_this<ShellService> {
 public:
  using EventSink = void (*)(void* context, const DeviceEndpointKey& peer,
                             const ShellServiceEvent& event);
  using AuditSink = void (*)(void* context, const DeviceEndpointKey& peer,
                             const ShellAuditRecord& record);
  using ScopeCheck = std::function<bool(std::string_view scope)>;

  ShellService(PeerSession& session, DeviceEndpointKey peer, ShellServiceConfig config,
               std::shared_ptr<IShellPtyDispatcher> pty, ScopeCheck scope_check,
               std::function<std::uint64_t()> wall_clock = {});
  ~ShellService();

  ShellService(const ShellService&) = delete;
  ShellService& operator=(const ShellService&) = delete;

  [[nodiscard]] Result<void> attach();

  // ---- Client role ----
  [[nodiscard]] Result<ShellId> open_shell(std::string profile,
                                           ShellOpenOptions options = {});
  [[nodiscard]] Result<void> send_input(const ShellId& id, std::span<const std::byte> data);
  [[nodiscard]] Result<void> resize_shell(const ShellId& id, std::uint32_t columns,
                                          std::uint32_t rows);
  [[nodiscard]] Result<void> signal_shell(const ShellId& id, ShellPortableSignal signal);
  [[nodiscard]] Result<void> send_eof(const ShellId& id);
  // Explicit local close: terminates the child on the serving side (M8-10).
  [[nodiscard]] Result<void> close_shell(const ShellId& id);

  // ---- PTY worker events (strand context) ----
  void handle_pty_event(const ShellPtyEvent& event);

  void set_event_sink(EventSink sink, void* context);
  void set_audit_sink(AuditSink sink, void* context);

  // Sends staged output while the channel admits it (periodic tick safe).
  void prune();

  // Session loss: every serving child is terminated per the disconnect
  // policy (default terminate, M8-05) and audited (M8-07).
  void handle_session_closed();

  [[nodiscard]] ShellServiceStats stats() const { return stats_; }
  [[nodiscard]] std::size_t active_shells() const;
  [[nodiscard]] bool attached() const noexcept { return attached_; }
  // Frame entry point (also used by tests for direct injection).
  void handle_frame(const FrameView& frame);

 private:
  struct ShellRecord {
    ShellId id;
    std::string profile;
    bool serving{true};
    ShellPhase phase{ShellPhase::opening};
    std::uint64_t next_input_offset{0U};   // expected from the peer (serving)
                                           // / next to send (client)
    std::uint64_t next_output_offset{0U};  // next to send (serving) / expected
                                           // from the peer (client)
    std::uint64_t input_bytes{0U};
    std::uint64_t output_bytes{0U};
    std::optional<std::pair<std::uint64_t, std::uint32_t>> last_input_slice;
    bool eof_received{false};  // serving: peer closed its input
    bool eof_sent{false};      // client: we closed our input
    bool terminal{false};
    bool error_sent{false};    // suppress duplicate SHELL_ERROR frames
    std::optional<std::int32_t> exit_code;
    ShellCloseReason close_reason{ShellCloseReason::process_exit};
    std::uint64_t opened_at_ms{0U};
    std::deque<std::vector<std::byte>> output_window;
    std::size_t output_window_bytes{0U};
    bool audit_emitted{false};
  };

  [[nodiscard]] std::uint64_t now() const;
  [[nodiscard]] Result<void> admit_frame(const FrameView& frame);
  void handle_inbound_open(const FrameView& frame);
  void handle_inbound_input(const FrameView& frame);
  void handle_inbound_output(const FrameView& frame);
  void handle_inbound_resize(const FrameView& frame);
  void handle_inbound_signal(const FrameView& frame);
  void handle_inbound_eof(const FrameView& frame);
  void handle_inbound_exit(const FrameView& frame);
  void handle_inbound_error(const FrameView& frame);
  void handle_inbound_close(const FrameView& frame);

  void finish_terminal(ShellRecord& record, ShellPhase phase,
                       ShellCloseReason reason, std::optional<Error> error);
  void send_error(ShellRecord& record, StableStatus status,
                  std::string_view safe_detail);
  void send_exit(const ShellRecord& record);
  void send_close(const ShellRecord& record, StableStatus status);
  bool send_data_frame(ShellRecord& record, FrameType type,
                       const std::vector<std::byte>& data);
  void drain_output_window(ShellRecord& record);
  void terminate_serving_child(ShellRecord& record, ShellCloseReason reason,
                               std::string_view safe_detail);
  void emit_event(ShellRecord& record, ShellPhase phase,
                  std::optional<Error> error = std::nullopt,
                  std::vector<std::byte> output = {});
  void emit_audit(ShellRecord& record);
  [[nodiscard]] const ShellProfileConfig* profile_config(std::string_view name) const;
  [[nodiscard]] std::size_t profile_active_sessions(std::string_view name) const;
  void evict_terminal_records();
  [[nodiscard]] ShellRecord* record_of(const ShellId& id);

  PeerSession& session_;
  DeviceEndpointKey peer_;
  ShellServiceConfig config_;
  std::shared_ptr<IShellPtyDispatcher> pty_;
  ScopeCheck scope_check_;
  std::function<std::uint64_t()> wall_clock_;
  EventSink event_sink_{};
  void* event_context_{};
  AuditSink audit_sink_{};
  void* audit_context_{};
  std::map<ShellId, ShellRecord> shells_;
  ShellServiceStats stats_;
  std::uint32_t channel_id_{};
  std::vector<std::uint32_t> owned_channels_;
  bool attached_{false};
};

}  // namespace heyaki
