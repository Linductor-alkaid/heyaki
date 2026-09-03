// ShellService implementation (M8). The class comment in shell_service.hpp
// carries the design; this file follows the FileService attach/admit/emit
// pattern: every public method runs on the owning Node's strand, PTY output
// arrives through the dispatcher sink on the same strand, and nothing from
// the peer mutates process parameters (program/user/cwd/env are local-only).

#include "shell_service.hpp"

#include <sodium.h>

#include <algorithm>
#include <utility>

namespace heyaki {
namespace {

Error shell_service_error(ErrorCode code, std::string_view detail) {
  return Error{code, "shell", std::string{detail}};
}

ShellId random_shell_id() {
  ShellId::Storage bytes{};
  do {
    randombytes_buf(bytes.data(), bytes.size());
  } while (ShellId{bytes}.is_zero());
  return ShellId{bytes};
}

bool safe_terminal_type(std::string_view value) noexcept {
  if (value.empty() || value.size() > max_shell_terminal_type_bytes) {
    return false;
  }
  for (const char character : value) {
    const bool ok = (character >= 'A' && character <= 'Z') ||
                    (character >= 'a' && character <= 'z') ||
                    (character >= '0' && character <= '9') || character == '-' ||
                    character == '_' || character == '.';
    if (!ok) {
      return false;
    }
  }
  return true;
}

bool safe_locale(std::string_view value) noexcept {
  if (value.size() > max_shell_locale_bytes) {
    return false;
  }
  for (const char character : value) {
    const bool ok = (character >= 'A' && character <= 'Z') ||
                    (character >= 'a' && character <= 'z') ||
                    (character >= '0' && character <= '9') || character == '-' ||
                    character == '_' || character == '.' || character == '@' ||
                    character == '=';
    if (!ok) {
      return false;
    }
  }
  return true;
}

ShellPtySpawnSpec build_spawn_spec(const ShellProfileConfig& profile,
                                   const ShellOpenBody& open) {
  ShellPtySpawnSpec spec;
  spec.shell_id = open.shell_id;
  spec.argv = profile.argv;
  spec.os_user = profile.os_user;
  spec.working_directory = profile.working_directory;
  spec.columns = open.columns;
  spec.rows = open.rows;
  // Environment resolution (M8-01/M8-02): only the local allowlist plus the
  // requester's TERM/locale — both charset-validated — ever reach the child.
  spec.environment.emplace_back("TERM",
                                safe_terminal_type(open.terminal_type)
                                    ? open.terminal_type
                                    : std::string{"xterm"});
  if (!open.locale.empty() && safe_locale(open.locale)) {
    spec.environment.emplace_back("LANG", open.locale);
  }
  for (const auto& rule : profile.environment) {
    if (rule.value) {
      spec.environment.emplace_back(rule.name, *rule.value);
      continue;
    }
    const char* inherited = std::getenv(rule.name.c_str());
    if (inherited != nullptr) {
      spec.environment.emplace_back(rule.name, std::string{inherited});
    }
  }
  spec.idle_timeout_ms = static_cast<std::uint64_t>(profile.idle_timeout.count());
  spec.absolute_timeout_ms =
      static_cast<std::uint64_t>(profile.absolute_timeout.count());
  spec.terminate_grace_ms = static_cast<std::uint64_t>(profile.terminate_grace.count());
  spec.max_output_bytes = profile.max_output_bytes;
  spec.max_output_pending_bytes = profile.max_output_pending_bytes;
  spec.max_input_pending_bytes = profile.max_input_pending_bytes;
  return spec;
}

}  // namespace

ShellService::ShellService(PeerSession& session, DeviceEndpointKey peer,
                           ShellServiceConfig config,
                           std::shared_ptr<IShellPtyDispatcher> pty,
                           ScopeCheck scope_check,
                           std::function<std::uint64_t()> wall_clock)
    : session_(session),
      peer_(std::move(peer)),
      config_(std::move(config)),
      pty_(std::move(pty)),
      scope_check_(std::move(scope_check)),
      wall_clock_(std::move(wall_clock)) {}

ShellService::~ShellService() {
  session_.set_domain_handler(session::ChannelDomain::shell, DomainFrameHandler{});
  for (const auto channel : owned_channels_) {
    session_.close_business_channel(channel);
  }
}

std::uint64_t ShellService::now() const {
  if (wall_clock_) return wall_clock_();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

const ShellProfileConfig* ShellService::profile_config(
    std::string_view name) const {
  for (const auto& profile : config_.profiles) {
    if (profile.name == name) {
      return &profile;
    }
  }
  return nullptr;
}

std::size_t ShellService::profile_active_sessions(std::string_view name) const {
  std::size_t active = 0U;
  for (const auto& [id, record] : shells_) {
    (void)id;
    if (record.serving && !record.terminal && record.profile == name) {
      ++active;
    }
  }
  return active;
}

std::size_t ShellService::active_shells() const {
  std::size_t active = 0U;
  for (const auto& [id, record] : shells_) {
    (void)id;
    if (!record.terminal) {
      ++active;
    }
  }
  return active;
}

Result<void> ShellService::attach() {
  if (attached_) {
    return Result<void>::success();
  }
  if (config_.channel_frame_capacity == 0U || config_.channel_byte_capacity == 0U ||
      config_.max_output_window_bytes == 0U || config_.max_retained_terminal == 0U) {
    return Result<void>::failure(
        shell_service_error(ErrorCode::configuration, "shell_config_invalid"));
  }
  for (const auto& profile : config_.profiles) {
    auto valid = validate_shell_profile(profile);
    if (!valid) {
      return Result<void>::failure(*valid.error_if());
    }
  }
  if (!pty_) {
    return Result<void>::failure(
        shell_service_error(ErrorCode::configuration, "pty_dispatcher_missing"));
  }
  auto weak = weak_from_this();
  auto opened = session_.open_business_channel(
      session::ChannelDomain::shell, session::QueueFullPolicy::reject,
      config_.channel_frame_capacity, config_.channel_byte_capacity,
      [weak](const FrameView& frame) {
        if (auto self = weak.lock()) self->handle_frame(frame);
      });
  if (!opened) return Result<void>::failure(*opened.error_if());
  channel_id_ = *opened.value_if();
  owned_channels_.push_back(channel_id_);
  session_.set_domain_handler(
      session::ChannelDomain::shell,
      [weak](const FrameView& frame) -> Result<void> {
        auto self = weak.lock();
        if (!self) {
          return Result<void>::failure(
              shell_service_error(ErrorCode::cancelled, "service_detached"));
        }
        return self->admit_frame(frame);
      });
  attached_ = true;
  return Result<void>::success();
}

// ---- Client role ----

Result<ShellId> ShellService::open_shell(std::string profile, ShellOpenOptions options) {
  if (!attached_) {
    return Result<ShellId>::failure(
        shell_service_error(ErrorCode::configuration, "service_not_attached"));
  }
  if (!safe_shell_profile_name(profile)) {
    return Result<ShellId>::failure(
        shell_service_error(ErrorCode::protocol, "profile_name_invalid"));
  }
  if (!safe_terminal_type(options.terminal_type) || !safe_locale(options.locale)) {
    return Result<ShellId>::failure(
        shell_service_error(ErrorCode::protocol, "open_text_invalid"));
  }
  if (active_shells() >= config_.max_retained_terminal) {
    return Result<ShellId>::failure(
        shell_service_error(ErrorCode::resource_exhausted, "shell_limit_reached"));
  }
  const ShellId id = random_shell_id();
  ShellRecord record;
  record.id = id;
  record.profile = profile;
  record.serving = false;
  record.opened_at_ms = now();
  ShellOpenBody open;
  open.shell_id = id;
  open.profile = profile;
  open.terminal_type = options.terminal_type;
  open.columns = options.columns;
  open.rows = options.rows;
  open.locale = options.locale;
  auto encoded = encode_shell_open(open);
  if (!encoded) {
    return Result<ShellId>::failure(*encoded.error_if());
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::shell_open);
  frame.payload = std::move(*encoded.value_if());
  auto sent = session_.send_frame(channel_id_, session::FrameClass::standard,
                                  std::move(frame));
  if (!sent) {
    return Result<ShellId>::failure(*sent.error_if());
  }
  shells_.emplace(id, std::move(record));
  ++stats_.opens_sent;
  emit_event(shells_.at(id), ShellPhase::opening);
  return Result<ShellId>::success(id);
}

Result<void> ShellService::send_input(const ShellId& id, std::span<const std::byte> data) {
  auto* record = record_of(id);
  if (record == nullptr) {
    return Result<void>::failure(
        shell_service_error(ErrorCode::peer_offline, "shell_unknown"));
  }
  if (record->serving || record->terminal || record->eof_sent) {
    return Result<void>::failure(
        shell_service_error(ErrorCode::protocol, "input_not_allowed"));
  }
  if (!send_data_frame(*record, FrameType::shell_input,
                       std::vector<std::byte>{data.begin(), data.end()})) {
    return Result<void>::failure(
        shell_service_error(ErrorCode::would_block, "input_send_rejected"));
  }
  record->input_bytes += data.size();
  ++stats_.inputs_sent;
  return Result<void>::success();
}

Result<void> ShellService::resize_shell(const ShellId& id, std::uint32_t columns,
                                        std::uint32_t rows) {
  auto* record = record_of(id);
  if (record == nullptr) {
    return Result<void>::failure(
        shell_service_error(ErrorCode::peer_offline, "shell_unknown"));
  }
  if (record->terminal) {
    return Result<void>::failure(
        shell_service_error(ErrorCode::protocol, "shell_terminal"));
  }
  ShellResizeBody resize;
  resize.shell_id = id;
  resize.columns = columns;
  resize.rows = rows;
  auto encoded = encode_shell_resize(resize);
  if (!encoded) {
    return Result<void>::failure(*encoded.error_if());
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::shell_resize);
  frame.payload = std::move(*encoded.value_if());
  auto sent = session_.send_frame(channel_id_, session::FrameClass::interactive,
                                  std::move(frame));
  if (!sent) {
    return Result<void>::failure(*sent.error_if());
  }
  return Result<void>::success();
}

Result<void> ShellService::signal_shell(const ShellId& id, ShellPortableSignal signal) {
  auto* record = record_of(id);
  if (record == nullptr) {
    return Result<void>::failure(
        shell_service_error(ErrorCode::peer_offline, "shell_unknown"));
  }
  if (record->terminal) {
    return Result<void>::failure(
        shell_service_error(ErrorCode::protocol, "shell_terminal"));
  }
  ShellSignalBody body;
  body.shell_id = id;
  body.signal = signal;
  auto encoded = encode_shell_signal(body);
  if (!encoded) {
    return Result<void>::failure(*encoded.error_if());
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::shell_signal);
  frame.payload = std::move(*encoded.value_if());
  auto sent = session_.send_frame(channel_id_, session::FrameClass::standard,
                                  std::move(frame));
  if (!sent) {
    return Result<void>::failure(*sent.error_if());
  }
  return Result<void>::success();
}

Result<void> ShellService::send_eof(const ShellId& id) {
  auto* record = record_of(id);
  if (record == nullptr) {
    return Result<void>::failure(
        shell_service_error(ErrorCode::peer_offline, "shell_unknown"));
  }
  if (record->serving || record->terminal || record->eof_sent) {
    return Result<void>::failure(
        shell_service_error(ErrorCode::protocol, "eof_not_allowed"));
  }
  record->eof_sent = true;
  ShellEofBody body;
  body.shell_id = id;
  auto encoded = encode_shell_eof(body);
  if (!encoded) {
    return Result<void>::failure(*encoded.error_if());
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::shell_eof);
  frame.payload = std::move(*encoded.value_if());
  auto sent = session_.send_frame(channel_id_, session::FrameClass::standard,
                                  std::move(frame));
  if (!sent) {
    return Result<void>::failure(*sent.error_if());
  }
  emit_event(*record, ShellPhase::input_eof);
  return Result<void>::success();
}

Result<void> ShellService::close_shell(const ShellId& id) {
  auto* record = record_of(id);
  if (record == nullptr) {
    return Result<void>::failure(
        shell_service_error(ErrorCode::peer_offline, "shell_unknown"));
  }
  if (record->serving) {
    terminate_serving_child(*record, ShellCloseReason::local_close, "local_close");
    return Result<void>::success();
  }
  if (!record->terminal) {
    send_close(*record, StableStatus::cancelled);
    finish_terminal(*record, ShellPhase::closed, ShellCloseReason::local_close,
                    std::nullopt);
  }
  return Result<void>::success();
}

// ---- PTY events ----

void ShellService::handle_pty_event(const ShellPtyEvent& event) {
  auto* record = record_of(event.shell_id);
  if (record == nullptr || !record->serving || record->terminal) {
    return;  // late or unknown: ignored and observable through stats only
  }
  switch (event.kind) {
    case ShellPtyEvent::Kind::started:
      record->phase = ShellPhase::active;
      ++stats_.spawns_started;
      emit_event(*record, ShellPhase::active);
      return;
    case ShellPtyEvent::Kind::output: {
      record->output_bytes += event.data.size();
      record->output_window.push_back(std::move(event.data));
      record->output_window_bytes += record->output_window.back().size();
      drain_output_window(*record);
      if (record->output_window_bytes > config_.max_output_window_bytes) {
        ++stats_.output_flood_terminated;
        send_error(*record, StableStatus::resource_exhausted, "output_window_flood");
        terminate_serving_child(*record, ShellCloseReason::output_limit,
                                "output_window_flood");
      }
      return;
    }
    case ShellPtyEvent::Kind::exit: {
      record->exit_code = event.exit_code;
      ShellCloseReason reason = ShellCloseReason::process_exit;
      switch (event.exit_reason) {
        case ShellPtyEvent::ExitReason::process:
          reason = ShellCloseReason::process_exit;
          break;
        case ShellPtyEvent::ExitReason::idle_timeout:
          reason = ShellCloseReason::idle_timeout;
          ++stats_.idle_timeouts;
          break;
        case ShellPtyEvent::ExitReason::absolute_timeout:
          reason = ShellCloseReason::absolute_timeout;
          ++stats_.absolute_timeouts;
          break;
        case ShellPtyEvent::ExitReason::output_limit:
          reason = ShellCloseReason::output_limit;
          ++stats_.output_limit_terminations;
          break;
        case ShellPtyEvent::ExitReason::input_backpressure:
          reason = ShellCloseReason::input_backpressure;
          break;
        case ShellPtyEvent::ExitReason::terminated:
          reason = ShellCloseReason::terminated;
          break;
        case ShellPtyEvent::ExitReason::worker_shutdown:
          reason = ShellCloseReason::session_closed;
          break;
      }
      if (reason != ShellCloseReason::process_exit && !record->error_sent) {
        send_error(*record,
                   reason == ShellCloseReason::idle_timeout ||
                           reason == ShellCloseReason::absolute_timeout
                       ? StableStatus::deadline_exceeded
                       : StableStatus::resource_exhausted,
                   "pty_" + std::string{shell_close_reason_name(reason)});
      }
      send_exit(*record);
      ++stats_.exits_sent;
      finish_terminal(*record, ShellPhase::exited, reason, std::nullopt);
      return;
    }
    case ShellPtyEvent::Kind::spawn_failed: {
      ++stats_.spawn_failures;
      send_error(*record, StableStatus::failed_precondition, "spawn_failed");
      finish_terminal(*record, ShellPhase::closed, ShellCloseReason::spawn_failed,
                      Error{ErrorCode::internal, "shell", "spawn_failed"});
      return;
    }
    case ShellPtyEvent::Kind::input_rejected: {
      ++stats_.input_backpressure_rejected;
      send_error(*record, StableStatus::resource_exhausted, "input_pending_limit");
      terminate_serving_child(*record, ShellCloseReason::input_backpressure,
                              "input_pending_limit");
      return;
    }
  }
}

void ShellService::set_event_sink(EventSink sink, void* context) {
  event_sink_ = sink;
  event_context_ = context;
}

void ShellService::set_audit_sink(AuditSink sink, void* context) {
  audit_sink_ = sink;
  audit_context_ = context;
}

void ShellService::prune() {
  for (auto& [id, record] : shells_) {
    (void)id;
    if (!record.terminal && record.serving && !record.output_window.empty()) {
      drain_output_window(record);
    }
  }
}

void ShellService::handle_session_closed() {
  for (auto& [id, record] : shells_) {
    (void)id;
    if (record.terminal) {
      continue;
    }
    if (record.serving) {
      // Disconnect policy (M8-05, default terminate): the child dies with
      // the session through the escalation ladder.
      ++stats_.session_close_terminations;
      terminate_serving_child(record, ShellCloseReason::session_closed,
                              "session_closed");
      record.terminal = true;
      record.close_reason = ShellCloseReason::session_closed;
      emit_audit(record);
      emit_event(record, ShellPhase::closed,
                 Error{ErrorCode::transport, "shell", "session_closed"});
    } else {
      finish_terminal(record, ShellPhase::closed, ShellCloseReason::session_closed,
                      Error{ErrorCode::transport, "shell", "session_closed"});
    }
  }
}

void ShellService::handle_frame(const FrameView& frame) {
  (void)admit_frame(frame);
}

Result<void> ShellService::admit_frame(const FrameView& frame) {
  if (!attached_) {
    return Result<void>::failure(
        shell_service_error(ErrorCode::configuration, "service_not_attached"));
  }
  const std::uint8_t type = frame.type;
  const bool first_frame =
      type == static_cast<std::uint8_t>(FrameType::shell_open) ||
      type == static_cast<std::uint8_t>(FrameType::shell_output) ||
      type == static_cast<std::uint8_t>(FrameType::shell_exit) ||
      type == static_cast<std::uint8_t>(FrameType::shell_error) ||
      type == static_cast<std::uint8_t>(FrameType::shell_close);
  if (first_frame && !session_.has_business_channel(frame.channel_id)) {
    auto weak = weak_from_this();
    auto adopted = session_.adopt_business_channel(
        frame.channel_id, session::ChannelDomain::shell,
        session::QueueFullPolicy::reject, config_.channel_frame_capacity,
        config_.channel_byte_capacity,
        [weak](const FrameView& inbound) {
          if (auto self = weak.lock()) self->handle_frame(inbound);
        });
    if (!adopted) return Result<void>::failure(*adopted.error_if());
    owned_channels_.push_back(*adopted.value_if());
  }
  switch (type) {
    case static_cast<std::uint8_t>(FrameType::shell_open):
      handle_inbound_open(frame);
      return Result<void>::success();
    case static_cast<std::uint8_t>(FrameType::shell_input):
      handle_inbound_input(frame);
      return Result<void>::success();
    case static_cast<std::uint8_t>(FrameType::shell_output):
      handle_inbound_output(frame);
      return Result<void>::success();
    case static_cast<std::uint8_t>(FrameType::shell_resize):
      handle_inbound_resize(frame);
      return Result<void>::success();
    case static_cast<std::uint8_t>(FrameType::shell_signal):
      handle_inbound_signal(frame);
      return Result<void>::success();
    case static_cast<std::uint8_t>(FrameType::shell_eof):
      handle_inbound_eof(frame);
      return Result<void>::success();
    case static_cast<std::uint8_t>(FrameType::shell_exit):
      handle_inbound_exit(frame);
      return Result<void>::success();
    case static_cast<std::uint8_t>(FrameType::shell_error):
      handle_inbound_error(frame);
      return Result<void>::success();
    case static_cast<std::uint8_t>(FrameType::shell_close):
      handle_inbound_close(frame);
      return Result<void>::success();
    default:
      return Result<void>::failure(
          shell_service_error(ErrorCode::protocol, "shell_domain_frame_unknown"));
  }
}

// ---- Serving-side inbound frames ----

void ShellService::handle_inbound_open(const FrameView& frame) {
  ++stats_.opens_received;
  auto parsed = parse_shell_open(frame.payload);
  if (!parsed) {
    ++stats_.protocol_violations;
    return;
  }
  const ShellOpenBody open = *parsed.value_if();
  if (shells_.contains(open.shell_id)) {
    ++stats_.protocol_violations;
    return;
  }
  const auto* profile = profile_config(open.profile);
  if (profile == nullptr) {
    ++stats_.unknown_profile_rejected;
    ShellRecord record;
    record.id = open.shell_id;
    record.profile = open.profile;
    record.serving = true;
    record.opened_at_ms = now();
    shells_.emplace(open.shell_id, std::move(record));
    ShellRecord& stored = shells_.at(open.shell_id);
    send_error(stored, StableStatus::not_found, "profile_unknown");
    finish_terminal(stored, ShellPhase::closed, ShellCloseReason::protocol_error,
                    Error{ErrorCode::permission, "shell", "profile_unknown"});
    return;
  }
  // Live scope check (M8-02): default deny; the grant adjudicated at upgrade
  // time governs every later frame.
  if (!scope_check_ || !scope_check_(shell_open_scope(open.profile))) {
    ++stats_.scope_rejected;
    ShellRecord record;
    record.id = open.shell_id;
    record.profile = open.profile;
    record.serving = true;
    record.opened_at_ms = now();
    shells_.emplace(open.shell_id, std::move(record));
    ShellRecord& stored = shells_.at(open.shell_id);
    send_error(stored, StableStatus::permission_denied, "scope_denied");
    finish_terminal(stored, ShellPhase::closed, ShellCloseReason::protocol_error,
                    Error{ErrorCode::permission, "shell", "scope_denied"});
    return;
  }
  if (!pty_->available()) {
    ++stats_.spawn_failures;
    ShellRecord record;
    record.id = open.shell_id;
    record.profile = open.profile;
    record.serving = true;
    record.opened_at_ms = now();
    shells_.emplace(open.shell_id, std::move(record));
    ShellRecord& stored = shells_.at(open.shell_id);
    send_error(stored, StableStatus::failed_precondition, "shell_disabled");
    finish_terminal(stored, ShellPhase::closed, ShellCloseReason::spawn_failed,
                    Error{ErrorCode::internal, "shell", "shell_disabled"});
    return;
  }
  if (profile_active_sessions(open.profile) >= profile->max_concurrent_sessions) {
    ++stats_.concurrency_rejected;
    ShellRecord record;
    record.id = open.shell_id;
    record.profile = open.profile;
    record.serving = true;
    record.opened_at_ms = now();
    shells_.emplace(open.shell_id, std::move(record));
    ShellRecord& stored = shells_.at(open.shell_id);
    send_error(stored, StableStatus::resource_exhausted, "concurrency_limit");
    finish_terminal(stored, ShellPhase::closed, ShellCloseReason::protocol_error,
                    Error{ErrorCode::resource_exhausted, "shell", "concurrency_limit"});
    return;
  }

  ShellRecord record;
  record.id = open.shell_id;
  record.profile = open.profile;
  record.serving = true;
  record.opened_at_ms = now();
  const ShellId id = record.id;
  shells_.emplace(id, std::move(record));
  ShellRecord& stored = shells_.at(id);
  emit_event(stored, ShellPhase::opening);

  auto weak = weak_from_this();
  auto opened = pty_->open(
      build_spawn_spec(*profile, open),
      [weak](const ShellPtyEvent& event) {
        if (auto self = weak.lock()) {
          self->handle_pty_event(event);
        }
      });
  if (!opened) {
    ++stats_.spawn_failures;
    send_error(stored, StableStatus::resource_exhausted, "pty_admission_rejected");
    finish_terminal(stored, ShellPhase::closed, ShellCloseReason::spawn_failed,
                    *opened.error_if());
    return;
  }
}

void ShellService::handle_inbound_input(const FrameView& frame) {
  auto parsed = parse_shell_data(frame.payload);
  if (!parsed) {
    ++stats_.protocol_violations;
    return;
  }
  auto* record = record_of(parsed.value_if()->header.shell_id);
  if (record == nullptr || !record->serving) {
    ++stats_.late_frames_ignored;
    return;
  }
  if (record->terminal) {
    ++stats_.late_frames_ignored;
    return;
  }
  ++stats_.inputs_received;
  const auto& header = parsed.value_if()->header;
  if (record->eof_received) {
    // Input after EOF is rejected (wire protocol 6.3).
    ++stats_.protocol_violations;
    send_error(*record, StableStatus::protocol_error, "input_after_eof");
    terminate_serving_child(*record, ShellCloseReason::protocol_error,
                            "input_after_eof");
    return;
  }
  const std::uint64_t end = header.offset + header.data_length;
  if (header.offset == record->next_input_offset) {
    record->next_input_offset = end;
    record->last_input_slice = {header.offset, header.data_length};
    record->input_bytes += header.data_length;
    stats_.input_bytes_received += header.data_length;
    if (header.data_length == 0U) {
      return;  // zero-length slice: offset bookkeeping only
    }
    auto written = pty_->write_stdin(record->id, parsed.value_if()->data);
    if (!written) {
      ++stats_.input_backpressure_rejected;
      send_error(*record, StableStatus::resource_exhausted, "input_write_rejected");
      terminate_serving_child(*record, ShellCloseReason::input_backpressure,
                              "input_write_rejected");
    }
    return;
  }
  if (end <= record->next_input_offset) {
    ++stats_.duplicate_input_slices;  // exact replay: idempotent
    return;
  }
  // Gap or conflict: close the shell (wire protocol 6.3).
  ++stats_.conflicting_input_slices;
  ++stats_.protocol_violations;
  send_error(*record, StableStatus::protocol_error, "input_offset_conflict");
  terminate_serving_child(*record, ShellCloseReason::protocol_error,
                          "input_offset_conflict");
}

void ShellService::handle_inbound_output(const FrameView& frame) {
  auto parsed = parse_shell_data(frame.payload);
  if (!parsed) {
    ++stats_.protocol_violations;
    return;
  }
  auto* record = record_of(parsed.value_if()->header.shell_id);
  if (record == nullptr || record->serving) {
    ++stats_.late_frames_ignored;
    return;
  }
  if (record->terminal) {
    ++stats_.late_frames_ignored;
    return;
  }
  ++stats_.outputs_received;
  const auto& header = parsed.value_if()->header;
  if (header.offset != record->next_output_offset) {
    if (header.offset + header.data_length <= record->next_output_offset) {
      return;  // duplicate slice
    }
    ++stats_.protocol_violations;
    send_close(*record, StableStatus::protocol_error);
    finish_terminal(*record, ShellPhase::closed, ShellCloseReason::protocol_error,
                    Error{ErrorCode::protocol, "shell", "output_offset_conflict"});
    return;
  }
  record->next_output_offset = header.offset + header.data_length;
  record->output_bytes += header.data_length;
  stats_.output_bytes_received += header.data_length;
  emit_event(*record, ShellPhase::active, std::nullopt,
             std::vector<std::byte>{parsed.value_if()->data.begin(),
                                    parsed.value_if()->data.end()});
}

void ShellService::handle_inbound_resize(const FrameView& frame) {
  auto parsed = parse_shell_resize(frame.payload);
  if (!parsed) {
    ++stats_.protocol_violations;
    return;
  }
  auto* record = record_of(parsed.value_if()->shell_id);
  if (record == nullptr || !record->serving || record->terminal) {
    ++stats_.late_frames_ignored;
    return;
  }
  ++stats_.resizes_received;
  // A newer accepted resize supersedes older state (wire protocol 6.3); a
  // submit failure drops this hint instead of failing the shell — resizes
  // are best-effort under storm.
  (void)pty_->resize(record->id, parsed.value_if()->columns, parsed.value_if()->rows);
}

void ShellService::handle_inbound_signal(const FrameView& frame) {
  auto parsed = parse_shell_signal(frame.payload);
  if (!parsed) {
    ++stats_.protocol_violations;
    return;
  }
  auto* record = record_of(parsed.value_if()->shell_id);
  if (record == nullptr || !record->serving || record->terminal) {
    ++stats_.late_frames_ignored;
    return;
  }
  ++stats_.signals_received;
  const auto* profile = profile_config(record->profile);
  if (profile == nullptr || !shell_signal_allowed(*profile, parsed.value_if()->signal)) {
    // Unsupported signal returns SHELL_ERROR and the shell stays active.
    ++stats_.signals_rejected;
    send_error(*record, StableStatus::unimplemented, "signal_not_allowed");
    return;
  }
  (void)pty_->signal(record->id, parsed.value_if()->signal);
}

void ShellService::handle_inbound_eof(const FrameView& frame) {
  auto parsed = parse_shell_eof(frame.payload);
  if (!parsed) {
    ++stats_.protocol_violations;
    return;
  }
  auto* record = record_of(parsed.value_if()->shell_id);
  if (record == nullptr || !record->serving || record->terminal) {
    ++stats_.late_frames_ignored;
    return;
  }
  ++stats_.eofs_received;
  if (record->eof_received) {
    return;  // duplicate EOF is idempotent
  }
  record->eof_received = true;
  record->phase = ShellPhase::input_eof;
  (void)pty_->close_stdin(record->id);
  emit_event(*record, ShellPhase::input_eof);
}

void ShellService::handle_inbound_exit(const FrameView& frame) {
  auto parsed = parse_shell_exit(frame.payload);
  if (!parsed) {
    ++stats_.protocol_violations;
    return;
  }
  auto* record = record_of(parsed.value_if()->shell_id);
  if (record == nullptr || record->serving) {
    ++stats_.late_frames_ignored;
    return;
  }
  if (record->terminal) {
    ++stats_.late_frames_ignored;
    return;
  }
  ++stats_.exits_received;
  // Exit status is immutable (wire protocol 6.3).
  record->exit_code = parsed.value_if()->exit_code;
  finish_terminal(*record, ShellPhase::exited, ShellCloseReason::process_exit,
                  std::nullopt);
}

void ShellService::handle_inbound_error(const FrameView& frame) {
  auto parsed = parse_shell_error(frame.payload);
  if (!parsed) {
    ++stats_.protocol_violations;
    return;
  }
  auto* record = record_of(parsed.value_if()->shell_id);
  if (record == nullptr || record->serving) {
    ++stats_.late_frames_ignored;
    return;
  }
  if (record->terminal) {
    ++stats_.late_frames_ignored;
    return;
  }
  ++stats_.errors_received;
  Error error{ErrorCode::remote_error, "shell",
              parsed.value_if()->safe_detail.empty()
                  ? std::string{"shell_error"}
                  : parsed.value_if()->safe_detail};
  if (parsed.value_if()->status == StableStatus::unimplemented) {
    // Signal policy NACK: reported, but the shell stays active (wire 6.3).
    emit_event(*record, record->phase, std::move(error));
    return;
  }
  ShellCloseReason reason = ShellCloseReason::process_exit;
  switch (parsed.value_if()->status) {
    case StableStatus::deadline_exceeded:
      reason = ShellCloseReason::idle_timeout;
      break;
    case StableStatus::resource_exhausted:
      reason = ShellCloseReason::output_limit;
      break;
    case StableStatus::permission_denied:
      reason = ShellCloseReason::protocol_error;
      break;
    case StableStatus::failed_precondition:
      reason = ShellCloseReason::spawn_failed;
      break;
    case StableStatus::protocol_error:
      reason = ShellCloseReason::protocol_error;
      break;
    default:
      reason = ShellCloseReason::terminated;
      break;
  }
  finish_terminal(*record, ShellPhase::closed, reason, std::move(error));
}

void ShellService::handle_inbound_close(const FrameView& frame) {
  auto parsed = parse_shell_close(frame.payload);
  if (!parsed) {
    ++stats_.protocol_violations;
    return;
  }
  auto* record = record_of(parsed.value_if()->shell_id);
  if (record == nullptr) {
    ++stats_.late_frames_ignored;
    return;
  }
  ++stats_.closes_received;
  if (record->terminal) {
    ++stats_.late_frames_ignored;
    return;
  }
  if (record->serving) {
    ++stats_.local_terminations;
    record->close_reason = ShellCloseReason::peer_close;
    pty_->terminate(record->id, "peer_close");
    finish_terminal(*record, ShellPhase::closed, ShellCloseReason::peer_close,
                    std::nullopt);
    return;
  }
  finish_terminal(*record, ShellPhase::closed, ShellCloseReason::peer_close,
                  std::nullopt);
}

// ---- Helpers ----

ShellService::ShellRecord* ShellService::record_of(const ShellId& id) {
  const auto found = shells_.find(id);
  return found == shells_.end() ? nullptr : &found->second;
}

bool ShellService::send_data_frame(ShellRecord& record, FrameType type,
                                   const std::vector<std::byte>& data) {
  ShellDataHeader header;
  header.shell_id = record.id;
  header.offset = record.next_input_offset;
  header.data_length = static_cast<std::uint32_t>(data.size());
  auto encoded = encode_shell_data(header, data);
  if (!encoded) {
    return false;
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(type);
  frame.payload = std::move(*encoded.value_if());
  auto sent = session_.send_frame(channel_id_, session::FrameClass::interactive,
                                  std::move(frame));
  if (!sent) {
    return false;
  }
  record.next_input_offset += data.size();
  record.last_input_slice = {header.offset, header.data_length};
  return true;
}

void ShellService::drain_output_window(ShellRecord& record) {
  while (!record.output_window.empty() && !record.terminal) {
    auto& front = record.output_window.front();
    ShellDataHeader header;
    header.shell_id = record.id;
    header.offset = record.next_output_offset;
    header.data_length = static_cast<std::uint32_t>(front.size());
    auto encoded = encode_shell_data(header, front);
    if (!encoded) {
      record.output_window.clear();
      record.output_window_bytes = 0U;
      return;
    }
    Frame frame;
    frame.type = static_cast<std::uint8_t>(FrameType::shell_output);
    frame.payload = std::move(*encoded.value_if());
    auto sent = session_.send_frame(channel_id_, session::FrameClass::interactive,
                                    std::move(frame));
    if (!sent) {
      ++stats_.output_send_deferred;  // stays in the bounded window (M8-06)
      return;
    }
    record.next_output_offset += front.size();
    record.output_window_bytes -= front.size();
    record.output_window.pop_front();
    ++stats_.output_frames_sent;
  }
}

void ShellService::send_error(ShellRecord& record, StableStatus status,
                              std::string_view safe_detail) {
  record.error_sent = true;
  ShellErrorBody body;
  body.shell_id = record.id;
  body.status = status;
  body.safe_detail = std::string{safe_detail};
  auto encoded = encode_shell_error(body);
  if (!encoded) {
    return;
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::shell_error);
  frame.payload = std::move(*encoded.value_if());
  // Standard class: exit/error never wait behind interactive output data
  // (M8-06 control non-starvation).
  (void)session_.send_frame(channel_id_, session::FrameClass::standard,
                            std::move(frame));
}

void ShellService::send_exit(const ShellRecord& record) {
  // Exactly one EXIT per shell: callers only invoke this on the terminal
  // transition.
  ShellExitBody body;
  body.shell_id = record.id;
  body.exit_code = record.exit_code;
  body.status = StableStatus::ok;
  auto encoded = encode_shell_exit(body);
  if (!encoded) {
    return;
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::shell_exit);
  frame.payload = std::move(*encoded.value_if());
  (void)session_.send_frame(channel_id_, session::FrameClass::standard,
                            std::move(frame));
}

void ShellService::send_close(const ShellRecord& record, StableStatus status) {
  ShellCloseBody body;
  body.shell_id = record.id;
  body.status = status;
  auto encoded = encode_shell_close(body);
  if (!encoded) {
    return;
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::shell_close);
  frame.payload = std::move(*encoded.value_if());
  (void)session_.send_frame(channel_id_, session::FrameClass::standard,
                            std::move(frame));
}

void ShellService::terminate_serving_child(ShellRecord& record,
                                           ShellCloseReason reason,
                                           std::string_view safe_detail) {
  if (!record.terminal) {
    ++stats_.local_terminations;
    record.close_reason = reason;
    pty_->terminate(record.id, safe_detail);
  }
}

void ShellService::finish_terminal(ShellRecord& record, ShellPhase phase,
                                   ShellCloseReason reason,
                                   std::optional<Error> error) {
  if (record.terminal) {
    return;  // exit status is immutable; late outcomes are ignored
  }
  record.terminal = true;
  record.phase = phase;
  record.close_reason = reason;
  emit_audit(record);
  emit_event(record, phase, std::move(error));
  evict_terminal_records();
}

void ShellService::emit_audit(ShellRecord& record) {
  if (!record.serving || record.audit_emitted) {
    return;
  }
  record.audit_emitted = true;
  if (audit_sink_ == nullptr) {
    return;
  }
  ShellAuditRecord audit;
  audit.initiator = peer_.device_id;
  audit.profile = record.profile;
  audit.opened_at_ms = record.opened_at_ms;
  audit.closed_at_ms = now();
  audit.exit_code = record.exit_code;
  audit.input_bytes = record.input_bytes;
  audit.output_bytes = record.output_bytes;
  audit.close_reason = record.close_reason;
  audit_sink_(audit_context_, peer_, audit);
}

void ShellService::emit_event(ShellRecord& record, ShellPhase phase,
                              std::optional<Error> error, std::vector<std::byte> output) {
  record.phase = phase;
  if (event_sink_ == nullptr) {
    return;
  }
  ShellServiceEvent event;
  event.shell_id = record.id;
  event.profile = record.profile;
  event.phase = phase;
  event.output = std::move(output);
  event.exit_code = record.exit_code;
  event.close_reason = record.close_reason;
  event.error = std::move(error);
  event.input_bytes = record.input_bytes;
  event.output_bytes = record.output_bytes;
  event.serving_role = record.serving;
  event_sink_(event_context_, peer_, event);
}

void ShellService::evict_terminal_records() {
  std::size_t terminal = 0U;
  for (const auto& [id, record] : shells_) {
    (void)id;
    if (record.terminal) {
      ++terminal;
    }
  }
  while (terminal > config_.max_retained_terminal && !shells_.empty()) {
    const auto oldest = std::find_if(shells_.begin(), shells_.end(), [](const auto& pair) {
      return pair.second.terminal;
    });
    if (oldest == shells_.end()) {
      return;
    }
    shells_.erase(oldest);
    --terminal;
  }
}

}  // namespace heyaki
