// Shell open/resize/signal/exit/eof/error/close bodies and the raw ShellData
// header (M8-03) over the frozen heyaki.protocol.shell.v1 schemas. Protobuf
// bodies go through the shared minimal wire codec; ShellData stays raw per
// wire protocol 2.1 so per-slice framing is fixed-size and allocation-free.
//
// ShellExit.exit_code is proto3 `optional sint32`: zigzag-encoded on the wire.
// The codec rejects trailing bytes, oversized bodies, and non-canonical
// varints before any state mutation (wire protocol section 6.3).

#include <heyaki/shell.hpp>

#include "proto_codec.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <utility>

namespace heyaki {
namespace {

using proto_codec::ProtoField;
using proto_codec::ProtoReader;

Error shell_error(std::string_view detail) {
  return Error{ErrorCode::protocol, "shell", std::string{detail}};
}

void append_big_u64(std::vector<std::byte>& output, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    output.push_back(static_cast<std::byte>((value >> shift) & 0xFFU));
  }
}

void append_big_u32(std::vector<std::byte>& output, std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    output.push_back(static_cast<std::byte>((value >> shift) & 0xFFU));
  }
}

std::uint64_t read_big_u64(const std::byte* bytes) {
  std::uint64_t value = 0U;
  for (std::size_t index = 0U; index < 8U; ++index) {
    value = (value << 8U) | static_cast<std::uint8_t>(bytes[index]);
  }
  return value;
}

std::uint32_t read_big_u32(const std::byte* bytes) {
  std::uint32_t value = 0U;
  for (std::size_t index = 0U; index < 4U; ++index) {
    value = (value << 8U) | static_cast<std::uint8_t>(bytes[index]);
  }
  return value;
}

// proto3 sint32 zigzag.
std::uint64_t zigzag_encode(std::int32_t value) {
  const auto wide = static_cast<std::int64_t>(value);
  return static_cast<std::uint64_t>((wide << 1U) ^ (wide >> 63U));
}

std::int32_t zigzag_decode(std::uint64_t value) {
  const auto wide = static_cast<std::int64_t>(value >> 1U) ^
                    (-static_cast<std::int64_t>(value & 1U));
  return static_cast<std::int32_t>(wide);
}

ShellId read_shell_id(std::span<const std::byte> bytes, std::string_view detail) {
  ShellId::Storage storage{};
  std::copy(bytes.begin(), bytes.end(), storage.begin());
  (void)detail;
  return ShellId{storage};
}

bool valid_shell_id_bytes(std::span<const std::byte> bytes) noexcept {
  return bytes.size() == shell_id_bytes;
}

bool control_bytes_ok(std::string_view text, std::size_t max_bytes) noexcept {
  if (text.size() > max_bytes) {
    return false;
  }
  for (const char character : text) {
    const auto code = static_cast<unsigned char>(character);
    if (code <= 0x1FU || code == 0x7FU) {
      return false;
    }
  }
  return true;
}

bool safe_env_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > 128U) {
    return false;
  }
  const bool first_ok = (name.front() >= 'A' && name.front() <= 'Z') ||
                        (name.front() >= 'a' && name.front() <= 'z') ||
                        name.front() == '_';
  if (!first_ok) {
    return false;
  }
  for (const char character : name) {
    const bool ok = (character >= 'A' && character <= 'Z') ||
                    (character >= 'a' && character <= 'z') ||
                    (character >= '0' && character <= '9') || character == '_';
    if (!ok) {
      return false;
    }
  }
  return true;
}

// Reads every field of a small shell control body; returns failure on the
// first structural problem. Field handling follows proto3: unknown fields are
// skipped, repeated occurrences of a scalar overwrite, and a missing required
// bytes field is caught by the final id presence check.
template <typename Handler>
Result<void> read_shell_body(std::span<const std::byte> payload, Handler&& handle) {
  ProtoReader reader{payload};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<void>::failure(*field.error_if());
    }
    auto routed = handle(*field.value_if(), reader);
    if (!routed) {
      return routed;
    }
  }
  return Result<void>::success();
}

Result<std::span<const std::byte>> expect_bytes(const ProtoField& field) {
  if (field.wire_type != 2U) {
    return Result<std::span<const std::byte>>::failure(
        shell_error("shell_field_wire_type"));
  }
  return Result<std::span<const std::byte>>::success(field.bytes);
}

Result<std::uint64_t> expect_uint(const ProtoField& field) {
  if (field.wire_type != 0U) {
    return Result<std::uint64_t>::failure(shell_error("shell_field_wire_type"));
  }
  return Result<std::uint64_t>::success(field.integer);
}

}  // namespace

std::string shell_open_scope(std::string_view profile) {
  std::string scope{"shell.open:"};
  scope.append(profile);
  return scope;
}

bool shell_signal_allowed(const ShellProfileConfig& profile,
                          ShellPortableSignal signal) noexcept {
  return std::find(profile.allowed_signals.begin(), profile.allowed_signals.end(),
                   signal) != profile.allowed_signals.end();
}

bool safe_shell_profile_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > max_shell_profile_name_bytes) {
    return false;
  }
  for (const char character : name) {
    const bool ok = (character >= 'a' && character <= 'z') ||
                    (character >= '0' && character <= '9') || character == '-';
    if (!ok) {
      return false;
    }
  }
  return name.front() != '-' && name.back() != '-';
}

Result<void> validate_shell_profile(const ShellProfileConfig& profile) {
  if (!safe_shell_profile_name(profile.name)) {
    return Result<void>::failure(
        shell_error("profile_name_invalid"));
  }
  if (profile.argv.empty()) {
    return Result<void>::failure(shell_error("profile_argv_empty"));
  }
  for (const auto& argument : profile.argv) {
    if (argument.find('\0') != std::string::npos || argument.size() > 4096U) {
      return Result<void>::failure(shell_error("profile_argv_invalid"));
    }
  }
  const std::string& executable = profile.argv.front();
  if (executable.empty() || executable.front() != '/') {
    return Result<void>::failure(shell_error("profile_executable_not_absolute"));
  }
  if (executable.find("..") != std::string::npos) {
    return Result<void>::failure(shell_error("profile_executable_traversal"));
  }
  if (profile.max_concurrent_sessions == 0U ||
      profile.max_concurrent_sessions > 16U) {
    return Result<void>::failure(shell_error("profile_concurrency_invalid"));
  }
  if (profile.idle_timeout <= std::chrono::milliseconds{0} ||
      profile.absolute_timeout <= std::chrono::milliseconds{0} ||
      profile.idle_timeout > profile.absolute_timeout) {
    return Result<void>::failure(shell_error("profile_timeouts_invalid"));
  }
  if (profile.terminate_grace <= std::chrono::milliseconds{0} ||
      profile.terminate_grace > std::chrono::milliseconds{60000}) {
    return Result<void>::failure(shell_error("profile_grace_invalid"));
  }
  if (profile.max_output_bytes == 0U || profile.max_output_pending_bytes == 0U ||
      profile.max_input_pending_bytes == 0U ||
      profile.max_output_pending_bytes > profile.max_output_bytes) {
    return Result<void>::failure(shell_error("profile_output_caps_invalid"));
  }
  for (const auto& rule : profile.environment) {
    if (!safe_env_name(rule.name) ||
        (rule.value && rule.value->find('\0') != std::string::npos)) {
      return Result<void>::failure(shell_error("profile_env_invalid"));
    }
  }
  constexpr std::size_t max_env_rules = 64U;
  if (profile.environment.size() > max_env_rules) {
    return Result<void>::failure(shell_error("profile_env_invalid"));
  }
  for (const auto signal : profile.allowed_signals) {
    switch (signal) {
      case ShellPortableSignal::hangup:
      case ShellPortableSignal::interrupt:
      case ShellPortableSignal::quit:
      case ShellPortableSignal::kill:
      case ShellPortableSignal::terminate:
        break;
      default:
        return Result<void>::failure(shell_error("profile_signal_invalid"));
    }
  }
  return Result<void>::success();
}

std::string_view shell_phase_name(ShellPhase phase) noexcept {
  switch (phase) {
    case ShellPhase::opening:
      return "opening";
    case ShellPhase::active:
      return "active";
    case ShellPhase::input_eof:
      return "input-eof";
    case ShellPhase::exited:
      return "exited";
    case ShellPhase::closed:
      return "closed";
  }
  return "unknown";
}

std::string_view shell_close_reason_name(ShellCloseReason reason) noexcept {
  switch (reason) {
    case ShellCloseReason::peer_close:
      return "peer_close";
    case ShellCloseReason::local_close:
      return "local_close";
    case ShellCloseReason::process_exit:
      return "process_exit";
    case ShellCloseReason::idle_timeout:
      return "idle_timeout";
    case ShellCloseReason::absolute_timeout:
      return "absolute_timeout";
    case ShellCloseReason::output_limit:
      return "output_limit";
    case ShellCloseReason::input_backpressure:
      return "input_backpressure";
    case ShellCloseReason::spawn_failed:
      return "spawn_failed";
    case ShellCloseReason::protocol_error:
      return "protocol_error";
    case ShellCloseReason::session_closed:
      return "session_closed";
    case ShellCloseReason::terminated:
      return "terminated";
  }
  return "unknown";
}

// ---- ShellOpen ----

Result<std::vector<std::byte>> encode_shell_open(const ShellOpenBody& open,
                                                 const Limits& limits) {
  if (!safe_shell_profile_name(open.profile)) {
    return Result<std::vector<std::byte>>::failure(shell_error("open_profile_invalid"));
  }
  if (!control_bytes_ok(open.terminal_type, max_shell_terminal_type_bytes) ||
      !control_bytes_ok(open.locale, max_shell_locale_bytes)) {
    return Result<std::vector<std::byte>>::failure(shell_error("open_text_invalid"));
  }
  if (open.columns == 0U || open.columns > 1024U || open.rows == 0U || open.rows > 1024U) {
    return Result<std::vector<std::byte>>::failure(shell_error("open_size_invalid"));
  }
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, std::span<const std::byte>{open.shell_id.bytes()});
  proto_codec::append_text(output, 2U, open.profile);
  proto_codec::append_text(output, 3U, open.terminal_type);
  proto_codec::append_uint(output, 4U, open.columns);
  proto_codec::append_uint(output, 5U, open.rows);
  if (!open.locale.empty()) {
    proto_codec::append_text(output, 6U, open.locale);
  }
  if (output.size() > limits.max_shell_control_bytes) {
    return Result<std::vector<std::byte>>::failure(shell_error("open_body_limit"));
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<ShellOpenBody> parse_shell_open(std::span<const std::byte> payload,
                                        const Limits& limits) {
  if (payload.size() > limits.max_shell_control_bytes) {
    return Result<ShellOpenBody>::failure(shell_error("open_body_limit"));
  }
  ShellOpenBody open;
  bool have_id = false;
  bool have_profile = false;
  auto read = [&](const ProtoField& field, ProtoReader& reader) -> Result<void> {
    switch (field.number) {
      case 1U: {
        auto bytes = expect_bytes(field);
        if (!bytes) return Result<void>::failure(*bytes.error_if());
        if (!valid_shell_id_bytes(*bytes.value_if())) {
          return Result<void>::failure(shell_error("open_id_invalid"));
        }
        open.shell_id = read_shell_id(*bytes.value_if(), "open");
        have_id = true;
        return Result<void>::success();
      }
      case 2U: {
        auto bytes = expect_bytes(field);
        if (!bytes) return Result<void>::failure(*bytes.error_if());
        open.profile = std::string{reader.text(field)};
        have_profile = true;
        return Result<void>::success();
      }
      case 3U: {
        auto bytes = expect_bytes(field);
        if (!bytes) return Result<void>::failure(*bytes.error_if());
        open.terminal_type = std::string{reader.text(field)};
        return Result<void>::success();
      }
      case 4U: {
        auto value = expect_uint(field);
        if (!value) return Result<void>::failure(*value.error_if());
        open.columns = static_cast<std::uint32_t>(*value.value_if());
        return Result<void>::success();
      }
      case 5U: {
        auto value = expect_uint(field);
        if (!value) return Result<void>::failure(*value.error_if());
        open.rows = static_cast<std::uint32_t>(*value.value_if());
        return Result<void>::success();
      }
      case 6U: {
        auto bytes = expect_bytes(field);
        if (!bytes) return Result<void>::failure(*bytes.error_if());
        open.locale = std::string{reader.text(field)};
        return Result<void>::success();
      }
      default:
        return Result<void>::success();  // unknown field: skip
    }
  };
  auto parsed = read_shell_body(payload, read);
  if (!parsed) {
    return Result<ShellOpenBody>::failure(*parsed.error_if());
  }
  if (!have_id || open.shell_id.is_zero()) {
    return Result<ShellOpenBody>::failure(shell_error("open_id_missing"));
  }
  if (!have_profile) {
    return Result<ShellOpenBody>::failure(shell_error("open_profile_missing"));
  }
  if (!safe_shell_profile_name(open.profile)) {
    return Result<ShellOpenBody>::failure(shell_error("open_profile_invalid"));
  }
  if (!control_bytes_ok(open.terminal_type, max_shell_terminal_type_bytes) ||
      !control_bytes_ok(open.locale, max_shell_locale_bytes)) {
    return Result<ShellOpenBody>::failure(shell_error("open_text_invalid"));
  }
  if (open.columns == 0U || open.columns > 1024U || open.rows == 0U || open.rows > 1024U) {
    return Result<ShellOpenBody>::failure(shell_error("open_size_invalid"));
  }
  return Result<ShellOpenBody>::success(std::move(open));
}

// ---- ShellResize ----

Result<std::vector<std::byte>> encode_shell_resize(const ShellResizeBody& resize) {
  if (resize.columns == 0U || resize.columns > 1024U || resize.rows == 0U ||
      resize.rows > 1024U) {
    return Result<std::vector<std::byte>>::failure(shell_error("resize_size_invalid"));
  }
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, std::span<const std::byte>{resize.shell_id.bytes()});
  proto_codec::append_uint(output, 2U, resize.columns);
  proto_codec::append_uint(output, 3U, resize.rows);
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<ShellResizeBody> parse_shell_resize(std::span<const std::byte> payload) {
  ShellResizeBody resize;
  bool have_id = false;
  auto read = [&](const ProtoField& field, ProtoReader& reader) -> Result<void> {
    (void)reader;
    switch (field.number) {
      case 1U: {
        auto bytes = expect_bytes(field);
        if (!bytes) return Result<void>::failure(*bytes.error_if());
        if (!valid_shell_id_bytes(*bytes.value_if())) {
          return Result<void>::failure(shell_error("resize_id_invalid"));
        }
        resize.shell_id = read_shell_id(*bytes.value_if(), "resize");
        have_id = true;
        return Result<void>::success();
      }
      case 2U: {
        auto value = expect_uint(field);
        if (!value) return Result<void>::failure(*value.error_if());
        resize.columns = static_cast<std::uint32_t>(*value.value_if());
        return Result<void>::success();
      }
      case 3U: {
        auto value = expect_uint(field);
        if (!value) return Result<void>::failure(*value.error_if());
        resize.rows = static_cast<std::uint32_t>(*value.value_if());
        return Result<void>::success();
      }
      default:
        return Result<void>::success();
    }
  };
  auto parsed = read_shell_body(payload, read);
  if (!parsed) {
    return Result<ShellResizeBody>::failure(*parsed.error_if());
  }
  if (!have_id || resize.shell_id.is_zero()) {
    return Result<ShellResizeBody>::failure(shell_error("resize_id_missing"));
  }
  if (resize.columns == 0U || resize.columns > 1024U || resize.rows == 0U ||
      resize.rows > 1024U) {
    return Result<ShellResizeBody>::failure(shell_error("resize_size_invalid"));
  }
  return Result<ShellResizeBody>::success(std::move(resize));
}

// ---- ShellSignal ----

Result<std::vector<std::byte>> encode_shell_signal(const ShellSignalBody& signal) {
  const auto raw = static_cast<std::uint32_t>(signal.signal);
  switch (signal.signal) {
    case ShellPortableSignal::hangup:
    case ShellPortableSignal::interrupt:
    case ShellPortableSignal::quit:
    case ShellPortableSignal::kill:
    case ShellPortableSignal::terminate:
      break;
    default:
      return Result<std::vector<std::byte>>::failure(shell_error("signal_value_invalid"));
  }
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, std::span<const std::byte>{signal.shell_id.bytes()});
  proto_codec::append_uint(output, 2U, raw);
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<ShellSignalBody> parse_shell_signal(std::span<const std::byte> payload) {
  ShellSignalBody signal;
  bool have_id = false;
  bool have_value = false;
  auto read = [&](const ProtoField& field, ProtoReader& reader) -> Result<void> {
    (void)reader;
    switch (field.number) {
      case 1U: {
        auto bytes = expect_bytes(field);
        if (!bytes) return Result<void>::failure(*bytes.error_if());
        if (!valid_shell_id_bytes(*bytes.value_if())) {
          return Result<void>::failure(shell_error("signal_id_invalid"));
        }
        signal.shell_id = read_shell_id(*bytes.value_if(), "signal");
        have_id = true;
        return Result<void>::success();
      }
      case 2U: {
        auto value = expect_uint(field);
        if (!value) return Result<void>::failure(*value.error_if());
        if (*value.value_if() > 0xFFFFFFFFU) {
          return Result<void>::failure(shell_error("signal_value_invalid"));
        }
        signal.signal = static_cast<ShellPortableSignal>(*value.value_if());
        have_value = true;
        return Result<void>::success();
      }
      default:
        return Result<void>::success();
    }
  };
  auto parsed = read_shell_body(payload, read);
  if (!parsed) {
    return Result<ShellSignalBody>::failure(*parsed.error_if());
  }
  if (!have_id || signal.shell_id.is_zero()) {
    return Result<ShellSignalBody>::failure(shell_error("signal_id_missing"));
  }
  if (!have_value) {
    return Result<ShellSignalBody>::failure(shell_error("signal_value_missing"));
  }
  switch (signal.signal) {
    case ShellPortableSignal::hangup:
    case ShellPortableSignal::interrupt:
    case ShellPortableSignal::quit:
    case ShellPortableSignal::kill:
    case ShellPortableSignal::terminate:
      return Result<ShellSignalBody>::success(std::move(signal));
    default:
      return Result<ShellSignalBody>::failure(shell_error("signal_value_invalid"));
  }
}

// ---- ShellExit ----

Result<std::vector<std::byte>> encode_shell_exit(const ShellExitBody& exit) {
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, std::span<const std::byte>{exit.shell_id.bytes()});
  if (exit.exit_code) {
    proto_codec::append_tag(output, 2U, 0U);
    proto_codec::append_varint(output, zigzag_encode(*exit.exit_code));
  }
  proto_codec::append_uint(output, 3U, static_cast<std::uint64_t>(exit.status));
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<ShellExitBody> parse_shell_exit(std::span<const std::byte> payload) {
  ShellExitBody exit;
  bool have_id = false;
  auto read = [&](const ProtoField& field, ProtoReader& reader) -> Result<void> {
    (void)reader;
    switch (field.number) {
      case 1U: {
        auto bytes = expect_bytes(field);
        if (!bytes) return Result<void>::failure(*bytes.error_if());
        if (!valid_shell_id_bytes(*bytes.value_if())) {
          return Result<void>::failure(shell_error("exit_id_invalid"));
        }
        exit.shell_id = read_shell_id(*bytes.value_if(), "exit");
        have_id = true;
        return Result<void>::success();
      }
      case 2U: {
        auto value = expect_uint(field);
        if (!value) return Result<void>::failure(*value.error_if());
        if (*value.value_if() > 0xFFFFFFFFU) {
          return Result<void>::failure(shell_error("exit_code_invalid"));
        }
        exit.exit_code = zigzag_decode(*value.value_if());
        return Result<void>::success();
      }
      case 3U: {
        auto value = expect_uint(field);
        if (!value) return Result<void>::failure(*value.error_if());
        exit.status = static_cast<StableStatus>(*value.value_if());
        return Result<void>::success();
      }
      default:
        return Result<void>::success();
    }
  };
  auto parsed = read_shell_body(payload, read);
  if (!parsed) {
    return Result<ShellExitBody>::failure(*parsed.error_if());
  }
  if (!have_id || exit.shell_id.is_zero()) {
    return Result<ShellExitBody>::failure(shell_error("exit_id_missing"));
  }
  return Result<ShellExitBody>::success(std::move(exit));
}

// ---- ShellEof ----

Result<std::vector<std::byte>> encode_shell_eof(const ShellEofBody& eof) {
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, std::span<const std::byte>{eof.shell_id.bytes()});
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<ShellEofBody> parse_shell_eof(std::span<const std::byte> payload) {
  ShellEofBody eof;
  bool have_id = false;
  auto read = [&](const ProtoField& field, ProtoReader& reader) -> Result<void> {
    (void)reader;
    if (field.number == 1U) {
      auto bytes = expect_bytes(field);
      if (!bytes) return Result<void>::failure(*bytes.error_if());
      if (!valid_shell_id_bytes(*bytes.value_if())) {
        return Result<void>::failure(shell_error("eof_id_invalid"));
      }
      eof.shell_id = read_shell_id(*bytes.value_if(), "eof");
      have_id = true;
      return Result<void>::success();
    }
    return Result<void>::success();
  };
  auto parsed = read_shell_body(payload, read);
  if (!parsed) {
    return Result<ShellEofBody>::failure(*parsed.error_if());
  }
  if (!have_id || eof.shell_id.is_zero()) {
    return Result<ShellEofBody>::failure(shell_error("eof_id_missing"));
  }
  return Result<ShellEofBody>::success(std::move(eof));
}

// ---- ShellError ----

Result<std::vector<std::byte>> encode_shell_error(const ShellErrorBody& error,
                                                  const Limits& limits) {
  // safe_detail stays bounded and control-free; it never carries terminal
  // content (M8-07).
  if (!control_bytes_ok(error.safe_detail, 256U)) {
    return Result<std::vector<std::byte>>::failure(shell_error("error_detail_invalid"));
  }
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, std::span<const std::byte>{error.shell_id.bytes()});
  proto_codec::append_uint(output, 2U, static_cast<std::uint64_t>(error.status));
  proto_codec::append_text(output, 3U, error.safe_detail);
  if (output.size() > limits.max_shell_control_bytes) {
    return Result<std::vector<std::byte>>::failure(shell_error("error_body_limit"));
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<ShellErrorBody> parse_shell_error(std::span<const std::byte> payload,
                                          const Limits& limits) {
  if (payload.size() > limits.max_shell_control_bytes) {
    return Result<ShellErrorBody>::failure(shell_error("error_body_limit"));
  }
  ShellErrorBody error;
  bool have_id = false;
  auto read = [&](const ProtoField& field, ProtoReader& reader) -> Result<void> {
    switch (field.number) {
      case 1U: {
        auto bytes = expect_bytes(field);
        if (!bytes) return Result<void>::failure(*bytes.error_if());
        if (!valid_shell_id_bytes(*bytes.value_if())) {
          return Result<void>::failure(shell_error("error_id_invalid"));
        }
        error.shell_id = read_shell_id(*bytes.value_if(), "error");
        have_id = true;
        return Result<void>::success();
      }
      case 2U: {
        auto value = expect_uint(field);
        if (!value) return Result<void>::failure(*value.error_if());
        error.status = static_cast<StableStatus>(*value.value_if());
        return Result<void>::success();
      }
      case 3U: {
        auto bytes = expect_bytes(field);
        if (!bytes) return Result<void>::failure(*bytes.error_if());
        error.safe_detail = std::string{reader.text(field)};
        return Result<void>::success();
      }
      default:
        return Result<void>::success();
    }
  };
  auto parsed = read_shell_body(payload, read);
  if (!parsed) {
    return Result<ShellErrorBody>::failure(*parsed.error_if());
  }
  if (!have_id || error.shell_id.is_zero()) {
    return Result<ShellErrorBody>::failure(shell_error("error_id_missing"));
  }
  if (!control_bytes_ok(error.safe_detail, 256U)) {
    return Result<ShellErrorBody>::failure(shell_error("error_detail_invalid"));
  }
  return Result<ShellErrorBody>::success(std::move(error));
}

// ---- ShellClose ----

Result<std::vector<std::byte>> encode_shell_close(const ShellCloseBody& close) {
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, std::span<const std::byte>{close.shell_id.bytes()});
  proto_codec::append_uint(output, 2U, static_cast<std::uint64_t>(close.status));
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<ShellCloseBody> parse_shell_close(std::span<const std::byte> payload) {
  ShellCloseBody close;
  bool have_id = false;
  auto read = [&](const ProtoField& field, ProtoReader& reader) -> Result<void> {
    (void)reader;
    switch (field.number) {
      case 1U: {
        auto bytes = expect_bytes(field);
        if (!bytes) return Result<void>::failure(*bytes.error_if());
        if (!valid_shell_id_bytes(*bytes.value_if())) {
          return Result<void>::failure(shell_error("close_id_invalid"));
        }
        close.shell_id = read_shell_id(*bytes.value_if(), "close");
        have_id = true;
        return Result<void>::success();
      }
      case 2U: {
        auto value = expect_uint(field);
        if (!value) return Result<void>::failure(*value.error_if());
        close.status = static_cast<StableStatus>(*value.value_if());
        return Result<void>::success();
      }
      default:
        return Result<void>::success();
    }
  };
  auto parsed = read_shell_body(payload, read);
  if (!parsed) {
    return Result<ShellCloseBody>::failure(*parsed.error_if());
  }
  if (!have_id || close.shell_id.is_zero()) {
    return Result<ShellCloseBody>::failure(shell_error("close_id_missing"));
  }
  return Result<ShellCloseBody>::success(std::move(close));
}

// ---- Raw ShellData ----

Result<std::vector<std::byte>> encode_shell_data(const ShellDataHeader& header,
                                                 std::span<const std::byte> data,
                                                 const Limits& limits) {
  if (header.data_length != data.size()) {
    return Result<std::vector<std::byte>>::failure(shell_error("data_length_mismatch"));
  }
  if (data.size() > limits.max_shell_data_bytes) {
    return Result<std::vector<std::byte>>::failure(shell_error("data_limit"));
  }
  if (header.shell_id.is_zero()) {
    return Result<std::vector<std::byte>>::failure(shell_error("data_id_invalid"));
  }
  std::vector<std::byte> output;
  output.reserve(shell_data_header_bytes + data.size());
  const auto& id = header.shell_id.bytes();
  output.insert(output.end(), id.begin(), id.end());
  append_big_u64(output, header.offset);
  append_big_u32(output, header.data_length);
  output.insert(output.end(), data.begin(), data.end());
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<ParsedShellData> parse_shell_data(std::span<const std::byte> payload,
                                          const Limits& limits) {
  if (payload.size() < shell_data_header_bytes) {
    return Result<ParsedShellData>::failure(shell_error("data_header_truncated"));
  }
  ShellDataHeader header;
  header.shell_id = read_shell_id(payload.first(shell_id_bytes), "data");
  header.offset = read_big_u64(payload.data() + shell_id_bytes);
  header.data_length = read_big_u32(payload.data() + shell_id_bytes + 8U);
  const std::size_t data_bytes = payload.size() - shell_data_header_bytes;
  if (header.data_length != data_bytes) {
    return Result<ParsedShellData>::failure(shell_error("data_length_mismatch"));
  }
  if (data_bytes > limits.max_shell_data_bytes) {
    return Result<ParsedShellData>::failure(shell_error("data_limit"));
  }
  if (header.shell_id.is_zero()) {
    return Result<ParsedShellData>::failure(shell_error("data_id_invalid"));
  }
  ParsedShellData parsed;
  parsed.header = header;
  parsed.data = payload.subspan(shell_data_header_bytes);
  return Result<ParsedShellData>::success(std::move(parsed));
}

}  // namespace heyaki
