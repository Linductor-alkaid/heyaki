#pragma once

// Remote Shell wire bodies, profiles, and lifecycle surfaces (M8-01..M8-07).
// ShellOpen/ShellResize/ShellSignal/ShellExit/ShellEof/ShellError/ShellClose
// follow the frozen heyaki.protocol.shell.v1 protobuf schemas; ShellData is
// deliberately NOT protobuf — it rides the raw 28-byte header from wire
// protocol 2.1:
//
//   ShellData := shell_id:ID16 | offset:U64 | data_length:U32 | data:data_length
//
// Remote Shell is the highest-risk capability and stays DEFAULT OFF: a node
// serves shells only when its configuration explicitly lists profiles, and
// every open additionally requires the live session scope shell.open:<profile>
// (M8-02). The wire ShellOpen carries no executable/env fields, so a requester
// structurally cannot override the fixed program or inject environment
// variables — only the server-side ShellProfileConfig decides those (M8-01).
//
// Audit records (M8-07) capture initiator device, profile, start/end time,
// exit code, byte counts, and the close reason — never terminal content.

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/limits.hpp>
#include <heyaki/pairing_protocol.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

// ---- Scope (M8-02) ----
// Checked on the SHELL-serving side before a child is spawned. The qualifier
// is the server-configured profile name; a granted shell.open:* wildcard
// covers every profile the local policy still chooses to expose.
[[nodiscard]] std::string shell_open_scope(std::string_view profile);

// ---- Profiles (M8-01) ----

// Portable signal set carried by heyaki.protocol.shell.v1.ShellSignal. The
// numeric values mirror POSIX signal numbers where a natural mapping exists;
// the serving side translates to the platform mechanism (process-group
// signal, ConPTY console event) and to the profile's allowlist.
enum class ShellPortableSignal : std::uint32_t {
  hangup = 1U,
  interrupt = 2U,
  quit = 3U,
  kill = 9U,
  terminate = 15U,
};

// One environment rule: `value` empty means "pass the server-side variable
// through", a set value pins a fixed override. Anything not listed is dropped.
struct ShellEnvRule {
  std::string name;
  std::optional<std::string> value;
};

struct ShellProfileConfig {
  // Logical profile name exposed through the shell.open:<profile> scope.
  std::string name;
  // Fixed program and arguments; argv[0] must be an absolute executable path.
  std::vector<std::string> argv;
  // OS user the child must run as. Empty means the node's own user. A
  // non-empty user that the process cannot become (not current, and the
  // process lacks the privilege to switch) fails the spawn closed.
  std::string os_user;
  // Working directory; empty uses the profile's home default (the process
  // working directory of the node).
  std::filesystem::path working_directory;
  // Environment allowlist (M8-01): only listed names reach the child.
  std::vector<ShellEnvRule> environment;
  // Concurrent shells this profile serves across all peers (M8-02).
  std::size_t max_concurrent_sessions{1U};
  // Idle timeout: no stdin bytes and no output bytes for this long
  // terminates the shell (M8-06). 0 keeps the default.
  std::chrono::milliseconds idle_timeout{600000};
  // Absolute lifetime cap per shell (M8-06). 0 keeps the default.
  std::chrono::milliseconds absolute_timeout{3600000};
  // Total output bytes per shell before termination (M8-06).
  std::uint64_t max_output_bytes{64ULL * 1024ULL * 1024ULL};
  // Output bytes allowed to sit unread between the PTY worker and the wire
  // before the shell is terminated for flooding (M8-06).
  std::uint64_t max_output_pending_bytes{256ULL * 1024ULL};
  // Pending stdin bytes tolerated before the writer gives up with
  // resource_exhausted (input backpressure, M8-06).
  std::uint64_t max_input_pending_bytes{64ULL * 1024ULL};
  // Grace between the cooperative/TERM phase and the hard process-tree kill
  // (M8-05).
  std::chrono::milliseconds terminate_grace{5000};
  // Signals a peer may deliver through SHELL_SIGNAL (M8-02 policy).
  std::vector<ShellPortableSignal> allowed_signals{ShellPortableSignal::interrupt,
                                                   ShellPortableSignal::terminate};
};

[[nodiscard]] bool shell_signal_allowed(const ShellProfileConfig& profile,
                                        ShellPortableSignal signal) noexcept;

// True when `name` is a safe profile name (single token, [a-z0-9-], bounded).
[[nodiscard]] bool safe_shell_profile_name(std::string_view name) noexcept;

// Validates one profile configuration (M8-01): absolute executable, bounded
// argv, safe env names, positive timeouts/caps, and sane signal policy.
[[nodiscard]] Result<void> validate_shell_profile(const ShellProfileConfig& profile);

// Resolved runtime view used by the PTY layer; derived server-side only.
struct ResolvedShellProfile {
  std::vector<std::string> argv;
  std::string os_user;
  std::filesystem::path working_directory;
  std::vector<std::pair<std::string, std::string>> environment;
};

// ---- Client-side open request ----
struct ShellOpenOptions {
  std::string terminal_type{"xterm"};
  std::uint32_t columns{80U};
  std::uint32_t rows{24U};
  std::string locale;
};

// ---- Lifecycle surfaces ----

enum class ShellPhase : std::uint8_t {
  opening,   // SHELL_OPEN sent / received, policy+authorization pending
  active,    // child spawned; bidirectional data flows
  input_eof, // peer closed its input side (duplicate EOF is idempotent)
  exited,    // child exited; exit status is immutable
  closed,    // terminal: buffers and process handle released
};

enum class ShellCloseReason : std::uint8_t {
  peer_close,     // SHELL_CLOSE from the peer
  local_close,    // explicit local close
  process_exit,   // child exited on its own
  idle_timeout,   // no activity for the profile idle timeout (M8-06)
  absolute_timeout, // profile absolute lifetime reached (M8-06)
  output_limit,   // total or pending output cap exceeded (M8-06)
  input_backpressure, // stdin pending cap exceeded (M8-06)
  spawn_failed,   // the child could not be started
  protocol_error, // offset gap/conflict or other protocol violation
  session_closed, // the peer session died; disconnect policy applied (M8-05)
  terminated,     // cooperative cancel escalated / disconnect termination
};

[[nodiscard]] std::string_view shell_phase_name(ShellPhase phase) noexcept;
[[nodiscard]] std::string_view shell_close_reason_name(ShellCloseReason reason) noexcept;

// Terminal audit record (M8-07): initiator device, profile, times, exit code,
// byte counts, and close reason. Deliberately carries no terminal content.
struct ShellAuditRecord {
  DeviceId initiator;
  std::string profile;
  std::uint64_t opened_at_ms{0U};
  std::uint64_t closed_at_ms{0U};
  std::optional<std::int32_t> exit_code;
  std::uint64_t input_bytes{0U};
  std::uint64_t output_bytes{0U};
  ShellCloseReason close_reason{ShellCloseReason::process_exit};
};

// Lifecycle notification for one shell (both roles). Output bytes arrive as
// separate notifications with phase active and a non-empty data span.
struct ShellSessionEvent {
  ShellId shell_id;
  std::string profile;
  ShellPhase phase{ShellPhase::opening};
  std::optional<std::int32_t> exit_code;
  std::optional<StableStatus> exit_status;
  ShellCloseReason close_reason{ShellCloseReason::process_exit};
  std::optional<Error> error;
  std::uint64_t input_bytes{0U};
  std::uint64_t output_bytes{0U};
};

// One lifecycle/data notification from a shell session; `output` is
// non-empty exactly for data slices. Shared by the service and the Node's
// public shell observer.
struct ShellServiceEvent {
  ShellId shell_id;
  std::string profile;
  ShellPhase phase{ShellPhase::opening};
  std::vector<std::byte> output;
  std::optional<std::int32_t> exit_code;
  ShellCloseReason close_reason{ShellCloseReason::process_exit};
  std::optional<Error> error;
  std::uint64_t input_bytes{0U};
  std::uint64_t output_bytes{0U};
  bool serving_role{true};
};

// ---- Wire bodies (heyaki.protocol.shell.v1) ----

inline constexpr std::size_t shell_id_bytes = 16U;
// shell_id(16) + offset(8) + data_length(4), big-endian (wire protocol 2.1).
inline constexpr std::size_t shell_data_header_bytes = 28U;
inline constexpr std::size_t max_shell_profile_name_bytes = 64U;
inline constexpr std::size_t max_shell_terminal_type_bytes = 64U;
inline constexpr std::size_t max_shell_locale_bytes = 64U;

struct ShellOpenBody {
  ShellId shell_id;
  std::string profile;
  std::string terminal_type;
  std::uint32_t columns{80U};
  std::uint32_t rows{24U};
  std::string locale;
};

[[nodiscard]] Result<std::vector<std::byte>> encode_shell_open(
    const ShellOpenBody& open, const Limits& limits = {});
[[nodiscard]] Result<ShellOpenBody> parse_shell_open(std::span<const std::byte> payload,
                                                     const Limits& limits = {});

struct ShellResizeBody {
  ShellId shell_id;
  std::uint32_t columns{};
  std::uint32_t rows{};
};

[[nodiscard]] Result<std::vector<std::byte>> encode_shell_resize(const ShellResizeBody& resize);
[[nodiscard]] Result<ShellResizeBody> parse_shell_resize(std::span<const std::byte> payload);

struct ShellSignalBody {
  ShellId shell_id;
  ShellPortableSignal signal{ShellPortableSignal::interrupt};
};

[[nodiscard]] Result<std::vector<std::byte>> encode_shell_signal(const ShellSignalBody& signal);
[[nodiscard]] Result<ShellSignalBody> parse_shell_signal(std::span<const std::byte> payload);

struct ShellExitBody {
  ShellId shell_id;
  std::optional<std::int32_t> exit_code;
  StableStatus status{StableStatus::ok};
};

[[nodiscard]] Result<std::vector<std::byte>> encode_shell_exit(const ShellExitBody& exit);
[[nodiscard]] Result<ShellExitBody> parse_shell_exit(std::span<const std::byte> payload);

struct ShellEofBody {
  ShellId shell_id;
};

[[nodiscard]] Result<std::vector<std::byte>> encode_shell_eof(const ShellEofBody& eof);
[[nodiscard]] Result<ShellEofBody> parse_shell_eof(std::span<const std::byte> payload);

struct ShellErrorBody {
  ShellId shell_id;
  StableStatus status{StableStatus::internal};
  std::string safe_detail;
};

[[nodiscard]] Result<std::vector<std::byte>> encode_shell_error(const ShellErrorBody& error,
                                                                const Limits& limits = {});
[[nodiscard]] Result<ShellErrorBody> parse_shell_error(std::span<const std::byte> payload,
                                                       const Limits& limits = {});

struct ShellCloseBody {
  ShellId shell_id;
  StableStatus status{StableStatus::cancelled};
};

[[nodiscard]] Result<std::vector<std::byte>> encode_shell_close(const ShellCloseBody& close);
[[nodiscard]] Result<ShellCloseBody> parse_shell_close(std::span<const std::byte> payload);

// Raw ShellData header (wire protocol 2.1): offsets frame each data slice.
struct ShellDataHeader {
  ShellId shell_id;
  std::uint64_t offset{};
  std::uint32_t data_length{};
};

// Encodes header + data into one frame payload (exactly header bytes + data).
[[nodiscard]] Result<std::vector<std::byte>> encode_shell_data(const ShellDataHeader& header,
                                                               std::span<const std::byte> data,
                                                               const Limits& limits = {});
// Parses a ShellData payload. The returned data span aliases `payload`.
struct ParsedShellData {
  ShellDataHeader header;
  std::span<const std::byte> data;
};

[[nodiscard]] Result<ParsedShellData> parse_shell_data(std::span<const std::byte> payload,
                                                       const Limits& limits = {});

// ---- Service statistics (M8-02..M8-07) ----
struct ShellServiceStats {
  // Serving role.
  std::uint64_t opens_received{};
  std::uint64_t scope_rejected{};
  std::uint64_t unknown_profile_rejected{};
  std::uint64_t concurrency_rejected{};
  std::uint64_t spawns_started{};
  std::uint64_t spawn_failures{};
  std::uint64_t inputs_received{};
  std::uint64_t input_bytes_received{};
  std::uint64_t input_backpressure_rejected{};
  std::uint64_t duplicate_input_slices{};
  std::uint64_t conflicting_input_slices{};
  std::uint64_t output_frames_sent{};
  std::uint64_t output_send_deferred{};
  std::uint64_t output_flood_terminated{};
  std::uint64_t idle_timeouts{};
  std::uint64_t absolute_timeouts{};
  std::uint64_t output_limit_terminations{};
  std::uint64_t signals_received{};
  std::uint64_t signals_rejected{};
  std::uint64_t resizes_received{};
  std::uint64_t eofs_received{};
  std::uint64_t exits_sent{};
  std::uint64_t closes_received{};
  std::uint64_t local_terminations{};
  std::uint64_t session_close_terminations{};
  std::uint64_t protocol_violations{};
  std::uint64_t late_frames_ignored{};
  // Client role.
  std::uint64_t opens_sent{};
  std::uint64_t opens_accepted{};
  std::uint64_t opens_rejected{};
  std::uint64_t outputs_received{};
  std::uint64_t output_bytes_received{};
  std::uint64_t inputs_sent{};
  std::uint64_t exits_received{};
  std::uint64_t errors_received{};
  std::uint64_t closes_sent{};
};

inline void accumulate(ShellServiceStats& total, const ShellServiceStats& delta) {
  total.opens_received += delta.opens_received;
  total.scope_rejected += delta.scope_rejected;
  total.unknown_profile_rejected += delta.unknown_profile_rejected;
  total.concurrency_rejected += delta.concurrency_rejected;
  total.spawns_started += delta.spawns_started;
  total.spawn_failures += delta.spawn_failures;
  total.inputs_received += delta.inputs_received;
  total.input_bytes_received += delta.input_bytes_received;
  total.input_backpressure_rejected += delta.input_backpressure_rejected;
  total.duplicate_input_slices += delta.duplicate_input_slices;
  total.conflicting_input_slices += delta.conflicting_input_slices;
  total.output_frames_sent += delta.output_frames_sent;
  total.output_send_deferred += delta.output_send_deferred;
  total.output_flood_terminated += delta.output_flood_terminated;
  total.idle_timeouts += delta.idle_timeouts;
  total.absolute_timeouts += delta.absolute_timeouts;
  total.output_limit_terminations += delta.output_limit_terminations;
  total.signals_received += delta.signals_received;
  total.signals_rejected += delta.signals_rejected;
  total.resizes_received += delta.resizes_received;
  total.eofs_received += delta.eofs_received;
  total.exits_sent += delta.exits_sent;
  total.closes_received += delta.closes_received;
  total.local_terminations += delta.local_terminations;
  total.session_close_terminations += delta.session_close_terminations;
  total.protocol_violations += delta.protocol_violations;
  total.late_frames_ignored += delta.late_frames_ignored;
  total.opens_sent += delta.opens_sent;
  total.opens_accepted += delta.opens_accepted;
  total.opens_rejected += delta.opens_rejected;
  total.outputs_received += delta.outputs_received;
  total.output_bytes_received += delta.output_bytes_received;
  total.inputs_sent += delta.inputs_sent;
  total.exits_received += delta.exits_received;
  total.errors_received += delta.errors_received;
  total.closes_sent += delta.closes_sent;
}

}  // namespace heyaki
