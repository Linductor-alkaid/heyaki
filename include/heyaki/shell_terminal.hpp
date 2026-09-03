#pragma once

// SafeTerminalModel: the M8-08/M8-09 conservative VT renderer. Remote shell
// bytes are NEVER written to the host terminal; they are parsed here into a
// bounded in-memory text model that the UI renders itself.
//
// Decision record (M8-08): Heyaki ships a first-party safe-subset VT parser
// (v1, this file) instead of vendoring a terminal emulation library. The
// frozen wire protocol allows "reject rather than pass through" for unknown
// sequences, and a first-party ~500-line state machine keeps the supply
// chain and the audit surface small. Version: heyaki-shell-terminal/1.
//
// Supported (safe subset):
//   - UTF-8 text (validated; invalid bytes become U+FFFD, never passthrough)
//   - BS, HT (bounded stops), LF/VT/FF, CR, and SGR which is accepted but
//     degraded to plain text (attributes dropped)
//   - CSI cursor movement/erase (CUU/CUD/CUF/CUB/CNL/CPL/CHA/CUP/VPA/ED/EL/
//     ICH/DCH/IL/DL/ECH), ANSI save/restore cursor, ESC D/M/E, RIS
// Rejected (dropped and counted, never executed, never passed through):
//   - OSC in any form — window title (OSC 0/2), clipboard (OSC 52),
//     hyperlinks (OSC 8) and every other payload
//   - DCS/SOS/PM/APC strings, charset designation, keypad/DEC private modes,
//     scroll regions, unknown or malformed/oversized sequences
//
// Every buffer is bounded by configuration; nothing allocates from peer data
// without a cap, and feed() always consumes progress.

#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>
#include <string>
#include <vector>

namespace heyaki {

struct SafeTerminalConfig {
  std::uint32_t columns{80U};
  std::uint32_t rows{24U};
  // Hard caps; larger peer resize requests clamp here.
  std::uint32_t max_columns{1024U};
  std::uint32_t max_rows{1024U};
  std::size_t max_scrollback_lines{4096U};
  // A single OSC/DCS/CSI sequence longer than this is dropped and the parser
  // resynchronizes.
  std::size_t max_sequence_bytes{4096U};
};

struct SafeTerminalStats {
  std::uint64_t bytes_fed{0U};
  std::uint64_t osc_dropped{0U};
  std::uint64_t csi_dropped{0U};
  std::uint64_t escape_dropped{0U};
  std::uint64_t sgr_degraded{0U};
  std::uint64_t control_dropped{0U};
  std::uint64_t invalid_utf8_replaced{0U};
  std::uint64_t lines_scrolled_out{0U};
  std::uint64_t bell_dropped{0U};
};

class SafeTerminalModel {
 public:
  explicit SafeTerminalModel(SafeTerminalConfig config = {});

  SafeTerminalModel(const SafeTerminalModel&) = delete;
  SafeTerminalModel& operator=(const SafeTerminalModel&) = delete;

  // Feeds raw remote output bytes; always makes progress.
  void feed(std::span<const std::byte> data);
  // Peer-driven resize; clamped to max_columns/max_rows.
  void resize(std::uint32_t columns, std::uint32_t rows);

  [[nodiscard]] std::uint32_t columns() const noexcept { return config_.columns; }
  [[nodiscard]] std::uint32_t rows() const noexcept { return config_.rows; }
  [[nodiscard]] const SafeTerminalStats& stats() const noexcept { return stats_; }

  // The last `max_lines` lines of the model (whole history tail).
  [[nodiscard]] std::vector<std::string> render_tail(std::size_t max_lines) const;
  // Number of lines currently retained.
  [[nodiscard]] std::size_t line_count() const noexcept { return lines_.size(); }

 private:
  enum class State : std::uint8_t {
    ground,
    escape,
    csi,
    osc,
    osc_escape,   // saw ESC inside OSC/DCS-style strings; ST needs '\'
    string_skip,  // DCS/SOS/PM/APC body until ST
    charset_payload,  // ESC ( / ) / * / + : exactly one payload byte
    utf8_collect,
  };

  void put_char(char32_t codepoint);
  // Handles one byte from the ground state (also reused to re-examine a byte
  // that terminated a malformed UTF-8 sequence).
  void handle_ground(unsigned char byte);
  void newline();
  void carriage_return();
  void linefeed();
  void backspace();
  void tab();
  void erase_in_display(int mode);
  void erase_in_line(int mode);
  void insert_chars(std::uint32_t count);
  void delete_chars(std::uint32_t count);
  void insert_lines(std::uint32_t count);
  void delete_lines(std::uint32_t count);
  void erase_chars(std::uint32_t count);
  void cursor_up(std::uint32_t count);
  void cursor_down(std::uint32_t count);
  void cursor_forward(std::uint32_t count);
  void cursor_back(std::uint32_t count);
  void move_cursor(std::uint32_t row, std::uint32_t column);
  void set_column(std::uint32_t column);
  void set_row(std::uint32_t row);
  void full_reset();
  void drop_sequence();

  [[nodiscard]] std::string& current_line();
  void clamp_cursor();

  SafeTerminalConfig config_;
  SafeTerminalStats stats_;
  State state_{State::ground};
  std::deque<std::string> lines_;
  std::size_t cursor_row_{0U};  // absolute index into the retained history
  std::size_t cursor_col_{0U};
  std::size_t saved_row_{0U};
  std::size_t saved_col_{0U};

  // In-flight sequence accumulation (bounded by max_sequence_bytes).
  std::vector<std::byte> sequence_;
  // In-flight UTF-8 codepoint.
  char32_t pending_codepoint_{0U};
  unsigned pending_continuations_{0U};
  unsigned seen_continuations_{0U};
};

}  // namespace heyaki
