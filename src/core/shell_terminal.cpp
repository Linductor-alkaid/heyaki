// SafeTerminalModel implementation (M8-08/M8-09). See the header for the
// supported/rejected sequence table and the bounded-input guarantees.

#include <heyaki/shell_terminal.hpp>

#include <algorithm>
#include <array>
#include <utility>

namespace heyaki {
namespace {

constexpr std::uint32_t kTabWidth = 8U;

bool is_csi_param(unsigned char value) noexcept {
  return value >= 0x30U && value <= 0x3FU;
}

bool is_csi_intermediate(unsigned char value) noexcept {
  return value >= 0x20U && value <= 0x2FU;
}

bool is_csi_final(unsigned char value) noexcept {
  return value >= 0x40U && value <= 0x7EU;
}

// Parses "n[;m...]" CSI parameters with defaults; returns false for junk.
bool parse_params(const std::vector<std::byte>& sequence, std::array<std::uint32_t, 8>& out,
                  std::size_t& count, bool& private_marker) {
  count = 0U;
  private_marker = false;
  std::uint32_t current = 0U;
  bool any_digit = false;
  for (const auto raw : sequence) {
    const unsigned value = static_cast<unsigned char>(raw);
    // Skip the ESC / '[' prefix bytes; parameters start after them.
    if (value < 0x20U || value == '[') {
      continue;
    }
    if (value > 0x7EU) {
      continue;
    }
    if (value == '?') {
      private_marker = true;  // DEC private sequences render as unsupported
      continue;
    }
    if (value >= '0' && value <= '9') {
      current = std::min<std::uint32_t>(current * 10U + (value - '0'), 0xFFFFU);
      any_digit = true;
      continue;
    }
    if (value == ';' || value == ':') {
      if (count >= out.size()) {
        return false;
      }
      out[count++] = any_digit ? current : 0U;
      current = 0U;
      any_digit = false;
      continue;
    }
    if (is_csi_param(static_cast<unsigned char>(value))) {
      continue;  // '<','=','>' and friends: tolerated, ignored
    }
    break;  // intermediates and the final byte end the parameter section
  }
  if (count >= out.size()) {
    return false;
  }
  out[count++] = any_digit ? current : 0U;
  return true;
}

void append_utf8(std::string& line, char32_t codepoint) {
  if (codepoint <= 0x7FU) {
    line.push_back(static_cast<char>(codepoint));
    return;
  }
  if (codepoint <= 0x7FFU) {
    line.push_back(static_cast<char>(0xC0U | (codepoint >> 6U)));
    line.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
    return;
  }
  if (codepoint <= 0xFFFFU) {
    line.push_back(static_cast<char>(0xE0U | (codepoint >> 12U)));
    line.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3FU)));
    line.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
    return;
  }
  line.push_back(static_cast<char>(0xF0U | (codepoint >> 18U)));
  line.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3FU)));
  line.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3FU)));
  line.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
}

}  // namespace

SafeTerminalModel::SafeTerminalModel(SafeTerminalConfig config) : config_(config) {
  config_.columns = std::min<std::uint32_t>(std::max<std::uint32_t>(config_.columns, 1U),
                                            config_.max_columns);
  config_.rows =
      std::min<std::uint32_t>(std::max<std::uint32_t>(config_.rows, 1U), config_.max_rows);
  config_.max_scrollback_lines = std::max<std::size_t>(config_.max_scrollback_lines, 16U);
  config_.max_sequence_bytes = std::max<std::size_t>(config_.max_sequence_bytes, 16U);
  lines_.push_back(std::string{});
}

void SafeTerminalModel::clamp_cursor() {
  if (lines_.empty()) {
    lines_.push_back(std::string{});
  }
  cursor_row_ = std::min(cursor_row_, lines_.size() - 1U);
  cursor_col_ = std::min(cursor_col_, static_cast<std::size_t>(config_.columns));
}

std::string& SafeTerminalModel::current_line() {
  if (lines_.empty()) {
    lines_.push_back(std::string{});
    cursor_row_ = 0U;
  }
  cursor_row_ = std::min(cursor_row_, lines_.size() - 1U);
  return lines_[cursor_row_];
}

void SafeTerminalModel::put_char(char32_t codepoint) {
  auto& line = current_line();
  if (line.size() >= static_cast<std::size_t>(config_.columns) * 12U) {
    // Per-line safety ceiling (config.columns wide chars times max UTF-8
    // width); scrolling keeps the model bounded even against wrap storms.
    newline();
    line = current_line();
  }
  append_utf8(line, codepoint);
  cursor_col_ = line.size();
  if (cursor_col_ >= static_cast<std::size_t>(config_.columns)) {
    newline();
  }
}

void SafeTerminalModel::newline() {
  if (lines_.empty()) {
    lines_.push_back(std::string{});
  }
  if (lines_.size() >= config_.max_scrollback_lines) {
    lines_.pop_front();
    ++stats_.lines_scrolled_out;
    if (cursor_row_ > 0U) {
      --cursor_row_;
    }
    if (saved_row_ > 0U) {
      --saved_row_;
    }
  }
  lines_.push_back(std::string{});
  cursor_row_ = lines_.size() - 1U;
  cursor_col_ = 0U;
}

void SafeTerminalModel::carriage_return() {
  cursor_col_ = 0U;
}

void SafeTerminalModel::linefeed() {
  // Simple screen model: the cursor stays inside the retained history; a
  // newline at the newest line appends, otherwise it moves down one line.
  if (lines_.empty() || cursor_row_ + 1U >= lines_.size()) {
    newline();
    return;
  }
  ++cursor_row_;
  cursor_col_ = 0U;
}

void SafeTerminalModel::backspace() {
  if (cursor_col_ > 0U) {
    --cursor_col_;
    auto& line = current_line();
    if (line.size() > cursor_col_) {
      line.resize(cursor_col_);
    }
  }
}

void SafeTerminalModel::tab() {
  const std::uint32_t next =
      (static_cast<std::uint32_t>(cursor_col_) / kTabWidth + 1U) * kTabWidth;
  cursor_col_ = std::min<std::size_t>(next, config_.columns);
  auto& line = current_line();
  if (line.size() < cursor_col_) {
    line.resize(cursor_col_, ' ');
  }
}

void SafeTerminalModel::erase_in_display(int mode) {
  if (lines_.empty()) {
    return;
  }
  if (mode == 2) {
    lines_.clear();
    lines_.push_back(std::string{});
    cursor_row_ = 0U;
    cursor_col_ = 0U;
    return;
  }
  auto& line = current_line();
  if (mode == 0) {
    line.resize(std::min(cursor_col_, line.size()));
    for (std::size_t index = cursor_row_ + 1U; index < lines_.size();) {
      lines_.erase(lines_.begin() + static_cast<std::ptrdiff_t>(index));
    }
    return;
  }
  // mode 1: erase from start through cursor
  for (std::size_t index = 0U; index + 1U < cursor_row_ + 1U; ++index) {
    if (index < lines_.size()) {
      lines_[index].clear();
    }
  }
  line.assign(cursor_col_, ' ');
}

void SafeTerminalModel::erase_in_line(int mode) {
  auto& line = current_line();
  const std::size_t position = std::min(cursor_col_, line.size());
  if (mode == 0) {
    line.resize(position);
  } else if (mode == 1) {
    line = std::string(position, ' ');
  } else {
    line.clear();
  }
}

void SafeTerminalModel::insert_chars(std::uint32_t count) {
  auto& line = current_line();
  count = std::min<std::uint32_t>(count, config_.columns);
  const std::size_t position = std::min(cursor_col_, line.size());
  line.insert(position, count, ' ');
  if (line.size() > static_cast<std::size_t>(config_.columns) * 12U) {
    line.resize(static_cast<std::size_t>(config_.columns) * 12U);
  }
}

void SafeTerminalModel::delete_chars(std::uint32_t count) {
  auto& line = current_line();
  const std::size_t position = std::min(cursor_col_, line.size());
  count = std::min<std::uint32_t>(count, static_cast<std::uint32_t>(line.size() - position));
  line.erase(position, count);
}

void SafeTerminalModel::insert_lines(std::uint32_t count) {
  count = std::min<std::uint32_t>(count, config_.rows);
  const std::size_t at = cursor_row_ + 1U;
  for (std::uint32_t index = 0U; index < count; ++index) {
    if (lines_.size() >= config_.max_scrollback_lines) {
      break;
    }
    lines_.insert(lines_.begin() + static_cast<std::ptrdiff_t>(
                                      std::min(at, lines_.size())),
                  std::string{});
  }
  clamp_cursor();
}

void SafeTerminalModel::delete_lines(std::uint32_t count) {
  if (lines_.empty()) {
    return;
  }
  count = std::min<std::uint32_t>(count, static_cast<std::uint32_t>(lines_.size() - cursor_row_));
  const std::size_t at = std::min(cursor_row_, lines_.size() - 1U);
  lines_.erase(lines_.begin() + static_cast<std::ptrdiff_t>(at),
               lines_.begin() + static_cast<std::ptrdiff_t>(at + count));
  if (lines_.empty()) {
    lines_.push_back(std::string{});
    cursor_row_ = 0U;
  }
  clamp_cursor();
}

void SafeTerminalModel::erase_chars(std::uint32_t count) {
  auto& line = current_line();
  const std::size_t position = std::min(cursor_col_, line.size());
  count = std::min<std::uint32_t>(count, static_cast<std::uint32_t>(line.size() - position));
  line.replace(position, count, count, ' ');
}

void SafeTerminalModel::cursor_up(std::uint32_t count) {
  cursor_row_ = cursor_row_ >= count ? cursor_row_ - count : 0U;
  clamp_cursor();
}

void SafeTerminalModel::cursor_down(std::uint32_t count) {
  if (lines_.empty()) {
    lines_.push_back(std::string{});
  }
  cursor_row_ = std::min(cursor_row_ + count, lines_.size() - 1U);
}

void SafeTerminalModel::cursor_forward(std::uint32_t count) {
  cursor_col_ = std::min<std::size_t>(cursor_col_ + count, config_.columns);
  auto& line = current_line();
  if (line.size() < cursor_col_) {
    line.resize(cursor_col_, ' ');
  }
}

void SafeTerminalModel::cursor_back(std::uint32_t count) {
  cursor_col_ = cursor_col_ >= count ? cursor_col_ - count : 0U;
}

void SafeTerminalModel::move_cursor(std::uint32_t row, std::uint32_t column) {
  set_row(row);
  set_column(column);
}

void SafeTerminalModel::set_column(std::uint32_t column) {
  cursor_col_ = std::min<std::size_t>(std::max<std::uint32_t>(column, 1U) - 1U,
                                      config_.columns);
}

void SafeTerminalModel::set_row(std::uint32_t row) {
  if (lines_.empty()) {
    lines_.push_back(std::string{});
  }
  // Screen row 1 maps to the oldest visible line of the retained history.
  const std::size_t screen_origin =
      lines_.size() > config_.rows ? lines_.size() - config_.rows : 0U;
  const std::size_t target = screen_origin + (std::max<std::uint32_t>(row, 1U) - 1U);
  cursor_row_ = std::min(target, lines_.size() - 1U);
  clamp_cursor();
}

void SafeTerminalModel::full_reset() {
  lines_.clear();
  lines_.push_back(std::string{});
  cursor_row_ = 0U;
  cursor_col_ = 0U;
  saved_row_ = 0U;
  saved_col_ = 0U;
}

void SafeTerminalModel::drop_sequence() {
  sequence_.clear();
  state_ = State::ground;
}

void SafeTerminalModel::resize(std::uint32_t columns, std::uint32_t rows) {
  config_.columns = std::min(std::max<std::uint32_t>(columns, 1U), config_.max_columns);
  config_.rows = std::min(std::max<std::uint32_t>(rows, 1U), config_.max_rows);
  clamp_cursor();
}

std::vector<std::string> SafeTerminalModel::render_tail(std::size_t max_lines) const {
  std::vector<std::string> output;
  if (lines_.empty() || max_lines == 0U) {
    return output;
  }
  const std::size_t count = std::min(max_lines, lines_.size());
  output.reserve(count);
  const std::size_t start = lines_.size() - count;
  for (std::size_t index = start; index < lines_.size(); ++index) {
    output.push_back(lines_[index]);
  }
  return output;
}

void SafeTerminalModel::handle_ground(unsigned char byte) {
  if (byte == 0x1BU) {
    sequence_.clear();
    sequence_.push_back(static_cast<std::byte>(byte));
    state_ = State::escape;
    return;
  }
  if (byte == 0x0AU || byte == 0x0BU || byte == 0x0CU) {
    linefeed();
    return;
  }
  if (byte == 0x0DU) {
    carriage_return();
    return;
  }
  if (byte == 0x08U) {
    backspace();
    return;
  }
  if (byte == 0x09U) {
    tab();
    return;
  }
  if (byte == 0x07U) {
    ++stats_.bell_dropped;
    return;
  }
  if (byte < 0x20U || byte == 0x7FU) {
    ++stats_.control_dropped;
    return;
  }
  if (byte < 0x80U) {
    put_char(byte);
    return;
  }
  if (byte >= 0xC2U && byte <= 0xDFU) {
    pending_codepoint_ = byte & 0x1FU;
    pending_continuations_ = 1U;
    seen_continuations_ = 0U;
    sequence_.clear();
    sequence_.push_back(static_cast<std::byte>(byte));
    state_ = State::utf8_collect;
    return;
  }
  if (byte >= 0xE0U && byte <= 0xEFU) {
    pending_codepoint_ = byte & 0x0FU;
    pending_continuations_ = 2U;
    seen_continuations_ = 0U;
    sequence_.clear();
    sequence_.push_back(static_cast<std::byte>(byte));
    state_ = State::utf8_collect;
    return;
  }
  if (byte >= 0xF0U && byte <= 0xF4U) {
    pending_codepoint_ = byte & 0x07U;
    pending_continuations_ = 3U;
    seen_continuations_ = 0U;
    sequence_.clear();
    sequence_.push_back(static_cast<std::byte>(byte));
    state_ = State::utf8_collect;
    return;
  }
  // 0x80-0xC1 and 0xF5-0xFF never start valid UTF-8.
  ++stats_.invalid_utf8_replaced;
  put_char(0xFFFDU);
}

void SafeTerminalModel::feed(std::span<const std::byte> data) {
  stats_.bytes_fed += data.size();
  for (const auto raw : data) {
    const auto byte = static_cast<unsigned char>(raw);

    // A sequence or string that outgrew the cap is dropped wholesale and the
    // parser resynchronizes at ground (never an unbounded buffer).
    if (state_ != State::ground && state_ != State::utf8_collect &&
        sequence_.size() >= config_.max_sequence_bytes) {
      if (state_ == State::osc || state_ == State::osc_escape ||
          state_ == State::string_skip) {
        ++stats_.osc_dropped;
      } else {
        ++stats_.csi_dropped;
      }
      drop_sequence();
    }

    switch (state_) {
      case State::ground:
        handle_ground(byte);
        continue;

      case State::utf8_collect:
        if ((byte & 0xC0U) == 0x80U) {
          pending_codepoint_ = (pending_codepoint_ << 6U) | (byte & 0x3FU);
          ++seen_continuations_;
          if (seen_continuations_ < pending_continuations_) {
            continue;
          }
          state_ = State::ground;
          sequence_.clear();
          if (pending_codepoint_ == 0U || pending_codepoint_ > 0x10FFFFU ||
              (pending_codepoint_ >= 0xD800U && pending_codepoint_ <= 0xDFFFU)) {
            ++stats_.invalid_utf8_replaced;
            put_char(0xFFFDU);
            continue;
          }
          put_char(pending_codepoint_);
          continue;
        }
        // Malformed continuation: replace, then re-examine this byte in the
        // ground state (it may start a fresh valid sequence).
        ++stats_.invalid_utf8_replaced;
        put_char(0xFFFDU);
        state_ = State::ground;
        sequence_.clear();
        handle_ground(byte);
        continue;

      case State::escape:
        sequence_.push_back(static_cast<std::byte>(byte));
        switch (byte) {
          case '[':
            state_ = State::csi;
            continue;
          case ']':
            state_ = State::osc;
            continue;
          case 'P':
          case 'X':
          case '^':
          case '_':
            state_ = State::string_skip;
            continue;
          case '7':
            saved_row_ = cursor_row_;
            saved_col_ = cursor_col_;
            drop_sequence();
            continue;
          case '8':
            cursor_row_ = saved_row_;
            cursor_col_ = saved_col_;
            clamp_cursor();
            drop_sequence();
            continue;
          case 'D':
            linefeed();
            drop_sequence();
            continue;
          case 'E':
            carriage_return();
            linefeed();
            drop_sequence();
            continue;
          case 'M': {
            if (cursor_row_ > 0U) {
              --cursor_row_;
            }
            drop_sequence();
            continue;
          }
          case 'c':
            full_reset();
            drop_sequence();
            continue;
          case '(':
          case ')':
          case '*':
          case '+':
          case '#':
            // Charset/attribute designation: exactly one payload byte.
            drop_sequence();
            state_ = State::charset_payload;
            continue;
          default:
            ++stats_.escape_dropped;
            drop_sequence();
            continue;
        }

      case State::charset_payload:
        ++stats_.escape_dropped;
        state_ = State::ground;
        continue;

      case State::csi:
        sequence_.push_back(static_cast<std::byte>(byte));
        if (is_csi_param(byte) || is_csi_intermediate(byte)) {
          continue;
        }
        if (!is_csi_final(byte)) {
          ++stats_.csi_dropped;
          drop_sequence();
          continue;
        }
        // Final byte reached: decide.
        {
          std::array<std::uint32_t, 8> params{};
          std::size_t count = 0U;
          bool private_marker = false;
          if (!parse_params(sequence_, params, count, private_marker)) {
            ++stats_.csi_dropped;
            drop_sequence();
            continue;
          }
          const auto first = [&](std::size_t index, std::uint32_t fallback) {
            return index < count && params[index] != 0U ? params[index] : fallback;
          };
          if (private_marker) {
            // DEC private modes (mouse tracking, bracketed paste, alt screen):
            // never emulated.
            ++stats_.csi_dropped;
            drop_sequence();
            continue;
          }
          switch (byte) {
            case 'A':
              cursor_up(first(0U, 1U));
              break;
            case 'B':
              cursor_down(first(0U, 1U));
              break;
            case 'C':
              cursor_forward(first(0U, 1U));
              break;
            case 'D':
              cursor_back(first(0U, 1U));
              break;
            case 'E':
              cursor_down(first(0U, 1U));
              carriage_return();
              break;
            case 'F':
              cursor_up(first(0U, 1U));
              carriage_return();
              break;
            case 'G':
              set_column(first(0U, 1U));
              break;
            case 'H':
            case 'f':
              move_cursor(first(0U, 1U), first(1U, 1U));
              break;
            case 'd':
              set_row(first(0U, 1U));
              break;
            case 'J':
              erase_in_display(static_cast<int>(first(0U, 0U)));
              break;
            case 'K':
              erase_in_line(static_cast<int>(first(0U, 0U)));
              break;
            case '@':
              insert_chars(first(0U, 1U));
              break;
            case 'P':
              delete_chars(first(0U, 1U));
              break;
            case 'X':
              erase_chars(first(0U, 1U));
              break;
            case 'L':
              insert_lines(first(0U, 1U));
              break;
            case 'M':
              delete_lines(first(0U, 1U));
              break;
            case 'm':
              // SGR accepted, degraded to plain text (M8-09).
              ++stats_.sgr_degraded;
              break;
            case 's':
              saved_row_ = cursor_row_;
              saved_col_ = cursor_col_;
              break;
            case 'u':
              cursor_row_ = saved_row_;
              cursor_col_ = saved_col_;
              clamp_cursor();
              break;
            default:
              ++stats_.csi_dropped;
              break;
          }
          drop_sequence();
          continue;
        }

      case State::osc:
        sequence_.push_back(static_cast<std::byte>(byte));
        if (byte == 0x07U) {
          // OSC never reaches title/clipboard/hyperlink handling (M8-09).
          ++stats_.osc_dropped;
          drop_sequence();
          continue;
        }
        if (byte == 0x1BU) {
          state_ = State::osc_escape;
          continue;
        }
        if (byte < 0x20U) {
          // Control characters terminate an unterminated OSC safely.
          ++stats_.osc_dropped;
          drop_sequence();
          continue;
        }
        continue;

      case State::osc_escape:
        if (byte == '\\') {
          ++stats_.osc_dropped;
          drop_sequence();
          continue;
        }
        // Not ST: keep dropping the string; ESC restarts escape handling.
        state_ = State::osc;
        continue;

      case State::string_skip:
        if (byte == 0x1BU) {
          sequence_.clear();
          sequence_.push_back(static_cast<std::byte>(byte));
          state_ = State::osc_escape;
          continue;
        }
        continue;
    }
  }
}

}  // namespace heyaki
