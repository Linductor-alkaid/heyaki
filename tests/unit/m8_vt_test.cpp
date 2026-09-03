// M8-08/M8-09 safe VT renderer tests: OSC (title/clipboard/hyperlink) never
// applies, unknown/DEC-private sequences drop, SGR degrades to plain text,
// UTF-8 is validated, every buffer stays bounded, and hostile input never
// escapes into the host terminal because the model never writes one.

#include <heyaki/shell_terminal.hpp>

#include <gtest/gtest.h>

#include <string>

namespace heyaki {
namespace {

void feed_text(SafeTerminalModel& model, std::string_view text) {
  model.feed({reinterpret_cast<const std::byte*>(text.data()), text.size()});
}

std::string tail_text(const SafeTerminalModel& model, std::size_t lines = 8U) {
  std::string joined;
  for (const auto& line : model.render_tail(lines)) {
    joined += line;
    joined += '\n';
  }
  return joined;
}

TEST(M8SafeTerminal, RendersPlainTextWithLineDiscipline) {
  SafeTerminalModel model;
  feed_text(model, "hello\r\nworld\n");
  // The trailing newline leaves the cursor on a fresh empty line.
  EXPECT_EQ(tail_text(model), "hello\nworld\n\n");
  EXPECT_EQ(model.stats().osc_dropped, 0U);
}

TEST(M8SafeTerminal, OscTitleClipboardAndHyperlinksNeverApply) {
  SafeTerminalModel model;
  feed_text(model, std::string{"\x1b]0;"} + "evil title\aafter-title\n");
  feed_text(model, std::string{"\x1b]52;c;base64,cGFzdGU="} + "\aafter-clipboard\n");
  feed_text(model, std::string{"\x1b]8;;https://evil.example"} + "\alink" + "\x1b]8;;" + "\aend\n");
  feed_text(model, std::string{"\x1b]0;"} + "unterminated stays dropped\n");
  const auto text = tail_text(model);
  EXPECT_EQ(text.find("evil title"), std::string::npos);
  EXPECT_EQ(text.find("cGFzdGU="), std::string::npos);
  EXPECT_EQ(text.find("https://evil.example"), std::string::npos);
  EXPECT_NE(text.find("after-title"), std::string::npos);
  EXPECT_NE(text.find("after-clipboard"), std::string::npos);
  EXPECT_NE(text.find("end"), std::string::npos);
  EXPECT_GE(model.stats().osc_dropped, 3U);
}

TEST(M8SafeTerminal, UnterminatedOscIsBoundedAndResynchronizes) {
  SafeTerminalConfig config;
  config.max_sequence_bytes = 256U;
  SafeTerminalModel model{config};
  feed_text(model, "\x1b]0;");
  std::string flood(4096U, 'A');
  feed_text(model, flood);
  feed_text(model, "\x1b\\\nvisible-after\n");
  EXPECT_NE(tail_text(model).find("visible-after"), std::string::npos);
  EXPECT_NE(tail_text(model).find(std::string(64U, 'A')), std::string::npos);
  EXPECT_GE(model.stats().osc_dropped, 1U);
  // Bounded: the 4 KiB flood cannot retain more than the model cap.
  EXPECT_LE(model.line_count(), config.max_scrollback_lines);
}

TEST(M8SafeTerminal, UnknownAndPrivateSequencesDropNotExecute) {
  SafeTerminalModel model;
  feed_text(model, "\x1b[?1049h\x1b[?1000h");  // alt screen + mouse: DEC private
  feed_text(model, "\x1b[9999z");              // unknown final
  feed_text(model, "\x1b(B");                  // charset designation
  feed_text(model, "\x1bM");                   // reverse index (supported path)
  feed_text(model, "\x1bZ");                   // unknown ESC final
  feed_text(model, "\x1bP+q data\x1b\\\n");    // DCS string skipped
  feed_text(model, "done\n");
  const auto text = tail_text(model);
  EXPECT_NE(text.find("done"), std::string::npos);
  EXPECT_EQ(text.find("1049"), std::string::npos);
  EXPECT_GE(model.stats().csi_dropped, 1U);
  EXPECT_GE(model.stats().escape_dropped, 1U);
  EXPECT_GE(model.stats().osc_dropped, 1U);  // DCS strings count as strings
}

TEST(M8SafeTerminal, SgrDegradesToPlainText) {
  SafeTerminalModel model;
  feed_text(model, "\x1b[1;31mred\x1b[0m plain\n");
  EXPECT_EQ(tail_text(model), "red plain\n\n");
  EXPECT_EQ(model.stats().sgr_degraded, 2U);
  EXPECT_EQ(model.stats().csi_dropped, 0U);
}

TEST(M8SafeTerminal, Utf8IsValidated) {
  SafeTerminalModel model;
  feed_text(model, "héllo → ✓\n");  // NFD-free valid UTF-8
  EXPECT_EQ(tail_text(model), "héllo → ✓\n\n");
  EXPECT_EQ(model.stats().invalid_utf8_replaced, 0U);

  SafeTerminalModel broken;
  const auto invalid = std::string{"\xff\xfe bad"};
  feed_text(broken, invalid);
  EXPECT_GE(broken.stats().invalid_utf8_replaced, 1U);

  // Truncated multibyte sequence split across feeds still validates.
  SafeTerminalModel split;
  feed_text(split, "\xE2\x9C");
  feed_text(split, "\x93\n");
  EXPECT_EQ(tail_text(split), "✓\n\n");
  EXPECT_EQ(split.stats().invalid_utf8_replaced, 0U);
}

TEST(M8SafeTerminal, CursorAndEraseSemantics) {
  SafeTerminalModel model;
  feed_text(model, "one\ntwo\nthree");
  feed_text(model, "\x1b[2;1H");   // cursor to row 2, col 1
  feed_text(model, "\x1b[0K");     // erase to end of line
  const auto text = tail_text(model);
  EXPECT_EQ(text, "one\n\nthree\n");
}

TEST(M8SafeTerminal, EveryByteValueFeedsWithoutCrashing) {
  SafeTerminalModel model;
  std::string all;
  for (int value = 0; value < 256; ++value) {
    all.push_back(static_cast<char>(value));
  }
  for (int round = 0; round < 64; ++round) {
    feed_text(model, all);
  }
  // Progress and boundedness invariants (fuzz property, smoke-checked here).
  EXPECT_EQ(model.stats().bytes_fed, all.size() * 64U);
  EXPECT_LE(model.line_count(), model.stats().lines_scrolled_out + 4200U);
}

TEST(M8SafeTerminal, ScrollbackAndResizeClamp) {
  SafeTerminalConfig config;
  config.max_scrollback_lines = 32U;
  config.max_columns = 40U;
  SafeTerminalModel model{config};
  for (int index = 0; index < 1000; ++index) {
    feed_text(model, "line\n");
  }
  EXPECT_LE(model.line_count(), 32U);
  EXPECT_GE(model.stats().lines_scrolled_out, 900U);

  model.resize(100000U, 100000U);
  EXPECT_EQ(model.columns(), 40U);
  model.resize(1U, 1U);
  EXPECT_EQ(model.columns(), 1U);
}

TEST(M8SafeTerminal, TabBackspaceAndBell) {
  SafeTerminalModel model;
  feed_text(model, "a\tb");
  feed_text(model, "\x08\x08z");  // back over 'b' then overwrite
  feed_text(model, "\a\n");
  const auto text = tail_text(model);
  EXPECT_EQ(text.find('\t'), std::string::npos);
  EXPECT_NE(text.find("a"), std::string::npos);
  EXPECT_NE(text.find("z"), std::string::npos);
  EXPECT_EQ(model.stats().bell_dropped, 1U);
  EXPECT_EQ(model.stats().control_dropped, 0U);
}

}  // namespace
}  // namespace heyaki
