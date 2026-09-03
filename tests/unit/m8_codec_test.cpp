// M8 codec tests: shell wire bodies (heyaki.protocol.shell.v1) and the raw
// ShellData header. Mirrors the M7 codec suite: round-trips, malformed
// inputs, bounds, and the frozen numeric expectations (28-byte header,
// zigzag exit codes, big-endian offsets).

#include "m8_support.hpp"

#include <gtest/gtest.h>

#include <heyaki/shell.hpp>

namespace heyaki::test {
namespace {

ShellId shell_id_of(std::uint8_t seed) {
  ShellId::Storage bytes{};
  bytes[0] = static_cast<std::byte>(seed);
  return ShellId{bytes};
}

std::vector<std::byte> text_bytes(std::string_view text) {
  return {reinterpret_cast<const std::byte*>(text.data()),
          reinterpret_cast<const std::byte*>(text.data()) + text.size()};
}

TEST(M8ShellCodec, OpenRoundTrips) {
  ShellOpenBody open;
  open.shell_id = shell_id_of(1U);
  open.profile = "maintenance";
  open.terminal_type = "xterm-256color";
  open.columns = 120U;
  open.rows = 40U;
  open.locale = "en_US.UTF-8";
  const auto encoded = encode_shell_open(open);
  ASSERT_TRUE(encoded);
  const auto parsed = parse_shell_open(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->shell_id, open.shell_id);
  EXPECT_EQ(parsed.value_if()->profile, "maintenance");
  EXPECT_EQ(parsed.value_if()->terminal_type, "xterm-256color");
  EXPECT_EQ(parsed.value_if()->columns, 120U);
  EXPECT_EQ(parsed.value_if()->rows, 40U);
  EXPECT_EQ(parsed.value_if()->locale, "en_US.UTF-8");
}

TEST(M8ShellCodec, OpenRejectsUnsafeTextAndSizes) {
  ShellOpenBody open;
  open.shell_id = shell_id_of(2U);
  open.profile = "maintenance";
  open.terminal_type = "xterm\033]";
  EXPECT_FALSE(encode_shell_open(open));
  open.terminal_type = "xterm";
  open.columns = 0U;
  EXPECT_FALSE(encode_shell_open(open));
  open.columns = 80U;
  open.rows = 5000U;
  EXPECT_FALSE(encode_shell_open(open));
  open.rows = 24U;
  open.profile = "../escape";
  EXPECT_FALSE(encode_shell_open(open));
}

TEST(M8ShellCodec, OpenRejectsTruncatedAndOversized) {
  const auto junk = text_bytes("\x0a\x01");
  EXPECT_FALSE(parse_shell_open(junk));
  ShellOpenBody open;
  open.shell_id = shell_id_of(3U);
  open.profile = "maintenance";
  open.locale = std::string(max_shell_locale_bytes + 1U, 'a');
  EXPECT_FALSE(encode_shell_open(open));
}

TEST(M8ShellCodec, ResizeSignalEofCloseRoundTrip) {
  ShellResizeBody resize{shell_id_of(4U), 100U, 30U};
  const auto resize_encoded = encode_shell_resize(resize);
  ASSERT_TRUE(resize_encoded);
  const auto resize_parsed = parse_shell_resize(*resize_encoded.value_if());
  ASSERT_TRUE(resize_parsed);
  EXPECT_EQ(resize_parsed.value_if()->columns, 100U);
  EXPECT_EQ(resize_parsed.value_if()->rows, 30U);

  ShellSignalBody signal{shell_id_of(5U), ShellPortableSignal::terminate};
  const auto signal_encoded = encode_shell_signal(signal);
  ASSERT_TRUE(signal_encoded);
  const auto signal_parsed = parse_shell_signal(*signal_encoded.value_if());
  ASSERT_TRUE(signal_parsed);
  EXPECT_EQ(signal_parsed.value_if()->signal, ShellPortableSignal::terminate);

  // Unknown portable signal values are refused on both ends.
  const auto raw_signal = std::vector<std::byte>{};
  ShellSignalBody bad{shell_id_of(5U), static_cast<ShellPortableSignal>(77U)};
  EXPECT_FALSE(encode_shell_signal(bad));

  ShellEofBody eof{shell_id_of(6U)};
  const auto eof_encoded = encode_shell_eof(eof);
  ASSERT_TRUE(eof_encoded);
  EXPECT_TRUE(parse_shell_eof(*eof_encoded.value_if()));

  ShellCloseBody close{shell_id_of(7U), StableStatus::cancelled};
  const auto close_encoded = encode_shell_close(close);
  ASSERT_TRUE(close_encoded);
  const auto close_parsed = parse_shell_close(*close_encoded.value_if());
  ASSERT_TRUE(close_parsed);
  EXPECT_EQ(close_parsed.value_if()->status, StableStatus::cancelled);
  (void)raw_signal;
}

TEST(M8ShellCodec, ExitZigZagRoundTrips) {
  for (const std::int32_t code : {0, 1, -1, 127, -128, 255, -255}) {
    ShellExitBody exit;
    exit.shell_id = shell_id_of(8U);
    exit.exit_code = code;
    exit.status = StableStatus::ok;
    const auto encoded = encode_shell_exit(exit);
    ASSERT_TRUE(encoded);
    const auto parsed = parse_shell_exit(*encoded.value_if());
    ASSERT_TRUE(parsed);
    ASSERT_TRUE(parsed.value_if()->exit_code.has_value());
    EXPECT_EQ(*parsed.value_if()->exit_code, code);
  }
  // Missing exit_code stays absent (child killed without a status).
  ShellExitBody exit;
  exit.shell_id = shell_id_of(9U);
  const auto encoded = encode_shell_exit(exit);
  ASSERT_TRUE(encoded);
  const auto parsed = parse_shell_exit(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_FALSE(parsed.value_if()->exit_code.has_value());
}

TEST(M8ShellCodec, ErrorBodyBoundsSafeDetail) {
  ShellErrorBody error;
  error.shell_id = shell_id_of(10U);
  error.status = StableStatus::resource_exhausted;
  error.safe_detail = "output_pending_flood";
  const auto encoded = encode_shell_error(error);
  ASSERT_TRUE(encoded);
  const auto parsed = parse_shell_error(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->safe_detail, "output_pending_flood");

  error.safe_detail = std::string(300U, 'x');
  error.safe_detail[5] = '\n';
  EXPECT_FALSE(encode_shell_error(error));
}

TEST(M8ShellCodec, ShellDataHeaderLayout) {
  // 28-byte raw header: shell_id(16) | offset(8) | data_length(4), big-endian
  // (wire protocol 2.1).
  const auto data = text_bytes("shell bytes");
  ShellDataHeader header;
  header.shell_id = shell_id_of(11U);
  header.offset = 0x0102030405060708ULL;
  header.data_length = static_cast<std::uint32_t>(data.size());
  const auto encoded = encode_shell_data(header, data);
  ASSERT_TRUE(encoded);
  ASSERT_EQ(encoded.value_if()->size(), shell_data_header_bytes + data.size());
  const auto parsed = parse_shell_data(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->header.shell_id, header.shell_id);
  EXPECT_EQ(parsed.value_if()->header.offset, 0x0102030405060708ULL);
  EXPECT_EQ(parsed.value_if()->header.data_length, data.size());
  std::string data_text;
  for (const auto value : parsed.value_if()->data) {
    data_text.push_back(static_cast<char>(static_cast<unsigned char>(value)));
  }
  EXPECT_EQ(data_text, "shell bytes");
}

TEST(M8ShellCodec, ShellDataRejectsMismatches) {
  ShellDataHeader header;
  header.shell_id = shell_id_of(12U);
  header.data_length = 5U;
  const auto data = text_bytes("12345678");
  EXPECT_FALSE(encode_shell_data(header, data));  // length mismatch
  header.data_length = 8U;
  Limits tiny;
  tiny.max_shell_data_bytes = 4U;
  EXPECT_FALSE(encode_shell_data(header, data, tiny));  // over the slice cap
  const auto encoded = encode_shell_data(header, data);
  ASSERT_TRUE(encoded);
  // Truncated and length-swapped payloads fail before data access.
  EXPECT_FALSE(parse_shell_data(
      std::span<const std::byte>{encoded.value_if()->data(),
                                 encoded.value_if()->size() - 1U}));
  auto corrupted = *encoded.value_if();
  corrupted[27] = static_cast<std::byte>(0xFF);  // declared != actual
  EXPECT_FALSE(parse_shell_data(corrupted));
  EXPECT_FALSE(parse_shell_data(
      std::span<const std::byte>{encoded.value_if()->data(),
                                 shell_data_header_bytes - 1U}));
}

TEST(M8ShellProfile, ValidationEnforcesSafeDefaults) {
  EXPECT_TRUE(validate_shell_profile(shell_test_profile()));
  EXPECT_FALSE(validate_shell_profile(shell_test_profile("Bad_Name")));
  auto relative = shell_test_profile();
  relative.argv = {"sh", "-c", "x"};
  EXPECT_FALSE(validate_shell_profile(relative));
  auto traversal = shell_test_profile();
  traversal.argv = {"/bin/../bin/sh"};
  EXPECT_FALSE(validate_shell_profile(traversal));
  auto bad_timeouts = shell_test_profile();
  bad_timeouts.idle_timeout = std::chrono::milliseconds{0};
  EXPECT_FALSE(validate_shell_profile(bad_timeouts));
  auto inverted = shell_test_profile();
  inverted.idle_timeout = std::chrono::milliseconds{3600000};
  inverted.absolute_timeout = std::chrono::milliseconds{600000};
  EXPECT_FALSE(validate_shell_profile(inverted));
  auto bad_env = shell_test_profile();
  bad_env.environment = {{"BAD NAME", std::nullopt}};
  EXPECT_FALSE(validate_shell_profile(bad_env));
  auto no_concurrency = shell_test_profile();
  no_concurrency.max_concurrent_sessions = 0U;
  EXPECT_FALSE(validate_shell_profile(no_concurrency));
}

TEST(M8ShellProfile, ScopeStringAndSignalPolicy) {
  EXPECT_EQ(shell_open_scope("maintenance"), "shell.open:maintenance");
  const auto profile = shell_test_profile();
  EXPECT_TRUE(shell_signal_allowed(profile, ShellPortableSignal::interrupt));
  EXPECT_TRUE(shell_signal_allowed(profile, ShellPortableSignal::terminate));
  EXPECT_FALSE(shell_signal_allowed(profile, ShellPortableSignal::kill));
  EXPECT_FALSE(shell_signal_allowed(profile, ShellPortableSignal::quit));
}

}  // namespace
}  // namespace heyaki::test
