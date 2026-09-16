// M9-15 security regression: authorization-matching and file-name grammar
// tables. These pin the two pure-function primitives every in-session
// authorization decision and file admission gate is built on; the attack-shaped
// end-to-end regressions for this round live next to their fixtures in
// m3a_lan_test, m5_pairing_service_test, m4_signaling_test,
// m4_relay_signaling_test, and m7_file_test (mapping in
// docs/security/m9-security-regression.md).

#include <heyaki/file.hpp>
#include <heyaki/trust_grant.hpp>

#include <gtest/gtest.h>

#include <string>
#include <string_view>

namespace heyaki {
namespace {

TEST(M9SecurityRegression, TrustScopeCoversPinsExactAndPrefixWildcardSemantics) {
  // Exact grants match only themselves.
  EXPECT_TRUE(trust_scope_covers("file.push", "file.push"));
  EXPECT_FALSE(trust_scope_covers("file.push", "file.pull"));
  EXPECT_FALSE(trust_scope_covers("file.push", "file.push:inbox"));

  // A prefix wildcard covers every scope that continues with a colon and has
  // a non-empty remainder; it never matches the bare prefix.
  EXPECT_TRUE(trust_scope_covers("shell.open:*", "shell.open:x"));
  EXPECT_TRUE(trust_scope_covers("shell.open:*", "shell.open:profile-a"));
  EXPECT_TRUE(trust_scope_covers("shell.open:*", "shell.open:x:deeper"));
  EXPECT_TRUE(trust_scope_covers("file.push:*", "file.push:inbox"));
  EXPECT_FALSE(trust_scope_covers("shell.open:*", "shell.open"));
  EXPECT_FALSE(trust_scope_covers("shell.open:*", "shell.open:"));
  EXPECT_FALSE(trust_scope_covers("shell.open:*", "shell.openx:y"));
  EXPECT_FALSE(trust_scope_covers("shell.open:*", "shell"));

  // A wildcard grant still matches itself exactly.
  EXPECT_TRUE(trust_scope_covers("shell.open:*", "shell.open:*"));

  // Degenerate shapes must not degrade into global wildcards.
  EXPECT_FALSE(trust_scope_covers(":*", "message.send"));
  EXPECT_FALSE(trust_scope_covers("*", "message.send"));
  EXPECT_FALSE(trust_scope_covers(std::string_view{}, "message.send"));
  EXPECT_FALSE(trust_scope_covers("message.send", std::string_view{}));
}

TEST(M9SecurityRegression, SafeLogicalFileNameParsesAttackShapedNames) {
  // Ordinary names, nested logical paths, and in-token punctuation pass.
  EXPECT_TRUE(safe_logical_file_name("report.bin"));
  EXPECT_TRUE(safe_logical_file_name("inbox/2026/report.bin"));
  EXPECT_TRUE(safe_logical_file_name("v1.2 (draft).bin"));
  EXPECT_TRUE(safe_logical_file_name("a-b_c.d"));
  EXPECT_TRUE(safe_logical_file_name(std::string(max_logical_name_bytes, 'a')));

  // Escapes and separators.
  EXPECT_FALSE(safe_logical_file_name(""));
  EXPECT_FALSE(safe_logical_file_name("/etc/passwd"));
  EXPECT_FALSE(safe_logical_file_name(R"(\server\share)"));
  EXPECT_FALSE(safe_logical_file_name(R"(inbox\report.bin)"));
  EXPECT_FALSE(safe_logical_file_name("inbox/"));
  EXPECT_FALSE(safe_logical_file_name("inbox//report.bin"));
  EXPECT_FALSE(safe_logical_file_name("."));
  EXPECT_FALSE(safe_logical_file_name(".."));
  EXPECT_FALSE(safe_logical_file_name("inbox/.."));
  EXPECT_FALSE(safe_logical_file_name("inbox/../report.bin"));

  // Byte-level injection: NUL, control bytes, and oversized names.
  EXPECT_FALSE(safe_logical_file_name(std::string("a\0b", 3U)));
  EXPECT_FALSE(safe_logical_file_name("a\x01b"));
  EXPECT_FALSE(safe_logical_file_name("a\x7f" "b"));
  EXPECT_FALSE(safe_logical_file_name(std::string(max_logical_name_bytes + 1U, 'a')));

  // Windows-reserved shapes in any casing and with extensions.
  EXPECT_FALSE(safe_logical_file_name("CON"));
  EXPECT_FALSE(safe_logical_file_name("con.bin"));
  EXPECT_FALSE(safe_logical_file_name("COM1"));
  EXPECT_FALSE(safe_logical_file_name("com9.txt"));
  EXPECT_FALSE(safe_logical_file_name("LPT1.aux"));
  EXPECT_FALSE(safe_logical_file_name("inbox/PRN"));

  // Trailing dots and spaces per segment (Windows prefix/suffix rules).
  EXPECT_FALSE(safe_logical_file_name("report.bin."));
  EXPECT_FALSE(safe_logical_file_name("report.bin "));
  EXPECT_FALSE(safe_logical_file_name("inbox/report.bin."));

  // Path depth stays bounded: exactly the cap passes, one more fails.
  std::string at_cap;
  for (std::size_t index = 0U; index < max_file_name_segments; ++index) {
    at_cap += (index == 0U ? "" : "/") + std::string{"d"};
  }
  EXPECT_TRUE(safe_logical_file_name(at_cap));
  EXPECT_FALSE(safe_logical_file_name(at_cap + "/d"));
}

}  // namespace
}  // namespace heyaki
