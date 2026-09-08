// M9-04 SLO rule validation: the dashboards and alerting shipped under
// deploy/observability/ may only reference metrics that the shipped
// exporters actually emit. This test renders both exporter surfaces from
// default-constructed aggregates (every family renders unconditionally),
// parses the Prometheus rule files and the Grafana dashboard, and fails on:
//
//   - a rule or panel expression naming a metric no exporter emits;
//   - a rule expression naming a heyaki:slo:* recording that is never
//     recorded;
//   - an alert missing for/severity/summary/runbook_url structure;
//   - a runbook_url anchor without a matching heading in the runbook;
//   - silent parser drift (the expected rule counts are pinned).

#include "relay_metrics.hpp"

#include <heyaki/metrics.hpp>
#include <heyaki/node.hpp>

#include <gtest/gtest.h>

#include <cctype>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::string_view observability_dir = HEYAKI_M9_OBSERVABILITY_DIR;
constexpr std::string_view runbook_file = HEYAKI_M9_RUNBOOK_FILE;

std::string read_file(const std::filesystem::path& path) {
  std::ifstream stream{path};
  if (!stream) {
    return {};
  }
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

// Metric family names: the first token of every non-comment sample line,
// before any '{' label block.
std::set<std::string> exposition_families(std::string_view text) {
  std::set<std::string> families;
  std::istringstream lines{std::string{text}};
  std::string line;
  while (std::getline(lines, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (line.empty() || line.front() == '#') {
      continue;
    }
    const auto end = line.find_first_of(" {");
    if (end == std::string::npos) {
      continue;
    }
    families.insert(line.substr(0, end));
  }
  return families;
}

// Tokens starting with "heyaki" and continuing over metric-name characters
// (including the ':' used by heyaki:slo:* recording names).
std::vector<std::string> heyaki_tokens(std::string_view expression) {
  std::vector<std::string> tokens;
  for (std::size_t index = 0; index + 6U <= expression.size(); ++index) {
    if (expression.compare(index, 6U, "heyaki") != 0) {
      continue;
    }
    const bool left_bounded =
        index == 0U || [&] {
          const char previous = expression[index - 1U];
          return !(std::isalnum(static_cast<unsigned char>(previous)) !=
                   0) &&
                 previous != '_' && previous != ':' && previous != '.' &&
                 previous != '"';
        }();
    if (!left_bounded) {
      continue;
    }
    std::size_t end = index + 6U;
    while (end < expression.size()) {
      const char character = expression[end];
      if (std::isalnum(static_cast<unsigned char>(character)) == 0 &&
          character != '_' && character != ':') {
        break;
      }
      ++end;
    }
    tokens.emplace_back(expression.substr(index, end - index));
    index = end - 1U;
  }
  return tokens;
}

std::string_view trim(std::string_view text) {
  while (!text.empty() &&
         std::isspace(static_cast<unsigned char>(text.front())) != 0) {
    text.remove_prefix(1U);
  }
  while (!text.empty() &&
         std::isspace(static_cast<unsigned char>(text.back())) != 0) {
    text.remove_suffix(1U);
  }
  return text;
}

std::string_view strip_quotes(std::string_view text) {
  text = trim(text);
  if (text.size() >= 2U && text.front() == '"' && text.back() == '"') {
    text = text.substr(1U, text.size() - 2U);
  }
  return text;
}

struct ParsedRule {
  bool is_alert{false};
  std::string name;
  std::string expr;
  std::string duration;      // "for:" — alerts only
  std::string severity;      // labels.severity — alerts only
  std::string summary;       // annotations.summary — alerts only
  std::string runbook_url;   // annotations.runbook_url — alerts only
};

std::size_t indentation_of(std::string_view line) {
  std::size_t indent = 0U;
  while (indent < line.size() && line[indent] == ' ') {
    ++indent;
  }
  return indent;
}

// Parses the controlled rule-file format used by the shipped YAML: rules
// introduced by "- record:"/"- alert:", single-line or folded (> / >-)
// expressions, and the documented alert keys. This is deliberately not a
// general YAML parser; the format is ours and CI-verified.
std::vector<ParsedRule> parse_rule_file(std::string_view text) {
  std::vector<ParsedRule> rules;
  std::istringstream lines{std::string{text}};
  std::string line;
  std::optional<ParsedRule> current;
  auto flush = [&] {
    if (current && !current->name.empty()) {
      rules.push_back(*current);
    }
    current.reset();
  };
  while (std::getline(lines, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    const std::string_view view{line};
    const std::string_view trimmed = trim(view);
    if (trimmed.empty() || trimmed.front() == '#') {
      continue;
    }
    if (trimmed.rfind("- record:", 0U) == 0U) {
      flush();
      current = ParsedRule{};
      current->name = std::string{strip_quotes(trimmed.substr(9U))};
      continue;
    }
    if (trimmed.rfind("- alert:", 0U) == 0U) {
      flush();
      current = ParsedRule{};
      current->is_alert = true;
      current->name = std::string{strip_quotes(trimmed.substr(8U))};
      continue;
    }
    if (!current) {
      continue;
    }
    if (trimmed.rfind("expr:", 0U) == 0U) {
      const std::string_view value = trim(trimmed.substr(5U));
      if (value == ">" || value == ">-") {
        const std::size_t base_indent = indentation_of(view);
        std::string folded;
        // The fold ends at the first non-empty line at or below the expr
        // indent; that terminator is a rule key and must still be
        // processed, so remember it instead of consuming it here.
        std::string terminator;
        bool terminated = false;
        while (std::getline(lines, line)) {
          if (!line.empty() && line.back() == '\r') {
            line.pop_back();
          }
          const std::string_view body{line};
          if (trim(body).empty()) {
            continue;
          }
          if (indentation_of(body) <= base_indent) {
            terminator = line;
            terminated = true;
            break;
          }
          if (!folded.empty()) {
            folded += ' ';
          }
          folded += std::string{trim(body)};
        }
        current->expr = std::move(folded);
        if (!terminated) {
          continue;
        }
        const std::string_view terminator_view{terminator};
        const std::string_view terminator_trimmed = trim(terminator_view);
        auto assign_fold_terminator = [&](std::string_view key,
                                          std::string& target) {
          if (terminator_trimmed.rfind(key, 0U) == 0U) {
            target =
                std::string{strip_quotes(terminator_trimmed.substr(key.size()))};
          }
        };
        assign_fold_terminator("for:", current->duration);
        assign_fold_terminator("severity:", current->severity);
        assign_fold_terminator("summary:", current->summary);
        assign_fold_terminator("runbook_url:", current->runbook_url);
      } else {
        current->expr = std::string{strip_quotes(value)};
      }
      continue;
    }
    auto assign_key = [&](std::string_view key, std::string& target) {
      if (trimmed.rfind(key, 0U) == 0U) {
        target = std::string{strip_quotes(trimmed.substr(key.size()))};
      }
    };
    assign_key("for:", current->duration);
    assign_key("severity:", current->severity);
    assign_key("summary:", current->summary);
    assign_key("runbook_url:", current->runbook_url);
  }
  flush();
  return rules;
}

// Grafana JSON string values for the given keys (e.g. "expr", "query"),
// with \" and \\ unescaped. Handles no other escape forms because the
// shipped dashboard does not use them.
std::vector<std::string> json_string_values(std::string_view text,
                                            std::string_view key) {
  std::vector<std::string> values;
  const std::string needle = "\"" + std::string{key} + "\"";
  std::size_t position = 0U;
  while ((position = text.find(needle, position)) != std::string::npos) {
    position += needle.size();
    std::size_t cursor = position;
    while (cursor < text.size() &&
           std::isspace(static_cast<unsigned char>(text[cursor])) != 0) {
      ++cursor;
    }
    if (cursor >= text.size() || text[cursor] != ':') {
      continue;
    }
    ++cursor;
    while (cursor < text.size() &&
           std::isspace(static_cast<unsigned char>(text[cursor])) != 0) {
      ++cursor;
    }
    if (cursor >= text.size() || text[cursor] != '"') {
      continue;
    }
    ++cursor;
    std::string value;
    while (cursor < text.size() && text[cursor] != '"') {
      if (text[cursor] == '\\' && cursor + 1U < text.size() &&
          (text[cursor + 1U] == '"' || text[cursor + 1U] == '\\')) {
        value += text[cursor + 1U];
        cursor += 2U;
      } else {
        value += text[cursor];
        ++cursor;
      }
    }
    values.push_back(std::move(value));
    position = cursor;
  }
  return values;
}

bool brackets_balance(std::string_view text) {
  long depth = 0;
  bool in_string = false;
  for (std::size_t index = 0U; index < text.size(); ++index) {
    const char character = text[index];
    if (in_string) {
      if (character == '\\') {
        ++index;
      } else if (character == '"') {
        in_string = false;
      }
      continue;
    }
    if (character == '"') {
      in_string = true;
    } else if (character == '{' || character == '[') {
      ++depth;
    } else if (character == '}' || character == ']') {
      --depth;
      if (depth < 0) {
        return false;
      }
    }
  }
  return depth == 0 && !in_string;
}

// GitHub-flavored-markdown heading anchor: lowercase, keep alphanumerics,
// spaces become hyphens, other characters drop. The runbook deliberately
// uses plain-word headings so this rule is exact for it.
std::string heading_anchor(std::string_view title) {
  std::string anchor;
  for (const char character : title) {
    const unsigned char raw = static_cast<unsigned char>(character);
    if (std::isalnum(raw) != 0) {
      anchor += static_cast<char>(std::tolower(raw));
    } else if (character == ' ') {
      anchor += '-';
    }
  }
  return anchor;
}

std::set<std::string> runbook_anchors(std::string_view text) {
  std::set<std::string> anchors;
  std::istringstream lines{std::string{text}};
  std::string line;
  while (std::getline(lines, line)) {
    std::string_view trimmed = trim(line);
    if (trimmed.rfind("#", 0U) != 0U) {
      continue;
    }
    while (!trimmed.empty() && trimmed.front() == '#') {
      trimmed.remove_prefix(1U);
    }
    anchors.insert(heading_anchor(trim(trimmed)));
  }
  return anchors;
}

// Shared surface: both exporters rendered from default aggregates.
struct ExporterSurface {
  std::set<std::string> families;
};

const ExporterSurface& exporter_surface() {
  static const ExporterSurface surface = [] {
    ExporterSurface result;
    const std::string node_text = heyaki::format_node_metrics_prometheus(
        heyaki::NodeMetrics{});
    const std::string relay_text = heyaki::format_relay_metrics_prometheus(
        heyaki::RelayServerSnapshot{}, "m9-slo-surface");
    for (const auto& family : exposition_families(node_text)) {
      result.families.insert(family);
    }
    for (const auto& family : exposition_families(relay_text)) {
      result.families.insert(family);
    }
    return result;
  }();
  return surface;
}

void expect_tokens_resolve(const std::string& expression,
                           const std::set<std::string>& recordings) {
  SCOPED_TRACE(expression);
  for (const auto& token : heyaki_tokens(expression)) {
    if (token.rfind("heyaki:slo:", 0U) == 0U) {
      EXPECT_TRUE(recordings.count(token) != 0U)
          << "recording " << token << " is referenced but never recorded";
    } else {
      EXPECT_TRUE(exporter_surface().families.count(token) != 0U)
          << "metric " << token << " is not emitted by any exporter";
    }
  }
}

std::set<std::string> recording_names(const std::vector<ParsedRule>& rules) {
  std::set<std::string> names;
  for (const auto& rule : rules) {
    if (!rule.is_alert) {
      names.insert(rule.name);
    }
  }
  return names;
}

}  // namespace

TEST(M9SloRulesTest, ExportersRenderTheFullFamilySurface) {
  // Default-constructed aggregates must still render every family: the
  // validation in the remaining tests depends on zero-value renders being
  // complete, and the exporters write families unconditionally.
  const std::string node_text = heyaki::format_node_metrics_prometheus(
      heyaki::NodeMetrics{});
  const std::string relay_text = heyaki::format_relay_metrics_prometheus(
      heyaki::RelayServerSnapshot{}, "m9-slo-surface");
  EXPECT_GE(exposition_families(node_text).size(), std::size_t{190U});
  EXPECT_GE(exposition_families(relay_text).size(), std::size_t{95U});
}

TEST(M9SloRulesTest, RecordingRulesOnlyReferenceRealMetrics) {
  const auto rules = parse_rule_file(
      read_file(std::filesystem::path{observability_dir} /
                "prometheus/heyaki-recording.yml"));
  // Pinned so a parser/format drift fails loudly instead of checking
  // nothing. Update together with heyaki-recording.yml.
  ASSERT_EQ(rules.size(), std::size_t{8U});
  const auto recordings = recording_names(rules);
  ASSERT_EQ(recordings.size(), std::size_t{8U});
  for (const auto& rule : rules) {
    ASSERT_FALSE(rule.is_alert);
    EXPECT_FALSE(rule.expr.empty()) << rule.name << " has no expression";
    EXPECT_EQ(rule.name.rfind("heyaki:slo:", 0U), 0U)
        << rule.name << " is not under the heyaki:slo: namespace";
    expect_tokens_resolve(rule.expr, recordings);
  }
}

TEST(M9SloRulesTest, AlertRulesReferenceRealMetricsAndRunbook) {
  const auto rules = parse_rule_file(
      read_file(std::filesystem::path{observability_dir} /
                "prometheus/heyaki-alerts.yml"));
  // Pinned: 8 relay-slo + 12 node-slo alerts. Update with the file.
  ASSERT_EQ(rules.size(), std::size_t{20U});

  const auto recording_rules = parse_rule_file(
      read_file(std::filesystem::path{observability_dir} /
                "prometheus/heyaki-recording.yml"));
  const auto recordings = recording_names(recording_rules);

  const auto anchors = runbook_anchors(read_file(runbook_file));
  std::set<std::string> alert_names;
  for (const auto& rule : rules) {
    ASSERT_TRUE(rule.is_alert);
    EXPECT_TRUE(alert_names.insert(rule.name).second)
        << "duplicate alert name " << rule.name;
    EXPECT_FALSE(rule.expr.empty()) << rule.name << " has no expression";
    EXPECT_FALSE(rule.duration.empty())
        << rule.name << " has no for: duration";
    EXPECT_TRUE(rule.severity == "critical" || rule.severity == "warning")
        << rule.name << " has severity " << rule.severity;
    EXPECT_FALSE(rule.summary.empty()) << rule.name << " has no summary";
    ASSERT_FALSE(rule.runbook_url.empty())
        << rule.name << " has no runbook_url";
    expect_tokens_resolve(rule.expr, recordings);

    const std::string prefix = "docs/operations/runbook.md#";
    EXPECT_EQ(rule.runbook_url.rfind(prefix, 0U), 0U)
        << rule.name << " runbook_url is not a runbook anchor";
    const std::string anchor = rule.runbook_url.substr(prefix.size());
    EXPECT_FALSE(anchor.empty());
    EXPECT_TRUE(anchors.count(anchor) != 0U)
        << rule.name << " points at missing runbook heading " << anchor;
  }
}

TEST(M9SloRulesTest, DashboardOnlyReferencesRealMetrics) {
  const std::string dashboard = read_file(
      std::filesystem::path{observability_dir} /
          "grafana/heyaki-overview.json");
  ASSERT_FALSE(dashboard.empty());
  ASSERT_TRUE(brackets_balance(dashboard));

  const auto recording_rules = parse_rule_file(
      read_file(std::filesystem::path{observability_dir} /
                "prometheus/heyaki-recording.yml"));
  const auto recordings = recording_names(recording_rules);

  const auto expressions = json_string_values(dashboard, "expr");
  // 24 panels; pinned loosely so adding panels never skips validation.
  ASSERT_GE(expressions.size(), std::size_t{60U});
  const auto titles = json_string_values(dashboard, "title");
  EXPECT_GE(titles.size(), std::size_t{24U});
  for (const auto& expression : expressions) {
    expect_tokens_resolve(expression, recordings);
  }
  // Template-variable queries go through "query" and must resolve too.
  for (const auto& query : json_string_values(dashboard, "query")) {
    expect_tokens_resolve(query, recordings);
  }
}
