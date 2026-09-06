#pragma once

// Shared Prometheus text-format (0.0.4 subset) writer for the M9 metric
// exporters. The device exporter (src/core/metrics.cpp) and the relay
// exporter (src/relay/relay_metrics.cpp) use the same writer so both
// surfaces share escaping rules, HELP/TYPE placement, and the counter
// `_total` convention.

#include <cstdint>
#include <string>
#include <string_view>

namespace heyaki {
namespace detail {

class MetricsTextWriter {
 public:
  explicit MetricsTextWriter(std::string_view instance) {
    if (!instance.empty()) {
      label_ = R"({instance=")";
      escape_label_value(label_, instance);
      label_.push_back('"');
      label_.push_back('}');
    }
  }

  void counter(std::string_view name, std::uint64_t value,
               std::string_view help) {
    family(name, "counter", help);
    sample(name, value);
  }

  void gauge(std::string_view name, std::uint64_t value,
             std::string_view help) {
    family(name, "gauge", help);
    sample(name, value);
  }

  const std::string& output() const noexcept { return output_; }

 private:
  void family(std::string_view name, std::string_view type,
              std::string_view help) {
    output_.append("# HELP ");
    output_.append(name);
    output_.push_back(' ');
    output_.append(help);
    output_.push_back('\n');
    output_.append("# TYPE ");
    output_.append(name);
    output_.push_back(' ');
    output_.append(type);
    output_.push_back('\n');
  }

  void sample(std::string_view name, std::uint64_t value) {
    output_.append(name);
    output_.append(label_);
    output_.push_back(' ');
    output_.append(std::to_string(value));
    output_.push_back('\n');
  }

  static void escape_label_value(std::string& out, std::string_view value) {
    for (const char character : value) {
      switch (character) {
        case '\\':
          out.append("\\\\");
          break;
        case '"':
          out.append("\\\"");
          break;
        case '\n':
          out.append("\\n");
          break;
        default:
          out.push_back(character);
          break;
      }
    }
  }

  std::string output_;
  std::string label_;
};

}  // namespace detail
}  // namespace heyaki
