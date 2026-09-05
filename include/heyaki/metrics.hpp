#pragma once

// Prometheus text-format serializer for NodeMetrics (M9-01). The metrics
// model itself lives in node.hpp next to the surfaces it aggregates; this
// header owns the export encoding so scrapers, CI assertions, and the M9-04
// dashboards share one format. Exposition follows the Prometheus text
// format 0.0.4 subset: every metric family gets `# HELP`/`# TYPE`, counters
// carry the `_total` suffix, gauges do not. No secrets, terminal content,
// or business payloads ever appear — only the counts and gauges already
// exposed by the aggregated diagnostics types.

#include <heyaki/node.hpp>

#include <cstdint>
#include <string>
#include <string_view>

namespace heyaki {

// Serializes `metrics` in the Prometheus text exposition format. Metric
// names are prefixed `heyaki_`; when `instance` is non-empty every sample
// carries an `instance` label for joinability with the M9-03 correlation
// IDs. Booleans and enums map to numeric gauges; duration summaries are
// exported as sample count, millisecond sum, and millisecond max.
[[nodiscard]] std::string format_node_metrics_prometheus(
    const NodeMetrics& metrics, std::string_view instance = {});

}  // namespace heyaki
