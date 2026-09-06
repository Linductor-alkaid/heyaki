#pragma once

// Prometheus text-format serializer for RelayServerSnapshot (M9-02). Pure
// serialization over the already-published snapshot: every value comes from
// the aggregated server/database/rate-limit/lease/directory/login/enrollment
// diagnostics, so this file never touches sockets, strands, or executor
// state. Families mirror the device-side export (heyaki/metrics.hpp): HELP
// and TYPE for every family, counters carry `_total`, gauges do not, and an
// optional `instance` label (the relay id hex) makes scrape joins with the
// structured relay logs and the M9-03 correlation ids possible. No secrets,
// tokens, or business payloads appear — only the counters and gauges the
// snapshot already exposes.

#include "relay_server.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace heyaki {

// Serializes `snapshot` in the Prometheus text exposition format with the
// `heyaki_relay_` prefix. Enums and booleans map to numeric gauges.
[[nodiscard]] std::string format_relay_metrics_prometheus(
    const RelayServerSnapshot& snapshot, std::string_view instance = {});

// Stable lowercase hex rendering of the relay id (SHA-256 of the serving
// certificate). The relay id is public: it is already signed into every
// enrollment/login challenge.
[[nodiscard]] std::string relay_id_to_hex(const RelayId& relay_id);

}  // namespace heyaki
