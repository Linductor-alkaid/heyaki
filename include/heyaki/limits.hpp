#pragma once

#include <heyaki/error.hpp>

#include <cstddef>
#include <cstdint>

namespace heyaki {

struct Limits {
  std::size_t max_frame_bytes{2U * 1024U * 1024U};
  std::size_t max_control_frame_bytes{64U * 1024U};
  std::size_t max_message_bytes{1024U * 1024U};
  std::size_t max_rpc_payload_bytes{1024U * 1024U};
  std::size_t max_send_queue_messages{1024U};
  std::size_t max_send_queue_bytes{8U * 1024U * 1024U};
  std::size_t max_receive_window_frames{256U};
  std::size_t max_receive_window_bytes{4U * 1024U * 1024U};
  std::uint64_t max_file_bytes{16ULL * 1024ULL * 1024ULL * 1024ULL};
  std::size_t max_file_chunk_bytes{256U * 1024U};
  std::size_t max_concurrent_operations{256U};
  std::size_t max_pairing_payload_bytes{8U * 1024U};
  std::size_t max_pairing_attempts_per_session{5U};
  std::size_t max_endpoint_manifest_bytes{64U * 1024U};
  std::size_t max_diagnostic_events{2048U};
};

[[nodiscard]] Result<void> validate_limits(const Limits& limits);

}  // namespace heyaki
