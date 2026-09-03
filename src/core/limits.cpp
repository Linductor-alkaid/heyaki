#include <heyaki/limits.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace heyaki {
namespace {

Result<void> invalid_limit(std::string_view name) {
  return Result<void>::failure(Error{ErrorCode::configuration, "limits", std::string{name}});
}

template <typename T, typename Minimum, typename Maximum>
bool outside(T value, Minimum minimum, Maximum maximum) {
  return value < static_cast<T>(minimum) || value > static_cast<T>(maximum);
}

}  // namespace

Result<void> validate_limits(const Limits& limits) {
  constexpr std::size_t kib = 1024U;
  constexpr std::size_t mib = 1024U * kib;
  constexpr std::size_t gib = 1024U * mib;

  if (outside(limits.max_frame_bytes, 256U, 64U * mib)) {
    return invalid_limit("max_frame_bytes");
  }
  if (outside(limits.max_control_frame_bytes, 256U, 1024U * kib) ||
      limits.max_control_frame_bytes > limits.max_frame_bytes) {
    return invalid_limit("max_control_frame_bytes");
  }
  if (outside(limits.max_message_bytes, 1U, 16U * mib) ||
      limits.max_message_bytes > limits.max_frame_bytes) {
    return invalid_limit("max_message_bytes");
  }
  if (outside(limits.max_rpc_payload_bytes, 1U, 16U * mib) ||
      limits.max_rpc_payload_bytes > limits.max_frame_bytes) {
    return invalid_limit("max_rpc_payload_bytes");
  }
  if (outside(limits.max_event_payload_bytes, 1U, 16U * mib) ||
      limits.max_event_payload_bytes > limits.max_frame_bytes) {
    return invalid_limit("max_event_payload_bytes");
  }
  if (outside(limits.max_send_queue_messages, 1U, 65536U)) {
    return invalid_limit("max_send_queue_messages");
  }
  if (outside(limits.max_send_queue_bytes, limits.max_frame_bytes, gib)) {
    return invalid_limit("max_send_queue_bytes");
  }
  if (outside(limits.max_receive_window_frames, 1U, 65536U)) {
    return invalid_limit("max_receive_window_frames");
  }
  if (outside(limits.max_receive_window_bytes, limits.max_frame_bytes, gib)) {
    return invalid_limit("max_receive_window_bytes");
  }
  constexpr std::uint64_t max_file_limit = 16ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
  if (limits.max_file_bytes < limits.max_file_chunk_bytes ||
      limits.max_file_bytes > max_file_limit) {
    return invalid_limit("max_file_bytes");
  }
  if (outside(limits.max_expanded_file_bytes, limits.max_file_chunk_bytes, max_file_limit)) {
    return invalid_limit("max_expanded_file_bytes");
  }
  if (outside(limits.max_file_chunk_bytes, 4U * kib, 1024U * kib) ||
      limits.max_file_chunk_bytes > limits.max_frame_bytes) {
    return invalid_limit("max_file_chunk_bytes");
  }
  if (outside(limits.max_concurrent_operations, 1U, 65536U)) {
    return invalid_limit("max_concurrent_operations");
  }
  if (outside(limits.max_pairing_payload_bytes, 256U, 64U * kib) ||
      limits.max_pairing_payload_bytes > limits.max_control_frame_bytes) {
    return invalid_limit("max_pairing_payload_bytes");
  }
  if (outside(limits.max_pairing_attempts_per_session, 1U, 20U)) {
    return invalid_limit("max_pairing_attempts_per_session");
  }
  if (outside(limits.max_endpoint_manifest_bytes, 256U, 1024U * kib) ||
      limits.max_endpoint_manifest_bytes > limits.max_frame_bytes) {
    return invalid_limit("max_endpoint_manifest_bytes");
  }
  if (outside(limits.max_diagnostic_events, 16U, 1024U * 1024U)) {
    return invalid_limit("max_diagnostic_events");
  }
  constexpr std::size_t shell_data_header_bytes = 28U;
  if (outside(limits.max_shell_data_bytes, 256U, 1024U * kib) ||
      limits.max_shell_data_bytes + shell_data_header_bytes > limits.max_frame_bytes) {
    return invalid_limit("max_shell_data_bytes");
  }
  if (outside(limits.max_shell_control_bytes, 256U, 64U * kib) ||
      limits.max_shell_control_bytes > limits.max_frame_bytes) {
    return invalid_limit("max_shell_control_bytes");
  }
  return Result<void>::success();
}

}  // namespace heyaki
