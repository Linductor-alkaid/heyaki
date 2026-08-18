#pragma once

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

inline constexpr std::size_t relay_wss_control_header_bytes = 5U;
inline constexpr std::size_t max_relay_wss_control_frame_bytes = 64U * 1024U;
inline constexpr std::string_view relay_wss_control_path = "/control";

enum class RelayWssControlType : std::uint8_t {
  enrollment_challenge = 1U,
  enrollment_challenge_response = 2U,
  enrollment_request = 3U,
  enrollment_result = 4U,
  control_error = 5U,
  login_challenge = 6U,
  login_challenge_response = 7U,
  login_request = 8U,
  login_result = 9U,
  heartbeat = 10U,
  heartbeat_ack = 11U,
  endpoint_publish = 12U,
  endpoint_publish_ack = 13U,
  endpoint_query = 14U,
  endpoint_query_result = 15U,
  signaling_send = 16U,
  signaling_deliver = 17U,
};

struct RelayWssControlFrame {
  RelayWssControlType type{RelayWssControlType::control_error};
  std::vector<std::byte> payload;
};

struct RelayWssEnrollmentResult {
  std::string tenant;
  std::uint64_t enrollment_generation{};
  std::uint64_t token_remaining_uses_after{};
};

struct RelayWssLoginResult {
  std::string tenant;
  std::uint64_t enrollment_generation{};
  std::uint32_t lease_milliseconds{};
};

struct RelayWssHeartbeatRequest {
  std::optional<std::uint32_t> lease_milliseconds;
};

struct RelayWssHeartbeatAck {
  std::uint64_t lease_generation{};
  std::uint32_t granted_lease_milliseconds{};
};

struct RelayWssEndpointPublish {
  std::vector<std::byte> endpoint_record;
  std::optional<std::vector<std::byte>> service_manifest;
};

struct RelayWssEndpointPublishAck {
  std::uint64_t record_generation{};
};

struct RelayWssEndpointQuery {
  std::optional<DeviceId> device_id;
  std::optional<EndpointId> endpoint_id;
};

struct RelayWssEndpointPublication {
  DeviceId device_id;
  EndpointId endpoint_id;
  std::optional<std::string> application_id;
  std::optional<std::uint64_t> record_generation;
  std::optional<std::uint64_t> manifest_generation;
  std::optional<std::array<std::byte, 32U>> manifest_sha256;
  std::optional<std::uint64_t> expires_unix_milliseconds;
  std::optional<std::uint64_t> lease_expires_unix_milliseconds;
};

struct RelayWssEndpointQueryResult {
  std::vector<RelayWssEndpointPublication> endpoints;
};

// Peer signaling forwarding. The relay treats the payload as opaque bounded bytes: the
// signed-object verification chain runs on the devices, never on the relay.
struct RelayWssSignalingSend {
  DeviceId target_device_id;
  EndpointId target_endpoint_id;
  std::uint8_t kind{};  // LanSignalingMessageKind value.
  RequestId request_id;
  std::vector<std::byte> payload;
};

struct RelayWssSignalingDeliver {
  DeviceId source_device_id;
  EndpointId source_endpoint_id;
  std::uint8_t kind{};  // LanSignalingMessageKind value.
  RequestId request_id;
  std::vector<std::byte> payload;
};

struct RelayWssControlError {
  ErrorCode code{ErrorCode::internal};
  std::string safe_detail;
};

[[nodiscard]] Result<std::vector<std::byte>> encode_relay_wss_control_frame(
    RelayWssControlType type, std::span<const std::byte> payload);
[[nodiscard]] Result<RelayWssControlFrame> parse_relay_wss_control_frame(
    std::span<const std::byte> frame);

[[nodiscard]] Result<std::vector<std::byte>> encode_relay_wss_enrollment_result(
    const RelayWssEnrollmentResult& result);
[[nodiscard]] Result<RelayWssEnrollmentResult> parse_relay_wss_enrollment_result(
    std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_relay_wss_control_error(
    ErrorCode code, std::string_view safe_detail);
[[nodiscard]] Result<RelayWssControlError> parse_relay_wss_control_error(
    std::span<const std::byte> payload);

[[nodiscard]] Result<std::vector<std::byte>> encode_relay_wss_login_result(
    const RelayWssLoginResult& result);
[[nodiscard]] Result<RelayWssLoginResult> parse_relay_wss_login_result(
    std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_relay_wss_heartbeat_request(
    const RelayWssHeartbeatRequest& request);
[[nodiscard]] Result<RelayWssHeartbeatRequest> parse_relay_wss_heartbeat_request(
    std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_relay_wss_heartbeat_ack(
    const RelayWssHeartbeatAck& ack);
[[nodiscard]] Result<RelayWssHeartbeatAck> parse_relay_wss_heartbeat_ack(
    std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_relay_wss_endpoint_publish(
    const RelayWssEndpointPublish& publish);
[[nodiscard]] Result<RelayWssEndpointPublish> parse_relay_wss_endpoint_publish(
    std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_relay_wss_endpoint_publish_ack(
    const RelayWssEndpointPublishAck& ack);
[[nodiscard]] Result<RelayWssEndpointPublishAck> parse_relay_wss_endpoint_publish_ack(
    std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_relay_wss_endpoint_query(
    const RelayWssEndpointQuery& query);
[[nodiscard]] Result<RelayWssEndpointQuery> parse_relay_wss_endpoint_query(
    std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_relay_wss_endpoint_query_result(
    const RelayWssEndpointQueryResult& result);
[[nodiscard]] Result<RelayWssEndpointQueryResult> parse_relay_wss_endpoint_query_result(
    std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_relay_wss_signaling_send(
    const RelayWssSignalingSend& send);
[[nodiscard]] Result<RelayWssSignalingSend> parse_relay_wss_signaling_send(
    std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_relay_wss_signaling_deliver(
    const RelayWssSignalingDeliver& deliver);
[[nodiscard]] Result<RelayWssSignalingDeliver> parse_relay_wss_signaling_deliver(
    std::span<const std::byte> payload);

}  // namespace heyaki
