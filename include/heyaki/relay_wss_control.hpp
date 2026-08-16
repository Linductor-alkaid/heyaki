#pragma once

#include <heyaki/error.hpp>

#include <cstddef>
#include <cstdint>
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

}  // namespace heyaki
