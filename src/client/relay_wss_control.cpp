#include <heyaki/relay_wss_control.hpp>
#include <heyaki/signaling_protocol.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

Error control_error(const char* detail) {
  return Error{ErrorCode::protocol, "relay_wss_control", detail};
}

bool valid_control_type(std::uint8_t value) noexcept {
  return value >= static_cast<std::uint8_t>(RelayWssControlType::enrollment_challenge) &&
         value <= static_cast<std::uint8_t>(RelayWssControlType::signaling_deliver);
}

bool valid_error_code(std::uint16_t value) noexcept {
  return value >= static_cast<std::uint16_t>(ErrorCode::configuration) &&
         value <= static_cast<std::uint16_t>(ErrorCode::storage);
}

bool valid_utf8(std::string_view value) noexcept {
  if (value.empty()) {
    return false;
  }
  std::size_t offset = 0U;
  while (offset < value.size()) {
    const auto lead = static_cast<std::uint8_t>(value[offset]);
    std::size_t continuation_count = 0U;
    std::uint32_t code_point = 0U;
    if (lead <= 0x7fU) {
      if (lead < 0x20U) {
        return false;
      }
      code_point = lead;
    } else if (lead >= 0xc2U && lead <= 0xdfU) {
      continuation_count = 1U;
      code_point = lead & 0x1fU;
    } else if (lead >= 0xe0U && lead <= 0xefU) {
      continuation_count = 2U;
      code_point = lead & 0x0fU;
    } else if (lead >= 0xf0U && lead <= 0xf4U) {
      continuation_count = 3U;
      code_point = lead & 0x07U;
    } else {
      return false;
    }
    if (offset + continuation_count >= value.size()) {
      return false;
    }
    for (std::size_t index = 0U; index < continuation_count; ++index) {
      const auto next = static_cast<std::uint8_t>(value[offset + index + 1U]);
      if ((next & 0xc0U) != 0x80U) {
        return false;
      }
      code_point = (code_point << 6U) | (next & 0x3fU);
    }
    if ((continuation_count == 2U && code_point < 0x800U) ||
        (continuation_count == 3U && code_point < 0x10000U) ||
        (code_point >= 0xd800U && code_point <= 0xdfffU) ||
        code_point > 0x10ffffU) {
      return false;
    }
    offset += continuation_count + 1U;
  }
  return true;
}

void append_varint(std::vector<std::byte>& output, std::uint64_t value) {
  do {
    auto byte = static_cast<std::uint8_t>(value & 0x7fU);
    value >>= 7U;
    if (value != 0U) {
      byte |= 0x80U;
    }
    output.push_back(static_cast<std::byte>(byte));
  } while (value != 0U);
}

void append_tag(std::vector<std::byte>& output, std::uint32_t field,
                std::uint8_t wire_type) {
  append_varint(output, (static_cast<std::uint64_t>(field) << 3U) | wire_type);
}

void append_uint(std::vector<std::byte>& output, std::uint32_t field,
                 std::uint64_t value) {
  append_tag(output, field, 0U);
  append_varint(output, value);
}

void append_bytes(std::vector<std::byte>& output, std::uint32_t field,
                  std::span<const std::byte> value) {
  append_tag(output, field, 2U);
  append_varint(output, value.size());
  output.insert(output.end(), value.begin(), value.end());
}

void append_string(std::vector<std::byte>& output, std::uint32_t field,
                   std::string_view value) {
  append_bytes(output, field,
               std::span<const std::byte>{
                   reinterpret_cast<const std::byte*>(value.data()), value.size()});
}

struct ProtoField {
  std::uint32_t number{};
  std::uint8_t wire_type{};
  std::uint64_t integer{};
  std::span<const std::byte> bytes;
};

class ProtoReader {
 public:
  explicit ProtoReader(std::span<const std::byte> input) : input_(input) {}

  [[nodiscard]] bool done() const noexcept { return offset_ == input_.size(); }

  Result<ProtoField> next() {
    auto tag = read_varint();
    if (!tag) {
      return Result<ProtoField>::failure(*tag.error_if());
    }
    if (*tag.value_if() == 0U || (*tag.value_if() >> 3U) > 536870911U) {
      return Result<ProtoField>::failure(control_error("protobuf_tag_invalid"));
    }
    ProtoField field;
    field.number = static_cast<std::uint32_t>(*tag.value_if() >> 3U);
    field.wire_type = static_cast<std::uint8_t>(*tag.value_if() & 0x07U);
    if (field.wire_type == 0U) {
      auto value = read_varint();
      if (!value) {
        return Result<ProtoField>::failure(*value.error_if());
      }
      field.integer = *value.value_if();
      return Result<ProtoField>::success(field);
    }
    if (field.wire_type == 2U) {
      auto length = read_varint();
      if (!length || *length.value_if() > input_.size() - offset_) {
        return Result<ProtoField>::failure(control_error("protobuf_length_invalid"));
      }
      const auto count = static_cast<std::size_t>(*length.value_if());
      field.bytes = input_.subspan(offset_, count);
      offset_ += count;
      return Result<ProtoField>::success(field);
    }
    return Result<ProtoField>::failure(control_error("protobuf_wire_type_unsupported"));
  }

 private:
  Result<std::uint64_t> read_varint() {
    std::uint64_t value = 0U;
    for (std::size_t index = 0U; index < 10U; ++index) {
      if (offset_ >= input_.size()) {
        return Result<std::uint64_t>::failure(control_error("protobuf_varint_truncated"));
      }
      const auto byte = std::to_integer<std::uint8_t>(input_[offset_++]);
      if (index == 9U && (byte & 0xfeU) != 0U) {
        return Result<std::uint64_t>::failure(control_error("protobuf_varint_overflow"));
      }
      value |= static_cast<std::uint64_t>(byte & 0x7fU) << (7U * index);
      if ((byte & 0x80U) == 0U) {
        if (index > 0U && (byte & 0x7fU) == 0U) {
          return Result<std::uint64_t>::failure(control_error("protobuf_varint_noncanonical"));
        }
        return Result<std::uint64_t>::success(value);
      }
    }
    return Result<std::uint64_t>::failure(control_error("protobuf_varint_overflow"));
  }

  std::span<const std::byte> input_;
  std::size_t offset_{};
};

}  // namespace

Result<std::vector<std::byte>> encode_relay_wss_control_frame(
    RelayWssControlType type, std::span<const std::byte> payload) {
  if (!valid_control_type(static_cast<std::uint8_t>(type))) {
    return Result<std::vector<std::byte>>::failure(control_error("frame_type_invalid"));
  }
  if (payload.size() >
      max_relay_wss_control_frame_bytes - relay_wss_control_header_bytes) {
    return Result<std::vector<std::byte>>::failure(control_error("frame_too_large"));
  }
  const auto length = static_cast<std::uint32_t>(payload.size());
  std::vector<std::byte> output;
  output.reserve(relay_wss_control_header_bytes + payload.size());
  output.push_back(static_cast<std::byte>(type));
  output.push_back(static_cast<std::byte>((length >> 24U) & 0xffU));
  output.push_back(static_cast<std::byte>((length >> 16U) & 0xffU));
  output.push_back(static_cast<std::byte>((length >> 8U) & 0xffU));
  output.push_back(static_cast<std::byte>(length & 0xffU));
  output.insert(output.end(), payload.begin(), payload.end());
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RelayWssControlFrame> parse_relay_wss_control_frame(
    std::span<const std::byte> frame) {
  if (frame.size() < relay_wss_control_header_bytes ||
      frame.size() > max_relay_wss_control_frame_bytes) {
    return Result<RelayWssControlFrame>::failure(control_error("frame_size_invalid"));
  }
  const auto type_value = std::to_integer<std::uint8_t>(frame[0U]);
  const std::uint32_t length =
      (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(frame[1U])) << 24U) |
      (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(frame[2U])) << 16U) |
      (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(frame[3U])) << 8U) |
      std::to_integer<std::uint8_t>(frame[4U]);
  if (length != frame.size() - relay_wss_control_header_bytes) {
    return Result<RelayWssControlFrame>::failure(control_error("frame_length_mismatch"));
  }
  if (!valid_control_type(type_value)) {
    return Result<RelayWssControlFrame>::failure(control_error("frame_type_unknown"));
  }
  RelayWssControlFrame output;
  output.type = static_cast<RelayWssControlType>(type_value);
  output.payload.assign(frame.begin() + relay_wss_control_header_bytes, frame.end());
  return Result<RelayWssControlFrame>::success(std::move(output));
}

Result<std::vector<std::byte>> encode_relay_wss_enrollment_result(
    const RelayWssEnrollmentResult& result) {
  if (result.tenant.empty() || result.tenant.size() > 128U ||
      !valid_utf8(result.tenant) || result.enrollment_generation == 0U) {
    return Result<std::vector<std::byte>>::failure(control_error("enrollment_result_invalid"));
  }
  std::vector<std::byte> output;
  append_string(output, 1U, result.tenant);
  append_uint(output, 2U, result.enrollment_generation);
  if (result.token_remaining_uses_after != 0U) {
    append_uint(output, 3U, result.token_remaining_uses_after);
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RelayWssEnrollmentResult> parse_relay_wss_enrollment_result(
    std::span<const std::byte> payload) {
  if (payload.empty() || payload.size() > 1024U) {
    return Result<RelayWssEnrollmentResult>::failure(
        control_error("enrollment_result_size_invalid"));
  }
  ProtoReader reader(payload);
  RelayWssEnrollmentResult result;
  std::array<bool, 3U> seen{};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RelayWssEnrollmentResult>::failure(*field.error_if());
    }
    if (field.value_if()->number == 0U || field.value_if()->number > seen.size() ||
        seen[field.value_if()->number - 1U]) {
      return Result<RelayWssEnrollmentResult>::failure(
          control_error("enrollment_result_field_conflict"));
    }
    seen[field.value_if()->number - 1U] = true;
    if (field.value_if()->number == 1U) {
      if (field.value_if()->wire_type != 2U || field.value_if()->bytes.empty() ||
          field.value_if()->bytes.size() > 128U) {
        return Result<RelayWssEnrollmentResult>::failure(
            control_error("enrollment_result_tenant_invalid"));
      }
      const auto* text = reinterpret_cast<const char*>(field.value_if()->bytes.data());
      result.tenant.assign(text, field.value_if()->bytes.size());
      if (!valid_utf8(result.tenant)) {
        return Result<RelayWssEnrollmentResult>::failure(
            control_error("enrollment_result_tenant_invalid"));
      }
    } else if (field.value_if()->wire_type != 0U ||
               (field.value_if()->number == 2U && field.value_if()->integer == 0U)) {
      return Result<RelayWssEnrollmentResult>::failure(
          control_error("enrollment_result_field_invalid"));
    } else if (field.value_if()->number == 2U) {
      result.enrollment_generation = field.value_if()->integer;
    } else if (field.value_if()->number == 3U) {
      result.token_remaining_uses_after = field.value_if()->integer;
    }
  }
  if (!seen[0U] || !seen[1U]) {
    return Result<RelayWssEnrollmentResult>::failure(
        control_error("enrollment_result_field_missing"));
  }
  return Result<RelayWssEnrollmentResult>::success(std::move(result));
}

Result<std::vector<std::byte>> encode_relay_wss_control_error(
    ErrorCode code, std::string_view safe_detail) {
  if (!valid_error_code(static_cast<std::uint16_t>(code)) ||
      !is_safe_detail_token(safe_detail)) {
    return Result<std::vector<std::byte>>::failure(control_error("control_error_invalid"));
  }
  std::vector<std::byte> output;
  append_uint(output, 1U, static_cast<std::uint16_t>(code));
  append_string(output, 2U, safe_detail);
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RelayWssControlError> parse_relay_wss_control_error(
    std::span<const std::byte> payload) {
  if (payload.empty() || payload.size() > 128U) {
    return Result<RelayWssControlError>::failure(control_error("control_error_size_invalid"));
  }
  ProtoReader reader(payload);
  RelayWssControlError output;
  std::array<bool, 2U> seen{};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RelayWssControlError>::failure(*field.error_if());
    }
    if (field.value_if()->number == 0U || field.value_if()->number > seen.size() ||
        seen[field.value_if()->number - 1U]) {
      return Result<RelayWssControlError>::failure(
          control_error("control_error_field_conflict"));
    }
    seen[field.value_if()->number - 1U] = true;
    if (field.value_if()->number == 1U) {
      if (field.value_if()->wire_type != 0U ||
          field.value_if()->integer > (std::numeric_limits<std::uint16_t>::max)() ||
          !valid_error_code(static_cast<std::uint16_t>(field.value_if()->integer))) {
        return Result<RelayWssControlError>::failure(
            control_error("control_error_code_invalid"));
      }
      output.code = static_cast<ErrorCode>(field.value_if()->integer);
    } else {
      if (field.value_if()->wire_type != 2U || field.value_if()->bytes.empty() ||
          field.value_if()->bytes.size() > max_safe_detail_bytes) {
        return Result<RelayWssControlError>::failure(
            control_error("control_error_detail_invalid"));
      }
      const auto* text = reinterpret_cast<const char*>(field.value_if()->bytes.data());
      output.safe_detail.assign(text, field.value_if()->bytes.size());
      if (!is_safe_detail_token(output.safe_detail)) {
        return Result<RelayWssControlError>::failure(
            control_error("control_error_detail_invalid"));
      }
    }
  }
  if (!std::all_of(seen.begin(), seen.end(), [](bool value) { return value; })) {
    return Result<RelayWssControlError>::failure(
        control_error("control_error_field_missing"));
  }
  return Result<RelayWssControlError>::success(std::move(output));
}



namespace {

constexpr std::size_t relay_wss_manifest_sha256_bytes = 32U;
constexpr std::uint32_t max_relay_wss_lease_milliseconds = 120000U;
constexpr std::size_t max_relay_wss_endpoint_record_bytes = 16U * 1024U;
constexpr std::size_t max_relay_wss_service_manifest_bytes = 16U * 1024U;

Result<void> copy_control_bytes(std::span<const std::byte> input,
                                std::span<std::byte> output,
                                const char* detail) {
  if (input.size() != output.size()) {
    return Result<void>::failure(control_error(detail));
  }
  std::copy_n(input.begin(), input.size(), output.begin());
  return Result<void>::success();
}

void append_control_publication(std::vector<std::byte>& output, std::uint32_t field,
                                const RelayWssEndpointPublication& publication) {
  std::vector<std::byte> nested;
  append_bytes(nested, 1U, publication.device_id.bytes());
  append_bytes(nested, 2U, publication.endpoint_id.bytes());
  if (publication.application_id) {
    append_string(nested, 3U, *publication.application_id);
  }
  if (publication.record_generation) {
    append_uint(nested, 4U, *publication.record_generation);
  }
  if (publication.manifest_generation) {
    append_uint(nested, 5U, *publication.manifest_generation);
  }
  if (publication.manifest_sha256) {
    append_bytes(nested, 6U, *publication.manifest_sha256);
  }
  if (publication.expires_unix_milliseconds) {
    append_uint(nested, 7U, *publication.expires_unix_milliseconds);
  }
  if (publication.lease_expires_unix_milliseconds) {
    append_uint(nested, 8U, *publication.lease_expires_unix_milliseconds);
  }
  append_bytes(output, field, nested);
}

Result<RelayWssEndpointPublication> parse_control_publication(
    std::span<const std::byte> payload) {
  if (payload.empty() || payload.size() > 4096U) {
    return Result<RelayWssEndpointPublication>::failure(
        control_error("endpoint_publication_size_invalid"));
  }
  ProtoReader reader(payload);
  RelayWssEndpointPublication output;
  std::array<bool, 8U> seen{};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RelayWssEndpointPublication>::failure(*field.error_if());
    }
    if (field.value_if()->number == 0U || field.value_if()->number > seen.size()) {
      return Result<RelayWssEndpointPublication>::failure(
          control_error("endpoint_publication_unknown_field"));
    }
    if (field.value_if()->number <= 2U) {
      if (seen[field.value_if()->number - 1U] || field.value_if()->wire_type != 2U) {
        return Result<RelayWssEndpointPublication>::failure(
            control_error("endpoint_publication_field_conflict"));
      }
      seen[field.value_if()->number - 1U] = true;
      DeviceId::Storage device{};
      EndpointId::Storage endpoint{};
      if (field.value_if()->number == 1U) {
        auto copied = copy_control_bytes(field.value_if()->bytes, device,
                                         "endpoint_publication_device_invalid");
        if (!copied) {
          return Result<RelayWssEndpointPublication>::failure(*copied.error_if());
        }
        output.device_id = DeviceId{device};
      } else {
        auto copied = copy_control_bytes(field.value_if()->bytes, endpoint,
                                         "endpoint_publication_endpoint_invalid");
        if (!copied) {
          return Result<RelayWssEndpointPublication>::failure(*copied.error_if());
        }
        output.endpoint_id = EndpointId{endpoint};
      }
      continue;
    }
    if (seen[field.value_if()->number - 1U]) {
      return Result<RelayWssEndpointPublication>::failure(
          control_error("endpoint_publication_field_conflict"));
    }
    seen[field.value_if()->number - 1U] = true;
    if (field.value_if()->number == 3U) {
      if (field.value_if()->wire_type != 2U || field.value_if()->bytes.empty() ||
          field.value_if()->bytes.size() > 255U) {
        return Result<RelayWssEndpointPublication>::failure(
            control_error("endpoint_publication_application_invalid"));
      }
      const auto* text = reinterpret_cast<const char*>(field.value_if()->bytes.data());
      output.application_id.emplace(text, field.value_if()->bytes.size());
      if (!valid_utf8(*output.application_id)) {
        return Result<RelayWssEndpointPublication>::failure(
            control_error("endpoint_publication_application_invalid"));
      }
    } else if (field.value_if()->number == 6U) {
      if (field.value_if()->wire_type != 2U ||
          field.value_if()->bytes.size() != relay_wss_manifest_sha256_bytes) {
        return Result<RelayWssEndpointPublication>::failure(
            control_error("endpoint_publication_manifest_invalid"));
      }
      std::array<std::byte, relay_wss_manifest_sha256_bytes> hash{};
      std::copy_n(field.value_if()->bytes.begin(), hash.size(), hash.begin());
      output.manifest_sha256 = hash;
    } else {
      if (field.value_if()->wire_type != 0U || field.value_if()->integer == 0U) {
        return Result<RelayWssEndpointPublication>::failure(
            control_error("endpoint_publication_field_invalid"));
      }
      if (field.value_if()->number == 4U) {
        output.record_generation = field.value_if()->integer;
      } else if (field.value_if()->number == 5U) {
        output.manifest_generation = field.value_if()->integer;
      } else if (field.value_if()->number == 7U) {
        output.expires_unix_milliseconds = field.value_if()->integer;
      } else if (field.value_if()->number == 8U) {
        output.lease_expires_unix_milliseconds = field.value_if()->integer;
      }
    }
  }
  if (!seen[0U] || !seen[1U]) {
    return Result<RelayWssEndpointPublication>::failure(
        control_error("endpoint_publication_field_missing"));
  }
  return Result<RelayWssEndpointPublication>::success(std::move(output));
}

Result<void> validate_control_lease_milliseconds(std::uint64_t value,
                                                 const char* detail) {
  if (value > max_relay_wss_lease_milliseconds) {
    return Result<void>::failure(control_error(detail));
  }
  return Result<void>::success();
}

}  // namespace

Result<std::vector<std::byte>> encode_relay_wss_login_result(
    const RelayWssLoginResult& result) {
  if (result.tenant.empty() || result.tenant.size() > 128U ||
      !valid_utf8(result.tenant) || result.enrollment_generation == 0U ||
      result.lease_milliseconds == 0U ||
      result.lease_milliseconds > max_relay_wss_lease_milliseconds) {
    return Result<std::vector<std::byte>>::failure(control_error("login_result_invalid"));
  }
  std::vector<std::byte> output;
  append_string(output, 1U, result.tenant);
  append_uint(output, 2U, result.enrollment_generation);
  append_uint(output, 3U, result.lease_milliseconds);
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RelayWssLoginResult> parse_relay_wss_login_result(
    std::span<const std::byte> payload) {
  if (payload.empty() || payload.size() > 1024U) {
    return Result<RelayWssLoginResult>::failure(control_error("login_result_size_invalid"));
  }
  ProtoReader reader(payload);
  RelayWssLoginResult result;
  std::array<bool, 3U> seen{};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RelayWssLoginResult>::failure(*field.error_if());
    }
    if (field.value_if()->number == 0U || field.value_if()->number > seen.size() ||
        seen[field.value_if()->number - 1U]) {
      return Result<RelayWssLoginResult>::failure(control_error("login_result_field_conflict"));
    }
    seen[field.value_if()->number - 1U] = true;
    if (field.value_if()->number == 1U) {
      if (field.value_if()->wire_type != 2U || field.value_if()->bytes.empty() ||
          field.value_if()->bytes.size() > 128U) {
        return Result<RelayWssLoginResult>::failure(control_error("login_result_tenant_invalid"));
      }
      const auto* text = reinterpret_cast<const char*>(field.value_if()->bytes.data());
      result.tenant.assign(text, field.value_if()->bytes.size());
      if (!valid_utf8(result.tenant)) {
        return Result<RelayWssLoginResult>::failure(control_error("login_result_tenant_invalid"));
      }
    } else {
      if (field.value_if()->wire_type != 0U || field.value_if()->integer == 0U) {
        return Result<RelayWssLoginResult>::failure(control_error("login_result_field_invalid"));
      }
      if (field.value_if()->number == 2U) {
        result.enrollment_generation = field.value_if()->integer;
      } else {
        auto valid = validate_control_lease_milliseconds(
            field.value_if()->integer, "login_result_lease_invalid");
        if (!valid) {
          return Result<RelayWssLoginResult>::failure(*valid.error_if());
        }
        result.lease_milliseconds = static_cast<std::uint32_t>(field.value_if()->integer);
      }
    }
  }
  if (!std::all_of(seen.begin(), seen.end(), [](bool value) { return value; })) {
    return Result<RelayWssLoginResult>::failure(control_error("login_result_field_missing"));
  }
  return Result<RelayWssLoginResult>::success(std::move(result));
}

Result<std::vector<std::byte>> encode_relay_wss_heartbeat_request(
    const RelayWssHeartbeatRequest& request) {
  std::vector<std::byte> output;
  if (request.lease_milliseconds) {
    if (*request.lease_milliseconds > max_relay_wss_lease_milliseconds) {
      return Result<std::vector<std::byte>>::failure(control_error("heartbeat_request_invalid"));
    }
    append_uint(output, 1U, *request.lease_milliseconds);
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RelayWssHeartbeatRequest> parse_relay_wss_heartbeat_request(
    std::span<const std::byte> payload) {
  if (payload.size() > 16U) {
    return Result<RelayWssHeartbeatRequest>::failure(
        control_error("heartbeat_request_size_invalid"));
  }
  ProtoReader reader(payload);
  RelayWssHeartbeatRequest request;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RelayWssHeartbeatRequest>::failure(*field.error_if());
    }
    if (field.value_if()->number != 1U || field.value_if()->wire_type != 0U ||
        request.lease_milliseconds) {
      return Result<RelayWssHeartbeatRequest>::failure(
          control_error("heartbeat_request_field_invalid"));
    }
    auto valid = validate_control_lease_milliseconds(
        field.value_if()->integer, "heartbeat_request_lease_invalid");
    if (!valid) {
      return Result<RelayWssHeartbeatRequest>::failure(*valid.error_if());
    }
    request.lease_milliseconds = static_cast<std::uint32_t>(field.value_if()->integer);
  }
  return Result<RelayWssHeartbeatRequest>::success(std::move(request));
}

Result<std::vector<std::byte>> encode_relay_wss_heartbeat_ack(
    const RelayWssHeartbeatAck& ack) {
  if (ack.lease_generation == 0U || ack.granted_lease_milliseconds == 0U ||
      ack.granted_lease_milliseconds > max_relay_wss_lease_milliseconds) {
    return Result<std::vector<std::byte>>::failure(control_error("heartbeat_ack_invalid"));
  }
  std::vector<std::byte> output;
  append_uint(output, 1U, ack.lease_generation);
  append_uint(output, 2U, ack.granted_lease_milliseconds);
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RelayWssHeartbeatAck> parse_relay_wss_heartbeat_ack(
    std::span<const std::byte> payload) {
  if (payload.empty() || payload.size() > 32U) {
    return Result<RelayWssHeartbeatAck>::failure(control_error("heartbeat_ack_size_invalid"));
  }
  ProtoReader reader(payload);
  RelayWssHeartbeatAck ack;
  std::array<bool, 2U> seen{};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RelayWssHeartbeatAck>::failure(*field.error_if());
    }
    if (field.value_if()->number == 0U || field.value_if()->number > seen.size() ||
        seen[field.value_if()->number - 1U] || field.value_if()->wire_type != 0U ||
        field.value_if()->integer == 0U) {
      return Result<RelayWssHeartbeatAck>::failure(control_error("heartbeat_ack_field_invalid"));
    }
    seen[field.value_if()->number - 1U] = true;
    if (field.value_if()->number == 1U) {
      ack.lease_generation = field.value_if()->integer;
    } else {
      auto valid = validate_control_lease_milliseconds(
          field.value_if()->integer, "heartbeat_ack_lease_invalid");
      if (!valid) {
        return Result<RelayWssHeartbeatAck>::failure(*valid.error_if());
      }
      ack.granted_lease_milliseconds = static_cast<std::uint32_t>(field.value_if()->integer);
    }
  }
  if (!std::all_of(seen.begin(), seen.end(), [](bool value) { return value; })) {
    return Result<RelayWssHeartbeatAck>::failure(control_error("heartbeat_ack_field_missing"));
  }
  return Result<RelayWssHeartbeatAck>::success(std::move(ack));
}

Result<std::vector<std::byte>> encode_relay_wss_endpoint_publish(
    const RelayWssEndpointPublish& publish) {
  if (publish.endpoint_record.empty() || publish.endpoint_record.size() > max_relay_wss_endpoint_record_bytes ||
      (publish.service_manifest &&
       (publish.service_manifest->empty() ||
        publish.service_manifest->size() > max_relay_wss_service_manifest_bytes))) {
    return Result<std::vector<std::byte>>::failure(control_error("endpoint_publish_invalid"));
  }
  std::vector<std::byte> output;
  append_bytes(output, 1U, publish.endpoint_record);
  if (publish.service_manifest) {
    append_bytes(output, 2U, *publish.service_manifest);
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RelayWssEndpointPublish> parse_relay_wss_endpoint_publish(
    std::span<const std::byte> payload) {
  if (payload.empty() || payload.size() > max_relay_wss_endpoint_record_bytes + max_relay_wss_service_manifest_bytes + 64U) {
    return Result<RelayWssEndpointPublish>::failure(
        control_error("endpoint_publish_size_invalid"));
  }
  ProtoReader reader(payload);
  RelayWssEndpointPublish output;
  std::array<bool, 2U> seen{};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RelayWssEndpointPublish>::failure(*field.error_if());
    }
    if (field.value_if()->number == 0U || field.value_if()->number > seen.size() ||
        seen[field.value_if()->number - 1U] || field.value_if()->wire_type != 2U ||
        field.value_if()->bytes.empty()) {
      return Result<RelayWssEndpointPublish>::failure(
          control_error("endpoint_publish_field_invalid"));
    }
    seen[field.value_if()->number - 1U] = true;
    if (field.value_if()->number == 1U) {
      if (field.value_if()->bytes.size() > max_relay_wss_endpoint_record_bytes) {
        return Result<RelayWssEndpointPublish>::failure(
            control_error("endpoint_publish_record_too_large"));
      }
      output.endpoint_record.assign(field.value_if()->bytes.begin(),
                                    field.value_if()->bytes.end());
    } else {
      if (field.value_if()->bytes.size() > max_relay_wss_service_manifest_bytes) {
        return Result<RelayWssEndpointPublish>::failure(
            control_error("endpoint_publish_manifest_too_large"));
      }
      output.service_manifest.emplace(field.value_if()->bytes.begin(),
                                      field.value_if()->bytes.end());
    }
  }
  if (!seen[0U]) {
    return Result<RelayWssEndpointPublish>::failure(
        control_error("endpoint_publish_field_missing"));
  }
  return Result<RelayWssEndpointPublish>::success(std::move(output));
}

Result<std::vector<std::byte>> encode_relay_wss_endpoint_publish_ack(
    const RelayWssEndpointPublishAck& ack) {
  if (ack.record_generation == 0U) {
    return Result<std::vector<std::byte>>::failure(
        control_error("endpoint_publish_ack_invalid"));
  }
  std::vector<std::byte> output;
  append_uint(output, 1U, ack.record_generation);
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RelayWssEndpointPublishAck> parse_relay_wss_endpoint_publish_ack(
    std::span<const std::byte> payload) {
  if (payload.empty() || payload.size() > 16U) {
    return Result<RelayWssEndpointPublishAck>::failure(
        control_error("endpoint_publish_ack_size_invalid"));
  }
  ProtoReader reader(payload);
  RelayWssEndpointPublishAck ack;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RelayWssEndpointPublishAck>::failure(*field.error_if());
    }
    if (field.value_if()->number != 1U || field.value_if()->wire_type != 0U ||
        field.value_if()->integer == 0U || ack.record_generation != 0U) {
      return Result<RelayWssEndpointPublishAck>::failure(
          control_error("endpoint_publish_ack_field_invalid"));
    }
    ack.record_generation = field.value_if()->integer;
  }
  if (ack.record_generation == 0U) {
    return Result<RelayWssEndpointPublishAck>::failure(
        control_error("endpoint_publish_ack_field_missing"));
  }
  return Result<RelayWssEndpointPublishAck>::success(std::move(ack));
}

Result<std::vector<std::byte>> encode_relay_wss_endpoint_query(
    const RelayWssEndpointQuery& query) {
  if (query.endpoint_id && !query.device_id) {
    return Result<std::vector<std::byte>>::failure(control_error("endpoint_query_invalid"));
  }
  std::vector<std::byte> output;
  if (query.device_id) {
    append_bytes(output, 1U, query.device_id->bytes());
  }
  if (query.endpoint_id) {
    append_bytes(output, 2U, query.endpoint_id->bytes());
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RelayWssEndpointQuery> parse_relay_wss_endpoint_query(
    std::span<const std::byte> payload) {
  if (payload.size() > 64U) {
    return Result<RelayWssEndpointQuery>::failure(
        control_error("endpoint_query_size_invalid"));
  }
  ProtoReader reader(payload);
  RelayWssEndpointQuery query;
  std::array<bool, 2U> seen{};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RelayWssEndpointQuery>::failure(*field.error_if());
    }
    if (field.value_if()->number == 0U || field.value_if()->number > seen.size() ||
        seen[field.value_if()->number - 1U] || field.value_if()->wire_type != 2U) {
      return Result<RelayWssEndpointQuery>::failure(
          control_error("endpoint_query_field_invalid"));
    }
    seen[field.value_if()->number - 1U] = true;
    if (field.value_if()->number == 1U) {
      DeviceId::Storage device{};
      auto copied = copy_control_bytes(field.value_if()->bytes, device,
                                       "endpoint_query_device_invalid");
      if (!copied) {
        return Result<RelayWssEndpointQuery>::failure(*copied.error_if());
      }
      query.device_id = DeviceId{device};
    } else {
      EndpointId::Storage endpoint{};
      auto copied = copy_control_bytes(field.value_if()->bytes, endpoint,
                                       "endpoint_query_endpoint_invalid");
      if (!copied) {
        return Result<RelayWssEndpointQuery>::failure(*copied.error_if());
      }
      query.endpoint_id = EndpointId{endpoint};
    }
  }
  if (query.endpoint_id && !query.device_id) {
    return Result<RelayWssEndpointQuery>::failure(control_error("endpoint_query_invalid"));
  }
  return Result<RelayWssEndpointQuery>::success(std::move(query));
}

Result<std::vector<std::byte>> encode_relay_wss_endpoint_query_result(
    const RelayWssEndpointQueryResult& result) {
  std::vector<std::byte> output;
  for (const auto& endpoint : result.endpoints) {
    if (endpoint.device_id.is_zero() || endpoint.endpoint_id.is_zero() ||
        (endpoint.application_id &&
         (endpoint.application_id->empty() ||
          endpoint.application_id->size() > 255U ||
          !valid_utf8(*endpoint.application_id))) ||
        (endpoint.record_generation && *endpoint.record_generation == 0U) ||
        (endpoint.manifest_generation && *endpoint.manifest_generation == 0U) ||
        (endpoint.expires_unix_milliseconds &&
         *endpoint.expires_unix_milliseconds == 0U) ||
        (endpoint.lease_expires_unix_milliseconds &&
         *endpoint.lease_expires_unix_milliseconds == 0U)) {
      return Result<std::vector<std::byte>>::failure(
          control_error("endpoint_query_result_invalid"));
    }
    append_control_publication(output, 1U, endpoint);
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RelayWssEndpointQueryResult> parse_relay_wss_endpoint_query_result(
    std::span<const std::byte> payload) {
  if (payload.size() > max_relay_wss_control_frame_bytes - relay_wss_control_header_bytes) {
    return Result<RelayWssEndpointQueryResult>::failure(
        control_error("endpoint_query_result_size_invalid"));
  }
  ProtoReader reader(payload);
  RelayWssEndpointQueryResult result;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RelayWssEndpointQueryResult>::failure(*field.error_if());
    }
    if (field.value_if()->number != 1U || field.value_if()->wire_type != 2U) {
      return Result<RelayWssEndpointQueryResult>::failure(
          control_error("endpoint_query_result_field_invalid"));
    }
    auto publication = parse_control_publication(field.value_if()->bytes);
    if (!publication) {
      return Result<RelayWssEndpointQueryResult>::failure(*publication.error_if());
    }
    result.endpoints.push_back(std::move(*publication.value_if()));
  }
  return Result<RelayWssEndpointQueryResult>::success(std::move(result));
}


namespace {

template <typename Target>
Result<Target> parse_signaling_target(std::span<const std::byte> payload) {
  ProtoReader reader(payload);
  std::optional<DeviceId> device_id;
  std::optional<EndpointId> endpoint_id;
  std::optional<std::uint8_t> kind;
  std::optional<RequestId> request_id;
  std::vector<std::byte> message_payload;
  bool payload_seen = false;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<Target>::failure(*field.error_if());
    }
    switch (field.value_if()->number) {
      case 1U: {
        DeviceId::Storage value{};
        if (field.value_if()->wire_type != 2U || device_id ||
            field.value_if()->bytes.size() != value.size()) {
          return Result<Target>::failure(control_error("signaling_device_id_invalid"));
        }
        std::copy(field.value_if()->bytes.begin(), field.value_if()->bytes.end(),
                  value.begin());
        device_id = DeviceId{value};
        break;
      }
      case 2U: {
        EndpointId::Storage value{};
        if (field.value_if()->wire_type != 2U || endpoint_id ||
            field.value_if()->bytes.size() != value.size()) {
          return Result<Target>::failure(control_error("signaling_endpoint_id_invalid"));
        }
        std::copy(field.value_if()->bytes.begin(), field.value_if()->bytes.end(),
                  value.begin());
        endpoint_id = EndpointId{value};
        break;
      }
      case 3U: {
        if (field.value_if()->wire_type != 0U || kind ||
            field.value_if()->integer > 255U || field.value_if()->integer == 0U) {
          return Result<Target>::failure(control_error("signaling_kind_invalid"));
        }
        kind = static_cast<std::uint8_t>(field.value_if()->integer);
        break;
      }
      case 4U: {
        RequestId::Storage value{};
        if (field.value_if()->wire_type != 2U || request_id ||
            field.value_if()->bytes.size() != value.size()) {
          return Result<Target>::failure(control_error("signaling_request_id_invalid"));
        }
        std::copy(field.value_if()->bytes.begin(), field.value_if()->bytes.end(),
                  value.begin());
        request_id = RequestId{value};
        break;
      }
      case 5U: {
        if (field.value_if()->wire_type != 2U || payload_seen ||
            field.value_if()->bytes.size() > max_signaling_object_bytes) {
          return Result<Target>::failure(control_error("signaling_payload_invalid"));
        }
        message_payload = std::vector<std::byte>{field.value_if()->bytes.begin(),
                                                 field.value_if()->bytes.end()};
        payload_seen = true;
        break;
      }
      default:
        return Result<Target>::failure(control_error("signaling_field_unknown"));
    }
  }
  if (!device_id || !endpoint_id || !kind || !request_id) {
    return Result<Target>::failure(control_error("signaling_field_missing"));
  }
  if (device_id->is_zero() || endpoint_id->is_zero() || request_id->is_zero()) {
    return Result<Target>::failure(control_error("signaling_identity_zero"));
  }
  Target target;
  target.device_id = *device_id;
  target.endpoint_id = *endpoint_id;
  target.kind = *kind;
  target.request_id = *request_id;
  target.payload = std::move(message_payload);
  return Result<Target>::success(std::move(target));
}

void append_signaling_common(std::vector<std::byte>& output, const DeviceId& device_id,
                             const EndpointId& endpoint_id, std::uint8_t kind,
                             const RequestId& request_id,
                             std::span<const std::byte> payload) {
  append_bytes(output, 1U, device_id.bytes());
  append_bytes(output, 2U, endpoint_id.bytes());
  append_uint(output, 3U, kind);
  append_bytes(output, 4U, request_id.bytes());
  // proto3 omits absent bytes fields; an empty payload is encoded as absence.
  if (!payload.empty()) {
    append_bytes(output, 5U, payload);
  }
}

}  // namespace

Result<std::vector<std::byte>> encode_relay_wss_signaling_send(
    const RelayWssSignalingSend& send) {
  if (send.target_device_id.is_zero() || send.target_endpoint_id.is_zero() ||
      send.request_id.is_zero() || send.kind == 0U ||
      send.payload.size() > max_signaling_object_bytes) {
    return Result<std::vector<std::byte>>::failure(
        control_error("signaling_send_invalid"));
  }
  std::vector<std::byte> output;
  append_signaling_common(output, send.target_device_id, send.target_endpoint_id,
                          send.kind, send.request_id, send.payload);
  return Result<std::vector<std::byte>>::success(std::move(output));
}

struct ParsedSignalingSend {
  DeviceId device_id;
  EndpointId endpoint_id;
  std::uint8_t kind{};
  RequestId request_id;
  std::vector<std::byte> payload;
};

Result<RelayWssSignalingSend> parse_relay_wss_signaling_send(
    std::span<const std::byte> payload) {
  if (payload.size() > max_relay_wss_control_frame_bytes - relay_wss_control_header_bytes) {
    return Result<RelayWssSignalingSend>::failure(
        control_error("signaling_send_size_invalid"));
  }
  auto parsed = parse_signaling_target<ParsedSignalingSend>(payload);
  if (!parsed) {
    return Result<RelayWssSignalingSend>::failure(*parsed.error_if());
  }
  RelayWssSignalingSend send;
  send.target_device_id = parsed.value_if()->device_id;
  send.target_endpoint_id = parsed.value_if()->endpoint_id;
  send.kind = parsed.value_if()->kind;
  send.request_id = parsed.value_if()->request_id;
  send.payload = std::move(parsed.value_if()->payload);
  return Result<RelayWssSignalingSend>::success(std::move(send));
}

Result<std::vector<std::byte>> encode_relay_wss_signaling_deliver(
    const RelayWssSignalingDeliver& deliver) {
  if (deliver.source_device_id.is_zero() || deliver.source_endpoint_id.is_zero() ||
      deliver.request_id.is_zero() || deliver.kind == 0U ||
      deliver.payload.size() > max_signaling_object_bytes) {
    return Result<std::vector<std::byte>>::failure(
        control_error("signaling_deliver_invalid"));
  }
  std::vector<std::byte> output;
  append_signaling_common(output, deliver.source_device_id, deliver.source_endpoint_id,
                          deliver.kind, deliver.request_id, deliver.payload);
  return Result<std::vector<std::byte>>::success(std::move(output));
}

struct ParsedSignalingDeliver {
  DeviceId device_id;
  EndpointId endpoint_id;
  std::uint8_t kind{};
  RequestId request_id;
  std::vector<std::byte> payload;
};

Result<RelayWssSignalingDeliver> parse_relay_wss_signaling_deliver(
    std::span<const std::byte> payload) {
  if (payload.size() > max_relay_wss_control_frame_bytes - relay_wss_control_header_bytes) {
    return Result<RelayWssSignalingDeliver>::failure(
        control_error("signaling_deliver_size_invalid"));
  }
  auto parsed = parse_signaling_target<ParsedSignalingDeliver>(payload);
  if (!parsed) {
    return Result<RelayWssSignalingDeliver>::failure(*parsed.error_if());
  }
  RelayWssSignalingDeliver deliver;
  deliver.source_device_id = parsed.value_if()->device_id;
  deliver.source_endpoint_id = parsed.value_if()->endpoint_id;
  deliver.kind = parsed.value_if()->kind;
  deliver.request_id = parsed.value_if()->request_id;
  deliver.payload = std::move(parsed.value_if()->payload);
  return Result<RelayWssSignalingDeliver>::success(std::move(deliver));
}

}  // namespace heyaki
