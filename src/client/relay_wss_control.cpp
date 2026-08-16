#include <heyaki/relay_wss_control.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
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
         value <= static_cast<std::uint8_t>(RelayWssControlType::control_error);
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

}  // namespace heyaki
