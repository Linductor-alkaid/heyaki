#pragma once

// Internal minimal Protobuf wire codec shared by hand-rolled core protocol
// payloads (trust grants, pairing). Not installed, not public API: the frozen
// schemas live under proto/, and core deliberately avoids linking the
// generated lite runtime.

#include <heyaki/error.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace heyaki::proto_codec {

inline Error protocol_error(std::string_view detail) {
  return Error{ErrorCode::protocol, "proto", std::string{detail}};
}

inline void append_varint(std::vector<std::byte>& output, std::uint64_t value) {
  do {
    auto byte = static_cast<std::uint8_t>(value & 0x7fU);
    value >>= 7U;
    if (value != 0U) {
      byte |= 0x80U;
    }
    output.push_back(static_cast<std::byte>(byte));
  } while (value != 0U);
}

inline void append_tag(std::vector<std::byte>& output, std::uint32_t field,
                       std::uint8_t wire_type) {
  append_varint(output, (static_cast<std::uint64_t>(field) << 3U) | wire_type);
}

inline void append_uint(std::vector<std::byte>& output, std::uint32_t field,
                        std::uint64_t value) {
  append_tag(output, field, 0U);
  append_varint(output, value);
}

inline void append_bytes(std::vector<std::byte>& output, std::uint32_t field,
                         std::span<const std::byte> value) {
  append_tag(output, field, 2U);
  append_varint(output, value.size());
  output.insert(output.end(), value.begin(), value.end());
}

inline void append_text(std::vector<std::byte>& output, std::uint32_t field,
                        std::string_view value) {
  append_bytes(output, field,
               std::span<const std::byte>{reinterpret_cast<const std::byte*>(value.data()),
                                          value.size()});
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
      return Result<ProtoField>::failure(protocol_error("protobuf_tag_invalid"));
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
        return Result<ProtoField>::failure(protocol_error("protobuf_length_invalid"));
      }
      const auto count = static_cast<std::size_t>(*length.value_if());
      field.bytes = input_.subspan(offset_, count);
      offset_ += count;
      return Result<ProtoField>::success(field);
    }
    return Result<ProtoField>::failure(protocol_error("protobuf_wire_type_unsupported"));
  }

  [[nodiscard]] std::string_view text(const ProtoField& field) const noexcept {
    return {reinterpret_cast<const char*>(field.bytes.data()), field.bytes.size()};
  }

 private:
  Result<std::uint64_t> read_varint() {
    std::uint64_t value = 0U;
    for (std::size_t index = 0U; index < 10U; ++index) {
      if (offset_ >= input_.size()) {
        return Result<std::uint64_t>::failure(protocol_error("protobuf_varint_truncated"));
      }
      const auto byte = std::to_integer<std::uint8_t>(input_[offset_++]);
      if (index == 9U && (byte & 0xfeU) != 0U) {
        return Result<std::uint64_t>::failure(protocol_error("protobuf_varint_overflow"));
      }
      value |= static_cast<std::uint64_t>(byte & 0x7fU) << (7U * index);
      if ((byte & 0x80U) == 0U) {
        if (index > 0U && (byte & 0x7fU) == 0U) {
          return Result<std::uint64_t>::failure(
              protocol_error("protobuf_varint_noncanonical"));
        }
        return Result<std::uint64_t>::success(value);
      }
    }
    return Result<std::uint64_t>::failure(protocol_error("protobuf_varint_overflow"));
  }

  std::span<const std::byte> input_;
  std::size_t offset_{};
};

template <typename Storage>
Result<void> copy_exact(std::span<const std::byte> source, Storage& destination,
                        std::string_view detail) {
  if (source.size() != destination.size()) {
    return Result<void>::failure(protocol_error(detail));
  }
  std::copy(source.begin(), source.end(), destination.begin());
  return Result<void>::success();
}

}  // namespace heyaki::proto_codec
