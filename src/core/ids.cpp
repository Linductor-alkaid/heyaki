#include <heyaki/ids.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace heyaki {
namespace {

constexpr std::string_view base32_alphabet = "abcdefghijklmnopqrstuvwxyz234567";

template <typename Id>
std::string encode_identifier(const Id& id, std::string_view prefix) {
  std::string encoded;
  encoded.reserve(prefix.size() + ((Id::size_bytes * 8U + 4U) / 5U));
  encoded.append(prefix);

  std::uint32_t accumulator = 0U;
  unsigned int bits = 0U;
  for (const auto byte : id.bytes()) {
    accumulator = (accumulator << 8U) | std::to_integer<std::uint8_t>(byte);
    bits += 8U;
    while (bits >= 5U) {
      bits -= 5U;
      encoded.push_back(base32_alphabet[(accumulator >> bits) & 0x1fU]);
    }
    accumulator &= bits == 0U ? 0U : ((1U << bits) - 1U);
  }
  if (bits != 0U) {
    encoded.push_back(base32_alphabet[(accumulator << (5U - bits)) & 0x1fU]);
  }
  return encoded;
}

int decode_base32_character(char character) noexcept {
  if (character >= 'a' && character <= 'z') {
    return character - 'a';
  }
  if (character >= '2' && character <= '7') {
    return character - '2' + 26;
  }
  return -1;
}

template <typename Id>
IdentifierDecodeResult<Id> decode_identifier(std::string_view text, std::string_view prefix) {
  if (!text.starts_with(prefix)) {
    return {.value = std::nullopt, .error = IdentifierDecodeError::invalid_prefix};
  }

  constexpr auto encoded_size = (Id::size_bytes * 8U + 4U) / 5U;
  if (text.size() != prefix.size() + encoded_size) {
    return {.value = std::nullopt, .error = IdentifierDecodeError::invalid_length};
  }

  typename Id::Storage bytes{};
  std::size_t output_index = 0U;
  std::uint32_t accumulator = 0U;
  unsigned int bits = 0U;
  for (const char character : text.substr(prefix.size())) {
    if (character >= 'A' && character <= 'Z') {
      return {.value = std::nullopt, .error = IdentifierDecodeError::non_canonical};
    }
    const int value = decode_base32_character(character);
    if (value < 0) {
      return {.value = std::nullopt, .error = IdentifierDecodeError::invalid_character};
    }

    accumulator = (accumulator << 5U) | static_cast<std::uint32_t>(value);
    bits += 5U;
    if (bits >= 8U) {
      bits -= 8U;
      if (output_index >= bytes.size()) {
        return {.value = std::nullopt, .error = IdentifierDecodeError::invalid_length};
      }
      bytes[output_index++] = static_cast<std::byte>((accumulator >> bits) & 0xffU);
    }
    accumulator &= bits == 0U ? 0U : ((1U << bits) - 1U);
  }

  if (output_index != bytes.size()) {
    return {.value = std::nullopt, .error = IdentifierDecodeError::invalid_length};
  }
  if (bits != 0U && accumulator != 0U) {
    return {.value = std::nullopt, .error = IdentifierDecodeError::non_canonical};
  }
  return {.value = Id{bytes}, .error = IdentifierDecodeError::none};
}

}  // namespace

std::string to_string(const DeviceId& id) { return encode_identifier(id, "hy1_"); }
std::string to_string(const EndpointId& id) { return encode_identifier(id, "hye1_"); }
std::string to_string(const SessionId& id) { return encode_identifier(id, "hys1_"); }
std::string to_string(const OperationId& id) { return encode_identifier(id, "hyo1_"); }
std::string to_string(const MessageId& id) { return encode_identifier(id, "hym1_"); }
std::string to_string(const RequestId& id) { return encode_identifier(id, "hyr1_"); }
std::string to_string(const TransferId& id) { return encode_identifier(id, "hyt1_"); }
std::string to_string(const GrantId& id) { return encode_identifier(id, "hyg1_"); }
std::string to_string(const ShellId& id) { return encode_identifier(id, "hysh1_"); }

IdentifierDecodeResult<DeviceId> parse_device_id(std::string_view text) {
  return decode_identifier<DeviceId>(text, "hy1_");
}
IdentifierDecodeResult<EndpointId> parse_endpoint_id(std::string_view text) {
  return decode_identifier<EndpointId>(text, "hye1_");
}
IdentifierDecodeResult<SessionId> parse_session_id(std::string_view text) {
  return decode_identifier<SessionId>(text, "hys1_");
}
IdentifierDecodeResult<OperationId> parse_operation_id(std::string_view text) {
  return decode_identifier<OperationId>(text, "hyo1_");
}
IdentifierDecodeResult<MessageId> parse_message_id(std::string_view text) {
  return decode_identifier<MessageId>(text, "hym1_");
}
IdentifierDecodeResult<RequestId> parse_request_id(std::string_view text) {
  return decode_identifier<RequestId>(text, "hyr1_");
}
IdentifierDecodeResult<TransferId> parse_transfer_id(std::string_view text) {
  return decode_identifier<TransferId>(text, "hyt1_");
}
IdentifierDecodeResult<GrantId> parse_grant_id(std::string_view text) {
  return decode_identifier<GrantId>(text, "hyg1_");
}

std::string_view identifier_decode_error_name(IdentifierDecodeError error) noexcept {
  switch (error) {
    case IdentifierDecodeError::none:
      return "none";
    case IdentifierDecodeError::invalid_prefix:
      return "invalid_prefix";
    case IdentifierDecodeError::invalid_length:
      return "invalid_length";
    case IdentifierDecodeError::invalid_character:
      return "invalid_character";
    case IdentifierDecodeError::non_canonical:
      return "non_canonical";
  }
  return "invalid_character";
}

}  // namespace heyaki
