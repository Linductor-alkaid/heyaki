#include "relay_enrollment.hpp"

#include "relay_database.hpp"

#include <heyaki/security.hpp>
#include <heyaki/signing.hpp>

#include <sodium.h>

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

Error enrollment_error(ErrorCode code, const char* detail) {
  return Error{code, "relay_enrollment", detail};
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

void append_tag(std::vector<std::byte>& output, std::uint32_t field, std::uint8_t wire_type) {
  append_varint(output, (static_cast<std::uint64_t>(field) << 3U) | wire_type);
}

void append_uint(std::vector<std::byte>& output, std::uint32_t field, std::uint64_t value) {
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
      return Result<ProtoField>::failure(enrollment_error(ErrorCode::protocol,
                                                          "protobuf_tag_invalid"));
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
        return Result<ProtoField>::failure(enrollment_error(ErrorCode::protocol,
                                                            "protobuf_length_invalid"));
      }
      const auto count = static_cast<std::size_t>(*length.value_if());
      field.bytes = input_.subspan(offset_, count);
      offset_ += count;
      return Result<ProtoField>::success(field);
    }
    return Result<ProtoField>::failure(enrollment_error(ErrorCode::protocol,
                                                        "protobuf_wire_type_unsupported"));
  }

 private:
  Result<std::uint64_t> read_varint() {
    std::uint64_t value = 0U;
    for (std::size_t index = 0U; index < 10U; ++index) {
      if (offset_ >= input_.size()) {
        return Result<std::uint64_t>::failure(enrollment_error(ErrorCode::protocol,
                                                               "protobuf_varint_truncated"));
      }
      const auto byte = std::to_integer<std::uint8_t>(input_[offset_++]);
      if (index == 9U && (byte & 0xfeU) != 0U) {
        return Result<std::uint64_t>::failure(enrollment_error(ErrorCode::protocol,
                                                               "protobuf_varint_overflow"));
      }
      value |= static_cast<std::uint64_t>(byte & 0x7fU) << (7U * index);
      if ((byte & 0x80U) == 0U) {
        if (index > 0U && (byte & 0x7fU) == 0U) {
          return Result<std::uint64_t>::failure(enrollment_error(ErrorCode::protocol,
                                                                 "protobuf_varint_noncanonical"));
        }
        return Result<std::uint64_t>::success(value);
      }
    }
    return Result<std::uint64_t>::failure(enrollment_error(ErrorCode::protocol,
                                                           "protobuf_varint_overflow"));
  }

  std::span<const std::byte> input_;
  std::size_t offset_{};
};

template <std::size_t Size>
Result<void> copy_exact(std::span<const std::byte> input, std::array<std::byte, Size>& output,
                        const char* detail) {
  if (input.size() != Size) {
    return Result<void>::failure(enrollment_error(ErrorCode::protocol, detail));
  }
  std::copy_n(input.begin(), Size, output.begin());
  return Result<void>::success();
}

bool is_nonempty_utf8(std::string_view value) noexcept {
  if (value.empty()) {
    return false;
  }
  std::size_t index = 0U;
  while (index < value.size()) {
    const auto first = static_cast<unsigned char>(value[index]);
    if (first <= 0x7fU) {
      ++index;
      continue;
    }
    std::size_t continuation_count = 0U;
    std::uint8_t second_minimum = 0x80U;
    std::uint8_t second_maximum = 0xbfU;
    if (first >= 0xc2U && first <= 0xdfU) {
      continuation_count = 1U;
    } else if (first >= 0xe0U && first <= 0xefU) {
      continuation_count = 2U;
      if (first == 0xe0U) {
        second_minimum = 0xa0U;
      } else if (first == 0xedU) {
        second_maximum = 0x9fU;
      }
    } else if (first >= 0xf0U && first <= 0xf4U) {
      continuation_count = 3U;
      if (first == 0xf0U) {
        second_minimum = 0x90U;
      } else if (first == 0xf4U) {
        second_maximum = 0x8fU;
      }
    } else {
      return false;
    }
    if (value.size() - index <= continuation_count) {
      return false;
    }
    const auto second = static_cast<unsigned char>(value[index + 1U]);
    if (second < second_minimum || second > second_maximum) {
      return false;
    }
    for (std::size_t offset = 2U; offset <= continuation_count; ++offset) {
      const auto continuation = static_cast<unsigned char>(value[index + offset]);
      if (continuation < 0x80U || continuation > 0xbfU) {
        return false;
      }
    }
    index += continuation_count + 1U;
  }
  return true;
}

bool is_printable_non_space(std::string_view value) noexcept {
  return value.size() >= relay_bootstrap_token_min_bytes &&
         value.size() <= relay_bootstrap_token_max_bytes &&
         std::all_of(value.begin(), value.end(), [](unsigned char character) {
           return character >= 0x21U && character <= 0x7eU;
         });
}

struct ParsedEndpoint {
  DeviceId device_id;
  EndpointId endpoint_id;
};

Result<ParsedEndpoint> parse_endpoint_message(std::span<const std::byte> input) {
  ProtoReader reader(input);
  DeviceId::Storage device{};
  EndpointId::Storage endpoint{};
  bool seen_device = false;
  bool seen_endpoint = false;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<ParsedEndpoint>::failure(*field.error_if());
    }
    if (field.value_if()->wire_type != 2U) {
      return Result<ParsedEndpoint>::failure(
          enrollment_error(ErrorCode::protocol, "endpoint_field_invalid"));
    }
    if (field.value_if()->number == 1U) {
      if (seen_device) {
        return Result<ParsedEndpoint>::failure(
            enrollment_error(ErrorCode::protocol, "endpoint_field_conflict"));
      }
      auto copied = copy_exact(field.value_if()->bytes, device, "endpoint_device_id_invalid");
      if (!copied) {
        return Result<ParsedEndpoint>::failure(*copied.error_if());
      }
      seen_device = true;
    } else if (field.value_if()->number == 2U) {
      if (seen_endpoint) {
        return Result<ParsedEndpoint>::failure(
            enrollment_error(ErrorCode::protocol, "endpoint_field_conflict"));
      }
      auto copied = copy_exact(field.value_if()->bytes, endpoint, "endpoint_id_invalid");
      if (!copied) {
        return Result<ParsedEndpoint>::failure(*copied.error_if());
      }
      seen_endpoint = true;
    } else {
      return Result<ParsedEndpoint>::failure(
          enrollment_error(ErrorCode::protocol, "endpoint_unknown_field"));
    }
  }
  if (!seen_device || !seen_endpoint) {
    return Result<ParsedEndpoint>::failure(
        enrollment_error(ErrorCode::protocol, "endpoint_field_missing"));
  }
  return Result<ParsedEndpoint>::success(
      ParsedEndpoint{.device_id = DeviceId{device}, .endpoint_id = EndpointId{endpoint}});
}

Result<ProtocolVersion> parse_version_message(std::span<const std::byte> input) {
  ProtoReader reader(input);
  bool seen_major = false;
  bool seen_minor = false;
  ProtocolVersion version;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<ProtocolVersion>::failure(*field.error_if());
    }
    if (field.value_if()->wire_type != 0U ||
        field.value_if()->integer > std::numeric_limits<std::uint32_t>::max()) {
      return Result<ProtocolVersion>::failure(
          enrollment_error(ErrorCode::protocol, "version_field_invalid"));
    }
    if (field.value_if()->number == 1U) {
      if (seen_major) {
        return Result<ProtocolVersion>::failure(
            enrollment_error(ErrorCode::protocol, "version_field_conflict"));
      }
      version.major = static_cast<std::uint32_t>(field.value_if()->integer);
      seen_major = true;
    } else if (field.value_if()->number == 2U) {
      if (seen_minor) {
        return Result<ProtocolVersion>::failure(
            enrollment_error(ErrorCode::protocol, "version_field_conflict"));
      }
      version.minor = static_cast<std::uint32_t>(field.value_if()->integer);
      seen_minor = true;
    } else {
      return Result<ProtocolVersion>::failure(
          enrollment_error(ErrorCode::protocol, "version_unknown_field"));
    }
  }
  if (!seen_major || !seen_minor) {
    return Result<ProtocolVersion>::failure(
        enrollment_error(ErrorCode::protocol, "version_field_missing"));
  }
  return Result<ProtocolVersion>::success(version);
}

struct CapabilityAdvertisement {
  CapabilitySet supported;
  CapabilitySet required;
};

Result<CapabilityAdvertisement> parse_capabilities_message(std::span<const std::byte> input) {
  ProtoReader reader(input);
  CapabilityAdvertisement output;
  bool seen_supported = false;
  bool seen_required = false;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<CapabilityAdvertisement>::failure(*field.error_if());
    }
    if (field.value_if()->wire_type != 0U) {
      return Result<CapabilityAdvertisement>::failure(
          enrollment_error(ErrorCode::protocol, "capability_field_invalid"));
    }
    if (field.value_if()->number == 1U) {
      if (seen_supported) {
        return Result<CapabilityAdvertisement>::failure(
            enrollment_error(ErrorCode::protocol, "capability_field_conflict"));
      }
      output.supported.bits = field.value_if()->integer;
      seen_supported = true;
    } else if (field.value_if()->number == 2U) {
      if (seen_required) {
        return Result<CapabilityAdvertisement>::failure(
            enrollment_error(ErrorCode::protocol, "capability_field_conflict"));
      }
      output.required.bits = field.value_if()->integer;
      seen_required = true;
    } else {
      return Result<CapabilityAdvertisement>::failure(
          enrollment_error(ErrorCode::protocol, "capability_unknown_field"));
    }
  }
  if (!seen_supported || !seen_required) {
    return Result<CapabilityAdvertisement>::failure(
        enrollment_error(ErrorCode::protocol, "capability_field_missing"));
  }
  if (output.supported.bits == 0U || !output.supported.contains(output.required)) {
    return Result<CapabilityAdvertisement>::failure(
        enrollment_error(ErrorCode::protocol, "capability_required_not_supported"));
  }
  return Result<CapabilityAdvertisement>::success(output);
}

Result<IdentitySignature> parse_signature_message(std::span<const std::byte> input) {
  ProtoReader reader(input);
  IdentitySignature signature{};
  bool seen = false;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<IdentitySignature>::failure(*field.error_if());
    }
    if (field.value_if()->number != 1U || field.value_if()->wire_type != 2U || seen) {
      return Result<IdentitySignature>::failure(
          enrollment_error(ErrorCode::protocol, "signature_field_invalid"));
    }
    auto copied = copy_exact(field.value_if()->bytes, signature, "signature_length_invalid");
    if (!copied) {
      return Result<IdentitySignature>::failure(*copied.error_if());
    }
    seen = true;
  }
  if (!seen) {
    return Result<IdentitySignature>::failure(
        enrollment_error(ErrorCode::protocol, "signature_field_missing"));
  }
  return Result<IdentitySignature>::success(signature);
}

std::vector<std::byte> encode_endpoint_message(DeviceId device_id, EndpointId endpoint_id) {
  std::vector<std::byte> output;
  append_bytes(output, 1U, device_id.bytes());
  append_bytes(output, 2U, endpoint_id.bytes());
  return output;
}

std::vector<std::byte> encode_version_message(ProtocolVersion version) {
  std::vector<std::byte> output;
  append_uint(output, 1U, version.major);
  append_uint(output, 2U, version.minor);
  return output;
}

std::vector<std::byte> encode_capabilities_message(CapabilitySet supported,
                                                   CapabilitySet required) {
  std::vector<std::byte> output;
  append_uint(output, 1U, supported.bits);
  append_uint(output, 2U, required.bits);
  return output;
}

std::vector<std::byte> encode_signature_message(IdentitySignature signature) {
  std::vector<std::byte> output;
  append_bytes(output, 1U, signature);
  return output;
}

}  // namespace

Result<EnrollmentChallenge> create_enrollment_challenge(
    RelayId relay_id, std::uint64_t now_unix_milliseconds,
    std::chrono::milliseconds validity) {
  if (relay_id == RelayId{}) {
    return Result<EnrollmentChallenge>::failure(
        enrollment_error(ErrorCode::configuration, "relay_id_zero"));
  }
  if (validity.count() <= 0 ||
      validity > std::chrono::milliseconds{maximum_signed_validity_milliseconds}) {
    return Result<EnrollmentChallenge>::failure(
        enrollment_error(ErrorCode::configuration, "challenge_validity_invalid"));
  }
  if (now_unix_milliseconds >
      std::numeric_limits<std::uint64_t>::max() -
          static_cast<std::uint64_t>(validity.count())) {
    return Result<EnrollmentChallenge>::failure(
        enrollment_error(ErrorCode::configuration, "challenge_expiry_overflow"));
  }
  const auto crypto = initialize_crypto();
  if (!crypto) {
    return Result<EnrollmentChallenge>::failure(*crypto.error_if());
  }
  EnrollmentChallenge challenge;
  challenge.relay_id = relay_id;
  randombytes_buf(challenge.nonce.data(), challenge.nonce.size());
  challenge.expires_unix_milliseconds =
      now_unix_milliseconds + static_cast<std::uint64_t>(validity.count());
  return Result<EnrollmentChallenge>::success(challenge);
}

Result<std::vector<std::byte>> encode_enrollment_challenge(
    const EnrollmentChallenge& challenge) {
  if (challenge.relay_id == RelayId{} || challenge.nonce == EnrollmentChallengeNonce{} ||
      challenge.expires_unix_milliseconds == 0U) {
    return Result<std::vector<std::byte>>::failure(
        enrollment_error(ErrorCode::configuration, "challenge_invalid"));
  }
  std::vector<std::byte> output;
  output.reserve(96U);
  append_bytes(output, 1U, challenge.relay_id);
  append_bytes(output, 2U, challenge.nonce);
  append_uint(output, 3U, challenge.expires_unix_milliseconds);
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<EnrollmentChallenge> parse_enrollment_challenge(std::span<const std::byte> payload) {
  if (payload.empty() || payload.size() > 4096U) {
    return Result<EnrollmentChallenge>::failure(
        enrollment_error(ErrorCode::protocol, "challenge_size_invalid"));
  }
  ProtoReader reader(payload);
  EnrollmentChallenge challenge;
  std::array<bool, 3U> seen{};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<EnrollmentChallenge>::failure(*field.error_if());
    }
    if (field.value_if()->number == 0U || field.value_if()->number > seen.size() ||
        seen[field.value_if()->number - 1U]) {
      return Result<EnrollmentChallenge>::failure(
          enrollment_error(ErrorCode::protocol, "challenge_field_conflict"));
    }
    seen[field.value_if()->number - 1U] = true;
    switch (field.value_if()->number) {
      case 1U: {
        auto copied = field.value_if()->wire_type == 2U
                          ? copy_exact(field.value_if()->bytes, challenge.relay_id,
                                       "challenge_relay_id_invalid")
                          : Result<void>::failure(enrollment_error(
                                ErrorCode::protocol, "challenge_relay_id_invalid"));
        if (!copied) {
          return Result<EnrollmentChallenge>::failure(*copied.error_if());
        }
        break;
      }
      case 2U: {
        auto copied = field.value_if()->wire_type == 2U
                          ? copy_exact(field.value_if()->bytes, challenge.nonce,
                                       "challenge_nonce_invalid")
                          : Result<void>::failure(enrollment_error(
                                ErrorCode::protocol, "challenge_nonce_invalid"));
        if (!copied) {
          return Result<EnrollmentChallenge>::failure(*copied.error_if());
        }
        break;
      }
      case 3U:
        if (field.value_if()->wire_type != 0U) {
          return Result<EnrollmentChallenge>::failure(
              enrollment_error(ErrorCode::protocol, "challenge_expiry_invalid"));
        }
        challenge.expires_unix_milliseconds = field.value_if()->integer;
        break;
      default:
        return Result<EnrollmentChallenge>::failure(
            enrollment_error(ErrorCode::protocol, "challenge_unknown_field"));
    }
  }
  if (!std::all_of(seen.begin(), seen.end(), [](bool value) { return value; })) {
    return Result<EnrollmentChallenge>::failure(
        enrollment_error(ErrorCode::protocol, "challenge_field_missing"));
  }
  if (challenge.relay_id == RelayId{} || challenge.nonce == EnrollmentChallengeNonce{} ||
      challenge.expires_unix_milliseconds == 0U) {
    return Result<EnrollmentChallenge>::failure(
        enrollment_error(ErrorCode::protocol, "challenge_invalid"));
  }
  return Result<EnrollmentChallenge>::success(challenge);
}

Result<std::vector<std::byte>> encode_enrollment_request(
    const EnrollmentRequest& request) {
  if (request.device_id.is_zero() || request.endpoint_id.is_zero() ||
      request.identity_public_key == IdentityPublicKey{} ||
      request.challenge_nonce == EnrollmentChallengeNonce{} ||
      !is_nonempty_utf8(request.tenant) || !is_printable_non_space(request.bootstrap_token) ||
      request.protocol_version.major == 0U ||
      request.supported.bits == 0U || !request.supported.contains(request.required) ||
      request.expires_unix_milliseconds == 0U ||
      request.signature == IdentitySignature{}) {
    return Result<std::vector<std::byte>>::failure(
        enrollment_error(ErrorCode::configuration, "enrollment_request_invalid"));
  }
  std::vector<std::byte> output;
  output.reserve(512U);
  append_bytes(output, 1U, encode_endpoint_message(request.device_id, request.endpoint_id));
  append_bytes(output, 2U, request.identity_public_key);
  append_bytes(output, 3U, request.challenge_nonce);
  append_string(output, 4U, request.tenant);
  append_string(output, 5U, request.bootstrap_token);
  append_bytes(output, 6U, encode_version_message(request.protocol_version));
  append_bytes(output, 7U, encode_capabilities_message(request.supported, request.required));
  append_uint(output, 8U, request.expires_unix_milliseconds);
  append_bytes(output, 9U, encode_signature_message(request.signature));
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<EnrollmentRequest> parse_enrollment_request(std::span<const std::byte> payload) {
  if (payload.empty() || payload.size() > max_enrollment_request_bytes) {
    return Result<EnrollmentRequest>::failure(
        enrollment_error(ErrorCode::protocol, "enrollment_request_size_invalid"));
  }
  ProtoReader reader(payload);
  EnrollmentRequest request;
  std::array<bool, 9U> seen{};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<EnrollmentRequest>::failure(*field.error_if());
    }
    if (field.value_if()->number == 0U || field.value_if()->number > seen.size() ||
        seen[field.value_if()->number - 1U]) {
      return Result<EnrollmentRequest>::failure(
          enrollment_error(ErrorCode::protocol, "enrollment_field_conflict"));
    }
    seen[field.value_if()->number - 1U] = true;
    switch (field.value_if()->number) {
      case 1U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<EnrollmentRequest>::failure(
              enrollment_error(ErrorCode::protocol, "enrollment_endpoint_invalid"));
        }
        auto endpoint = parse_endpoint_message(field.value_if()->bytes);
        if (!endpoint) {
          return Result<EnrollmentRequest>::failure(*endpoint.error_if());
        }
        request.device_id = endpoint.value_if()->device_id;
        request.endpoint_id = endpoint.value_if()->endpoint_id;
        break;
      }
      case 2U: {
        auto copied = field.value_if()->wire_type == 2U
                          ? copy_exact(field.value_if()->bytes, request.identity_public_key,
                                       "enrollment_public_key_invalid")
                          : Result<void>::failure(enrollment_error(
                                ErrorCode::protocol, "enrollment_public_key_invalid"));
        if (!copied) {
          return Result<EnrollmentRequest>::failure(*copied.error_if());
        }
        break;
      }
      case 3U: {
        auto copied = field.value_if()->wire_type == 2U
                          ? copy_exact(field.value_if()->bytes, request.challenge_nonce,
                                       "enrollment_challenge_nonce_invalid")
                          : Result<void>::failure(enrollment_error(
                                ErrorCode::protocol, "enrollment_challenge_nonce_invalid"));
        if (!copied) {
          return Result<EnrollmentRequest>::failure(*copied.error_if());
        }
        break;
      }
      case 4U: {
        if (field.value_if()->wire_type != 2U || field.value_if()->bytes.empty() ||
            field.value_if()->bytes.size() > 256U) {
          return Result<EnrollmentRequest>::failure(
              enrollment_error(ErrorCode::protocol, "enrollment_tenant_invalid"));
        }
        const auto* text = reinterpret_cast<const char*>(field.value_if()->bytes.data());
        request.tenant.assign(text, field.value_if()->bytes.size());
        break;
      }
      case 5U: {
        if (field.value_if()->wire_type != 2U || field.value_if()->bytes.empty() ||
            field.value_if()->bytes.size() > 256U) {
          return Result<EnrollmentRequest>::failure(
              enrollment_error(ErrorCode::protocol, "enrollment_token_invalid"));
        }
        const auto* text = reinterpret_cast<const char*>(field.value_if()->bytes.data());
        request.bootstrap_token.assign(text, field.value_if()->bytes.size());
        break;
      }
      case 6U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<EnrollmentRequest>::failure(
              enrollment_error(ErrorCode::protocol, "enrollment_version_invalid"));
        }
        auto version = parse_version_message(field.value_if()->bytes);
        if (!version) {
          return Result<EnrollmentRequest>::failure(*version.error_if());
        }
        request.protocol_version = *version.value_if();
        break;
      }
      case 7U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<EnrollmentRequest>::failure(
              enrollment_error(ErrorCode::protocol, "enrollment_capabilities_invalid"));
        }
        auto capabilities = parse_capabilities_message(field.value_if()->bytes);
        if (!capabilities) {
          return Result<EnrollmentRequest>::failure(*capabilities.error_if());
        }
        request.supported = capabilities.value_if()->supported;
        request.required = capabilities.value_if()->required;
        break;
      }
      case 8U:
        if (field.value_if()->wire_type != 0U) {
          return Result<EnrollmentRequest>::failure(
              enrollment_error(ErrorCode::protocol, "enrollment_expiry_invalid"));
        }
        request.expires_unix_milliseconds = field.value_if()->integer;
        break;
      case 9U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<EnrollmentRequest>::failure(
              enrollment_error(ErrorCode::protocol, "enrollment_signature_invalid"));
        }
        auto signature = parse_signature_message(field.value_if()->bytes);
        if (!signature) {
          return Result<EnrollmentRequest>::failure(*signature.error_if());
        }
        request.signature = *signature.value_if();
        break;
      }
      default:
        return Result<EnrollmentRequest>::failure(
            enrollment_error(ErrorCode::protocol, "enrollment_unknown_field"));
    }
  }
  if (!std::all_of(seen.begin(), seen.end(), [](bool value) { return value; })) {
    return Result<EnrollmentRequest>::failure(
        enrollment_error(ErrorCode::protocol, "enrollment_field_missing"));
  }
  return Result<EnrollmentRequest>::success(std::move(request));
}

Result<std::vector<std::byte>> canonical_enrollment_request(
    const EnrollmentRequest& request, RelayId relay_id) {
  std::vector<CanonicalField> fields;
  fields.reserve(11U);
  fields.push_back(CanonicalField{1U, canonical_bytes(request.device_id)});
  fields.push_back(CanonicalField{2U, canonical_bytes(request.endpoint_id)});
  fields.push_back(CanonicalField{
      3U, {request.identity_public_key.begin(), request.identity_public_key.end()}});
  fields.push_back(CanonicalField{4U, {relay_id.begin(), relay_id.end()}});
  fields.push_back(CanonicalField{5U, {request.challenge_nonce.begin(),
                                       request.challenge_nonce.end()}});
  fields.push_back(CanonicalField{
      6U, std::vector<std::byte>{reinterpret_cast<const std::byte*>(request.tenant.data()),
                                 reinterpret_cast<const std::byte*>(request.tenant.data()) +
                                     request.tenant.size()}});
  fields.push_back(CanonicalField{7U, canonical_uint32(request.protocol_version.major)});
  fields.push_back(CanonicalField{8U, canonical_uint32(request.protocol_version.minor)});
  fields.push_back(CanonicalField{9U, canonical_uint64(request.supported.bits)});
  fields.push_back(CanonicalField{10U, canonical_uint64(request.required.bits)});
  fields.push_back(CanonicalField{11U, canonical_uint64(request.expires_unix_milliseconds)});
  return canonicalize_for_signature(SigningDomain::enrollment, fields);
}

Result<void> sign_enrollment_request(EnrollmentRequest& request, RelayId relay_id,
                                     const IdentityKeyPair& identity) {
  auto canonical = canonical_enrollment_request(request, relay_id);
  if (!canonical) {
    return Result<void>::failure(*canonical.error_if());
  }
  auto signature = sign_identity_message(identity, *canonical.value_if());
  if (!signature) {
    return Result<void>::failure(*signature.error_if());
  }
  request.signature = *signature.value_if();
  return Result<void>::success();
}

Result<void> validate_enrollment_request(const EnrollmentRequest& request,
                                         const EnrollmentChallenge& challenge,
                                         std::uint64_t now_unix_milliseconds) {
  if (request.device_id.is_zero() || request.endpoint_id.is_zero() ||
      request.identity_public_key == IdentityPublicKey{} ||
      request.challenge_nonce == EnrollmentChallengeNonce{} ||
      !is_nonempty_utf8(request.tenant) || !is_printable_non_space(request.bootstrap_token) ||
      request.supported.bits == 0U ||
      request.expires_unix_milliseconds == 0U ||
      request.signature == IdentitySignature{} || challenge.relay_id == RelayId{} ||
      challenge.nonce == EnrollmentChallengeNonce{} ||
      challenge.expires_unix_milliseconds == 0U) {
    return Result<void>::failure(
        enrollment_error(ErrorCode::authentication, "enrollment_request_invalid"));
  }

  auto derived = derive_device_id(request.identity_public_key);
  if (!derived || *derived.value_if() != request.device_id) {
    return Result<void>::failure(
        enrollment_error(ErrorCode::authentication, "enrollment_device_id_mismatch"));
  }
  if (request.challenge_nonce != challenge.nonce) {
    return Result<void>::failure(
        enrollment_error(ErrorCode::authentication, "enrollment_challenge_nonce_mismatch"));
  }
  auto challenge_expiry = validate_signed_expiry(challenge.expires_unix_milliseconds,
                                                 now_unix_milliseconds);
  if (!challenge_expiry) {
    return Result<void>::failure(
        Error{ErrorCode::authentication, "relay_enrollment",
              std::string{challenge_expiry.error_if()->safe_detail()}});
  }
  if (request.expires_unix_milliseconds > challenge.expires_unix_milliseconds) {
    return Result<void>::failure(
        enrollment_error(ErrorCode::authentication, "enrollment_expiry_exceeds_challenge"));
  }
  auto request_expiry =
      validate_signed_expiry(request.expires_unix_milliseconds, now_unix_milliseconds);
  if (!request_expiry) {
    return Result<void>::failure(
        Error{ErrorCode::authentication, "relay_enrollment",
              std::string{request_expiry.error_if()->safe_detail()}});
  }

  const ProtocolHello local_hello{.version = current_protocol_version,
                                  .supported = CapabilitySet{known_capability_bits},
                                  .required = CapabilitySet{
                                      static_cast<std::uint64_t>(Capability::enrollment)}};
  const ProtocolHello remote_hello{.version = request.protocol_version,
                                   .supported = request.supported,
                                   .required = request.required};
  auto negotiated = negotiate_protocol(local_hello, remote_hello);
  if (!negotiated) {
    return Result<void>::failure(
        Error{ErrorCode::protocol, "relay_enrollment",
              std::string{negotiated.error_if()->safe_detail()}});
  }

  auto canonical = canonical_enrollment_request(request, challenge.relay_id);
  if (!canonical) {
    return Result<void>::failure(
        Error{ErrorCode::protocol, "relay_enrollment",
              std::string{canonical.error_if()->safe_detail()}});
  }
  return verify_identity_signature(request.identity_public_key, *canonical.value_if(),
                                   request.signature);
}

}  // namespace heyaki
