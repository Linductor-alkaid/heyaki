#include "relay_endpoint.hpp"

#include <heyaki/security.hpp>
#include <heyaki/signing.hpp>

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

Error endpoint_error(ErrorCode code, const char* detail) {
  return Error{code, "relay_endpoint", detail};
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
      return Result<ProtoField>::failure(endpoint_error(ErrorCode::protocol,
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
        return Result<ProtoField>::failure(endpoint_error(ErrorCode::protocol,
                                                          "protobuf_length_invalid"));
      }
      const auto count = static_cast<std::size_t>(*length.value_if());
      field.bytes = input_.subspan(offset_, count);
      offset_ += count;
      return Result<ProtoField>::success(field);
    }
    return Result<ProtoField>::failure(endpoint_error(ErrorCode::protocol,
                                                      "protobuf_wire_type_unsupported"));
  }

 private:
  Result<std::uint64_t> read_varint() {
    std::uint64_t value = 0U;
    for (std::size_t index = 0U; index < 10U; ++index) {
      if (offset_ >= input_.size()) {
        return Result<std::uint64_t>::failure(endpoint_error(ErrorCode::protocol,
                                                             "protobuf_varint_truncated"));
      }
      const auto byte = std::to_integer<std::uint8_t>(input_[offset_++]);
      if (index == 9U && (byte & 0xfeU) != 0U) {
        return Result<std::uint64_t>::failure(endpoint_error(ErrorCode::protocol,
                                                             "protobuf_varint_overflow"));
      }
      value |= static_cast<std::uint64_t>(byte & 0x7fU) << (7U * index);
      if ((byte & 0x80U) == 0U) {
        if (index > 0U && (byte & 0x7fU) == 0U) {
          return Result<std::uint64_t>::failure(endpoint_error(ErrorCode::protocol,
                                                               "protobuf_varint_noncanonical"));
        }
        return Result<std::uint64_t>::success(value);
      }
    }
    return Result<std::uint64_t>::failure(endpoint_error(ErrorCode::protocol,
                                                         "protobuf_varint_overflow"));
  }

  std::span<const std::byte> input_;
  std::size_t offset_{};
};

template <std::size_t Size>
Result<void> copy_exact(std::span<const std::byte> input, std::array<std::byte, Size>& output,
                        const char* detail) {
  if (input.size() != Size) {
    return Result<void>::failure(endpoint_error(ErrorCode::protocol, detail));
  }
  std::copy_n(input.begin(), Size, output.begin());
  return Result<void>::success();
}

Result<RelayEndpointKey> parse_endpoint_message(std::span<const std::byte> input) {
  ProtoReader reader(input);
  DeviceId::Storage device{};
  EndpointId::Storage endpoint{};
  bool seen_device = false;
  bool seen_endpoint = false;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RelayEndpointKey>::failure(*field.error_if());
    }
    if (field.value_if()->wire_type != 2U) {
      return Result<RelayEndpointKey>::failure(
          endpoint_error(ErrorCode::protocol, "endpoint_field_invalid"));
    }
    if (field.value_if()->number == 1U) {
      if (seen_device) {
        return Result<RelayEndpointKey>::failure(
            endpoint_error(ErrorCode::protocol, "endpoint_field_conflict"));
      }
      auto copied = copy_exact(field.value_if()->bytes, device, "endpoint_device_id_invalid");
      if (!copied) {
        return Result<RelayEndpointKey>::failure(*copied.error_if());
      }
      seen_device = true;
    } else if (field.value_if()->number == 2U) {
      if (seen_endpoint) {
        return Result<RelayEndpointKey>::failure(
            endpoint_error(ErrorCode::protocol, "endpoint_field_conflict"));
      }
      auto copied = copy_exact(field.value_if()->bytes, endpoint, "endpoint_id_invalid");
      if (!copied) {
        return Result<RelayEndpointKey>::failure(*copied.error_if());
      }
      seen_endpoint = true;
    } else {
      return Result<RelayEndpointKey>::failure(
          endpoint_error(ErrorCode::protocol, "endpoint_unknown_field"));
    }
  }
  if (!seen_device || !seen_endpoint) {
    return Result<RelayEndpointKey>::failure(
        endpoint_error(ErrorCode::protocol, "endpoint_field_missing"));
  }
  return Result<RelayEndpointKey>::success(
      RelayEndpointKey{.device_id = DeviceId{device}, .endpoint_id = EndpointId{endpoint}});
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
          endpoint_error(ErrorCode::protocol, "signature_field_invalid"));
    }
    auto copied = copy_exact(field.value_if()->bytes, signature, "signature_length_invalid");
    if (!copied) {
      return Result<IdentitySignature>::failure(*copied.error_if());
    }
    seen = true;
  }
  if (!seen) {
    return Result<IdentitySignature>::failure(
        endpoint_error(ErrorCode::protocol, "signature_field_missing"));
  }
  return Result<IdentitySignature>::success(signature);
}

std::vector<std::byte> encode_endpoint_message(RelayEndpointKey endpoint) {
  std::vector<std::byte> output;
  append_bytes(output, 1U, endpoint.device_id.bytes());
  append_bytes(output, 2U, endpoint.endpoint_id.bytes());
  return output;
}

std::vector<std::byte> encode_signature_message(IdentitySignature signature) {
  std::vector<std::byte> output;
  append_bytes(output, 1U, signature);
  return output;
}

bool is_nonempty_utf8(std::string_view value) noexcept {
  if (value.empty() || value.size() > max_endpoint_application_id_bytes) {
    return false;
  }
  std::size_t index = 0U;
  while (index < value.size()) {
    const auto first = static_cast<unsigned char>(value[index]);
    if (first <= 0x7fU) {
      if (first < 0x20U) {
        return false;
      }
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

bool valid_record_shape(const RelayEndpointRecord& record) {
  return record.endpoint.device_id.is_zero() == false &&
         record.endpoint.endpoint_id.is_zero() == false &&
         is_nonempty_utf8(record.application_id) && record.record_generation != 0U &&
         record.manifest_sha256 != RelayManifestSha256{} &&
         record.expires_unix_milliseconds != 0U &&
         record.signature != IdentitySignature{};
}

bool valid_manifest_shape(const RelayServiceManifest& manifest) {
  return manifest.endpoint.device_id.is_zero() == false &&
         manifest.endpoint.endpoint_id.is_zero() == false &&
         manifest.manifest_generation != 0U &&
         manifest.canonical_manifest_sha256 != RelayManifestSha256{} &&
         manifest.expires_unix_milliseconds != 0U &&
         manifest.signature != IdentitySignature{};
}

}  // namespace

Result<std::vector<std::byte>> encode_relay_endpoint_record(
    const RelayEndpointRecord& record) {
  if (!valid_record_shape(record)) {
    return Result<std::vector<std::byte>>::failure(
        endpoint_error(ErrorCode::configuration, "endpoint_record_invalid"));
  }
  std::vector<std::byte> output;
  output.reserve(320U);
  append_bytes(output, 1U, encode_endpoint_message(record.endpoint));
  append_string(output, 2U, record.application_id);
  append_uint(output, 3U, record.record_generation);
  append_bytes(output, 4U, record.manifest_sha256);
  append_uint(output, 5U, record.expires_unix_milliseconds);
  append_bytes(output, 6U, encode_signature_message(record.signature));
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RelayEndpointRecord> parse_relay_endpoint_record(std::span<const std::byte> payload) {
  if (payload.empty() || payload.size() > max_endpoint_record_bytes) {
    return Result<RelayEndpointRecord>::failure(
        endpoint_error(ErrorCode::protocol, "endpoint_record_size_invalid"));
  }
  ProtoReader reader(payload);
  RelayEndpointRecord record;
  std::array<bool, 6U> seen{};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RelayEndpointRecord>::failure(*field.error_if());
    }
    if (field.value_if()->number == 0U || field.value_if()->number > seen.size() ||
        seen[field.value_if()->number - 1U]) {
      return Result<RelayEndpointRecord>::failure(
          endpoint_error(ErrorCode::protocol, "endpoint_record_field_conflict"));
    }
    seen[field.value_if()->number - 1U] = true;
    switch (field.value_if()->number) {
      case 1U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<RelayEndpointRecord>::failure(
              endpoint_error(ErrorCode::protocol, "endpoint_record_endpoint_invalid"));
        }
        auto endpoint = parse_endpoint_message(field.value_if()->bytes);
        if (!endpoint) {
          return Result<RelayEndpointRecord>::failure(*endpoint.error_if());
        }
        record.endpoint = *endpoint.value_if();
        break;
      }
      case 2U: {
        if (field.value_if()->wire_type != 2U || field.value_if()->bytes.empty() ||
            field.value_if()->bytes.size() > max_endpoint_application_id_bytes) {
          return Result<RelayEndpointRecord>::failure(
              endpoint_error(ErrorCode::protocol, "endpoint_application_id_invalid"));
        }
        const auto* text = reinterpret_cast<const char*>(field.value_if()->bytes.data());
        record.application_id.assign(text, field.value_if()->bytes.size());
        break;
      }
      case 3U:
        if (field.value_if()->wire_type != 0U || field.value_if()->integer == 0U) {
          return Result<RelayEndpointRecord>::failure(
              endpoint_error(ErrorCode::protocol, "endpoint_record_generation_invalid"));
        }
        record.record_generation = field.value_if()->integer;
        break;
      case 4U: {
        auto copied = field.value_if()->wire_type == 2U
                          ? copy_exact(field.value_if()->bytes, record.manifest_sha256,
                                       "endpoint_manifest_hash_invalid")
                          : Result<void>::failure(endpoint_error(
                                ErrorCode::protocol, "endpoint_manifest_hash_invalid"));
        if (!copied) {
          return Result<RelayEndpointRecord>::failure(*copied.error_if());
        }
        break;
      }
      case 5U:
        if (field.value_if()->wire_type != 0U || field.value_if()->integer == 0U) {
          return Result<RelayEndpointRecord>::failure(
              endpoint_error(ErrorCode::protocol, "endpoint_record_expiry_invalid"));
        }
        record.expires_unix_milliseconds = field.value_if()->integer;
        break;
      case 6U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<RelayEndpointRecord>::failure(
              endpoint_error(ErrorCode::protocol, "endpoint_record_signature_invalid"));
        }
        auto signature = parse_signature_message(field.value_if()->bytes);
        if (!signature) {
          return Result<RelayEndpointRecord>::failure(*signature.error_if());
        }
        record.signature = *signature.value_if();
        break;
      }
      default:
        return Result<RelayEndpointRecord>::failure(
            endpoint_error(ErrorCode::protocol, "endpoint_record_unknown_field"));
    }
  }
  if (!std::all_of(seen.begin(), seen.end(), [](bool value) { return value; })) {
    return Result<RelayEndpointRecord>::failure(
        endpoint_error(ErrorCode::protocol, "endpoint_record_field_missing"));
  }
  return Result<RelayEndpointRecord>::success(std::move(record));
}

Result<std::vector<std::byte>> canonical_relay_endpoint_record(
    const RelayEndpointRecord& record) {
  std::vector<CanonicalField> fields;
  fields.reserve(6U);
  fields.push_back(CanonicalField{1U, canonical_bytes(record.endpoint.device_id)});
  fields.push_back(CanonicalField{2U, canonical_bytes(record.endpoint.endpoint_id)});
  fields.push_back(CanonicalField{
      3U, std::vector<std::byte>{reinterpret_cast<const std::byte*>(record.application_id.data()),
                                 reinterpret_cast<const std::byte*>(record.application_id.data()) +
                                     record.application_id.size()}});
  fields.push_back(CanonicalField{4U, canonical_uint64(record.record_generation)});
  fields.push_back(CanonicalField{
      5U, {record.manifest_sha256.begin(), record.manifest_sha256.end()}});
  fields.push_back(CanonicalField{6U, canonical_uint64(record.expires_unix_milliseconds)});
  return canonicalize_for_signature(SigningDomain::endpoint_record, fields);
}

Result<void> sign_relay_endpoint_record(RelayEndpointRecord& record,
                                        const IdentityKeyPair& identity) {
  auto canonical = canonical_relay_endpoint_record(record);
  if (!canonical) {
    return Result<void>::failure(*canonical.error_if());
  }
  auto signature = sign_identity_message(identity, *canonical.value_if());
  if (!signature) {
    return Result<void>::failure(*signature.error_if());
  }
  record.signature = *signature.value_if();
  return Result<void>::success();
}

Result<void> validate_relay_endpoint_record(const RelayEndpointRecord& record,
                                            const RelayDeviceRecord& device,
                                            std::uint64_t now_unix_milliseconds) {
  if (!valid_record_shape(record) || device.device_id != record.endpoint.device_id) {
    return Result<void>::failure(
        endpoint_error(ErrorCode::authentication, "endpoint_record_invalid"));
  }
  if (device.status == RelayDeviceStatus::revoked) {
    return Result<void>::failure(
        endpoint_error(ErrorCode::enrollment_revoked, "endpoint_record_device_revoked"));
  }
  auto expiry = validate_signed_expiry(record.expires_unix_milliseconds,
                                       now_unix_milliseconds);
  if (!expiry) {
    return Result<void>::failure(
        Error{ErrorCode::authentication, "relay_endpoint",
              std::string{expiry.error_if()->safe_detail()}});
  }
  auto canonical = canonical_relay_endpoint_record(record);
  if (!canonical) {
    return Result<void>::failure(
        Error{ErrorCode::protocol, "relay_endpoint",
              std::string{canonical.error_if()->safe_detail()}});
  }
  return verify_identity_signature(device.public_key, *canonical.value_if(),
                                   record.signature);
}

Result<std::vector<std::byte>> encode_relay_service_manifest(
    const RelayServiceManifest& manifest) {
  if (!valid_manifest_shape(manifest)) {
    return Result<std::vector<std::byte>>::failure(
        endpoint_error(ErrorCode::configuration, "service_manifest_invalid"));
  }
  std::vector<std::byte> output;
  output.reserve(192U);
  append_bytes(output, 1U, encode_endpoint_message(manifest.endpoint));
  append_uint(output, 2U, manifest.manifest_generation);
  append_bytes(output, 3U, manifest.canonical_manifest_sha256);
  append_uint(output, 4U, manifest.expires_unix_milliseconds);
  append_bytes(output, 5U, encode_signature_message(manifest.signature));
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RelayServiceManifest> parse_relay_service_manifest(std::span<const std::byte> payload) {
  if (payload.empty() || payload.size() > max_service_manifest_bytes) {
    return Result<RelayServiceManifest>::failure(
        endpoint_error(ErrorCode::protocol, "service_manifest_size_invalid"));
  }
  ProtoReader reader(payload);
  RelayServiceManifest manifest;
  std::array<bool, 5U> seen{};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RelayServiceManifest>::failure(*field.error_if());
    }
    if (field.value_if()->number == 0U || field.value_if()->number > seen.size() ||
        seen[field.value_if()->number - 1U]) {
      return Result<RelayServiceManifest>::failure(
          endpoint_error(ErrorCode::protocol, "service_manifest_field_conflict"));
    }
    seen[field.value_if()->number - 1U] = true;
    switch (field.value_if()->number) {
      case 1U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<RelayServiceManifest>::failure(
              endpoint_error(ErrorCode::protocol, "service_manifest_endpoint_invalid"));
        }
        auto endpoint = parse_endpoint_message(field.value_if()->bytes);
        if (!endpoint) {
          return Result<RelayServiceManifest>::failure(*endpoint.error_if());
        }
        manifest.endpoint = *endpoint.value_if();
        break;
      }
      case 2U:
        if (field.value_if()->wire_type != 0U || field.value_if()->integer == 0U) {
          return Result<RelayServiceManifest>::failure(
              endpoint_error(ErrorCode::protocol, "manifest_generation_invalid"));
        }
        manifest.manifest_generation = field.value_if()->integer;
        break;
      case 3U: {
        auto copied = field.value_if()->wire_type == 2U
                          ? copy_exact(field.value_if()->bytes,
                                       manifest.canonical_manifest_sha256,
                                       "manifest_hash_invalid")
                          : Result<void>::failure(
                                endpoint_error(ErrorCode::protocol, "manifest_hash_invalid"));
        if (!copied) {
          return Result<RelayServiceManifest>::failure(*copied.error_if());
        }
        break;
      }
      case 4U:
        if (field.value_if()->wire_type != 0U || field.value_if()->integer == 0U) {
          return Result<RelayServiceManifest>::failure(
              endpoint_error(ErrorCode::protocol, "manifest_expiry_invalid"));
        }
        manifest.expires_unix_milliseconds = field.value_if()->integer;
        break;
      case 5U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<RelayServiceManifest>::failure(
              endpoint_error(ErrorCode::protocol, "manifest_signature_invalid"));
        }
        auto signature = parse_signature_message(field.value_if()->bytes);
        if (!signature) {
          return Result<RelayServiceManifest>::failure(*signature.error_if());
        }
        manifest.signature = *signature.value_if();
        break;
      }
      default:
        return Result<RelayServiceManifest>::failure(
            endpoint_error(ErrorCode::protocol, "service_manifest_unknown_field"));
    }
  }
  if (!std::all_of(seen.begin(), seen.end(), [](bool value) { return value; })) {
    return Result<RelayServiceManifest>::failure(
        endpoint_error(ErrorCode::protocol, "service_manifest_field_missing"));
  }
  return Result<RelayServiceManifest>::success(std::move(manifest));
}

Result<std::vector<std::byte>> canonical_relay_service_manifest(
    const RelayServiceManifest& manifest) {
  std::vector<CanonicalField> fields;
  fields.reserve(5U);
  fields.push_back(CanonicalField{1U, canonical_bytes(manifest.endpoint.device_id)});
  fields.push_back(CanonicalField{2U, canonical_bytes(manifest.endpoint.endpoint_id)});
  fields.push_back(CanonicalField{3U, canonical_uint64(manifest.manifest_generation)});
  fields.push_back(CanonicalField{
      4U, {manifest.canonical_manifest_sha256.begin(),
           manifest.canonical_manifest_sha256.end()}});
  fields.push_back(CanonicalField{5U, canonical_uint64(manifest.expires_unix_milliseconds)});
  return canonicalize_for_signature(SigningDomain::service_manifest, fields);
}

Result<void> sign_relay_service_manifest(RelayServiceManifest& manifest,
                                         const IdentityKeyPair& identity) {
  auto canonical = canonical_relay_service_manifest(manifest);
  if (!canonical) {
    return Result<void>::failure(*canonical.error_if());
  }
  auto signature = sign_identity_message(identity, *canonical.value_if());
  if (!signature) {
    return Result<void>::failure(*signature.error_if());
  }
  manifest.signature = *signature.value_if();
  return Result<void>::success();
}

Result<void> validate_relay_service_manifest(
    const RelayServiceManifest& manifest, const RelayDeviceRecord& device,
    std::uint64_t now_unix_milliseconds,
    const std::optional<RelayEndpointRecord>& bound_record) {
  if (!valid_manifest_shape(manifest) || device.device_id != manifest.endpoint.device_id) {
    return Result<void>::failure(
        endpoint_error(ErrorCode::authentication, "service_manifest_invalid"));
  }
  if (device.status == RelayDeviceStatus::revoked) {
    return Result<void>::failure(
        endpoint_error(ErrorCode::enrollment_revoked, "service_manifest_device_revoked"));
  }
  if (bound_record &&
      (bound_record->endpoint != manifest.endpoint ||
       bound_record->manifest_sha256 != manifest.canonical_manifest_sha256)) {
    return Result<void>::failure(
        endpoint_error(ErrorCode::authentication, "service_manifest_record_mismatch"));
  }
  auto expiry = validate_signed_expiry(manifest.expires_unix_milliseconds,
                                       now_unix_milliseconds);
  if (!expiry) {
    return Result<void>::failure(
        Error{ErrorCode::authentication, "relay_endpoint",
              std::string{expiry.error_if()->safe_detail()}});
  }
  auto canonical = canonical_relay_service_manifest(manifest);
  if (!canonical) {
    return Result<void>::failure(
        Error{ErrorCode::protocol, "relay_endpoint",
              std::string{canonical.error_if()->safe_detail()}});
  }
  return verify_identity_signature(device.public_key, *canonical.value_if(),
                                   manifest.signature);
}

Result<RelayEndpointPublication> publish_relay_endpoint(
    const RelayEndpointRecord& record,
    const std::optional<RelayServiceManifest>& manifest,
    const RelayTenantExposurePolicy& policy, std::uint64_t now_unix_milliseconds) {
  if (!valid_record_shape(record)) {
    return Result<RelayEndpointPublication>::failure(
        endpoint_error(ErrorCode::configuration, "endpoint_record_invalid"));
  }
  auto record_expiry = validate_signed_expiry(record.expires_unix_milliseconds,
                                              now_unix_milliseconds);
  if (!record_expiry) {
    return Result<RelayEndpointPublication>::failure(
        Error{ErrorCode::authentication, "relay_endpoint",
              std::string{record_expiry.error_if()->safe_detail()}});
  }
  if (manifest) {
    if (!valid_manifest_shape(*manifest) || manifest->endpoint != record.endpoint ||
        manifest->canonical_manifest_sha256 != record.manifest_sha256) {
      return Result<RelayEndpointPublication>::failure(
          endpoint_error(ErrorCode::authentication, "service_manifest_record_mismatch"));
    }
    auto manifest_expiry = validate_signed_expiry(manifest->expires_unix_milliseconds,
                                                  now_unix_milliseconds);
    if (!manifest_expiry) {
      return Result<RelayEndpointPublication>::failure(
          Error{ErrorCode::authentication, "relay_endpoint",
                std::string{manifest_expiry.error_if()->safe_detail()}});
    }
  }

  RelayEndpointPublication publication;
  publication.endpoint = record.endpoint;
  if (policy.expose_application_id) {
    publication.application_id = record.application_id;
  }
  if (policy.expose_record_generation) {
    publication.record_generation = record.record_generation;
  }
  if (policy.expose_manifest_sha256) {
    publication.manifest_sha256 = record.manifest_sha256;
  }
  if (manifest && policy.expose_manifest_generation) {
    publication.manifest_generation = manifest->manifest_generation;
  }
  if (policy.expose_expiry) {
    publication.expires_unix_milliseconds = record.expires_unix_milliseconds;
  }
  return Result<RelayEndpointPublication>::success(std::move(publication));
}

}  // namespace heyaki
