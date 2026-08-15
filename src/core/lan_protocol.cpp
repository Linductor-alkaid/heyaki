#include <heyaki/lan_protocol.hpp>

#include <heyaki/signing.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

Error lan_protocol_error(ErrorCode code, const char* detail) {
  return {code, "lan_discovery", detail};
}

Error lan_signaling_error(ErrorCode code, const char* detail) {
  return {code, "lan_signaling", detail};
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

void append_message(std::vector<std::byte>& output, std::uint32_t field,
                    const std::vector<std::byte>& value) {
  append_bytes(output, field, value);
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
      return Result<ProtoField>::failure(
          lan_protocol_error(ErrorCode::protocol, "protobuf_tag_invalid"));
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
        return Result<ProtoField>::failure(
            lan_protocol_error(ErrorCode::protocol, "protobuf_length_invalid"));
      }
      const auto count = static_cast<std::size_t>(*length.value_if());
      field.bytes = input_.subspan(offset_, count);
      offset_ += count;
      return Result<ProtoField>::success(field);
    }
    return Result<ProtoField>::failure(
        lan_protocol_error(ErrorCode::protocol, "protobuf_wire_type_unsupported"));
  }

 private:
  Result<std::uint64_t> read_varint() {
    std::uint64_t value = 0U;
    for (std::size_t index = 0U; index < 10U; ++index) {
      if (offset_ >= input_.size()) {
        return Result<std::uint64_t>::failure(
            lan_protocol_error(ErrorCode::protocol, "protobuf_varint_truncated"));
      }
      const auto byte = std::to_integer<std::uint8_t>(input_[offset_++]);
      if (index == 9U && (byte & 0xfeU) != 0U) {
        return Result<std::uint64_t>::failure(
            lan_protocol_error(ErrorCode::protocol, "protobuf_varint_overflow"));
      }
      value |= static_cast<std::uint64_t>(byte & 0x7fU) << (7U * index);
      if ((byte & 0x80U) == 0U) {
        if (index > 0U && (byte & 0x7fU) == 0U) {
          return Result<std::uint64_t>::failure(
              lan_protocol_error(ErrorCode::protocol, "protobuf_varint_noncanonical"));
        }
        return Result<std::uint64_t>::success(value);
      }
    }
    return Result<std::uint64_t>::failure(
        lan_protocol_error(ErrorCode::protocol, "protobuf_varint_overflow"));
  }

  std::span<const std::byte> input_;
  std::size_t offset_{};
};

Result<std::pair<std::uint32_t, std::uint32_t>> parse_protocol_version(
    std::span<const std::byte> bytes) {
  ProtoReader reader(bytes);
  std::optional<std::uint32_t> major;
  std::optional<std::uint32_t> minor;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<std::pair<std::uint32_t, std::uint32_t>>::failure(*field.error_if());
    }
    if (field.value_if()->wire_type != 0U || field.value_if()->integer >
                                                  std::numeric_limits<std::uint32_t>::max()) {
      return Result<std::pair<std::uint32_t, std::uint32_t>>::failure(
          lan_protocol_error(ErrorCode::protocol, "protocol_version_field_invalid"));
    }
    auto& destination = field.value_if()->number == 1U ? major : minor;
    if ((field.value_if()->number != 1U && field.value_if()->number != 2U) || destination) {
      return Result<std::pair<std::uint32_t, std::uint32_t>>::failure(
          lan_protocol_error(ErrorCode::protocol, "protocol_version_field_conflict"));
    }
    destination = static_cast<std::uint32_t>(field.value_if()->integer);
  }
  if (!major || !minor) {
    return Result<std::pair<std::uint32_t, std::uint32_t>>::failure(
        lan_protocol_error(ErrorCode::protocol, "protocol_version_missing"));
  }
  return Result<std::pair<std::uint32_t, std::uint32_t>>::success({*major, *minor});
}

Result<std::pair<std::uint64_t, std::uint64_t>> parse_capabilities(
    std::span<const std::byte> bytes) {
  ProtoReader reader(bytes);
  std::optional<std::uint64_t> supported;
  std::optional<std::uint64_t> required;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<std::pair<std::uint64_t, std::uint64_t>>::failure(*field.error_if());
    }
    if (field.value_if()->wire_type != 0U) {
      return Result<std::pair<std::uint64_t, std::uint64_t>>::failure(
          lan_protocol_error(ErrorCode::protocol, "capability_field_invalid"));
    }
    auto& destination = field.value_if()->number == 1U ? supported : required;
    if ((field.value_if()->number != 1U && field.value_if()->number != 2U) || destination) {
      return Result<std::pair<std::uint64_t, std::uint64_t>>::failure(
          lan_protocol_error(ErrorCode::protocol, "capability_field_conflict"));
    }
    destination = field.value_if()->integer;
  }
  if (!supported || !required) {
    return Result<std::pair<std::uint64_t, std::uint64_t>>::failure(
        lan_protocol_error(ErrorCode::protocol, "capability_field_missing"));
  }
  return Result<std::pair<std::uint64_t, std::uint64_t>>::success({*supported, *required});
}

Result<void> copy_exact(std::span<const std::byte> source, std::span<std::byte> destination,
                        const char* detail);

Result<IdentitySignature> parse_signature(std::span<const std::byte> bytes) {
  ProtoReader reader(bytes);
  std::optional<IdentitySignature> signature;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<IdentitySignature>::failure(*field.error_if());
    }
    if (field.value_if()->number != 1U || field.value_if()->wire_type != 2U || signature ||
        field.value_if()->bytes.size() != ed25519_signature_bytes) {
      return Result<IdentitySignature>::failure(
          lan_protocol_error(ErrorCode::protocol, "presence_signature_field_invalid"));
    }
    IdentitySignature value{};
    std::copy(field.value_if()->bytes.begin(), field.value_if()->bytes.end(), value.begin());
    signature = value;
  }
  if (!signature) {
    return Result<IdentitySignature>::failure(
        lan_protocol_error(ErrorCode::protocol, "presence_signature_missing"));
  }
  return Result<IdentitySignature>::success(*signature);
}

Result<std::pair<DeviceId, EndpointId>> parse_device_endpoint_fields(
    std::span<const std::byte> bytes) {
  ProtoReader reader(bytes);
  std::optional<DeviceId> device_id;
  std::optional<EndpointId> endpoint_id;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<std::pair<DeviceId, EndpointId>>::failure(*field.error_if());
    }
    if (field.value_if()->wire_type != 2U) {
      return Result<std::pair<DeviceId, EndpointId>>::failure(
          lan_protocol_error(ErrorCode::protocol, "hello_endpoint_field_invalid"));
    }
    if (field.value_if()->number == 1U && !device_id) {
      DeviceId::Storage value{};
      auto copied = copy_exact(field.value_if()->bytes, value, "hello_device_id_invalid");
      if (!copied) {
        return Result<std::pair<DeviceId, EndpointId>>::failure(*copied.error_if());
      }
      device_id = DeviceId{value};
    } else if (field.value_if()->number == 2U && !endpoint_id) {
      EndpointId::Storage value{};
      auto copied = copy_exact(field.value_if()->bytes, value, "hello_endpoint_id_invalid");
      if (!copied) {
        return Result<std::pair<DeviceId, EndpointId>>::failure(*copied.error_if());
      }
      endpoint_id = EndpointId{value};
    } else {
      return Result<std::pair<DeviceId, EndpointId>>::failure(
          lan_protocol_error(ErrorCode::protocol, "hello_endpoint_field_conflict"));
    }
  }
  if (!device_id || !endpoint_id) {
    return Result<std::pair<DeviceId, EndpointId>>::failure(
        lan_protocol_error(ErrorCode::protocol, "hello_endpoint_field_missing"));
  }
  return Result<std::pair<DeviceId, EndpointId>>::success({*device_id, *endpoint_id});
}

std::vector<std::byte> encode_device_endpoint(const DeviceId& device_id,
                                              const EndpointId& endpoint_id) {
  std::vector<std::byte> output;
  append_bytes(output, 1U, device_id.bytes());
  append_bytes(output, 2U, endpoint_id.bytes());
  return output;
}

template <std::size_t Size>
bool all_zero(const std::array<std::byte, Size>& value) noexcept {
  return std::all_of(value.begin(), value.end(), [](std::byte byte) {
    return byte == std::byte{0};
  });
}

bool is_known_lan_signaling_kind(LanSignalingMessageKind kind) noexcept {
  switch (kind) {
    case LanSignalingMessageKind::connect_request:
    case LanSignalingMessageKind::connect_accept:
    case LanSignalingMessageKind::connect_deny:
    case LanSignalingMessageKind::signed_offer:
    case LanSignalingMessageKind::signed_answer:
    case LanSignalingMessageKind::signed_candidate:
      return true;
  }
  return false;
}

bool is_signed_lan_signaling_kind(LanSignalingMessageKind kind) noexcept {
  return kind == LanSignalingMessageKind::signed_offer ||
         kind == LanSignalingMessageKind::signed_answer ||
         kind == LanSignalingMessageKind::signed_candidate;
}

Result<void> copy_exact(std::span<const std::byte> source, std::span<std::byte> destination,
                        const char* detail) {
  if (source.size() != destination.size()) {
    return Result<void>::failure(lan_protocol_error(ErrorCode::protocol, detail));
  }
  std::copy(source.begin(), source.end(), destination.begin());
  return Result<void>::success();
}

}  // namespace

Result<void> validate_lan_signaling_frame(const LanSignalingFrame& frame) {
  if (!is_known_lan_signaling_kind(frame.kind)) {
    return Result<void>::failure(
        lan_signaling_error(ErrorCode::protocol, "signaling_kind_invalid"));
  }
  if (frame.request_id.is_zero()) {
    return Result<void>::failure(
        lan_signaling_error(ErrorCode::protocol, "signaling_request_id_invalid"));
  }
  if (frame.payload.size() > max_lan_signaling_payload_bytes) {
    return Result<void>::failure(lan_signaling_error(
        ErrorCode::resource_exhausted, "signaling_payload_too_large"));
  }
  if (is_signed_lan_signaling_kind(frame.kind)) {
    if (frame.payload.empty()) {
      return Result<void>::failure(
          lan_signaling_error(ErrorCode::protocol, "signed_signaling_empty"));
    }
  } else if (!frame.payload.empty()) {
    return Result<void>::failure(lan_signaling_error(
        ErrorCode::protocol, "connect_control_payload_invalid"));
  }
  return Result<void>::success();
}

Result<std::vector<std::byte>> encode_lan_signaling_frame(
    const LanSignalingFrame& frame) {
  auto valid = validate_lan_signaling_frame(frame);
  if (!valid) {
    return Result<std::vector<std::byte>>::failure(*valid.error_if());
  }

  const auto body_size = lan_signaling_frame_fixed_body_bytes + frame.payload.size();
  const auto encoded_body_size = static_cast<std::uint32_t>(body_size);
  std::vector<std::byte> output;
  output.reserve(lan_signaling_frame_header_bytes + body_size);
  output.push_back(static_cast<std::byte>((encoded_body_size >> 24U) & 0xffU));
  output.push_back(static_cast<std::byte>((encoded_body_size >> 16U) & 0xffU));
  output.push_back(static_cast<std::byte>((encoded_body_size >> 8U) & 0xffU));
  output.push_back(static_cast<std::byte>(encoded_body_size & 0xffU));
  output.push_back(static_cast<std::byte>(frame.kind));
  output.insert(output.end(), frame.request_id.bytes().begin(),
                frame.request_id.bytes().end());
  output.insert(output.end(), frame.payload.begin(), frame.payload.end());
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<LanSignalingFrame> parse_lan_signaling_frame(
    std::span<const std::byte> input) {
  if (input.size() < lan_signaling_frame_header_bytes) {
    return Result<LanSignalingFrame>::failure(
        lan_signaling_error(ErrorCode::protocol, "signaling_frame_truncated"));
  }
  const auto body_size =
      (static_cast<std::size_t>(std::to_integer<std::uint8_t>(input[0])) << 24U) |
      (static_cast<std::size_t>(std::to_integer<std::uint8_t>(input[1])) << 16U) |
      (static_cast<std::size_t>(std::to_integer<std::uint8_t>(input[2])) << 8U) |
      static_cast<std::size_t>(std::to_integer<std::uint8_t>(input[3]));
  if (body_size < lan_signaling_frame_fixed_body_bytes ||
      body_size > max_lan_signaling_body_bytes) {
    return Result<LanSignalingFrame>::failure(
        lan_signaling_error(ErrorCode::protocol, "signaling_length_invalid"));
  }
  const auto frame_size = lan_signaling_frame_header_bytes + body_size;
  if (input.size() < frame_size) {
    return Result<LanSignalingFrame>::failure(
        lan_signaling_error(ErrorCode::protocol, "signaling_frame_truncated"));
  }
  if (input.size() > frame_size) {
    return Result<LanSignalingFrame>::failure(
        lan_signaling_error(ErrorCode::protocol, "signaling_frame_trailing_bytes"));
  }

  RequestId::Storage request_bytes{};
  const auto body = input.subspan(lan_signaling_frame_header_bytes);
  std::copy_n(body.begin() + 1, RequestId::size_bytes, request_bytes.begin());
  LanSignalingFrame frame;
  frame.kind = static_cast<LanSignalingMessageKind>(
      std::to_integer<std::uint8_t>(body.front()));
  frame.request_id = RequestId{request_bytes};
  frame.payload.assign(
      body.begin() + static_cast<std::ptrdiff_t>(lan_signaling_frame_fixed_body_bytes),
      body.end());
  auto valid = validate_lan_signaling_frame(frame);
  if (!valid) {
    return Result<LanSignalingFrame>::failure(*valid.error_if());
  }
  return Result<LanSignalingFrame>::success(std::move(frame));
}

Result<std::vector<std::byte>> canonical_lan_presence(const LanPresence& presence) {
  const std::array fields{
      CanonicalField{1U, canonical_uint32(presence.protocol_version.major)},
      CanonicalField{2U, canonical_uint32(presence.protocol_version.minor)},
      CanonicalField{3U, canonical_uint64(presence.supported.bits)},
      CanonicalField{4U, canonical_uint64(presence.required.bits)},
      CanonicalField{5U, canonical_bytes(presence.device_id)},
      CanonicalField{6U, std::vector<std::byte>(presence.identity_public_key.begin(),
                                               presence.identity_public_key.end())},
      CanonicalField{7U, canonical_bytes(presence.endpoint_id)},
      CanonicalField{8U, std::vector<std::byte>(presence.boot_nonce.begin(),
                                               presence.boot_nonce.end())},
      CanonicalField{9U, canonical_uint64(presence.sequence)},
      CanonicalField{10U, canonical_uint16(presence.tls_signaling_port)},
      CanonicalField{11U, canonical_uint32(static_cast<std::uint32_t>(presence.lease.count()))}};
  return canonicalize_for_signature(SigningDomain::lan_presence, fields);
}

Result<void> sign_lan_presence(LanPresence& presence, const IdentityKeyPair& identity) {
  presence.device_id = identity.device_id();
  presence.identity_public_key = identity.public_key();
  auto canonical = canonical_lan_presence(presence);
  if (!canonical) {
    return Result<void>::failure(*canonical.error_if());
  }
  auto signature = sign_identity_message(identity, *canonical.value_if());
  if (!signature) {
    return Result<void>::failure(*signature.error_if());
  }
  presence.signature = *signature.value_if();
  return Result<void>::success();
}

Result<void> validate_lan_presence(const LanPresence& presence) {
  const auto discovery_bit = static_cast<std::uint64_t>(Capability::lan_discovery_v1);
  const auto signaling_bit = static_cast<std::uint64_t>(Capability::lan_signaling_v1);
  if (presence.protocol_version.major != current_protocol_version.major ||
      presence.protocol_version.minor < current_protocol_version.minor ||
      (presence.supported.bits & (discovery_bit | signaling_bit)) !=
          (discovery_bit | signaling_bit) ||
      (presence.required.bits & ~presence.supported.bits) != 0U ||
      (presence.required.bits & ~known_capability_bits) != 0U ||
      presence.device_id.is_zero() || presence.endpoint_id.is_zero() ||
      all_zero(presence.boot_nonce) || presence.sequence == 0U ||
      presence.tls_signaling_port == 0U ||
      presence.lease < std::chrono::milliseconds{min_lan_presence_lease_milliseconds} ||
      presence.lease > std::chrono::milliseconds{max_lan_presence_lease_milliseconds}) {
    return Result<void>::failure(
        lan_protocol_error(ErrorCode::protocol, "presence_fields_invalid"));
  }
  auto derived = derive_device_id(presence.identity_public_key);
  if (!derived || *derived.value_if() != presence.device_id) {
    return Result<void>::failure(
        lan_protocol_error(ErrorCode::authentication, "presence_device_id_mismatch"));
  }
  auto canonical = canonical_lan_presence(presence);
  if (!canonical) {
    return Result<void>::failure(*canonical.error_if());
  }
  auto verified = verify_identity_signature(presence.identity_public_key, *canonical.value_if(),
                                            presence.signature);
  if (!verified) {
    return Result<void>::failure(
        lan_protocol_error(ErrorCode::authentication, "presence_signature_invalid"));
  }
  return Result<void>::success();
}

Result<std::vector<std::byte>> encode_lan_presence(const LanPresence& presence) {
  auto valid = validate_lan_presence(presence);
  if (!valid) {
    return Result<std::vector<std::byte>>::failure(*valid.error_if());
  }
  std::vector<std::byte> version;
  append_uint(version, 1U, presence.protocol_version.major);
  append_uint(version, 2U, presence.protocol_version.minor);
  std::vector<std::byte> capabilities;
  append_uint(capabilities, 1U, presence.supported.bits);
  append_uint(capabilities, 2U, presence.required.bits);
  std::vector<std::byte> signature;
  append_bytes(signature, 1U, presence.signature);

  std::vector<std::byte> output;
  output.reserve(256U);
  append_message(output, 1U, version);
  append_message(output, 2U, capabilities);
  append_bytes(output, 3U, presence.device_id.bytes());
  append_bytes(output, 4U, presence.identity_public_key);
  append_bytes(output, 5U, presence.endpoint_id.bytes());
  append_bytes(output, 6U, presence.boot_nonce);
  append_uint(output, 7U, presence.sequence);
  append_uint(output, 8U, presence.tls_signaling_port);
  append_uint(output, 9U, static_cast<std::uint32_t>(presence.lease.count()));
  append_message(output, 10U, signature);
  if (output.size() > max_lan_datagram_payload_bytes) {
    return Result<std::vector<std::byte>>::failure(
        lan_protocol_error(ErrorCode::resource_exhausted, "presence_payload_too_large"));
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<LanPresence> parse_lan_presence(std::span<const std::byte> payload) {
  if (payload.empty() || payload.size() > max_lan_datagram_payload_bytes) {
    return Result<LanPresence>::failure(
        lan_protocol_error(ErrorCode::protocol, "presence_payload_size_invalid"));
  }
  ProtoReader reader(payload);
  LanPresence presence;
  std::array<bool, 10U> seen{};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<LanPresence>::failure(*field.error_if());
    }
    if (field.value_if()->number == 0U || field.value_if()->number > seen.size() ||
        seen[field.value_if()->number - 1U]) {
      return Result<LanPresence>::failure(
          lan_protocol_error(ErrorCode::protocol, "presence_field_conflict"));
    }
    seen[field.value_if()->number - 1U] = true;
    switch (field.value_if()->number) {
      case 1U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<LanPresence>::failure(
              lan_protocol_error(ErrorCode::protocol, "presence_version_invalid"));
        }
        auto version = parse_protocol_version(field.value_if()->bytes);
        if (!version) {
          return Result<LanPresence>::failure(*version.error_if());
        }
        presence.protocol_version = {version.value_if()->first, version.value_if()->second};
        break;
      }
      case 2U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<LanPresence>::failure(
              lan_protocol_error(ErrorCode::protocol, "presence_capabilities_invalid"));
        }
        auto capabilities = parse_capabilities(field.value_if()->bytes);
        if (!capabilities) {
          return Result<LanPresence>::failure(*capabilities.error_if());
        }
        presence.supported.bits = capabilities.value_if()->first;
        presence.required.bits = capabilities.value_if()->second;
        break;
      }
      case 3U: {
        DeviceId::Storage bytes{};
        auto copied = field.value_if()->wire_type == 2U
                          ? copy_exact(field.value_if()->bytes, bytes, "presence_device_id_invalid")
                          : Result<void>::failure(lan_protocol_error(
                                ErrorCode::protocol, "presence_device_id_invalid"));
        if (!copied) {
          return Result<LanPresence>::failure(*copied.error_if());
        }
        presence.device_id = DeviceId{bytes};
        break;
      }
      case 4U: {
        auto copied = field.value_if()->wire_type == 2U
                          ? copy_exact(field.value_if()->bytes, presence.identity_public_key,
                                       "presence_public_key_invalid")
                          : Result<void>::failure(lan_protocol_error(
                                ErrorCode::protocol, "presence_public_key_invalid"));
        if (!copied) {
          return Result<LanPresence>::failure(*copied.error_if());
        }
        break;
      }
      case 5U: {
        EndpointId::Storage bytes{};
        auto copied = field.value_if()->wire_type == 2U
                          ? copy_exact(field.value_if()->bytes, bytes, "presence_endpoint_invalid")
                          : Result<void>::failure(lan_protocol_error(
                                ErrorCode::protocol, "presence_endpoint_invalid"));
        if (!copied) {
          return Result<LanPresence>::failure(*copied.error_if());
        }
        presence.endpoint_id = EndpointId{bytes};
        break;
      }
      case 6U: {
        auto copied = field.value_if()->wire_type == 2U
                          ? copy_exact(field.value_if()->bytes, presence.boot_nonce,
                                       "presence_boot_nonce_invalid")
                          : Result<void>::failure(lan_protocol_error(
                                ErrorCode::protocol, "presence_boot_nonce_invalid"));
        if (!copied) {
          return Result<LanPresence>::failure(*copied.error_if());
        }
        break;
      }
      case 7U:
        if (field.value_if()->wire_type != 0U) {
          return Result<LanPresence>::failure(
              lan_protocol_error(ErrorCode::protocol, "presence_sequence_invalid"));
        }
        presence.sequence = field.value_if()->integer;
        break;
      case 8U:
        if (field.value_if()->wire_type != 0U ||
            field.value_if()->integer > std::numeric_limits<std::uint16_t>::max()) {
          return Result<LanPresence>::failure(
              lan_protocol_error(ErrorCode::protocol, "presence_port_invalid"));
        }
        presence.tls_signaling_port = static_cast<std::uint16_t>(field.value_if()->integer);
        break;
      case 9U:
        if (field.value_if()->wire_type != 0U ||
            field.value_if()->integer > std::numeric_limits<std::uint32_t>::max()) {
          return Result<LanPresence>::failure(
              lan_protocol_error(ErrorCode::protocol, "presence_lease_invalid"));
        }
        presence.lease = std::chrono::milliseconds{field.value_if()->integer};
        break;
      case 10U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<LanPresence>::failure(
              lan_protocol_error(ErrorCode::protocol, "presence_signature_invalid"));
        }
        auto signature = parse_signature(field.value_if()->bytes);
        if (!signature) {
          return Result<LanPresence>::failure(*signature.error_if());
        }
        presence.signature = *signature.value_if();
        break;
      }
      default:
        return Result<LanPresence>::failure(
            lan_protocol_error(ErrorCode::protocol, "presence_unknown_field"));
    }
  }
  if (!std::all_of(seen.begin(), seen.end(), [](bool value) { return value; })) {
    return Result<LanPresence>::failure(
        lan_protocol_error(ErrorCode::protocol, "presence_field_missing"));
  }
  auto valid = validate_lan_presence(presence);
  if (!valid) {
    return Result<LanPresence>::failure(*valid.error_if());
  }
  return Result<LanPresence>::success(std::move(presence));
}

Result<std::vector<std::byte>> encode_lan_presence_datagram(const LanPresence& presence) {
  auto payload = encode_lan_presence(presence);
  if (!payload) {
    return Result<std::vector<std::byte>>::failure(*payload.error_if());
  }
  return encode_lan_datagram(LanDatagramType::presence, *payload.value_if());
}

Result<LanPresence> parse_lan_presence_datagram(std::span<const std::byte> datagram) {
  const auto envelope = parse_lan_datagram(datagram);
  if (envelope.status != LanDatagramParseStatus::parsed || !envelope.datagram ||
      envelope.datagram->type != LanDatagramType::presence) {
    return Result<LanPresence>::failure(
        lan_protocol_error(ErrorCode::protocol, "presence_datagram_invalid"));
  }
  return parse_lan_presence(envelope.datagram->payload);
}

Result<std::vector<std::byte>> canonical_lan_hello(const LanHello& hello) {
  const std::array fields{
      CanonicalField{1U, canonical_uint32(static_cast<std::uint32_t>(hello.role))},
      CanonicalField{2U, canonical_bytes(hello.sender_device_id)},
      CanonicalField{3U, canonical_bytes(hello.sender_endpoint_id)},
      CanonicalField{4U, canonical_bytes(hello.peer_device_id)},
      CanonicalField{5U, canonical_bytes(hello.peer_endpoint_id)},
      CanonicalField{6U, std::vector<std::byte>(hello.sender_identity_public_key.begin(),
                                               hello.sender_identity_public_key.end())},
      CanonicalField{7U, std::vector<std::byte>(hello.initiator_nonce.begin(),
                                               hello.initiator_nonce.end())},
      CanonicalField{8U, std::vector<std::byte>(hello.responder_nonce.begin(),
                                               hello.responder_nonce.end())},
      CanonicalField{9U, std::vector<std::byte>(
                               hello.sender_tls_certificate_sha256.begin(),
                               hello.sender_tls_certificate_sha256.end())},
      CanonicalField{10U, std::vector<std::byte>(
                                hello.observed_peer_tls_certificate_sha256.begin(),
                                hello.observed_peer_tls_certificate_sha256.end())},
      CanonicalField{11U, std::vector<std::byte>(hello.sender_boot_nonce.begin(),
                                                hello.sender_boot_nonce.end())},
      CanonicalField{12U, canonical_uint32(hello.protocol_version.major)},
      CanonicalField{13U, canonical_uint32(hello.protocol_version.minor)},
      CanonicalField{14U, canonical_uint64(hello.supported.bits)},
      CanonicalField{15U, canonical_uint64(hello.required.bits)},
      CanonicalField{16U, canonical_uint32(static_cast<std::uint32_t>(hello.expiry.count()))}};
  return canonicalize_for_signature(SigningDomain::lan_hello, fields);
}

Result<void> sign_lan_hello(LanHello& hello, const IdentityKeyPair& identity) {
  hello.sender_device_id = identity.device_id();
  hello.sender_identity_public_key = identity.public_key();
  auto canonical = canonical_lan_hello(hello);
  if (!canonical) {
    return Result<void>::failure(*canonical.error_if());
  }
  auto signature = sign_identity_message(identity, *canonical.value_if());
  if (!signature) {
    return Result<void>::failure(*signature.error_if());
  }
  hello.signature = *signature.value_if();
  return Result<void>::success();
}

Result<void> validate_lan_hello(const LanHello& hello) {
  const bool valid_role = hello.role == LanHelloRole::initiator ||
                          hello.role == LanHelloRole::responder;
  const bool responder_nonce_valid = !all_zero(hello.responder_nonce) ||
                                     hello.role == LanHelloRole::initiator;
  const auto signaling_bit = static_cast<std::uint64_t>(Capability::lan_signaling_v1);
  if (!valid_role || hello.sender_device_id.is_zero() || hello.sender_endpoint_id.is_zero() ||
      hello.peer_device_id.is_zero() || hello.peer_endpoint_id.is_zero() ||
      (hello.sender_device_id == hello.peer_device_id &&
       hello.sender_endpoint_id == hello.peer_endpoint_id) ||
      all_zero(hello.initiator_nonce) || !responder_nonce_valid ||
      all_zero(hello.sender_tls_certificate_sha256) ||
      all_zero(hello.observed_peer_tls_certificate_sha256) ||
      all_zero(hello.sender_boot_nonce) ||
      hello.protocol_version.major != current_protocol_version.major ||
      hello.protocol_version.minor < current_protocol_version.minor ||
      (hello.supported.bits & signaling_bit) == 0U ||
      (hello.required.bits & ~hello.supported.bits) != 0U ||
      (hello.required.bits & ~known_capability_bits) != 0U || hello.expiry.count() <= 0 ||
      hello.expiry > std::chrono::milliseconds{max_lan_hello_expiry_milliseconds}) {
    return Result<void>::failure(
        lan_protocol_error(ErrorCode::protocol, "hello_fields_invalid"));
  }
  auto derived = derive_device_id(hello.sender_identity_public_key);
  if (!derived || *derived.value_if() != hello.sender_device_id) {
    return Result<void>::failure(
        lan_protocol_error(ErrorCode::authentication, "hello_device_id_mismatch"));
  }
  auto canonical = canonical_lan_hello(hello);
  if (!canonical) {
    return Result<void>::failure(*canonical.error_if());
  }
  auto verified = verify_identity_signature(hello.sender_identity_public_key,
                                            *canonical.value_if(), hello.signature);
  if (!verified) {
    return Result<void>::failure(
        lan_protocol_error(ErrorCode::authentication, "hello_signature_invalid"));
  }
  return Result<void>::success();
}

Result<std::vector<std::byte>> encode_lan_hello(const LanHello& hello) {
  auto valid = validate_lan_hello(hello);
  if (!valid) {
    return Result<std::vector<std::byte>>::failure(*valid.error_if());
  }
  const auto sender = encode_device_endpoint(hello.sender_device_id, hello.sender_endpoint_id);
  const auto peer = encode_device_endpoint(hello.peer_device_id, hello.peer_endpoint_id);
  std::vector<std::byte> version;
  append_uint(version, 1U, hello.protocol_version.major);
  append_uint(version, 2U, hello.protocol_version.minor);
  std::vector<std::byte> capabilities;
  append_uint(capabilities, 1U, hello.supported.bits);
  append_uint(capabilities, 2U, hello.required.bits);
  std::vector<std::byte> signature;
  append_bytes(signature, 1U, hello.signature);

  std::vector<std::byte> output;
  output.reserve(512U);
  append_uint(output, 1U, static_cast<std::uint32_t>(hello.role));
  append_message(output, 2U, sender);
  append_message(output, 3U, peer);
  append_bytes(output, 4U, hello.sender_identity_public_key);
  append_bytes(output, 5U, hello.initiator_nonce);
  append_bytes(output, 6U, hello.responder_nonce);
  append_bytes(output, 7U, hello.sender_tls_certificate_sha256);
  append_bytes(output, 8U, hello.observed_peer_tls_certificate_sha256);
  append_bytes(output, 9U, hello.sender_boot_nonce);
  append_message(output, 10U, version);
  append_message(output, 11U, capabilities);
  append_uint(output, 12U, static_cast<std::uint32_t>(hello.expiry.count()));
  append_message(output, 13U, signature);
  if (output.size() > max_lan_datagram_payload_bytes) {
    return Result<std::vector<std::byte>>::failure(
        lan_protocol_error(ErrorCode::resource_exhausted, "hello_payload_too_large"));
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<LanHello> parse_lan_hello(std::span<const std::byte> payload) {
  if (payload.empty() || payload.size() > max_lan_datagram_payload_bytes) {
    return Result<LanHello>::failure(
        lan_protocol_error(ErrorCode::protocol, "hello_payload_size_invalid"));
  }
  ProtoReader reader(payload);
  LanHello hello;
  std::array<bool, 13U> seen{};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<LanHello>::failure(*field.error_if());
    }
    if (field.value_if()->number == 0U || field.value_if()->number > seen.size() ||
        seen[field.value_if()->number - 1U]) {
      return Result<LanHello>::failure(
          lan_protocol_error(ErrorCode::protocol, "hello_field_conflict"));
    }
    seen[field.value_if()->number - 1U] = true;
    switch (field.value_if()->number) {
      case 1U:
        if (field.value_if()->wire_type != 0U || field.value_if()->integer > 2U) {
          return Result<LanHello>::failure(
              lan_protocol_error(ErrorCode::protocol, "hello_role_invalid"));
        }
        hello.role = static_cast<LanHelloRole>(field.value_if()->integer);
        break;
      case 2U:
      case 3U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<LanHello>::failure(
              lan_protocol_error(ErrorCode::protocol, "hello_endpoint_invalid"));
        }
        auto endpoint = parse_device_endpoint_fields(field.value_if()->bytes);
        if (!endpoint) {
          return Result<LanHello>::failure(*endpoint.error_if());
        }
        if (field.value_if()->number == 2U) {
          hello.sender_device_id = endpoint.value_if()->first;
          hello.sender_endpoint_id = endpoint.value_if()->second;
        } else {
          hello.peer_device_id = endpoint.value_if()->first;
          hello.peer_endpoint_id = endpoint.value_if()->second;
        }
        break;
      }
      case 4U: {
        auto copied = field.value_if()->wire_type == 2U
                          ? copy_exact(field.value_if()->bytes,
                                       hello.sender_identity_public_key,
                                       "hello_public_key_invalid")
                          : Result<void>::failure(lan_protocol_error(
                                ErrorCode::protocol, "hello_public_key_invalid"));
        if (!copied) {
          return Result<LanHello>::failure(*copied.error_if());
        }
        break;
      }
      case 5U:
      case 6U:
      case 7U:
      case 8U:
      case 9U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<LanHello>::failure(
              lan_protocol_error(ErrorCode::protocol, "hello_bytes_field_invalid"));
        }
        std::span<std::byte> destination;
        switch (field.value_if()->number) {
          case 5U:
            destination = hello.initiator_nonce;
            break;
          case 6U:
            destination = hello.responder_nonce;
            break;
          case 7U:
            destination = hello.sender_tls_certificate_sha256;
            break;
          case 8U:
            destination = hello.observed_peer_tls_certificate_sha256;
            break;
          default:
            destination = hello.sender_boot_nonce;
            break;
        }
        auto copied = copy_exact(field.value_if()->bytes, destination,
                                 "hello_bytes_field_invalid");
        if (!copied) {
          return Result<LanHello>::failure(*copied.error_if());
        }
        break;
      }
      case 10U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<LanHello>::failure(
              lan_protocol_error(ErrorCode::protocol, "hello_version_invalid"));
        }
        auto version = parse_protocol_version(field.value_if()->bytes);
        if (!version) {
          return Result<LanHello>::failure(*version.error_if());
        }
        hello.protocol_version = {version.value_if()->first, version.value_if()->second};
        break;
      }
      case 11U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<LanHello>::failure(
              lan_protocol_error(ErrorCode::protocol, "hello_capabilities_invalid"));
        }
        auto capabilities = parse_capabilities(field.value_if()->bytes);
        if (!capabilities) {
          return Result<LanHello>::failure(*capabilities.error_if());
        }
        hello.supported.bits = capabilities.value_if()->first;
        hello.required.bits = capabilities.value_if()->second;
        break;
      }
      case 12U:
        if (field.value_if()->wire_type != 0U ||
            field.value_if()->integer > std::numeric_limits<std::uint32_t>::max()) {
          return Result<LanHello>::failure(
              lan_protocol_error(ErrorCode::protocol, "hello_expiry_invalid"));
        }
        hello.expiry = std::chrono::milliseconds{field.value_if()->integer};
        break;
      case 13U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<LanHello>::failure(
              lan_protocol_error(ErrorCode::protocol, "hello_signature_invalid"));
        }
        auto signature = parse_signature(field.value_if()->bytes);
        if (!signature) {
          return Result<LanHello>::failure(*signature.error_if());
        }
        hello.signature = *signature.value_if();
        break;
      }
      default:
        return Result<LanHello>::failure(
            lan_protocol_error(ErrorCode::protocol, "hello_unknown_field"));
    }
  }
  if (!std::all_of(seen.begin(), seen.end(), [](bool value) { return value; })) {
    return Result<LanHello>::failure(
        lan_protocol_error(ErrorCode::protocol, "hello_field_missing"));
  }
  auto valid = validate_lan_hello(hello);
  if (!valid) {
    return Result<LanHello>::failure(*valid.error_if());
  }
  return Result<LanHello>::success(std::move(hello));
}

}  // namespace heyaki
