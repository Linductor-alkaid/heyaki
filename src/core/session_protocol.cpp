#include <heyaki/session_protocol.hpp>

#include <heyaki/security.hpp>
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

Error session_error(ErrorCode code, const char* detail) {
  return Error{code, "session_hello", detail};
}

template <std::size_t Size>
bool all_zero(const std::array<std::byte, Size>& value) noexcept {
  return std::all_of(value.begin(), value.end(), [](std::byte byte) {
    return byte == std::byte{0};
  });
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
          session_error(ErrorCode::protocol, "protobuf_tag_invalid"));
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
            session_error(ErrorCode::protocol, "protobuf_length_invalid"));
      }
      const auto count = static_cast<std::size_t>(*length.value_if());
      field.bytes = input_.subspan(offset_, count);
      offset_ += count;
      return Result<ProtoField>::success(field);
    }
    return Result<ProtoField>::failure(
        session_error(ErrorCode::protocol, "protobuf_wire_type_unsupported"));
  }

 private:
  Result<std::uint64_t> read_varint() {
    std::uint64_t value = 0U;
    for (std::size_t index = 0U; index < 10U; ++index) {
      if (offset_ >= input_.size()) {
        return Result<std::uint64_t>::failure(
            session_error(ErrorCode::protocol, "protobuf_varint_truncated"));
      }
      const auto byte = std::to_integer<std::uint8_t>(input_[offset_++]);
      if (index == 9U && (byte & 0xfeU) != 0U) {
        return Result<std::uint64_t>::failure(
            session_error(ErrorCode::protocol, "protobuf_varint_overflow"));
      }
      value |= static_cast<std::uint64_t>(byte & 0x7fU) << (7U * index);
      if ((byte & 0x80U) == 0U) {
        if (index > 0U && (byte & 0x7fU) == 0U) {
          return Result<std::uint64_t>::failure(
              session_error(ErrorCode::protocol, "protobuf_varint_noncanonical"));
        }
        return Result<std::uint64_t>::success(value);
      }
    }
    return Result<std::uint64_t>::failure(
        session_error(ErrorCode::protocol, "protobuf_varint_overflow"));
  }

  std::span<const std::byte> input_;
  std::size_t offset_{};
};

Result<void> copy_exact(std::span<const std::byte> source, std::span<std::byte> destination,
                        const char* detail) {
  if (source.size() != destination.size()) {
    return Result<void>::failure(session_error(ErrorCode::protocol, detail));
  }
  std::copy(source.begin(), source.end(), destination.begin());
  return Result<void>::success();
}

std::vector<CanonicalField> session_hello_fields(const SignedSessionHello& hello) {
  return {
      {1U, canonical_bytes(hello.sender.device_id)},
      {2U, canonical_bytes(hello.sender.endpoint_id)},
      {3U, canonical_bytes(hello.peer.device_id)},
      {4U, canonical_bytes(hello.peer.endpoint_id)},
      {5U, canonical_bytes(hello.session_id)},
      {6U, canonical_uint64(hello.session_epoch)},
      {7U, {hello.initiator_nonce.begin(), hello.initiator_nonce.end()}},
      {8U, {hello.responder_nonce.begin(), hello.responder_nonce.end()}},
      {9U, {hello.signaling_transcript_sha256.begin(),
            hello.signaling_transcript_sha256.end()}},
      {10U, canonical_uint32(hello.protocol_version.major)},
      {11U, canonical_uint32(hello.protocol_version.minor)},
      {12U, canonical_uint64(hello.supported.bits)},
      {13U, canonical_uint64(hello.required.bits)},
      {14U, canonical_uint64(hello.expires_unix_milliseconds)},
  };
}

std::vector<std::byte> encode_device_endpoint(const DeviceEndpointKey& endpoint) {
  std::vector<std::byte> output;
  append_bytes(output, 1U, endpoint.device_id.bytes());
  append_bytes(output, 2U, endpoint.endpoint_id.bytes());
  return output;
}

std::vector<std::byte> encode_protocol_version(ProtocolVersion version) {
  std::vector<std::byte> output;
  append_uint(output, 1U, version.major);
  append_uint(output, 2U, version.minor);
  return output;
}

std::vector<std::byte> encode_capabilities(CapabilitySet supported,
                                           CapabilitySet required) {
  std::vector<std::byte> output;
  append_uint(output, 1U, supported.bits);
  append_uint(output, 2U, required.bits);
  return output;
}

std::vector<std::byte> encode_signature(const IdentitySignature& signature) {
  std::vector<std::byte> output;
  append_bytes(output, 1U, signature);
  return output;
}

Result<DeviceEndpointKey> parse_device_endpoint(std::span<const std::byte> payload) {
  ProtoReader reader(payload);
  std::optional<DeviceId> device_id;
  std::optional<EndpointId> endpoint_id;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<DeviceEndpointKey>::failure(*field.error_if());
    }
    if (field.value_if()->wire_type != 2U) {
      return Result<DeviceEndpointKey>::failure(
          session_error(ErrorCode::protocol, "endpoint_field_invalid"));
    }
    if (field.value_if()->number == 1U && !device_id) {
      DeviceId::Storage value{};
      auto copied = copy_exact(field.value_if()->bytes, value, "endpoint_device_id_invalid");
      if (!copied) {
        return Result<DeviceEndpointKey>::failure(*copied.error_if());
      }
      device_id = DeviceId{value};
    } else if (field.value_if()->number == 2U && !endpoint_id) {
      EndpointId::Storage value{};
      auto copied = copy_exact(field.value_if()->bytes, value, "endpoint_id_invalid");
      if (!copied) {
        return Result<DeviceEndpointKey>::failure(*copied.error_if());
      }
      endpoint_id = EndpointId{value};
    } else {
      return Result<DeviceEndpointKey>::failure(
          session_error(ErrorCode::protocol, "endpoint_field_conflict"));
    }
  }
  if (!device_id || !endpoint_id) {
    return Result<DeviceEndpointKey>::failure(
        session_error(ErrorCode::protocol, "endpoint_field_missing"));
  }
  return Result<DeviceEndpointKey>::success({*device_id, *endpoint_id});
}

Result<ProtocolVersion> parse_protocol_version(std::span<const std::byte> payload) {
  ProtoReader reader(payload);
  std::optional<std::uint32_t> major;
  std::optional<std::uint32_t> minor;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<ProtocolVersion>::failure(*field.error_if());
    }
    if (field.value_if()->wire_type != 0U ||
        field.value_if()->integer > std::numeric_limits<std::uint32_t>::max()) {
      return Result<ProtocolVersion>::failure(
          session_error(ErrorCode::protocol, "version_field_invalid"));
    }
    if (field.value_if()->number == 1U && !major) {
      major = static_cast<std::uint32_t>(field.value_if()->integer);
    } else if (field.value_if()->number == 2U && !minor) {
      minor = static_cast<std::uint32_t>(field.value_if()->integer);
    } else {
      return Result<ProtocolVersion>::failure(
          session_error(ErrorCode::protocol, "version_field_conflict"));
    }
  }
  if (!major || !minor) {
    return Result<ProtocolVersion>::failure(
        session_error(ErrorCode::protocol, "version_field_missing"));
  }
  return Result<ProtocolVersion>::success({*major, *minor});
}

Result<std::pair<CapabilitySet, CapabilitySet>> parse_capabilities(
    std::span<const std::byte> payload) {
  ProtoReader reader(payload);
  std::optional<std::uint64_t> supported;
  std::optional<std::uint64_t> required;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<std::pair<CapabilitySet, CapabilitySet>>::failure(*field.error_if());
    }
    if (field.value_if()->wire_type != 0U) {
      return Result<std::pair<CapabilitySet, CapabilitySet>>::failure(
          session_error(ErrorCode::protocol, "capabilities_field_invalid"));
    }
    if (field.value_if()->number == 1U && !supported) {
      supported = field.value_if()->integer;
    } else if (field.value_if()->number == 2U && !required) {
      required = field.value_if()->integer;
    } else {
      return Result<std::pair<CapabilitySet, CapabilitySet>>::failure(
          session_error(ErrorCode::protocol, "capabilities_field_conflict"));
    }
  }
  if (!supported || !required) {
    return Result<std::pair<CapabilitySet, CapabilitySet>>::failure(
        session_error(ErrorCode::protocol, "capabilities_field_missing"));
  }
  return Result<std::pair<CapabilitySet, CapabilitySet>>::success(
      {{*supported}, {*required}});
}

Result<IdentitySignature> parse_signature(std::span<const std::byte> payload) {
  ProtoReader reader(payload);
  std::optional<IdentitySignature> signature;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<IdentitySignature>::failure(*field.error_if());
    }
    if (field.value_if()->number != 1U || field.value_if()->wire_type != 2U || signature) {
      return Result<IdentitySignature>::failure(
          session_error(ErrorCode::protocol, "signature_field_conflict"));
    }
    IdentitySignature value{};
    auto copied = copy_exact(field.value_if()->bytes, value, "signature_field_invalid");
    if (!copied) {
      return Result<IdentitySignature>::failure(*copied.error_if());
    }
    signature = value;
  }
  if (!signature) {
    return Result<IdentitySignature>::failure(
        session_error(ErrorCode::protocol, "signature_field_missing"));
  }
  return Result<IdentitySignature>::success(*signature);
}

Result<void> verify_signature_and_identity(const SignedSessionHello& hello,
                                           std::span<const std::byte> public_key) {
  auto canonical = canonicalize_for_signature(SigningDomain::session_hello,
                                               session_hello_fields(hello));
  if (!canonical) {
    return Result<void>::failure(*canonical.error_if());
  }
  auto verified = verify_identity_signature(public_key, *canonical.value_if(), hello.signature);
  if (!verified) {
    return Result<void>::failure(
        session_error(ErrorCode::authentication, "signature_invalid"));
  }
  auto derived = derive_device_id(public_key);
  if (!derived || *derived.value_if() != hello.sender.device_id) {
    return Result<void>::failure(
        session_error(ErrorCode::authentication, "sender_identity_mismatch"));
  }
  return Result<void>::success();
}

bool matches_expectation_except_epoch(const SignedSessionHello& hello,
                                      const SessionHelloExpectation& expected) noexcept {
  return hello.sender == expected.sender && hello.peer == expected.peer &&
         hello.session_id == expected.session_id &&
         hello.initiator_nonce == expected.initiator_nonce &&
         hello.responder_nonce == expected.responder_nonce &&
         hello.signaling_transcript_sha256 == expected.signaling_transcript_sha256;
}

}  // namespace

Result<void> validate_signed_session_hello(const SignedSessionHello& hello) {
  if (hello.sender.device_id.is_zero() || hello.sender.endpoint_id.is_zero() ||
      hello.peer.device_id.is_zero() || hello.peer.endpoint_id.is_zero() ||
      hello.sender == hello.peer) {
    return Result<void>::failure(
        session_error(ErrorCode::protocol, "endpoint_binding_invalid"));
  }
  if (hello.session_id.is_zero() || hello.session_epoch == 0U) {
    return Result<void>::failure(
        session_error(ErrorCode::protocol, "session_binding_invalid"));
  }
  if (all_zero(hello.initiator_nonce) || all_zero(hello.responder_nonce) ||
      all_zero(hello.signaling_transcript_sha256)) {
    return Result<void>::failure(
        session_error(ErrorCode::protocol, "signaling_binding_invalid"));
  }
  const auto session_bit = static_cast<std::uint64_t>(Capability::session);
  if (hello.protocol_version.major == 0U ||
      !hello.supported.contains(hello.required) ||
      (hello.supported.bits & session_bit) == 0U ||
      (hello.required.bits & session_bit) == 0U) {
    return Result<void>::failure(
        session_error(ErrorCode::protocol, "protocol_advertisement_invalid"));
  }
  if (hello.expires_unix_milliseconds == 0U) {
    return Result<void>::failure(session_error(ErrorCode::protocol, "expiry_invalid"));
  }
  return Result<void>::success();
}

Result<std::vector<std::byte>> canonical_signed_session_hello(
    const SignedSessionHello& hello) {
  auto validated = validate_signed_session_hello(hello);
  if (!validated) {
    return Result<std::vector<std::byte>>::failure(*validated.error_if());
  }
  return canonicalize_for_signature(SigningDomain::session_hello,
                                    session_hello_fields(hello));
}

Result<void> sign_signed_session_hello(SignedSessionHello& hello,
                                       const IdentityKeyPair& identity) {
  auto canonical = canonical_signed_session_hello(hello);
  if (!canonical) {
    return Result<void>::failure(*canonical.error_if());
  }
  if (identity.device_id() != hello.sender.device_id) {
    return Result<void>::failure(
        session_error(ErrorCode::identity, "signer_identity_mismatch"));
  }
  auto signature = sign_identity_message(identity, *canonical.value_if());
  if (!signature) {
    return Result<void>::failure(*signature.error_if());
  }
  hello.signature = *signature.value_if();
  return Result<void>::success();
}

Result<void> verify_signed_session_hello(const SignedSessionHello& hello,
                                         std::span<const std::byte> sender_public_key,
                                         std::uint64_t now_unix_milliseconds) {
  auto validated = validate_signed_session_hello(hello);
  if (!validated) {
    return validated;
  }
  auto expiry = validate_signed_expiry(hello.expires_unix_milliseconds,
                                       now_unix_milliseconds);
  if (!expiry) {
    return expiry;
  }
  return verify_signature_and_identity(hello, sender_public_key);
}

Result<std::vector<std::byte>> encode_signed_session_hello(
    const SignedSessionHello& hello) {
  auto validated = validate_signed_session_hello(hello);
  if (!validated) {
    return Result<std::vector<std::byte>>::failure(*validated.error_if());
  }
  std::vector<std::byte> output;
  output.reserve(384U);
  append_bytes(output, 1U, encode_device_endpoint(hello.sender));
  append_bytes(output, 2U, encode_device_endpoint(hello.peer));
  append_bytes(output, 3U, hello.session_id.bytes());
  append_uint(output, 4U, hello.session_epoch);
  append_bytes(output, 5U, hello.initiator_nonce);
  append_bytes(output, 6U, hello.responder_nonce);
  append_bytes(output, 7U, hello.signaling_transcript_sha256);
  append_bytes(output, 8U, encode_protocol_version(hello.protocol_version));
  append_bytes(output, 9U, encode_capabilities(hello.supported, hello.required));
  append_uint(output, 10U, hello.expires_unix_milliseconds);
  append_bytes(output, 11U, encode_signature(hello.signature));
  if (output.size() > max_session_hello_bytes) {
    return Result<std::vector<std::byte>>::failure(
        session_error(ErrorCode::resource_exhausted, "object_too_large"));
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<SignedSessionHello> parse_signed_session_hello(std::span<const std::byte> payload) {
  if (payload.size() > max_session_hello_bytes) {
    return Result<SignedSessionHello>::failure(
        session_error(ErrorCode::resource_exhausted, "object_too_large"));
  }
  ProtoReader reader(payload);
  std::optional<DeviceEndpointKey> sender;
  std::optional<DeviceEndpointKey> peer;
  std::optional<SessionId> session_id;
  std::optional<std::uint64_t> epoch;
  std::optional<SignalingNonce> initiator_nonce;
  std::optional<SignalingNonce> responder_nonce;
  std::optional<SignalingTranscriptSha256> transcript;
  std::optional<ProtocolVersion> version;
  std::optional<std::pair<CapabilitySet, CapabilitySet>> capabilities;
  std::optional<std::uint64_t> expiry;
  std::optional<IdentitySignature> signature;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<SignedSessionHello>::failure(*field.error_if());
    }
    switch (field.value_if()->number) {
      case 1U:
      case 2U: {
        auto& destination = field.value_if()->number == 1U ? sender : peer;
        if (field.value_if()->wire_type != 2U || destination) {
          return Result<SignedSessionHello>::failure(
              session_error(ErrorCode::protocol, "endpoint_field_conflict"));
        }
        auto parsed = parse_device_endpoint(field.value_if()->bytes);
        if (!parsed) {
          return Result<SignedSessionHello>::failure(*parsed.error_if());
        }
        destination = *parsed.value_if();
        break;
      }
      case 3U: {
        if (field.value_if()->wire_type != 2U || session_id) {
          return Result<SignedSessionHello>::failure(
              session_error(ErrorCode::protocol, "session_id_field_conflict"));
        }
        SessionId::Storage value{};
        auto copied = copy_exact(field.value_if()->bytes, value, "session_id_field_invalid");
        if (!copied) {
          return Result<SignedSessionHello>::failure(*copied.error_if());
        }
        session_id = SessionId{value};
        break;
      }
      case 4U:
        if (field.value_if()->wire_type != 0U || epoch) {
          return Result<SignedSessionHello>::failure(
              session_error(ErrorCode::protocol, "epoch_field_conflict"));
        }
        epoch = field.value_if()->integer;
        break;
      case 5U:
      case 6U: {
        auto& destination = field.value_if()->number == 5U ? initiator_nonce : responder_nonce;
        if (field.value_if()->wire_type != 2U || destination) {
          return Result<SignedSessionHello>::failure(
              session_error(ErrorCode::protocol, "nonce_field_conflict"));
        }
        SignalingNonce value{};
        auto copied = copy_exact(field.value_if()->bytes, value, "nonce_field_invalid");
        if (!copied) {
          return Result<SignedSessionHello>::failure(*copied.error_if());
        }
        destination = value;
        break;
      }
      case 7U: {
        if (field.value_if()->wire_type != 2U || transcript) {
          return Result<SignedSessionHello>::failure(
              session_error(ErrorCode::protocol, "transcript_field_conflict"));
        }
        SignalingTranscriptSha256 value{};
        auto copied = copy_exact(field.value_if()->bytes, value, "transcript_field_invalid");
        if (!copied) {
          return Result<SignedSessionHello>::failure(*copied.error_if());
        }
        transcript = value;
        break;
      }
      case 8U: {
        if (field.value_if()->wire_type != 2U || version) {
          return Result<SignedSessionHello>::failure(
              session_error(ErrorCode::protocol, "version_field_conflict"));
        }
        auto parsed = parse_protocol_version(field.value_if()->bytes);
        if (!parsed) {
          return Result<SignedSessionHello>::failure(*parsed.error_if());
        }
        version = *parsed.value_if();
        break;
      }
      case 9U: {
        if (field.value_if()->wire_type != 2U || capabilities) {
          return Result<SignedSessionHello>::failure(
              session_error(ErrorCode::protocol, "capabilities_field_conflict"));
        }
        auto parsed = parse_capabilities(field.value_if()->bytes);
        if (!parsed) {
          return Result<SignedSessionHello>::failure(*parsed.error_if());
        }
        capabilities = *parsed.value_if();
        break;
      }
      case 10U:
        if (field.value_if()->wire_type != 0U || expiry) {
          return Result<SignedSessionHello>::failure(
              session_error(ErrorCode::protocol, "expiry_field_conflict"));
        }
        expiry = field.value_if()->integer;
        break;
      case 11U: {
        if (field.value_if()->wire_type != 2U || signature) {
          return Result<SignedSessionHello>::failure(
              session_error(ErrorCode::protocol, "signature_field_conflict"));
        }
        auto parsed = parse_signature(field.value_if()->bytes);
        if (!parsed) {
          return Result<SignedSessionHello>::failure(*parsed.error_if());
        }
        signature = *parsed.value_if();
        break;
      }
      default:
        return Result<SignedSessionHello>::failure(
            session_error(ErrorCode::protocol, "field_unknown"));
    }
  }
  if (!sender || !peer || !session_id || !epoch || !initiator_nonce ||
      !responder_nonce || !transcript || !version || !capabilities || !expiry ||
      !signature) {
    return Result<SignedSessionHello>::failure(
        session_error(ErrorCode::protocol, "field_missing"));
  }
  SignedSessionHello hello;
  hello.sender = *sender;
  hello.peer = *peer;
  hello.session_id = *session_id;
  hello.session_epoch = *epoch;
  hello.initiator_nonce = *initiator_nonce;
  hello.responder_nonce = *responder_nonce;
  hello.signaling_transcript_sha256 = *transcript;
  hello.protocol_version = *version;
  hello.supported = capabilities->first;
  hello.required = capabilities->second;
  hello.expires_unix_milliseconds = *expiry;
  hello.signature = *signature;
  auto validated = validate_signed_session_hello(hello);
  if (!validated) {
    return Result<SignedSessionHello>::failure(*validated.error_if());
  }
  return Result<SignedSessionHello>::success(std::move(hello));
}

SessionHelloAdmission::SessionHelloAdmission(SessionHelloExpectation expectation,
                                             IdentityPublicKey sender_public_key,
                                             ProtocolHello local_protocol)
    : expectation_(std::move(expectation)),
      sender_public_key_(sender_public_key),
      local_protocol_(local_protocol) {}

Result<SessionHelloAdmissionOutcome> SessionHelloAdmission::admit(
    std::span<const std::byte> payload, std::uint64_t now_unix_milliseconds) {
  auto parsed = parse_signed_session_hello(payload);
  if (!parsed) {
    return Result<SessionHelloAdmissionOutcome>::failure(*parsed.error_if());
  }
  const auto& hello = *parsed.value_if();
  auto signature = verify_signature_and_identity(hello, sender_public_key_);
  if (!signature) {
    return Result<SessionHelloAdmissionOutcome>::failure(*signature.error_if());
  }
  if (!matches_expectation_except_epoch(hello, expectation_)) {
    return Result<SessionHelloAdmissionOutcome>::failure(
        session_error(ErrorCode::authentication, "binding_mismatch"));
  }
  if (hello.session_epoch < expectation_.session_epoch) {
    return Result<SessionHelloAdmissionOutcome>::success(
        {.action = SessionHelloAdmissionAction::late_epoch, .negotiated_protocol = std::nullopt});
  }
  if (hello.session_epoch > expectation_.session_epoch) {
    return Result<SessionHelloAdmissionOutcome>::failure(
        session_error(ErrorCode::authentication, "higher_epoch_requires_new_transport"));
  }
  if (accepted_payload_) {
    if (std::equal(payload.begin(), payload.end(), accepted_payload_->begin(),
                   accepted_payload_->end())) {
      return Result<SessionHelloAdmissionOutcome>::success(
          {.action = SessionHelloAdmissionAction::duplicate,
           .negotiated_protocol = negotiated_protocol_});
    }
    return Result<SessionHelloAdmissionOutcome>::failure(
        session_error(ErrorCode::authentication, "conflicting_duplicate"));
  }
  auto expiry = validate_signed_expiry(hello.expires_unix_milliseconds,
                                       now_unix_milliseconds);
  if (!expiry) {
    return Result<SessionHelloAdmissionOutcome>::failure(*expiry.error_if());
  }
  auto negotiated = negotiate_protocol(
      local_protocol_,
      {.version = hello.protocol_version,
       .supported = hello.supported,
       .required = hello.required});
  if (!negotiated) {
    return Result<SessionHelloAdmissionOutcome>::failure(*negotiated.error_if());
  }
  accepted_payload_ = std::vector<std::byte>{payload.begin(), payload.end()};
  negotiated_protocol_ = *negotiated.value_if();
  return Result<SessionHelloAdmissionOutcome>::success(
      {.action = SessionHelloAdmissionAction::accepted,
       .negotiated_protocol = negotiated_protocol_});
}

}  // namespace heyaki
