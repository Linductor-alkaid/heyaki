#include <heyaki/signaling_protocol.hpp>

#include <heyaki/security.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

Error signaling_error(ErrorCode code, const char* detail) {
  return Error{code, "signaling", detail};
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
          signaling_error(ErrorCode::protocol, "protobuf_tag_invalid"));
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
            signaling_error(ErrorCode::protocol, "protobuf_length_invalid"));
      }
      const auto count = static_cast<std::size_t>(*length.value_if());
      field.bytes = input_.subspan(offset_, count);
      offset_ += count;
      return Result<ProtoField>::success(field);
    }
    return Result<ProtoField>::failure(
        signaling_error(ErrorCode::protocol, "protobuf_wire_type_unsupported"));
  }

 private:
  Result<std::uint64_t> read_varint() {
    std::uint64_t value = 0U;
    for (std::size_t index = 0U; index < 10U; ++index) {
      if (offset_ >= input_.size()) {
        return Result<std::uint64_t>::failure(
            signaling_error(ErrorCode::protocol, "protobuf_varint_truncated"));
      }
      const auto byte = std::to_integer<std::uint8_t>(input_[offset_++]);
      if (index == 9U && (byte & 0xfeU) != 0U) {
        return Result<std::uint64_t>::failure(
            signaling_error(ErrorCode::protocol, "protobuf_varint_overflow"));
      }
      value |= static_cast<std::uint64_t>(byte & 0x7fU) << (7U * index);
      if ((byte & 0x80U) == 0U) {
        if (index > 0U && (byte & 0x7fU) == 0U) {
          return Result<std::uint64_t>::failure(
              signaling_error(ErrorCode::protocol, "protobuf_varint_noncanonical"));
        }
        return Result<std::uint64_t>::success(value);
      }
    }
    return Result<std::uint64_t>::failure(
        signaling_error(ErrorCode::protocol, "protobuf_varint_overflow"));
  }

  std::span<const std::byte> input_;
  std::size_t offset_{};
};

template <std::size_t Size>
bool all_zero(const std::array<std::byte, Size>& value) noexcept {
  return std::all_of(value.begin(), value.end(), [](std::byte byte) {
    return byte == std::byte{0};
  });
}

Result<void> copy_exact(std::span<const std::byte> source, std::span<std::byte> destination,
                        const char* detail) {
  if (source.size() != destination.size()) {
    return Result<void>::failure(signaling_error(ErrorCode::protocol, detail));
  }
  std::copy(source.begin(), source.end(), destination.begin());
  return Result<void>::success();
}

bool is_printable_ascii(std::string_view value) noexcept {
  return std::all_of(value.begin(), value.end(), [](char character) {
    const auto byte = static_cast<unsigned char>(character);
    return byte >= 0x20U && byte <= 0x7eU;
  });
}

Result<void> validate_binding_common(const SignalBinding& binding) {
  if (binding.initiator.device_id.is_zero() || binding.initiator.endpoint_id.is_zero() ||
      binding.responder.device_id.is_zero() || binding.responder.endpoint_id.is_zero()) {
    return Result<void>::failure(
        signaling_error(ErrorCode::protocol, "signaling_binding_identity_zero"));
  }
  if (binding.initiator == binding.responder) {
    return Result<void>::failure(
        signaling_error(ErrorCode::protocol, "signaling_binding_self_referential"));
  }
  if (binding.request_id.is_zero() || binding.session_id.is_zero()) {
    return Result<void>::failure(
        signaling_error(ErrorCode::protocol, "signaling_binding_ids_zero"));
  }
  if (all_zero(binding.initiator_nonce)) {
    return Result<void>::failure(
        signaling_error(ErrorCode::protocol, "signaling_initiator_nonce_zero"));
  }
  if (binding.expires_unix_milliseconds == 0U) {
    return Result<void>::failure(
        signaling_error(ErrorCode::protocol, "signaling_expiry_zero"));
  }
  return Result<void>::success();
}

Result<void> validate_ufrag(std::string_view ufrag) {
  if (ufrag.size() < min_signaling_ice_ufrag_bytes ||
      ufrag.size() > max_signaling_ice_ufrag_bytes || !is_printable_ascii(ufrag)) {
    return Result<void>::failure(
        signaling_error(ErrorCode::protocol, "signaling_ufrag_invalid"));
  }
  return Result<void>::success();
}

std::vector<CanonicalField> binding_fields(const SignalBinding& binding,
                                           bool require_responder_nonce) {
  std::vector<CanonicalField> fields;
  fields.reserve(8U);
  fields.push_back(CanonicalField{1U, canonical_bytes(binding.initiator.device_id)});
  fields.push_back(CanonicalField{2U, canonical_bytes(binding.initiator.endpoint_id)});
  fields.push_back(CanonicalField{3U, canonical_bytes(binding.responder.device_id)});
  fields.push_back(CanonicalField{4U, canonical_bytes(binding.responder.endpoint_id)});
  fields.push_back(CanonicalField{5U, canonical_bytes(binding.request_id)});
  fields.push_back(CanonicalField{6U, canonical_bytes(binding.session_id)});
  fields.push_back(CanonicalField{7U, {binding.initiator_nonce.begin(),
                                      binding.initiator_nonce.end()}});
  if (require_responder_nonce && binding.responder_nonce.has_value()) {
    fields.push_back(CanonicalField{8U, {binding.responder_nonce->begin(),
                                        binding.responder_nonce->end()}});
  }
  return fields;
}

std::vector<std::byte> fingerprint_bytes(const DtlsFingerprint& fingerprint) {
  return {fingerprint.begin(), fingerprint.end()};
}

std::vector<CanonicalField> offer_fields(const SignedOffer& offer) {
  auto fields = binding_fields(offer.binding, false);
  fields.reserve(10U);
  fields.push_back(
      CanonicalField{8U, canonical_uint64(offer.binding.expires_unix_milliseconds)});
  fields.push_back(CanonicalField{9U, offer.sdp});
  fields.push_back(CanonicalField{10U, fingerprint_bytes(offer.dtls_fingerprint)});
  return fields;
}

std::vector<CanonicalField> answer_fields(const SignedAnswer& answer) {
  auto fields = binding_fields(answer.binding, true);
  fields.reserve(11U);
  fields.push_back(
      CanonicalField{9U, canonical_uint64(answer.binding.expires_unix_milliseconds)});
  fields.push_back(CanonicalField{10U, answer.sdp});
  fields.push_back(CanonicalField{11U, fingerprint_bytes(answer.dtls_fingerprint)});
  return fields;
}

std::vector<CanonicalField> candidate_fields(const SignedCandidate& candidate) {
  auto fields = binding_fields(candidate.binding, true);
  fields.reserve(14U);
  fields.push_back(
      CanonicalField{9U, canonical_uint64(candidate.binding.expires_unix_milliseconds)});
  fields.push_back(CanonicalField{10U, canonical_uint32(candidate.sequence)});
  fields.push_back(CanonicalField{11U, candidate.candidate});
  fields.push_back(CanonicalField{12U, {candidate.signaling_transcript_sha256.begin(),
                                        candidate.signaling_transcript_sha256.end()}});
  const auto* ufrag_data =
      reinterpret_cast<const std::byte*>(candidate.owner_ice_ufrag.data());
  fields.push_back(CanonicalField{
      13U, std::vector<std::byte>{ufrag_data, ufrag_data + candidate.owner_ice_ufrag.size()}});
  fields.push_back(CanonicalField{14U, fingerprint_bytes(candidate.owner_dtls_fingerprint)});
  return fields;
}

std::vector<std::byte> encode_device_endpoint(const DeviceEndpointKey& endpoint) {
  std::vector<std::byte> output;
  append_bytes(output, 1U, endpoint.device_id.bytes());
  append_bytes(output, 2U, endpoint.endpoint_id.bytes());
  return output;
}

std::vector<std::byte> encode_signature(const IdentitySignature& signature) {
  std::vector<std::byte> output;
  append_bytes(output, 1U,
               std::span<const std::byte>{signature.data(), signature.size()});
  return output;
}

Result<DeviceEndpointKey> parse_device_endpoint(std::span<const std::byte> bytes) {
  ProtoReader reader(bytes);
  std::optional<DeviceId> device_id;
  std::optional<EndpointId> endpoint_id;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<DeviceEndpointKey>::failure(*field.error_if());
    }
    if (field.value_if()->wire_type != 2U) {
      return Result<DeviceEndpointKey>::failure(
          signaling_error(ErrorCode::protocol, "endpoint_field_invalid"));
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
      auto copied = copy_exact(field.value_if()->bytes, value, "endpoint_endpoint_id_invalid");
      if (!copied) {
        return Result<DeviceEndpointKey>::failure(*copied.error_if());
      }
      endpoint_id = EndpointId{value};
    } else {
      return Result<DeviceEndpointKey>::failure(
          signaling_error(ErrorCode::protocol, "endpoint_field_conflict"));
    }
  }
  if (!device_id || !endpoint_id) {
    return Result<DeviceEndpointKey>::failure(
        signaling_error(ErrorCode::protocol, "endpoint_field_missing"));
  }
  return Result<DeviceEndpointKey>::success(DeviceEndpointKey{*device_id, *endpoint_id});
}

Result<IdentitySignature> parse_signature_message(std::span<const std::byte> bytes) {
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
          signaling_error(ErrorCode::protocol, "signature_field_invalid"));
    }
    IdentitySignature value{};
    std::copy(field.value_if()->bytes.begin(), field.value_if()->bytes.end(), value.begin());
    signature = value;
  }
  if (!signature) {
    return Result<IdentitySignature>::failure(
        signaling_error(ErrorCode::protocol, "signature_field_missing"));
  }
  return Result<IdentitySignature>::success(*signature);
}

Result<SignalBinding> parse_binding(std::span<const std::byte> bytes, bool allow_responder,
                                    bool require_responder) {
  ProtoReader reader(bytes);
  std::optional<DeviceEndpointKey> initiator;
  std::optional<DeviceEndpointKey> responder;
  std::optional<RequestId> request_id;
  std::optional<SessionId> session_id;
  std::optional<SignalingNonce> initiator_nonce;
  std::optional<SignalingNonce> responder_nonce;
  std::optional<std::uint64_t> expires;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<SignalBinding>::failure(*field.error_if());
    }
    switch (field.value_if()->number) {
      case 1U:
      case 2U: {
        if (field.value_if()->wire_type != 2U ||
            (field.value_if()->number == 1U ? initiator : responder)) {
          return Result<SignalBinding>::failure(
              signaling_error(ErrorCode::protocol, "binding_endpoint_field_conflict"));
        }
        auto endpoint = parse_device_endpoint(field.value_if()->bytes);
        if (!endpoint) {
          return Result<SignalBinding>::failure(*endpoint.error_if());
        }
        if (field.value_if()->number == 1U) {
          initiator = *endpoint.value_if();
        } else {
          responder = *endpoint.value_if();
        }
        break;
      }
      case 3U: {
        RequestId::Storage value{};
        if (field.value_if()->wire_type != 2U || request_id ||
            !copy_exact(field.value_if()->bytes, value, "binding_request_id_invalid")) {
          return Result<SignalBinding>::failure(
              signaling_error(ErrorCode::protocol, "binding_request_id_invalid"));
        }
        request_id = RequestId{value};
        break;
      }
      case 4U: {
        SessionId::Storage value{};
        if (field.value_if()->wire_type != 2U || session_id ||
            !copy_exact(field.value_if()->bytes, value, "binding_session_id_invalid")) {
          return Result<SignalBinding>::failure(
              signaling_error(ErrorCode::protocol, "binding_session_id_invalid"));
        }
        session_id = SessionId{value};
        break;
      }
      case 5U: {
        SignalingNonce value{};
        if (field.value_if()->wire_type != 2U || initiator_nonce ||
            !copy_exact(field.value_if()->bytes, value, "binding_initiator_nonce_invalid")) {
          return Result<SignalBinding>::failure(
              signaling_error(ErrorCode::protocol, "binding_initiator_nonce_invalid"));
        }
        initiator_nonce = value;
        break;
      }
      case 6U: {
        if (field.value_if()->wire_type != 0U || expires) {
          return Result<SignalBinding>::failure(
              signaling_error(ErrorCode::protocol, "binding_expiry_field_conflict"));
        }
        expires = field.value_if()->integer;
        break;
      }
      case 7U: {
        SignalingNonce value{};
        if (field.value_if()->wire_type != 2U || responder_nonce ||
            !copy_exact(field.value_if()->bytes, value, "binding_responder_nonce_invalid")) {
          return Result<SignalBinding>::failure(
              signaling_error(ErrorCode::protocol, "binding_responder_nonce_invalid"));
        }
        responder_nonce = value;
        break;
      }
      default:
        return Result<SignalBinding>::failure(
            signaling_error(ErrorCode::protocol, "binding_field_unknown"));
    }
  }
  if (!initiator || !responder || !request_id || !session_id || !initiator_nonce || !expires) {
    return Result<SignalBinding>::failure(
        signaling_error(ErrorCode::protocol, "binding_field_missing"));
  }
  if (responder_nonce.has_value() && !allow_responder) {
    return Result<SignalBinding>::failure(
        signaling_error(ErrorCode::protocol, "binding_responder_nonce_unexpected"));
  }
  if (require_responder && !responder_nonce.has_value()) {
    return Result<SignalBinding>::failure(
        signaling_error(ErrorCode::protocol, "binding_responder_nonce_missing"));
  }
  SignalBinding binding;
  binding.initiator = *initiator;
  binding.responder = *responder;
  binding.request_id = *request_id;
  binding.session_id = *session_id;
  binding.initiator_nonce = *initiator_nonce;
  binding.expires_unix_milliseconds = *expires;
  binding.responder_nonce = responder_nonce;
  return Result<SignalBinding>::success(std::move(binding));
}

Result<DtlsFingerprint> parse_fingerprint(std::span<const std::byte> bytes,
                                          const char* detail) {
  DtlsFingerprint value{};
  auto copied = copy_exact(bytes, value, detail);
  if (!copied) {
    return Result<DtlsFingerprint>::failure(*copied.error_if());
  }
  return Result<DtlsFingerprint>::success(value);
}

Result<void> verify_signed_object(SigningDomain domain,
                                   const std::vector<CanonicalField>& fields,
                                   std::span<const std::byte> signature,
                                   std::span<const std::byte> signer_public_key,
                                   const DeviceId& expected_signer_device,
                                   std::uint64_t expires_unix_milliseconds,
                                   std::uint64_t now_unix_milliseconds) {
  auto canonical = canonicalize_for_signature(domain, fields);
  if (!canonical) {
    return Result<void>::failure(*canonical.error_if());
  }
  const auto expiry = validate_signed_expiry(expires_unix_milliseconds, now_unix_milliseconds);
  if (!expiry) {
    return Result<void>::failure(*expiry.error_if());
  }
  auto verified =
      verify_identity_signature(signer_public_key, *canonical.value_if(), signature);
  if (!verified) {
    return Result<void>::failure(
        signaling_error(ErrorCode::authentication, "signaling_signature_invalid"));
  }
  auto derived = derive_device_id(signer_public_key);
  if (!derived || *derived.value_if() != expected_signer_device) {
    return Result<void>::failure(
        signaling_error(ErrorCode::authentication, "signaling_signer_identity_mismatch"));
  }
  return Result<void>::success();
}

}  // namespace

Result<std::vector<std::byte>> canonical_signed_offer(const SignedOffer& offer) {
  auto validated = validate_signed_offer(offer);
  if (!validated) {
    return Result<std::vector<std::byte>>::failure(*validated.error_if());
  }
  return canonicalize_for_signature(SigningDomain::offer, offer_fields(offer));
}

Result<std::vector<std::byte>> canonical_signed_answer(const SignedAnswer& answer) {
  auto validated = validate_signed_answer(answer);
  if (!validated) {
    return Result<std::vector<std::byte>>::failure(*validated.error_if());
  }
  return canonicalize_for_signature(SigningDomain::answer, answer_fields(answer));
}

Result<std::vector<std::byte>> canonical_signed_candidate(const SignedCandidate& candidate) {
  auto validated = validate_signed_candidate(candidate);
  if (!validated) {
    return Result<std::vector<std::byte>>::failure(*validated.error_if());
  }
  return canonicalize_for_signature(SigningDomain::candidate, candidate_fields(candidate));
}

Result<void> validate_signed_offer(const SignedOffer& offer) {
  auto binding = validate_binding_common(offer.binding);
  if (!binding) {
    return binding;
  }
  if (offer.binding.responder_nonce.has_value()) {
    return Result<void>::failure(
        signaling_error(ErrorCode::protocol, "signaling_offer_responder_nonce_present"));
  }
  if (offer.sdp.empty() || offer.sdp.size() > max_signaling_sdp_bytes) {
    return Result<void>::failure(signaling_error(ErrorCode::protocol, "signaling_sdp_invalid"));
  }
  if (all_zero(offer.dtls_fingerprint)) {
    return Result<void>::failure(
        signaling_error(ErrorCode::protocol, "signaling_fingerprint_zero"));
  }
  return Result<void>::success();
}

Result<void> validate_signed_answer(const SignedAnswer& answer) {
  auto binding = validate_binding_common(answer.binding);
  if (!binding) {
    return binding;
  }
  if (!answer.binding.responder_nonce.has_value() ||
      all_zero(*answer.binding.responder_nonce)) {
    return Result<void>::failure(
        signaling_error(ErrorCode::protocol, "signaling_responder_nonce_missing"));
  }
  if (answer.sdp.empty() || answer.sdp.size() > max_signaling_sdp_bytes) {
    return Result<void>::failure(signaling_error(ErrorCode::protocol, "signaling_sdp_invalid"));
  }
  if (all_zero(answer.dtls_fingerprint)) {
    return Result<void>::failure(
        signaling_error(ErrorCode::protocol, "signaling_fingerprint_zero"));
  }
  return Result<void>::success();
}

Result<void> validate_signed_candidate(const SignedCandidate& candidate) {
  auto binding = validate_binding_common(candidate.binding);
  if (!binding) {
    return binding;
  }
  if (!candidate.binding.responder_nonce.has_value() ||
      all_zero(*candidate.binding.responder_nonce)) {
    return Result<void>::failure(
        signaling_error(ErrorCode::protocol, "signaling_responder_nonce_missing"));
  }
  if (candidate.sequence == 0U) {
    return Result<void>::failure(
        signaling_error(ErrorCode::protocol, "signaling_candidate_sequence_zero"));
  }
  if (candidate.candidate.empty() ||
      candidate.candidate.size() > max_signaling_candidate_bytes) {
    return Result<void>::failure(
        signaling_error(ErrorCode::protocol, "signaling_candidate_bytes_invalid"));
  }
  if (all_zero(candidate.signaling_transcript_sha256)) {
    return Result<void>::failure(
        signaling_error(ErrorCode::protocol, "signaling_transcript_zero"));
  }
  auto ufrag = validate_ufrag(candidate.owner_ice_ufrag);
  if (!ufrag) {
    return ufrag;
  }
  if (all_zero(candidate.owner_dtls_fingerprint)) {
    return Result<void>::failure(
        signaling_error(ErrorCode::protocol, "signaling_fingerprint_zero"));
  }
  return Result<void>::success();
}

Result<void> sign_signed_offer(SignedOffer& offer, const IdentityKeyPair& identity) {
  auto validated = validate_signed_offer(offer);
  if (!validated) {
    return validated;
  }
  auto canonical = canonicalize_for_signature(SigningDomain::offer, offer_fields(offer));
  if (!canonical) {
    return Result<void>::failure(*canonical.error_if());
  }
  auto signature = sign_identity_message(identity, *canonical.value_if());
  if (!signature) {
    return Result<void>::failure(*signature.error_if());
  }
  offer.signature = *signature.value_if();
  return Result<void>::success();
}

Result<void> sign_signed_answer(SignedAnswer& answer, const IdentityKeyPair& identity) {
  auto validated = validate_signed_answer(answer);
  if (!validated) {
    return validated;
  }
  auto canonical = canonicalize_for_signature(SigningDomain::answer, answer_fields(answer));
  if (!canonical) {
    return Result<void>::failure(*canonical.error_if());
  }
  auto signature = sign_identity_message(identity, *canonical.value_if());
  if (!signature) {
    return Result<void>::failure(*signature.error_if());
  }
  answer.signature = *signature.value_if();
  return Result<void>::success();
}

Result<void> sign_signed_candidate(SignedCandidate& candidate, const IdentityKeyPair& identity) {
  auto validated = validate_signed_candidate(candidate);
  if (!validated) {
    return validated;
  }
  auto canonical =
      canonicalize_for_signature(SigningDomain::candidate, candidate_fields(candidate));
  if (!canonical) {
    return Result<void>::failure(*canonical.error_if());
  }
  auto signature = sign_identity_message(identity, *canonical.value_if());
  if (!signature) {
    return Result<void>::failure(*signature.error_if());
  }
  candidate.signature = *signature.value_if();
  return Result<void>::success();
}

Result<void> verify_signed_offer(const SignedOffer& offer,
                                 std::span<const std::byte> initiator_public_key,
                                 std::uint64_t now_unix_milliseconds) {
  auto validated = validate_signed_offer(offer);
  if (!validated) {
    return validated;
  }
  return verify_signed_object(
      SigningDomain::offer, offer_fields(offer),
      std::span<const std::byte>{offer.signature.data(), offer.signature.size()},
      initiator_public_key, offer.binding.initiator.device_id,
      offer.binding.expires_unix_milliseconds, now_unix_milliseconds);
}

Result<void> verify_signed_answer(const SignedAnswer& answer,
                                  std::span<const std::byte> responder_public_key,
                                  std::uint64_t now_unix_milliseconds) {
  auto validated = validate_signed_answer(answer);
  if (!validated) {
    return validated;
  }
  return verify_signed_object(
      SigningDomain::answer, answer_fields(answer),
      std::span<const std::byte>{answer.signature.data(), answer.signature.size()},
      responder_public_key, answer.binding.responder.device_id,
      answer.binding.expires_unix_milliseconds, now_unix_milliseconds);
}

Result<SignalingCandidateOwner> verify_signed_candidate(
    const SignedCandidate& candidate, std::span<const std::byte> owner_public_key,
    std::uint64_t now_unix_milliseconds) {
  auto validated = validate_signed_candidate(candidate);
  if (!validated) {
    return Result<SignalingCandidateOwner>::failure(*validated.error_if());
  }
  auto canonical =
      canonicalize_for_signature(SigningDomain::candidate, candidate_fields(candidate));
  if (!canonical) {
    return Result<SignalingCandidateOwner>::failure(*canonical.error_if());
  }
  const auto expiry = validate_signed_expiry(
      candidate.binding.expires_unix_milliseconds, now_unix_milliseconds);
  if (!expiry) {
    return Result<SignalingCandidateOwner>::failure(*expiry.error_if());
  }
  auto verified = verify_identity_signature(
      owner_public_key, *canonical.value_if(),
      std::span<const std::byte>{candidate.signature.data(), candidate.signature.size()});
  if (!verified) {
    return Result<SignalingCandidateOwner>::failure(
        signaling_error(ErrorCode::authentication, "signaling_signature_invalid"));
  }
  auto derived = derive_device_id(owner_public_key);
  if (!derived) {
    return Result<SignalingCandidateOwner>::failure(*derived.error_if());
  }
  if (*derived.value_if() == candidate.binding.initiator.device_id) {
    return Result<SignalingCandidateOwner>::success(SignalingCandidateOwner::initiator);
  }
  if (*derived.value_if() == candidate.binding.responder.device_id) {
    return Result<SignalingCandidateOwner>::success(SignalingCandidateOwner::responder);
  }
  return Result<SignalingCandidateOwner>::failure(
      signaling_error(ErrorCode::authentication, "signaling_signer_identity_mismatch"));
}

Result<std::vector<std::byte>> encode_signed_offer(const SignedOffer& offer) {
  auto validated = validate_signed_offer(offer);
  if (!validated) {
    return Result<std::vector<std::byte>>::failure(*validated.error_if());
  }
  std::vector<std::byte> binding;
  append_bytes(binding, 1U, encode_device_endpoint(offer.binding.initiator));
  append_bytes(binding, 2U, encode_device_endpoint(offer.binding.responder));
  append_bytes(binding, 3U, offer.binding.request_id.bytes());
  append_bytes(binding, 4U, offer.binding.session_id.bytes());
  append_bytes(binding, 5U,
               std::span<const std::byte>{offer.binding.initiator_nonce.data(),
                                          offer.binding.initiator_nonce.size()});
  append_uint(binding, 6U, offer.binding.expires_unix_milliseconds);
  if (offer.binding.responder_nonce.has_value()) {
    append_bytes(binding, 7U,
                 std::span<const std::byte>{offer.binding.responder_nonce->data(),
                                            offer.binding.responder_nonce->size()});
  }

  std::vector<std::byte> output;
  output.reserve(offer.sdp.size() + 192U);
  append_bytes(output, 1U, binding);
  append_bytes(output, 2U, offer.sdp);
  append_bytes(output, 3U, fingerprint_bytes(offer.dtls_fingerprint));
  append_bytes(output, 4U, encode_signature(offer.signature));
  if (output.size() > max_signaling_object_bytes) {
    return Result<std::vector<std::byte>>::failure(
        signaling_error(ErrorCode::protocol, "signaling_object_too_large"));
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<SignedOffer> parse_signed_offer(std::span<const std::byte> payload) {
  if (payload.size() > max_signaling_object_bytes) {
    return Result<SignedOffer>::failure(
        signaling_error(ErrorCode::protocol, "signaling_object_too_large"));
  }
  ProtoReader reader(payload);
  std::optional<SignalBinding> binding;
  std::optional<std::vector<std::byte>> sdp;
  std::optional<DtlsFingerprint> fingerprint;
  std::optional<IdentitySignature> signature;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<SignedOffer>::failure(*field.error_if());
    }
    switch (field.value_if()->number) {
      case 1U: {
        if (field.value_if()->wire_type != 2U || binding) {
          return Result<SignedOffer>::failure(
              signaling_error(ErrorCode::protocol, "offer_binding_field_conflict"));
        }
        auto parsed_binding = parse_binding(field.value_if()->bytes, false, false);
        if (!parsed_binding) {
          return Result<SignedOffer>::failure(*parsed_binding.error_if());
        }
        binding = *parsed_binding.value_if();
        break;
      }
      case 2U:
        if (field.value_if()->wire_type != 2U || sdp) {
          return Result<SignedOffer>::failure(
              signaling_error(ErrorCode::protocol, "offer_sdp_field_conflict"));
        }
        sdp = std::vector<std::byte>{field.value_if()->bytes.begin(),
                                     field.value_if()->bytes.end()};
        break;
      case 3U: {
        if (field.value_if()->wire_type != 2U || fingerprint) {
          return Result<SignedOffer>::failure(
              signaling_error(ErrorCode::protocol, "offer_fingerprint_field_conflict"));
        }
        auto parsed_fingerprint = parse_fingerprint(
            field.value_if()->bytes, "offer_fingerprint_field_invalid");
        if (!parsed_fingerprint) {
          return Result<SignedOffer>::failure(*parsed_fingerprint.error_if());
        }
        fingerprint = *parsed_fingerprint.value_if();
        break;
      }
      case 4U: {
        if (field.value_if()->wire_type != 2U || signature) {
          return Result<SignedOffer>::failure(
              signaling_error(ErrorCode::protocol, "offer_signature_field_conflict"));
        }
        auto parsed_signature = parse_signature_message(field.value_if()->bytes);
        if (!parsed_signature) {
          return Result<SignedOffer>::failure(*parsed_signature.error_if());
        }
        signature = *parsed_signature.value_if();
        break;
      }
      default:
        return Result<SignedOffer>::failure(
            signaling_error(ErrorCode::protocol, "offer_field_unknown"));
    }
  }
  if (!binding || !sdp || !fingerprint || !signature) {
    return Result<SignedOffer>::failure(
        signaling_error(ErrorCode::protocol, "offer_field_missing"));
  }
  SignedOffer offer;
  offer.binding = *binding;
  offer.sdp = std::move(*sdp);
  offer.dtls_fingerprint = *fingerprint;
  offer.signature = *signature;
  auto validated = validate_signed_offer(offer);
  if (!validated) {
    return Result<SignedOffer>::failure(*validated.error_if());
  }
  return Result<SignedOffer>::success(std::move(offer));
}

Result<std::vector<std::byte>> encode_signed_answer(const SignedAnswer& answer) {
  auto validated = validate_signed_answer(answer);
  if (!validated) {
    return Result<std::vector<std::byte>>::failure(*validated.error_if());
  }
  std::vector<std::byte> binding;
  append_bytes(binding, 1U, encode_device_endpoint(answer.binding.initiator));
  append_bytes(binding, 2U, encode_device_endpoint(answer.binding.responder));
  append_bytes(binding, 3U, answer.binding.request_id.bytes());
  append_bytes(binding, 4U, answer.binding.session_id.bytes());
  append_bytes(binding, 5U,
               std::span<const std::byte>{answer.binding.initiator_nonce.data(),
                                          answer.binding.initiator_nonce.size()});
  append_uint(binding, 6U, answer.binding.expires_unix_milliseconds);
  append_bytes(binding, 7U,
               std::span<const std::byte>{answer.binding.responder_nonce->data(),
                                          answer.binding.responder_nonce->size()});

  std::vector<std::byte> output;
  output.reserve(answer.sdp.size() + 192U);
  append_bytes(output, 1U, binding);
  append_bytes(output, 2U, answer.sdp);
  append_bytes(output, 3U, fingerprint_bytes(answer.dtls_fingerprint));
  append_bytes(output, 4U, encode_signature(answer.signature));
  if (output.size() > max_signaling_object_bytes) {
    return Result<std::vector<std::byte>>::failure(
        signaling_error(ErrorCode::protocol, "signaling_object_too_large"));
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<SignedAnswer> parse_signed_answer(std::span<const std::byte> payload) {
  if (payload.size() > max_signaling_object_bytes) {
    return Result<SignedAnswer>::failure(
        signaling_error(ErrorCode::protocol, "signaling_object_too_large"));
  }
  ProtoReader reader(payload);
  std::optional<SignalBinding> binding;
  std::optional<std::vector<std::byte>> sdp;
  std::optional<DtlsFingerprint> fingerprint;
  std::optional<IdentitySignature> signature;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<SignedAnswer>::failure(*field.error_if());
    }
    switch (field.value_if()->number) {
      case 1U: {
        if (field.value_if()->wire_type != 2U || binding) {
          return Result<SignedAnswer>::failure(
              signaling_error(ErrorCode::protocol, "answer_binding_field_conflict"));
        }
        auto parsed_binding = parse_binding(field.value_if()->bytes, true, true);
        if (!parsed_binding) {
          return Result<SignedAnswer>::failure(*parsed_binding.error_if());
        }
        binding = *parsed_binding.value_if();
        break;
      }
      case 2U:
        if (field.value_if()->wire_type != 2U || sdp) {
          return Result<SignedAnswer>::failure(
              signaling_error(ErrorCode::protocol, "answer_sdp_field_conflict"));
        }
        sdp = std::vector<std::byte>{field.value_if()->bytes.begin(),
                                     field.value_if()->bytes.end()};
        break;
      case 3U: {
        if (field.value_if()->wire_type != 2U || fingerprint) {
          return Result<SignedAnswer>::failure(
              signaling_error(ErrorCode::protocol, "answer_fingerprint_field_conflict"));
        }
        auto parsed_fingerprint = parse_fingerprint(
            field.value_if()->bytes, "answer_fingerprint_field_invalid");
        if (!parsed_fingerprint) {
          return Result<SignedAnswer>::failure(*parsed_fingerprint.error_if());
        }
        fingerprint = *parsed_fingerprint.value_if();
        break;
      }
      case 4U: {
        if (field.value_if()->wire_type != 2U || signature) {
          return Result<SignedAnswer>::failure(
              signaling_error(ErrorCode::protocol, "answer_signature_field_conflict"));
        }
        auto parsed_signature = parse_signature_message(field.value_if()->bytes);
        if (!parsed_signature) {
          return Result<SignedAnswer>::failure(*parsed_signature.error_if());
        }
        signature = *parsed_signature.value_if();
        break;
      }
      default:
        return Result<SignedAnswer>::failure(
            signaling_error(ErrorCode::protocol, "answer_field_unknown"));
    }
  }
  if (!binding || !sdp || !fingerprint || !signature) {
    return Result<SignedAnswer>::failure(
        signaling_error(ErrorCode::protocol, "answer_field_missing"));
  }
  SignedAnswer answer;
  answer.binding = *binding;
  answer.sdp = std::move(*sdp);
  answer.dtls_fingerprint = *fingerprint;
  answer.signature = *signature;
  auto validated = validate_signed_answer(answer);
  if (!validated) {
    return Result<SignedAnswer>::failure(*validated.error_if());
  }
  return Result<SignedAnswer>::success(std::move(answer));
}

Result<std::vector<std::byte>> encode_signed_candidate(const SignedCandidate& candidate) {
  auto validated = validate_signed_candidate(candidate);
  if (!validated) {
    return Result<std::vector<std::byte>>::failure(*validated.error_if());
  }
  std::vector<std::byte> binding;
  append_bytes(binding, 1U, encode_device_endpoint(candidate.binding.initiator));
  append_bytes(binding, 2U, encode_device_endpoint(candidate.binding.responder));
  append_bytes(binding, 3U, candidate.binding.request_id.bytes());
  append_bytes(binding, 4U, candidate.binding.session_id.bytes());
  append_bytes(binding, 5U,
               std::span<const std::byte>{candidate.binding.initiator_nonce.data(),
                                          candidate.binding.initiator_nonce.size()});
  append_uint(binding, 6U, candidate.binding.expires_unix_milliseconds);
  append_bytes(binding, 7U,
               std::span<const std::byte>{candidate.binding.responder_nonce->data(),
                                          candidate.binding.responder_nonce->size()});

  std::vector<std::byte> output;
  output.reserve(candidate.candidate.size() + 320U);
  append_bytes(output, 1U, binding);
  append_uint(output, 2U, candidate.sequence);
  append_bytes(output, 3U, candidate.candidate);
  append_bytes(output, 4U,
               std::span<const std::byte>{
                   candidate.signaling_transcript_sha256.data(),
                   candidate.signaling_transcript_sha256.size()});
  append_bytes(
      output, 5U,
      std::span<const std::byte>{
          reinterpret_cast<const std::byte*>(candidate.owner_ice_ufrag.data()),
          candidate.owner_ice_ufrag.size()});
  append_bytes(output, 6U, fingerprint_bytes(candidate.owner_dtls_fingerprint));
  append_bytes(output, 7U, encode_signature(candidate.signature));
  if (output.size() > max_signaling_object_bytes) {
    return Result<std::vector<std::byte>>::failure(
        signaling_error(ErrorCode::protocol, "signaling_object_too_large"));
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<SignedCandidate> parse_signed_candidate(std::span<const std::byte> payload) {
  if (payload.size() > max_signaling_object_bytes) {
    return Result<SignedCandidate>::failure(
        signaling_error(ErrorCode::protocol, "signaling_object_too_large"));
  }
  ProtoReader reader(payload);
  std::optional<SignalBinding> binding;
  std::optional<std::uint32_t> sequence;
  std::optional<std::vector<std::byte>> candidate;
  std::optional<SignalingTranscriptSha256> transcript;
  std::optional<std::string> ufrag;
  std::optional<DtlsFingerprint> fingerprint;
  std::optional<IdentitySignature> signature;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<SignedCandidate>::failure(*field.error_if());
    }
    switch (field.value_if()->number) {
      case 1U: {
        if (field.value_if()->wire_type != 2U || binding) {
          return Result<SignedCandidate>::failure(
              signaling_error(ErrorCode::protocol, "candidate_binding_field_conflict"));
        }
        auto parsed_binding = parse_binding(field.value_if()->bytes, true, true);
        if (!parsed_binding) {
          return Result<SignedCandidate>::failure(*parsed_binding.error_if());
        }
        binding = *parsed_binding.value_if();
        break;
      }
      case 2U:
        if (field.value_if()->wire_type != 0U || sequence ||
            field.value_if()->integer > std::numeric_limits<std::uint32_t>::max()) {
          return Result<SignedCandidate>::failure(
              signaling_error(ErrorCode::protocol, "candidate_sequence_field_invalid"));
        }
        sequence = static_cast<std::uint32_t>(field.value_if()->integer);
        break;
      case 3U:
        if (field.value_if()->wire_type != 2U || candidate) {
          return Result<SignedCandidate>::failure(
              signaling_error(ErrorCode::protocol, "candidate_bytes_field_conflict"));
        }
        candidate = std::vector<std::byte>{field.value_if()->bytes.begin(),
                                           field.value_if()->bytes.end()};
        break;
      case 4U: {
        if (field.value_if()->wire_type != 2U || transcript) {
          return Result<SignedCandidate>::failure(
              signaling_error(ErrorCode::protocol, "candidate_transcript_field_conflict"));
        }
        SignalingTranscriptSha256 value{};
        auto copied =
            copy_exact(field.value_if()->bytes, value, "candidate_transcript_field_invalid");
        if (!copied) {
          return Result<SignedCandidate>::failure(*copied.error_if());
        }
        transcript = value;
        break;
      }
      case 5U:
        if (field.value_if()->wire_type != 2U || ufrag) {
          return Result<SignedCandidate>::failure(
              signaling_error(ErrorCode::protocol, "candidate_ufrag_field_conflict"));
        }
        ufrag = std::string{reinterpret_cast<const char*>(field.value_if()->bytes.data()),
                            field.value_if()->bytes.size()};
        break;
      case 6U: {
        if (field.value_if()->wire_type != 2U || fingerprint) {
          return Result<SignedCandidate>::failure(
              signaling_error(ErrorCode::protocol, "candidate_fingerprint_field_conflict"));
        }
        auto parsed_fingerprint = parse_fingerprint(
            field.value_if()->bytes, "candidate_fingerprint_field_invalid");
        if (!parsed_fingerprint) {
          return Result<SignedCandidate>::failure(*parsed_fingerprint.error_if());
        }
        fingerprint = *parsed_fingerprint.value_if();
        break;
      }
      case 7U: {
        if (field.value_if()->wire_type != 2U || signature) {
          return Result<SignedCandidate>::failure(
              signaling_error(ErrorCode::protocol, "candidate_signature_field_conflict"));
        }
        auto parsed_signature = parse_signature_message(field.value_if()->bytes);
        if (!parsed_signature) {
          return Result<SignedCandidate>::failure(*parsed_signature.error_if());
        }
        signature = *parsed_signature.value_if();
        break;
      }
      default:
        return Result<SignedCandidate>::failure(
            signaling_error(ErrorCode::protocol, "candidate_field_unknown"));
    }
  }
  if (!binding || !sequence || !candidate || !transcript || !ufrag || !fingerprint ||
      !signature) {
    return Result<SignedCandidate>::failure(
        signaling_error(ErrorCode::protocol, "candidate_field_missing"));
  }
  SignedCandidate parsed;
  parsed.binding = *binding;
  parsed.sequence = *sequence;
  parsed.candidate = std::move(*candidate);
  parsed.signaling_transcript_sha256 = *transcript;
  parsed.owner_ice_ufrag = std::move(*ufrag);
  parsed.owner_dtls_fingerprint = *fingerprint;
  parsed.signature = *signature;
  auto validated = validate_signed_candidate(parsed);
  if (!validated) {
    return Result<SignedCandidate>::failure(*validated.error_if());
  }
  return Result<SignedCandidate>::success(std::move(parsed));
}

Result<std::string> parse_sdp_ice_ufrag(std::span<const std::byte> sdp) {
  constexpr std::string_view marker{"a=ice-ufrag:"};
  std::size_t offset = 0U;
  while (offset < sdp.size()) {
    const auto line_end = static_cast<std::size_t>(
        std::find(sdp.begin() + static_cast<std::ptrdiff_t>(offset), sdp.end(),
                  std::byte{'\n'}) -
        sdp.begin());
    const auto line = sdp.subspan(offset, line_end - offset);
    auto* line_data = reinterpret_cast<const char*>(line.data());
    std::string_view line_view{line_data, line.size()};
    if (!line_view.empty() && line_view.back() == '\r') {
      line_view.remove_suffix(1U);
    }
    if (line_view.starts_with(marker)) {
      const auto value = line_view.substr(marker.size());
      if (value.size() < min_signaling_ice_ufrag_bytes ||
          value.size() > max_signaling_ice_ufrag_bytes || !is_printable_ascii(value)) {
        return Result<std::string>::failure(
            signaling_error(ErrorCode::protocol, "sdp_ice_ufrag_invalid"));
      }
      return Result<std::string>::success(std::string{value});
    }
    if (line_end == sdp.size()) {
      break;
    }
    offset = line_end + 1U;
  }
  return Result<std::string>::failure(
      signaling_error(ErrorCode::protocol, "sdp_ice_ufrag_missing"));
}

std::string_view signaling_candidate_owner_name(SignalingCandidateOwner owner) noexcept {
  switch (owner) {
    case SignalingCandidateOwner::initiator:
      return "initiator";
    case SignalingCandidateOwner::responder:
      return "responder";
  }
  return "unknown";
}

}  // namespace heyaki
