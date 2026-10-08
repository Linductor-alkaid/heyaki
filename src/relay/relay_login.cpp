#include "relay_login.hpp"
#include "../core/proto_codec.hpp"

#include <heyaki/security.hpp>
#include <heyaki/signing.hpp>

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

constexpr auto kProtoComponent = "relay_login";

Error login_error(ErrorCode code, const char* detail) {
  return Error{code, "relay_login", detail};
}

struct ParsedEndpoint {
  DeviceId device_id;
  EndpointId endpoint_id;
};

Result<ParsedEndpoint> parse_endpoint_message(std::span<const std::byte> input) {
  proto_codec::ProtoReader reader(input, kProtoComponent);
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
          login_error(ErrorCode::protocol, "endpoint_field_invalid"));
    }
    if (field.value_if()->number == 1U) {
      if (seen_device) {
        return Result<ParsedEndpoint>::failure(
            login_error(ErrorCode::protocol, "endpoint_field_conflict"));
      }
      auto copied = proto_codec::copy_exact(field.value_if()->bytes, device, kProtoComponent,
                                            "endpoint_device_id_invalid");
      if (!copied) {
        return Result<ParsedEndpoint>::failure(*copied.error_if());
      }
      seen_device = true;
    } else if (field.value_if()->number == 2U) {
      if (seen_endpoint) {
        return Result<ParsedEndpoint>::failure(
            login_error(ErrorCode::protocol, "endpoint_field_conflict"));
      }
      auto copied = proto_codec::copy_exact(field.value_if()->bytes, endpoint, kProtoComponent,
                                            "endpoint_id_invalid");
      if (!copied) {
        return Result<ParsedEndpoint>::failure(*copied.error_if());
      }
      seen_endpoint = true;
    } else {
      return Result<ParsedEndpoint>::failure(
          login_error(ErrorCode::protocol, "endpoint_unknown_field"));
    }
  }
  if (!seen_device || !seen_endpoint) {
    return Result<ParsedEndpoint>::failure(
        login_error(ErrorCode::protocol, "endpoint_field_missing"));
  }
  return Result<ParsedEndpoint>::success(
      ParsedEndpoint{.device_id = DeviceId{device}, .endpoint_id = EndpointId{endpoint}});
}

Result<ProtocolVersion> parse_version_message(std::span<const std::byte> input) {
  proto_codec::ProtoReader reader(input, kProtoComponent);
  ProtocolVersion version;
  bool seen_major = false;
  bool seen_minor = false;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<ProtocolVersion>::failure(*field.error_if());
    }
    if (field.value_if()->wire_type != 0U ||
        field.value_if()->integer > std::numeric_limits<std::uint32_t>::max()) {
      return Result<ProtocolVersion>::failure(
          login_error(ErrorCode::protocol, "version_field_invalid"));
    }
    if (field.value_if()->number == 1U) {
      if (seen_major) {
        return Result<ProtocolVersion>::failure(
            login_error(ErrorCode::protocol, "version_field_conflict"));
      }
      version.major = static_cast<std::uint32_t>(field.value_if()->integer);
      seen_major = true;
    } else if (field.value_if()->number == 2U) {
      if (seen_minor) {
        return Result<ProtocolVersion>::failure(
            login_error(ErrorCode::protocol, "version_field_conflict"));
      }
      version.minor = static_cast<std::uint32_t>(field.value_if()->integer);
      seen_minor = true;
    } else {
      return Result<ProtocolVersion>::failure(
          login_error(ErrorCode::protocol, "version_unknown_field"));
    }
  }
  if (!seen_major || !seen_minor) {
    return Result<ProtocolVersion>::failure(
        login_error(ErrorCode::protocol, "version_field_missing"));
  }
  return Result<ProtocolVersion>::success(version);
}

struct CapabilityAdvertisement {
  CapabilitySet supported;
  CapabilitySet required;
};

Result<CapabilityAdvertisement> parse_capabilities_message(std::span<const std::byte> input) {
  proto_codec::ProtoReader reader(input, kProtoComponent);
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
          login_error(ErrorCode::protocol, "capability_field_invalid"));
    }
    if (field.value_if()->number == 1U) {
      if (seen_supported) {
        return Result<CapabilityAdvertisement>::failure(
            login_error(ErrorCode::protocol, "capability_field_conflict"));
      }
      output.supported.bits = field.value_if()->integer;
      seen_supported = true;
    } else if (field.value_if()->number == 2U) {
      if (seen_required) {
        return Result<CapabilityAdvertisement>::failure(
            login_error(ErrorCode::protocol, "capability_field_conflict"));
      }
      output.required.bits = field.value_if()->integer;
      seen_required = true;
    } else {
      return Result<CapabilityAdvertisement>::failure(
          login_error(ErrorCode::protocol, "capability_unknown_field"));
    }
  }
  if (!seen_supported || !seen_required) {
    return Result<CapabilityAdvertisement>::failure(
        login_error(ErrorCode::protocol, "capability_field_missing"));
  }
  if (output.supported.bits == 0U || !output.supported.contains(output.required)) {
    return Result<CapabilityAdvertisement>::failure(
        login_error(ErrorCode::protocol, "capability_required_not_supported"));
  }
  return Result<CapabilityAdvertisement>::success(output);
}

Result<IdentitySignature> parse_signature_message(std::span<const std::byte> input) {
  proto_codec::ProtoReader reader(input, kProtoComponent);
  IdentitySignature signature{};
  bool seen = false;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<IdentitySignature>::failure(*field.error_if());
    }
    if (field.value_if()->number != 1U || field.value_if()->wire_type != 2U || seen) {
      return Result<IdentitySignature>::failure(
          login_error(ErrorCode::protocol, "signature_field_invalid"));
    }
    auto copied = proto_codec::copy_exact(field.value_if()->bytes, signature, kProtoComponent,
                                          "signature_length_invalid");
    if (!copied) {
      return Result<IdentitySignature>::failure(*copied.error_if());
    }
    seen = true;
  }
  if (!seen) {
    return Result<IdentitySignature>::failure(
        login_error(ErrorCode::protocol, "signature_field_missing"));
  }
  return Result<IdentitySignature>::success(signature);
}

std::vector<std::byte> encode_endpoint_message(DeviceId device_id, EndpointId endpoint_id) {
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, device_id.bytes());
  proto_codec::append_bytes(output, 2U, endpoint_id.bytes());
  return output;
}

std::vector<std::byte> encode_version_message(ProtocolVersion version) {
  std::vector<std::byte> output;
  proto_codec::append_uint(output, 1U, version.major);
  proto_codec::append_uint(output, 2U, version.minor);
  return output;
}

std::vector<std::byte> encode_capabilities_message(CapabilitySet supported,
                                                   CapabilitySet required) {
  std::vector<std::byte> output;
  proto_codec::append_uint(output, 1U, supported.bits);
  proto_codec::append_uint(output, 2U, required.bits);
  return output;
}

std::vector<std::byte> encode_signature_message(IdentitySignature signature) {
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, signature);
  return output;
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

}  // namespace

Result<std::vector<std::byte>> encode_relay_login_request(
    const RelayLoginRequest& request) {
  if (request.device_id.is_zero() || request.endpoint_id.is_zero() ||
      request.identity_public_key == IdentityPublicKey{} ||
      request.challenge_nonce == RelayLoginNonce{} || !is_nonempty_utf8(request.tenant) ||
      request.protocol_version.major == 0U || request.supported.bits == 0U ||
      !request.supported.contains(request.required) || request.enrollment_generation == 0U ||
      request.expires_unix_milliseconds == 0U || request.signature == IdentitySignature{}) {
    return Result<std::vector<std::byte>>::failure(
        login_error(ErrorCode::configuration, "login_request_invalid"));
  }
  std::vector<std::byte> output;
  output.reserve(512U);
  proto_codec::append_bytes(output, 1U,
                            encode_endpoint_message(request.device_id, request.endpoint_id));
  proto_codec::append_bytes(output, 2U, request.identity_public_key);
  proto_codec::append_bytes(output, 3U, request.challenge_nonce);
  proto_codec::append_text(output, 4U, request.tenant);
  proto_codec::append_bytes(output, 5U, encode_version_message(request.protocol_version));
  proto_codec::append_bytes(output, 6U,
                            encode_capabilities_message(request.supported, request.required));
  proto_codec::append_uint(output, 7U, request.enrollment_generation);
  proto_codec::append_uint(output, 8U, request.expires_unix_milliseconds);
  proto_codec::append_bytes(output, 9U, encode_signature_message(request.signature));
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RelayLoginRequest> parse_relay_login_request(std::span<const std::byte> payload) {
  if (payload.empty() || payload.size() > max_relay_login_request_bytes) {
    return Result<RelayLoginRequest>::failure(
        login_error(ErrorCode::protocol, "login_request_size_invalid"));
  }
  proto_codec::ProtoReader reader(payload, kProtoComponent);
  RelayLoginRequest request;
  std::array<bool, 9U> seen{};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RelayLoginRequest>::failure(*field.error_if());
    }
    if (field.value_if()->number == 0U || field.value_if()->number > seen.size() ||
        seen[field.value_if()->number - 1U]) {
      return Result<RelayLoginRequest>::failure(
          login_error(ErrorCode::protocol, "login_field_conflict"));
    }
    seen[field.value_if()->number - 1U] = true;
    switch (field.value_if()->number) {
      case 1U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<RelayLoginRequest>::failure(
              login_error(ErrorCode::protocol, "login_endpoint_invalid"));
        }
        auto endpoint = parse_endpoint_message(field.value_if()->bytes);
        if (!endpoint) {
          return Result<RelayLoginRequest>::failure(*endpoint.error_if());
        }
        request.device_id = endpoint.value_if()->device_id;
        request.endpoint_id = endpoint.value_if()->endpoint_id;
        break;
      }
      case 2U: {
        auto copied =
            field.value_if()->wire_type == 2U
                ? proto_codec::copy_exact(field.value_if()->bytes, request.identity_public_key,
                                          kProtoComponent, "login_public_key_invalid")
                : Result<void>::failure(
                      login_error(ErrorCode::protocol, "login_public_key_invalid"));
        if (!copied) {
          return Result<RelayLoginRequest>::failure(*copied.error_if());
        }
        break;
      }
      case 3U: {
        auto copied =
            field.value_if()->wire_type == 2U
                ? proto_codec::copy_exact(field.value_if()->bytes, request.challenge_nonce,
                                          kProtoComponent, "login_challenge_nonce_invalid")
                : Result<void>::failure(
                      login_error(ErrorCode::protocol, "login_challenge_nonce_invalid"));
        if (!copied) {
          return Result<RelayLoginRequest>::failure(*copied.error_if());
        }
        break;
      }
      case 4U: {
        if (field.value_if()->wire_type != 2U || field.value_if()->bytes.empty() ||
            field.value_if()->bytes.size() > 128U) {
          return Result<RelayLoginRequest>::failure(
              login_error(ErrorCode::protocol, "login_tenant_invalid"));
        }
        const auto* text = reinterpret_cast<const char*>(field.value_if()->bytes.data());
        request.tenant.assign(text, field.value_if()->bytes.size());
        break;
      }
      case 5U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<RelayLoginRequest>::failure(
              login_error(ErrorCode::protocol, "login_version_invalid"));
        }
        auto version = parse_version_message(field.value_if()->bytes);
        if (!version) {
          return Result<RelayLoginRequest>::failure(*version.error_if());
        }
        request.protocol_version = *version.value_if();
        break;
      }
      case 6U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<RelayLoginRequest>::failure(
              login_error(ErrorCode::protocol, "login_capabilities_invalid"));
        }
        auto capabilities = parse_capabilities_message(field.value_if()->bytes);
        if (!capabilities) {
          return Result<RelayLoginRequest>::failure(*capabilities.error_if());
        }
        request.supported = capabilities.value_if()->supported;
        request.required = capabilities.value_if()->required;
        break;
      }
      case 7U:
        if (field.value_if()->wire_type != 0U || field.value_if()->integer == 0U) {
          return Result<RelayLoginRequest>::failure(
              login_error(ErrorCode::protocol, "login_generation_invalid"));
        }
        request.enrollment_generation = field.value_if()->integer;
        break;
      case 8U:
        if (field.value_if()->wire_type != 0U || field.value_if()->integer == 0U) {
          return Result<RelayLoginRequest>::failure(
              login_error(ErrorCode::protocol, "login_expiry_invalid"));
        }
        request.expires_unix_milliseconds = field.value_if()->integer;
        break;
      case 9U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<RelayLoginRequest>::failure(
              login_error(ErrorCode::protocol, "login_signature_invalid"));
        }
        auto signature = parse_signature_message(field.value_if()->bytes);
        if (!signature) {
          return Result<RelayLoginRequest>::failure(*signature.error_if());
        }
        request.signature = *signature.value_if();
        break;
      }
      default:
        return Result<RelayLoginRequest>::failure(
            login_error(ErrorCode::protocol, "login_unknown_field"));
    }
  }
  if (!std::all_of(seen.begin(), seen.end(), [](bool value) { return value; })) {
    return Result<RelayLoginRequest>::failure(
        login_error(ErrorCode::protocol, "login_field_missing"));
  }
  return Result<RelayLoginRequest>::success(std::move(request));
}

Result<std::vector<std::byte>> canonical_relay_login_request(
    const RelayLoginRequest& request, RelayId relay_id) {
  std::vector<CanonicalField> fields;
  fields.reserve(12U);
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
  fields.push_back(CanonicalField{12U, canonical_uint64(request.enrollment_generation)});
  return canonicalize_for_signature(SigningDomain::relay_login, fields);
}

Result<void> sign_relay_login_request(RelayLoginRequest& request, RelayId relay_id,
                                      const IdentityKeyPair& identity) {
  auto canonical = canonical_relay_login_request(request, relay_id);
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

Result<void> validate_relay_login_request(const RelayLoginRequest& request,
                                          const RelayLoginChallenge& challenge,
                                          const RelayDeviceRecord& device,
                                          std::uint64_t now_unix_milliseconds) {
  if (request.device_id.is_zero() || request.endpoint_id.is_zero() ||
      request.identity_public_key == IdentityPublicKey{} ||
      request.challenge_nonce == RelayLoginNonce{} || !is_nonempty_utf8(request.tenant) ||
      request.supported.bits == 0U || request.enrollment_generation == 0U ||
      request.expires_unix_milliseconds == 0U || request.signature == IdentitySignature{} ||
      challenge.relay_id == RelayId{} || challenge.nonce == RelayLoginNonce{} ||
      challenge.expires_unix_milliseconds == 0U) {
    return Result<void>::failure(login_error(ErrorCode::authentication, "login_request_invalid"));
  }

  auto derived = derive_device_id(request.identity_public_key);
  if (!derived || *derived.value_if() != request.device_id) {
    return Result<void>::failure(
        login_error(ErrorCode::authentication, "login_device_id_mismatch"));
  }
  if (request.challenge_nonce != challenge.nonce) {
    return Result<void>::failure(login_error(ErrorCode::authentication,
                                             "login_challenge_nonce_mismatch"));
  }
  auto challenge_expiry = validate_signed_expiry(challenge.expires_unix_milliseconds,
                                                 now_unix_milliseconds);
  if (!challenge_expiry) {
    return Result<void>::failure(
        Error{ErrorCode::authentication, "relay_login",
              std::string{challenge_expiry.error_if()->safe_detail()}});
  }
  if (request.expires_unix_milliseconds > challenge.expires_unix_milliseconds) {
    return Result<void>::failure(login_error(ErrorCode::authentication,
                                             "login_expiry_exceeds_challenge"));
  }
  auto request_expiry =
      validate_signed_expiry(request.expires_unix_milliseconds, now_unix_milliseconds);
  if (!request_expiry) {
    return Result<void>::failure(
        Error{ErrorCode::authentication, "relay_login",
              std::string{request_expiry.error_if()->safe_detail()}});
  }

  if (device.device_id != request.device_id ||
      device.public_key != request.identity_public_key || device.tenant != request.tenant) {
    return Result<void>::failure(login_error(ErrorCode::authentication,
                                             "login_device_record_mismatch"));
  }
  if (device.status == RelayDeviceStatus::revoked) {
    return Result<void>::failure(login_error(ErrorCode::enrollment_revoked,
                                             "relay_login_device_revoked"));
  }
  if (device.enrollment_generation != request.enrollment_generation) {
    return Result<void>::failure(login_error(ErrorCode::authentication,
                                             "login_generation_mismatch"));
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
        Error{ErrorCode::protocol, "relay_login",
              std::string{negotiated.error_if()->safe_detail()}});
  }

  auto canonical = canonical_relay_login_request(request, challenge.relay_id);
  if (!canonical) {
    return Result<void>::failure(
        Error{ErrorCode::protocol, "relay_login",
              std::string{canonical.error_if()->safe_detail()}});
  }
  return verify_identity_signature(request.identity_public_key, *canonical.value_if(),
                                   request.signature);
}

}  // namespace heyaki
