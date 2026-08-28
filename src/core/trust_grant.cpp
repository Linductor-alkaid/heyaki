#include <heyaki/trust_grant.hpp>

#include "proto_codec.hpp"

#include <heyaki/security.hpp>
#include <heyaki/signing.hpp>

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <utility>

namespace heyaki {
namespace {

Error trust_grant_error(ErrorCode code, const char* detail) {
  return {code, "trust_grant", detail};
}

bool is_printable_ascii_scope_byte(char value) noexcept {
  return value >= 0x21 && value <= 0x7E;
}

std::vector<std::byte> canonical_scope_list(const std::vector<std::string>& scopes) {
  // Wire protocol 5: U16 big-endian count, then per scope U16 big-endian
  // length plus exact ASCII bytes, sorted and unique.
  std::vector<std::byte> output;
  output.push_back(static_cast<std::byte>((scopes.size() >> 8U) & 0xFFU));
  output.push_back(static_cast<std::byte>(scopes.size() & 0xFFU));
  for (const auto& scope : scopes) {
    output.push_back(static_cast<std::byte>((scope.size() >> 8U) & 0xFFU));
    output.push_back(static_cast<std::byte>(scope.size() & 0xFFU));
    output.insert(output.end(), reinterpret_cast<const std::byte*>(scope.data()),
                  reinterpret_cast<const std::byte*>(scope.data()) + scope.size());
  }
  return output;
}

std::vector<CanonicalField> trust_grant_fields(const SignedTrustGrant& grant) {
  std::vector<CanonicalField> fields;
  fields.reserve(8U);
  fields.push_back({1U, canonical_bytes(grant.grant_id)});
  fields.push_back({2U, canonical_bytes(grant.issuer)});
  fields.push_back({3U, canonical_bytes(grant.subject)});
  fields.push_back({4U, canonical_scope_list(grant.granted_scopes)});
  fields.push_back({5U, canonical_uint64(grant.password_generation)});
  fields.push_back({6U, canonical_uint64(grant.issued_unix_milliseconds)});
  if (grant.expires_unix_milliseconds.has_value()) {
    fields.push_back({7U, canonical_uint64(*grant.expires_unix_milliseconds)});
  }
  fields.push_back(
      {8U, std::vector<std::byte>{grant.nonce.begin(), grant.nonce.end()}});
  return fields;
}

bool all_zero(const PairingNonce& nonce) noexcept {
  return std::all_of(nonce.begin(), nonce.end(),
                     [](std::byte byte) { return byte == std::byte{0}; });
}

}  // namespace

bool is_valid_trust_scope(std::string_view scope) noexcept {
  if (scope.empty() || scope.size() > max_trust_scope_bytes) {
    return false;
  }
  return std::all_of(scope.begin(), scope.end(), is_printable_ascii_scope_byte);
}

Result<std::vector<std::string>> normalize_trust_scopes(std::vector<std::string> scopes) {
  if (scopes.size() > max_trust_scopes) {
    return Result<std::vector<std::string>>::failure(
        trust_grant_error(ErrorCode::protocol, "scope_count_limit"));
  }
  for (const auto& scope : scopes) {
    if (!is_valid_trust_scope(scope)) {
      return Result<std::vector<std::string>>::failure(
          trust_grant_error(ErrorCode::protocol, "scope_syntax_invalid"));
    }
  }
  std::sort(scopes.begin(), scopes.end());
  scopes.erase(std::unique(scopes.begin(), scopes.end()), scopes.end());
  return Result<std::vector<std::string>>::success(std::move(scopes));
}

bool trust_scope_covers(std::string_view granted, std::string_view requested) noexcept {
  if (granted == requested) {
    return true;
  }
  constexpr std::string_view wildcard{":*"};
  if (granted.size() > wildcard.size() &&
      granted.substr(granted.size() - wildcard.size()) == wildcard) {
    const auto prefix = granted.substr(0, granted.size() - wildcard.size());
    return requested.size() > prefix.size() + 1U &&
           requested.substr(0, prefix.size()) == prefix &&
           requested[prefix.size()] == ':';
  }
  return false;
}

std::vector<std::string> intersect_trust_scopes(
    const std::vector<std::string>& requested, const std::vector<std::string>& granted) {
  std::vector<std::string> allowed;
  allowed.reserve(requested.size());
  for (const auto& scope : requested) {
    if (std::any_of(granted.begin(), granted.end(), [&](const auto& grant_scope) {
          return trust_scope_covers(grant_scope, scope);
        })) {
      allowed.push_back(scope);
    }
  }
  return allowed;
}

Result<void> validate_signed_trust_grant(const SignedTrustGrant& grant) {
  if (grant.grant_id.is_zero() || grant.issuer.is_zero() || grant.subject.is_zero() ||
      grant.issuer == grant.subject) {
    return Result<void>::failure(
        trust_grant_error(ErrorCode::protocol, "grant_binding_invalid"));
  }
  if (grant.password_generation == 0U || grant.issued_unix_milliseconds == 0U) {
    return Result<void>::failure(
        trust_grant_error(ErrorCode::protocol, "grant_generation_invalid"));
  }
  if (all_zero(grant.nonce)) {
    return Result<void>::failure(
        trust_grant_error(ErrorCode::protocol, "grant_nonce_invalid"));
  }
  if (grant.granted_scopes.empty() || grant.granted_scopes.size() > max_trust_scopes) {
    return Result<void>::failure(
        trust_grant_error(ErrorCode::protocol, "grant_scope_count_invalid"));
  }
  for (const auto& scope : grant.granted_scopes) {
    if (!is_valid_trust_scope(scope)) {
      return Result<void>::failure(
          trust_grant_error(ErrorCode::protocol, "scope_syntax_invalid"));
    }
  }
  if (!std::is_sorted(grant.granted_scopes.begin(), grant.granted_scopes.end()) ||
      std::adjacent_find(grant.granted_scopes.begin(), grant.granted_scopes.end()) !=
          grant.granted_scopes.end()) {
    return Result<void>::failure(
        trust_grant_error(ErrorCode::protocol, "scope_list_not_canonical"));
  }
  if (grant.expires_unix_milliseconds.has_value() &&
      *grant.expires_unix_milliseconds <= grant.issued_unix_milliseconds) {
    return Result<void>::failure(
        trust_grant_error(ErrorCode::protocol, "grant_expiry_invalid"));
  }
  return Result<void>::success();
}

Result<std::vector<std::byte>> canonical_signed_trust_grant(const SignedTrustGrant& grant) {
  auto validated = validate_signed_trust_grant(grant);
  if (!validated) {
    return Result<std::vector<std::byte>>::failure(*validated.error_if());
  }
  auto fields = trust_grant_fields(grant);
  return canonicalize_for_signature(SigningDomain::trust_grant,
                                    std::span<const CanonicalField>{fields});
}

Result<void> sign_signed_trust_grant(SignedTrustGrant& grant,
                                     const IdentityKeyPair& issuer_identity) {
  if (issuer_identity.device_id() != grant.issuer) {
    return Result<void>::failure(
        trust_grant_error(ErrorCode::identity, "signer_identity_mismatch"));
  }
  auto canonical = canonical_signed_trust_grant(grant);
  if (!canonical) {
    return Result<void>::failure(*canonical.error_if());
  }
  auto signature = sign_identity_message(issuer_identity, *canonical.value_if());
  if (!signature) {
    return Result<void>::failure(*signature.error_if());
  }
  grant.signature = *signature.value_if();
  return Result<void>::success();
}

Result<void> verify_signed_trust_grant(const SignedTrustGrant& grant,
                                       std::span<const std::byte> issuer_public_key,
                                       std::uint64_t now_unix_milliseconds) {
  auto validated = validate_signed_trust_grant(grant);
  if (!validated) {
    return validated;
  }
  if (grant.expires_unix_milliseconds.has_value()) {
    auto expiry = validate_signed_expiry(*grant.expires_unix_milliseconds,
                                         now_unix_milliseconds);
    if (!expiry) {
      return expiry;
    }
  }
  auto canonical = canonical_signed_trust_grant(grant);
  if (!canonical) {
    return Result<void>::failure(*canonical.error_if());
  }
  auto verified =
      verify_identity_signature(issuer_public_key, *canonical.value_if(), grant.signature);
  if (!verified) {
    return Result<void>::failure(
        trust_grant_error(ErrorCode::authentication, "signature_invalid"));
  }
  auto derived = derive_device_id(issuer_public_key);
  if (!derived || *derived.value_if() != grant.issuer) {
    return Result<void>::failure(
        trust_grant_error(ErrorCode::authentication, "issuer_identity_mismatch"));
  }
  return Result<void>::success();
}

Result<std::vector<std::byte>> encode_signed_trust_grant(const SignedTrustGrant& grant) {
  auto validated = validate_signed_trust_grant(grant);
  if (!validated) {
    return Result<std::vector<std::byte>>::failure(*validated.error_if());
  }
  std::vector<std::byte> output;
  output.reserve(256U);
  proto_codec::append_bytes(output, 1U, grant.grant_id.bytes());
  proto_codec::append_bytes(output, 2U, grant.issuer.bytes());
  proto_codec::append_bytes(output, 3U, grant.subject.bytes());
  for (const auto& scope : grant.granted_scopes) {
    proto_codec::append_text(output, 4U, scope);
  }
  proto_codec::append_uint(output, 5U, grant.password_generation);
  proto_codec::append_uint(output, 6U, grant.issued_unix_milliseconds);
  if (grant.expires_unix_milliseconds.has_value()) {
    proto_codec::append_uint(output, 7U, *grant.expires_unix_milliseconds);
  }
  proto_codec::append_bytes(output, 8U,
                            std::span<const std::byte>{grant.nonce.data(),
                                                       grant.nonce.size()});
  proto_codec::append_bytes(output, 9U,
                            std::span<const std::byte>{grant.signature.data(),
                                                       grant.signature.size()});
  if (output.size() > max_trust_grant_wire_bytes) {
    return Result<std::vector<std::byte>>::failure(
        trust_grant_error(ErrorCode::resource_exhausted, "object_too_large"));
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<SignedTrustGrant> parse_signed_trust_grant(std::span<const std::byte> payload) {
  if (payload.size() > max_trust_grant_wire_bytes) {
    return Result<SignedTrustGrant>::failure(
        trust_grant_error(ErrorCode::resource_exhausted, "object_too_large"));
  }
  proto_codec::ProtoReader reader(payload);
  std::optional<GrantId> grant_id;
  std::optional<DeviceId> issuer;
  std::optional<DeviceId> subject;
  std::optional<std::vector<std::string>> scopes;
  std::optional<std::uint64_t> password_generation;
  std::optional<std::uint64_t> issued;
  std::optional<std::uint64_t> expires;
  std::optional<PairingNonce> nonce;
  std::optional<IdentitySignature> signature;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<SignedTrustGrant>::failure(*field.error_if());
    }
    switch (field.value_if()->number) {
      case 1U: {
        if (field.value_if()->wire_type != 2U || grant_id) {
          return Result<SignedTrustGrant>::failure(
              trust_grant_error(ErrorCode::protocol, "grant_id_field_conflict"));
        }
        GrantId::Storage value{};
        auto copied = proto_codec::copy_exact(field.value_if()->bytes, value,
                                              "grant_id_field_invalid");
        if (!copied) {
          return Result<SignedTrustGrant>::failure(*copied.error_if());
        }
        grant_id = GrantId{value};
        break;
      }
      case 2U: {
        if (field.value_if()->wire_type != 2U || issuer) {
          return Result<SignedTrustGrant>::failure(
              trust_grant_error(ErrorCode::protocol, "issuer_field_conflict"));
        }
        DeviceId::Storage value{};
        auto copied = proto_codec::copy_exact(field.value_if()->bytes, value,
                                              "issuer_field_invalid");
        if (!copied) {
          return Result<SignedTrustGrant>::failure(*copied.error_if());
        }
        issuer = DeviceId{value};
        break;
      }
      case 3U: {
        if (field.value_if()->wire_type != 2U || subject) {
          return Result<SignedTrustGrant>::failure(
              trust_grant_error(ErrorCode::protocol, "subject_field_conflict"));
        }
        DeviceId::Storage value{};
        auto copied = proto_codec::copy_exact(field.value_if()->bytes, value,
                                              "subject_field_invalid");
        if (!copied) {
          return Result<SignedTrustGrant>::failure(*copied.error_if());
        }
        subject = DeviceId{value};
        break;
      }
      case 4U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<SignedTrustGrant>::failure(
              trust_grant_error(ErrorCode::protocol, "scope_field_invalid"));
        }
        const auto text = reader.text(*field.value_if());
        if (!is_valid_trust_scope(text)) {
          return Result<SignedTrustGrant>::failure(
              trust_grant_error(ErrorCode::protocol, "scope_syntax_invalid"));
        }
        if (!scopes) scopes.emplace();
        if (scopes->size() >= max_trust_scopes) {
          return Result<SignedTrustGrant>::failure(
              trust_grant_error(ErrorCode::protocol, "scope_count_limit"));
        }
        scopes->emplace_back(text);
        break;
      }
      case 5U:
        if (field.value_if()->wire_type != 0U || password_generation) {
          return Result<SignedTrustGrant>::failure(
              trust_grant_error(ErrorCode::protocol, "generation_field_conflict"));
        }
        password_generation = field.value_if()->integer;
        break;
      case 6U:
        if (field.value_if()->wire_type != 0U || issued) {
          return Result<SignedTrustGrant>::failure(
              trust_grant_error(ErrorCode::protocol, "issued_field_conflict"));
        }
        issued = field.value_if()->integer;
        break;
      case 7U:
        if (field.value_if()->wire_type != 0U || expires) {
          return Result<SignedTrustGrant>::failure(
              trust_grant_error(ErrorCode::protocol, "expiry_field_conflict"));
        }
        expires = field.value_if()->integer;
        break;
      case 8U: {
        if (field.value_if()->wire_type != 2U || nonce) {
          return Result<SignedTrustGrant>::failure(
              trust_grant_error(ErrorCode::protocol, "nonce_field_conflict"));
        }
        PairingNonce value{};
        auto copied =
            proto_codec::copy_exact(field.value_if()->bytes, value, "nonce_field_invalid");
        if (!copied) {
          return Result<SignedTrustGrant>::failure(*copied.error_if());
        }
        nonce = value;
        break;
      }
      case 9U: {
        if (field.value_if()->wire_type != 2U || signature) {
          return Result<SignedTrustGrant>::failure(
              trust_grant_error(ErrorCode::protocol, "signature_field_conflict"));
        }
        IdentitySignature value{};
        auto copied = proto_codec::copy_exact(field.value_if()->bytes, value,
                                              "signature_field_invalid");
        if (!copied) {
          return Result<SignedTrustGrant>::failure(*copied.error_if());
        }
        signature = value;
        break;
      }
      default:
        return Result<SignedTrustGrant>::failure(
            trust_grant_error(ErrorCode::protocol, "field_unknown"));
    }
  }
  if (!grant_id || !issuer || !subject || !scopes || scopes->empty() ||
      !password_generation || !issued || !nonce || !signature) {
    return Result<SignedTrustGrant>::failure(
        trust_grant_error(ErrorCode::protocol, "field_missing"));
  }
  SignedTrustGrant grant;
  grant.grant_id = *grant_id;
  grant.issuer = *issuer;
  grant.subject = *subject;
  grant.granted_scopes = *scopes;
  grant.password_generation = *password_generation;
  grant.issued_unix_milliseconds = *issued;
  grant.expires_unix_milliseconds = expires;
  grant.nonce = *nonce;
  grant.signature = *signature;
  auto validated = validate_signed_trust_grant(grant);
  if (!validated) {
    return Result<SignedTrustGrant>::failure(*validated.error_if());
  }
  return Result<SignedTrustGrant>::success(std::move(grant));
}

TrustAdjudication adjudicate_trust_scopes(
    const std::vector<std::string>& requested_scopes,
    const std::vector<std::string>& grant_scopes,
    const std::optional<std::vector<std::string>>& local_policy_scopes) {
  TrustAdjudication result;
  auto allowed = intersect_trust_scopes(requested_scopes, grant_scopes);
  if (local_policy_scopes.has_value()) {
    allowed = intersect_trust_scopes(allowed, *local_policy_scopes);
  }
  result.allowed_scopes = std::move(allowed);
  result.authorized = !result.allowed_scopes.empty();
  return result;
}

}  // namespace heyaki
