#pragma once

// M5 test helper: seeds mutual TrustStore trust between two profile stores so
// their sessions authorize without pairing. The Node's session layer is
// default-deny (RULE-03): an identity-verified but untrusted peer lands in
// pairing_restricted and never reaches `authenticated`. Tests that only care
// about connectivity (M3/M4 scenarios) pre-seed grants instead of running the
// password pairing flow; M5's own tests exercise the pairing path.

#include <heyaki/identity.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/trust_grant.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace heyaki::test {

inline constexpr std::uint64_t seed_grant_time = 1'700'000'000'000U;

[[nodiscard]] inline Result<void> seed_one_way_trust(
    ProfileStore& issuer_store, ProfileStore& subject_store,
    const std::vector<std::string>& scopes, std::uint64_t now_unix_milliseconds,
    std::optional<std::uint64_t> expires = std::nullopt, std::byte grant_slot = std::byte{0}) {
  auto issuer_identity = issuer_store.load_identity();
  if (!issuer_identity) return Result<void>::failure(*issuer_identity.error_if());
  auto normalized = normalize_trust_scopes(scopes);
  if (!normalized) return Result<void>::failure(*normalized.error_if());
  SignedTrustGrant grant;
  grant.issuer = issuer_store.device_id();
  grant.subject = subject_store.device_id();
  // Deterministic per (issuer, subject, direction) so repeated seeding of
  // several pairs never collides on the TrustStore primary key.
  GrantId::Storage grant_bytes{};
  const auto& issuer_bytes = grant.issuer.bytes();
  const auto& subject_bytes = grant.subject.bytes();
  const auto slot = std::to_integer<std::uint8_t>(grant_slot);
  for (std::size_t index = 0U; index < grant_bytes.size(); ++index) {
    grant_bytes[index] = static_cast<std::byte>(
        (std::to_integer<std::uint8_t>(issuer_bytes[index % issuer_bytes.size()]) *
             7U +
         std::to_integer<std::uint8_t>(subject_bytes[index % subject_bytes.size()]) *
             13U +
         static_cast<unsigned>(slot) * 29U + index * 31U + 5U) &
        0xFFU);
  }
  grant.grant_id = GrantId{grant_bytes};
  if (grant.grant_id.is_zero()) {
    return Result<void>::failure(
        Error{ErrorCode::internal, "m5_support", "grant_id_zero"});
  }
  grant.granted_scopes = *normalized.value_if();
  grant.password_generation = 1U;
  grant.issued_unix_milliseconds = now_unix_milliseconds;
  grant.expires_unix_milliseconds = expires;
  PairingNonce nonce{};
  for (std::size_t index = 0U; index < nonce.size(); ++index) {
    nonce[index] = static_cast<std::byte>((index * 17U + 3U) & 0xFFU);
  }
  grant.nonce = nonce;
  auto signed_grant = sign_signed_trust_grant(grant, *issuer_identity.value_if());
  if (!signed_grant) return Result<void>::failure(*signed_grant.error_if());

  auto as_record = [](const SignedTrustGrant& value,
                      TrustGrantDirection direction) -> TrustGrantRecord {
    TrustGrantRecord record;
    record.grant_id = value.grant_id;
    record.direction = direction;
    record.issuer = value.issuer;
    record.subject = value.subject;
    record.scopes = value.granted_scopes;
    record.password_generation = value.password_generation;
    record.issued_unix_milliseconds = value.issued_unix_milliseconds;
    record.expires_unix_milliseconds = value.expires_unix_milliseconds;
    record.signature.assign(value.signature.begin(), value.signature.end());
    record.revoked = false;
    return record;
  };
  auto issued = issuer_store.put_trust_grant(
      as_record(grant, TrustGrantDirection::issued));
  if (!issued) return issued;
  return subject_store.put_trust_grant(
      as_record(grant, TrustGrantDirection::received));
}

[[nodiscard]] inline Result<void> seed_mutual_trust(
    ProfileStore& first, ProfileStore& second,
    const std::vector<std::string>& scopes,
    std::uint64_t now_unix_milliseconds = seed_grant_time) {
  auto one_way = seed_one_way_trust(first, second, scopes, now_unix_milliseconds,
                                    std::nullopt, std::byte{1});
  if (!one_way) return one_way;
  return seed_one_way_trust(second, first, scopes, now_unix_milliseconds, std::nullopt,
                            std::byte{2});
}

}  // namespace heyaki::test
