#pragma once

// Directional TrustGrant (M5-11/M5-12). A grant is the persistent credential
// issued by a target device (issuer) to a connecting device (subject) during
// password pairing. It is signed over the frozen canonical domain
// `heyaki.trust-grant.v1` (wire protocol section 5), stored in the local
// ProfileStore TrustStore of both sides, and re-adjudicated on every session:
// the issuer's local TrustStore state is the final authority, so a subject's
// stale stored grant cannot bypass revocation.

#include <heyaki/error.hpp>
#include <heyaki/identity.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/signaling_protocol.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

inline constexpr std::size_t max_pairing_nonce_bytes = 32U;
using PairingNonce = std::array<std::byte, max_pairing_nonce_bytes>;

inline constexpr std::size_t max_trust_scopes = 256U;
inline constexpr std::size_t max_trust_scope_bytes = 256U;
inline constexpr std::size_t max_trust_grant_wire_bytes = 8U * 1024U;

enum class TrustScopeSyntax : std::uint8_t {
  // `name.space.action` without wildcards: exact scope grant.
  exact,
  // `name.space.action:*` grants every sub-scope under the prefix.
  prefix_wildcard,
};

struct SignedTrustGrant {
  GrantId grant_id;
  DeviceId issuer;
  DeviceId subject;
  // Sorted, unique, printable-ASCII scopes (for example `file.push:inbox`).
  std::vector<std::string> granted_scopes;
  std::uint64_t password_generation{1U};
  std::uint64_t issued_unix_milliseconds{};
  std::optional<std::uint64_t> expires_unix_milliseconds;
  PairingNonce nonce{};
  IdentitySignature signature{};
};

// A locally stored grant plus its revocation state, as kept by the TrustStore.
struct StoredTrustGrant {
  SignedTrustGrant grant;
  bool revoked{false};
};

[[nodiscard]] bool is_valid_trust_scope(std::string_view scope) noexcept;
// Sorts and de-duplicates; fails on invalid scope tokens.
[[nodiscard]] Result<std::vector<std::string>> normalize_trust_scopes(
    std::vector<std::string> scopes);
// True when `granted` covers `requested` under the scope syntax rules above.
[[nodiscard]] bool trust_scope_covers(std::string_view granted,
                                      std::string_view requested) noexcept;
// Filters `requested` down to the scopes actually covered by `granted`.
[[nodiscard]] std::vector<std::string> intersect_trust_scopes(
    const std::vector<std::string>& requested, const std::vector<std::string>& granted);

[[nodiscard]] Result<void> validate_signed_trust_grant(const SignedTrustGrant& grant);
[[nodiscard]] Result<std::vector<std::byte>> canonical_signed_trust_grant(
    const SignedTrustGrant& grant);
[[nodiscard]] Result<void> sign_signed_trust_grant(SignedTrustGrant& grant,
                                                   const IdentityKeyPair& issuer_identity);
// Verifies structure, the issuer signature, the issuer identity derivation,
// and (when present) the expiry against `now`.
[[nodiscard]] Result<void> verify_signed_trust_grant(
    const SignedTrustGrant& grant, std::span<const std::byte> issuer_public_key,
    std::uint64_t now_unix_milliseconds);

// Wire codec for `heyaki.protocol.pairing.v1.TrustGrant`.
[[nodiscard]] Result<std::vector<std::byte>> encode_signed_trust_grant(
    const SignedTrustGrant& grant);
[[nodiscard]] Result<SignedTrustGrant> parse_signed_trust_grant(
    std::span<const std::byte> payload);

// Session-level adjudication (M5-12): the effective scopes are the intersection
// of what the peer requested, what the grant covers, and what local endpoint or
// service policy still allows. `authorized` is false when the intersection is
// empty.
struct TrustAdjudication {
  bool authorized{false};
  std::vector<std::string> allowed_scopes;
};

[[nodiscard]] TrustAdjudication adjudicate_trust_scopes(
    const std::vector<std::string>& requested_scopes,
    const std::vector<std::string>& grant_scopes,
    const std::optional<std::vector<std::string>>& local_policy_scopes);

}  // namespace heyaki
