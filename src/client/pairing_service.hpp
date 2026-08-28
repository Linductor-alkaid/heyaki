#pragma once

// Pairing and trust service (M5-09..M5-13). The Node wires one instance of
// this class into every PeerSession: it evaluates inbound pairing requests
// against the local Argon2id verifier and pairing policy, applies per-source
// failure counting with exponential backoff, issues and persists directional
// TrustGrants, verifies returned grants as the pairing initiator, and
// adjudicates session authorization from the local TrustStore.

#include "peer_session.hpp"

#include <heyaki/identity.hpp>
#include <heyaki/pairing_protocol.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/trust_grant.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

enum class PairingAuditKind : std::uint8_t {
  attempt,
  denied_password,
  denied_policy,
  denied_backoff,
  granted,
  grant_accepted,
  grant_rejected,
  grant_revoked,
  password_rotated,
  grants_revoked,
};

// Structured audit record; never contains the password, verifier, or grant
// signature bytes.
struct PairingAuditEvent {
  PairingAuditKind kind{PairingAuditKind::attempt};
  DeviceId peer;
  std::uint64_t unix_milliseconds{};
  const char* detail{""};
};

struct PairingServiceConfig {
  ProfileStore* profile{nullptr};
  IdentityKeyPair identity;
  // 0 = grants without expiry.
  std::uint64_t grant_ttl_milliseconds{0U};
  // Per-source failure budget before backoff engages (M5-10).
  std::size_t failure_threshold{3U};
  std::chrono::milliseconds backoff_base{1000};
  std::chrono::milliseconds backoff_max{60000};
  // Bounded per-source failure table size.
  std::size_t failure_table_capacity{256U};
  std::function<std::uint64_t()> wall_clock;
  std::function<void(const PairingAuditEvent&)> audit_sink;
};

class PairingService {
 public:
  explicit PairingService(PairingServiceConfig config);

  PairingService(const PairingService&) = delete;
  PairingService& operator=(const PairingService&) = delete;

  // ---- Target side (M5-09/M5-10/M5-11) ----
  // Evaluates one admitted PAIRING_REQUEST from an identity-verified peer:
  // backoff gate, Argon2id password verification, pairing-policy scope
  // adjudication, grant issuance, TrustStore persistence, audit.
  [[nodiscard]] Result<PairingResultBody> evaluate(
      const PairingRequestBody& request, const DeviceId& peer_device,
      std::span<const std::byte> peer_public_key);

  // ---- Initiator side (M5-09/M5-12) ----
  // Verifies a returned grant (signature under the peer's already-verified
  // session key, issuer identity, subject binding, nonce echo, scope subset)
  // and persists it as a received grant.
  [[nodiscard]] Result<void> accept_grant(
      const PairingResultBody& result, const RequestId& pending_request_id,
      const PairingNonce& pending_nonce, const DeviceId& issuer_device,
      const IdentityPublicKey& issuer_public_key,
      const std::vector<std::string>& requested_scopes);

  // ---- Session authorization (M5-12) ----
  [[nodiscard]] Result<SessionAuthorization> authorize(const DeviceId& peer,
                                                       std::uint64_t now_unix_milliseconds);

  // ---- Trust management (M5-13) ----
  [[nodiscard]] Result<void> revoke_grant(const GrantId& grant_id);
  // "Rotate only": installs the new verifier and bumps the generation.
  // Existing grants keep their validity.
  [[nodiscard]] Result<std::uint64_t> rotate_password(
      const PasswordVerifier& new_verifier);
  // "Rotate and revoke": additionally revokes every still-valid issued grant
  // whose generation is below the new one.
  [[nodiscard]] Result<std::uint64_t> rotate_password_and_revoke_grants(
      const PasswordVerifier& new_verifier);

  [[nodiscard]] Result<std::vector<TrustGrantRecord>> grants_for_peer(
      const DeviceId& peer, std::uint64_t now_unix_milliseconds) const;

  [[nodiscard]] const PairingServiceConfig& config() const noexcept;
  [[nodiscard]] std::size_t tracked_failure_sources() const noexcept;

 private:
  struct FailureRecord {
    std::size_t failures{};
    std::uint64_t last_failure_unix_milliseconds{};
  };

  [[nodiscard]] std::uint64_t now() const;
  void audit(PairingAuditKind kind, const DeviceId& peer, const char* detail);
  [[nodiscard]] bool backoff_blocks(const DeviceId& peer, std::uint64_t now_value) const;
  void record_failure(const DeviceId& peer, std::uint64_t now_value);
  void clear_failures(const DeviceId& peer);
  [[nodiscard]] TrustGrantRecord to_record(const SignedTrustGrant& grant,
                                           TrustGrantDirection direction) const;

  PairingServiceConfig config_;
  std::map<DeviceId, FailureRecord> failures_;
};

}  // namespace heyaki
