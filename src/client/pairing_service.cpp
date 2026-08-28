#include "pairing_service.hpp"

#include <sodium/randombytes.h>

#include <algorithm>
#include <iterator>
#include <limits>
#include <utility>

namespace heyaki {
namespace {

Error pairing_service_error(ErrorCode code, const char* detail) {
  return {code, "pairing_service", detail};
}

GrantId random_grant_id() {
  GrantId::Storage bytes{};
  do {
    randombytes_buf(bytes.data(), bytes.size());
  } while (GrantId{bytes}.is_zero());
  return GrantId{bytes};
}

constexpr std::size_t max_identity_public_key_bytes = 32U;

}  // namespace

PairingService::PairingService(PairingServiceConfig config)
    : config_(std::move(config)) {
  if (config_.failure_threshold == 0U) config_.failure_threshold = 1U;
  if (config_.backoff_base <= std::chrono::milliseconds::zero()) {
    config_.backoff_base = std::chrono::milliseconds{1000};
  }
  if (config_.backoff_max < config_.backoff_base) config_.backoff_max = config_.backoff_base;
  if (config_.failure_table_capacity == 0U) config_.failure_table_capacity = 1U;
}

const PairingServiceConfig& PairingService::config() const noexcept { return config_; }

std::uint64_t PairingService::now() const {
  if (config_.wall_clock) return config_.wall_clock();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

void PairingService::audit(PairingAuditKind kind, const DeviceId& peer,
                           const char* detail) {
  if (!config_.audit_sink) return;
  config_.audit_sink(PairingAuditEvent{.kind = kind,
                                       .peer = peer,
                                       .unix_milliseconds = now(),
                                       .detail = detail});
}

bool PairingService::backoff_blocks(const DeviceId& peer,
                                    std::uint64_t now_value) const {
  auto found = failures_.find(peer);
  if (found == failures_.end()) return false;
  const auto& record = found->second;
  if (record.failures < config_.failure_threshold) return false;
  // Exponential backoff from the last failure: base * 2^(failures-threshold),
  // capped. One clean window does not reset the counter (only a successful
  // verification does); the wait just keeps doubling per failure.
  const auto exponent = std::min<std::size_t>(
      record.failures - config_.failure_threshold, 16U);
  const auto base = static_cast<std::uint64_t>(config_.backoff_base.count());
  std::uint64_t wait = base;
  for (std::size_t index = 0U; index < exponent; ++index) {
    if (wait > std::numeric_limits<std::uint64_t>::max() / 2U) {
      wait = std::numeric_limits<std::uint64_t>::max();
      break;
    }
    wait *= 2U;
  }
  wait = std::min<std::uint64_t>(wait,
                                 static_cast<std::uint64_t>(config_.backoff_max.count()));
  return now_value < record.last_failure_unix_milliseconds + wait;
}

void PairingService::record_failure(const DeviceId& peer, std::uint64_t now_value) {
  auto [iterator, inserted] = failures_.try_emplace(peer);
  if (inserted && failures_.size() > config_.failure_table_capacity) {
    // Bounded table: evict the oldest entry, never grow without limit. An
    // evicted source simply starts with a fresh counter; the attempt budget
    // of the pairing session still bounds it.
    auto oldest = std::min_element(
        failures_.begin(), failures_.end(), [](const auto& left, const auto& right) {
          return left.second.last_failure_unix_milliseconds <
                 right.second.last_failure_unix_milliseconds;
        });
    failures_.erase(oldest);
    iterator = failures_.try_emplace(peer).first;
  }
  iterator->second.failures += 1U;
  iterator->second.last_failure_unix_milliseconds = now_value;
}

void PairingService::clear_failures(const DeviceId& peer) { failures_.erase(peer); }

Result<PairingResultBody> PairingService::evaluate(
    const PairingRequestBody& request, const DeviceId& peer_device,
    std::span<const std::byte> peer_public_key) {
  if (config_.profile == nullptr) {
    return Result<PairingResultBody>::failure(
        pairing_service_error(ErrorCode::configuration, "profile_missing"));
  }
  const auto now_value = now();

  PairingResultBody result;
  result.request_id = request.request_id;
  auto deny = [&](ErrorCode code, StableStatus status, PairingAuditKind kind,
                  const char* audit_detail) -> Result<PairingResultBody> {
    audit(kind, peer_device, audit_detail);
    result.status = status;
    return Result<PairingResultBody>::success(result);
  };

  auto policy = config_.profile->pairing_policy();
  if (!policy) {
    return Result<PairingResultBody>::failure(*policy.error_if());
  }
  if (!policy.value_if()->password_pairing_enabled) {
    return deny(ErrorCode::pairing_denied, StableStatus::permission_denied,
                PairingAuditKind::denied_policy, "pairing_disabled");
  }

  // M5-10: per-source backoff gate before any expensive verification.
  if (backoff_blocks(peer_device, now_value)) {
    return deny(ErrorCode::pairing_rate_limited, StableStatus::resource_exhausted,
                PairingAuditKind::denied_backoff, "pairing_backoff");
  }
  audit(PairingAuditKind::attempt, peer_device, "pairing_attempt");

  auto verifier = config_.profile->password_verifier();
  if (!verifier) {
    return Result<PairingResultBody>::failure(*verifier.error_if());
  }
  if (!verifier.value_if()->has_value()) {
    return deny(ErrorCode::pairing_denied, StableStatus::permission_denied,
                PairingAuditKind::denied_policy, "verifier_missing");
  }
  auto verified = verify_password(request.password_utf8, **verifier.value_if());
  if (!verified) {
    return Result<PairingResultBody>::failure(*verified.error_if());
  }
  if (!*verified.value_if()) {
    record_failure(peer_device, now_value);
    return deny(ErrorCode::authentication, StableStatus::unauthenticated,
                PairingAuditKind::denied_password, "password_mismatch");
  }
  clear_failures(peer_device);

  // M5-12: the granted set is the intersection of requested scopes and the
  // current pairing policy; an empty intersection denies the request.
  auto policy_scopes = normalize_trust_scopes(policy.value_if()->default_scopes);
  if (!policy_scopes) {
    return Result<PairingResultBody>::failure(*policy_scopes.error_if());
  }
  auto adjudication = adjudicate_trust_scopes(
      request.requested_scopes, *policy_scopes.value_if(), std::nullopt);
  if (!adjudication.authorized) {
    return deny(ErrorCode::permission, StableStatus::permission_denied,
                PairingAuditKind::denied_policy, "scope_intersection_empty");
  }

  // M5-11: issue the directional grant bound to both identities, the pairing
  // nonce, the password generation, and an optional expiry.
  SignedTrustGrant grant;
  grant.grant_id = random_grant_id();
  grant.issuer = config_.profile->device_id();
  grant.subject = peer_device;
  grant.granted_scopes = adjudication.allowed_scopes;
  auto generation = config_.profile->password_generation();
  if (!generation) {
    return Result<PairingResultBody>::failure(*generation.error_if());
  }
  grant.password_generation = *generation.value_if();
  grant.issued_unix_milliseconds = now_value;
  if (config_.grant_ttl_milliseconds > 0U) {
    grant.expires_unix_milliseconds = now_value + config_.grant_ttl_milliseconds;
  }
  grant.nonce = request.nonce;
  auto signed_grant = sign_signed_trust_grant(grant, config_.identity);
  if (!signed_grant) {
    return Result<PairingResultBody>::failure(*signed_grant.error_if());
  }
  if (peer_public_key.size() > max_identity_public_key_bytes) {
    return Result<PairingResultBody>::failure(
        pairing_service_error(ErrorCode::protocol, "peer_public_key_invalid"));
  }
  auto persisted = config_.profile->put_trust_grant(
      to_record(grant, TrustGrantDirection::issued));
  if (!persisted) {
    return Result<PairingResultBody>::failure(*persisted.error_if());
  }
  audit(PairingAuditKind::granted, peer_device, "grant_issued");
  result.status = StableStatus::ok;
  result.grant = std::move(grant);
  return Result<PairingResultBody>::success(std::move(result));
}

Result<void> PairingService::accept_grant(
    const PairingResultBody& result, const RequestId& pending_request_id,
    const PairingNonce& pending_nonce, const DeviceId& issuer_device,
    const IdentityPublicKey& issuer_public_key,
    const std::vector<std::string>& requested_scopes) {
  if (config_.profile == nullptr) {
    return Result<void>::failure(
        pairing_service_error(ErrorCode::configuration, "profile_missing"));
  }
  if (!result.grant.has_value()) {
    audit(PairingAuditKind::grant_rejected, issuer_device, "result_without_grant");
    return Result<void>::failure(
        pairing_service_error(ErrorCode::protocol, "result_without_grant"));
  }
  const auto& grant = *result.grant;
  if (result.request_id != pending_request_id || grant.nonce != pending_nonce) {
    audit(PairingAuditKind::grant_rejected, issuer_device, "grant_binding_mismatch");
    return Result<void>::failure(
        pairing_service_error(ErrorCode::authentication, "grant_binding_mismatch"));
  }
  if (grant.issuer != issuer_device || grant.subject != config_.profile->device_id()) {
    audit(PairingAuditKind::grant_rejected, issuer_device, "grant_identity_mismatch");
    return Result<void>::failure(
        pairing_service_error(ErrorCode::authentication, "grant_identity_mismatch"));
  }
  // The issuer's public key was already verified against the session hello
  // signature; the same key must verify the grant signature.
  auto verified = verify_signed_trust_grant(
      grant,
      std::span<const std::byte>{issuer_public_key.data(), issuer_public_key.size()},
      now());
  if (!verified) {
    audit(PairingAuditKind::grant_rejected, issuer_device, "grant_signature_invalid");
    return Result<void>::failure(*verified.error_if());
  }
  // A grant may only carry scopes the initiator actually requested.
  for (const auto& scope : grant.granted_scopes) {
    if (std::find(requested_scopes.begin(), requested_scopes.end(), scope) ==
        requested_scopes.end()) {
      audit(PairingAuditKind::grant_rejected, issuer_device, "grant_scope_overreach");
      return Result<void>::failure(
          pairing_service_error(ErrorCode::authentication, "grant_scope_overreach"));
    }
  }
  auto persisted = config_.profile->put_trust_grant(
      to_record(grant, TrustGrantDirection::received));
  if (!persisted) {
    return Result<void>::failure(*persisted.error_if());
  }
  audit(PairingAuditKind::grant_accepted, issuer_device, "grant_stored");
  return Result<void>::success();
}

Result<SessionAuthorization> PairingService::authorize(
    const DeviceId& peer, std::uint64_t now_unix_milliseconds) {
  if (config_.profile == nullptr) {
    return Result<SessionAuthorization>::failure(
        pairing_service_error(ErrorCode::configuration, "profile_missing"));
  }
  SessionAuthorization authorization;
  auto policy = config_.profile->pairing_policy();
  if (!policy) {
    return Result<SessionAuthorization>::failure(*policy.error_if());
  }
  authorization.pairing_allowed = policy.value_if()->password_pairing_enabled;
  auto grants = config_.profile->trust_grants_for_peer(peer, now_unix_milliseconds);
  if (!grants) {
    return Result<SessionAuthorization>::failure(*grants.error_if());
  }
  std::vector<std::string> scopes;
  for (const auto& record : *grants.value_if()) {
    scopes.insert(scopes.end(), record.scopes.begin(), record.scopes.end());
  }
  if (scopes.empty()) {
    authorization.trusted = false;
    return Result<SessionAuthorization>::success(authorization);
  }
  auto normalized = normalize_trust_scopes(std::move(scopes));
  if (!normalized) {
    return Result<SessionAuthorization>::failure(*normalized.error_if());
  }
  authorization.trusted = true;
  authorization.scopes = std::move(*normalized.value_if());
  return Result<SessionAuthorization>::success(authorization);
}

Result<void> PairingService::revoke_grant(const GrantId& grant_id) {
  if (config_.profile == nullptr) {
    return Result<void>::failure(
        pairing_service_error(ErrorCode::configuration, "profile_missing"));
  }
  auto revoked = config_.profile->revoke_trust_grant(grant_id, now());
  if (!revoked) return revoked;
  audit(PairingAuditKind::grant_revoked, DeviceId{}, "grant_revoked");
  return Result<void>::success();
}

Result<std::uint64_t> PairingService::rotate_password(const PasswordVerifier& new_verifier) {
  if (config_.profile == nullptr) {
    return Result<std::uint64_t>::failure(
        pairing_service_error(ErrorCode::configuration, "profile_missing"));
  }
  auto current = config_.profile->password_generation();
  if (!current) {
    return Result<std::uint64_t>::failure(*current.error_if());
  }
  const auto next = *current.value_if() + 1U;
  auto stored = config_.profile->set_password_verifier(new_verifier, next);
  if (!stored) {
    return Result<std::uint64_t>::failure(*stored.error_if());
  }
  audit(PairingAuditKind::password_rotated, DeviceId{}, "password_rotated");
  return Result<std::uint64_t>::success(next);
}

Result<std::uint64_t> PairingService::rotate_password_and_revoke_grants(
    const PasswordVerifier& new_verifier) {
  auto rotated = rotate_password(new_verifier);
  if (!rotated) return rotated;
  auto revoked = config_.profile->revoke_issued_trust_grants_below_generation(
      *rotated.value_if(), now());
  if (!revoked) {
    return Result<std::uint64_t>::failure(*revoked.error_if());
  }
  audit(PairingAuditKind::grants_revoked, DeviceId{}, "old_generation_grants_revoked");
  return rotated;
}

Result<std::vector<TrustGrantRecord>> PairingService::grants_for_peer(
    const DeviceId& peer, std::uint64_t now_unix_milliseconds) const {
  if (config_.profile == nullptr) {
    return Result<std::vector<TrustGrantRecord>>::failure(
        pairing_service_error(ErrorCode::configuration, "profile_missing"));
  }
  return config_.profile->trust_grants_for_peer(peer, now_unix_milliseconds);
}

std::size_t PairingService::tracked_failure_sources() const noexcept {
  return failures_.size();
}

TrustGrantRecord PairingService::to_record(const SignedTrustGrant& grant,
                                           TrustGrantDirection direction) const {
  TrustGrantRecord record;
  record.grant_id = grant.grant_id;
  record.direction = direction;
  record.issuer = grant.issuer;
  record.subject = grant.subject;
  record.scopes = grant.granted_scopes;
  record.password_generation = grant.password_generation;
  record.issued_unix_milliseconds = grant.issued_unix_milliseconds;
  record.expires_unix_milliseconds = grant.expires_unix_milliseconds;
  record.signature.assign(grant.signature.begin(), grant.signature.end());
  record.revoked = false;
  return record;
}

}  // namespace heyaki
