# Pairing And Trust

## Pairing

`pair_peer(peer, password, requested_scopes)` submits one attempt against
the peer's pairing-restricted session. Outcomes surface through a one-time
observer (`set_pairing_observer`) or the session snapshot. The peer side
verifies the password with Argon2id.

## TrustGrants and scopes

Successful pairing stores a signed `TrustGrant` locally. Supporting APIs:
`trust_grants_for`, `revoke_trust_grant`,
`rotate_authorization_password[_and_revoke]`, and the bounded
`pairing_audit_records()` ring (correlation ids — never the password).

The **effective scope is always the intersection** of what the caller
requested and what the target's policy grants — never more. Scope grammar
(`trust_scope_covers`):

- `prefix:*` matches `prefix:x` and `prefix:x:y` — wildcards cover deeper
  segments only.
- `*` alone is not a global grant.
- Service scopes are checked live, per frame, on the serving side; a
  revoked grant stops mattering immediately.

## Pitfalls

- Default-deny: without a grant covering a service's scope, the serving
  side refuses the frame — check the session snapshot's authorized scopes
  before blaming the service call.
- Pairing attempts are rate-limited with exponential backoff on the serving
  side; a burst of attempts failing is expected behavior, not a bug.
- The audit ring is bounded and content-free: it never carries passwords or
  payloads.

## Next

Which scopes a service needs is stated on each service card — start from
[scenarios](scenarios.md).
