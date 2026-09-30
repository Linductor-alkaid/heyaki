# Pairing And Trust

## Pairing

`pair_peer(peer, password, requested_scopes)` returns `Result<RequestId>`.
Admission is synchronous and bounded: strand-level rejections (missing
session, session neither pairing-restricted nor authorized, pairing already
pending) return a failure and produce no observer outcome. On admission the
call returns the stable wire request id, and the one-time observer
(`set_pairing_observer`) reports exactly one terminal outcome for it —
success with the effective scopes, or failure (denial, deadline, disconnect,
cancel, shutdown). On an already-authorized session a pairing request is
answered explicitly (repair, renewal, reverse grant); a denial there reports
the stable failure outcome without closing the authorized session. The
peer side verifies the password with Argon2id.

## Basic communication without device trust

`NodeConfig::basic_communication` (default off) lets identity-verified,
untrusted sessions exchange messages and push files into the configured
`file_receive_roots` without a TrustGrant or password pairing. It never
covers shell/RPC/events/streams/gateway and never mints a grant; each end
enforces its own policy, so a one-sided opt-in fails explicitly. The session
snapshot separates `policy_scopes` (policy-derived) from `authorized_scopes`
(grant-only, empty while untrusted); a successful pairing supersedes the
policy for that session.

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
