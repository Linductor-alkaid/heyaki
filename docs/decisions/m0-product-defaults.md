# Product Decision Defaults

Status: provisional until the named freeze milestone. These defaults prevent engineering work from
stalling; they are not a substitute for product approval. DEC-01 through DEC-09 were established in
M0; DEC-10 through DEC-12 record the LAN serverless design delta; DEC-13 records the M10 Gateway
design delta (2026-08-27) and DEC-14 records the M11 Android port scope (2026-08-29). The freeze
points for DEC-01 through DEC-05 and DEC-07 through DEC-12 have since passed (the last was the
M5 entry gate, reached after the M4 close on 2026-08-27) with these defaults applied unchanged
and no override recorded, so they remain the
governing defaults pending explicit product confirmation; DEC-03 final values freeze at M9; DEC-06 froze at M8 entry
(2026-09-03) applied unchanged: Shell is interactive-maintenance only, default off,
and requires an independent security review sign-off before production enablement.

| ID | Provisional default | Owner | Freeze no later than |
| --- | --- | --- | --- |
| DEC-01 | MVP targets Linux x86_64; v1 also gates on Windows x64; constrained embedded targets are deferred. | Product + Architecture | M1 exit |
| DEC-02 | TURN/TCP/TLS is required for v1; authenticated HTTP proxy support is deferred. | Networking | M3B entry |
| DEC-03 | M0 uses configurable conservative limits; peer, RPC, subscriber, file-size, and throughput limits freeze after measurement. | Product + Performance | M5 entry, final values at M9 |
| DEC-04 | Default pairing grants a read/file template without Shell; password rotation does not automatically revoke existing grants. | Security + Product | M5 entry |
| DEC-05 | MVP is a single-tenant self-hosted relay; public multi-tenant service is deferred. | Product + Operations | M3B entry |
| DEC-06 | Shell is for interactive maintenance only; unattended work uses narrow RPC/job services. | Security + Product | M8 entry |
| DEC-07 | v1 does not promise lossless session migration across mobile network changes. | Networking + Product | M4 entry |
| DEC-08 | Default ProfileStore ownership is per-user; system services must name an explicit system profile. | Security + Platform | M2 entry |
| DEC-09 | A tenant sees only the endpoint capability summary required for connection selection. | Security + Product | M3B entry |
| DEC-10 | v1 serverless discovery covers only the same layer-2 multicast domain; cross-VLAN discovery requires relay or explicit endpoint hints. | Networking + Product | M3A entry |
| DEC-11 | v1 uses a bounded Heyaki UDP multicast discovery protocol over the executor-managed Asio runtime; mDNS/DNS-SD interoperability is deferred. | Networking + Architecture | M3A entry |
| DEC-12 | Enabling LAN mode exposes full DeviceId/EndpointId but no display name or service manifest; automatic connection is limited to trusted peers and configured capacity. | Security + Product | M3A entry |
| DEC-13 | The Gateway proxy is disabled by default and not part of the standard pairing template; the first version is TCP-only; the default profile allows only B-side directly reachable ranges with public egress requiring explicit opt-in; gateway traffic on the TURN data path is allowed by default but metered independently (configurable rate limit or deny); simultaneous gateway and shell authorization requires explicit confirmation. | Security + Product | M10 entry |
| DEC-14 | The v1.x Android deliverable is the C++20 core library cross-compiled with the NDK plus a JNI integration boundary — not a full Android app/UI; the TUI, fuzzers, and coturn deployment pieces are not ported; the Android profile storage location and secret-backend equivalent must be confirmed at M11 kickoff. **Confirmed at M11 (2026-10-04):** the profile storage location is the app-scoped directory passed explicitly by the host through `ProfileStore::create/open` (the XDG/HOME default factories fail explicitly on Android instead of guessing env vars); the secret-backend equivalent for the Android alpha is the encrypted-file backend (the libsecret OS-store probe is compiled out; an Android Keystore backend remains a future product decision). See `docs/compatibility/android-ndk.md`. | Product + Platform | M11 entry |
| DEC-15 | Relay enrollment gains an admission-mode config (`enrollment_mode = token \| password \| closed`, default `token`). Password mode (2026-10-07): the client presents a relay-bound Argon2id proof (`Argon2id(password, BLAKE2b-128("heyaki/relay-enrollment-password/v1" ‖ relay_id))`, fixed 64MiB/t=2) in the new optional `EnrollmentRequest.enrollment_password_proof` wire field; the proof is a secret (never logged, never in the signed canonical object) and a long-lived bearer credential in the same class as a bootstrap token. The relay stores a static Argon2id verifier of the proof (hex input) in the schema-v3 `enrollment_password` table; the plaintext password never reaches the relay and a DB leak costs two Argon2id layers. Design note: a challenge-bound (per-attempt fresh) proof is unverifiable against a static verifier — that is the PAKE gap; OPAQUE/SRP remains future work (threat-model §5a records the trade-off). Wire versioning decision: the field rides protocol 1.3 under a new optional capability bit `relay_enrollment_password_v1` (same pattern as `pairing_approval_v1`); old relays reject the unknown field cleanly and old clients never send it, so token-mode bytes are unchanged. Password-mode tenants must equal `enrollment_default_tenant`. `EnrollmentResult` gains an optional `relay_certificate_sha256` returned only for password-mode completions (TOFU pin anchor); token-mode responses stay byte-identical. Certificate rotation changes the derivation salt, so the runbook re-provisions the verifier via `heyaki-relay --init`. | Security + Architecture | applied; review at next security freeze |

Any override must update the architecture, implementation plan, relevant protocol/security tests,
and this decision record in the same change.
