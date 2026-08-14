# Heyaki Threat Model

> Baseline: protocol 1.0, M1
>
> Scope: device library, `heyaki-relay`, coturn integration, ProfileStore, and TUI

## 1. Assets and trust boundaries

The primary assets are the Ed25519 identity private key, authorization password and Argon2id verifier,
relay bootstrap/TURN/session credentials, TrustGrant and TrustStore state, service payloads, file data,
and terminal input/output. Device identity and authorization are end-to-end decisions. The relay is
trusted for enrollment policy, presence, and availability, but not for business confidentiality or for
asserting a peer identity without a device signature. Coturn is trusted only to forward encrypted
packets and enforce allocation policy.

TLS authenticates device-to-relay control connections. DTLS protects the peer data path, while signed
offer/answer/candidate objects bind the DTLS fingerprint, both identities/endpoints, nonce, session,
and expiry. `SESSION_HELLO` binds the authenticated signaling exchange to the actual DTLS exporter value.
ProfileStore protection terminates at the local OS security principal; a process allowed to read a
profile can act as that device.

## 2. Adversaries and controls

| Threat | Attack | Required control and failure behavior |
| --- | --- | --- |
| Malicious registered device | malformed frames, privilege requests, slow consumption, identifier collision attempts | fixed-width ID validation, signed identity derivation, default-deny scopes, per-peer limits, bounded queues, parser/state fuzzing; reject before allocation or handler dispatch |
| Controlled relay | replace SDP/fingerprint, replay signaling, enumerate metadata, deny service | canonical device signatures bind both peers, endpoints, nonces, expiry and DTLS fingerprint; hello verifies channel binding; relay can still observe metadata or deny service |
| Password guessing | repeated pairing attempts from devices/IPs or distributed sources | minimum strength, generated 128-bit passphrases, local Argon2id, per-source/target/session rate limits and exponential delay; no permanent global lockout |
| ProfileStore theft | steal private key, verifier, grants, or relay pin | OS secret backend, encrypted file fallback, owner-only permissions, secure buffers, atomic storage, audit; treat copied usable private key as full device compromise |
| Replay | replay enrollment, offer, candidate, hello, pairing, RPC, or grant | signed random nonce plus request/session/grant ID, expiry, epoch, bounded replay cache; cache saturation rejects high-risk requests and emits an observable counter |
| Downgrade | force old major/minor or strip capability bits | signed version/capability fields, exact major match, explicit required bits, no fallback after authenticated incompatibility |
| Resource exhaustion | huge length, queue/window fill, connection churn, decompression bomb, diagnostic flood | validate lengths before allocation, centralized hard limits, admission rejection, byte and count quotas, reserved control capacity, expanded-size limits, bounded diagnostics |
| Path traversal | absolute paths, `..`, NUL, Windows device names, symlink race | logical names only, receive-root mapping, platform canonicalization, handle-relative safe open, quotas, temporary non-executable file, fsync and atomic rename |
| Malicious terminal data | escape injection, clipboard/OSC abuse, oversized control sequence, secret capture | vetted bounded VT parser, command/OSC allowlist, raw content excluded from logs, Remote Shell off by default, restricted profile and process tree limits |
| Supply-chain compromise | moved tag, malicious generated source, unexpected link closure | commit pins, recursive pin verification, generated files confined to build tree, SBOM/license inventory, dependency review and reproducible release provenance |

## 3. Secret and logging policy

Structured logging accepts only fields classified as `public_value`, `operational`, or `identifier`.
The following matrix is mandatory:

| Class | Examples | Default log handling |
| --- | --- | --- |
| Public | protocol version, capability names, safe error code | allowed |
| Operational | queue depth, duration, path type, byte count | allowed |
| Identifier | full DeviceId, endpoint/session/operation IDs | allowed with deployment retention policy; never substitute short IDs in protocol decisions |
| Secret key | identity private key, secret backend plaintext | redact, never export through diagnostics |
| Token | bootstrap, TURN password, session credential | redact; at most log non-secret record ID or expiry |
| Password | entered/generated authorization password | redact; never history, metrics, trace, crash context, or relay field |
| Verifier | Argon2id salt/parameters/output as one verifier record | redact; parameters may be logged separately only without salt/output |
| Payload | message/RPC/event/file bytes | redact by default; application-owned opt-in occurs outside core diagnostics |
| Terminal content | shell input/output and VT sequences | always redact from ordinary logs |

`value_for_log` enforces this baseline and returns a fixed redaction marker for unsafe classes. Error
objects accept only stable code, numeric underlying code, peer/operation IDs, component, and a
pre-reviewed safe detail token. Callers must not put remote text or payload fragments in `safe_detail`.

## 4. Replay cache

The replay key is a typed tuple, never an unscoped nonce:

```text
(protocol_domain, signer_device_id, peer_device_id?, request_or_session_id, nonce)
```

Entries expire at the earlier of the signed expiry plus bounded skew and ten minutes after local
monotonic insertion. The default capacity is 4096 entries per process security domain. Partitions and
per-peer quotas prevent one peer from evicting the entire cache. An exact duplicate may return a cached
idempotent response; a key collision with different canonical bytes is rejected and audited.

When capacity is exhausted, enrollment, login, signaling, pairing, grant, and session hello fail closed
with `resource_exhausted`. No untracked eviction admits a high-risk request. The cache reports current
entries, expiry removals, duplicate hits, conflicting duplicates, and full rejections through the
existing executor/communication and protocol diagnostic facilities; it does not create a parallel task
health system.

## 5. Password and verifier baseline

- User-chosen authorization passwords contain at least 16 Unicode scalar values and at most 256 UTF-8
  bytes. The TUI offers a locally generated value with at least 128 bits of entropy and no universal
  default.
- Verifier format version 1 identifies Argon2id v1.3, salt, calibrated operations/memory, and password
  generation. Parameters are not inferred from string formatting.
- Calibration targets 500 ms on the owning device, accepted range 250-750 ms, memory range 64-512 MiB,
  and operations range 2-6. Constrained-device changes require an explicit policy/version review.
- Verification uses libsodium, constant-time comparison where applicable, locked/guarded secure buffers
  when available, and `sodium_memzero` before releasing password and derived temporary buffers.
- Rotation increments a non-zero 64-bit password generation transactionally. Old passwords stop issuing
  grants immediately. Existing grants remain until explicit revocation unless the user selects rotation
  with generation revocation.

## 6. TLS, DTLS, and channel-binding review

An active relay that replaces an offer fingerprint cannot produce the initiator's Ed25519 signature.
Replacing the whole offer with a replay fails nonce/request expiry and replay-cache checks. Relaying a
valid offer into another connection fails because answer and hello bind both device/endpoint pairs,
session ID, and both nonces. Replacing the DTLS endpoint after signed signaling produces a certificate
fingerprint mismatch. Forwarding the valid DTLS session to a different transport produces a different
DTLS exporter; `SESSION_HELLO` signature and channel-binding comparison fail before authorization.

Therefore a relay cannot silently become a peer or read business plaintext. It can drop/delay traffic,
serve stale presence within bounded lease behavior, perform traffic analysis, and refuse TURN
credentials. These availability and metadata risks are residual and require operational monitoring,
regional deployment, and retention policy rather than new cryptography.

## 7. Security gates

Protocol parsers and state machines must cover golden, truncated, duplicate, unknown, boundary, and
oversize inputs under sanitizer and fuzz smoke runs. Enrollment and session code must prove replay-cache
full rejection, signature/fingerprint/channel-binding failures, and restricted-session isolation before
M4. File code must prove path containment and quota checks before M7. Shell remains disabled until its
VT parser, process containment, logging exclusions, and termination escalation receive a separate
review in M8.

Residual risks accepted for v1 are relay/coturn denial of service and traffic analysis, compromise of a
device OS principal, and lack of lossless network migration. They are not represented as successful or
authorized operation outcomes.
