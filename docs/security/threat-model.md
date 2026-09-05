# Heyaki Threat Model

> Baseline: protocol 1.2 — the frozen optional LAN extension (1.1), the M4 session-restart
> renegotiation (1.2), and protocol 1.0 N-1 behavior. The M5 authorization/ByteStream,
> M6 message/unary-RPC, and M7 event/file surfaces operate inside the session, pairing,
> and replay boundaries analyzed below; the M7 file receive path adds its own pre-byte
> admission gate (root scope, quota, and logical-name safety before any byte is
> accepted, plus symlink-race-resistant staging with atomic rename). The M8 Remote Shell
> (delivered 2026-09-03, compiled but disabled by default) executes the "malicious
> terminal data" row below with a locally configured profile boundary, an
> executor-owned child-process worker with escalation and caps, a content-free audit
> trail, and a safe-subset VT renderer; its production enablement (POSIX only — Windows
> stays fail-closed pending the path-validation fix) was signed off on 2026-09-04 per
> the independent security review recorded in `m8-remote-shell-security-review.md` and
> the M8 milestone file.
>
> Scope: device library, LAN discovery/signaling, `heyaki-relay`, coturn integration, ProfileStore,
> and TUI

## 1. Assets and trust boundaries

The primary assets are the Ed25519 identity private key, authorization password and Argon2id verifier,
relay bootstrap/TURN/session credentials, TrustGrant and TrustStore state, service payloads, file data,
and terminal input/output. Device identity and authorization are end-to-end decisions. The relay is
trusted for enrollment policy, presence, and availability, but not for business confidentiality or for
asserting a peer identity without a device signature. The local network is untrusted: any host may
observe or inject multicast traffic, open the signaling listener, and advertise arbitrary self-created
identities. Coturn is trusted only to forward encrypted packets and enforce allocation policy.

PKI TLS authenticates device-to-relay control connections. LAN TLS provides confidentiality but uses
boot-scoped self-signed certificates; device authentication comes from a signed `LAN_HELLO` binding
both identities, nonces, boot nonce, and both peers' observed certificate fingerprints. DTLS protects
the peer data path. A signed
offer binds the initiator nonce; the signed answer adds the responder nonce; candidates sent after the
answer bind both. Offer and answer bind the relevant DTLS fingerprints, both identities/endpoints,
session, and expiry. Each candidate additionally binds the verified offer/answer transcript hash and
its owner's ICE ufrag and fingerprint. `SESSION_HELLO` signs that transcript hash over the actual
fingerprint-verified DataChannel.
ProfileStore protection terminates at the local OS security principal; a process allowed to read a
profile can act as that device.

## 2. Adversaries and controls

| Threat | Attack | Required control and failure behavior |
| --- | --- | --- |
| Malicious registered device | malformed frames, privilege requests, slow consumption, identifier collision attempts | fixed-width ID validation, signed identity derivation, default-deny scopes, per-peer limits, bounded queues, parser/state fuzzing; reject before allocation or handler dispatch |
| Malicious LAN device | advertise unlimited identities/endpoints, spoof source addresses, probe the TLS listener, trigger crossed connects | discovery is never authorization; validate before allocation, bound per-interface/source/peer state, rate-limit provisional TLS and attempts, auto-connect only trusted peers |
| LAN observer | enumerate stable DeviceId/EndpointId, source address, timing, and traffic volume | do not advertise names/manifests/scopes; protect SDP/candidates with TLS; document stable-ID enumeration as accepted v1 metadata exposure and allow LAN mode to be disabled |
| Discovery injection/replay | forge, alter, replay, or flood presence datagrams | derive DeviceId from included key, verify signature/boot nonce/sequence/relative lease, use bounded caches, reject conflicts and full capacity, fuzz datagram parser |
| LAN signaling MITM | terminate two self-signed TLS sessions, replace certificates/SDP/candidates, relay a valid hello | signed LAN hello binds roles, both IDs/endpoints, both nonces, boot nonce, and local/peer certificate fingerprints; no signaling is accepted before binding verification |
| Controlled relay | replace SDP/fingerprint, replay signaling, enumerate metadata, deny service | canonical signatures bind both peers, endpoints, nonces, expiry and fingerprints; candidates and hello bind the verified signaling transcript; relay can still observe metadata or deny service |
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
| Identifier | full DeviceId, endpoint/session/operation IDs | allowed with deployment retention policy; LAN presence exposes device/endpoint IDs when enabled; never substitute short IDs in protocol decisions |
| Secret key | identity private key, secret backend plaintext | redact, never export through diagnostics |
| Token | bootstrap, TURN password, session credential | redact; at most log non-secret record ID or expiry |
| Password | entered/generated authorization password | redact; never history, metrics, trace, crash context, or relay field |
| Verifier | Argon2id salt/parameters/output as one verifier record | redact; parameters may be logged separately only without salt/output |
| Payload | message/RPC/event/file bytes | redact by default; application-owned opt-in occurs outside core diagnostics |
| Terminal content | shell input/output and VT sequences | always redact from ordinary logs |

`value_for_log` enforces this baseline and returns a fixed redaction marker for unsafe classes. Error
objects accept only stable code, numeric underlying code, peer/operation IDs, component, and a
pre-reviewed safe detail token. A received token must pass `is_safe_detail_token`: 1-64 ASCII bytes
from `[a-z0-9_.-]`. Invalid values are replaced by a local stable protocol token before logging;
callers must not put remote text or payload fragments in `safe_detail`.

## 4. Replay cache

The replay key is a typed tuple, never an unscoped nonce:

```text
(protocol_domain, signer_device_id, peer_device_id?, request_or_session_id, boot_nonce?, nonce/sequence)
```

Every accepted entry remains for the fixed ten minutes after local monotonic insertion. Signed
transient objects may be at most five minutes in the verifier's future and have only 30 seconds of
negative clock-skew grace, so replay retention exceeds the entire remaining acceptance window. The
default capacity is 4096 entries per process security domain and 256 per peer.
Partitions and the per-peer quota prevent one peer from evicting the entire cache. An exact duplicate
may return a cached
idempotent response; a key collision with different canonical bytes is rejected and audited.

When capacity is exhausted, enrollment, login, LAN presence/hello, signaling, pairing, grant, and session hello fail closed
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
- `validate_security_policy` treats those lower and upper bounds as hard v1 limits. A constrained
  profile cannot weaken them through ordinary configuration; it requires a new reviewed policy version.
- Verification uses libsodium, constant-time comparison where applicable, locked/guarded secure buffers
  when available, and `sodium_memzero` before releasing password and derived temporary buffers.
- Rotation increments a non-zero 64-bit password generation transactionally. Old passwords stop issuing
  grants immediately. Existing grants remain until explicit revocation unless the user selects rotation
  with generation revocation.

## 6. LAN TLS, relay TLS, DTLS, and signaling-transcript review

A LAN attacker can present its own TLS certificate to both devices and relay plaintext between two TLS
connections. This fails after `LAN_HELLO`: each real device signs both its own certificate fingerprint
and the peer certificate fingerprint observed on its TLS connection, with explicit initiator/responder
roles and both nonces. The attacker cannot replace either fingerprint in the signed object and cannot
complete the expected binding on both legs. No offer, answer, candidate, credential, grant, or password
is processed before this check. A replayed hello fails boot nonce, nonce, role, expiry, or replay-cache
validation.

An active relay that replaces an offer fingerprint cannot produce the initiator's Ed25519 signature.
Replacing the whole offer with a replay fails nonce/request expiry and replay-cache checks. Relaying a
valid offer into another connection fails because answer and hello bind both device/endpoint pairs,
session ID, and both nonces. Replacing the DTLS endpoint after signed signaling produces a certificate
fingerprint mismatch. Moving a candidate to another ICE generation fails its transcript, owner ufrag,
and owner fingerprint checks. Forwarding a valid hello to a connection established from another
offer/answer pair fails the signed transcript comparison before authorization. Pinned libdatachannel
v0.23.2 has no public DTLS exporter API; protocol 1.0 therefore uses this reproducible transcript
binding and does not claim exporter semantics.

Therefore a LAN signaling attacker or relay cannot silently become a peer or read business plaintext.
They can drop/delay traffic, advertise arbitrary new identities, serve stale presence within bounded
lease behavior, perform traffic analysis, and refuse connectivity. LAN presence also exposes stable
device/endpoint identifiers to local observers. These availability and metadata risks are residual and
require product controls, operational monitoring, retention policy, or disabling LAN mode rather than
being represented as authenticated success.

## 7. Security gates

Protocol parsers and state machines must cover golden, truncated, duplicate, unknown, boundary, and
oversize frame/datagram inputs under sanitizer and fuzz smoke runs. LAN code had to prove multicast
flood limits, provisional TLS limits, certificate-binding MITM rejection, crossed-connect arbitration,
replay-cache full rejection, cancellation, and shutdown convergence before M4 — verified at M4 close
(2026-08-27, CI network matrix MATRIX_OK). Enrollment and minimal
session code had to prove signature/fingerprint/transcript failures before M4, and restricted-session
isolation had to pass before M5 opened pairing — both gates passed with the M4/M5 closures
(2026-08-27/2026-08-28). File code must prove path containment and quota checks
before M7. Shell code landed with M8 (2026-09-03): the safe-subset VT parser (OSC/DCS/
private/unknown sequences dropped and counted, SGR degraded, UTF-8 validated, bounded
buffers) and its fuzz target, child-process containment (single executor-managed PTY
worker, pre-fork fork-safe plan, TERM→grace→process-tree-kill escalation, idle/absolute/
output caps, bounded stdin, disconnect termination, no-zombie reaping), terminal-content
logging exclusion, and content-free audit records are implemented and covered by the M8
test suite on the CI matrix. Remote Shell stays compiled but disabled by default; production
enablement (POSIX only for now) was signed off on 2026-09-04 after the independent security
review in `m8-remote-shell-security-review.md` — no P0/P1 findings; the review's P2-F2
(silent PTY-worker session-limit refusal) was fixed before enablement
(`spawn_failed`/`worker_session_limit` is now observable end to end). The P2-F1 blocker on
Windows enablement was fixed on 2026-09-05 together with P3-F3 (the profile input-pending
budget is now capped at the ConPTY stdin pipe buffer on Windows) and P4-F7 (ConPTY command
lines use canonical MSVCRT argv quoting); Windows enablement follows the same posture —
explicitly listed profiles only.

Residual risks accepted for v1 are LAN stable-ID enumeration, local/relay/coturn denial of service and
traffic analysis, compromise of a device OS principal, lack of cross-VLAN serverless discovery, and lack
of lossless network migration. Remote Shell adds two accepted residuals (review P3-F4/P3-F5): a POSIX
child that escapes its process group (its own `setsid`/daemonization) is outside the escalation ladder's
signal reach — mitigated by operator profile discipline (fixed programs, non-privileged `os_user`) and
the same class of exposure as PTY-based remote shells without cgroups, while the Windows job object
contains its tree; and shell scopes are adjudicated from the session's upgrade-time snapshot, so a grant
expiring mid-session does not close already-open shells — bounded by session lifetime and the profile
absolute timeout (default 1 h). They are not represented as successful or authorized operation outcomes.
