# Heyaki Wire Protocol v1

> Status: M1 protocol baseline
>
> Protocol version: 1.0
>
> Incompatible changes require a protocol major increment.

This document is normative for Heyaki framing, identifiers, negotiation, signed objects, and
per-domain state handling. The schemas under `proto/heyaki/*/v1` are normative for Protobuf fields.
The words MUST, MUST NOT, SHOULD, and MAY describe interoperability requirements.

## 1. Primitive encodings

- Fixed-width integers are unsigned big-endian unless a schema explicitly uses Protobuf encoding.
- `uvarint32` is canonical unsigned LEB128, limited to five bytes. Redundant leading zero groups,
  overflow above 32 bits, unterminated values, and values above the field limit are protocol errors.
- Raw identifiers are fixed-size byte strings. They are never C++ object representations.
- Text is UTF-8. Fields used in ACL or dispatch are compared as exact bytes after their domain-specific
  validation; no locale-sensitive comparison is allowed.
- A `safe_detail` is a 1-64 byte ASCII token matching `[a-z0-9_.-]+`. Remote free-form text is never a
  safe detail and must not be copied into errors or logs.
- A relative duration is an unsigned millisecond count. The receiver starts its own monotonic timer
  when the field is received and clamps it to its local maximum.
- A Unix millisecond timestamp is metadata or a bounded expiry hint. Wall-clock agreement MUST NOT be
  required for ordering, operation deadlines, replay uniqueness, or session correctness.

### 1.1 Identifier encodings

| Type | Wire bytes | Canonical text |
| --- | ---: | --- |
| `DeviceId` | 32 | `hy1_` + 52 lower-case RFC 4648 base32 characters |
| `EndpointId` | 16 | `hye1_` + 26 lower-case RFC 4648 base32 characters |
| `SessionId` | 16 | `hys1_` + 26 lower-case RFC 4648 base32 characters |
| `OperationId` | 16 | `hyo1_` + 26 lower-case RFC 4648 base32 characters |
| `MessageId` | 16 | `hym1_` + 26 lower-case RFC 4648 base32 characters |
| `RequestId` | 16 | `hyr1_` + 26 lower-case RFC 4648 base32 characters |
| `TransferId` | 16 | `hyt1_` + 26 lower-case RFC 4648 base32 characters |

Base32 has no padding. Upper-case input, non-zero unused trailing bits, aliases, whitespace, wrong
prefixes, and wrong lengths are rejected. `DeviceId` is exactly `SHA-256(raw Ed25519 public key)`.
Only the full 32-byte value participates in protocol comparison, storage keys, signatures, and ACLs.

## 2. Frame encoding

Every transport channel carries a sequence of frames:

```text
frame_length : uvarint32
frame_type   : uint8
flags        : uint8
channel_id   : uvarint32
message_id   : 16 raw bytes
payload      : frame_length - header bytes
```

`frame_length` counts all bytes after itself. Its minimum is 19 bytes and its configured maximum is
`Limits::max_frame_bytes` (2 MiB by default). `channel_id` is logical and is independent of a WebRTC
DataChannel ID. `message_id` remains present for control frames so diagnostics and duplicate handling
have one stable correlation field.

The only v1 flag is bit 0, `REQUIRED`. Bits 1-7 MUST be zero. A receiver skips an unknown frame when
`REQUIRED` is clear and closes that logical channel with `protocol` when it is set. Unknown optional
frames do not change state. Reserved flags, malformed varints, truncated declared frames, and known
frames that violate a domain limit are protocol errors.

| Range | Domain | Known v1 frame types |
| --- | --- | --- |
| `0x01-0x0f` | control | hello, close, ping, pong, cancel |
| `0x10-0x1f` | pairing | request, result |
| `0x20-0x2f` | message | message, ack |
| `0x30-0x3f` | RPC | request, response, cancel |
| `0x40-0x4f` | event | subscribe, item, unsubscribe |
| `0x50-0x5f` | stream | open, data, window update, fin, reset |
| `0x60-0x6f` | file | manifest, accept, chunk, complete, reject |
| `0x70-0x7f` | shell | open, input, output, resize, signal, exit, EOF, error, close |

The parser reads and validates the length varint before waiting for or allocating the payload. It then
validates the minimum header, flags, channel varint, and domain-specific payload limit. A streaming
implementation MAY retain at most the validated declared frame length. It MUST NOT reserve or allocate
from an unvalidated peer length.

Malformed service frames close only their logical channel unless identity, session binding, framing
alignment, or control-channel integrity is no longer trustworthy. A malformed control frame closes the
session. Resource exhaustion rejects the operation before state mutation and remains observable as
`resource_exhausted` or `would_block`.

## 3. Limits

`heyaki::Limits` is the single public baseline. Defaults are 2 MiB/frame, 64 KiB/control frame,
1 MiB/message and RPC payload, 8 MiB/1024-message send queue, 4 MiB/256-frame receive window,
16 GiB/file and 16 GiB/expanded file, 256 KiB/file chunk, 256 concurrent operations,
8 KiB/pairing payload, five pairing
attempts, 64 KiB/endpoint manifest, and 2048 diagnostic events. Validation also applies hard safety
ceilings. Negotiation may only reduce a local limit; a peer advertisement cannot raise it.

Queue message counts and byte counts are enforced together. Control traffic has separately reserved
capacity. Reject, drop-oldest, and keep-latest are semantic policies, not interchangeable defaults;
reliable control, pairing, message, RPC, stream, file, and shell frames default to rejection rather than
silent loss.

For a compressed file, manifest `size` is the encoded byte count and `expanded_size` is mandatory.
Receivers enforce both `max_file_bytes` and `max_expanded_file_bytes` before accepting the transfer.

## 4. Version and capability negotiation

Both peers send `{major, minor, supported_bits, required_bits}` in `SESSION_HELLO`. Required bits MUST
be a subset of the sender's supported bits. Major versions must match. The negotiated minor is the
smaller minor and negotiated capabilities are the intersection. If either peer requires a bit the other
does not support, negotiation fails explicitly with `protocol`; unknown optional bits are ignored.

Capability bits v1 are: enrollment `0`, signaling `1`, session `2`, pairing `3`, message `4`, unary RPC
`5`, event `6`, byte stream `7`, file `8`, and shell `9`. A schema field being parseable does not enable
its behavior without the corresponding negotiated capability.

Protobuf unknown fields follow normal proto3 preservation/skipping rules. Adding an optional field or
optional capability is a minor change. Changing field meaning, identifier width, canonical signing
bytes, framing, or a required state transition is a major change. Field numbers and enum numeric values
MUST NOT be reused.

## 5. Canonical signed objects

JSON and serialized Protobuf bytes MUST NOT be signed directly. Every signature input uses:

```text
magic          : 48 59 53 47 ("HYSG")
format_version : uint8 = 1
domain_length  : uint8
domain         : exact ASCII bytes
field_count    : uint16 big-endian
fields         : repeated in strictly increasing field number
  field_number : uint16 big-endian, non-zero
  value_length : uint32 big-endian
  value        : exact canonical bytes
```

The whole object is limited to 1 MiB. Integers use their documented fixed width in big-endian form;
IDs and hashes use raw fixed-width bytes; strings use exact validated UTF-8/ASCII bytes. There are no
implicit defaults. Required fields are always emitted, including zero-valued integers. Optional fields
are omitted, never encoded as an empty stand-in.

The field numbers and value encodings are fixed below. An omitted optional field is absent, not an empty
value. `ID32`, `ID16`, `NONCE32`, `HASH32`, `U16`, `U32`, and `U64` mean respectively raw 32-byte ID,
raw 16-byte ID, 32-byte nonce, 32-byte SHA-256/BLAKE3 digest, and fixed-width unsigned big-endian
integers. `TEXT` is exact validated UTF-8; `ASCII` is exact bytes in the printable ASCII range.

| Domain separator | Field number and value encoding, in order | Signer/role |
| --- | --- | --- |
| `heyaki.enrollment.v1` | 1 ID32 device, 2 ID16 endpoint, 3 raw 32-byte identity public key, 4 raw 32-byte relay ID, 5 NONCE32 challenge, 6 TEXT tenant, 7 U32 major, 8 U32 minor, 9 U64 supported bits, 10 U64 required bits, 11 U64 expiry | enrolling device |
| `heyaki.enrollment-record.v1` | 1 ID32 device, 2 ID16 endpoint, 3 raw 32-byte relay ID, 4 TEXT tenant, 5 U64 generation, 6 U64 issued time | relay |
| `heyaki.endpoint-record.v1` | 1 ID32 device, 2 ID16 endpoint, 3 TEXT application ID, 4 U64 record generation, 5 HASH32 manifest, 6 U64 expiry | device |
| `heyaki.service-manifest.v1` | 1 ID32 device, 2 ID16 endpoint, 3 U64 manifest generation, 4 HASH32 canonical manifest, 5 U64 expiry | device |
| `heyaki.offer.v1` | 1 initiator ID32, 2 initiator ID16 endpoint, 3 responder ID32, 4 responder ID16 endpoint, 5 ID16 request, 6 ID16 session, 7 NONCE32 initiator nonce, 8 U64 expiry, 9 exact SDP bytes, 10 raw 32-byte DTLS fingerprint | initiator |
| `heyaki.answer.v1` | 1-6 same signaling binding, 7 NONCE32 initiator nonce, 8 NONCE32 responder nonce, 9 U64 expiry, 10 exact SDP bytes, 11 raw 32-byte DTLS fingerprint | responder |
| `heyaki.candidate.v1` | 1-6 same signaling binding, 7 NONCE32 initiator nonce, 8 NONCE32 responder nonce, 9 U64 expiry, 10 U32 candidate sequence, 11 exact candidate bytes | candidate owner |
| `heyaki.session-hello.v1` | 1 sender ID32, 2 sender ID16 endpoint, 3 peer ID32, 4 peer ID16 endpoint, 5 ID16 session, 6 U64 epoch, 7 NONCE32 initiator nonce, 8 NONCE32 responder nonce, 9 raw 32-byte DTLS exporter binding, 10 U32 major, 11 U32 minor, 12 U64 supported bits, 13 U64 required bits, 14 U64 expiry | hello sender |
| `heyaki.trust-grant.v1` | 1 ID16 grant, 2 issuer ID32, 3 subject ID32, 4 scope list, 5 U64 password generation, 6 U64 issued time, optional 7 U64 expiry, 8 NONCE32 pairing nonce | grant issuer |

The scope-list value is `U16 count` followed by `count` repetitions of `U16 byte length` and
`ASCII` scope bytes. It is sorted by byte order, unique, and bounded to 0-256 scopes of 1-256
bytes each. The two device identities and endpoints are always bound for signaling and session
objects. Expiry is checked with a bounded local skew policy; replay uniqueness relies on the signed
nonce/ID tuple. Bootstrap tokens and other secrets are never canonicalized or signed.

An offer omits `responder_nonce`. A valid answer supplies it, and candidate transmission starts only
after that answer has been verified so every candidate binds both nonces. The canonical answer and
candidate objects therefore always contain fields 7 and 8.

Signatures are Ed25519 over the canonical bytes. Verification also checks that each declared
`DeviceId` derives from the supplied public key, the signing role is correct, and all fixed widths and
semantic limits hold before accepting state.

## 6. State machines and exceptional frames

| Domain | States | Duplicate, order, and late-frame rule |
| --- | --- | --- |
| Enrollment | challenge, submitted, persisting, complete/error | Same request ID and bytes may replay the cached response; changed bytes are rejected. Expired challenges never restart implicitly. |
| Signaling | idle, offered, answered, candidates, expired/closed | Answer before offer and candidates for an unknown request are rejected. Candidate sequence duplicates are ignored only when bytes match. |
| Session | transport-connected, authenticating, pairing-restricted/authorized, active, reconnecting, closed | Business frames before authorization are rejected. Every frame belongs to one epoch; lower epochs are late and ignored, higher epochs require a new authenticated hello. |
| Pairing | awaiting-request, verifying, granted/denied, closed | Nonce/request duplicates use a bounded cached result. Attempts above the limit are denied and observed; no business channel is opened on failure. |
| Message | received, validated, delivered/duplicate, acked | Message IDs are deduplicated in a bounded TTL window. Independent messages may arrive out of order; a late epoch is ignored. |
| RPC | received, executing, responded/cancelled/outcome-unknown | A request ID maps to one immutable request. Cancellation is cooperative. Non-idempotent work interrupted after admission returns outcome unknown and is not retried. |
| Event | subscribed, active, unsubscribed/closed | Publisher sequence detects gaps and duplicates. Best-effort may drop; reliable-live closes only the subscription on irrecoverable overflow. |
| Stream | idle, open, half-closed-local/remote, closed/reset | DATA offsets must match the next expected offset. Exact already-consumed duplicates may be ignored; gaps, conflicting duplicates, and DATA after FIN reset the stream. |
| File | offered, accepted/rejected, transferring, verifying, committed/failed | REJECT is an explicit terminal response. Chunks may arrive out of order within the negotiated bitmap/window. Same offset and hash is idempotent; conflict fails the transfer. COMPLETE before all chunks is rejected. |
| Shell | opening, active, input-eof, exited, closed | EOF is explicit and idempotent. Data offsets are ordered. Resize may supersede older resize state. Input after EOF and frames after EXIT are rejected locally; ERROR/CLOSE terminates only the shell channel. |

Every transition validates frame size before decoding payload and validates the session epoch before
mutating state. Oversize frames fail at the parser. Protobuf decode failure, a repeated identifier with
different immutable bytes, or an impossible transition yields stable `protocol` status and the local
failure scope above. No parser loops waiting on an already complete invalid input.

## 7. Golden vectors

`tests/vectors/m1-golden-vectors.json` contains the normative DeviceId derivation, canonical signing
encoding, Ed25519 signature over that canonical offer, Protobuf Lite envelope bytes, and complete frame
bytes. Tests read
that JSON at configure time and compare exact bytes. Implementations must not normalize or reserialize
the expected values before comparison.
