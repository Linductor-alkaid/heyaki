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
DataChannel ID. `message_id` MUST be a non-zero, unpredictable 16-byte value. It identifies one
logical emitted frame; an exact retransmission preserves it, while a different frame gets a new value.
It is diagnostic/deduplication correlation only and never replaces the immutable request, stream,
transfer, subscription, shell, or operation ID inside the payload.

The only v1 flag is bit 0, `REQUIRED`. Bits 1-7 MUST be zero. A receiver skips an unknown frame when
`REQUIRED` is clear and closes that logical channel with `protocol` when it is set. Unknown optional
frames do not change state. Reserved flags, malformed varints, truncated declared frames, and known
frames that violate a domain limit are protocol errors.

The v1 numeric values and payload codecs are frozen below. `PB` means one complete Protobuf Lite
message of the named type with no length prefix inside `payload`. `RAW` means the exact layout in
section 2.1. Values not listed are unknown frame types and MUST NOT be assigned a v1 meaning later.

| Value | Frame | Channel | Payload codec |
| ---: | --- | ---: | --- |
| `0x01` | `SESSION_HELLO` | `0` | PB `heyaki.protocol.session.v1.SessionHello` |
| `0x02` | `PROTOCOL_CLOSE` | `0` | PB `heyaki.protocol.session.v1.SessionClose` |
| `0x03` | `PING` | `0` | RAW `ping_id: U64` |
| `0x04` | `PONG` | `0` | RAW `ping_id: U64`, exactly echoing a received PING |
| `0x05` | `CANCEL` | target channel, `0` for session operation | RAW `operation_id: ID16, session_epoch: U64` |
| `0x10` | `PAIRING_REQUEST` | `0` | PB `heyaki.protocol.pairing.v1.PairingRequest` |
| `0x11` | `PAIRING_RESULT` | `0` | PB `heyaki.protocol.pairing.v1.PairingResult` |
| `0x20` | `MESSAGE` | non-zero | PB `heyaki.protocol.message.v1.MessageEnvelope` |
| `0x21` | `MESSAGE_ACK` | non-zero | PB `heyaki.protocol.message.v1.MessageAck` |
| `0x30` | `RPC_REQUEST` | non-zero | PB `heyaki.protocol.rpc.v1.RpcRequest` |
| `0x31` | `RPC_RESPONSE` | non-zero | PB `heyaki.protocol.rpc.v1.RpcResponse` |
| `0x32` | `RPC_CANCEL` | non-zero | PB `heyaki.protocol.rpc.v1.RpcCancel` |
| `0x40` | `EVENT_SUBSCRIBE` | non-zero | PB `heyaki.protocol.event.v1.EventSubscribe` |
| `0x41` | `EVENT_ITEM` | non-zero | PB `heyaki.protocol.event.v1.EventItem` |
| `0x42` | `EVENT_UNSUBSCRIBE` | non-zero | PB `heyaki.protocol.event.v1.EventUnsubscribe` |
| `0x50` | `STREAM_OPEN` | non-zero | PB `heyaki.protocol.stream.v1.StreamOpen` |
| `0x51` | `STREAM_DATA` | non-zero | RAW `StreamData` |
| `0x52` | `STREAM_WINDOW_UPDATE` | non-zero | PB `heyaki.protocol.stream.v1.WindowUpdate` |
| `0x53` | `STREAM_FIN` | non-zero | PB `heyaki.protocol.stream.v1.StreamFinish` |
| `0x54` | `STREAM_RESET` | non-zero | PB `heyaki.protocol.stream.v1.StreamReset` |
| `0x60` | `FILE_MANIFEST` | non-zero | PB `heyaki.protocol.file.v1.FileManifest` |
| `0x61` | `FILE_ACCEPT` | non-zero | PB `heyaki.protocol.file.v1.FileAccept` |
| `0x62` | `FILE_CHUNK` | non-zero | RAW `FileChunk` |
| `0x63` | `FILE_COMPLETE` | non-zero | PB `heyaki.protocol.file.v1.FileComplete` |
| `0x64` | `FILE_REJECT` | non-zero | PB `heyaki.protocol.file.v1.FileReject` |
| `0x70` | `SHELL_OPEN` | non-zero | PB `heyaki.protocol.shell.v1.ShellOpen` |
| `0x71` | `SHELL_INPUT` | non-zero | RAW `ShellData` |
| `0x72` | `SHELL_OUTPUT` | non-zero | RAW `ShellData` |
| `0x73` | `SHELL_RESIZE` | non-zero | PB `heyaki.protocol.shell.v1.ShellResize` |
| `0x74` | `SHELL_SIGNAL` | non-zero | PB `heyaki.protocol.shell.v1.ShellSignal` |
| `0x75` | `SHELL_EXIT` | non-zero | PB `heyaki.protocol.shell.v1.ShellExit` |
| `0x76` | `SHELL_EOF` | non-zero | PB `heyaki.protocol.shell.v1.ShellEof` |
| `0x77` | `SHELL_ERROR` | non-zero | PB `heyaki.protocol.shell.v1.ShellError` |
| `0x78` | `SHELL_CLOSE` | non-zero | PB `heyaki.protocol.shell.v1.ShellClose` |

Control and pairing frames listed with channel `0` are rejected on any other channel. All listed
business frames are rejected on channel `0`. Each non-zero channel is opened for one protocol domain
and cannot change domain. Response payload IDs MUST equal the request ID they answer; outer
`message_id` values remain distinct. A duplicate outer `message_id` is accepted only when type, flags,
channel, and payload bytes are identical.

### 2.1 Raw payloads

All raw integers are unsigned big-endian. Each ID is exactly 16 raw bytes. The declared `data_length`
MUST equal the number of remaining payload bytes; mismatch, overflow, truncation, or trailing bytes is
a protocol error before delivery or allocation.

```text
StreamData := stream_id:ID16 | offset:U64 | data_length:U32 | data:data_length
FileChunk  := transfer_id:ID16 | offset:U64 | data_length:U32 | blake3:32 bytes |
              data:data_length
ShellData  := shell_id:ID16 | offset:U64 | data_length:U32 | data:data_length
```

The fixed header sizes are 28 bytes for `StreamData` and `ShellData`, and 60 bytes for `FileChunk`.
`StreamDataHeader`, `FileChunkHeader`, and `ShellDataHeader` are deliberately not Protobuf messages.
`FILE_CHUNK.data_length` is included in `Limits::max_file_chunk_bytes`; a receiver validates both the
frame and chunk limits before retaining the bytes.

### 2.2 Session epoch context

Only `SESSION_HELLO` carries `session_id` and `session_epoch`. After both signed hellos authenticate,
the transport channel is bound to exactly that `(SessionId, SessionEpoch)` tuple. Every later frame is
interpreted inside that immutable context; an implementation MUST pass the authenticated context into
payload/state validation and MUST NOT infer an epoch from `channel_id` or `message_id`. Reconnect creates
new logical channels and requires a new hello with a strictly greater epoch. Bytes from an old
transport cannot be injected into the new epoch. Deduplication and operation keys therefore include
the authenticated session tuple plus the domain ID.

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
integers. `TEXT` is non-empty exact validated UTF-8; `ASCII` is exact bytes in the printable ASCII
range.

| Domain separator | Field number and value encoding, in order | Signer/role |
| --- | --- | --- |
| `heyaki.enrollment.v1` | 1 ID32 device, 2 ID16 endpoint, 3 raw 32-byte identity public key, 4 raw 32-byte relay ID, 5 NONCE32 challenge, 6 TEXT tenant, 7 U32 major, 8 U32 minor, 9 U64 supported bits, 10 U64 required bits, 11 U64 expiry | enrolling device |
| `heyaki.enrollment-record.v1` | 1 ID32 device, 2 ID16 endpoint, 3 raw 32-byte relay ID, 4 TEXT tenant, 5 U64 generation, 6 U64 issued time | relay |
| `heyaki.endpoint-record.v1` | 1 ID32 device, 2 ID16 endpoint, 3 TEXT application ID, 4 U64 record generation, 5 HASH32 manifest, 6 U64 expiry | device |
| `heyaki.service-manifest.v1` | 1 ID32 device, 2 ID16 endpoint, 3 U64 manifest generation, 4 HASH32 canonical manifest, 5 U64 expiry | device |
| `heyaki.offer.v1` | 1 initiator ID32, 2 initiator ID16 endpoint, 3 responder ID32, 4 responder ID16 endpoint, 5 ID16 request, 6 ID16 session, 7 NONCE32 initiator nonce, 8 U64 expiry, 9 exact SDP bytes, 10 raw 32-byte DTLS fingerprint | initiator |
| `heyaki.answer.v1` | 1-6 same signaling binding, 7 NONCE32 initiator nonce, 8 NONCE32 responder nonce, 9 U64 expiry, 10 exact SDP bytes, 11 raw 32-byte DTLS fingerprint | responder |
| `heyaki.candidate.v1` | 1-6 same signaling binding, 7 NONCE32 initiator nonce, 8 NONCE32 responder nonce, 9 U64 expiry, 10 U32 candidate sequence, 11 exact candidate bytes, 12 HASH32 signaling transcript, 13 ASCII candidate-owner ICE ufrag, 14 raw 32-byte candidate-owner DTLS fingerprint | candidate owner |
| `heyaki.session-hello.v1` | 1 sender ID32, 2 sender ID16 endpoint, 3 peer ID32, 4 peer ID16 endpoint, 5 ID16 session, 6 U64 epoch, 7 NONCE32 initiator nonce, 8 NONCE32 responder nonce, 9 HASH32 signaling transcript, 10 U32 major, 11 U32 minor, 12 U64 supported bits, 13 U64 required bits, 14 U64 expiry | hello sender |
| `heyaki.trust-grant.v1` | 1 ID16 grant, 2 issuer ID32, 3 subject ID32, 4 scope list, 5 U64 password generation, 6 U64 issued time, optional 7 U64 expiry, 8 NONCE32 pairing nonce | grant issuer |

The scope-list value is `U16 count` followed by `count` repetitions of `U16 byte length` and
`ASCII` scope bytes. It is sorted by byte order, unique, and bounded to 0-256 scopes of 1-256
bytes each. The two device identities and endpoints are always bound for signaling and session
objects. Bootstrap tokens and other secrets are never canonicalized or signed.

An offer omits `responder_nonce`. A valid answer supplies it, and candidate transmission starts only
after that answer has been verified so every candidate binds both nonces. The canonical answer and
candidate objects therefore always contain fields 7 and 8. The candidate owner is derived from the
verified signing key. Its signed ICE ufrag and fingerprint MUST exactly equal that owner's values in
the verified offer or answer; its transcript hash MUST equal the session's verified transcript. Thus
a relay cannot move a valid candidate to another ICE generation, fingerprint, answer, or session.

The signaling transcript is not a Protobuf serialization and is not a DTLS exporter. It is exactly:

```text
ASCII "heyaki.signaling-transcript.v1"
U32 big-endian canonical_offer_length | canonical heyaki.offer.v1 bytes
U32 big-endian canonical_answer_length | canonical heyaki.answer.v1 bytes
```

The transcript value is SHA-256 over those exact bytes, with the offer first and answer second. Each
canonical object is limited to 1 MiB. `SESSION_HELLO` carries and signs this digest over the actual
DataChannel only after WebRTC has verified the signed DTLS fingerprint from the corresponding SDP.
Both peers MUST compare the digest to their locally verified offer/answer pair before authorizing the
session. Pinned libdatachannel v0.23.2 exposes no public DTLS exporter API, so protocol 1.0 does not
claim an unavailable exporter binding.

For protocol 1.0, a signed transient object's expiry may be at most five minutes in the verifier's
future and is accepted for at most 30 seconds of negative clock skew. The replay-cache key is the
signing domain, signer `DeviceId`, request/session/grant ID as applicable, nonce tuple, and sequence
when present. An accepted key is retained for the fixed ten-minute replay TTL, which exceeds the
maximum five-minute validity plus skew. Cache saturation rejects admission and emits the documented
security counter; eviction MUST NOT silently reopen a still-valid replay window.

Signatures are Ed25519 over the canonical bytes. Verification also checks that each declared
`DeviceId` derives from the supplied public key, the signing role is correct, and all fixed widths and
semantic limits hold before accepting state.

## 6. State machines and exceptional frames

Enrollment and signaling run on the relay control plane before frame transport. Enrollment transitions
`challenge -> submitted -> persisting -> complete|error`; only an identical request may receive a
bounded cached response, while changed bytes under the same request/challenge are rejected. Signaling
transitions `idle -> offered -> answered -> candidates -> expired|closed`. An answer before its offer,
a candidate before the verified answer, or any object with a different binding tuple is rejected.
Candidate sequence duplicates are idempotent only when the entire signed object is byte-identical.

### 6.1 Session and pairing

| Current state | Accepted frame/event | Next state and action |
| --- | --- | --- |
| `transport-connected` | local transport ready | `authenticating`; send `SESSION_HELLO` |
| `transport-connected` or `authenticating` | verified peer `SESSION_HELLO` with exact session, epoch, nonces, transcript, identities, and capabilities | `pairing-restricted` when no grant exists, otherwise `authorized` |
| `authenticating` | byte-identical duplicate hello | no state change; resend cached local hello if needed |
| `authenticating` | conflicting hello, business frame, or failed signature/transcript/fingerprint check | `closed`; send `PROTOCOL_CLOSE` when integrity permits |
| `pairing-restricted` | `PAIRING_REQUEST` or `PAIRING_RESULT` | remain restricted while verifying; successful grant moves to `authorized` |
| `pairing-restricted` | any business frame (`0x20-0x78`) | reject and close the offending channel; repeated violation closes the session |
| `authorized` | first valid business channel/frame | `active` |
| `authorized` or `active` | `PING`, matching `PONG`, valid `CANCEL` | remain; update liveness or request cooperative cancellation |
| any non-terminal state | `PROTOCOL_CLOSE` or transport loss | `closed` or local `reconnecting`; no new admission |
| `closed` | any late frame | ignore without response or state resurrection |

A hello with a lower epoch is late and ignored. A higher epoch is never accepted on the existing
transport; it requires a new transport and fresh mutual hello. A duplicate hello with changed bytes is
an authentication failure. `PAIRING_REQUEST` is keyed by `(session, epoch, request_id, nonce)`; an
identical duplicate reuses the bounded cached result, while a conflicting duplicate is `protocol`.
Denied, rate-limited, and granted results are terminal for that request. Password verification failure
never opens a business channel.

### 6.2 Message, RPC, and event

| Domain/current state | Frame | Transition and duplicate/late rule |
| --- | --- | --- |
| Message `idle` | `MESSAGE` | validate immutable envelope, then `delivered` or `duplicate`; send `MESSAGE_ACK` only for peer-acked mode |
| Message `delivered` | same message ID and exact envelope | no redelivery; replay cached ACK when applicable |
| Message `delivered` | same message ID with changed bytes | close message channel with `protocol` |
| Message any | `MESSAGE_ACK` | mark the matching sent message `acked`; unknown/late ACK is ignored and counted |
| RPC `idle` | `RPC_REQUEST` | `executing` after validation and admission; request ID binds one immutable request |
| RPC `executing` | identical `RPC_REQUEST` | do not execute twice; replay terminal response when cached, otherwise keep executing |
| RPC `executing` | `RPC_CANCEL` or matching generic `CANCEL` | request cooperative cancellation; cancellation does not imply work stopped |
| RPC `executing` | local completion | `responded`, `cancelled`, or `outcome-unknown`; emit exactly one terminal `RPC_RESPONSE` |
| RPC terminal | duplicate request/cancel | replay the cached response or ignore cancel; changed request bytes are `protocol` |
| Event `idle` | `EVENT_SUBSCRIBE` | `active`; subscription ID binds topic, match mode, and QoS immutably |
| Event `active` | `EVENT_ITEM` | accept increasing publisher sequence; exact duplicate is ignored, conflicting duplicate closes the subscription |
| Event `active` | `EVENT_UNSUBSCRIBE` | `unsubscribed`; release buffers and stop publication |
| Event terminal | late item/unsubscribe | ignore and count; never recreate the subscription |

Independent message IDs, RPC request IDs, and subscriptions may progress out of order. Best-effort
events may expose a sequence gap. Reliable-live overflow terminates only that subscription with an
observable error; it does not silently drop or close unrelated channels. Non-idempotent RPC work that
loses its transport after admission becomes `outcome-unknown` and is never automatically retried.

### 6.3 Stream, file, and shell

| Domain/current state | Frame | Transition and exceptional rule |
| --- | --- | --- |
| Stream `idle` | `STREAM_OPEN` | `open`; fix stream ID and receive windows |
| Stream `open` | `STREAM_DATA` | accept only the next offset; exact already-consumed bytes are duplicate, gaps/conflicts reset |
| Stream `open` | `STREAM_WINDOW_UPDATE` | increase credit only from a monotonic consumed offset; stale update is ignored, overflow resets |
| Stream `open` | `STREAM_FIN` | `half-closed-remote`; final offset MUST equal received end |
| Stream open/half-closed | `STREAM_RESET` | `reset`; release buffers and fail only this stream |
| Stream half-closed | local FIN and both final offsets reached | `closed` |
| Stream `closed` or `reset` | late DATA/window/FIN | ignore; an exact repeated RESET is idempotent |
| File `idle` | `FILE_MANIFEST` | `offered`; bind transfer ID, size, digest, chunk size, and compression fields |
| File `offered` | `FILE_ACCEPT` | `transferring`; fix present-chunk set and receive bounds |
| File `offered` | `FILE_REJECT` | `rejected`; terminal and explicit |
| File `transferring` | `FILE_CHUNK` | accept an in-window offset; same offset/length/hash/data is idempotent, any conflict fails transfer |
| File `transferring` | `FILE_COMPLETE` | `verifying` only after all bytes exist; early complete is `protocol` |
| File `verifying` | local size/digest/commit success or failure | `committed` or `failed`; emit/retain one terminal result |
| File terminal | any late chunk/complete/reject | ignore exact terminal replay; never reopen or overwrite committed output |
| Shell `idle` | `SHELL_OPEN` | `opening`, then `active` only after policy and authorization succeed |
| Shell `active` | `SHELL_INPUT` or `SHELL_OUTPUT` | accept exactly next directional offset; duplicate bytes are ignored, gap/conflict closes shell |
| Shell `active` | `SHELL_RESIZE` | remain active; a newer accepted resize supersedes older state |
| Shell `active` | `SHELL_SIGNAL` | remain active after policy validation; unsupported signal returns `SHELL_ERROR` |
| Shell `active` | `SHELL_EOF` | `input-eof`; duplicate EOF is idempotent and input after EOF is rejected |
| Shell active/input-eof | `SHELL_EXIT` | `exited`; exit status is immutable |
| Shell non-terminal | `SHELL_ERROR` or `SHELL_CLOSE` | `closed`; release terminal buffers and process handle through the owning service |
| Shell `exited` or `closed` | any late non-identical frame | ignore and count; never restart the process or channel |

Every transition validates frame length and domain limit before payload decoding, then validates the
authenticated session/epoch context, channel domain, payload ID, and current state before mutation.
Protobuf decode failure, raw length mismatch, repeated ID with different immutable bytes, impossible
transition, or data offset overflow yields stable `protocol` status at the smallest trustworthy scope.
Malformed control/session binding closes the session; a service-state failure closes only its logical
channel. No parser loops waiting on an already complete invalid input.

## 7. Golden vectors

`tests/vectors/m1-golden-vectors.json` contains the normative DeviceId derivation, canonical signing
encoding, Ed25519 signature over that canonical offer, Protobuf Lite envelope bytes, and complete frame
bytes. Tests read
that JSON at configure time and compare exact bytes. Implementations must not normalize or reserialize
the expected values before comparison.
