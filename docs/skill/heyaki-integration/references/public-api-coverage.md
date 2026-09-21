# Public API Coverage

## Library targets

Installed and exported by the SDK (`find_package(heyaki)`):

| Target | Contents |
| --- | --- |
| `heyaki::core` | Wire protocol, identity, signing, errors, ids, time — no I/O |
| `heyaki::profile` | `ProfileStore`, password verifier, secret backends |
| `heyaki::client` | `Node`, sessions, LAN directory, relay control, services, file store |
| `heyaki::services` | Thin module umbrella over the service layer |
| `heyaki::transport_webrtc` | The v1 data-plane backend (libdatachannel) |

In-tree components, **not** in the SDK export set: `heyaki::relay` (the
`heyaki-relay` binary's `RelayServer`/`RelayDatabase`) and `heyaki::socks`
(the TUI's SOCKS5 frontend). Downstream consumers get the relay as the
shipped `heyaki-relay` executable and the SOCKS frontend through the TUI —
see [relay](relay.md) and [gateway](gateway.md) for what that means in
practice.

Everything public is in namespace `heyaki`, headers under `include/heyaki/`.
The full reference is [api.md](../../../api.md); the CMake consumption surface
is [client-library.md](../../../client-library.md).

## Protocol compatibility

- Wire protocol version is `{1, 3}`; negotiation (`negotiate_protocol`)
  takes the intersection: same major required, minor = min, capabilities
  intersected, required bits double-checked.
- **Parsers reject unknown fields** (canonical signed objects — skipping a
  field would change the signature input). New optional fields in v1.x are
  emitted gated on the negotiated minor.
- N-1 devices interoperate: LAN discovery admits same-major peers back to
  the LAN floor (minor 1), relay login clamps granted capabilities to the
  negotiated version, relay schema migrations are forward-only.
- CMake consumers get `SameMajorVersion` package compatibility: 1.x SDK
  upgrades are drop-in; the installed-consumer test gates the export set.

## Compatibility policy sources

[compatibility/](../../../compatibility/) and the frozen
[wire protocol](../../../design/heyaki-wire-protocol.md); the `heyaki_m9_compat`
suite pins all of the above in CI.
