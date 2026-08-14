# libdatachannel v0.23.2 Compatibility Matrix

Pinned source: `v0.23.2` at commit `9e6a13abbb6846c003d817d0387b6706466e2b03` with recursive
submodules verified by `scripts/fetch_third_party.sh`.

| Area | Selected M0 baseline | Evidence | Verification status |
| --- | --- | --- | --- |
| ICE backend | bundled libjuice | libdatachannel defaults `USE_NICE=OFF`; pinned libjuice submodule is initialized | Source/config verified; build pending M4 |
| TURN/UDP | required | libjuice documents RFC 5766/8656 TURN relay support | Capability documented; coturn interop pending M4 |
| TURN/TCP/TLS | v1 requirement, backend unresolved | `IceServer` exposes `TurnTcp`/`TurnTls`, but `IceTransport` explicitly rejects both when built with libjuice; the libnice branch maps them | Default backend cannot meet DEC-02; pin/test libnice or revise the requirement before M3 |
| Certificate/TLS | OpenSSL, one process-wide TLS family | libdatachannel defaults `USE_GNUTLS=OFF`, `USE_MBEDTLS=OFF` | Linux/Windows exact artifacts freeze before M3 |
| Linux GCC | x86_64 | M0 empty wrapper target builds without libdatachannel | Full backend build pending M4 |
| Linux Clang | x86_64 | CI job defined | Runner result pending |
| Windows MSVC | x64 | upstream declares Windows/MSVC support; CI job defined | Runner result and TURN modes pending |

M0 therefore establishes the pin and identifies a concrete backend mismatch, but does not mark the
WebRTC compatibility task complete. The current `USE_NICE=OFF` default is suitable only for the UDP
ICE/TURN path. Meeting the current v1 requirement needs a pinned libnice/GLib dependency set and
Windows build proof, or an explicit product decision that changes DEC-02. TURN/TCP/TLS must then be
tested against the selected coturn artifact; configuration enums alone are not evidence of support.
