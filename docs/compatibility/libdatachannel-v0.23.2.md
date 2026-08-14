# libdatachannel v0.23.2 Compatibility Matrix

Pinned source: `v0.23.2` at commit `9e6a13abbb6846c003d817d0387b6706466e2b03` with recursive
submodules verified by `scripts/fetch_third_party.sh`.

| Area | Selected M0 baseline | Evidence | Verification status |
| --- | --- | --- | --- |
| Build profile | static DataChannel-only library; examples, upstream tests, media, and WebSocket disabled | `BUILD_SHARED_LIBS=OFF`, `NO_EXAMPLES=ON`, `NO_TESTS=ON`, `NO_MEDIA=ON`, `NO_WEBSOCKET=ON` | GCC 13.3 Release build passed locally; GCC/Clang/MSVC gate added to CI |
| ICE backend | bundled libjuice | libdatachannel defaults `USE_NICE=OFF`; pinned libjuice submodule is initialized and included by the baseline build | GCC 13.3 build verified; GCC/Clang/MSVC CI result pending |
| TURN/UDP | required | libjuice documents RFC 5766/8656 TURN relay support | Capability documented; coturn interop pending M4 |
| TURN/TCP/TLS | v1 requirement, unavailable in selected M0 backend | `IceTransport` explicitly rejects both with libjuice; its libnice branch maps `TurnTcp` and `TurnTls` to the corresponding `NiceRelayType` | Negative capability verified by a pinned-source contract test; select/pin libnice or revise DEC-02 before M3 |
| Certificate/TLS | OpenSSL, one process-wide TLS family | libdatachannel defaults `USE_GNUTLS=OFF`, `USE_MBEDTLS=OFF`; local CMake selected OpenSSL 3.0.13 | Baseline build verified locally; Linux/Windows release artifacts freeze before M3 |
| Linux GCC | x86_64 | standalone pinned source build with the M0 profile | GCC 13.3 Release passed locally; CI gate pending |
| Linux Clang | x86_64 | standalone pinned source build added to the Clang matrix job | CI gate pending |
| Windows MSVC | x64 | standalone pinned source build uses the `windows-2025` OpenSSL development package | CI gate pending |

The M0 gate is a compile and capability baseline, not a claim of network interoperability. It is
complete only when the standalone pinned build passes GCC, Clang, and MSVC CI. The selected
`USE_NICE=OFF` profile is suitable only for UDP ICE/TURN and is an explicit negative result for
TURN/TCP/TLS. Meeting DEC-02 still requires a pinned libnice/GLib dependency set with Linux and
Windows build proof, or an explicit product decision changing the requirement, before M3 starts.
TURN/UDP/TCP/TLS must then be tested against the selected coturn artifact in M4; configuration enums
and compile success alone are not interoperability evidence.
