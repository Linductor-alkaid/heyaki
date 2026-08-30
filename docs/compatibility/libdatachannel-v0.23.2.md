# libdatachannel v0.23.2 Compatibility Matrix

Pinned source: `v0.23.2` at commit `9e6a13abbb6846c003d817d0387b6706466e2b03` with recursive
submodules verified by `scripts/fetch_third_party.sh`.

| Area | Selected M0 baseline | Evidence | Verification status |
| --- | --- | --- | --- |
| Build profile | static DataChannel-only library; examples, upstream tests, media, WebSocket, and install rules disabled | `BUILD_SHARED_LIBS=OFF`, `NO_EXAMPLES=ON`, `NO_TESTS=ON`, `NO_MEDIA=ON`, `NO_WEBSOCKET=ON`, `CMAKE_SKIP_INSTALL_RULES=ON` | GCC 13.3 local build and GCC/Clang/MSVC CI passed |
| ICE backend | bundled libjuice | libdatachannel defaults `USE_NICE=OFF`; pinned libjuice submodule is initialized and included by the baseline build | GCC/Clang/MSVC baseline build passed |
| TURN/UDP | required | libjuice documents RFC 5766/8656 TURN relay support | Verified against the pinned coturn artifact in the M4 CI network matrix (direct / forced TURN / TURN-fallback topologies, MATRIX_OK 2026-08-27) |
| TURN/TCP/TLS | v1 requirement, unavailable in selected backend | `IceTransport` explicitly rejects both with libjuice; its libnice branch maps `TurnTcp` and `TurnTls` to the corresponding `NiceRelayType` | Negative capability verified by a pinned-source contract test; still requires selecting/pinning libnice or a DEC-02 product decision (open) |
| Certificate/TLS | OpenSSL, one process-wide TLS family | libdatachannel defaults `USE_GNUTLS=OFF`, `USE_MBEDTLS=OFF`; local CMake selected OpenSSL 3.0.13 | OpenSSL-backed Linux/Windows CI builds passed since the M3A LAN TLS baseline; exact release-package artifacts remain a release-provenance gate (M9) |
| Linux GCC | x86_64 | standalone pinned source build with the M0 profile | CI passed at `72c55d7` |
| Linux Clang | x86_64 | standalone pinned source build with the M0 profile | CI passed at `72c55d7` |
| Windows MSVC | x64 | standalone pinned source build uses the `windows-2025` OpenSSL development package | CI passed at `72c55d7` |

The pinned upstream CMake evaluates `$<TARGET_PDB_FILE:datachannel>` from an install rule whenever
MSVC is active. With `BUILD_SHARED_LIBS=OFF`, `datachannel` is static and that generator expression
is invalid. The M0 probe does not install libdatachannel, so it sets `CMAKE_SKIP_INSTALL_RULES=ON`
instead of patching pinned source or changing the library type. Heyaki still does not install
libdatachannel as a separate artifact (the CI baseline keeps `CMAKE_SKIP_INSTALL_RULES=ON`); the
upstream install rule must be revisited first if that ever changes.

The M0 compile and capability gate passed on GCC, Clang, and MSVC, and the M4 CI network matrix
(2026-08-27, MATRIX_OK) since verified TURN/UDP interoperability against the pinned coturn artifact
across direct / forced TURN / TURN-fallback / UDP-blocked / lossy / relay-restart topologies. The
selected `USE_NICE=OFF` profile is suitable only for UDP ICE/TURN and remains an
explicit negative result for TURN/TCP/TLS. Meeting DEC-02 still requires a pinned libnice/GLib
dependency set with Linux and Windows build proof, or an explicit product decision changing the
requirement; configuration enums and compile success alone are not interoperability evidence.
