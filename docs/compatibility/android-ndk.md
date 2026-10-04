# Android (NDK) Port Compatibility Notes

Status: M11 alpha baseline (2026-10-04). Scope per `docs/todolists/m11-android-port.md`:
the C++20 core libraries (`heyaki-core`, profile, client, services, socks, transport_webrtc)
cross-compile and install for Android; apps, demos, fuzzers, and host test targets stay
desktop-only, and no full Android application/UI is delivered.

## Build entry points

| Item | Value |
| --- | --- |
| Toolchain | NDK r26d (26.3.11579264) via `android.toolchain.cmake`; the executor CI line uses the same r26 series |
| API floor | `android-24` — bionic provides `getifaddrs`/`if_nametoindex` from API 24 and the LAN route's POSIX interface enumeration requires them (M11 plan A3) |
| ABIs | `arm64-v8a`, `x86_64` verified; `armeabi-v7a`/`x86` map to OpenSSL `android-arm`/`android-x86` Configure targets but are not part of the alpha gate |
| Script | `scripts/build_android.sh --ndk <ndk> [--abi arm64-v8a,x86_64] [--api 24]` |
| CMake mode | `HEYAKI_ANDROID=ON` (resolved from the toolchain's `ANDROID`); forces `HEYAKI_BUILD_APPS=OFF`, `HEYAKI_BUILD_FUZZERS=OFF`, `BUILD_TESTING=OFF` |
| TLS backend | vendored OpenSSL 3.5.9 (pinned lock atom, Apache-2.0), cross-built with OpenSSL's own `Configure` into `<build>/vendored/openssl-stage` and consumed through the standard `find_package(OpenSSL 3.0 …)` gates (3.x floor, 4.x freeze); desktop builds keep the system OpenSSL path |

## Per-dependency cross-compile verification (M11-03)

All runtime lock atoms compile unmodified (no Android patches; `third_party/patches/`
unchanged). Versions are the `third_party/dependencies.lock` pins; the lockfile was not
upgraded for M11.

| Dependency | Lock version | Android build | Notes |
| --- | --- | --- | --- |
| executor | `e2362736c697` | compiled (static) | upstream Android adaptation already in the pin (`if(ANDROID)` CMake branches, bionic adjustments, NDK CI) |
| boost-asio / boost-beast 1.88.0 closure | 26 header-only modules | compiled (header-only) | consumed through the pinned include dirs; no bionic-specific changes |
| libsodium | 1.0.20 | compiled (static) | vendored CMake target; the x86 SIMD translation units self-guard on non-x86 targets and compile to empty units on aarch64 |
| blake3 | 1.8.2 | compiled (static) | portable C core only (`BLAKE3_NO_SSE2/SSE41/AVX2/AVX512/NEON`), architecture-independent |
| sqlite | 3.50.4 | compiled (static) | amalgamation generated host-side (`configure`+`make` produce the amalgamation text; the NDK compiler is only used for the target compile) |
| OpenSSL | 3.5.9 | cross-built (static, vendored) | M11-02; `no-shared no-tests no-docs`, `-D__ANDROID_API__=24`, NDK clang resolved from PATH; installed into the Android artifact set |
| libdatachannel | v0.23.2 (+5 recursive submodules: libjuice, usrsctp, plog, libsrtp, nlohmann-json) | compiled (static) | `NO_MEDIA`/`NO_WEBSOCKET` profile unchanged from the desktop baseline; OpenSSL resolved from the vendored stage |
| protobuf / abseil | v31.1 / 20250127.0 | not built | test-only toolchain (protoc + generated-code tests); Android unit-test execution is an M11-07/M11-08 deliverable |
| googletest | v1.17.0 | not built | host test group (`BUILD_TESTING=OFF` on Android for the alpha baseline) |
| FTXUI | 989917eba88b | not built | TUI-only (desktop) |
| zstd | v1.5.7 | not built | optional group, not built in v1 on any platform |

Verification evidence: clean `scripts/build_android.sh` run for both ABIs (exit 0),
installed archives checked per ABI (`libheyaki_core/profile/client/services/transport_webrtc`
+ `libssl/libcrypto`), NDK `llvm-objdump` architecture spot-checks (`aarch64` / `x86-64`),
`CMakeCache` showing `ANDROID_PLATFORM=android-24`, and the M11-01/M11-02 independent
verification report (2026-10-04).

## Platform-layer mapping (M11-04, plan item A3)

| Area | Desktop behavior | Android behavior | Disposition |
| --- | --- | --- | --- |
| Profile storage location | `XDG_STATE_HOME` / `HOME` (XDG line) or `%LOCALAPPDATA%` | app-process env has neither `XDG_STATE_HOME` nor a usable `HOME`; `default_profiles_root()`/`*_default()` factories fail explicitly with `configuration`/"home_directory_unavailable" | the JNI/host layer passes the app-scoped directory (e.g. `context.getFilesDir()`) into `ProfileStore::create/open(database_path, …)` explicitly; no env-var fallback is invented |
| File lock (`flock`) | `profile_store.cpp` advisory lock | bionic `flock` (kernel VFS, app-local storage filesystems) | same POSIX semantics; file-lock + atomic-replacement behavior is exercised by the desktop suite (79/79) and re-verified on-device in M11-07/M11-08 |
| Atomic file replacement | rename-based | same syscalls on bionic | unchanged |
| Interface enumeration | `getifaddrs`/`if_nametoindex` POSIX branch | bionic from API 24 (build floor enforces this) | unchanged code path |
| OS secret store (`dlfcn` libsecret probe) | dlopen `libsecret-1.so.0`, graceful `secret_backend_degraded` when absent | skipped at compile time (`#if defined(__linux__) && !defined(__ANDROID__)`): no dlopen attempt, identical error texts, straight to the encrypted-file backend policy | an Android Keystore/Keystore-equivalent backend is a DEC-14 decision (M11-09 conclusion), not an M11-04 change |

## LAN multicast on Android (M11-05, plan item A2)

Android requires `WifiManager.MulticastLock` (with `CHANGE_WIFI_MULTICAST_STATE`) for
multicast reception; that is an application-layer runtime concern and stays with the host
app/JNI layer. The core already treats multicast unavailability as an explicit, observable
degradation rather than a hang:

- a failed `IP_ADD_MEMBERSHIP` closes the per-interface discovery socket and records
  `multicast_join_failed` (`src/client/node.cpp`);
- if the 1.5 s readiness probe never observes a looped announcement, the node reports
  `multicast_probe_timed_out` and `LanReadinessState::degraded`;
- the relay route is independent of the LAN sockets and remains fully available while the
  LAN route is degraded/disabled;
- `NodeConfig.lan_override` lets a host that knows it cannot hold a MulticastLock disable
  the LAN route preemptively.

The desktop suite already asserts both degraded paths (`tests/unit/m3a_lan_test.cpp`,
`LanReadinessState::degraded` after join failure / probe timeout). On-device multicast
behavior is verified by the M11-07/M11-08 smoke lane, not by this document.

## Out of scope for the alpha baseline

Device/emulator execution, the JNI integration boundary (M11-06), the smoke runner (M11-07),
CI workflow (M11-08), and the DEC-14 conclusions (M11-09) are separate M11 deliverables.
