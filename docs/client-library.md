# Using the Heyaki Client Library

How to reference and use Heyaki from your own application on Linux and
Windows. The SDK is the release archive of the install tree: static
libraries, public headers, and ready-made CMake packages. A companion
walk-through of the API itself is [api.md](api.md); this page is about
getting it to link and run on both platforms.

## What is in the SDK

| Path | Content |
| --- | --- |
| `lib/` | Static libraries: `heyaki_core`, `heyaki_profile`, `heyaki_client`, `heyaki_services`, `heyaki_transport_webrtc`, plus every pinned dependency statically linked in (`libdatachannel`, `libjuice`, `usrsctp`, `libexecutor`, libsodium, BLAKE3, SQLite amalgamation) |
| `include/` | Public headers: `heyaki/`, `executor/`, `rtc/` |
| `lib/cmake/` | CMake packages: `heyaki`, `executor`, `LibDataChannel` |
| `bin/` | The applications (`heyaki-relay`, `heyaki-tui`, demos, helpers) — Windows SDKs also carry `datachannel.dll` and the OpenSSL runtime DLLs here |
| `share/heyaki/` | Proto schemas, coturn example configuration, license texts, SPDX SBOM |

Release asset names:

- `heyaki-<version>-linux-x86_64-sdk.tar.gz`
- `heyaki-<version>-windows-x64-sdk.zip`

The archives are built by CI from the release tag (see
[.github/workflows/release-sdk.yml](../.github/workflows/release-sdk.yml)).

## Prerequisites

| | Linux | Windows |
| --- | --- | --- |
| Distribution / baseline | Ubuntu 20.04 or newer — the SDK is built on the 20.04 baseline (glibc ≥ 2.31, libstdc++ ≥ 3.4.28), so it runs on 20.04 and every newer distribution | Windows 10/11, x64 |
| Toolchain | GCC 11+ (C++20; the pinned `executor` dependency uses `std::atomic` wait/notify, which libstdc++ implements from 11.1 — Ubuntu 20.04: `g++-11` from the `ubuntu-toolchain-r/test` PPA, which also brings the matching runtime) — GCC 13 / Clang 17 recommended | Visual Studio 2022 (MSVC 19.38+), x64 |
| CMake | ≥ 3.25 | ≥ 3.25 |
| OpenSSL | 3.x development package (`libssl-dev`; ≥ 3.0, < 4.0) — or use the copy bundled in the SDK (see [Ubuntu 20.04](#ubuntu-2004)) | OpenSSL 3.x — headers + import libraries for compiling (e.g. from [slproweb](https://slproweb.com/products/Win32OpenSSL.html) installed to the default location, or set `OPENSSL_ROOT_DIR`); the runtime DLLs ship inside the SDK `bin/` |
| Runtime | `libssl.so.3` / `libcrypto.so.3` — system package, or the SDK's bundled copy | MSVC redistributable (matching VS 2022); `datachannel.dll` and OpenSSL DLLs are in the SDK `bin/` |

Everything else — executor, libdatachannel, boost.Beast/Asio headers,
libsodium, BLAKE3, SQLite, usrsctp, libjuice — is statically inside the SDK
and needs nothing on the consumer machine.

The SDKs are built with the default `juice` ICE backend (TURN/UDP). If you
need the TURN/TCP client, build Heyaki from source with
`-DHEYAKI_ICE_BACKEND=nice` (Linux only; see
[cross-os-matrix.md](operations/cross-os-matrix.md)).

## Consume with CMake

Extract the archive anywhere, e.g. `C:\heyaki-sdk` or `~/heyaki-sdk`, and
point your project at it. `CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.25)
project(my_device_app LANGUAGES CXX)

find_package(heyaki CONFIG REQUIRED)

add_executable(my_device_app main.cpp)
target_compile_features(my_device_app PRIVATE cxx_std_20)
target_link_libraries(my_device_app PRIVATE heyaki::client heyaki::services)
```

Configure with the SDK on the prefix path (the package pulls in `executor`,
`LibDataChannel`, `OpenSSL`, and `Threads` transitively):

```sh
# Linux
cmake -S . -B build -DCMAKE_PREFIX_PATH=$HOME/heyaki-sdk -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

```powershell
# Windows (VS 2022 generator)
cmake -S . -B build -A x64 "-DCMAKE_PREFIX_PATH=C:\heyaki-sdk" -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL"
cmake --build build --config Release
```

If OpenSSL is in the default location on Windows, `OPENSSL_ROOT_DIR` can be
omitted. Do not pass the SDK's `lib/` directory as `CMAKE_PREFIX_PATH` —
point at the archive root, where `lib/cmake/` lives.

## Ubuntu 20.04

The SDK archives are built inside an `ubuntu:20.04` container (GCC 11,
pinned CMake, source-built OpenSSL 3.0.x — see
[.github/actions/ubuntu-2004-toolchain](../.github/actions/ubuntu-2004-toolchain/action.yml)),
and a CI job builds and runs the full test suite on that baseline, so the
archives run on 20.04 and newer. What that means for you on a 20.04 machine:

- **Compiler**: install `g++-11` or newer —
  `sudo add-apt-repository ppa:ubuntu-toolchain-r/test && sudo apt install g++-11`.
  GCC 10 is not enough (the pinned `executor` dependency uses
  `std::atomic` wait/notify, a libstdc++ 11 feature), and the PPA install
  also updates the system `libstdc++` runtime your compiled apps need.
- **Ready-to-run binaries**: the executables inside the SDK (`bin/`) link
  libstdc++/libgcc statically, so `heyaki-relay`, `heyaki-tui`, and the
  demos run on a bare 20.04 as extracted.
- **CMake**: the distro package is 3.16 — install ≥ 3.25 (Kitware's official
  tarball or `pip install cmake`).
- **OpenSSL 3**: focal ships the 1.1 line, and Heyaki freezes the 3.x ABI
  line. The SDK bundles OpenSSL 3 headers and runtime libraries, so point
  your configure at the SDK instead of installing one system-wide:

```sh
cmake -S . -B build   -DCMAKE_PREFIX_PATH=$HOME/heyaki-sdk   -DOPENSSL_ROOT_DIR=$HOME/heyaki-sdk   -DCMAKE_BUILD_TYPE=Release
cmake --build build
LD_LIBRARY_PATH=$HOME/heyaki-sdk/lib ./build/my_device_app
```

  `OPENSSL_ROOT_DIR` makes `find_package(OpenSSL)` (pulled transitively by
  the heyaki package) resolve the bundled copy; at runtime the loader needs
  the SDK `lib/` on its path (`LD_LIBRARY_PATH` as above, or bake an rpath
  with `-DCMAKE_INSTALL_RPATH=$HOME/heyaki-sdk/lib`). On distributions with
  a system OpenSSL 3 (22.04+) none of this is needed.

Building Heyaki **from source** on 20.04 uses the same recipe the CI job
runs: `g++-11` (toolchain PPA), CMake ≥ 3.25, OpenSSL 3 from source, then
the normal [build steps](#building-the-sdk-from-source-instead).

## Your first program

The minimal lifecycle: open (or create) a profile store, run local
initialization once, start a `Node`, do work, shut down. This exact program
is compiled and executed by the docs sync test (`heyaki_m9_docs_examples`),
so it always matches the shipped API:

```heyaki-cpp sdk-first-program
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <filesystem>
#include <iostream>

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: my_device_app <state-directory>\n";
    return 2;
  }
  const auto database = std::filesystem::path{argv[1]} / "profile.sqlite";
  auto opened = heyaki::ProfileStore::open(database);
  if (!opened) {
    opened = heyaki::ProfileStore::create(database);
  }
  if (!opened) {
    std::cerr << "profile store unavailable\n";
    return 1;
  }
  auto* profile = opened.value_if();

  // First run only: local initialization (what the TUI walks you through).
  auto readiness = profile->local_readiness("com.example.my_device_app");
  if (readiness && !readiness.value_if()->ready()) {
    auto verifier = heyaki::create_password_verifier(
        "device password", heyaki::PasswordHashParameters{},
        heyaki::PasswordSecurityPolicy{});
    if (!verifier) {
      std::cerr << "password verifier rejected\n";
      return 1;
    }
    heyaki::LocalProfileInitialization initialization;
    initialization.application_id = "com.example.my_device_app";
    initialization.password_verifier = std::move(*verifier.value_if());
    auto initialized = profile->initialize_local(initialization);
    if (!initialized) {
      std::cerr << "local initialization failed\n";
      return 1;
    }
  }

  heyaki::NodeConfig config;
  config.profile = profile;
  config.application_id = "com.example.my_device_app";
  auto node = heyaki::Node::create(std::move(config));
  if (!node) {
    std::cerr << "node create failed\n";
    return 1;
  }

  std::cout << "device="
            << heyaki::to_string(node.value_if()->snapshot().device_id)
            << " lan_endpoints=" << node.value_if()->endpoints().size()
            << '\n';
  const auto report = node.value_if()->shutdown();
  return report.stopped ? 0 : 1;
}
```

From here the API surface is [api.md](api.md): discovery and sessions
(`connect`, `peer_sessions`), the five services (`send_message`, `call_rpc`,
`publish_event`/`subscribe_events`, `push_file`/`pull_file`, `open_shell`),
metrics, and pairing. Worked two-device demos ship in the SDK `bin/`
(`heyaki-m6-message-rpc-demo`, `heyaki-m7-data-demo`) and their sources are
in `apps/demo/`.

## Runtime deployment

- **Linux**: your executable dynamically needs `libssl.so.3` and
  `libcrypto.so.3` only (plus glibc/libstdc++ for your toolchain).
- **Windows**: copy the SDK's `bin/` next to your `.exe` (or add it to
  `PATH`) — it carries `datachannel.dll`, `libssl-3-x64.dll`, and
  `libcrypto-3-x64.dll`. Install the VS 2022 redistributable on target
  machines if no Visual Studio is present.
- The state directory you pass must be per-user and permission-tight: the
  profile store refuses group/other-accessible directories.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `find_package(heyaki)` reports the package but configure fails on `executor` or `LibDataChannel` | `CMAKE_PREFIX_PATH` points inside `lib/` — point it at the SDK root (the packages live under `lib/cmake/` of that root) |
| Could not find OpenSSL / wrong version | Linux: install `libssl-dev` from the same 3.x line, or on Ubuntu 20.04 pass `-DOPENSSL_ROOT_DIR=<sdk>` to use the bundled copy. Windows: set `-DOPENSSL_ROOT_DIR` to your OpenSSL 3.x prefix; a 4.x install is rejected by the freeze |
| Binary fails on an older distribution with `GLIBC_x.y` / `GLIBCXX_x.y` not found | The binary was not built from the SDK (whose baseline is glibc 2.31 / GLIBCXX 3.4.28) — link against the SDK libraries instead of a locally built copy, or rebuild on the target distribution |
| App exits at startup with `profile_*` error | The state directory (or a parent) is group/other accessible — `chmod 700` it |
| Windows: `datachannel-*.dll` or `libssl-3-x64.dll` not found at launch | The SDK `bin/` is not next to the exe / on `PATH` |
| Link errors about missing `rtc::*` symbols | You linked `heyaki::client` from a hand-rolled copy — use `find_package(heyaki)` targets so `heyaki::transport_webrtc` and its pinned `LibDataChannel` come in transitively |
| MSVC complains `heyaki::NodeConfig` initializers are missing fields | Aggregate designated initializers skipping members trip `/w44246`-style diagnostics — default-construct then assign members (the samples above do this) |

## Building the SDK from source instead

```sh
scripts/fetch_third_party.sh --all
cmake --preset release && cmake --build --preset release   # auto-installs to build/release/install
cmake --install build/release --prefix /your/sdk/prefix
```

The release workflow does exactly this on both platforms
([.github/workflows/release-sdk.yml](../.github/workflows/release-sdk.yml)).
