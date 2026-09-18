# Getting Started

This guide builds Heyaki from source, installs it, runs a relay, and brings up
a first device with the TUI. For configuration details see
[configuration.md](configuration.md); for production topologies see
[deployment.md](deployment.md).

## Prerequisites

| Requirement | Notes |
| --- | --- |
| OS | Linux (Ubuntu 20.04 or newer — on 20.04 follow the [compatibility notes](client-library.md#ubuntu-2004)) or Windows 10/11 with Visual Studio 2022 |
| C++ compiler | GCC 13+, Clang 17+ (with libstdc++ 13+), or MSVC 19.38+ — C++20 |
| CMake | 3.25 or newer |
| OpenSSL | 3.x (>= 3.0, < 4.0) with development headers |
| Git | for the pinned dependency checkout |
| Optional, Linux | `libnice >= 0.1.21` + `glib` + `pkg-config` when building with `HEYAKI_ICE_BACKEND=nice` (TURN/TCP client; see [cross-os-matrix.md](operations/cross-os-matrix.md)) |

Pinned dependencies (executor, libdatachannel, boost, libsodium, blake3,
sqlite, FTXUI, and test-only protobuf/abseil/googletest) are fetched from
`third_party/*.lock` — no system packages needed for them.

## Build from source

```sh
git clone <repository> heyaki && cd heyaki
scripts/fetch_third_party.sh --all     # synchronizes pinned dependencies
cmake --preset release                 # configure (Debug: --preset debug)
cmake --build --preset release --parallel
```

The first configure compiles the vendored dependencies, so expect several
minutes. Build outputs land in `build/release/`. With the default
`HEYAKI_AUTO_INSTALL=ON`, every successful build also installs into
`build/release/install/` via the `heyaki-deploy` target, so the binaries are
immediately runnable from one place.

Useful configure options (all are CMake cache variables):

| Option | Default | Meaning |
| --- | --- | --- |
| `HEYAKI_BUILD_APPS` | `ON` | Build `heyaki-relay`, `heyaki-tui`, demos, helpers |
| `HEYAKI_ICE_BACKEND` | `juice` | `juice` = vendored libjuice (TURN/UDP); `nice` = system libnice (TURN/UDP+TCP, Linux only) |
| `HEYAKI_HARDENING` | `ON` | PIE, full RELRO, NX stack, stack protector, FORTIFY, CET/CF |
| `HEYAKI_SANITIZER` | `none` | `address` / `undefined` / `thread` (presets `asan`/`ubsan`/`tsan`) |
| `HEYAKI_BUILD_FUZZERS` | `OFF` | libFuzzer protocol targets (Clang only) |
| `HEYAKI_WARNINGS_AS_ERRORS` | `OFF` | Treat warnings as errors (CI turns this on) |
| `HEYAKI_AUTO_INSTALL` | `ON` | Auto-install into `HEYAKI_INSTALL_PREFIX` after each build |

## Install into a prefix

```sh
cmake --install build/release --prefix /opt/heyaki
```

The install tree contains the client libraries and CMake package
(`lib/`, `include/`), the executables (`bin/`), and shared data (proto files,
SBOM, third-party license notices). See [deployment.md](deployment.md#packaged-artifacts)
for the packaged release layout.

### Consume the installed package

```cmake
cmake_minimum_required(VERSION 3.25)
project(heyaki_consumer LANGUAGES CXX)

find_package(heyaki CONFIG REQUIRED)

add_executable(heyaki_consumer main.cpp)
target_compile_features(heyaki_consumer PRIVATE cxx_std_20)
target_link_libraries(heyaki_consumer PRIVATE
  heyaki::core
  heyaki::profile
  heyaki::client
  heyaki::services
  heyaki::transport_webrtc)
```

```sh
cmake -S . -B build -DCMAKE_PREFIX_PATH=/opt/heyaki
cmake --build build
```

This snippet mirrors `tests/consumer/`, which CI compiles and runs as
`heyaki_installed_consumer` — if the packaging breaks, the build breaks.

## Run a relay

The relay is a single process with a TLS control listener. Minimal setup:

```sh
mkdir -p /opt/heyaki-relay/certs
cd /opt/heyaki-relay
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout certs/relay.key -out certs/relay.crt \
  -subj "/CN=heyaki-relay.local" -addext "subjectAltName=DNS:heyaki-relay.local"
```

Create `relay.conf` (all keys are documented in
[configuration.md](configuration.md); this minimal form is validated by the
same sync test):

```heyaki-relay-config getting-started-minimal
listen_address = 0.0.0.0
listen_port = 8443
tls_certificate_file = certs/relay.crt
tls_private_key_file = certs/relay.key
database_file = relay.sqlite
```

Start and verify:

```sh
/opt/heyaki/bin/heyaki-relay --config relay.conf --check-config   # validate only
/opt/heyaki/bin/heyaki-relay --config relay.conf                  # run
curl --cacert certs/relay.crt https://localhost:8443/health       # readiness
```

`--help` prints the full CLI. Devices trust the relay through the CA that
signed the leaf certificate; production deployments pin the leaf (see
[deployment.md](deployment.md#relay-host)).

## Bring up a first device (TUI)

`heyaki-tui` is the first-party device application:

```sh
/opt/heyaki/bin/heyaki-tui            # interactive local setup on first run
/opt/heyaki/bin/heyaki-tui --status   # non-interactive status dump
```

First run walks through local initialization (device identity + profile store
under the platform state directory — `$XDG_STATE_HOME/heyaki/profiles` or
`~/.local/state/heyaki/profiles` on Linux, `%LOCALAPPDATA%\Heyaki\profiles`
on Windows), then optionally enrollment against a relay (bootstrap token + CA
file from the relay operator). After setup, the TUI shows LAN discovery,
sessions, messages, RPC, events, transfers, and shell views; each view lists
its commands via in-app help. Two TUI devices on the same LAN find each other
without any relay.

The profile store is shared: any application running as the same OS user can
reuse the TUI-initialized profile (`ProfileStore::open_default()`), which is
the intended "initialize once, many apps" flow (see
[api.md](api.md#profile-store)).

## Demos and helpers

| Binary | Purpose |
| --- | --- |
| `heyaki-m2-profile-demo` | Profile store create/open + endpoint derivation |
| `heyaki-m3b-relay-demo` | Full device lifecycle against a relay (enroll, login, publish) |
| `heyaki-m6-message-rpc-demo` | Message + unary RPC semantics between two devices |
| `heyaki-m7-data-demo` | Event fan-out, file push/pull, resume semantics |
| `heyaki-m4-matrix-node` | Test-harness node driving all network-matrix scenarios |
| `heyaki-test-turn-server` | Embedded TURN/UDP server for tests and local experiments |
| `heyaki-release-sign` | Release manifest signing (see [operations/release-signing.md](operations/release-signing.md)) |

## Where to go next

- [configuration.md](configuration.md) — every relay key and device-side knob
- [api.md](api.md) — client library reference
- [deployment.md](deployment.md) — production relay + coturn + observability
- [troubleshooting.md](troubleshooting.md) — symptom-first diagnosis
- [operations/runbook.md](operations/runbook.md) — operator procedures
