# Quick Start

## Consume the SDK

`CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.25)
project(my_device_app LANGUAGES CXX)

find_package(heyaki CONFIG REQUIRED)

add_executable(my_device_app main.cpp)
target_compile_features(my_device_app PRIVATE cxx_std_20)
target_link_libraries(my_device_app PRIVATE heyaki::client heyaki::services)
```

Configure with the SDK archive root on the prefix path (the root that
contains `lib/cmake/`, never the `lib/` directory itself):

```sh
cmake -S . -B build -DCMAKE_PREFIX_PATH=$HOME/heyaki-sdk -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Toolchain floor: GCC 11+ or VS 2022, CMake ≥ 3.25, OpenSSL 3.x (< 4.0).
Everything else (executor, libdatachannel, libsodium, BLAKE3, SQLite,
usrsctp, libjuice) is statically inside the SDK. Ubuntu 20.04 and Windows
details (bundled OpenSSL, `OPENSSL_ROOT_DIR`, DLL layout):
[client-library.md](../../../client-library.md).

## Minimal Runnable Program

The lifecycle is: open (or create) a per-user profile store, run local
initialization once, create a `Node`, do work, call `shutdown()`:

```cpp
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
  if (!opened) return 1;
  auto* profile = opened.value_if();

  // First run only — what the TUI walks a user through.
  auto readiness = profile->local_readiness("com.example.my_device_app");
  if (readiness && !readiness.value_if()->ready()) {
    auto verifier = heyaki::create_password_verifier(
        "device password", heyaki::PasswordHashParameters{},
        heyaki::PasswordSecurityPolicy{});
    if (!verifier) return 1;
    heyaki::LocalProfileInitialization initialization;
    initialization.application_id = "com.example.my_device_app";
    initialization.password_verifier = std::move(*verifier.value_if());
    if (!profile->initialize_local(initialization)) return 1;
  }

  heyaki::NodeConfig config;   // every field has a default
  config.profile = profile;
  config.application_id = "com.example.my_device_app";
  auto node = heyaki::Node::create(std::move(config));
  if (!node) return 1;

  std::cout << "device="
            << heyaki::to_string(node.value_if()->snapshot().device_id)
            << '\n';
  return node.value_if()->shutdown().stopped ? 0 : 1;
}
```

This mirrors the sync-tested sample in
[client-library.md](../../../client-library.md) — prefer that one when in doubt.
`ProfileStore::create_default(name)` / `open_default(name)` are the
per-OS-user variants under the platform state directory.

## First Boundary

`Node::create` returns after admission; the node's identity, LAN presence,
and relay registration come up asynchronously on the pinned `executor`
runtime. Application code never creates threads. `Node` callbacks fire on
executor contexts — keep handlers cheap and hand off through
`executor::comm` components when crossing into application code.
`shutdown()` is the only teardown path and returns a `NodeShutdownReport`.

The state directory must be per-user and permission-tight (0700): the
profile store refuses group/other-accessible directories.

## Next

To reach another device read
[sessions and discovery](sessions-and-discovery.md). For the shared
Result/error and concurrency model read
[node lifecycle](node-lifecycle.md). Otherwise return to the entry router.
