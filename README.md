# Heyaki

Heyaki is a C++20 device-to-device communication infrastructure project. The repository is
currently at the M0 engineering baseline: targets, installation, dependency verification, test
entry points, and build metadata exist; networking and service behavior are not implemented yet.

## Build

Fetch and verify the pinned source dependencies, then use a preset:

```sh
scripts/fetch_third_party.sh --with-tests
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

`asan`, `ubsan`, and `tsan` presets provide the sanitizer entry points. The build fails with an
actionable dependency command when a selected runtime, test, or optional checkout is absent or no
longer matches its locked commit.

Generated protocol files, test profiles and credentials, and fuzz corpora are constrained to the
build tree. `cmake --build build/debug --target heyaki-sbom` regenerates the SPDX inventory and
license manifest from the lock files.

