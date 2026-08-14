# M0 Linkage And License Audit

Date: 2026-08-14

## Scope

This audit covers the M0 build and install targets, all records in
`third_party/dependencies.lock`, and the recursive records in
`third_party/transitive-dependencies.lock`. It is a current-package audit, not approval for future
targets to begin linking dependencies without another review.

## Installed closure

The M0 install contains Heyaki headers, five Heyaki static archives, `heyaki-relay`, `heyaki-tui`,
CMake package metadata, the SPDX document, and the license manifest. The production CMake target
graph links only Heyaki targets to each other. No pinned dependency archive, shared library, header,
or source file is installed. Googletest is linked only by the non-installed unit-test executable.

On the audited Linux GCC 13.3 build, `ldd` reports only the platform C/C++ runtime, math library,
loader, and GCC support library for both installed executables. These platform libraries are not
redistributed by the Heyaki install. Windows system-library closure is covered by the MSVC installed
consumer CI job and must be captured from the final packaged binaries at M9.

## Pinned source inventory

| Dependency set | Count | M0 disposition |
| --- | --- | --- |
| Direct runtime/test/optional pins | 9 | Recorded in SPDX and license manifest; not installed or linked by production targets |
| libdatachannel recursive submodules | 5 | Recorded with parent relationships and exact commits |
| System/deployed dependencies | 0 linked | Boost, release OpenSSL, libnice and coturn freeze before first use |

The minimal libdatachannel compatibility build uses OpenSSL, libjuice, usrsctp, plog, and the
platform thread/socket libraries. `nlohmann-json` is not used because examples are disabled;
`libsrtp` is not used because media is disabled. The compatibility build is a CI probe and is not
installed as part of M0.

## License disposition

The current Heyaki package contains no third-party code, so it has no third-party binary
redistribution obligation beyond retaining the generated inventory. The pinned inventory contains
permissive licenses, SQLite's blessing, and MPL-2.0 for libdatachannel/libjuice. Before distributing
an artifact that contains MPL-covered files, the packaging review must preserve notices and satisfy
MPL source-availability requirements for covered files. Optional BLAKE3 and zstd use must record the
selected license branch and actual linked files when enabled.

## Re-audit gates

- M2 entry: freeze and inventory the Boost artifact before first linkage.
- M3 entry: resolve the libjuice/libnice decision and freeze Linux/Windows OpenSSL plus coturn.
- M4 exit: record actual libdatachannel, ICE, TLS and coturn static/dynamic closure and notices.
- Every dependency upgrade: regenerate inventory and review license/security changes.
- M9 release: scan the packaged binaries and installation tree, then archive final SPDX, notices,
  artifact digests and linkage reports with the release provenance.
