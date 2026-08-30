# Dependency And Supply-Chain Policy

## Source dependencies

`third_party/dependencies.lock` is authoritative for vendored runtime, test, and optional source
dependencies. Each record contains the upstream URL, human-readable ref, resolved commit, recursive
submodule policy, and dependency group. `third_party/transitive-dependencies.lock` records the exact
recursive submodules selected by those pins for SBOM and license accounting. The parent Git tree is
the checkout authority; the transitive lock makes that otherwise nested inventory reviewable.
`scripts/fetch_third_party.sh` rejects moved refs, mismatched origins or commits, dirty checkouts, and
incomplete recursive submodules.

The supported offline checks are:

```sh
scripts/fetch_third_party.sh --check
scripts/fetch_third_party.sh --check --with-tests
scripts/fetch_third_party.sh --check --all
```

Configure verifies runtime plus every enabled group. Missing checkouts produce the exact fetch
command required to repair the build.

## System and deployed dependencies

Boost, the TLS backend, and coturn follow the reproducible release strategy below. They were not
linked by the M0 empty targets; since then Boost/Beast and OpenSSL are linked by the shipped
milestones (M3A/M3B onward) and coturn runs as an external, digest-pinned deployment artifact:

| Component | Strategy | Evidence (updated through M4) | Freeze gate |
| --- | --- | --- | --- |
| Boost | Pin the exact modular Asio/System header closure used by M2; freeze Asio SSL integration before M3A and add Beast plus its reviewed closure before M3B WSS work. | Boost 1.88.0 Asio/System/Config/Assert/ThrowException/Predef/WinAPI commits are source-locked; Beast 1.88.0 and the 18 additional reviewed module commits were frozen at M3B entry. | Asio complete for M2; SSL at M3A entry; Beast frozen at M3B entry |
| TLS backend | Use the OpenSSL 3.x ABI line for Asio LAN TLS, Boost.Beast, and libdatachannel on Linux/Windows; CMake rejects other major lines, while release provenance records the exact headers/runtime package version and digest. | M3A development baseline links OpenSSL 3.0.13 on Linux; the host CLI may differ and is not treated as link evidence. | OpenSSL 3.x line frozen at M3A entry; exact package artifacts remain a release-provenance gate |
| coturn | Run an external image/package referenced by immutable version and digest; keep its config and image provenance in the deployment tree. | Pinned deployment baseline since M3B (`deploy/coturn`: image `coturn/coturn:4.10.0-debian` by digest, Ubuntu 24.04 `coturn=4.6.1-1build4` fallback); exercised by the M4 CI network matrix topologies. | M3B entry |

This table deliberately does not claim the developer machine's packages are reproducible. A
milestone cannot consume one of these components until its exact artifact or package baseline has
been committed.

## License inventory and SBOM

`third_party/licenses.lock` maps every direct and transitive pinned dependency to an SPDX expression
and upstream license file. The `heyaki-sbom` target cross-checks all three locks, verifies every
license file exists, and emits an SPDX 2.3 tag-value document plus a Markdown license manifest.
Generation fails for a missing, duplicate, extra, or malformed package/license record. CTest also
checks all expected packages and parent/submodule relationships.

The inventory covers 35 direct pins and the 5 recursive libdatachannel submodules. The Boost.Beast WSS closure was added and frozen at M3B entry as Beast 1.88.0 plus its reviewed Asio/System/Config/Assert/ThrowException/Predef/WinAPI/Bind/ContainerHash/Core/Describe/Endian/Intrusive/IO/Move/Mp11/Optional/Preprocessor/SmartPtr/StaticAssert/StaticString/TypeIndex/TypeTraits/Utility module closure. Abseil is pinned
as the build/runtime dependency required by the pinned Protobuf 31.1 Lite toolchain. The
[M0 linkage and license audit](m0-linkage-license-audit.md) is the point-in-time record from before
the first pins were linked; since M1/M2, built artifacts link and redistribute the pinned runtime
dependencies and ship the generated license manifest (`THIRD_PARTY_LICENSES.md` in the build tree).
M3A/M3B/M4 additionally inventory Boost, OpenSSL, coturn and the selected ICE backend artifacts;
M9 repeats the audit against the final release package.

## Upgrade workflow

Dependency upgrades are isolated changes:

1. Update the upstream ref and resolved commit together; update recursive submodule state where used.
2. Fetch from the ref and prove it still resolves to the recorded commit.
3. Review upstream release notes, security notices, ABI/build changes, and license changes.
4. Update `licenses.lock`, the compatibility matrix, SBOM, and release provenance.
5. Run Linux GCC/Clang and Windows MSVC builds, all sanitizer jobs, protocol/security tests, and the
   deterministic direct/TURN network suite once those suites exist.
6. Record user-visible and wire-compatibility differences in the upgrade change.

Moved tags are never accepted by simply replacing the commit without review.
