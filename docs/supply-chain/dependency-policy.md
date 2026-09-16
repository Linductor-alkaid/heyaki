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
| ICE backend (libnice) | System libnice/GLib pair for `HEYAKI_ICE_BACKEND=nice` builds (M9-19, Linux only): version floor 0.1.21 = the ubuntu-24.04 distro line, probed through the pinned libdatachannel's own find modules. libnice is LGPL-2.1 OR MPL-1.1 and drags GLib (LGPL-2.1+) — copyleft, so it may only ever enter as a **dynamically linked shared library**, never vendored or statically linked, and only in explicitly selected nice-backend builds. Default artifacts keep the vendored libjuice backend and stay inside the permissive closure. | Floor frozen at M9-19 (2026-09-16); CI `coturn-topology` job builds nice against Ubuntu 24.04 `libnice-dev` and runs the full NAT/fault/soak/bench surface on it. | Nice-backend builds must record the exact distro package versions in release provenance; M9-17 packaging must ship the libnice/GLib license texts alongside nice-backend artifacts and keep relinkability (LGPL §4). |

This table deliberately does not claim the developer machine's packages are reproducible. A
milestone cannot consume one of these components until its exact artifact or package baseline has
been committed.

## License inventory and SBOM

`third_party/licenses.lock` maps every direct and transitive pinned dependency to an SPDX expression
and upstream license file. The `heyaki-sbom` target cross-checks all three locks, verifies every
license file exists, and emits an SPDX 2.3 tag-value document plus a Markdown license manifest.
Generation fails for a missing, duplicate, extra, or malformed package/license record. CTest also
checks all expected packages and parent/submodule relationships.

Since M9-14 generation additionally enforces the **license policy**: dependencies linked into
shipped artifacts (lock groups `runtime` and `test`, plus the recursive submodules) must not carry
any copyleft atom (AGPL/GPL/LGPL/SSPL); the `optional` group tolerates a copyleft atom only behind
a permissive OR branch (zstd: `BSD-3-Clause OR GPL-2.0-only`, not built in v1). The SBOM also
describes the heyaki package itself with the exact project version and build commit; see
[m9-release-audit.md](m9-release-audit.md). The gate scopes itself to lock-file atoms; the M9-19
libnice/GLib system pair is the one copyleft surface and is governed by the system-dependency row
above (dynamic linkage, nice-backend builds only) instead.

The inventory covers 35 direct pins and the 5 recursive libdatachannel submodules. M7
promoted the pinned BLAKE3 checkout (1.8.2, previously a locked-but-unbuilt runtime pin) to
a built vendored target `heyaki_blake3` compiled from its portable C core only
(`BLAKE3_NO_SSE2/SSE41/AVX2/AVX512/NEON`): no per-file architecture flags, no assembly
sources, and deterministic behavior under every sanitizer preset. The SIMD dispatch remains
available for a future throughput-driven revision. The Boost.Beast WSS closure was added and frozen at M3B entry as Beast 1.88.0 plus its reviewed Asio/System/Config/Assert/ThrowException/Predef/WinAPI/Bind/ContainerHash/Core/Describe/Endian/Intrusive/IO/Move/Mp11/Optional/Preprocessor/SmartPtr/StaticAssert/StaticString/TypeIndex/TypeTraits/Utility module closure. Abseil is pinned
as the build/runtime dependency required by the pinned Protobuf 31.1 Lite toolchain. The
[M0 linkage and license audit](m0-linkage-license-audit.md) is the point-in-time record from before
the first pins were linked; since M1/M2, built artifacts link and redistribute the pinned runtime
dependencies and ship the generated license manifest (`THIRD_PARTY_LICENSES.md` in the build tree).
M3A/M3B/M4 additionally inventory Boost, OpenSSL, coturn and the selected ICE backend artifacts;
M9 repeats the audit against the final release package.

## Vulnerability and secret scanning (M9-14)

Two recurring release gates, both enforced as CTests in the CI `supply-chain`
job:

- `scripts/osv_vulnerability_scan.py` (`heyaki_m9_vulnerability_scan`,
  gate `HEYAKI_REQUIRE_VULN_SCAN=1`): queries OSV.dev for every pinned
  commit (35 direct + 5 recursive) after proving detection on a
  known-vulnerable control commit; acknowledgements live in
  `deploy/security/osv-triage.tsv`, anything untriaged fails.
- `scripts/run_secret_scan.sh` (`heyaki_m9_secret_scan`, gate
  `HEYAKI_REQUIRE_SECRET_SCAN=1`): gitleaks 8.24.3, digest-pinned in
  `deploy/security/secret-scan.lock`, over the full git history with the
  reviewed allowlist in `deploy/security/gitleaks.toml`; a planted
  credential must be detected before an all-clear is reported.

Results, limitations, and the coturn deployment-artifact audit are recorded
in [m9-release-audit.md](m9-release-audit.md).

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
