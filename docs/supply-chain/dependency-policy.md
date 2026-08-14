# Dependency And Supply-Chain Policy

## Source dependencies

`third_party/dependencies.lock` is authoritative for vendored runtime, test, and optional source
dependencies. Each record contains the upstream URL, human-readable ref, resolved commit, recursive
submodule policy, and dependency group. `scripts/fetch_third_party.sh` rejects moved refs, mismatched
origins or commits, dirty checkouts, and incomplete recursive submodules.

The supported offline checks are:

```sh
scripts/fetch_third_party.sh --check
scripts/fetch_third_party.sh --check --with-tests
scripts/fetch_third_party.sh --check --all
```

Configure verifies runtime plus every enabled group. Missing checkouts produce the exact fetch
command required to repair the build.

## System and deployed dependencies

Boost, the TLS backend, and coturn are not linked by the M0 empty targets. Their reproducible release
strategy is fixed now, while exact package artifacts freeze before first use:

| Component | Strategy | Current M0 evidence | Freeze gate |
| --- | --- | --- | --- |
| Boost | Pin an exact version and package-manager baseline in the M2 toolchain; reject a different discovered version in release presets. | Not required by M0 targets. | M2 entry |
| TLS backend | Use one OpenSSL line for Boost.Beast and libdatachannel on Linux/Windows; record exact headers/runtime versions and package digest in release provenance. | Local probe: OpenSSL 3.5.7; not a release pin. | M3 entry |
| coturn | Run an external image/package referenced by immutable version and digest; keep its config and image provenance in the deployment tree. | Not deployed in M0. | M3 entry |

This table deliberately does not claim the developer machine's packages are reproducible. A
milestone cannot consume one of these components until its exact artifact or package baseline has
been committed.

## License inventory and SBOM

`third_party/licenses.lock` maps every pinned dependency to an SPDX expression and upstream license
file. The `heyaki-sbom` target cross-checks both locks and emits an SPDX 2.3 tag-value document plus
a Markdown license manifest. Configure fails generation if a pin has no license record.

The M0 inventory covers direct pins. M3/M4 release packaging must additionally inventory transitive
submodules, system libraries, the coturn artifact, and the actual static/dynamic linkage closure.

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

