# M9 Release Supply-Chain Audit

Deliverable record for M9-14 (2026-09-15): secret scan, dependency
vulnerability scan, SBOM, license policy, compile hardening, and release
artifact signing. Every control here is enforced by a CTest that runs in CI
(the `supply-chain` job), not only by this document.

## Summary

| Control | Mechanism | Enforcement | Result |
| --- | --- | --- | --- |
| Secret scan | gitleaks 8.24.3, digest-pinned, full git history | `heyaki_m9_secret_scan` (`HEYAKI_REQUIRE_SECRET_SCAN`) | 31 raw findings → 0 after remediation/reviewed allowlist |
| Dependency vulnerability scan | OSV.dev commit queries over all 40 pins with self-test | `heyaki_m9_vulnerability_scan` (`HEYAKI_REQUIRE_VULN_SCAN`) | 0 advisories on pinned commits; coturn deployment artifact audited separately (below) |
| SBOM | SPDX 2.3, heyaki package + version/build-commit identity | `heyaki-sbom` target + `heyaki_supply_chain_inventory` | generated on every build; license manifest installed with the tree |
| License policy | copyleft atoms rejected for linked groups at generation time | SBOM generation fails closed | all linked dependencies permissive; only optional zstd keeps a GPL alternative behind a permissive OR |
| Compile hardening | PIE/full RELRO/NX/stack protector/FORTIFY/CET (+MSVC /GS /guard:cf /GUARD:CF /CETCOMPAT) | `HEYAKI_HARDENING` option + `heyaki_m9_hardening_check` | asserted on shipped Linux executables; FORTIFY asserted in Release |
| Release signing | Ed25519 detached signatures over deterministic SHA-256 manifests (`heyaki-release-sign`) | `heyaki_m9_release_signing` roundtrip incl. all tamper directions | procedure: [docs/operations/release-signing.md](../operations/release-signing.md) |

## Secret scan

Tooling: `deploy/security/secret-scan.lock` pins the gitleaks 8.24.3
linux-x64 tarball by the upstream release checksum
(`9991e0b2…4ee29c`); `scripts/run_secret_scan.sh` verifies the digest,
proves the rule set fires on a planted credential, then scans the full git
history with `deploy/security/gitleaks.toml` (default rules extended).

First full-history baseline (2026-09-15): 31 findings.

- 30 findings inside `.mimosa/hook-state/…` — session-tool snapshots that
  were **accidentally committed** in 48d7ef40/386f82a (2026-08-25) and have
  been untracked again in this round (`git rm -r --cached .mimosa` +
  `/.mimosa/` in `.gitignore`). The flagged strings are source-code
  identifiers and tool-generated hashes of the snapshot tool itself
  (sqlite3 API names, `key=` values of the tool), not Heyaki credentials.
  History rewrite is against repository policy, so the historical paths stay
  allowlisted with that rationale until the history ages out; the paths are
  ignored and cannot re-enter the tree.
- 1 finding in `src/profile/password.cpp` — the `Error{code, "password",
  detail}` construction trips the generic-api-key heuristic on the facility
  string `password`. The token after the facility is a stable snake_case
  error id from a closed set; the allowlist entry enumerates those exact
  strings, so a real `"password", "<secret>"` would still fail the scan.

Test fixture key material (seeded trust grants, TLS certificates, fuzz
corpora) produced **no** findings under the default rule set; no blanket
`tests/` allowlist was granted.

## Dependency vulnerability scan

`scripts/osv_vulnerability_scan.py` queries OSV.dev for every one of the 40
pinned commits (35 direct + 5 recursive submodules) in a single batch call,
after proving detection with a positive control: a historical OpenSSL commit
inside six CVE git ranges must return advisories, otherwise the scan fails
closed (`SELF_TEST_OK` in the report). Advisories can be acknowledged per
dependency in `deploy/security/osv-triage.tsv`; untriaged advisories fail.

Result 2026-09-15: **0 advisories** match any pinned commit.

Coverage caveat: OSV's advisory coverage for native C/C++ projects is
sparse; a clean result means "no known advisory in OSV's data", not proof of
absence. Compensating controls: exact-commit pinning with
`scripts/fetch_third_party.sh --check` at every configure, and the upgrade
workflow (review upstream security notices) in
[dependency-policy.md](dependency-policy.md).

### coturn deployment artifact (not a linked dependency)

The TURN deployment is digest-pinned outside `dependencies.lock`
(`deploy/coturn/`), so it was audited manually against OSV/GitHub:

- Image `coturn/coturn:4.10.0-debian`: coturn ≤4.6.x/4.7.0-era advisories
  (CVE-2025-69217 weak RNG, CVE-2026-27624 denied-peer-ip IPv4-mapped-IPv6
  bypass, CVE-2026-40613 STUN parser misalignment, CVE-2026-43994
  `decode_oauth_token_gcm` overflow) are fixed at or before 4.10.0 (fix
  commits verified as ancestors of the 4.10.0 tag). Two 2026 advisories are
  **not** in 4.10.0: CVE-2026-43915 (stored XSS) and CVE-2026-53448 (SQL
  injection), both in the HTTPS **admin panel**. The Heyaki deployment
  ships `no-cli` and no `web-admin` listener, so both are not-affected;
  re-verify at release time and bump the image when an upstream release
  containing the fixes lands.
- Ubuntu 24.04 fallback package `coturn=4.6.1-1build4`: within OSV affected
  ranges for several of the above. It exists for the CI/lab path
  (namespaced loopback topologies) and as a bootstrap fallback; production
  deployments must use the digest-pinned image. Runbook already steers
  operators this way.

## SBOM and license policy

`heyaki-sbom` emits SPDX 2.3 + `THIRD_PARTY_LICENSES.md` from the three
locks on every build. M9-14 changes:

- The document now describes the **heyaki package itself**
  (`SPDXRef-Package-heyaki`, version `<project version>+<build commit>`,
  license MIT as of the v1.0.0 decision) in addition to the
  third-party closure; the document namespace is versioned
  (`…/sbom/<version>/<commit>`). `Created` stays pinned (2026-08-14) so the
  document is byte-reproducible for a given tree; the namespace identifies
  the release it describes.
- **License policy gate**: SBOM generation fails if any dependency that is
  linked into shipped artifacts (groups `runtime` and `test`, plus the
  recursive submodules) declares a copyleft atom (AGPL/GPL/LGPL/SSPL). The
  `optional` group tolerates a copyleft atom only behind a permissive OR
  branch, because the build then selects the permissive side (zstd:
  `BSD-3-Clause OR GPL-2.0-only`, not built in v1).

Current inventory: all linked dependencies are permissive (MIT, ISC,
BSD-2/3-Clause, Apache-2.0, BSL-1.0, MPL-2.0, public-domain `blessing`,
CC0). The manifest table now also shows each pin's lock group.

## Compile hardening

`HEYAKI_HARDENING` (default ON):

- Project-wide object-level: `-fstack-protector-strong`, position
  independent code (covers vendored C libraries and pinned in-tree
  dependencies, not only Heyaki-authored code), `-fcf-protection=full`
  (probed, x86), `-D_FORTIFY_SOURCE=3` (probed ladder 3→2; optimized
  configurations only — at -O0 glibc warns it is inactive, fatal under
  `-Werror`; the probe avoids redefinition warnings on distro toolchains
  that predefine it).
- Heyaki executables and shared objects: `-pie` (executables),
  `-Wl,-z,relro -Wl,-z,now` (full RELRO), `-Wl,-z,noexecstack`.
- MSVC (Heyaki targets): `/GS /guard:cf` compile, `/GUARD:CF /CETCOMPAT`
  link on x64.

Verification: `tests/supply_chain/run_hardening_check.sh`
(`heyaki_m9_hardening_check`) asserts on the shipped Linux executables:
ELF type DYN (PIE), GNU_STACK without execute, GNU_RELRO + BIND_NOW,
`__stack_chk_fail`, and (Release) at least one FORTIFY `__*_chk` symbol.
Sanitizer presets and non-Linux hosts are excluded at registration; the
Windows flags have no scriptable equivalent and are recorded here as
compile-time flags (MSVC `/GS` and `/DYNAMICBASE /NXCOMPAT` defaults apply
to the whole build).

## Release artifact signing

`heyaki-release-sign` (pinned libsodium Ed25519): `keygen` / `manifest` /
`sign` / `verify` / `check`. Procedure, key management, rotation, and threat
model: [docs/operations/release-signing.md](../operations/release-signing.md).
`heyaki_m9_release_signing` replays the whole procedure over real build
artifacts and asserts rejection of modified artifacts, modified manifests,
wrong keys, and extra/missing files.
