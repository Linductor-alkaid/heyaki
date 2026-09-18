# v1 Release Checklist (M9-18)

This checklist is the v1.0.0 release record and the procedure to cut the
release. Milestone delivery state: see the
[M9 milestone file](../todolists/m9-production-hardening.md); supply-chain
controls: [m9-release-audit.md](../supply-chain/m9-release-audit.md);
signing procedure: [release-signing.md](release-signing.md).

## Release identity

| Item | Value |
| --- | --- |
| Product version | 1.0.0 (`project(heyaki VERSION 1.0.0)`, stamped into `--version`, SBOM namespace, CMake package version) |
| Wire protocol | `{major 1, minor 2}` (`include/heyaki/protocol.hpp`; capability bits frozen; schema change control in [proto/README.md](../../proto/README.md) and the [wire protocol](../design/heyaki-wire-protocol.md)) |
| Release commit | Stamp at tag time: the commit whose full CI run (all 11 jobs) is green, recorded below in "Verification evidence" |
| License of heyaki itself | MIT ([LICENSE](../../LICENSE)), decided at v1.0.0 (2026-09-18); the SBOM declares `PackageLicenseDeclared: MIT` (enforced by `heyaki_supply_chain_inventory`); the third-party closure is permissive-only by policy ([dependency-policy.md](../supply-chain/dependency-policy.md)) |

## Dependency pins (recorded at release)

Source of truth (committed in the release commit; record their `git hash-object` at tag time):

- `third_party/dependencies.lock` — 35 direct pins (executor, libdatachannel
  v0.23.2, boost 1.88.0 subset, libsodium 1.0.20, protobuf v31.1, abseil,
  blake3, sqlite 3.50.4, FTXUI, googletest, zstd optional)
- `third_party/transitive-dependencies.lock` — 5 recursive pins under
  libdatachannel (libjuice, usrsctp, plog, libsrtp, …)
- `third_party/licenses.lock` — one license record per package; all texts
  ship in the tarball (`share/heyaki/licenses/`, 40 files; +LGPL-2.1 and
  NOTICE-libnice on `nice` builds)
- System dependencies (platform, not lock-file atoms): OpenSSL ≥3.0 <4.0;
  libnice ≥0.1.21 + GLib (nice builds only, dynamically linked, LGPL notice
  shipped); coturn image `coturn/coturn:4.10.0-debian` digest
  `sha256:f4c2af06c3c535c4f49d64e14d484104e7e4fcc98c4cb83d6e154f64d1e6158`
  (fallback Ubuntu package 4.6.1-1build4 is in CVE impact ranges — production
  must use the digest-pinned image; see
  [deploy/coturn/README.md](../../deploy/coturn/README.md))

Pre-tag re-checks (fail the release on new findings):

1. `scripts/osv_vulnerability_scan.py` (CI `heyaki_m9_vulnerability_scan`):
   zero untriaged hits on all pins.
2. coturn image re-audit: confirm the 2025/2026 CVE fix set still covers the
   digest and the admin-panel not-affected rationale (`no-cli`, no web-admin)
   still holds.
3. Secret scan (`heyaki_m9_secret_scan`): zero findings outside the
   documented historical allowlist.

## Verification evidence

CI matrix on the release commit (all must be green in one run):

| Job | Covers |
| --- | --- |
| linux (gcc/clang × Debug/Release) | Full unit/integration suites, protocol golden vectors, fuzz smoke + time-boxed libFuzzer, doc example sync (`heyaki_m9_docs_examples`) |
| windows (Debug/Release) | Full suites on MSVC (ConPTY, NTFS semantics, firewall matrix, TUI harness) |
| sanitizer (asan/ubsan/tsan) | Full suites under sanitizers |
| coturn-topology | libnice-backend build; NAT matrix (incl. `turn_tcp`), fault matrix, soak, bench with v1 acceptance gates |
| supply-chain | Release+`-g` build; secret/OSV scans, SBOM/license gates, hardening checks, release-signing round-trip, **release packaging flow** (`heyaki_m9_package`) |

Acceptance numbers (loopback benchmarks; topology-real P95 in the NAT/bench
matrices): registration P95 22–32 ms (gate < 2 s), direct connect P95
300–1021 ms juice / libnice in-family (gate < 3 s), TURN fallback P95
663–1077 ms (gate < 5 s), message P95 0.3–4 ms, RPC P95 2.3–8.5 ms,
single-file 4–13 MiB/s. Margins and per-parameter basis:
[parameter-freeze.md](parameter-freeze.md).

Local release-time gates (operator machine): `heyaki_m9_release_signing`
round-trip on the actual artifacts; soak/bench procedures from the
[runbook](runbook.md) if the fleet baseline needs re-baselining.

**Stamp on release**: run ID + commit SHA of the final green CI run, and the
`SHA256SUMS` of the produced tarballs, recorded here before tagging.

## Known limitations (v1)

Behavior accepted with rationale at release; each has a follow-up owner
note in the linked record:

1. **TURN/TLS rejected everywhere** — no pinned ICE backend implements it
   (libnice's TURN_TLS is a plaintext-compat placeholder); `turns:`
   configuration fails validation with `turn_tls_backend_not_verified`
   (M9-19). Unlock: upstream libnice/libjuice work or a first-party stack.
2. **libnice consent-freshness upstream defect** — dead-peer detection
   degrades to keepalive (~80 s window vs ~30 s on libjuice); soak gates
   accept the bounded window. Fix rides the next libdatachannel pin bump
   (`NICE_AGENT_OPTION_CONSENT_FRESHNESS`).
3. **Loss/jitter estimation absent** — libdatachannel exposes bytes/rtt
   only; packetsLost stays a bytes/rtt substitute face (freeze §9.3).
4. **Relay control-plane byte counters absent** — signaling throughput is
   proxied by `signaling_forwarded_total` deltas.
5. **`/metrics` has no client authentication beyond TLS trust** — accepted
   with rate limits; revisit for multi-tenant relays
   ([m9-security-regression.md](../security/m9-security-regression.md)).
6. **No relay admin CLI** — device revocation is the documented SQL
   procedure (runbook); bootstrap token issuance rides the relay database
   API/demo.
7. **Cross-OS Linux↔Windows pairs are not CI-able on hosted runners** —
   coverage is per-OS full-matrix + self-hosted fleet procedures
   ([cross-os-matrix.md](cross-os-matrix.md)); Windows udp_blocked is not
   single-machine simulatable (WFP loopback exemption).
8. **Disk-full simulation is POSIX-only** (RLIMIT_FSIZE); Windows ENOSPC
   paths partially covered by permission suites.
9. **Shared-egress NAT** can trip the relay per-IP rate limit (32/s);
   deployment observation item (freeze §9.3).
10. **Shell interactive latency** p50 ≈ 300 ms — PTY output drains on the
    frozen 500 ms tick (design; event-driven drain is a v1.x candidate).
11. **SCTP practical frame ceiling** ~60 KiB (libjuice path, M7 record);
    larger logical writes split at the stream layer.
12. **Parsers reject unknown wire fields** — deliberate (canonical signed
    objects); v1.x optional fields must be emitted gated on the negotiated
    minor (M9-12, wire §4).
13. **Tarball packaging is Linux-only** — Windows consumption is
    source/vcpkg-style builds plus the installed-consumer test; a Windows
    installer is out of v1 scope.

## Rollback plan

- **Relay binary/schema**: [Roll back a version](runbook.md#roll-back-a-version);
  a downgraded relay refuses to open a newer schema (`schema_too_new`) —
  that is the rollback boundary. Rolling forward again is
  [Roll a relay upgrade](runbook.md#roll-a-relay-upgrade) (backup →
  `PRAGMA user_version` check → swap binary → verify login continuity).
- **Devices**: N-1 interop is guaranteed by the compat suite
  (`heyaki_m9_compat`): same major, LAN discovery floor minor 1, capability
  clamping, restart-frame gating — a relay rollback does not strand
  enrolled devices.
- **TURN**: secret rotation keeps four generations valid
  ([rotate the TURN shared secret](runbook.md#rotate-the-turn-shared-secret)),
  so credential-plane rollbacks are non-breaking.
- **Client library consumers**: `heyakiConfigVersion` uses
  SameMajorVersion compatibility; 1.x upgrades are drop-in for CMake
  consumers, and the installed-consumer test gates the export set.

## Release procedure

1. Confirm the release commit: full CI matrix green (all jobs, one run);
   stamp the run ID and SHA in "Verification evidence".
2. Re-run the pre-tag dependency re-checks (OSV, coturn image, secret scan).
3. `scripts/package_release.sh --output <dist-dir>` from a clean checkout of
   the release commit (fresh RelWithDebInfo build by default) — produces
   `heyaki-1.0.0-linux-<arch>.tar.gz`, the `-dbg` companion, and SHA256SUMS.
4. Sign per [release-signing.md](release-signing.md): keygen (offline) →
   `manifest` → `sign` → `verify` → `check` over the tarball set; publish
   the public key id alongside the artifacts.
5. Record the artifact digests in this document; attach the SBOM
   (`share/heyaki/supply-chain/heyaki.spdx` from the tarball).
6. Tag `v1.0.0` and publish the artifacts. Tagging and publication are
   product-owner actions outside the engineering standing authorization.
7. Post-release: watch the SLO dashboard for the first 24 h
   ([observability](../../deploy/observability/README.md)); any
   regression follows the runbook triage paths.
