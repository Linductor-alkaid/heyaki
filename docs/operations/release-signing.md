# Release Artifact Signing

M9-14 deliverable: every published v1 release bundle is signed with an
offline-held Ed25519 key through the pinned libsodium, using the
`heyaki-release-sign` tool built from the release tree.

## Threat model and scope

The signature covers the **content of the bundle**: an attacker who can
modify, add, remove, or substitute any file inside a published bundle cannot
produce a valid signature. It does not pin the transport: consumers must
still fetch the public key out-of-band (see below), and the manifest cannot
say anything about files the distributor keeps outside the bundle.

## Key management

- One signing key pair per release train. `keygen` is run on the offline
  signing host; the secret key never touches the release working tree, CI,
  or any network-attached machine:
  ```sh
  heyaki-release-sign keygen heyaki-v1-release.secret heyaki-v1-release.pub
  heyaki-release-sign: RELEASE_KEY_ID <16 hex chars>   # publish this id
  ```
- The secret key file is created with owner-only permissions; the tool
  refuses nothing, so verify with `ls -l` — mode must be `600`.
- The public key and the key id are published with the release
  announcement. The key id is the first 16 hex chars of SHA-256(public key).
- Rotation: generate the successor key offline, sign the new public key with
  the old key, publish both, then retire the old key after one release train.

## Signing a release bundle

A release bundle is a directory containing the artifacts to publish
(binaries, `heyaki.spdx`, `THIRD_PARTY_LICENSES.md`; the exact layout is
defined by the M9-17 packaging step). On the release host:

```sh
heyaki-release-sign manifest <bundle-dir> <bundle-dir>/MANIFEST.txt
heyaki-release-sign sign <bundle-dir>/MANIFEST.txt heyaki-v1-release.secret
```

This produces `MANIFEST.txt` (deterministic: regular files only, byte-sorted
POSIX paths, SHA-256 per file; symlinks are excluded so a rewritten link
target cannot smuggle content) and `MANIFEST.txt.sig` (64-byte detached
Ed25519 signature over the manifest bytes). Publish the bundle with both
files. The manifest itself must be generated outside the bundle directory or
the bundle directory cleaned first — the signer signs whatever files the
directory contains.

## Verifying a release

Consumers run both checks — cryptographic authenticity, then content
integrity:

```sh
heyaki-release-sign verify MANIFEST.txt heyaki-v1-release.pub MANIFEST.txt.sig
heyaki-release-sign check MANIFEST.txt <bundle-dir>
heyaki-release-sign: SIGNATURE_VALID MANIFEST.txt
heyaki-release-sign: CHECK_OK <n> files match MANIFEST.txt
```

`verify` fails on any manifest byte change or wrong key; `check` fails on
modified, missing, or unlisted files. Either failure means the bundle must
not be used.

## CI enforcement

`heyaki_m9_release_signing` (CTest) replays the full procedure on every CI
run with an ephemeral key over real build artifacts (relay binary, SPDX
SBOM, license manifest) and asserts every tamper direction is rejected:
modified artifact, modified manifest, wrong key, extra unlisted file, and
missing file. The production release key is never present in CI.

## Notes

- The tool is a single-shot synchronous CLI with no concurrent work; it is
  outside the executor concurrency boundary by design.
- Manifest format: `heyaki-release-manifest/1`, a file-count line, then
  `SHA256 <64-hex> <path>` lines in byte-sorted path order. Parsing is
  strict (count mismatch, unsorted entries, unsafe paths, and malformed
  digests are all errors) so a signature always covers an unambiguous file
  list.
