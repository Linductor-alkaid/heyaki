# Troubleshooting

## Build, configure, link

The symptom → cause → fix tables live in the authoritative docs:

- SDK consumption failures (find_package, OpenSSL, GLIBC/GLIBCXX, DLLs,
  `rtc::*` link errors, MSVC initializer diagnostics):
  [client-library.md](../../../client-library.md#troubleshooting).
- Runtime symptoms by area (devices, relay, TUI):
  [troubleshooting.md](../../../troubleshooting.md).

The two most common first-integration failures:

- `CMAKE_PREFIX_PATH` pointing inside the SDK's `lib/` instead of the
  archive root — the packages live under `lib/cmake/` of the root.
- A group/other-accessible state directory — the profile store refuses it
  (`chmod 700`).

## Verify release artifacts

Published bundles carry a deterministic content manifest and a detached
Ed25519 signature:

```sh
heyaki-release-sign verify MANIFEST.txt heyaki-v1-release.pub MANIFEST.txt.sig
heyaki-release-sign check MANIFEST.txt <bundle-dir>
```

Fetch the public key out-of-band (it ships with the release announcement;
key id = first 16 hex chars of SHA-256 of the public key). Procedure:
[release-signing.md](../../../operations/release-signing.md).

## When to suspect the library

Reproduce with the shipped demos (`bin/heyaki-m6-message-rpc-demo`,
`bin/heyaki-m7-data-demo` in the SDK) before filing: if a demo shows the
same behavior with two stock devices, collect `Node::metrics()` output and
the correlation ids, then report against the public API surface.
