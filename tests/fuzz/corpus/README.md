# Fuzz regression corpus (M9-13)

Minimized seed/regression inputs for the libFuzzer targets. Every directory
feeds one fuzzer entry; the deterministic smoke test
(`heyaki_fuzz_smoke`, CTest `heyaki_fuzz_smoke`) replays every file in this
tree against the corresponding targets on every test run, so a crash found by
a long fuzzing session is fixed together with a minimized unit committed here.

| Directory | libFuzzer target | Covered targets (tests/fuzz/fuzz_targets.hpp) |
| --- | --- | --- |
| `frame-parser/` | `heyaki_frame_parser_fuzzer` | frame parser, frame stream decoder, LAN datagram/hello/signaling, signed offer/answer/candidate/session-hello, pairing request, trust grant, m8 shell, m8 VT |
| `protocol-state/` | `heyaki_protocol_state_fuzzer` | protocol state machines |
| `protobuf-parser/` | `heyaki_protobuf_parser_fuzzer` | protobuf schema parser |
| `lan-directory-state/` | `heyaki_lan_state_fuzzer` | LAN directory state machine |
| `connection-attempt-state/` | `heyaki_connection_state_fuzzer` | connection attempt state machine |
| `profile-store/` | `heyaki_profile_store_fuzzer` | ProfileStore open/migration over v1 fixtures, truncated and raw corrupt databases |

## Conventions

- Files are raw fuzz input bytes; keep them minimal. One behavior per file.
- `frame-parser/golden-frame` derives from `tests/vectors/m1-golden-vectors.json`
  (`frame.bytes_hex`); the other files are hand-minimized edge cases
  (truncation, unknown/duplicate fields, oversized lengths, corrupt/truncated
  profile databases).
- CI seeds each target from its directory here plus the generated seeds in
  `build/fuzz-corpus/<directory>`, with a wall-clock budget per target; the
  same directories are the seed corpora for local long runs, e.g.
  `build/tests/heyaki_frame_parser_fuzzer -max_total_time=1800 \
  tests/fuzz/corpus/frame-parser build/fuzz-corpus/frame-parser`.
- When a fuzzer finds a crash, minimize it (`-minimize_crash=1`), reduce it to
  the smallest file that still exercises the bug, and commit it here next to
  the fix.
