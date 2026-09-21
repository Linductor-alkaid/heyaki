# File Transfer

`push_file` / `pull_file` between paired devices, with pause / resume /
cancel, resumable by `TransferId` after interruption or restart.

## Semantics

- Pipeline: manifest → bitmap accept → bounded-window chunks → BLAKE3
  verify → fsync → atomic rename. A completed file is fully written or not
  present — there is no partial-file window on the receiver.
- Receive roots are explicit allowlists configured per profile, with
  per-peer quotas; a sender cannot write outside them.
- Logical file names are validated by a strict grammar
  (`safe_logical_file_name`): no path traversal, no Windows reserved
  device names. Use logical names in APIs, never host paths.

## Pitfalls

- The receiving side must configure receive roots before a pull/push can
  land anywhere; without a matching root the transfer is refused.
- Chunk windows are bounded and frozen: a slow receiver applies
  backpressure, it does not balloon memory.
- Treat pause/resume as ordinary operations: they exist so you do not have
  to restart from byte zero — persist the `TransferId` if your app may
  restart mid-transfer.

The complete worked example is `apps/demo/m7_data_demo.cpp`.
