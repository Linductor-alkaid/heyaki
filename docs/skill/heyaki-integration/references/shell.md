# Shell

Remote terminal over an authenticated session. Entry points: `open_shell`,
input, resize, signal, eof, `close_shell`.

## Serving side is default-off

Shells serve only when the node's `NodeConfig` carries an explicit
`ShellProfileConfig` list — one profile per environment you choose to
expose, each with its own bounds. Without it, `open_shell` is refused. A
live `shell.open:<profile>` scope is required per frame; the audit records
are content-free (no keystrokes or output are logged).

## Pitfalls

- Escalation is fixed: TERM → grace → kill. Signal the session's semantics,
  not a specific kill mode.
- Input and output flow through bounded queues with a frozen drain tick;
  interactive latency is designed around that tick, not zero.
- Windows serving uses ConPTY; do not assume POSIX pty behavior in portable
  clients, and do not put secrets in shell input — the echo path is a
  terminal renderer, not a password prompt.
- Shells are per-session: closing the session closes the shell; there is no
  detached background shell in v1.

## Next

For structured exchange instead of a terminal read
[services](services.md); for tunneling arbitrary TCP read
[gateway](gateway.md).
