# Index By Scenario

| The application needs to | Read |
| --- | --- |
| Find peers (same LAN with no infrastructure, or across networks via the relay) and connect | [Sessions and discovery](sessions-and-discovery.md) |
| Authorize a new device with a password and grant it scoped access | [Pairing and trust](pairing-and-trust.md) |
| Exchange messages with another device (best-effort or peer-acked) | [Services: message, RPC, events](services.md) |
| Make request/response calls between devices (deadlines, cancellation) | [Services: message, RPC, events](services.md) |
| Fan out state updates / telemetry to subscribing devices | [Services: message, RPC, events](services.md) |
| Transfer files between devices, resumable and integrity-verified | [File transfer](file-transfer.md) |
| Operate a terminal on a remote device | [Shell](shell.md) |
| Reach a TCP service on, or behind, another device — including via SOCKS5 | [Gateway](gateway.md) |
| Run the control-plane relay yourself (hosted or embedded) | [Relay](relay.md) |
| Expose health and behavior of the app (metrics, Prometheus) | [Observability](observability.md) |

Pick exactly one row; each card carries the entry points, the required trust
scopes, and the pitfalls for that scenario. Cross-cutting concerns (bounds,
shutdown, platform support, build failures) route from
[by requirement](by-requirement.md).
