# Index By API Or Type

| Known API, type, scope, or term | Read |
| --- | --- |
| `Node`, `NodeConfig`, `Node::create`, `shutdown`, `NodeShutdownReport`, `Result`, `Error`, `error_code_name`, `safe_detail` | [Node lifecycle](node-lifecycle.md) |
| `ProfileStore`, `create_default`, `open_default`, `endpoint_for`, `local_readiness`, `initialize_local`, `create_password_verifier`, `SecretBackend` | [Quick start](quick-start.md) |
| `endpoints`, `connect`, `connect_lan`, `peer_sessions`, `restart_session`, `refresh_interfaces`, `PairingRestricted`, `data_path` | [Sessions and discovery](sessions-and-discovery.md) |
| `pair_peer`, `set_pairing_observer`, `TrustGrant`, `trust_grants_for`, `revoke_trust_grant`, `trust_scope_covers`, `rotate_authorization_password`, `pairing_audit_records` | [Pairing and trust](pairing-and-trust.md) |
| `send_message`, `register_rpc_method`, `call_rpc`, `cancel_rpc`, `outcome_unknown`, `subscribe_events`, `publish_event`, `EventQos`, `best_effort_latest`, `reliable_live` | [Services](services.md) |
| `push_file`, `pull_file`, `TransferId`, `safe_logical_file_name`, receive roots, BLAKE3 | [File transfer](file-transfer.md) |
| `open_shell`, `close_shell`, `ShellProfileConfig`, `shell.open:<profile>` | [Shell](shell.md) |
| `open_gateway_stream`, `GatewayConnect`, `NodeGatewayStreamOptions`, `on_connected`, `gateway.use`, `gateway.provide:<profile>`, `gateway_profiles`, `gateway_audit_records`, `SocksFrontend` | [Gateway](gateway.md) |
| `RelayNodeConfig`, `relay_override`, enrollment, `NodeIceServer`, TURN credentials | [Relay](relay.md) |
| `heyaki-relay`, `RelayServer`, `RelayDatabase` (in-tree, not in the SDK) | [Relay](relay.md) |
| `metrics`, `NodeMetrics`, `format_node_metrics_prometheus`, relay `/metrics`, QUEUES view | [Observability](observability.md) |
| `RuntimeConfig`, `validate_config`, `validate_relay_node_config` | [Node lifecycle](node-lifecycle.md) |
| protocol `1.3`, `gateway_v1`, `negotiate_protocol`, capability bits, `heyaki::core`/`profile`/`client`/`services`/`transport_webrtc` targets | [Public API coverage](public-api-coverage.md) |

Use this index when an error message, code review, or existing application
symbol gives the starting term. Read the linked card before adding adjacent
APIs.
