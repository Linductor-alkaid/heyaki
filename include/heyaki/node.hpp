#pragma once

#include <heyaki/byte_stream.hpp>
#include <heyaki/event.hpp>
#include <heyaki/file.hpp>
#include <heyaki/lan_directory.hpp>
#include <heyaki/message.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/rpc.hpp>
#include <heyaki/runtime.hpp>

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace heyaki {

enum class LanReadinessState : std::uint8_t {
  disabled,
  starting,
  ready,
  degraded,
  failed,
  stopped,
};

enum class LanInterfaceFamily : std::uint8_t {
  ipv4,
  ipv6,
};

struct LanInterfaceSnapshot {
  std::string name;
  std::uint32_t index{};
  LanInterfaceFamily family{LanInterfaceFamily::ipv4};
  std::string address;
  bool joined{false};
  bool multicast_verified{false};
  std::optional<Error> error;
};

struct LanTlsSnapshot {
  bool listener_ready{false};
  std::uint16_t listen_port{};
  TlsCertificateFingerprint certificate_sha256{};
  std::size_t provisional_connections{};
  std::size_t authenticated_connections{};
  std::uint64_t accepted{};
  std::uint64_t rejected{};
  std::uint64_t capacity_rejected{};
  std::uint64_t rate_limited{};
  std::uint64_t timed_out{};
  std::uint64_t handshake_failed{};
  std::uint64_t hello_rejected{};
};

enum class SignalingRouteKind : std::uint8_t {
  lan,
  relay,
};

enum class NodePeerSessionState : std::uint8_t {
  signaling,
  transport_connecting,
  authenticating,
  // Identity verified but untrusted: only pairing frames flow; business
  // channels cannot exist (RULE-03).
  pairing_restricted,
  authenticated,
  closed,
};

enum class NodeConnectionStage : std::uint8_t {
  idle,
  resolving_endpoint,
  signaling,
  gathering,
  checking,
  transport_connected,
  authenticating,
  authenticated,
  closed,
};

enum class NodeDataPathKind : std::uint8_t {
  unknown,
  direct_host,
  direct_srflx,
  turn_udp,
  turn_tcp,
  turn_tls,
};

enum class NodeIceServerKind : std::uint8_t {
  stun,
  turn_udp,
  turn_tcp,
  turn_tls,
};

struct NodeIceServer {
  NodeIceServerKind kind{NodeIceServerKind::stun};
  std::string hostname;
  std::uint16_t port{};
  std::string username;
  std::string credential;
};

// Transport-neutral data-path policy following the architecture's candidate
// priority order: IPv6 host, LAN IPv4 host, server-reflexive UDP, TURN/UDP,
// then verified TURN/TCP/TLS. A disabled class is excluded from local
// gathering and remote admission; enabling a class never invents connectivity
// the network cannot provide. TURN/TCP and TURN/TLS stay disabled until a
// backend providing them is explicitly verified for the pinned dependency.
struct PeerPathPolicy {
  bool allow_ipv6_host{true};
  bool allow_ipv4_host{true};
  bool allow_server_reflexive{true};
  bool allow_turn_udp{true};
  bool allow_turn_tcp{false};
  bool allow_turn_tls{false};
  // Restricts ICE to relayed candidates so the data path must traverse TURN.
  // Requires at least one allowed TURN class and one TURN server.
  bool force_turn_data_path{false};
  std::vector<NodeIceServer> ice_servers;
};

// Returns the policy a Node resolves for the mode when no explicit override is
// configured: lan_only never configures ICE servers or non-host candidates,
// while automatic and relay_only keep every class available for the ICE agent
// to use as the network allows.
[[nodiscard]] Result<PeerPathPolicy> default_peer_path_policy(
    ConnectivityMode mode) noexcept;
[[nodiscard]] Result<void> validate_peer_path_policy(const PeerPathPolicy& policy,
                                                    ConnectivityMode mode);

struct NodePeerSessionSnapshot {
  DeviceEndpointKey peer;
  RequestId request_id;
  SessionId session_id;
  std::uint64_t session_epoch{1U};
  SignalingRouteKind signaling_route{SignalingRouteKind::lan};
  NodePeerSessionState state{NodePeerSessionState::signaling};
  NodeConnectionStage connection_stage{NodeConnectionStage::idle};
  NodeDataPathKind data_path{NodeDataPathKind::unknown};
  std::string selected_candidate;
  std::chrono::milliseconds rtt{};
  std::size_t buffered_amount{};
  bool initiator{false};
  bool restart_in_flight{false};
  // Trust state of the session (M5): restricted sessions wait for pairing;
  // authorized sessions carry the effective grant scopes.
  bool pairing_restricted{false};
  std::vector<std::string> authorized_scopes;
  std::optional<Error> error;
};

struct LanSignalingMessage {
  DeviceEndpointKey peer;
  LanSignalingMessageKind kind{LanSignalingMessageKind::connect_request};
  RequestId request_id;
  std::vector<std::byte> payload;
};

enum class LanSignalingConnectionState : std::uint8_t {
  connecting,
  provisional_tls,
  authenticated,
  closed,
  failed,
};

struct LanSignalingConnectionSnapshot {
  DeviceEndpointKey peer;
  LanSignalingConnectionState state{LanSignalingConnectionState::connecting};
  bool inbound{false};
  bool local_offer_owner{false};
  std::string address;
  std::optional<Error> error;
};

struct LanResourceSnapshot {
  std::size_t discovery_sockets{};
  std::size_t peak_discovery_sockets{};
  bool tls_listener_open{false};
  std::size_t active_timers{};
  std::size_t peak_active_timers{};
  std::size_t signaling_connections{};
  std::size_t peak_signaling_connections{};
  std::size_t signaling_callbacks_in_flight{};
  bool interface_scan_in_flight{false};
  std::uint64_t interface_scan_result_depth{};
  std::uint64_t interface_scan_result_peak_depth{};
  std::uint64_t signaling_command_depth{};
  std::uint64_t signaling_command_peak_depth{};
  std::uint64_t signaling_result_depth{};
  std::uint64_t signaling_result_peak_depth{};
  std::size_t pending_outbound_messages{};
};

using LanSignalingValidator =
    std::function<Result<void>(const LanSignalingMessage& message)>;
using LanSignalingHandler =
    std::function<Result<void>(const LanSignalingMessage& message)>;

enum class RelayNodeState : std::uint8_t {
  disabled,
  starting,
  ready,
  degraded,
  failed,
  stopped,
};

struct RelayNodeConfig {
  bool enabled{true};
  std::string relay_url;
  std::optional<std::vector<std::byte>> relay_pin;
  std::string tenant;
  std::uint64_t enrollment_generation{1U};
  std::optional<std::filesystem::path> tls_ca_file;
  bool tls_verify_peer{true};
  std::chrono::milliseconds connect_timeout{5000};
  std::chrono::milliseconds handshake_timeout{5000};
  std::chrono::milliseconds close_timeout{2000};
  std::chrono::milliseconds heartbeat_interval{15000};
  std::chrono::milliseconds lease_duration{45000};
  std::size_t missed_heartbeat_limit{3U};
  std::chrono::milliseconds minimum_backoff{1000};
  std::chrono::milliseconds maximum_backoff{60000};
  std::chrono::milliseconds poll_interval{100};
  std::size_t receive_capacity{64U};
  std::size_t send_capacity{64U};
};

struct RelayNodeSnapshot {
  bool enabled{false};
  RelayNodeState state{RelayNodeState::disabled};
  std::string relay_url;
  std::string tenant;
  std::uint64_t enrollment_generation{};
  std::uint64_t lease_generation{};
  std::uint64_t heartbeats_sent{};
  std::uint64_t heartbeats_missed{};
  std::uint64_t reconnect_count{};
  std::chrono::milliseconds backoff{};
  std::optional<Error> last_error;
};

// Session-coordinator health as observed by the owning Node: bounded attempt
// state and the signed-object replay guard depth. Executor facilities remain
// the source of truth for task health; these fields cover protocol state.
struct NodeSessionCoordinatorDiagnostics {
  std::uint64_t replay_rejected{};
  std::uint64_t attempts_expired{};
  std::uint64_t attempts_closed{};
  std::size_t current_attempts{};
  std::size_t peak_attempts{};
  std::size_t replay_current_entries{};
  std::size_t replay_peak_entries{};
};

// Protocol-1.2 in-place restart renegotiation state: a replacement transport
// negotiated over an authenticated control channel. Executor facilities remain
// the source of truth for task health; these fields cover protocol state.
struct NodeSessionRestartDiagnostics {
  std::uint64_t restarts_initiated{};
  std::uint64_t restarts_completed{};
  std::uint64_t restarts_failed{};
  std::uint64_t restarts_suppressed{};
  std::size_t current_restarts{};
  std::size_t peak_restarts{};
};

struct NodeSnapshot {
  bool local_initialized{false};
  DeviceId device_id;
  EndpointId endpoint_id;
  ConnectivityMode connectivity_mode{ConnectivityMode::automatic};
  bool lan_enabled{false};
  bool discoverable{false};
  LanReadinessState lan_state{LanReadinessState::disabled};
  std::vector<LanInterfaceSnapshot> interfaces;
  LanTlsSnapshot tls;
  EndpointDirectoryDiagnostics directory;
  std::uint64_t announcements_sent{};
  std::uint64_t datagrams_received{};
  std::uint64_t datagrams_rejected{};
  RelayNodeSnapshot relay;
  NodeSessionCoordinatorDiagnostics session_coordinator;
  NodeSessionRestartDiagnostics session_restarts;
  LanResourceSnapshot resources;
  std::optional<Error> last_error;
};

struct NodeConfig {
  ProfileStore* profile{nullptr};
  Runtime* runtime{nullptr};
  std::string application_id;
  std::optional<LanConfiguration> lan_override;
  RuntimeConfig runtime_config;
  LanSignalingValidator signaling_validator;
  LanSignalingHandler signaling_handler;
  std::optional<RelayNodeConfig> relay_override;
  std::optional<PeerPathPolicy> path_policy_override;
  // M5 pairing hardening: pairing policy/failure backoff knobs forwarded to
  // the Node's PairingService. Zero values keep the service defaults.
  std::size_t pairing_failure_threshold{0U};
  std::chrono::milliseconds pairing_backoff_base{0};
  std::chrono::milliseconds pairing_backoff_max{0};
  // Optional grant TTL; 0 disables expiry.
  std::uint64_t pairing_grant_ttl_milliseconds{0U};
  // ---- M7 remote events & file transfer ----
  // Per-remote-subscriber staging (items) and per-peer subscription cap for
  // the event service; zero keeps service defaults.
  std::size_t event_subscriber_queue_items{0U};
  std::size_t event_max_subscriptions_per_peer{0U};
  // Accepted receive roots for the file service; a push/pull into an
  // unlisted root is rejected before any byte is accepted (M7-09).
  std::vector<FileRootConfig> file_receive_roots;
  // Per-peer cumulative received-byte quota; 0 disables the user quota.
  std::uint64_t file_max_peer_receive_bytes{0U};
};

// Terminal outcome of one password pairing attempt; `value` holds the
// effective scopes on success.
using NodePairingOutcome = Result<std::vector<std::string>>;
using NodePairingObserver =
    std::function<void(const DeviceEndpointKey& peer, const NodePairingOutcome& outcome)>;

// Options for Node::open_byte_stream.
struct NodeByteStreamOptions {
  std::uint64_t receive_window_bytes{256U * 1024U};
  std::uint32_t receive_window_frames{64U};
};

// ---- M7 remote events & file transfer ----
// One local fan-out message bridged at the device boundary (M7-05): the
// local counterpart of a remote EventItemBody with deliberately distinct
// naming and lifecycle (executor::comm topic semantics, not wire QoS).
struct NodeLocalEvent {
  std::string topic;
  std::uint32_t schema_version{1U};
  std::vector<std::byte> payload;
};

// Movable handle onto the node's local event topic; try_receive drains one
// fanned-out message without blocking.
class NodeLocalEventSubscription {
 public:
  NodeLocalEventSubscription();
  ~NodeLocalEventSubscription();
  NodeLocalEventSubscription(NodeLocalEventSubscription&&) noexcept;
  NodeLocalEventSubscription& operator=(NodeLocalEventSubscription&&) noexcept;
  NodeLocalEventSubscription(const NodeLocalEventSubscription&) = delete;
  NodeLocalEventSubscription& operator=(const NodeLocalEventSubscription&) = delete;
  [[nodiscard]] bool valid() const noexcept { return impl_ != nullptr; }
  [[nodiscard]] bool try_receive(NodeLocalEvent& out);

 private:
  friend class Node;
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Inbound remote event delivery (scope-checked and sequence-validated at
// protocol level before this fires); `pattern` is the matched subscription.
using NodeEventInboundHandler =
    std::function<void(const DeviceEndpointKey&, std::string_view pattern,
                       const EventItemBody& item)>;
// File transfer lifecycle (phase changes and per-chunk progress).
using NodeFileEventObserver =
    std::function<void(const DeviceEndpointKey&, const FileTransferEvent&)>;

// Aggregate service diagnostics across every authorized peer session; executor
// facilities remain the source of truth for task health (EXEC-08).
struct NodeServiceDiagnostics {
  MessageServiceStats message;
  RpcServiceStats rpc;
  EventServiceStats event;
  FileServiceStats file;
  std::size_t message_pending_acks{};
  std::size_t rpc_pending_calls{};
  std::size_t rpc_retry_queue{};
  std::size_t message_sessions{};
  std::size_t rpc_sessions{};
  std::size_t event_sessions{};
  std::size_t file_sessions{};
  std::size_t file_paused_transfers{};
};

// Inbound message delivery (already deduplicated, scope-checked, and
// ACK-answered at protocol level before this fires).
using NodeMessageInboundHandler =
    std::function<void(const DeviceEndpointKey&, const MessageEnvelope&)>;
// Delivery lifecycle of sent messages (queued/send_failed/acked/
// peer_rejected/ack_timeout/session_closed).
using NodeMessageAckObserver = std::function<void(
    const DeviceEndpointKey&, const MessageId&, MessageDeliveryEvent,
    std::optional<Error>)>;
// Terminal RPC outcome; peer statuses (including outcome_unknown) arrive as
// successful Results carrying RpcCallOutcome::status.
using NodeRpcCompletion = std::function<void(const DeviceEndpointKey&,
                                             Result<RpcCallOutcome>)>;

struct NodeShutdownReport {
  bool stopped{false};
  bool timed_out{false};
  LanResourceSnapshot final_resources;
};

class Node {
 public:
  class Impl;

  Node(Node&&) noexcept;
  Node& operator=(Node&&) noexcept;
  ~Node();

  Node(const Node&) = delete;
  Node& operator=(const Node&) = delete;

  [[nodiscard]] static Result<Node> create(NodeConfig config);
  [[nodiscard]] NodeSnapshot snapshot() const;
  [[nodiscard]] std::vector<EndpointDirectoryEntrySnapshot> endpoints() const;
  [[nodiscard]] std::vector<LanSignalingConnectionSnapshot> signaling_connections() const;
  [[nodiscard]] std::vector<NodePeerSessionSnapshot> peer_sessions() const;
  [[nodiscard]] Result<void> refresh_interfaces();
  [[nodiscard]] Result<void> connect(DeviceEndpointKey peer);
  [[nodiscard]] Result<void> connect_lan(DeviceEndpointKey peer);
  // Initiates the protocol-1.2 in-place restart renegotiation for an
  // authenticated session: a replacement transport is negotiated over the
  // existing control channel, preserving the SessionId with a bumped epoch.
  // The same path is triggered automatically when the interface binding set
  // changes; it is not a lossless migration.
  [[nodiscard]] Result<void> restart_session(DeviceEndpointKey peer);
  [[nodiscard]] Result<void> send_lan_signaling(LanSignalingMessage message);
  [[nodiscard]] Result<void> close_lan(DeviceEndpointKey peer);

  // ---- M5 pairing, trust, and streams ----
  // Submits one password pairing attempt on the peer's pairing-restricted
  // session. The one-time observer (or session snapshot) reports the terminal
  // outcome; the password is never stored or logged.
  [[nodiscard]] Result<void> pair_peer(DeviceEndpointKey peer, std::string_view password,
                                       std::vector<std::string> requested_scopes);
  void set_pairing_observer(NodePairingObserver observer);
  // Trust view data for the pairing & trust UI.
  [[nodiscard]] Result<std::vector<TrustGrantRecord>> trust_grants_for(
      const DeviceEndpointKey& peer) const;
  [[nodiscard]] Result<void> revoke_trust_grant(const GrantId& grant_id);
  // "Rotate only": keeps existing grants valid.
  [[nodiscard]] Result<std::uint64_t> rotate_authorization_password(
      std::string_view new_password);
  // "Rotate and revoke": also revokes grants issued under older generations.
  [[nodiscard]] Result<std::uint64_t> rotate_authorization_password_and_revoke(
      std::string_view new_password);
  // Opens a stream on the peer's authorized session; inbound peer streams
  // are surfaced through the inbound handler set below.
  [[nodiscard]] Result<ByteStream> open_byte_stream(
      const DeviceEndpointKey& peer,
      const NodeByteStreamOptions& options = {});
  void set_byte_stream_inbound_handler(
      std::function<void(const DeviceEndpointKey&, ByteStream)> handler);

  // ---- M6 message & unary RPC (public API) ----
  // Sends one typed message to an authorized peer. Fails immediately with
  // peer_offline when no authorized session exists (v1 has no offline
  // queue, M6-06); delivery outcomes surface through the ack observer.
  [[nodiscard]] Result<MessageId> send_message(const DeviceEndpointKey& peer,
                                               MessageEnvelope envelope);
  void set_message_inbound_handler(NodeMessageInboundHandler handler);
  void set_message_ack_observer(NodeMessageAckObserver observer);
  // Registers one server-side unary method for every peer session; the
  // descriptor's required scope is checked before any handler runs.
  [[nodiscard]] Result<void> register_rpc_method(RpcMethodDescriptor descriptor,
                                                 RpcMethodHandler handler);
  [[nodiscard]] Result<void> unregister_rpc_method(std::string_view service,
                                                   std::string_view method);
  [[nodiscard]] std::vector<RpcMethodSummary> rpc_methods() const;
  // Starts one unary call. The completion fires exactly once with the
  // terminal outcome (from the node's strand context).
  [[nodiscard]] Result<RequestId> call_rpc(const DeviceEndpointKey& peer,
                                           std::string service, std::string method,
                                           std::vector<std::byte> payload,
                                           RpcCallOptions options,
                                           NodeRpcCompletion completion);
  // Cooperatively cancels one pending call (M6-10).
  [[nodiscard]] Result<void> cancel_rpc(const DeviceEndpointKey& peer,
                                        const RequestId& request_id);
  [[nodiscard]] NodeServiceDiagnostics service_diagnostics();

  // ---- M7 remote events (public API) ----
  // Subscribes to the peer's topic pattern (exact match, or segment-boundary
  // prefix when prefix_match). Items surface through the event inbound
  // handler and the local event topic below.
  [[nodiscard]] Result<EventSubscriptionId> subscribe_events(
      const DeviceEndpointKey& peer, std::string pattern, bool prefix_match,
      EventQos qos);
  // Unsubscribes every local subscription with this exact pattern.
  [[nodiscard]] std::size_t unsubscribe_events(const DeviceEndpointKey& peer,
                                               std::string_view pattern);
  // Publishes one event under `topic` to the peer's matching subscriptions
  // (QoS is per subscription). Returns the matched subscription count.
  [[nodiscard]] Result<std::size_t> publish_event(const DeviceEndpointKey& peer,
                                                  std::string topic,
                                                  std::vector<std::byte> payload,
                                                  std::uint32_t schema_version);
  void set_event_inbound_handler(
      std::function<void(const DeviceEndpointKey&, std::string_view pattern,
                         const EventItemBody& item)> handler);
  // The local half of the M7-05 bridge: remote events fan out through the
  // node's executor::comm topic, and locally published messages bridge to
  // matching remote subscriptions.
  [[nodiscard]] NodeLocalEventSubscription subscribe_local_events();
  [[nodiscard]] Result<std::size_t> publish_local_event(const DeviceEndpointKey& peer,
                                                        std::string topic,
                                                        std::vector<std::byte> payload,
                                                        std::uint32_t schema_version);

  // ---- M7 file transfer (public API) ----
  // Starts pushing one local file into the peer's logical root under
  // `logical_name`. A caller-provided transfer id resumes a prior transfer
  // on the receiver (M7-13). Progress surfaces through the file observer.
  [[nodiscard]] Result<TransferId> push_file(const DeviceEndpointKey& peer,
                                             std::string root, std::string logical_name,
                                             std::filesystem::path source_path,
                                             TransferId transfer_id = {});
  // Asks the file owner to send `logical_name` from its root; the transfer
  // lands in this node's same-named receive root under the file.pull scope.
  [[nodiscard]] Result<TransferId> pull_file(const DeviceEndpointKey& peer,
                                             std::string root, std::string logical_name);
  [[nodiscard]] Result<void> pause_file_transfer(const DeviceEndpointKey& peer,
                                                 const TransferId& id);
  [[nodiscard]] Result<void> resume_file_transfer(const DeviceEndpointKey& peer,
                                                  const TransferId& id);
  [[nodiscard]] Result<void> cancel_file_transfer(const DeviceEndpointKey& peer,
                                                  const TransferId& id);
  void set_file_event_observer(
      std::function<void(const DeviceEndpointKey&, const FileTransferEvent&)> observer);
  [[nodiscard]] std::vector<FileTransferSummary> file_transfers(
      const DeviceEndpointKey& peer);

  [[nodiscard]] NodeShutdownReport shutdown();

 private:
  explicit Node(std::shared_ptr<Impl> impl) noexcept;
  std::shared_ptr<Impl> impl_;
};

[[nodiscard]] std::string_view lan_readiness_state_name(LanReadinessState state) noexcept;
[[nodiscard]] std::string_view relay_node_state_name(RelayNodeState state) noexcept;
[[nodiscard]] std::string_view node_peer_session_state_name(
    NodePeerSessionState state) noexcept;
[[nodiscard]] std::string_view signaling_route_kind_name(
    SignalingRouteKind kind) noexcept;
[[nodiscard]] std::string_view node_connection_stage_name(
    NodeConnectionStage stage) noexcept;
[[nodiscard]] std::string_view node_data_path_kind_name(
    NodeDataPathKind kind) noexcept;
[[nodiscard]] bool is_lan_offer_owner(DeviceEndpointKey local,
                                      DeviceEndpointKey peer) noexcept;
[[nodiscard]] Result<SignalingRouteKind> select_signaling_route(
    ConnectivityMode mode, bool lan_available, bool relay_available) noexcept;

}  // namespace heyaki
