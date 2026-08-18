#pragma once

#include <heyaki/lan_directory.hpp>
#include <heyaki/profile_store.hpp>
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

struct NodePeerSessionSnapshot {
  DeviceEndpointKey peer;
  RequestId request_id;
  SessionId session_id;
  SignalingRouteKind signaling_route{SignalingRouteKind::lan};
  NodePeerSessionState state{NodePeerSessionState::signaling};
  NodeConnectionStage connection_stage{NodeConnectionStage::idle};
  NodeDataPathKind data_path{NodeDataPathKind::unknown};
  std::string selected_candidate;
  std::chrono::milliseconds rtt{};
  std::size_t buffered_amount{};
  bool initiator{false};
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
};

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
  [[nodiscard]] Result<void> send_lan_signaling(LanSignalingMessage message);
  [[nodiscard]] Result<void> close_lan(DeviceEndpointKey peer);
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
