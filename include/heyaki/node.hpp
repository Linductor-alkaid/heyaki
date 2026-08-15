#pragma once

#include <heyaki/lan_directory.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/runtime.hpp>

#include <chrono>
#include <cstddef>
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

using LanSignalingValidator =
    std::function<Result<void>(const LanSignalingMessage& message)>;
using LanSignalingHandler =
    std::function<Result<void>(const LanSignalingMessage& message)>;

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
};

struct NodeShutdownReport {
  bool stopped{false};
  bool timed_out{false};
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
  [[nodiscard]] Result<void> refresh_interfaces();
  [[nodiscard]] Result<void> connect_lan(DeviceEndpointKey peer);
  [[nodiscard]] Result<void> send_lan_signaling(LanSignalingMessage message);
  [[nodiscard]] Result<void> close_lan(DeviceEndpointKey peer);
  [[nodiscard]] NodeShutdownReport shutdown();

 private:
  explicit Node(std::shared_ptr<Impl> impl) noexcept;
  std::shared_ptr<Impl> impl_;
};

[[nodiscard]] std::string_view lan_readiness_state_name(LanReadinessState state) noexcept;
[[nodiscard]] bool is_lan_offer_owner(DeviceEndpointKey local,
                                      DeviceEndpointKey peer) noexcept;
[[nodiscard]] Result<SignalingRouteKind> select_signaling_route(
    ConnectivityMode mode, bool lan_available, bool relay_available) noexcept;

}  // namespace heyaki
