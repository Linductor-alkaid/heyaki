#pragma once

// Serving side of the gateway proxy (M10-07). One GatewayService per
// authorized peer session: it receives every gateway-carrying STREAM_OPEN
// the session's ByteStreamService admits (protocol 1.3, wire 6.3.1),
// adjudicates it against the live gateway.provide:<profile> scope and the
// configured profiles (admission engine, M10-05), dials the surviving
// target addresses on the executor-owned Asio runtime, announces success
// with the 2-byte prelude, and pumps bytes bidirectionally between the
// tunnel stream and the local socket.
//
// Concurrency model (executor boundary):
//   * the service object, the tunnel registry, and all ByteStreamHandle
//     interaction live on the node strand (the session's execution
//     context), exactly like the other per-session services;
//   * every socket and resolver lives on a private Asio strand created
//     from detail::RuntimeAccess::io_executor — no second worker, no
//     bare thread (EXEC rules). Socket handlers post continuations back
//     through `poster` (the node strand) holding weak/shared references;
//   * each direction allows exactly one outstanding chunk (read -> write
//     -> read chain), so tunnel buffering is bounded by construction at
//     one data chunk per direction; overload therefore surfaces as write
//     deadline/idle-timeout resets, never unbounded growth.

#include "byte_stream.hpp"

#include <heyaki/gateway.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace heyaki {

struct GatewayServiceConfig {
  // Validated at Node::create (M10-04); an empty set never constructs a
  // GatewayService — inbound gateway opens reset with `unimplemented`.
  std::vector<GatewayProfileConfig> profiles;
  // Identity of the remote peer this service serves (confirm prompts).
  DeviceId peer_device;
  GatewayConfirmSink confirm_sink;
};

// Counters for M10-11 groundwork (metrics export lands with that task).
// Refusals are indexed by GatewayRefusal (gateway_refusal_name for labels).
struct GatewayServiceStats {
  std::array<std::uint64_t,
             static_cast<std::size_t>(GatewayRefusal::local_failure) + 1U>
      refusals{};
  std::uint64_t opens_received{0};
  std::uint64_t dials_succeeded{0};
  std::uint64_t dials_failed{0};
  std::uint64_t bytes_from_tunnel{0};  // A -> target
  std::uint64_t bytes_to_tunnel{0};    // target -> A
  std::uint64_t tunnels_closed_clean{0};
  std::uint64_t idle_timeout_resets{0};
  std::uint64_t duration_timeout_resets{0};
  std::uint64_t byte_quota_resets{0};
  std::size_t tunnels_active{0};
};

class GatewayService final : public std::enable_shared_from_this<GatewayService> {
 public:
  using ScopeCheck = std::function<bool(std::string_view)>;
  // Posts a task onto the node strand (the session's execution context).
  using NodePoster = std::function<void(std::function<void()>)>;

  GatewayService(PeerSession& session, ByteStreamService& streams,
                 GatewayServiceConfig config, boost::asio::any_io_executor io,
                 NodePoster poster, ScopeCheck scope_check,
                 std::function<std::uint64_t()> wall_clock,
                 GatewayConfirmSink confirm_sink = {});
  // Closes every local socket (on the io strand) and drops the registry
  // before the raw session references dangle.
  ~GatewayService();

  GatewayService(const GatewayService&) = delete;
  GatewayService& operator=(const GatewayService&) = delete;

  // Installs the gateway inbound handler on the session's ByteStreamService.
  [[nodiscard]] Result<void> attach();
  // Session loss: reset-owned state, close every socket, no detached work.
  void handle_session_closed();
  // Idle/duration sweeps and byte-quota enforcement (node maintenance tick).
  void prune();

  [[nodiscard]] const GatewayServiceStats& stats() const noexcept { return stats_; }

 private:
  // One gateway connection. Node-strand fields (stream, timestamps,
  // registry membership) and io-strand fields (socket) are disjoint; the
  // shared_ptr travels with posted continuations so a tunnel outlives its
  // in-flight handler chains exactly as long as needed.
  struct Tunnel final : std::enable_shared_from_this<Tunnel> {
    explicit Tunnel(StreamId stream_id) : id(stream_id) {}

    const StreamId id;
    std::shared_ptr<ByteStreamHandle> stream;  // node strand
    const GatewayProfileConfig* profile{nullptr};
    std::string profile_name;
    std::vector<GatewayIp> dial_addresses;
    std::uint64_t opened_unix_ms{0};
    std::uint64_t last_activity_unix_ms{0};
    std::uint64_t bytes_from_tunnel{0};
    std::uint64_t bytes_to_tunnel{0};
    bool finished{false};      // node strand: tunnel left the registry
    // Awaiting the human confirmation decision (design 3.3); the connect
    // request is parked until the decider runs or the deadline denies.
    bool awaiting_confirm{false};
    GatewayConnect pending_connect;
    // Node-strand state (set when the dial continuation lands):
    bool socket_connected{false};
    // io strand only:
    std::shared_ptr<boost::asio::ip::tcp::socket> socket;
    std::shared_ptr<boost::asio::steady_timer> dial_timer;
  };

  void handle_gateway_open(const std::shared_ptr<ByteStreamHandle>& stream,
                           const GatewayConnect& connect);
  // Runs one confirmed/pending open through admission: reserve the slot,
  // optionally park on the confirm sink, then resolve+dial.
  void begin_tunnel(const std::shared_ptr<ByteStreamHandle>& stream,
                    const GatewayConnect& connect, const GatewayProfileConfig* profile);
  void ask_confirmation(const std::shared_ptr<Tunnel>& tunnel,
                        const GatewayConnect& connect);
  void on_confirm_decided(const std::shared_ptr<Tunnel>& tunnel, bool allowed);
  // Post-confirmation path: literal targets go straight to admission,
  // hostnames resolve on the io strand.
  void dispatch_after_confirm(const std::shared_ptr<Tunnel>& tunnel);
  // Node strand: runs the scope check + admission engine once addresses
  // are known, then either refuses (stream reset) or dispatches the dial.
  void continue_admission(const std::shared_ptr<Tunnel>& tunnel,
                          const GatewayConnect& connect,
                          Result<std::vector<GatewayIp>> resolved);
  void dispatch_dial(const std::shared_ptr<Tunnel>& tunnel,
                     const GatewayConnect& connect);
  // Node strand after a successful dial + prelude write.
  void on_dial_succeeded(const std::shared_ptr<Tunnel>& tunnel);
  void on_prelude_written(const std::shared_ptr<Tunnel>& tunnel,
                          StreamIoResult written);
  void start_pumps(const std::shared_ptr<Tunnel>& tunnel);
  void pump_tunnel_to_socket(const std::shared_ptr<Tunnel>& tunnel);
  void on_tunnel_read(const std::shared_ptr<Tunnel>& tunnel,
                      const std::shared_ptr<std::vector<std::byte>>& buffer,
                      StreamIoResult read);
  void on_socket_read(const std::shared_ptr<Tunnel>& tunnel,
                      const std::shared_ptr<std::vector<std::byte>>& buffer,
                      boost::system::error_code error, std::size_t bytes);
  void on_socket_written(const std::shared_ptr<Tunnel>& tunnel,
                         StreamIoResult written);
  void on_dial_failed(const std::shared_ptr<Tunnel>& tunnel,
                      GatewayRefusal refusal);
  void on_tunnel_bytes(const std::shared_ptr<Tunnel>& tunnel,
                       std::uint64_t from_tunnel, std::uint64_t to_tunnel);
  // Terminal path for one tunnel: resets the stream (stable status), closes
  // the socket on the io strand, drops registry membership, updates stats.
  // Takes the tunnel by value: callers may hold a reference into the
  // registry this function erases from.
  void close_tunnel(std::shared_ptr<Tunnel> tunnel, StableStatus reason,
                    bool clean);
  void refuse_open(const std::shared_ptr<ByteStreamHandle>& stream,
                   const std::shared_ptr<Tunnel>& tunnel, GatewayRefusal refusal);
  [[nodiscard]] static boost::asio::ip::tcp::endpoint endpoint_for(
      const GatewayIp& address, std::uint16_t port) noexcept;
  [[nodiscard]] std::uint64_t now() const noexcept;

  PeerSession& session_;
  ByteStreamService& streams_;
  GatewayServiceConfig config_;
  GatewayConfirmSink confirm_sink_;
  boost::asio::strand<boost::asio::any_io_executor> io_strand_;
  NodePoster poster_;
  ScopeCheck scope_check_;
  std::function<std::uint64_t()> wall_clock_;
  std::map<StreamId, std::shared_ptr<Tunnel>> tunnels_;
  // first_use confirmations remembered per profile for this session
  // (cross-restart persistence is deferred to the v1.x policy store).
  std::set<std::string> confirmed_profiles_;
  // Live per-profile accounting feeding the admission context.
  struct ProfileUsage {
    std::size_t active{0};
    std::uint64_t bytes{0};
  };
  std::map<std::string, ProfileUsage> usage_;
  GatewayServiceStats stats_;
  bool attached_{false};
};

}  // namespace heyaki
