#pragma once

#include "relay_config.hpp"
#include "relay_database.hpp"

#include <heyaki/error.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace heyaki {

enum class RelayServerState : std::uint8_t {
  stopped,
  starting,
  running,
  draining,
  failed,
};

struct RelayServerSnapshot {
  RelayServerState state{RelayServerState::stopped};
  std::string listen_address;
  std::uint16_t listen_port{};
  std::size_t active_sessions{};
  std::size_t connection_capacity{};
  std::uint64_t tcp_accepted{};
  std::uint64_t websocket_accepted{};
  std::uint64_t health_checks{};
  std::uint64_t capacity_rejected{};
  std::uint64_t handshake_timeouts{};
  std::uint64_t handshake_failed{};
  std::uint64_t protocol_rejected{};
  RelayDatabaseSnapshot database;
  bool stop_requested{false};
  std::optional<Error> last_error;
};

struct RelayServerShutdownReport {
  bool stopped{false};
  bool timed_out{false};
  RuntimeShutdownReport runtime;
  RelayServerSnapshot final_snapshot;
};

class RelayServer {
 public:
  struct Impl;

  RelayServer(RelayServer&&) noexcept;
  RelayServer& operator=(RelayServer&&) noexcept;
  ~RelayServer();

  RelayServer(const RelayServer&) = delete;
  RelayServer& operator=(const RelayServer&) = delete;

  [[nodiscard]] static Result<RelayServer> create(RelayServerConfig config,
                                                  Runtime* runtime = nullptr);
  [[nodiscard]] RelayServerSnapshot snapshot() const;
  [[nodiscard]] bool stop_requested() const noexcept;
  [[nodiscard]] RelayServerShutdownReport shutdown();

 private:
  explicit RelayServer(std::shared_ptr<Impl> impl) noexcept;

  std::shared_ptr<Impl> impl_;
};

[[nodiscard]] std::string_view relay_server_state_name(RelayServerState state) noexcept;

}  // namespace heyaki
