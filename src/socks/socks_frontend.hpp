#pragma once

// Optional SOCKS5 CONNECT frontend for the M10 gateway proxy (M10-09).
// User-space, zero-privilege convenience layer OUTSIDE the core library
// dependency closure (nothing in heyaki_client depends on it): it works
// only through the public Node API (`open_gateway_stream`) and the
// executor-owned Asio runtime obtained through the internal runtime
// accessor — no private protocol, no second worker.
//
// Wire subset (RFC 1928): version 5, NO-AUTH only (0x00), CONNECT (0x01)
// only. Domain targets (ATYP 0x03) pass through VERBATIM so the serving
// side resolves them in its network context (split-DNS, design 4.3). The
// frontend binds loopback by default; its credentials are intentionally
// unrelated to Heyaki identity.
//
// Concurrency: acceptor and every client socket live on one private Asio
// strand created from the runtime's io executor; tunnel completions arrive
// on the node context and are re-posted to the frontend strand. One
// bounded chunk in flight per direction per connection. `Node`'s blocking
// open API is invoked from the strand; the default runtime runs at least
// two executor threads, which keeps that bounded wait deadlock-free.

#include <heyaki/byte_stream.hpp>
#include <heyaki/error.hpp>
#include <heyaki/gateway.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/node.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace heyaki::socks {

struct SocksFrontendConfig {
  // Loopback-only by default (design 5): the frontend must not expose the
  // peer's gateway to the local network without explicit configuration.
  std::string bind_address{"127.0.0.1"};
  std::uint16_t port{1080U};
  std::size_t max_concurrent_connections{16U};
  // Profile stamped onto every open (empty = serving side's default).
  std::string profile;
  // Absolute deadline handed to open_gateway_stream per connection
  // (relative, converted at request time).
  std::chrono::milliseconds connect_deadline{15000};
};

struct SocksFrontendStats {
  std::uint64_t accepted{0};
  std::uint64_t handshakes_failed{0};
  std::uint64_t connects_succeeded{0};
  std::uint64_t connects_failed{0};
  std::uint64_t bytes_from_clients{0};
  std::uint64_t bytes_to_clients{0};
  std::size_t connections_active{0};
  std::uint16_t bound_port{0};
  bool listening{false};
};

class SocksFrontend {
 public:
  // `runtime` supplies the executor-owned Asio executor; `node`/`peer`
  // carry every tunnel. The frontend does not take ownership.
  [[nodiscard]] static Result<std::shared_ptr<SocksFrontend>> create(
      Node& node, Runtime& runtime, DeviceEndpointKey peer,
      SocksFrontendConfig config);

  ~SocksFrontend();
  SocksFrontend(const SocksFrontend&) = delete;
  SocksFrontend& operator=(const SocksFrontend&) = delete;

  // Opens the listener and starts accepting.
  [[nodiscard]] Result<void> start();
  // Closes the listener and every active client connection.
  void stop();

  [[nodiscard]] SocksFrontendStats stats() const;

 private:
  SocksFrontend(Node& node, Runtime& runtime, DeviceEndpointKey peer,
                SocksFrontendConfig config,
                boost::asio::any_io_executor executor);
  struct State;
  std::shared_ptr<State> state_;
};

}  // namespace heyaki::socks
