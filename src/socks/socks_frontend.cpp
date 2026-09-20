#include "socks_frontend.hpp"

#include "../client/runtime_access.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/write.hpp>

#include <algorithm>
#include <optional>
#include <array>
#include <functional>
#include <utility>

namespace heyaki::socks {
namespace {

constexpr std::size_t socks_chunk_bytes = 16U * 1024U;

// RFC 1928 reply codes (subset the frontend can emit).
constexpr std::uint8_t socks_rep_succeeded = 0x00U;
constexpr std::uint8_t socks_rep_general_failure = 0x01U;
constexpr std::uint8_t socks_rep_command_not_supported = 0x07U;
constexpr std::uint8_t socks_rep_address_not_supported = 0x08U;

Error socks_error(ErrorCode code, const char* detail) {
  return {code, "socks_frontend", detail};
}

// VER(5) REP RSV(0) ATYP(1=IPv4) BND.ADDR(0.0.0.0) BND.PORT(0): the bound
// address is unspecified — the SOCKS client sends to the frontend socket,
// and the real egress address is the serving peer's, not ours.
std::array<std::byte, 10U> socks_reply(std::uint8_t rep) {
  return {std::byte{0x05U}, std::byte{rep},     std::byte{0x00U}, std::byte{0x01U},
          std::byte{0x00U}, std::byte{0x00U},   std::byte{0x00U}, std::byte{0x00U},
          std::byte{0x00U}, std::byte{0x00U}};
}

std::uint64_t unix_milliseconds_now() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

// One accepted client connection driving one gateway stream.
struct ClientConnection final : std::enable_shared_from_this<ClientConnection> {
  ClientConnection(boost::asio::ip::tcp::socket socket,
                   SocksFrontendStats& stats)
      : socket(std::move(socket)), stats(stats) {}

  boost::asio::ip::tcp::socket socket;
  SocksFrontendStats& stats;
  std::optional<ByteStream> stream;
  bool closed{false};
  std::vector<std::byte> request;
};

}  // namespace

struct SocksFrontend::State final : std::enable_shared_from_this<State> {
  State(Node& node_value, Runtime& runtime_value, DeviceEndpointKey peer_value,
        SocksFrontendConfig config_value, boost::asio::any_io_executor executor)
      : node(node_value),
        runtime(runtime_value),
        peer(std::move(peer_value)),
        config(std::move(config_value)),
        strand(boost::asio::make_strand(std::move(executor))),
        acceptor(strand) {}

  Node& node;
  Runtime& runtime;
  DeviceEndpointKey peer;
  SocksFrontendConfig config;
  boost::asio::strand<boost::asio::any_io_executor> strand;
  boost::asio::ip::tcp::acceptor acceptor;
  SocksFrontendStats stats{};
  std::vector<std::shared_ptr<ClientConnection>> connections;
  bool stopping{false};

  void start_accept();
  void on_accept(boost::system::error_code error,
                 boost::asio::ip::tcp::socket socket);
  void read_greeting(const std::shared_ptr<ClientConnection>& connection);
  void read_request(const std::shared_ptr<ClientConnection>& connection,
                    std::size_t header_bytes);
  void open_tunnel(const std::shared_ptr<ClientConnection>& connection,
                   GatewayConnect target);
  void reply_and_pump(const std::shared_ptr<ClientConnection>& connection,
                      std::uint8_t rep);
  void pump_client_to_tunnel(const std::shared_ptr<ClientConnection>& connection);
  void pump_tunnel_to_client(const std::shared_ptr<ClientConnection>& connection);
  void close_connection(const std::shared_ptr<ClientConnection>& connection);
};

void SocksFrontend::State::start_accept() {
  if (stopping) return;
  auto weak = weak_from_this();
  acceptor.async_accept(
      [weak](boost::system::error_code error, boost::asio::ip::tcp::socket socket) {
        if (auto self = weak.lock()) {
          self->on_accept(error, std::move(socket));
        }
      });
}

void SocksFrontend::State::on_accept(boost::system::error_code error,
                                     boost::asio::ip::tcp::socket socket) {
  if (stopping) return;
  if (!error && connections.size() < config.max_concurrent_connections) {
    ++stats.accepted;
    auto connection = std::make_shared<ClientConnection>(std::move(socket), stats);
    connections.push_back(connection);
    ++stats.connections_active;
    read_greeting(connection);
  } else if (!error) {
    // Admission is full: close without a reply (the SOCKS handshake never
    // started on this socket).
    boost::system::error_code ignored;
    socket.close(ignored);
    ++stats.handshakes_failed;
  }
  start_accept();
}

void SocksFrontend::State::read_greeting(
    const std::shared_ptr<ClientConnection>& connection) {
  // [VER NMETHODS METHODS...]: read VER+NMETHODS first, then the methods.
  auto weak = weak_from_this();
  auto header = std::make_shared<std::array<std::byte, 2U>>();
  boost::asio::async_read(
      connection->socket, boost::asio::buffer(header->data(), header->size()),
      [weak, connection, header](boost::system::error_code error, std::size_t) {
        auto self = weak.lock();
        if (!self || connection->closed) return;
        if (error || (*header)[0] != std::byte{0x05U} ||
            (*header)[1] == std::byte{0x00U}) {
          ++connection->stats.handshakes_failed;
          self->close_connection(connection);
          return;
        }
        const auto methods = std::to_integer<std::size_t>((*header)[1]);
        auto offered = std::make_shared<std::vector<std::byte>>(methods);
        boost::asio::async_read(
            connection->socket, boost::asio::buffer(offered->data(), methods),
            [weak, connection, offered](boost::system::error_code error2,
                                        std::size_t) {
              auto self = weak.lock();
              if (!self || connection->closed) return;
              const bool no_auth = error2 == boost::system::error_code{} &&
                                   std::any_of(offered->begin(), offered->end(),
                                               [](std::byte method) {
                                                 return method == std::byte{0x00U};
                                               });
              if (!no_auth) {
                // No acceptable method: reply 0xFF and close.
                const std::array<std::byte, 2U> reject{std::byte{0x05U},
                                                       std::byte{0xFFU}};
                boost::asio::async_write(
                    connection->socket, boost::asio::buffer(reject),
                    [weak, connection](boost::system::error_code, std::size_t) {
                      if (auto self = weak.lock()) {
                        ++connection->stats.handshakes_failed;
                        self->close_connection(connection);
                      }
                    });
                return;
              }
              const std::array<std::byte, 2U> select{std::byte{0x05U},
                                                    std::byte{0x00U}};
              boost::asio::async_write(
                  connection->socket, boost::asio::buffer(select),
                  [weak, connection](boost::system::error_code error3, std::size_t) {
                    auto self = weak.lock();
                    if (!self || connection->closed) return;
                    if (error3) {
                      ++connection->stats.handshakes_failed;
                      self->close_connection(connection);
                      return;
                    }
                    self->read_request(connection, 0U);
                  });
            });
      });
}

void SocksFrontend::State::read_request(
    const std::shared_ptr<ClientConnection>& connection, std::size_t) {
  // [VER CMD RSV ATYP ...]: read the fixed 4-byte head, then the address
  // by ATYP, then the 2-byte port.
  auto weak = weak_from_this();
  auto head = std::make_shared<std::array<std::byte, 4U>>();
  boost::asio::async_read(
      connection->socket, boost::asio::buffer(head->data(), head->size()),
      [weak, connection, head](boost::system::error_code error, std::size_t) {
        auto self = weak.lock();
        if (!self || connection->closed) return;
        if (error || (*head)[0] != std::byte{0x05U}) {
          ++connection->stats.handshakes_failed;
          self->close_connection(connection);
          return;
        }
        if ((*head)[1] != std::byte{0x01U}) {
          self->reply_and_pump(connection, socks_rep_command_not_supported);
          return;
        }
        const auto atyp = std::to_integer<std::uint8_t>((*head)[3]);
        std::size_t address_bytes = 0U;
        bool length_prefixed = false;
        if (atyp == 0x01U) {
          address_bytes = 4U;
        } else if (atyp == 0x03U) {
          length_prefixed = true;
        } else if (atyp == 0x04U) {
          address_bytes = 16U;
        } else {
          self->reply_and_pump(connection, socks_rep_address_not_supported);
          return;
        }
        const auto read_address = [weak, connection, atyp](
                                      std::vector<std::byte> address,
                                      bool ok) {
          auto self = weak.lock();
          if (!self || connection->closed) return;
          if (!ok) {
            ++connection->stats.handshakes_failed;
            self->close_connection(connection);
            return;
          }
          // Trailing 2-byte port.
          auto port_bytes = std::make_shared<std::array<std::byte, 2U>>();
          boost::asio::async_read(
              connection->socket,
              boost::asio::buffer(port_bytes->data(), port_bytes->size()),
              [weak, connection, atyp, address = std::move(address),
               port_bytes](boost::system::error_code error2, std::size_t) mutable {
                auto self = weak.lock();
                if (!self || connection->closed) return;
                if (error2) {
                  ++connection->stats.handshakes_failed;
                  self->close_connection(connection);
                  return;
                }
                GatewayConnect target;
                if (atyp == 0x03U) {
                  // Domain: pass through VERBATIM (design 4.3) — no local
                  // resolution, the serving side resolves in its context.
                  const auto length = std::to_integer<std::size_t>(address[0]);
                  target.host.assign(
                      reinterpret_cast<const char*>(address.data() + 1), length);
                } else {
                  // Binary address literal: build GatewayIp directly.
                  GatewayIp ip;
                  ip.v4 = atyp == 0x01U;
                  const auto width = ip.v4 ? 4U : 16U;
                  if (address.size() < width) {
                    ++connection->stats.handshakes_failed;
                    self->close_connection(connection);
                    return;
                  }
                  std::copy_n(address.begin(), width, ip.bytes.begin());
                  target.host = format_gateway_ip(ip);
                }
                target.port = static_cast<std::uint16_t>(
                    (std::to_integer<unsigned>(port_bytes->at(0)) << 8U) |
                    std::to_integer<unsigned>(port_bytes->at(1)));
                target.profile = self->config.profile;
                self->open_tunnel(connection, std::move(target));
              });
        };
        if (length_prefixed) {
          auto length_byte = std::make_shared<std::byte>();
          boost::asio::async_read(
              connection->socket, boost::asio::buffer(length_byte.get(), 1U),
              [weak, connection, read_address, length_byte](
                  boost::system::error_code error2, std::size_t) {
                auto self = weak.lock();
                if (!self || connection->closed || error2) {
                  read_address({}, false);
                  return;
                }
                const auto length = std::to_integer<std::size_t>(*length_byte);
                auto domain = std::make_shared<std::vector<std::byte>>(1U + length);
                (*domain)[0] = *length_byte;
                boost::asio::async_read(
                    connection->socket,
                    boost::asio::buffer(domain->data() + 1, length),
                    [weak, connection, read_address, domain](
                        boost::system::error_code error3, std::size_t) {
                      auto self = weak.lock();
                      if (!self || connection->closed || error3) {
                        read_address({}, false);
                        return;
                      }
                      read_address(std::move(*domain), true);
                    });
              });
          return;
        }
        auto address = std::make_shared<std::vector<std::byte>>(address_bytes);
        boost::asio::async_read(
            connection->socket, boost::asio::buffer(address->data(), address_bytes),
            [weak, read_address, address](boost::system::error_code error2,
                                          std::size_t) {
              if (error2) {
                read_address({}, false);
                return;
              }
              read_address(std::move(*address), true);
            });
      });
}

void SocksFrontend::State::open_tunnel(const std::shared_ptr<ClientConnection>& connection,
                                       GatewayConnect target) {
  // The Node API posts onto the node context and waits bounded. The
  // runtime's Asio context runs on a single worker that also serves this
  // frontend strand, so calling it inline would self-deadlock until the
  // bounded wait expired. Dispatch the blocking open onto the executor's
  // general pool (separate threads); the result comes back on our strand.
  const auto weak = weak_from_this();
  auto* node_ptr = &node;
  const auto peer_key = peer;
  const auto deadline_budget =
      static_cast<std::uint64_t>(config.connect_deadline.count());
  GatewayConnect request = std::move(target);
  request.profile = config.profile;
  const auto dispatched = detail::RuntimeAccess::dispatch_general(
      runtime, "socks-gateway-open",
      [weak, connection, node_ptr, peer_key, request = std::move(request),
       deadline_budget]() mutable {
        NodeGatewayStreamOptions options;
        options.dial_deadline_unix_milliseconds =
            unix_milliseconds_now() + deadline_budget;
        options.on_connected = [weak, connection](Result<void> outcome) {
          auto self = weak.lock();
          if (!self || connection->closed) return;
          boost::asio::post(self->strand,
                            [weak, connection, outcome = std::move(outcome)]() {
                              auto self = weak.lock();
                              if (!self || connection->closed) return;
                              if (outcome) {
                                ++connection->stats.connects_succeeded;
                                self->reply_and_pump(connection,
                                                     socks_rep_succeeded);
                              } else {
                                ++connection->stats.connects_failed;
                                self->reply_and_pump(connection,
                                                     socks_rep_general_failure);
                              }
                            });
        };
        auto opened = node_ptr->open_gateway_stream(peer_key, request, options);
        if (opened) {
          // The stream handle moves into the connection on the frontend
          // strand (its facade marshals ops onto the node context from
          // any thread).
          auto stream = std::make_shared<ByteStream>(std::move(*opened.value_if()));
          auto self = weak.lock();
          if (!self) return;
          boost::asio::post(self->strand, [weak, connection, stream] {
            auto self = weak.lock();
            if (!self || connection->closed) return;
            connection->stream = std::move(*stream);
          });
          return;
        }
        auto self = weak.lock();
        if (!self) return;
        boost::asio::post(self->strand, [weak, connection] {
          auto self = weak.lock();
          if (!self || connection->closed) return;
          ++connection->stats.connects_failed;
          self->reply_and_pump(connection, socks_rep_general_failure);
        });
      });
  if (!dispatched) {
    ++stats.connects_failed;
    reply_and_pump(connection, socks_rep_general_failure);
  }
}

void SocksFrontend::State::reply_and_pump(
    const std::shared_ptr<ClientConnection>& connection, std::uint8_t rep) {
  auto weak = weak_from_this();
  const auto reply = std::make_shared<std::array<std::byte, 10U>>(socks_reply(rep));
  boost::asio::async_write(
      connection->socket, boost::asio::buffer(reply->data(), reply->size()),
      [weak, connection, reply, ok = rep == socks_rep_succeeded](
          boost::system::error_code error, std::size_t) {
        auto self = weak.lock();
        if (!self || connection->closed) return;
        if (error || !ok) {
          self->close_connection(connection);
          return;
        }
        self->pump_client_to_tunnel(connection);
        self->pump_tunnel_to_client(connection);
      });
}

void SocksFrontend::State::pump_client_to_tunnel(
    const std::shared_ptr<ClientConnection>& connection) {
  if (connection->closed) return;
  auto buffer = std::make_shared<std::vector<std::byte>>(socks_chunk_bytes);
  connection->socket.async_read_some(
      boost::asio::buffer(buffer->data(), buffer->size()),
      [weak = weak_from_this(), connection, buffer](
          boost::system::error_code error, std::size_t bytes) {
        auto self = weak.lock();
        if (!self || connection->closed) return;
        if (error == boost::asio::error::eof) {
          // Client half-closed: propagate to the tunnel.
          if (connection->stream.has_value()) {
            (void)connection->stream->shutdown_write();
          }
          return;
        }
        if (error || bytes == 0U) {
          self->close_connection(connection);
          return;
        }
        connection->stats.bytes_from_clients += bytes;
        // The public facade marshals the write onto the node context.
        if (!connection->stream.has_value()) {
          self->close_connection(connection);
          return;
        }
        connection->stream->async_write(
            std::span<const std::byte>{buffer->data(), bytes},
            [weak, connection, buffer](ByteStreamIoResult) {
              // The write task marshals to the node context with the span
              // as-is (public contract: buffers stay valid until the
              // handler fires), so the chunk must live here; completion
              // arrives on the node context — hop back onto the frontend
              // strand before touching the socket again.
              auto self = weak.lock();
              if (!self) return;
              boost::asio::post(self->strand, [weak, connection] {
                if (auto self = weak.lock()) {
                  self->pump_client_to_tunnel(connection);
                }
              });
            });
      });
}

void SocksFrontend::State::pump_tunnel_to_client(
    const std::shared_ptr<ClientConnection>& connection) {
  if (connection->closed) return;
  if (!connection->stream.has_value()) {
    close_connection(connection);
    return;
  }
  auto buffer = std::make_shared<std::vector<std::byte>>(socks_chunk_bytes);
  connection->stream->async_read_some(
      std::span<std::byte>{buffer->data(), buffer->size()},
      [weak = weak_from_this(), connection, buffer](ByteStreamIoResult result) {
        auto self = weak.lock();
        if (!self || connection->closed) return;
        if (result.error.has_value()) {
          self->close_connection(connection);
          return;
        }
        if (result.bytes == 0U) {
          // Tunnel half-closed: propagate EOF to the client.
          boost::asio::post(self->strand, [connection] {
            boost::system::error_code ignored;
            connection->socket.shutdown(
                boost::asio::ip::tcp::socket::shutdown_send, ignored);
          });
          return;
        }
        connection->stats.bytes_to_clients += result.bytes;
        boost::asio::post(self->strand, [weak, connection, buffer,
                                         total = result.bytes] {
          auto self = weak.lock();
          if (!self || connection->closed) return;
          boost::asio::async_write(
              connection->socket,
              boost::asio::buffer(buffer->data(), total),
              [weak, connection](boost::system::error_code error, std::size_t) {
                auto self = weak.lock();
                if (!self || connection->closed) return;
                if (error) {
                  self->close_connection(connection);
                  return;
                }
                self->pump_tunnel_to_client(connection);
              });
        });
      });
}

void SocksFrontend::State::close_connection(
    const std::shared_ptr<ClientConnection>& connection) {
  if (connection->closed) return;
  connection->closed = true;
  boost::system::error_code ignored;
  connection->socket.close(ignored);
  if (connection->stream.has_value()) {
      connection->stream->reset(StableStatus::cancelled);
    }
  std::erase(connections, connection);
  stats.connections_active = connections.size();
}

Result<std::shared_ptr<SocksFrontend>> SocksFrontend::create(
    Node& node, Runtime& runtime, DeviceEndpointKey peer,
    SocksFrontendConfig config) {
  auto executor = detail::RuntimeAccess::io_executor(runtime);
  if (!executor) {
    return Result<std::shared_ptr<SocksFrontend>>::failure(*executor.error_if());
  }
  if (config.max_concurrent_connections == 0U) {
    return Result<std::shared_ptr<SocksFrontend>>::failure(
        socks_error(ErrorCode::configuration, "socks_capacity_invalid"));
  }
  boost::system::error_code address_error;
  const auto address =
      boost::asio::ip::make_address(config.bind_address, address_error);
  if (address_error || address.is_multicast()) {
    return Result<std::shared_ptr<SocksFrontend>>::failure(
        socks_error(ErrorCode::configuration, "socks_bind_invalid"));
  }
  return Result<std::shared_ptr<SocksFrontend>>::success(
      std::shared_ptr<SocksFrontend>(new SocksFrontend(
          node, runtime, std::move(peer), std::move(config),
          *executor.value_if())));
}

SocksFrontend::SocksFrontend(Node& node, Runtime& runtime, DeviceEndpointKey peer,
                             SocksFrontendConfig config,
                             boost::asio::any_io_executor executor)
    : state_(std::make_shared<State>(node, runtime, std::move(peer),
                                     std::move(config), std::move(executor))) {}

SocksFrontend::~SocksFrontend() { stop(); }

Result<void> SocksFrontend::start() {
  if (state_->stats.listening) {
    return Result<void>::success();
  }
  boost::system::error_code open_error;
  const auto endpoint = boost::asio::ip::tcp::endpoint{
      boost::asio::ip::make_address(state_->config.bind_address, open_error),
      state_->config.port};
  state_->acceptor.open(endpoint.protocol(), open_error);
  if (open_error) {
    return Result<void>::failure(
        socks_error(ErrorCode::transport, "socks_open_failed"));
  }
  state_->acceptor.set_option(boost::asio::socket_base::reuse_address(true),
                              open_error);
  state_->acceptor.bind(endpoint, open_error);
  if (open_error) {
    return Result<void>::failure(
        socks_error(ErrorCode::transport, "socks_bind_failed"));
  }
  state_->acceptor.listen(boost::asio::socket_base::max_listen_connections,
                          open_error);
  if (open_error) {
    return Result<void>::failure(
        socks_error(ErrorCode::transport, "socks_listen_failed"));
  }
  state_->stats.bound_port = state_->acceptor.local_endpoint(open_error).port();
  state_->stats.listening = true;
  state_->start_accept();
  return Result<void>::success();
}

void SocksFrontend::stop() {
  auto state = state_;
  if (!state) return;
  boost::asio::post(state->strand, [state] {
    state->stopping = true;
    boost::system::error_code ignored;
    state->acceptor.close(ignored);
    for (const auto& connection : state->connections) {
      connection->closed = true;
      connection->socket.close(ignored);
      if (connection->stream.has_value()) {
      connection->stream->reset(StableStatus::cancelled);
    }
    }
    state->connections.clear();
    state->stats.connections_active = 0U;
    state->stats.listening = false;
  });
}

SocksFrontendStats SocksFrontend::stats() const {
  // The counters live on the frontend strand; snapshot them there (bounded
  // wait, inlining when already on the strand) so off-thread callers never
  // read torn values.
  auto state = state_;
  if (!state) return {};
  if (state->strand.running_in_this_thread()) {
    return state->stats;
  }
  auto promise = std::make_shared<std::promise<SocksFrontendStats>>();
  auto future = promise->get_future();
  try {
    boost::asio::post(state->strand, [state, promise] {
      promise->set_value(state->stats);
    });
  } catch (...) {
    return {};
  }
  if (future.wait_for(std::chrono::seconds{1}) != std::future_status::ready) {
    return {};
  }
  return future.get();
}

}  // namespace heyaki::socks
