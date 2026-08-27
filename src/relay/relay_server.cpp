#include "relay_server.hpp"

#include "client/runtime_access.hpp"
#include "relay_enrollment_service.hpp"
#include "relay_endpoint.hpp"
#include "relay_endpoint_directory.hpp"
#include "relay_lease_table.hpp"
#include "relay_login_service.hpp"

#include <heyaki/lan_protocol.hpp>
#include <heyaki/relay_wss_control.hpp>
#include <heyaki/signaling_protocol.hpp>

#include <executor/comm.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/core/buffers_to_string.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/websocket.hpp>

#include <openssl/ssl.h>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <deque>
#include <cstdint>
#include <future>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>

#include <csignal>

namespace heyaki {

using boost::asio::ip::tcp;

Error relay_error(ErrorCode code, const char* detail,
                  std::optional<std::int64_t> underlying = std::nullopt) {
  return Error{code, "relay", detail, underlying};
}

std::uint64_t unix_milliseconds_now() noexcept {
  const auto count = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
  return count > 0 ? static_cast<std::uint64_t>(count) : 0U;
}

Result<std::string> tenant_rate_key(std::string_view tenant) {
  std::array<unsigned char, crypto_hash_sha256_BYTES> digest{};
  if (crypto_hash_sha256(
          digest.data(), reinterpret_cast<const unsigned char*>(tenant.data()),
          static_cast<unsigned long long>(tenant.size())) != 0) {
    return Result<std::string>::failure(
        relay_error(ErrorCode::internal, "tenant_rate_key_failed"));
  }
  static constexpr char hex[] = "0123456789abcdef";
  std::string output(digest.size() * 2U, '0');
  for (std::size_t index = 0U; index < digest.size(); ++index) {
    output[index * 2U] = hex[digest[index] >> 4U];
    output[index * 2U + 1U] = hex[digest[index] & 0x0fU];
  }
  return Result<std::string>::success(std::move(output));
}

bool is_shutting_down(RelayServerState state) noexcept {
  return state == RelayServerState::draining || state == RelayServerState::stopped;
}

class RelaySession;

struct RelayServer::Impl : std::enable_shared_from_this<RelayServer::Impl> {
  Impl(RelayServerConfig config_value, std::shared_ptr<Runtime> owned_value,
       Runtime* runtime_value, boost::asio::any_io_executor executor)
      : config(std::move(config_value)),
        owned_runtime(std::move(owned_value)),
        runtime(runtime_value),
        strand(boost::asio::make_strand(std::move(executor))),
        tls_context(boost::asio::ssl::context::tls_server),
        acceptor(strand),
        signals(strand),
        sweep_timer(strand),
        snapshots("heyaki-relay-snapshots"),
        connection_capacity(config.max_connections) {
    current.state = RelayServerState::starting;
    current.listen_address = config.listen_address;
    current.connection_capacity = config.max_connections;
    published_state = current.state;
    published_stop_requested = current.stop_requested;
    publish();
  }

  ~Impl() {
    if (owned_runtime) {
      (void)owned_runtime->shutdown();
    }
  }

  Result<void> initialize();
  Result<void> register_lifecycle();
  void begin();
  void start_accept();
  void schedule_sweep();
  void on_accept(boost::system::error_code error, tcp::socket socket);
  void on_session_finished(const std::shared_ptr<RelaySession>& session,
                           bool handshake_timeout, bool handshake_error,
                           bool protocol_rejected);
  void session_send_health(const std::shared_ptr<RelaySession>& session);
  void session_start_control(const std::shared_ptr<RelaySession>& session);
  void session_handle_control(const std::shared_ptr<RelaySession>& session,
                              std::span<const std::byte> payload, bool binary);
  void session_reject_policy(const std::shared_ptr<RelaySession>& session);
  Result<void> admit_control_request(const RelaySession& session,
                                     std::string_view tenant = {},
                                     bool include_base_scopes = true,
                                     const std::string* precomputed_rate_key = nullptr);
  Result<void> require_active_device(const std::shared_ptr<RelaySession>& session,
                                     std::uint64_t now_unix_milliseconds);
  void session_handle_logged_in(const std::shared_ptr<RelaySession>& session,
                                RelayWssControlType type,
                                std::span<const std::byte> payload);
  void session_cleanup(const std::shared_ptr<RelaySession>& session);
  void session_handle_heartbeat(const std::shared_ptr<RelaySession>& session,
                                std::span<const std::byte> payload);
  void session_handle_endpoint_publish(const std::shared_ptr<RelaySession>& session,
                                       std::span<const std::byte> payload);
  void session_handle_signaling_send(const std::shared_ptr<RelaySession>& session,
                                     std::span<const std::byte> payload);
  void session_handle_endpoint_query(const std::shared_ptr<RelaySession>& session,
                                     std::span<const std::byte> payload);
  Result<RuntimeShutdownCompletion> begin_shutdown();
  void finish_shutdown();
  void request_stop();
  void publish();
  void publish_last_error(Error error);
  void close_socket(tcp::socket& socket);

  RelayServerConfig config;
  std::shared_ptr<Runtime> owned_runtime;
  Runtime* runtime{nullptr};
  boost::asio::strand<boost::asio::any_io_executor> strand;
  boost::asio::ssl::context tls_context;
  tcp::acceptor acceptor;
  boost::asio::signal_set signals;
  boost::asio::steady_timer sweep_timer;
  std::optional<RelayDatabase> database;
  std::optional<RelayRateLimiter> rate_limiter;
  std::optional<RelayEnrollmentService> enrollment_service;
  std::optional<RelayLoginService> login_service;
  std::optional<RelayLeaseTable> lease_table;
  std::optional<RelayEndpointDirectory> endpoint_directory;
  RelayId relay_id{};
  executor::comm::DoubleBuffer<RelayServerSnapshot> snapshots;
  std::set<std::shared_ptr<RelaySession>> sessions;
  std::map<RelayLeaseKey, std::weak_ptr<RelaySession>> online_endpoints;
  std::promise<Result<void>> shutdown_promise;
  std::shared_future<Result<void>> shutdown_completion;
  bool shutdown_posted{false};
  bool shutdown_finished{false};
  std::atomic<bool> stop_requested{false};
  RelayServerState published_state{RelayServerState::stopped};
  bool published_stop_requested{false};
  bool publish_deferred{false};
  bool publish_pending{false};

  // Coalesces the snapshot publications of one control message into a single
  // DoubleBuffer write on message-handler exit.
  struct DeferredPublish {
    Impl& impl;
    explicit DeferredPublish(Impl& value) : impl(value) { impl.publish_deferred = true; }
    ~DeferredPublish() {
      impl.publish_deferred = false;
      if (impl.publish_pending) {
        impl.publish_pending = false;
        impl.publish();
      }
    }
  };

  std::size_t connection_capacity{};
  std::uint64_t next_connection_id{1U};
  RelayServerSnapshot current;
};

class RelaySession : public std::enable_shared_from_this<RelaySession> {
 public:
  struct ControlWriteLimits {
    std::size_t frames{64U};
    std::size_t bytes{1024U * 1024U};
  };

  RelaySession(tcp::socket socket, boost::asio::ssl::context& tls_context,
               std::shared_ptr<RelayServer::Impl> server, std::string connection_id_value,
               std::string source_ip_value, ControlWriteLimits write_limits_value)
      : websocket(std::move(socket), tls_context),
        timer(websocket.get_executor()),
        server(std::move(server)),
        connection_id(std::move(connection_id_value)),
        source_ip(std::move(source_ip_value)),
        write_limits(write_limits_value) {
    websocket.read_message_max(max_relay_wss_control_frame_bytes);
    parser.header_limit(8192U);
    parser.body_limit(0U);
  }

  void start() {
    auto owner = server.lock();
    if (!owner) {
      close_socket();
      return;
    }
    timer.expires_after(owner->config.handshake_timeout);
    timer.async_wait([self = shared_from_this()](boost::system::error_code error) {
      self->on_timeout(error);
    });
    websocket.next_layer().async_handshake(
        boost::asio::ssl::stream_base::server,
        [self = shared_from_this()](boost::system::error_code error) {
          self->on_tls_handshake(error);
        });
  }

 private:
  friend struct RelayServer::Impl;

  void on_tls_handshake(boost::system::error_code error) {
    if (error) {
      fail(false);
      return;
    }
    boost::beast::http::async_read(
        websocket.next_layer(), buffer, parser,
        [self = shared_from_this()](boost::system::error_code read_error,
                                    std::size_t /*bytes_transferred*/) {
          self->on_upgrade_request(read_error);
        });
  }

  void on_upgrade_request(boost::system::error_code error) {
    if (error) {
      fail(false);
      return;
    }
    request_path = std::string{parser.get().target()};
    websocket.async_accept(parser.get(),
                           [self = shared_from_this()](
                               boost::system::error_code accept_error) {
                             self->on_websocket_accept(accept_error);
                           });
  }

  void on_websocket_accept(boost::system::error_code error) {
    if (error) {
      fail(false);
      return;
    }
    handshake_complete = true;
    (void)timer.cancel();
    if (auto owner = server.lock()) {
      if (request_path == owner->config.health_path) {
        owner->session_send_health(shared_from_this());
      } else if (request_path == relay_wss_control_path) {
        owner->session_start_control(shared_from_this());
      } else {
        owner->session_reject_policy(shared_from_this());
      }
    } else {
      close_socket();
    }
  }

  void send_health() {
    websocket.text(true);
    websocket.async_write(
        boost::asio::buffer(response),
        [self = shared_from_this()](boost::system::error_code error,
                                    std::size_t /*bytes_transferred*/) {
          self->on_health_written(error);
        });
  }

  void on_health_written(boost::system::error_code error) {
    if (error) {
      fail(false);
      return;
    }
    websocket.async_close(
        boost::beast::websocket::close_code::normal,
        [self = shared_from_this()](boost::system::error_code close_error) {
          self->on_closed(close_error);
        });
  }

  void reject_policy() {
    websocket.async_close(
        boost::beast::websocket::close_code::policy_error,
        [self = shared_from_this()](boost::system::error_code close_error) {
          self->on_closed(close_error);
        });
  }

  void start_control() {
    websocket.binary(true);
    read_control();
  }

  void read_control() {
    websocket.async_read(
        buffer, [self = shared_from_this()](boost::system::error_code error,
                                            std::size_t /*bytes_transferred*/) {
          self->on_control_read(error);
        });
  }

  void on_control_read(boost::system::error_code error) {
    if (error) {
      if (error == boost::beast::websocket::error::closed ||
          error == boost::asio::error::operation_aborted) {
        on_closed(error);
      } else {
        fail(false);
      }
      return;
    }
    const bool binary = !websocket.got_text();
    const std::string bytes = boost::beast::buffers_to_string(buffer.data());
    buffer.consume(buffer.size());
    if (auto owner = server.lock()) {
      owner->session_handle_control(
          shared_from_this(),
          std::span<const std::byte>{reinterpret_cast<const std::byte*>(bytes.data()),
                                     bytes.size()},
          binary);
      if (!finished.load()) {
        read_control();
      }
    } else {
      close_socket();
    }
  }

  // Returns false when the per-session write watermark is exhausted; the
  // caller decides between failing the session (responses) and answering the
  // sender with endpoint_offline (forwarded signaling).
  bool send_control(RelayWssControlType type, std::span<const std::byte> payload,
                    bool close_after_write = false, bool protocol_error = false) {
    if (finished.load()) {
      return false;
    }
    auto encoded = encode_relay_wss_control_frame(type, payload);
    if (!encoded) {
      fail(false);
      return false;
    }
    if (pending_control_writes.size() >= write_limits.frames ||
        pending_control_bytes + encoded.value_if()->size() > write_limits.bytes) {
      return false;
    }
    pending_control_bytes += encoded.value_if()->size();
    pending_control_writes.push_back(PendingControlWrite{std::move(*encoded.value_if()),
                                                         close_after_write,
                                                         protocol_error});
    pump_control_writes();
    return true;
  }

  void pump_control_writes() {
    if (control_write_in_flight || pending_control_writes.empty()) {
      return;
    }
    auto entry = std::move(pending_control_writes.front());
    pending_control_writes.pop_front();
    pending_control_bytes -= entry.bytes.size();
    control_write_in_flight = true;
    control_write_closes = entry.close_after_write;
    control_write_protocol_error = entry.protocol_error;
    response_bytes = std::move(entry.bytes);
    websocket.binary(true);
    websocket.async_write(
        boost::asio::buffer(response_bytes),
        [self = shared_from_this()](boost::system::error_code error,
                                    std::size_t /*bytes_transferred*/) {
          self->on_control_written(error);
        });
  }

  void send_error(const Error& error, bool protocol_error) {
    auto payload = encode_relay_wss_control_error(error.code(), error.safe_detail());
    if (!payload) {
      fail(false);
      return;
    }
    if (!send_control(RelayWssControlType::control_error, *payload.value_if(), true,
                      protocol_error)) {
      fail(false);
    }
  }

  // Operational signaling failures answer without terminating the control session;
  // protocol misuse still closes through send_error.
  void send_signaling_error(const Error& error) {
    auto payload = encode_relay_wss_control_error(error.code(), error.safe_detail());
    if (!payload) {
      fail(false);
      return;
    }
    if (!send_control(RelayWssControlType::control_error, *payload.value_if(), false,
                      false)) {
      fail(false);
    }
  }

  void on_control_written(boost::system::error_code error) {
    control_write_in_flight = false;
    response_bytes.clear();
    if (error) {
      fail(false);
      return;
    }
    if (!control_write_closes) {
      pump_control_writes();
      return;
    }
    websocket.async_close(
        control_write_protocol_error ? boost::beast::websocket::close_code::policy_error
                                     : boost::beast::websocket::close_code::normal,
        [self = shared_from_this()](boost::system::error_code close_error) {
          self->on_control_closed(close_error);
        });
  }

  void on_control_closed(boost::system::error_code error) {
    if (finished.exchange(true)) {
      return;
    }
    close_socket();
    if (auto owner = server.lock()) {
      owner->on_session_finished(shared_from_this(), false, false,
                                 control_write_protocol_error);
    }
    (void)error;
  }

  void on_closed(boost::system::error_code /*error*/) {
    if (finished.exchange(true)) {
      return;
    }
    close_socket();
    if (auto owner = server.lock()) {
      owner->on_session_finished(shared_from_this(), false, false, false);
    }
  }

  void on_timeout(boost::system::error_code error) {
    if (error || handshake_complete) {
      return;
    }
    if (finished.exchange(true)) {
      return;
    }
    close_socket();
    if (auto owner = server.lock()) {
      owner->on_session_finished(shared_from_this(), true, false, false);
    }
  }

  void fail(bool /*unused*/) {
    if (finished.exchange(true)) {
      return;
    }
    close_socket();
    if (auto owner = server.lock()) {
      owner->on_session_finished(shared_from_this(), false, true, false);
    }
  }

  void close_socket() {
    boost::system::error_code ignored;
    auto& lowest = boost::beast::get_lowest_layer(websocket);
    lowest.socket().shutdown(tcp::socket::shutdown_both, ignored);
    lowest.socket().close(ignored);
  }

  boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>>
      websocket;
  boost::beast::flat_buffer buffer;
  boost::beast::http::request_parser<boost::beast::http::empty_body> parser;
  boost::asio::steady_timer timer;
  std::weak_ptr<RelayServer::Impl> server;
  std::string request_path;
  std::string response{"ok\n"};
  std::vector<std::byte> response_bytes;
  std::string connection_id;
  std::string source_ip;
  enum class ControlState : std::uint8_t {
    awaiting_challenge,
    awaiting_enrollment,
    awaiting_login,
    enrolled,
    logged_in,
  };
  enum class PendingChallengeKind : std::uint8_t {
    none,
    enrollment,
    login,
  };
  ControlState control_state{ControlState::awaiting_challenge};
  PendingChallengeKind challenge_kind{PendingChallengeKind::none};
  std::optional<EnrollmentChallengeNonce> control_challenge_nonce;
  std::optional<DeviceId> logged_in_device_id;
  std::optional<EndpointId> logged_in_endpoint_id;
  std::string logged_in_tenant;
  // SHA-256 rate-limit key of the logged-in tenant, computed once at login
  // instead of on every admitted control message.
  std::optional<std::string> logged_in_rate_key;
  std::uint64_t logged_in_generation{};
  std::chrono::steady_clock::time_point signaling_window_start{};
  std::size_t signaling_window_count{};
  bool handshake_complete{false};
  std::atomic<bool> finished{false};

  // Serialized control writes: server-initiated pushes (forwarded signaling) may arrive
  // while a response write is in flight, so writes queue instead of assuming one
  // request-response pair at a time. The queue is bounded by ControlWriteLimits.
  struct PendingControlWrite {
    std::vector<std::byte> bytes;
    bool close_after_write{false};
    bool protocol_error{false};
  };
  std::deque<PendingControlWrite> pending_control_writes;
  std::size_t pending_control_bytes{0};
  ControlWriteLimits write_limits;
  bool control_write_in_flight{false};
  bool control_write_closes{false};
  bool control_write_protocol_error{false};
};

Result<void> RelayServer::Impl::initialize() {
  boost::system::error_code error;
  tls_context.set_options(
      boost::asio::ssl::context::default_workarounds |
          boost::asio::ssl::context::no_sslv2 |
          boost::asio::ssl::context::no_sslv3 |
          boost::asio::ssl::context::no_tlsv1 |
          boost::asio::ssl::context::no_tlsv1_1 |
          boost::asio::ssl::context::no_tlsv1_2,
      error);
  if (error) {
    return Result<void>::failure(relay_error(ErrorCode::configuration,
                                             "relay_tls_configuration_failed",
                                             error.value()));
  }
  tls_context.use_certificate_chain_file(config.tls_certificate_file.string(), error);
  if (error) {
    return Result<void>::failure(relay_error(ErrorCode::configuration,
                                             "relay_tls_certificate_load_failed",
                                             error.value()));
  }
  tls_context.use_private_key_file(config.tls_private_key_file.string(),
                                   boost::asio::ssl::context::pem, error);
  if (error) {
    return Result<void>::failure(relay_error(ErrorCode::configuration,
                                             "relay_tls_private_key_load_failed",
                                             error.value()));
  }
  if (SSL_CTX_set_min_proto_version(tls_context.native_handle(), TLS1_3_VERSION) != 1) {
    return Result<void>::failure(relay_error(ErrorCode::configuration,
                                             "relay_tls13_required"));
  }

  const auto address = boost::asio::ip::make_address(config.listen_address, error);
  if (error) {
    return Result<void>::failure(relay_error(ErrorCode::configuration,
                                             "relay_listen_address_invalid",
                                             error.value()));
  }
  tcp::endpoint endpoint{address, config.listen_port};
  acceptor.open(endpoint.protocol(), error);
  if (error) {
    return Result<void>::failure(relay_error(ErrorCode::transport,
                                             "relay_listener_open_failed",
                                             error.value()));
  }
  acceptor.set_option(tcp::acceptor::reuse_address(true), error);
  if (error) {
    return Result<void>::failure(relay_error(ErrorCode::transport,
                                             "relay_listener_option_failed",
                                             error.value()));
  }
  acceptor.bind(endpoint, error);
  if (error) {
    return Result<void>::failure(relay_error(ErrorCode::transport,
                                             "relay_listener_bind_failed",
                                             error.value()));
  }
  acceptor.listen(boost::asio::socket_base::max_listen_connections, error);
  if (error) {
    return Result<void>::failure(relay_error(ErrorCode::transport,
                                             "relay_listener_listen_failed",
                                             error.value()));
  }

  const auto local = acceptor.local_endpoint(error);
  if (!error) {
    current.listen_address = local.address().to_string();
    current.listen_port = local.port();
  }

  if (config.database_file == ":memory:") {
    auto memory_database = RelayDatabase::open(":memory:");
    if (!memory_database) {
      return Result<void>::failure(*memory_database.error_if());
    }
    database.emplace(std::move(*memory_database.value_if()));
    current.database = database->cached_snapshot();
  } else {
    auto file_database = RelayDatabase::open(config.database_file);
    if (!file_database) {
      return Result<void>::failure(*file_database.error_if());
    }
    database.emplace(std::move(*file_database.value_if()));
    current.database = database->cached_snapshot();
  }
  auto limits = RelayRateLimiter::create(config.rate_limits);
  if (!limits) {
    return Result<void>::failure(*limits.error_if());
  }
  rate_limiter.emplace(std::move(*limits.value_if()));
  current.rate_limits = rate_limiter->diagnostics();

  X509* certificate = SSL_CTX_get0_certificate(tls_context.native_handle());
  unsigned int relay_id_size = 0U;
  if (certificate == nullptr ||
      X509_digest(certificate, EVP_sha256(),
                  reinterpret_cast<unsigned char*>(relay_id.data()),
                  &relay_id_size) != 1 ||
      relay_id_size != relay_id.size() || relay_id == RelayId{}) {
    return Result<void>::failure(relay_error(ErrorCode::configuration,
                                             "relay_id_derivation_failed"));
  }
  auto enrollment = RelayEnrollmentService::create(&*database, relay_id);
  if (!enrollment) {
    return Result<void>::failure(*enrollment.error_if());
  }
  enrollment_service.emplace(std::move(*enrollment.value_if()));

  auto login = RelayLoginService::create(&*database, relay_id);
  if (!login) {
    return Result<void>::failure(*login.error_if());
  }
  login_service.emplace(std::move(*login.value_if()));

  auto leases = RelayLeaseTable::create(config.lease);
  if (!leases) {
    return Result<void>::failure(*leases.error_if());
  }
  lease_table.emplace(std::move(*leases.value_if()));

  auto endpoints = RelayEndpointDirectory::create(config.endpoint_directory);
  if (!endpoints) {
    return Result<void>::failure(*endpoints.error_if());
  }
  endpoint_directory.emplace(std::move(*endpoints.value_if()));
  current.leases = lease_table->diagnostics();
  current.endpoints = endpoint_directory->diagnostics();

  if (config.install_signal_handlers) {
    signals.add(SIGINT, error);
    if (!error) {
#ifndef _WIN32
      signals.add(SIGTERM, error);
#endif
    }
    if (error) {
      return Result<void>::failure(relay_error(ErrorCode::configuration,
                                               "relay_signal_registration_failed",
                                               error.value()));
    }
  }
  return Result<void>::success();
}

Result<void> RelayServer::Impl::register_lifecycle() {
  auto weak = std::weak_ptr<RelayServer::Impl>{shared_from_this()};
  return runtime->register_shutdown_hook(RuntimeShutdownHook{
      .stage = RuntimeShutdownStage::stop_producers,
      .name = "relay-server",
      .begin = [weak]() -> Result<RuntimeShutdownCompletion> {
        auto self = weak.lock();
        if (!self) {
          return Result<RuntimeShutdownCompletion>::failure(
              relay_error(ErrorCode::cancelled, "relay_server_unavailable"));
        }
        return self->begin_shutdown();
      }});
}

void RelayServer::Impl::begin() {
  if (is_shutting_down(current.state)) {
    return;
  }
  current.state = RelayServerState::running;
  publish();

  if (config.install_signal_handlers) {
    signals.async_wait([weak = weak_from_this()](boost::system::error_code error,
                                                 int /*signal_number*/) {
      if (error) {
        return;
      }
      if (auto self = weak.lock()) {
        self->request_stop();
      }
    });
  }
  schedule_sweep();
  start_accept();
}

// Periodic expiry for the lease table and endpoint directory so per-message
// handlers never run full-table scans; lookups still filter by expiry time, so
// correctness does not depend on this cadence.
void RelayServer::Impl::schedule_sweep() {
  if (is_shutting_down(current.state)) {
    return;
  }
  sweep_timer.expires_after(std::chrono::milliseconds{1000});
  auto weak = weak_from_this();
  sweep_timer.async_wait([weak](const boost::system::error_code& error) {
    if (!error) {
      if (auto self = weak.lock()) {
        const auto now = std::chrono::steady_clock::now();
        if (self->lease_table) {
          self->lease_table->expire(now);
          self->current.leases = self->lease_table->diagnostics();
        }
        if (self->endpoint_directory) {
          self->endpoint_directory->expire(now);
          self->current.endpoints = self->endpoint_directory->diagnostics();
        }
        self->publish();
        self->schedule_sweep();
      }
    }
  });
}

void RelayServer::Impl::start_accept() {
  if (is_shutting_down(current.state)) {
    return;
  }
  acceptor.async_accept(
      strand,
      [weak = weak_from_this()](boost::system::error_code error, tcp::socket socket) {
        if (auto self = weak.lock()) {
          self->on_accept(error, std::move(socket));
        }
      });
}

void RelayServer::Impl::on_accept(boost::system::error_code error,
                                  tcp::socket socket) {
  if (is_shutting_down(current.state)) {
    if (socket.is_open()) {
      close_socket(socket);
    }
    return;
  }
  if (error) {
    if (error != boost::asio::error::operation_aborted) {
      publish_last_error(relay_error(ErrorCode::transport,
                                     "relay_accept_failed", error.value()));
    }
    return;
  }

  ++current.tcp_accepted;
  if (sessions.size() >= connection_capacity) {
    ++current.capacity_rejected;
    close_socket(socket);
    publish();
    start_accept();
    return;
  }

  boost::system::error_code endpoint_error;
  const auto remote = socket.remote_endpoint(endpoint_error);
  const std::string source_ip = endpoint_error ? "unknown" : remote.address().to_string();
  const std::string connection_id = std::to_string(next_connection_id++);
  auto session = std::make_shared<RelaySession>(
      std::move(socket), tls_context, shared_from_this(), connection_id, source_ip,
      RelaySession::ControlWriteLimits{config.control_write_queue_frames,
                                       config.control_write_queue_bytes});
  sessions.insert(session);
  current.active_sessions = sessions.size();
  publish();
  session->start();
  start_accept();
}

void RelayServer::Impl::on_session_finished(
    const std::shared_ptr<RelaySession>& session, bool handshake_timeout,
    bool handshake_error, bool protocol_rejected) {
  session_cleanup(session);
  const auto erased = sessions.erase(session);
  if (erased == 0U) {
    return;
  }
  if (handshake_timeout) {
    ++current.handshake_timeouts;
  } else if (handshake_error) {
    ++current.handshake_failed;
  } else if (protocol_rejected) {
    ++current.protocol_rejected;
  }
  current.active_sessions = sessions.size();
  publish();
}

void RelayServer::Impl::session_send_health(
    const std::shared_ptr<RelaySession>& session) {
  ++current.health_checks;
  ++current.websocket_accepted;
  publish();
  session->send_health();
}

void RelayServer::Impl::session_start_control(
    const std::shared_ptr<RelaySession>& session) {
  ++current.websocket_accepted;
  ++current.control_sessions;
  publish();
  session->start_control();
}

Result<void> RelayServer::Impl::admit_control_request(
    const RelaySession& session, std::string_view tenant,
    bool include_base_scopes, const std::string* precomputed_rate_key) {
  if (!rate_limiter) {
    return Result<void>::failure(
        relay_error(ErrorCode::cancelled, "relay_rate_limiter_unavailable"));
  }
  auto admitted = Result<void>::success();
  if (include_base_scopes) {
    auto connection_admitted =
        rate_limiter->check_connection(session.connection_id);
    auto request_admitted = rate_limiter->check_request();
    auto ip_admitted = rate_limiter->check_ip(session.source_ip);
    if (!connection_admitted) {
      admitted = Result<void>::failure(*connection_admitted.error_if());
    } else if (!request_admitted) {
      admitted = Result<void>::failure(*request_admitted.error_if());
    } else if (!ip_admitted) {
      admitted = Result<void>::failure(*ip_admitted.error_if());
    }
  }
  if (admitted && !tenant.empty()) {
    if (precomputed_rate_key != nullptr) {
      admitted = rate_limiter->check_tenant(*precomputed_rate_key);
    } else {
      auto key = tenant_rate_key(tenant);
      if (!key) {
        admitted = Result<void>::failure(*key.error_if());
      } else {
        admitted = rate_limiter->check_tenant(*key.value_if());
      }
    }
  }
  current.rate_limits = rate_limiter->diagnostics();
  if (!admitted) {
    ++current.control_rejected;
  }
  publish();
  return admitted;
}

void RelayServer::Impl::session_handle_control(
    const std::shared_ptr<RelaySession>& session, std::span<const std::byte> payload,
    bool binary) {
  DeferredPublish deferred_publish{*this};
  auto admitted = admit_control_request(*session);
  if (!admitted) {
    session->send_error(*admitted.error_if(), false);
    return;
  }
  if (!binary) {
    ++current.control_rejected;
    publish();
    session->send_error(
        relay_error(ErrorCode::protocol, "relay_control_binary_required"), true);
    return;
  }
  auto frame = parse_relay_wss_control_frame(payload);
  if (!frame) {
    ++current.control_rejected;
    publish();
    session->send_error(*frame.error_if(), true);
    return;
  }
  const auto type = frame.value_if()->type;

  if (session->control_state == RelaySession::ControlState::awaiting_challenge) {
    const bool enrollment_challenge =
        type == RelayWssControlType::enrollment_challenge;
    const bool login_challenge = type == RelayWssControlType::login_challenge;
    if ((!enrollment_challenge && !login_challenge) ||
        !frame.value_if()->payload.empty()) {
      ++current.control_rejected;
      publish();
      session->send_error(
          relay_error(ErrorCode::protocol, "relay_control_challenge_request_invalid"), true);
      return;
    }

    Result<std::vector<std::byte>> challenge =
        Result<std::vector<std::byte>>::failure(
            relay_error(ErrorCode::cancelled, "relay_challenge_service_unavailable"));
    if (enrollment_challenge && enrollment_service) {
      challenge = enrollment_service->begin_challenge(unix_milliseconds_now());
    } else if (login_challenge && login_service) {
      challenge = login_service->begin_challenge(unix_milliseconds_now());
    }
    if (!challenge) {
      ++current.control_rejected;
      publish();
      session->send_error(*challenge.error_if(), false);
      return;
    }
    auto parsed_challenge = parse_enrollment_challenge(*challenge.value_if());
    if (!parsed_challenge) {
      ++current.control_rejected;
      publish();
      session->send_error(
          relay_error(ErrorCode::internal, "relay_challenge_encoding_failed"), false);
      return;
    }
    session->control_challenge_nonce = parsed_challenge.value_if()->nonce;
    if (enrollment_challenge) {
      session->challenge_kind = RelaySession::PendingChallengeKind::enrollment;
      session->control_state = RelaySession::ControlState::awaiting_enrollment;
      ++current.enrollment_challenges;
    } else {
      session->challenge_kind = RelaySession::PendingChallengeKind::login;
      session->control_state = RelaySession::ControlState::awaiting_login;
      ++current.login_challenges;
    }
    current.enrollment = enrollment_service
                             ? enrollment_service->diagnostics()
                             : RelayEnrollmentServiceDiagnostics{};
    current.login = login_service ? login_service->diagnostics()
                                  : RelayLoginServiceDiagnostics{};
    publish();
    if (!session->send_control(
            enrollment_challenge ? RelayWssControlType::enrollment_challenge_response
                                 : RelayWssControlType::login_challenge_response,
            *challenge.value_if())) {
      session->fail(false);
    }
    return;
  }

  if (session->control_state == RelaySession::ControlState::awaiting_enrollment) {
    if (type != RelayWssControlType::enrollment_request) {
      ++current.control_rejected;
      publish();
      session->send_error(
          relay_error(ErrorCode::protocol, "enrollment_request_expected"), true);
      return;
    }
    auto parsed = parse_enrollment_request(frame.value_if()->payload);
    if (!parsed) {
      ++current.control_rejected;
      publish();
      session->send_error(*parsed.error_if(), true);
      return;
    }
    if (session->challenge_kind != RelaySession::PendingChallengeKind::enrollment ||
        !session->control_challenge_nonce ||
        parsed.value_if()->challenge_nonce != *session->control_challenge_nonce) {
      ++current.control_rejected;
      publish();
      session->send_error(
          relay_error(ErrorCode::authentication,
                      "enrollment_challenge_session_mismatch"),
          false);
      return;
    }
    auto tenant_admitted =
        admit_control_request(*session, parsed.value_if()->tenant, false);
    if (!tenant_admitted) {
      session->send_error(*tenant_admitted.error_if(), false);
      return;
    }
    auto completed =
        enrollment_service->complete(frame.value_if()->payload, unix_milliseconds_now());
    if (!completed) {
      ++current.control_rejected;
      current.database = database->cached_snapshot();
      current.enrollment =
          enrollment_service->diagnostics();
      publish();
      session->send_error(*completed.error_if(), false);
      return;
    }
    RelayWssEnrollmentResult result{
        .tenant = completed.value_if()->tenant,
        .enrollment_generation = completed.value_if()->enrollment_generation,
        .token_remaining_uses_after =
            completed.value_if()->token_remaining_uses_after.value_or(0U)};
    auto encoded = encode_relay_wss_enrollment_result(result);
    if (!encoded) {
      ++current.control_rejected;
      publish();
      session->send_error(*encoded.error_if(), false);
      return;
    }
    session->control_state = RelaySession::ControlState::enrolled;
    session->challenge_kind = RelaySession::PendingChallengeKind::none;
    session->control_challenge_nonce.reset();
    ++current.enrollments_completed;
    current.database = database->cached_snapshot();
    current.enrollment = enrollment_service->diagnostics();
    publish();
    if (!session->send_control(RelayWssControlType::enrollment_result,
                               *encoded.value_if())) {
      session->fail(false);
    }
    return;
  }

  if (session->control_state == RelaySession::ControlState::awaiting_login) {
    if (type != RelayWssControlType::login_request) {
      ++current.control_rejected;
      publish();
      session->send_error(relay_error(ErrorCode::protocol, "login_request_expected"),
                          true);
      return;
    }
    auto parsed = parse_relay_login_request(frame.value_if()->payload);
    if (!parsed) {
      ++current.control_rejected;
      publish();
      session->send_error(*parsed.error_if(), true);
      return;
    }
    if (session->challenge_kind != RelaySession::PendingChallengeKind::login ||
        !session->control_challenge_nonce ||
        parsed.value_if()->challenge_nonce != *session->control_challenge_nonce) {
      ++current.control_rejected;
      publish();
      session->send_error(
          relay_error(ErrorCode::authentication, "login_challenge_session_mismatch"),
          false);
      return;
    }
    auto tenant_admitted =
        admit_control_request(*session, parsed.value_if()->tenant, false);
    if (!tenant_admitted) {
      session->send_error(*tenant_admitted.error_if(), false);
      return;
    }
    auto authenticated = login_service->authenticate(frame.value_if()->payload,
                                                     unix_milliseconds_now());
    if (!authenticated) {
      ++current.control_rejected;
      current.database = database->cached_snapshot();
      current.login = login_service->diagnostics();
      publish();
      session->send_error(*authenticated.error_if(), false);
      return;
    }
    session->control_state = RelaySession::ControlState::logged_in;
    session->challenge_kind = RelaySession::PendingChallengeKind::none;
    session->control_challenge_nonce.reset();
    session->logged_in_device_id = authenticated.value_if()->device_id;
    session->logged_in_endpoint_id = authenticated.value_if()->endpoint_id;
    session->logged_in_tenant = authenticated.value_if()->tenant;
    auto tenant_key = tenant_rate_key(authenticated.value_if()->tenant);
    session->logged_in_rate_key =
        tenant_key ? std::optional<std::string>{std::move(*tenant_key.value_if())}
                   : std::nullopt;
    session->logged_in_generation =
        authenticated.value_if()->enrollment_generation;
    ++current.logins_completed;
    online_endpoints[RelayLeaseKey{.device_id = *session->logged_in_device_id,
                                   .endpoint_id = *session->logged_in_endpoint_id}] =
        session;
    current.database = database->cached_snapshot();
    current.login = login_service->diagnostics();
    publish();

    RelayWssLoginResult result{
        .tenant = authenticated.value_if()->tenant,
        .enrollment_generation =
            authenticated.value_if()->enrollment_generation,
        .lease_milliseconds =
            static_cast<std::uint32_t>(config.lease.default_lease.count())};
    auto encoded = encode_relay_wss_login_result(result);
    if (!encoded) {
      ++current.control_rejected;
      publish();
      session->send_error(*encoded.error_if(), false);
      return;
    }
    if (!session->send_control(RelayWssControlType::login_result, *encoded.value_if())) {
      session->fail(false);
    }
    return;
  }

  if (session->control_state == RelaySession::ControlState::logged_in) {
    if (type != RelayWssControlType::heartbeat &&
        type != RelayWssControlType::endpoint_publish &&
        type != RelayWssControlType::endpoint_query &&
        type != RelayWssControlType::signaling_send) {
      ++current.control_rejected;
      publish();
      session->send_error(
          relay_error(ErrorCode::protocol, "relay_logged_in_message_invalid"), true);
      return;
    }
    const std::string* tenant_rate_key_ptr =
        session->logged_in_rate_key ? &*session->logged_in_rate_key : nullptr;
    auto tenant_admitted = admit_control_request(*session, session->logged_in_tenant,
                                                 false, tenant_rate_key_ptr);
    if (!tenant_admitted) {
      session->send_error(*tenant_admitted.error_if(), false);
      return;
    }
    auto active = require_active_device(session, unix_milliseconds_now());
    if (!active) {
      session->send_error(*active.error_if(), false);
      return;
    }
    session_handle_logged_in(session, type, frame.value_if()->payload);
    return;
  }

  ++current.control_rejected;
  publish();
  session->send_error(
      relay_error(ErrorCode::protocol, "relay_control_session_already_completed"), true);
}

Result<void> RelayServer::Impl::require_active_device(
    const std::shared_ptr<RelaySession>& session,
    std::uint64_t /*now_unix_milliseconds*/) {
  if (!session->logged_in_device_id || !session->logged_in_endpoint_id) {
    return Result<void>::failure(
        relay_error(ErrorCode::authentication, "relay_session_not_logged_in"));
  }
  if (!config.close_revoked_sessions) {
    return Result<void>::success();
  }
  auto device = database->device(*session->logged_in_device_id);
  if (!device) {
    return Result<void>::failure(*device.error_if());
  }
  if (!device.value_if()->has_value()) {
    return Result<void>::failure(
        relay_error(ErrorCode::enrollment_revoked, "relay_device_unknown"));
  }
  const auto& record = device.value_if()->value();
  if (record.status != RelayDeviceStatus::active ||
      record.enrollment_generation != session->logged_in_generation ||
      record.tenant != session->logged_in_tenant) {
    return Result<void>::failure(
        relay_error(ErrorCode::enrollment_revoked,
                    "relay_device_revoked_or_generation_changed"));
  }
  return Result<void>::success();
}

void RelayServer::Impl::session_cleanup(
    const std::shared_ptr<RelaySession>& session) {
  if (session->logged_in_device_id && session->logged_in_endpoint_id &&
      session->control_state == RelaySession::ControlState::logged_in) {
    const RelayLeaseKey key{.device_id = *session->logged_in_device_id,
                            .endpoint_id = *session->logged_in_endpoint_id};
    if (auto registered = online_endpoints.find(key);
        registered != online_endpoints.end() &&
        !registered->second.owner_before(session) &&
        !session.owner_before(registered->second)) {
      online_endpoints.erase(registered);
    }
    if (lease_table) {
      (void)lease_table->remove(key);
      current.leases = lease_table->diagnostics();
    }
    if (endpoint_directory) {
      (void)endpoint_directory->remove(
        RelayEndpointKey{.device_id = key.device_id,
                         .endpoint_id = key.endpoint_id});
      current.endpoints = endpoint_directory->diagnostics();
    }
    session->control_state = RelaySession::ControlState::enrolled;
  }
}


void RelayServer::Impl::session_handle_signaling_send(
    const std::shared_ptr<RelaySession>& session, std::span<const std::byte> payload) {
  auto parsed = parse_relay_wss_signaling_send(payload);
  if (!parsed) {
    ++current.control_rejected;
    ++current.signaling_rejected;
    publish();
    session->send_error(*parsed.error_if(), true);
    return;
  }
  const auto& send = *parsed.value_if();
  const auto kind = static_cast<LanSignalingMessageKind>(send.kind);
  const bool control_kind = kind == LanSignalingMessageKind::connect_request ||
                            kind == LanSignalingMessageKind::connect_accept ||
                            kind == LanSignalingMessageKind::connect_deny;
  const bool signed_kind = kind == LanSignalingMessageKind::signed_offer ||
                           kind == LanSignalingMessageKind::signed_answer ||
                           kind == LanSignalingMessageKind::signed_candidate;
  if (!control_kind && !signed_kind) {
    ++current.control_rejected;
    ++current.signaling_rejected;
    publish();
    session->send_error(
        relay_error(ErrorCode::protocol, "signaling_kind_unknown"), false);
    return;
  }
  if ((control_kind && !send.payload.empty()) ||
      (!control_kind && send.payload.empty())) {
    ++current.control_rejected;
    ++current.signaling_rejected;
    publish();
    session->send_error(
        relay_error(ErrorCode::protocol, "signaling_payload_policy_invalid"), false);
    return;
  }
  if (!session->logged_in_device_id || !session->logged_in_endpoint_id) {
    session->send_error(
        relay_error(ErrorCode::authentication, "relay_session_not_logged_in"), false);
    return;
  }

  const auto now = std::chrono::steady_clock::now();
  if (now - session->signaling_window_start >= std::chrono::seconds{1}) {
    session->signaling_window_start = now;
    session->signaling_window_count = 0U;
  }
  ++session->signaling_window_count;
  if (session->signaling_window_count > config.signaling_rate_per_second) {
    ++current.signaling_rejected;
    publish();
    session->send_signaling_error(
        relay_error(ErrorCode::resource_exhausted, "signaling_rate_exceeded"));
    return;
  }

  const RelayLeaseKey target_key{.device_id = send.target_device_id,
                                 .endpoint_id = send.target_endpoint_id};
  std::shared_ptr<RelaySession> target;
  if (auto registered = online_endpoints.find(target_key);
      registered != online_endpoints.end()) {
    target = registered->second.lock();
    if (!target) {
      online_endpoints.erase(registered);
    }
  }
  if (!target || target->finished.load() ||
      target->control_state != RelaySession::ControlState::logged_in) {
    ++current.signaling_rejected;
    publish();
    session->send_signaling_error(
        relay_error(ErrorCode::endpoint_offline, "signaling_target_offline"));
    return;
  }
  if (target->logged_in_tenant != session->logged_in_tenant) {
    ++current.signaling_rejected;
    publish();
    session->send_signaling_error(
        relay_error(ErrorCode::permission, "signaling_tenant_mismatch"));
    return;
  }

  RelayWssSignalingDeliver deliver;
  deliver.source_device_id = *session->logged_in_device_id;
  deliver.source_endpoint_id = *session->logged_in_endpoint_id;
  deliver.kind = send.kind;
  deliver.request_id = send.request_id;
  deliver.payload = send.payload;
  auto encoded = encode_relay_wss_signaling_deliver(deliver);
  if (!encoded) {
    ++current.signaling_rejected;
    publish();
    session->send_error(*encoded.error_if(), false);
    return;
  }
  if (!target->send_control(RelayWssControlType::signaling_deliver,
                            *encoded.value_if())) {
    // The target session stopped reading and its bounded write queue filled;
    // answer the sender instead of buffering the frame without bound.
    ++current.signaling_rejected;
    ++current.signaling_backpressure_dropped;
    publish();
    session->send_signaling_error(
        relay_error(ErrorCode::endpoint_offline, "signaling_target_backpressure"));
    return;
  }
  ++current.signaling_forwarded;
  publish();
}

void RelayServer::Impl::session_handle_logged_in(
    const std::shared_ptr<RelaySession>& session, RelayWssControlType type,
    std::span<const std::byte> payload) {
  switch (type) {
    case RelayWssControlType::heartbeat:
      session_handle_heartbeat(session, payload);
      return;
    case RelayWssControlType::endpoint_publish:
      session_handle_endpoint_publish(session, payload);
      return;
    case RelayWssControlType::endpoint_query:
      session_handle_endpoint_query(session, payload);
      return;
    case RelayWssControlType::signaling_send:
      session_handle_signaling_send(session, payload);
      return;
    default:
      session->send_error(
          relay_error(ErrorCode::protocol, "relay_logged_in_message_invalid"), true);
      return;
  }
}

void RelayServer::Impl::session_handle_heartbeat(
    const std::shared_ptr<RelaySession>& session,
    std::span<const std::byte> payload) {
  auto parsed = parse_relay_wss_heartbeat_request(payload);
  if (!parsed) {
    ++current.control_rejected;
    publish();
    session->send_error(*parsed.error_if(), true);
    return;
  }
  if (!session->logged_in_device_id || !session->logged_in_endpoint_id ||
      !lease_table) {
    session->send_error(
        relay_error(ErrorCode::authentication, "relay_session_not_logged_in"), false);
    return;
  }
  const auto requested = parsed.value_if()->lease_milliseconds.value_or(0U);
  const auto before = std::chrono::steady_clock::now();
  auto heartbeat = lease_table->heartbeat(
      RelayLeaseKey{.device_id = *session->logged_in_device_id,
                    .endpoint_id = *session->logged_in_endpoint_id},
      session->logged_in_tenant,
      std::chrono::milliseconds{static_cast<std::int64_t>(requested)}, before);
  if (!heartbeat) {
    session->send_error(*heartbeat.error_if(), false);
    return;
  }
  const auto granted = std::max<std::int64_t>(
      1, std::chrono::duration_cast<std::chrono::milliseconds>(
             heartbeat.value_if()->expires_at - before)
             .count());
  RelayWssHeartbeatAck ack{
      .lease_generation = heartbeat.value_if()->lease_generation,
      .granted_lease_milliseconds = static_cast<std::uint32_t>(granted)};
  auto encoded = encode_relay_wss_heartbeat_ack(ack);
  if (!encoded) {
    session->send_error(*encoded.error_if(), false);
    return;
  }
  ++current.heartbeats;
  current.leases = lease_table->diagnostics();
  publish();
  if (!session->send_control(RelayWssControlType::heartbeat_ack,
                             *encoded.value_if())) {
    session->fail(false);
  }
}

void RelayServer::Impl::session_handle_endpoint_publish(
    const std::shared_ptr<RelaySession>& session,
    std::span<const std::byte> payload) {
  auto parsed_publish = parse_relay_wss_endpoint_publish(payload);
  if (!parsed_publish) {
    ++current.control_rejected;
    publish();
    session->send_error(*parsed_publish.error_if(), true);
    return;
  }
  auto record =
      parse_relay_endpoint_record(parsed_publish.value_if()->endpoint_record);
  if (!record) {
    ++current.control_rejected;
    publish();
    session->send_error(*record.error_if(), true);
    return;
  }
  std::optional<RelayServiceManifest> manifest;
  if (parsed_publish.value_if()->service_manifest) {
    auto parsed_manifest =
        parse_relay_service_manifest(*parsed_publish.value_if()->service_manifest);
    if (!parsed_manifest) {
      ++current.control_rejected;
      publish();
      session->send_error(*parsed_manifest.error_if(), true);
      return;
    }
    manifest = std::move(*parsed_manifest.value_if());
  }
  if (!session->logged_in_device_id || !session->logged_in_endpoint_id) {
    session->send_error(
        relay_error(ErrorCode::authentication, "relay_session_not_logged_in"), false);
    return;
  }
  const RelayLeaseKey key{.device_id = *session->logged_in_device_id,
                          .endpoint_id = *session->logged_in_endpoint_id};
  const RelayEndpointKey endpoint_key{.device_id = key.device_id,
                                      .endpoint_id = key.endpoint_id};
  if (record.value_if()->endpoint != endpoint_key) {
    ++current.control_rejected;
    publish();
    session->send_error(
        relay_error(ErrorCode::authentication, "endpoint_record_session_mismatch"),
        false);
    return;
  }
  if (!lease_table ||
      !lease_table->get(key, std::chrono::steady_clock::now())) {
    session->send_error(
        relay_error(ErrorCode::permission, "endpoint_lease_required"), false);
    return;
  }
  auto device = database->device(*session->logged_in_device_id);
  if (!device || !device.value_if()->has_value()) {
    const auto error = device ? relay_error(ErrorCode::authentication,
                                            "endpoint_device_unknown")
                              : *device.error_if();
    session->send_error(error, false);
    return;
  }
  if (!endpoint_directory) {
    session->send_error(
        relay_error(ErrorCode::cancelled, "endpoint_directory_unavailable"), false);
    return;
  }
  const auto now_wall = unix_milliseconds_now();
  const auto now_steady = std::chrono::steady_clock::now();
  auto published = endpoint_directory->publish(
      *record.value_if(), manifest, device.value_if()->value(),
      session->logged_in_tenant, now_wall, now_steady);
  if (!published) {
    ++current.control_rejected;
    current.endpoints = endpoint_directory->diagnostics();
    publish();
    session->send_error(*published.error_if(), false);
    return;
  }
  RelayWssEndpointPublishAck ack{
      .record_generation = record.value_if()->record_generation};
  auto encoded = encode_relay_wss_endpoint_publish_ack(ack);
  if (!encoded) {
    session->send_error(*encoded.error_if(), false);
    return;
  }
  ++current.endpoint_publications;
  current.endpoints = endpoint_directory->diagnostics();
  publish();
  if (!session->send_control(RelayWssControlType::endpoint_publish_ack,
                             *encoded.value_if())) {
    session->fail(false);
  }
}

void RelayServer::Impl::session_handle_endpoint_query(
    const std::shared_ptr<RelaySession>& session,
    std::span<const std::byte> payload) {
  auto parsed = parse_relay_wss_endpoint_query(payload);
  if (!parsed) {
    ++current.control_rejected;
    publish();
    session->send_error(*parsed.error_if(), true);
    return;
  }
  if (!lease_table || !endpoint_directory) {
    session->send_error(
        relay_error(ErrorCode::cancelled, "relay_directory_unavailable"), false);
    return;
  }
  // Expiry runs on the periodic sweep timer; lookups below already treat
  // expired entries as absent.
  const auto now_steady = std::chrono::steady_clock::now();
  auto online = lease_table->online_tenant(session->logged_in_tenant, now_steady);
  if (online.size() > config.endpoint_query_max_results) {
    ++current.control_rejected;
    session->send_error(
        relay_error(ErrorCode::resource_exhausted,
                    "endpoint_query_result_capacity_exceeded"),
        false);
    return;
  }
  const auto now_wall = unix_milliseconds_now();
  RelayWssEndpointQueryResult result;
  for (const auto& lease : online) {
    if (parsed.value_if()->device_id &&
        lease.key.device_id != *parsed.value_if()->device_id) {
      continue;
    }
    if (parsed.value_if()->endpoint_id &&
        lease.key.endpoint_id != *parsed.value_if()->endpoint_id) {
      continue;
    }
    auto entry = endpoint_directory->get(
        RelayEndpointKey{.device_id = lease.key.device_id,
                         .endpoint_id = lease.key.endpoint_id},
        now_steady);
    if (!entry) {
      continue;
    }
    auto publication = publish_relay_endpoint(
        entry->record, entry->manifest, config.endpoint_exposure, now_wall);
    if (!publication) {
      continue;
    }
    RelayWssEndpointPublication wire_publication;
    wire_publication.device_id = publication.value_if()->endpoint.device_id;
    wire_publication.endpoint_id = publication.value_if()->endpoint.endpoint_id;
    wire_publication.application_id = publication.value_if()->application_id;
    wire_publication.record_generation = publication.value_if()->record_generation;
    wire_publication.manifest_generation = publication.value_if()->manifest_generation;
    wire_publication.manifest_sha256 = publication.value_if()->manifest_sha256;
    wire_publication.expires_unix_milliseconds =
        publication.value_if()->expires_unix_milliseconds;
    const auto lease_remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        lease.expires_at - now_steady);
    const auto lease_expiry = lease_remaining.count() > 0
        ? now_wall + static_cast<std::uint64_t>(lease_remaining.count())
        : now_wall;
    wire_publication.lease_expires_unix_milliseconds = lease_expiry;
    auto record_bytes = encode_relay_endpoint_record(entry->record);
    if (!record_bytes) {
      continue;
    }
    wire_publication.endpoint_record = std::move(*record_bytes.value_if());
    wire_publication.identity_public_key = entry->identity_public_key;
    result.endpoints.push_back(std::move(wire_publication));
  }
  auto encoded = encode_relay_wss_endpoint_query_result(result);
  if (!encoded) {
    session->send_error(*encoded.error_if(), false);
    return;
  }
  if (encoded.value_if()->size() >
      max_relay_wss_control_frame_bytes - relay_wss_control_header_bytes) {
    ++current.control_rejected;
    session->send_error(
        relay_error(ErrorCode::resource_exhausted,
                    "endpoint_query_result_frame_too_large"),
        false);
    return;
  }
  ++current.endpoint_queries;
  current.leases = lease_table->diagnostics();
  current.endpoints = endpoint_directory->diagnostics();
  publish();
  if (!session->send_control(RelayWssControlType::endpoint_query_result,
                             *encoded.value_if())) {
    session->fail(false);
  }
}

void RelayServer::Impl::session_reject_policy(
    const std::shared_ptr<RelaySession>& session) {
  ++current.protocol_rejected;
  ++current.websocket_accepted;
  publish();
  session->reject_policy();
}

Result<RuntimeShutdownCompletion> RelayServer::Impl::begin_shutdown() {
  if (!shutdown_completion.valid()) {
    shutdown_completion = shutdown_promise.get_future().share();
  }
  if (!shutdown_posted) {
    shutdown_posted = true;
    auto weak = std::weak_ptr<RelayServer::Impl>{shared_from_this()};
    try {
      boost::asio::post(strand, [weak] {
        if (auto self = weak.lock()) {
          self->finish_shutdown();
        }
      });
    } catch (...) {
      shutdown_finished = true;
      try {
        shutdown_promise.set_value(Result<void>::failure(
            relay_error(ErrorCode::cancelled, "relay_shutdown_post_failed")));
      } catch (...) {
      }
    }
  }
  return Result<RuntimeShutdownCompletion>::success(shutdown_completion);
}

void RelayServer::Impl::finish_shutdown() {
  if (shutdown_finished) {
    return;
  }
  shutdown_finished = true;
  current.state = RelayServerState::draining;
  current.stop_requested = true;
  publish();

  boost::system::error_code ignored;
  acceptor.close(ignored);
  signals.cancel(ignored);
  (void)sweep_timer.cancel();
  for (const auto& session : sessions) {
    auto& lowest = boost::beast::get_lowest_layer(session->websocket);
    lowest.socket().shutdown(tcp::socket::shutdown_both, ignored);
    lowest.socket().close(ignored);
  }
  sessions.clear();
  current.active_sessions = 0U;
  current.state = RelayServerState::stopped;
  publish();

  try {
    shutdown_promise.set_value(Result<void>::success());
  } catch (...) {
  }
}

void RelayServer::Impl::request_stop() {
  stop_requested.store(true, std::memory_order_release);
  current.stop_requested = true;
  publish();
}

void RelayServer::Impl::publish() {
  if (publish_deferred) {
    publish_pending = true;
    return;
  }
  const bool observable_change =
      current.state != published_state || current.stop_requested != published_stop_requested;
  // Waiting publish: try_publish silently drops the update when every version
  // slot is pinned by a reader, which left observers (tests, embedders, the
  // relay main loop) reading stale counters after the per-message publish was
  // coalesced to exactly one flush. The waiting variant yields until readers
  // finish their copies; readers never wait on writers, so this cannot
  // deadlock on the strand.
  try {
    (void)snapshots.publish(current);
  } catch (...) {
    (void)snapshots.try_publish(current);
  }
  if (observable_change) {
    published_state = current.state;
    published_stop_requested = current.stop_requested;
    if (config.on_state_changed) {
      try {
        config.on_state_changed();
      } catch (...) {
      }
    }
  }
}

void RelayServer::Impl::publish_last_error(Error error) {
  current.last_error = std::move(error);
  publish();
}

void RelayServer::Impl::close_socket(tcp::socket& socket) {
  boost::system::error_code ignored;
  socket.shutdown(tcp::socket::shutdown_both, ignored);
  socket.close(ignored);
}

std::string_view relay_server_state_name(RelayServerState state) noexcept {
  switch (state) {
    case RelayServerState::stopped:
      return "stopped";
    case RelayServerState::starting:
      return "starting";
    case RelayServerState::running:
      return "running";
    case RelayServerState::draining:
      return "draining";
    case RelayServerState::failed:
      return "failed";
  }
  return "unknown";
}

Result<RelayServer> RelayServer::create(RelayServerConfig config, Runtime* runtime) {
  auto valid = validate_relay_server_config(config);
  if (!valid) {
    return Result<RelayServer>::failure(*valid.error_if());
  }

  std::shared_ptr<Runtime> owned_runtime;
  if (runtime == nullptr) {
    RuntimeConfig runtime_config = config.runtime;
    runtime_config.producer_stop_timeout = config.shutdown_timeout;
    auto created = Runtime::create_owned(runtime_config);
    if (!created) {
      return Result<RelayServer>::failure(*created.error_if());
    }
    owned_runtime = std::make_shared<Runtime>(std::move(*created.value_if()));
    runtime = owned_runtime.get();
  }

  auto executor = detail::RuntimeAccess::io_executor(*runtime);
  if (!executor) {
    if (owned_runtime) {
      (void)owned_runtime->shutdown();
    }
    return Result<RelayServer>::failure(*executor.error_if());
  }

  std::shared_ptr<Impl> impl;
  try {
    impl = std::make_shared<Impl>(std::move(config), std::move(owned_runtime), runtime,
                                  std::move(*executor.value_if()));
  } catch (...) {
    return Result<RelayServer>::failure(relay_error(ErrorCode::internal,
                                                    "relay_alloc_failed"));
  }

  auto initialized = impl->initialize();
  if (!initialized) {
    if (impl->owned_runtime) {
      (void)impl->owned_runtime->shutdown();
    }
    return Result<RelayServer>::failure(*initialized.error_if());
  }
  auto lifecycle = impl->register_lifecycle();
  if (!lifecycle) {
    if (impl->owned_runtime) {
      (void)impl->owned_runtime->shutdown();
    }
    return Result<RelayServer>::failure(*lifecycle.error_if());
  }

  auto weak = std::weak_ptr<RelayServer::Impl>{impl};
  try {
    boost::asio::post(impl->strand, [weak] {
      if (auto self = weak.lock()) {
        self->begin();
      }
    });
  } catch (...) {
    if (impl->owned_runtime) {
      (void)impl->owned_runtime->shutdown();
    }
    return Result<RelayServer>::failure(relay_error(ErrorCode::internal,
                                                    "relay_start_post_failed"));
  }
  return Result<RelayServer>::success(RelayServer{std::move(impl)});
}

RelayServer::RelayServer(std::shared_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
RelayServer::RelayServer(RelayServer&&) noexcept = default;
RelayServer& RelayServer::operator=(RelayServer&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}
RelayServer::~RelayServer() = default;

RelayServerSnapshot RelayServer::snapshot() const {
  return impl_ ? impl_->snapshots.load().value : RelayServerSnapshot{};
}

bool RelayServer::stop_requested() const noexcept {
  return impl_ ? impl_->stop_requested.load(std::memory_order_acquire) : true;
}

RelayServerShutdownReport RelayServer::shutdown() {
  RelayServerShutdownReport report;
  if (!impl_) {
    report.stopped = true;
    return report;
  }
  if (impl_->owned_runtime) {
    report.runtime = impl_->owned_runtime->shutdown();
  } else {
    auto completion = impl_->begin_shutdown();
    if (completion) {
      if (completion.value_if()->wait_for(impl_->config.shutdown_timeout) !=
          std::future_status::ready) {
        report.timed_out = true;
      }
    }
  }
  report.final_snapshot = snapshot();
  report.stopped = report.final_snapshot.state == RelayServerState::stopped;
  if (impl_->owned_runtime) {
    report.timed_out = std::any_of(
        report.runtime.hooks.begin(), report.runtime.hooks.end(),
        [](const RuntimeShutdownHookReport& hook) {
          return hook.outcome == RuntimeShutdownHookOutcome::timed_out;
        });
  }
  return report;
}

}  // namespace heyaki
