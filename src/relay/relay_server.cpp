#include "relay_server.hpp"

#include "client/runtime_access.hpp"

#include <executor/comm.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/websocket.hpp>

#include <openssl/ssl.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <future>
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
        snapshots("heyaki-relay-snapshots"),
        connection_capacity(config.max_connections) {
    current.state = RelayServerState::starting;
    current.listen_address = config.listen_address;
    current.connection_capacity = config.max_connections;
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
  void on_accept(boost::system::error_code error, tcp::socket socket);
  void on_session_finished(const std::shared_ptr<RelaySession>& session,
                           bool handshake_timeout, bool handshake_error,
                           bool protocol_rejected);
  void session_send_health(const std::shared_ptr<RelaySession>& session);
  void session_reject_policy(const std::shared_ptr<RelaySession>& session);
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
  std::optional<RelayDatabase> database;
  std::optional<RelayRateLimiter> rate_limiter;
  executor::comm::DoubleBuffer<RelayServerSnapshot> snapshots;
  std::set<std::shared_ptr<RelaySession>> sessions;
  std::promise<Result<void>> shutdown_promise;
  std::shared_future<Result<void>> shutdown_completion;
  bool shutdown_posted{false};
  bool shutdown_finished{false};
  std::atomic<bool> stop_requested{false};

  std::size_t connection_capacity{};
  RelayServerSnapshot current;
};

class RelaySession : public std::enable_shared_from_this<RelaySession> {
 public:
  RelaySession(tcp::socket socket, boost::asio::ssl::context& tls_context,
               std::shared_ptr<RelayServer::Impl> server)
      : websocket(std::move(socket), tls_context),
        timer(websocket.get_executor()),
        server(std::move(server)) {
    websocket.read_message_max(1024U);
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
      } else {
        owner->session_reject_policy(shared_from_this());
      }
    } else {
      close_socket();
    }
  }

  void send_health() {
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
  bool handshake_complete{false};
  std::atomic<bool> finished{false};
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
    current.database = database->snapshot();
  } else {
    auto file_database = RelayDatabase::open(config.database_file);
    if (!file_database) {
      return Result<void>::failure(*file_database.error_if());
    }
    database.emplace(std::move(*file_database.value_if()));
    current.database = database->snapshot();
  }
  auto limits = RelayRateLimiter::create(config.rate_limits);
  if (!limits) {
    return Result<void>::failure(*limits.error_if());
  }
  rate_limiter.emplace(std::move(*limits.value_if()));
  current.rate_limits = rate_limiter->diagnostics();

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
  start_accept();
}

void RelayServer::Impl::start_accept() {
  if (is_shutting_down(current.state)) {
    return;
  }
  acceptor.async_accept(
      boost::asio::make_strand(strand),
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

  auto session = std::make_shared<RelaySession>(std::move(socket), tls_context,
                                                shared_from_this());
  sessions.insert(session);
  current.active_sessions = sessions.size();
  publish();
  session->start();
  start_accept();
}

void RelayServer::Impl::on_session_finished(
    const std::shared_ptr<RelaySession>& session, bool handshake_timeout,
    bool handshake_error, bool protocol_rejected) {
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
  current.websocket_accepted = current.health_checks + current.protocol_rejected;
  publish();
  session->send_health();
}

void RelayServer::Impl::session_reject_policy(
    const std::shared_ptr<RelaySession>& session) {
  ++current.protocol_rejected;
  current.websocket_accepted = current.health_checks + current.protocol_rejected;
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
  (void)snapshots.try_publish(current);
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
