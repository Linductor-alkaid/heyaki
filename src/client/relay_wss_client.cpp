#include "relay_wss_client.hpp"

#include "runtime_access.hpp"

#include <heyaki/relay_wss_control.hpp>

#include <executor/comm.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core/buffers_to_string.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <future>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

using boost::asio::ip::tcp;

Error wss_error(ErrorCode code, const char* detail,
                std::optional<std::int64_t> underlying = std::nullopt) {
  return Error{code, "relay_wss", detail, underlying};
}

struct ParsedUrl {
  std::string host;
  std::string port{"443"};
  std::string path{"/"};
};

Result<ParsedUrl> parse_wss_url(std::string_view url) {
  constexpr std::string_view scheme = "wss://";
  if (!url.starts_with(scheme) || url.size() <= scheme.size()) {
    return Result<ParsedUrl>::failure(wss_error(ErrorCode::configuration,
                                                "wss_url_scheme_invalid"));
  }
  std::string_view authority = url.substr(scheme.size());
  const auto path_separator = authority.find('/');
  if (path_separator != std::string_view::npos) {
    const auto path = authority.substr(path_separator);
    if (path.empty() || path.size() > 256U) {
      return Result<ParsedUrl>::failure(wss_error(ErrorCode::configuration,
                                                  "wss_url_path_invalid"));
    }
    authority = authority.substr(0U, path_separator);
  }
  if (authority.empty() || authority.size() > 258U) {
    return Result<ParsedUrl>::failure(wss_error(ErrorCode::configuration,
                                                "wss_url_authority_invalid"));
  }
  ParsedUrl parsed;
  if (path_separator != std::string_view::npos) {
    parsed.path = std::string{url.substr(scheme.size() + path_separator)};
  }

  if (authority.front() == '[') {
    const auto close = authority.find(']');
    if (close == std::string_view::npos || close == 1U) {
      return Result<ParsedUrl>::failure(wss_error(ErrorCode::configuration,
                                                  "wss_url_host_invalid"));
    }
    parsed.host = std::string{authority.substr(1U, close - 1U)};
    if (close + 1U < authority.size()) {
      if (authority[close + 1U] != ':' || close + 2U >= authority.size()) {
        return Result<ParsedUrl>::failure(wss_error(ErrorCode::configuration,
                                                    "wss_url_port_invalid"));
      }
      parsed.port = std::string{authority.substr(close + 2U)};
    }
  } else {
    const auto colon = authority.rfind(':');
    if (colon != std::string_view::npos) {
      parsed.host = std::string{authority.substr(0U, colon)};
      parsed.port = std::string{authority.substr(colon + 1U)};
    } else {
      parsed.host = std::string{authority};
    }
  }
  if (parsed.host.empty() || parsed.port.empty() || parsed.port.size() > 5U ||
      std::any_of(parsed.port.begin(), parsed.port.end(),
                  [](char character) { return character < '0' || character > '9'; })) {
    return Result<ParsedUrl>::failure(wss_error(ErrorCode::configuration,
                                                "wss_url_host_port_invalid"));
  }
  return Result<ParsedUrl>::success(std::move(parsed));
}

Error classify_error(const boost::system::error_code& error) {
  if (error == boost::asio::error::operation_aborted) {
    return wss_error(ErrorCode::cancelled, "wss_operation_cancelled", error.value());
  }
  if (error == boost::asio::error::host_not_found ||
      error == boost::asio::error::host_unreachable ||
      error == boost::asio::error::network_unreachable ||
      error == boost::asio::error::connection_refused ||
      error == boost::asio::error::connection_reset) {
    return wss_error(ErrorCode::relay_unavailable, "wss_connection_failed",
                     error.value());
  }
  if (error == boost::asio::error::timed_out) {
    return wss_error(ErrorCode::timeout, "wss_timeout", error.value());
  }
  if (error.category() == boost::asio::error::get_ssl_category()) {
    return wss_error(ErrorCode::authentication, "wss_tls_verification_failed",
                     error.value());
  }
  if (error == boost::beast::websocket::error::closed) {
    return wss_error(ErrorCode::cancelled, "wss_websocket_closed", error.value());
  }
  return wss_error(ErrorCode::transport, "wss_transport_failed", error.value());
}

}  // namespace

struct RelayWssClient::Impl : std::enable_shared_from_this<RelayWssClient::Impl> {
  Impl(RelayWssClientConfig config_value, std::shared_ptr<Runtime> owned_value,
       Runtime* runtime_value, boost::asio::any_io_executor executor,
       boost::asio::ssl::context tls_context)
      : parsed(parse_wss_url(config_value.url)),
        config(std::move(config_value)),
        owned_runtime(std::move(owned_value)),
        runtime(runtime_value),
        strand(boost::asio::make_strand(std::move(executor))),
        ssl_context(std::move(tls_context)),
        websocket(strand, ssl_context),
        resolver(strand),
        timer(strand),
        received(executor::comm::ChannelOptions{
            .capacity = config_value.receive_capacity,
            .drop_policy = executor::comm::DropPolicy::RejectNewest,
            .enable_stats = true,
            .name = "heyaki-wss-received"}),
        outgoing(executor::comm::ChannelOptions{
            .capacity = config_value.send_capacity,
            .drop_policy = executor::comm::DropPolicy::RejectNewest,
            .enable_stats = true,
            .name = "heyaki-wss-outgoing"}),
        snapshots("heyaki-wss-snapshots") {}

  ~Impl() {
    received.close();
    outgoing.close();
    if (owned_runtime) {
      (void)owned_runtime->shutdown();
    }
  }

  Result<void> initialize() {
    if (!parsed) {
      return Result<void>::failure(*parsed.error_if());
    }
    current.host = parsed.value_if()->host;
    current.port = parsed.value_if()->port;
    current.path = parsed.value_if()->path;
    websocket.read_message_max(max_relay_wss_control_frame_bytes);
    return Result<void>::success();
  }

  std::shared_future<Result<void>> begin_connect();
  void start_connect();
  void on_resolve(boost::system::error_code error,
                  tcp::resolver::results_type results);
  void on_tcp(boost::system::error_code error,
              const tcp::endpoint& /*endpoint*/);
  void on_tls(boost::system::error_code error);
  void on_handshake(boost::system::error_code error);
  void start_read();
  void on_read(boost::system::error_code error, std::size_t bytes_transferred);
  void drain_send();
  void write_next();
  void on_write(boost::system::error_code error, std::size_t bytes_transferred);
  std::shared_future<Result<void>> begin_close();
  void do_close();
  void on_close(boost::system::error_code error);
  void fail(Error error);
  void publish();

  Result<ParsedUrl> parsed;
  RelayWssClientConfig config;
  std::shared_ptr<Runtime> owned_runtime;
  Runtime* runtime{nullptr};
  boost::asio::strand<boost::asio::any_io_executor> strand;
  boost::asio::ssl::context ssl_context;
  boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>>
      websocket;
  tcp::resolver resolver;
  boost::asio::steady_timer timer;
  boost::beast::flat_buffer read_buffer;
  executor::comm::MpscChannel<RelayWssMessage> received;
  executor::comm::MpscChannel<std::vector<std::byte>> outgoing;
  std::deque<std::vector<std::byte>> write_queue;
  bool write_in_flight{false};
  bool connect_pending{false};
  bool close_pending{false};
  bool failed{false};
  std::promise<Result<void>> connect_promise;
  std::shared_future<Result<void>> connect_completion;
  std::promise<Result<void>> close_promise;
  std::shared_future<Result<void>> close_completion;
  executor::comm::DoubleBuffer<RelayWssSnapshot> snapshots;
  RelayWssSnapshot current;
};

std::shared_future<Result<void>> RelayWssClient::Impl::begin_connect() {
  if (!connect_completion.valid()) {
    connect_completion = connect_promise.get_future().share();
  }
  if (!connect_pending && current.state != RelayWssState::ready) {
    connect_pending = true;
    auto weak = std::weak_ptr<RelayWssClient::Impl>{shared_from_this()};
    try {
      boost::asio::post(strand, [weak] {
        if (auto self = weak.lock()) {
          self->start_connect();
        }
      });
    } catch (...) {
      connect_pending = false;
      try {
        connect_promise.set_value(Result<void>::failure(
            wss_error(ErrorCode::cancelled, "wss_connect_post_failed")));
      } catch (...) {
      }
    }
  }
  return connect_completion;
}

void RelayWssClient::Impl::start_connect() {
  if (current.state == RelayWssState::ready) {
    try {
      connect_promise.set_value(Result<void>::success());
    } catch (...) {
    }
    return;
  }
  if (current.state == RelayWssState::connecting || current.state == RelayWssState::closing ||
      failed) {
    return;
  }
  current.state = RelayWssState::connecting;
  current.last_error.reset();
  publish();

  timer.expires_after(config.connect_timeout + config.handshake_timeout);
  timer.async_wait([weak = weak_from_this()](boost::system::error_code error) {
    if (!error) {
      if (auto self = weak.lock()) {
        self->fail(wss_error(ErrorCode::timeout, "wss_connect_timeout"));
      }
    }
  });

  resolver.async_resolve(
      parsed.value_if()->host, parsed.value_if()->port,
      [weak = weak_from_this()](boost::system::error_code error,
                                tcp::resolver::results_type results) {
        if (auto self = weak.lock()) {
          self->on_resolve(error, std::move(results));
        }
      });
}

void RelayWssClient::Impl::on_resolve(boost::system::error_code error,
                                      tcp::resolver::results_type results) {
  if (failed) {
    return;
  }
  if (error) {
    fail(classify_error(error));
    return;
  }
  boost::asio::async_connect(
      boost::beast::get_lowest_layer(websocket).socket(), results,
      [weak = weak_from_this()](boost::system::error_code connect_error,
                                const tcp::endpoint& endpoint) {
        if (auto self = weak.lock()) {
          self->on_tcp(connect_error, endpoint);
        }
      });
}

void RelayWssClient::Impl::on_tcp(boost::system::error_code error,
                                  const tcp::endpoint& /*endpoint*/) {
  if (failed) {
    return;
  }
  if (error) {
    fail(classify_error(error));
    return;
  }
  websocket.next_layer().async_handshake(
      boost::asio::ssl::stream_base::client,
      [weak = weak_from_this()](boost::system::error_code handshake_error) {
        if (auto self = weak.lock()) {
          self->on_tls(handshake_error);
        }
      });
}

void RelayWssClient::Impl::on_tls(boost::system::error_code error) {
  if (failed) {
    return;
  }
  if (error) {
    fail(classify_error(error));
    return;
  }
  if (config.relay_pin) {
    X509* certificate = SSL_get1_peer_certificate(
        websocket.next_layer().native_handle());
    if (certificate == nullptr) {
      fail(wss_error(ErrorCode::authentication, "wss_tls_peer_certificate_missing"));
      return;
    }
    RelayTlsPin pin{};
    unsigned int pin_size = 0U;
    const bool pin_matches =
        X509_digest(certificate, EVP_sha256(),
                    reinterpret_cast<unsigned char*>(pin.data()), &pin_size) == 1 &&
        pin_size == pin.size() && pin == *config.relay_pin;
    X509_free(certificate);
    if (!pin_matches) {
      fail(wss_error(ErrorCode::authentication, "wss_tls_pin_mismatch"));
      return;
    }
  }
  websocket.async_handshake(
      parsed.value_if()->host, parsed.value_if()->path,
      [weak = weak_from_this()](boost::system::error_code handshake_error) {
        if (auto self = weak.lock()) {
          self->on_handshake(handshake_error);
        }
      });
}

void RelayWssClient::Impl::on_handshake(boost::system::error_code error) {
  if (failed) {
    return;
  }
  if (error) {
    fail(classify_error(error));
    return;
  }
  (void)timer.cancel();
  websocket.binary(true);
  current.state = RelayWssState::ready;
  publish();
  try {
    connect_promise.set_value(Result<void>::success());
  } catch (...) {
  }
  start_read();
}

void RelayWssClient::Impl::start_read() {
  if (current.state != RelayWssState::ready) {
    return;
  }
  websocket.async_read(
      read_buffer,
      [weak = weak_from_this()](boost::system::error_code error,
                                std::size_t bytes_transferred) {
        if (auto self = weak.lock()) {
          self->on_read(error, bytes_transferred);
        }
      });
}

void RelayWssClient::Impl::on_read(boost::system::error_code error,
                                   std::size_t bytes_transferred) {
  if (error) {
    if (error == boost::beast::websocket::error::closed) {
      boost::system::error_code ignored;
      boost::beast::get_lowest_layer(websocket).socket().close(ignored);
      received.close();
      outgoing.close();
      current.state = RelayWssState::disconnected;
      publish();
    } else if (error != boost::asio::error::operation_aborted &&
        current.state != RelayWssState::closing &&
        current.state != RelayWssState::disconnected && !failed) {
      fail(classify_error(error));
    }
    return;
  }
  RelayWssMessage message;
  message.text = websocket.got_text();
  const std::string text = boost::beast::buffers_to_string(read_buffer.data());
  message.payload.reserve(text.size());
  const auto* bytes = reinterpret_cast<const std::byte*>(text.data());
  message.payload.insert(message.payload.end(), bytes, bytes + text.size());
  current.messages_received += 1U;
  current.bytes_received += bytes_transferred;
  read_buffer.consume(read_buffer.size());
  publish();
  if (!received.try_send(std::move(message))) {
    ++current.receive_rejected;
    fail(wss_error(ErrorCode::resource_exhausted, "wss_receive_queue_full"));
    return;
  }
  start_read();
}

void RelayWssClient::Impl::drain_send() {
  if (current.state != RelayWssState::ready) {
    return;
  }
  std::vector<std::byte> payload;
  while (outgoing.try_receive(payload)) {
    if (write_queue.size() >= config.send_capacity) {
      ++current.send_rejected;
      fail(wss_error(ErrorCode::resource_exhausted, "wss_send_queue_full"));
      return;
    }
    write_queue.push_back(std::move(payload));
  }
  write_next();
}

void RelayWssClient::Impl::write_next() {
  if (write_in_flight || write_queue.empty() || current.state != RelayWssState::ready) {
    return;
  }
  write_in_flight = true;
  websocket.async_write(
      boost::asio::buffer(write_queue.front().data(), write_queue.front().size()),
      [weak = weak_from_this()](boost::system::error_code error,
                                std::size_t bytes_transferred) {
        if (auto self = weak.lock()) {
          self->on_write(error, bytes_transferred);
        }
      });
}

void RelayWssClient::Impl::on_write(boost::system::error_code error,
                                    std::size_t bytes_transferred) {
  write_in_flight = false;
  if (!write_queue.empty()) {
    current.messages_sent += 1U;
    current.bytes_sent += bytes_transferred;
    write_queue.pop_front();
    publish();
  }
  if (error) {
    fail(classify_error(error));
    return;
  }
  write_next();
}

std::shared_future<Result<void>> RelayWssClient::Impl::begin_close() {
  if (!close_completion.valid()) {
    close_completion = close_promise.get_future().share();
  }
  if (!close_pending && current.state == RelayWssState::disconnected) {
    close_pending = true;
    try {
      close_promise.set_value(Result<void>::success());
    } catch (...) {
    }
    return close_completion;
  }
  if (!close_pending && current.state != RelayWssState::disconnected &&
      current.state != RelayWssState::failed) {
    close_pending = true;
    auto weak = std::weak_ptr<RelayWssClient::Impl>{shared_from_this()};
    try {
      boost::asio::post(strand, [weak] {
        if (auto self = weak.lock()) {
          self->do_close();
        }
      });
    } catch (...) {
      close_pending = false;
      try {
        close_promise.set_value(Result<void>::failure(
            wss_error(ErrorCode::cancelled, "wss_close_post_failed")));
      } catch (...) {
      }
    }
  }
  return close_completion;
}

void RelayWssClient::Impl::do_close() {
  if (current.state == RelayWssState::disconnected ||
      current.state == RelayWssState::failed) {
    try {
      close_promise.set_value(Result<void>::success());
    } catch (...) {
    }
    return;
  }
  current.state = RelayWssState::closing;
  publish();
  websocket.async_close(
      boost::beast::websocket::close_code::normal,
      [weak = weak_from_this()](boost::system::error_code error) {
        if (auto self = weak.lock()) {
          self->on_close(error);
        }
      });
}

void RelayWssClient::Impl::on_close(boost::system::error_code error) {
  boost::system::error_code ignored;
  boost::beast::get_lowest_layer(websocket).socket().close(ignored);
  received.close();
  outgoing.close();
  const bool close_failed =
      error && error != boost::asio::error::operation_aborted &&
      error != boost::beast::websocket::error::closed;
  if (close_failed) {
    current.last_error = classify_error(error);
  }
  current.state = RelayWssState::disconnected;
  publish();
  try {
    close_promise.set_value(close_failed ? Result<void>::failure(classify_error(error))
                                         : Result<void>::success());
  } catch (...) {
  }
}

void RelayWssClient::Impl::fail(Error error) {
  if (failed) {
    return;
  }
  failed = true;
  current.last_error = error;
  current.state = RelayWssState::failed;
  (void)timer.cancel();
  boost::system::error_code ignored;
  boost::beast::get_lowest_layer(websocket).socket().close(ignored);
  received.close();
  outgoing.close();
  publish();
  try {
    connect_promise.set_value(Result<void>::failure(error));
  } catch (...) {
  }
  try {
    close_promise.set_value(Result<void>::failure(error));
  } catch (...) {
  }
}

void RelayWssClient::Impl::publish() {
  (void)snapshots.try_publish(current);
}

std::string_view relay_wss_state_name(RelayWssState state) noexcept {
  switch (state) {
    case RelayWssState::disconnected:
      return "disconnected";
    case RelayWssState::connecting:
      return "connecting";
    case RelayWssState::ready:
      return "ready";
    case RelayWssState::closing:
      return "closing";
    case RelayWssState::failed:
      return "failed";
  }
  return "unknown";
}

RelayWssClient::RelayWssClient(std::shared_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}
RelayWssClient::RelayWssClient(RelayWssClient&&) noexcept = default;
RelayWssClient& RelayWssClient::operator=(RelayWssClient&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}
RelayWssClient::~RelayWssClient() = default;

Result<RelayWssClient> RelayWssClient::create(RelayWssClientConfig config,
                                              Runtime* runtime) {
  auto parsed = parse_wss_url(config.url);
  if (!parsed) {
    return Result<RelayWssClient>::failure(*parsed.error_if());
  }
  if (config.receive_capacity == 0U || config.send_capacity == 0U ||
      config.connect_timeout.count() <= 0 || config.handshake_timeout.count() <= 0 ||
      config.close_timeout.count() <= 0) {
    return Result<RelayWssClient>::failure(wss_error(ErrorCode::configuration,
                                                     "wss_config_invalid"));
  }
  std::shared_ptr<Runtime> owned_runtime;
  if (runtime == nullptr) {
    auto created = Runtime::create_owned(config.runtime);
    if (!created) {
      return Result<RelayWssClient>::failure(*created.error_if());
    }
    owned_runtime = std::make_shared<Runtime>(std::move(*created.value_if()));
    runtime = owned_runtime.get();
  }
  auto executor = detail::RuntimeAccess::io_executor(*runtime);
  if (!executor) {
    if (owned_runtime) {
      (void)owned_runtime->shutdown();
    }
    return Result<RelayWssClient>::failure(*executor.error_if());
  }
  boost::asio::ssl::context tls_context{boost::asio::ssl::context::tls_client};
  if (config.tls_verify_peer) {
    tls_context.set_verify_mode(boost::asio::ssl::verify_peer);
    const std::string expected_host = parsed.value_if()->host;
    tls_context.set_verify_callback(
        [expected_host](bool preverified,
                        boost::asio::ssl::verify_context& context) {
          if (!preverified) {
            return false;
          }
          return boost::asio::ssl::host_name_verification(expected_host)(true,
                                                                          context);
        });
    if (config.tls_ca_file) {
      boost::system::error_code error;
      tls_context.load_verify_file(config.tls_ca_file->string(), error);
      if (error) {
        return Result<RelayWssClient>::failure(
            wss_error(ErrorCode::configuration, "wss_ca_file_load_failed", error.value()));
      }
    } else {
      boost::system::error_code error;
      tls_context.set_default_verify_paths(error);
      if (error) {
        return Result<RelayWssClient>::failure(
            wss_error(ErrorCode::configuration, "wss_default_verify_paths_failed",
                      error.value()));
      }
    }
  } else {
    tls_context.set_verify_mode(boost::asio::ssl::verify_none);
  }

  std::shared_ptr<Impl> impl;
  try {
    impl = std::make_shared<Impl>(std::move(config), std::move(owned_runtime), runtime,
                                  std::move(*executor.value_if()),
                                  std::move(tls_context));
  } catch (...) {
    return Result<RelayWssClient>::failure(wss_error(ErrorCode::internal,
                                                     "wss_alloc_failed"));
  }
  auto initialized = impl->initialize();
  if (!initialized) {
    return Result<RelayWssClient>::failure(*initialized.error_if());
  }
  return Result<RelayWssClient>::success(RelayWssClient{std::move(impl)});
}

Result<void> RelayWssClient::connect(std::chrono::milliseconds timeout) {
  if (!impl_) {
    return Result<void>::failure(wss_error(ErrorCode::cancelled, "wss_not_initialized"));
  }
  if (timeout.count() < 0) {
    return Result<void>::failure(wss_error(ErrorCode::configuration, "wss_timeout_invalid"));
  }
  auto completion = impl_->begin_connect();
  if (completion.wait_for(timeout) != std::future_status::ready) {
    return Result<void>::failure(wss_error(ErrorCode::timeout, "wss_connect_wait_timeout"));
  }
  try {
    return completion.get();
  } catch (...) {
    return Result<void>::failure(wss_error(ErrorCode::internal, "wss_connect_exception"));
  }
}

Result<void> RelayWssClient::start_connect() {
  if (!impl_) {
    return Result<void>::failure(wss_error(ErrorCode::cancelled, "wss_not_initialized"));
  }
  auto completion = impl_->begin_connect();
  if (!completion.valid()) {
    return Result<void>::failure(wss_error(ErrorCode::cancelled,
                                           "wss_connect_start_failed"));
  }
  return Result<void>::success();
}

Result<RelayWssReceiveStatus> RelayWssClient::try_receive(
    RelayWssMessage& message) {
  if (!impl_) {
    return Result<RelayWssReceiveStatus>::failure(
        wss_error(ErrorCode::cancelled, "wss_not_initialized"));
  }
  if (impl_->received.try_receive(message)) {
    return Result<RelayWssReceiveStatus>::success(RelayWssReceiveStatus::message);
  }
  const auto snapshot = impl_->snapshots.load().value;
  if (snapshot.state == RelayWssState::failed ||
      snapshot.state == RelayWssState::disconnected) {
    return Result<RelayWssReceiveStatus>::success(RelayWssReceiveStatus::closed);
  }
  return Result<RelayWssReceiveStatus>::success(RelayWssReceiveStatus::empty);
}

Result<void> RelayWssClient::send(std::span<const std::byte> payload) {
  if (!impl_) {
    return Result<void>::failure(wss_error(ErrorCode::cancelled, "wss_not_initialized"));
  }
  if (impl_->snapshots.load().value.state != RelayWssState::ready) {
    return Result<void>::failure(wss_error(ErrorCode::cancelled, "wss_not_ready"));
  }
  if (payload.empty() || payload.size() > max_relay_wss_control_frame_bytes) {
    return Result<void>::failure(wss_error(ErrorCode::configuration, "wss_payload_invalid"));
  }
  std::vector<std::byte> copy(payload.begin(), payload.end());
  if (!impl_->outgoing.try_send(std::move(copy))) {
    return Result<void>::failure(wss_error(ErrorCode::resource_exhausted,
                                           "wss_send_queue_full"));
  }
  auto weak = std::weak_ptr<RelayWssClient::Impl>{impl_};
  try {
    boost::asio::post(impl_->strand, [weak] {
      if (auto self = weak.lock()) {
        self->drain_send();
      }
    });
  } catch (...) {
    return Result<void>::failure(wss_error(ErrorCode::internal, "wss_send_post_failed"));
  }
  return Result<void>::success();
}

Result<RelayWssMessage> RelayWssClient::receive(std::chrono::milliseconds timeout) {
  if (!impl_) {
    return Result<RelayWssMessage>::failure(wss_error(ErrorCode::cancelled,
                                                      "wss_not_initialized"));
  }
  RelayWssMessage message;
  auto received = impl_->received.receive_for(message, timeout);
  if (!received) {
    return Result<RelayWssMessage>::failure(
        received.error_code == executor::comm::CommErrorCode::Timeout
            ? wss_error(ErrorCode::timeout, "wss_receive_timeout")
            : wss_error(ErrorCode::cancelled, "wss_receive_closed"));
  }
  return Result<RelayWssMessage>::success(std::move(message));
}

Result<void> RelayWssClient::start_close() {
  if (!impl_) {
    return Result<void>::failure(wss_error(ErrorCode::cancelled, "wss_not_initialized"));
  }
  auto completion = impl_->begin_close();
  if (!completion.valid()) {
    return Result<void>::failure(wss_error(ErrorCode::cancelled,
                                           "wss_close_start_failed"));
  }
  return Result<void>::success();
}

Result<void> RelayWssClient::close(std::chrono::milliseconds timeout) {
  if (!impl_) {
    return Result<void>::failure(wss_error(ErrorCode::cancelled, "wss_not_initialized"));
  }
  auto completion = impl_->begin_close();
  if (completion.wait_for(timeout) != std::future_status::ready) {
    return Result<void>::failure(wss_error(ErrorCode::timeout, "wss_close_wait_timeout"));
  }
  try {
    return completion.get();
  } catch (...) {
    return Result<void>::failure(wss_error(ErrorCode::internal, "wss_close_exception"));
  }
}

RelayWssSnapshot RelayWssClient::snapshot() const {
  return impl_ ? impl_->snapshots.load().value : RelayWssSnapshot{};
}

}  // namespace heyaki
