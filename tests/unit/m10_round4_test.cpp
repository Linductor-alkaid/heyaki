// M10 Round 4 independent verification: the initiator-side `opening`/
// on_connected semantics (M10-08 explicit connect state), the serving-side
// human confirmation flow (M10-06), and the SOCKS5 CONNECT frontend
// (M10-09) — including a Node-level end-to-end round trip through a real
// Runtime, plus TUI CLI parse smoke against the built binary.
//
// Harness model mirrors m10_gateway_service_test.cpp: one test thread,
// pump-driven loopback transport, gateway sockets/resolver on a test-owned
// io_context polled by the same thread. The SOCKS section additionally
// drives a real (executor-owned) Runtime for node A.

#include "byte_stream.hpp"
#include "gateway_service.hpp"
#include "m4_support.hpp"
#include "m5_support.hpp"
#include "peer_session.hpp"
#include "socks_frontend.hpp"

#include <heyaki/byte_stream.hpp>
#include <heyaki/error.hpp>
#include <heyaki/gateway.hpp>
#include <heyaki/identity.hpp>
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/runtime.hpp>
#include <heyaki/signaling_protocol.hpp>

#include <executor/comm.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace heyaki {
namespace {

constexpr std::uint64_t kNow = 1'700'000'000'000U;

template <typename Storage, std::size_t Size = sizeof(Storage)>
Storage filled(std::uint8_t seed) {
  Storage storage{};
  auto* bytes = reinterpret_cast<std::uint8_t*>(&storage);
  for (std::size_t index = 0U; index < Size; ++index) {
    bytes[index] = static_cast<std::uint8_t>(seed + index);
  }
  return storage;
}

template <std::size_t Size>
std::array<std::byte, Size> filled_array(std::uint8_t seed) {
  std::array<std::byte, Size> value{};
  for (std::size_t index = 0U; index < Size; ++index) {
    value[index] = static_cast<std::byte>(seed + index);
  }
  return value;
}

std::span<const std::byte> as_bytes(std::string_view text) {
  return std::span<const std::byte>{reinterpret_cast<const std::byte*>(text.data()),
                                    text.size()};
}

std::string as_text(const std::vector<std::byte>& data) {
  std::string text;
  text.reserve(data.size());
  for (const auto byte : data) {
    text.push_back(static_cast<char>(byte));
  }
  return text;
}

// ---- Loopback session pair (same harness as the Round 3 suite) ----------------

struct GatewaySessionPair {
  test::LoopbackTransportPair pair;
  Result<IdentityKeyPair> left_identity{create_identity()};
  Result<IdentityKeyPair> right_identity{create_identity()};
  std::map<DeviceId, std::vector<std::string>> left_trust;
  std::map<DeviceId, std::vector<std::string>> right_trust;
  std::shared_ptr<PeerSession> left;
  std::shared_ptr<PeerSession> right;

  GatewaySessionPair(ProtocolHello left_protocol, ProtocolHello right_protocol) {
    EXPECT_TRUE(left_identity && right_identity);
    pair.connect();
    transport::ChannelOptions control_options;
    pair.left().async_open_channel(transport::ChannelKind::control, control_options,
                                   [](Result<transport::TransportChannel*>) {});
    pair.right().async_open_channel(transport::ChannelKind::control, control_options,
                                    [](Result<transport::TransportChannel*>) {});
    build_sessions(left_protocol, right_protocol);
  }

  [[nodiscard]] DeviceEndpointKey left_key() const {
    return {left_identity.value_if()->device_id(), filled<EndpointId>(0x20U)};
  }
  [[nodiscard]] DeviceEndpointKey right_key() const {
    return {right_identity.value_if()->device_id(), filled<EndpointId>(0x40U)};
  }

  void build_sessions(ProtocolHello left_protocol, ProtocolHello right_protocol) {
    const auto session_id = filled<SessionId>(0x60U);
    const auto initiator_nonce = filled_array<signaling_nonce_bytes>(0x10U);
    const auto responder_nonce = filled_array<signaling_nonce_bytes>(0x30U);
    const auto transcript = filled_array<signaling_transcript_sha256_bytes>(0x50U);
    auto left_transport = std::shared_ptr<transport::TransportSession>(
        &pair.left(), [](transport::TransportSession*) {});
    auto right_transport = std::shared_ptr<transport::TransportSession>(
        &pair.right(), [](transport::TransportSession*) {});
    VerifiedSessionBinding left_binding{
        {right_key(), left_key(), session_id, 1U, initiator_nonce, responder_nonce,
         transcript},
        {},
        "peer-ufrag",
        true};
    VerifiedSessionBinding right_binding{
        {left_key(), right_key(), session_id, 1U, initiator_nonce, responder_nonce,
         transcript},
        {},
        "peer-ufrag",
        false};

    auto left_timeline = std::make_shared<ConnectionAttemptTimeline>();
    EXPECT_TRUE(left_timeline->transition(ConnectionStage::resolving_endpoint, "test",
                                          "endpoint_selected"));
    EXPECT_TRUE(left_timeline->transition(ConnectionStage::signaling, "test",
                                          "attempt_accepted"));
    auto right_timeline = std::make_shared<ConnectionAttemptTimeline>();
    EXPECT_TRUE(right_timeline->transition(ConnectionStage::resolving_endpoint, "test",
                                          "endpoint_selected"));
    EXPECT_TRUE(right_timeline->transition(ConnectionStage::signaling, "test",
                                          "attempt_accepted"));

    auto build = [&](VerifiedSessionBinding binding,
                     const IdentityKeyPair& identity, const IdentityKeyPair& peer,
                     ProtocolHello protocol,
                     std::map<DeviceId, std::vector<std::string>>& trust,
                     const std::shared_ptr<ConnectionAttemptTimeline>& timeline,
                     std::shared_ptr<transport::TransportSession> transport)
        -> Result<std::shared_ptr<PeerSession>> {
      return PeerSession::create_verified(
          {.transport = std::move(transport),
           .binding = binding,
           .local_identity = &identity,
           .peer_public_key = peer.public_key(),
           .local_protocol = protocol,
           .expires_unix_milliseconds = kNow + 60'000U,
           .now_unix_milliseconds = kNow,
           .observer = {},
           .timeline = timeline,
           .clock = {},
           .trust_authorizer = [&trust, peer_id = peer.device_id()](std::uint64_t now) {
             SessionAuthorization authorization;
             auto found = trust.find(peer_id);
             if (found != trust.end()) {
               authorization.trusted = true;
               authorization.scopes = found->second;
             }
             authorization.pairing_allowed = false;
             (void)now;
             return Result<SessionAuthorization>::success(authorization);
           },
           .wall_clock = [] { return kNow; }});
    };

    auto left_created = build(left_binding, *left_identity.value_if(),
                              *right_identity.value_if(), left_protocol, left_trust,
                              left_timeline, left_transport);
    ASSERT_TRUE(left_created);
    left = *left_created.value_if();
    auto right_created = build(right_binding, *right_identity.value_if(),
                               *left_identity.value_if(), right_protocol, right_trust,
                               right_timeline, right_transport);
    ASSERT_TRUE(right_created);
    right = *right_created.value_if();
  }

  void pump_all(int rounds = 8) {
    for (int round = 0; round < rounds; ++round) {
      pair.left().pump();
      pair.right().pump();
    }
  }

  void start_authenticated(const std::vector<std::string>& scopes = {"stream.open"}) {
    left_trust[right_identity.value_if()->device_id()] = scopes;
    right_trust[left_identity.value_if()->device_id()] = scopes;
    ASSERT_TRUE(left->start());
    ASSERT_TRUE(right->start());
    pump_all();
    ASSERT_TRUE(left->authenticated() && right->authenticated());
  }
};

ProtocolHello protocol_13_hello() {
  return {.version = ProtocolVersion{1U, 3U},
          .supported = {protocol_1_3_capability_bits},
          .required = {static_cast<std::uint64_t>(Capability::session)}};
}

// ---- Local network detection / echo target ------------------------------------

std::string detect_non_loopback_v4(boost::asio::io_context& io) {
  // Candidate from the UDP egress probe, then PROVE dialability with a
  // real TCP round trip: on some CI runners the egress interface address
  // exists but hairpin TCP dials to it are dropped by the host fabric —
  // the gateway echo tests then flap on dial timeouts. A candidate that
  // cannot round-trip here means "environment unsuitable" (the callers
  // skip), not a product failure.
  boost::system::error_code ec;
  boost::asio::ip::udp::socket probe{io};
  probe.open(boost::asio::ip::udp::v4(), ec);
  if (ec) return {};
  probe.connect(boost::asio::ip::udp::endpoint{
                    boost::asio::ip::make_address("8.8.8.8", ec), 53U},
                ec);
  if (ec) return {};
  const auto local = probe.local_endpoint(ec);
  boost::system::error_code ignored;
  probe.close(ignored);
  if (ec || local.address().is_loopback() || local.address().is_unspecified()) {
    return {};
  }
  const auto candidate = local.address();
  boost::asio::ip::tcp::acceptor verifier{io};
  verifier.open(boost::asio::ip::tcp::v4(), ec);
  if (ec) return {};
  verifier.bind(boost::asio::ip::tcp::endpoint{candidate, 0U}, ec);
  if (ec) return {};
  verifier.listen(1, ec);
  if (ec) return {};
  boost::asio::ip::tcp::socket client{io};
  client.connect(verifier.local_endpoint(ec), ec);
  if (ec) return {};
  boost::system::error_code close_ec;
  client.close(close_ec);
  verifier.close(close_ec);
  return candidate.to_string();
}

class EchoTarget : public std::enable_shared_from_this<EchoTarget> {
 public:
  explicit EchoTarget(boost::asio::io_context& io, const std::string& address)
      : acceptor_{std::make_unique<boost::asio::ip::tcp::acceptor>(io)} {
    boost::system::error_code ec;
    const auto addr = boost::asio::ip::make_address(address, ec);
    if (ec) return;
    boost::asio::ip::tcp::endpoint endpoint{addr, 0U};
    acceptor_->open(endpoint.protocol(), ec);
    if (ec) return;
    acceptor_->bind(endpoint, ec);
    if (ec) return;
    acceptor_->listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) return;
    port_ = acceptor_->local_endpoint(ec).port();
    ok_ = !ec && port_ != 0U;
  }

  void start() {
    if (ok_) start_accept();
  }

  [[nodiscard]] bool ok() const noexcept { return ok_; }
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] std::size_t accepted() const noexcept { return accepted_; }
  [[nodiscard]] std::size_t closed() const noexcept { return closed_; }

 private:
  void start_accept() {
    auto socket =
        std::make_shared<boost::asio::ip::tcp::socket>(acceptor_->get_executor());
    acceptor_->async_accept(
        *socket, [self = shared_from_this(), socket](const boost::system::error_code& error) {
          if (error) return;
          ++self->accepted_;
          self->connections_.push_back(socket);
          self->do_read(socket);
          self->start_accept();
        });
  }

  void do_read(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) {
    auto buffer = std::make_shared<std::vector<std::byte>>(4096U);
    socket->async_read_some(
        boost::asio::buffer(buffer->data(), buffer->size()),
        [self = shared_from_this(), socket, buffer](const boost::system::error_code& error,
                                                    std::size_t bytes) {
          if (error || bytes == 0U) {
            self->close_socket(socket);
            return;
          }
          boost::asio::async_write(
              *socket, boost::asio::buffer(buffer->data(), bytes),
              [self, socket](const boost::system::error_code& error, std::size_t) {
                if (error) {
                  self->close_socket(socket);
                  return;
                }
                self->do_read(socket);
              });
        });
  }

  void close_socket(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) {
    ++closed_;
    boost::system::error_code ignored;
    socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
    socket->close(ignored);
  }

  std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
  std::vector<std::shared_ptr<boost::asio::ip::tcp::socket>> connections_;
  std::uint16_t port_{0U};
  bool ok_{false};
  std::size_t accepted_{0U};
  std::size_t closed_{0U};
};

// ---- Shared round-4 fixture: stream pair + optional GatewayService ------------

struct CapturedRead {
  bool completed{false};
  std::size_t bytes{0U};
  std::optional<Error> error;
  std::vector<std::byte> data;
};

// Records the one-shot connect outcome for gateway initiator streams.
// Always hold this via shared_ptr and capture the shared_ptr by value in the
// on_connected lambda: since the D1 fix the handler fires during
// ByteStreamService teardown (fail_all / service destruction), which happens
// in TearDown after the test body's frame — including any stack ConnectOutcome
// — is already destroyed. The shared_ptr anchor keeps the late fire writing
// to live memory (it reproduces as SIGSEGV in basic_string::assign otherwise).
struct ConnectOutcome {
  std::atomic<int> fires{0};
  bool has_error{false};
  ErrorCode code{ErrorCode::internal};
  std::string detail;

  void record(Result<void> result) {
    const int count = fires.fetch_add(1) + 1;
    (void)count;
    if (!result) {
      has_error = true;
      code = result.error_if()->code();
      detail = result.error_if()->safe_detail();
    }
  }
};

[[nodiscard]] std::shared_ptr<ConnectOutcome> new_connect_outcome() {
  return std::make_shared<ConnectOutcome>();
}

// Heap-anchored capture for one-shot write completions: a write that never
// finishes in the test body is completed by fail_all during service teardown
// (after the caller's frame is gone), so the handler must not reference the
// frame's locals.
struct WriteCapture {
  bool done{false};
  std::optional<Error> error;
};

class M10Round4Test : public ::testing::Test {
 protected:
  void SetUp() override {
    pair_ = std::make_unique<GatewaySessionPair>(protocol_13_hello(),
                                                  protocol_13_hello());
    pair_->start_authenticated();
    ByteStreamLimits limits;
    limits.default_receive_window_bytes = 4096U;
    limits.default_receive_window_frames = 4U;
    limits.max_data_chunk_bytes = 1024U;
    left_ = std::make_unique<ByteStreamService>(*pair_->left, limits,
                                                [this] { return now_ms_; });
    right_ = std::make_unique<ByteStreamService>(*pair_->right, limits,
                                                 [this] { return now_ms_; });
    ASSERT_TRUE(left_->attach() && right_->attach());
    pair_->pump_all();
    local_address_ = detect_non_loopback_v4(io_);
  }

  void TearDown() override {
    gw_.reset();
    for (int round = 0; round < 8; ++round) {
      if (io_.stopped()) io_.restart();
      const auto ran = io_.poll();
      pair_->pump_all();
      if (ran == 0U) break;
    }
    right_.reset();
    left_.reset();
    pair_.reset();
  }

  // Installs a serving-side GatewayService. `confirm_sink` rides the 8th
  // constructor parameter exactly like the node wiring (the effective sink).
  void install_gateway(std::vector<GatewayProfileConfig> profiles,
                       std::vector<std::string> provide_scopes,
                       GatewayConfirmSink confirm_sink = {}) {
    GatewayServiceConfig config;
    config.profiles = std::move(profiles);
    config.peer_device = pair_->left_identity.value_if()->device_id();
    config.confirm_sink = confirm_sink;
    provide_scopes_ = std::move(provide_scopes);
    gw_ = std::make_shared<GatewayService>(
        *pair_->right, *right_, std::move(config), io_.get_executor(),
        [this](std::function<void()> task) {
          boost::asio::post(io_, std::move(task));
        },
        [this](std::string_view scope) {
          return std::find(provide_scopes_.begin(), provide_scopes_.end(),
                           std::string{scope}) != provide_scopes_.end();
        },
        [this] { return now_ms_; }, std::move(confirm_sink));
    ASSERT_TRUE(gw_->attach());
  }

  [[nodiscard]] Result<std::shared_ptr<ByteStreamHandle>> open_from_a(
      const GatewayConnect& target, std::uint64_t dial_deadline = 0U,
      std::function<void(Result<void>)> on_connected = {}) {
    return left_->open_gateway_stream(target, 4096U, 4U, dial_deadline,
                                      std::move(on_connected));
  }

  void drive_io(std::chrono::milliseconds budget) {
    if (io_.stopped()) io_.restart();
    (void)io_.run_for(budget);
  }

  void spin(int rounds = 16) {
    for (int round = 0; round < rounds; ++round) {
      if (io_.stopped()) io_.restart();
      (void)io_.poll();
      pair_->pump_all();
    }
  }

  template <typename Predicate>
  bool spin_until(Predicate predicate, int total_milliseconds,
                  int slice_milliseconds = 25) {
    for (int waited = 0; !predicate() && waited < total_milliseconds;
         waited += slice_milliseconds) {
      drive_io(std::chrono::milliseconds{slice_milliseconds});
      pair_->pump_all();
    }
    pair_->pump_all();
    return predicate();
  }

  [[nodiscard]] static std::shared_ptr<CapturedRead> pend_read(
      ByteStreamHandle& stream, std::size_t capacity) {
    auto out = std::make_shared<CapturedRead>();
    auto buffer = std::make_shared<std::array<std::byte, 4096U>>();
    const std::size_t bounded = std::min(capacity, buffer->size());
    stream.async_read_some(std::span<std::byte>{buffer->data(), bounded},
                           [out, buffer](StreamIoResult result) {
                             out->completed = true;
                             out->bytes = result.bytes;
                             out->error = result.error;
                             if (result.bytes > 0U) {
                               out->data.assign(buffer->begin(),
                                                buffer->begin() +
                                                    static_cast<std::ptrdiff_t>(
                                                        result.bytes));
                             }
                           });
    return out;
  }

  [[nodiscard]] bool write_bytes(ByteStreamHandle& stream,
                                 std::span<const std::byte> data) {
    auto capture = std::make_shared<WriteCapture>();
    stream.async_write(data, [capture](StreamIoResult result) {
      capture->done = true;
      capture->error = result.error;
    });
    pair_->pump_all();
    return capture->done && !capture->error.has_value();
  }

  [[nodiscard]] bool write_all(ByteStreamHandle& stream, std::string_view text) {
    return write_bytes(stream, as_bytes(text));
  }

  static std::uint64_t refusals_of(const GatewayService& service,
                                   GatewayRefusal refusal) {
    return service.stats().refusals[static_cast<std::size_t>(refusal)];
  }

  boost::asio::io_context io_;
  std::unique_ptr<GatewaySessionPair> pair_;
  std::uint64_t now_ms_{kNow};
  std::vector<std::string> provide_scopes_;
  std::string local_address_;
  std::unique_ptr<ByteStreamService> left_;
  std::unique_ptr<ByteStreamService> right_;
  std::shared_ptr<GatewayService> gw_;
};

GatewayProfileConfig profile_for(const std::string& name,
                                 std::initializer_list<std::string> cidrs) {
  GatewayProfileConfig profile;
  profile.name = name;
  for (const auto& cidr : cidrs) {
    auto parsed = parse_gateway_cidr(cidr);
    if (parsed.has_value()) {
      profile.allowed_cidrs.push_back(*parsed);
    }
  }
  profile.allowed_ports.push_back(GatewayPortRange{1U, 65535U});
  return profile;
}

// ==== 1. Initiator opening / on_connected semantics (M10-08) ===================

TEST_F(M10Round4Test, InitiatorOpeningUntilPreludeThenConnectedOnce) {
  auto inbound = std::make_shared<std::vector<std::shared_ptr<ByteStreamHandle>>>();
  right_->set_gateway_inbound_handler(
      [inbound](const std::shared_ptr<ByteStreamHandle>& stream, const GatewayConnect&) {
        inbound->push_back(stream);
      });

  auto connected = new_connect_outcome();
  auto opened = open_from_a({.host = "203.0.113.9", .port = 443, .profile = "office"},
                            0U, [connected](Result<void> result) {
                              connected->record(std::move(result));
                            });
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();

  // Pre-prelude: the stream reports `opening`, never `open`, and the
  // one-shot connect handler must not have fired.
  EXPECT_EQ(stream->state(), StreamState::opening);
  pair_->pump_all();
  EXPECT_EQ(stream->state(), StreamState::opening);
  EXPECT_EQ(connected->fires.load(), 0);
  ASSERT_EQ(inbound->size(), 1U);

  // A write while opening queues normally (connecting != not writable).
  ASSERT_TRUE(write_all(*stream, "EARLY"));
  EXPECT_EQ(stream->state(), StreamState::opening);

  const auto prelude = encode_gateway_prelude(gateway_prelude_connected);
  ASSERT_TRUE(write_bytes(*(*inbound)[0],
                          std::span<const std::byte>{prelude.data(), prelude.size()}));
  pair_->pump_all();

  // Prelude validated: promoted to open, connect handler fired exactly once
  // with success.
  EXPECT_EQ(stream->state(), StreamState::open);
  EXPECT_EQ(connected->fires.load(), 1);
  EXPECT_FALSE(connected->has_error);

  // Further data must not re-trigger the connect handler.
  ASSERT_TRUE(write_all(*(*inbound)[0], "PAYLOAD"));
  pair_->pump_all();
  EXPECT_EQ(connected->fires.load(), 1);
  auto read = pend_read(*stream, 64U);
  ASSERT_TRUE(read->completed);
  EXPECT_EQ(as_text(read->data), "PAYLOAD");
  EXPECT_EQ(stream->state(), StreamState::open);
}

TEST_F(M10Round4Test, InitiatorConnectedFailsOnceOnPrePreludeReset) {
  right_->set_gateway_inbound_handler(
      [](const std::shared_ptr<ByteStreamHandle>& stream, const GatewayConnect&) {
        stream->reset(StableStatus::permission_denied);
      });

  auto connected = new_connect_outcome();
  auto opened = open_from_a({.host = "203.0.113.9", .port = 443, .profile = "office"},
                            0U, [connected](Result<void> result) {
                              connected->record(std::move(result));
                            });
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  pair_->pump_all();

  ASSERT_EQ(stream->state(), StreamState::reset);
  ASSERT_EQ(connected->fires.load(), 1);
  ASSERT_TRUE(connected->has_error);
  // The reset's StableStatus rides the failure: permission_denied == 5 on
  // the wire, surfaced as remote_error / gateway_connect_failed_5.
  EXPECT_EQ(connected->code, ErrorCode::remote_error);
  EXPECT_EQ(connected->detail, "gateway_connect_failed_5");
  // Safe-detail token grammar: lowercase letters, digits, and underscore only.
  EXPECT_EQ(connected->detail.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_"),
            std::string::npos)
      << "detail must be a safe token: " << connected->detail;

  // A repeated RESET is idempotent and must not fire the handler again.
  pair_->pump_all();
  EXPECT_EQ(connected->fires.load(), 1);
}

// SPEC (M10-08): a gateway initiator stream that ends before the prelude —
// including session loss — must complete on_connected exactly once with an
// error (gateway_connect_closed or the gateway_connect_failed_<status>
// family).
//
// Regression guard (M10-R4-D1, fixed 2026-09-20): ByteStreamService::fail_all
// (src/client/byte_stream.cpp, called from the service destructor — exactly
// what node.cpp teardown_peer_services runs on session loss via
// stream_services.erase) previously completed pending reads/writes and
// marked the stream reset, but never fired the one-shot
// gateway_connected_handler_ (`fires` stayed 0): a caller waiting on the
// connect outcome (the SOCKS frontend times its REP reply on it) hung until
// its own deadline when the session died mid-connect. fail_all now fails the
// handler exactly once with cancelled/gateway_connect_closed before the
// pending read/write completions. Semantic consequence this test relies on:
// the handler may fire during service destruction/teardown, so callers must
// anchor captured state (see ConnectOutcome).
TEST_F(M10Round4Test, InitiatorConnectedFailsOnServiceTeardownBeforePrelude) {
  right_->set_gateway_inbound_handler(
      [](const std::shared_ptr<ByteStreamHandle>&, const GatewayConnect&) {});
  auto connected = new_connect_outcome();
  auto opened = open_from_a({.host = "203.0.113.9", .port = 443, .profile = "office"},
                            0U, [connected](Result<void> result) {
                              connected->record(std::move(result));
                            });
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  auto read = pend_read(*stream, 64U);
  pair_->pump_all();
  EXPECT_EQ(stream->state(), StreamState::opening);
  EXPECT_EQ(connected->fires.load(), 0);

  // Session loss in production tears the ByteStreamService down via
  // stream_services.erase() (node.cpp teardown_peer_services), whose
  // destructor runs exactly this fail_all() path. The one-shot connect
  // handler must complete with an error exactly once (gateway_connect_closed
  // or the gateway_connect_failed_<status> family).
  left_->fail_all(Error{ErrorCode::cancelled, "byte_stream", "service_closed"});
  ASSERT_EQ(stream->state(), StreamState::reset);
  ASSERT_TRUE(read->completed);
  ASSERT_EQ(connected->fires.load(), 1) << "session close before the prelude must "
                                          "complete on_connected exactly once";
  ASSERT_TRUE(connected->has_error);
  const bool closed_family = connected->detail == "gateway_connect_closed";
  const bool failed_family = connected->detail.rfind("gateway_connect_failed_", 0U) == 0U;
  EXPECT_TRUE(closed_family || failed_family)
      << "unexpected connect-failure detail: " << connected->detail;
}

TEST_F(M10Round4Test, PlainStreamStaysImmediatelyOpen) {
  // Regression: only gateway initiator streams gained `opening`; a plain
  // stream is open the moment open_stream returns.
  auto inbound = std::make_shared<std::vector<std::shared_ptr<ByteStreamHandle>>>();
  right_->set_inbound_handler(
      [inbound](const std::shared_ptr<ByteStreamHandle>& stream) {
        inbound->push_back(stream);
      });
  auto opened = left_->open_stream(4096U, 4U);
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  EXPECT_FALSE(stream->is_gateway());
  EXPECT_EQ(stream->state(), StreamState::open);
  pair_->pump_all();
  ASSERT_EQ(inbound->size(), 1U);
  EXPECT_EQ((*inbound)[0]->state(), StreamState::open);
  ASSERT_TRUE(write_all(*stream, "PLAIN"));
  auto read = pend_read(*(*inbound)[0], 32U);
  EXPECT_TRUE(read->completed);
  EXPECT_EQ(as_text(read->data), "PLAIN");
}

// ==== 2. Serving-side confirmation flow (M10-06) ================================

// One parked confirmation: the request shown to the operator plus the decider.
struct CapturedConfirm {
  GatewayConfirmRequest request;
  std::function<void(bool)> decide;
};

TEST_F(M10Round4Test, ConfirmNeverSkipsSinkAndAdmits) {
  auto profile = profile_for("office", {"203.0.113.0/24"});
  profile.confirm = GatewayConfirmMode::never;
  profile.dial_deadline = std::chrono::milliseconds{30000};
  auto sink_calls = std::make_shared<int>(0);  // heap-anchored for the sink lambda
  install_gateway({profile}, {"gateway.provide:office"},
                  [sink_calls](const GatewayConfirmRequest&, std::function<void(bool)>) {
                    ++*sink_calls;
                  });

  auto connected = new_connect_outcome();
  auto opened = open_from_a({.host = "203.0.113.1", .port = 80, .profile = "office"},
                            0U, [connected](Result<void> result) {
                              connected->record(std::move(result));
                            });
  ASSERT_TRUE(opened);
  spin(6);
  EXPECT_EQ(*sink_calls, 0);
  EXPECT_EQ(connected->fires.load(), 0);
  // Admitted (tunnel registered, mid-dial, so no prelude yet).
  EXPECT_EQ(gw_->stats().tunnels_active, 1U);
  EXPECT_EQ((*opened.value_if())->state(), StreamState::opening);
}

TEST_F(M10Round4Test, ConfirmAlwaysParksThenProceedsAfterYes) {
  auto profile = profile_for("office", {"10.0.0.0/8"});
  profile.confirm = GatewayConfirmMode::always;
  // Anchored on the heap: the confirm sink is owned by the GatewayService and
  // could in principle observe a late in-flight open during TearDown's drain
  // (after this frame is gone), so the sink captures the shared_ptr by value.
  auto asks = std::make_shared<std::vector<CapturedConfirm>>();
  install_gateway({profile}, {"gateway.provide:office"},
                  [asks](const GatewayConfirmRequest& request,
                         std::function<void(bool)> decide) {
                    asks->push_back(CapturedConfirm{request, std::move(decide)});
                  });

  auto connected = new_connect_outcome();
  // A hostname that cannot resolve: after the decision the continuation is
  // observable as dial_failed (the serving side attempted the resolve).
  auto opened = open_from_a(
      {.host = "no-such-host.invalid", .port = 80, .profile = "office"},
      0U, [connected](Result<void> result) { connected->record(std::move(result)); });
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();

  ASSERT_TRUE(spin_until([&] { return asks->size() >= 1U; }, 2000))
      << "confirm sink never asked";
  EXPECT_EQ(stream->state(), StreamState::opening);
  EXPECT_EQ(connected->fires.load(), 0);
  // Parked: the slot is held, but nothing resolves or dials yet.
  EXPECT_EQ(gw_->stats().tunnels_active, 1U);
  EXPECT_EQ(gw_->stats().dials_failed, 0U);

  // The prompt carries the validated request for the operator.
  EXPECT_EQ((*asks)[0].request.profile, "office");
  EXPECT_EQ((*asks)[0].request.host, "no-such-host.invalid");
  EXPECT_EQ((*asks)[0].request.port, 80U);
  EXPECT_EQ((*asks)[0].request.peer_device,
            pair_->left_identity.value_if()->device_id());

  (*asks)[0].decide(true);
  ASSERT_TRUE(spin_until([&] { return stream->state() == StreamState::reset; }, 5000))
      << "post-confirmation continuation never ran";
  EXPECT_EQ(gw_->stats().dials_failed, 1U);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::dial_failed), 1U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
  EXPECT_EQ(asks->size(), 1U);
  // The connect outcome surfaces the coarse unavailable status (10).
  ASSERT_EQ(connected->fires.load(), 1);
  ASSERT_TRUE(connected->has_error);
  EXPECT_EQ(connected->detail, "gateway_connect_failed_10");
}

TEST_F(M10Round4Test, ConfirmAlwaysAsksAgainOnEveryOpen) {
  auto profile = profile_for("office", {"10.0.0.0/8"});
  profile.confirm = GatewayConfirmMode::always;
  // Anchored on the heap: the confirm sink is owned by the GatewayService and
  // could in principle observe a late in-flight open during TearDown's drain
  // (after this frame is gone), so the sink captures the shared_ptr by value.
  auto asks = std::make_shared<std::vector<CapturedConfirm>>();
  install_gateway({profile}, {"gateway.provide:office"},
                  [asks](const GatewayConfirmRequest& request,
                         std::function<void(bool)> decide) {
                    asks->push_back(CapturedConfirm{request, std::move(decide)});
                  });

  auto first = open_from_a(
      {.host = "no-such-host.invalid", .port = 80, .profile = "office"});
  ASSERT_TRUE(first);
  ASSERT_TRUE(spin_until([&] { return asks->size() >= 1U; }, 2000));
  (*asks)[0].decide(true);
  ASSERT_TRUE(spin_until([&] { return (*first.value_if())->state() == StreamState::reset; },
                         5000));

  // `always` never remembers: the second open asks again.
  auto second = open_from_a(
      {.host = "no-such-host.invalid", .port = 81, .profile = "office"});
  ASSERT_TRUE(second);
  ASSERT_TRUE(spin_until([&] { return asks->size() >= 2U; }, 2000));
  EXPECT_EQ((*asks)[1].request.port, 81U);
  (*asks)[1].decide(true);
  ASSERT_TRUE(spin_until([&] { return (*second.value_if())->state() == StreamState::reset; },
                         5000));
  EXPECT_EQ(gw_->stats().dials_failed, 2U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
}

TEST_F(M10Round4Test, ConfirmFirstUseRemembersProfileAfterYes) {
  auto profile = profile_for("office", {"10.0.0.0/8"});
  profile.confirm = GatewayConfirmMode::first_use;
  // Anchored on the heap: the confirm sink is owned by the GatewayService and
  // could in principle observe a late in-flight open during TearDown's drain
  // (after this frame is gone), so the sink captures the shared_ptr by value.
  auto asks = std::make_shared<std::vector<CapturedConfirm>>();
  install_gateway({profile}, {"gateway.provide:office"},
                  [asks](const GatewayConfirmRequest& request,
                         std::function<void(bool)> decide) {
                    asks->push_back(CapturedConfirm{request, std::move(decide)});
                  });

  auto first = open_from_a(
      {.host = "no-such-host.invalid", .port = 80, .profile = "office"});
  ASSERT_TRUE(first);
  ASSERT_TRUE(spin_until([&] { return asks->size() >= 1U; }, 2000));
  (*asks)[0].decide(true);
  ASSERT_TRUE(spin_until([&] { return (*first.value_if())->state() == StreamState::reset; },
                         5000));

  // Second open under the same profile: remembered, no second ask, and the
  // request proceeds straight into the (failing) resolve — proving it was
  // admitted rather than silently denied.
  auto second = open_from_a(
      {.host = "no-such-host.invalid", .port = 82, .profile = "office"});
  ASSERT_TRUE(second);
  ASSERT_TRUE(spin_until([&] { return (*second.value_if())->state() == StreamState::reset; },
                         5000));
  EXPECT_EQ(asks->size(), 1U) << "first_use must not re-ask for a remembered profile";
  EXPECT_EQ(gw_->stats().dials_failed, 2U);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::policy_denied), 0U);
}

TEST_F(M10Round4Test, ConfirmDenyResetsPolicyDeniedAndReleasesSlot) {
  auto profile = profile_for("office", {"10.0.0.0/8"});
  profile.confirm = GatewayConfirmMode::always;
  profile.max_concurrent_streams_per_session = 1U;
  // Anchored on the heap: the confirm sink is owned by the GatewayService and
  // could in principle observe a late in-flight open during TearDown's drain
  // (after this frame is gone), so the sink captures the shared_ptr by value.
  auto asks = std::make_shared<std::vector<CapturedConfirm>>();
  install_gateway({profile}, {"gateway.provide:office"},
                  [asks](const GatewayConfirmRequest& request,
                         std::function<void(bool)> decide) {
                    asks->push_back(CapturedConfirm{request, std::move(decide)});
                  });

  auto connected = new_connect_outcome();
  auto opened = open_from_a(
      {.host = "no-such-host.invalid", .port = 80, .profile = "office"},
      0U, [connected](Result<void> result) { connected->record(std::move(result)); });
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  ASSERT_TRUE(spin_until([&] { return asks->size() >= 1U; }, 2000));
  EXPECT_EQ(gw_->stats().tunnels_active, 1U);

  (*asks)[0].decide(false);
  pair_->pump_all();
  ASSERT_TRUE(spin_until([&] { return stream->state() == StreamState::reset; }, 2000));
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::policy_denied), 1U);
  EXPECT_EQ(gw_->stats().dials_failed, 0U);
  // The slot is released with the refusal.
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
  // The initiator observes permission_denied (5) through the connect path.
  ASSERT_EQ(connected->fires.load(), 1);
  ASSERT_TRUE(connected->has_error);
  EXPECT_EQ(connected->detail, "gateway_connect_failed_5");

  // The service is not wedged: the next open is asked again and can proceed.
  auto second = open_from_a(
      {.host = "no-such-host.invalid", .port = 83, .profile = "office"});
  ASSERT_TRUE(second);
  ASSERT_TRUE(spin_until([&] { return asks->size() >= 2U; }, 2000));
  (*asks)[1].decide(true);
  ASSERT_TRUE(spin_until([&] { return (*second.value_if())->state() == StreamState::reset; },
                         5000));
  EXPECT_EQ(gw_->stats().dials_failed, 1U);
}

TEST_F(M10Round4Test, ConfirmWithoutSinkFailsClosed) {
  auto profile = profile_for("office", {"10.0.0.0/8"});
  profile.confirm = GatewayConfirmMode::always;
  install_gateway({profile}, {"gateway.provide:office"},
                  GatewayConfirmSink{});  // nobody can answer

  auto connected = new_connect_outcome();
  auto opened = open_from_a(
      {.host = "no-such-host.invalid", .port = 80, .profile = "office"},
      0U, [connected](Result<void> result) { connected->record(std::move(result)); });
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  pair_->pump_all();

  EXPECT_EQ(stream->state(), StreamState::reset);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::policy_denied), 1U);
  EXPECT_EQ(gw_->stats().dials_failed, 0U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
  ASSERT_EQ(connected->fires.load(), 1);
  ASSERT_TRUE(connected->has_error);
  EXPECT_EQ(connected->detail, "gateway_connect_failed_5");
}

TEST_F(M10Round4Test, ConfirmDeadlineAutoDeniesAfterThirtySeconds) {
  auto profile = profile_for("office", {"10.0.0.0/8"});
  profile.confirm = GatewayConfirmMode::always;
  // Anchored on the heap: the confirm sink is owned by the GatewayService and
  // could in principle observe a late in-flight open during TearDown's drain
  // (after this frame is gone), so the sink captures the shared_ptr by value.
  auto asks = std::make_shared<std::vector<CapturedConfirm>>();
  install_gateway({profile}, {"gateway.provide:office"},
                  [asks](const GatewayConfirmRequest& request,
                         std::function<void(bool)> decide) {
                    asks->push_back(CapturedConfirm{request, std::move(decide)});
                  });

  auto connected = new_connect_outcome();
  auto opened = open_from_a(
      {.host = "no-such-host.invalid", .port = 80, .profile = "office"},
      0U, [connected](Result<void> result) { connected->record(std::move(result)); });
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  ASSERT_TRUE(spin_until([&] { return asks->size() >= 1U; }, 2000));
  // The operator never answers.

  // Exactly at the 30s boundary the sweep must not deny (strictly greater).
  now_ms_ = kNow + static_cast<std::uint64_t>(gateway_confirm_deadline.count());
  gw_->prune();
  pair_->pump_all();
  EXPECT_EQ(gw_->stats().tunnels_active, 1U);
  EXPECT_EQ(stream->state(), StreamState::opening);
  EXPECT_EQ(connected->fires.load(), 0);

  // One millisecond past the deadline: auto-denied, slot released.
  now_ms_ = kNow + static_cast<std::uint64_t>(gateway_confirm_deadline.count()) + 1U;
  gw_->prune();
  pair_->pump_all();
  EXPECT_EQ(stream->state(), StreamState::reset);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::policy_denied), 1U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
  ASSERT_EQ(connected->fires.load(), 1);
  ASSERT_TRUE(connected->has_error);
  EXPECT_EQ(connected->detail, "gateway_connect_failed_5");

  // A late operator YES is a no-op: the tunnel is gone, nothing dials.
  (*asks)[0].decide(true);
  spin(4);
  EXPECT_EQ(gw_->stats().dials_failed, 0U);
  EXPECT_EQ(gw_->stats().dials_succeeded, 0U);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::policy_denied), 1U);
}

TEST_F(M10Round4Test, AwaitingConfirmTunnelNotIdleSwept) {
  auto profile = profile_for("office", {"10.0.0.0/8"});
  profile.confirm = GatewayConfirmMode::always;
  profile.stream_idle_timeout = std::chrono::milliseconds{1000};
  profile.stream_max_duration = std::chrono::milliseconds{86400000};
  // Anchored on the heap: the confirm sink is owned by the GatewayService and
  // could in principle observe a late in-flight open during TearDown's drain
  // (after this frame is gone), so the sink captures the shared_ptr by value.
  auto asks = std::make_shared<std::vector<CapturedConfirm>>();
  install_gateway({profile}, {"gateway.provide:office"},
                  [asks](const GatewayConfirmRequest& request,
                         std::function<void(bool)> decide) {
                    asks->push_back(CapturedConfirm{request, std::move(decide)});
                  });

  auto opened = open_from_a(
      {.host = "no-such-host.invalid", .port = 80, .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  ASSERT_TRUE(spin_until([&] { return asks->size() >= 1U; }, 2000));

  // Far past the idle timeout, still inside the 30s confirm window: the
  // idle sweep must not touch an awaiting tunnel.
  now_ms_ = kNow + 5'000U;
  gw_->prune();
  pair_->pump_all();
  EXPECT_EQ(gw_->stats().idle_timeout_resets, 0U);
  EXPECT_EQ(gw_->stats().tunnels_active, 1U);
  EXPECT_EQ(stream->state(), StreamState::opening);

  // The parked tunnel still works: the decision continues it.
  (*asks)[0].decide(true);
  ASSERT_TRUE(spin_until([&] { return stream->state() == StreamState::reset; }, 5000));
  EXPECT_EQ(gw_->stats().dials_failed, 1U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
}

// ==== 3. SOCKS5 frontend end-to-end over a Node pair (M10-09) ==================

LanConfiguration fast_lan_only() {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  return configuration;
}

enum class LanPairStatus { ready, no_interfaces, discovery_failed, auth_failed };

// History (M10-R4-D2, fixed 2026-09-20): open_tunnel used to call the
// blocking Node::open_gateway_stream inline on the frontend strand, which
// shares the runtime's single Asio worker with the node strand — every live
// CONNECT deadlocked into the 5s run_on_strandAndWait bound, and the timeout
// returned while the queued lambda still held [&] references into the dead
// caller frame (SIGSEGV). open_tunnel now dispatches the blocking open via
// RuntimeAccess::dispatch_general (executor general pool) and posts the
// result back to the frontend strand; the three live-CONNECT tests below run
// for real and regress the deadlock/dangling path.

struct LanNodePair {
  std::optional<ProfileStore> first_store;
  std::optional<ProfileStore> second_store;
  std::optional<Node> first;
  std::optional<Node> second;
  DeviceEndpointKey first_key;
  DeviceEndpointKey second_key;
};

constexpr const char* kRound4ApplicationId = "com.example.m10-round4";

// A minimal SOCKS5 client on the test-owned io_context; every read is
// bounded by a run_for budget so a broken frontend fails the test instead
// of hanging it. Several clients share the io_context, and it may have
// stopped (run out of work) under a previous client, so every entry point
// re-arms it first.
class TestSocksClient {
 public:
  explicit TestSocksClient(boost::asio::io_context& io) : io_{io}, socket_{io} {}

  bool connect(const std::string& address, std::uint16_t port) {
    boost::system::error_code ec;
    const auto endpoint = boost::asio::ip::tcp::endpoint{
        boost::asio::ip::make_address(address, ec), port};
    if (ec) return false;
    socket_.connect(endpoint, ec);
    return !ec;
  }

  bool send(std::string_view bytes) {
    boost::system::error_code ec;
    boost::asio::write(socket_, boost::asio::buffer(bytes.data(), bytes.size()), ec);
    return !ec;
  }

  // Reads exactly out.size() bytes within the budget; false on timeout,
  // EOF, or error. Runs the io_context in small slices instead of one
  // run_for(budget): with EchoTarget's permanently pending async_accept the
  // io_context never runs out of work, so a single run_for would always
  // block the full budget even after the read completed (observed: every
  // handshake phase burning its whole 4s/8s budget). Slices return control
  // as soon as the completion handler has run.
  bool read_exact(std::span<std::byte> out, std::chrono::milliseconds budget) {
    if (io_.stopped()) io_.restart();
    bool done = false;
    bool ok = false;
    boost::asio::async_read(
        socket_, boost::asio::buffer(out.data(), out.size()),
        [&done, &ok](const boost::system::error_code& error, std::size_t) {
          ok = !error;
          done = true;
        });
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!done && std::chrono::steady_clock::now() < deadline) {
      (void)io_.run_for(std::chrono::milliseconds{10});
    }
    return done && ok;
  }

  // Waits for the peer to close (EOF) within the budget.
  bool read_eof(std::chrono::milliseconds budget) {
    if (io_.stopped()) io_.restart();
    std::optional<std::size_t> received;
    auto buffer = std::make_shared<std::array<std::byte, 64U>>();
    socket_.async_read_some(
        boost::asio::buffer(buffer->data(), buffer->size()),
        [&received](const boost::system::error_code& error, std::size_t bytes) {
          received = error == boost::asio::error::eof ? 0U : bytes;
        });
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!received.has_value() && std::chrono::steady_clock::now() < deadline) {
      (void)io_.run_for(std::chrono::milliseconds{25});
    }
    return received.has_value() && *received == 0U;
  }

  void close() {
    boost::system::error_code ignored;
    socket_.close(ignored);
  }

 private:
  boost::asio::io_context& io_;
  boost::asio::ip::tcp::socket socket_;
};

class M10Round4SocksTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M10_ROUND4_TEST_STATE_DIR} /
            ("node-" + std::to_string(::testing::UnitTest::GetInstance()
                                           ->random_seed()));
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
    std::filesystem::create_directories(root_);
  }

  void TearDown() override {
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
  }

  Result<ProfileStore> initialized_profile(const std::string& name) {
    ProfileOpenOptions options;
    options.secret_backend.prefer_os_backend = false;
    auto profile = ProfileStore::create(root_ / name / "profile.sqlite", options);
    if (!profile) {
      return profile;
    }
    PasswordVerifier verifier{.format_version = 1U,
                              .parameters = PasswordHashParameters{},
                              .encoded = "$argon2id$v=19$m=65536,t=2,p=1$test$test"};
    LocalProfileInitialization initialization{
        .application_id = kRound4ApplicationId,
        .password_verifier = std::move(verifier),
        .password_generation = 1U,
        .pairing_policy = PairingPolicy{},
        .lan = LanConfiguration{}};
    auto initialized = profile.value_if()->initialize_local(initialization);
    if (!initialized) {
      return Result<ProfileStore>::failure(*initialized.error_if());
    }
    return profile;
  }

  Result<Node> make_node(ProfileStore& store, Runtime* runtime,
                         std::vector<GatewayProfileConfig> gateway_profiles) {
    NodeConfig config{.profile = &store,
                      .runtime = runtime,
                      .application_id = kRound4ApplicationId,
                      .lan_override = fast_lan_only(),
                      .runtime_config = RuntimeConfig{},
                      .signaling_validator = {},
                      .signaling_handler = {},
                      .relay_override = std::nullopt,
                      .path_policy_override = std::nullopt,
                      .pairing_failure_threshold = 0U,
                      .pairing_backoff_base = std::chrono::milliseconds{0},
                      .pairing_backoff_max = std::chrono::milliseconds{0},
                      .pairing_grant_ttl_milliseconds = 0U,
                      .event_subscriber_queue_items = 0U,
                      .event_max_subscriptions_per_peer = 0U,
                      .file_receive_roots = {},
                      .file_max_peer_receive_bytes = 0U,
                      .shell_profiles = {},
                      .gateway_profiles = std::move(gateway_profiles),
                      .gateway_confirm_sink = {}};
    return Node::create(std::move(config));
  }

  template <typename Predicate>
  bool wait_until(Predicate&& predicate, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    executor::comm::PhaseGate poll{"m10-round4-poll"};
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
        return true;
      }
      (void)poll.wait_for(1U, std::chrono::milliseconds{2});
    }
    return predicate();
  }

  LanPairStatus establish_lan_pair(LanNodePair& pair, Runtime* first_runtime,
                                   std::vector<GatewayProfileConfig> second_profiles) {
    const std::vector<std::string> trust_scopes{
        "stream.open", std::string{gateway_use_scope},
        gateway_provide_scope("office")};
    auto first_profile = initialized_profile("lan-first");
    auto second_profile = initialized_profile("lan-second");
    if (!first_profile || !second_profile) {
      return LanPairStatus::no_interfaces;
    }
    if (!heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                         *second_profile.value_if(), trust_scopes)) {
      return LanPairStatus::no_interfaces;
    }
    pair.first_store.emplace(std::move(*first_profile.value_if()));
    pair.second_store.emplace(std::move(*second_profile.value_if()));

    auto first_node = make_node(*pair.first_store, first_runtime, {});
    auto second_node =
        make_node(*pair.second_store, nullptr, std::move(second_profiles));
    if (!first_node || !second_node) {
      return LanPairStatus::no_interfaces;
    }
    pair.first.emplace(std::move(*first_node.value_if()));
    pair.second.emplace(std::move(*second_node.value_if()));

    const auto first_snapshot = pair.first.value().snapshot();
    const auto second_snapshot = pair.second.value().snapshot();
    if (first_snapshot.interfaces.empty() || second_snapshot.interfaces.empty()) {
      return LanPairStatus::no_interfaces;
    }
    pair.first_key =
        DeviceEndpointKey{first_snapshot.device_id, first_snapshot.endpoint_id};
    pair.second_key =
        DeviceEndpointKey{second_snapshot.device_id, second_snapshot.endpoint_id};

    const auto discovered = [](const Node& node, const DeviceEndpointKey& peer) {
      const auto entries = node.endpoints();
      return std::any_of(entries.begin(), entries.end(),
                         [&](const auto& entry) { return entry.key == peer; });
    };
    if (!wait_until([&] {
          return discovered(pair.first.value(), pair.second_key) &&
                 discovered(pair.second.value(), pair.first_key);
        },
                     std::chrono::milliseconds{8000})) {
      return LanPairStatus::discovery_failed;
    }
    if (!pair.first.value().connect_lan(pair.second_key)) {
      return LanPairStatus::auth_failed;
    }
    const auto authenticated = [](const Node& node) {
      const auto sessions = node.peer_sessions();
      return std::any_of(
          sessions.begin(), sessions.end(), [](const NodePeerSessionSnapshot& session) {
            return session.state == NodePeerSessionState::authenticated;
          });
    };
    if (!wait_until(
            [&] {
              return authenticated(pair.first.value()) &&
                     authenticated(pair.second.value());
            },
            std::chrono::milliseconds{12000})) {
      return LanPairStatus::auth_failed;
    }
    return LanPairStatus::ready;
  }

  void skip_unless_lan_ready(LanPairStatus status) {
    if (status == LanPairStatus::ready) return;
    const char* required = std::getenv("HEYAKI_REQUIRE_LAN_INTERFACES");
    if (required != nullptr && std::string_view{required} == "1") {
      FAIL() << "LAN pair establishment failed (status=" << static_cast<int>(status)
             << ")";
    }
    GTEST_SKIP() << "LAN pair establishment unavailable (status="
                 << static_cast<int>(status) << ")";
  }

  std::filesystem::path root_;
};

TEST_F(M10Round4SocksTest, SocksConnectEchoRoundTrip) {
  boost::asio::io_context io;
  const std::string local_address = [&] {
    boost::system::error_code ec;
    boost::asio::ip::udp::socket probe{io};
    probe.open(boost::asio::ip::udp::v4(), ec);
    if (ec) return std::string{};
    probe.connect(boost::asio::ip::udp::endpoint{
                      boost::asio::ip::make_address("8.8.8.8", ec), 53U},
                  ec);
    if (ec) return std::string{};
    const auto local = probe.local_endpoint(ec);
    probe.close(ec);
    if (ec || local.address().is_loopback() || local.address().is_unspecified()) {
      return std::string{};
    }
    return local.address().to_string();
  }();
  if (local_address.empty()) {
    GTEST_SKIP() << "no non-loopback unicast IPv4 address: the serving side's "
                    "builtin deny list makes gateway dials untestable";
  }

  auto echo = std::make_shared<EchoTarget>(io, local_address);
  ASSERT_TRUE(echo->ok());
  echo->start();

  auto profile = profile_for("office", {local_address + "/32"});
  // The runtime host is declared FIRST and the nodes/frontends after it, so
  // destruction order matches the TUI (frontend -> node -> runtime).
  std::optional<Runtime> runtime_host;
  auto runtime_created = Runtime::create_owned(RuntimeConfig{});
  ASSERT_TRUE(runtime_created) << runtime_created.error_if()->safe_detail();
  runtime_host.emplace(std::move(*runtime_created.value_if()));

  LanNodePair pair;
  const auto status = establish_lan_pair(pair, &*runtime_host, {profile});
  skip_unless_lan_ready(status);

  auto frontend_created = socks::SocksFrontend::create(
      pair.first.value(), *runtime_host, pair.second_key,
      socks::SocksFrontendConfig{.bind_address = "127.0.0.1",
                                 .port = 0U,
                                 .max_concurrent_connections = 4U,
                                 .profile = "office",
                                 .connect_deadline = std::chrono::milliseconds{15000}});
  ASSERT_TRUE(frontend_created)
      << frontend_created.error_if()->safe_detail();
  auto frontend = *frontend_created.value_if();
  auto started = frontend->start();
  ASSERT_TRUE(started) << started.error_if()->safe_detail();
  const auto bound = frontend->stats().bound_port;
  ASSERT_NE(bound, 0U);

  TestSocksClient client{io};
  ASSERT_TRUE(client.connect("127.0.0.1", bound));

  // Greeting: VER5, one method, NO-AUTH.
  ASSERT_TRUE(client.send(std::string_view{"\x05\x01\x00", 3}));
  std::array<std::byte, 2U> method{};
  ASSERT_TRUE(client.read_exact(std::span<std::byte>{method.data(), method.size()},
                                std::chrono::milliseconds{4000}))
      << "method selection reply never arrived";
  EXPECT_EQ(std::to_integer<unsigned>(method[0]), 0x05U);
  EXPECT_EQ(std::to_integer<unsigned>(method[1]), 0x00U);

  // CONNECT with ATYP=1 (IPv4 literal of the echo target).
  std::array<std::uint8_t, 10U> request{};
  request[0] = 0x05U;
  request[1] = 0x01U;  // CONNECT
  request[3] = 0x01U;  // ATYP IPv4
  {
    unsigned a = 0U, b = 0U, c = 0U, d = 0U;
    ASSERT_EQ(std::sscanf(local_address.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d), 4);
    const std::uint32_t raw = (a << 24U) | (b << 16U) | (c << 8U) | d;
    request[4] = static_cast<std::uint8_t>(raw >> 24U);
    request[5] = static_cast<std::uint8_t>(raw >> 16U);
    request[6] = static_cast<std::uint8_t>(raw >> 8U);
    request[7] = static_cast<std::uint8_t>(raw);
  }
  request[8] = static_cast<std::uint8_t>(echo->port() >> 8U);
  request[9] = static_cast<std::uint8_t>(echo->port());
  ASSERT_TRUE(client.send(std::string_view{reinterpret_cast<const char*>(request.data()),
                                           request.size()}));
  std::array<std::byte, 10U> reply{};
  ASSERT_TRUE(client.read_exact(std::span<std::byte>{reply.data(), reply.size()},
                                std::chrono::milliseconds{8000}))
      << "CONNECT reply never arrived";
  EXPECT_EQ(std::to_integer<unsigned>(reply[0]), 0x05U);
  ASSERT_EQ(std::to_integer<unsigned>(reply[1]), 0x00U)
      << "CONNECT was refused (REP=" << std::to_integer<unsigned>(reply[1]) << ")";

  // Payload round trip through the tunnel.
  const std::string payload = "SOCKS-E2E";
  ASSERT_TRUE(client.send(payload));
  std::array<std::byte, 64U> echoed{};
  ASSERT_TRUE(client.read_exact(std::span<std::byte>{echoed.data(), payload.size()},
                                std::chrono::milliseconds{15000}));
  const std::string echoed_text{reinterpret_cast<const char*>(echoed.data()),
                                payload.size()};
  EXPECT_EQ(echoed_text, payload);

  ASSERT_TRUE(wait_until([&] { return echo->accepted() >= 1U; },
                         std::chrono::milliseconds{2000}));

  const auto stats = [&] {
    executor::comm::PhaseGate settle{"m10-round4-stats-settle"};
    (void)settle.wait_for(1U, std::chrono::milliseconds{50});
    return frontend->stats();
  }();
  EXPECT_TRUE(stats.listening);
  EXPECT_GE(stats.accepted, 1U);
  EXPECT_EQ(stats.connects_succeeded, 1U);
  EXPECT_EQ(stats.connects_failed, 0U);
  EXPECT_GE(stats.bytes_from_clients, payload.size());
  EXPECT_GE(stats.bytes_to_clients, payload.size());
  EXPECT_GE(stats.connections_active, 1U);
  EXPECT_EQ(stats.handshakes_failed, 0U);

  // Teardown order is stop() BEFORE client.close(): closing the client
  // first makes the frontend strand's EOF branch call the BLOCKING public
  // ByteStream::shutdown_write() (socks_frontend.cpp, pump_client_to_tunnel
  // eof path) while the runtime's single asio worker serves both the
  // frontend and node strands — the posted op can never run, the strand
  // self-deadlocks for the facade's 5s future timeout, Node::shutdown's 2s
  // stopped gate then times out and impl_.reset() destroys peer_attempts
  // (freeing the PeerSession) before stream_services, whose ~ByteStreamService
  // calls back into the freed session — the SEGFAULT seen in CI run
  // 35503655450 (supply-chain). stop() first closes the connection server
  // side (pending reads complete with operation_aborted, handlers early-out
  // on connection->closed), so no blocking call is ever made from the
  // strand. Product-side defects reported separately (socks EOF-branch
  // blocking hop; Node::shutdown timeout teardown; ~Impl member order;
  // stats() fabricating {} on strand timeout).
  frontend->stop();
  client.close();
  ASSERT_TRUE(wait_until([&] { return !frontend->stats().listening; },
                         std::chrono::milliseconds{2000}))
      << "stop() never closed the listener";
  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

TEST_F(M10Round4SocksTest, SocksDomainPassthroughResolvesOnServingSide) {
  boost::asio::io_context io;
  const std::string local_address = [&] {
    boost::system::error_code ec;
    boost::asio::ip::udp::socket probe{io};
    probe.open(boost::asio::ip::udp::v4(), ec);
    if (ec) return std::string{};
    probe.connect(boost::asio::ip::udp::endpoint{
                      boost::asio::ip::make_address("8.8.8.8", ec), 53U},
                  ec);
    if (ec) return std::string{};
    const auto local = probe.local_endpoint(ec);
    probe.close(ec);
    if (ec || local.address().is_loopback() || local.address().is_unspecified()) {
      return std::string{};
    }
    return local.address().to_string();
  }();
  if (local_address.empty()) {
    GTEST_SKIP() << "no non-loopback unicast IPv4 address for the echo target";
  }

  // The hostname must resolve (from this host) to the same non-loopback
  // address the profile allows: only then does a successful domain CONNECT
  // prove the bytes crossed to the serving side and were resolved THERE.
  char hostname[256] = {};
  if (::gethostname(hostname, sizeof(hostname)) != 0) {
    GTEST_SKIP() << "gethostname failed";
  }
  boost::system::error_code resolve_ec;
  boost::asio::ip::tcp::resolver resolver{io};
  const auto results = resolver.resolve(
      std::string{hostname}, "80",
      boost::asio::ip::tcp::resolver::flags::address_configured, resolve_ec);
  bool resolves_to_local = false;
  if (!resolve_ec) {
    for (const auto& entry : results) {
      if (entry.endpoint().address().to_string() == local_address) {
        resolves_to_local = true;
        break;
      }
    }
  }
  if (!resolves_to_local) {
    GTEST_SKIP() << "hostname does not resolve to the non-loopback address ("
                 << local_address << "); domain e2e untestable here";
  }

  auto echo = std::make_shared<EchoTarget>(io, local_address);
  ASSERT_TRUE(echo->ok());
  echo->start();

  auto profile = profile_for("office", {local_address + "/32"});
  std::optional<Runtime> runtime_host;
  auto runtime_created = Runtime::create_owned(RuntimeConfig{});
  ASSERT_TRUE(runtime_created);
  runtime_host.emplace(std::move(*runtime_created.value_if()));

  LanNodePair pair;
  const auto status = establish_lan_pair(pair, &*runtime_host, {profile});
  skip_unless_lan_ready(status);

  auto frontend_created = socks::SocksFrontend::create(
      pair.first.value(), *runtime_host, pair.second_key,
      socks::SocksFrontendConfig{.bind_address = "127.0.0.1",
                                 .port = 0U,
                                 .max_concurrent_connections = 4U,
                                 .profile = "office",
                                 .connect_deadline = std::chrono::milliseconds{15000}});
  ASSERT_TRUE(frontend_created);
  auto frontend = *frontend_created.value_if();
  ASSERT_TRUE(frontend->start());
  const auto bound = frontend->stats().bound_port;
  ASSERT_NE(bound, 0U);

  TestSocksClient client{io};
  ASSERT_TRUE(client.connect("127.0.0.1", bound));
  ASSERT_TRUE(client.send(std::string_view{"\x05\x01\x00", 3}));
  std::array<std::byte, 2U> method{};
  ASSERT_TRUE(client.read_exact(std::span<std::byte>{method.data(), method.size()},
                                std::chrono::milliseconds{4000}));
  ASSERT_EQ(std::to_integer<unsigned>(method[1]), 0x00U);

  // CONNECT with ATYP=3 and the bare hostname: the frontend must pass the
  // domain verbatim; the serving side resolves it and dials the echo target.
  const std::string domain = std::string{hostname};
  std::vector<std::uint8_t> request;
  request.push_back(0x05U);
  request.push_back(0x01U);
  request.push_back(0x00U);
  request.push_back(0x03U);
  request.push_back(static_cast<std::uint8_t>(domain.size()));
  request.insert(request.end(), domain.begin(), domain.end());
  request.push_back(static_cast<std::uint8_t>(echo->port() >> 8U));
  request.push_back(static_cast<std::uint8_t>(echo->port()));
  ASSERT_TRUE(client.send(std::string_view{reinterpret_cast<const char*>(request.data()),
                                           request.size()}));
  std::array<std::byte, 10U> reply{};
  ASSERT_TRUE(client.read_exact(std::span<std::byte>{reply.data(), reply.size()},
                                std::chrono::milliseconds{8000}));
  ASSERT_EQ(std::to_integer<unsigned>(reply[1]), 0x00U)
      << "domain CONNECT failed (REP=" << std::to_integer<unsigned>(reply[1]) << ")";

  const std::string payload = "DOMAIN-E2E";
  ASSERT_TRUE(client.send(payload));
  std::array<std::byte, 64U> echoed{};
  ASSERT_TRUE(client.read_exact(std::span<std::byte>{echoed.data(), payload.size()},
                                std::chrono::milliseconds{15000}));
  const std::string echoed_text{reinterpret_cast<const char*>(echoed.data()),
                                payload.size()};
  EXPECT_EQ(echoed_text, payload);
  EXPECT_EQ(frontend->stats().connects_succeeded, 1U);

  // See SocksConnectEchoRoundTrip: stop() before client.close() keeps the
  // EOF branch's blocking shutdown_write() off the single asio worker
  // (CI supply-chain SEGFAULT family, run 35503655450).
  frontend->stop();
  client.close();
  ASSERT_TRUE(wait_until([&] { return !frontend->stats().listening; },
                         std::chrono::milliseconds{2000}));
  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

TEST_F(M10Round4SocksTest, SocksFalseDomainFailsWithRep01) {
  std::optional<Runtime> runtime_host;
  auto runtime_created = Runtime::create_owned(RuntimeConfig{});
  ASSERT_TRUE(runtime_created);
  runtime_host.emplace(std::move(*runtime_created.value_if()));

  auto profile = profile_for("office", {"10.0.0.0/8"});
  LanNodePair pair;
  const auto status = establish_lan_pair(pair, &*runtime_host, {profile});
  skip_unless_lan_ready(status);

  auto frontend_created = socks::SocksFrontend::create(
      pair.first.value(), *runtime_host, pair.second_key,
      socks::SocksFrontendConfig{.bind_address = "127.0.0.1",
                                 .port = 0U,
                                 .max_concurrent_connections = 4U,
                                 .profile = "office",
                                 .connect_deadline = std::chrono::milliseconds{15000}});
  ASSERT_TRUE(frontend_created);
  auto frontend = *frontend_created.value_if();
  ASSERT_TRUE(frontend->start());
  const auto bound = frontend->stats().bound_port;

  boost::asio::io_context io;
  TestSocksClient client{io};
  ASSERT_TRUE(client.connect("127.0.0.1", bound));
  ASSERT_TRUE(client.send(std::string_view{"\x05\x01\x00", 3}));
  std::array<std::byte, 2U> method{};
  ASSERT_TRUE(client.read_exact(std::span<std::byte>{method.data(), method.size()},
                                std::chrono::milliseconds{4000}));
  ASSERT_EQ(std::to_integer<unsigned>(method[1]), 0x00U);

  // A syntactically legal domain that cannot resolve: the grammar is fine
  // locally, so the failure must come from the connect outcome reported by
  // the serving side (on_connected error -> REP 0x01), never from a local
  // refusal.
  const std::string domain = "no-such-host-round4.invalid";
  std::vector<std::uint8_t> request;
  request.push_back(0x05U);
  request.push_back(0x01U);
  request.push_back(0x00U);
  request.push_back(0x03U);
  request.push_back(static_cast<std::uint8_t>(domain.size()));
  request.insert(request.end(), domain.begin(), domain.end());
  request.push_back(0x00U);
  request.push_back(0x50U);
  ASSERT_TRUE(client.send(std::string_view{reinterpret_cast<const char*>(request.data()),
                                           request.size()}));
  std::array<std::byte, 10U> reply{};
  ASSERT_TRUE(client.read_exact(std::span<std::byte>{reply.data(), reply.size()},
                                std::chrono::milliseconds{20000}))
      << "no reply for an unresolvable domain";
  EXPECT_EQ(std::to_integer<unsigned>(reply[1]), 0x01U);
  // The frontend closed the connection after the failure reply.
  EXPECT_TRUE(client.read_eof(std::chrono::milliseconds{3000}));
  EXPECT_EQ(frontend->stats().connects_failed, 1U);

  client.close();
  frontend->stop();
  ASSERT_TRUE(wait_until([&] { return !frontend->stats().listening; },
                         std::chrono::milliseconds{2000}));
  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

TEST_F(M10Round4SocksTest, SocksProtocolRejectionsAndCapacity) {
  std::optional<Runtime> runtime_host;
  auto runtime_created = Runtime::create_owned(RuntimeConfig{});
  ASSERT_TRUE(runtime_created);
  runtime_host.emplace(std::move(*runtime_created.value_if()));

  auto profile = profile_for("office", {"10.0.0.0/8"});
  LanNodePair pair;
  const auto status = establish_lan_pair(pair, &*runtime_host, {profile});
  skip_unless_lan_ready(status);

  auto frontend_created = socks::SocksFrontend::create(
      pair.first.value(), *runtime_host, pair.second_key,
      socks::SocksFrontendConfig{.bind_address = "127.0.0.1",
                                 .port = 0U,
                                 .max_concurrent_connections = 1U,
                                 .profile = "office",
                                 .connect_deadline = std::chrono::milliseconds{15000}});
  ASSERT_TRUE(frontend_created);
  auto frontend = *frontend_created.value_if();
  ASSERT_TRUE(frontend->start());
  const auto bound = frontend->stats().bound_port;

  boost::asio::io_context io;

  // (a) Greeting without NO-AUTH: 05 FF then close, handshakes_failed.
  {
    TestSocksClient client{io};
    ASSERT_TRUE(client.connect("127.0.0.1", bound));
    ASSERT_TRUE(client.send(std::string_view{"\x05\x01\x01", 3}));
    std::array<std::byte, 2U> method{};
    ASSERT_TRUE(client.read_exact(std::span<std::byte>{method.data(), method.size()},
                                  std::chrono::milliseconds{4000}));
    EXPECT_EQ(std::to_integer<unsigned>(method[0]), 0x05U);
    EXPECT_EQ(std::to_integer<unsigned>(method[1]), 0xFFU);
    EXPECT_TRUE(client.read_eof(std::chrono::milliseconds{3000}));
    client.close();
  }

  // (b) Capacity 1: one parked connection (connected, greeting never sent)
  // occupies the slot; the second is closed without any reply.
  TestSocksClient parked{io};
  ASSERT_TRUE(parked.connect("127.0.0.1", bound));
  ASSERT_TRUE(wait_until([&] { return frontend->stats().accepted >= 1U; },
                         std::chrono::milliseconds{4000}));
  {
    TestSocksClient overflow{io};
    ASSERT_TRUE(overflow.connect("127.0.0.1", bound));
    EXPECT_TRUE(overflow.read_eof(std::chrono::milliseconds{4000}))
        << "the connection over the cap must be closed without a reply";
    overflow.close();
  }
  EXPECT_EQ(frontend->stats().accepted, 2U)
      << "the no-auth client and the parked client only; the capped "
         "connection is never admitted";
  EXPECT_EQ(frontend->stats().handshakes_failed, 2U)
      << "no-auth rejection + capacity rejection";
  EXPECT_EQ(frontend->stats().connections_active, 1U);

  // (c) Unsupported command BIND (0x02) on the parked slot after a proper
  // greeting: REP 0x07 and close.
  {
    ASSERT_TRUE(parked.send(std::string_view{"\x05\x01\x00", 3}));
    std::array<std::byte, 2U> method{};
    ASSERT_TRUE(parked.read_exact(std::span<std::byte>{method.data(), method.size()},
                                  std::chrono::milliseconds{4000}));
    ASSERT_EQ(std::to_integer<unsigned>(method[1]), 0x00U);
    const std::array<std::uint8_t, 10U> bind{
        0x05U, 0x02U, 0x00U, 0x01U, 10U, 0U, 0U, 1U, 0U, 80U};
    ASSERT_TRUE(parked.send(std::string_view{
        reinterpret_cast<const char*>(bind.data()), bind.size()}));
    std::array<std::byte, 10U> reply{};
    ASSERT_TRUE(parked.read_exact(std::span<std::byte>{reply.data(), reply.size()},
                                  std::chrono::milliseconds{4000}));
    EXPECT_EQ(std::to_integer<unsigned>(reply[1]), 0x07U);
    EXPECT_TRUE(parked.read_eof(std::chrono::milliseconds{3000}));
  }

  // (d) Bad ATYP (0x02) on a fresh connection (the slot is free again):
  // REP 0x08 and close.
  {
    TestSocksClient client{io};
    ASSERT_TRUE(client.connect("127.0.0.1", bound));
    ASSERT_TRUE(client.send(std::string_view{"\x05\x01\x00", 3}));
    std::array<std::byte, 2U> method{};
    ASSERT_TRUE(client.read_exact(std::span<std::byte>{method.data(), method.size()},
                                  std::chrono::milliseconds{4000}));
    ASSERT_EQ(std::to_integer<unsigned>(method[1]), 0x00U);
    const std::array<std::uint8_t, 10U> bad_atyp{
        0x05U, 0x01U, 0x00U, 0x02U, 0U, 0U, 0U, 0U, 0U, 80U};
    ASSERT_TRUE(client.send(std::string_view{
        reinterpret_cast<const char*>(bad_atyp.data()), bad_atyp.size()}));
    std::array<std::byte, 10U> reply{};
    ASSERT_TRUE(client.read_exact(std::span<std::byte>{reply.data(), reply.size()},
                                  std::chrono::milliseconds{4000}));
    EXPECT_EQ(std::to_integer<unsigned>(reply[1]), 0x08U);
    EXPECT_TRUE(client.read_eof(std::chrono::milliseconds{3000}));
    client.close();
  }

  parked.close();
  frontend->stop();
  ASSERT_TRUE(wait_until([&] { return !frontend->stats().listening; },
                         std::chrono::milliseconds{2000}));
  EXPECT_EQ(frontend->stats().connections_active, 0U);
  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

TEST_F(M10Round4SocksTest, SocksStopClosesActiveClientConnection) {
  std::optional<Runtime> runtime_host;
  auto runtime_created = Runtime::create_owned(RuntimeConfig{});
  ASSERT_TRUE(runtime_created);
  runtime_host.emplace(std::move(*runtime_created.value_if()));

  auto profile = profile_for("office", {"10.0.0.0/8"});
  LanNodePair pair;
  const auto status = establish_lan_pair(pair, &*runtime_host, {profile});
  skip_unless_lan_ready(status);

  auto frontend_created = socks::SocksFrontend::create(
      pair.first.value(), *runtime_host, pair.second_key,
      socks::SocksFrontendConfig{.bind_address = "127.0.0.1",
                                 .port = 0U,
                                 .max_concurrent_connections = 4U,
                                 .profile = "office",
                                 .connect_deadline = std::chrono::milliseconds{15000}});
  ASSERT_TRUE(frontend_created);
  auto frontend = *frontend_created.value_if();
  ASSERT_TRUE(frontend->start());
  const auto bound = frontend->stats().bound_port;

  boost::asio::io_context io;
  TestSocksClient client{io};
  ASSERT_TRUE(client.connect("127.0.0.1", bound));
  ASSERT_TRUE(client.send(std::string_view{"\x05\x01\x00", 3}));
  std::array<std::byte, 2U> method{};
  ASSERT_TRUE(client.read_exact(std::span<std::byte>{method.data(), method.size()},
                                std::chrono::milliseconds{4000}));
  ASSERT_EQ(std::to_integer<unsigned>(method[1]), 0x00U);
  ASSERT_TRUE(wait_until([&] { return frontend->stats().accepted >= 1U; },
                         std::chrono::milliseconds{4000}));

  frontend->stop();
  ASSERT_TRUE(wait_until([&] { return !frontend->stats().listening; },
                         std::chrono::milliseconds{2000}));
  // The established client connection is closed too.
  EXPECT_TRUE(client.read_eof(std::chrono::milliseconds{3000}));
  EXPECT_EQ(frontend->stats().connections_active, 0U);

  // A new connect after stop() is refused: the listener is gone.
  boost::system::error_code connect_error;
  boost::asio::ip::tcp::socket probe{io};
  probe.connect(
      boost::asio::ip::tcp::endpoint{boost::asio::ip::make_address("127.0.0.1"), bound},
      connect_error);
  EXPECT_TRUE(connect_error) << "listener still accepting after stop()";

  client.close();
  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// ==== 4. TUI CLI parse smoke (M10-09 gateway flags) =============================

#ifndef HEYAKI_TUI_BINARY
#define HEYAKI_TUI_BINARY ""
#endif

// Runs the built TUI with `arguments` (already shell-quoted by the caller
// where needed); returns the exit status and captures stdout.
struct TuiRunResult {
  int exit_code{-1};
  std::string stdout_text;
};

TuiRunResult run_tui(const std::string& arguments) {
#ifdef _WIN32
  const std::string command =
      "\"" + std::string{HEYAKI_TUI_BINARY} + "\" " + arguments + " 2>nul";
  TuiRunResult result;
  FILE* pipe = ::_popen(command.c_str(), "r");
  if (pipe == nullptr) {
    return result;
  }
  std::array<char, 256U> chunk{};
  while (std::fgets(chunk.data(), static_cast<int>(chunk.size()), pipe) != nullptr) {
    result.stdout_text += chunk.data();
  }
  result.exit_code = ::_pclose(pipe);
  return result;
#else
  const std::string command =
      "\"" + std::string{HEYAKI_TUI_BINARY} + "\" " + arguments + " 2>/dev/null";
  TuiRunResult result;
  FILE* pipe = ::popen(command.c_str(), "r");
  if (pipe == nullptr) {
    return result;
  }
  std::array<char, 256U> chunk{};
  while (std::fgets(chunk.data(), static_cast<int>(chunk.size()), pipe) != nullptr) {
    result.stdout_text += chunk.data();
  }
  const int status = ::pclose(pipe);
  result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  return result;
#endif
}

class M10Round4TuiCliTest : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string_view{HEYAKI_TUI_BINARY}.empty()) {
      GTEST_SKIP() << "heyaki-tui binary not built (HEYAKI_BUILD_APPS off)";
    }
  }
};

TEST_F(M10Round4TuiCliTest, HelpDocumentsGatewayFlags) {
  const auto run = run_tui("--help");
  ASSERT_EQ(run.exit_code, 0);
  EXPECT_NE(run.stdout_text.find("--gateway-profile"), std::string::npos);
  EXPECT_NE(run.stdout_text.find("--gateway-confirm"), std::string::npos);
  EXPECT_NE(run.stdout_text.find("never|first_use|always"), std::string::npos);
}

TEST_F(M10Round4TuiCliTest, ValidProfileListsAndConfirmModesParse) {
  EXPECT_EQ(run_tui("--gateway-profile office=10.0.0.0/8 "
                    "--gateway-profile x=192.168.0.0/16,172.16.0.0/12 --help")
                .exit_code,
            0);
  EXPECT_EQ(run_tui("--gateway-confirm never --help").exit_code, 0);
  EXPECT_EQ(run_tui("--gateway-confirm first_use --help").exit_code, 0);
  EXPECT_EQ(run_tui("--gateway-confirm always --help").exit_code, 0);
}

TEST_F(M10Round4TuiCliTest, InvalidArgumentsRejectedWithUsage) {
  // Missing '=' between name and CIDR list.
  const auto no_equals = run_tui("--gateway-profile office --help");
  EXPECT_NE(no_equals.exit_code, 0);
  EXPECT_NE(no_equals.stdout_text.find("usage:"), std::string::npos);

  // Malformed CIDR (IPv4 does not take /64).
  EXPECT_NE(run_tui("--gateway-profile office=10.0.0.0/64 --help").exit_code, 0);
  // Empty CIDR list.
  EXPECT_NE(run_tui("--gateway-profile office= --help").exit_code, 0);
  // Catch-all without the internet opt-in fails profile validation.
  EXPECT_NE(run_tui("--gateway-profile office=0.0.0.0/0 --help").exit_code, 0);
  // Bad profile name grammar.
  EXPECT_NE(run_tui("--gateway-profile Bad_Name=10.0.0.0/8 --help").exit_code, 0);
  // Unknown confirm mode.
  EXPECT_NE(run_tui("--gateway-confirm bogus --help").exit_code, 0);
}

}  // namespace
}  // namespace heyaki
