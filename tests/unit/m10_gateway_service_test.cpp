// M10 Round 3 independent verification: the B-side GatewayService (M10-07)
// and the A-side gateway initiator surfaces (M10-08) — prelude semantics,
// dial deadline, admission/refusal accounting over the loopback session
// harness, real dials against a local echo target (non-loopback unicast),
// injected-clock idle/duration/quota sweeps, session-close cleanup, and the
// Node-level open_gateway_stream public API (local validation + gateway.use
// scope gate + one end-to-end public-API round trip over LAN).
//
// Concurrency model of the harness: one test thread. The loopback transport
// is pump-driven (no io), and every GatewayService socket/resolver lives on
// a test-owned io_context that the same thread polls, so the "node strand"
// and the "io strand" interleave deterministically without any bare thread.

#include "byte_stream.hpp"
#include "gateway_service.hpp"
#include "m4_support.hpp"
#include "m5_support.hpp"
#include "peer_session.hpp"

#include <heyaki/byte_stream.hpp>
#include <heyaki/error.hpp>
#include <heyaki/gateway.hpp>
#include <heyaki/identity.hpp>
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/signaling_protocol.hpp>

#include <executor/comm.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/write.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
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

// ---- Loopback session pair (copied from the Round 1 m10_protocol_test
// harness so this suite stays self-contained) --------------------------------

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

// ---- Local network detection -------------------------------------------------

// The built-in gateway deny list covers all of 127/8 and ::1/128, so a real
// dial needs this host's non-loopback unicast IPv4 address. A connected UDP
// socket resolves it from the routing table without sending any packet.
std::string detect_non_loopback_v4(boost::asio::io_context& io) {
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
  return local.address().to_string();
}

// ---- Echo target -------------------------------------------------------------

// A small TCP echo server on the test io_context. Every accepted connection
// echoes bytes back; EOF/errors close the connection and count it. Handlers
// keep the object alive through shared_from_this so late completions (for
// example during the fixture's teardown poll) never touch a dead stack
// object.
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

// ---- B-side harness fixture ---------------------------------------------------

struct CapturedRead {
  bool completed{false};
  std::size_t bytes{0U};
  std::optional<Error> error;
  std::vector<std::byte> data;
};

class M10GatewayServiceTest : public ::testing::Test {
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
    // Drain posted cleanup chains (socket cancels -> completions -> posted
    // node-strand continuations) until quiet before tearing the rest down.
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

  // Installs a GatewayService on the right (serving) side with the given
  // profiles and the set of gateway.provide:<profile> scopes the session is
  // considered to hold.
  void install_gateway(std::vector<GatewayProfileConfig> profiles,
                       std::vector<std::string> provide_scopes) {
    GatewayServiceConfig config;
    config.profiles = std::move(profiles);
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
        [this] { return now_ms_; });
    ASSERT_TRUE(gw_->attach());
  }

  [[nodiscard]] Result<std::shared_ptr<ByteStreamHandle>> open_from_a(
      const GatewayConnect& target, std::uint64_t dial_deadline = 0U) {
    return left_->open_gateway_stream(target, 4096U, 4U, dial_deadline);
  }

  // Drives both loopback directions plus the io_context (gateway sockets,
  // posted node-strand continuations) until quiet. An io_context whose run
  // family returned with zero outstanding work stays "stopped" until
  // restart(), so each drive re-arms it first (otherwise later posts would
  // silently never run).
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

  [[nodiscard]] bool write_all(ByteStreamHandle& stream, std::string_view text) {
    bool done = false;
    std::optional<Error> error;
    stream.async_write(as_bytes(text), [&](StreamIoResult result) {
      done = true;
      error = result.error;
    });
    pair_->pump_all();
    return done && !error.has_value();
  }

  [[nodiscard]] bool write_bytes(ByteStreamHandle& stream,
                                 std::span<const std::byte> data) {
    bool done = false;
    std::optional<Error> error;
    stream.async_write(data, [&](StreamIoResult result) {
      done = true;
      error = result.error;
    });
    pair_->pump_all();
    return done && !error.has_value();
  }

  static std::uint64_t refusals_of(const GatewayService& service,
                                   GatewayRefusal refusal) {
    return service.stats()
        .refusals[static_cast<std::size_t>(refusal)];
  }

  // Failure diagnostics: which stage the serving side actually reached.
  void dump_gateway_state(const char* label, const ByteStreamHandle* stream) {
    std::cout << "[diag " << label << "] a_state="
              << (stream == nullptr ? -1 : static_cast<int>(stream->state()))
              << " opens=" << gw_->stats().opens_received
              << " dials_ok=" << gw_->stats().dials_succeeded
              << " dials_fail=" << gw_->stats().dials_failed
              << " tunnels=" << gw_->stats().tunnels_active
              << " ref[dial_failed]="
              << refusals_of(*gw_, GatewayRefusal::dial_failed)
              << " ref[dial_deadline]="
              << refusals_of(*gw_, GatewayRefusal::dial_deadline)
              << " ref[quota]="
              << refusals_of(*gw_, GatewayRefusal::quota_exhausted)
              << " bytes_from_tunnel=" << gw_->stats().bytes_from_tunnel
              << " bytes_to_tunnel=" << gw_->stats().bytes_to_tunnel
              << " b_streams=" << right_->active_streams() << "\n";
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

// ---- A-side prelude semantics (M10-08) ---------------------------------------

TEST_F(M10GatewayServiceTest, InitiatorPreludeConsumedBeforePayload) {
  std::vector<std::shared_ptr<ByteStreamHandle>> inbound;
  right_->set_gateway_inbound_handler(
      [&](const std::shared_ptr<ByteStreamHandle>& stream, const GatewayConnect&) {
        inbound.push_back(stream);
      });
  auto opened = open_from_a({.host = "203.0.113.9", .port = 443, .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  ASSERT_TRUE(stream->is_gateway());
  pair_->pump_all();
  ASSERT_EQ(inbound.size(), 1U);

  // A read pends before anything arrived and must not complete.
  auto read = pend_read(*stream, 64U);
  EXPECT_FALSE(read->completed);
  EXPECT_EQ(stream->pending_reads(), 1U);

  // The connected prelude alone must still not satisfy the read: the API may
  // not report "connected" (or any data) before tunnel payload exists.
  const auto prelude = encode_gateway_prelude(gateway_prelude_connected);
  ASSERT_TRUE(write_bytes(*inbound[0],
                          std::span<const std::byte>{prelude.data(), prelude.size()}));
  pair_->pump_all();
  EXPECT_FALSE(read->completed);
  // Full-frame charging (wire 6.3.1): the offset accounts the prelude bytes,
  // the receive buffer does not carry them.
  EXPECT_EQ(stream->window().next_receive_offset, prelude.size());
  EXPECT_EQ(stream->window().receive_buffered_bytes, 0U);

  ASSERT_TRUE(write_all(*inbound[0], "PAYLOAD"));
  pair_->pump_all();
  ASSERT_TRUE(read->completed);
  EXPECT_FALSE(read->error.has_value());
  EXPECT_EQ(read->bytes, 7U);
  EXPECT_EQ(as_text(read->data), "PAYLOAD");
  EXPECT_EQ(stream->window().receive_buffered_bytes, 0U);
  // Offset accounting spans prelude + payload (2 + 7).
  EXPECT_EQ(stream->window().next_receive_offset, 9U);
  EXPECT_EQ(stream->state(), StreamState::open);
}

TEST_F(M10GatewayServiceTest, InitiatorSplitPreludeAcrossFramesStillValid) {
  std::vector<std::shared_ptr<ByteStreamHandle>> inbound;
  right_->set_gateway_inbound_handler(
      [&](const std::shared_ptr<ByteStreamHandle>& stream, const GatewayConnect&) {
        inbound.push_back(stream);
      });
  auto opened = open_from_a({.host = "203.0.113.9", .port = 443, .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  pair_->pump_all();
  ASSERT_EQ(inbound.size(), 1U);
  auto read = pend_read(*stream, 64U);

  // First byte of the prelude, then (second prelude byte + payload).
  const std::vector<std::byte> first{std::byte{0x00U}};
  ASSERT_TRUE(write_bytes(*inbound[0], std::span<const std::byte>{first}));
  pair_->pump_all();
  EXPECT_FALSE(read->completed);
  EXPECT_EQ(stream->window().next_receive_offset, 1U);

  const std::vector<std::byte> second{std::byte{0x00U}, std::byte{'P'},
                                      std::byte{'A'}, std::byte{'Y'}};
  ASSERT_TRUE(write_bytes(*inbound[0], std::span<const std::byte>{second}));
  pair_->pump_all();
  ASSERT_TRUE(read->completed);
  EXPECT_FALSE(read->error.has_value());
  EXPECT_EQ(read->bytes, 3U);
  EXPECT_EQ(as_text(read->data), "PAY");
}

TEST_F(M10GatewayServiceTest, InitiatorReadStaysPendedWithoutPrelude) {
  right_->set_gateway_inbound_handler(
      [](const std::shared_ptr<ByteStreamHandle>&, const GatewayConnect&) {});
  auto opened = open_from_a({.host = "203.0.113.9", .port = 443, .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  pair_->pump_all();

  auto read = pend_read(*stream, 64U);
  pair_->pump_all();
  // Bounded real wait: the pending read must stay pending, not complete as a
  // zero-byte (empty) read.
  executor::comm::PhaseGate gate{"m10-gateway-pend"};
  (void)gate.wait_for(1U, std::chrono::milliseconds{100});
  pair_->pump_all();
  EXPECT_FALSE(read->completed);
  EXPECT_EQ(stream->state(), StreamState::open);
  EXPECT_EQ(stream->pending_reads(), 1U);
}

TEST_F(M10GatewayServiceTest, InitiatorNonzeroPreludeResetsProtocolError) {
  std::vector<std::shared_ptr<ByteStreamHandle>> inbound;
  right_->set_gateway_inbound_handler(
      [&](const std::shared_ptr<ByteStreamHandle>& stream, const GatewayConnect&) {
        inbound.push_back(stream);
        const std::vector<std::byte> bad_prelude{std::byte{0x00U}, std::byte{0x01U}};
        (void)stream->async_write(std::span<const std::byte>{bad_prelude},
                                  [](StreamIoResult) {});
        (void)stream->async_write(as_bytes("PAYLOAD"), [](StreamIoResult) {});
      });
  auto opened = open_from_a({.host = "203.0.113.9", .port = 443, .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  auto read = pend_read(*stream, 64U);
  pair_->pump_all();

  ASSERT_EQ(stream->state(), StreamState::reset);
  ASSERT_TRUE(read->completed);
  ASSERT_TRUE(read->error.has_value());
  EXPECT_EQ(read->error->code(), ErrorCode::cancelled);
  EXPECT_EQ(read->error->safe_detail(), "stream_reset");
  EXPECT_EQ(read->bytes, 0U);
  // The initiator's local reset travels back and fails the serving-side
  // stream as well.
  ASSERT_EQ(inbound.size(), 1U);
  EXPECT_EQ(inbound[0]->state(), StreamState::reset);
  EXPECT_EQ(left_->active_streams(), 0U);
}

// The destructive half of the dial-deadline sweep (an expired initiator
// stream being reset from inside ByteStreamService::check_deadlines' own
// streams_ iteration) is covered by InitiatorDialDeadlineSweepResetsStream
// at the END of this file: the current implementation erases the stream from
// the map mid-iteration, which is undefined behaviour and segfaults, so it
// runs last to keep the rest of the suite observable.
TEST_F(M10GatewayServiceTest, InitiatorDialDeadlineSemanticsWithoutSweep) {
  right_->set_gateway_inbound_handler(
      [](const std::shared_ptr<ByteStreamHandle>&, const GatewayConnect&) {});

  // Deadline 0 means "no dial deadline": the stream never resets on sweeps.
  auto undated = open_from_a({.host = "203.0.113.9", .port = 443, .profile = "office"});
  ASSERT_TRUE(undated);
  auto undated_stream = *undated.value_if();
  auto undated_read = pend_read(*undated_stream, 64U);
  pair_->pump_all();

  now_ms_ = kNow + 1'000'000U;
  left_->check_deadlines();  // no dated stream exists: nothing to erase
  EXPECT_EQ(undated_stream->state(), StreamState::open);
  EXPECT_FALSE(undated_read->completed);

  // Boundary: at exactly the deadline the sweep must not fire (strictly
  // greater-than comparison).
  now_ms_ = kNow;
  auto boundary =
      open_from_a({.host = "203.0.113.9", .port = 443, .profile = "office"}, kNow + 5000U);
  ASSERT_TRUE(boundary);
  pair_->pump_all();
  now_ms_ = kNow + 5000U;
  left_->check_deadlines();  // both streams unexpired at this instant
  EXPECT_EQ((*boundary.value_if())->state(), StreamState::open);
  EXPECT_EQ(undated_stream->state(), StreamState::open);
}

// ---- B-side admission / refusal ----------------------------------------------

TEST_F(M10GatewayServiceTest, ScopeGateResetsPermissionDenied) {
  auto profile = profile_for("office", {"10.0.0.0/8"});
  install_gateway({profile}, {});  // session holds no gateway.provide:office
  auto opened = open_from_a({.host = "10.1.2.3", .port = 80, .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  auto read = pend_read(*stream, 64U);
  pair_->pump_all();

  EXPECT_EQ(stream->state(), StreamState::reset);
  ASSERT_TRUE(read->completed);
  ASSERT_TRUE(read->error.has_value());
  EXPECT_EQ(read->error->code(), ErrorCode::cancelled);
  const auto& stats = gw_->stats();
  EXPECT_EQ(stats.opens_received, 1U);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::scope_denied), 1U);
  EXPECT_EQ(stats.tunnels_active, 0U);
  EXPECT_EQ(stats.dials_failed, 0U);
  EXPECT_EQ(stats.dials_succeeded, 0U);
}

TEST_F(M10GatewayServiceTest, NamedProfileMissRefusedPolicyDenied) {
  auto profile = profile_for("office", {"10.0.0.0/8"});
  install_gateway({profile}, {"gateway.provide:office"});
  auto opened = open_from_a({.host = "10.1.2.3", .port = 80, .profile = "home"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  pair_->pump_all();
  EXPECT_EQ(stream->state(), StreamState::reset);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::policy_denied), 1U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
}

TEST_F(M10GatewayServiceTest, EmptyProfileWithTwoProfilesRefusedNotEnabled) {
  auto office = profile_for("office", {"10.0.0.0/8"});
  auto home = profile_for("home", {"192.168.0.0/16"});
  install_gateway({office, home},
                  {"gateway.provide:office", "gateway.provide:home"});
  auto opened = open_from_a({.host = "10.1.2.3", .port = 80, .profile = ""});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  pair_->pump_all();
  EXPECT_EQ(stream->state(), StreamState::reset);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::not_enabled), 1U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
}

TEST_F(M10GatewayServiceTest, PortOutsideAllowlistRefused) {
  auto profile = profile_for("office", {"10.0.0.0/8"});
  profile.allowed_ports.clear();
  profile.allowed_ports.push_back(GatewayPortRange{5000U, 5010U});
  install_gateway({profile}, {"gateway.provide:office"});
  auto opened = open_from_a({.host = "10.1.2.3", .port = 443, .profile = "office"});
  ASSERT_TRUE(opened);
  pair_->pump_all();
  EXPECT_EQ((*opened.value_if())->state(), StreamState::reset);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::policy_denied), 1U);
}

TEST_F(M10GatewayServiceTest, TargetOutsideAllowedCidrRefused) {
  auto profile = profile_for("office", {"10.0.0.0/8"});
  install_gateway({profile}, {"gateway.provide:office"});
  auto opened = open_from_a({.host = "203.0.113.1", .port = 80, .profile = "office"});
  ASSERT_TRUE(opened);
  pair_->pump_all();
  EXPECT_EQ((*opened.value_if())->state(), StreamState::reset);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::policy_denied), 1U);
}

TEST_F(M10GatewayServiceTest, BuiltinDenyBlocksLoopbackEvenWithInternet) {
  auto profile = profile_for("office", {"0.0.0.0/0"});
  profile.allow_internet = true;  // a catch-all allowlist is legal with opt-in
  ASSERT_TRUE(validate_gateway_profile(profile));
  install_gateway({profile}, {"gateway.provide:office"});
  auto opened = open_from_a({.host = "127.0.0.1", .port = 80, .profile = "office"});
  ASSERT_TRUE(opened);
  pair_->pump_all();
  EXPECT_EQ((*opened.value_if())->state(), StreamState::reset);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::policy_denied), 1U);
  EXPECT_EQ(gw_->stats().dials_failed, 0U);
  EXPECT_EQ(gw_->stats().dials_succeeded, 0U);
}

TEST_F(M10GatewayServiceTest, HostnameResolveFailureRefusedUnavailable) {
  auto profile = profile_for("office", {"10.0.0.0/8"});
  profile.dial_deadline = std::chrono::milliseconds{30000};
  install_gateway({profile}, {"gateway.provide:office"});
  auto opened =
      open_from_a({.host = "no-such-host.invalid", .port = 80, .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  const auto reset = spin_until([&] { return stream->state() == StreamState::reset; },
                                3000);
  if (!reset) dump_gateway_state("resolve-fail", stream.get());
  ASSERT_TRUE(reset) << "resolve failure never reset the initiator stream";
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::dial_failed), 1U);
  EXPECT_EQ(gw_->stats().dials_failed, 1U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
}

// Spec (M10-05 / design 3.2): with max_concurrent_streams_per_session = 1
// the FIRST tunnel must be admitted; only a second concurrent open exhausts
// the cap. The service reserves the candidate's slot before admission, so
// the admission context must describe the tunnels active BEFORE this one.
TEST_F(M10GatewayServiceTest, ConcurrencyCapAdmitsFirstRefusesSecond) {
  auto profile = profile_for("office", {"203.0.113.0/24"});
  profile.max_concurrent_streams_per_session = 1U;
  profile.max_concurrent_streams_per_profile = 16U;
  // Long dial deadline keeps the first tunnel alive mid-dial (203.0.113.1 is
  // TEST-NET-3: unannounced, so connect() hangs without completing).
  profile.dial_deadline = std::chrono::milliseconds{30000};
  install_gateway({profile}, {"gateway.provide:office"});

  auto first = open_from_a({.host = "203.0.113.1", .port = 80, .profile = "office"});
  ASSERT_TRUE(first);
  auto first_stream = *first.value_if();
  spin(6);
  ASSERT_EQ(first_stream->state(), StreamState::open)
      << "with an unused cap of 1 the first gateway open must be admitted";
  ASSERT_EQ(gw_->stats().tunnels_active, 1U);
  EXPECT_EQ(gw_->stats().refusals[static_cast<std::size_t>(
                                GatewayRefusal::quota_exhausted)],
            0U);

  auto second = open_from_a({.host = "203.0.113.2", .port = 80, .profile = "office"});
  ASSERT_TRUE(second);
  auto second_stream = *second.value_if();
  pair_->pump_all();
  EXPECT_EQ(second_stream->state(), StreamState::reset);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::quota_exhausted), 1U);
  EXPECT_EQ(gw_->stats().tunnels_active, 1U);
}

// Companion to the cap=1 spec test: with a cap of 2 exactly two concurrent
// tunnels are admitted. The service reserves the candidate's slot before
// admission, so if the admission context wrongly counted the candidate
// itself the effective cap would be N-1 (the second open refused here);
// conversely a context that ignored the reservation would admit past the
// cap. The refused third open must release its reserved slot: after the
// refusal tunnels_active is back to 2, not stuck at 3, and repeated
// refusals neither accumulate reservations nor wedge the admitted tunnels.
TEST_F(M10GatewayServiceTest, ConcurrencyCapTwoAdmitsExactlyTwo) {
  auto profile = profile_for("office", {"203.0.113.0/24"});
  profile.max_concurrent_streams_per_session = 2U;
  profile.max_concurrent_streams_per_profile = 16U;
  profile.dial_deadline = std::chrono::milliseconds{30000};
  install_gateway({profile}, {"gateway.provide:office"});

  auto first = open_from_a({.host = "203.0.113.1", .port = 80, .profile = "office"});
  ASSERT_TRUE(first);
  auto first_stream = *first.value_if();
  ASSERT_TRUE(spin_until([&] { return first_stream->state() == StreamState::open; },
                         2000))
      << "with an unused cap of 2 the first gateway open must be admitted";
  ASSERT_EQ(gw_->stats().tunnels_active, 1U);

  // The second concurrent open still sees one pre-existing tunnel (1 < 2),
  // so it is admitted too — the candidate's own reservation is excluded
  // from the admission context.
  auto second = open_from_a({.host = "203.0.113.2", .port = 80, .profile = "office"});
  ASSERT_TRUE(second);
  auto second_stream = *second.value_if();
  ASSERT_TRUE(spin_until([&] { return second_stream->state() == StreamState::open; },
                         2000))
      << "cap=2 must admit a second concurrent tunnel (an effective cap of "
         "N-1 would refuse it)";
  EXPECT_EQ(gw_->stats().tunnels_active, 2U);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::quota_exhausted), 0U);

  // The third concurrent open sees two active tunnels (2 >= 2) and is
  // refused; the refused candidate releases its reserved slot, so
  // tunnels_active stays at 2 instead of leaking the reservation as 3.
  auto third = open_from_a({.host = "203.0.113.3", .port = 80, .profile = "office"});
  ASSERT_TRUE(third);
  auto third_stream = *third.value_if();
  pair_->pump_all();
  EXPECT_EQ(third_stream->state(), StreamState::reset);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::quota_exhausted), 1U);
  EXPECT_EQ(gw_->stats().tunnels_active, 2U)
      << "the refused candidate must release its reserved slot";

  // The released slot is not reusable while both tunnels live: a fourth
  // open is refused the same way, refusals accumulate per attempt, and the
  // two admitted tunnels stay open (the refusal path wedges nothing).
  auto fourth = open_from_a({.host = "203.0.113.4", .port = 80, .profile = "office"});
  ASSERT_TRUE(fourth);
  auto fourth_stream = *fourth.value_if();
  pair_->pump_all();
  EXPECT_EQ(fourth_stream->state(), StreamState::reset);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::quota_exhausted), 2U);
  EXPECT_EQ(gw_->stats().tunnels_active, 2U);
  EXPECT_EQ(first_stream->state(), StreamState::open);
  EXPECT_EQ(second_stream->state(), StreamState::open);
}

// ---- Real dial e2e -----------------------------------------------------------

TEST_F(M10GatewayServiceTest, EchoRoundTripHalfCloseAndByteStats) {
  if (local_address_.empty()) {
    GTEST_SKIP() << "no non-loopback unicast IPv4 address: gateway dials are "
                    "untestable (loopback is builtin-denied)";
  }
  auto echo = std::make_shared<EchoTarget>(io_, local_address_);
  ASSERT_TRUE(echo->ok());
  echo->start();

  auto profile = profile_for("office", {local_address_ + "/32"});
  install_gateway({profile}, {"gateway.provide:office"});
  auto opened = open_from_a(
      {.host = local_address_, .port = echo->port(), .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  auto read = pend_read(*stream, 64U);
  spin(24);
  EXPECT_EQ(gw_->stats().dials_succeeded, 1U);
  EXPECT_EQ(gw_->stats().tunnels_active, 1U);
  EXPECT_EQ(echo->accepted(), 1U);

  // The first caller read starts with tunnel payload: the 2-byte prelude was
  // consumed internally and never surfaces.
  ASSERT_TRUE(write_all(*stream, "HELLO-GW"));
  ASSERT_TRUE(spin_until([&] { return read->completed; }, 2000));
  ASSERT_FALSE(read->error.has_value()) << read->error->safe_detail();
  if (read->bytes != 8U || as_text(read->data) != "HELLO-GW") {
    dump_gateway_state("echo-read", stream.get());
  }
  EXPECT_EQ(read->bytes, 8U);
  EXPECT_EQ(as_text(read->data), "HELLO-GW");

  // Initiator half-close -> serving side shuts the socket send side down ->
  // target EOF -> FIN back to the initiator.
  ASSERT_TRUE(stream->shutdown_write());
  auto eof_read = pend_read(*stream, 64U);
  ASSERT_TRUE(spin_until([&] { return eof_read->completed; }, 3000));
  EXPECT_FALSE(eof_read->error.has_value());
  EXPECT_EQ(eof_read->bytes, 0U);
  EXPECT_EQ(stream->state(), StreamState::closed);

  const auto& stats = gw_->stats();
  EXPECT_GE(stats.bytes_from_tunnel, 8U);  // A -> target
  EXPECT_GE(stats.bytes_to_tunnel, 8U);    // target -> A
  EXPECT_EQ(stats.dials_failed, 0U);
  // A clean EOF leaves the tunnel registered until a sweep or teardown.
  EXPECT_EQ(stats.tunnels_active, 1U);
}

TEST_F(M10GatewayServiceTest, ClosedPortResetsUnavailable) {
  if (local_address_.empty()) {
    GTEST_SKIP() << "no non-loopback unicast IPv4 address";
  }
  // Reserve a port then stop listening: the dial must fail (coarse
  // `unavailable`, never distinguishing refused).
  boost::asio::ip::tcp::acceptor probe{io_};
  boost::system::error_code ec;
  auto addr = boost::asio::ip::make_address(local_address_, ec);
  ASSERT_FALSE(ec);
  boost::asio::ip::tcp::endpoint endpoint{addr, 0U};
  probe.open(endpoint.protocol(), ec);
  ASSERT_FALSE(ec);
  probe.bind(endpoint, ec);
  ASSERT_FALSE(ec);
  probe.listen(1, ec);
  ASSERT_FALSE(ec);
  const auto port = probe.local_endpoint(ec).port();
  ASSERT_FALSE(ec);
  probe.close(ec);

  auto profile = profile_for("office", {local_address_ + "/32"});
  install_gateway({profile}, {"gateway.provide:office"});
  auto opened = open_from_a({.host = local_address_, .port = port, .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  if (!spin_until([&] { return stream->state() == StreamState::reset; }, 3000)) {
    dump_gateway_state("closed-port", stream.get());
  }
  ASSERT_TRUE(stream->state() == StreamState::reset);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::dial_failed), 1U);
  EXPECT_EQ(gw_->stats().dials_failed, 1U);
  EXPECT_EQ(gw_->stats().dials_succeeded, 0U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
}

TEST_F(M10GatewayServiceTest, DialDeadlineResetsDeadlineExceeded) {
  if (local_address_.empty()) {
    GTEST_SKIP() << "no non-loopback unicast IPv4 address (used only to prove "
                    "the environment could dial at all)";
  }
  auto profile = profile_for("office", {"203.0.113.0/24"});
  profile.dial_deadline = std::chrono::milliseconds{1000};
  install_gateway({profile}, {"gateway.provide:office"});
  auto opened = open_from_a({.host = "203.0.113.1", .port = 65500, .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  const auto reset = spin_until([&] { return stream->state() == StreamState::reset; },
                                2600);
  if (!reset) dump_gateway_state("dial-deadline", stream.get());
  ASSERT_TRUE(reset) << "dial deadline never fired";
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::dial_deadline), 1U);
  EXPECT_EQ(gw_->stats().dials_failed, 1U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
}

TEST_F(M10GatewayServiceTest, ByteQuotaResetMidStreamAndFutureAdmission) {
  if (local_address_.empty()) {
    GTEST_SKIP() << "no non-loopback unicast IPv4 address";
  }
  auto echo = std::make_shared<EchoTarget>(io_, local_address_);
  ASSERT_TRUE(echo->ok());
  echo->start();
  auto profile = profile_for("office", {local_address_ + "/32"});
  profile.max_profile_bytes = 100U;  // 60 bytes each way exceeds it
  install_gateway({profile}, {"gateway.provide:office"});
  auto opened = open_from_a(
      {.host = local_address_, .port = echo->port(), .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  auto read = pend_read(*stream, 64U);
  spin(24);
  ASSERT_EQ(gw_->stats().dials_succeeded, 1U);

  ASSERT_TRUE(write_all(*stream, std::string(60U, 'q')));
  ASSERT_TRUE(spin_until([&] { return read->completed; }, 2000));
  ASSERT_FALSE(read->error.has_value());
  if (read->bytes != 60U) dump_gateway_state("quota-read", stream.get());
  EXPECT_EQ(read->bytes, 60U);
  EXPECT_GE(gw_->stats().bytes_from_tunnel + gw_->stats().bytes_to_tunnel, 100U);

  // The quota sweep resets the live tunnel.
  gw_->prune();
  pair_->pump_all();
  EXPECT_EQ(gw_->stats().byte_quota_resets, 1U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
  EXPECT_EQ(stream->state(), StreamState::reset);

  // The lifetime quota now also fails future admissions for the profile.
  auto second = open_from_a(
      {.host = local_address_, .port = echo->port(), .profile = "office"});
  ASSERT_TRUE(second);
  pair_->pump_all();
  EXPECT_EQ((*second.value_if())->state(), StreamState::reset);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::quota_exhausted), 1U);
}

// ---- Timeout sweeps (injected clock) -----------------------------------------

TEST_F(M10GatewayServiceTest, PruneDurationTimeoutSweepsDialingTunnel) {
  auto profile = profile_for("office", {"203.0.113.0/24"});
  profile.stream_max_duration = std::chrono::milliseconds{1000};
  profile.dial_deadline = std::chrono::milliseconds{30000};
  install_gateway({profile}, {"gateway.provide:office"});
  auto opened = open_from_a({.host = "203.0.113.1", .port = 80, .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  spin(6);
  ASSERT_EQ(gw_->stats().tunnels_active, 1U);

  now_ms_ = kNow + 1001U;  // past the total-duration cap
  gw_->prune();
  pair_->pump_all();
  EXPECT_EQ(gw_->stats().duration_timeout_resets, 1U);
  EXPECT_EQ(gw_->stats().idle_timeout_resets, 0U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
  EXPECT_EQ(stream->state(), StreamState::reset);
}

TEST_F(M10GatewayServiceTest, PruneIdleIgnoresDialingTunnel) {
  auto profile = profile_for("office", {"203.0.113.0/24"});
  profile.stream_idle_timeout = std::chrono::milliseconds{1000};
  profile.stream_max_duration = std::chrono::milliseconds{86400000};
  profile.dial_deadline = std::chrono::milliseconds{30000};
  install_gateway({profile}, {"gateway.provide:office"});
  auto opened = open_from_a({.host = "203.0.113.1", .port = 80, .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  spin(6);
  ASSERT_EQ(gw_->stats().tunnels_active, 1U);

  // Far past the idle timeout, still mid-dial and within the duration cap:
  // the idle sweep must not fire.
  now_ms_ = kNow + 60'000U;
  gw_->prune();
  pair_->pump_all();
  EXPECT_EQ(gw_->stats().idle_timeout_resets, 0U);
  EXPECT_EQ(gw_->stats().duration_timeout_resets, 0U);
  EXPECT_EQ(gw_->stats().tunnels_active, 1U);
  EXPECT_EQ(stream->state(), StreamState::open);
}

TEST_F(M10GatewayServiceTest, PruneIdleResetsConnectedTunnel) {
  if (local_address_.empty()) {
    GTEST_SKIP() << "no non-loopback unicast IPv4 address: the idle sweep only "
                    "applies to connected tunnels";
  }
  auto echo = std::make_shared<EchoTarget>(io_, local_address_);
  ASSERT_TRUE(echo->ok());
  echo->start();
  auto profile = profile_for("office", {local_address_ + "/32"});
  profile.stream_idle_timeout = std::chrono::milliseconds{1000};
  profile.stream_max_duration = std::chrono::milliseconds{86400000};
  install_gateway({profile}, {"gateway.provide:office"});
  auto opened = open_from_a(
      {.host = local_address_, .port = echo->port(), .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  auto read = pend_read(*stream, 64U);
  spin(24);
  ASSERT_EQ(gw_->stats().dials_succeeded, 1U);
  ASSERT_TRUE(write_all(*stream, "PING"));
  ASSERT_TRUE(spin_until([&] { return read->completed; }, 2000));

  now_ms_ = kNow + 1001U;  // connected and silent past the idle timeout
  gw_->prune();
  pair_->pump_all();
  EXPECT_EQ(gw_->stats().idle_timeout_resets, 1U);
  EXPECT_EQ(gw_->stats().duration_timeout_resets, 0U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
  EXPECT_EQ(stream->state(), StreamState::reset);
}

// ---- Session close / resource reclaim ----------------------------------------

TEST_F(M10GatewayServiceTest, SessionCloseClosesSocketsAndRegistry) {
  if (local_address_.empty()) {
    GTEST_SKIP() << "no non-loopback unicast IPv4 address";
  }
  auto echo = std::make_shared<EchoTarget>(io_, local_address_);
  ASSERT_TRUE(echo->ok());
  echo->start();
  auto profile = profile_for("office", {local_address_ + "/32"});
  profile.stream_idle_timeout = std::chrono::milliseconds{86400000};
  profile.stream_max_duration = std::chrono::milliseconds{86400000};
  install_gateway({profile}, {"gateway.provide:office"});
  auto opened = open_from_a(
      {.host = local_address_, .port = echo->port(), .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  auto read = pend_read(*stream, 64U);
  spin(24);
  ASSERT_EQ(gw_->stats().dials_succeeded, 1U);
  ASSERT_TRUE(write_all(*stream, "PING"));
  ASSERT_TRUE(spin_until([&] { return read->completed; }, 2000));
  ASSERT_EQ(echo->closed(), 0U);

  // Session loss: every socket closes, the registry empties, and repeated
  // sweeps are no-ops.
  gw_->handle_session_closed();
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
  ASSERT_TRUE(spin_until([&] { return echo->closed() >= 1U; }, 2000))
      << "target never observed the socket close";

  const auto before = gw_->stats();
  gw_->prune();
  const auto after = gw_->stats();
  EXPECT_EQ(after.idle_timeout_resets, before.idle_timeout_resets);
  EXPECT_EQ(after.duration_timeout_resets, before.duration_timeout_resets);
  EXPECT_EQ(after.byte_quota_resets, before.byte_quota_resets);
  EXPECT_EQ(after.tunnels_active, 0U);
}

// ---- Node-level public API (M10-08) ------------------------------------------

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

struct LanNodePair {
  std::optional<ProfileStore> first_store;
  std::optional<ProfileStore> second_store;
  std::optional<Node> first;
  std::optional<Node> second;
  DeviceEndpointKey first_key;
  DeviceEndpointKey second_key;
};

constexpr const char* kNodeTestApplicationId = "com.example.m10-gateway-service";

class M10NodeGatewayApiTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M10_SERVICE_TEST_STATE_DIR} /
            ("node-" + std::to_string(::testing::UnitTest::GetInstance()
                                           ->random_seed()));
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
    std::filesystem::create_directories(root_);
    std::filesystem::permissions(root_.parent_path(),
                                 std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    std::filesystem::permissions(root_, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
  }

  void TearDown() override {
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
  }

  Result<ProfileStore> initialized_profile(const std::string& name,
                                           const std::string& application_id) {
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
        .application_id = application_id,
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

  Result<Node> make_node(ProfileStore& store,
                         std::vector<GatewayProfileConfig> gateway_profiles,
                         std::optional<LanConfiguration> lan = std::nullopt) {
    NodeConfig config{.profile = &store,
                      .runtime = nullptr,
                      .application_id = kNodeTestApplicationId,
                      .lan_override = lan,
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
                      .gateway_profiles = std::move(gateway_profiles)};
    return Node::create(std::move(config));
  }

  template <typename Predicate>
  bool wait_until(Predicate&& predicate, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    executor::comm::PhaseGate poll{"m10-gateway-service-poll"};
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
        return true;
      }
      (void)poll.wait_for(1U, std::chrono::milliseconds{2});
    }
    return predicate();
  }

  // Establishes an authenticated LAN session between two nodes with the
  // given mutual trust scopes; the second node carries the given gateway
  // profiles (the serving side).
  LanPairStatus establish_lan_pair(LanNodePair& pair,
                                   const std::vector<std::string>& trust_scopes,
                                   std::vector<GatewayProfileConfig> second_profiles) {
    auto first_profile = initialized_profile("lan-first", kNodeTestApplicationId);
    auto second_profile =
        initialized_profile("lan-second", kNodeTestApplicationId);
    if (!first_profile || !second_profile) {
      return LanPairStatus::no_interfaces;
    }
    if (!heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                         *second_profile.value_if(), trust_scopes)) {
      return LanPairStatus::no_interfaces;
    }
    pair.first_store.emplace(std::move(*first_profile.value_if()));
    pair.second_store.emplace(std::move(*second_profile.value_if()));

    auto first_node = make_node(*pair.first_store, {}, fast_lan_only());
    auto second_node =
        make_node(*pair.second_store, std::move(second_profiles), fast_lan_only());
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

    const auto discovered = [&pair](const Node& node, const DeviceEndpointKey& peer) {
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

  std::filesystem::path root_;
};

TEST_F(M10NodeGatewayApiTest, LocalValidationRejectsBadTargetAndWindows) {
  auto profile = initialized_profile("local-validation", kNodeTestApplicationId);
  ASSERT_TRUE(profile);
  auto node = make_node(*profile.value_if(), {});
  ASSERT_TRUE(node) << node.error_if()->safe_detail();

  const DeviceEndpointKey peer{filled<DeviceId>(0x11U), filled<EndpointId>(0x22U)};
  const auto bad_host = node.value_if()->open_gateway_stream(
      peer,
      GatewayConnect{.host = "bad_host", .port = 443, .profile = ""},
      NodeGatewayStreamOptions{});
  ASSERT_FALSE(bad_host);
  ASSERT_NE(bad_host.error_if(), nullptr);
  EXPECT_EQ(bad_host.error_if()->code(), ErrorCode::permission);
  EXPECT_EQ(bad_host.error_if()->component(), "gateway");
  EXPECT_EQ(bad_host.error_if()->safe_detail(), "gateway_host_invalid");

  const auto zero_port = node.value_if()->open_gateway_stream(
      peer, GatewayConnect{.host = "nas.local", .port = 0U, .profile = ""},
      NodeGatewayStreamOptions{});
  ASSERT_FALSE(zero_port);
  EXPECT_EQ(zero_port.error_if()->safe_detail(), "gateway_port_invalid");

  NodeGatewayStreamOptions zero_window;
  zero_window.receive_window_bytes = 0U;
  const auto bad_window = node.value_if()->open_gateway_stream(
      peer, GatewayConnect{.host = "nas.local", .port = 443U, .profile = ""},
      zero_window);
  ASSERT_FALSE(bad_window);
  EXPECT_EQ(bad_window.error_if()->code(), ErrorCode::configuration);
  EXPECT_EQ(bad_window.error_if()->safe_detail(), "stream_window_invalid");

  NodeGatewayStreamOptions zero_frames;
  zero_frames.receive_window_frames = 0U;
  const auto bad_frames = node.value_if()->open_gateway_stream(
      peer, GatewayConnect{.host = "nas.local", .port = 443U, .profile = ""},
      zero_frames);
  ASSERT_FALSE(bad_frames);
  EXPECT_EQ(bad_frames.error_if()->safe_detail(), "stream_window_invalid");

  EXPECT_TRUE(node.value_if()->shutdown().stopped);
}

TEST_F(M10NodeGatewayApiTest, WithoutSessionFailsPairingRequired) {
  auto profile = initialized_profile("no-session", kNodeTestApplicationId);
  ASSERT_TRUE(profile);
  auto node = make_node(*profile.value_if(), {});
  ASSERT_TRUE(node) << node.error_if()->safe_detail();

  const DeviceEndpointKey peer{filled<DeviceId>(0x11U), filled<EndpointId>(0x22U)};
  const auto opened = node.value_if()->open_gateway_stream(
      peer, GatewayConnect{.host = "10.1.2.3", .port = 80, .profile = "office"},
      NodeGatewayStreamOptions{});
  ASSERT_FALSE(opened);
  ASSERT_NE(opened.error_if(), nullptr);
  EXPECT_EQ(opened.error_if()->code(), ErrorCode::pairing_required);
  EXPECT_EQ(opened.error_if()->safe_detail(), "session_not_authorized");
  EXPECT_TRUE(node.value_if()->shutdown().stopped);
}

TEST_F(M10NodeGatewayApiTest, GatewayUseScopeGateBlocksOpenWithoutScope) {
  LanNodePair pair;
  const auto status = establish_lan_pair(pair, {"stream.open"}, {});
  if (status != LanPairStatus::ready) {
    const char* required = std::getenv("HEYAKI_REQUIRE_LAN_INTERFACES");
    if (required != nullptr && std::string_view{required} == "1") {
      FAIL() << "LAN pair establishment failed (status=" << static_cast<int>(status)
             << ")";
    }
    GTEST_SKIP() << "LAN pair establishment unavailable (status="
                 << static_cast<int>(status) << ")";
  }

  const auto sessions = pair.first.value().peer_sessions();
  const auto session = std::find_if(
      sessions.begin(), sessions.end(), [](const NodePeerSessionSnapshot& snapshot) {
        return snapshot.state == NodePeerSessionState::authenticated;
      });
  ASSERT_NE(session, sessions.end());
  EXPECT_EQ(std::count(session->authorized_scopes.begin(),
                       session->authorized_scopes.end(), "gateway.use"),
            0U);

  const auto opened = pair.first.value().open_gateway_stream(
      pair.second_key,
      GatewayConnect{.host = "10.1.2.3", .port = 80, .profile = "office"},
      NodeGatewayStreamOptions{});
  ASSERT_FALSE(opened);
  ASSERT_NE(opened.error_if(), nullptr);
  EXPECT_EQ(opened.error_if()->code(), ErrorCode::permission);
  EXPECT_EQ(opened.error_if()->safe_detail(), "gateway_use_scope_missing");

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

TEST_F(M10NodeGatewayApiTest, EndToEndEchoThroughPublicApi) {
  // The B side dials a real target, so the echo endpoint needs the host's
  // non-loopback address (loopback is builtin-denied).
  boost::asio::io_context io;
  boost::system::error_code ec;
  boost::asio::ip::udp::socket probe{io};
  probe.open(boost::asio::ip::udp::v4(), ec);
  ASSERT_FALSE(ec);
  probe.connect(boost::asio::ip::udp::endpoint{
                    boost::asio::ip::make_address("8.8.8.8", ec), 53U}, ec);
  ASSERT_FALSE(ec);
  const auto local = probe.local_endpoint(ec);
  probe.close(ec);
  if (ec || local.address().is_loopback() || local.address().is_unspecified()) {
    GTEST_SKIP() << "no non-loopback unicast IPv4 address for the echo target";
  }
  const std::string local_address = local.address().to_string();

  auto echo = std::make_shared<EchoTarget>(io, local_address);
  ASSERT_TRUE(echo->ok());
  echo->start();

  auto profile = profile_for("office", {local_address + "/32"});
  LanNodePair pair;
  const auto status = establish_lan_pair(
      pair, {"stream.open", std::string{gateway_use_scope},
             gateway_provide_scope("office")},
      {profile});
  if (status != LanPairStatus::ready) {
    const char* required = std::getenv("HEYAKI_REQUIRE_LAN_INTERFACES");
    if (required != nullptr && std::string_view{required} == "1") {
      FAIL() << "LAN pair establishment failed (status=" << static_cast<int>(status)
             << ")";
    }
    GTEST_SKIP() << "LAN pair establishment unavailable (status="
                 << static_cast<int>(status) << ")";
  }

  auto opened = pair.first.value().open_gateway_stream(
      pair.second_key,
      GatewayConnect{.host = local_address, .port = echo->port(), .profile = "office"},
      NodeGatewayStreamOptions{});
  ASSERT_TRUE(opened) << (opened.error_if() != nullptr
                              ? opened.error_if()->safe_detail()
                              : std::string{"unknown"});
  ByteStream stream{std::move(*opened.value_if())};
  EXPECT_EQ(stream.state(), ByteStreamState::open);

  // One bounded thread-free pump for the echo target side.
  auto pump_echo = [&]() {
    (void)io.poll();
    return true;
  };

  std::atomic<bool> write_done{false};
  std::optional<Error> write_error;  // set before write_done flips
  stream.async_write(as_bytes("HELLO-NODE"), [&](ByteStreamIoResult result) {
    if (result.error.has_value()) write_error = result.error;
    write_done.store(true);
  });
  EXPECT_TRUE(wait_until([&] { return write_done.load(); },
                         std::chrono::milliseconds{3000}));
  ASSERT_FALSE(write_error.has_value()) << write_error->safe_detail();

  std::atomic<std::size_t> received{0U};
  std::atomic<bool> read_done{false};
  std::optional<Error> read_error;
  auto buffer = std::make_shared<std::array<std::byte, 64U>>();
  stream.async_read_some(std::span<std::byte>{buffer->data(), buffer->size()},
                         [&, buffer](ByteStreamIoResult result) {
                           if (result.error.has_value()) read_error = result.error;
                           received.store(result.bytes);
                           read_done.store(true);
                         });
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
  while (!read_done.load() && std::chrono::steady_clock::now() < deadline) {
    (void)pump_echo();
    executor::comm::PhaseGate poll{"m10-gateway-service-echo-poll"};
    (void)poll.wait_for(1U, std::chrono::milliseconds{2});
  }
  ASSERT_TRUE(read_done.load()) << "echo never reached the public stream";
  ASSERT_FALSE(read_error.has_value()) << read_error->safe_detail();
  ASSERT_EQ(received.load(), 10U);
  const std::string echoed{reinterpret_cast<const char*>(buffer->data()),
                            received.load()};
  EXPECT_EQ(echoed, "HELLO-NODE");

  // Half-close propagates to the target and back as a clean EOF.
  ASSERT_TRUE(stream.shutdown_write());
  std::atomic<bool> eof_seen{false};
  std::atomic<std::size_t> eof_bytes{0U};
  std::optional<Error> eof_error;
  auto eof_buffer = std::make_shared<std::array<std::byte, 16U>>();
  stream.async_read_some(std::span<std::byte>{eof_buffer->data(), eof_buffer->size()},
                         [&, eof_buffer](ByteStreamIoResult result) {
                           if (result.error.has_value()) eof_error = result.error;
                           eof_bytes.store(result.bytes);
                           eof_seen.store(true);
                         });
  const auto eof_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
  while (!eof_seen.load() && std::chrono::steady_clock::now() < eof_deadline) {
    (void)pump_echo();
    executor::comm::PhaseGate poll{"m10-gateway-service-eof-poll"};
    (void)poll.wait_for(1U, std::chrono::milliseconds{2});
  }
  ASSERT_TRUE(eof_seen.load()) << "clean EOF never reached the public stream";
  ASSERT_FALSE(eof_error.has_value()) << eof_error->safe_detail();
  EXPECT_EQ(eof_bytes.load(), 0U);

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// Spec (M10-08): an initiator-side gateway stream whose 2-byte prelude does
// not arrive before dial_deadline must be RESET(deadline_exceeded) by the
// deadline sweep, and its pending read must complete with an error.
//
// DEFECT (deliberately last so the rest of the suite stays observable):
// ByteStreamService::check_deadlines (src/client/byte_stream.cpp) iterates
// `streams_` with a range-for while the gateway dial-deadline branch calls
// handle_reset_frame_for -> finish_stream, which erases the current element
// from that same map. The subsequent iterator increment is undefined
// behaviour and crashes the process (SIGSEGV inside std::_Rb_tree_increment;
// ASAN reports the use-after-free). The Node 500ms prune tick drives the
// same function, so any real initiator whose dial deadline expires hits
// this. Expected: stream reset + pending read error, process intact.
// Separate suite so this crash-demonstrating test registers (and therefore
// runs) after every other suite in this file, keeping their results
// observable.
class M10GatewayDialDeadlineSweepTest : public M10GatewayServiceTest {};

TEST_F(M10GatewayDialDeadlineSweepTest, InitiatorDialDeadlineSweepResetsStream) {
  right_->set_gateway_inbound_handler(
      [](const std::shared_ptr<ByteStreamHandle>&, const GatewayConnect&) {});

  auto undated = open_from_a({.host = "203.0.113.9", .port = 443, .profile = "office"});
  ASSERT_TRUE(undated);
  auto undated_stream = *undated.value_if();
  auto undated_read = pend_read(*undated_stream, 64U);

  auto dated =
      open_from_a({.host = "203.0.113.9", .port = 443, .profile = "office"}, kNow + 1000U);
  ASSERT_TRUE(dated);
  auto dated_stream = *dated.value_if();
  auto dated_read = pend_read(*dated_stream, 64U);
  pair_->pump_all();

  now_ms_ = kNow + 1001U;
  left_->check_deadlines();  // <-- crashes here today (iterator invalidation)
  EXPECT_EQ(dated_stream->state(), StreamState::reset);
  ASSERT_TRUE(dated_read->completed);
  ASSERT_TRUE(dated_read->error.has_value());
  EXPECT_EQ(dated_read->error->code(), ErrorCode::cancelled);
  EXPECT_EQ(dated_read->error->safe_detail(), "stream_reset");
  EXPECT_EQ(undated_stream->state(), StreamState::open);
  EXPECT_FALSE(undated_read->completed);
}

}  // namespace
}  // namespace heyaki
