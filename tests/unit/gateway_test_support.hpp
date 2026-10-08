#pragma once

// Shared harness for the M10 gateway suites (round4 / gateway_service /
// metrics_audit): byte-fill and byte/text helpers, a pump-driven loopback
// PeerSession pair, the non-loopback v4 prober, a TCP echo target, and the
// one-shot completion captures. Test-only; no production code may include
// this header. Header-only so each test target keeps its existing links.

#include "m4_support.hpp"

#include "connection_attempt.hpp"
#include "peer_session.hpp"
#include "transport/transport_session.hpp"

#include <heyaki/error.hpp>
#include <heyaki/gateway.hpp>
#include <heyaki/identity.hpp>
#include <heyaki/node.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/signaling_protocol.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/write.hpp>

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace heyaki::test {
inline namespace gateway_support {

inline constexpr std::uint64_t kNow = 1'700'000'000'000U;

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

inline std::span<const std::byte> as_bytes(std::string_view text) {
  return std::span<const std::byte>{reinterpret_cast<const std::byte*>(text.data()),
                                    text.size()};
}

inline std::string as_text(const std::vector<std::byte>& data) {
  std::string text;
  text.reserve(data.size());
  for (const auto byte : data) {
    text.push_back(static_cast<char>(byte));
  }
  return text;
}

// ---- Loopback session pair -----------------------------------------------------

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

inline ProtocolHello protocol_13_hello() {
  return {.version = ProtocolVersion{1U, 3U},
          .supported = {protocol_1_3_capability_bits},
          .required = {static_cast<std::uint64_t>(Capability::session)}};
}

// ---- Local network detection ---------------------------------------------------

// The built-in gateway deny list covers all of 127/8 and ::1/128, so a real
// dial needs this host's non-loopback unicast IPv4 address. A connected UDP
// socket resolves it from the routing table without sending any packet; the
// candidate is then PROVEN dialable with a real TCP round trip (some CI
// runners drop hairpin TCP, which means "environment unsuitable" — callers
// skip — not a product failure).
inline std::string detect_non_loopback_v4(boost::asio::io_context& io) {
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

// ---- Echo target ---------------------------------------------------------------

// A small TCP echo server on the test io_context. Every accepted connection
// echoes bytes back; EOF/errors close the connection and count it. Handlers
// keep the object alive through shared_from_this so late completions (for
// example during a fixture's teardown poll) never touch a dead stack object.
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

// ---- One-shot completion captures ----------------------------------------------

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

[[nodiscard]] inline std::shared_ptr<ConnectOutcome> new_connect_outcome() {
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

inline GatewayProfileConfig profile_for(const std::string& name,
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

inline LanConfiguration fast_lan_only() {
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

}  // inline namespace gateway_support
}  // namespace heyaki::test
