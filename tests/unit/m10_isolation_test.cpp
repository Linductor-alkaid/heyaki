// M10 Round 6 protocol-isolation tests: gateway streams must never leak
// across the session-restart epoch boundary (M5-18 applied to the gateway
// state machine).
//
//  1. LateOldEpochGatewayFramesDroppedByRestartedSession — the wire format
//     carries no epoch on STREAM_* frames; isolation rests on the physical
//     session boundary. After a restart (epoch 1 session retired, epoch 2
//     successor built on a fresh transport with the same SessionId), frames
//     naming the OLD stream id that land on the new session's stream domain
//     must be dropped without creating state, without delivering data, and
//     without failing the new session — and the old handle itself must be
//     reset by the retirement teardown (the node destroys the per-session
//     ByteStreamService; fail_all is the M5-18 mechanism).
//  2. SessionRestartResetsOldGatewayStream — Node-level: a live gateway
//     tunnel (prelude exchanged, echo verified) across a real LAN pair is
//     broken by restart_session(): the old public stream reaches `reset`,
//     reads complete with an error, the one-shot on_connected never
//     refires, the serving side's audit trail stays well-formed, and the
//     epoch-2 successor serves a FRESH gateway stream normally.
//
// Harness model mirrors m10_protocol_test.cpp / m10_metrics_audit_test.cpp:
// pump-driven loopback transports at the session layer, real LAN nodes at
// the Node layer (skipped without a non-loopback interface).

#include "byte_stream.hpp"
#include "m4_support.hpp"
#include "m5_support.hpp"
#include "peer_session.hpp"
#include "session_channels.hpp"

#include "core/proto_codec.hpp"

#include <heyaki/byte_stream.hpp>
#include <heyaki/error.hpp>
#include <heyaki/gateway.hpp>
#include <heyaki/identity.hpp>
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/signaling_protocol.hpp>
#include <heyaki/wire.hpp>

#include <executor/comm.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/write.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
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

#ifndef HEYAKI_M10_ISOLATION_TEST_STATE_DIR
#define HEYAKI_M10_ISOLATION_TEST_STATE_DIR "/tmp/heyaki-m10-isolation"
#endif

namespace heyaki {
namespace {

constexpr std::uint64_t kNow = 1'700'000'000'000U;

template <typename Value>
Value filled(std::uint8_t seed) {
  typename Value::Storage bytes{};
  for (std::size_t index = 0U; index < bytes.size(); ++index) {
    bytes[index] = static_cast<std::byte>(seed + index);
  }
  return Value{bytes};
}

template <std::size_t Size>
std::array<std::byte, Size> filled_array(std::uint8_t seed) {
  std::array<std::byte, Size> bytes{};
  for (std::size_t index = 0U; index < Size; ++index) {
    bytes[index] = static_cast<std::byte>(seed + index);
  }
  return bytes;
}

std::span<const std::byte> as_bytes(std::string_view text) {
  return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

ProtocolHello protocol_13_hello() {
  return {.version = ProtocolVersion{1U, 3U},
          .supported = {protocol_1_3_capability_bits},
          .required = {static_cast<std::uint64_t>(Capability::session)}};
}

// Loopback session pair parametrized by session epoch: a restart successor
// keeps the SessionId and bumps the epoch, so the harness builds the two
// physical generations with identical identities and ids.
struct GatewayEpochPair {
  test::LoopbackTransportPair pair;
  Result<IdentityKeyPair> left_identity{create_identity()};
  Result<IdentityKeyPair> right_identity{create_identity()};
  std::map<DeviceId, std::vector<std::string>> left_trust;
  std::map<DeviceId, std::vector<std::string>> right_trust;
  std::shared_ptr<PeerSession> left;
  std::shared_ptr<PeerSession> right;
  const std::uint64_t epoch;

  explicit GatewayEpochPair(std::uint64_t session_epoch)
      : epoch(session_epoch) {
    EXPECT_TRUE(left_identity && right_identity);
    pair.connect();
    transport::ChannelOptions control_options;
    pair.left().async_open_channel(transport::ChannelKind::control, control_options,
                                   [](Result<transport::TransportChannel*>) {});
    pair.right().async_open_channel(transport::ChannelKind::control, control_options,
                                    [](Result<transport::TransportChannel*>) {});
    build_sessions();
  }

  [[nodiscard]] DeviceEndpointKey left_key() const {
    return {left_identity.value_if()->device_id(), filled<EndpointId>(0x20U)};
  }
  [[nodiscard]] DeviceEndpointKey right_key() const {
    return {right_identity.value_if()->device_id(), filled<EndpointId>(0x40U)};
  }

  void build_sessions() {
    const auto session_id = filled<SessionId>(0x60U);
    const auto initiator_nonce = filled_array<signaling_nonce_bytes>(0x10U);
    const auto responder_nonce = filled_array<signaling_nonce_bytes>(0x30U);
    const auto transcript = filled_array<signaling_transcript_sha256_bytes>(0x50U);
    auto left_transport = std::shared_ptr<transport::TransportSession>(
        &pair.left(), [](transport::TransportSession*) {});
    auto right_transport = std::shared_ptr<transport::TransportSession>(
        &pair.right(), [](transport::TransportSession*) {});
    VerifiedSessionBinding left_binding{
        {right_key(), left_key(), session_id, epoch, initiator_nonce,
         responder_nonce, transcript},
        {},
        "peer-ufrag",
        true};
    VerifiedSessionBinding right_binding{
        {left_key(), right_key(), session_id, epoch, initiator_nonce,
         responder_nonce, transcript},
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
                     std::map<DeviceId, std::vector<std::string>>& trust,
                     const std::shared_ptr<ConnectionAttemptTimeline>& timeline,
                     std::shared_ptr<transport::TransportSession> transport)
        -> Result<std::shared_ptr<PeerSession>> {
      return PeerSession::create_verified(
          {.transport = std::move(transport),
           .binding = binding,
           .local_identity = &identity,
           .peer_public_key = peer.public_key(),
           .local_protocol = protocol_13_hello(),
           .expires_unix_milliseconds = kNow + 60'000U,
           .now_unix_milliseconds = kNow,
           .observer = {},
           .timeline = timeline,
           .clock = {},
           .trust_authorizer = [&trust, peer_id = peer.device_id()](
                                   std::uint64_t now) {
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
                              *right_identity.value_if(), left_trust, left_timeline,
                              left_transport);
    ASSERT_TRUE(left_created);
    left = *left_created.value_if();
    auto right_created = build(right_binding, *right_identity.value_if(),
                               *left_identity.value_if(), right_trust, right_timeline,
                               right_transport);
    ASSERT_TRUE(right_created);
    right = *right_created.value_if();
  }

  void pump_all(int rounds = 8) {
    for (int round = 0; round < rounds; ++round) {
      pair.left().pump();
      pair.right().pump();
    }
  }

  void start_authenticated(const std::vector<std::string>& scopes) {
    left_trust[right_identity.value_if()->device_id()] = scopes;
    right_trust[left_identity.value_if()->device_id()] = scopes;
    ASSERT_TRUE(left->start());
    ASSERT_TRUE(right->start());
    pump_all();
    ASSERT_TRUE(left->authenticated() && right->authenticated());
  }
};

const std::vector<std::string>& gateway_scopes() {
  static const std::vector<std::string> scopes{
      "stream.open", std::string{gateway_use_scope},
      std::string{gateway_provide_scope("office")}};
  return scopes;
}

// ---- Session-layer epoch isolation ------------------------------------------

// Heap-anchored one-shot counters/captures: handlers may fire during service
// destruction, so nothing may point into a dead stack frame.
struct GatewayConnectCount {
  std::atomic<int> fires{0};
  std::atomic<int> failures{0};

  void record(Result<void> result) {
    fires.fetch_add(1);
    if (!result) failures.fetch_add(1);
  }
};

struct CapturedIo {
  std::atomic<bool> completed{false};
  std::atomic<std::size_t> bytes{0};
  std::optional<Error> error;
};

TEST(M10Isolation, LateOldEpochGatewayFramesDroppedByRestartedSession) {
  // ---- epoch 1: one live gateway tunnel with the prelude exchanged ----
  auto epoch1 = std::make_unique<GatewayEpochPair>(1U);
  epoch1->start_authenticated(gateway_scopes());
  ASSERT_TRUE(epoch1->left->diagnostics().negotiated_capabilities.has(
      Capability::gateway_v1));

  ByteStreamLimits limits;
  limits.default_receive_window_bytes = 4096U;
  limits.default_receive_window_frames = 4U;
  limits.max_data_chunk_bytes = 1024U;
  auto left1 = std::make_unique<ByteStreamService>(*epoch1->left, limits,
                                                   [] { return kNow; });
  auto right1 = std::make_unique<ByteStreamService>(*epoch1->right, limits,
                                                    [] { return kNow; });
  ASSERT_TRUE(left1->attach() && right1->attach());
  epoch1->pump_all();

  std::vector<std::shared_ptr<ByteStreamHandle>> served1;
  right1->set_gateway_inbound_handler(
      [&](const std::shared_ptr<ByteStreamHandle>& stream, const GatewayConnect&) {
        served1.push_back(stream);
      });

  const auto connect_count = std::make_shared<GatewayConnectCount>();
  const GatewayConnect target{.host = "target.lan", .port = 443U,
                              .profile = "office"};
  auto opened = left1->open_gateway_stream(
      target, 4096U, 4U, 0U,
      [connect_count](Result<void> result) { connect_count->record(result); });
  ASSERT_TRUE(opened) << opened.error_if()->safe_detail();
  auto initiator1 = *opened.value_if();
  epoch1->pump_all();
  ASSERT_EQ(served1.size(), 1U);
  ASSERT_TRUE(initiator1->is_gateway());
  const StreamId old_id = initiator1->stream_id();
  EXPECT_FALSE(old_id == StreamId{});

  // Serving side answers with the connected prelude; the initiator's read of
  // the first payload stays pending (nothing sent yet beyond the prelude).
  const auto prelude = encode_gateway_prelude(gateway_prelude_connected);
  bool prelude_written = false;
  served1[0]->async_write(
      std::span<const std::byte>{prelude.data(), prelude.size()},
      [&prelude_written](StreamIoResult result) {
        prelude_written = !result.error.has_value();
      });
  epoch1->pump_all();
  ASSERT_TRUE(prelude_written);
  ASSERT_EQ(initiator1->state(), StreamState::open)
      << "prelude never promoted the epoch-1 initiator stream";
  EXPECT_EQ(connect_count->fires.load(), 1);
  EXPECT_EQ(connect_count->failures.load(), 0);
  const auto pending_read = std::make_shared<CapturedIo>();
  const auto read_buffer = std::make_shared<std::array<std::byte, 64U>>();
  initiator1->async_read_some(
      std::span<std::byte>{read_buffer->data(), read_buffer->size()},
      [pending_read](StreamIoResult result) {
        pending_read->bytes.store(result.bytes);
        if (result.error.has_value()) pending_read->error = result.error;
        pending_read->completed.store(true);
      });

  // ---- restart: retire the epoch-1 physical session like the node does ----
  epoch1->pair.left().close(transport::CloseReason::local_shutdown);
  epoch1->pair.right().close(transport::CloseReason::local_shutdown);
  // teardown_peer_services order: the stream service is destroyed, and its
  // destructor fails every stream (M5-18).
  left1.reset();
  right1.reset();
  EXPECT_TRUE(pending_read->completed.load())
      << "retirement teardown never completed the pending read";
  ASSERT_TRUE(pending_read->error.has_value())
      << "the pending read completed without an error after session loss";
  EXPECT_EQ(initiator1->state(), StreamState::reset);
  // The one-shot connect callback fired exactly once at the prelude and must
  // never refire on teardown.
  EXPECT_EQ(connect_count->fires.load(), 1);
  EXPECT_EQ(connect_count->failures.load(), 0);

  // ---- epoch 2: same SessionId, bumped epoch, fresh transport ----
  auto epoch2 = std::make_unique<GatewayEpochPair>(2U);
  epoch2->start_authenticated(gateway_scopes());
  ASSERT_TRUE(epoch2->left->authenticated());
  auto left2 = std::make_unique<ByteStreamService>(*epoch2->left, limits,
                                                   [] { return kNow; });
  auto right2 = std::make_unique<ByteStreamService>(*epoch2->right, limits,
                                                    [] { return kNow; });
  ASSERT_TRUE(left2->attach() && right2->attach());
  epoch2->pump_all();
  std::vector<std::shared_ptr<ByteStreamHandle>> served2;
  right2->set_gateway_inbound_handler(
      [&](const std::shared_ptr<ByteStreamHandle>& stream, const GatewayConnect&) {
        served2.push_back(stream);
      });

  // Late old-epoch STREAM_DATA naming the retired stream id: the RAW layout
  // puts the id at offset 0, offset at 16, length at 24.
  const auto inject_channel = epoch2->left->open_business_channel(
      session::ChannelDomain::stream, session::QueueFullPolicy::reject, 16U,
      64U * 1024U, [](const FrameView&) {});
  ASSERT_TRUE(inject_channel);

  auto inject_frame = [&](FrameType type, std::vector<std::byte> payload) {
    Frame frame;
    frame.type = static_cast<std::uint8_t>(type);
    frame.channel_id = *inject_channel.value_if();
    frame.message_id = filled<MessageId>(0x7U);
    frame.payload = std::move(payload);
    return epoch2->left->send_frame(*inject_channel.value_if(),
                                    session::FrameClass::standard,
                                    std::move(frame));
  };
  std::vector<std::byte> data_payload(stream_data_header_bytes + 8U,
                                      std::byte{0x5AU});
  std::copy_n(old_id.begin(), 16U, data_payload.begin());
  // offset 0 and length 8 stay as initialized (header bytes are zero, then
  // the data section carries the 0x5A bytes).
  for (std::size_t index = 0U; index < 8U; ++index) {
    data_payload[stream_data_header_bytes + index] = std::byte{0x5AU};
  }
  ASSERT_TRUE(inject_frame(FrameType::stream_data, data_payload));
  std::vector<std::byte> pb_id_payload;
  proto_codec::append_bytes(pb_id_payload, 1U,
                            std::span<const std::byte>{old_id.data(), old_id.size()});
  ASSERT_TRUE(inject_frame(FrameType::stream_fin, pb_id_payload));
  ASSERT_TRUE(inject_frame(FrameType::stream_reset, pb_id_payload));
  epoch2->pump_all();

  // Nothing was created, nothing was delivered, the new session is healthy.
  // (The stream-domain handler admits the frame — admission is by frame
  // TYPE — and drops it inside because no such stream exists; the drop is
  // observable as the absence of stream state, not as a rejection counter.)
  EXPECT_EQ(right2->active_streams(), 0U)
      << "a late old-epoch frame created stream state in the restarted session";
  EXPECT_EQ(right2->stream(old_id), nullptr)
      << "the retired stream id was resurrected in the restarted session";
  EXPECT_TRUE(served2.empty());
  EXPECT_TRUE(epoch2->right->authenticated())
      << "the late old-epoch frames failed the restarted session";

  // ---- the epoch-2 session serves a FRESH gateway stream normally ----
  auto reopened = left2->open_gateway_stream(target, 4096U, 4U);
  ASSERT_TRUE(reopened) << reopened.error_if()->safe_detail();
  epoch2->pump_all();
  ASSERT_EQ(served2.size(), 1U);
  auto initiator2 = *reopened.value_if();
  const auto prelude2 = encode_gateway_prelude(gateway_prelude_connected);
  bool prelude2_written = false;
  served2[0]->async_write(
      std::span<const std::byte>{prelude2.data(), prelude2.size()},
      [&prelude2_written](StreamIoResult result) {
        prelude2_written = !result.error.has_value();
      });
  epoch2->pump_all();
  ASSERT_TRUE(prelude2_written);
  ASSERT_EQ(initiator2->state(), StreamState::open);
  EXPECT_FALSE(initiator2->stream_id() == old_id)
      << "the restarted session reused the retired stream id";
}

// ---- Node-level restart isolation -------------------------------------------

// Minimal TCP echo target on a non-loopback address (the built-in gateway
// deny list blocks loopback targets).
class RestartEchoTarget {
 public:
  explicit RestartEchoTarget(boost::asio::io_context& io,
                             const std::string& address)
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

 private:
  void start_accept() {
    auto socket =
        std::make_shared<boost::asio::ip::tcp::socket>(acceptor_->get_executor());
    acceptor_->async_accept(
        *socket, [this, socket](const boost::system::error_code& error) {
          if (error) return;
          do_read(socket);
          start_accept();
        });
  }

  void do_read(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) {
    auto buffer = std::make_shared<std::vector<std::byte>>(4096U);
    socket->async_read_some(
        boost::asio::buffer(buffer->data(), buffer->size()),
        [this, socket, buffer](const boost::system::error_code& error,
                               std::size_t bytes) {
          if (error || bytes == 0U) {
            boost::system::error_code ignored;
            socket->close(ignored);
            return;
          }
          boost::asio::async_write(
              *socket, boost::asio::buffer(buffer->data(), bytes),
              [this, socket](const boost::system::error_code& error, std::size_t) {
                if (error) {
                  boost::system::error_code ignored;
                  socket->close(ignored);
                  return;
                }
                do_read(socket);
              });
        });
  }

  std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
  std::uint16_t port_{0U};
  bool ok_{false};
};

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

// The Node-level scenario runs in a forked child on POSIX: the restarted
// successor session currently leaves its stream/gateway services untorn
// (restart_session_changed's closed case is a no-op once the restart record
// is erased), so Node::shutdown()/~Node() can die on a use-after-free in
// ByteStreamService::~ByteStreamService. The child reproduces the whole
// scenario and exits 0 only if every property holds AND both nodes shut
// down cleanly; a signal death surfaces here as a controlled failure that
// names the defect instead of killing the test binary.
int run_restart_isolation_child(const std::filesystem::path& root) {
  const auto child_check = [](bool condition, const char* what) {
    if (!condition) {
      std::fprintf(stderr, "CHILD_FAIL %s (errno-style detail above)\n", what);
    }
    return condition;
  };
  const auto child_step = [](const char* what) {
    std::fprintf(stderr, "CHILD_STEP %s ok\n", what);
  };
  boost::asio::io_context io;
  std::string local_address;
  {
    boost::system::error_code ec;
    boost::asio::ip::udp::socket probe{io};
    probe.open(boost::asio::ip::udp::v4(), ec);
    if (!ec) {
      probe.connect(boost::asio::ip::udp::endpoint{
                        boost::asio::ip::make_address("8.8.8.8", ec), 53U},
                    ec);
      if (!ec) {
        const auto local = probe.local_endpoint(ec);
        if (!ec && !local.address().is_loopback() &&
            !local.address().is_unspecified()) {
          local_address = local.address().to_string();
        }
      }
    }
  }
  if (local_address.empty()) {
    std::fprintf(stderr, "CHILD_SKIP no non-loopback IPv4 address\n");
    return 3;
  }
  RestartEchoTarget echo{io, local_address};
  if (!echo.ok()) {
    std::fprintf(stderr, "CHILD_SKIP echo target bind failed\n");
    return 3;
  }
  echo.start();

  std::error_code ignored_ec;
  std::filesystem::remove_all(root, ignored_ec);
  std::filesystem::create_directories(root, ignored_ec);
  auto make_store = [&](const std::string& name) {
    ProfileOpenOptions options;
    options.secret_backend.prefer_os_backend = false;
    return ProfileStore::create(root / name / "profile.sqlite", options);
  };
  auto initialize = [&make_store](Result<ProfileStore> profile) {
    if (!profile) return profile;
    PasswordVerifier verifier{
        .format_version = 1U, .parameters = PasswordHashParameters{},
        .encoded = "$argon2id$v=19$m=65536,t=2,p=1$test$test"};
    LocalProfileInitialization initialization{
        .application_id = std::string{"com.example.m10-isolation"},
        .password_verifier = std::move(verifier),
        .password_generation = 1U,
        .pairing_policy = PairingPolicy{},
        .lan = fast_lan_only()};
    auto initialized = profile.value_if()->initialize_local(initialization);
    if (!initialized) {
      return Result<ProfileStore>::failure(*initialized.error_if());
    }
    return profile;
  };
  auto first_profile = initialize(make_store("child-first"));
  auto second_profile = initialize(make_store("child-second"));
  if (!child_check(first_profile && second_profile, "profile init")) return 2;
  if (!child_check(test::seed_mutual_trust(*first_profile.value_if(),
                                           *second_profile.value_if(),
                                           gateway_scopes())
                       .has_value(),
                   "seed trust")) {
    return 2;
  }

  GatewayProfileConfig profile;
  profile.name = "office";
  profile.allowed_cidrs = {*parse_gateway_cidr(local_address + "/32")};
  profile.allowed_ports = {GatewayPortRange{1U, 65535U}};
  // Every NodeConfig member is listed: the pinned release build treats a
  // shorter designated initializer as an error.
  auto child_node_config = [&](ProfileStore& store,
                               std::vector<GatewayProfileConfig> profiles) {
    return NodeConfig{.profile = &store,
                      .runtime = nullptr,
                      .application_id = "com.example.m10-isolation",
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
                      .gateway_profiles = std::move(profiles),
                      .gateway_confirm_sink = {}};
  };
  auto first_node = Node::create(child_node_config(*first_profile.value_if(), {}));
  auto second_node =
      Node::create(child_node_config(*second_profile.value_if(), {profile}));
  if (!child_check(first_node && second_node, "node create")) return 2;
  if (first_node.value_if()->snapshot().interfaces.empty() ||
      second_node.value_if()->snapshot().interfaces.empty()) {
    std::fprintf(stderr, "CHILD_SKIP no LAN interface\n");
    (void)first_node.value_if()->shutdown();
    (void)second_node.value_if()->shutdown();
    return 3;
  }
  const auto first_key = DeviceEndpointKey{
      first_node.value_if()->snapshot().device_id,
      first_node.value_if()->snapshot().endpoint_id};
  const auto second_key = DeviceEndpointKey{
      second_node.value_if()->snapshot().device_id,
      second_node.value_if()->snapshot().endpoint_id};

  const auto deadline_for = [](std::chrono::milliseconds budget) {
    return std::chrono::steady_clock::now() + budget;
  };
  executor::comm::PhaseGate child_poll{"m10-isolation-child-poll"};
  const auto wait_for = [&](const std::function<bool()>& predicate,
                            std::chrono::milliseconds budget) {
    const auto deadline = deadline_for(budget);
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) return true;
      (void)child_poll.wait_for(1U, std::chrono::milliseconds{2});
    }
    return predicate();
  };
  const auto authenticated_of = [](Node& node) {
    const auto sessions = node.peer_sessions();
    return std::any_of(
        sessions.begin(), sessions.end(), [](const NodePeerSessionSnapshot& s) {
          return s.state == NodePeerSessionState::authenticated;
        });
  };
  const auto discovered_peer = [](Node& node, const DeviceEndpointKey& peer) {
    const auto entries = node.endpoints();
    return std::any_of(entries.begin(), entries.end(),
                       [&](const auto& entry) { return entry.key == peer; });
  };
  if (!child_check(wait_for(
                      [&] {
                        return discovered_peer(*first_node.value_if(), second_key) &&
                               discovered_peer(*second_node.value_if(), first_key);
                      },
                      std::chrono::milliseconds{10000}),
                   "mutual discovery")) {
    return 2;
  }
  if (!child_check(first_node.value_if()->connect_lan(second_key).has_value(),
                   "connect_lan")) {
    return 2;
  }
  if (!child_check(wait_for([&] {
        return authenticated_of(*first_node.value_if()) &&
               authenticated_of(*second_node.value_if());
      }, std::chrono::milliseconds{12000}), "baseline authenticated")) {
    return 2;
  }
  {
    const auto sessions = first_node.value_if()->peer_sessions();
    const auto baseline = std::find_if(
        sessions.begin(), sessions.end(), [](const auto& session) {
          return session.state == NodePeerSessionState::authenticated;
        });
    if (!child_check(baseline != sessions.end() &&
                     baseline->session_epoch == 1U, "baseline epoch 1")) {
      return 2;
    }
  }
  child_step("baseline-session");

  const auto connect_count = std::make_shared<GatewayConnectCount>();
  auto opened = first_node.value_if()->open_gateway_stream(
      second_key,
      GatewayConnect{.host = local_address, .port = echo.port(),
                     .profile = "office"},
      NodeGatewayStreamOptions{.receive_window_bytes = 4096U,
                               .receive_window_frames = 4U,
                               .dial_deadline_unix_milliseconds = 0U,
                               .on_connected = [connect_count](Result<void> r) {
                                 connect_count->record(r);
                               }});
  if (!child_check(opened.has_value(), "open_gateway_stream")) return 2;
  ByteStream tunnel{std::move(*opened.value_if())};
  // Budget note (compat-2004): the gateway dial + prelude handshake rides a
  // full LAN session; on the slow 20.04 container the 5s budget timed out
  // (CI run 35492361592, CHILD_FAIL "prelude promoted the tunnel"), so the
  // tunnel-lifecycle waits below carry a 15s budget; the propagation-only
  // checks keep 10s.
  if (!child_check(wait_for([&] { return tunnel.state() == ByteStreamState::open; },
                            std::chrono::milliseconds{15000}),
                   "prelude promoted the tunnel")) {
    return 2;
  }
  child_step("gateway-tunnel-open");
  // One echo round trip proves the tunnel was genuinely live.
  {
    struct WriteIo {
      std::atomic<bool> done{false};
      std::optional<Error> error;
    };
    const auto write_state = std::make_shared<WriteIo>();
    tunnel.async_write(as_bytes("ISOLATION-PING"),
                       [write_state](ByteStreamIoResult result) {
                         if (result.error.has_value()) {
                           write_state->error = result.error;
                         }
                         write_state->done.store(true);
                       });
    if (!child_check(wait_for([&] { return write_state->done.load(); },
                              std::chrono::milliseconds{15000}),
                     "tunnel write")) {
      return 2;
    }
    if (!child_check(!write_state->error.has_value(), "tunnel write clean")) {
      return 2;
    }
    struct ReadIo {
      std::atomic<bool> done{false};
      std::atomic<std::size_t> bytes{0U};
      std::optional<Error> error;
    };
    const auto read_state = std::make_shared<ReadIo>();
    const auto buffer = std::make_shared<std::array<std::byte, 64U>>();
    tunnel.async_read_some(
        std::span<std::byte>{buffer->data(), buffer->size()},
        [read_state, buffer](ByteStreamIoResult result) {
          if (result.error.has_value()) read_state->error = result.error;
          read_state->bytes.store(result.bytes);
          read_state->done.store(true);
        });
    if (!child_check(wait_for([&] {
          (void)io.poll();
          return read_state->done.load();
        }, std::chrono::milliseconds{15000}), "tunnel echo read")) {
      return 2;
    }
    const std::string echoed{reinterpret_cast<const char*>(buffer->data()),
                             read_state->bytes.load()};
    if (!child_check(!read_state->error.has_value() && echoed == "ISOLATION-PING",
                     "tunnel echo round trip")) {
      return 2;
    }
  }
  if (!child_check(connect_count->fires.load() == 1 &&
                       connect_count->failures.load() == 0,
                   "on_connected fired once at the prelude")) {
    return 2;
  }
  child_step("gateway-echo-verified");

  auto restarted = first_node.value_if()->restart_session(second_key);
  if (!child_check(restarted.has_value(), "restart_session")) return 2;
  const auto epoch2_of = [&](Node& node, const DeviceEndpointKey& peer) {
    const auto sessions = node.peer_sessions();
    return std::any_of(
        sessions.begin(), sessions.end(), [&](const auto& session) {
          return session.peer == peer &&
                 session.state == NodePeerSessionState::authenticated &&
                 session.session_epoch == 2U;
        });
  };
  if (!child_check(wait_for([&] {
        return epoch2_of(*first_node.value_if(), second_key) &&
               epoch2_of(*second_node.value_if(), first_key);
      }, std::chrono::milliseconds{20000}), "restart reached epoch 2")) {
    return 2;
  }
  child_step("restart-epoch2");
  if (!child_check(wait_for([&] { return tunnel.state() == ByteStreamState::reset; },
                            std::chrono::milliseconds{10000}),
                   "old gateway stream reset by the restart")) {
    return 2;
  }
  {
    struct PostIo {
      std::atomic<bool> done{false};
      std::optional<Error> error;
    };
    const auto post_read = std::make_shared<PostIo>();
    const auto post_buffer = std::make_shared<std::array<std::byte, 64U>>();
    tunnel.async_read_some(
        std::span<std::byte>{post_buffer->data(), post_buffer->size()},
        [post_read](ByteStreamIoResult result) {
          if (result.error.has_value()) post_read->error = result.error;
          post_read->done.store(true);
        });
    if (!child_check(wait_for([&] { return post_read->done.load(); },
                              std::chrono::milliseconds{10000}) &&
                         post_read->error.has_value(),
                     "post-restart read completes with an error")) {
      return 2;
    }
  }
  if (!child_check(connect_count->fires.load() == 1,
                   "on_connected never refired")) {
    return 2;
  }
  if (!child_check(wait_for([&] {
        return second_node.value_if()->service_diagnostics().gateway
                   .tunnels_active == 0U;
      }, std::chrono::milliseconds{10000}), "no tunnel stays active")) {
    return 2;
  }
  for (const auto& record : second_node.value_if()->gateway_audit_records()) {
    const bool well_formed = record.profile == "office" &&
                             record.target_host == local_address &&
                             record.started_unix_ms <= record.ended_unix_ms &&
                             record.end_status != StableStatus::unspecified;
    if (!child_check(well_formed, "audit record well-formed")) return 2;
  }
  child_step("old-stream-isolated");

  auto reopened = first_node.value_if()->open_gateway_stream(
      second_key,
      GatewayConnect{.host = local_address, .port = echo.port(),
                     .profile = "office"},
      NodeGatewayStreamOptions{});
  if (!child_check(reopened.has_value(), "fresh gateway open on epoch 2")) {
    return 2;
  }
  ByteStream successor{std::move(*reopened.value_if())};
  if (!child_check(wait_for([&] { return successor.state() == ByteStreamState::open; },
                            std::chrono::milliseconds{15000}),
                   "fresh gateway tunnel reached open on epoch 2")) {
    return 2;
  }
  successor.reset(StableStatus::cancelled);
  child_step("epoch2-fresh-tunnel");

  if (!io.stopped()) {
    (void)io.poll();
  }
  const auto first_shutdown = first_node.value_if()->shutdown();
  if (!child_check(first_shutdown.stopped, "initiator shutdown drained")) {
    return 2;
  }
  const auto second_shutdown = second_node.value_if()->shutdown();
  if (!child_check(second_shutdown.stopped, "responder shutdown drained")) {
    return 2;
  }
  child_step("shutdown-clean");
  return 0;
}

class M10IsolationNodeTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M10_ISOLATION_TEST_STATE_DIR} /
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

  std::filesystem::path root_;
};

TEST_F(M10IsolationNodeTest, SessionRestartResetsOldGatewayStream) {
#ifdef _WIN32
  GTEST_SKIP() << "POSIX fork crash-harness only";
#else
  // Pre-flight in the parent: without a non-loopback IPv4 address the child
  // cannot host the echo target.
  {
    boost::asio::io_context io;
    boost::system::error_code ec;
    boost::asio::ip::udp::socket probe{io};
    probe.open(boost::asio::ip::udp::v4(), ec);
    if (ec) {
      GTEST_SKIP() << "no IPv4 stack for the echo target probe";
    }
    probe.connect(boost::asio::ip::udp::endpoint{
                      boost::asio::ip::make_address("8.8.8.8", ec), 53U},
                  ec);
    boost::system::error_code local_ec;
    const auto local = probe.local_endpoint(local_ec);
    probe.close(ec);
    if (ec || local_ec || local.address().is_loopback() ||
        local.address().is_unspecified()) {
      GTEST_SKIP() << "no non-loopback unicast IPv4 address for the echo target";
    }
  }
  std::fflush(nullptr);
  const pid_t child = ::fork();
  ASSERT_GE(child, 0) << std::strerror(errno);
  if (child == 0) {
    const int status = run_restart_isolation_child(root_);
    std::fflush(nullptr);
    ::_exit(status);
  }
  int status = 0;
  ASSERT_GT(::waitpid(child, &status, 0), 0);
  if (WIFSIGNALED(status)) {
    ADD_FAILURE()
        << "restart isolation child died from signal " << WTERMSIG(status)
        << " (SIGSEGV = use-after-free): the restart successor session never "
           "runs teardown_peer_services on close (restart_session_changed's "
           "closed case is a no-op after the restart record is erased), so "
           "stream_services survives with a ByteStreamService bound to the "
           "destroyed PeerSession; ~ByteStreamService then calls "
           "close_business_channel on freed memory. Production defect — see "
           "the Round 6 verification report.";
    return;
  }
  ASSERT_TRUE(WIFEXITED(status));
  const int code = WEXITSTATUS(status);
  if (code == 3) {
    GTEST_SKIP() << "child could not establish the LAN/echo prerequisites";
  }
  EXPECT_EQ(code, 0)
      << "restart isolation child reported a scenario failure (see the "
         "CHILD_FAIL line above)";
#endif
}

}  // namespace
}  // namespace heyaki
