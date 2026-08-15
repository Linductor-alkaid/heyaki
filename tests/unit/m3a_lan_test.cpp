#include <heyaki/identity.hpp>
#include <heyaki/lan_directory.hpp>
#include <heyaki/lan_protocol.hpp>
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <executor/comm.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <string>
#include <thread>

namespace heyaki {
namespace {

class M3aNodeTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M3A_TEST_STATE_DIR} / "node";
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
    std::filesystem::create_directories(root_);
  }

  void TearDown() override {
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
  }

  Result<ProfileStore> initialized_profile(std::string_view name,
                                           std::string_view application_id,
                                           const LanConfiguration& lan) {
    ProfileOpenOptions options;
    options.secret_backend.prefer_os_backend = false;
    auto profile = ProfileStore::create(root_ / std::string{name} / "profile.sqlite", options);
    if (!profile) {
      return profile;
    }
    PasswordVerifier verifier{.format_version = 1U,
                              .parameters = PasswordHashParameters{},
                              .encoded = "$argon2id$v=19$m=65536,t=2,p=1$test$test"};
    LocalProfileInitialization initialization{
        .application_id = std::string{application_id},
        .password_verifier = std::move(verifier),
        .password_generation = 1U,
        .pairing_policy = PairingPolicy{},
        .lan = lan};
    auto initialized = profile.value_if()->initialize_local(initialization);
    if (!initialized) {
      return Result<ProfileStore>::failure(*initialized.error_if());
    }
    return profile;
  }

  template <typename Predicate>
  bool wait_until(Predicate&& predicate, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
        return true;
      }
      std::this_thread::yield();
    }
    return predicate();
  }

  std::filesystem::path root_;
};

NodeConfig node_config(ProfileStore& profile, std::string application_id,
                       LanSignalingValidator validator = {},
                       LanSignalingHandler handler = {}) {
  return NodeConfig{.profile = &profile,
                    .runtime = nullptr,
                    .application_id = std::move(application_id),
                    .lan_override = std::nullopt,
                    .runtime_config = RuntimeConfig{},
                    .signaling_validator = std::move(validator),
                    .signaling_handler = std::move(handler)};
}

RequestId request_id(std::uint8_t tag) {
  RequestId::Storage bytes{};
  bytes[0] = static_cast<std::byte>(tag);
  return RequestId{bytes};
}

bool has_authenticated_connection(const Node& node, DeviceEndpointKey peer) {
  const auto connections = node.signaling_connections();
  return std::any_of(connections.begin(), connections.end(), [&](const auto& connection) {
    return connection.peer == peer &&
           connection.state == LanSignalingConnectionState::authenticated;
  });
}

Result<void> trust_peer(ProfileStore& profile, const DeviceId& peer,
                        std::uint8_t tag) {
  GrantId::Storage grant_bytes{};
  grant_bytes[0] = static_cast<std::byte>(tag);
  const auto now = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
  return profile.put_trust_grant(
      TrustGrantRecord{.grant_id = GrantId{grant_bytes},
                       .direction = TrustGrantDirection::issued,
                       .issuer = profile.device_id(),
                       .subject = peer,
                       .scopes = {"pairing.connect"},
                       .password_generation = 1U,
                       .issued_unix_milliseconds = now,
                       .expires_unix_milliseconds = now + 60'000U,
                       .signature = std::vector<std::byte>(64U,
                                                           std::byte{0x5aU}),
                       .revoked = false});
}

TEST(SignalingRouteTest, SelectsLanFirstAndReportsUnavailableModes) {
  auto automatic_lan =
      select_signaling_route(ConnectivityMode::automatic, true, true);
  ASSERT_TRUE(automatic_lan);
  EXPECT_EQ(*automatic_lan.value_if(), SignalingRouteKind::lan);

  auto automatic_relay =
      select_signaling_route(ConnectivityMode::automatic, false, true);
  ASSERT_TRUE(automatic_relay);
  EXPECT_EQ(*automatic_relay.value_if(), SignalingRouteKind::relay);

  auto lan_only =
      select_signaling_route(ConnectivityMode::lan_only, false, true);
  ASSERT_FALSE(lan_only);
  EXPECT_EQ(lan_only.error_if()->code(), ErrorCode::endpoint_offline);

  auto relay_only =
      select_signaling_route(ConnectivityMode::relay_only, true, false);
  ASSERT_FALSE(relay_only);
  EXPECT_EQ(relay_only.error_if()->code(), ErrorCode::relay_unavailable);

  auto no_route =
      select_signaling_route(ConnectivityMode::automatic, false, false);
  ASSERT_FALSE(no_route);
  EXPECT_EQ(no_route.error_if()->code(), ErrorCode::peer_offline);
}

TEST(SignalingRouteTest, OfferOwnerUsesTheCompleteEndpointTuple) {
  DeviceId::Storage device_bytes{};
  device_bytes[0] = std::byte{1U};
  EndpointId::Storage first_endpoint_bytes{};
  first_endpoint_bytes[0] = std::byte{1U};
  EndpointId::Storage second_endpoint_bytes{};
  second_endpoint_bytes[0] = std::byte{2U};
  const DeviceEndpointKey first{DeviceId{device_bytes},
                                EndpointId{first_endpoint_bytes}};
  const DeviceEndpointKey second{DeviceId{device_bytes},
                                 EndpointId{second_endpoint_bytes}};

  EXPECT_TRUE(is_lan_offer_owner(first, second));
  EXPECT_FALSE(is_lan_offer_owner(second, first));
  EXPECT_FALSE(is_lan_offer_owner(first, first));
}

LanPresence signed_presence(const IdentityKeyPair& identity, std::uint8_t endpoint_tag,
                            std::uint8_t boot_tag, std::uint64_t sequence,
                            std::chrono::milliseconds lease = std::chrono::milliseconds{15000}) {
  LanPresence presence;
  EndpointId::Storage endpoint{};
  endpoint[0] = static_cast<std::byte>(endpoint_tag);
  presence.endpoint_id = EndpointId{endpoint};
  presence.boot_nonce[0] = static_cast<std::byte>(boot_tag);
  presence.sequence = sequence;
  presence.tls_signaling_port = 49190U;
  presence.lease = lease;
  EXPECT_TRUE(sign_lan_presence(presence, identity));
  return presence;
}

LanConfiguration constrained_configuration() {
  LanConfiguration configuration;
  configuration.directory_capacity = 3U;
  configuration.trusted_directory_reserve = 1U;
  configuration.per_interface_directory_capacity = 3U;
  configuration.per_source_presence_capacity = 3U;
  configuration.unknown_identity_capacity = 2U;
  configuration.replay_capacity = 8U;
  configuration.diagnostic_capacity = 4U;
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  return configuration;
}

TEST(EndpointDirectoryTest, PreservesTrustedCapacityAndBoundsDiagnostics) {
  auto directory = EndpointDirectory::create(constrained_configuration());
  ASSERT_TRUE(directory) << directory.error_if()->safe_detail();
  auto first = create_identity();
  auto second = create_identity();
  auto third = create_identity();
  ASSERT_TRUE(first && second && third);
  const auto now = std::chrono::steady_clock::now();

  EXPECT_TRUE(directory.value_if()->observe_lan(
      signed_presence(*first.value_if(), 1U, 1U, 1U), "192.0.2.1", "eth0", false, now));
  EXPECT_TRUE(directory.value_if()->observe_lan(
      signed_presence(*second.value_if(), 2U, 2U, 1U), "192.0.2.2", "eth0", false, now));
  auto untrusted_full = directory.value_if()->observe_lan(
      signed_presence(*third.value_if(), 3U, 3U, 1U), "192.0.2.3", "eth0", false, now);
  ASSERT_FALSE(untrusted_full);
  EXPECT_EQ(untrusted_full.error_if()->code(), ErrorCode::resource_exhausted);
  EXPECT_EQ(untrusted_full.error_if()->safe_detail(), "untrusted_directory_capacity_full");

  auto trusted = directory.value_if()->observe_lan(
      signed_presence(*third.value_if(), 3U, 3U, 2U), "192.0.2.3", "eth0", true, now);
  ASSERT_TRUE(trusted) << trusted.error_if()->safe_detail();
  EXPECT_EQ(directory.value_if()->snapshot(now).size(), 3U);
  EXPECT_LE(directory.value_if()->diagnostic_history().size(), 4U);
  const auto diagnostics = directory.value_if()->diagnostics();
  EXPECT_EQ(diagnostics.current_entries, 3U);
  EXPECT_EQ(diagnostics.capacity_rejected, 1U);
}

TEST(EndpointDirectoryTest, RejectsSequenceAndRetiredBootReplay) {
  LanConfiguration configuration;
  configuration.per_source_announcement_rate = 32U;
  auto directory = EndpointDirectory::create(configuration);
  auto identity = create_identity();
  ASSERT_TRUE(directory && identity);
  const auto now = std::chrono::steady_clock::now();

  auto initial = signed_presence(*identity.value_if(), 4U, 1U, 10U);
  ASSERT_TRUE(directory.value_if()->observe_lan(initial, "192.0.2.4", "eth0", false, now));
  auto duplicate = directory.value_if()->observe_lan(
      initial, "192.0.2.4", "eth0", false, now + std::chrono::milliseconds{1});
  ASSERT_TRUE(duplicate);
  EXPECT_EQ(duplicate.value_if()->outcome, DirectoryObservationOutcome::duplicate);

  auto lower = directory.value_if()->observe_lan(
      signed_presence(*identity.value_if(), 4U, 1U, 9U), "192.0.2.4", "eth0", false,
      now + std::chrono::milliseconds{2});
  ASSERT_FALSE(lower);
  EXPECT_EQ(lower.error_if()->safe_detail(), "presence_sequence_replay");

  ASSERT_TRUE(directory.value_if()->observe_lan(
      signed_presence(*identity.value_if(), 4U, 2U, 1U), "192.0.2.4", "eth0", false,
      now + std::chrono::milliseconds{3}));
  auto retired = directory.value_if()->observe_lan(
      signed_presence(*identity.value_if(), 4U, 1U, 11U), "192.0.2.4", "eth0", false,
      now + std::chrono::milliseconds{4});
  ASSERT_FALSE(retired);
  EXPECT_EQ(retired.error_if()->safe_detail(), "presence_boot_replay");
  EXPECT_EQ(directory.value_if()->diagnostics().replay_rejected, 2U);
}

TEST(EndpointDirectoryTest, RejectsSameSequenceWithDifferentSignedFields) {
  LanConfiguration configuration;
  configuration.per_source_announcement_rate = 32U;
  auto directory = EndpointDirectory::create(configuration);
  auto identity = create_identity();
  ASSERT_TRUE(directory && identity);
  const auto now = std::chrono::steady_clock::now();

  auto initial = signed_presence(*identity.value_if(), 8U, 8U, 1U);
  ASSERT_TRUE(directory.value_if()->observe_lan(
      initial, "192.0.2.8", "eth0", false, now));
  auto conflicting = initial;
  conflicting.tls_signaling_port = 49191U;
  ASSERT_TRUE(sign_lan_presence(conflicting, *identity.value_if()));
  auto rejected = directory.value_if()->observe_lan(
      conflicting, "192.0.2.8", "eth0", false,
      now + std::chrono::milliseconds{1});
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "presence_sequence_conflict");
  EXPECT_EQ(directory.value_if()->diagnostics().conflict_rejected, 1U);
}

TEST(EndpointDirectoryTest, DoesNotEvictLiveRetiredBootReplayState) {
  LanConfiguration configuration;
  configuration.per_source_announcement_rate = 32U;
  auto directory = EndpointDirectory::create(configuration);
  auto identity = create_identity();
  ASSERT_TRUE(directory && identity);
  const auto now = std::chrono::steady_clock::now();

  for (std::uint8_t boot = 1U; boot <= 5U; ++boot) {
    ASSERT_TRUE(directory.value_if()->observe_lan(
        signed_presence(*identity.value_if(), 9U, boot, 1U),
        "192.0.2.9", "eth0", false,
        now + std::chrono::milliseconds{boot}));
  }
  auto history_full = directory.value_if()->observe_lan(
      signed_presence(*identity.value_if(), 9U, 6U, 1U),
      "192.0.2.9", "eth0", false,
      now + std::chrono::milliseconds{6});
  ASSERT_FALSE(history_full);
  EXPECT_EQ(history_full.error_if()->safe_detail(),
            "presence_boot_history_full");

  auto retired_replay = directory.value_if()->observe_lan(
      signed_presence(*identity.value_if(), 9U, 1U, 2U),
      "192.0.2.9", "eth0", false,
      now + std::chrono::milliseconds{7});
  ASSERT_FALSE(retired_replay);
  EXPECT_EQ(retired_replay.error_if()->safe_detail(), "presence_boot_replay");
}

TEST(EndpointDirectoryTest, LanExpiryDoesNotDeleteRelayPresence) {
  auto directory = EndpointDirectory::create(LanConfiguration{});
  auto identity = create_identity();
  ASSERT_TRUE(directory && identity);
  const auto now = std::chrono::steady_clock::now();
  auto presence = signed_presence(*identity.value_if(), 5U, 5U, 1U,
                                  std::chrono::milliseconds{1000});
  ASSERT_TRUE(directory.value_if()->observe_lan(
      presence, "192.0.2.5", "eth0", true, now));
  const DeviceEndpointKey key{presence.device_id, presence.endpoint_id};
  ASSERT_TRUE(directory.value_if()->upsert_relay(
      key, "wss://relay.example.invalid", true, std::chrono::seconds{30}, now));

  directory.value_if()->expire(now + std::chrono::seconds{2});
  auto after_lan_expiry = directory.value_if()->snapshot(now + std::chrono::seconds{2});
  ASSERT_EQ(after_lan_expiry.size(), 1U);
  EXPECT_FALSE(after_lan_expiry.front().lan.has_value());
  EXPECT_TRUE(after_lan_expiry.front().relay.has_value());
  EXPECT_TRUE(after_lan_expiry.front().trusted);

  directory.value_if()->expire(now + std::chrono::seconds{31});
  EXPECT_TRUE(directory.value_if()->snapshot(now + std::chrono::seconds{31}).empty());
}

TEST(EndpointDirectoryTest, RateAndPerSourceLimitsAreExplicit) {
  LanConfiguration configuration;
  configuration.per_source_announcement_rate = 1U;
  configuration.announcement_rate_per_second = 2U;
  auto directory = EndpointDirectory::create(configuration);
  auto first = create_identity();
  auto second = create_identity();
  ASSERT_TRUE(directory && first && second);
  const auto now = std::chrono::steady_clock::now();

  ASSERT_TRUE(directory.value_if()->observe_lan(
      signed_presence(*first.value_if(), 6U, 6U, 1U), "192.0.2.6", "eth0", false, now));
  auto limited = directory.value_if()->observe_lan(
      signed_presence(*second.value_if(), 7U, 7U, 1U), "192.0.2.6", "eth0", false, now);
  ASSERT_FALSE(limited);
  EXPECT_EQ(limited.error_if()->safe_detail(), "presence_rate_limited");
  EXPECT_EQ(directory.value_if()->diagnostics().rate_rejected, 1U);
}

TEST(EndpointDirectoryTest, GlobalAnnouncementRateIsExplicit) {
  LanConfiguration configuration;
  configuration.per_source_announcement_rate = 2U;
  configuration.announcement_rate_per_second = 2U;
  auto directory = EndpointDirectory::create(configuration);
  auto first = create_identity();
  auto second = create_identity();
  auto third = create_identity();
  ASSERT_TRUE(directory && first && second && third);
  const auto now = std::chrono::steady_clock::now();

  ASSERT_TRUE(directory.value_if()->observe_lan(
      signed_presence(*first.value_if(), 10U, 10U, 1U),
      "192.0.2.10", "eth0", false, now));
  ASSERT_TRUE(directory.value_if()->observe_lan(
      signed_presence(*second.value_if(), 11U, 11U, 1U),
      "192.0.2.11", "eth0", false, now));
  auto limited = directory.value_if()->observe_lan(
      signed_presence(*third.value_if(), 12U, 12U, 1U),
      "192.0.2.12", "eth0", false, now);
  ASSERT_FALSE(limited);
  EXPECT_EQ(limited.error_if()->safe_detail(), "presence_rate_limited");
  EXPECT_EQ(directory.value_if()->diagnostics().rate_rejected, 1U);
}

TEST_F(M3aNodeTest, NodeRequiresLocalInitializationAndValidControlCapacity) {
  ProfileOpenOptions options;
  options.secret_backend.prefer_os_backend = false;
  auto profile = ProfileStore::create(root_ / "uninitialized" / "profile.sqlite", options);
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  auto uninitialized =
      Node::create(node_config(*profile.value_if(), "com.example.node"));
  ASSERT_FALSE(uninitialized);
  EXPECT_EQ(uninitialized.error_if()->code(), ErrorCode::not_registered);
  EXPECT_EQ(uninitialized.error_if()->safe_detail(), "local_profile_not_initialized");

  LanConfiguration relay_only;
  relay_only.connectivity_mode = ConnectivityMode::relay_only;
  relay_only.enabled = false;
  auto ready_profile = initialized_profile("invalid-capacity", "com.example.node", relay_only);
  ASSERT_TRUE(ready_profile) << ready_profile.error_if()->safe_detail();
  auto invalid = relay_only;
  invalid.pending_signaling_capacity = 0U;
  auto invalid_config = node_config(*ready_profile.value_if(), "com.example.node");
  invalid_config.lan_override = invalid;
  auto invalid_node = Node::create(std::move(invalid_config));
  ASSERT_FALSE(invalid_node);
  EXPECT_EQ(invalid_node.error_if()->code(), ErrorCode::configuration);
}

TEST_F(M3aNodeTest, RelayOnlyNodeIsLocallyReadyWithoutLanOrEnrollment) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::relay_only;
  configuration.enabled = false;
  auto profile = initialized_profile("relay-only", "com.example.node", configuration);
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();

  auto node = Node::create(node_config(*profile.value_if(), "com.example.node"));
  ASSERT_TRUE(node) << node.error_if()->safe_detail();
  const auto snapshot = node.value_if()->snapshot();
  EXPECT_TRUE(snapshot.local_initialized);
  EXPECT_FALSE(snapshot.lan_enabled);
  EXPECT_EQ(snapshot.lan_state, LanReadinessState::disabled);
  EXPECT_FALSE(snapshot.tls.listener_ready);
  const auto shutdown = node.value_if()->shutdown();
  EXPECT_TRUE(shutdown.stopped);
  EXPECT_FALSE(shutdown.timed_out);
}

TEST_F(M3aNodeTest, ProvisionalTlsIsPerSourceRateLimitedAndTimesOut) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.provisional_connection_capacity = 2U;
  configuration.per_source_provisional_capacity = 2U;
  configuration.provisional_accept_rate_per_second = 2U;
  configuration.per_source_provisional_rate = 1U;
  configuration.handshake_timeout = std::chrono::milliseconds{200};
  configuration.hello_timeout = std::chrono::milliseconds{100};
  auto profile = initialized_profile("provisional-pressure", "com.example.node",
                                     configuration);
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();

  auto node = Node::create(node_config(*profile.value_if(), "com.example.node"));
  if (!node && node.error_if()->safe_detail() == "lan_no_ready_interface") {
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  ASSERT_TRUE(node) << node.error_if()->safe_detail();
  const auto port = node.value_if()->snapshot().tls.listen_port;
  ASSERT_NE(port, 0U);

  boost::asio::io_context io;
  boost::asio::ip::tcp::socket first{io};
  boost::asio::ip::tcp::socket second{io};
  const boost::asio::ip::tcp::endpoint listener{
      boost::asio::ip::make_address_v6("::1"), port};
  ASSERT_NO_THROW(first.connect(listener));
  ASSERT_TRUE(wait_until(
      [&] {
        return node.value_if()->snapshot().tls.provisional_connections == 1U;
      },
      std::chrono::seconds{1}));

  ASSERT_NO_THROW(second.connect(listener));
  EXPECT_TRUE(wait_until(
      [&] {
        const auto snapshot = node.value_if()->snapshot();
        return snapshot.tls.rejected >= 1U &&
               snapshot.tls.rate_limited >= 1U && snapshot.last_error &&
               snapshot.last_error->safe_detail() ==
                   "source_provisional_rate_limited";
      },
      std::chrono::seconds{1}));
  EXPECT_TRUE(wait_until(
      [&] {
        const auto tls = node.value_if()->snapshot().tls;
        return tls.timed_out >= 1U && tls.provisional_connections == 0U;
      },
      std::chrono::seconds{1}));

  boost::system::error_code ignored;
  first.close(ignored);
  second.close(ignored);
  const auto shutdown = node.value_if()->shutdown();
  EXPECT_TRUE(shutdown.stopped);
  EXPECT_FALSE(shutdown.timed_out);
}

TEST_F(M3aNodeTest, TwoLanNodesDiscoverEachOtherWithoutRelay) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::automatic;
  configuration.announcement_interval = std::chrono::milliseconds{200};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  auto first_profile = initialized_profile("first", "com.example.first", configuration);
  auto second_profile = initialized_profile("second", "com.example.second", configuration);
  ASSERT_TRUE(first_profile && second_profile);

  auto first = Node::create(
      node_config(*first_profile.value_if(), "com.example.first"));
  auto second = Node::create(
      node_config(*second_profile.value_if(), "com.example.second"));
  ASSERT_TRUE(first) << first.error_if()->safe_detail();
  ASSERT_TRUE(second) << second.error_if()->safe_detail();
  const auto first_snapshot = first.value_if()->snapshot();
  const auto second_snapshot = second.value_if()->snapshot();
  ASSERT_TRUE(first_snapshot.tls.listener_ready);
  ASSERT_TRUE(second_snapshot.tls.listener_ready);
  const auto first_joined = std::count_if(
      first_snapshot.interfaces.begin(), first_snapshot.interfaces.end(),
      [](const LanInterfaceSnapshot& interface) { return interface.joined; });
  const auto second_joined = std::count_if(
      second_snapshot.interfaces.begin(), second_snapshot.interfaces.end(),
      [](const LanInterfaceSnapshot& interface) { return interface.joined; });
  if (first_joined == 0 || second_joined == 0) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  EXPECT_TRUE(wait_until(
      [&] {
        return !first.value_if()->endpoints().empty() &&
               !second.value_if()->endpoints().empty();
      },
      std::chrono::seconds{4}));
  ASSERT_EQ(first.value_if()->endpoints().size(), 1U);
  ASSERT_EQ(second.value_if()->endpoints().size(), 1U);
  EXPECT_EQ(first.value_if()->endpoints().front().key.device_id,
            second_profile.value_if()->device_id());
  EXPECT_EQ(second.value_if()->endpoints().front().key.device_id,
            first_profile.value_if()->device_id());
  EXPECT_FALSE(first.value_if()->endpoints().front().trusted);
  EXPECT_FALSE(second.value_if()->endpoints().front().trusted);

  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
}

TEST_F(M3aNodeTest, AuthenticatesLanTlsAndForwardsBoundedControlMessages) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  auto first_profile = initialized_profile("signal-first", "com.example.first",
                                           configuration);
  auto second_profile = initialized_profile("signal-second", "com.example.second",
                                            configuration);
  ASSERT_TRUE(first_profile && second_profile);

  std::atomic<std::uint64_t> accepted{0U};
  std::atomic<std::uint64_t> requested{0U};
  std::atomic<std::uint64_t> validated{0U};
  std::atomic<std::uint64_t> signed_received{0U};
  std::atomic<Node*> second_node{nullptr};
  auto validator = [&](const LanSignalingMessage& message) {
    validated.fetch_add(1U, std::memory_order_relaxed);
    if (message.payload == std::vector<std::byte>{std::byte{0x42U}}) {
      return Result<void>::success();
    }
    return Result<void>::failure(
        Error{ErrorCode::authentication, "test", "signed_signal_invalid"});
  };
  auto first_handler = [&](const LanSignalingMessage& message) {
    if (message.kind == LanSignalingMessageKind::connect_accept) {
      accepted.fetch_add(1U, std::memory_order_relaxed);
    }
    return Result<void>::success();
  };
  auto second_handler = [&](const LanSignalingMessage& message) {
    if (message.kind == LanSignalingMessageKind::signed_offer) {
      signed_received.fetch_add(1U, std::memory_order_relaxed);
      return Result<void>::success();
    }
    if (message.kind != LanSignalingMessageKind::connect_request) {
      return Result<void>::success();
    }
    requested.fetch_add(1U, std::memory_order_relaxed);
    auto* node = second_node.load(std::memory_order_acquire);
    if (node == nullptr) {
      return Result<void>::failure(
          Error{ErrorCode::internal, "test", "second_node_unavailable"});
    }
    return node->send_lan_signaling(
        LanSignalingMessage{.peer = message.peer,
                            .kind = LanSignalingMessageKind::connect_accept,
                            .request_id = message.request_id,
                            .payload = {}});
  };

  auto first = Node::create(node_config(*first_profile.value_if(),
                                        "com.example.first", validator,
                                        first_handler));
  auto second = Node::create(node_config(*second_profile.value_if(),
                                         "com.example.second", validator,
                                         second_handler));
  ASSERT_TRUE(first && second);
  second_node.store(second.value_if(), std::memory_order_release);
  if (first.value_if()->snapshot().interfaces.empty() ||
      second.value_if()->snapshot().interfaces.empty()) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  ASSERT_TRUE(wait_until(
      [&] {
        return first.value_if()->endpoints().size() == 1U &&
               second.value_if()->endpoints().size() == 1U;
      },
      std::chrono::seconds{4}));
  const auto peer = first.value_if()->endpoints().front().key;
  auto unauthenticated = first.value_if()->send_lan_signaling(
      LanSignalingMessage{.peer = peer,
                          .kind = LanSignalingMessageKind::signed_offer,
                          .request_id = request_id(2U),
                          .payload = {std::byte{0x42U}}});
  ASSERT_FALSE(unauthenticated);
  EXPECT_EQ(unauthenticated.error_if()->code(), ErrorCode::would_block);
  ASSERT_TRUE(first.value_if()->connect_lan(peer));
  ASSERT_TRUE(wait_until(
      [&] {
        const auto first_connections = first.value_if()->signaling_connections();
        const auto second_connections = second.value_if()->signaling_connections();
        const auto authenticated = [](const auto& connection) {
          return connection.state == LanSignalingConnectionState::authenticated;
        };
        return std::count_if(first_connections.begin(), first_connections.end(),
                             authenticated) == 1 &&
               std::count_if(second_connections.begin(), second_connections.end(),
                             authenticated) == 1;
      },
      std::chrono::seconds{4}));

  ASSERT_TRUE(first.value_if()->send_lan_signaling(
      LanSignalingMessage{.peer = peer,
                          .kind = LanSignalingMessageKind::connect_request,
                          .request_id = request_id(1U),
                          .payload = {}}));
  const bool forwarded = wait_until(
      [&] {
        return requested.load(std::memory_order_relaxed) == 1U &&
               accepted.load(std::memory_order_relaxed) == 1U;
      },
      std::chrono::seconds{2});
  const auto first_after = first.value_if()->snapshot();
  const auto second_after = second.value_if()->snapshot();
  const auto first_signal_after = first.value_if()->signaling_connections();
  const auto second_signal_after = second.value_if()->signaling_connections();
  EXPECT_TRUE(forwarded)
      << "requested=" << requested.load(std::memory_order_relaxed)
      << " accepted=" << accepted.load(std::memory_order_relaxed)
      << " first_error="
      << (first_after.last_error ? first_after.last_error->safe_detail() : "none")
      << " second_error="
      << (second_after.last_error ? second_after.last_error->safe_detail() : "none")
      << " first_connections=" << first_signal_after.size()
      << " first_state="
      << (first_signal_after.empty()
              ? -1
              : static_cast<int>(first_signal_after.front().state))
      << " first_signal_error="
      << (first_signal_after.empty() || !first_signal_after.front().error
              ? "none"
              : first_signal_after.front().error->safe_detail())
      << " second_connections=" << second_signal_after.size()
      << " second_state="
      << (second_signal_after.empty()
              ? -1
              : static_cast<int>(second_signal_after.front().state))
      << " second_signal_error="
      << (second_signal_after.empty() || !second_signal_after.front().error
              ? "none"
              : second_signal_after.front().error->safe_detail());

  ASSERT_TRUE(first.value_if()->send_lan_signaling(
      LanSignalingMessage{.peer = peer,
                          .kind = LanSignalingMessageKind::signed_offer,
                          .request_id = request_id(3U),
                          .payload = {std::byte{0x42U}}}));
  EXPECT_TRUE(wait_until(
      [&] {
        return validated.load(std::memory_order_relaxed) == 2U &&
               signed_received.load(std::memory_order_relaxed) == 1U;
      },
      std::chrono::seconds{2}));

  ASSERT_TRUE(first.value_if()->send_lan_signaling(
      LanSignalingMessage{.peer = peer,
                          .kind = LanSignalingMessageKind::signed_candidate,
                          .request_id = request_id(4U),
                          .payload = {std::byte{0x41U}}}));
  EXPECT_TRUE(wait_until(
      [&] {
        const auto connections = first.value_if()->signaling_connections();
        return std::any_of(connections.begin(), connections.end(),
                           [](const auto& connection) {
                             return connection.state ==
                                        LanSignalingConnectionState::failed &&
                                    connection.error &&
                                    connection.error->safe_detail() ==
                                        "signed_signal_invalid";
                           });
      },
      std::chrono::seconds{2}));

  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
}

TEST_F(M3aNodeTest, TrustedAutoConnectUsesOnlyTheTupleOfferOwner) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.auto_connect_trusted = true;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  auto first_profile = initialized_profile("auto-first", "com.example.first",
                                           configuration);
  auto second_profile = initialized_profile("auto-second", "com.example.second",
                                            configuration);
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(trust_peer(*first_profile.value_if(),
                         second_profile.value_if()->device_id(), 1U));
  ASSERT_TRUE(trust_peer(*second_profile.value_if(),
                         first_profile.value_if()->device_id(), 2U));

  auto first = Node::create(
      node_config(*first_profile.value_if(), "com.example.first"));
  auto second = Node::create(
      node_config(*second_profile.value_if(), "com.example.second"));
  ASSERT_TRUE(first && second);
  const auto first_snapshot = first.value_if()->snapshot();
  const auto second_snapshot = second.value_if()->snapshot();
  if (std::none_of(first_snapshot.interfaces.begin(), first_snapshot.interfaces.end(),
                   [](const auto& interface) { return interface.joined; }) ||
      std::none_of(second_snapshot.interfaces.begin(), second_snapshot.interfaces.end(),
                   [](const auto& interface) { return interface.joined; })) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  ASSERT_TRUE(wait_until(
      [&] {
        const auto first_connections = first.value_if()->signaling_connections();
        const auto second_connections = second.value_if()->signaling_connections();
        const auto authenticated = [](const auto& connection) {
          return connection.state == LanSignalingConnectionState::authenticated;
        };
        return std::count_if(first_connections.begin(), first_connections.end(),
                             authenticated) == 1 &&
               std::count_if(second_connections.begin(), second_connections.end(),
                             authenticated) == 1;
      },
      std::chrono::seconds{4}));

  const auto first_key = DeviceEndpointKey{first_snapshot.device_id,
                                           first_snapshot.endpoint_id};
  const auto second_key = DeviceEndpointKey{second_snapshot.device_id,
                                            second_snapshot.endpoint_id};
  const bool first_owner = is_lan_offer_owner(first_key, second_key);
  const auto first_connections = first.value_if()->signaling_connections();
  const auto second_connections = second.value_if()->signaling_connections();
  const auto first_active = std::find_if(
      first_connections.begin(), first_connections.end(), [](const auto& connection) {
        return connection.state == LanSignalingConnectionState::authenticated;
      });
  const auto second_active = std::find_if(
      second_connections.begin(), second_connections.end(), [](const auto& connection) {
        return connection.state == LanSignalingConnectionState::authenticated;
      });
  ASSERT_NE(first_active, first_connections.end());
  ASSERT_NE(second_active, second_connections.end());
  EXPECT_EQ(first_active->inbound, !first_owner);
  EXPECT_EQ(second_active->inbound, first_owner);
  EXPECT_EQ(first_active->local_offer_owner, first_owner);
  EXPECT_EQ(second_active->local_offer_owner, !first_owner);

  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
}

TEST_F(M3aNodeTest, ShutdownDrainsPendingSignalingHandlerWithinBudget) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  auto first_profile = initialized_profile("shutdown-first", "com.example.first",
                                           configuration);
  auto second_profile = initialized_profile("shutdown-second", "com.example.second",
                                            configuration);
  ASSERT_TRUE(first_profile && second_profile);

  executor::comm::PhaseGate handler_entered{"m3a-handler-entered"};
  executor::comm::PhaseGate handler_release{"m3a-handler-release"};
  auto blocking_handler = [&](const LanSignalingMessage&) {
    (void)handler_entered.advance_to(1U);
    (void)handler_release.wait_for(1U, std::chrono::milliseconds{200});
    return Result<void>::success();
  };
  auto first = Node::create(
      node_config(*first_profile.value_if(), "com.example.first"));
  auto second = Node::create(node_config(*second_profile.value_if(),
                                         "com.example.second", {},
                                         blocking_handler));
  ASSERT_TRUE(first && second);
  const auto first_snapshot = first.value_if()->snapshot();
  const auto second_snapshot = second.value_if()->snapshot();
  if (std::none_of(first_snapshot.interfaces.begin(), first_snapshot.interfaces.end(),
                   [](const auto& interface) { return interface.joined; }) ||
      std::none_of(second_snapshot.interfaces.begin(), second_snapshot.interfaces.end(),
                   [](const auto& interface) { return interface.joined; })) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  ASSERT_TRUE(wait_until(
      [&] {
        return first.value_if()->endpoints().size() == 1U &&
               second.value_if()->endpoints().size() == 1U;
      },
      std::chrono::seconds{4}));
  const auto peer = first.value_if()->endpoints().front().key;
  ASSERT_TRUE(first.value_if()->connect_lan(peer));
  ASSERT_TRUE(wait_until(
      [&] { return has_authenticated_connection(*first.value_if(), peer); },
      std::chrono::seconds{4}));
  ASSERT_TRUE(first.value_if()->send_lan_signaling(
      LanSignalingMessage{.peer = peer,
                          .kind = LanSignalingMessageKind::connect_request,
                          .request_id = request_id(5U),
                          .payload = {}}));
  ASSERT_TRUE(handler_entered.wait_for(1U, std::chrono::seconds{2}));

  const auto started = std::chrono::steady_clock::now();
  const auto shutdown = second.value_if()->shutdown();
  const auto elapsed = std::chrono::steady_clock::now() - started;
  EXPECT_TRUE(shutdown.stopped);
  EXPECT_FALSE(shutdown.timed_out);
  EXPECT_LT(elapsed, std::chrono::seconds{2});
  EXPECT_TRUE(first.value_if()->shutdown().stopped);
}

}  // namespace
}  // namespace heyaki
