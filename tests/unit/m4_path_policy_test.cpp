#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <executor/comm.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {
namespace {

NodeIceServer turn_udp_server(std::string hostname = "127.0.0.1",
                              std::uint16_t port = 3478U) {
  return NodeIceServer{.kind = NodeIceServerKind::turn_udp,
                       .hostname = std::move(hostname),
                       .port = port,
                       .username = "user",
                       .credential = "credential"};
}

NodeIceServer stun_server(std::string hostname = "stun.example",
                          std::uint16_t port = 3478U) {
  return NodeIceServer{.kind = NodeIceServerKind::stun,
                       .hostname = std::move(hostname),
                       .port = port,
                       .username = {},
                       .credential = {}};
}

bool environment_requires_lan_interfaces() {
  const char* value = std::getenv("HEYAKI_REQUIRE_LAN_INTERFACES");
  return value != nullptr && std::string_view{value} == "1";
}

// Waiting for a specific peer endpoint keeps the e2e cases robust when other
// concurrently running LAN tests announce presence on the same multicast group.
bool discovered(const Node& node, const DeviceEndpointKey& peer) {
  const auto entries = node.endpoints();
  return std::any_of(entries.begin(), entries.end(),
                     [&](const auto& entry) { return entry.key == peer; });
}

TEST(M4PathPolicy, DefaultsFollowConnectivityMode) {
  const auto automatic = default_peer_path_policy(ConnectivityMode::automatic);
  ASSERT_TRUE(automatic);
  EXPECT_TRUE(automatic.value_if()->allow_ipv6_host);
  EXPECT_TRUE(automatic.value_if()->allow_ipv4_host);
  EXPECT_TRUE(automatic.value_if()->allow_server_reflexive);
  EXPECT_TRUE(automatic.value_if()->allow_turn_udp);
  EXPECT_FALSE(automatic.value_if()->allow_turn_tcp);
  EXPECT_FALSE(automatic.value_if()->allow_turn_tls);
  EXPECT_FALSE(automatic.value_if()->force_turn_data_path);
  EXPECT_TRUE(automatic.value_if()->ice_servers.empty());
  EXPECT_TRUE(
      validate_peer_path_policy(*automatic.value_if(), ConnectivityMode::automatic));

  const auto lan_only = default_peer_path_policy(ConnectivityMode::lan_only);
  ASSERT_TRUE(lan_only);
  EXPECT_TRUE(lan_only.value_if()->allow_ipv6_host);
  EXPECT_TRUE(lan_only.value_if()->allow_ipv4_host);
  EXPECT_FALSE(lan_only.value_if()->allow_server_reflexive);
  EXPECT_FALSE(lan_only.value_if()->allow_turn_udp);
  EXPECT_FALSE(lan_only.value_if()->force_turn_data_path);
  EXPECT_TRUE(lan_only.value_if()->ice_servers.empty());
  EXPECT_TRUE(
      validate_peer_path_policy(*lan_only.value_if(), ConnectivityMode::lan_only));

  const auto relay_only = default_peer_path_policy(ConnectivityMode::relay_only);
  ASSERT_TRUE(relay_only);
  EXPECT_TRUE(
      validate_peer_path_policy(*relay_only.value_if(), ConnectivityMode::relay_only));

  const auto invalid = default_peer_path_policy(static_cast<ConnectivityMode>(0U));
  ASSERT_FALSE(invalid);
  EXPECT_EQ(invalid.error_if()->code(), ErrorCode::configuration);
}

TEST(M4PathPolicy, RejectsEmptyAndLanOnlyConflicts) {
  PeerPathPolicy no_candidates;
  no_candidates.allow_ipv6_host = false;
  no_candidates.allow_ipv4_host = false;
  no_candidates.allow_server_reflexive = false;
  no_candidates.allow_turn_udp = false;
  auto rejected =
      validate_peer_path_policy(no_candidates, ConnectivityMode::automatic);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "no_candidate_class_allowed");

  PeerPathPolicy lan_ice =
      *default_peer_path_policy(ConnectivityMode::lan_only).value_if();
  lan_ice.ice_servers.push_back(turn_udp_server());
  rejected = validate_peer_path_policy(lan_ice, ConnectivityMode::lan_only);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "lan_only_disallows_ice_servers");

  PeerPathPolicy lan_srflx =
      *default_peer_path_policy(ConnectivityMode::lan_only).value_if();
  lan_srflx.allow_server_reflexive = true;
  rejected = validate_peer_path_policy(lan_srflx, ConnectivityMode::lan_only);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(),
            "lan_only_disallows_reflexive_candidates");

  PeerPathPolicy lan_turn =
      *default_peer_path_policy(ConnectivityMode::lan_only).value_if();
  lan_turn.allow_turn_udp = true;
  rejected = validate_peer_path_policy(lan_turn, ConnectivityMode::lan_only);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "lan_only_disallows_turn");

  PeerPathPolicy lan_forced =
      *default_peer_path_policy(ConnectivityMode::lan_only).value_if();
  lan_forced.force_turn_data_path = true;
  rejected = validate_peer_path_policy(lan_forced, ConnectivityMode::lan_only);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "lan_only_disallows_turn");
}

TEST(M4PathPolicy, RejectsUnverifiedTcpTurnUntilBackendIsVerified) {
  PeerPathPolicy tcp = PeerPathPolicy{};
  tcp.allow_turn_tcp = true;
  tcp.ice_servers.push_back(NodeIceServer{
      .kind = NodeIceServerKind::turn_tcp,
      .hostname = "turn.example",
      .port = 3478U,
      .username = "user",
      .credential = "credential"});
  auto rejected = validate_peer_path_policy(tcp, ConnectivityMode::automatic);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "tcp_turn_backend_not_verified");

  PeerPathPolicy tls = PeerPathPolicy{};
  tls.allow_turn_tls = true;
  rejected = validate_peer_path_policy(tls, ConnectivityMode::automatic);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "tcp_turn_backend_not_verified");
}

TEST(M4PathPolicy, ForcedTurnRequiresTurnClassAndServer) {
  PeerPathPolicy forced = PeerPathPolicy{};
  forced.force_turn_data_path = true;
  auto rejected = validate_peer_path_policy(forced, ConnectivityMode::automatic);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(),
            "forced_turn_requires_turn_class_and_server");

  PeerPathPolicy with_stun_only = PeerPathPolicy{};
  with_stun_only.force_turn_data_path = true;
  with_stun_only.ice_servers.push_back(stun_server());
  rejected = validate_peer_path_policy(with_stun_only, ConnectivityMode::automatic);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(),
            "forced_turn_requires_turn_class_and_server");

  PeerPathPolicy valid = PeerPathPolicy{};
  valid.force_turn_data_path = true;
  valid.ice_servers.push_back(turn_udp_server());
  EXPECT_TRUE(
      static_cast<bool>(validate_peer_path_policy(valid, ConnectivityMode::relay_only)));
}

TEST(M4PathPolicy, ValidatesIceServerFieldsAndCapacity) {
  PeerPathPolicy policy = PeerPathPolicy{};

  PeerPathPolicy empty_host = policy;
  empty_host.ice_servers.push_back(turn_udp_server(""));
  auto rejected = validate_peer_path_policy(empty_host, ConnectivityMode::automatic);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "ice_server_fields_invalid");

  PeerPathPolicy zero_port = policy;
  zero_port.ice_servers.push_back(turn_udp_server("127.0.0.1", 0U));
  rejected = validate_peer_path_policy(zero_port, ConnectivityMode::automatic);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "ice_server_fields_invalid");

  PeerPathPolicy no_credentials = policy;
  no_credentials.ice_servers.push_back(NodeIceServer{
      .kind = NodeIceServerKind::turn_udp,
      .hostname = "127.0.0.1",
      .port = 3478U,
      .username = {},
      .credential = {}});
  rejected = validate_peer_path_policy(no_credentials, ConnectivityMode::automatic);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "turn_server_requires_credentials");

  PeerPathPolicy stun_with_credentials = policy;
  stun_with_credentials.ice_servers.push_back(NodeIceServer{
      .kind = NodeIceServerKind::stun,
      .hostname = "stun.example",
      .port = 3478U,
      .username = "user",
      .credential = {}});
  rejected =
      validate_peer_path_policy(stun_with_credentials, ConnectivityMode::automatic);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "stun_server_disallows_credentials");

  PeerPathPolicy over_capacity = policy;
  for (std::size_t index = 0U; index < 9U; ++index) {
    over_capacity.ice_servers.push_back(stun_server());
  }
  rejected = validate_peer_path_policy(over_capacity, ConnectivityMode::automatic);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "ice_server_capacity_exceeded");

  PeerPathPolicy valid_stun = policy;
  valid_stun.ice_servers.push_back(stun_server());
  EXPECT_TRUE(
      static_cast<bool>(validate_peer_path_policy(valid_stun, ConnectivityMode::automatic)));
}

class M4PathPolicyNodeTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M4_PATH_TEST_STATE_DIR} / "node";
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
    auto profile =
        ProfileStore::create(root_ / std::string{name} / "profile.sqlite", options);
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
    executor::comm::PhaseGate poll{"m4-path-policy-poll"};
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
        return true;
      }
      (void)poll.wait_for(1U, std::chrono::milliseconds{1});
    }
    return predicate();
  }

  // Both e2e cases skip when the host has no multicast-capable non-loopback
  // interface, mirroring the M3A node suite.
  bool lan_interfaces_unavailable(const Node& first, const Node& second) {
    return first.snapshot().interfaces.empty() || second.snapshot().interfaces.empty();
  }

  std::filesystem::path root_;
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

LanConfiguration fast_automatic() {
  LanConfiguration configuration = fast_lan_only();
  configuration.connectivity_mode = ConnectivityMode::automatic;
  return configuration;
}

NodeConfig policy_node_config(ProfileStore& profile, std::string application_id,
                              std::optional<LanConfiguration> lan_override = {}) {
  return NodeConfig{.profile = &profile,
                    .runtime = nullptr,
                    .application_id = std::move(application_id),
                    .lan_override = std::move(lan_override),
                    .runtime_config = RuntimeConfig{},
                    .signaling_validator = {},
                    .signaling_handler = {},
                    .relay_override = std::nullopt,
                    .path_policy_override = std::nullopt};
}

TEST_F(M4PathPolicyNodeTest, NodeCreateFailsFastOnInvalidPolicyOverride) {
  auto profile =
      initialized_profile("invalid-policy", "com.example.policy", fast_lan_only());
  ASSERT_TRUE(profile);

  auto lan_with_server =
      policy_node_config(*profile.value_if(), "com.example.policy");
  PeerPathPolicy lan_ice =
      *default_peer_path_policy(ConnectivityMode::lan_only).value_if();
  lan_ice.ice_servers.push_back(turn_udp_server());
  lan_with_server.path_policy_override = lan_ice;
  auto rejected = Node::create(std::move(lan_with_server));
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->code(), ErrorCode::configuration);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "lan_only_disallows_ice_servers");

  auto forced_without_server = policy_node_config(*profile.value_if(),
                                                  "com.example.policy",
                                                  fast_automatic());
  PeerPathPolicy forced = PeerPathPolicy{};
  forced.force_turn_data_path = true;
  forced_without_server.path_policy_override = forced;
  rejected = Node::create(std::move(forced_without_server));
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(),
            "forced_turn_requires_turn_class_and_server");

  auto unverified_tcp = policy_node_config(*profile.value_if(), "com.example.policy",
                                           fast_automatic());
  PeerPathPolicy tcp = PeerPathPolicy{};
  tcp.allow_turn_tcp = true;
  unverified_tcp.path_policy_override = tcp;
  rejected = Node::create(std::move(unverified_tcp));
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "tcp_turn_backend_not_verified");
}

TEST_F(M4PathPolicyNodeTest, HostOnlyOverrideStillAssemblesAuthenticatedSession) {
  auto first_profile =
      initialized_profile("host-first", "com.example.host.first", fast_lan_only());
  auto second_profile =
      initialized_profile("host-second", "com.example.host.second", fast_lan_only());
  ASSERT_TRUE(first_profile && second_profile);

  PeerPathPolicy host_only =
      *default_peer_path_policy(ConnectivityMode::lan_only).value_if();
  host_only.allow_server_reflexive = false;
  host_only.allow_turn_udp = false;

  auto first_config =
      policy_node_config(*first_profile.value_if(), "com.example.host.first");
  first_config.path_policy_override = host_only;
  auto second_config =
      policy_node_config(*second_profile.value_if(), "com.example.host.second");
  second_config.path_policy_override = host_only;

  auto first = Node::create(std::move(first_config));
  auto second = Node::create(std::move(second_config));
  ASSERT_TRUE(first && second)
      << (first ? std::string{} : first.error_if()->safe_detail())
      << (second ? std::string{} : second.error_if()->safe_detail());
  if (lan_interfaces_unavailable(*first.value_if(), *second.value_if())) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    if (environment_requires_lan_interfaces()) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  const auto second_key = DeviceEndpointKey{second.value_if()->snapshot().device_id,
                                            second.value_if()->snapshot().endpoint_id};
  const auto first_key = DeviceEndpointKey{first.value_if()->snapshot().device_id,
                                           first.value_if()->snapshot().endpoint_id};
  ASSERT_TRUE(wait_until(
      [&] {
        return discovered(*first.value_if(), second_key) &&
               discovered(*second.value_if(), first_key);
      },
      std::chrono::seconds{10}));
  const auto peer = second_key;
  ASSERT_TRUE(first.value_if()->connect_lan(peer));
  const bool authenticated = wait_until(
      [&] {
        const auto first_sessions = first.value_if()->peer_sessions();
        const auto second_sessions = second.value_if()->peer_sessions();
        return first_sessions.size() == 1U && second_sessions.size() == 1U &&
               first_sessions.front().state == NodePeerSessionState::authenticated &&
               second_sessions.front().state == NodePeerSessionState::authenticated;
      },
      std::chrono::seconds{10});
  ASSERT_TRUE(authenticated);
  const auto first_sessions = first.value_if()->peer_sessions();
  ASSERT_EQ(first_sessions.size(), 1U);
  EXPECT_EQ(first_sessions.front().data_path, NodeDataPathKind::direct_host);
  EXPECT_FALSE(first_sessions.front().selected_candidate.empty());

  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
}

TEST_F(M4PathPolicyNodeTest, ForcedTurnWithoutReachableServerTerminatesExplicitly) {
  auto first_profile =
      initialized_profile("turn-first", "com.example.turn.first", fast_automatic());
  auto second_profile =
      initialized_profile("turn-second", "com.example.turn.second", fast_automatic());
  ASSERT_TRUE(first_profile && second_profile);

  PeerPathPolicy forced_turn = PeerPathPolicy{};
  forced_turn.force_turn_data_path = true;
  // Port 1 on loopback has no TURN listener, so allocation must fail instead
  // of pretending a relayed path exists.
  forced_turn.ice_servers.push_back(turn_udp_server("127.0.0.1", 1U));

  auto first_config =
      policy_node_config(*first_profile.value_if(), "com.example.turn.first");
  first_config.path_policy_override = forced_turn;
  auto second_config =
      policy_node_config(*second_profile.value_if(), "com.example.turn.second");
  second_config.path_policy_override = forced_turn;

  auto first = Node::create(std::move(first_config));
  auto second = Node::create(std::move(second_config));
  ASSERT_TRUE(first && second)
      << (first ? std::string{} : first.error_if()->safe_detail())
      << (second ? std::string{} : second.error_if()->safe_detail());
  if (lan_interfaces_unavailable(*first.value_if(), *second.value_if())) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    if (environment_requires_lan_interfaces()) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  const auto second_key = DeviceEndpointKey{second.value_if()->snapshot().device_id,
                                            second.value_if()->snapshot().endpoint_id};
  const auto first_key = DeviceEndpointKey{first.value_if()->snapshot().device_id,
                                           first.value_if()->snapshot().endpoint_id};
  ASSERT_TRUE(wait_until(
      [&] {
        return discovered(*first.value_if(), second_key) &&
               discovered(*second.value_if(), first_key);
      },
      std::chrono::seconds{10}));
  const auto peer = second_key;
  ASSERT_TRUE(first.value_if()->connect_lan(peer));
  const bool terminated = wait_until(
      [&] {
        const auto sessions = first.value_if()->peer_sessions();
        return std::any_of(sessions.begin(), sessions.end(),
                           [](const NodePeerSessionSnapshot& session) {
                             return session.state == NodePeerSessionState::closed &&
                                    session.error.has_value();
                           });
      },
      std::chrono::seconds{20});
  ASSERT_TRUE(terminated)
      << "forced TURN attempt did not reach an explicit terminal state";
  const auto sessions = first.value_if()->peer_sessions();
  const auto failed = std::find_if(
      sessions.begin(), sessions.end(),
      [](const NodePeerSessionSnapshot& session) {
        return session.state == NodePeerSessionState::closed && session.error;
      });
  ASSERT_NE(failed, sessions.end());
  EXPECT_TRUE(failed->error->code() == ErrorCode::nat_traversal ||
              failed->error->code() == ErrorCode::transport ||
              failed->error->code() == ErrorCode::timeout)
      << "actual error: " << failed->error->safe_detail();
  for (const auto& session : sessions) {
    EXPECT_NE(session.state, NodePeerSessionState::authenticated);
  }

  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
}

}  // namespace
}  // namespace heyaki
