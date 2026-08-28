// M4 network-matrix rows that need no privileged topology: one DeviceId
// exposing multiple endpoints, and both peers connecting to each other at the
// same time (cross connection with a single transport winner).
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <executor/comm.hpp>

#include <gtest/gtest.h>

#include "m5_support.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

bool discovered(const Node& node, const DeviceEndpointKey& peer) {
  const auto entries = node.endpoints();
  return std::any_of(entries.begin(), entries.end(),
                     [&](const auto& entry) { return entry.key == peer; });
}

LanConfiguration fast_lan() {
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

class M4TopologyMatrixTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M4_TOPOLOGY_TEST_STATE_DIR} / "node";
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
    std::filesystem::create_directories(root_);
  }

  void TearDown() override {
    nodes_.clear();
    profiles_.clear();
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
  }

  Result<Node*> make_node(const std::filesystem::path& database,
                          std::string_view application_id) {
    ProfileOpenOptions options;
    options.secret_backend.prefer_os_backend = false;
    std::optional<ProfileStore> opened_store;
    auto opened = ProfileStore::open(database);
    if (opened) {
      opened_store = std::move(*opened.value_if());
    } else {
      auto created = ProfileStore::create(database, options);
      if (!created) {
        return Result<Node*>::failure(*created.error_if());
      }
      PasswordVerifier verifier{.format_version = 1U,
                                .parameters = PasswordHashParameters{},
                                .encoded = "$argon2id$v=19$m=65536,t=2,p=1$test$test"};
      LocalProfileInitialization initialization{
          .application_id = std::string{application_id},
          .password_verifier = std::move(verifier),
          .password_generation = 1U,
          .pairing_policy = PairingPolicy{},
          .lan = fast_lan()};
      auto initialized = created.value_if()->initialize_local(initialization);
      if (!initialized) {
        return Result<Node*>::failure(*initialized.error_if());
      }
      opened_store = std::move(*created.value_if());
    }
    // Registering a further application on an existing profile allocates its
    // persistent EndpointId; local_readiness then reports ready for it.
    auto endpoint = opened_store->endpoint_for(application_id);
    if (!endpoint) {
      return Result<Node*>::failure(*endpoint.error_if());
    }
    auto inserted = profiles_.emplace(database.string(), std::move(*opened_store));
    NodeConfig config{.profile = &inserted.first->second,
                      .runtime = nullptr,
                      .application_id = std::string{application_id},
                      .lan_override = fast_lan(),
                      .runtime_config = RuntimeConfig{},
                      .signaling_validator = {},
                      .signaling_handler = {},
                      .relay_override = std::nullopt,
                      .path_policy_override = std::nullopt};
    auto node = Node::create(std::move(config));
    if (!node) {
      return Result<Node*>::failure(*node.error_if());
    }
    nodes_.push_back(std::move(*node.value_if()));
    return Result<Node*>::success(&nodes_.back());
  }

  template <typename Predicate>
  bool wait_until(Predicate&& predicate, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    executor::comm::PhaseGate poll{"m4-topology-poll"};
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
        return true;
      }
      (void)poll.wait_for(1U, std::chrono::milliseconds{1});
    }
    return predicate();
  }

  bool wait_stable_mutual_discovery(Node& first, Node& second) {
    const auto second_key =
        DeviceEndpointKey{second.snapshot().device_id, second.snapshot().endpoint_id};
    const auto first_key =
        DeviceEndpointKey{first.snapshot().device_id, first.snapshot().endpoint_id};
    int stable_polls = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
    executor::comm::PhaseGate poll{"m4-topology-stable"};
    while (std::chrono::steady_clock::now() < deadline) {
      const bool mutual =
          discovered(first, second_key) && discovered(second, first_key);
      stable_polls = mutual ? stable_polls + 1 : 0;
      if (stable_polls >= 5) {
        return true;
      }
      (void)poll.wait_for(1U, std::chrono::milliseconds{150});
    }
    return false;
  }

  bool lan_interfaces_unavailable() {
    if (nodes_.empty()) return true;
    return nodes_.front().snapshot().interfaces.empty();
  }

  std::filesystem::path root_;
  std::map<std::string, ProfileStore> profiles_;
  std::deque<Node> nodes_;
};

TEST_F(M4TopologyMatrixTest, SameDeviceIdServesTwoEndpointsIndependently) {
  // One profile (one DeviceId) hosts two Nodes with different application
  // ids, hence two EndpointIds; a third device discovers both endpoints and
  // establishes one authenticated session to each.
  const auto shared_db = root_ / "shared" / "profile.sqlite";
  auto app_a = make_node(shared_db, "org.example.device.appa");
  auto app_b = make_node(shared_db, "org.example.device.appb");
  auto observer = make_node(root_ / "observer" / "profile.sqlite",
                            "org.example.observer");
  ASSERT_TRUE(app_a && app_b && observer)
      << (app_a ? std::string{} : std::string{app_a.error_if()->safe_detail()})
      << (app_b ? std::string{} : std::string{app_b.error_if()->safe_detail()})
      << (observer ? std::string{} : std::string{observer.error_if()->safe_detail()});
  {
    // Device-level trust covers both endpoints of the shared DeviceId.
    auto shared = profiles_.find(shared_db.string());
    auto observer_profile = profiles_.find((root_ / "observer" / "profile.sqlite").string());
    ASSERT_NE(shared, profiles_.end());
    ASSERT_NE(observer_profile, profiles_.end());
    ASSERT_TRUE(heyaki::test::seed_mutual_trust(shared->second,
                                                observer_profile->second, {"m4.test"}));
  }
  if (lan_interfaces_unavailable()) {
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  const auto device = (*app_a.value_if())->snapshot().device_id;
  EXPECT_EQ((*app_b.value_if())->snapshot().device_id, device);
  EXPECT_NE((*app_a.value_if())->snapshot().endpoint_id,
            (*app_b.value_if())->snapshot().endpoint_id);
  const DeviceEndpointKey endpoint_a{
      device, (*app_a.value_if())->snapshot().endpoint_id};
  const DeviceEndpointKey endpoint_b{
      device, (*app_b.value_if())->snapshot().endpoint_id};
  ASSERT_NE(endpoint_a, endpoint_b);

  ASSERT_TRUE(wait_stable_mutual_discovery(**observer.value_if(),
                                           **app_a.value_if()));
  ASSERT_TRUE(wait_until(
      [&] {
        return discovered(**observer.value_if(), endpoint_a) &&
               discovered(**observer.value_if(), endpoint_b);
      },
      std::chrono::seconds{10}))
      << "observer did not discover both endpoints of the shared DeviceId";

  ASSERT_TRUE((*observer.value_if())->connect_lan(endpoint_a));
  ASSERT_TRUE((*observer.value_if())->connect_lan(endpoint_b));
  const bool both = wait_until(
      [&] {
        std::size_t authenticated = 0U;
        for (const auto& session : (*observer.value_if())->peer_sessions()) {
          if (session.state == NodePeerSessionState::authenticated) {
            ++authenticated;
          }
        }
        return authenticated == 2U;
      },
      std::chrono::seconds{15});
  ASSERT_TRUE(both) << "sessions to the two endpoints did not authenticate";
  std::size_t sessions_on_device = 0U;
  for (const auto& session : (*observer.value_if())->peer_sessions()) {
    if (session.peer.device_id == device &&
        session.state == NodePeerSessionState::authenticated) {
      ++sessions_on_device;
      EXPECT_FALSE(session.request_id.is_zero());
    }
  }
  EXPECT_EQ(sessions_on_device, 2U);

  for (auto& node : nodes_) {
    EXPECT_TRUE(node.shutdown().stopped);
  }
}

TEST_F(M4TopologyMatrixTest, SimultaneousCrossConnectionsYieldSingleWinner) {
  auto first = make_node(root_ / "cross-first" / "profile.sqlite",
                         "org.example.cross.first");
  auto second = make_node(root_ / "cross-second" / "profile.sqlite",
                          "org.example.cross.second");
  ASSERT_TRUE(first && second);
  {
    auto first_profile = profiles_.find((root_ / "cross-first" / "profile.sqlite").string());
    auto second_profile = profiles_.find((root_ / "cross-second" / "profile.sqlite").string());
    ASSERT_NE(first_profile, profiles_.end());
    ASSERT_NE(second_profile, profiles_.end());
    ASSERT_TRUE(heyaki::test::seed_mutual_trust(first_profile->second,
                                                second_profile->second, {"m4.test"}));
  }
  if (lan_interfaces_unavailable()) {
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  const auto second_key =
      DeviceEndpointKey{(*second.value_if())->snapshot().device_id,
                        (*second.value_if())->snapshot().endpoint_id};
  const auto first_key =
      DeviceEndpointKey{(*first.value_if())->snapshot().device_id,
                        (*first.value_if())->snapshot().endpoint_id};
  ASSERT_TRUE(
      wait_stable_mutual_discovery(**first.value_if(), **second.value_if()));

  // Both sides dial each other at the same moment; the LAN connection
  // arbitration must keep exactly one authenticated session per side.
  ASSERT_TRUE((*first.value_if())->connect_lan(second_key));
  ASSERT_TRUE((*second.value_if())->connect_lan(first_key));
  const bool authenticated = wait_until(
      [&] {
        const auto left = (*first.value_if())->peer_sessions();
        const auto right = (*second.value_if())->peer_sessions();
        auto count = [](const auto& sessions) {
          return static_cast<std::size_t>(std::count_if(
              sessions.begin(), sessions.end(), [](const auto& session) {
                return session.state == NodePeerSessionState::authenticated;
              }));
        };
        return !left.empty() && !right.empty() &&
               count(left) == count(right) && count(left) >= 1U;
      },
      std::chrono::seconds{60});
  ASSERT_TRUE(authenticated) << "cross connection never authenticated";

  // Wait a grace period for the losing duplicate connection to arbitrate.
  executor::comm::PhaseGate grace{"m4-cross-grace"};
  (void)grace.wait_for(1U, std::chrono::milliseconds{5000});
  const auto left = (*first.value_if())->peer_sessions();
  std::size_t active = 0U;
  for (const auto& session : left) {
    if (session.state == NodePeerSessionState::authenticated) {
      ++active;
    }
  }
  EXPECT_EQ(active, 1U) << "cross connection produced more than one winner";

  EXPECT_TRUE((*first.value_if())->shutdown().stopped);
  EXPECT_TRUE((*second.value_if())->shutdown().stopped);
}

}  // namespace
}  // namespace heyaki
