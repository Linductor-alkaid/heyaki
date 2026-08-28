// M4-10 in-place session restart e2e: two real LAN nodes authenticate, then
// renegotiate a replacement transport over the authenticated control channel
// through the protocol-1.2 signed restart frames. The SessionId is preserved,
// the epoch bumps, and the old physical session retires explicitly.
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
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {
namespace {

bool environment_requires_lan_interfaces() {
  const char* value = std::getenv("HEYAKI_REQUIRE_LAN_INTERFACES");
  return value != nullptr && std::string_view{value} == "1";
}

bool discovered(const Node& node, const DeviceEndpointKey& peer) {
  const auto entries = node.endpoints();
  return std::any_of(entries.begin(), entries.end(),
                     [&](const auto& entry) { return entry.key == peer; });
}

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

class M4SessionRestartE2ETest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M4_RESTART_TEST_STATE_DIR} / "node";
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
    std::filesystem::create_directories(root_);
  }

  void TearDown() override {
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
  }

  Result<ProfileStore> initialized_profile(std::string_view name,
                                           std::string_view application_id) {
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
        .lan = fast_lan_only()};
    auto initialized = profile.value_if()->initialize_local(initialization);
    if (!initialized) {
      return Result<ProfileStore>::failure(*initialized.error_if());
    }
    return profile;
  }

  // Mutual discovery stable across refresh cycles; a once-glimpsed entry can
  // race the directory lease on a busy multicast group.
  bool wait_stable_mutual_discovery(Node& first, Node& second) {
    const auto second_key =
        DeviceEndpointKey{second.snapshot().device_id, second.snapshot().endpoint_id};
    const auto first_key =
        DeviceEndpointKey{first.snapshot().device_id, first.snapshot().endpoint_id};
    int stable_polls = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
    executor::comm::PhaseGate poll{"m4-restart-stable-discovery"};
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

  template <typename Predicate>
  bool wait_until(Predicate&& predicate, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    executor::comm::PhaseGate poll{"m4-restart-poll"};
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
        return true;
      }
      (void)poll.wait_for(1U, std::chrono::milliseconds{1});
    }
    return predicate();
  }

  bool lan_interfaces_unavailable(const Node& first, const Node& second) {
    return first.snapshot().interfaces.empty() || second.snapshot().interfaces.empty();
  }

  std::filesystem::path root_;
};

NodeConfig restart_node_config(ProfileStore& profile,
                               std::string application_id) {
  return NodeConfig{.profile = &profile,
                    .runtime = nullptr,
                    .application_id = std::move(application_id),
                    .lan_override = fast_lan_only(),
                    .runtime_config = RuntimeConfig{},
                    .signaling_validator = {},
                    .signaling_handler = {},
                    .relay_override = std::nullopt,
                    .path_policy_override = std::nullopt};
}

std::optional<NodePeerSessionSnapshot> active_session(const Node& node,
                                                      const DeviceEndpointKey& peer) {
  const auto sessions = node.peer_sessions();
  const auto iterator = std::find_if(
      sessions.begin(), sessions.end(), [&](const auto& session) {
        return session.peer == peer && session.state != NodePeerSessionState::closed;
      });
  if (iterator == sessions.end()) return std::nullopt;
  return *iterator;
}

TEST_F(M4SessionRestartE2ETest, RestartSwapsTransportAndBumpsEpoch) {
  auto first_profile = initialized_profile("restart-first", "com.example.restart.first");
  auto second_profile =
      initialized_profile("restart-second", "com.example.restart.second");
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));

  auto first =
      Node::create(restart_node_config(*first_profile.value_if(),
                                       "com.example.restart.first"));
  auto second =
      Node::create(restart_node_config(*second_profile.value_if(),
                                       "com.example.restart.second"));
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

  const auto first_key = DeviceEndpointKey{first.value_if()->snapshot().device_id,
                                           first.value_if()->snapshot().endpoint_id};
  const auto second_key = DeviceEndpointKey{
      second.value_if()->snapshot().device_id,
      second.value_if()->snapshot().endpoint_id};
  ASSERT_TRUE(wait_stable_mutual_discovery(*first.value_if(),
                                        *second.value_if()));
  ASSERT_TRUE(first.value_if()->connect_lan(second_key));
  ASSERT_TRUE(wait_until(
      [&] {
        const auto left = active_session(*first.value_if(), second_key);
        const auto right = active_session(*second.value_if(), first_key);
        return left.has_value() && right.has_value() &&
               left->state == NodePeerSessionState::authenticated &&
               right->state == NodePeerSessionState::authenticated;
      },
      std::chrono::seconds{10}))
      << "baseline authenticated session was not established";

  const auto baseline = active_session(*first.value_if(), second_key);
  ASSERT_TRUE(baseline.has_value());
  EXPECT_EQ(baseline->session_epoch, 1U);
  const auto original_request_id = baseline->request_id;

  // Restart before any second restart can be admitted (cooldown applies to
  // inbound offers, not to the explicit operator-initiated path).
  auto restarted = first.value_if()->restart_session(second_key);
  ASSERT_TRUE(restarted)
      << restarted.error_if()->safe_detail();

  const bool swapped = wait_until(
      [&] {
        const auto left = active_session(*first.value_if(), second_key);
        const auto right = active_session(*second.value_if(), first_key);
        const auto& first_restart =
            first.value_if()->snapshot().session_restarts;
        const auto& second_restart =
            second.value_if()->snapshot().session_restarts;
        return left.has_value() && right.has_value() &&
               left->state == NodePeerSessionState::authenticated &&
               right->state == NodePeerSessionState::authenticated &&
               left->session_id == baseline->session_id &&
               right->session_id == baseline->session_id &&
               left->session_epoch == 2U && right->session_epoch == 2U &&
               first_restart.restarts_completed == 1U &&
               second_restart.restarts_completed == 1U &&
               first_restart.current_restarts == 0U &&
               second_restart.current_restarts == 0U;
      },
      std::chrono::seconds{20});
  if (!swapped) {
    const auto& first_state = first.value_if()->snapshot();
    const auto& second_state = second.value_if()->snapshot();
    const auto sessions = first.value_if()->peer_sessions();
    ADD_FAILURE() << "restart renegotiation did not complete; "
                  << "a_init=" << first_state.session_restarts.restarts_initiated
                  << " a_done=" << first_state.session_restarts.restarts_completed
                  << " a_fail=" << first_state.session_restarts.restarts_failed
                  << " a_sup=" << first_state.session_restarts.restarts_suppressed
                  << " a_cur=" << first_state.session_restarts.current_restarts
                  << " a_err="
                  << (first_state.last_error
                          ? std::string{first_state.last_error->safe_detail()}
                          : std::string{"-"})
                  << " b_init=" << second_state.session_restarts.restarts_initiated
                  << " b_done=" << second_state.session_restarts.restarts_completed
                  << " b_fail=" << second_state.session_restarts.restarts_failed
                  << " b_cur=" << second_state.session_restarts.current_restarts
                  << " sessions=" << sessions.size();
    for (const auto& session : sessions) {
      ADD_FAILURE() << "session state=" << (int)session.state
                    << " epoch=" << session.session_epoch
                    << " stage=" << (int)session.connection_stage;
    }
  }

  const auto successor = active_session(*first.value_if(), second_key);
  ASSERT_TRUE(successor.has_value());
  // A brand-new physical attempt carries a fresh request id; the same
  // SessionId and the bumped epoch prove the logical session continued.
  EXPECT_NE(successor->request_id, original_request_id);
  EXPECT_EQ(successor->session_id, baseline->session_id);
  EXPECT_EQ(successor->session_epoch, 2U);
  EXPECT_FALSE(successor->restart_in_flight);
  EXPECT_EQ(successor->data_path, NodeDataPathKind::direct_host);

  // The superseded physical session appears exactly once as a closed entry
  // in the bounded diagnostic history, without an error.
  const auto history = first.value_if()->peer_sessions();
  std::size_t closed_for_peer = 0U;
  std::size_t active_for_peer = 0U;
  for (const auto& session : history) {
    if (session.peer != second_key) continue;
    if (session.state == NodePeerSessionState::closed) {
      ++closed_for_peer;
      EXPECT_FALSE(session.error.has_value())
          << (session.error ? std::string{session.error->safe_detail()} : std::string{});
    } else {
      ++active_for_peer;
    }
  }
  EXPECT_EQ(closed_for_peer, 1U);
  EXPECT_EQ(active_for_peer, 1U);

  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
}

TEST_F(M4SessionRestartE2ETest, RestartRequiresAuthenticatedSession) {
  auto profile = initialized_profile("restart-unauthenticated",
                                     "com.example.restart.unauth");
  ASSERT_TRUE(profile);
  auto node =
      Node::create(restart_node_config(*profile.value_if(),
                                       "com.example.restart.unauth"));
  ASSERT_TRUE(node);
  const DeviceEndpointKey peer{};
  // A zero peer key is rejected without touching session state.
  EXPECT_FALSE(node.value_if()->restart_session(peer));
  EXPECT_TRUE(node.value_if()->shutdown().stopped);
}

TEST_F(M4SessionRestartE2ETest, RefreshWithoutChangeDoesNotRestart) {
  auto first_profile =
      initialized_profile("refresh-first", "com.example.refresh.first");
  auto second_profile =
      initialized_profile("refresh-second", "com.example.refresh.second");
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));
  auto first =
      Node::create(restart_node_config(*first_profile.value_if(),
                                       "com.example.refresh.first"));
  auto second =
      Node::create(restart_node_config(*second_profile.value_if(),
                                       "com.example.refresh.second"));
  ASSERT_TRUE(first && second);
  if (lan_interfaces_unavailable(*first.value_if(), *second.value_if())) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    if (environment_requires_lan_interfaces()) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  const auto second_key = DeviceEndpointKey{
      second.value_if()->snapshot().device_id,
      second.value_if()->snapshot().endpoint_id};
  ASSERT_TRUE(
      wait_stable_mutual_discovery(*first.value_if(), *second.value_if()));
  ASSERT_TRUE(first.value_if()->connect_lan(second_key));
  ASSERT_TRUE(wait_until(
      [&] {
        const auto session = active_session(*first.value_if(), second_key);
        return session.has_value() &&
               session->state == NodePeerSessionState::authenticated;
      },
      std::chrono::seconds{10}));

  // Interface refreshes with an unchanged binding set must not disturb the
  // session: no restart is initiated and the epoch stays at 1.
  for (int scan = 0; scan < 3; ++scan) {
    ASSERT_TRUE(first.value_if()->refresh_interfaces());
  }
  EXPECT_TRUE(wait_until(
      [&] {
        return !first.value_if()->snapshot().resources.interface_scan_in_flight;
      },
      std::chrono::seconds{5}));
  const auto session = active_session(*first.value_if(), second_key);
  ASSERT_TRUE(session.has_value());
  EXPECT_EQ(session->state, NodePeerSessionState::authenticated);
  EXPECT_EQ(session->session_epoch, 1U);
  EXPECT_EQ(first.value_if()->snapshot().session_restarts.restarts_initiated, 0U);
  EXPECT_EQ(first.value_if()->snapshot().session_restarts.current_restarts, 0U);

  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
}

}  // namespace
}  // namespace heyaki
