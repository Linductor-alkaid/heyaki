// M4 leak-enumeration exit condition: every failure/cancel/close path ends in
// an observable terminal state with executor-owned work, Asio work,
// DataChannels, coordinator attempts, and replay-cache entries fully drained.
//
// Enumerated paths (each maps to a case below; paths already covered by named
// suites are referenced rather than duplicated):
//   1 shutdown before any connect
//   2 shutdown during LAN signaling
//   3 shutdown during transport establishment
//   4 shutdown during authentication
//   5 shutdown of an authenticated session
//   6 shutdown with an in-flight session restart (M4-10)
//   7 association loss of an authenticated session (peer destroyed)
//   8 connect admission to an endpoint that is not in the directory
//   9 explicit close_lan cancellation during signaling
//  10 forced TURN without a reachable server   -> heyaki_m4_path_policy
//  11 tampered hello / signaling objects       -> heyaki_m4_signaling,
//                                                 heyaki_m4_session_restart
//  12 relay WSS loss before the session exists -> heyaki_m3b_relay
//  13 repeated association-loss cycles         -> heyaki_m3a_lan
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
  configuration.presence_lease = std::chrono::milliseconds{3000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  return configuration;
}

class M4ShutdownMatrixTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M4_SHUTDOWN_TEST_STATE_DIR} / "node";
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

  // Profiles and nodes stay owned by the fixture so every test body only
  // concerns itself with lifecycle assertions.
  Result<Node*> make_node(std::string_view name) {
    ProfileOpenOptions options;
    options.secret_backend.prefer_os_backend = false;
    auto profile =
        ProfileStore::create(root_ / std::string{name} / "profile.sqlite", options);
    if (!profile) {
      return Result<Node*>::failure(*profile.error_if());
    }
    PasswordVerifier verifier{.format_version = 1U,
                              .parameters = PasswordHashParameters{},
                              .encoded = "$argon2id$v=19$m=65536,t=2,p=1$test$test"};
    LocalProfileInitialization initialization{
        .application_id = std::string{name},
        .password_verifier = std::move(verifier),
        .password_generation = 1U,
        .pairing_policy = PairingPolicy{},
        .lan = fast_lan()};
    auto initialized = profile.value_if()->initialize_local(initialization);
    if (!initialized) {
      return Result<Node*>::failure(*initialized.error_if());
    }
    auto inserted =
        profiles_.emplace(std::string{name}, std::move(*profile.value_if()));
    NodeConfig config{.profile = &inserted.first->second,
                      .runtime = nullptr,
                      .application_id = std::string{name},
                      .lan_override = fast_lan(),
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
                        .shell_profiles = {}};
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
    executor::comm::PhaseGate poll{"m4-shutdown-poll"};
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

  // Mutual discovery must be stable across a refresh cycle before the test
  // connects: an entry glimpsed once can still race the directory lease on a
  // busy multicast group, which would fail the LAN hello binding check for
  // reasons unrelated to the lifecycle path under test.
  bool wait_mutual_discovery(Node& first, Node& second) {
    const auto second_key =
        DeviceEndpointKey{second.snapshot().device_id, second.snapshot().endpoint_id};
    const auto first_key =
        DeviceEndpointKey{first.snapshot().device_id, first.snapshot().endpoint_id};
    int stable_polls = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
    executor::comm::PhaseGate poll{"m4-stable-discovery"};
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

  // The single drain invariant every enumerated path must satisfy after its
  // terminal state: no Asio timers, sockets, or pending writes remain; the
  // coordinator holds no attempts and its replay guard stays inside capacity;
  // no restart is left in flight; and every published session is terminal.
  void assert_fully_drained(const Node& node, const char* path) {
    const auto snapshot = node.snapshot();
    const auto& resources = snapshot.resources;
    EXPECT_EQ(resources.discovery_sockets, 0U) << path;
    EXPECT_EQ(resources.signaling_connections, 0U) << path;
    EXPECT_EQ(resources.active_timers, 0U) << path;
    EXPECT_EQ(resources.pending_outbound_messages, 0U) << path;
    EXPECT_EQ(snapshot.session_coordinator.current_attempts, 0U) << path;
    EXPECT_LE(snapshot.session_coordinator.replay_current_entries, 4096U) << path;
    EXPECT_EQ(snapshot.session_restarts.current_restarts, 0U) << path;
    const auto sessions = node.peer_sessions();
    for (const auto& session : sessions) {
      EXPECT_EQ(session.state, NodePeerSessionState::closed) << path;
    }
    EXPECT_LE(sessions.size(), 16U) << path;
  }

  std::filesystem::path root_;
  void seed_trust(const std::string& first, const std::string& second) {
    auto first_profile = profiles_.find(first);
    auto second_profile = profiles_.find(second);
    ASSERT_NE(first_profile, profiles_.end()) << first;
    ASSERT_NE(second_profile, profiles_.end()) << second;
    ASSERT_TRUE(heyaki::test::seed_mutual_trust(first_profile->second,
                                                second_profile->second, {"m4.test"}));
  }

  std::map<std::string, ProfileStore> profiles_;
  std::deque<Node> nodes_;
};

// Paths 1-6: shutdown at every lifecycle phase always stops and drains.
class M4ShutdownPhaseMatrix
    : public M4ShutdownMatrixTest,
      public ::testing::WithParamInterface<std::chrono::milliseconds> {};

TEST_P(M4ShutdownPhaseMatrix, ShutdownAtPhaseStopsAndDrains) {
  const auto phase_delay = GetParam();
  auto first = make_node("matrix-first");
  auto second = make_node("matrix-second");
  seed_trust("matrix-first", "matrix-second");
  ASSERT_TRUE(first && second);
  if (lan_interfaces_unavailable(**first.value_if(), **second.value_if())) {
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  const auto second_key =
      DeviceEndpointKey{(*second.value_if())->snapshot().device_id,
                        (*second.value_if())->snapshot().endpoint_id};
  ASSERT_TRUE(wait_mutual_discovery(**first.value_if(), **second.value_if()));
  (void)(*first.value_if())->connect_lan(second_key);
  executor::comm::PhaseGate delay{"m4-shutdown-delay"};
  (void)delay.wait_for(1U, phase_delay);
  const auto report = (*first.value_if())->shutdown();
  EXPECT_TRUE(report.stopped);
  EXPECT_FALSE(report.timed_out);
  assert_fully_drained(**first.value_if(), "shutdown-at-phase");
  EXPECT_TRUE((*second.value_if())->shutdown().stopped);
  assert_fully_drained(**second.value_if(), "shutdown-at-phase-peer");
}

INSTANTIATE_TEST_SUITE_P(ShutdownPhases, M4ShutdownPhaseMatrix,
                         ::testing::Values(std::chrono::milliseconds{0},
                                           std::chrono::milliseconds{50},
                                           std::chrono::milliseconds{200},
                                           std::chrono::milliseconds{500},
                                           std::chrono::milliseconds{1500}),
                         [](const auto& info) {
                           return "delay" + std::to_string(info.param.count()) + "ms";
                         });

TEST_F(M4ShutdownMatrixTest, ShutdownDuringAuthenticatedSessionDrains) {
  auto first = make_node("auth-drain-first");
  auto second = make_node("auth-drain-second");
  seed_trust("auth-drain-first", "auth-drain-second");
  ASSERT_TRUE(first && second);
  if (lan_interfaces_unavailable(**first.value_if(), **second.value_if())) {
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  const auto second_key =
      DeviceEndpointKey{(*second.value_if())->snapshot().device_id,
                        (*second.value_if())->snapshot().endpoint_id};
  ASSERT_TRUE(wait_mutual_discovery(**first.value_if(), **second.value_if()));
  ASSERT_TRUE((*first.value_if())->connect_lan(second_key));
  ASSERT_TRUE(wait_until(
      [&] {
        const auto sessions = (*first.value_if())->peer_sessions();
        return !sessions.empty() &&
               sessions.front().state == NodePeerSessionState::authenticated;
      },
      std::chrono::seconds{10}));
  const auto report = (*first.value_if())->shutdown();
  EXPECT_TRUE(report.stopped);
  EXPECT_FALSE(report.timed_out);
  assert_fully_drained(**first.value_if(), "shutdown-authenticated");
  EXPECT_TRUE((*second.value_if())->shutdown().stopped);
  assert_fully_drained(**second.value_if(), "shutdown-authenticated-peer");
}

TEST_F(M4ShutdownMatrixTest, ShutdownDuringInFlightRestartDrains) {
  auto first = make_node("restart-drain-first");
  auto second = make_node("restart-drain-second");
  seed_trust("restart-drain-first", "restart-drain-second");
  ASSERT_TRUE(first && second);
  if (lan_interfaces_unavailable(**first.value_if(), **second.value_if())) {
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  const auto second_key =
      DeviceEndpointKey{(*second.value_if())->snapshot().device_id,
                        (*second.value_if())->snapshot().endpoint_id};
  ASSERT_TRUE(wait_mutual_discovery(**first.value_if(), **second.value_if()));
  ASSERT_TRUE((*first.value_if())->connect_lan(second_key));
  ASSERT_TRUE(wait_until(
      [&] {
        const auto sessions = (*first.value_if())->peer_sessions();
        return !sessions.empty() &&
               sessions.front().state == NodePeerSessionState::authenticated;
      },
      std::chrono::seconds{10}));
  // Begin the restart renegotiation, then shut down while it is in flight:
  // the restart transport, deadline timer, and admission state must all be
  // released by the close-peers phase.
  ASSERT_TRUE((*first.value_if())->restart_session(second_key));
  ASSERT_TRUE(wait_until(
      [&] {
        return (*first.value_if())->snapshot().session_restarts.current_restarts == 1U;
      },
      std::chrono::seconds{5}));
  const auto report = (*first.value_if())->shutdown();
  EXPECT_TRUE(report.stopped);
  EXPECT_FALSE(report.timed_out);
  assert_fully_drained(**first.value_if(), "shutdown-restart-in-flight");
  EXPECT_TRUE((*second.value_if())->shutdown().stopped);
  assert_fully_drained(**second.value_if(), "shutdown-restart-in-flight-peer");
}

TEST_F(M4ShutdownMatrixTest, AssociationLossReachesTerminalAndDrains) {
  auto first = make_node("loss-first");
  auto second = make_node("loss-second");
  seed_trust("loss-first", "loss-second");
  ASSERT_TRUE(first && second);
  if (lan_interfaces_unavailable(**first.value_if(), **second.value_if())) {
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  const auto second_key =
      DeviceEndpointKey{(*second.value_if())->snapshot().device_id,
                        (*second.value_if())->snapshot().endpoint_id};
  ASSERT_TRUE(wait_mutual_discovery(**first.value_if(), **second.value_if()));
  ASSERT_TRUE((*first.value_if())->connect_lan(second_key));
  {
    const bool authenticated = wait_until(
        [&] {
          const auto sessions = (*first.value_if())->peer_sessions();
          return std::any_of(sessions.begin(), sessions.end(), [](const auto& s) {
            return s.state == NodePeerSessionState::authenticated;
          });
        },
        std::chrono::seconds{10});
    if (!authenticated) {
      const auto state = (*first.value_if())->snapshot();
      const auto sessions = (*first.value_if())->peer_sessions();
      ADD_FAILURE() << "auth failed; sessions=" << sessions.size()
                    << " err="
                    << (state.last_error
                            ? std::string{state.last_error->safe_detail()}
                            : std::string{"-"})
                    << " coords=" << state.session_coordinator.current_attempts;
    }
  }
  // Destroy the peer node entirely; the surviving side must land in a
  // closed-with-error terminal state (not a hang) and then drain cleanly.
  EXPECT_TRUE((*second.value_if())->shutdown().stopped);
  nodes_.pop_back();
  ASSERT_TRUE(wait_until(
      [&] {
        const auto sessions = (*first.value_if())->peer_sessions();
        return std::any_of(sessions.begin(), sessions.end(), [](const auto& session) {
          return session.state == NodePeerSessionState::closed && session.error.has_value();
        });
      },
      std::chrono::seconds{20}))
      << "association loss never reached a terminal state";
  const auto report = (*first.value_if())->shutdown();
  EXPECT_TRUE(report.stopped);
  EXPECT_FALSE(report.timed_out);
  assert_fully_drained(**first.value_if(), "association-loss");
}

TEST_F(M4ShutdownMatrixTest, ConnectToUnknownEndpointRejectsAndKeepsCapacity) {
  auto node = make_node("unknown-endpoint");
  ASSERT_TRUE(node);
  DeviceEndpointKey peer{};
  {
    DeviceId::Storage device_bytes{};
    device_bytes[0] = std::byte{0x7f};
    EndpointId::Storage endpoint_bytes{};
    endpoint_bytes[0] = std::byte{0x3c};
    peer.device_id = DeviceId{device_bytes};
    peer.endpoint_id = EndpointId{endpoint_bytes};
  }
  const auto rejected = (*node.value_if())->connect_lan(peer);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->code(), ErrorCode::endpoint_offline);
  EXPECT_EQ((*node.value_if())->snapshot().session_coordinator.current_attempts, 0U);
  EXPECT_TRUE((*node.value_if())->shutdown().stopped);
  assert_fully_drained(**node.value_if(), "connect-unknown-endpoint");
}

TEST_F(M4ShutdownMatrixTest, CloseLanDuringSignalingCancelsAndDrains) {
  auto first = make_node("cancel-first");
  auto second = make_node("cancel-second");
  seed_trust("cancel-first", "cancel-second");
  ASSERT_TRUE(first && second);
  if (lan_interfaces_unavailable(**first.value_if(), **second.value_if())) {
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  const auto second_key =
      DeviceEndpointKey{(*second.value_if())->snapshot().device_id,
                        (*second.value_if())->snapshot().endpoint_id};
  ASSERT_TRUE(wait_mutual_discovery(**first.value_if(), **second.value_if()));
  ASSERT_TRUE((*first.value_if())->connect_lan(second_key));
  executor::comm::PhaseGate delay{"m4-cancel-delay"};
  (void)delay.wait_for(1U, std::chrono::milliseconds{20});
  (void)(*first.value_if())->close_lan(second_key);
  const auto report = (*first.value_if())->shutdown();
  EXPECT_TRUE(report.stopped);
  EXPECT_FALSE(report.timed_out);
  assert_fully_drained(**first.value_if(), "close-lan-cancel");
  EXPECT_TRUE((*second.value_if())->shutdown().stopped);
  assert_fully_drained(**second.value_if(), "close-lan-cancel-peer");
}

}  // namespace
}  // namespace heyaki
