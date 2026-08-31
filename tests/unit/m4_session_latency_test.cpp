#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <executor/comm.hpp>

#include <gtest/gtest.h>

#include "m5_support.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {
namespace {

class M4SessionLatencyTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M4_LATENCY_TEST_STATE_DIR} / "node";
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
        .lan = LanConfiguration{}};
    auto initialized = profile.value_if()->initialize_local(initialization);
    if (!initialized) {
      return Result<ProfileStore>::failure(*initialized.error_if());
    }
    return profile;
  }

  template <typename Predicate>
  bool wait_until(Predicate&& predicate, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    executor::comm::PhaseGate poll{"m4-latency-poll"};
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
        return true;
      }
      (void)poll.wait_for(1U, std::chrono::milliseconds{1});
    }
    return predicate();
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

TEST_F(M4SessionLatencyTest, DirectHostSessionEstablishmentP95UnderThreeSeconds) {
  // M4 exit condition, direct half: on a hole-punchable network (here: one
  // LAN with host candidates, no relay/STUN/TURN), the P95 from connect()
  // admission to the authenticated session must stay under three seconds.
  // The TURN-fallback half needs a real coturn allocation environment and is
  // tracked with the network matrix gate.
  std::vector<double> samples;
  constexpr std::size_t kCycles = 10U;
  for (std::size_t cycle = 0U; cycle < kCycles; ++cycle) {
    auto first_profile = initialized_profile("latency-first-" + std::to_string(cycle),
                                             "com.example.latency.first");
    auto second_profile =
        initialized_profile("latency-second-" + std::to_string(cycle),
                            "com.example.latency.second");
    ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));

    const auto node_config_for = [&](ProfileStore& profile,
                                     const char* application_id) {
      return NodeConfig{.profile = &profile,
                        .runtime = nullptr,
                        .application_id = application_id,
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
                        .file_max_peer_receive_bytes = 0U};
    };
    NodeConfig first_config = node_config_for(*first_profile.value_if(),
                                              "com.example.latency.first");
    NodeConfig second_config = node_config_for(*second_profile.value_if(),
                                               "com.example.latency.second");
    auto first = Node::create(std::move(first_config));
    auto second = Node::create(std::move(second_config));
    ASSERT_TRUE(first && second)
        << (first ? std::string{} : first.error_if()->safe_detail())
        << (second ? std::string{} : second.error_if()->safe_detail());
    if (first.value_if()->snapshot().interfaces.empty() ||
        second.value_if()->snapshot().interfaces.empty()) {
      (void)first.value_if()->shutdown();
      (void)second.value_if()->shutdown();
      const char* required = std::getenv("HEYAKI_REQUIRE_LAN_INTERFACES");
      if (required != nullptr && std::string_view{required} == "1") {
        FAIL() << "Required LAN interface is unavailable";
      }
      GTEST_SKIP() << "No multicast-capable non-loopback interface";
    }

    const auto second_key =
        DeviceEndpointKey{second.value_if()->snapshot().device_id,
                          second.value_if()->snapshot().endpoint_id};
    const auto first_key = DeviceEndpointKey{first.value_if()->snapshot().device_id,
                                             first.value_if()->snapshot().endpoint_id};
    const auto discovered = [](const Node& node, const DeviceEndpointKey& peer) {
      const auto entries = node.endpoints();
      return std::any_of(entries.begin(), entries.end(),
                         [&](const auto& entry) { return entry.key == peer; });
    };
    ASSERT_TRUE(wait_until(
        [&] {
          return discovered(*first.value_if(), second_key) &&
                 discovered(*second.value_if(), first_key);
        },
        std::chrono::seconds{10}))
        << "cycle " << cycle << ": discovery did not complete";

    const auto begin = std::chrono::steady_clock::now();
    ASSERT_TRUE(first.value_if()->connect_lan(second_key));
    const bool authenticated = wait_until(
        [&] {
          const auto sessions = first.value_if()->peer_sessions();
          return std::any_of(sessions.begin(), sessions.end(),
                             [](const NodePeerSessionSnapshot& session) {
                               return session.state ==
                                      NodePeerSessionState::authenticated;
                             });
        },
        std::chrono::seconds{15});
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    ASSERT_TRUE(authenticated) << "cycle " << cycle << ": session never authenticated";
    samples.push_back(
        std::chrono::duration<double, std::milli>(elapsed).count());
    ASSERT_TRUE(first.value_if()->shutdown().stopped);
    ASSERT_TRUE(second.value_if()->shutdown().stopped);
  }

  ASSERT_EQ(samples.size(), kCycles);
  std::vector<double> sorted = samples;
  std::sort(sorted.begin(), sorted.end());
  const auto p95_index =
      std::min(sorted.size() - 1U,
               static_cast<std::size_t>(
                   std::ceil(static_cast<double>(sorted.size()) * 0.95)) -
                   1U);
  const double p95 = sorted[p95_index];
  std::cout << "M4 direct session latency ms p95=" << p95
            << " min=" << sorted.front() << " median=" << sorted[sorted.size() / 2U]
            << " max=" << sorted.back() << "\n";
  EXPECT_LT(p95, 3000.0);
}

}  // namespace
}  // namespace heyaki
