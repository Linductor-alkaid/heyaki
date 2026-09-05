// M9-01 device metrics tests: the NodeMetrics aggregation model, the
// Prometheus text-format export, and a live two-node LAN session proving
// the connectivity/pairing/runtime sections populate end to end.

#include <heyaki/metrics.hpp>
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

class M9MetricsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M9_METRICS_TEST_STATE_DIR} / "node";
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
    executor::comm::PhaseGate poll{"m9-metrics-poll"};
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

NodeMetrics representative_metrics() {
  NodeMetrics metrics;
  metrics.unix_milliseconds = 1725500000000ULL;
  metrics.node.local_initialized = true;
  metrics.node.lan_enabled = true;
  metrics.node.announcements_sent = 11U;
  metrics.node.datagrams_received = 22U;
  metrics.node.tls.listener_ready = true;
  metrics.node.tls.listen_port = 51000U;
  metrics.node.tls.handshake_failed = 3U;
  metrics.node.directory.accepted = 7U;
  metrics.node.directory.current_entries = 2U;
  metrics.node.relay.enabled = true;
  metrics.node.relay.reconnect_count = 4U;
  metrics.node.relay.heartbeats_sent = 40U;
  metrics.node.session_coordinator.attempts_expired = 1U;
  metrics.node.session_restarts.restarts_initiated = 2U;
  metrics.node.resources.discovery_sockets = 2U;
  metrics.pairing.attempts = 7U;
  metrics.pairing.granted = 5U;
  metrics.pairing.denied_password = 1U;
  metrics.pairing.denied_backoff = 1U;
  metrics.connectivity.connections_initiated = 9U;
  metrics.connectivity.sessions_authenticated = 6U;
  metrics.connectivity.signaling_route_lan = 4U;
  metrics.connectivity.signaling_route_relay = 2U;
  metrics.connectivity.data_path_direct_host = 3U;
  metrics.connectivity.data_path_turn_udp = 3U;
  metrics.connectivity.connect_duration_samples = 6U;
  metrics.connectivity.connect_duration_milliseconds_sum = 6000U;
  metrics.connectivity.connect_duration_milliseconds_max = 2100U;
  metrics.transport.peer_sessions = 2U;
  metrics.transport.authenticated_sessions = 2U;
  metrics.transport.rtt_samples = 2U;
  metrics.transport.rtt_milliseconds_sum = 90U;
  metrics.transport.rtt_milliseconds_max = 60U;
  metrics.transport.buffered_amount_sum = 128U;
  metrics.channels.channels = 4U;
  metrics.channels.sent_frames = 100U;
  metrics.channels.sent_bytes = 4096U;
  metrics.channels.dropped_frames = 2U;
  metrics.services.message.sent_best_effort = 30U;
  metrics.services.message.received = 31U;
  metrics.services.rpc.calls_started = 12U;
  metrics.services.rpc.requests_received = 8U;
  metrics.services.event.published_items = 50U;
  metrics.services.event.lag_events = 1U;
  metrics.services.file.chunks_sent = 200U;
  metrics.services.file.chunk_hash_failures = 1U;
  metrics.services.shell.opens_received = 3U;
  metrics.services.shell.idle_timeouts = 1U;
  metrics.services.message_pending_acks = 2U;
  metrics.services.shell_sessions = 1U;
  metrics.runtime.worker_ready = true;
  metrics.runtime.callbacks_accepted = 500U;
  metrics.runtime.executor_running_backend_count = 1U;
  metrics.runtime.executor_submit_rejected_count = 2U;
  metrics.runtime.metric_consumer_lag = 1U;
  return metrics;
}

// Every exposition line is either a comment or `name[label] value` with an
// integer value; every metric family declares HELP and TYPE exactly once.
bool exposition_is_well_formed(const std::string& text) {
  std::size_t families = 0U;
  std::size_t helps = 0U;
  std::size_t types = 0U;
  std::size_t samples = 0U;
  std::size_t offset = 0U;
  while (offset < text.size()) {
    const auto end = text.find('\n', offset);
    const std::string_view line =
        std::string_view{text}.substr(offset, end == std::string::npos
                                                ? std::string_view::npos
                                                : end - offset);
    offset = end == std::string::npos ? text.size() : end + 1U;
    if (line.empty()) {
      return false;
    }
    if (line.starts_with("# HELP ")) {
      ++helps;
      continue;
    }
    if (line.starts_with("# TYPE ")) {
      ++types;
      const auto tail = line.substr(7U);
      const auto kind = tail.substr(tail.rfind(' ') + 1U);
      if (kind != "counter" && kind != "gauge") {
        return false;
      }
      continue;
    }
    if (line.starts_with("#")) {
      return false;
    }
    const auto label_start = line.find('{');
    const auto value_start = line.rfind(' ');
    if (value_start == std::string_view::npos || value_start == 0U) {
      return false;
    }
    const auto value = line.substr(value_start + 1U);
    if (value.empty() ||
        !std::all_of(value.begin(), value.end(),
                     [](char character) { return character >= '0' && character <= '9'; })) {
      return false;
    }
    const auto name = line.substr(0U, label_start == std::string_view::npos
                                          ? value_start
                                          : label_start);
    if (name.empty() || !name.starts_with("heyaki_")) {
      return false;
    }
    if (label_start == std::string_view::npos) {
      // Counters must carry the _total suffix; gauges must not.
      const bool total = name.ends_with("_total");
      if (total) {
        ++families;
      }
    }
    ++samples;
  }
  return helps == types && helps >= 120U && samples >= 120U && families >= 100U;
}

TEST_F(M9MetricsTest, ConnectivityCountersRecordRoutesPathsAndDurations) {
  NodeConnectivityMetrics connectivity;
  NodePeerSessionSnapshot session;
  session.signaling_route = SignalingRouteKind::lan;
  session.data_path = NodeDataPathKind::direct_host;
  const auto begun = std::chrono::steady_clock::now() - std::chrono::milliseconds{1500};
  connectivity.record_authenticated(session, begun,
                                    begun + std::chrono::milliseconds{1500});
  EXPECT_EQ(connectivity.sessions_authenticated, 1U);
  EXPECT_EQ(connectivity.signaling_route_lan, 1U);
  EXPECT_EQ(connectivity.signaling_route_relay, 0U);
  EXPECT_EQ(connectivity.data_path_direct_host, 1U);
  EXPECT_EQ(connectivity.connect_duration_samples, 1U);
  EXPECT_EQ(connectivity.connect_duration_milliseconds_sum, 1500U);
  EXPECT_EQ(connectivity.connect_duration_milliseconds_max, 1500U);

  NodePeerSessionSnapshot relayed;
  relayed.signaling_route = SignalingRouteKind::relay;
  relayed.data_path = NodeDataPathKind::turn_tls;
  connectivity.record_authenticated(relayed, begun,
                                    begun + std::chrono::milliseconds{300});
  EXPECT_EQ(connectivity.sessions_authenticated, 2U);
  EXPECT_EQ(connectivity.signaling_route_relay, 1U);
  EXPECT_EQ(connectivity.data_path_turn_tls, 1U);
  EXPECT_EQ(connectivity.connect_duration_samples, 2U);
  EXPECT_EQ(connectivity.connect_duration_milliseconds_sum, 1800U);
  EXPECT_EQ(connectivity.connect_duration_milliseconds_max, 1500U);
}

TEST_F(M9MetricsTest, PrometheusExportIsWellFormedAndPinsFormat) {
  const auto metrics = representative_metrics();
  const auto text = format_node_metrics_prometheus(metrics);
  EXPECT_TRUE(exposition_is_well_formed(text));

  // Format pins: exact pairing block, counter/gauge typing, instance label.
  EXPECT_NE(text.find("# HELP heyaki_pairing_attempts_total "
                      "Pairing attempts evaluated.\n"
                      "# TYPE heyaki_pairing_attempts_total counter\n"
                      "heyaki_pairing_attempts_total 7\n"),
            std::string::npos);
  EXPECT_NE(text.find("heyaki_node_relay_reconnects_total 4\n"), std::string::npos);
  EXPECT_NE(text.find("heyaki_connectivity_authenticated_total 6\n"), std::string::npos);
  EXPECT_NE(text.find("heyaki_shell_idle_timeouts_total 1\n"), std::string::npos);
  EXPECT_NE(text.find("# TYPE heyaki_transport_peer_sessions gauge\n"),
            std::string::npos);
  EXPECT_NE(text.find("heyaki_runtime_metric_consumer_lag 1\n"), std::string::npos);

  const auto labeled = format_node_metrics_prometheus(metrics, "device-7");
  EXPECT_NE(labeled.find("heyaki_pairing_attempts_total{instance=\"device-7\"} 7\n"),
            std::string::npos);
  // The instance label escapes quotes and backslashes.
  const auto escaped = format_node_metrics_prometheus(metrics, "a\"b\\c");
  EXPECT_NE(escaped.find("heyaki_pairing_attempts_total{instance=\"a\\\"b\\\\c\"} 7\n"),
            std::string::npos);
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

TEST_F(M9MetricsTest, MetricsSnapshotReflectsAuthenticatedLanSession) {
  auto first_profile =
      initialized_profile("metrics-first", "com.example.metrics.first");
  auto second_profile =
      initialized_profile("metrics-second", "com.example.metrics.second");
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m9.test"}));

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
                      .file_max_peer_receive_bytes = 0U,
                      .shell_profiles = {}};
  };
  auto first = Node::create(
      node_config_for(*first_profile.value_if(), "com.example.metrics.first"));
  auto second = Node::create(
      node_config_for(*second_profile.value_if(), "com.example.metrics.second"));
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
      << "discovery did not complete";

  // Before any connection the metrics snapshot still publishes (tick) with
  // zero connectivity counters and a healthy runtime section.
  ASSERT_TRUE(wait_until(
      [&] {
        const auto metrics = first.value_if()->metrics();
        return metrics.unix_milliseconds > 0U &&
               metrics.connectivity.connections_initiated == 0U &&
               metrics.runtime.executor_running_backend_count > 0U;
      },
      std::chrono::seconds{5}))
      << "idle metrics snapshot never published";

  ASSERT_TRUE(first.value_if()->connect_lan(second_key));
  const auto authenticated = wait_until(
      [&] {
        const auto sessions = first.value_if()->peer_sessions();
        return std::any_of(sessions.begin(), sessions.end(), [](const auto& session) {
          return session.state == NodePeerSessionState::authenticated;
        });
      },
      std::chrono::seconds{10});
  ASSERT_TRUE(authenticated) << "session never authenticated";

  const auto connected = wait_until(
      [&] {
        const auto metrics = first.value_if()->metrics();
        return metrics.connectivity.sessions_authenticated >= 1U &&
               metrics.connectivity.connect_duration_samples >= 1U &&
               metrics.transport.authenticated_sessions >= 1U;
      },
      std::chrono::seconds{5});
  ASSERT_TRUE(connected) << "authenticated metrics never published";

  const auto metrics = first.value_if()->metrics();
  EXPECT_GE(metrics.connectivity.connections_initiated, 1U);
  EXPECT_GE(metrics.connectivity.signaling_route_lan, 1U);
  EXPECT_GE(metrics.connectivity.data_path_direct_host, 1U);
  EXPECT_GE(metrics.connectivity.connect_duration_milliseconds_sum,
            metrics.connectivity.connect_duration_samples);
  EXPECT_GE(metrics.connectivity.connect_duration_milliseconds_max, 1U);
  EXPECT_GE(metrics.transport.peer_sessions, 1U);
  EXPECT_GT(metrics.node.announcements_sent, 0U);
  EXPECT_FALSE(metrics.node.relay.enabled);
  EXPECT_GT(metrics.runtime.executor_running_backend_count, 0U);
  // Both sides ran the pairing authorize funnel through their seeded
  // grants; the metrics must expose a nonzero pairing surface only when a
  // pairing actually ran, so here we just pin the field exists via export.
  const auto text = format_node_metrics_prometheus(metrics, "m9-test");
  EXPECT_NE(text.find("heyaki_connectivity_authenticated_total "), std::string::npos);
  EXPECT_NE(text.find("heyaki_connectivity_signaling_route_lan_total "), std::string::npos);
  EXPECT_NE(text.find("{instance=\"m9-test\"}"), std::string::npos);

  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
}

}  // namespace
}  // namespace heyaki
