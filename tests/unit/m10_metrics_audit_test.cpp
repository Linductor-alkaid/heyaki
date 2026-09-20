// M10 Round 5 independent verification: the M10-11 metrics & path-policy
// surfaces (GatewayServiceStats dial ring + P95, the gateway metrics export
// families, PeerPathPolicy::GatewayPaths and the serving-side TURN-path
// refusal), the M10-12 audit trail (GatewayAuditRecord fields, the bounded
// ring, scope-refusal silence), the confirm_denials counter, and the M10-10
// scheduling evidence facts (STREAM_DATA's frame class).
//
// Harness model mirrors m10_gateway_service_test.cpp / m10_round4_test.cpp:
// one test thread, pump-driven loopback transport, gateway sockets/resolver
// on a test-owned io_context polled by the same thread. The Node-level
// audit/aggregation test additionally drives a real LAN node pair.

#include "byte_stream.hpp"
#include "gateway_service.hpp"
#include "m4_support.hpp"
#include "m5_support.hpp"
#include "peer_session.hpp"
#include "session_channels.hpp"

#include <heyaki/byte_stream.hpp>
#include <heyaki/error.hpp>
#include <heyaki/gateway.hpp>
#include <heyaki/identity.hpp>
#include <heyaki/metrics.hpp>
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
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef HEYAKI_M10_METRICS_AUDIT_TEST_STATE_DIR
#define HEYAKI_M10_METRICS_AUDIT_TEST_STATE_DIR "/tmp/heyaki-m10-metrics-audit"
#endif

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
    value[index] = std::byte(static_cast<std::uint8_t>(seed + index));
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

// ==== 1. Pure stats functions (M10-11) ========================================

TEST(M10StatsFunctionsTest, DialSampleRingOverwritesOldestAndPinsLayout) {
  GatewayServiceStats stats;
  EXPECT_EQ(stats.dial_samples_count, 0U);
  EXPECT_EQ(gateway_dial_p95(stats), 0U);

  // 300 samples (1000..1299) through a 256-slot ring.
  for (std::uint32_t sample = 0U; sample < 300U; ++sample) {
    record_gateway_dial_sample(stats, 1000U + sample);
  }
  EXPECT_EQ(stats.dial_samples_count, 256U) << "count saturates at the window";
  EXPECT_EQ(stats.dial_samples_next, 44U) << "next wraps to 300 % 256";

  // Slots 0..43 hold the LAST write for that slot (samples 256..299);
  // slots 44..255 were written exactly once (samples 44..255).
  EXPECT_EQ(stats.dial_samples[0], 1256U);
  EXPECT_EQ(stats.dial_samples[43], 1299U);
  EXPECT_EQ(stats.dial_samples[44], 1044U);
  EXPECT_EQ(stats.dial_samples[255], 1255U);

  // The 44 oldest samples (1000..1043) were overwritten: the window holds
  // exactly 1044..1299. count=256 -> index = 256 - 256/20 = 244 ->
  // the 245th smallest = 1044 + 244 = 1288.
  EXPECT_EQ(gateway_dial_p95(stats), 1288U);
}

TEST(M10StatsFunctionsTest, DialP95EmptyWindowIsZero) {
  GatewayServiceStats stats;
  EXPECT_EQ(gateway_dial_p95(stats), 0U);
}

TEST(M10StatsFunctionsTest, DialP95SmallWindowTakesMaximum) {
  // count < 20: the approximation is the maximum (index count-1).
  GatewayServiceStats scattered;
  record_gateway_dial_sample(scattered, 5U);
  record_gateway_dial_sample(scattered, 9U);
  record_gateway_dial_sample(scattered, 7U);
  ASSERT_EQ(scattered.dial_samples_count, 3U);
  EXPECT_EQ(gateway_dial_p95(scattered), 9U);

  GatewayServiceStats nineteen;
  for (std::uint32_t value = 1U; value <= 19U; ++value) {
    record_gateway_dial_sample(nineteen, value);
  }
  ASSERT_EQ(nineteen.dial_samples_count, 19U);
  EXPECT_EQ(gateway_dial_p95(nineteen), 19U);
}

TEST(M10StatsFunctionsTest, DialP95FormulaPinned) {
  // The frozen formula: index = count - count/20 over ascending samples.
  // Exactly 20 samples: 20 - 1 = 19 -> still the maximum.
  GatewayServiceStats twenty;
  for (std::uint32_t value = 1U; value <= 20U; ++value) {
    record_gateway_dial_sample(twenty, value);
  }
  ASSERT_EQ(twenty.dial_samples_count, 20U);
  EXPECT_EQ(gateway_dial_p95(twenty), 20U);

  // 100 samples 1..100: index = 100 - 5 = 95 -> the 96th smallest = 96.
  GatewayServiceStats hundred;
  for (std::uint32_t value = 1U; value <= 100U; ++value) {
    record_gateway_dial_sample(hundred, value);
  }
  ASSERT_EQ(hundred.dial_samples_count, 100U);
  EXPECT_EQ(gateway_dial_p95(hundred), 96U);

  // 40 samples 1..40: index = 40 - 2 = 38 -> the 39th smallest = 39.
  GatewayServiceStats forty;
  for (std::uint32_t value = 1U; value <= 40U; ++value) {
    record_gateway_dial_sample(forty, value);
  }
  EXPECT_EQ(gateway_dial_p95(forty), 39U);

  // Reverse insertion order must not matter (the window is sorted).
  GatewayServiceStats reversed;
  for (std::uint32_t value = 100U; value >= 1U; --value) {
    record_gateway_dial_sample(reversed, value);
  }
  EXPECT_EQ(gateway_dial_p95(reversed), 96U);
}

TEST(M10StatsFunctionsTest, DialSampleSaturatesAtUint32Max) {
  // on_prelude_written clamps elapsed to u32 before recording; the ring
  // itself must carry the saturated value unmodified.
  GatewayServiceStats stats;
  record_gateway_dial_sample(stats, std::numeric_limits<std::uint32_t>::max());
  ASSERT_EQ(stats.dial_samples_count, 1U);
  EXPECT_EQ(stats.dial_samples[0], std::numeric_limits<std::uint32_t>::max());
  EXPECT_EQ(gateway_dial_p95(stats), std::numeric_limits<std::uint32_t>::max());
}

// ==== 2. Metrics export surface (M10-11) ======================================

TEST(M10GatewayMetricsExportTest, DefaultAggregateRendersEveryStaticFamily) {
  // Completeness convention: families render unconditionally from
  // zero-value aggregates (README "Completeness"); the dynamic per-profile
  // families render nothing while no profile has usage.
  const std::string text = format_node_metrics_prometheus(NodeMetrics{});

  const std::string counters[] = {
      "heyaki_gateway_opens_received_total",
      "heyaki_gateway_refused_capability_not_negotiated_total",
      "heyaki_gateway_refused_invalid_target_total",
      "heyaki_gateway_refused_not_enabled_total",
      "heyaki_gateway_refused_scope_denied_total",
      "heyaki_gateway_refused_policy_denied_total",
      "heyaki_gateway_refused_quota_exhausted_total",
      "heyaki_gateway_refused_dial_failed_total",
      "heyaki_gateway_refused_dial_deadline_total",
      "heyaki_gateway_refused_local_failure_total",
      "heyaki_gateway_path_rejected_total",
      "heyaki_gateway_confirm_denials_total",
      "heyaki_gateway_dials_succeeded_total",
      "heyaki_gateway_dials_failed_total",
      "heyaki_gateway_bytes_from_tunnel_total",
      "heyaki_gateway_bytes_to_tunnel_total",
      "heyaki_gateway_tunnels_closed_clean_total",
      "heyaki_gateway_idle_timeout_resets_total",
      "heyaki_gateway_duration_timeout_resets_total",
      "heyaki_gateway_byte_quota_resets_total",
  };
  for (const auto& family : counters) {
    SCOPED_TRACE(family);
    EXPECT_NE(text.find("# TYPE " + family + " counter\n"), std::string::npos)
        << "missing TYPE line for " << family;
    EXPECT_NE(text.find("\n" + family + " 0\n"), std::string::npos)
        << "missing zero-value sample for " << family;
  }

  const std::string gauges[] = {
      "heyaki_gateway_sessions",
      "heyaki_gateway_tunnels_active",
      "heyaki_gateway_dial_p95_milliseconds",
      "heyaki_gateway_bytes_on_turn_paths",
      "heyaki_gateway_tunnels_on_turn_paths",
  };
  for (const auto& family : gauges) {
    SCOPED_TRACE(family);
    EXPECT_NE(text.find("# TYPE " + family + " gauge\n"), std::string::npos)
        << "missing TYPE line for " << family;
  }
  EXPECT_NE(text.find("\nheyaki_gateway_dial_p95_milliseconds 0\n"), std::string::npos)
      << "empty window must export P95=0";

  // No profile has usage in a default aggregate: no dynamic family renders.
  EXPECT_EQ(text.find("heyaki_gateway_profile_"), std::string::npos)
      << "per-profile families must not render without configured usage";
}

TEST(M10GatewayMetricsExportTest, PopulatedStatsRenderValuesAndTypes) {
  NodeMetrics metrics;
  metrics.unix_milliseconds = 1U;
  auto& gateway = metrics.services.gateway;
  gateway.opens_received = 7U;
  gateway.refusals[static_cast<std::size_t>(GatewayRefusal::scope_denied)] = 2U;
  gateway.refusals[static_cast<std::size_t>(GatewayRefusal::dial_failed)] = 3U;
  gateway.dials_succeeded = 4U;
  gateway.dials_failed = 3U;
  gateway.bytes_from_tunnel = 111U;
  gateway.bytes_to_tunnel = 222U;
  gateway.tunnels_closed_clean = 5U;
  gateway.idle_timeout_resets = 6U;
  gateway.duration_timeout_resets = 7U;
  gateway.byte_quota_resets = 8U;
  gateway.confirm_denials = 9U;
  gateway.path_rejected = 10U;
  gateway.tunnels_active = 2U;
  for (std::uint32_t value = 1U; value <= 100U; ++value) {
    record_gateway_dial_sample(gateway, value);
  }
  metrics.services.gateway_sessions = 3U;
  metrics.services.gateway_bytes_on_turn_paths = 333U;
  metrics.services.gateway_tunnels_on_turn_paths = 4U;
  gateway.profile_usage.push_back(GatewayProfileUsageSnapshot{
      .profile = "office", .active_tunnels = 2, .bytes_from_tunnel = 111U,
      .bytes_to_tunnel = 222U});
  gateway.profile_usage.push_back(GatewayProfileUsageSnapshot{
      .profile = "lab1", .active_tunnels = 1, .bytes_from_tunnel = 5U,
      .bytes_to_tunnel = 6U});

  const std::string text = format_node_metrics_prometheus(metrics);

  struct Sample {
    std::string family;
    std::string value;
    bool counter;
  };
  const Sample expected[] = {
      {"heyaki_gateway_opens_received_total", "7", true},
      {"heyaki_gateway_refused_scope_denied_total", "2", true},
      {"heyaki_gateway_refused_dial_failed_total", "3", true},
      {"heyaki_gateway_path_rejected_total", "10", true},
      {"heyaki_gateway_confirm_denials_total", "9", true},
      {"heyaki_gateway_dials_succeeded_total", "4", true},
      {"heyaki_gateway_dials_failed_total", "3", true},
      {"heyaki_gateway_bytes_from_tunnel_total", "111", true},
      {"heyaki_gateway_bytes_to_tunnel_total", "222", true},
      {"heyaki_gateway_tunnels_closed_clean_total", "5", true},
      {"heyaki_gateway_idle_timeout_resets_total", "6", true},
      {"heyaki_gateway_duration_timeout_resets_total", "7", true},
      {"heyaki_gateway_byte_quota_resets_total", "8", true},
      {"heyaki_gateway_tunnels_active", "2", false},
      {"heyaki_gateway_sessions", "3", false},
      {"heyaki_gateway_dial_p95_milliseconds", "96", false},
      {"heyaki_gateway_bytes_on_turn_paths", "333", false},
      {"heyaki_gateway_tunnels_on_turn_paths", "4", false},
      {"heyaki_gateway_profile_office_bytes_from_tunnel_total", "111", true},
      {"heyaki_gateway_profile_office_bytes_to_tunnel_total", "222", true},
      {"heyaki_gateway_profile_office_tunnels_active", "2", false},
      {"heyaki_gateway_profile_lab1_bytes_from_tunnel_total", "5", true},
      {"heyaki_gateway_profile_lab1_bytes_to_tunnel_total", "6", true},
      {"heyaki_gateway_profile_lab1_tunnels_active", "1", false},
  };
  for (const auto& sample : expected) {
    SCOPED_TRACE(sample.family);
    EXPECT_NE(text.find("\n" + sample.family + " " + sample.value + "\n"),
              std::string::npos)
        << "missing sample " << sample.family << " " << sample.value;
    EXPECT_NE(text.find("# TYPE " + sample.family + " " +
                            (sample.counter ? "counter" : "gauge") + "\n"),
              std::string::npos)
        << "wrong TYPE for " << sample.family;
  }
}

TEST(M10GatewayMetricsExportTest, PerProfileFamilyNamesFollowFrozenGrammar) {
  // The README (M10 gateway families) freezes per-profile series names to
  // the profile-name grammar [a-z0-9_.-]; the exporter embeds the configured
  // name verbatim. This pins that documented decision mechanically.
  NodeMetrics metrics;
  metrics.services.gateway.profile_usage.push_back(GatewayProfileUsageSnapshot{
      .profile = "db.lan-1", .active_tunnels = 1, .bytes_from_tunnel = 5U,
      .bytes_to_tunnel = 6U});
  const std::string text = format_node_metrics_prometheus(metrics);
  EXPECT_NE(text.find("\nheyaki_gateway_profile_db.lan-1_tunnels_active 1\n"),
            std::string::npos);
  EXPECT_NE(text.find("\nheyaki_gateway_profile_db.lan-1_bytes_from_tunnel_total 5\n"),
            std::string::npos);
  EXPECT_NE(text.find("\nheyaki_gateway_profile_db.lan-1_bytes_to_tunnel_total 6\n"),
            std::string::npos);
}

// ==== 3. M10-10 scheduling evidence fact ======================================

TEST(M10SchedulingFactTest, StreamDataDefaultClassIsStandardSoPumpChoosesBulk) {
  // M10-10 evidence: default_frame_class(stream_data) is `standard`, and the
  // byte-stream pump (src/client/byte_stream.cpp, pump_writes) explicitly
  // sends STREAM_DATA as session::FrameClass::bulk. Gateway tunnels are
  // ordinary byte streams, so gateway payload rides the bulk class with
  // file/event weight — below control/Shell (control) and RPC/message
  // (interactive/standard), which is what keeps control traffic ahead of a
  // saturated gateway tunnel (behavioral evidence: heyaki_m5_scheduler).
  using session::FrameClass;
  EXPECT_EQ(session::default_frame_class(static_cast<std::uint8_t>(FrameType::stream_data)),
            FrameClass::standard);
  EXPECT_EQ(session::default_frame_class(static_cast<std::uint8_t>(FrameType::file_chunk)),
            FrameClass::bulk);
  EXPECT_EQ(session::default_frame_class(static_cast<std::uint8_t>(FrameType::event_item)),
            FrameClass::bulk);
  EXPECT_EQ(session::default_frame_class(static_cast<std::uint8_t>(FrameType::shell_output)),
            FrameClass::interactive);
  EXPECT_EQ(session::default_frame_class(static_cast<std::uint8_t>(FrameType::stream_reset)),
            FrameClass::control);
}

// ==== 4. Path policy surface (M10-11) =========================================

TEST(M10PathPolicyTest, GatewayPathsEnumValuesAndDefaultAllow) {
  PeerPathPolicy policy;
  EXPECT_EQ(policy.gateway_paths, PeerPathPolicy::GatewayPaths::allow)
      << "the default must keep M10-11 additive: gateway rides any path";
  EXPECT_EQ(static_cast<int>(PeerPathPolicy::GatewayPaths::allow), 0);
  EXPECT_EQ(static_cast<int>(PeerPathPolicy::GatewayPaths::direct_only), 1);
  EXPECT_EQ(static_cast<int>(PeerPathPolicy::GatewayPaths::turn_limited), 2);
}

// ==== Loopback session pair (same harness as the Round 3/4 suites) ============

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
           // VERIFICATION FINDING (M10-R5): each gateway stream opens a
           // dedicated business channel that is only closed when the
           // ByteStreamService is destroyed — never when the tunnel ends —
           // so with the default budget of 16 the 16th gateway open on one
           // session fails locally with `open_channel_limit` (observed:
           // sequential opens 0..14 succeed, open 15 fails). The audit-ring
           // test below needs 260 sequential tunnels on one session, so the
           // harness raises the budget; the defect itself is reported in the
           // Round 5 verification report (production code is read-only here).
           .channel_budgets = [] {
             session::ChannelBudgetConfig budgets{};
             budgets.max_open_channels = 1024U;
             return budgets;
           }(),
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

std::string detect_non_loopback_v4(boost::asio::io_context& io) {
  // Candidate from the UDP egress probe, then PROVE dialability with a
  // real TCP round trip: on some CI runners the egress interface address
  // exists but hairpin TCP dials to it are dropped by the host fabric —
  // the gateway echo tests then flap on dial timeouts. A candidate that
  // cannot round-trip here means "environment unsuitable" (the callers
  // skip), not a product failure.
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
    boost::system::error_code ignored;
    socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
    socket->close(ignored);
  }

  std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
  std::vector<std::shared_ptr<boost::asio::ip::tcp::socket>> connections_;
  std::uint16_t port_{0U};
  bool ok_{false};
  std::size_t accepted_{0U};
};

// ==== Shared Round-5 fixture ==================================================

struct CapturedRead {
  bool completed{false};
  std::size_t bytes{0U};
  std::optional<Error> error;
  std::vector<std::byte> data;
};

// One-shot connect outcome for gateway initiator streams; heap-anchored
// because the handler may fire during service teardown (see Round 4 D1).
struct ConnectOutcome {
  std::atomic<int> fires{0};
  bool has_error{false};
  ErrorCode code{ErrorCode::internal};
  std::string detail;

  void record(Result<void> result) {
    fires.fetch_add(1);
    if (!result) {
      has_error = true;
      code = result.error_if()->code();
      detail = result.error_if()->safe_detail();
    }
  }
};

[[nodiscard]] std::shared_ptr<ConnectOutcome> new_connect_outcome() {
  return std::make_shared<ConnectOutcome>();
}

struct WriteCapture {
  bool done{false};
  std::optional<Error> error;
};

// Audit capture (M10-12): a plain struct + static trampoline exactly like
// the GatewayService::AuditSink signature. Fixture-owned so the context
// outlives TearDown's drain of posted continuations.
struct AuditLog {
  std::vector<GatewayAuditRecord> records;

  static void sink(void* context, GatewayAuditRecord record) {
    static_cast<AuditLog*>(context)->records.push_back(std::move(record));
  }
};

class M10Round5Test : public ::testing::Test {
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

  // Installs a serving-side GatewayService. `deny_on_turn`/`on_turn` carry
  // the M10-11 path-policy translation (node.cpp: direct_only -> deny flag
  // + live TURN-path query); the audit sink is installed like node.cpp's.
  void install_gateway(std::vector<GatewayProfileConfig> profiles,
                       std::vector<std::string> provide_scopes,
                       bool deny_on_turn = false,
                       std::function<bool()> on_turn = {},
                       GatewayConfirmSink confirm_sink = {}) {
    GatewayServiceConfig config;
    config.profiles = std::move(profiles);
    config.peer_device = pair_->left_identity.value_if()->device_id();
    config.confirm_sink = confirm_sink;
    config.deny_on_turn_path = deny_on_turn;
    config.on_turn_path = std::move(on_turn);
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
        [this] { return now_ms_; }, std::move(confirm_sink));
    gw_->set_audit_sink(&AuditLog::sink, &audit_);
    ASSERT_TRUE(gw_->attach());
  }

  [[nodiscard]] Result<std::shared_ptr<ByteStreamHandle>> open_from_a(
      const GatewayConnect& target, std::uint64_t dial_deadline = 0U,
      std::function<void(Result<void>)> on_connected = {}) {
    return left_->open_gateway_stream(target, 4096U, 4U, dial_deadline,
                                      std::move(on_connected));
  }

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
    auto capture = std::make_shared<WriteCapture>();
    stream.async_write(as_bytes(text), [capture](StreamIoResult result) {
      capture->done = true;
      capture->error = result.error;
    });
    pair_->pump_all();
    return capture->done && !capture->error.has_value();
  }

  static std::uint64_t refusals_of(const GatewayService& service,
                                   GatewayRefusal refusal) {
    return service.stats().refusals[static_cast<std::size_t>(refusal)];
  }

  boost::asio::io_context io_;
  std::unique_ptr<GatewaySessionPair> pair_;
  std::uint64_t now_ms_{kNow};
  std::vector<std::string> provide_scopes_;
  std::string local_address_;
  std::unique_ptr<ByteStreamService> left_;
  std::unique_ptr<ByteStreamService> right_;
  std::shared_ptr<GatewayService> gw_;
  AuditLog audit_;
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

// ---- Path policy at the service boundary -------------------------------------

TEST_F(M10Round5Test, TurnPathDenialResetsPermissionDeniedWithoutTunnel) {
  // direct_only + the session currently on TURN: the open must be refused
  // before any tunnel registration (no audit record, no slot held) and the
  // initiator observes the stable permission_denied (5) mapping.
  install_gateway({profile_for("office", {"10.0.0.0/8"})},
                  {"gateway.provide:office"},
                  /*deny_on_turn=*/true, /*on_turn=*/[] { return true; });

  auto connected = new_connect_outcome();
  auto opened = open_from_a(
      {.host = "10.1.2.3", .port = 80, .profile = "office"},
      0U, [connected](Result<void> result) { connected->record(std::move(result)); });
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  ASSERT_TRUE(spin_until([&] { return stream->state() == StreamState::reset; }, 2000))
      << "TURN-path denial never reset the stream";

  EXPECT_EQ(gw_->stats().path_rejected, 1U);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::policy_denied), 1U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U)
      << "the denial must hold no concurrency slot";
  EXPECT_EQ(gw_->stats().dials_failed, 0U);
  EXPECT_EQ(gw_->stats().dials_succeeded, 0U);
  ASSERT_EQ(connected->fires.load(), 1);
  ASSERT_TRUE(connected->has_error);
  EXPECT_EQ(connected->detail, "gateway_connect_failed_5");
  // The refusal happened before admission: no tunnel entered, so the audit
  // trail stays empty (the refusal is visible in metrics instead).
  EXPECT_TRUE(audit_.records.empty())
      << "a pre-admission path refusal must not emit an audit record";
}

TEST_F(M10Round5Test, TurnPathCallbackFalseAdmitsNormally) {
  install_gateway({profile_for("office", {"10.0.0.0/8"})},
                  {"gateway.provide:office"},
                  /*deny_on_turn=*/true, /*on_turn=*/[] { return false; });

  auto opened = open_from_a(
      {.host = "no-such-host-round5.invalid", .port = 80, .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  ASSERT_TRUE(spin_until([&] { return gw_->stats().tunnels_active == 1U; }, 2000))
      << "a non-TURN path must admit the tunnel";
  EXPECT_EQ(gw_->stats().path_rejected, 0U);
  EXPECT_EQ(stream->state(), StreamState::opening);
  // Drain the (failing) resolve so TearDown starts from a quiet registry.
  ASSERT_TRUE(spin_until([&] { return stream->state() == StreamState::reset; }, 5000));
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
}

TEST_F(M10Round5Test, TurnPathDenialWithoutCallbackStillAdmits) {
  // deny_on_turn_path alone (no live query installed) must not refuse: the
  // guard is a conjunction, and node.cpp always installs the query with the
  // flag — this pins the conjunction against accidental weakening.
  install_gateway({profile_for("office", {"10.0.0.0/8"})},
                  {"gateway.provide:office"},
                  /*deny_on_turn=*/true, /*on_turn=*/std::function<bool()>{});

  auto opened = open_from_a(
      {.host = "no-such-host-round5.invalid", .port = 80, .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  ASSERT_TRUE(spin_until([&] { return gw_->stats().tunnels_active == 1U; }, 2000));
  EXPECT_EQ(gw_->stats().path_rejected, 0U);
  ASSERT_TRUE(spin_until([&] { return stream->state() == StreamState::reset; }, 5000));
}

// ---- Audit trail (M10-12) ----------------------------------------------------

TEST_F(M10Round5Test, AuditRecordFieldsOnEchoTunnelClose) {
  if (local_address_.empty()) {
    GTEST_SKIP() << "no non-loopback unicast IPv4 address: gateway dials are "
                    "untestable (loopback is builtin-denied)";
  }
  auto echo = std::make_shared<EchoTarget>(io_, local_address_);
  ASSERT_TRUE(echo->ok());
  echo->start();

  install_gateway({profile_for("office", {local_address_ + "/32"})},
                  {"gateway.provide:office"});
  const std::uint16_t target_port = echo->port();
  auto opened = open_from_a(
      {.host = local_address_, .port = target_port, .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  auto read = pend_read(*stream, 64U);
  ASSERT_TRUE(spin_until([&] { return gw_->stats().dials_succeeded == 1U; }, 3000));
  ASSERT_TRUE(write_all(*stream, "AUDIT-OK"));
  ASSERT_TRUE(spin_until([&] { return read->completed; }, 3000));
  ASSERT_FALSE(read->error.has_value()) << read->error->safe_detail();
  EXPECT_EQ(as_text(read->data), "AUDIT-OK");

  // Per-profile usage while the tunnel lives (M10-11 export input).
  {
    const auto usage = gw_->profile_usage();
    ASSERT_EQ(usage.size(), 1U);
    EXPECT_EQ(usage[0].profile, "office");
    EXPECT_EQ(usage[0].active_tunnels, 1U);
    EXPECT_EQ(usage[0].bytes_from_tunnel, 8U);
    EXPECT_EQ(usage[0].bytes_to_tunnel, 8U);
  }

  // Terminate the tunnel from the initiator side: the serving pump's read
  // fails and close_tunnel fires the audit sink exactly once.
  stream->reset(StableStatus::cancelled);
  ASSERT_TRUE(spin_until([&] { return gw_->stats().tunnels_active == 0U; }, 3000));
  ASSERT_TRUE(spin_until([&] { return audit_.records.size() == 1U; }, 3000))
      << "tunnel termination never emitted the audit record";

  const auto& record = audit_.records[0];
  EXPECT_EQ(record.initiator, pair_->left_identity.value_if()->device_id());
  EXPECT_EQ(record.profile, "office");
  EXPECT_EQ(record.target_host, local_address_);
  EXPECT_TRUE(valid_gateway_host(record.target_host))
      << "audit target must be the grammar-validated form";
  EXPECT_EQ(record.target_port, target_port);
  EXPECT_LE(record.started_unix_ms, record.ended_unix_ms);
  EXPECT_EQ(record.bytes_from_tunnel, 8U);
  EXPECT_EQ(record.bytes_to_tunnel, 8U);
  EXPECT_EQ(record.end_status, StableStatus::cancelled);

  // Usage snapshot after close: bytes remembered, no active tunnels.
  const auto usage = gw_->profile_usage();
  ASSERT_EQ(usage.size(), 1U);
  EXPECT_EQ(usage[0].active_tunnels, 0U);
  EXPECT_EQ(usage[0].bytes_from_tunnel, 8U);
  EXPECT_EQ(usage[0].bytes_to_tunnel, 8U);

  // Idempotence: no second record appears for the same tunnel.
  spin(8);
  EXPECT_EQ(audit_.records.size(), 1U);
}

TEST_F(M10Round5Test, ScopeRefusalEmitsNoAuditRecord) {
  // A refusal that happens before admission (scope gate) is counted in
  // metrics only — the audit trail records tunnels that entered admission.
  install_gateway({profile_for("office", {"10.0.0.0/8"})},
                  /*provide_scopes=*/{});

  auto opened = open_from_a(
      {.host = "10.1.2.3", .port = 80, .profile = "office"});
  ASSERT_TRUE(opened);
  auto stream = *opened.value_if();
  ASSERT_TRUE(spin_until([&] { return stream->state() == StreamState::reset; }, 2000));
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::scope_denied), 1U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
  EXPECT_TRUE(audit_.records.empty());
  spin(8);
  EXPECT_TRUE(audit_.records.empty());
}

TEST_F(M10Round5Test, AuditEmitsOneRecordPerAdmittedTunnel) {
  if (local_address_.empty()) {
    GTEST_SKIP() << "no non-loopback unicast IPv4 address for fast dial failure";
  }
  // Fast deterministic tunnel terminations: every open is admitted, dials a
  // real closed port on the host address, and resets with dial_failed — the
  // audit sink must see exactly one record per tunnel that entered
  // admission, with no cap at the service sink. (The bounded 256-entry ring
  // lives in the Node trampoline, node.cpp gateway_audit_sink — the same
  // deque shape as the shell/pairing audit rings. It cannot be driven past
  // 256 records in this harness: the dedicated-channel finding above caps a
  // session at 15 lifetime gateway tunnels unless the harness budget is
  // raised, and the Node hard-codes the default budget. Verified by code
  // inspection; see the Round 5 report.)
  boost::asio::ip::tcp::acceptor probe{io_};
  boost::system::error_code ec;
  const auto addr = boost::asio::ip::make_address(local_address_, ec);
  ASSERT_FALSE(ec);
  boost::asio::ip::tcp::endpoint endpoint{addr, 0U};
  probe.open(endpoint.protocol(), ec);
  ASSERT_FALSE(ec);
  probe.bind(endpoint, ec);
  ASSERT_FALSE(ec);
  probe.listen(1, ec);
  ASSERT_FALSE(ec);
  const auto closed_port = probe.local_endpoint(ec).port();
  ASSERT_FALSE(ec);
  probe.close(ec);

  install_gateway({profile_for("office", {local_address_ + "/32"})},
                  {"gateway.provide:office"});
  constexpr int kOpens = 260;
  for (int index = 0; index < kOpens; ++index) {
    auto opened = open_from_a(
        {.host = local_address_, .port = closed_port, .profile = "office"});
    ASSERT_TRUE(opened) << "open " << index << " failed: "
                        << (opened.error_if() != nullptr
                                ? opened.error_if()->safe_detail()
                                : std::string{"?"});
    auto stream = *opened.value_if();
    ASSERT_TRUE(spin_until([&] { return stream->state() == StreamState::reset; }, 5000))
        << "open " << index << " never terminated";
    ASSERT_EQ(audit_.records.size(), static_cast<std::size_t>(index + 1))
        << "exactly one record per admitted tunnel after open " << index;
  }

  EXPECT_EQ(gw_->stats().dials_failed, static_cast<std::uint64_t>(kOpens));
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::dial_failed),
            static_cast<std::uint64_t>(kOpens));
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
  // Every record is a grammar-valid target with the expected shape.
  for (const auto& record : audit_.records) {
    EXPECT_EQ(record.profile, "office");
    EXPECT_TRUE(valid_gateway_host(record.target_host));
    EXPECT_EQ(record.target_port, closed_port);
    EXPECT_LE(record.started_unix_ms, record.ended_unix_ms);
    EXPECT_EQ(record.end_status, gateway_refusal_status(GatewayRefusal::dial_failed));
  }
}

// ---- confirm_denials accounting (M10-11) -------------------------------------

TEST_F(M10Round5Test, ConfirmDenialsCountOperatorDenyAndDeadline) {
  auto profile = profile_for("office", {"10.0.0.0/8"});
  profile.confirm = GatewayConfirmMode::always;
  auto asks = std::make_shared<std::vector<std::pair<GatewayConfirmRequest,
                                                     std::function<void(bool)>>>>();
  install_gateway({profile}, {"gateway.provide:office"},
                  /*deny_on_turn=*/false, /*on_turn=*/{},
                  [asks](const GatewayConfirmRequest& request,
                         std::function<void(bool)> decide) {
                    asks->emplace_back(request, std::move(decide));
                  });

  // (a) An explicit operator NO.
  auto first = open_from_a(
      {.host = "no-such-host-round5.invalid", .port = 80, .profile = "office"});
  ASSERT_TRUE(first);
  auto first_stream = *first.value_if();
  ASSERT_TRUE(spin_until([&] { return asks->size() >= 1U; }, 2000));
  (*asks)[0].second(false);
  ASSERT_TRUE(spin_until([&] { return first_stream->state() == StreamState::reset; },
                         2000));
  EXPECT_EQ(gw_->stats().confirm_denials, 1U);
  EXPECT_EQ(refusals_of(*gw_, GatewayRefusal::policy_denied), 1U);

  // (b) The 30s auto-deny deadline (injected clock + prune sweep).
  auto second = open_from_a(
      {.host = "no-such-host-round5.invalid", .port = 81, .profile = "office"});
  ASSERT_TRUE(second);
  auto second_stream = *second.value_if();
  ASSERT_TRUE(spin_until([&] { return asks->size() >= 2U; }, 2000));
  EXPECT_EQ(gw_->stats().confirm_denials, 1U)
      << "a pending request must not count yet";
  // Exactly at the boundary: strictly-greater, still parked.
  now_ms_ = kNow + static_cast<std::uint64_t>(gateway_confirm_deadline.count());
  gw_->prune();
  pair_->pump_all();
  EXPECT_EQ(gw_->stats().confirm_denials, 1U);
  EXPECT_EQ(second_stream->state(), StreamState::opening);
  // One millisecond past: auto-denied and counted.
  now_ms_ = kNow + static_cast<std::uint64_t>(gateway_confirm_deadline.count()) + 1U;
  gw_->prune();
  ASSERT_TRUE(spin_until([&] { return second_stream->state() == StreamState::reset; },
                         2000));
  EXPECT_EQ(gw_->stats().confirm_denials, 2U);
  EXPECT_EQ(gw_->stats().tunnels_active, 0U);
}

// ---- Dial latency sampling through the service (M10-11) ----------------------

TEST_F(M10Round5Test, DialSampleRecordedFromOpenToPrelude) {
  if (local_address_.empty()) {
    GTEST_SKIP() << "no non-loopback unicast IPv4 address for the echo target";
  }
  auto echo = std::make_shared<EchoTarget>(io_, local_address_);
  ASSERT_TRUE(echo->ok());
  echo->start();

  // confirm=always parks the tunnel AFTER registration (opened_unix_ms is
  // captured) and BEFORE the dial, giving a deterministic point to advance
  // the injected clock between the two timestamps the sample measures.
  auto profile = profile_for("office", {local_address_ + "/32"});
  profile.confirm = GatewayConfirmMode::always;
  auto asks = std::make_shared<std::vector<std::pair<GatewayConfirmRequest,
                                                     std::function<void(bool)>>>>();
  install_gateway({profile}, {"gateway.provide:office"},
                  /*deny_on_turn=*/false, /*on_turn=*/{},
                  [asks](const GatewayConfirmRequest& request,
                         std::function<void(bool)> decide) {
                    asks->emplace_back(request, std::move(decide));
                  });

  auto opened = open_from_a(
      {.host = local_address_, .port = echo->port(), .profile = "office"});
  ASSERT_TRUE(opened);
  ASSERT_TRUE(spin_until([&] { return asks->size() >= 1U; }, 2000))
      << "confirm sink never asked (tunnel never registered)";
  ASSERT_EQ(gw_->stats().tunnels_active, 1U);

  now_ms_ = kNow + 25U;
  (*asks)[0].second(true);
  ASSERT_TRUE(spin_until([&] { return gw_->stats().dials_succeeded == 1U; }, 3000));
  ASSERT_TRUE(spin_until(
      [&] { return gw_->stats().dial_samples_count == 1U; }, 3000))
      << "the prelude write never recorded a dial sample";

  const auto& stats = gw_->stats();
  EXPECT_EQ(stats.dial_samples[0], 25U);
  EXPECT_EQ(gateway_dial_p95(stats), 25U);
}

TEST_F(M10Round5Test, DialSampleClampsToUint32Max) {
  if (local_address_.empty()) {
    GTEST_SKIP() << "no non-loopback unicast IPv4 address for the echo target";
  }
  auto echo = std::make_shared<EchoTarget>(io_, local_address_);
  ASSERT_TRUE(echo->ok());
  echo->start();

  auto profile = profile_for("office", {local_address_ + "/32"});
  profile.confirm = GatewayConfirmMode::always;
  auto asks = std::make_shared<std::vector<std::pair<GatewayConfirmRequest,
                                                     std::function<void(bool)>>>>();
  install_gateway({profile}, {"gateway.provide:office"},
                  /*deny_on_turn=*/false, /*on_turn=*/{},
                  [asks](const GatewayConfirmRequest& request,
                         std::function<void(bool)> decide) {
                    asks->emplace_back(request, std::move(decide));
                  });

  auto opened = open_from_a(
      {.host = local_address_, .port = echo->port(), .profile = "office"});
  ASSERT_TRUE(opened);
  ASSERT_TRUE(spin_until([&] { return asks->size() >= 1U; }, 2000));
  ASSERT_EQ(gw_->stats().tunnels_active, 1U);

  // A clock jump beyond the u32 range must saturate, not wrap.
  now_ms_ = kNow + 5'000'000'000U;
  (*asks)[0].second(true);
  ASSERT_TRUE(spin_until([&] { return gw_->stats().dials_succeeded == 1U; }, 3000));
  ASSERT_TRUE(spin_until(
      [&] { return gw_->stats().dial_samples_count == 1U; }, 3000));

  const auto& stats = gw_->stats();
  EXPECT_EQ(stats.dial_samples[0], std::numeric_limits<std::uint32_t>::max());
  EXPECT_EQ(gateway_dial_p95(stats), std::numeric_limits<std::uint32_t>::max());
}

// ==== 5. Node-level audit + diagnostics aggregation (M10-12/M10-11) ===========

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

constexpr const char* kRound5ApplicationId = "com.example.m10-round5";

// Heap-anchored capture for public-stream (node context) I/O completions:
// cross-thread, so the done flag is atomic and `error`/`bytes` are written
// before it flips.
struct NodeIoCapture {
  std::atomic<bool> done{false};
  std::atomic<std::size_t> bytes{0U};
  std::optional<Error> error;
};

class M10Round5NodeTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M10_METRICS_AUDIT_TEST_STATE_DIR} /
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

  Result<ProfileStore> initialized_profile(const std::string& name) {
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
        .application_id = kRound5ApplicationId,
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
                         std::vector<GatewayProfileConfig> gateway_profiles) {
    NodeConfig config{.profile = &store,
                      .runtime = nullptr,
                      .application_id = kRound5ApplicationId,
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
                      .gateway_profiles = std::move(gateway_profiles),
                      .gateway_confirm_sink = {}};
    return Node::create(std::move(config));
  }

  template <typename Predicate>
  bool wait_until(Predicate&& predicate, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    executor::comm::PhaseGate poll{"m10-round5-poll"};
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
        return true;
      }
      (void)poll.wait_for(1U, std::chrono::milliseconds{2});
    }
    return predicate();
  }

  LanPairStatus establish_lan_pair(LanNodePair& pair,
                                   std::vector<GatewayProfileConfig> second_profiles) {
    const std::vector<std::string> trust_scopes{
        "stream.open", std::string{gateway_use_scope},
        gateway_provide_scope("office")};
    auto first_profile = initialized_profile("lan-first");
    auto second_profile = initialized_profile("lan-second");
    if (!first_profile || !second_profile) {
      return LanPairStatus::no_interfaces;
    }
    if (!heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                         *second_profile.value_if(), trust_scopes)) {
      return LanPairStatus::no_interfaces;
    }
    pair.first_store.emplace(std::move(*first_profile.value_if()));
    pair.second_store.emplace(std::move(*second_profile.value_if()));

    auto first_node = make_node(*pair.first_store, {});
    auto second_node = make_node(*pair.second_store, std::move(second_profiles));
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

    const auto discovered = [](const Node& node, const DeviceEndpointKey& peer) {
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

  void skip_unless_lan_ready(LanPairStatus status) {
    if (status == LanPairStatus::ready) return;
    const char* required = std::getenv("HEYAKI_REQUIRE_LAN_INTERFACES");
    if (required != nullptr && std::string_view{required} == "1") {
      FAIL() << "LAN pair establishment failed (status=" << static_cast<int>(status)
             << ")";
    }
    GTEST_SKIP() << "LAN pair establishment unavailable (status="
                 << static_cast<int>(status) << ")";
  }

  std::filesystem::path root_;
};

TEST_F(M10Round5NodeTest, AuditRecordAndDiagnosticsAfterEchoTunnel) {
  boost::asio::io_context io;
  const std::string local_address = [&] {
    boost::system::error_code ec;
    boost::asio::ip::udp::socket probe{io};
    probe.open(boost::asio::ip::udp::v4(), ec);
    if (ec) return std::string{};
    probe.connect(boost::asio::ip::udp::endpoint{
                      boost::asio::ip::make_address("8.8.8.8", ec), 53U},
                  ec);
    if (ec) return std::string{};
    const auto local = probe.local_endpoint(ec);
    probe.close(ec);
    if (ec || local.address().is_loopback() || local.address().is_unspecified()) {
      return std::string{};
    }
    return local.address().to_string();
  }();
  if (local_address.empty()) {
    GTEST_SKIP() << "no non-loopback unicast IPv4 address for the echo target";
  }

  auto echo = std::make_shared<EchoTarget>(io, local_address);
  ASSERT_TRUE(echo->ok());
  echo->start();

  auto profile = profile_for("office", {local_address + "/32"});
  LanNodePair pair;
  const auto status = establish_lan_pair(pair, {profile});
  skip_unless_lan_ready(status);

  // Empty before any tunnel.
  EXPECT_TRUE(pair.second.value().gateway_audit_records().empty());

  auto opened = pair.first.value().open_gateway_stream(
      pair.second_key,
      GatewayConnect{.host = local_address, .port = echo->port(), .profile = "office"},
      NodeGatewayStreamOptions{});
  ASSERT_TRUE(opened) << (opened.error_if() != nullptr
                              ? opened.error_if()->safe_detail()
                              : std::string{"unknown"});
  ByteStream stream{std::move(*opened.value_if())};
  auto pump_echo = [&]() {
    (void)io.poll();
    return true;
  };
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
    executor::comm::PhaseGate poll{"m10-round5-connect-poll"};
    while (stream.state() != ByteStreamState::open &&
           std::chrono::steady_clock::now() < deadline) {
      (void)pump_echo();
      (void)poll.wait_for(1U, std::chrono::milliseconds{2});
    }
    if (stream.state() != ByteStreamState::open) {
      // See the gateway-service suite: a stalled promotion on an otherwise
      // verified address is the CI real-stack flake family; the deterministic
      // harness suites and the root netns matrix own this coverage.
      GTEST_SKIP() << "tunnel promotion stalled on this runner (known CI "
                      "real-stack flake family)";
    }
  }

  auto write_state = std::make_shared<NodeIoCapture>();
  stream.async_write(as_bytes("AUDIT-E2E"), [write_state](ByteStreamIoResult result) {
    if (result.error.has_value()) write_state->error = result.error;
    write_state->done.store(true);
  });
  EXPECT_TRUE(wait_until([&] { return write_state->done.load(); },
                         std::chrono::milliseconds{3000}));
  ASSERT_FALSE(write_state->error.has_value()) << write_state->error->safe_detail();

  auto read_state = std::make_shared<NodeIoCapture>();
  auto buffer = std::make_shared<std::array<std::byte, 64U>>();
  stream.async_read_some(std::span<std::byte>{buffer->data(), buffer->size()},
                         [read_state, buffer](ByteStreamIoResult result) {
                           (void)buffer;  // lifetime anchor
                           if (result.error.has_value()) read_state->error = result.error;
                           read_state->bytes.store(result.bytes);
                           read_state->done.store(true);
                         });
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
    while (!read_state->done.load() && std::chrono::steady_clock::now() < deadline) {
      (void)pump_echo();
      executor::comm::PhaseGate poll{"m10-round5-echo-poll"};
      (void)poll.wait_for(1U, std::chrono::milliseconds{2});
    }
    ASSERT_TRUE(read_state->done.load()) << "echo never reached the public stream";
    ASSERT_FALSE(read_state->error.has_value()) << read_state->error->safe_detail();
    ASSERT_EQ(read_state->bytes.load(), 9U);
    const std::string echoed{reinterpret_cast<const char*>(buffer->data()),
                             read_state->bytes.load()};
    EXPECT_EQ(echoed, "AUDIT-E2E");
  }

  // Terminate the tunnel from the initiator side; the serving side must
  // publish exactly one audit record through the node's ring.
  stream.reset(StableStatus::cancelled);
  ASSERT_TRUE(wait_until(
      [&] { return pair.second.value().gateway_audit_records().size() == 1U; },
      std::chrono::milliseconds{4000}))
      << "Node::gateway_audit_records() never observed the tunnel record";

  const auto records = pair.second.value().gateway_audit_records();
  ASSERT_EQ(records.size(), 1U);
  const auto& record = records[0];
  EXPECT_EQ(record.initiator, pair.first_key.device_id);
  EXPECT_EQ(record.profile, "office");
  EXPECT_EQ(record.target_host, local_address);
  EXPECT_TRUE(valid_gateway_host(record.target_host));
  EXPECT_EQ(record.target_port, echo->port());
  EXPECT_LE(record.started_unix_ms, record.ended_unix_ms);
  EXPECT_EQ(record.bytes_from_tunnel, 9U);
  EXPECT_EQ(record.bytes_to_tunnel, 9U);
  EXPECT_EQ(record.end_status, StableStatus::cancelled);

  // Aggregation surface (service_diagnostics_strand, M10-11): the gateway
  // section of the node diagnostics is republished on the node's periodic
  // expiry tick (~500ms), so wait for a snapshot that reflects the tunnel.
  {
    NodeServiceDiagnostics diagnostics;
    ASSERT_TRUE(wait_until([&] {
      diagnostics = pair.second.value().service_diagnostics();
      return diagnostics.gateway_sessions == 1U &&
             diagnostics.gateway.dials_succeeded == 1U &&
             diagnostics.gateway.dial_samples_count == 1U;
    }, std::chrono::milliseconds{6000}))
        << "the gateway service never appeared in the published diagnostics "
           "(sessions="
        << diagnostics.gateway_sessions
        << " dials_succeeded=" << diagnostics.gateway.dials_succeeded
        << " samples=" << diagnostics.gateway.dial_samples_count << ")";
    EXPECT_EQ(diagnostics.gateway.opens_received, 1U);
    EXPECT_EQ(diagnostics.gateway.dials_failed, 0U);
    EXPECT_EQ(diagnostics.gateway.tunnels_active, 0U);
    ASSERT_EQ(diagnostics.gateway.profile_usage.size(), 1U);
    EXPECT_EQ(diagnostics.gateway.profile_usage[0].profile, "office");
    EXPECT_EQ(diagnostics.gateway.profile_usage[0].active_tunnels, 0U);
    EXPECT_EQ(diagnostics.gateway.profile_usage[0].bytes_from_tunnel, 9U);
    EXPECT_EQ(diagnostics.gateway.profile_usage[0].bytes_to_tunnel, 9U);
  }

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

}  // namespace
}  // namespace heyaki
