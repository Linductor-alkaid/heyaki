#include "client/peer_session.hpp"
#include "m4_support.hpp"

#include <heyaki/identity.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <string_view>

namespace {

template <typename Value>
Value filled(std::uint8_t seed) {
  typename Value::Storage bytes{};
  for (std::size_t index = 0U; index < bytes.size(); ++index) {
    bytes[index] = static_cast<std::byte>(seed + static_cast<std::uint8_t>(index));
  }
  return Value{bytes};
}

template <std::size_t Size>
std::array<std::byte, Size> filled_array(std::uint8_t seed) {
  std::array<std::byte, Size> bytes{};
  for (std::size_t index = 0U; index < bytes.size(); ++index) {
    bytes[index] = static_cast<std::byte>(seed + static_cast<std::uint8_t>(index));
  }
  return bytes;
}

heyaki::ProtocolHello protocol() {
  return {.version = heyaki::current_protocol_version,
          .supported = {heyaki::protocol_1_1_capability_bits},
          .required = {static_cast<std::uint64_t>(heyaki::Capability::session)}};
}

void expect_transition(const heyaki::ConnectionTransition& transition,
                       heyaki::ConnectionStage from, heyaki::ConnectionStage to,
                       std::string_view source, std::string_view reason) {
  EXPECT_EQ(transition.from, from);
  EXPECT_EQ(transition.to, to);
  EXPECT_EQ(transition.source, source);
  EXPECT_EQ(transition.reason, reason);
}

void expect_complete_loopback_timeline(const heyaki::ConnectionAttemptTimeline& timeline,
                                       std::string_view authentication_reason) {
  const auto& transitions = timeline.transitions();
  ASSERT_EQ(transitions.size(), 5U);
  expect_transition(transitions[0], heyaki::ConnectionStage::idle,
                    heyaki::ConnectionStage::resolving_endpoint, "node",
                    "endpoint_selected");
  expect_transition(transitions[1], heyaki::ConnectionStage::resolving_endpoint,
                    heyaki::ConnectionStage::signaling, "signaling",
                    "attempt_accepted");
  expect_transition(transitions[2], heyaki::ConnectionStage::signaling,
                    heyaki::ConnectionStage::transport_connected, "peer_session",
                    authentication_reason == "session_hello_sent"
                        ? "control_channel_open"
                        : "inbound_control_channel_ready");
  expect_transition(transitions[3], heyaki::ConnectionStage::transport_connected,
                    heyaki::ConnectionStage::authenticating, "peer_session",
                    authentication_reason);
  expect_transition(transitions[4], heyaki::ConnectionStage::authenticating,
                    heyaki::ConnectionStage::authenticated, "peer_session",
                    "session_hello_verified");
  for (std::size_t index = 1U; index < transitions.size(); ++index) {
    EXPECT_LE(transitions[index - 1U].timestamp, transitions[index].timestamp);
    EXPECT_EQ(transitions[index - 1U].to, transitions[index].from);
  }
}

TEST(M4PeerSession, AuthenticatesControlHelloAndAllowsOnlyControlPing) {
  auto left_identity = heyaki::create_identity();
  auto right_identity = heyaki::create_identity();
  ASSERT_TRUE(left_identity);
  ASSERT_TRUE(right_identity);
  const heyaki::DeviceEndpointKey left{left_identity.value_if()->device_id(),
                                       filled<heyaki::EndpointId>(0x20U)};
  const heyaki::DeviceEndpointKey right{right_identity.value_if()->device_id(),
                                        filled<heyaki::EndpointId>(0x40U)};
  const auto session_id = filled<heyaki::SessionId>(0x60U);
  const auto initiator_nonce = filled_array<heyaki::signaling_nonce_bytes>(0x10U);
  const auto responder_nonce = filled_array<heyaki::signaling_nonce_bytes>(0x30U);
  const auto transcript =
      filled_array<heyaki::signaling_transcript_sha256_bytes>(0x50U);
  heyaki::test::LoopbackTransportPair pair;
  pair.connect();
  auto left_transport = std::shared_ptr<heyaki::transport::TransportSession>(
      &pair.left(), [](heyaki::transport::TransportSession*) {});
  auto right_transport = std::shared_ptr<heyaki::transport::TransportSession>(
      &pair.right(), [](heyaki::transport::TransportSession*) {});
  heyaki::VerifiedSessionBinding left_binding{
      {right, left, session_id, 1U, initiator_nonce, responder_nonce, transcript},
      {}, "peer-ufrag", true};
  heyaki::VerifiedSessionBinding right_binding{
      {left, right, session_id, 1U, initiator_nonce, responder_nonce, transcript},
      {}, "peer-ufrag", false};
  auto idle_timeline = std::make_shared<heyaki::ConnectionAttemptTimeline>();
  auto idle_session = heyaki::PeerSession::create_verified(
      {left_transport, left_binding, left_identity.value_if(),
       right_identity.value_if()->public_key(), protocol(), 1'060'000U, 1'000'000U, {},
       idle_timeline, {}});
  ASSERT_FALSE(idle_session);
  EXPECT_EQ(idle_session.error_if()->safe_detail(), "connection_timeline_not_ready");

  auto short_timeline = std::make_shared<heyaki::ConnectionAttemptTimeline>(4U);
  ASSERT_TRUE(short_timeline->transition(heyaki::ConnectionStage::resolving_endpoint,
                                         "node", "endpoint_selected"));
  ASSERT_TRUE(short_timeline->transition(heyaki::ConnectionStage::signaling,
                                         "signaling", "attempt_accepted"));
  auto short_session = heyaki::PeerSession::create_verified(
      {left_transport, left_binding, left_identity.value_if(),
       right_identity.value_if()->public_key(), protocol(), 1'060'000U, 1'000'000U, {},
       short_timeline, {}});
  ASSERT_FALSE(short_session);
  EXPECT_EQ(short_session.error_if()->safe_detail(),
            "connection_timeline_capacity_insufficient");

  auto left_timeline = std::make_shared<heyaki::ConnectionAttemptTimeline>();
  auto right_timeline = std::make_shared<heyaki::ConnectionAttemptTimeline>();
  ASSERT_TRUE(left_timeline->transition(heyaki::ConnectionStage::resolving_endpoint,
                                        "node", "endpoint_selected"));
  ASSERT_TRUE(left_timeline->transition(heyaki::ConnectionStage::signaling,
                                        "signaling", "attempt_accepted"));
  ASSERT_TRUE(right_timeline->transition(heyaki::ConnectionStage::resolving_endpoint,
                                         "node", "endpoint_selected"));
  ASSERT_TRUE(right_timeline->transition(heyaki::ConnectionStage::signaling,
                                         "signaling", "attempt_accepted"));
  auto left_session = heyaki::PeerSession::create_verified(
      {left_transport, left_binding, left_identity.value_if(),
       right_identity.value_if()->public_key(), protocol(), 1'060'000U, 1'000'000U, {},
       left_timeline, {}});
  auto right_session = heyaki::PeerSession::create_verified(
      {right_transport, right_binding, right_identity.value_if(),
       left_identity.value_if()->public_key(), protocol(), 1'060'000U, 1'000'000U, {},
       right_timeline, {}});
  ASSERT_TRUE(left_session);
  ASSERT_TRUE(right_session);
  ASSERT_TRUE((*right_session.value_if())->start());
  heyaki::transport::TransportChannel* business = nullptr;
  pair.left().async_open_channel(
      heyaki::transport::ChannelKind::message, {},
      [&](heyaki::Result<heyaki::transport::TransportChannel*> opened) {
        ASSERT_TRUE(opened);
        business = *opened.value_if();
      });
  pair.right().async_open_channel(
      heyaki::transport::ChannelKind::message, {},
      [](heyaki::Result<heyaki::transport::TransportChannel*>) {});
  ASSERT_NE(business, nullptr);
  ASSERT_TRUE(business->send(std::array<std::byte, 1U>{std::byte{0x20U}}));
  pair.right().pump();
  EXPECT_EQ((*right_session.value_if())->diagnostics().business_frames_rejected, 1U);
  heyaki::transport::ChannelOptions incoming_control;
  incoming_control.priority = heyaki::transport::ChannelPriority::control;
  pair.right().async_open_channel(
      heyaki::transport::ChannelKind::control, incoming_control,
      [](heyaki::Result<heyaki::transport::TransportChannel*>) {});
  ASSERT_TRUE((*left_session.value_if())->start());
  auto early_ping = (*left_session.value_if())->send_ping(1U);
  ASSERT_FALSE(early_ping);
  EXPECT_EQ(early_ping.error_if()->code(), heyaki::ErrorCode::permission);
  pair.right().pump();
  pair.left().pump();
  EXPECT_TRUE((*left_session.value_if())->authenticated());
  EXPECT_TRUE((*right_session.value_if())->authenticated());
  EXPECT_EQ((*left_session.value_if())->diagnostics().hellos_sent, 1U);
  EXPECT_EQ((*right_session.value_if())->diagnostics().hellos_received, 1U);
  ASSERT_TRUE((*left_session.value_if())->send_ping(42U));
  pair.right().pump();
  pair.left().pump();
  EXPECT_EQ((*right_session.value_if())->diagnostics().pings_received, 1U);
  EXPECT_EQ((*left_session.value_if())->diagnostics().pongs_received, 1U);
  EXPECT_EQ(left_timeline->stage(), heyaki::ConnectionStage::authenticated);
  EXPECT_EQ(right_timeline->stage(), heyaki::ConnectionStage::authenticated);
  expect_complete_loopback_timeline(*left_timeline, "session_hello_sent");
  expect_complete_loopback_timeline(*right_timeline, "session_hello_received");

  (*left_session.value_if())->close(heyaki::transport::CloseReason::local_shutdown);
  (*right_session.value_if())->close(heyaki::transport::CloseReason::local_shutdown);
  EXPECT_EQ(left_timeline->stage(), heyaki::ConnectionStage::closed);
  EXPECT_EQ(right_timeline->stage(), heyaki::ConnectionStage::closed);
  ASSERT_EQ(left_timeline->transitions().size(), 6U);
  expect_transition(left_timeline->transitions().back(),
                    heyaki::ConnectionStage::authenticated,
                    heyaki::ConnectionStage::closed, "peer_session", "local_shutdown");
}

TEST(M4PeerSession, TimelineRejectsRegressionsAndFullHistory) {
  heyaki::ConnectionAttemptTimeline timeline(2U);
  EXPECT_TRUE(timeline.transition(heyaki::ConnectionStage::resolving_endpoint,
                                  "node", "endpoint_selected"));
  auto regression = timeline.transition(heyaki::ConnectionStage::idle,
                                        "node", "invalid_regression");
  ASSERT_FALSE(regression);
  EXPECT_EQ(regression.error_if()->safe_detail(), "connection_transition_invalid");
  EXPECT_TRUE(timeline.transition(heyaki::ConnectionStage::signaling,
                                  "signaling", "attempt_started"));
  auto full = timeline.transition(heyaki::ConnectionStage::checking,
                                  "transport", "ice_checking");
  ASSERT_FALSE(full);
  EXPECT_EQ(full.error_if()->safe_detail(), "transition_history_full");
}

TEST(M4PeerSession, TimelineBoundsMetadataAndRecordsCallerTimestamp) {
  using namespace std::chrono_literals;
  heyaki::ConnectionAttemptTimeline timeline;
  const auto timestamp = std::chrono::steady_clock::time_point{37ms};
  ASSERT_TRUE(timeline.transition(heyaki::ConnectionStage::resolving_endpoint,
                                  "node", "endpoint_selected", timestamp));
  ASSERT_EQ(timeline.transitions().size(), 1U);
  EXPECT_EQ(timeline.transitions().front().timestamp, timestamp);

  const std::string oversized_source(65U, 's');
  auto invalid_source = timeline.transition(heyaki::ConnectionStage::signaling,
                                            oversized_source, "attempt_started");
  ASSERT_FALSE(invalid_source);
  EXPECT_EQ(invalid_source.error_if()->safe_detail(), "transition_metadata_invalid");
  const std::string oversized_reason(129U, 'r');
  auto invalid_reason = timeline.transition(heyaki::ConnectionStage::signaling,
                                            "signaling", oversized_reason);
  ASSERT_FALSE(invalid_reason);
  EXPECT_EQ(invalid_reason.error_if()->safe_detail(), "transition_metadata_invalid");
  EXPECT_EQ(timeline.stage(), heyaki::ConnectionStage::resolving_endpoint);
  EXPECT_EQ(timeline.transitions().size(), 1U);

  EXPECT_EQ(heyaki::connection_stage_name(heyaki::ConnectionStage::idle), "idle");
  EXPECT_EQ(heyaki::connection_stage_name(heyaki::ConnectionStage::resolving_endpoint),
            "resolving_endpoint");
  EXPECT_EQ(heyaki::connection_stage_name(heyaki::ConnectionStage::signaling), "signaling");
  EXPECT_EQ(heyaki::connection_stage_name(heyaki::ConnectionStage::gathering), "gathering");
  EXPECT_EQ(heyaki::connection_stage_name(heyaki::ConnectionStage::checking), "checking");
  EXPECT_EQ(heyaki::connection_stage_name(heyaki::ConnectionStage::transport_connected),
            "transport_connected");
  EXPECT_EQ(heyaki::connection_stage_name(heyaki::ConnectionStage::authenticating),
            "authenticating");
  EXPECT_EQ(heyaki::connection_stage_name(heyaki::ConnectionStage::authenticated),
            "authenticated");
  EXPECT_EQ(heyaki::connection_stage_name(heyaki::ConnectionStage::closed), "closed");
}

}  // namespace
