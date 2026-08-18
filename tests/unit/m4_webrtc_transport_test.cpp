#include "webrtc_transport_session.hpp"
#include "client/peer_session.hpp"

#include <heyaki/runtime.hpp>

#include <executor/comm.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <array>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace {

using namespace std::chrono_literals;
using heyaki::transport::ChannelKind;
using heyaki::transport::ChannelOptions;
using heyaki::transport::DataPathKind;
using heyaki::transport::TransportChannel;
using heyaki::transport::TransportState;
using heyaki::transport::webrtc::WebRtcTransportConfig;
using heyaki::transport::webrtc::WebRtcTransportSession;

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

heyaki::ProtocolHello session_protocol() {
  return {.version = heyaki::current_protocol_version,
          .supported = {heyaki::protocol_1_1_capability_bits},
          .required = {static_cast<std::uint64_t>(heyaki::Capability::session)}};
}

heyaki::transport::webrtc::RuntimeDispatcher runtime_dispatcher(
    const heyaki::RuntimeContext& context) {
  return [context](std::string_view name,
                   std::function<heyaki::Result<void>()> callback) {
    heyaki::RuntimeSecurityContext security;
    security.application_id = "org.heyaki.m4.webrtc-test";
    security.authorization_scope = std::string{name};
    security.epoch = heyaki::SessionEpoch{1U};
    auto operation = context.submit(
        std::move(security),
        [callback = std::move(callback)]() mutable { return callback(); });
    if (!operation) {
      return heyaki::Result<void>::failure(*operation.error_if());
    }
    return heyaki::Result<void>::success();
  };
}

TEST(M4WebRtcTransport, RejectsUnverifiedTcpTurnAndInvalidWatermarks) {
  auto dispatcher = [](std::string_view, std::function<heyaki::Result<void>()>) {
    return heyaki::Result<void>::success();
  };
  WebRtcTransportConfig config;
  config.candidates.allow_turn_tcp = true;
  EXPECT_FALSE(WebRtcTransportSession::create(config, dispatcher).has_value());

  config.candidates.allow_turn_tcp = false;
  config.buffered_amount_low_water = config.buffered_amount_high_water;
  EXPECT_FALSE(WebRtcTransportSession::create(config, dispatcher).has_value());
}

TEST(M4WebRtcTransport, HostCandidateDataChannelUsesExecutorDispatcher) {
  auto runtime = heyaki::Runtime::create_owned();
  ASSERT_TRUE(runtime) << runtime.error_if()->safe_detail();
  auto context = runtime.value_if()->create_context(
      heyaki::RuntimeContextKind::peer_session, "m4-webrtc-pair");
  ASSERT_TRUE(context) << context.error_if()->safe_detail();

  executor::comm::PhaseGate left_authenticated("m4-left-authenticated");
  executor::comm::PhaseGate right_authenticated("m4-right-authenticated");
  executor::comm::PhaseGate pong_received("m4-pong-received");

  std::shared_ptr<WebRtcTransportSession> left;
  std::shared_ptr<WebRtcTransportSession> right;
  WebRtcTransportConfig left_config;
  left_config.offerer = true;
  left_config.signaling_path = heyaki::transport::SignalingPathKind::lan;
  left_config.ice_servers.clear();
  left_config.candidates.allow_server_reflexive = false;
  left_config.candidates.allow_turn_udp = false;
  WebRtcTransportConfig right_config = left_config;
  right_config.offerer = false;

  heyaki::transport::webrtc::WebRtcSignalingHandler left_signaling;
  left_signaling.on_local_description =
      [&](std::vector<std::byte> sdp, std::string type) {
        ASSERT_TRUE(right);
        EXPECT_TRUE(right->set_remote_description(sdp, type).has_value());
      };
  left_signaling.on_local_candidate = [&](std::vector<std::byte> candidate) {
    ASSERT_TRUE(right);
    EXPECT_TRUE(right->add_remote_candidate(candidate).has_value());
  };
  heyaki::transport::webrtc::WebRtcSignalingHandler right_signaling;
  right_signaling.on_local_description =
      [&](std::vector<std::byte> sdp, std::string type) {
        ASSERT_TRUE(left);
        EXPECT_TRUE(left->set_remote_description(sdp, type).has_value());
      };
  right_signaling.on_local_candidate = [&](std::vector<std::byte> candidate) {
    ASSERT_TRUE(left);
    EXPECT_TRUE(left->add_remote_candidate(candidate).has_value());
  };

  auto created_left = WebRtcTransportSession::create(
      left_config, runtime_dispatcher(*context.value_if()), std::move(left_signaling));
  ASSERT_TRUE(created_left) << created_left.error_if()->safe_detail();
  left = *created_left.value_if();
  auto created_right = WebRtcTransportSession::create(
      right_config, runtime_dispatcher(*context.value_if()), std::move(right_signaling));
  ASSERT_TRUE(created_right) << created_right.error_if()->safe_detail();
  right = *created_right.value_if();

  auto left_identity = heyaki::create_identity();
  auto right_identity = heyaki::create_identity();
  ASSERT_TRUE(left_identity);
  ASSERT_TRUE(right_identity);
  const heyaki::DeviceEndpointKey left_endpoint{
      left_identity.value_if()->device_id(), filled<heyaki::EndpointId>(0x20U)};
  const heyaki::DeviceEndpointKey right_endpoint{
      right_identity.value_if()->device_id(), filled<heyaki::EndpointId>(0x40U)};
  const auto session_id = filled<heyaki::SessionId>(0x60U);
  const auto initiator_nonce = filled_array<heyaki::signaling_nonce_bytes>(0x10U);
  const auto responder_nonce = filled_array<heyaki::signaling_nonce_bytes>(0x30U);
  const auto transcript =
      filled_array<heyaki::signaling_transcript_sha256_bytes>(0x50U);
  heyaki::VerifiedSessionBinding left_binding{
      {right_endpoint, left_endpoint, session_id, 1U, initiator_nonce, responder_nonce,
       transcript},
      {}, "peer-ufrag", true};
  heyaki::VerifiedSessionBinding right_binding{
      {left_endpoint, right_endpoint, session_id, 1U, initiator_nonce, responder_nonce,
       transcript},
      {}, "peer-ufrag", false};
  auto left_peer = heyaki::PeerSession::create_verified(
      {left, left_binding, left_identity.value_if(), right_identity.value_if()->public_key(),
       session_protocol(), 1'060'000U, 1'000'000U,
       [&](const heyaki::PeerSessionDiagnostics& value) {
         if (value.state == heyaki::PeerSessionState::authenticated) {
           (void)left_authenticated.advance_to(1U);
         }
         if (value.pongs_received != 0U) (void)pong_received.advance_to(1U);
       }});
  auto right_peer = heyaki::PeerSession::create_verified(
      {right, right_binding, right_identity.value_if(), left_identity.value_if()->public_key(),
       session_protocol(), 1'060'000U, 1'000'000U,
       [&](const heyaki::PeerSessionDiagnostics& value) {
         if (value.state == heyaki::PeerSessionState::authenticated) {
           (void)right_authenticated.advance_to(1U);
         }
       }});
  ASSERT_TRUE(left_peer);
  ASSERT_TRUE(right_peer);
  ASSERT_TRUE((*right_peer.value_if())->start());
  ASSERT_TRUE((*left_peer.value_if())->start());
  const auto started = left->start();
  ASSERT_TRUE(started) << started.error_if()->safe_detail();
  ASSERT_TRUE(left_authenticated.wait_for(1U, 10s));
  ASSERT_TRUE(right_authenticated.wait_for(1U, 10s));
  ASSERT_TRUE((*left_peer.value_if())->send_ping(42U));
  ASSERT_TRUE(pong_received.wait_for(1U, 5s));

  EXPECT_EQ(left->snapshot().path.data_path, DataPathKind::direct_host);
  EXPECT_EQ(right->snapshot().path.data_path, DataPathKind::direct_host);
  EXPECT_GT(left->diagnostics().callbacks_dispatched, 0U);
  EXPECT_EQ(left->diagnostics().callbacks_rejected, 0U);
  EXPECT_EQ(right->diagnostics().callbacks_rejected, 0U);

  left->close(heyaki::transport::CloseReason::local_shutdown);
  right->close(heyaki::transport::CloseReason::local_shutdown);
  EXPECT_EQ(left->snapshot().state, TransportState::closed);
  EXPECT_EQ(right->snapshot().state, TransportState::closed);
  const auto shutdown = runtime.value_if()->shutdown();
  EXPECT_EQ(shutdown.final_phase, heyaki::RuntimePhase::stopped);
}

}  // namespace
