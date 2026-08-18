#include "webrtc_transport_session.hpp"

#include <heyaki/runtime.hpp>

#include <executor/comm.hpp>

#include <gtest/gtest.h>

#include <chrono>
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

  executor::comm::PhaseGate left_connected("m4-left-connected");
  executor::comm::PhaseGate right_connected("m4-right-connected");
  executor::comm::PhaseGate message_received("m4-message-received");
  executor::comm::PhaseGate channel_opened("m4-channel-opened");

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

  left->set_state_handler([&](const heyaki::transport::TransportSessionSnapshot& snapshot) {
    if (snapshot.state == TransportState::connected) {
      (void)left_connected.advance_to(1U);
    }
  });
  right->set_state_handler([&](const heyaki::transport::TransportSessionSnapshot& snapshot) {
    if (snapshot.state == TransportState::connected) {
      (void)right_connected.advance_to(1U);
    }
  });
  right->set_message_handler(
      [&](TransportChannel& channel, std::vector<std::byte> payload) {
        EXPECT_EQ(channel.kind(), ChannelKind::control);
        EXPECT_EQ(std::string(reinterpret_cast<const char*>(payload.data()), payload.size()),
                  "ping");
        (void)message_received.advance_to(1U);
      });

  TransportChannel* control = nullptr;
  ChannelOptions options;
  options.send_queue_bytes = 64U * 1024U;
  options.max_message_bytes = 64U * 1024U;
  left->async_open_channel(ChannelKind::control, options,
                           [&](heyaki::Result<TransportChannel*> opened) {
                             ASSERT_TRUE(opened) << opened.error_if()->safe_detail();
                             control = *opened.value_if();
                             (void)channel_opened.advance_to(1U);
                           });
  const auto started = left->start();
  ASSERT_TRUE(started) << started.error_if()->safe_detail();
  ASSERT_TRUE(left_connected.wait_for(1U, 10s));
  ASSERT_TRUE(right_connected.wait_for(1U, 10s));
  ASSERT_TRUE(channel_opened.wait_for(1U, 5s));
  ASSERT_NE(control, nullptr);

  const std::string ping = "ping";
  const auto bytes = std::span<const std::byte>{
      reinterpret_cast<const std::byte*>(ping.data()), ping.size()};
  const auto sent = control->send(bytes);
  ASSERT_TRUE(sent) << sent.error_if()->safe_detail();
  ASSERT_TRUE(message_received.wait_for(1U, 5s));

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
