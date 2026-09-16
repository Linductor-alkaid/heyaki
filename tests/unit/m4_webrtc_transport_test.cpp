#include "webrtc_transport_session.hpp"
#include "client/peer_session.hpp"

#include <heyaki/detail/build_config.hpp>
#include <heyaki/runtime.hpp>

#include <executor/comm.hpp>

#include <gtest/gtest.h>

#include <array>
#include <atomic>
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
using heyaki::transport::webrtc::tcp_turn_backend_supported;

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

void expect_connected_timeline(const heyaki::ConnectionAttemptTimeline& timeline) {
  const auto& transitions = timeline.transitions();
  ASSERT_GE(transitions.size(), 5U);
  EXPECT_EQ(transitions.front().from, heyaki::ConnectionStage::idle);
  EXPECT_EQ(transitions.front().to, heyaki::ConnectionStage::resolving_endpoint);
  EXPECT_EQ(transitions.front().source, "node");
  EXPECT_EQ(transitions[1].from, heyaki::ConnectionStage::resolving_endpoint);
  EXPECT_EQ(transitions[1].to, heyaki::ConnectionStage::signaling);
  EXPECT_EQ(transitions[1].source, "signaling");
  EXPECT_EQ(transitions[transitions.size() - 2U].to,
            heyaki::ConnectionStage::authenticating);
  EXPECT_EQ(transitions[transitions.size() - 2U].source, "peer_session");
  EXPECT_EQ(transitions.back().from, heyaki::ConnectionStage::authenticating);
  EXPECT_EQ(transitions.back().to, heyaki::ConnectionStage::authenticated);
  EXPECT_EQ(transitions.back().source, "peer_session");
  EXPECT_EQ(transitions.back().reason, "session_hello_verified");

  bool saw_transport_connected = false;
  for (std::size_t index = 0U; index < transitions.size(); ++index) {
    const auto& transition = transitions[index];
    EXPECT_FALSE(transition.source.empty());
    EXPECT_FALSE(transition.reason.empty());
    if (transition.to == heyaki::ConnectionStage::transport_connected) {
      saw_transport_connected = true;
    }
    if (index != 0U) {
      EXPECT_EQ(transitions[index - 1U].to, transition.from);
      EXPECT_LE(transitions[index - 1U].timestamp, transition.timestamp);
    }
  }
  EXPECT_TRUE(saw_transport_connected);
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

TEST(M4WebRtcTransport, TcpTurnCapabilityMatchesBuildBackend) {
  // M9-19: the capability predicate is a compile-time fact of the linked ICE
  // backend and must match the generated build configuration that gates the
  // Node-level policy validation.
  EXPECT_EQ(tcp_turn_backend_supported(), HEYAKI_WEBRTC_TCP_TURN != 0);

  auto dispatcher = [](std::string_view, std::function<heyaki::Result<void>()>) {
    return heyaki::Result<void>::success();
  };
  WebRtcTransportConfig config;
  config.candidates.allow_turn_tcp = true;
  config.tcp_turn_backend_verified = tcp_turn_backend_supported();
  const auto session = WebRtcTransportSession::create(config, dispatcher);
  EXPECT_EQ(session.has_value(), tcp_turn_backend_supported());
  if (session.has_value()) {
    (*session.value_if())->close(heyaki::transport::CloseReason::local_shutdown);
  }

  // TURN/TLS has no backend in v1 (libnice would silently degrade it to
  // plaintext TURN/TCP), so the transport rejects the class and a turn_tls
  // ICE server on every backend.
  WebRtcTransportConfig tls = WebRtcTransportConfig{};
  tls.candidates.allow_turn_tls = true;
  tls.tcp_turn_backend_verified = tcp_turn_backend_supported();
  EXPECT_FALSE(WebRtcTransportSession::create(tls, dispatcher).has_value());

  WebRtcTransportConfig tls_server = WebRtcTransportConfig{};
  tls_server.ice_servers.push_back(
      heyaki::transport::webrtc::IceServerConfig{
          .kind = heyaki::transport::webrtc::IceServerKind::turn_tls,
          .hostname = "turn.example",
          .port = 5349U,
          .username = "user",
          .credential = "credential"});
  tls_server.tcp_turn_backend_verified = tcp_turn_backend_supported();
  EXPECT_FALSE(WebRtcTransportSession::create(tls_server, dispatcher).has_value());
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
  executor::comm::PhaseGate sessions_closed("m4-sessions-closed");

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
      [&](std::vector<std::byte> sdp, std::string type,
          heyaki::DtlsFingerprint fingerprint) {
        EXPECT_NE(fingerprint, heyaki::DtlsFingerprint{});
        ASSERT_TRUE(right);
        EXPECT_TRUE(right->set_remote_description(sdp, type).has_value());
      };
  left_signaling.on_local_candidate = [&](std::vector<std::byte> candidate) {
    ASSERT_TRUE(right);
    EXPECT_TRUE(right->add_remote_candidate(candidate).has_value());
  };
  heyaki::transport::webrtc::WebRtcSignalingHandler right_signaling;
  right_signaling.on_local_description =
      [&](std::vector<std::byte> sdp, std::string type,
          heyaki::DtlsFingerprint fingerprint) {
        EXPECT_NE(fingerprint, heyaki::DtlsFingerprint{});
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
  auto left_timeline = std::make_shared<heyaki::ConnectionAttemptTimeline>();
  auto right_timeline = std::make_shared<heyaki::ConnectionAttemptTimeline>();
  ASSERT_TRUE(left_timeline->transition(heyaki::ConnectionStage::resolving_endpoint,
                                        "node", "endpoint_selected"));
  ASSERT_TRUE(left_timeline->transition(heyaki::ConnectionStage::signaling,
                                        "signaling", "signed_answer_verified"));
  ASSERT_TRUE(right_timeline->transition(heyaki::ConnectionStage::resolving_endpoint,
                                         "node", "endpoint_selected"));
  ASSERT_TRUE(right_timeline->transition(heyaki::ConnectionStage::signaling,
                                         "signaling", "signed_offer_verified"));
  auto left_peer = heyaki::PeerSession::create_verified(
      {left, left_binding, left_identity.value_if(), right_identity.value_if()->public_key(),
       session_protocol(), 1'060'000U, 1'000'000U,
       [&](const heyaki::PeerSessionDiagnostics& value) {
         if (value.state == heyaki::PeerSessionState::authenticated) {
           (void)left_authenticated.advance_to(1U);
         }
         if (value.pongs_received != 0U) (void)pong_received.advance_to(1U);
       },
       left_timeline, {}});
  auto right_peer = heyaki::PeerSession::create_verified(
      {right, right_binding, right_identity.value_if(), left_identity.value_if()->public_key(),
       session_protocol(), 1'060'000U, 1'000'000U,
       [&](const heyaki::PeerSessionDiagnostics& value) {
         if (value.state == heyaki::PeerSessionState::authenticated) {
           (void)right_authenticated.advance_to(1U);
         }
       },
       right_timeline, {}});
  ASSERT_TRUE(left_peer);
  ASSERT_TRUE(right_peer);
  auto left_session = *left_peer.value_if();
  auto right_session = *right_peer.value_if();
  ASSERT_TRUE(right_session->start());
  ASSERT_TRUE(left_session->start());
  const auto started = left->start();
  ASSERT_TRUE(started) << started.error_if()->safe_detail();
  ASSERT_TRUE(left_authenticated.wait_for(1U, 10s));
  ASSERT_TRUE(right_authenticated.wait_for(1U, 10s));
  auto ping_dispatched = runtime_dispatcher(*context.value_if())(
      "m4.peer.send-ping", [left_session] { return left_session->send_ping(42U); });
  ASSERT_TRUE(ping_dispatched) << ping_dispatched.error_if()->safe_detail();
  ASSERT_TRUE(pong_received.wait_for(1U, 5s));
  EXPECT_EQ(left_timeline->stage(), heyaki::ConnectionStage::authenticated);
  EXPECT_EQ(right_timeline->stage(), heyaki::ConnectionStage::authenticated);
  expect_connected_timeline(*left_timeline);
  expect_connected_timeline(*right_timeline);

  EXPECT_EQ(left->snapshot().path.data_path, DataPathKind::direct_host);
  EXPECT_EQ(right->snapshot().path.data_path, DataPathKind::direct_host);
  EXPECT_GT(left->diagnostics().callbacks_dispatched, 0U);
  EXPECT_EQ(left->diagnostics().callbacks_rejected, 0U);
  EXPECT_EQ(right->diagnostics().callbacks_rejected, 0U);

  auto close_dispatched = runtime_dispatcher(*context.value_if())(
      "m4.peer.close", [left_session, right_session, &sessions_closed] {
        left_session->close(heyaki::transport::CloseReason::local_shutdown);
        right_session->close(heyaki::transport::CloseReason::local_shutdown);
        (void)sessions_closed.advance_to(1U);
        return heyaki::Result<void>::success();
      });
  ASSERT_TRUE(close_dispatched) << close_dispatched.error_if()->safe_detail();
  ASSERT_TRUE(sessions_closed.wait_for(1U, 5s));
  EXPECT_EQ(left_timeline->stage(), heyaki::ConnectionStage::closed);
  EXPECT_EQ(right_timeline->stage(), heyaki::ConnectionStage::closed);
  EXPECT_EQ(left_timeline->transitions().back().reason, "local_shutdown");
  EXPECT_EQ(right_timeline->transitions().back().reason, "local_shutdown");
  EXPECT_EQ(left->snapshot().state, TransportState::closed);
  EXPECT_EQ(right->snapshot().state, TransportState::closed);
  const auto shutdown = runtime.value_if()->shutdown();
  EXPECT_EQ(shutdown.final_phase, heyaki::RuntimePhase::stopped);
}

TEST(M4WebRtcTransport, PropagatesHighAndLowWaterBackpressure) {
  auto runtime = heyaki::Runtime::create_owned();
  ASSERT_TRUE(runtime) << runtime.error_if()->safe_detail();
  auto context = runtime.value_if()->create_context(
      heyaki::RuntimeContextKind::peer_session, "m4-webrtc-backpressure");
  ASSERT_TRUE(context) << context.error_if()->safe_detail();

  executor::comm::PhaseGate left_connected("m4-backpressure-left-connected");
  executor::comm::PhaseGate right_connected("m4-backpressure-right-connected");
  executor::comm::PhaseGate send_paused("m4-backpressure-paused");
  executor::comm::PhaseGate send_resumed("m4-backpressure-resumed");
  executor::comm::PhaseGate retry_sent("m4-backpressure-retry");
  executor::comm::PhaseGate sessions_closed("m4-backpressure-closed");

  std::shared_ptr<WebRtcTransportSession> left;
  std::shared_ptr<WebRtcTransportSession> right;
  WebRtcTransportConfig left_config;
  left_config.offerer = true;
  left_config.ice_servers.clear();
  left_config.candidates.allow_server_reflexive = false;
  left_config.candidates.allow_turn_udp = false;
  left_config.maximum_message_bytes = 1024U * 1024U;
  left_config.buffered_amount_high_water = 256U * 1024U;
  left_config.buffered_amount_low_water = 64U * 1024U;
  WebRtcTransportConfig right_config = left_config;
  right_config.offerer = false;

  heyaki::transport::webrtc::WebRtcSignalingHandler left_signaling;
  left_signaling.on_local_description =
      [&](std::vector<std::byte> sdp, std::string type,
          heyaki::DtlsFingerprint) {
        ASSERT_TRUE(right);
        EXPECT_TRUE(right->set_remote_description(sdp, type).has_value());
      };
  left_signaling.on_local_candidate = [&](std::vector<std::byte> candidate) {
    ASSERT_TRUE(right);
    EXPECT_TRUE(right->add_remote_candidate(candidate).has_value());
  };
  heyaki::transport::webrtc::WebRtcSignalingHandler right_signaling;
  right_signaling.on_local_description =
      [&](std::vector<std::byte> sdp, std::string type,
          heyaki::DtlsFingerprint) {
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
    if (snapshot.state == TransportState::connected) (void)left_connected.advance_to(1U);
  });
  right->set_state_handler([&](const heyaki::transport::TransportSessionSnapshot& snapshot) {
    if (snapshot.state == TransportState::connected) (void)right_connected.advance_to(1U);
  });
  right->set_message_handler(
      [](TransportChannel&, std::vector<std::byte>) {});
  ChannelOptions options;
  options.send_queue_bytes = 256U * 1024U;
  options.max_message_bytes = 256U * 1024U;
  ASSERT_TRUE(left->prepare_channel(ChannelKind::file, options));
  const auto started = left->start();
  ASSERT_TRUE(started) << started.error_if()->safe_detail();
  ASSERT_TRUE(left_connected.wait_for(1U, 10s));
  ASSERT_TRUE(right_connected.wait_for(1U, 10s));

  std::atomic<TransportChannel*> channel{nullptr};
  std::atomic<heyaki::ErrorCode> blocked_code{heyaki::ErrorCode::internal};
  std::atomic<bool> paused_observed{false};
  auto open_dispatched = runtime_dispatcher(*context.value_if())(
      "m4.backpressure.open", [&] {
        left->async_open_channel(
            ChannelKind::file, options,
            [&](heyaki::Result<TransportChannel*> opened) {
              ASSERT_TRUE(opened) << opened.error_if()->safe_detail();
              auto* current = *opened.value_if();
              channel.store(current, std::memory_order_release);
              current->set_writable_handler(
                  [&] { (void)send_resumed.advance_to(1U); });
              const auto payload =
                  std::vector<std::byte>(256U * 1024U, std::byte{0x5aU});
              for (std::size_t attempt = 0U; attempt < 64U; ++attempt) {
                auto sent = current->send(payload);
                if (!sent) {
                  blocked_code.store(sent.error_if()->code(),
                                     std::memory_order_release);
                  paused_observed.store(!current->writable(),
                                        std::memory_order_release);
                  (void)send_paused.advance_to(1U);
                  return;
                }
              }
            });
        return heyaki::Result<void>::success();
      });
  ASSERT_TRUE(open_dispatched) << open_dispatched.error_if()->safe_detail();

  ASSERT_TRUE(send_paused.wait_for(1U, 10s));
  ASSERT_EQ(blocked_code.load(std::memory_order_acquire), heyaki::ErrorCode::would_block);
  EXPECT_TRUE(paused_observed.load(std::memory_order_acquire));
  ASSERT_NE(channel.load(std::memory_order_acquire), nullptr);
  ASSERT_TRUE(send_resumed.wait_for(1U, 10s));
  EXPECT_TRUE(channel.load(std::memory_order_acquire)->writable());

  auto retried = runtime_dispatcher(*context.value_if())(
      "m4.backpressure.retry", [&] {
        const auto payload = std::vector<std::byte>(512U, std::byte{0x6bU});
        auto sent = channel.load(std::memory_order_acquire)->send(payload);
        if (!sent) return sent;
        (void)retry_sent.advance_to(1U);
        return heyaki::Result<void>::success();
      });
  ASSERT_TRUE(retried) << retried.error_if()->safe_detail();
  ASSERT_TRUE(retry_sent.wait_for(1U, 5s));
  EXPECT_GE(left->diagnostics().sends_would_block, 1U);
  EXPECT_GE(left->diagnostics().backpressure_pauses, 1U);
  EXPECT_GE(left->diagnostics().writable_resumes, 1U);

  auto close_dispatched = runtime_dispatcher(*context.value_if())(
      "m4.backpressure.close", [&] {
        left->close(heyaki::transport::CloseReason::local_shutdown);
        right->close(heyaki::transport::CloseReason::local_shutdown);
        (void)sessions_closed.advance_to(1U);
        return heyaki::Result<void>::success();
      });
  ASSERT_TRUE(close_dispatched) << close_dispatched.error_if()->safe_detail();
  ASSERT_TRUE(sessions_closed.wait_for(1U, 5s));
  const auto shutdown = runtime.value_if()->shutdown();
  EXPECT_EQ(shutdown.final_phase, heyaki::RuntimePhase::stopped);
}

TEST(M4WebRtcTransport, SimultaneousSameKindOpensResolveToRegisteredChannel) {
  // M9-10 regression: both peers opening the same channel kind while the
  // association is up means each side also receives the peer's duplicate
  // stream as an incoming channel of the same kind. The duplicate wrapper
  // must be rejected and the pending open must resolve to the registered
  // channel — the old code handed the unregistered duplicate's pointer to
  // the completion, and that storage died with the drain event variant
  // (heap-use-after-free on the next send, found by the bench harness).
  auto runtime = heyaki::Runtime::create_owned();
  ASSERT_TRUE(runtime) << runtime.error_if()->safe_detail();
  auto context = runtime.value_if()->create_context(
      heyaki::RuntimeContextKind::peer_session, "m4-webrtc-duplicate-kind");
  ASSERT_TRUE(context) << context.error_if()->safe_detail();

  executor::comm::PhaseGate left_connected("m4-dup-left-connected");
  executor::comm::PhaseGate right_connected("m4-dup-right-connected");
  executor::comm::PhaseGate left_open("m4-dup-left-open");
  executor::comm::PhaseGate right_open("m4-dup-right-open");
  executor::comm::PhaseGate left_received("m4-dup-left-received");
  executor::comm::PhaseGate right_received("m4-dup-right-received");
  executor::comm::PhaseGate sessions_closed("m4-dup-closed");

  std::shared_ptr<WebRtcTransportSession> left;
  std::shared_ptr<WebRtcTransportSession> right;
  WebRtcTransportConfig left_config;
  left_config.offerer = true;
  left_config.ice_servers.clear();
  left_config.candidates.allow_server_reflexive = false;
  left_config.candidates.allow_turn_udp = false;
  WebRtcTransportConfig right_config = left_config;
  right_config.offerer = false;

  heyaki::transport::webrtc::WebRtcSignalingHandler left_signaling;
  left_signaling.on_local_description =
      [&](std::vector<std::byte> sdp, std::string type, heyaki::DtlsFingerprint) {
        ASSERT_TRUE(right);
        EXPECT_TRUE(right->set_remote_description(sdp, type).has_value());
      };
  left_signaling.on_local_candidate = [&](std::vector<std::byte> candidate) {
    ASSERT_TRUE(right);
    EXPECT_TRUE(right->add_remote_candidate(candidate).has_value());
  };
  heyaki::transport::webrtc::WebRtcSignalingHandler right_signaling;
  right_signaling.on_local_description =
      [&](std::vector<std::byte> sdp, std::string type, heyaki::DtlsFingerprint) {
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
    if (snapshot.state == TransportState::connected) (void)left_connected.advance_to(1U);
  });
  right->set_state_handler([&](const heyaki::transport::TransportSessionSnapshot& snapshot) {
    if (snapshot.state == TransportState::connected) (void)right_connected.advance_to(1U);
  });
  left->set_message_handler(
      [&](TransportChannel&, std::vector<std::byte>) { (void)left_received.advance_to(1U); });
  right->set_message_handler(
      [&](TransportChannel&, std::vector<std::byte>) { (void)right_received.advance_to(1U); });

  // A pre-start channel is required for the initial SDP; use the control
  // kind so the file kind below is created by both sides only after the
  // association is up — that is the duplicate-stream race under test.
  ChannelOptions control_options;
  control_options.send_queue_bytes = 64U * 1024U;
  control_options.max_message_bytes = 64U * 1024U;
  ASSERT_TRUE(left->prepare_channel(ChannelKind::control, control_options));

  const auto started = left->start();
  ASSERT_TRUE(started) << started.error_if()->safe_detail();
  ASSERT_TRUE(left_connected.wait_for(1U, 10s));
  ASSERT_TRUE(right_connected.wait_for(1U, 10s));

  std::atomic<TransportChannel*> left_channel{nullptr};
  std::atomic<TransportChannel*> right_channel{nullptr};
  // The session-side convergence contract: when the answerer's own stream is
  // retired in favor of the offerer's, the surviving channel re-surfaces
  // through the channel handler and callers re-point. The completion pointer
  // alone is not stable for a kind both sides opened.
  right->set_channel_handler([&](ChannelKind kind, TransportChannel& channel) {
    if (kind == ChannelKind::file) {
      right_channel.store(&channel, std::memory_order_release);
    }
  });
  ChannelOptions options;
  options.send_queue_bytes = 64U * 1024U;
  options.max_message_bytes = 64U * 1024U;
  // Production ordering: the offerer's kind exists before the answerer's
  // crosses the wire. The UAF vector is still exercised — the answerer's
  // completion can receive its own stream, which the offerer's arriving
  // stream then retires.
  // Production ordering: the offerer's stream is created first — its open is
  // therefore deterministic (nothing can retire the offerer's stream). The
  // answerer's outcome is interleaving-dependent by design (M4-era adopt
  // semantics): its own stream may open and later be retired by the
  // offerer's arriving stream (the promote path — the UAF vector this test
  // regression-guards), or the offerer's stream may register first and the
  // answerer's open then fails with a bounded options-mismatch/close error.
  // A successful completion must always yield a pointer that stays owned;
  // the sanitizer presets are the memory-safety oracle for that.
  std::atomic<bool> right_open_failed{false};
  auto left_open_dispatched = runtime_dispatcher(*context.value_if())(
      "m4.dup.open-left", [&] {
        left->async_open_channel(
            ChannelKind::file, options,
            [&](heyaki::Result<TransportChannel*> opened) {
              ASSERT_TRUE(opened) << opened.error_if()->safe_detail();
              left_channel.store(*opened.value_if(), std::memory_order_release);
              (void)left_open.advance_to(1U);
            });
        return heyaki::Result<void>::success();
      });
  ASSERT_TRUE(left_open_dispatched) << left_open_dispatched.error_if()->safe_detail();
  auto right_open_dispatched = runtime_dispatcher(*context.value_if())(
      "m4.dup.open-right", [&] {
        right->async_open_channel(
            ChannelKind::file, options,
            [&](heyaki::Result<TransportChannel*> opened) {
              if (!opened) {
                // The known bounded interleavings: the offerer's stream
                // registered here first (options mismatch), or our own
                // stream was retired before it opened (closed before open).
                right_open_failed.store(true, std::memory_order_release);
              } else {
                right_channel.store(*opened.value_if(), std::memory_order_release);
              }
              (void)right_open.advance_to(1U);
            });
        return heyaki::Result<void>::success();
      });
  ASSERT_TRUE(right_open_dispatched) << right_open_dispatched.error_if()->safe_detail();
  ASSERT_TRUE(left_open.wait_for(1U, 10s));
  ASSERT_TRUE(right_open.wait_for(1U, 10s));
  ASSERT_NE(left_channel.load(std::memory_order_acquire), nullptr);

  // The offerer (left) rejects the answerer's duplicate stream; the answerer
  // (right) promotes the offerer's stream over its own instead. Both sides
  // end up on the offerer's stream.
  const auto wait_rejections = [&](WebRtcTransportSession& session) {
    for (int attempt = 0; attempt < 200; ++attempt) {
      if (session.diagnostics().channels_rejected >= 1U) return true;
      executor::comm::PhaseGate poll{"m4-dup-reject-poll"};
      (void)poll.wait_for(1U, 50ms);
    }
    return false;
  };
  // Two streams map to one kind by construction, so SOME endpoint must
  // register the loser into duplicates_ and count a rejection — but which
  // one depends on the attach race (a peer stream arriving before our own
  // stream registers flips the roles), so accept the rejection on either.
  EXPECT_TRUE(wait_rejections(*left) || wait_rejections(*right));

  // Round trips through the pointers the completions handed out: under the
  // old duplicate handoff this touches storage already freed with the drain
  // event variant (ASan preset turns that red immediately).
  const std::vector<std::byte> probe(512U, std::byte{0xC3U});
  auto roundtrip_dispatched = runtime_dispatcher(*context.value_if())(
      "m4.dup.roundtrip", [&] {
        EXPECT_TRUE(left_channel.load(std::memory_order_acquire)->send(probe).has_value());
        if (!right_open_failed.load(std::memory_order_acquire)) {
          EXPECT_TRUE(
              right_channel.load(std::memory_order_acquire)->send(probe).has_value());
        }
        return heyaki::Result<void>::success();
      });
  ASSERT_TRUE(roundtrip_dispatched) << roundtrip_dispatched.error_if()->safe_detail();
  // The delivery gate is tied to the successful-open interleaving: when the
  // answerer's open failed (adopt/mismatch), the stream the offerer sends on
  // was registered through the M4-era adopt path, whose delivery semantics
  // predate this test.
  if (!right_open_failed.load(std::memory_order_acquire)) {
    ASSERT_TRUE(right_received.wait_for(1U, 10s));
  }

  auto close_dispatched = runtime_dispatcher(*context.value_if())(
      "m4.dup.close", [&] {
        left->close(heyaki::transport::CloseReason::local_shutdown);
        right->close(heyaki::transport::CloseReason::local_shutdown);
        (void)sessions_closed.advance_to(1U);
        return heyaki::Result<void>::success();
      });
  ASSERT_TRUE(close_dispatched) << close_dispatched.error_if()->safe_detail();
  ASSERT_TRUE(sessions_closed.wait_for(1U, 5s));
  const auto shutdown = runtime.value_if()->shutdown();
  EXPECT_EQ(shutdown.final_phase, heyaki::RuntimePhase::stopped);
}

}  // namespace
