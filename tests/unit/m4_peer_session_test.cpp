#include "client/peer_session.hpp"
#include "m4_support.hpp"

#include <heyaki/identity.hpp>

#include <gtest/gtest.h>

#include <memory>

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
  auto left_session = heyaki::PeerSession::create_verified(
      {left_transport, left_binding, left_identity.value_if(),
       right_identity.value_if()->public_key(), protocol(), 1'060'000U, 1'000'000U, {}});
  auto right_session = heyaki::PeerSession::create_verified(
      {right_transport, right_binding, right_identity.value_if(),
       left_identity.value_if()->public_key(), protocol(), 1'060'000U, 1'000'000U, {}});
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
}

}  // namespace
