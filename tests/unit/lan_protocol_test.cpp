#include <heyaki/identity.hpp>
#include <heyaki/lan_protocol.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <vector>

namespace heyaki {
namespace {

LanPresence make_presence(const IdentityKeyPair& identity) {
  EndpointId::Storage endpoint_bytes{};
  endpoint_bytes[0] = std::byte{0x42U};
  LanPresence presence;
  presence.endpoint_id = EndpointId{endpoint_bytes};
  for (std::size_t index = 0U; index < presence.boot_nonce.size(); ++index) {
    presence.boot_nonce[index] = static_cast<std::byte>(index + 1U);
  }
  presence.sequence = 9U;
  presence.tls_signaling_port = 49190U;
  presence.lease = std::chrono::milliseconds{15000};
  EXPECT_TRUE(sign_lan_presence(presence, identity));
  return presence;
}

LanHello make_hello(const IdentityKeyPair& sender, const IdentityKeyPair& peer,
                    LanHelloRole role) {
  LanHello hello;
  hello.role = role;
  EndpointId::Storage sender_endpoint{};
  sender_endpoint[0] = std::byte{0x11U};
  EndpointId::Storage peer_endpoint{};
  peer_endpoint[0] = std::byte{0x22U};
  hello.sender_endpoint_id = EndpointId{sender_endpoint};
  hello.peer_device_id = peer.device_id();
  hello.peer_endpoint_id = EndpointId{peer_endpoint};
  hello.initiator_nonce[0] = std::byte{0x31U};
  hello.responder_nonce[0] = std::byte{0x32U};
  hello.sender_tls_certificate_sha256[0] = std::byte{0x41U};
  hello.observed_peer_tls_certificate_sha256[0] = std::byte{0x42U};
  hello.sender_boot_nonce[0] = std::byte{0x51U};
  EXPECT_TRUE(sign_lan_hello(hello, sender));
  return hello;
}

RequestId make_request_id() {
  RequestId::Storage bytes{};
  bytes[0] = std::byte{0x61U};
  return RequestId{bytes};
}

TEST(LanPresenceProtocolTest, SignedPresenceRoundTripsThroughDatagramEnvelope) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  auto presence = make_presence(*identity.value_if());

  auto encoded = encode_lan_presence_datagram(presence);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();
  EXPECT_LE(encoded.value_if()->size(), max_lan_datagram_bytes);
  auto parsed = parse_lan_presence_datagram(*encoded.value_if());
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  EXPECT_EQ(parsed.value_if()->device_id, identity.value_if()->device_id());
  EXPECT_EQ(parsed.value_if()->endpoint_id, presence.endpoint_id);
  EXPECT_EQ(parsed.value_if()->boot_nonce, presence.boot_nonce);
  EXPECT_EQ(parsed.value_if()->sequence, presence.sequence);
  EXPECT_EQ(parsed.value_if()->tls_signaling_port, presence.tls_signaling_port);
  EXPECT_EQ(parsed.value_if()->lease, presence.lease);
}

TEST(LanPresenceProtocolTest, RejectsTamperingUnknownFieldsAndTruncation) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  auto payload = encode_lan_presence(make_presence(*identity.value_if()));
  ASSERT_TRUE(payload) << payload.error_if()->safe_detail();

  auto tampered = *payload.value_if();
  ASSERT_GT(tampered.size(), 20U);
  tampered[20U] ^= std::byte{0x01U};
  auto tampered_result = parse_lan_presence(tampered);
  ASSERT_FALSE(tampered_result);
  EXPECT_TRUE(tampered_result.error_if()->code() == ErrorCode::authentication ||
              tampered_result.error_if()->code() == ErrorCode::protocol);

  auto unknown = *payload.value_if();
  unknown.push_back(std::byte{0x58U});
  unknown.push_back(std::byte{0x01U});
  auto unknown_result = parse_lan_presence(unknown);
  ASSERT_FALSE(unknown_result);
  EXPECT_EQ(unknown_result.error_if()->safe_detail(), "presence_field_conflict");

  auto truncated = *payload.value_if();
  truncated.pop_back();
  EXPECT_FALSE(parse_lan_presence(truncated));

  const std::vector<std::byte> oversized(max_lan_datagram_payload_bytes + 1U,
                                          std::byte{0U});
  auto oversized_result = parse_lan_presence(oversized);
  ASSERT_FALSE(oversized_result);
  EXPECT_EQ(oversized_result.error_if()->safe_detail(), "presence_payload_size_invalid");
}

TEST(LanPresenceProtocolTest, RejectsInvalidIdentityLeaseAndSignature) {
  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  auto presence = make_presence(*identity.value_if());

  presence.device_id = DeviceId{};
  auto invalid_id = validate_lan_presence(presence);
  ASSERT_FALSE(invalid_id);
  EXPECT_EQ(invalid_id.error_if()->code(), ErrorCode::protocol);

  presence = make_presence(*identity.value_if());
  presence.lease = std::chrono::milliseconds{999};
  EXPECT_FALSE(validate_lan_presence(presence));

  presence = make_presence(*identity.value_if());
  presence.signature[0] ^= std::byte{0x80U};
  auto invalid_signature = validate_lan_presence(presence);
  ASSERT_FALSE(invalid_signature);
  EXPECT_EQ(invalid_signature.error_if()->code(), ErrorCode::authentication);
}

TEST(LanHelloProtocolTest, SignedHelloRoundTripsAndBindsBothEndpoints) {
  auto sender = create_identity();
  auto peer = create_identity();
  ASSERT_TRUE(sender && peer);
  auto hello = make_hello(*sender.value_if(), *peer.value_if(), LanHelloRole::responder);

  auto encoded = encode_lan_hello(hello);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();
  auto parsed = parse_lan_hello(*encoded.value_if());
  ASSERT_TRUE(parsed) << parsed.error_if()->safe_detail();
  EXPECT_EQ(parsed.value_if()->sender_device_id, sender.value_if()->device_id());
  EXPECT_EQ(parsed.value_if()->peer_device_id, peer.value_if()->device_id());
  EXPECT_EQ(parsed.value_if()->sender_endpoint_id, hello.sender_endpoint_id);
  EXPECT_EQ(parsed.value_if()->peer_endpoint_id, hello.peer_endpoint_id);
  EXPECT_EQ(parsed.value_if()->initiator_nonce, hello.initiator_nonce);
  EXPECT_EQ(parsed.value_if()->responder_nonce, hello.responder_nonce);
  EXPECT_EQ(parsed.value_if()->sender_tls_certificate_sha256,
            hello.sender_tls_certificate_sha256);
  EXPECT_EQ(parsed.value_if()->observed_peer_tls_certificate_sha256,
            hello.observed_peer_tls_certificate_sha256);
}

TEST(LanHelloProtocolTest, ProvisionalInitiatorMayCarryZeroResponderNonceOnly) {
  auto sender = create_identity();
  auto peer = create_identity();
  ASSERT_TRUE(sender && peer);
  auto initiator = make_hello(*sender.value_if(), *peer.value_if(), LanHelloRole::initiator);
  initiator.responder_nonce = {};
  ASSERT_TRUE(sign_lan_hello(initiator, *sender.value_if()));
  EXPECT_TRUE(validate_lan_hello(initiator));

  auto responder = initiator;
  responder.role = LanHelloRole::responder;
  ASSERT_TRUE(sign_lan_hello(responder, *sender.value_if()));
  auto invalid = validate_lan_hello(responder);
  ASSERT_FALSE(invalid);
  EXPECT_EQ(invalid.error_if()->safe_detail(), "hello_fields_invalid");
}

TEST(LanHelloProtocolTest, RejectsCertificateAndSignatureReplacement) {
  auto sender = create_identity();
  auto peer = create_identity();
  ASSERT_TRUE(sender && peer);
  auto hello = make_hello(*sender.value_if(), *peer.value_if(), LanHelloRole::responder);

  hello.observed_peer_tls_certificate_sha256[1] ^= std::byte{0x01U};
  auto replaced_fingerprint = validate_lan_hello(hello);
  ASSERT_FALSE(replaced_fingerprint);
  EXPECT_EQ(replaced_fingerprint.error_if()->code(), ErrorCode::authentication);

  hello = make_hello(*sender.value_if(), *peer.value_if(), LanHelloRole::responder);
  hello.signature[0] ^= std::byte{0x01U};
  auto replaced_signature = validate_lan_hello(hello);
  ASSERT_FALSE(replaced_signature);
  EXPECT_EQ(replaced_signature.error_if()->safe_detail(), "hello_signature_invalid");
}

TEST(LanHelloProtocolTest, RejectsProtocolDowngrade) {
  auto sender = create_identity();
  auto peer = create_identity();
  ASSERT_TRUE(sender && peer);
  auto hello = make_hello(*sender.value_if(), *peer.value_if(),
                          LanHelloRole::responder);
  hello.protocol_version.minor = 0U;
  ASSERT_TRUE(sign_lan_hello(hello, *sender.value_if()));
  auto downgraded = validate_lan_hello(hello);
  ASSERT_FALSE(downgraded);
  EXPECT_EQ(downgraded.error_if()->code(), ErrorCode::protocol);
  EXPECT_EQ(downgraded.error_if()->safe_detail(), "hello_fields_invalid");
}

TEST(LanSignalingFrameProtocolTest, ControlAndSignedFramesRoundTrip) {
  const LanSignalingFrame control{
      LanSignalingMessageKind::connect_request, make_request_id(), {}};
  auto encoded_control = encode_lan_signaling_frame(control);
  ASSERT_TRUE(encoded_control) << encoded_control.error_if()->safe_detail();
  ASSERT_EQ(encoded_control.value_if()->size(),
            lan_signaling_frame_header_bytes +
                lan_signaling_frame_fixed_body_bytes);
  EXPECT_EQ((*encoded_control.value_if())[0], std::byte{0x00U});
  EXPECT_EQ((*encoded_control.value_if())[1], std::byte{0x00U});
  EXPECT_EQ((*encoded_control.value_if())[2], std::byte{0x00U});
  EXPECT_EQ((*encoded_control.value_if())[3], std::byte{0x11U});
  auto parsed_control = parse_lan_signaling_frame(*encoded_control.value_if());
  ASSERT_TRUE(parsed_control) << parsed_control.error_if()->safe_detail();
  EXPECT_EQ(parsed_control.value_if()->kind, control.kind);
  EXPECT_EQ(parsed_control.value_if()->request_id, control.request_id);
  EXPECT_TRUE(parsed_control.value_if()->payload.empty());

  const LanSignalingFrame signed_offer{
      LanSignalingMessageKind::signed_offer,
      make_request_id(),
      {std::byte{0x01U}, std::byte{0x02U}, std::byte{0x03U}}};
  auto encoded_offer = encode_lan_signaling_frame(signed_offer);
  ASSERT_TRUE(encoded_offer) << encoded_offer.error_if()->safe_detail();
  auto parsed_offer = parse_lan_signaling_frame(*encoded_offer.value_if());
  ASSERT_TRUE(parsed_offer) << parsed_offer.error_if()->safe_detail();
  EXPECT_EQ(parsed_offer.value_if()->kind, signed_offer.kind);
  EXPECT_EQ(parsed_offer.value_if()->request_id, signed_offer.request_id);
  EXPECT_EQ(parsed_offer.value_if()->payload, signed_offer.payload);
}

TEST(LanSignalingFrameProtocolTest, RejectsInvalidSemanticShapes) {
  LanSignalingFrame frame{LanSignalingMessageKind::connect_request,
                          make_request_id(), {}};

  frame.kind = static_cast<LanSignalingMessageKind>(0x7fU);
  EXPECT_FALSE(validate_lan_signaling_frame(frame));

  frame.kind = LanSignalingMessageKind::connect_request;
  frame.request_id = RequestId{};
  EXPECT_FALSE(validate_lan_signaling_frame(frame));

  frame.request_id = make_request_id();
  frame.payload = {std::byte{0x01U}};
  EXPECT_FALSE(validate_lan_signaling_frame(frame));

  frame.kind = LanSignalingMessageKind::signed_answer;
  frame.payload.clear();
  EXPECT_FALSE(validate_lan_signaling_frame(frame));

  frame.payload.assign(max_lan_signaling_payload_bytes + 1U, std::byte{0U});
  auto oversized = validate_lan_signaling_frame(frame);
  ASSERT_FALSE(oversized);
  EXPECT_EQ(oversized.error_if()->code(), ErrorCode::resource_exhausted);
}

TEST(LanSignalingFrameProtocolTest, RejectsMalformedLengthsAndBytes) {
  const LanSignalingFrame frame{
      LanSignalingMessageKind::signed_candidate,
      make_request_id(),
      {std::byte{0x51U}, std::byte{0x52U}}};
  auto encoded = encode_lan_signaling_frame(frame);
  ASSERT_TRUE(encoded) << encoded.error_if()->safe_detail();

  auto truncated = *encoded.value_if();
  truncated.pop_back();
  auto truncated_result = parse_lan_signaling_frame(truncated);
  ASSERT_FALSE(truncated_result);
  EXPECT_EQ(truncated_result.error_if()->safe_detail(),
            "signaling_frame_truncated");

  auto trailing = *encoded.value_if();
  trailing.push_back(std::byte{0U});
  auto trailing_result = parse_lan_signaling_frame(trailing);
  ASSERT_FALSE(trailing_result);
  EXPECT_EQ(trailing_result.error_if()->safe_detail(),
            "signaling_frame_trailing_bytes");

  auto unknown_kind = *encoded.value_if();
  unknown_kind[lan_signaling_frame_header_bytes] = std::byte{0x7fU};
  EXPECT_FALSE(parse_lan_signaling_frame(unknown_kind));

  auto zero_request = *encoded.value_if();
  std::fill_n(zero_request.begin() +
                  static_cast<std::ptrdiff_t>(lan_signaling_frame_header_bytes + 1U),
              RequestId::size_bytes, std::byte{0U});
  EXPECT_FALSE(parse_lan_signaling_frame(zero_request));

  const std::array<std::byte, 4U> undersized_length{
      std::byte{0x00U}, std::byte{0x00U}, std::byte{0x00U}, std::byte{0x10U}};
  EXPECT_FALSE(parse_lan_signaling_frame(undersized_length));

  const std::array<std::byte, 4U> oversized_length{
      std::byte{0x00U}, std::byte{0x01U}, std::byte{0x00U}, std::byte{0x12U}};
  EXPECT_FALSE(parse_lan_signaling_frame(oversized_length));
}

}  // namespace
}  // namespace heyaki
