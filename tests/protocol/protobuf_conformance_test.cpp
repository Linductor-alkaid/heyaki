#include "m1_golden_vectors.hpp"
#include "test_bytes.hpp"

#include "heyaki/message/v1/message.pb.h"
#include "heyaki/discovery/v1/discovery.pb.h"
#include "heyaki/session/v1/session.pb.h"
#include "heyaki/signaling/v1/lan.pb.h"
#include "heyaki/signaling/v1/signaling.pb.h"

#include <gtest/gtest.h>

#include <google/protobuf/message_lite.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

namespace {

using MessageEnvelope = heyaki::protocol::message::v1::MessageEnvelope;
using SessionHello = heyaki::protocol::session::v1::SessionHello;
using SignedCandidate = heyaki::protocol::signaling::v1::SignedCandidate;
using LanPresence = heyaki::protocol::discovery::v1::LanPresence;
using LanHello = heyaki::protocol::signaling::v1::LanHello;

static_assert(std::is_base_of_v<google::protobuf::MessageLite, MessageEnvelope>);
static_assert(std::is_base_of_v<google::protobuf::MessageLite, SessionHello>);
static_assert(std::is_base_of_v<google::protobuf::MessageLite, SignedCandidate>);
static_assert(std::is_base_of_v<google::protobuf::MessageLite, LanPresence>);
static_assert(std::is_base_of_v<google::protobuf::MessageLite, LanHello>);

TEST(ProtobufLite, ParsesAndReencodesPublishedEnvelope) {
  const auto encoded =
      heyaki::test::bytes_from_hex(heyaki::test_vectors::protobuf_envelope_hex);
  MessageEnvelope message;
  ASSERT_TRUE(message.ParseFromArray(encoded.data(), static_cast<int>(encoded.size())));
  EXPECT_EQ(message.message_id(),
            std::string("\x00\x11\x22\x33\x44\x55\x66\x77"
                        "\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
                        16U));
  EXPECT_EQ(message.type(), "test");
  EXPECT_EQ(message.schema_version(), 1U);
  EXPECT_EQ(message.relative_ttl_milliseconds(), 1000U);
  EXPECT_EQ(message.delivery_mode(),
            heyaki::protocol::message::v1::DELIVERY_MODE_BEST_EFFORT);
  EXPECT_EQ(message.payload(), "abc");
  EXPECT_FALSE(message.has_wall_time_unix_milliseconds());
  EXPECT_EQ(message.SerializeAsString(),
            std::string(reinterpret_cast<const char*>(encoded.data()), encoded.size()));
}

TEST(ProtobufLite, PreservesUnknownFieldsAndRejectsMalformedInput) {
  auto encoded = heyaki::test::bytes_from_hex(heyaki::test_vectors::protobuf_envelope_hex);
  encoded.insert(encoded.end(), {std::byte{0x7aU}, std::byte{0x01U}, std::byte{0xffU}});

  MessageEnvelope with_unknown;
  ASSERT_TRUE(
      with_unknown.ParseFromArray(encoded.data(), static_cast<int>(encoded.size())));
  const auto reencoded = with_unknown.SerializeAsString();
  ASSERT_GE(reencoded.size(), 3U);
  EXPECT_EQ(static_cast<unsigned char>(reencoded[reencoded.size() - 3U]), 0x7aU);
  EXPECT_EQ(static_cast<unsigned char>(reencoded[reencoded.size() - 2U]), 0x01U);
  EXPECT_EQ(static_cast<unsigned char>(reencoded.back()), 0xffU);

  encoded.pop_back();
  MessageEnvelope truncated;
  EXPECT_FALSE(truncated.ParseFromArray(encoded.data(), static_cast<int>(encoded.size())));
  const std::vector<std::byte> oversized_length{std::byte{0x0aU}, std::byte{0xffU},
                                                std::byte{0xffU}, std::byte{0xffU},
                                                std::byte{0xffU}, std::byte{0x0fU}};
  MessageEnvelope malformed;
  EXPECT_FALSE(malformed.ParseFromArray(oversized_length.data(),
                                        static_cast<int>(oversized_length.size())));
}

TEST(ProtobufLite, CandidateAndHelloExposeFrozenTranscriptBindings) {
  SignedCandidate candidate;
  candidate.set_sequence(7U);
  candidate.set_candidate("candidate:1 1 UDP 1 192.0.2.1 5000 typ host");
  candidate.set_signaling_transcript_sha256(std::string(32U, '\x11'));
  candidate.set_owner_ice_ufrag("ice1");
  candidate.set_owner_dtls_fingerprint(std::string(32U, '\x22'));

  SignedCandidate parsed_candidate;
  const auto candidate_bytes = candidate.SerializeAsString();
  ASSERT_TRUE(parsed_candidate.ParseFromString(candidate_bytes));
  EXPECT_EQ(parsed_candidate.signaling_transcript_sha256().size(), 32U);
  EXPECT_EQ(parsed_candidate.owner_ice_ufrag(), "ice1");
  EXPECT_EQ(parsed_candidate.owner_dtls_fingerprint().size(), 32U);

  SessionHello hello;
  hello.set_signaling_transcript_sha256(std::string(32U, '\x33'));
  EXPECT_EQ(hello.signaling_transcript_sha256().size(), 32U);
}

TEST(ProtobufLite, LanPresenceAndHelloExposeFrozenIdentityBindings) {
  LanPresence presence;
  presence.mutable_protocol_version()->set_major(1U);
  presence.mutable_protocol_version()->set_minor(1U);
  presence.mutable_capabilities()->set_supported_bits(0xc06U);
  presence.set_device_id(std::string(32U, '\x11'));
  presence.set_identity_public_key(std::string(32U, '\x22'));
  presence.set_endpoint_id(std::string(16U, '\x33'));
  presence.set_boot_nonce(std::string(32U, '\x44'));
  presence.set_sequence(42U);
  presence.set_tls_signaling_port(49189U);
  presence.set_lease_milliseconds(15000U);
  presence.mutable_signature()->set_ed25519(std::string(64U, '\x55'));

  LanPresence parsed_presence;
  ASSERT_TRUE(parsed_presence.ParseFromString(presence.SerializeAsString()));
  EXPECT_EQ(parsed_presence.device_id().size(), 32U);
  EXPECT_EQ(parsed_presence.endpoint_id().size(), 16U);
  EXPECT_EQ(parsed_presence.sequence(), 42U);

  LanHello hello;
  hello.set_role(heyaki::protocol::signaling::v1::LAN_HELLO_ROLE_INITIATOR);
  hello.mutable_sender()->set_device_id(std::string(32U, '\x11'));
  hello.mutable_sender()->set_endpoint_id(std::string(16U, '\x33'));
  hello.mutable_peer()->set_device_id(std::string(32U, '\x66'));
  hello.mutable_peer()->set_endpoint_id(std::string(16U, '\x77'));
  hello.set_sender_tls_certificate_sha256(std::string(32U, '\x88'));
  hello.set_observed_peer_tls_certificate_sha256(std::string(32U, '\x99'));
  hello.set_expiry_milliseconds(5000U);

  LanHello parsed_hello;
  ASSERT_TRUE(parsed_hello.ParseFromString(hello.SerializeAsString()));
  EXPECT_EQ(parsed_hello.role(),
            heyaki::protocol::signaling::v1::LAN_HELLO_ROLE_INITIATOR);
  EXPECT_EQ(parsed_hello.sender_tls_certificate_sha256().size(), 32U);
  EXPECT_EQ(parsed_hello.observed_peer_tls_certificate_sha256().size(), 32U);
}

}  // namespace
