#include <heyaki/session_protocol.hpp>

#include <heyaki/session/v1/session.pb.h>

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

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

struct Fixture {
  heyaki::IdentityKeyPair peer_identity;
  heyaki::SignedSessionHello hello;

  static Fixture create(std::uint64_t epoch = 7U) {
    auto identity = heyaki::create_identity();
    EXPECT_TRUE(identity);
    heyaki::SignedSessionHello hello;
    hello.sender = {identity.value_if()->device_id(), filled<heyaki::EndpointId>(0x31U)};
    hello.peer = {filled<heyaki::DeviceId>(0x51U), filled<heyaki::EndpointId>(0x71U)};
    hello.session_id = filled<heyaki::SessionId>(0x91U);
    hello.session_epoch = epoch;
    hello.initiator_nonce = filled_array<heyaki::signaling_nonce_bytes>(0x11U);
    hello.responder_nonce = filled_array<heyaki::signaling_nonce_bytes>(0x41U);
    hello.signaling_transcript_sha256 =
        filled_array<heyaki::signaling_transcript_sha256_bytes>(0x81U);
    hello.expires_unix_milliseconds = 1'060'000U;
    EXPECT_TRUE(heyaki::sign_signed_session_hello(hello, *identity.value_if()));
    return {std::move(*identity.value_if()), hello};
  }
};

heyaki::SessionHelloExpectation expectation_for(const heyaki::SignedSessionHello& hello,
                                                 std::uint64_t epoch) {
  return {.sender = hello.sender,
          .peer = hello.peer,
          .session_id = hello.session_id,
          .session_epoch = epoch,
          .initiator_nonce = hello.initiator_nonce,
          .responder_nonce = hello.responder_nonce,
          .signaling_transcript_sha256 = hello.signaling_transcript_sha256};
}

heyaki::ProtocolHello local_protocol() {
  return {.version = heyaki::current_protocol_version,
          .supported = {heyaki::protocol_1_1_capability_bits},
          .required = {static_cast<std::uint64_t>(heyaki::Capability::session)}};
}

TEST(M4SessionHello, RoundTripsAndMatchesFrozenProtobufSchema) {
  auto fixture = Fixture::create();
  auto encoded = heyaki::encode_signed_session_hello(fixture.hello);
  ASSERT_TRUE(encoded);
  auto parsed = heyaki::parse_signed_session_hello(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->sender, fixture.hello.sender);
  EXPECT_EQ(parsed.value_if()->session_epoch, fixture.hello.session_epoch);
  EXPECT_EQ(parsed.value_if()->signaling_transcript_sha256,
            fixture.hello.signaling_transcript_sha256);
  EXPECT_TRUE(heyaki::verify_signed_session_hello(
      *parsed.value_if(), fixture.peer_identity.public_key(), 1'000'000U));

  heyaki::protocol::session::v1::SessionHello protobuf;
  ASSERT_TRUE(protobuf.ParseFromArray(encoded.value_if()->data(),
                                      static_cast<int>(encoded.value_if()->size())));
  EXPECT_EQ(protobuf.session_epoch(), 7U);
  EXPECT_EQ(protobuf.sender().device_id().size(), 32U);
  EXPECT_EQ(protobuf.signature().ed25519().size(), 64U);
}

TEST(M4SessionHello, RejectsSignatureAndTranscriptSubstitution) {
  auto fixture = Fixture::create();
  fixture.hello.signaling_transcript_sha256[0] ^= std::byte{1U};
  auto verified = heyaki::verify_signed_session_hello(
      fixture.hello, fixture.peer_identity.public_key(), 1'000'000U);
  ASSERT_FALSE(verified);
  EXPECT_EQ(verified.error_if()->code(), heyaki::ErrorCode::authentication);
}

TEST(M4SessionHello, AdmitsOnceAndRejectsConflictingDuplicate) {
  auto fixture = Fixture::create();
  heyaki::SessionHelloAdmission admission(
      expectation_for(fixture.hello, 7U), fixture.peer_identity.public_key(), local_protocol());
  auto encoded = heyaki::encode_signed_session_hello(fixture.hello);
  ASSERT_TRUE(encoded);
  auto first = admission.admit(*encoded.value_if(), 1'000'000U);
  ASSERT_TRUE(first);
  EXPECT_EQ(first.value_if()->action, heyaki::SessionHelloAdmissionAction::accepted);
  ASSERT_TRUE(first.value_if()->negotiated_protocol);
  EXPECT_TRUE(admission.authenticated());
  auto duplicate = admission.admit(*encoded.value_if(), 1'000'000U);
  ASSERT_TRUE(duplicate);
  EXPECT_EQ(duplicate.value_if()->action, heyaki::SessionHelloAdmissionAction::duplicate);

  fixture.hello.expires_unix_milliseconds += 1U;
  ASSERT_TRUE(heyaki::sign_signed_session_hello(fixture.hello, fixture.peer_identity));
  auto conflicting = heyaki::encode_signed_session_hello(fixture.hello);
  ASSERT_TRUE(conflicting);
  auto rejected = admission.admit(*conflicting.value_if(), 1'000'000U);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->code(), heyaki::ErrorCode::authentication);
}

TEST(M4SessionHello, IgnoresLowerEpochAndRequiresNewTransportForHigherEpoch) {
  auto late = Fixture::create(6U);
  heyaki::SessionHelloAdmission admission(
      expectation_for(late.hello, 7U), late.peer_identity.public_key(), local_protocol());
  auto encoded_late = heyaki::encode_signed_session_hello(late.hello);
  ASSERT_TRUE(encoded_late);
  auto ignored = admission.admit(*encoded_late.value_if(), 1'000'000U);
  ASSERT_TRUE(ignored);
  EXPECT_EQ(ignored.value_if()->action, heyaki::SessionHelloAdmissionAction::late_epoch);
  EXPECT_FALSE(admission.authenticated());

  late.hello.session_epoch = 8U;
  ASSERT_TRUE(heyaki::sign_signed_session_hello(late.hello, late.peer_identity));
  auto encoded_future = heyaki::encode_signed_session_hello(late.hello);
  ASSERT_TRUE(encoded_future);
  auto rejected = admission.admit(*encoded_future.value_if(), 1'000'000U);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->code(), heyaki::ErrorCode::authentication);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "higher_epoch_requires_new_transport");
}

}  // namespace
