// M5 core tests: incremental frame codec (M5-01), TrustGrant canonical
// signing and scope adjudication (M5-11/M5-12), and pairing wire admission
// (M5-07/M5-09 structural rules).

#include <heyaki/frame_stream.hpp>
#include <heyaki/identity.hpp>
#include <heyaki/pairing_protocol.hpp>
#include <heyaki/trust_grant.hpp>
#include <heyaki/wire.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <random>

namespace heyaki {
namespace {

MessageId test_message_id() {
  MessageId::Storage bytes{};
  for (std::size_t index = 0U; index < bytes.size(); ++index) {
    bytes[index] = static_cast<std::byte>((index * 7U + 1U) & 0xFFU);
  }
  return MessageId{bytes};
}

Frame sample_frame(std::uint8_t type, std::uint32_t channel, std::size_t payload_size) {
  Frame frame;
  frame.type = type;
  frame.channel_id = channel;
  frame.message_id = test_message_id();
  frame.payload.resize(payload_size);
  for (std::size_t index = 0U; index < payload_size; ++index) {
    frame.payload[index] = static_cast<std::byte>(index & 0xFFU);
  }
  return frame;
}

TEST(M5FrameStream, DecodesFramesDeliveredByteByByte) {
  FrameStreamDecoder decoder;
  const auto frame = sample_frame(0x20U, 7U, 64U);
  auto encoded = encode_frame(frame);
  ASSERT_TRUE(encoded);
  for (const auto byte : *encoded.value_if()) {
    ASSERT_TRUE(decoder.append(std::span{&byte, 1U}));
  }
  auto taken = decoder.take_frame();
  ASSERT_TRUE(taken);
  ASSERT_TRUE(taken.value_if()->has_value());
  const auto& parsed = **taken.value_if();
  EXPECT_EQ(parsed.type, frame.type);
  EXPECT_EQ(parsed.channel_id, frame.channel_id);
  EXPECT_EQ(parsed.message_id, frame.message_id);
  EXPECT_EQ(parsed.payload, frame.payload);
  EXPECT_EQ(decoder.buffered_bytes(), 0U);
}

TEST(M5FrameStream, DecodesCoalescedFramesAndSplitsAcrossAppends) {
  FrameStreamDecoder decoder;
  auto first = encode_frame(sample_frame(0x51U, 3U, 32U));
  auto second = encode_frame(sample_frame(0x41U, 5U, 16U));
  ASSERT_TRUE(first && second);
  std::vector<std::byte> coalesced = *first.value_if();
  coalesced.insert(coalesced.end(), second.value_if()->begin(),
                   second.value_if()->end());
  // Split at every possible boundary offset to prove boundary independence.
  for (std::size_t split = 0U; split <= coalesced.size(); ++split) {
    FrameStreamDecoder split_decoder;
    ASSERT_TRUE(split_decoder.append(std::span{coalesced.data(), split}));
    ASSERT_TRUE(split_decoder.append(
        std::span{coalesced.data() + split, coalesced.size() - split}));
    auto a = split_decoder.take_frame();
    auto b = split_decoder.take_frame();
    ASSERT_TRUE(a && a.value_if()->has_value());
    ASSERT_TRUE(b && b.value_if()->has_value());
    EXPECT_EQ((*a.value_if())->type, 0x51U);
    EXPECT_EQ((*b.value_if())->type, 0x41U);
    auto done = split_decoder.take_frame();
    ASSERT_TRUE(done);
    EXPECT_FALSE(done.value_if()->has_value());
  }
}

TEST(M5FrameStream, RejectsNonCanonicalVarintsAndOversizedFrames) {
  {
    FrameStreamDecoder decoder;
    // 0x80 0x00 is a non-canonical encoding of zero.
    const std::array bytes{std::byte{0x80}, std::byte{0x00}};
    ASSERT_TRUE(decoder.append(bytes));
    const auto step = decoder.next_view();
    EXPECT_EQ(step.status, FrameStreamStatus::invalid);
    EXPECT_EQ(step.error->safe_detail(), "non_canonical_varint");
    EXPECT_TRUE(decoder.poisoned());
  }
  {
    FrameStreamDecoder decoder;
    // Varint continues past five bytes.
    const std::array bytes{std::byte{0x80}, std::byte{0x80}, std::byte{0x80},
                           std::byte{0x80}, std::byte{0x80}};
    ASSERT_TRUE(decoder.append(bytes));
    const auto step = decoder.next_view();
    EXPECT_EQ(step.status, FrameStreamStatus::invalid);
    EXPECT_TRUE(decoder.poisoned());
  }
  {
    FrameStreamDecoder decoder;
    // Declared length 0xFFFFFFFF exceeds the default 2 MiB ceiling: rejected
    // before any payload could arrive.
    const std::array bytes{std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF},
                           std::byte{0xFF}, std::byte{0x0F}};
    ASSERT_TRUE(decoder.append(bytes));
    const auto step = decoder.next_view();
    EXPECT_EQ(step.status, FrameStreamStatus::invalid);
    EXPECT_EQ(step.error->safe_detail(), "varint_limit");
    EXPECT_TRUE(decoder.poisoned());
    decoder.reset();
    EXPECT_FALSE(decoder.poisoned());
  }
}

TEST(M5FrameStream, EncoderMatchesOneShotBytesAndReservesExactSize) {
  FrameStreamEncoder encoder;
  const auto frame = sample_frame(0x62U, 12U, 100U);
  auto reference = encode_frame(frame);
  ASSERT_TRUE(reference);
  std::vector<std::byte> output;
  const auto size = encoder.encoded_size(frame.type, 0U, frame.channel_id,
                                         frame.payload.size());
  ASSERT_TRUE(size);
  EXPECT_EQ(*size.value_if(), reference.value_if()->size());
  output.reserve(*size.value_if());
  const auto header = encoder.encode_header(output, frame.type, 0U, frame.channel_id,
                                            frame.message_id,
                                            frame.payload.size());
  ASSERT_TRUE(header);
  output.insert(output.end(), frame.payload.begin(), frame.payload.end());
  EXPECT_EQ(output, *reference.value_if());
}

TEST(M5FrameStream, DecoderRejectsBusinessFrameOnControlChannel) {
  // Hand-built wire bytes: a MESSAGE frame claiming channel 0. encode_frame
  // refuses this shape, so the decoder is the line under test.
  const auto id = test_message_id();
  std::vector<std::byte> bytes{std::byte{0x17}, std::byte{0x20}, std::byte{0x00},
                               std::byte{0x00}};
  bytes.insert(bytes.end(), id.bytes().begin(), id.bytes().end());
  bytes.insert(bytes.end(), 4U, std::byte{0xAA});
  FrameStreamDecoder decoder;
  ASSERT_TRUE(decoder.append(bytes));
  const auto step = decoder.next_view();
  EXPECT_EQ(step.status, FrameStreamStatus::invalid);
  EXPECT_EQ(step.error->safe_detail(), "business_channel_required");
}

struct TrustFixture : public ::testing::Test {
  IdentityKeyPair issuer{[] {
    auto identity = create_identity();
    EXPECT_TRUE(identity);
    return std::move(*identity.value_if());
  }()};
  IdentityKeyPair subject{[] {
    auto identity = create_identity();
    EXPECT_TRUE(identity);
    return std::move(*identity.value_if());
  }()};

  SignedTrustGrant make_grant() {
    SignedTrustGrant grant;
    GrantId::Storage bytes{};
    for (std::size_t index = 0U; index < bytes.size(); ++index) {
      bytes[index] = static_cast<std::byte>((index * 11U + 3U) & 0xFFU);
    }
    grant.grant_id = GrantId{bytes};
    grant.issuer = issuer.device_id();
    grant.subject = subject.device_id();
    grant.granted_scopes = {"file.push:inbox", "message.send"};
    grant.password_generation = 2U;
    grant.issued_unix_milliseconds = 1'700'000'000'000U;
    grant.nonce = PairingNonce{};
    for (std::size_t index = 0U; index < grant.nonce.size(); ++index) {
      grant.nonce[index] = static_cast<std::byte>((index * 5U + 1U) & 0xFFU);
    }
    auto signed_grant = sign_signed_trust_grant(grant, issuer);
    EXPECT_TRUE(signed_grant);
    return grant;
  }
};

TEST_F(TrustFixture, GrantRoundTripsAndVerifiesUnderIssuerKey) {
  auto grant = make_grant();
  EXPECT_TRUE(verify_signed_trust_grant(
      grant, std::span<const std::byte>{issuer.public_key().data(),
                                        issuer.public_key().size()},
      grant.issued_unix_milliseconds + 1000U));
  auto encoded = encode_signed_trust_grant(grant);
  ASSERT_TRUE(encoded);
  auto parsed = parse_signed_trust_grant(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->granted_scopes, grant.granted_scopes);
  EXPECT_EQ(parsed.value_if()->issuer, grant.issuer);
  EXPECT_EQ(parsed.value_if()->nonce, grant.nonce);
  EXPECT_TRUE(verify_signed_trust_grant(
      *parsed.value_if(),
      std::span<const std::byte>{issuer.public_key().data(),
                                 issuer.public_key().size()},
      grant.issued_unix_milliseconds + 1000U));
}

TEST_F(TrustFixture, ForgedAndTamperedGrantsFailVerification) {
  auto grant = make_grant();
  // Wrong key: a different issuer cannot have signed this grant.
  EXPECT_FALSE(verify_signed_trust_grant(
      grant, std::span<const std::byte>{subject.public_key().data(),
                                        subject.public_key().size()},
      grant.issued_unix_milliseconds + 1000U));
  // Tampered scopes invalidate the signature.
  auto tampered = grant;
  tampered.granted_scopes.push_back("shell.open:maintenance");
  EXPECT_FALSE(verify_signed_trust_grant(
      tampered, std::span<const std::byte>{issuer.public_key().data(),
                                           issuer.public_key().size()},
      tampered.issued_unix_milliseconds + 1000U));
  // Expired grants fail once past their optional expiry.
  auto expired = make_grant();
  expired.expires_unix_milliseconds = expired.issued_unix_milliseconds + 10'000U;
  EXPECT_FALSE(verify_signed_trust_grant(
      expired, std::span<const std::byte>{issuer.public_key().data(),
                                          issuer.public_key().size()},
      *expired.expires_unix_milliseconds + 1U));
}

TEST(M5TrustScopes, NormalizationAndIntersection) {
  auto normalized = normalize_trust_scopes({"b.scope", "a.scope", "b.scope"});
  ASSERT_TRUE(normalized);
  EXPECT_EQ(*normalized.value_if(), (std::vector<std::string>{"a.scope", "b.scope"}));
  EXPECT_FALSE(normalize_trust_scopes({std::string(300U, 'a')}));
  EXPECT_FALSE(normalize_trust_scopes({std::string{"bad scope"}}));

  const std::vector<std::string> granted = {"file.push:*", "message.send"};
  const auto allowed =
      intersect_trust_scopes({"file.push:inbox", "message.send", "shell.open:x"},
                             granted);
  EXPECT_EQ(allowed, (std::vector<std::string>{"file.push:inbox", "message.send"}));

  const auto adjudication =
      adjudicate_trust_scopes({"file.push:inbox"}, granted, std::nullopt);
  EXPECT_TRUE(adjudication.authorized);
  const auto narrowed = adjudicate_trust_scopes(
      {"file.push:inbox"}, granted, std::vector<std::string>{"message.send"});
  EXPECT_FALSE(narrowed.authorized);
}

TEST(M5PairingProtocol, RequestResultRoundTripAndStructuralDenials) {
  PairingRequestBody request;
  RequestId::Storage bytes{};
  for (std::size_t index = 0U; index < bytes.size(); ++index) {
    bytes[index] = static_cast<std::byte>((index * 3U + 1U) & 0xFFU);
  }
  request.request_id = RequestId{bytes};
  request.nonce = PairingNonce{};
  request.nonce[0] = std::byte{0x42};
  request.password_utf8 = "correct horse";
  request.requested_scopes = {"message.send"};
  auto encoded = encode_pairing_request(request);
  ASSERT_TRUE(encoded);
  auto parsed = parse_pairing_request(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->password_utf8, request.password_utf8);
  // Empty scopes / empty password / zero nonce are structural failures.
  auto broken = request;
  broken.requested_scopes.clear();
  EXPECT_FALSE(encode_pairing_request(broken));
  broken = request;
  broken.password_utf8.clear();
  EXPECT_FALSE(encode_pairing_request(broken));
  broken = request;
  broken.nonce = PairingNonce{};
  EXPECT_FALSE(encode_pairing_request(broken));

  PairingResultBody result;
  result.request_id = request.request_id;
  result.status = StableStatus::permission_denied;
  auto result_encoded = encode_pairing_result(result);
  ASSERT_TRUE(result_encoded);
  auto result_parsed = parse_pairing_result(*result_encoded.value_if());
  ASSERT_TRUE(result_parsed);
  EXPECT_EQ(result_parsed.value_if()->status, StableStatus::permission_denied);
  // ok without a grant, or a grant with a failure status, are inconsistent.
  auto inconsistent = result;
  inconsistent.status = StableStatus::ok;
  EXPECT_FALSE(encode_pairing_result(inconsistent));
}

TEST(M5PairingProtocol, AdmissionReplaysDuplicatesAndCapsAttempts) {
  PairingRequestAdmission admission;
  PairingRequestBody request;
  RequestId::Storage bytes{};
  bytes[0] = std::byte{9U};
  request.request_id = RequestId{bytes};
  request.nonce = PairingNonce{};
  request.nonce[1] = std::byte{7U};
  request.password_utf8 = "pw";
  request.requested_scopes = {"message.send"};

  auto admitted = admission.admit_request(request);
  ASSERT_TRUE(admitted);
  EXPECT_EQ(admitted.value_if()->action, PairingAdmissionAction::admitted);

  PairingResultBody terminal;
  terminal.request_id = request.request_id;
  terminal.status = StableStatus::unauthenticated;
  ASSERT_TRUE(admission.record_result(terminal));

  // Byte-identical duplicate replays the terminal result.
  auto duplicate = admission.admit_request(request);
  ASSERT_TRUE(duplicate);
  EXPECT_EQ(duplicate.value_if()->action, PairingAdmissionAction::duplicate);
  ASSERT_TRUE(duplicate.value_if()->cached_result.has_value());
  EXPECT_EQ(duplicate.value_if()->cached_result->status, StableStatus::unauthenticated);

  // Same request id with a different nonce is a conflicting duplicate.
  auto conflicting = request;
  conflicting.nonce[2] = std::byte{1U};
  EXPECT_FALSE(admission.admit_request(conflicting));

  // Distinct requests burn the attempt budget and then rate-limit.
  for (std::size_t attempt = 1U;
       attempt < Limits{}.max_pairing_attempts_per_session; ++attempt) {
    auto next = request;
    next.request_id = RequestId{[attempt] {
      RequestId::Storage id{};
      id[0] = static_cast<std::byte>(attempt + 1U);
      return id;
    }()};
    auto ok = admission.admit_request(next);
    ASSERT_TRUE(ok);
    PairingResultBody denied;
    denied.request_id = next.request_id;
    denied.status = StableStatus::unauthenticated;
    ASSERT_TRUE(admission.record_result(denied));
  }
  auto fresh = request;
  fresh.request_id = RequestId{[] {
    RequestId::Storage id{};
    id[0] = std::byte{0xEE};
    return id;
  }()};
  const auto exhausted = admission.admit_request(fresh);
  ASSERT_FALSE(exhausted);
  EXPECT_EQ(exhausted.error_if()->code(), ErrorCode::pairing_rate_limited);
  EXPECT_TRUE(admission.exhausted());
}

}  // namespace
}  // namespace heyaki
