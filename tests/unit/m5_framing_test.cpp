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

// ---- Passwordless pairing approval (pairing_approval_v1, issue #2) --------

PairingApprovalRequestBody approval_request(std::uint8_t seed) {
  PairingApprovalRequestBody request;
  RequestId::Storage bytes{};
  for (std::size_t index = 0U; index < bytes.size(); ++index) {
    bytes[index] = static_cast<std::byte>((index * 5U + seed) & 0xFFU);
  }
  request.request_id = RequestId{bytes};
  request.nonce = PairingNonce{};
  request.nonce[0] = std::byte{seed};
  request.nonce[31] = std::byte{static_cast<std::uint8_t>(seed ^ 0xA5U)};
  request.requested_scopes = {"message.send", "file.push:inbox"};
  return request;
}

TEST(M5PairingApprovalProtocol, RequestRoundTripMatchesFields) {
  const auto request = approval_request(0x2AU);
  auto encoded = encode_pairing_approval_request(request);
  ASSERT_TRUE(encoded);
  EXPECT_LE(encoded.value_if()->size(), Limits{}.max_pairing_payload_bytes);
  auto parsed = parse_pairing_approval_request(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->request_id, request.request_id);
  EXPECT_EQ(parsed.value_if()->nonce, request.nonce);
  EXPECT_EQ(parsed.value_if()->requested_scopes, request.requested_scopes);
  // Round-trip stability: re-encoding the parsed body is byte-identical.
  auto re_encoded = encode_pairing_approval_request(*parsed.value_if());
  ASSERT_TRUE(re_encoded);
  EXPECT_EQ(*re_encoded.value_if(), *encoded.value_if());
}

TEST(M5PairingApprovalProtocol, EncodeRejectsInvalidStructures) {
  const auto request = approval_request(0x11U);

  auto zero_id = request;
  zero_id.request_id = RequestId{};
  auto failed = encode_pairing_approval_request(zero_id);
  ASSERT_FALSE(failed);
  EXPECT_EQ(failed.error_if()->code(), ErrorCode::protocol);
  EXPECT_EQ(failed.error_if()->safe_detail(), "request_id_zero");

  auto zero_nonce = request;
  zero_nonce.nonce = PairingNonce{};
  failed = encode_pairing_approval_request(zero_nonce);
  ASSERT_FALSE(failed);
  EXPECT_EQ(failed.error_if()->safe_detail(), "nonce_zero");

  auto empty_scopes = request;
  empty_scopes.requested_scopes.clear();
  failed = encode_pairing_approval_request(empty_scopes);
  ASSERT_FALSE(failed);
  EXPECT_EQ(failed.error_if()->safe_detail(), "requested_scope_count_invalid");

  auto too_many = request;
  too_many.requested_scopes.assign(max_pairing_requested_scopes + 1U, "message.send");
  failed = encode_pairing_approval_request(too_many);
  ASSERT_FALSE(failed);
  EXPECT_EQ(failed.error_if()->safe_detail(), "requested_scope_count_invalid");

  auto bad_scope = request;
  bad_scope.requested_scopes = {"bad scope"};
  failed = encode_pairing_approval_request(bad_scope);
  ASSERT_FALSE(failed);
  EXPECT_EQ(failed.error_if()->safe_detail(), "requested_scope_syntax_invalid");
}

TEST(M5PairingApprovalProtocol, ParseRejectsPasswordField) {
  const auto request = approval_request(0x33U);
  auto encoded = encode_pairing_approval_request(request);
  ASSERT_TRUE(encoded);
  // Field 3 carries the password on the password pairing body; splicing it
  // into an approval payload must be refused, not silently ignored.
  std::vector<std::byte> with_password = *encoded.value_if();
  const std::array<std::byte, 5> password_field{std::byte{0x1AU}, std::byte{0x03U},
                                                std::byte{'p'}, std::byte{'w'},
                                                std::byte{'!'}};
  with_password.insert(with_password.end(), password_field.begin(), password_field.end());
  auto parsed = parse_pairing_approval_request(with_password);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error_if()->code(), ErrorCode::protocol);
  EXPECT_EQ(parsed.error_if()->safe_detail(), "password_field_unexpected");
  // The clean payload still parses: the rejection came from the field itself.
  ASSERT_TRUE(parse_pairing_approval_request(*encoded.value_if()));
}

TEST(M5PairingApprovalProtocol, ParseRejectsMalformedPayloads) {
  const auto request = approval_request(0x44U);
  auto encoded = encode_pairing_approval_request(request);
  ASSERT_TRUE(encoded);
  const auto valid = *encoded.value_if();

  // Duplicate request id field (field 1, length-delimited, 16 bytes).
  std::vector<std::byte> duplicate = valid;
  duplicate.push_back(std::byte{0x0AU});
  duplicate.push_back(std::byte{0x10U});
  for (std::size_t index = 0U; index < 16U; ++index) {
    duplicate.push_back(std::byte{0U});
  }
  auto parsed = parse_pairing_approval_request(duplicate);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error_if()->safe_detail(), "request_id_field_conflict");

  // Unknown field (field 5, length-delimited, empty).
  std::vector<std::byte> unknown = valid;
  unknown.push_back(std::byte{0x2AU});
  unknown.push_back(std::byte{0x00U});
  parsed = parse_pairing_approval_request(unknown);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error_if()->safe_detail(), "field_unknown");

  // Missing fields: only the request id is present.
  std::vector<std::byte> minimal{std::byte{0x0AU}, std::byte{0x10U}};
  for (std::size_t index = 0U; index < 16U; ++index) {
    minimal.push_back(static_cast<std::byte>(index));
  }
  parsed = parse_pairing_approval_request(minimal);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error_if()->safe_detail(), "field_missing");

  // Scope field with a non-length-delimited wire type (varint).
  std::vector<std::byte> varint_scope = valid;
  varint_scope.push_back(std::byte{0x20U});
  varint_scope.push_back(std::byte{0x01U});
  parsed = parse_pairing_approval_request(varint_scope);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error_if()->safe_detail(), "scope_field_invalid");
}

TEST(M5PairingApprovalProtocol, PayloadCeilingMatchesPairingLimit) {
  // Encode: 256 max-length scopes exceed the 8 KiB pairing payload ceiling.
  auto request = approval_request(0x55U);
  request.requested_scopes.clear();
  for (std::size_t index = 0U; index < max_pairing_requested_scopes; ++index) {
    request.requested_scopes.push_back("s" + std::to_string(index) +
                                       std::string(200U, 'a'));
  }
  auto oversized = encode_pairing_approval_request(request);
  ASSERT_FALSE(oversized);
  EXPECT_EQ(oversized.error_if()->code(), ErrorCode::resource_exhausted);
  EXPECT_EQ(oversized.error_if()->safe_detail(), "object_too_large");

  // Parse: any payload above the ceiling is refused before field parsing.
  const std::vector<std::byte> too_big(Limits{}.max_pairing_payload_bytes + 1U);
  auto parsed = parse_pairing_approval_request(too_big);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error_if()->code(), ErrorCode::resource_exhausted);
  EXPECT_EQ(parsed.error_if()->safe_detail(), "object_too_large");

  // Exactly at the ceiling (31 x 255-byte scopes + 1 x 139-byte scope + the
  // id and nonce = 8192 bytes) both gates pass and the body parses.
  PairingApprovalRequestBody at_limit = approval_request(0x66U);
  at_limit.requested_scopes.assign(31U, std::string(255U, 'a'));
  at_limit.requested_scopes.push_back(std::string(139U, 'b'));
  auto at_limit_encoded = encode_pairing_approval_request(at_limit);
  ASSERT_TRUE(at_limit_encoded);
  EXPECT_EQ(at_limit_encoded.value_if()->size(), Limits{}.max_pairing_payload_bytes);
  auto at_limit_parsed = parse_pairing_approval_request(*at_limit_encoded.value_if());
  ASSERT_TRUE(at_limit_parsed);
  EXPECT_EQ(at_limit_parsed.value_if()->requested_scopes.size(), 32U);

  // The frame layer applies the same domain limit to the approval frame.
  const auto approval_type =
      static_cast<std::uint8_t>(FrameType::pairing_approval_request);
  EXPECT_STREQ(frame_payload_limit_error(approval_type,
                                         Limits{}.max_pairing_payload_bytes + 1U,
                                         Limits{}),
               "pairing_payload_limit");
  EXPECT_EQ(frame_payload_limit_error(approval_type, Limits{}.max_pairing_payload_bytes,
                                      Limits{}),
            nullptr);
}

TEST(M5PairingApprovalProtocol, ApprovalFrameIsKnownAndRidesTheControlChannel) {
  const auto approval_type =
      static_cast<std::uint8_t>(FrameType::pairing_approval_request);
  EXPECT_EQ(approval_type, 0x12U);
  EXPECT_TRUE(is_known_frame_type(approval_type));

  const auto request = approval_request(0x77U);
  auto payload = encode_pairing_approval_request(request);
  ASSERT_TRUE(payload);

  Frame frame;
  frame.type = approval_type;
  frame.message_id = test_message_id();
  frame.channel_id = 0U;
  frame.payload = *payload.value_if();
  auto encoded = encode_frame(frame);
  ASSERT_TRUE(encoded);
  auto decoded = parse_frame(*encoded.value_if());
  ASSERT_TRUE(decoded.frame.has_value());
  auto body = parse_pairing_approval_request(decoded.frame->payload);
  ASSERT_TRUE(body);
  EXPECT_EQ(body.value_if()->request_id, request.request_id);
  EXPECT_EQ(body.value_if()->nonce, request.nonce);
  EXPECT_EQ(body.value_if()->requested_scopes, request.requested_scopes);

  // Control-channel discipline: a non-zero channel is refused on encode.
  frame.channel_id = 7U;
  auto misplaced = encode_frame(frame);
  ASSERT_FALSE(misplaced);
  EXPECT_EQ(misplaced.error_if()->safe_detail(), "control_channel_required");
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
