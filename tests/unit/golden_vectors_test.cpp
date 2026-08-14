#include "m1_golden_vectors.hpp"
#include "test_bytes.hpp"

#include <heyaki/identity.hpp>
#include <heyaki/signing.hpp>
#include <heyaki/version.hpp>
#include <heyaki/wire.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

namespace {

TEST(GoldenVectors, DeviceIdDerivationAndTextAreExact) {
  const auto public_key =
      heyaki::test::bytes_from_hex(heyaki::test_vectors::identity_public_key_hex);
  const auto expected_digest =
      heyaki::test::bytes_from_hex(heyaki::test_vectors::device_digest_hex);
  const auto derived = heyaki::derive_device_id(public_key);
  ASSERT_TRUE(derived);
  ASSERT_NE(derived.value_if(), nullptr);
  EXPECT_TRUE(std::equal(derived.value_if()->bytes().begin(), derived.value_if()->bytes().end(),
                         expected_digest.begin(), expected_digest.end()));
  EXPECT_EQ(heyaki::to_string(*derived.value_if()), heyaki::test_vectors::device_id_text);
  EXPECT_EQ(*heyaki::parse_device_id(heyaki::test_vectors::device_id_text).value,
            *derived.value_if());
}

TEST(GoldenVectors, CanonicalOfferBytesAreExact) {
  const std::array field_hex{
      heyaki::test_vectors::canonical_field_1_hex,
      heyaki::test_vectors::canonical_field_2_hex,
      heyaki::test_vectors::canonical_field_3_hex,
      heyaki::test_vectors::canonical_field_4_hex,
      heyaki::test_vectors::canonical_field_5_hex,
      heyaki::test_vectors::canonical_field_6_hex,
      heyaki::test_vectors::canonical_field_7_hex,
      heyaki::test_vectors::canonical_field_8_hex,
      heyaki::test_vectors::canonical_field_9_hex,
      heyaki::test_vectors::canonical_field_10_hex,
  };
  std::vector<heyaki::CanonicalField> fields;
  for (std::size_t index = 0U; index < field_hex.size(); ++index) {
    fields.push_back({.number = static_cast<std::uint16_t>(index + 1U),
                      .value = heyaki::test::bytes_from_hex(field_hex[index])});
  }

  EXPECT_EQ(heyaki::signing_domain_separator(heyaki::SigningDomain::offer),
            heyaki::test_vectors::canonical_domain);
  const auto canonical =
      heyaki::canonicalize_for_signature(heyaki::SigningDomain::offer, fields);
  ASSERT_TRUE(canonical);
  EXPECT_EQ(*canonical.value_if(),
            heyaki::test::bytes_from_hex(heyaki::test_vectors::canonical_hex));
}

TEST(GoldenVectors, Ed25519SignatureCoversCanonicalOffer) {
  EXPECT_EQ(heyaki::test::bytes_from_hex(heyaki::test_vectors::ed25519_seed_hex).size(), 32U);
  EXPECT_EQ(heyaki::test::bytes_from_hex(heyaki::test_vectors::ed25519_public_key_hex).size(), 32U);
  EXPECT_EQ(heyaki::test_vectors::ed25519_message_hex,
            heyaki::test_vectors::canonical_hex);
  EXPECT_EQ(heyaki::test::bytes_from_hex(heyaki::test_vectors::ed25519_signature_hex).size(), 64U);
  EXPECT_EQ(heyaki::test_vectors::ed25519_public_key_hex,
            heyaki::test_vectors::identity_public_key_hex);
}

TEST(GoldenVectors, ProtobufEnvelopeAndFrameBytesAreExact) {
  const auto encoded_frame = heyaki::test::bytes_from_hex(heyaki::test_vectors::frame_hex);
  const auto envelope = heyaki::test::bytes_from_hex(heyaki::test_vectors::protobuf_envelope_hex);
  const auto parsed = heyaki::parse_frame(encoded_frame);
  ASSERT_EQ(parsed.status, heyaki::FrameParseStatus::parsed);
  ASSERT_TRUE(parsed.frame.has_value());
  EXPECT_EQ(parsed.consumed, encoded_frame.size());
  EXPECT_EQ(parsed.frame->type, static_cast<std::uint8_t>(heyaki::FrameType::message));
  EXPECT_TRUE(std::equal(parsed.frame->payload.begin(), parsed.frame->payload.end(),
                         envelope.begin(), envelope.end()));

  heyaki::Frame owning{.type = parsed.frame->type,
                       .flags = parsed.frame->flags,
                       .channel_id = parsed.frame->channel_id,
                       .message_id = parsed.frame->message_id,
                       .payload = envelope};
  const auto reencoded = heyaki::encode_frame(owning);
  ASSERT_TRUE(reencoded);
  EXPECT_EQ(*reencoded.value_if(), encoded_frame);

  const auto info = heyaki::build_info();
  EXPECT_EQ(info.protocol_major, heyaki::test_vectors::protocol_major);
  EXPECT_EQ(info.protocol_minor, heyaki::test_vectors::protocol_minor);
}

}  // namespace
