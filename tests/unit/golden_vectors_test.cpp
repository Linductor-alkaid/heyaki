#include "m1_golden_vectors.hpp"
#include "m3a_lan_golden_vectors.hpp"
#include "test_bytes.hpp"

#include <heyaki/identity.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/signing.hpp>
#include <heyaki/version.hpp>
#include <heyaki/wire.hpp>

#include <gtest/gtest.h>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

namespace {

bool verifies_ed25519(std::span<const std::byte> public_key,
                      std::span<const std::byte> message,
                      std::span<const std::byte> signature) {
  auto* key = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, nullptr,
      reinterpret_cast<const unsigned char*>(public_key.data()), public_key.size());
  if (key == nullptr) {
    return false;
  }
  auto* context = EVP_MD_CTX_new();
  const bool verified =
      context != nullptr && EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1 &&
      EVP_DigestVerify(context, reinterpret_cast<const unsigned char*>(signature.data()),
                       signature.size(), reinterpret_cast<const unsigned char*>(message.data()),
                       message.size()) == 1;
  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  return verified;
}

std::vector<heyaki::CanonicalField> fields_from_hex(
    std::span<const std::string_view> fields) {
  std::vector<heyaki::CanonicalField> result;
  result.reserve(fields.size());
  for (std::size_t index = 0U; index < fields.size(); ++index) {
    result.push_back({.number = static_cast<std::uint16_t>(index + 1U),
                      .value = heyaki::test::bytes_from_hex(fields[index])});
  }
  return result;
}

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

TEST(GoldenVectors, SignalingTranscriptHashIsExact) {
  EXPECT_EQ(heyaki::test_vectors::signaling_transcript_domain,
            "heyaki.signaling-transcript.v1");
  const auto offer = heyaki::test::bytes_from_hex(heyaki::test_vectors::canonical_hex);
  const auto answer =
      heyaki::test::bytes_from_hex(heyaki::test_vectors::canonical_answer_hex);
  const auto expected = heyaki::test::bytes_from_hex(
      heyaki::test_vectors::signaling_transcript_sha256_hex);
  const auto transcript = heyaki::hash_signaling_transcript(offer, answer);
  ASSERT_TRUE(transcript);
  EXPECT_TRUE(std::equal(transcript.value_if()->begin(), transcript.value_if()->end(),
                         expected.begin(), expected.end()));

  auto changed_answer = answer;
  changed_answer.back() ^= std::byte{1U};
  const auto changed = heyaki::hash_signaling_transcript(offer, changed_answer);
  ASSERT_TRUE(changed);
  EXPECT_NE(*changed.value_if(), *transcript.value_if());
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
  EXPECT_EQ(heyaki::test_vectors::protocol_major, 1U);
  EXPECT_EQ(heyaki::test_vectors::protocol_minor, 0U);
  EXPECT_EQ(info.protocol_major, heyaki::test_vectors::lan::protocol_major);
  EXPECT_EQ(info.protocol_minor, heyaki::test_vectors::lan::protocol_minor);
}

TEST(GoldenVectors, LanDiscoveryConstantsAreExact) {
  EXPECT_EQ(heyaki::test_vectors::lan::protocol_major, 1U);
  EXPECT_EQ(heyaki::test_vectors::lan::protocol_minor, 1U);
  EXPECT_EQ(heyaki::lan_discovery_ipv4_group, heyaki::test_vectors::lan::ipv4_group);
  EXPECT_EQ(heyaki::lan_discovery_ipv6_group, heyaki::test_vectors::lan::ipv6_group);
  EXPECT_EQ(heyaki::lan_discovery_udp_port, heyaki::test_vectors::lan::udp_port);
  EXPECT_EQ(heyaki::lan_discovery_hop_limit, heyaki::test_vectors::lan::hop_limit);
  EXPECT_EQ(std::vector(heyaki::lan_datagram_magic.begin(), heyaki::lan_datagram_magic.end()),
            heyaki::test::bytes_from_hex(heyaki::test_vectors::lan::datagram_magic_hex));
  EXPECT_EQ(heyaki::lan_datagram_envelope_version,
            heyaki::test_vectors::lan::datagram_envelope_version);
  EXPECT_EQ(static_cast<std::uint8_t>(heyaki::LanDatagramType::presence),
            heyaki::test_vectors::lan::presence_type);
  EXPECT_EQ(heyaki::max_lan_datagram_bytes,
            heyaki::test_vectors::lan::max_datagram_bytes);
}

TEST(GoldenVectors, CanonicalLanPresenceAndSignatureAreExact) {
  EXPECT_EQ(heyaki::signing_domain_separator(heyaki::SigningDomain::lan_presence),
            heyaki::test_vectors::lan::presence_domain);
  const auto canonical = heyaki::canonicalize_for_signature(
      heyaki::SigningDomain::lan_presence,
      fields_from_hex(heyaki::test_vectors::lan::presence_fields));
  ASSERT_TRUE(canonical);
  EXPECT_EQ(*canonical.value_if(), heyaki::test::bytes_from_hex(
                                       heyaki::test_vectors::lan::presence_canonical_hex));
  EXPECT_TRUE(verifies_ed25519(
      heyaki::test::bytes_from_hex(heyaki::test_vectors::lan::ed25519_public_key_hex),
      *canonical.value_if(),
      heyaki::test::bytes_from_hex(heyaki::test_vectors::lan::presence_signature_hex)));
}

TEST(GoldenVectors, CanonicalLanHelloAndSignatureAreExact) {
  EXPECT_EQ(heyaki::signing_domain_separator(heyaki::SigningDomain::lan_hello),
            heyaki::test_vectors::lan::hello_domain);
  const auto canonical = heyaki::canonicalize_for_signature(
      heyaki::SigningDomain::lan_hello,
      fields_from_hex(heyaki::test_vectors::lan::hello_fields));
  ASSERT_TRUE(canonical);
  EXPECT_EQ(*canonical.value_if(), heyaki::test::bytes_from_hex(
                                       heyaki::test_vectors::lan::hello_canonical_hex));
  EXPECT_TRUE(verifies_ed25519(
      heyaki::test::bytes_from_hex(heyaki::test_vectors::lan::ed25519_public_key_hex),
      *canonical.value_if(),
      heyaki::test::bytes_from_hex(heyaki::test_vectors::lan::hello_signature_hex)));
}

}  // namespace
