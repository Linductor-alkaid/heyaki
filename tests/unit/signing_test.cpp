#include "m1_golden_vectors.hpp"
#include "test_bytes.hpp"

#include <heyaki/signing.hpp>

#include <gtest/gtest.h>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <initializer_list>
#include <memory>
#include <vector>

namespace {

TEST(Signing, CanonicalOfferSeedProducesThePublishedKeyAndSignature) {
  const auto seed = heyaki::test::bytes_from_hex(heyaki::test_vectors::ed25519_seed_hex);
  const auto public_key =
      heyaki::test::bytes_from_hex(heyaki::test_vectors::ed25519_public_key_hex);
  const auto message = heyaki::test::bytes_from_hex(heyaki::test_vectors::ed25519_message_hex);
  const auto signature = heyaki::test::bytes_from_hex(heyaki::test_vectors::ed25519_signature_hex);
  ASSERT_EQ(seed.size(), 32U);
  ASSERT_EQ(public_key.size(), 32U);
  ASSERT_EQ(signature.size(), 64U);
  ASSERT_FALSE(message.empty());

  using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
  using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

  Key private_key{EVP_PKEY_new_raw_private_key(
                      EVP_PKEY_ED25519, nullptr,
                      reinterpret_cast<const unsigned char*>(seed.data()), seed.size()),
                  EVP_PKEY_free};
  ASSERT_NE(private_key, nullptr);

  std::array<unsigned char, 32U> derived_public_key{};
  std::size_t derived_public_key_size = derived_public_key.size();
  ASSERT_EQ(EVP_PKEY_get_raw_public_key(private_key.get(), derived_public_key.data(),
                                        &derived_public_key_size),
            1);
  ASSERT_EQ(derived_public_key_size, public_key.size());
  EXPECT_TRUE(std::equal(public_key.begin(), public_key.end(), derived_public_key.begin(),
                         [](std::byte expected, unsigned char actual) {
                           return std::to_integer<unsigned char>(expected) == actual;
                         }));

  Context signing_context{EVP_MD_CTX_new(), EVP_MD_CTX_free};
  ASSERT_NE(signing_context, nullptr);
  ASSERT_EQ(EVP_DigestSignInit(signing_context.get(), nullptr, nullptr, nullptr,
                               private_key.get()),
            1);
  std::array<unsigned char, 64U> generated_signature{};
  std::size_t generated_signature_size = generated_signature.size();
  ASSERT_EQ(EVP_DigestSign(signing_context.get(), generated_signature.data(),
                           &generated_signature_size,
                           reinterpret_cast<const unsigned char*>(message.data()), message.size()),
            1);
  ASSERT_EQ(generated_signature_size, signature.size());
  EXPECT_TRUE(std::equal(signature.begin(), signature.end(), generated_signature.begin(),
                         [](std::byte expected, unsigned char actual) {
                           return std::to_integer<unsigned char>(expected) == actual;
                         }));

  Key verification_key{EVP_PKEY_new_raw_public_key(
                           EVP_PKEY_ED25519, nullptr,
                           reinterpret_cast<const unsigned char*>(public_key.data()),
                           public_key.size()),
                       EVP_PKEY_free};
  ASSERT_NE(verification_key, nullptr);
  Context verification_context{EVP_MD_CTX_new(), EVP_MD_CTX_free};
  ASSERT_NE(verification_context, nullptr);
  ASSERT_EQ(EVP_DigestVerifyInit(verification_context.get(), nullptr, nullptr, nullptr,
                                 verification_key.get()),
            1);
  EXPECT_EQ(EVP_DigestVerify(
                verification_context.get(),
                reinterpret_cast<const unsigned char*>(signature.data()), signature.size(),
                reinterpret_cast<const unsigned char*>(message.data()), message.size()),
            1);
}

TEST(Signing, CanonicalizerRejectsMissingDomainFields) {
  std::vector<heyaki::CanonicalField> fields;
  for (std::uint16_t number = 1U; number < 10U; ++number) {
    fields.push_back({.number = number, .value = std::vector<std::byte>(16U, std::byte{0})});
  }
  const auto result = heyaki::canonicalize_for_signature(heyaki::SigningDomain::offer, fields);
  EXPECT_FALSE(result);
  ASSERT_NE(result.error_if(), nullptr);
  EXPECT_EQ(result.error_if()->safe_detail(), "invalid_signed_field_shape");
}

TEST(Signing, EverySignedDomainAcceptsItsFrozenFieldShape) {
  const auto expect_shape = [](heyaki::SigningDomain domain,
                               std::initializer_list<std::size_t> sizes) {
    std::vector<heyaki::CanonicalField> fields;
    std::uint16_t number = 1U;
    for (const auto size : sizes) {
      fields.push_back(
          {.number = number++, .value = std::vector<std::byte>(size, std::byte{0})});
    }
    if (domain == heyaki::SigningDomain::candidate) {
      fields[12U].value = {std::byte{'i'}, std::byte{'c'}, std::byte{'e'}, std::byte{'1'}};
    }
    EXPECT_TRUE(heyaki::canonicalize_for_signature(domain, fields));
  };

  expect_shape(heyaki::SigningDomain::enrollment,
               {32U, 16U, 32U, 32U, 32U, 1U, 4U, 4U, 8U, 8U, 8U});
  expect_shape(heyaki::SigningDomain::enrollment_record, {32U, 16U, 32U, 1U, 8U, 8U});
  expect_shape(heyaki::SigningDomain::endpoint_record, {32U, 16U, 1U, 8U, 32U, 8U});
  expect_shape(heyaki::SigningDomain::service_manifest, {32U, 16U, 8U, 32U, 8U});
  expect_shape(heyaki::SigningDomain::offer,
               {32U, 16U, 32U, 16U, 16U, 16U, 32U, 8U, 1U, 32U});
  expect_shape(heyaki::SigningDomain::answer,
               {32U, 16U, 32U, 16U, 16U, 16U, 32U, 32U, 8U, 1U, 32U});
  expect_shape(heyaki::SigningDomain::candidate,
               {32U, 16U, 32U, 16U, 16U, 16U, 32U, 32U, 8U, 4U, 1U, 32U, 4U, 32U});
  expect_shape(heyaki::SigningDomain::session_hello,
               {32U, 16U, 32U, 16U, 16U, 8U, 32U, 32U, 32U, 4U, 4U, 8U, 8U, 8U});
  expect_shape(heyaki::SigningDomain::trust_grant,
               {16U, 32U, 32U, 2U, 8U, 8U, 8U, 32U});

  std::vector<heyaki::CanonicalField> without_expiry;
  const std::array sizes{16U, 32U, 32U, 2U, 8U, 8U};
  for (std::size_t index = 0U; index < sizes.size(); ++index) {
    without_expiry.push_back({.number = static_cast<std::uint16_t>(index + 1U),
                              .value = std::vector<std::byte>(sizes[index], std::byte{0})});
  }
  without_expiry.push_back({.number = 8U, .value = std::vector<std::byte>(32U, std::byte{0})});
  EXPECT_TRUE(heyaki::canonicalize_for_signature(heyaki::SigningDomain::trust_grant,
                                                  without_expiry));
}

TEST(Signing, SignalingTranscriptRejectsMissingOrOversizedObjects) {
  const std::vector<std::byte> one_byte{std::byte{1U}};
  EXPECT_FALSE(heyaki::hash_signaling_transcript({}, one_byte));
  EXPECT_FALSE(heyaki::hash_signaling_transcript(one_byte, {}));

  const std::vector<std::byte> oversized(heyaki::max_canonical_signing_bytes + 1U);
  EXPECT_FALSE(heyaki::hash_signaling_transcript(oversized, one_byte));
  EXPECT_FALSE(heyaki::hash_signaling_transcript(one_byte, oversized));
  EXPECT_FALSE(heyaki::hash_signaling_transcript(one_byte, one_byte));
}

TEST(Signing, TrustGrantRejectsNonCanonicalScopeLists) {
  const auto canonicalize = [](std::string_view scope_list_hex) {
    std::vector<heyaki::CanonicalField> fields{
        {.number = 1U, .value = std::vector<std::byte>(16U)},
        {.number = 2U, .value = std::vector<std::byte>(32U)},
        {.number = 3U, .value = std::vector<std::byte>(32U)},
        {.number = 4U, .value = heyaki::test::bytes_from_hex(scope_list_hex)},
        {.number = 5U, .value = std::vector<std::byte>(8U)},
        {.number = 6U, .value = std::vector<std::byte>(8U)},
        {.number = 8U, .value = std::vector<std::byte>(32U)},
    };
    return heyaki::canonicalize_for_signature(heyaki::SigningDomain::trust_grant, fields);
  };

  EXPECT_TRUE(canonicalize("000200087270632e72656164000a7368656c6c2e72656164"));
  EXPECT_FALSE(canonicalize("0001000261"));
  EXPECT_FALSE(canonicalize("0002000161000161"));
  EXPECT_FALSE(canonicalize("0002000162000161"));
  EXPECT_FALSE(canonicalize("000100011f"));
}

}  // namespace
