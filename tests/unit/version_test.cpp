#include <heyaki/protocol.hpp>
#include <heyaki/version.hpp>

#include <gtest/gtest.h>

TEST(BuildInfo, ExposesVersionProtocolAndFeatures) {
  const auto info = heyaki::build_info();

  EXPECT_FALSE(info.version.empty());
  EXPECT_FALSE(info.commit.empty());
  EXPECT_EQ(info.protocol_major, 1U);
  EXPECT_EQ(info.protocol_minor, 2U);
  EXPECT_EQ(info.protocol_major, heyaki::current_protocol_version.major);
  EXPECT_EQ(info.protocol_minor, heyaki::current_protocol_version.minor);
  EXPECT_TRUE(info.features.has(heyaki::BuildFeature::profile));
  EXPECT_TRUE(info.features.has(heyaki::BuildFeature::client));
  EXPECT_TRUE(info.features.has(heyaki::BuildFeature::services));
  EXPECT_TRUE(info.features.has(heyaki::BuildFeature::transport_webrtc));
  EXPECT_EQ(info.features.has(heyaki::BuildFeature::relay), HEYAKI_TEST_EXPECT_APPS != 0);
  EXPECT_EQ(info.features.has(heyaki::BuildFeature::tui), HEYAKI_TEST_EXPECT_APPS != 0);
  EXPECT_EQ(info.features.has(heyaki::BuildFeature::zstd), HEYAKI_TEST_EXPECT_ZSTD != 0);
}

TEST(BuildFeatures, RejectsUnsetBits) {
  const auto info = heyaki::build_info();
  EXPECT_FALSE(info.features.has(static_cast<heyaki::BuildFeature>(1U << 31U)));
}
