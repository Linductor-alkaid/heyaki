#include <heyaki/version.hpp>

#include <heyaki/detail/build_config.hpp>

namespace heyaki {

BuildInfo build_info() noexcept {
  constexpr auto base_features = static_cast<std::uint32_t>(BuildFeature::profile) |
                                 static_cast<std::uint32_t>(BuildFeature::client) |
                                 static_cast<std::uint32_t>(BuildFeature::services) |
                                 static_cast<std::uint32_t>(BuildFeature::transport_webrtc);
  constexpr auto features =
      base_features |
      (HEYAKI_BUILD_FEATURE_RELAY ? static_cast<std::uint32_t>(BuildFeature::relay) : 0U) |
      (HEYAKI_BUILD_FEATURE_TUI ? static_cast<std::uint32_t>(BuildFeature::tui) : 0U) |
      (HEYAKI_BUILD_FEATURE_ZSTD ? static_cast<std::uint32_t>(BuildFeature::zstd) : 0U);
  return BuildInfo{
      .version = HEYAKI_VERSION_STRING,
      .commit = HEYAKI_BUILD_COMMIT_STRING,
      .protocol_major = HEYAKI_PROTOCOL_VERSION_MAJOR,
      .protocol_minor = HEYAKI_PROTOCOL_VERSION_MINOR,
      .features = BuildFeatures{features},
  };
}

}  // namespace heyaki
