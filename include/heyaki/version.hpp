#pragma once

#include <cstdint>
#include <string_view>

namespace heyaki {

enum class BuildFeature : std::uint32_t {
  profile = 1U << 0U,
  client = 1U << 1U,
  services = 1U << 2U,
  transport_webrtc = 1U << 3U,
  relay = 1U << 4U,
  tui = 1U << 5U,
  zstd = 1U << 6U,
};

class BuildFeatures {
 public:
  explicit constexpr BuildFeatures(std::uint32_t bits) noexcept : bits_(bits) {}

  [[nodiscard]] constexpr bool has(BuildFeature feature) const noexcept {
    return (bits_ & static_cast<std::uint32_t>(feature)) != 0U;
  }

  [[nodiscard]] constexpr std::uint32_t bits() const noexcept { return bits_; }

 private:
  std::uint32_t bits_{};
};

struct BuildInfo {
  std::string_view version;
  std::string_view commit;
  std::uint16_t protocol_major;
  std::uint16_t protocol_minor;
  BuildFeatures features;
};

[[nodiscard]] BuildInfo build_info() noexcept;

}  // namespace heyaki
