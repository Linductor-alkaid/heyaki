#pragma once

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>

#include <cstddef>
#include <span>

namespace heyaki {

inline constexpr std::size_t ed25519_public_key_bytes = 32;

[[nodiscard]] Result<DeviceId> derive_device_id(std::span<const std::byte> public_key);

}  // namespace heyaki
