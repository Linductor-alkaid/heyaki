#pragma once

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>

#include <array>
#include <cstddef>
#include <span>

namespace heyaki {

inline constexpr std::size_t ed25519_public_key_bytes = 32;
inline constexpr std::size_t ed25519_secret_key_bytes = 64;

using IdentityPublicKey = std::array<std::byte, ed25519_public_key_bytes>;

class IdentityKeyPair {
 public:
  IdentityKeyPair(IdentityKeyPair&& other) noexcept;
  IdentityKeyPair& operator=(IdentityKeyPair&& other) noexcept;
  ~IdentityKeyPair();

  IdentityKeyPair(const IdentityKeyPair&) = delete;
  IdentityKeyPair& operator=(const IdentityKeyPair&) = delete;

  [[nodiscard]] const DeviceId& device_id() const noexcept { return device_id_; }
  [[nodiscard]] const IdentityPublicKey& public_key() const noexcept { return public_key_; }
  [[nodiscard]] std::span<const std::byte> secret_key() const noexcept { return secret_key_; }

 private:
  friend Result<IdentityKeyPair> create_identity();
  friend Result<IdentityKeyPair> import_identity(std::span<const std::byte>,
                                                  std::span<const std::byte>);

  IdentityKeyPair(DeviceId device_id, IdentityPublicKey public_key,
                  std::array<std::byte, ed25519_secret_key_bytes> secret_key) noexcept;

  DeviceId device_id_;
  IdentityPublicKey public_key_{};
  std::array<std::byte, ed25519_secret_key_bytes> secret_key_{};
};

[[nodiscard]] Result<DeviceId> derive_device_id(std::span<const std::byte> public_key);
[[nodiscard]] Result<void> initialize_crypto();
[[nodiscard]] Result<IdentityKeyPair> create_identity();
[[nodiscard]] Result<IdentityKeyPair> import_identity(
    std::span<const std::byte> public_key, std::span<const std::byte> secret_key);

}  // namespace heyaki
