#include <heyaki/identity.hpp>

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <span>

namespace heyaki {

Result<DeviceId> derive_device_id(std::span<const std::byte> public_key) {
  if (public_key.size() != ed25519_public_key_bytes) {
    return Result<DeviceId>::failure(
        Error{ErrorCode::identity, "identity", "invalid_public_key_length"});
  }

  DeviceId::Storage digest{};
  if (crypto_hash_sha256(reinterpret_cast<unsigned char*>(digest.data()),
                         reinterpret_cast<const unsigned char*>(public_key.data()),
                         public_key.size()) != 0) {
    return Result<DeviceId>::failure(Error{ErrorCode::internal, "identity", "sha256_failed"});
  }
  return Result<DeviceId>::success(DeviceId{digest});
}

IdentityKeyPair::IdentityKeyPair(
    DeviceId device_id, IdentityPublicKey public_key,
    std::array<std::byte, ed25519_secret_key_bytes> secret_key) noexcept
    : device_id_(device_id), public_key_(public_key), secret_key_(secret_key) {}

IdentityKeyPair::IdentityKeyPair(IdentityKeyPair&& other) noexcept
    : device_id_(other.device_id_), public_key_(other.public_key_), secret_key_(other.secret_key_) {
  sodium_memzero(other.secret_key_.data(), other.secret_key_.size());
}

IdentityKeyPair& IdentityKeyPair::operator=(IdentityKeyPair&& other) noexcept {
  if (this != &other) {
    sodium_memzero(secret_key_.data(), secret_key_.size());
    device_id_ = other.device_id_;
    public_key_ = other.public_key_;
    secret_key_ = other.secret_key_;
    sodium_memzero(other.secret_key_.data(), other.secret_key_.size());
  }
  return *this;
}

IdentityKeyPair::~IdentityKeyPair() { sodium_memzero(secret_key_.data(), secret_key_.size()); }

Result<void> initialize_crypto() {
  if (sodium_init() < 0) {
    return Result<void>::failure(Error{ErrorCode::internal, "crypto", "sodium_init_failed"});
  }
  return Result<void>::success();
}

Result<IdentityKeyPair> create_identity() {
  const auto initialized = initialize_crypto();
  if (!initialized) {
    return Result<IdentityKeyPair>::failure(*initialized.error_if());
  }

  IdentityPublicKey public_key{};
  std::array<std::byte, ed25519_secret_key_bytes> secret_key{};
  if (crypto_sign_keypair(reinterpret_cast<unsigned char*>(public_key.data()),
                          reinterpret_cast<unsigned char*>(secret_key.data())) != 0) {
    sodium_memzero(secret_key.data(), secret_key.size());
    return Result<IdentityKeyPair>::failure(
        Error{ErrorCode::internal, "identity", "key_generation_failed"});
  }

  auto device_id = derive_device_id(public_key);
  if (!device_id) {
    sodium_memzero(secret_key.data(), secret_key.size());
    return Result<IdentityKeyPair>::failure(*device_id.error_if());
  }
  return Result<IdentityKeyPair>::success(
      IdentityKeyPair{*device_id.value_if(), public_key, secret_key});
}

Result<IdentityKeyPair> import_identity(std::span<const std::byte> public_key,
                                        std::span<const std::byte> secret_key) {
  const auto initialized = initialize_crypto();
  if (!initialized) {
    return Result<IdentityKeyPair>::failure(*initialized.error_if());
  }
  if (public_key.size() != ed25519_public_key_bytes ||
      secret_key.size() != ed25519_secret_key_bytes) {
    return Result<IdentityKeyPair>::failure(
        Error{ErrorCode::identity, "identity", "invalid_key_length"});
  }

  IdentityPublicKey public_key_copy{};
  std::copy(public_key.begin(), public_key.end(), public_key_copy.begin());
  std::array<std::byte, ed25519_secret_key_bytes> secret_key_copy{};
  std::copy(secret_key.begin(), secret_key.end(), secret_key_copy.begin());

  std::array<unsigned char, crypto_sign_SEEDBYTES> seed{};
  IdentityPublicKey derived_public_key{};
  std::array<std::byte, ed25519_secret_key_bytes> derived_secret_key{};
  const int extracted = crypto_sign_ed25519_sk_to_seed(
      seed.data(), reinterpret_cast<const unsigned char*>(secret_key_copy.data()));
  const int derived = crypto_sign_seed_keypair(
      reinterpret_cast<unsigned char*>(derived_public_key.data()),
      reinterpret_cast<unsigned char*>(derived_secret_key.data()), seed.data());
  sodium_memzero(seed.data(), seed.size());
  const bool mismatch =
      extracted != 0 || derived != 0 ||
      sodium_memcmp(derived_public_key.data(), public_key_copy.data(), public_key_copy.size()) != 0 ||
      sodium_memcmp(derived_secret_key.data(), secret_key_copy.data(), secret_key_copy.size()) != 0;
  sodium_memzero(derived_secret_key.data(), derived_secret_key.size());
  if (mismatch) {
    sodium_memzero(secret_key_copy.data(), secret_key_copy.size());
    return Result<IdentityKeyPair>::failure(
        Error{ErrorCode::identity, "identity", "public_private_key_mismatch"});
  }

  auto device_id = derive_device_id(public_key_copy);
  if (!device_id) {
    sodium_memzero(secret_key_copy.data(), secret_key_copy.size());
    return Result<IdentityKeyPair>::failure(*device_id.error_if());
  }
  return Result<IdentityKeyPair>::success(
      IdentityKeyPair{*device_id.value_if(), public_key_copy, secret_key_copy});
}

}  // namespace heyaki
