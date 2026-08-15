#pragma once

#include <heyaki/error.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

enum class SecretBackendSecurity : std::uint8_t {
  os_protected,
  encrypted_file_fallback,
};

struct SecretHandle {
  std::string value;
};

struct SecretBackendOptions {
  bool allow_encrypted_file_fallback{true};
  bool create_if_missing{true};
};

class SecretBackend {
 public:
  virtual ~SecretBackend() = default;

  [[nodiscard]] virtual SecretBackendSecurity security() const noexcept = 0;
  [[nodiscard]] virtual Result<SecretHandle> store(std::string_view label,
                                                    std::span<const std::byte> secret) = 0;
  [[nodiscard]] virtual Result<std::vector<std::byte>> load(
      const SecretHandle& handle) const = 0;
  [[nodiscard]] virtual Result<void> erase(const SecretHandle& handle) = 0;
};

[[nodiscard]] Result<std::shared_ptr<SecretBackend>> open_default_secret_backend(
    const std::filesystem::path& root, const SecretBackendOptions& options = {});

}  // namespace heyaki
