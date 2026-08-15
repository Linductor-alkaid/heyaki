#pragma once

#include <heyaki/error.hpp>
#include <heyaki/security.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace heyaki {

struct PasswordHashParameters {
  std::uint64_t operations{2U};
  std::size_t memory_bytes{64U * 1024U * 1024U};
};

struct PasswordVerifier {
  std::uint16_t format_version{1U};
  PasswordHashParameters parameters;
  std::string encoded;
};

[[nodiscard]] Result<PasswordHashParameters> calibrate_password_parameters(
    const PasswordSecurityPolicy& policy = {});
[[nodiscard]] Result<PasswordVerifier> create_password_verifier(
    std::string_view password, PasswordHashParameters parameters,
    const PasswordSecurityPolicy& policy = {});
[[nodiscard]] Result<bool> verify_password(std::string_view password,
                                           const PasswordVerifier& verifier);
[[nodiscard]] Result<bool> password_verifier_needs_upgrade(
    const PasswordVerifier& verifier, PasswordHashParameters desired,
    std::uint16_t desired_format_version = 1U);

}  // namespace heyaki
