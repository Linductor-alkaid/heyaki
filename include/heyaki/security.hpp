#pragma once

#include <heyaki/error.hpp>

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace heyaki {

enum class LogDataClass : std::uint8_t {
  public_value,
  operational,
  identifier,
  secret_key,
  token,
  password,
  verifier,
  payload,
  terminal_content,
};

[[nodiscard]] constexpr bool is_safe_log_class(LogDataClass data_class) noexcept {
  return data_class == LogDataClass::public_value || data_class == LogDataClass::operational ||
         data_class == LogDataClass::identifier;
}

[[nodiscard]] std::string_view value_for_log(LogDataClass data_class,
                                             std::string_view value) noexcept;

enum class ReplayCacheFullPolicy : std::uint8_t { reject };

struct ReplayCachePolicy {
  std::uint32_t ttl_milliseconds{10U * 60U * 1000U};
  std::size_t capacity{4096U};
  ReplayCacheFullPolicy full_policy{ReplayCacheFullPolicy::reject};
};

struct PasswordSecurityPolicy {
  std::uint16_t verifier_format_version{1U};
  std::size_t minimum_unicode_scalars{16U};
  std::size_t maximum_utf8_bytes{256U};
  std::uint16_t generated_entropy_bits{128U};
  std::uint32_t argon2_target_milliseconds{500U};
  std::uint32_t argon2_minimum_memory_kib{64U * 1024U};
  std::uint32_t argon2_maximum_memory_kib{512U * 1024U};
  std::uint32_t argon2_minimum_operations{2U};
  std::uint32_t argon2_maximum_operations{6U};
};

[[nodiscard]] Result<void> validate_security_policy(const ReplayCachePolicy& replay,
                                                    const PasswordSecurityPolicy& password);

}  // namespace heyaki
