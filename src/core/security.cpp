#include <heyaki/security.hpp>

namespace heyaki {

std::string_view value_for_log(LogDataClass data_class, std::string_view value) noexcept {
  return is_safe_log_class(data_class) ? value : std::string_view{"[REDACTED]"};
}

Result<void> validate_security_policy(const ReplayCachePolicy& replay,
                                      const PasswordSecurityPolicy& password) {
  if (replay.ttl_milliseconds < 1000U || replay.ttl_milliseconds > 24U * 60U * 60U * 1000U) {
    return Result<void>::failure(Error{ErrorCode::configuration, "security", "replay_ttl"});
  }
  if (replay.capacity < 64U || replay.capacity > 1024U * 1024U) {
    return Result<void>::failure(Error{ErrorCode::configuration, "security", "replay_capacity"});
  }
  if (password.verifier_format_version == 0U || password.minimum_unicode_scalars < 12U ||
      password.maximum_utf8_bytes < password.minimum_unicode_scalars ||
      password.maximum_utf8_bytes > 4096U || password.generated_entropy_bits < 96U ||
      password.argon2_target_milliseconds < 100U ||
      password.argon2_target_milliseconds > 2000U ||
      password.argon2_minimum_memory_kib < 32U * 1024U ||
      password.argon2_maximum_memory_kib < password.argon2_minimum_memory_kib ||
      password.argon2_maximum_memory_kib > 1024U * 1024U ||
      password.argon2_minimum_operations < 1U ||
      password.argon2_maximum_operations < password.argon2_minimum_operations ||
      password.argon2_maximum_operations > 10U) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "security", "password_policy"});
  }
  return Result<void>::success();
}

}  // namespace heyaki
