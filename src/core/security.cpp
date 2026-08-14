#include <heyaki/security.hpp>

namespace heyaki {

std::string_view value_for_log(LogDataClass data_class, std::string_view value) noexcept {
  return is_safe_log_class(data_class) ? value : std::string_view{"[REDACTED]"};
}

Result<void> validate_security_policy(const ReplayCachePolicy& replay,
                                      const PasswordSecurityPolicy& password) {
  if (replay.ttl_milliseconds < 1000U || replay.ttl_milliseconds > 10U * 60U * 1000U) {
    return Result<void>::failure(Error{ErrorCode::configuration, "security", "replay_ttl"});
  }
  if (replay.capacity < 64U || replay.capacity > 1024U * 1024U) {
    return Result<void>::failure(Error{ErrorCode::configuration, "security", "replay_capacity"});
  }
  if (replay.per_peer_capacity < 16U || replay.per_peer_capacity > replay.capacity) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "security", "replay_per_peer_capacity"});
  }
  if (password.verifier_format_version != 1U || password.minimum_unicode_scalars < 16U ||
      password.maximum_utf8_bytes < password.minimum_unicode_scalars ||
      password.maximum_utf8_bytes > 256U || password.generated_entropy_bits < 128U ||
      password.argon2_target_milliseconds < 250U ||
      password.argon2_target_milliseconds > 750U ||
      password.argon2_minimum_memory_kib < 64U * 1024U ||
      password.argon2_maximum_memory_kib < password.argon2_minimum_memory_kib ||
      password.argon2_maximum_memory_kib > 512U * 1024U ||
      password.argon2_minimum_operations < 2U ||
      password.argon2_maximum_operations < password.argon2_minimum_operations ||
      password.argon2_maximum_operations > 6U) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "security", "password_policy"});
  }
  return Result<void>::success();
}

}  // namespace heyaki
