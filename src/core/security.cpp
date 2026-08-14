#include <heyaki/security.hpp>

#include <limits>

namespace heyaki {

std::string_view value_for_log(LogDataClass data_class, std::string_view value) noexcept {
  return is_safe_log_class(data_class) ? value : std::string_view{"[REDACTED]"};
}

Result<void> validate_security_policy(const ReplayCachePolicy& replay,
                                      const PasswordSecurityPolicy& password) {
  if (replay.ttl_milliseconds != replay_cache_ttl_milliseconds) {
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

Result<void> validate_signed_expiry(std::uint64_t expires_unix_milliseconds,
                                    std::uint64_t now_unix_milliseconds) {
  const auto earliest = now_unix_milliseconds > maximum_expiry_clock_skew_milliseconds
                            ? now_unix_milliseconds - maximum_expiry_clock_skew_milliseconds
                            : 0U;
  const auto latest = now_unix_milliseconds >
                              std::numeric_limits<std::uint64_t>::max() -
                                  maximum_signed_validity_milliseconds
                          ? std::numeric_limits<std::uint64_t>::max()
                          : now_unix_milliseconds + maximum_signed_validity_milliseconds;
  if (expires_unix_milliseconds < earliest) {
    return Result<void>::failure(
        Error{ErrorCode::authentication, "security", "signed_object_expired"});
  }
  if (expires_unix_milliseconds > latest) {
    return Result<void>::failure(
        Error{ErrorCode::authentication, "security", "signed_expiry_too_far"});
  }
  return Result<void>::success();
}

}  // namespace heyaki
