#include <heyaki/password.hpp>

#include <heyaki/identity.hpp>

#include <sodium.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace heyaki {
namespace {

class PasswordCopy {
 public:
  explicit PasswordCopy(std::string_view password) : bytes_(password.begin(), password.end()) {}
  ~PasswordCopy() { sodium_memzero(bytes_.data(), bytes_.size()); }

  PasswordCopy(const PasswordCopy&) = delete;
  PasswordCopy& operator=(const PasswordCopy&) = delete;

  [[nodiscard]] const char* data() const noexcept { return bytes_.data(); }
  [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }

 private:
  std::vector<char> bytes_;
};

Result<std::size_t> count_unicode_scalars(std::string_view value) {
  std::size_t scalars = 0U;
  std::size_t index = 0U;
  while (index < value.size()) {
    const auto first = static_cast<unsigned char>(value[index]);
    std::size_t continuation_count = 0U;
    unsigned char second_minimum = 0x80U;
    unsigned char second_maximum = 0xbfU;
    if (first <= 0x7fU) {
      continuation_count = 0U;
    } else if (first >= 0xc2U && first <= 0xdfU) {
      continuation_count = 1U;
    } else if (first >= 0xe0U && first <= 0xefU) {
      continuation_count = 2U;
      if (first == 0xe0U) {
        second_minimum = 0xa0U;
      } else if (first == 0xedU) {
        second_maximum = 0x9fU;
      }
    } else if (first >= 0xf0U && first <= 0xf4U) {
      continuation_count = 3U;
      if (first == 0xf0U) {
        second_minimum = 0x90U;
      } else if (first == 0xf4U) {
        second_maximum = 0x8fU;
      }
    } else {
      return Result<std::size_t>::failure(
          Error{ErrorCode::configuration, "password", "invalid_utf8"});
    }
    if (value.size() - index <= continuation_count) {
      return Result<std::size_t>::failure(
          Error{ErrorCode::configuration, "password", "invalid_utf8"});
    }
    if (continuation_count != 0U) {
      const auto second = static_cast<unsigned char>(value[index + 1U]);
      if (second < second_minimum || second > second_maximum) {
        return Result<std::size_t>::failure(
            Error{ErrorCode::configuration, "password", "invalid_utf8"});
      }
      for (std::size_t offset = 2U; offset <= continuation_count; ++offset) {
        const auto continuation = static_cast<unsigned char>(value[index + offset]);
        if (continuation < 0x80U || continuation > 0xbfU) {
          return Result<std::size_t>::failure(
              Error{ErrorCode::configuration, "password", "invalid_utf8"});
        }
      }
    }
    ++scalars;
    index += continuation_count + 1U;
  }
  return Result<std::size_t>::success(scalars);
}

Result<void> validate_password(std::string_view password, const PasswordSecurityPolicy& policy) {
  if (password.size() > policy.maximum_utf8_bytes) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "password", "password_too_long"});
  }
  auto scalars = count_unicode_scalars(password);
  if (!scalars) {
    return Result<void>::failure(*scalars.error_if());
  }
  if (*scalars.value_if() < policy.minimum_unicode_scalars) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "password", "password_too_short"});
  }
  return Result<void>::success();
}

bool valid_parameters(const PasswordHashParameters& parameters,
                      const PasswordSecurityPolicy& policy) noexcept {
  const auto memory_kib = parameters.memory_bytes / 1024U;
  return parameters.memory_bytes % 1024U == 0U &&
         parameters.operations >= policy.argon2_minimum_operations &&
         parameters.operations <= policy.argon2_maximum_operations &&
         memory_kib >= policy.argon2_minimum_memory_kib &&
         memory_kib <= policy.argon2_maximum_memory_kib;
}

}  // namespace

Result<PasswordHashParameters> calibrate_password_parameters(
    const PasswordSecurityPolicy& policy) {
  const auto valid_policy = validate_security_policy({}, policy);
  if (!valid_policy) {
    return Result<PasswordHashParameters>::failure(*valid_policy.error_if());
  }
  const auto initialized = initialize_crypto();
  if (!initialized) {
    return Result<PasswordHashParameters>::failure(*initialized.error_if());
  }

  PasswordHashParameters parameters{
      .operations = policy.argon2_minimum_operations,
      .memory_bytes = static_cast<std::size_t>(policy.argon2_minimum_memory_kib) * 1024U};
  std::array<unsigned char, crypto_pwhash_SALTBYTES> salt{};
  std::array<unsigned char, 32U> output{};
  randombytes_buf(salt.data(), salt.size());
  constexpr std::string_view probe = "heyaki-argon2-calibration";

  while (true) {
    const auto started = std::chrono::steady_clock::now();
    const int result = crypto_pwhash(
        output.data(), output.size(), probe.data(), probe.size(), salt.data(),
        parameters.operations, parameters.memory_bytes, crypto_pwhash_ALG_ARGON2ID13);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    sodium_memzero(output.data(), output.size());
    if (result != 0) {
      return Result<PasswordHashParameters>::failure(
          Error{ErrorCode::resource_exhausted, "password", "argon2_calibration_failed"});
    }
    if (elapsed.count() >= policy.argon2_target_milliseconds ||
        parameters.operations >= policy.argon2_maximum_operations) {
      return Result<PasswordHashParameters>::success(parameters);
    }
    ++parameters.operations;
  }
}

Result<PasswordVerifier> create_password_verifier(
    std::string_view password, PasswordHashParameters parameters,
    const PasswordSecurityPolicy& policy) {
  const auto valid_policy = validate_security_policy({}, policy);
  if (!valid_policy) {
    return Result<PasswordVerifier>::failure(*valid_policy.error_if());
  }
  const auto valid_password = validate_password(password, policy);
  if (!valid_password) {
    return Result<PasswordVerifier>::failure(*valid_password.error_if());
  }
  if (!valid_parameters(parameters, policy)) {
    return Result<PasswordVerifier>::failure(
        Error{ErrorCode::configuration, "password", "invalid_argon2_parameters"});
  }
  const auto initialized = initialize_crypto();
  if (!initialized) {
    return Result<PasswordVerifier>::failure(*initialized.error_if());
  }

  PasswordCopy password_copy{password};
  std::array<char, crypto_pwhash_STRBYTES> encoded{};
  if (crypto_pwhash_str_alg(encoded.data(), password_copy.data(), password_copy.size(),
                            parameters.operations, parameters.memory_bytes,
                            crypto_pwhash_ALG_ARGON2ID13) != 0) {
    sodium_memzero(encoded.data(), encoded.size());
    return Result<PasswordVerifier>::failure(
        Error{ErrorCode::resource_exhausted, "password", "argon2_hash_failed"});
  }

  PasswordVerifier verifier{
      .format_version = policy.verifier_format_version,
      .parameters = parameters,
      .encoded = encoded.data()};
  sodium_memzero(encoded.data(), encoded.size());
  return Result<PasswordVerifier>::success(std::move(verifier));
}

Result<bool> verify_password(std::string_view password, const PasswordVerifier& verifier) {
  const auto initialized = initialize_crypto();
  if (!initialized) {
    return Result<bool>::failure(*initialized.error_if());
  }
  if (verifier.format_version != 1U || verifier.encoded.empty() ||
      verifier.encoded.size() >= crypto_pwhash_STRBYTES) {
    return Result<bool>::failure(
        Error{ErrorCode::identity, "password", "corrupt_password_verifier"});
  }

  PasswordCopy password_copy{password};
  const int result = crypto_pwhash_str_verify(verifier.encoded.c_str(), password_copy.data(),
                                               password_copy.size());
  return Result<bool>::success(result == 0);
}

Result<bool> password_verifier_needs_upgrade(const PasswordVerifier& verifier,
                                             PasswordHashParameters desired,
                                             std::uint16_t desired_format_version) {
  if (verifier.format_version != desired_format_version) {
    return Result<bool>::success(true);
  }
  if (verifier.encoded.empty() || verifier.encoded.size() >= crypto_pwhash_STRBYTES) {
    return Result<bool>::failure(
        Error{ErrorCode::identity, "password", "corrupt_password_verifier"});
  }
  const int result = crypto_pwhash_str_needs_rehash(
      verifier.encoded.c_str(), desired.operations, desired.memory_bytes);
  if (result < 0) {
    return Result<bool>::failure(
        Error{ErrorCode::identity, "password", "corrupt_password_verifier"});
  }
  return Result<bool>::success(result != 0);
}

}  // namespace heyaki
