#include "local_setup.hpp"

#include <heyaki/password.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

namespace heyaki::tui {
namespace {

void wipe_string(std::string& value) noexcept {
  volatile char* bytes = value.empty() ? nullptr : value.data();
  for (std::size_t index = 0U; index < value.size(); ++index) {
    bytes[index] = '\0';
  }
  value.clear();
}

void report_retryable_error(const SetupErrorObserver& observer,
                            const Error& error) {
  if (observer) {
    observer(error);
  }
}

bool retryable_password_error(const Error& error) noexcept {
  return error.code() == ErrorCode::configuration &&
         error.component() == "password";
}

}  // namespace

Result<LocalProfileInitialization> read_local_profile_initialization(
    std::string_view application_id, const SecretReader& read_secret,
    const SetupErrorObserver& retryable_error) {
  const PasswordSecurityPolicy password_policy{};
  const auto password_prompt =
      "password (minimum " +
      std::to_string(password_policy.minimum_unicode_scalars) +
      " Unicode characters): ";
  while (true) {
    auto password = read_secret(password_prompt);
    if (!password) {
      return Result<LocalProfileInitialization>::failure(*password.error_if());
    }
    auto confirmation = read_secret("confirm password: ");
    if (!confirmation) {
      wipe_string(*password.value_if());
      return Result<LocalProfileInitialization>::failure(*confirmation.error_if());
    }
    if (*password.value_if() != *confirmation.value_if()) {
      wipe_string(*password.value_if());
      wipe_string(*confirmation.value_if());
      const Error mismatch{ErrorCode::authentication, "tui",
                           "password_confirmation_mismatch"};
      report_retryable_error(retryable_error, mismatch);
      continue;
    }

    auto verifier = create_password_verifier(
        *password.value_if(), PasswordHashParameters{}, password_policy);
    wipe_string(*password.value_if());
    wipe_string(*confirmation.value_if());
    if (!verifier) {
      if (retryable_password_error(*verifier.error_if())) {
        report_retryable_error(retryable_error, *verifier.error_if());
        continue;
      }
      return Result<LocalProfileInitialization>::failure(*verifier.error_if());
    }

    return Result<LocalProfileInitialization>::success(
        LocalProfileInitialization{
            .application_id = std::string{application_id},
            .password_verifier = std::move(*verifier.value_if()),
            .password_generation = 1U,
            .pairing_policy = PairingPolicy{},
            .lan = LanConfiguration{}});
  }
}

}  // namespace heyaki::tui
