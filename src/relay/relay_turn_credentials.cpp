#include "relay_turn_credentials.hpp"

#include <sodium.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

Error turn_error(ErrorCode code, const char* detail) {
  return Error{code, "relay_turn", detail};
}

bool valid_hmac_secret(std::string_view value) noexcept {
  if (value.empty() || value.size() > turn_secret_max_bytes) {
    return false;
  }
  for (const char raw : value) {
    const auto character = static_cast<unsigned char>(raw);
    if (character < 0x21U || character > 0x7eU) {
      return false;
    }
  }
  return true;
}

bool valid_secret(std::string_view value) noexcept {
  if (value.size() < turn_secret_min_bytes || value.size() > turn_secret_max_bytes) {
    return false;
  }
  for (const char raw : value) {
    const auto character = static_cast<unsigned char>(raw);
    if (character < 0x21U || character > 0x7eU) {
      return false;
    }
  }
  return true;
}

bool valid_username_component(std::string_view value) noexcept {
  if (value.empty() || value.size() > 128U) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](char raw) {
    const auto character = static_cast<unsigned char>(raw);
    return (character >= 'a' && character <= 'z') ||
           (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9') || character == '.' ||
           character == '_' || character == '-';
  });
}

bool valid_turn_username(std::string_view value) noexcept {
  if (value.empty() || value.size() > 512U) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](char raw) {
    const auto character = static_cast<unsigned char>(raw);
    return character >= 0x21U && character <= 0x7eU && character != ' ';
  });
}

struct SecretEntry {
  SecretEntry(std::uint64_t generation, std::string value,
              std::uint64_t activated)
      : generation(generation), secret(std::move(value)), activated_unix_seconds(activated) {}

  ~SecretEntry() { sodium_memzero(secret.data(), secret.size()); }

  SecretEntry(const SecretEntry&) = delete;
  SecretEntry& operator=(const SecretEntry&) = delete;

  std::uint64_t generation{};
  std::string secret;
  std::uint64_t activated_unix_seconds{};
};

std::string base64_encode(std::span<const unsigned char> input) {
  std::string output;
  output.resize(4U * ((input.size() + 2U) / 3U));
  const int encoded = EVP_EncodeBlock(
      reinterpret_cast<unsigned char*>(output.data()), input.data(),
      static_cast<int>(input.size()));
  output.resize(static_cast<std::size_t>(encoded));
  return output;
}

}  // namespace

struct RelayTurnCredentialService::Impl {
  explicit Impl(RelayTurnSecretConfig config_value) : config(std::move(config_value)) {}

  RelayTurnSecretConfig config;
  std::vector<std::unique_ptr<SecretEntry>> secrets;
  RelayTurnCredentialDiagnostics stats;
};

RelayTurnCredentialService::RelayTurnCredentialService(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}
RelayTurnCredentialService::RelayTurnCredentialService(RelayTurnCredentialService&&) noexcept =
    default;
RelayTurnCredentialService& RelayTurnCredentialService::operator=(
    RelayTurnCredentialService&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}
RelayTurnCredentialService::~RelayTurnCredentialService() = default;

Result<void> RelayTurnCredentialService::validate_config(
    const RelayTurnSecretConfig& config) {
  if (config.max_secrets == 0U || config.max_secrets > 16U ||
      config.credential_ttl.count() <= 0 ||
      config.credential_ttl.count() > turn_credential_max_ttl_seconds) {
    return Result<void>::failure(turn_error(ErrorCode::configuration,
                                            "turn_secret_config_invalid"));
  }
  return Result<void>::success();
}

Result<RelayTurnCredentialService> RelayTurnCredentialService::create(
    const RelayTurnSecretConfig& config) {
  auto valid = validate_config(config);
  if (!valid) {
    return Result<RelayTurnCredentialService>::failure(*valid.error_if());
  }
  return Result<RelayTurnCredentialService>::success(
      RelayTurnCredentialService{std::make_unique<Impl>(config)});
}

Result<void> validate_turn_secret(std::string_view secret) {
  return valid_secret(secret)
             ? Result<void>::success()
             : Result<void>::failure(
                   turn_error(ErrorCode::configuration, "turn_secret_invalid"));
}

Result<std::string> turn_rest_password(std::string_view secret,
                                       std::string_view username) {
  if (!valid_hmac_secret(secret)) {
    return Result<std::string>::failure(turn_error(ErrorCode::configuration,
                                                   "turn_hmac_secret_invalid"));
  }
  if (!valid_turn_username(username)) {
    return Result<std::string>::failure(turn_error(ErrorCode::configuration,
                                                   "turn_username_invalid"));
  }
  std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
  unsigned int digest_size = 0U;
  if (HMAC(EVP_sha1(), secret.data(), static_cast<int>(secret.size()),
           reinterpret_cast<const unsigned char*>(username.data()), username.size(),
           digest.data(), &digest_size) == nullptr ||
      digest_size == 0U) {
    return Result<std::string>::failure(turn_error(ErrorCode::internal,
                                                   "turn_hmac_failed"));
  }
  return Result<std::string>::success(
      base64_encode(std::span<const unsigned char>{digest.data(), digest_size}));
}

Result<void> RelayTurnCredentialService::set_secret(std::uint64_t generation,
                                                    std::string_view secret,
                                                    std::uint64_t activated_unix_seconds) {
  if (!impl_) {
    return Result<void>::failure(turn_error(ErrorCode::cancelled,
                                            "turn_service_not_initialized"));
  }
  if (generation == 0U || activated_unix_seconds == 0U || !valid_secret(secret)) {
    return Result<void>::failure(turn_error(ErrorCode::configuration,
                                            "turn_secret_invalid"));
  }

  const auto existing = std::find_if(
      impl_->secrets.begin(), impl_->secrets.end(),
      [generation](const std::unique_ptr<SecretEntry>& entry) {
        return entry->generation == generation;
      });
  if (existing != impl_->secrets.end()) {
    sodium_memzero((*existing)->secret.data(), (*existing)->secret.size());
    (*existing)->secret.assign(secret);
    (*existing)->activated_unix_seconds = activated_unix_seconds;
  } else {
    if (impl_->secrets.size() >= impl_->config.max_secrets) {
      impl_->secrets.erase(impl_->secrets.begin());
    }
    impl_->secrets.push_back(
        std::make_unique<SecretEntry>(generation, std::string{secret},
                                      activated_unix_seconds));
    std::sort(impl_->secrets.begin(), impl_->secrets.end(),
              [](const std::unique_ptr<SecretEntry>& left,
                 const std::unique_ptr<SecretEntry>& right) {
                return left->generation < right->generation;
              });
  }
  impl_->stats.active_secrets = impl_->secrets.size();
  impl_->stats.latest_secret_generation = impl_->secrets.back()->generation;
  return Result<void>::success();
}

Result<RelayTurnCredential> RelayTurnCredentialService::issue(
    std::string_view tenant, const DeviceId& device_id,
    std::uint64_t now_unix_seconds) {
  if (!impl_) {
    return Result<RelayTurnCredential>::failure(turn_error(ErrorCode::cancelled,
                                                           "turn_service_not_initialized"));
  }
  if (impl_->secrets.empty()) {
    return Result<RelayTurnCredential>::failure(
        turn_error(ErrorCode::secret_unavailable, "turn_secret_unavailable"));
  }
  if (device_id.is_zero() || !valid_username_component(tenant)) {
    return Result<RelayTurnCredential>::failure(
        turn_error(ErrorCode::configuration, "turn_credential_identity_invalid"));
  }
  const auto ttl = static_cast<std::uint64_t>(impl_->config.credential_ttl.count());
  if (now_unix_seconds > std::numeric_limits<std::uint64_t>::max() - ttl) {
    return Result<RelayTurnCredential>::failure(
        turn_error(ErrorCode::configuration, "turn_credential_expiry_overflow"));
  }
  const auto expires = now_unix_seconds + ttl;
  const std::string username =
      std::to_string(expires) + ":" + std::string{tenant} + ":" + to_string(device_id);
  const auto& active = impl_->secrets.back();
  auto password = turn_rest_password(active->secret, username);
  if (!password) {
    return Result<RelayTurnCredential>::failure(*password.error_if());
  }
  ++impl_->stats.issued;
  return Result<RelayTurnCredential>::success(RelayTurnCredential{
      .username = username,
      .password = std::move(*password.value_if()),
      .expires_unix_seconds = expires,
      .secret_generation = active->generation});
}

Result<std::uint64_t> RelayTurnCredentialService::validate(
    std::string_view username, std::string_view password,
    std::uint64_t now_unix_seconds) {
  if (!impl_) {
    return Result<std::uint64_t>::failure(turn_error(ErrorCode::cancelled,
                                                     "turn_service_not_initialized"));
  }
  const auto separator = username.find(':');
  if (separator == std::string_view::npos || separator == 0U) {
    ++impl_->stats.validation_rejected;
    return Result<std::uint64_t>::failure(turn_error(ErrorCode::authentication,
                                                     "turn_username_invalid"));
  }
  const auto expiry_text = username.substr(0U, separator);
  std::uint64_t expires = 0U;
  for (const char character : expiry_text) {
    if (character < '0' || character > '9') {
      ++impl_->stats.validation_rejected;
      return Result<std::uint64_t>::failure(turn_error(ErrorCode::authentication,
                                                       "turn_username_invalid"));
    }
    const auto digit = static_cast<std::uint64_t>(character - '0');
    if (expires > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) {
      ++impl_->stats.validation_rejected;
      return Result<std::uint64_t>::failure(turn_error(ErrorCode::authentication,
                                                       "turn_username_invalid"));
    }
    expires = expires * 10U + digit;
  }
  if (expires <= now_unix_seconds || !valid_turn_username(username)) {
    ++impl_->stats.validation_rejected;
    return Result<std::uint64_t>::failure(turn_error(ErrorCode::authentication,
                                                     "turn_credential_expired"));
  }

  for (const auto& entry : impl_->secrets) {
    auto expected = turn_rest_password(entry->secret, username);
    if (!expected) {
      continue;
    }
    if (expected.value_if()->size() == password.size() &&
        CRYPTO_memcmp(expected.value_if()->data(), password.data(), password.size()) == 0) {
      ++impl_->stats.validated;
      return Result<std::uint64_t>::success(entry->generation);
    }
  }
  ++impl_->stats.validation_rejected;
  return Result<std::uint64_t>::failure(turn_error(ErrorCode::authentication,
                                                   "turn_credential_invalid"));
}

RelayTurnCredentialDiagnostics RelayTurnCredentialService::diagnostics() const noexcept {
  auto output = impl_ ? impl_->stats : RelayTurnCredentialDiagnostics{};
  if (impl_) {
    output.active_secrets = impl_->secrets.size();
    output.latest_secret_generation =
        impl_->secrets.empty() ? 0U : impl_->secrets.back()->generation;
  }
  return output;
}

}  // namespace heyaki
