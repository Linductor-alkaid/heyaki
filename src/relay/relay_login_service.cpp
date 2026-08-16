#include "relay_login_service.hpp"

#include <heyaki/error.hpp>
#include <heyaki/security.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

Error service_error(ErrorCode code, const char* detail) {
  return Error{code, "relay_login_service", detail};
}

std::chrono::steady_clock::time_point steady_now() {
  return std::chrono::steady_clock::now();
}

}  // namespace

struct RelayLoginService::Impl {
  Impl(RelayDatabase* database_value, RelayId relay_id_value,
       RelayLoginServiceConfig config_value,
       RelayTtlTable<RelayLoginNonce, RelayLoginChallenge> table_value) noexcept
      : database(database_value),
        relay_id(relay_id_value),
        config(std::move(config_value)),
        challenges(std::move(table_value)) {}

  RelayDatabase* database{nullptr};
  RelayId relay_id{};
  RelayLoginServiceConfig config;
  RelayTtlTable<RelayLoginNonce, RelayLoginChallenge> challenges;
  RelayLoginServiceDiagnostics stats;
};

RelayLoginService::RelayLoginService(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}
RelayLoginService::RelayLoginService(RelayLoginService&&) noexcept = default;
RelayLoginService& RelayLoginService::operator=(RelayLoginService&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}
RelayLoginService::~RelayLoginService() = default;

Result<RelayLoginService> RelayLoginService::create(
    RelayDatabase* database, RelayId relay_id,
    const RelayLoginServiceConfig& config) {
  if (database == nullptr || relay_id == RelayId{} || config.challenge_capacity == 0U ||
      config.challenge_validity.count() <= 0 ||
      config.challenge_validity > std::chrono::milliseconds{maximum_signed_validity_milliseconds}) {
    return Result<RelayLoginService>::failure(
        service_error(ErrorCode::configuration, "login_service_config_invalid"));
  }
  auto challenges = RelayTtlTable<RelayLoginNonce, RelayLoginChallenge>::create(
      config.challenge_capacity);
  if (!challenges) {
    return Result<RelayLoginService>::failure(*challenges.error_if());
  }
  auto impl = std::make_unique<Impl>(database, relay_id, config,
                                     std::move(*challenges.value_if()));
  return Result<RelayLoginService>::success(RelayLoginService{std::move(impl)});
}

Result<std::vector<std::byte>> RelayLoginService::begin_challenge(
    std::uint64_t now_unix_milliseconds) {
  if (!impl_) {
    return Result<std::vector<std::byte>>::failure(
        service_error(ErrorCode::cancelled, "login_service_not_initialized"));
  }
  auto challenge = create_enrollment_challenge(impl_->relay_id, now_unix_milliseconds,
                                               impl_->config.challenge_validity);
  if (!challenge) {
    return Result<std::vector<std::byte>>::failure(*challenge.error_if());
  }
  auto inserted = impl_->challenges.upsert(challenge.value_if()->nonce,
                                           *challenge.value_if(),
                                           impl_->config.challenge_validity, steady_now());
  if (!inserted) {
    return Result<std::vector<std::byte>>::failure(*inserted.error_if());
  }
  auto encoded = encode_enrollment_challenge(*challenge.value_if());
  if (!encoded) {
    (void)impl_->challenges.erase(challenge.value_if()->nonce);
    return Result<std::vector<std::byte>>::failure(*encoded.error_if());
  }
  ++impl_->stats.challenges_issued;
  return encoded;
}

Result<RelayLoginCompletion> RelayLoginService::authenticate(
    std::span<const std::byte> encoded_request, std::uint64_t now_unix_milliseconds) {
  if (!impl_) {
    return Result<RelayLoginCompletion>::failure(
        service_error(ErrorCode::cancelled, "login_service_not_initialized"));
  }
  auto parsed = parse_relay_login_request(encoded_request);
  if (!parsed) {
    ++impl_->stats.validation_rejected;
    return Result<RelayLoginCompletion>::failure(*parsed.error_if());
  }
  const auto request = std::move(*parsed.value_if());

  auto challenge = impl_->challenges.take(request.challenge_nonce, steady_now());
  if (!challenge) {
    ++impl_->stats.challenges_unknown;
    return Result<RelayLoginCompletion>::failure(
        service_error(ErrorCode::authentication, "login_challenge_unknown_or_expired"));
  }

  auto device = impl_->database->device(request.device_id);
  if (!device) {
    ++impl_->stats.device_rejected;
    return Result<RelayLoginCompletion>::failure(*device.error_if());
  }
  if (!device.value_if()->has_value()) {
    ++impl_->stats.device_rejected;
    return Result<RelayLoginCompletion>::failure(
        service_error(ErrorCode::authentication, "login_device_unknown"));
  }

  auto valid = validate_relay_login_request(request, *challenge, **device.value_if(),
                                            now_unix_milliseconds);
  if (!valid) {
    ++impl_->stats.validation_rejected;
    (void)impl_->database->record_device_audit(
        request.device_id, "device_login_rejected", now_unix_milliseconds,
        "generation=" + std::to_string(request.enrollment_generation));
    return Result<RelayLoginCompletion>::failure(*valid.error_if());
  }

  auto audit = impl_->database->record_device_audit(
      request.device_id, "device_login", now_unix_milliseconds,
      "generation=" + std::to_string(request.enrollment_generation));
  if (!audit) {
    ++impl_->stats.audit_failed;
    return Result<RelayLoginCompletion>::failure(*audit.error_if());
  }

  ++impl_->stats.logins_succeeded;
  impl_->stats.challenge_table = impl_->challenges.diagnostics();
  const auto capabilities = request.supported.bits & known_capability_bits;
  return Result<RelayLoginCompletion>::success(RelayLoginCompletion{
      .device_id = request.device_id,
      .endpoint_id = request.endpoint_id,
      .tenant = request.tenant,
      .enrollment_generation = request.enrollment_generation,
      .capabilities = CapabilitySet{capabilities}});
}

RelayLoginServiceDiagnostics RelayLoginService::diagnostics() const noexcept {
  auto output = impl_ ? impl_->stats : RelayLoginServiceDiagnostics{};
  if (impl_) {
    output.challenge_table = impl_->challenges.diagnostics();
  }
  return output;
}

}  // namespace heyaki
