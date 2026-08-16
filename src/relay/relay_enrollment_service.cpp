#include "relay_enrollment_service.hpp"

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
  return Error{code, "relay_enrollment_service", detail};
}

std::chrono::steady_clock::time_point steady_now() {
  return std::chrono::steady_clock::now();
}

}  // namespace

struct RelayEnrollmentService::Impl {
  Impl(RelayDatabase* database_value, RelayId relay_id_value,
       RelayEnrollmentServiceConfig config_value,
       RelayTtlTable<EnrollmentChallengeNonce, EnrollmentChallenge> table_value) noexcept
      : database(database_value),
        relay_id(relay_id_value),
        config(std::move(config_value)),
        challenges(std::move(table_value)) {}

  RelayDatabase* database{nullptr};
  RelayId relay_id{};
  RelayEnrollmentServiceConfig config;
  RelayTtlTable<EnrollmentChallengeNonce, EnrollmentChallenge> challenges;
  RelayEnrollmentServiceDiagnostics stats;
};

RelayEnrollmentService::RelayEnrollmentService(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}
RelayEnrollmentService::RelayEnrollmentService(RelayEnrollmentService&&) noexcept = default;
RelayEnrollmentService& RelayEnrollmentService::operator=(RelayEnrollmentService&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}
RelayEnrollmentService::~RelayEnrollmentService() = default;

Result<RelayEnrollmentService> RelayEnrollmentService::create(
    RelayDatabase* database, RelayId relay_id,
    const RelayEnrollmentServiceConfig& config) {
  if (database == nullptr || relay_id == RelayId{} || config.challenge_capacity == 0U ||
      config.challenge_validity.count() <= 0 ||
      config.challenge_validity > std::chrono::milliseconds{maximum_signed_validity_milliseconds}) {
    return Result<RelayEnrollmentService>::failure(
        service_error(ErrorCode::configuration, "enrollment_service_config_invalid"));
  }
  auto challenges = RelayTtlTable<EnrollmentChallengeNonce, EnrollmentChallenge>::create(
      config.challenge_capacity);
  if (!challenges) {
    return Result<RelayEnrollmentService>::failure(*challenges.error_if());
  }
  auto impl = std::make_unique<Impl>(database, relay_id, config,
                                     std::move(*challenges.value_if()));
  return Result<RelayEnrollmentService>::success(
      RelayEnrollmentService{std::move(impl)});
}

Result<std::vector<std::byte>> RelayEnrollmentService::begin_challenge(
    std::uint64_t now_unix_milliseconds) {
  if (!impl_) {
    return Result<std::vector<std::byte>>::failure(
        service_error(ErrorCode::cancelled, "enrollment_service_not_initialized"));
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

Result<RelayEnrollmentCompletion> RelayEnrollmentService::complete(
    std::span<const std::byte> encoded_request, std::uint64_t now_unix_milliseconds) {
  if (!impl_) {
    return Result<RelayEnrollmentCompletion>::failure(
        service_error(ErrorCode::cancelled, "enrollment_service_not_initialized"));
  }
  auto parsed = parse_enrollment_request(encoded_request);
  if (!parsed) {
    ++impl_->stats.validation_rejected;
    return Result<RelayEnrollmentCompletion>::failure(*parsed.error_if());
  }
  const auto request = std::move(*parsed.value_if());

  auto challenge = impl_->challenges.take(request.challenge_nonce, steady_now());
  if (!challenge) {
    ++impl_->stats.challenges_unknown;
    return Result<RelayEnrollmentCompletion>::failure(
        service_error(ErrorCode::authentication, "enrollment_challenge_unknown_or_expired"));
  }
  auto valid = validate_enrollment_request(request, *challenge, now_unix_milliseconds);
  if (!valid) {
    ++impl_->stats.validation_rejected;
    return Result<RelayEnrollmentCompletion>::failure(*valid.error_if());
  }

  auto existing = impl_->database->device(request.device_id);
  if (!existing) {
    ++impl_->stats.database_rejected;
    return Result<RelayEnrollmentCompletion>::failure(*existing.error_if());
  }
  if (existing.value_if() && (*existing.value_if())->status == RelayDeviceStatus::active &&
      (*existing.value_if())->public_key == request.identity_public_key &&
      (*existing.value_if())->tenant == request.tenant) {
    ++impl_->stats.challenges_completed;
    return Result<RelayEnrollmentCompletion>::success(RelayEnrollmentCompletion{
        .device_id = request.device_id,
        .endpoint_id = request.endpoint_id,
        .tenant = request.tenant,
        .enrollment_generation = (*existing.value_if())->enrollment_generation,
        .token_remaining_uses_after = std::nullopt});
  }

  auto consumed = impl_->database->consume_bootstrap_token(
      request.bootstrap_token, request.tenant, request.device_id, now_unix_milliseconds);
  if (!consumed) {
    ++impl_->stats.token_rejected;
    return Result<RelayEnrollmentCompletion>::failure(*consumed.error_if());
  }

  const std::uint64_t generation =
      existing.value_if() ? (*existing.value_if())->enrollment_generation + 1U : 1U;
  RelayDeviceRecord record;
  record.device_id = request.device_id;
  record.public_key = request.identity_public_key;
  record.tenant = request.tenant;
  record.display_name = "device";
  record.enrollment_generation = generation;
  record.status = RelayDeviceStatus::active;
  auto enrolled = impl_->database->enroll_device(record, now_unix_milliseconds);
  if (!enrolled) {
    ++impl_->stats.database_rejected;
    return Result<RelayEnrollmentCompletion>::failure(*enrolled.error_if());
  }

  ++impl_->stats.challenges_completed;
  impl_->stats.challenge_table = impl_->challenges.diagnostics();
  return Result<RelayEnrollmentCompletion>::success(RelayEnrollmentCompletion{
      .device_id = request.device_id,
      .endpoint_id = request.endpoint_id,
      .tenant = std::move(record.tenant),
      .enrollment_generation = generation,
      .token_remaining_uses_after = consumed.value_if()->remaining_uses_after});
}

RelayEnrollmentServiceDiagnostics RelayEnrollmentService::diagnostics() const noexcept {
  auto output = impl_ ? impl_->stats : RelayEnrollmentServiceDiagnostics{};
  if (impl_) {
    output.challenge_table = impl_->challenges.diagnostics();
  }
  return output;
}

}  // namespace heyaki
