#include "relay_enrollment_service.hpp"

#include <heyaki/error.hpp>
#include <heyaki/password.hpp>
#include <heyaki/security.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
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

bool valid_default_tenant(std::string_view tenant) noexcept {
  if (tenant.empty() || tenant.size() > 128U) {
    return false;
  }
  for (const char raw : tenant) {
    const auto character = static_cast<unsigned char>(raw);
    if (character < 0x20U || character > 0x7eU) {
      return false;
    }
  }
  return true;
}

// Verifier input encoding: both --init and the service feed the LOWERCASE HEX
// of the 32-byte proof into create_password_verifier / verify_password, since
// create_password_verifier enforces UTF-8 policy on its input and the raw
// proof bytes are binary. The wire format stays the raw 32 bytes.
std::string hex_proof(const EnrollmentPasswordProof& proof) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string output;
  output.reserve(proof.size() * 2U);
  for (const auto byte : proof) {
    const auto value = std::to_integer<unsigned char>(byte);
    output.push_back(digits[value >> 4U]);
    output.push_back(digits[value & 0x0fU]);
  }
  return output;
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
      config.challenge_validity > std::chrono::milliseconds{maximum_signed_validity_milliseconds} ||
      (config.mode == RelayEnrollmentMode::password &&
       !valid_default_tenant(config.default_tenant))) {
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
  if (impl_->config.mode == RelayEnrollmentMode::closed) {
    ++impl_->stats.mode_rejected;
    return Result<std::vector<std::byte>>::failure(
        service_error(ErrorCode::permission, "enrollment_closed"));
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

  // Admission mode gate. Token mode keeps the historical bootstrap-token
  // consume below; password mode verifies the relay-bound Argon2id proof
  // against the stored owner verifier; closed mode rejects everything that
  // got this far (defense in depth: begin_challenge already refuses to issue
  // challenges). The proof is a bearer credential in the same class as a
  // bootstrap token; replay/freshness defenses are the single-use challenge
  // plus the device signature chain, and online guessing is bounded by the
  // per-IP enrollment throttle at the server layer.
  if (impl_->config.mode == RelayEnrollmentMode::closed) {
    ++impl_->stats.mode_rejected;
    return Result<RelayEnrollmentCompletion>::failure(
        service_error(ErrorCode::permission, "enrollment_closed"));
  }
  if (impl_->config.mode == RelayEnrollmentMode::password) {
    if (!request.password_proof) {
      ++impl_->stats.mode_rejected;
      return Result<RelayEnrollmentCompletion>::failure(service_error(
          ErrorCode::authentication, "enrollment_password_proof_required"));
    }
    if ((request.supported.bits &
         static_cast<std::uint64_t>(Capability::relay_enrollment_password_v1)) == 0U) {
      ++impl_->stats.mode_rejected;
      return Result<RelayEnrollmentCompletion>::failure(service_error(
          ErrorCode::authentication, "enrollment_password_capability_missing"));
    }
    if (request.tenant != impl_->config.default_tenant) {
      ++impl_->stats.mode_rejected;
      return Result<RelayEnrollmentCompletion>::failure(
          service_error(ErrorCode::authentication, "enrollment_tenant_unknown"));
    }
    auto stored = impl_->database->enrollment_password_verifier();
    if (!stored) {
      ++impl_->stats.database_rejected;
      return Result<RelayEnrollmentCompletion>::failure(*stored.error_if());
    }
    if (!stored.value_if()->has_value()) {
      ++impl_->stats.mode_rejected;
      return Result<RelayEnrollmentCompletion>::failure(service_error(
          ErrorCode::configuration, "enrollment_password_not_provisioned"));
    }
    const auto& record = **stored.value_if();
    PasswordVerifier verifier;
    verifier.format_version = record.format_version;
    verifier.parameters.operations = record.argon2_operations;
    verifier.parameters.memory_bytes =
        static_cast<std::size_t>(record.argon2_memory_kib) * 1024U;
    verifier.encoded = record.encoded;
    auto verified = verify_password(hex_proof(*request.password_proof), verifier);
    if (!verified) {
      ++impl_->stats.database_rejected;
      return Result<RelayEnrollmentCompletion>::failure(*verified.error_if());
    }
    if (!*verified.value_if()) {
      ++impl_->stats.password_rejected;
      return Result<RelayEnrollmentCompletion>::failure(service_error(
          ErrorCode::authentication, "enrollment_password_rejected"));
    }
  }

  auto existing = impl_->database->device(request.device_id);
  if (!existing) {
    ++impl_->stats.database_rejected;
    return Result<RelayEnrollmentCompletion>::failure(*existing.error_if());
  }
  if (existing.value_if()->has_value() &&
      (*existing.value_if())->status == RelayDeviceStatus::active &&
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

  std::optional<std::uint64_t> token_remaining_uses_after;
  if (impl_->config.mode == RelayEnrollmentMode::token) {
    auto consumed = impl_->database->consume_bootstrap_token(
        request.bootstrap_token, request.tenant, request.device_id, now_unix_milliseconds);
    if (!consumed) {
      ++impl_->stats.token_rejected;
      return Result<RelayEnrollmentCompletion>::failure(*consumed.error_if());
    }
    token_remaining_uses_after = consumed.value_if()->remaining_uses_after;
  }

  const std::uint64_t generation =
      existing.value_if()->has_value()
          ? (*existing.value_if())->enrollment_generation + 1U
          : 1U;
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
      .token_remaining_uses_after = token_remaining_uses_after});
}

RelayEnrollmentServiceDiagnostics RelayEnrollmentService::diagnostics() const noexcept {
  auto output = impl_ ? impl_->stats : RelayEnrollmentServiceDiagnostics{};
  if (impl_) {
    output.challenge_table = impl_->challenges.diagnostics();
  }
  return output;
}

}  // namespace heyaki
