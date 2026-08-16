#include <heyaki/relay_enrollment_client.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

Error enrollment_client_error(ErrorCode code, const char* detail) {
  return Error{code, "relay_enrollment_client", detail};
}

bool valid_enrollment_token(std::string_view token) noexcept {
  if (token.size() < 16U || token.size() > 256U) {
    return false;
  }
  return std::all_of(token.begin(), token.end(), [](char raw) {
    const auto character = static_cast<unsigned char>(raw);
    return character >= 0x21U && character <= 0x7eU;
  });
}

bool valid_tenant(std::string_view value) noexcept {
  if (value.empty() || value.size() > 128U) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](char raw) {
    const auto character = static_cast<unsigned char>(raw);
    return character >= 0x21U && character <= 0x7eU;
  });
}

}  // namespace

Result<RelayEnrollmentClientResult> enroll_relay_profile(
    const RelayEnrollmentClientConfig& config, std::string_view bootstrap_token,
    std::uint64_t now_unix_milliseconds) {
  if (config.profile == nullptr || config.application_id.empty() ||
      config.relay_url.empty() || config.relay_url.size() > 2048U ||
      !valid_tenant(config.tenant) || !valid_enrollment_token(bootstrap_token) ||
      !config.exchange) {
    return Result<RelayEnrollmentClientResult>::failure(
        enrollment_client_error(ErrorCode::configuration, "enrollment_config_invalid"));
  }
  if (config.relay_pin && config.relay_pin->size() != 32U) {
    return Result<RelayEnrollmentClientResult>::failure(
        enrollment_client_error(ErrorCode::configuration, "enrollment_pin_invalid"));
  }

  auto readiness = config.profile->local_readiness(config.application_id);
  if (!readiness) {
    return Result<RelayEnrollmentClientResult>::failure(*readiness.error_if());
  }
  if (!readiness.value_if()->ready()) {
    return Result<RelayEnrollmentClientResult>::failure(
        enrollment_client_error(ErrorCode::not_registered, "profile_not_initialized"));
  }
  auto identity = config.profile->load_identity();
  if (!identity) {
    return Result<RelayEnrollmentClientResult>::failure(*identity.error_if());
  }
  auto endpoint = config.profile->endpoint_for(config.application_id);
  if (!endpoint) {
    return Result<RelayEnrollmentClientResult>::failure(*endpoint.error_if());
  }
  if (endpoint.value_if()->is_zero()) {
    return Result<RelayEnrollmentClientResult>::failure(
        enrollment_client_error(ErrorCode::identity, "endpoint_invalid"));
  }

  auto exchanged = config.exchange(*identity.value_if(), *endpoint.value_if(),
                                   config.tenant, bootstrap_token,
                                   now_unix_milliseconds);
  if (!exchanged) {
    return Result<RelayEnrollmentClientResult>::failure(*exchanged.error_if());
  }
  const auto& exchange_result = *exchanged.value_if();
  if (exchange_result.relay_url != config.relay_url ||
      exchange_result.tenant != config.tenant ||
      exchange_result.enrollment_generation == 0U) {
    if (config.rollback) {
      (void)config.rollback(identity.value_if()->device_id(), config.tenant,
                            exchange_result.enrollment_generation);
    }
    return Result<RelayEnrollmentClientResult>::failure(
        enrollment_client_error(ErrorCode::outcome_unknown,
                                "enrollment_exchange_result_mismatch"));
  }

  RelayEnrollmentRecord record;
  record.relay_url = exchange_result.relay_url;
  record.relay_pin = config.relay_pin;
  record.tenant = exchange_result.tenant;
  record.enrollment_generation = exchange_result.enrollment_generation;
  record.auto_connect = config.auto_connect;
  record.revoked = false;
  auto persisted = config.profile->put_relay_enrollment(record);
  if (!persisted) {
    if (config.rollback) {
      auto rolled_back =
          config.rollback(identity.value_if()->device_id(), record.tenant,
                          record.enrollment_generation);
      if (!rolled_back) {
        return Result<RelayEnrollmentClientResult>::failure(Error{
            ErrorCode::outcome_unknown, "relay_enrollment_client",
            "relay_enrollment_rollback_failed",
            persisted.error_if()->underlying_code()});
      }
    }
    return Result<RelayEnrollmentClientResult>::failure(*persisted.error_if());
  }

  return Result<RelayEnrollmentClientResult>::success(RelayEnrollmentClientResult{
      .relay_url = record.relay_url,
      .tenant = record.tenant,
      .enrollment_generation = record.enrollment_generation,
      .token_remaining_uses_after = exchange_result.token_remaining_uses_after});
}

}  // namespace heyaki
