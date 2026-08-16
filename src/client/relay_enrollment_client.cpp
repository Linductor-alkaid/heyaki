#include <heyaki/relay_enrollment_client.hpp>

#include "relay_wss_client.hpp"
#include "../relay/relay_enrollment.hpp"

#include <heyaki/protocol.hpp>
#include <heyaki/relay_wss_control.hpp>

#include <algorithm>
#include <chrono>
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

static std::string relay_control_url(std::string relay_url) {
  while (relay_url.size() > 1U && relay_url.back() == '/') {
    relay_url.pop_back();
  }
  if (relay_url.ends_with(relay_wss_control_path)) {
    return relay_url;
  }
  relay_url.append(relay_wss_control_path);
  return relay_url;
}

Error enrollment_wss_error(ErrorCode code, const char* detail) {
  return Error{code, "relay_enrollment_wss", detail};
}

Result<RelayEnrollmentExchangeResult> enroll_relay_over_wss(
    const RelayEnrollmentWssTransportConfig& transport,
    const IdentityKeyPair& identity, const EndpointId& endpoint_id,
    std::string_view tenant, std::string_view bootstrap_token,
    std::uint64_t now_unix_milliseconds) {
  if (transport.relay_url.empty() || transport.relay_url.size() > 2048U ||
      endpoint_id.is_zero() || !valid_tenant(tenant) ||
      !valid_enrollment_token(bootstrap_token) || transport.connect_timeout.count() <= 0 ||
      transport.handshake_timeout.count() <= 0 || transport.close_timeout.count() <= 0) {
    return Result<RelayEnrollmentExchangeResult>::failure(
        enrollment_wss_error(ErrorCode::configuration, "enrollment_transport_invalid"));
  }
  if (transport.relay_pin && transport.relay_pin->size() != relay_tls_pin_bytes) {
    return Result<RelayEnrollmentExchangeResult>::failure(
        enrollment_wss_error(ErrorCode::configuration, "enrollment_pin_invalid"));
  }

  RelayWssClientConfig client_config;
  client_config.url = relay_control_url(transport.relay_url);
  if (transport.relay_pin) {
    RelayTlsPin pin{};
    std::copy_n(transport.relay_pin->begin(), pin.size(), pin.begin());
    client_config.relay_pin = pin;
  }
  client_config.tls_ca_file = transport.tls_ca_file;
  client_config.tls_verify_peer = transport.tls_verify_peer;
  client_config.connect_timeout = transport.connect_timeout;
  client_config.handshake_timeout = transport.handshake_timeout;
  client_config.close_timeout = transport.close_timeout;
  client_config.runtime = transport.runtime;

  auto client = RelayWssClient::create(std::move(client_config));
  if (!client) {
    return Result<RelayEnrollmentExchangeResult>::failure(*client.error_if());
  }
  auto close_best_effort = [&] {
    (void)client.value_if()->close(transport.close_timeout);
  };

  auto connected = client.value_if()->connect(
      transport.connect_timeout + transport.handshake_timeout);
  if (!connected) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(*connected.error_if());
  }

  auto challenge_frame = encode_relay_wss_control_frame(
      RelayWssControlType::enrollment_challenge, {});
  if (!challenge_frame) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(*challenge_frame.error_if());
  }
  auto sent = client.value_if()->send(*challenge_frame.value_if());
  if (!sent) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(*sent.error_if());
  }
  auto challenge_message = client.value_if()->receive(transport.connect_timeout);
  if (!challenge_message) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(*challenge_message.error_if());
  }
  if (challenge_message.value_if()->text) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(
        enrollment_wss_error(ErrorCode::protocol, "enrollment_challenge_not_binary"));
  }
  auto challenge_envelope =
      parse_relay_wss_control_frame(challenge_message.value_if()->payload);
  if (!challenge_envelope ||
      challenge_envelope.value_if()->type !=
          RelayWssControlType::enrollment_challenge_response) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(
        challenge_envelope
            ? enrollment_wss_error(ErrorCode::protocol,
                                   "enrollment_challenge_response_expected")
            : *challenge_envelope.error_if());
  }
  auto challenge =
      parse_enrollment_challenge(challenge_envelope.value_if()->payload);
  if (!challenge) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(*challenge.error_if());
  }

  EnrollmentRequest request;
  request.device_id = identity.device_id();
  request.endpoint_id = endpoint_id;
  request.identity_public_key = identity.public_key();
  request.challenge_nonce = challenge.value_if()->nonce;
  request.tenant = std::string{tenant};
  request.bootstrap_token = std::string{bootstrap_token};
  request.protocol_version = current_protocol_version;
  request.supported.bits = known_capability_bits;
  request.required.bits = static_cast<std::uint64_t>(Capability::enrollment);
  const std::uint64_t requested_expiry =
      now_unix_milliseconds + 30U * 1000U;
  request.expires_unix_milliseconds =
      std::min(requested_expiry, challenge.value_if()->expires_unix_milliseconds - 1U);
  auto signed_request =
      sign_enrollment_request(request, challenge.value_if()->relay_id, identity);
  if (!signed_request) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(*signed_request.error_if());
  }
  auto encoded_request = encode_enrollment_request(request);
  if (!encoded_request) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(*encoded_request.error_if());
  }
  auto request_frame = encode_relay_wss_control_frame(
      RelayWssControlType::enrollment_request, *encoded_request.value_if());
  if (!request_frame) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(*request_frame.error_if());
  }
  sent = client.value_if()->send(*request_frame.value_if());
  if (!sent) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(*sent.error_if());
  }
  auto result_message = client.value_if()->receive(transport.connect_timeout);
  if (!result_message) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(*result_message.error_if());
  }
  if (result_message.value_if()->text) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(
        enrollment_wss_error(ErrorCode::protocol, "enrollment_result_not_binary"));
  }
  auto result_envelope =
      parse_relay_wss_control_frame(result_message.value_if()->payload);
  if (!result_envelope) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(*result_envelope.error_if());
  }
  if (result_envelope.value_if()->type == RelayWssControlType::control_error) {
    auto remote = parse_relay_wss_control_error(result_envelope.value_if()->payload);
    close_best_effort();
    if (!remote) {
      return Result<RelayEnrollmentExchangeResult>::failure(*remote.error_if());
    }
    return Result<RelayEnrollmentExchangeResult>::failure(
        Error{remote.value_if()->code, "relay_enrollment_wss",
              remote.value_if()->safe_detail});
  }
  if (result_envelope.value_if()->type != RelayWssControlType::enrollment_result) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(
        enrollment_wss_error(ErrorCode::protocol, "enrollment_result_expected"));
  }
  auto result =
      parse_relay_wss_enrollment_result(result_envelope.value_if()->payload);
  if (!result) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(*result.error_if());
  }
  if (result.value_if()->tenant != tenant) {
    close_best_effort();
    return Result<RelayEnrollmentExchangeResult>::failure(
        enrollment_wss_error(ErrorCode::outcome_unknown,
                             "enrollment_tenant_mismatch"));
  }
  close_best_effort();
  return Result<RelayEnrollmentExchangeResult>::success(RelayEnrollmentExchangeResult{
      .relay_url = transport.relay_url,
      .tenant = result.value_if()->tenant,
      .enrollment_generation = result.value_if()->enrollment_generation,
      .token_remaining_uses_after = result.value_if()->token_remaining_uses_after});
}

RelayEnrollmentExchange make_relay_enrollment_wss_exchange(
    RelayEnrollmentWssTransportConfig transport) {
  return [transport = std::move(transport)](
             const IdentityKeyPair& identity, const EndpointId& endpoint_id,
             std::string_view tenant, std::string_view bootstrap_token,
             std::uint64_t now_unix_milliseconds) mutable {
    return enroll_relay_over_wss(transport, identity, endpoint_id, tenant,
                                 bootstrap_token, now_unix_milliseconds);
  };
}

Result<RelayEnrollmentClientResult> enroll_relay_profile(
    const RelayEnrollmentClientConfig& config, std::string_view bootstrap_token,
    std::uint64_t now_unix_milliseconds) {
  if (config.profile == nullptr || config.application_id.empty() ||
      config.relay_url.empty() || config.relay_url.size() > 2048U ||
      !valid_tenant(config.tenant) || !valid_enrollment_token(bootstrap_token) ||
      (!config.exchange && !config.wss_transport)) {
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

  const auto exchange = config.exchange
                               ? config.exchange
                               : make_relay_enrollment_wss_exchange(
                                     *config.wss_transport);
  auto exchanged = exchange(*identity.value_if(), *endpoint.value_if(),
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
