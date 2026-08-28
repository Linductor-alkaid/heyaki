#include <heyaki/pairing_protocol.hpp>

#include "proto_codec.hpp"

#include <algorithm>
#include <iterator>
#include <utility>

namespace heyaki {
namespace {

Error pairing_error(ErrorCode code, const char* detail) {
  return {code, "pairing", detail};
}

bool all_zero(const PairingNonce& nonce) noexcept {
  return std::all_of(nonce.begin(), nonce.end(),
                     [](std::byte byte) { return byte == std::byte{0}; });
}

// Ceiling mirrors Limits::max_pairing_payload_bytes, which the frame layer
// enforces for the PAIRING_* payload slice.
constexpr std::size_t pairing_payload_ceiling = Limits{}.max_pairing_payload_bytes;

Result<void> validate_pairing_request(const PairingRequestBody& request) {
  if (request.request_id.is_zero()) {
    return Result<void>::failure(pairing_error(ErrorCode::protocol, "request_id_zero"));
  }
  if (all_zero(request.nonce)) {
    return Result<void>::failure(pairing_error(ErrorCode::protocol, "nonce_zero"));
  }
  if (request.password_utf8.empty() || request.password_utf8.size() > max_pairing_password_bytes) {
    return Result<void>::failure(pairing_error(ErrorCode::protocol, "password_length_invalid"));
  }
  if (request.requested_scopes.empty() ||
      request.requested_scopes.size() > max_pairing_requested_scopes) {
    return Result<void>::failure(
        pairing_error(ErrorCode::protocol, "requested_scope_count_invalid"));
  }
  for (const auto& scope : request.requested_scopes) {
    if (!is_valid_trust_scope(scope)) {
      return Result<void>::failure(
          pairing_error(ErrorCode::protocol, "requested_scope_syntax_invalid"));
    }
  }
  return Result<void>::success();
}

}  // namespace

Result<std::vector<std::byte>> encode_pairing_request(const PairingRequestBody& request) {
  auto validated = validate_pairing_request(request);
  if (!validated) {
    return Result<std::vector<std::byte>>::failure(*validated.error_if());
  }
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, request.request_id.bytes());
  proto_codec::append_bytes(output, 2U,
                            std::span<const std::byte>{request.nonce.data(),
                                                       request.nonce.size()});
  proto_codec::append_text(output, 3U, request.password_utf8);
  for (const auto& scope : request.requested_scopes) {
    proto_codec::append_text(output, 4U, scope);
  }
  if (output.size() > max_pairing_password_bytes + pairing_payload_ceiling) {
    return Result<std::vector<std::byte>>::failure(
        pairing_error(ErrorCode::resource_exhausted, "object_too_large"));
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<PairingRequestBody> parse_pairing_request(std::span<const std::byte> payload) {
  if (payload.size() > pairing_payload_ceiling) {
    return Result<PairingRequestBody>::failure(
        pairing_error(ErrorCode::resource_exhausted, "object_too_large"));
  }
  proto_codec::ProtoReader reader(payload);
  std::optional<RequestId> request_id;
  std::optional<PairingNonce> nonce;
  std::optional<std::string> password;
  std::optional<std::vector<std::string>> scopes;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<PairingRequestBody>::failure(*field.error_if());
    }
    switch (field.value_if()->number) {
      case 1U: {
        if (field.value_if()->wire_type != 2U || request_id) {
          return Result<PairingRequestBody>::failure(
              pairing_error(ErrorCode::protocol, "request_id_field_conflict"));
        }
        RequestId::Storage value{};
        auto copied = proto_codec::copy_exact(field.value_if()->bytes, value,
                                              "request_id_field_invalid");
        if (!copied) {
          return Result<PairingRequestBody>::failure(*copied.error_if());
        }
        request_id = RequestId{value};
        break;
      }
      case 2U: {
        if (field.value_if()->wire_type != 2U || nonce) {
          return Result<PairingRequestBody>::failure(
              pairing_error(ErrorCode::protocol, "nonce_field_conflict"));
        }
        PairingNonce value{};
        auto copied =
            proto_codec::copy_exact(field.value_if()->bytes, value, "nonce_field_invalid");
        if (!copied) {
          return Result<PairingRequestBody>::failure(*copied.error_if());
        }
        nonce = value;
        break;
      }
      case 3U: {
        if (field.value_if()->wire_type != 2U || password) {
          return Result<PairingRequestBody>::failure(
              pairing_error(ErrorCode::protocol, "password_field_conflict"));
        }
        password = std::string{reader.text(*field.value_if())};
        break;
      }
      case 4U: {
        if (field.value_if()->wire_type != 2U) {
          return Result<PairingRequestBody>::failure(
              pairing_error(ErrorCode::protocol, "scope_field_invalid"));
        }
        const auto text = reader.text(*field.value_if());
        if (!is_valid_trust_scope(text)) {
          return Result<PairingRequestBody>::failure(
              pairing_error(ErrorCode::protocol, "requested_scope_syntax_invalid"));
        }
        if (!scopes) scopes.emplace();
        if (scopes->size() >= max_pairing_requested_scopes) {
          return Result<PairingRequestBody>::failure(
              pairing_error(ErrorCode::protocol, "requested_scope_count_invalid"));
        }
        scopes->emplace_back(text);
        break;
      }
      default:
        return Result<PairingRequestBody>::failure(
            pairing_error(ErrorCode::protocol, "field_unknown"));
    }
  }
  if (!request_id || !nonce || !password || !scopes || scopes->empty()) {
    return Result<PairingRequestBody>::failure(pairing_error(ErrorCode::protocol,
                                                             "field_missing"));
  }
  PairingRequestBody request;
  request.request_id = *request_id;
  request.nonce = *nonce;
  request.password_utf8 = std::move(*password);
  request.requested_scopes = std::move(*scopes);
  auto validated = validate_pairing_request(request);
  if (!validated) {
    return Result<PairingRequestBody>::failure(*validated.error_if());
  }
  return Result<PairingRequestBody>::success(std::move(request));
}

Result<std::vector<std::byte>> encode_pairing_result(const PairingResultBody& result) {
  if (result.request_id.is_zero()) {
    return Result<std::vector<std::byte>>::failure(
        pairing_error(ErrorCode::protocol, "request_id_zero"));
  }
  if (result.status == StableStatus::unspecified) {
    return Result<std::vector<std::byte>>::failure(
        pairing_error(ErrorCode::protocol, "status_unspecified"));
  }
  if (result.grant.has_value() && result.status != StableStatus::ok) {
    return Result<std::vector<std::byte>>::failure(
        pairing_error(ErrorCode::protocol, "grant_with_failure_status"));
  }
  if (!result.grant.has_value() && result.status == StableStatus::ok) {
    return Result<std::vector<std::byte>>::failure(
        pairing_error(ErrorCode::protocol, "ok_without_grant"));
  }
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, result.request_id.bytes());
  proto_codec::append_uint(output, 2U, static_cast<std::uint64_t>(result.status));
  if (result.grant.has_value()) {
    auto encoded = encode_signed_trust_grant(*result.grant);
    if (!encoded) {
      return Result<std::vector<std::byte>>::failure(*encoded.error_if());
    }
    proto_codec::append_bytes(output, 3U, *encoded.value_if());
  }
  if (output.size() > pairing_payload_ceiling) {
    return Result<std::vector<std::byte>>::failure(
        pairing_error(ErrorCode::resource_exhausted, "object_too_large"));
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<PairingResultBody> parse_pairing_result(std::span<const std::byte> payload) {
  if (payload.size() > pairing_payload_ceiling) {
    return Result<PairingResultBody>::failure(
        pairing_error(ErrorCode::resource_exhausted, "object_too_large"));
  }
  proto_codec::ProtoReader reader(payload);
  std::optional<RequestId> request_id;
  std::optional<StableStatus> status;
  std::optional<SignedTrustGrant> grant;
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<PairingResultBody>::failure(*field.error_if());
    }
    switch (field.value_if()->number) {
      case 1U: {
        if (field.value_if()->wire_type != 2U || request_id) {
          return Result<PairingResultBody>::failure(
              pairing_error(ErrorCode::protocol, "request_id_field_conflict"));
        }
        RequestId::Storage value{};
        auto copied = proto_codec::copy_exact(field.value_if()->bytes, value,
                                              "request_id_field_invalid");
        if (!copied) {
          return Result<PairingResultBody>::failure(*copied.error_if());
        }
        request_id = RequestId{value};
        break;
      }
      case 2U: {
        if (field.value_if()->wire_type != 0U || status) {
          return Result<PairingResultBody>::failure(
              pairing_error(ErrorCode::protocol, "status_field_conflict"));
        }
        const auto value = static_cast<std::uint32_t>(field.value_if()->integer);
        if (value > static_cast<std::uint32_t>(StableStatus::outcome_unknown)) {
          return Result<PairingResultBody>::failure(
              pairing_error(ErrorCode::protocol, "status_unknown"));
        }
        status = static_cast<StableStatus>(value);
        break;
      }
      case 3U: {
        if (field.value_if()->wire_type != 2U || grant) {
          return Result<PairingResultBody>::failure(
              pairing_error(ErrorCode::protocol, "grant_field_conflict"));
        }
        auto parsed = parse_signed_trust_grant(field.value_if()->bytes);
        if (!parsed) {
          return Result<PairingResultBody>::failure(*parsed.error_if());
        }
        grant = std::move(*parsed.value_if());
        break;
      }
      default:
        return Result<PairingResultBody>::failure(
            pairing_error(ErrorCode::protocol, "field_unknown"));
    }
  }
  if (!request_id || !status) {
    return Result<PairingResultBody>::failure(pairing_error(ErrorCode::protocol,
                                                             "field_missing"));
  }
  if (grant.has_value() && *status != StableStatus::ok) {
    return Result<PairingResultBody>::failure(
        pairing_error(ErrorCode::protocol, "grant_with_failure_status"));
  }
  PairingResultBody result;
  result.request_id = *request_id;
  result.status = *status;
  result.grant = std::move(grant);
  return Result<PairingResultBody>::success(std::move(result));
}

PairingRequestAdmission::PairingRequestAdmission(Limits limits) : limits_(limits) {}

Result<PairingAdmissionOutcome> PairingRequestAdmission::admit_request(
    const PairingRequestBody& request) {
  auto validated = validate_pairing_request(request);
  if (!validated) {
    return Result<PairingAdmissionOutcome>::failure(*validated.error_if());
  }
  for (const auto& [terminal_key, result] : terminal_results_) {
    if (terminal_key.first != request.request_id) continue;
    if (terminal_key.second == request.nonce) {
      // Byte-identical retransmission of a terminal request replays the
      // cached result without re-verifying the password.
      return Result<PairingAdmissionOutcome>::success(
          {.action = PairingAdmissionAction::duplicate,
           .cached_result = result});
    }
    // Same request id with a different nonce is a conflicting duplicate.
    return Result<PairingAdmissionOutcome>::failure(
        pairing_error(ErrorCode::protocol, "conflicting_duplicate_request"));
  }
  if (attempts_used_ >= limits_.max_pairing_attempts_per_session) {
    return Result<PairingAdmissionOutcome>::failure(
        pairing_error(ErrorCode::pairing_rate_limited, "pairing_attempts_exhausted"));
  }
  pending_key_ = std::make_pair(request.request_id, request.nonce);
  ++attempts_used_;
  return Result<PairingAdmissionOutcome>::success(
      {.action = PairingAdmissionAction::admitted, .cached_result = std::nullopt});
}

Result<void> PairingRequestAdmission::record_result(PairingResultBody result) {
  if (!pending_key_.has_value() || pending_key_->first != result.request_id) {
    return Result<void>::failure(
        pairing_error(ErrorCode::configuration, "no_admitted_request"));
  }
  for (auto& [terminal_key, cached] : terminal_results_) {
    if (terminal_key.first == result.request_id) {
      cached = std::move(result);
      pending_key_.reset();
      return Result<void>::success();
    }
  }
  if (terminal_results_.size() >= limits_.max_pairing_attempts_per_session) {
    terminal_results_.erase(terminal_results_.begin());
  }
  terminal_results_.emplace_back(*pending_key_, std::move(result));
  pending_key_.reset();
  return Result<void>::success();
}

std::size_t PairingRequestAdmission::attempts_used() const noexcept {
  return attempts_used_;
}

bool PairingRequestAdmission::exhausted() const noexcept {
  return attempts_used_ >= limits_.max_pairing_attempts_per_session;
}

const Limits& PairingRequestAdmission::limits() const noexcept { return limits_; }

}  // namespace heyaki
