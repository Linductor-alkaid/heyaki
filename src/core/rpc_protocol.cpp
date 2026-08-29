// Unary RPC wire codec (M6-08) over the frozen heyaki.protocol.rpc.v1
// schemas, plus the process-wide ServiceRegistry (M6-07) and the handler
// call context (M6-10). The library encodes these payloads through the
// shared minimal protobuf wire codec instead of a generated lite runtime.

#include <heyaki/rpc.hpp>

#include "proto_codec.hpp"

#include <algorithm>
#include <array>
#include <utility>

namespace heyaki {
namespace {

Error rpc_error(std::string_view detail) {
  return Error{ErrorCode::protocol, "rpc", std::string{detail}};
}

bool printable_ascii(std::string_view value) noexcept {
  for (const char character : value) {
    const auto byte = static_cast<unsigned char>(character);
    if (byte < 0x20U || byte > 0x7EU) {
      return false;
    }
  }
  return true;
}

Result<void> validate_request_domain(const RpcRequestBody& request,
                                     const Limits& limits) {
  if (request.request_id.is_zero()) {
    return Result<void>::failure(rpc_error("request_id_missing"));
  }
  if (request.service.empty() || request.service.size() > max_rpc_service_name_bytes ||
      !printable_ascii(request.service)) {
    return Result<void>::failure(rpc_error("service_name_invalid"));
  }
  if (request.method.empty() || request.method.size() > max_rpc_method_name_bytes ||
      !printable_ascii(request.method)) {
    return Result<void>::failure(rpc_error("method_name_invalid"));
  }
  if (request.schema_version == 0U || request.schema_version > max_rpc_schema_version) {
    return Result<void>::failure(rpc_error("schema_version_invalid"));
  }
  if (request.deadline_remaining_milliseconds < min_rpc_deadline_milliseconds ||
      request.deadline_remaining_milliseconds > max_rpc_deadline_milliseconds) {
    return Result<void>::failure(rpc_error("deadline_out_of_range"));
  }
  if (request.idempotency_key.has_value() &&
      (request.idempotency_key->empty() ||
       request.idempotency_key->size() > max_rpc_idempotency_key_bytes)) {
    return Result<void>::failure(rpc_error("idempotency_key_invalid"));
  }
  if (request.metadata.size() > max_rpc_metadata_entries) {
    return Result<void>::failure(rpc_error("metadata_count_exceeded"));
  }
  for (const auto& entry : request.metadata) {
    if (entry.name.empty() || entry.name.size() > max_rpc_metadata_name_bytes ||
        !printable_ascii(entry.name)) {
      return Result<void>::failure(rpc_error("metadata_name_invalid"));
    }
    if (entry.value.size() > max_rpc_metadata_value_bytes) {
      return Result<void>::failure(rpc_error("metadata_value_oversized"));
    }
  }
  if (request.payload.size() > limits.max_rpc_payload_bytes) {
    return Result<void>::failure(rpc_error("payload_oversized"));
  }
  return Result<void>::success();
}

void append_metadata_entry(std::vector<std::byte>& output,
                           const RpcMetadataEntry& entry) {
  // map<string, bytes> entry: nested message { string key = 1; bytes value = 2 }.
  std::vector<std::byte> nested;
  proto_codec::append_text(nested, 1U, entry.name);
  proto_codec::append_bytes(nested, 2U, entry.value);
  proto_codec::append_bytes(output, 7U, nested);
}

}  // namespace

Result<std::vector<std::byte>> encode_rpc_request(const RpcRequestBody& request,
                                                  const Limits& limits) {
  auto valid = validate_request_domain(request, limits);
  if (!valid) {
    return Result<std::vector<std::byte>>::failure(*valid.error_if());
  }
  std::vector<std::byte> output;
  output.reserve(request.payload.size() + 64U);
  proto_codec::append_bytes(output, 1U, request.request_id.bytes());
  proto_codec::append_text(output, 2U, request.service);
  proto_codec::append_text(output, 3U, request.method);
  proto_codec::append_uint(output, 4U, request.schema_version);
  // RelativeDeadline { uint32 remaining_milliseconds = 1 }.
  std::vector<std::byte> deadline;
  proto_codec::append_uint(deadline, 1U, request.deadline_remaining_milliseconds);
  proto_codec::append_bytes(output, 5U, deadline);
  if (request.idempotency_key.has_value()) {
    proto_codec::append_bytes(output, 6U, *request.idempotency_key);
  }
  for (const auto& entry : request.metadata) {
    append_metadata_entry(output, entry);
  }
  proto_codec::append_bytes(output, 8U, request.payload);
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RpcRequestBody> parse_rpc_request(std::span<const std::byte> payload,
                                         const Limits& limits) {
  if (payload.size() > limits.max_rpc_payload_bytes + 1024U) {
    return Result<RpcRequestBody>::failure(rpc_error("request_oversized"));
  }
  RpcRequestBody request;
  std::array<std::byte, 16> id_storage{};
  bool have_id = false;
  bool have_service = false;
  bool have_method = false;
  bool have_schema = false;
  bool have_deadline = false;
  proto_codec::ProtoReader reader{payload};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RpcRequestBody>::failure(*field.error_if());
    }
    const auto& value = *field.value_if();
    if (value.number == 1U && value.wire_type == 2U) {
      if (value.bytes.size() != id_storage.size()) {
        return Result<RpcRequestBody>::failure(rpc_error("request_id_field_invalid"));
      }
      std::copy(value.bytes.begin(), value.bytes.end(), id_storage.begin());
      request.request_id = RequestId{id_storage};
      have_id = true;
    } else if (value.number == 2U && value.wire_type == 2U) {
      request.service.assign(reader.text(value));
      have_service = true;
    } else if (value.number == 3U && value.wire_type == 2U) {
      request.method.assign(reader.text(value));
      have_method = true;
    } else if (value.number == 4U && value.wire_type == 0U) {
      request.schema_version = static_cast<std::uint32_t>(value.integer);
      have_schema = true;
    } else if (value.number == 5U && value.wire_type == 2U) {
      proto_codec::ProtoReader deadline{value.bytes};
      while (!deadline.done()) {
        auto deadline_field = deadline.next();
        if (!deadline_field) {
          return Result<RpcRequestBody>::failure(*deadline_field.error_if());
        }
        if (deadline_field.value_if()->number == 1U &&
            deadline_field.value_if()->wire_type == 0U) {
          request.deadline_remaining_milliseconds =
              static_cast<std::uint32_t>(deadline_field.value_if()->integer);
          have_deadline = true;
        }
      }
    } else if (value.number == 6U && value.wire_type == 2U) {
      request.idempotency_key =
          std::vector<std::byte>{value.bytes.begin(), value.bytes.end()};
    } else if (value.number == 7U && value.wire_type == 2U) {
      if (request.metadata.size() >= max_rpc_metadata_entries) {
        return Result<RpcRequestBody>::failure(rpc_error("metadata_count_exceeded"));
      }
      RpcMetadataEntry entry;
      proto_codec::ProtoReader nested{value.bytes};
      bool have_key = false;
      while (!nested.done()) {
        auto nested_field = nested.next();
        if (!nested_field) {
          return Result<RpcRequestBody>::failure(*nested_field.error_if());
        }
        if (nested_field.value_if()->number == 1U &&
            nested_field.value_if()->wire_type == 2U) {
          entry.name.assign(nested.text(*nested_field.value_if()));
          have_key = true;
        } else if (nested_field.value_if()->number == 2U &&
                   nested_field.value_if()->wire_type == 2U) {
          entry.value.assign(nested_field.value_if()->bytes.begin(),
                             nested_field.value_if()->bytes.end());
        }
      }
      if (!have_key) {
        return Result<RpcRequestBody>::failure(rpc_error("metadata_key_missing"));
      }
      request.metadata.push_back(std::move(entry));
    } else if (value.number == 8U && value.wire_type == 2U) {
      request.payload.assign(value.bytes.begin(), value.bytes.end());
    }
    // Unknown fields follow proto3 skipping rules.
  }
  if (!have_id || !have_service || !have_method || !have_schema || !have_deadline) {
    return Result<RpcRequestBody>::failure(rpc_error("request_field_missing"));
  }
  auto valid = validate_request_domain(request, limits);
  if (!valid) {
    return Result<RpcRequestBody>::failure(*valid.error_if());
  }
  return Result<RpcRequestBody>::success(std::move(request));
}

Result<std::vector<std::byte>> encode_rpc_response(const RpcResponseBody& response,
                                                   const Limits& limits) {
  if (response.request_id.is_zero()) {
    return Result<std::vector<std::byte>>::failure(rpc_error("request_id_missing"));
  }
  if (response.status == StableStatus::unspecified) {
    return Result<std::vector<std::byte>>::failure(rpc_error("status_unspecified"));
  }
  if (response.payload.size() > limits.max_rpc_payload_bytes) {
    return Result<std::vector<std::byte>>::failure(rpc_error("payload_oversized"));
  }
  if (!is_safe_detail_token(response.safe_detail)) {
    return Result<std::vector<std::byte>>::failure(rpc_error("safe_detail_invalid"));
  }
  std::vector<std::byte> output;
  output.reserve(response.payload.size() + 64U);
  proto_codec::append_bytes(output, 1U, response.request_id.bytes());
  proto_codec::append_uint(output, 2U, static_cast<std::uint64_t>(response.status));
  proto_codec::append_text(output, 3U, response.safe_detail);
  proto_codec::append_bytes(output, 4U, response.payload);
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RpcResponseBody> parse_rpc_response(std::span<const std::byte> payload,
                                           const Limits& limits) {
  if (payload.size() > limits.max_rpc_payload_bytes + 1024U) {
    return Result<RpcResponseBody>::failure(rpc_error("response_oversized"));
  }
  RpcResponseBody response;
  std::array<std::byte, 16> id_storage{};
  bool have_id = false;
  proto_codec::ProtoReader reader{payload};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RpcResponseBody>::failure(*field.error_if());
    }
    const auto& value = *field.value_if();
    if (value.number == 1U && value.wire_type == 2U) {
      if (value.bytes.size() != id_storage.size()) {
        return Result<RpcResponseBody>::failure(rpc_error("request_id_field_invalid"));
      }
      std::copy(value.bytes.begin(), value.bytes.end(), id_storage.begin());
      response.request_id = RequestId{id_storage};
      have_id = true;
    } else if (value.number == 2U && value.wire_type == 0U) {
      response.status = static_cast<StableStatus>(value.integer);
    } else if (value.number == 3U && value.wire_type == 2U) {
      response.safe_detail.assign(reader.text(value));
    } else if (value.number == 4U && value.wire_type == 2U) {
      response.payload.assign(value.bytes.begin(), value.bytes.end());
    }
  }
  if (!have_id) {
    return Result<RpcResponseBody>::failure(rpc_error("request_id_field_missing"));
  }
  if (response.status == StableStatus::unspecified) {
    return Result<RpcResponseBody>::failure(rpc_error("status_unspecified"));
  }
  if (!is_safe_detail_token(response.safe_detail)) {
    return Result<RpcResponseBody>::failure(rpc_error("safe_detail_invalid"));
  }
  return Result<RpcResponseBody>::success(std::move(response));
}

Result<std::vector<std::byte>> encode_rpc_cancel(const RpcCancelBody& cancel) {
  if (cancel.request_id.is_zero()) {
    return Result<std::vector<std::byte>>::failure(rpc_error("request_id_missing"));
  }
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, cancel.request_id.bytes());
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<RpcCancelBody> parse_rpc_cancel(std::span<const std::byte> payload) {
  RpcCancelBody cancel;
  std::array<std::byte, 16> id_storage{};
  bool have_id = false;
  proto_codec::ProtoReader reader{payload};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<RpcCancelBody>::failure(*field.error_if());
    }
    const auto& value = *field.value_if();
    if (value.number == 1U && value.wire_type == 2U) {
      if (value.bytes.size() != id_storage.size()) {
        return Result<RpcCancelBody>::failure(rpc_error("request_id_field_invalid"));
      }
      std::copy(value.bytes.begin(), value.bytes.end(), id_storage.begin());
      cancel.request_id = RequestId{id_storage};
      have_id = true;
    }
  }
  if (!have_id) {
    return Result<RpcCancelBody>::failure(rpc_error("request_id_field_missing"));
  }
  return Result<RpcCancelBody>::success(cancel);
}

RpcCallContext::RpcCallContext(RequestId request_id, std::vector<std::byte> payload,
                               std::vector<RpcMetadataEntry> metadata,
                               std::uint64_t deadline_unix_milliseconds,
                               const std::shared_ptr<const std::atomic<bool>>& cancelled)
    : request_id_(request_id),
      payload_(std::move(payload)),
      metadata_(std::move(metadata)),
      deadline_unix_milliseconds_(deadline_unix_milliseconds),
      cancelled_(cancelled) {}

Result<void> ServiceRegistry::register_method(RpcMethodDescriptor descriptor,
                                              RpcMethodHandler handler) {
  if (!handler) {
    return Result<void>::failure(rpc_error("handler_missing"));
  }
  if (descriptor.service.empty() ||
      descriptor.service.size() > max_rpc_service_name_bytes ||
      !printable_ascii(descriptor.service)) {
    return Result<void>::failure(rpc_error("service_name_invalid"));
  }
  if (descriptor.method.empty() || descriptor.method.size() > max_rpc_method_name_bytes ||
      !printable_ascii(descriptor.method)) {
    return Result<void>::failure(rpc_error("method_name_invalid"));
  }
  if (descriptor.schema_version == 0U ||
      descriptor.schema_version > max_rpc_schema_version) {
    return Result<void>::failure(rpc_error("schema_version_invalid"));
  }
  if (descriptor.required_scope.empty() || !printable_ascii(descriptor.required_scope)) {
    return Result<void>::failure(rpc_error("required_scope_invalid"));
  }
  const auto key = std::make_pair(descriptor.service, descriptor.method);
  std::scoped_lock lock{mutex_};
  if (methods_.contains(key)) {
    return Result<void>::failure(rpc_error("method_already_registered"));
  }
  methods_.emplace(key, std::make_pair(std::move(descriptor), std::move(handler)));
  return Result<void>::success();
}

Result<void> ServiceRegistry::unregister_method(std::string_view service,
                                                std::string_view method) {
  std::scoped_lock lock{mutex_};
  const auto removed = methods_.erase(
      std::make_pair(std::string{service}, std::string{method}));
  if (removed == 0U) {
    return Result<void>::failure(rpc_error("method_not_registered"));
  }
  return Result<void>::success();
}

std::optional<std::pair<RpcMethodDescriptor, RpcMethodHandler>> ServiceRegistry::lookup(
    std::string_view service, std::string_view method) const {
  std::scoped_lock lock{mutex_};
  const auto found = methods_.find(
      std::make_pair(std::string{service}, std::string{method}));
  if (found == methods_.end()) {
    return std::nullopt;
  }
  return found->second;
}

std::vector<RpcMethodSummary> ServiceRegistry::methods() const {
  std::scoped_lock lock{mutex_};
  std::vector<RpcMethodSummary> summaries;
  summaries.reserve(methods_.size());
  for (const auto& [key, value] : methods_) {
    summaries.push_back(RpcMethodSummary{.service = value.first.service,
                                         .method = value.first.method,
                                         .schema_version = value.first.schema_version,
                                         .required_scope = value.first.required_scope,
                                         .streaming = value.first.streaming});
  }
  return summaries;
}

std::size_t ServiceRegistry::registered_methods() const {
  std::scoped_lock lock{mutex_};
  return methods_.size();
}

}  // namespace heyaki
