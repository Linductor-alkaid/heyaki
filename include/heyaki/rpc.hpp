#pragma once

// Unary RPC protocol (M6-07..M6-13). RpcRequest/RpcResponse/RpcCancel follow
// the frozen heyaki.protocol.rpc.v1 schemas and ride the non-zero logical rpc
// channel of an authorized session. Deadlines are relative on the wire (no
// clock synchronization assumed), cancellation is cooperative, exactly one
// terminal response exists per request, and v1 delivers unary calls only —
// streaming methods stay unimplemented by design (M6-13).

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/limits.hpp>
#include <heyaki/pairing_protocol.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace heyaki {

inline constexpr std::size_t max_rpc_service_name_bytes = 128U;
inline constexpr std::size_t max_rpc_method_name_bytes = 128U;
inline constexpr std::uint32_t max_rpc_schema_version = 65535U;
inline constexpr std::uint32_t min_rpc_deadline_milliseconds = 1U;
inline constexpr std::uint32_t max_rpc_deadline_milliseconds = 600'000U;
inline constexpr std::uint32_t default_rpc_deadline_milliseconds = 10'000U;
inline constexpr std::size_t max_rpc_metadata_entries = 64U;
inline constexpr std::size_t max_rpc_metadata_name_bytes = 64U;
inline constexpr std::size_t max_rpc_metadata_value_bytes = 256U;
inline constexpr std::size_t max_rpc_idempotency_key_bytes = 64U;

struct RpcMetadataEntry {
  std::string name;
  std::vector<std::byte> value;
};

// Wire request body. `deadline_remaining_milliseconds` is computed at send
// time; the receiver turns it into a local absolute deadline on receipt
// (M6-08). An idempotency key marks the request explicitly idempotent and is
// the hook any policy-based retry relies on (M6-12).
struct RpcRequestBody {
  RequestId request_id;
  std::string service;
  std::string method;
  std::uint32_t schema_version{1U};
  std::uint32_t deadline_remaining_milliseconds{default_rpc_deadline_milliseconds};
  std::optional<std::vector<std::byte>> idempotency_key;
  std::vector<RpcMetadataEntry> metadata;
  std::vector<std::byte> payload;
};

struct RpcResponseBody {
  RequestId request_id;
  StableStatus status{StableStatus::unspecified};
  std::string safe_detail;
  std::vector<std::byte> payload;
};

struct RpcCancelBody {
  RequestId request_id;
};

[[nodiscard]] Result<std::vector<std::byte>> encode_rpc_request(
    const RpcRequestBody& request, const Limits& limits = {});
[[nodiscard]] Result<RpcRequestBody> parse_rpc_request(std::span<const std::byte> payload,
                                                       const Limits& limits = {});
[[nodiscard]] Result<std::vector<std::byte>> encode_rpc_response(
    const RpcResponseBody& response, const Limits& limits = {});
[[nodiscard]] Result<RpcResponseBody> parse_rpc_response(std::span<const std::byte> payload,
                                                         const Limits& limits = {});
[[nodiscard]] Result<std::vector<std::byte>> encode_rpc_cancel(const RpcCancelBody& cancel);
[[nodiscard]] Result<RpcCancelBody> parse_rpc_cancel(std::span<const std::byte> payload);

// ---- Service registry (M6-07) ----

// Server-side method registration. `required_scope` is checked against the
// caller session's effective scopes before any handler runs; `streaming`
// methods are registered to declare intent but always answer `unimplemented`
// in v1 (M6-13).
struct RpcMethodDescriptor {
  std::string service;
  std::string method;
  std::uint32_t schema_version{1U};
  std::string required_scope;
  bool streaming{false};
};

// What one executing handler observes. `cancelled()` is the cooperative
// stop signal: a handler must poll it and return early; the runtime never
// kills running C++ code (M6-10). `deadline_unix_milliseconds()` is the
// receiver-local absolute deadline derived from the wire's relative value.
class RpcCallContext {
 public:
  RpcCallContext(RequestId request_id, std::vector<std::byte> payload,
                 std::vector<RpcMetadataEntry> metadata,
                 std::uint64_t deadline_unix_milliseconds,
                 const std::shared_ptr<const std::atomic<bool>>& cancelled);

  [[nodiscard]] RequestId request_id() const noexcept { return request_id_; }
  [[nodiscard]] std::span<const std::byte> payload() const noexcept {
    return payload_;
  }
  [[nodiscard]] const std::vector<RpcMetadataEntry>& metadata() const noexcept {
    return metadata_;
  }
  [[nodiscard]] std::uint64_t deadline_unix_milliseconds() const noexcept {
    return deadline_unix_milliseconds_;
  }
  [[nodiscard]] bool cancelled() const noexcept {
    return cancelled_ != nullptr && cancelled_->load(std::memory_order_acquire);
  }

 private:
  RequestId request_id_;
  std::vector<std::byte> payload_;
  std::vector<RpcMetadataEntry> metadata_;
  std::uint64_t deadline_unix_milliseconds_;
  std::shared_ptr<const std::atomic<bool>> cancelled_;
};

// Handler result. `status` is the stable wire status; `safe_detail` must be a
// short safe token (bounded/sanitized to max_safe_detail_bytes) because it
// crosses to the peer; `payload` is opaque application bytes.
struct RpcHandlerResult {
  StableStatus status{StableStatus::ok};
  std::vector<std::byte> payload;
  std::string safe_detail;
};

using RpcMethodHandler =
    std::function<RpcHandlerResult(const RpcCallContext& context)>;

struct RpcMethodSummary {
  std::string service;
  std::string method;
  std::uint32_t schema_version{};
  std::string required_scope;
  bool streaming{false};
};

// Process-wide method table shared by every session (M6-07). Register/unregister
// may be called from any thread; lookups are safe concurrently.
class ServiceRegistry {
 public:
  ServiceRegistry() = default;

  ServiceRegistry(const ServiceRegistry&) = delete;
  ServiceRegistry& operator=(const ServiceRegistry&) = delete;

  [[nodiscard]] Result<void> register_method(RpcMethodDescriptor descriptor,
                                             RpcMethodHandler handler);
  [[nodiscard]] Result<void> unregister_method(std::string_view service,
                                               std::string_view method);
  // Returns (handler, descriptor) for an exact service+method match, or
  // nullptr when unknown.
  [[nodiscard]] std::optional<std::pair<RpcMethodDescriptor, RpcMethodHandler>>
  lookup(std::string_view service, std::string_view method) const;
  [[nodiscard]] std::vector<RpcMethodSummary> methods() const;
  [[nodiscard]] std::size_t registered_methods() const;

 private:
  mutable std::mutex mutex_;
  std::map<std::pair<std::string, std::string>,
           std::pair<RpcMethodDescriptor, RpcMethodHandler>>
      methods_;
};

// Options for one client call. `deadline_remaining_milliseconds` is relative
// (M6-08: no clock synchronization assumed). Only explicitly idempotent
// calls may opt into policy-driven retry on a future session; the library
// itself NEVER retries automatically (M6-12).
struct RpcCallOptions {
  std::uint32_t deadline_remaining_milliseconds{default_rpc_deadline_milliseconds};
  bool idempotent{false};
  std::optional<std::vector<std::byte>> idempotency_key;
  bool retry_on_reconnect{false};
  std::vector<RpcMetadataEntry> metadata;
};

// Terminal outcome of one call. Peer statuses (including structured
// failures like permission_denied and outcome_unknown) arrive as successful
// Results carrying `status`; a failed Result means the call never started
// (local admission rejection with a deterministic outcome).
struct RpcCallOutcome {
  StableStatus status{StableStatus::unspecified};
  std::string safe_detail;
  std::vector<std::byte> payload;
};

// Counters for one RPC service (M6-07..M6-12): every rejection before the
// handler, every late/dropped result, and every dispatch failure is
// observable.
struct RpcServiceStats {
  // Client side.
  std::uint64_t calls_started{};
  std::uint64_t calls_admission_rejected{};
  std::uint64_t responses_matched{};
  std::uint64_t responses_unknown{};
  std::uint64_t cancels_sent{};
  std::uint64_t local_deadline_exceeded{};
  std::uint64_t outcome_unknown_calls{};
  std::uint64_t retryable_handled{};
  // Server side.
  std::uint64_t requests_received{};
  std::uint64_t invalid_requests{};
  std::uint64_t duplicate_requests{};
  std::uint64_t conflicting_requests{};
  std::uint64_t replayed_responses{};
  std::uint64_t scope_rejected{};
  std::uint64_t unimplemented_answers{};
  std::uint64_t schema_rejected{};
  std::uint64_t oversized_rejected{};
  std::uint64_t concurrency_rejected{};
  std::uint64_t deadline_rejected{};
  std::uint64_t dispatch_rejected{};
  std::uint64_t handlers_executed{};
  std::uint64_t handler_exceptions{};
  std::uint64_t handler_cancelled{};
  std::uint64_t handler_deadline_exceeded{};
  std::uint64_t late_results_dropped{};
  std::uint64_t responses_sent{};
  std::uint64_t response_send_failures{};
};

}  // namespace heyaki
