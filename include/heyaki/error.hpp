#pragma once

#include <heyaki/ids.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace heyaki {

inline constexpr std::size_t max_safe_detail_bytes = 64U;
[[nodiscard]] bool is_safe_detail_token(std::string_view value) noexcept;

enum class ErrorCode : std::uint16_t {
  configuration = 1,
  identity = 2,
  authentication = 3,
  permission = 4,
  not_registered = 5,
  enrollment_revoked = 6,
  profile_locked = 7,
  pairing_required = 8,
  pairing_denied = 9,
  pairing_rate_limited = 10,
  peer_offline = 11,
  endpoint_offline = 12,
  signaling = 13,
  nat_traversal = 14,
  relay_unavailable = 15,
  transport = 16,
  protocol = 17,
  timeout = 18,
  cancelled = 19,
  would_block = 20,
  resource_exhausted = 21,
  remote_error = 22,
  outcome_unknown = 23,
  internal = 24,
  secret_unavailable = 25,
  secret_backend_degraded = 26,
  profile_permissions = 27,
  profile_corrupt = 28,
  schema_too_new = 29,
  storage = 30,
};

class Error {
 public:
  Error() = default;
  Error(ErrorCode code, std::string component, std::string safe_detail,
        std::optional<std::int64_t> underlying_code = std::nullopt,
        std::optional<DeviceId> peer_id = std::nullopt,
        std::optional<OperationId> operation_id = std::nullopt);

  [[nodiscard]] ErrorCode code() const noexcept { return code_; }
  [[nodiscard]] const std::optional<std::int64_t>& underlying_code() const noexcept {
    return underlying_code_;
  }
  [[nodiscard]] const std::optional<DeviceId>& peer_id() const noexcept { return peer_id_; }
  [[nodiscard]] const std::optional<OperationId>& operation_id() const noexcept {
    return operation_id_;
  }
  [[nodiscard]] std::string_view component() const noexcept { return component_; }
  [[nodiscard]] std::string_view safe_detail() const noexcept { return safe_detail_; }

 private:
  ErrorCode code_{ErrorCode::internal};
  std::optional<std::int64_t> underlying_code_;
  std::optional<DeviceId> peer_id_;
  std::optional<OperationId> operation_id_;
  std::string component_{"core"};
  std::string safe_detail_{"internal_error"};
};

[[nodiscard]] std::string_view error_code_name(ErrorCode code) noexcept;

template <typename T>
class Result {
 public:
  [[nodiscard]] static Result success(T value) { return Result{std::move(value)}; }
  [[nodiscard]] static Result failure(Error error) { return Result{std::move(error)}; }

  [[nodiscard]] bool has_value() const noexcept { return std::holds_alternative<T>(storage_); }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

  [[nodiscard]] T* value_if() noexcept { return std::get_if<T>(&storage_); }
  [[nodiscard]] const T* value_if() const noexcept { return std::get_if<T>(&storage_); }
  [[nodiscard]] Error* error_if() noexcept { return std::get_if<Error>(&storage_); }
  [[nodiscard]] const Error* error_if() const noexcept { return std::get_if<Error>(&storage_); }

 private:
  explicit Result(T value) : storage_(std::move(value)) {}
  explicit Result(Error error) : storage_(std::move(error)) {}

  std::variant<T, Error> storage_;
};

template <>
class Result<void> {
 public:
  [[nodiscard]] static Result success() { return Result{}; }
  [[nodiscard]] static Result failure(Error error) { return Result{std::move(error)}; }

  [[nodiscard]] bool has_value() const noexcept { return !error_.has_value(); }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }
  [[nodiscard]] Error* error_if() noexcept { return error_ ? &*error_ : nullptr; }
  [[nodiscard]] const Error* error_if() const noexcept { return error_ ? &*error_ : nullptr; }

 private:
  Result() = default;
  explicit Result(Error error) : error_(std::move(error)) {}

  std::optional<Error> error_;
};

}  // namespace heyaki
