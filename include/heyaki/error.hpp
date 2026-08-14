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
  identity,
  authentication,
  permission,
  not_registered,
  enrollment_revoked,
  profile_locked,
  pairing_required,
  pairing_denied,
  pairing_rate_limited,
  peer_offline,
  endpoint_offline,
  signaling,
  nat_traversal,
  relay_unavailable,
  transport,
  protocol,
  timeout,
  cancelled,
  would_block,
  resource_exhausted,
  remote_error,
  outcome_unknown,
  internal,
};

struct Error {
  Error() = default;
  Error(ErrorCode code_value, std::string component_value, std::string safe_detail_value)
      : code(code_value),
        component(std::move(component_value)),
        safe_detail(is_safe_detail_token(safe_detail_value) ? std::move(safe_detail_value)
                                                             : "invalid_safe_detail") {}

  ErrorCode code{ErrorCode::internal};
  std::optional<std::int64_t> underlying_code;
  std::optional<DeviceId> peer_id;
  std::optional<OperationId> operation_id;
  std::string component;
  std::string safe_detail{"internal_error"};
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
