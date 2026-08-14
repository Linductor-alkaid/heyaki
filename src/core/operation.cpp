#include <heyaki/operation.hpp>

#include <optional>
#include <string_view>
#include <utility>

namespace heyaki {
namespace {

Result<OperationStatus> invalid_transition(OperationStatus current,
                                           std::string_view detail) {
  return Result<OperationStatus>::failure(
      Error{ErrorCode::protocol, "operation", std::string{detail}, std::nullopt, std::nullopt,
            current.id});
}

}  // namespace

Result<OperationStatus> transition_operation(OperationStatus current, OperationState next,
                                             std::optional<Error> error) {
  if (current.epoch.value() == 0U) {
    return invalid_transition(std::move(current), "zero_session_epoch");
  }
  if (current.state != OperationState::pending) {
    if (current.state == next && !error.has_value()) {
      return Result<OperationStatus>::success(std::move(current));
    }
    return invalid_transition(std::move(current), "terminal_state_transition");
  }
  if (next == OperationState::pending) {
    return invalid_transition(std::move(current), "pending_to_pending");
  }
  if (next == OperationState::success && error.has_value()) {
    return invalid_transition(std::move(current), "success_with_error");
  }
  if (next == OperationState::error && !error.has_value()) {
    return invalid_transition(std::move(current), "error_without_detail");
  }
  if (next == OperationState::cancelled && !error.has_value()) {
    error = Error{ErrorCode::cancelled, "operation", "cancelled", std::nullopt, std::nullopt,
                  current.id};
  }
  if (next == OperationState::outcome_unknown && !error.has_value()) {
    error = Error{ErrorCode::outcome_unknown, "operation", "connection_lost", std::nullopt,
                  std::nullopt, current.id};
  }

  current.state = next;
  current.error = std::move(error);
  return Result<OperationStatus>::success(std::move(current));
}

std::string_view operation_state_name(OperationState state) noexcept {
  switch (state) {
    case OperationState::pending:
      return "pending";
    case OperationState::success:
      return "success";
    case OperationState::error:
      return "error";
    case OperationState::cancelled:
      return "cancelled";
    case OperationState::outcome_unknown:
      return "outcome_unknown";
  }
  return "error";
}

}  // namespace heyaki
