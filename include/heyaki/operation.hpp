#pragma once

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>

#include <cstdint>
#include <optional>
#include <string_view>

namespace heyaki {

enum class OperationState : std::uint8_t {
  pending,
  success,
  error,
  cancelled,
  outcome_unknown,
};

class SessionEpoch {
 public:
  explicit constexpr SessionEpoch(std::uint64_t value = 1U) noexcept : value_(value) {}

  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }
  [[nodiscard]] constexpr std::optional<SessionEpoch> next() const noexcept {
    if (value_ == UINT64_MAX) {
      return std::nullopt;
    }
    return SessionEpoch{value_ + 1U};
  }

  friend constexpr bool operator==(SessionEpoch, SessionEpoch) noexcept = default;
  friend constexpr auto operator<=>(SessionEpoch, SessionEpoch) noexcept = default;

 private:
  std::uint64_t value_;
};

struct OperationStatus {
  OperationId id;
  SessionEpoch epoch{1U};
  OperationState state{OperationState::pending};
  std::optional<Error> error;
};

[[nodiscard]] Result<OperationStatus> transition_operation(OperationStatus current,
                                                           OperationState next,
                                                           std::optional<Error> error =
                                                               std::nullopt);
[[nodiscard]] std::string_view operation_state_name(OperationState state) noexcept;

}  // namespace heyaki
