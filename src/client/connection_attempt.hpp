#pragma once

#include <heyaki/error.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

enum class ConnectionStage : std::uint8_t {
  idle,
  resolving_endpoint,
  signaling,
  gathering,
  checking,
  transport_connected,
  authenticating,
  authenticated,
  closed,
};

[[nodiscard]] std::string_view connection_stage_name(ConnectionStage stage) noexcept;

struct ConnectionTransition {
  ConnectionStage from{ConnectionStage::idle};
  ConnectionStage to{ConnectionStage::idle};
  std::chrono::steady_clock::time_point timestamp{};
  std::string source;
  std::string reason;
};

class ConnectionAttemptTimeline {
 public:
  explicit ConnectionAttemptTimeline(std::size_t capacity = 32U);

  [[nodiscard]] Result<void> transition(
      ConnectionStage next, std::string_view source, std::string_view reason,
      std::chrono::steady_clock::time_point timestamp = std::chrono::steady_clock::now());
  [[nodiscard]] ConnectionStage stage() const noexcept { return stage_; }
  [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
  [[nodiscard]] const std::vector<ConnectionTransition>& transitions() const noexcept {
    return transitions_;
  }

 private:
  std::size_t capacity_;
  ConnectionStage stage_{ConnectionStage::idle};
  std::vector<ConnectionTransition> transitions_;
};

}  // namespace heyaki
