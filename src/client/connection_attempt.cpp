#include "connection_attempt.hpp"

namespace heyaki {
namespace {

Error timeline_error(ErrorCode code, const char* detail) {
  return {code, "connection_timeline", detail};
}

bool legal_transition(ConnectionStage from, ConnectionStage to) noexcept {
  if (to == ConnectionStage::closed && from != ConnectionStage::closed) return true;
  switch (from) {
    case ConnectionStage::idle:
      return to == ConnectionStage::resolving_endpoint;
    case ConnectionStage::resolving_endpoint:
      return to == ConnectionStage::signaling;
    case ConnectionStage::signaling:
      return to == ConnectionStage::gathering || to == ConnectionStage::checking ||
             to == ConnectionStage::transport_connected;
    case ConnectionStage::gathering:
      return to == ConnectionStage::checking ||
             to == ConnectionStage::transport_connected;
    case ConnectionStage::checking:
      return to == ConnectionStage::transport_connected;
    case ConnectionStage::transport_connected:
      return to == ConnectionStage::authenticating;
    case ConnectionStage::authenticating:
      return to == ConnectionStage::authenticated;
    case ConnectionStage::authenticated:
    case ConnectionStage::closed:
      return false;
  }
  return false;
}

}  // namespace

ConnectionAttemptTimeline::ConnectionAttemptTimeline(std::size_t capacity)
    : capacity_(capacity) {
  transitions_.reserve(capacity_);
}

Result<void> ConnectionAttemptTimeline::transition(
    ConnectionStage next, std::string_view source, std::string_view reason,
    std::chrono::steady_clock::time_point timestamp) {
  if (capacity_ == 0U || source.empty() || source.size() > 64U || reason.empty() ||
      reason.size() > 128U) {
    return Result<void>::failure(
        timeline_error(ErrorCode::configuration, "transition_metadata_invalid"));
  }
  if (!legal_transition(stage_, next)) {
    return Result<void>::failure(
        timeline_error(ErrorCode::protocol, "connection_transition_invalid"));
  }
  if (transitions_.size() >= capacity_) {
    return Result<void>::failure(
        timeline_error(ErrorCode::resource_exhausted, "transition_history_full"));
  }
  transitions_.push_back({stage_, next, timestamp, std::string{source}, std::string{reason}});
  stage_ = next;
  return Result<void>::success();
}

std::string_view connection_stage_name(ConnectionStage stage) noexcept {
  switch (stage) {
    case ConnectionStage::idle:
      return "idle";
    case ConnectionStage::resolving_endpoint:
      return "resolving_endpoint";
    case ConnectionStage::signaling:
      return "signaling";
    case ConnectionStage::gathering:
      return "gathering";
    case ConnectionStage::checking:
      return "checking";
    case ConnectionStage::transport_connected:
      return "transport_connected";
    case ConnectionStage::authenticating:
      return "authenticating";
    case ConnectionStage::authenticated:
      return "authenticated";
    case ConnectionStage::closed:
      return "closed";
  }
  return "unknown";
}

}  // namespace heyaki
