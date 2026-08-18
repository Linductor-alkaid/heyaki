#pragma once

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/security.hpp>
#include <heyaki/signaling_protocol.hpp>
#include <heyaki/signing.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace heyaki {

enum class SignalingReplayDecision : std::uint8_t {
  admitted,
  duplicate,
  capacity_rejected,
};

struct SignalingReplayDiagnostics {
  std::uint64_t admitted{};
  std::uint64_t duplicates_rejected{};
  std::uint64_t capacity_rejected{};
  std::uint64_t per_peer_rejected{};
  std::uint64_t expired_evicted{};
  std::size_t current_entries{};
  std::size_t peak_entries{};
  std::size_t peak_per_peer_entries{};
};

// Bounded replay guard for signed signaling objects. The key is the signing domain, the
// signer DeviceId, the request/session IDs, the nonce tuple, and the candidate sequence when
// present, per the wire protocol's replay rules. Accepted keys are retained for the fixed
// replay TTL; when the cache is saturated admission is rejected and counted instead of
// evicting an entry that may still cover a valid replay window.
class SignalingReplayCache {
 public:
  class Impl;

  SignalingReplayCache(SignalingReplayCache&& other) noexcept;
  SignalingReplayCache& operator=(SignalingReplayCache&& other) noexcept;
  ~SignalingReplayCache();

  SignalingReplayCache(const SignalingReplayCache&) = delete;
  SignalingReplayCache& operator=(const SignalingReplayCache&) = delete;

  [[nodiscard]] static Result<SignalingReplayCache> create(ReplayCachePolicy policy);

  // Connect requests are not signed objects, but their sender identity is already bound by
  // the authenticated signaling route. Retain the sender/request tuple across attempt
  // teardown so an old request cannot be admitted again during the replay window.
  [[nodiscard]] Result<SignalingReplayDecision> admit_connect_request(
      const DeviceId& sender, const RequestId& request_id,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

  [[nodiscard]] Result<SignalingReplayDecision> admit(
      SigningDomain domain, const DeviceId& signer, const RequestId& request_id,
      const SessionId& session_id, const SignalingNonce& initiator_nonce,
      const std::optional<SignalingNonce>& responder_nonce,
      const std::optional<std::uint32_t>& sequence,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

  void expire(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

  [[nodiscard]] SignalingReplayDiagnostics diagnostics() const noexcept;

 private:
  explicit SignalingReplayCache(std::unique_ptr<Impl> impl) noexcept;
  std::unique_ptr<Impl> impl_;
};

}  // namespace heyaki
