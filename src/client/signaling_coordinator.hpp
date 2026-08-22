// Unified connect/accept/deny/trickle signaling state machine shared by every signaling
// route (LAN TLS today, relay control later). The coordinator enforces the pending-attempt
// bounds, the signed-object verification chain, and the replay guard; SDP and candidates
// only become visible to the session layer through verified delegate callbacks.
#pragma once

#include <heyaki/identity.hpp>
#include <heyaki/lan_directory.hpp>
#include <heyaki/lan_protocol.hpp>
#include <heyaki/node.hpp>
#include <heyaki/signaling_protocol.hpp>
#include <heyaki/signaling_replay_cache.hpp>
#include <heyaki/session_protocol.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace heyaki {

// Route-agnostic signaling envelope. Control kinds carry an empty payload; signed kinds
// carry exactly one encoded signed object.
struct SignalingEnvelope {
  DeviceEndpointKey peer;
  LanSignalingMessageKind kind{LanSignalingMessageKind::connect_request};
  RequestId request_id;
  std::vector<std::byte> payload;
};

class SignalingRoute {
 public:
  virtual ~SignalingRoute() = default;
  [[nodiscard]] virtual SignalingRouteKind kind() const noexcept = 0;
  [[nodiscard]] virtual Result<void> send(const SignalingEnvelope& message) = 0;
};

enum class SignalingAttemptPhase : std::uint8_t {
  requesting,  // outbound: connect_request sent, waiting connect_accept
  accepted,    // outbound: connect_accept received, waiting local offer
  responding,  // inbound: connect_accept sent, waiting signed offer
  offered,     // initiator: signed offer sent; responder: verified offer received
  answered,    // initiator: verified answer received; responder: signed answer sent
  candidates,  // trickle candidates flowing
  closed,
};

[[nodiscard]] std::string_view signaling_attempt_phase_name(
    SignalingAttemptPhase phase) noexcept;

struct SignalingAttemptSnapshot {
  RequestId request_id;
  SessionId session_id;
  DeviceEndpointKey peer;
  bool inbound{false};
  SignalingRouteKind route{SignalingRouteKind::lan};
  SignalingAttemptPhase phase{SignalingAttemptPhase::requesting};
  std::chrono::steady_clock::time_point created_at{};
  std::chrono::milliseconds ttl{};
  std::uint32_t sent_candidates{};
  std::uint32_t received_candidates{};
};

struct VerifiedSessionBinding {
  SessionHelloExpectation expectation;
  DtlsFingerprint peer_fingerprint{};
  std::string peer_ufrag;
  bool initiator{false};
};

struct SignalingCoordinatorConfig {
  DeviceEndpointKey local;
  // Signing identity; must derive local.device_id. Not owned.
  const IdentityKeyPair* identity{nullptr};
  std::size_t max_pending_attempts{64U};
  std::size_t max_inbound_attempts{64U};
  std::chrono::milliseconds attempt_ttl{15000};
  std::size_t max_signaling_payload_bytes{max_signaling_object_bytes};
  std::size_t max_candidates_per_attempt{128U};
  std::chrono::milliseconds inbound_rate_window{1000};
  std::size_t inbound_rate_limit{32U};
  std::size_t rate_key_capacity{256U};
  std::uint64_t signaling_validity_milliseconds{30000};
  ReplayCachePolicy replay_policy{};
};

struct SignalingCoordinatorDiagnostics {
  std::uint64_t messages_received{};
  std::uint64_t messages_dispatched{};
  std::uint64_t rate_rejected{};
  std::uint64_t payload_rejected{};
  std::uint64_t attempts_begun{};
  std::uint64_t inbound_accepted{};
  std::uint64_t inbound_denied{};
  std::uint64_t outbound_capacity_rejected{};
  std::uint64_t inbound_capacity_rejected{};
  std::uint64_t duplicate_request_rejected{};
  std::uint64_t parse_rejected{};
  std::uint64_t signature_rejected{};
  std::uint64_t binding_rejected{};
  std::uint64_t replay_rejected{};
  std::uint64_t candidate_rejected{};
  std::uint64_t attempts_expired{};
  std::uint64_t attempts_closed{};
  std::uint64_t route_missing{};
  std::size_t current_attempts{};
  std::size_t peak_attempts{};
  std::size_t replay_current_entries{};
  std::size_t replay_peak_entries{};
};

// Delegate callbacks run synchronously on the coordinator's driving context. Every signed
// object delivered through them has already passed the full verification chain; unverified
// SDP or candidates never reach the delegate.
struct SignalingDelegate {
  std::function<std::optional<IdentityPublicKey>(const DeviceEndpointKey&)> peer_identity;
  // Returning false denies the inbound connect; a missing callback denies by default.
  std::function<bool(const SignalingAttemptSnapshot&)> on_inbound_connect;
  std::function<void(const SignalingAttemptSnapshot&)> on_outbound_accepted;
  std::function<void(const SignalingAttemptSnapshot&, const SignedOffer&)> on_verified_offer;
  std::function<void(const SignalingAttemptSnapshot&, const SignedAnswer&,
                     const SignalingTranscriptSha256&)>
      on_verified_answer;
  std::function<void(const SignalingAttemptSnapshot&, const SignedCandidate&)>
      on_verified_candidate;
  std::function<void(const SignalingAttemptSnapshot&, const Error&)> on_attempt_error;
};

class SignalingCoordinator {
 public:
  class Impl;

  SignalingCoordinator(SignalingCoordinator&& other) noexcept;
  SignalingCoordinator& operator=(SignalingCoordinator&& other) noexcept;
  ~SignalingCoordinator();

  SignalingCoordinator(const SignalingCoordinator&) = delete;
  SignalingCoordinator& operator=(const SignalingCoordinator&) = delete;

  // The delegate is shared so its callbacks can be wired after creation; the coordinator
  // always reads the current callbacks.
  [[nodiscard]] static Result<SignalingCoordinator> create(
      SignalingCoordinatorConfig config, std::shared_ptr<SignalingDelegate> delegate);

  // Routes are not owned; at most one route per kind may be attached.
  void attach_route(SignalingRoute* route);

  // Starts an outbound attempt: sends connect_request and returns the request ID.
  [[nodiscard]] Result<RequestId> begin_attempt(
      DeviceEndpointKey peer, SignalingRouteKind route,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

  // Local side supplies SDP produced by its transport once the attempt is ready.
  [[nodiscard]] Result<void> send_local_offer(
      RequestId request_id, std::span<const std::byte> sdp,
      const DtlsFingerprint& fingerprint,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now(),
      std::uint64_t now_unix_milliseconds = static_cast<std::uint64_t>(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch())
              .count()));
  [[nodiscard]] Result<void> send_local_answer(
      RequestId request_id, std::span<const std::byte> sdp,
      const DtlsFingerprint& fingerprint,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now(),
      std::uint64_t now_unix_milliseconds = static_cast<std::uint64_t>(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch())
              .count()));
  [[nodiscard]] Result<void> send_local_candidate(
      RequestId request_id, std::span<const std::byte> candidate,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now(),
      std::uint64_t now_unix_milliseconds = static_cast<std::uint64_t>(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch())
              .count()));

  // Dispatches one inbound envelope through rate limits and the verification chain.
  [[nodiscard]] Result<void> handle_message(
      const SignalingEnvelope& message, SignalingRouteKind source,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now(),
      std::uint64_t now_unix_milliseconds = static_cast<std::uint64_t>(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch())
              .count()));

  [[nodiscard]] Result<void> cancel_attempt(
      RequestId request_id, std::chrono::steady_clock::time_point now);

  // Expires attempts whose age exceeded the configured TTL.
  void expire(std::chrono::steady_clock::time_point now);

  [[nodiscard]] std::vector<SignalingAttemptSnapshot> attempts() const;
  [[nodiscard]] Result<VerifiedSessionBinding> verified_session_binding(
      RequestId request_id, std::uint64_t session_epoch = 1U) const;
  [[nodiscard]] SignalingCoordinatorDiagnostics diagnostics() const noexcept;

 private:
  explicit SignalingCoordinator(std::unique_ptr<Impl> impl) noexcept;
  std::unique_ptr<Impl> impl_;
};

}  // namespace heyaki
