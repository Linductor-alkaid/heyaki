#pragma once

#include "connection_attempt.hpp"
#include "signaling_coordinator.hpp"
#include "../transport/transport_session.hpp"

#include <heyaki/identity.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/session_protocol.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

namespace heyaki {

enum class PeerSessionState : std::uint8_t {
  idle,
  authenticating,
  pairing_restricted,
  authenticated,
  closed,
};

struct PeerSessionDiagnostics;

struct PeerSessionConfig {
  std::shared_ptr<transport::TransportSession> transport;
  SignedSessionHello local_hello;
  SessionHelloExpectation expectation;
  IdentityPublicKey peer_public_key{};
  ProtocolHello local_protocol;
  std::uint64_t now_unix_milliseconds{};
  bool initiator{false};
  std::function<void(const PeerSessionDiagnostics&)> observer;
  std::shared_ptr<ConnectionAttemptTimeline> timeline;
  std::function<std::chrono::steady_clock::time_point()> clock;
};

struct VerifiedPeerSessionConfig {
  std::shared_ptr<transport::TransportSession> transport;
  VerifiedSessionBinding binding;
  const IdentityKeyPair* local_identity{nullptr};
  IdentityPublicKey peer_public_key{};
  ProtocolHello local_protocol;
  std::uint64_t expires_unix_milliseconds{};
  std::uint64_t now_unix_milliseconds{};
  std::function<void(const PeerSessionDiagnostics&)> observer;
  std::shared_ptr<ConnectionAttemptTimeline> timeline;
  std::function<std::chrono::steady_clock::time_point()> clock;
};

struct PeerSessionDiagnostics {
  PeerSessionState state{PeerSessionState::idle};
  std::uint64_t hellos_sent{};
  std::uint64_t hellos_received{};
  std::uint64_t pings_received{};
  std::uint64_t pings_sent{};
  std::uint64_t pongs_sent{};
  std::uint64_t pongs_received{};
  std::uint64_t business_frames_rejected{};
  std::optional<Error> last_error;
};

class PeerSession final : public std::enable_shared_from_this<PeerSession> {
 public:
  [[nodiscard]] static Result<std::shared_ptr<PeerSession>> create(
      PeerSessionConfig config);
  [[nodiscard]] static Result<std::shared_ptr<PeerSession>> create_verified(
      VerifiedPeerSessionConfig config);
  ~PeerSession();

  PeerSession(const PeerSession&) = delete;
  PeerSession& operator=(const PeerSession&) = delete;

  [[nodiscard]] Result<void> start();
  [[nodiscard]] Result<void> send_ping(std::uint64_t ping_id);
  [[nodiscard]] PeerSessionDiagnostics diagnostics() const noexcept;
  [[nodiscard]] bool authenticated() const noexcept;
  void close(transport::CloseReason reason);

 private:
  explicit PeerSession(PeerSessionConfig config);
  void handle_message(transport::TransportChannel& channel,
                      std::vector<std::byte> payload);
  [[nodiscard]] Result<void> send_hello(transport::TransportChannel& channel);
  void fail(Error error);
  void notify() const;
  [[nodiscard]] Result<void> record(ConnectionStage stage, std::string_view source,
                                    std::string_view reason);

  PeerSessionConfig config_;
  std::unique_ptr<SessionHelloAdmission> admission_;
  transport::TransportChannel* control_{nullptr};
  PeerSessionDiagnostics diagnostics_;
  std::optional<std::uint64_t> pending_ping_;
  bool started_{false};
};

}  // namespace heyaki
