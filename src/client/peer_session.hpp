#pragma once

#include "connection_attempt.hpp"
#include "signaling_coordinator.hpp"
#include "session_channels.hpp"
#include "../transport/transport_session.hpp"

#include <heyaki/identity.hpp>
#include <heyaki/limits.hpp>
#include <heyaki/pairing_protocol.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/session_protocol.hpp>
#include <heyaki/trust_grant.hpp>
#include <heyaki/wire.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace heyaki {

enum class PeerSessionState : std::uint8_t {
  idle,
  authenticating,
  // Peer identity verified but untrusted: only the pairing protocol runs on
  // the control channel with strict size/duration/attempt caps; business
  // channels cannot exist (RULE-03).
  pairing_restricted,
  // Trust adjudication passed for this session; business channels may open.
  authenticated,
  // Authorized and at least one business channel has carried a frame.
  active,
  closed,
};

struct PeerSessionDiagnostics;

// Result of the per-session trust adjudication (M5-12): the local TrustStore
// plus endpoint/service policy decide whether an identity-verified peer is
// authorized and with which effective scopes.
struct SessionAuthorization {
  bool trusted{false};
  std::vector<std::string> scopes;
  // Whether this side accepts password pairing attempts at all.
  bool pairing_allowed{false};
};

using SessionTrustAuthorizer =
    std::function<Result<SessionAuthorization>(std::uint64_t now_unix_milliseconds)>;
// Target-side pairing evaluation (M5-09/M5-10): verifies the password against
// the local Argon2id verifier, applies failure limits/backoff and pairing
// policy, and issues (or denies) a signed TrustGrant.
using PairingEvaluator =
    std::function<Result<PairingResultBody>(const PairingRequestBody&)>;
// Initiator-side result sink (M5-09/M5-12): verifies the returned grant
// (signature, identities, scopes, nonce, expiry) and persists it; an error
// return rejects the grant and closes the restricted session. Receives the
// pending request binding so the verifier can check the nonce echo and scope
// subset without duplicating PeerSession state.
using PairingResultSink = std::function<Result<void>(
    const PairingResultBody&, const RequestId& pending_request_id,
    const PairingNonce& pending_nonce,
    const std::vector<std::string>& requested_scopes)>;
// Inbound business-frame dispatcher per logical channel.
using BusinessFrameHandler = std::function<void(const FrameView&)>;
// Domain-level dispatcher: receives inbound business frames of one domain on
// channel ids this side never opened (the peer opened them). The handler
// owns admitting the logical channel; returning an error closes only the
// physical channel the frame arrived on.
using DomainFrameHandler = std::function<Result<void>(const FrameView&)>;

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
  // ---- M5 authorization extensions (appended: positional M4 callers keep
  // working and get legacy trust semantics) ----
  // When set, a verified hello leads to pairing_restricted unless the
  // authorizer trusts the peer. When absent the session keeps the M4 test
  // semantics: hello-verified equals authorized with unrestricted scopes.
  SessionTrustAuthorizer trust_authorizer;
  // Required to answer PAIRING_REQUEST on a restricted session.
  PairingEvaluator pairing_evaluator;
  // Required to accept PAIRING_RESULT grants as the pairing initiator.
  PairingResultSink pairing_result_sink;
  Limits limits{};
  session::ChannelBudgetConfig channel_budgets{};
  // Lifetime cap of a pairing-restricted session (M5-07).
  std::chrono::milliseconds pairing_deadline{60000};
  std::function<std::uint64_t()> wall_clock;
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
  // ---- M5 extensions, same meaning as in PeerSessionConfig ----
  SessionTrustAuthorizer trust_authorizer;
  PairingEvaluator pairing_evaluator;
  PairingResultSink pairing_result_sink;
  Limits limits{};
  session::ChannelBudgetConfig channel_budgets{};
  std::chrono::milliseconds pairing_deadline{60000};
  std::function<std::uint64_t()> wall_clock;
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
  std::uint64_t restart_frames_sent{};
  std::uint64_t restart_frames_received{};
  std::uint64_t pairing_requests_sent{};
  std::uint64_t pairing_requests_received{};
  std::uint64_t pairing_results_sent{};
  std::uint64_t pairing_results_received{};
  // Scopes in force for this session; empty while untrusted in legacy mode
  // means unrestricted (M4 semantics).
  std::vector<std::string> authorized_scopes;
  bool pairing_restricted{false};
  CapabilitySet negotiated_capabilities;
  std::optional<Error> last_error;
};

// Inbound session-restart objects (protocol 1.2 session_restart_v1) already
// framed on the control channel. Verification is owned by the Node's restart
// state machine; PeerSession only routes the payloads.
struct PeerSessionRestartHandler {
  std::function<void(std::vector<std::byte>)> on_restart_offer;
  std::function<void(std::vector<std::byte>)> on_restart_answer;
  std::function<void(std::vector<std::byte>)> on_restart_candidate;
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
  // Sends one signed restart object on the authenticated control channel.
  // Fails without sending unless the session is authenticated.
  [[nodiscard]] Result<void> send_restart_frame(FrameType type,
                                                std::span<const std::byte> payload);
  void set_restart_handler(PeerSessionRestartHandler handler);
  [[nodiscard]] const SignedSessionHello& local_hello() const noexcept;
  [[nodiscard]] PeerSessionDiagnostics diagnostics() const noexcept;
  [[nodiscard]] bool authenticated() const noexcept;
  [[nodiscard]] bool pairing_restricted() const noexcept;
  [[nodiscard]] const std::vector<std::string>& authorized_scopes() const noexcept;

  // ---- Pairing (initiator side, M5-09) ----
  // Submits password, requested scopes, and a one-time nonce on the
  // authenticated end-to-end control channel of a pairing-restricted session.
  [[nodiscard]] Result<void> submit_pairing_request(
      std::string_view password_utf8, std::vector<std::string> requested_scopes);

  // ---- Business channels (M5-02/M5-06/M5-14) ----
  // Opens a logical business channel. Requires an authorized session and the
  // negotiated capability for the domain; the handler receives inbound frames
  // for exactly this channel id.
  [[nodiscard]] Result<std::uint32_t> open_business_channel(
      session::ChannelDomain domain, session::QueueFullPolicy policy,
      std::size_t queued_frame_capacity, std::size_t queued_byte_capacity,
      BusinessFrameHandler handler);
  // Local close of one logical channel; the session keeps running.
  void close_business_channel(std::uint32_t channel_id);
  [[nodiscard]] bool has_business_channel(std::uint32_t channel_id) const noexcept;
  // Registers (or replaces) the inbound dispatcher for a whole domain. Frames
  // on channel ids without a per-channel handler go to the domain handler,
  // which may admit peer-initiated logical channels.
  void set_domain_handler(session::ChannelDomain domain, DomainFrameHandler handler);
  // Registers a peer-initiated logical channel (used by domain handlers that
  // accepted an inbound open).
  [[nodiscard]] Result<std::uint32_t> adopt_business_channel(
      std::uint32_t channel_id, session::ChannelDomain domain,
      session::QueueFullPolicy policy, std::size_t queued_frame_capacity,
      std::size_t queued_byte_capacity, BusinessFrameHandler handler);
  // Enqueues a frame (type/flags/payload set by the caller; message id is
  // assigned here) and drains the scheduler into the transport.
  [[nodiscard]] Result<void> send_frame(std::uint32_t channel_id,
                                        session::FrameClass klass, Frame frame);

  [[nodiscard]] const session::SessionChannelManager& channels() const noexcept;
  // Drains queued frames into writable transport channels.
  void pump();

  void close(transport::CloseReason reason);

 private:
  explicit PeerSession(PeerSessionConfig config);
  void handle_message(transport::TransportChannel& channel,
                      std::vector<std::byte> payload);
  void handle_control_frame(transport::TransportChannel& channel, FrameView frame);
  void handle_business_frame(transport::TransportChannel& channel, FrameView frame);
  void handle_pairing_request(FrameView frame);
  void handle_pairing_result(FrameView frame);
  [[nodiscard]] Result<void> send_hello(transport::TransportChannel& channel);
  [[nodiscard]] Result<void> enqueue_control_frame(std::uint8_t type,
                                                   std::uint8_t flags,
                                                   std::vector<std::byte> payload);
  [[nodiscard]] Result<void> enforce_pairing_deadline();
  void upgrade_to_authorized(std::vector<std::string> scopes,
                             std::string_view reason);
  [[nodiscard]] StableStatus status_for_error(const Error& error) const noexcept;
  [[nodiscard]] transport::TransportChannel* physical_channel_for_domain(
      session::ChannelDomain domain);
  void ensure_physical_channel(session::ChannelDomain domain);
  [[nodiscard]] std::uint64_t wall_clock_now() const;
  void note_business_violation(transport::TransportChannel& channel);
  void fail(Error error);
  void notify() const;
  [[nodiscard]] Result<void> record(ConnectionStage stage, std::string_view source,
                                    std::string_view reason);

  PeerSessionConfig config_;
  std::unique_ptr<SessionHelloAdmission> admission_;
  std::unique_ptr<session::SessionChannelManager> channels_;
  std::unique_ptr<PairingRequestAdmission> pairing_admission_;
  transport::TransportChannel* control_{nullptr};
  std::map<session::ChannelDomain, transport::TransportChannel*> physical_channels_;
  std::map<std::uint32_t, BusinessFrameHandler> channel_handlers_;
  std::map<session::ChannelDomain, DomainFrameHandler> domain_handlers_;
  PeerSessionDiagnostics diagnostics_;
  PeerSessionRestartHandler restart_handler_;
  std::optional<std::uint64_t> pending_ping_;
  std::optional<std::pair<RequestId, PairingNonce>> pending_pairing_;
  std::vector<std::string> pending_pairing_scopes_;
  std::optional<std::uint64_t> restricted_since_;
  std::uint64_t business_violations_{};
  bool started_{false};
};

}  // namespace heyaki
