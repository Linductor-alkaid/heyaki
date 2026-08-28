#pragma once

// Pairing wire protocol (M5-07/M5-09). PAIRING_REQUEST/PAIRING_RESULT ride the
// control channel (channel 0) of a pairing-restricted session: the peer has
// already authenticated its long-term identity in SESSION_HELLO over the
// fingerprint-verified DataChannel, so the password never crosses an
// unauthenticated hop. Payloads follow the frozen
// heyaki.protocol.pairing.v1 schemas.

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/limits.hpp>
#include <heyaki/trust_grant.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace heyaki {

// Mirrors heyaki.protocol.common.v1.StableStatusCode. Wire-stable; never
// renumbered.
enum class StableStatus : std::uint32_t {
  unspecified = 0U,
  ok = 1U,
  cancelled = 2U,
  deadline_exceeded = 3U,
  unauthenticated = 4U,
  permission_denied = 5U,
  not_found = 6U,
  already_exists = 7U,
  resource_exhausted = 8U,
  failed_precondition = 9U,
  unavailable = 10U,
  internal = 11U,
  unimplemented = 12U,
  protocol_error = 13U,
  outcome_unknown = 14U,
};

inline constexpr std::size_t max_pairing_password_bytes = 1024U;
inline constexpr std::size_t max_pairing_requested_scopes = max_trust_scopes;

struct PairingRequestBody {
  RequestId request_id;
  PairingNonce nonce{};
  // Secret: exists only inside the authenticated end-to-end channel and the
  // local verifier call. Never logged, never persisted.
  std::string password_utf8;
  std::vector<std::string> requested_scopes;
};

struct PairingResultBody {
  RequestId request_id;
  StableStatus status{StableStatus::unspecified};
  std::optional<SignedTrustGrant> grant;
};

[[nodiscard]] Result<std::vector<std::byte>> encode_pairing_request(
    const PairingRequestBody& request);
[[nodiscard]] Result<PairingRequestBody> parse_pairing_request(
    std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> encode_pairing_result(
    const PairingResultBody& result);
[[nodiscard]] Result<PairingResultBody> parse_pairing_result(
    std::span<const std::byte> payload);

enum class PairingAdmissionAction : std::uint8_t {
  // A new request passed structural admission; verify the password.
  admitted,
  // Byte-identical retransmission of an already-terminal request: replay the
  // cached result instead of re-verifying the password.
  duplicate,
};

struct PairingAdmissionOutcome {
  PairingAdmissionAction action{PairingAdmissionAction::admitted};
  std::optional<PairingResultBody> cached_result;
};

// Per-session PAIRING_REQUEST admission (wire protocol 6.1): requests are
// keyed by (request_id, nonce); identical duplicates replay the bounded cached
// result, conflicting duplicates are protocol errors, and the session-wide
// attempt budget from Limits rejects further attempts without verifying.
class PairingRequestAdmission {
 public:
  explicit PairingRequestAdmission(Limits limits = {});

  PairingRequestAdmission(const PairingRequestAdmission&) = delete;
  PairingRequestAdmission& operator=(const PairingRequestAdmission&) = delete;

  [[nodiscard]] Result<PairingAdmissionOutcome> admit_request(
      const PairingRequestBody& request);

  // Records the terminal result for the most recently admitted request and
  // replays it for identical duplicates. Failed verifications count against
  // the attempt budget exactly like grants.
  [[nodiscard]] Result<void> record_result(PairingResultBody result);

  [[nodiscard]] std::size_t attempts_used() const noexcept;
  [[nodiscard]] bool exhausted() const noexcept;
  [[nodiscard]] const Limits& limits() const noexcept;

 private:
  Limits limits_;
  std::vector<std::pair<std::pair<RequestId, PairingNonce>, PairingResultBody>>
      terminal_results_;
  std::optional<std::pair<RequestId, PairingNonce>> pending_key_;
  std::size_t attempts_used_{};
};

}  // namespace heyaki
