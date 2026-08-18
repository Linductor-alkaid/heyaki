#pragma once

#include <heyaki/identity.hpp>
#include <heyaki/lan_directory.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/signaling_protocol.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace heyaki {

inline constexpr std::size_t max_session_hello_bytes = 64U * 1024U;

struct SignedSessionHello {
  DeviceEndpointKey sender;
  DeviceEndpointKey peer;
  SessionId session_id;
  std::uint64_t session_epoch{};
  SignalingNonce initiator_nonce{};
  SignalingNonce responder_nonce{};
  SignalingTranscriptSha256 signaling_transcript_sha256{};
  ProtocolVersion protocol_version{current_protocol_version};
  CapabilitySet supported{protocol_1_1_capability_bits};
  CapabilitySet required{static_cast<std::uint64_t>(Capability::session)};
  std::uint64_t expires_unix_milliseconds{};
  IdentitySignature signature{};
};

struct SessionHelloExpectation {
  DeviceEndpointKey sender;
  DeviceEndpointKey peer;
  SessionId session_id;
  std::uint64_t session_epoch{};
  SignalingNonce initiator_nonce{};
  SignalingNonce responder_nonce{};
  SignalingTranscriptSha256 signaling_transcript_sha256{};
};

[[nodiscard]] Result<void> validate_signed_session_hello(const SignedSessionHello& hello);
[[nodiscard]] Result<std::vector<std::byte>> canonical_signed_session_hello(
    const SignedSessionHello& hello);
[[nodiscard]] Result<void> sign_signed_session_hello(SignedSessionHello& hello,
                                                     const IdentityKeyPair& identity);
[[nodiscard]] Result<void> verify_signed_session_hello(
    const SignedSessionHello& hello, std::span<const std::byte> sender_public_key,
    std::uint64_t now_unix_milliseconds);
[[nodiscard]] Result<std::vector<std::byte>> encode_signed_session_hello(
    const SignedSessionHello& hello);
[[nodiscard]] Result<SignedSessionHello> parse_signed_session_hello(
    std::span<const std::byte> payload);

enum class SessionHelloAdmissionAction : std::uint8_t {
  accepted,
  duplicate,
  late_epoch,
};

struct SessionHelloAdmissionOutcome {
  SessionHelloAdmissionAction action{SessionHelloAdmissionAction::accepted};
  std::optional<NegotiatedProtocol> negotiated_protocol;
};

class SessionHelloAdmission {
 public:
  SessionHelloAdmission(SessionHelloExpectation expectation,
                        IdentityPublicKey sender_public_key,
                        ProtocolHello local_protocol);

  [[nodiscard]] Result<SessionHelloAdmissionOutcome> admit(
      std::span<const std::byte> payload, std::uint64_t now_unix_milliseconds);
  [[nodiscard]] bool authenticated() const noexcept { return accepted_payload_.has_value(); }

 private:
  SessionHelloExpectation expectation_;
  IdentityPublicKey sender_public_key_{};
  ProtocolHello local_protocol_;
  std::optional<std::vector<std::byte>> accepted_payload_;
  std::optional<NegotiatedProtocol> negotiated_protocol_;
};

}  // namespace heyaki
