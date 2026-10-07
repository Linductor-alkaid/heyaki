#pragma once

#include <heyaki/error.hpp>
#include <heyaki/identity.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/runtime.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

struct RelayEnrollmentExchangeResult {
  std::string relay_url;
  std::string tenant;
  std::uint64_t enrollment_generation{};
  std::uint64_t token_remaining_uses_after{};
  // Password-mode completions: SHA-256 of the relay leaf certificate as
  // returned by the relay (TOFU pin anchor for URL+password bootstrap).
  // Token-mode exchanges leave this empty.
  std::optional<std::vector<std::byte>> relay_certificate_sha256;
};

// Enrollment admission credential. `token` is the historical bootstrap token;
// `password` is the owner enrollment password for relays running
// `enrollment_mode = password` (URL + password bootstrap).
struct RelayEnrollmentCredential {
  enum class Kind : std::uint8_t {
    token = 1U,
    password = 2U,
  };
  Kind kind{Kind::token};
  std::string secret;
};

using RelayEnrollmentExchange = std::function<Result<RelayEnrollmentExchangeResult>(
    const IdentityKeyPair& identity, const EndpointId& endpoint_id,
    std::string_view tenant, std::string_view bootstrap_token,
    std::uint64_t now_unix_milliseconds)>;
using RelayEnrollmentCredentialExchange =
    std::function<Result<RelayEnrollmentExchangeResult>(
        const IdentityKeyPair& identity, const EndpointId& endpoint_id,
        std::string_view tenant, const RelayEnrollmentCredential& credential,
        std::uint64_t now_unix_milliseconds)>;
using RelayEnrollmentRollback = std::function<Result<void>(
    const DeviceId& device_id, std::string_view tenant,
    std::uint64_t enrollment_generation)>;

struct RelayEnrollmentWssTransportConfig {
  std::string relay_url;
  std::optional<std::vector<std::byte>> relay_pin;
  std::optional<std::filesystem::path> tls_ca_file;
  bool tls_verify_peer{true};
  std::chrono::milliseconds connect_timeout{5000};
  std::chrono::milliseconds handshake_timeout{5000};
  std::chrono::milliseconds close_timeout{2000};
  RuntimeConfig runtime;
  // Optional borrowed host Runtime (same discipline as NodeConfig::runtime):
  // when set, the exchange's WSS transport runs on this runtime's executor
  // and enters its lifecycle view, so a host shutdown cancels an in-flight
  // exchange instead of leaving an unmonitored owned runtime behind. When
  // null, the exchange creates its own owned runtime from `runtime` (the
  // original behavior, kept for existing callers). The borrowed runtime must
  // outlive the exchange call.
  Runtime* runtime_borrowed{nullptr};
};

struct RelayEnrollmentClientConfig {
  ProfileStore* profile{nullptr};
  std::string application_id;
  std::string relay_url;
  std::string tenant;
  std::optional<std::vector<std::byte>> relay_pin;
  bool auto_connect{true};
  std::optional<RelayEnrollmentWssTransportConfig> wss_transport;
  RelayEnrollmentExchange exchange;
  // Credential-aware exchange; when empty, the token-based `exchange` (or the
  // built-in WSS transport) is used. Takes precedence over `exchange` when
  // set.
  RelayEnrollmentCredentialExchange credential_exchange;
  RelayEnrollmentRollback rollback;
};

struct RelayEnrollmentClientResult {
  std::string relay_url;
  std::string tenant;
  std::uint64_t enrollment_generation{};
  std::uint64_t token_remaining_uses_after{};
  // Password-mode completions: relay leaf certificate SHA-256 (TOFU pin
  // anchor). Token-mode exchanges leave this empty.
  std::optional<std::vector<std::byte>> relay_certificate_sha256;
};

[[nodiscard]] Result<RelayEnrollmentExchangeResult> enroll_relay_over_wss(
    const RelayEnrollmentWssTransportConfig& transport,
    const IdentityKeyPair& identity, const EndpointId& endpoint_id,
    std::string_view tenant, std::string_view bootstrap_token,
    std::uint64_t now_unix_milliseconds);

// Credential-aware exchange: token credentials behave like
// `enroll_relay_over_wss`; password credentials derive the challenge-bound
// Argon2id proof and enroll against a relay in password mode.
[[nodiscard]] Result<RelayEnrollmentExchangeResult> enroll_relay_over_wss_with_credential(
    const RelayEnrollmentWssTransportConfig& transport,
    const IdentityKeyPair& identity, const EndpointId& endpoint_id,
    std::string_view tenant, const RelayEnrollmentCredential& credential,
    std::uint64_t now_unix_milliseconds);

[[nodiscard]] RelayEnrollmentExchange make_relay_enrollment_wss_exchange(
    RelayEnrollmentWssTransportConfig transport);

[[nodiscard]] RelayEnrollmentCredentialExchange
make_relay_enrollment_wss_credential_exchange(RelayEnrollmentWssTransportConfig transport);

[[nodiscard]] Result<RelayEnrollmentClientResult> enroll_relay_profile(
    const RelayEnrollmentClientConfig& config, std::string_view bootstrap_token,
    std::uint64_t now_unix_milliseconds);

// Profile-level enrollment with an explicit credential (token or password).
[[nodiscard]] Result<RelayEnrollmentClientResult> enroll_relay_profile_with_credential(
    const RelayEnrollmentClientConfig& config, const RelayEnrollmentCredential& credential,
    std::uint64_t now_unix_milliseconds);

}  // namespace heyaki
