#pragma once

#include <heyaki/error.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace heyaki {

// `heyaki-relay --init`: first-run bootstrap for owner-operated relays.
// Generates anything missing (config, self-signed TLS certificate with local
// SANs, owner enrollment password verifier, TURN shared secret), overwrites
// nothing that already exists, and prints the client access card (URL, leaf
// pin, tenant). Flags override every step so unattended provisioning works.
struct RelayInitOptions {
  std::filesystem::path config_file{"relay.conf"};
  std::optional<std::string> listen_address;
  std::optional<std::uint16_t> listen_port;
  std::optional<std::filesystem::path> tls_certificate_file;
  std::optional<std::filesystem::path> tls_private_key_file;
  std::optional<std::filesystem::path> database_file;
  std::string enrollment_tenant{"default"};
  // Owner enrollment password sources, tried in order: file, then
  // HEYAKI_INIT_PASSWORD, then interactive prompt (POSIX only). When all are
  // unavailable and the database has no verifier yet, init fails instead of
  // guessing.
  std::optional<std::filesystem::path> password_file;
  bool generate_turn_secret{true};
};

[[nodiscard]] Result<void> run_relay_init(const RelayInitOptions& options);

// Non-loopback hostnames and address literals of this machine, plus
// localhost/127.0.0.1 — the SAN set for the generated certificate.
[[nodiscard]] Result<std::vector<std::string>> collect_local_san_entries();

// Self-signed P-256 certificate with the given SAN entries; returns the leaf
// SHA-256 digest (the relay id / client pin). Creates parent directories;
// refuses to overwrite existing files; private key is written 0600.
[[nodiscard]] Result<std::array<std::byte, 32U>> generate_self_signed_relay_certificate(
    const std::filesystem::path& certificate_file,
    const std::filesystem::path& private_key_file,
    const std::vector<std::string>& san_entries);

// Random printable-ASCII shared secret for coturn static-auth
// (>= 16 chars per validate_turn_secret).
[[nodiscard]] Result<std::string> generate_turn_secret();

// Reads and validates an owner password from a file (first line, trailing
// newline stripped).
[[nodiscard]] Result<std::string> read_owner_password_file(
    const std::filesystem::path& password_file);

// Interactive double-entry prompt with terminal echo disabled (POSIX only;
// Windows reports a configuration error pointing at --init-password-file).
[[nodiscard]] Result<std::string> prompt_owner_password();

}  // namespace heyaki
