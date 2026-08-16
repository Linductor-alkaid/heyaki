#pragma once

#include "relay_database.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace heyaki {

inline constexpr std::size_t relay_manifest_sha256_bytes = 32U;
inline constexpr std::size_t max_endpoint_record_bytes = 16U * 1024U;
inline constexpr std::size_t max_service_manifest_bytes = 16U * 1024U;
inline constexpr std::size_t max_endpoint_application_id_bytes = 255U;

using RelayManifestSha256 = std::array<std::byte, relay_manifest_sha256_bytes>;

struct RelayEndpointKey {
  DeviceId device_id;
  EndpointId endpoint_id;

  friend constexpr bool operator==(const RelayEndpointKey&,
                                   const RelayEndpointKey&) noexcept = default;
  friend constexpr auto operator<=>(const RelayEndpointKey&,
                                    const RelayEndpointKey&) noexcept = default;
};

struct RelayEndpointRecord {
  RelayEndpointKey endpoint;
  std::string application_id;
  std::uint64_t record_generation{};
  RelayManifestSha256 manifest_sha256{};
  std::uint64_t expires_unix_milliseconds{};
  IdentitySignature signature{};
};

struct RelayServiceManifest {
  RelayEndpointKey endpoint;
  std::uint64_t manifest_generation{};
  RelayManifestSha256 canonical_manifest_sha256{};
  std::uint64_t expires_unix_milliseconds{};
  IdentitySignature signature{};
};

struct RelayTenantExposurePolicy {
  bool expose_application_id{false};
  bool expose_record_generation{false};
  bool expose_manifest_sha256{false};
  bool expose_manifest_generation{false};
  bool expose_expiry{true};
};

struct RelayEndpointPublication {
  RelayEndpointKey endpoint;
  std::optional<std::string> application_id;
  std::optional<std::uint64_t> record_generation;
  std::optional<std::uint64_t> manifest_generation;
  std::optional<RelayManifestSha256> manifest_sha256;
  std::optional<std::uint64_t> expires_unix_milliseconds;
};

[[nodiscard]] Result<std::vector<std::byte>> encode_relay_endpoint_record(
    const RelayEndpointRecord& record);
[[nodiscard]] Result<RelayEndpointRecord> parse_relay_endpoint_record(
    std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> canonical_relay_endpoint_record(
    const RelayEndpointRecord& record);
[[nodiscard]] Result<void> sign_relay_endpoint_record(
    RelayEndpointRecord& record, const IdentityKeyPair& identity);
[[nodiscard]] Result<void> validate_relay_endpoint_record(
    const RelayEndpointRecord& record, const RelayDeviceRecord& device,
    std::uint64_t now_unix_milliseconds);

[[nodiscard]] Result<std::vector<std::byte>> encode_relay_service_manifest(
    const RelayServiceManifest& manifest);
[[nodiscard]] Result<RelayServiceManifest> parse_relay_service_manifest(
    std::span<const std::byte> payload);
[[nodiscard]] Result<std::vector<std::byte>> canonical_relay_service_manifest(
    const RelayServiceManifest& manifest);
[[nodiscard]] Result<void> sign_relay_service_manifest(
    RelayServiceManifest& manifest, const IdentityKeyPair& identity);
[[nodiscard]] Result<void> validate_relay_service_manifest(
    const RelayServiceManifest& manifest, const RelayDeviceRecord& device,
    std::uint64_t now_unix_milliseconds,
    const std::optional<RelayEndpointRecord>& bound_record = std::nullopt);

[[nodiscard]] Result<RelayEndpointPublication> publish_relay_endpoint(
    const RelayEndpointRecord& record,
    const std::optional<RelayServiceManifest>& manifest,
    const RelayTenantExposurePolicy& policy, std::uint64_t now_unix_milliseconds);

}  // namespace heyaki
