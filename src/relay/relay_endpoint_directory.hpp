#pragma once

#include "relay_database.hpp"
#include "relay_endpoint.hpp"
#include "relay_ttl_table.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace heyaki {

struct RelayEndpointDirectoryConfig {
  std::size_t capacity{4096U};
  std::chrono::milliseconds maximum_ttl{5 * 60 * 1000};
};

struct RelayEndpointDirectoryEntry {
  RelayEndpointRecord record;
  IdentityPublicKey identity_public_key{};
  std::optional<RelayServiceManifest> manifest;
  std::string tenant;
  std::uint64_t wall_clock_expires_unix_milliseconds{};
};

struct RelayEndpointDirectoryDiagnostics {
  std::uint64_t published{};
  std::uint64_t updated{};
  std::uint64_t expired{};
  std::uint64_t removed{};
  std::uint64_t capacity_rejected{};
  std::uint64_t validation_rejected{};
  std::uint64_t tenant_conflict_rejected{};
  RelayTtlDiagnostics table;
};

class RelayEndpointDirectory {
 public:
  struct Impl;

  RelayEndpointDirectory(RelayEndpointDirectory&&) noexcept;
  RelayEndpointDirectory& operator=(RelayEndpointDirectory&&) noexcept;
  ~RelayEndpointDirectory();

  RelayEndpointDirectory(const RelayEndpointDirectory&) = delete;
  RelayEndpointDirectory& operator=(const RelayEndpointDirectory&) = delete;

  [[nodiscard]] static Result<RelayEndpointDirectory> create(
      const RelayEndpointDirectoryConfig& config = {});

  [[nodiscard]] Result<void> publish(
      const RelayEndpointRecord& record,
      const std::optional<RelayServiceManifest>& manifest,
      const RelayDeviceRecord& device, std::string_view tenant,
      std::uint64_t now_unix_milliseconds,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  [[nodiscard]] Result<void> remove(const RelayEndpointKey& key);
  [[nodiscard]] std::optional<RelayEndpointDirectoryEntry> get(
      const RelayEndpointKey& key,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const;
  void expire(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  [[nodiscard]] RelayEndpointDirectoryDiagnostics diagnostics() const noexcept;

 private:
  explicit RelayEndpointDirectory(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

}  // namespace heyaki
