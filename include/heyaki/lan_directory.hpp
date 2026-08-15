#pragma once

#include <heyaki/lan_protocol.hpp>
#include <heyaki/profile_store.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace heyaki {

struct DeviceEndpointKey {
  DeviceId device_id;
  EndpointId endpoint_id;

  friend constexpr bool operator==(const DeviceEndpointKey&,
                                   const DeviceEndpointKey&) noexcept = default;
  friend constexpr auto operator<=>(const DeviceEndpointKey&,
                                    const DeviceEndpointKey&) noexcept = default;
};

enum class DirectoryObservationOutcome : std::uint8_t {
  inserted,
  updated,
  duplicate,
};

struct DirectoryObservation {
  DirectoryObservationOutcome outcome{DirectoryObservationOutcome::inserted};
  DeviceEndpointKey key;
};

struct LanEndpointSnapshot {
  std::string address;
  std::string interface_name;
  std::uint16_t tls_signaling_port{};
  LanBootNonce boot_nonce{};
  std::uint64_t sequence{};
  std::chrono::milliseconds ttl{};
};

struct RelayEndpointSnapshot {
  std::string relay_url;
  std::chrono::milliseconds ttl{};
};

struct EndpointDirectoryEntrySnapshot {
  DeviceEndpointKey key;
  bool trusted{false};
  std::optional<LanEndpointSnapshot> lan;
  std::optional<RelayEndpointSnapshot> relay;
};

struct EndpointDirectoryDiagnostics {
  std::uint64_t accepted{};
  std::uint64_t updated{};
  std::uint64_t duplicate{};
  std::uint64_t replay_rejected{};
  std::uint64_t conflict_rejected{};
  std::uint64_t capacity_rejected{};
  std::uint64_t rate_rejected{};
  std::uint64_t expired{};
  std::size_t current_entries{};
  std::size_t peak_entries{};
  std::size_t replay_entries{};
  std::size_t source_rate_entries{};
  std::size_t diagnostic_history_size{};
};

struct EndpointDirectoryEvent {
  std::chrono::steady_clock::time_point observed_at;
  ErrorCode code{ErrorCode::internal};
  std::string safe_detail;
};

class EndpointDirectory {
 public:
  class Impl;

  EndpointDirectory(EndpointDirectory&&) noexcept;
  EndpointDirectory& operator=(EndpointDirectory&&) noexcept;
  ~EndpointDirectory();

  EndpointDirectory(const EndpointDirectory&) = delete;
  EndpointDirectory& operator=(const EndpointDirectory&) = delete;

  [[nodiscard]] static Result<EndpointDirectory> create(
      const LanConfiguration& configuration);
  [[nodiscard]] Result<DirectoryObservation> observe_lan(
      const LanPresence& presence, std::string_view source_address,
      std::string_view interface_name, bool trusted,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  [[nodiscard]] Result<void> upsert_relay(
      DeviceEndpointKey key, std::string relay_url, bool trusted,
      std::chrono::milliseconds lease,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  [[nodiscard]] Result<void> set_trusted(DeviceEndpointKey key, bool trusted);
  void expire(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  [[nodiscard]] std::vector<EndpointDirectoryEntrySnapshot> snapshot(
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const;
  [[nodiscard]] EndpointDirectoryDiagnostics diagnostics() const noexcept;
  [[nodiscard]] std::vector<EndpointDirectoryEvent> diagnostic_history() const;

 private:
  explicit EndpointDirectory(std::unique_ptr<Impl> impl) noexcept;
  std::unique_ptr<Impl> impl_;
};

}  // namespace heyaki
