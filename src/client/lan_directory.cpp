#include <heyaki/lan_directory.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

using SteadyTime = std::chrono::steady_clock::time_point;

bool valid_directory_text(std::string_view value, std::size_t maximum) noexcept {
  return !value.empty() && value.size() <= maximum &&
         std::all_of(value.begin(), value.end(), [](unsigned char character) {
           return character >= 0x20U && character <= 0x7eU;
         });
}

Error directory_error(ErrorCode code, const char* detail) {
  return {code, "endpoint_directory", detail};
}

std::chrono::milliseconds remaining_ttl(SteadyTime expires_at, SteadyTime now) {
  if (expires_at <= now) {
    return std::chrono::milliseconds{0};
  }
  return std::chrono::duration_cast<std::chrono::milliseconds>(expires_at - now);
}

}  // namespace

class EndpointDirectory::Impl {
 public:
  explicit Impl(LanConfiguration configuration)
      : configuration(std::move(configuration)) {}

  struct LanHint {
    std::string address;
    std::string interface_name;
    std::uint16_t port{};
    LanBootNonce boot_nonce{};
    std::uint64_t sequence{};
    SteadyTime expires_at;
    SteadyTime observed_at;
  };

  struct RelayHint {
    std::string relay_url;
    SteadyTime expires_at;
    SteadyTime observed_at;
  };

  struct Entry {
    bool trusted{false};
    std::optional<LanHint> lan;
    std::optional<RelayHint> relay;
    SteadyTime last_update;
  };

  struct ReplayState {
    LanBootNonce current_boot{};
    std::uint64_t last_sequence{};
    IdentitySignature last_signature{};
    std::array<LanBootNonce, 4U> retired_boots{};
    std::size_t retired_count{};
    SteadyTime retain_until;
  };

  struct SourceRate {
    SteadyTime window_start;
    std::size_t count{};
    SteadyTime last_seen;
  };

  void record(ErrorCode code, const char* detail, SteadyTime now) {
    if (events.size() == configuration.diagnostic_capacity) {
      events.pop_front();
    }
    events.push_back(EndpointDirectoryEvent{
        .observed_at = now, .code = code, .safe_detail = detail});
  }

  std::size_t lan_count_for_source(std::string_view address) const {
    return static_cast<std::size_t>(std::count_if(
        entries.begin(), entries.end(), [&](const auto& item) {
          return item.second.lan && item.second.lan->address == address;
        }));
  }

  std::size_t lan_count_for_interface(std::string_view name) const {
    return static_cast<std::size_t>(std::count_if(
        entries.begin(), entries.end(), [&](const auto& item) {
          return item.second.lan && item.second.lan->interface_name == name;
        }));
  }

  std::size_t unknown_count() const {
    return static_cast<std::size_t>(std::count_if(
        entries.begin(), entries.end(), [](const auto& item) { return !item.second.trusted; }));
  }

  void purge_rate_state(SteadyTime now) {
    constexpr auto retention = std::chrono::seconds{2};
    for (auto iterator = source_rates.begin(); iterator != source_rates.end();) {
      if (iterator->second.last_seen + retention <= now) {
        iterator = source_rates.erase(iterator);
      } else {
        ++iterator;
      }
    }
  }

  bool admit_rate(std::string_view source, SteadyTime now) {
    if (global_rate_window + std::chrono::seconds{1} <= now) {
      global_rate_window = now;
      global_rate_count = 0U;
    }
    if (global_rate_count >= configuration.announcement_rate_per_second) {
      return false;
    }
    purge_rate_state(now);
    auto iterator = source_rates.find(std::string{source});
    if (iterator == source_rates.end()) {
      if (source_rates.size() >= configuration.per_source_presence_capacity) {
        return false;
      }
      iterator = source_rates.emplace(std::string{source}, SourceRate{now, 0U, now}).first;
    }
    auto& state = iterator->second;
    if (state.window_start + std::chrono::seconds{1} <= now) {
      state.window_start = now;
      state.count = 0U;
    }
    state.last_seen = now;
    if (state.count >= configuration.per_source_announcement_rate) {
      return false;
    }
    ++state.count;
    ++global_rate_count;
    return true;
  }

  bool is_retired_boot(const ReplayState& replay, const LanBootNonce& boot) const noexcept {
    for (std::size_t index = 0U; index < replay.retired_count; ++index) {
      if (replay.retired_boots[index] == boot) {
        return true;
      }
    }
    return false;
  }

  bool retire_current_boot(ReplayState& replay) {
    if (replay.retired_count == replay.retired_boots.size()) {
      return false;
    }
    replay.retired_boots[replay.retired_count++] = replay.current_boot;
    return true;
  }

  bool evict_untrusted_lan_only() {
    auto candidate = entries.end();
    for (auto iterator = entries.begin(); iterator != entries.end(); ++iterator) {
      if (iterator->second.trusted || iterator->second.relay) {
        continue;
      }
      if (candidate == entries.end() ||
          iterator->second.last_update < candidate->second.last_update) {
        candidate = iterator;
      }
    }
    if (candidate == entries.end()) {
      return false;
    }
    entries.erase(candidate);
    return true;
  }

  LanConfiguration configuration;
  std::map<DeviceEndpointKey, Entry> entries;
  std::map<DeviceEndpointKey, ReplayState> replay;
  std::map<std::string, SourceRate> source_rates;
  std::deque<EndpointDirectoryEvent> events;
  EndpointDirectoryDiagnostics metrics;
  SteadyTime global_rate_window{std::chrono::steady_clock::now()};
  std::size_t global_rate_count{};
};

EndpointDirectory::EndpointDirectory(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}
EndpointDirectory::EndpointDirectory(EndpointDirectory&&) noexcept = default;
EndpointDirectory& EndpointDirectory::operator=(EndpointDirectory&&) noexcept = default;
EndpointDirectory::~EndpointDirectory() = default;

Result<EndpointDirectory> EndpointDirectory::create(
    const LanConfiguration& configuration) {
  auto valid = validate_lan_configuration(configuration);
  if (!valid) {
    return Result<EndpointDirectory>::failure(*valid.error_if());
  }
  return Result<EndpointDirectory>::success(
      EndpointDirectory{std::make_unique<Impl>(configuration)});
}

Result<DirectoryObservation> EndpointDirectory::observe_lan(
    const LanPresence& presence, std::string_view source_address,
    std::string_view interface_name, bool trusted, SteadyTime now) {
  if (!valid_directory_text(source_address, 64U) ||
      !valid_directory_text(interface_name, 128U)) {
    return Result<DirectoryObservation>::failure(
        directory_error(ErrorCode::configuration, "invalid_observation_context"));
  }
  auto valid = validate_lan_presence(presence);
  if (!valid) {
    return Result<DirectoryObservation>::failure(*valid.error_if());
  }
  if (!impl_->admit_rate(source_address, now)) {
    ++impl_->metrics.rate_rejected;
    impl_->record(ErrorCode::resource_exhausted, "presence_rate_limited", now);
    return Result<DirectoryObservation>::failure(
        directory_error(ErrorCode::resource_exhausted, "presence_rate_limited"));
  }

  const DeviceEndpointKey key{presence.device_id, presence.endpoint_id};
  auto replay_iterator = impl_->replay.find(key);
  if (replay_iterator == impl_->replay.end()) {
    if (impl_->replay.size() >= impl_->configuration.replay_capacity) {
      auto oldest = std::min_element(
          impl_->replay.begin(), impl_->replay.end(), [](const auto& left, const auto& right) {
            return left.second.retain_until < right.second.retain_until;
          });
      if (oldest != impl_->replay.end() && oldest->second.retain_until <= now) {
        impl_->replay.erase(oldest);
      } else {
        ++impl_->metrics.capacity_rejected;
        impl_->record(ErrorCode::resource_exhausted, "replay_capacity_full", now);
        return Result<DirectoryObservation>::failure(
            directory_error(ErrorCode::resource_exhausted, "replay_capacity_full"));
      }
    }
    replay_iterator = impl_->replay.emplace(
        key, Impl::ReplayState{.current_boot = presence.boot_nonce,
                               .last_sequence = 0U,
                               .retain_until = now + presence.lease * 2})
                          .first;
  }
  auto& replay = replay_iterator->second;
  if (replay.current_boot == presence.boot_nonce) {
    if (presence.sequence < replay.last_sequence) {
      ++impl_->metrics.replay_rejected;
      impl_->record(ErrorCode::protocol, "presence_sequence_replay", now);
      return Result<DirectoryObservation>::failure(
          directory_error(ErrorCode::protocol, "presence_sequence_replay"));
    }
    if (presence.sequence == replay.last_sequence && replay.last_sequence != 0U) {
      if (presence.signature == replay.last_signature) {
        ++impl_->metrics.duplicate;
        impl_->record(ErrorCode::would_block, "presence_duplicate", now);
        return Result<DirectoryObservation>::success(
            DirectoryObservation{DirectoryObservationOutcome::duplicate, key});
      }
      ++impl_->metrics.conflict_rejected;
      impl_->record(ErrorCode::protocol, "presence_sequence_conflict", now);
      return Result<DirectoryObservation>::failure(
          directory_error(ErrorCode::protocol, "presence_sequence_conflict"));
    }
  } else {
    if (impl_->is_retired_boot(replay, presence.boot_nonce)) {
      ++impl_->metrics.replay_rejected;
      impl_->record(ErrorCode::protocol, "presence_boot_replay", now);
      return Result<DirectoryObservation>::failure(
          directory_error(ErrorCode::protocol, "presence_boot_replay"));
    }
    if (!impl_->retire_current_boot(replay)) {
      ++impl_->metrics.capacity_rejected;
      impl_->record(ErrorCode::resource_exhausted,
                    "presence_boot_history_full", now);
      return Result<DirectoryObservation>::failure(directory_error(
          ErrorCode::resource_exhausted, "presence_boot_history_full"));
    }
    replay.current_boot = presence.boot_nonce;
    replay.last_sequence = 0U;
    replay.last_signature = {};
  }

  auto entry_iterator = impl_->entries.find(key);
  const bool new_entry = entry_iterator == impl_->entries.end();
  const bool new_lan_hint = new_entry || !entry_iterator->second.lan;
  if (new_lan_hint &&
      impl_->lan_count_for_source(source_address) >=
          impl_->configuration.per_source_presence_capacity) {
    ++impl_->metrics.capacity_rejected;
    impl_->record(ErrorCode::resource_exhausted, "source_presence_capacity_full", now);
    return Result<DirectoryObservation>::failure(
        directory_error(ErrorCode::resource_exhausted, "source_presence_capacity_full"));
  }
  if (new_lan_hint &&
      impl_->lan_count_for_interface(interface_name) >=
          impl_->configuration.per_interface_directory_capacity) {
    ++impl_->metrics.capacity_rejected;
    impl_->record(ErrorCode::resource_exhausted, "interface_directory_capacity_full", now);
    return Result<DirectoryObservation>::failure(
        directory_error(ErrorCode::resource_exhausted, "interface_directory_capacity_full"));
  }
  if (new_entry) {
    const auto untrusted_limit = impl_->configuration.directory_capacity -
                                 impl_->configuration.trusted_directory_reserve;
    if (!trusted && (impl_->entries.size() >= untrusted_limit ||
                     impl_->unknown_count() >= impl_->configuration.unknown_identity_capacity)) {
      ++impl_->metrics.capacity_rejected;
      impl_->record(ErrorCode::resource_exhausted, "untrusted_directory_capacity_full", now);
      return Result<DirectoryObservation>::failure(
          directory_error(ErrorCode::resource_exhausted,
                          "untrusted_directory_capacity_full"));
    }
    if (impl_->entries.size() >= impl_->configuration.directory_capacity &&
        (!trusted || !impl_->evict_untrusted_lan_only())) {
      ++impl_->metrics.capacity_rejected;
      impl_->record(ErrorCode::resource_exhausted, "directory_capacity_full", now);
      return Result<DirectoryObservation>::failure(
          directory_error(ErrorCode::resource_exhausted, "directory_capacity_full"));
    }
    entry_iterator = impl_->entries.emplace(key, Impl::Entry{}).first;
  }

  auto& entry = entry_iterator->second;
  entry.trusted = entry.trusted || trusted;
  entry.lan = Impl::LanHint{.address = std::string{source_address},
                            .interface_name = std::string{interface_name},
                            .port = presence.tls_signaling_port,
                            .boot_nonce = presence.boot_nonce,
                            .sequence = presence.sequence,
                            .expires_at = now + presence.lease,
                            .observed_at = now};
  entry.last_update = now;
  replay.last_sequence = presence.sequence;
  replay.last_signature = presence.signature;
  replay.retain_until = now + presence.lease * 2;
  if (new_entry) {
    ++impl_->metrics.accepted;
  } else {
    ++impl_->metrics.updated;
  }
  impl_->metrics.current_entries = impl_->entries.size();
  impl_->metrics.peak_entries = std::max(impl_->metrics.peak_entries, impl_->entries.size());
  impl_->metrics.replay_entries = impl_->replay.size();
  impl_->metrics.source_rate_entries = impl_->source_rates.size();
  impl_->record(ErrorCode::internal, new_entry ? "presence_accepted" : "presence_updated", now);
  return Result<DirectoryObservation>::success(DirectoryObservation{
      new_entry ? DirectoryObservationOutcome::inserted
                : DirectoryObservationOutcome::updated,
      key});
}

Result<void> EndpointDirectory::upsert_relay(DeviceEndpointKey key, std::string relay_url,
                                             bool trusted, std::chrono::milliseconds lease,
                                             SteadyTime now) {
  if (key.device_id.is_zero() || key.endpoint_id.is_zero() ||
      !valid_directory_text(relay_url, 2048U) || lease.count() <= 0 ||
      lease > std::chrono::hours{24}) {
    return Result<void>::failure(
        directory_error(ErrorCode::configuration, "invalid_relay_hint"));
  }
  auto iterator = impl_->entries.find(key);
  if (iterator == impl_->entries.end()) {
    if (impl_->entries.size() >= impl_->configuration.directory_capacity &&
        (!trusted || !impl_->evict_untrusted_lan_only())) {
      ++impl_->metrics.capacity_rejected;
      return Result<void>::failure(
          directory_error(ErrorCode::resource_exhausted, "directory_capacity_full"));
    }
    iterator = impl_->entries.emplace(key, Impl::Entry{}).first;
  }
  auto& entry = iterator->second;
  entry.trusted = entry.trusted || trusted;
  entry.relay = Impl::RelayHint{
      .relay_url = std::move(relay_url), .expires_at = now + lease, .observed_at = now};
  entry.last_update = now;
  impl_->metrics.current_entries = impl_->entries.size();
  impl_->metrics.peak_entries = std::max(impl_->metrics.peak_entries, impl_->entries.size());
  return Result<void>::success();
}

Result<void> EndpointDirectory::set_trusted(DeviceEndpointKey key, bool trusted) {
  auto iterator = impl_->entries.find(key);
  if (iterator == impl_->entries.end()) {
    return Result<void>::failure(
        directory_error(ErrorCode::endpoint_offline, "endpoint_not_in_directory"));
  }
  iterator->second.trusted = trusted;
  return Result<void>::success();
}

void EndpointDirectory::expire(SteadyTime now) {
  for (auto iterator = impl_->entries.begin(); iterator != impl_->entries.end();) {
    if (iterator->second.lan && iterator->second.lan->expires_at <= now) {
      iterator->second.lan.reset();
      ++impl_->metrics.expired;
    }
    if (iterator->second.relay && iterator->second.relay->expires_at <= now) {
      iterator->second.relay.reset();
      ++impl_->metrics.expired;
    }
    if (!iterator->second.lan && !iterator->second.relay) {
      iterator = impl_->entries.erase(iterator);
    } else {
      ++iterator;
    }
  }
  for (auto iterator = impl_->replay.begin(); iterator != impl_->replay.end();) {
    if (iterator->second.retain_until <= now) {
      iterator = impl_->replay.erase(iterator);
    } else {
      ++iterator;
    }
  }
  impl_->purge_rate_state(now);
  impl_->metrics.current_entries = impl_->entries.size();
  impl_->metrics.replay_entries = impl_->replay.size();
  impl_->metrics.source_rate_entries = impl_->source_rates.size();
}

std::vector<EndpointDirectoryEntrySnapshot> EndpointDirectory::snapshot(SteadyTime now) const {
  std::vector<EndpointDirectoryEntrySnapshot> output;
  output.reserve(impl_->entries.size());
  for (const auto& [key, entry] : impl_->entries) {
    EndpointDirectoryEntrySnapshot snapshot{
        .key = key, .trusted = entry.trusted, .lan = std::nullopt, .relay = std::nullopt};
    if (entry.lan && entry.lan->expires_at > now) {
      snapshot.lan = LanEndpointSnapshot{.address = entry.lan->address,
                                         .interface_name = entry.lan->interface_name,
                                         .tls_signaling_port = entry.lan->port,
                                         .boot_nonce = entry.lan->boot_nonce,
                                         .sequence = entry.lan->sequence,
                                         .ttl = remaining_ttl(entry.lan->expires_at, now)};
    }
    if (entry.relay && entry.relay->expires_at > now) {
      snapshot.relay = RelayEndpointSnapshot{
          .relay_url = entry.relay->relay_url,
          .ttl = remaining_ttl(entry.relay->expires_at, now)};
    }
    if (snapshot.lan || snapshot.relay) {
      output.push_back(std::move(snapshot));
    }
  }
  return output;
}

EndpointDirectoryDiagnostics EndpointDirectory::diagnostics() const noexcept {
  auto output = impl_->metrics;
  output.current_entries = impl_->entries.size();
  output.replay_entries = impl_->replay.size();
  output.source_rate_entries = impl_->source_rates.size();
  output.diagnostic_history_size = impl_->events.size();
  return output;
}

std::vector<EndpointDirectoryEvent> EndpointDirectory::diagnostic_history() const {
  return {impl_->events.begin(), impl_->events.end()};
}

}  // namespace heyaki
