#include "relay_endpoint_directory.hpp"

#include <heyaki/error.hpp>
#include <heyaki/security.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace heyaki {
namespace {

Error directory_error(ErrorCode code, const char* detail) {
  return Error{code, "relay_endpoint_directory", detail};
}

std::chrono::milliseconds record_ttl(std::uint64_t expires_unix_milliseconds,
                                     std::uint64_t now_unix_milliseconds,
                                     std::chrono::milliseconds maximum_ttl) {
  if (expires_unix_milliseconds <= now_unix_milliseconds) {
    return std::chrono::milliseconds{0};
  }
  const auto remaining = expires_unix_milliseconds - now_unix_milliseconds;
  if (remaining > static_cast<std::uint64_t>(maximum_ttl.count())) {
    return maximum_ttl;
  }
  return std::chrono::milliseconds{static_cast<std::int64_t>(remaining)};
}

}  // namespace

struct RelayEndpointDirectory::Impl {
  Impl(RelayEndpointDirectoryConfig config_value,
       RelayTtlTable<RelayEndpointKey, RelayEndpointDirectoryEntry> table_value) noexcept
      : config(std::move(config_value)), entries(std::move(table_value)) {}

  RelayEndpointDirectoryConfig config;
  RelayTtlTable<RelayEndpointKey, RelayEndpointDirectoryEntry> entries;
  RelayEndpointDirectoryDiagnostics stats;
};

RelayEndpointDirectory::RelayEndpointDirectory(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}
RelayEndpointDirectory::RelayEndpointDirectory(RelayEndpointDirectory&&) noexcept = default;
RelayEndpointDirectory& RelayEndpointDirectory::operator=(
    RelayEndpointDirectory&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}
RelayEndpointDirectory::~RelayEndpointDirectory() = default;

Result<RelayEndpointDirectory> RelayEndpointDirectory::create(
    const RelayEndpointDirectoryConfig& config) {
  if (config.capacity == 0U || config.maximum_ttl.count() <= 0 ||
      config.maximum_ttl > std::chrono::milliseconds{maximum_signed_validity_milliseconds}) {
    return Result<RelayEndpointDirectory>::failure(
        directory_error(ErrorCode::configuration, "endpoint_directory_config_invalid"));
  }
  auto entries = RelayTtlTable<RelayEndpointKey, RelayEndpointDirectoryEntry>::create(
      config.capacity);
  if (!entries) {
    return Result<RelayEndpointDirectory>::failure(*entries.error_if());
  }
  return Result<RelayEndpointDirectory>::success(
      RelayEndpointDirectory{std::make_unique<Impl>(config, std::move(*entries.value_if()))});
}

Result<void> RelayEndpointDirectory::publish(
    const RelayEndpointRecord& record,
    const std::optional<RelayServiceManifest>& manifest,
    const RelayDeviceRecord& device, std::string_view tenant,
    std::uint64_t now_unix_milliseconds,
    std::chrono::steady_clock::time_point now) {
  if (!impl_) {
    return Result<void>::failure(
        directory_error(ErrorCode::cancelled, "endpoint_directory_not_initialized"));
  }
  auto record_valid =
      validate_relay_endpoint_record(record, device, now_unix_milliseconds);
  if (!record_valid) {
    ++impl_->stats.validation_rejected;
    return Result<void>::failure(*record_valid.error_if());
  }
  if (manifest) {
    auto manifest_valid = validate_relay_service_manifest(
        *manifest, device, now_unix_milliseconds, record);
    if (!manifest_valid) {
      ++impl_->stats.validation_rejected;
      return Result<void>::failure(*manifest_valid.error_if());
    }
    if (manifest->expires_unix_milliseconds < record.expires_unix_milliseconds) {
      ++impl_->stats.validation_rejected;
      return Result<void>::failure(
          directory_error(ErrorCode::authentication, "endpoint_manifest_expires_before_record"));
    }
  }

  auto existing = impl_->entries.get(record.endpoint, now);
  if (existing) {
    if (existing->tenant != tenant) {
      ++impl_->stats.tenant_conflict_rejected;
      return Result<void>::failure(
          directory_error(ErrorCode::permission, "endpoint_directory_tenant_conflict"));
    }
    if (record.record_generation < existing->record.record_generation) {
      ++impl_->stats.validation_rejected;
      return Result<void>::failure(
          directory_error(ErrorCode::permission, "endpoint_record_generation_older"));
    }
    if (record.record_generation == existing->record.record_generation) {
      auto encoded_record = encode_relay_endpoint_record(record);
      auto encoded_existing = encode_relay_endpoint_record(existing->record);
      const bool same_record = encoded_record && encoded_existing &&
                               *encoded_record.value_if() == *encoded_existing.value_if();
      bool same_manifest = !manifest && !existing->manifest;
      if (manifest && existing->manifest) {
        auto encoded_manifest = encode_relay_service_manifest(*manifest);
        auto encoded_existing_manifest =
            encode_relay_service_manifest(*existing->manifest);
        same_manifest = encoded_manifest && encoded_existing_manifest &&
                        *encoded_manifest.value_if() ==
                            *encoded_existing_manifest.value_if();
      }
      if (!same_record || !same_manifest) {
        ++impl_->stats.validation_rejected;
        return Result<void>::failure(
            directory_error(ErrorCode::authentication,
                            "endpoint_record_generation_conflict"));
      }
    }
  }

  auto ttl = record_ttl(record.expires_unix_milliseconds, now_unix_milliseconds,
                        impl_->config.maximum_ttl);
  if (ttl.count() <= 0) {
    ++impl_->stats.validation_rejected;
    return Result<void>::failure(
        directory_error(ErrorCode::timeout, "endpoint_record_expired"));
  }
  auto stored = impl_->entries.upsert(
      record.endpoint,
      RelayEndpointDirectoryEntry{
          .record = record,
          .identity_public_key = device.public_key,
          .manifest = manifest,
          .tenant = std::string{tenant},
          .wall_clock_expires_unix_milliseconds = record.expires_unix_milliseconds},
      ttl, now);
  if (!stored) {
    if (stored.error_if()->code() == ErrorCode::resource_exhausted) {
      ++impl_->stats.capacity_rejected;
    }
    return Result<void>::failure(*stored.error_if());
  }
  if (*stored.value_if() == RelayTtlUpsertOutcome::inserted) {
    ++impl_->stats.published;
  } else {
    ++impl_->stats.updated;
  }
  impl_->stats.table = impl_->entries.diagnostics();
  return Result<void>::success();
}

Result<void> RelayEndpointDirectory::remove(const RelayEndpointKey& key) {
  if (!impl_) {
    return Result<void>::failure(
        directory_error(ErrorCode::cancelled, "endpoint_directory_not_initialized"));
  }
  if (impl_->entries.contains(key)) {
    auto erased = impl_->entries.erase(key);
    if (!erased) {
      return erased;
    }
    ++impl_->stats.removed;
    impl_->stats.table = impl_->entries.diagnostics();
  }
  return Result<void>::success();
}

std::optional<RelayEndpointDirectoryEntry> RelayEndpointDirectory::get(
    const RelayEndpointKey& key, std::chrono::steady_clock::time_point now) const {
  if (!impl_) {
    return std::nullopt;
  }
  return impl_->entries.get(key, now);
}

void RelayEndpointDirectory::expire(std::chrono::steady_clock::time_point now) {
  if (!impl_) {
    return;
  }
  const auto before = impl_->entries.diagnostics().current_entries;
  impl_->entries.expire(now);
  const auto after = impl_->entries.diagnostics().current_entries;
  if (after < before) {
    impl_->stats.expired += before - after;
  }
  impl_->stats.table = impl_->entries.diagnostics();
}

RelayEndpointDirectoryDiagnostics RelayEndpointDirectory::diagnostics() const noexcept {
  auto output = impl_ ? impl_->stats : RelayEndpointDirectoryDiagnostics{};
  if (impl_) {
    output.table = impl_->entries.diagnostics();
  }
  return output;
}

}  // namespace heyaki
