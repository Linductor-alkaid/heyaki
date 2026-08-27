#pragma once

#include <heyaki/error.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace heyaki {

enum class RelayTtlUpsertOutcome : std::uint8_t {
  inserted,
  updated,
};

template <typename Key, typename Value>
struct RelayTtlEntry {
  Key key;
  Value value;
  std::chrono::steady_clock::time_point expires_at;
};

struct RelayTtlDiagnostics {
  std::uint64_t accepted{};
  std::uint64_t updated{};
  std::uint64_t capacity_rejected{};
  std::uint64_t expired{};
  std::size_t current_entries{};
  std::size_t peak_entries{};
};

template <typename Key, typename Value>
class RelayTtlTable {
 public:
  struct Impl;

  RelayTtlTable(RelayTtlTable&&) noexcept;
  RelayTtlTable& operator=(RelayTtlTable&&) noexcept;
  ~RelayTtlTable();

  RelayTtlTable(const RelayTtlTable&) = delete;
  RelayTtlTable& operator=(const RelayTtlTable&) = delete;

  [[nodiscard]] static Result<RelayTtlTable> create(std::size_t capacity);

  [[nodiscard]] Result<RelayTtlUpsertOutcome> upsert(
      Key key, Value value, std::chrono::milliseconds ttl,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  [[nodiscard]] std::optional<Value> get(
      const Key& key,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const;
  [[nodiscard]] bool contains(
      const Key& key,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const;
  [[nodiscard]] Result<void> erase(const Key& key);
  [[nodiscard]] std::optional<Value> take(
      const Key& key,
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  void expire(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
  [[nodiscard]] std::vector<RelayTtlEntry<Key, Value>> snapshot(
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const;
  [[nodiscard]] RelayTtlDiagnostics diagnostics() const noexcept;

 private:
  explicit RelayTtlTable(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

template <typename Key, typename Value>
struct RelayTtlTable<Key, Value>::Impl {
  explicit Impl(std::size_t capacity_value) : capacity(capacity_value) {}

  std::size_t capacity{};
  std::map<Key, RelayTtlEntry<Key, Value>, std::less<>> entries;
  RelayTtlDiagnostics stats;
};

template <typename Key, typename Value>
RelayTtlTable<Key, Value>::RelayTtlTable(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

template <typename Key, typename Value>
RelayTtlTable<Key, Value>::RelayTtlTable(RelayTtlTable&&) noexcept = default;

template <typename Key, typename Value>
RelayTtlTable<Key, Value>& RelayTtlTable<Key, Value>::operator=(
    RelayTtlTable&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}

template <typename Key, typename Value>
RelayTtlTable<Key, Value>::~RelayTtlTable() = default;

template <typename Key, typename Value>
Result<RelayTtlTable<Key, Value>> RelayTtlTable<Key, Value>::create(
    std::size_t capacity) {
  if (capacity == 0U) {
    return Result<RelayTtlTable>::failure(
        Error{ErrorCode::configuration, "relay_ttl", "relay_ttl_capacity_invalid"});
  }
  return Result<RelayTtlTable>::success(
      RelayTtlTable{std::make_unique<Impl>(capacity)});
}

template <typename Key, typename Value>
Result<RelayTtlUpsertOutcome> RelayTtlTable<Key, Value>::upsert(
    Key key, Value value, std::chrono::milliseconds ttl,
    std::chrono::steady_clock::time_point now) {
  if (!impl_) {
    return Result<RelayTtlUpsertOutcome>::failure(
        Error{ErrorCode::cancelled, "relay_ttl", "relay_ttl_not_initialized"});
  }
  if (ttl.count() <= 0) {
    return Result<RelayTtlUpsertOutcome>::failure(
        Error{ErrorCode::configuration, "relay_ttl", "relay_ttl_ttl_invalid"});
  }

  auto existing = impl_->entries.find(key);
  if (existing != impl_->entries.end()) {
    if (existing->second.expires_at > now) {
      existing->second.value = std::move(value);
      existing->second.expires_at = now + ttl;
      ++impl_->stats.updated;
      return Result<RelayTtlUpsertOutcome>::success(RelayTtlUpsertOutcome::updated);
    }
    impl_->entries.erase(existing);
    ++impl_->stats.expired;
    impl_->stats.current_entries = impl_->entries.size();
  }

  if (impl_->entries.size() >= impl_->capacity) {
    // Capacity pressure first evicts already-expired entries so abandoned
    // challenges cannot lock out new ones; rejection only happens when the
    // table is full of live entries.
    expire(now);
    if (impl_->entries.size() >= impl_->capacity) {
      ++impl_->stats.capacity_rejected;
      return Result<RelayTtlUpsertOutcome>::failure(
          Error{ErrorCode::resource_exhausted, "relay_ttl", "relay_ttl_capacity_exhausted"});
    }
  }

  const RelayTtlEntry<Key, Value> entry{.key = key,
                                        .value = std::move(value),
                                        .expires_at = now + ttl};
  impl_->entries.emplace(key, entry);
  ++impl_->stats.accepted;
  impl_->stats.current_entries = impl_->entries.size();
  impl_->stats.peak_entries = std::max(impl_->stats.peak_entries, impl_->entries.size());
  return Result<RelayTtlUpsertOutcome>::success(RelayTtlUpsertOutcome::inserted);
}

template <typename Key, typename Value>
std::optional<Value> RelayTtlTable<Key, Value>::get(const Key& key,
                                                    std::chrono::steady_clock::time_point now) const {
  if (!impl_) {
    return std::nullopt;
  }
  const auto found = impl_->entries.find(key);
  if (found == impl_->entries.end() || found->second.expires_at <= now) {
    return std::nullopt;
  }
  return found->second.value;
}

template <typename Key, typename Value>
bool RelayTtlTable<Key, Value>::contains(const Key& key,
                                         std::chrono::steady_clock::time_point now) const {
  return get(key, now).has_value();
}

template <typename Key, typename Value>
Result<void> RelayTtlTable<Key, Value>::erase(const Key& key) {
  if (!impl_) {
    return Result<void>::failure(
        Error{ErrorCode::cancelled, "relay_ttl", "relay_ttl_not_initialized"});
  }
  const auto erased = impl_->entries.erase(key);
  if (erased > 0U) {
    impl_->stats.current_entries = impl_->entries.size();
  }
  return Result<void>::success();
}

template <typename Key, typename Value>
std::optional<Value> RelayTtlTable<Key, Value>::take(const Key& key,
                                                    std::chrono::steady_clock::time_point now) {
  if (!impl_) {
    return std::nullopt;
  }
  const auto found = impl_->entries.find(key);
  if (found == impl_->entries.end()) {
    return std::nullopt;
  }
  if (found->second.expires_at <= now) {
    impl_->entries.erase(found);
    ++impl_->stats.expired;
    impl_->stats.current_entries = impl_->entries.size();
    return std::nullopt;
  }
  std::optional<Value> output{std::move(found->second.value)};
  impl_->entries.erase(found);
  impl_->stats.current_entries = impl_->entries.size();
  return output;
}

template <typename Key, typename Value>
void RelayTtlTable<Key, Value>::expire(std::chrono::steady_clock::time_point now) {
  if (!impl_) {
    return;
  }
  for (auto iterator = impl_->entries.begin(); iterator != impl_->entries.end();) {
    if (iterator->second.expires_at <= now) {
      iterator = impl_->entries.erase(iterator);
      ++impl_->stats.expired;
    } else {
      ++iterator;
    }
  }
  impl_->stats.current_entries = impl_->entries.size();
}

template <typename Key, typename Value>
std::vector<RelayTtlEntry<Key, Value>> RelayTtlTable<Key, Value>::snapshot(
    std::chrono::steady_clock::time_point now) const {
  std::vector<RelayTtlEntry<Key, Value>> output;
  if (!impl_) {
    return output;
  }
  for (const auto& [key, entry] : impl_->entries) {
    if (entry.expires_at > now) {
      output.push_back(entry);
    }
  }
  return output;
}

template <typename Key, typename Value>
RelayTtlDiagnostics RelayTtlTable<Key, Value>::diagnostics() const noexcept {
  return impl_ ? impl_->stats : RelayTtlDiagnostics{};
}

}  // namespace heyaki
