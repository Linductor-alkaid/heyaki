#include "relay_rate_limiter.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace heyaki {
namespace {

constexpr std::uint64_t micro_units_per_token = 1000000U;

Error limiter_error(ErrorCode code, const char* detail) {
  return Error{code, "relay_rate_limit", detail};
}

bool valid_key(std::string_view value, std::size_t maximum) noexcept {
  if (value.empty() || value.size() > maximum) {
    return false;
  }
  for (const char raw : value) {
    const auto character = static_cast<unsigned char>(raw);
    if (character < 0x21U || character > 0x7eU) {
      return false;
    }
  }
  return true;
}

bool valid_rule(const RelayRateLimitRule& rule) {
  return rule.capacity > 0U && rule.capacity <= 1000000U && rule.window.count() > 0 &&
         rule.window.count() <= 3600000 && rule.max_keys > 0U && rule.max_keys <= 1000000U;
}

std::int64_t elapsed_milliseconds(std::chrono::steady_clock::time_point from,
                                  std::chrono::steady_clock::time_point to) {
  return std::max<std::int64_t>(
      0, std::chrono::duration_cast<std::chrono::milliseconds>(to - from).count());
}

struct Bucket {
  std::uint64_t available_micro_tokens{};
  std::chrono::steady_clock::time_point last_refill;
};

struct ScopeState {
  RelayRateLimitRule rule;
  std::map<std::string, Bucket, std::less<>> buckets;

  void refill(Bucket& bucket, std::chrono::steady_clock::time_point now) {
    const auto elapsed =
        std::min<std::int64_t>(elapsed_milliseconds(bucket.last_refill, now),
                               rule.window.count());
    if (elapsed <= 0) {
      return;
    }
    const auto full_micro = static_cast<std::uint64_t>(rule.capacity) *
                            micro_units_per_token;
    const auto refill_per_millisecond =
        full_micro / static_cast<std::uint64_t>(rule.window.count());
    const auto credit = refill_per_millisecond * static_cast<std::uint64_t>(elapsed);
    bucket.available_micro_tokens =
        std::min(full_micro, bucket.available_micro_tokens + credit);
    bucket.last_refill = now;
  }

  void prune(std::chrono::steady_clock::time_point now,
             std::chrono::milliseconds entry_ttl) {
    for (auto iterator = buckets.begin(); iterator != buckets.end();) {
      if (elapsed_milliseconds(iterator->second.last_refill, now) >= entry_ttl.count()) {
        iterator = buckets.erase(iterator);
      } else {
        ++iterator;
      }
    }
  }
};

}  // namespace

struct RelayRateLimiter::Impl {
  explicit Impl(RelayRateLimitPolicy policy_value) : policy(std::move(policy_value)) {
    connection.rule = policy.connection;
    request.rule = policy.request;
    tenant.rule = policy.tenant;
    ip.rule = policy.ip;
  }

  Result<void> admit(RelayRateLimitScope scope, std::string_view key,
                     std::chrono::steady_clock::time_point now) {
    ScopeState* state = nullptr;
    RelayRateLimitCounters* counters = nullptr;
    switch (scope) {
      case RelayRateLimitScope::connection:
        state = &connection;
        counters = &diagnostics.connection;
        break;
      case RelayRateLimitScope::request:
        state = &request;
        counters = &diagnostics.request;
        break;
      case RelayRateLimitScope::tenant:
        state = &tenant;
        counters = &diagnostics.tenant;
        break;
      case RelayRateLimitScope::ip:
        state = &ip;
        counters = &diagnostics.ip;
        break;
    }
    if (state == nullptr) {
      return Result<void>::failure(limiter_error(ErrorCode::configuration,
                                                 "rate_limit_scope_invalid"));
    }

    if (scope != RelayRateLimitScope::request && !valid_key(key, 128U)) {
      return Result<void>::failure(limiter_error(ErrorCode::configuration,
                                                 "rate_limit_key_invalid"));
    }

    const std::string lookup_key =
        scope == RelayRateLimitScope::request ? std::string{} : std::string{key};
    auto found = state->buckets.find(lookup_key);
    if (found == state->buckets.end()) {
      if (state->buckets.size() >= state->rule.max_keys) {
        state->prune(now, policy.entry_ttl);
        counters->current_keys = state->buckets.size();
      }
      if (state->buckets.size() >= state->rule.max_keys) {
        ++counters->capacity_rejected;
        return Result<void>::failure(limiter_error(ErrorCode::resource_exhausted,
                                                   "rate_limit_key_capacity_exhausted"));
      }
      const auto full_micro = static_cast<std::uint64_t>(state->rule.capacity) *
                              micro_units_per_token;
      found = state->buckets.emplace(lookup_key,
                                     Bucket{.available_micro_tokens = full_micro,
                                            .last_refill = now})
                  .first;
      counters->current_keys = state->buckets.size();
      counters->peak_keys = std::max(counters->peak_keys, counters->current_keys);
    }

    Bucket& bucket = found->second;
    state->refill(bucket, now);
    if (bucket.available_micro_tokens < micro_units_per_token) {
      ++counters->rejected;
      return Result<void>::failure(limiter_error(ErrorCode::resource_exhausted,
                                                 "rate_limit_exceeded"));
    }
    bucket.available_micro_tokens -= micro_units_per_token;
    ++counters->allowed;
    return Result<void>::success();
  }

  RelayRateLimitPolicy policy;
  ScopeState connection;
  ScopeState request;
  ScopeState tenant;
  ScopeState ip;
  RelayRateLimitDiagnostics diagnostics;
};

RelayRateLimiter::RelayRateLimiter(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}
RelayRateLimiter::RelayRateLimiter(RelayRateLimiter&&) noexcept = default;
RelayRateLimiter& RelayRateLimiter::operator=(RelayRateLimiter&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}
RelayRateLimiter::~RelayRateLimiter() = default;

Result<void> RelayRateLimiter::validate_policy(const RelayRateLimitPolicy& policy) {
  if (!valid_rule(policy.connection) || !valid_rule(policy.request) ||
      !valid_rule(policy.tenant) || !valid_rule(policy.ip) ||
      policy.entry_ttl.count() <= 0 || policy.entry_ttl.count() > 3600000) {
    return Result<void>::failure(limiter_error(ErrorCode::configuration,
                                               "rate_limit_policy_invalid"));
  }
  return Result<void>::success();
}

Result<RelayRateLimiter> RelayRateLimiter::create(const RelayRateLimitPolicy& policy) {
  auto valid = validate_policy(policy);
  if (!valid) {
    return Result<RelayRateLimiter>::failure(*valid.error_if());
  }
  return Result<RelayRateLimiter>::success(
      RelayRateLimiter{std::make_unique<Impl>(policy)});
}

Result<void> RelayRateLimiter::check_connection(
    std::string_view connection_id, std::chrono::steady_clock::time_point now) {
  return impl_ ? impl_->admit(RelayRateLimitScope::connection, connection_id, now)
               : Result<void>::failure(
                     limiter_error(ErrorCode::cancelled, "rate_limiter_not_initialized"));
}

Result<void> RelayRateLimiter::check_request(std::chrono::steady_clock::time_point now) {
  return impl_ ? impl_->admit(RelayRateLimitScope::request, {}, now)
               : Result<void>::failure(
                     limiter_error(ErrorCode::cancelled, "rate_limiter_not_initialized"));
}

Result<void> RelayRateLimiter::check_tenant(std::string_view tenant,
                                            std::chrono::steady_clock::time_point now) {
  return impl_ ? impl_->admit(RelayRateLimitScope::tenant, tenant, now)
               : Result<void>::failure(
                     limiter_error(ErrorCode::cancelled, "rate_limiter_not_initialized"));
}

Result<void> RelayRateLimiter::check_ip(std::string_view ip,
                                        std::chrono::steady_clock::time_point now) {
  return impl_ ? impl_->admit(RelayRateLimitScope::ip, ip, now)
               : Result<void>::failure(
                     limiter_error(ErrorCode::cancelled, "rate_limiter_not_initialized"));
}

void RelayRateLimiter::prune(std::chrono::steady_clock::time_point now) {
  if (!impl_) {
    return;
  }
  impl_->connection.prune(now, impl_->policy.entry_ttl);
  impl_->request.prune(now, impl_->policy.entry_ttl);
  impl_->tenant.prune(now, impl_->policy.entry_ttl);
  impl_->ip.prune(now, impl_->policy.entry_ttl);
  impl_->diagnostics.connection.current_keys = impl_->connection.buckets.size();
  impl_->diagnostics.request.current_keys = impl_->request.buckets.size();
  impl_->diagnostics.tenant.current_keys = impl_->tenant.buckets.size();
  impl_->diagnostics.ip.current_keys = impl_->ip.buckets.size();
}

RelayRateLimitDiagnostics RelayRateLimiter::diagnostics() const noexcept {
  return impl_ ? impl_->diagnostics : RelayRateLimitDiagnostics{};
}

std::string_view relay_rate_limit_scope_name(RelayRateLimitScope scope) noexcept {
  switch (scope) {
    case RelayRateLimitScope::connection:
      return "connection";
    case RelayRateLimitScope::request:
      return "request";
    case RelayRateLimitScope::tenant:
      return "tenant";
    case RelayRateLimitScope::ip:
      return "ip";
  }
  return "unknown";
}

}  // namespace heyaki
