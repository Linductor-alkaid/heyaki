#include <heyaki/signaling_replay_cache.hpp>

#include <algorithm>
#include <memory>
#include <optional>
#include <utility>

#include <cstddef>
#include <cstdint>

namespace heyaki {
namespace {

constexpr std::uint8_t connect_request_replay_domain = 0xffU;

Error replay_error(const char* detail) {
  return Error{ErrorCode::resource_exhausted, "signaling_replay", detail};
}

struct ReplayKey {
  std::uint8_t domain{};
  DeviceId signer;
  RequestId request_id;
  SessionId session_id;
  SignalingNonce initiator_nonce{};
  bool has_responder_nonce{false};
  SignalingNonce responder_nonce{};
  bool has_sequence{false};
  std::uint32_t sequence{};

  friend constexpr bool operator<(const ReplayKey& lhs, const ReplayKey& rhs) noexcept {
    if (lhs.domain != rhs.domain) {
      return lhs.domain < rhs.domain;
    }
    if (lhs.signer != rhs.signer) {
      return lhs.signer < rhs.signer;
    }
    if (lhs.request_id != rhs.request_id) {
      return lhs.request_id < rhs.request_id;
    }
    if (lhs.session_id != rhs.session_id) {
      return lhs.session_id < rhs.session_id;
    }
    if (lhs.initiator_nonce != rhs.initiator_nonce) {
      return lhs.initiator_nonce < rhs.initiator_nonce;
    }
    if (lhs.has_responder_nonce != rhs.has_responder_nonce) {
      return lhs.has_responder_nonce < rhs.has_responder_nonce;
    }
    if (lhs.has_responder_nonce && rhs.has_responder_nonce &&
        lhs.responder_nonce != rhs.responder_nonce) {
      return lhs.responder_nonce < rhs.responder_nonce;
    }
    if (lhs.has_sequence != rhs.has_sequence) {
      return lhs.has_sequence < rhs.has_sequence;
    }
    if (lhs.has_sequence && rhs.has_sequence) {
      return lhs.sequence < rhs.sequence;
    }
    return false;
  }
};

}  // namespace

class SignalingReplayCache::Impl {
 public:
  explicit Impl(ReplayCachePolicy policy) : policy_(policy) {}

  Result<SignalingReplayDecision> admit(const ReplayKey& key,
                                        std::chrono::steady_clock::time_point now) {
    // The full-table sweep is throttled: admission runs per signed message and
    // must not scan the whole cache. Expired keys are still handled inline, so
    // correctness never depends on the sweep.
    if (now >= next_sweep_) {
      expire(now);
      next_sweep_ = now + std::chrono::seconds{1};
    }
    const auto ttl = std::chrono::milliseconds{policy_.ttl_milliseconds};
    if (auto it = entries_.find(key); it != entries_.end()) {
      if (now < it->second) {
        ++diagnostics_.duplicates_rejected;
        return Result<SignalingReplayDecision>::success(SignalingReplayDecision::duplicate);
      }
      evict_entry(it);
    }
    auto& peer_count = per_peer_[key.signer];
    if (peer_count >= policy_.per_peer_capacity) {
      ++diagnostics_.per_peer_rejected;
      ++diagnostics_.capacity_rejected;
      return Result<SignalingReplayDecision>::success(
          SignalingReplayDecision::capacity_rejected);
    }
    if (entries_.size() >= policy_.capacity) {
      ++diagnostics_.capacity_rejected;
      return Result<SignalingReplayDecision>::success(
          SignalingReplayDecision::capacity_rejected);
    }
    entries_.emplace(key, now + ttl);
    ++peer_count;
    ++diagnostics_.admitted;
    diagnostics_.current_entries = entries_.size();
    diagnostics_.peak_entries = std::max(diagnostics_.peak_entries, entries_.size());
    diagnostics_.peak_per_peer_entries =
        std::max(diagnostics_.peak_per_peer_entries, peer_count);
    return Result<SignalingReplayDecision>::success(SignalingReplayDecision::admitted);
  }

  void expire(std::chrono::steady_clock::time_point now) {
    for (auto it = entries_.begin(); it != entries_.end();) {
      if (now >= it->second) {
        it = evict_entry(it);
      } else {
        ++it;
      }
    }
    diagnostics_.current_entries = entries_.size();
  }

  SignalingReplayDiagnostics diagnostics() const noexcept { return diagnostics_; }

 private:
  using EntryIterator =
      std::map<ReplayKey, std::chrono::steady_clock::time_point>::iterator;

  EntryIterator evict_entry(EntryIterator it) {
    const auto signer = it->first.signer;
    auto peer = per_peer_.find(signer);
    if (peer != per_peer_.end() && peer->second > 0U) {
      --peer->second;
      if (peer->second == 0U) {
        per_peer_.erase(peer);
      }
    }
    const auto next = entries_.erase(it);
    ++diagnostics_.expired_evicted;
    return next;
  }

  ReplayCachePolicy policy_;
  std::map<ReplayKey, std::chrono::steady_clock::time_point> entries_;
  std::map<DeviceId, std::size_t> per_peer_;
  std::chrono::steady_clock::time_point next_sweep_{};
  SignalingReplayDiagnostics diagnostics_;
};

SignalingReplayCache::SignalingReplayCache(SignalingReplayCache&& other) noexcept = default;
SignalingReplayCache& SignalingReplayCache::operator=(SignalingReplayCache&&) noexcept =
    default;
SignalingReplayCache::~SignalingReplayCache() = default;

Result<SignalingReplayCache> SignalingReplayCache::create(ReplayCachePolicy policy) {
  auto validated = validate_security_policy(policy, PasswordSecurityPolicy{});
  if (!validated) {
    return Result<SignalingReplayCache>::failure(*validated.error_if());
  }
  if (policy.capacity < policy.per_peer_capacity) {
    return Result<SignalingReplayCache>::failure(
        replay_error("replay_capacity_below_per_peer"));
  }
  return Result<SignalingReplayCache>::success(
      SignalingReplayCache(std::make_unique<Impl>(policy)));
}

Result<SignalingReplayDecision> SignalingReplayCache::admit(
    SigningDomain domain, const DeviceId& signer, const RequestId& request_id,
    const SessionId& session_id, const SignalingNonce& initiator_nonce,
    const std::optional<SignalingNonce>& responder_nonce,
    const std::optional<std::uint32_t>& sequence,
    std::chrono::steady_clock::time_point now) {
  if (signer.is_zero()) {
    return Result<SignalingReplayDecision>::failure(replay_error("replay_signer_zero"));
  }
  ReplayKey key;
  key.domain = static_cast<std::uint8_t>(domain);
  key.signer = signer;
  key.request_id = request_id;
  key.session_id = session_id;
  key.initiator_nonce = initiator_nonce;
  key.has_responder_nonce = responder_nonce.has_value();
  if (responder_nonce.has_value()) {
    key.responder_nonce = *responder_nonce;
  }
  key.has_sequence = sequence.has_value();
  if (sequence.has_value()) {
    key.sequence = *sequence;
  }
  return impl_->admit(key, now);
}

Result<SignalingReplayDecision> SignalingReplayCache::admit_connect_request(
    const DeviceId& sender, const RequestId& request_id,
    std::chrono::steady_clock::time_point now) {
  if (sender.is_zero() || request_id.is_zero()) {
    return Result<SignalingReplayDecision>::failure(
        replay_error("connect_request_replay_key_zero"));
  }
  ReplayKey key;
  key.domain = connect_request_replay_domain;
  key.signer = sender;
  key.request_id = request_id;
  return impl_->admit(key, now);
}

void SignalingReplayCache::expire(std::chrono::steady_clock::time_point now) {
  impl_->expire(now);
}

SignalingReplayDiagnostics SignalingReplayCache::diagnostics() const noexcept {
  return impl_->diagnostics();
}

SignalingReplayCache::SignalingReplayCache(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

}  // namespace heyaki
