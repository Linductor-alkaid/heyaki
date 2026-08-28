#include "session_channels.hpp"

#include <heyaki/frame_stream.hpp>

#include <algorithm>
#include <iterator>
#include <utility>

namespace heyaki::session {
namespace {

Error channel_error(ErrorCode code, const char* detail) {
  return {code, "session_channels", detail};
}

// Weighted-round tokens refilled per scheduling cycle. Weights follow the
// architecture: control and interactive traffic preempt, standard follows,
// bulk consumes the remainder — but every class keeps a non-zero share, so a
// sustained flood in any class starves neither control nor bulk.
constexpr std::size_t frame_class_weight(FrameClass klass) {
  switch (klass) {
    case FrameClass::control:
      return 8U;
    case FrameClass::interactive:
      return 8U;
    case FrameClass::standard:
      return 4U;
    case FrameClass::bulk:
      return 1U;
  }
  return 1U;
}

std::size_t frame_wire_size(const Frame& frame, const Limits& limits) {
  FrameStreamEncoder encoder{limits};
  const auto size =
      encoder.encoded_size(frame.type, frame.flags, frame.channel_id, frame.payload.size());
  return *size.value_if();
}

}  // namespace

std::string_view channel_domain_name(ChannelDomain domain) noexcept {
  switch (domain) {
    case ChannelDomain::control:
      return "control";
    case ChannelDomain::message:
      return "message";
    case ChannelDomain::rpc:
      return "rpc";
    case ChannelDomain::event:
      return "event";
    case ChannelDomain::file:
      return "file";
    case ChannelDomain::shell:
      return "shell";
    case ChannelDomain::stream:
      return "stream";
  }
  return "unknown";
}

bool is_control_domain_frame_type(std::uint8_t frame_type) noexcept {
  return frame_type < static_cast<std::uint8_t>(FrameType::message);
}

std::optional<ChannelDomain> frame_type_domain(std::uint8_t frame_type) {
  const auto type = static_cast<FrameType>(frame_type);
  switch (type) {
    case FrameType::message:
    case FrameType::message_ack:
      return ChannelDomain::message;
    case FrameType::rpc_request:
    case FrameType::rpc_response:
    case FrameType::rpc_cancel:
      return ChannelDomain::rpc;
    case FrameType::event_subscribe:
    case FrameType::event_item:
    case FrameType::event_unsubscribe:
      return ChannelDomain::event;
    case FrameType::file_manifest:
    case FrameType::file_accept:
    case FrameType::file_chunk:
    case FrameType::file_complete:
    case FrameType::file_reject:
      return ChannelDomain::file;
    case FrameType::shell_open:
    case FrameType::shell_input:
    case FrameType::shell_output:
    case FrameType::shell_resize:
    case FrameType::shell_signal:
    case FrameType::shell_exit:
    case FrameType::shell_eof:
    case FrameType::shell_error:
    case FrameType::shell_close:
      return ChannelDomain::shell;
    case FrameType::stream_open:
    case FrameType::stream_data:
    case FrameType::stream_window_update:
    case FrameType::stream_fin:
    case FrameType::stream_reset:
      return ChannelDomain::stream;
    default:
      return std::nullopt;
  }
}

FrameClass default_frame_class(std::uint8_t frame_type) noexcept {
  const auto type = static_cast<FrameType>(frame_type);
  switch (type) {
    case FrameType::session_hello:
    case FrameType::protocol_close:
    case FrameType::ping:
    case FrameType::pong:
    case FrameType::cancel:
    case FrameType::session_restart_offer:
    case FrameType::session_restart_answer:
    case FrameType::session_restart_candidate:
    case FrameType::pairing_request:
    case FrameType::pairing_result:
      return FrameClass::control;
    case FrameType::stream_window_update:
    case FrameType::stream_reset:
    case FrameType::stream_fin:
    case FrameType::message_ack:
      // Small bookkeeping frames must keep flowing while bulk traffic floods
      // the association: window updates and resets are the stream escape
      // hatches, ACKs unblock the peer's send queue.
      return FrameClass::control;
    case FrameType::shell_input:
    case FrameType::shell_output:
    case FrameType::shell_resize:
    case FrameType::shell_signal:
      return FrameClass::interactive;
    case FrameType::file_chunk:
    case FrameType::event_item:
      return FrameClass::bulk;
    default:
      return FrameClass::standard;
  }
}

std::string_view queue_full_policy_name(QueueFullPolicy policy) noexcept {
  switch (policy) {
    case QueueFullPolicy::reject:
      return "reject";
    case QueueFullPolicy::drop_oldest:
      return "drop_oldest";
    case QueueFullPolicy::keep_latest:
      return "keep_latest";
  }
  return "unknown";
}

Result<void> validate_channel_budget_config(const ChannelBudgetConfig& config) {
  if (config.max_open_channels == 0U || config.max_open_channels > 1024U) {
    return Result<void>::failure(
        channel_error(ErrorCode::configuration, "max_open_channels_invalid"));
  }
  if (config.per_peer_queued_frames == 0U || config.per_peer_queued_bytes == 0U) {
    return Result<void>::failure(
        channel_error(ErrorCode::configuration, "per_peer_budget_invalid"));
  }
  if (config.control_reserved_frames == 0U || config.control_reserved_bytes == 0U) {
    return Result<void>::failure(
        channel_error(ErrorCode::configuration, "control_reservation_invalid"));
  }
  if (config.max_channel_queued_frames == 0U || config.max_channel_queued_bytes == 0U) {
    return Result<void>::failure(
        channel_error(ErrorCode::configuration, "channel_queue_bounds_invalid"));
  }
  if (config.control_reserved_frames > config.per_peer_queued_frames ||
      config.control_reserved_bytes > config.per_peer_queued_bytes) {
    return Result<void>::failure(
        channel_error(ErrorCode::configuration, "control_reservation_exceeds_budget"));
  }
  return Result<void>::success();
}

CapacityWaitTicket::CapacityWaitTicket(Control* control) : control_(control) {}

CapacityWaitTicket::CapacityWaitTicket(std::uint32_t channel_id, Completion completion) {
  control_ = new Control{};
  control_->channel_id = channel_id;
  control_->completion = std::move(completion);
}

CapacityWaitTicket::CapacityWaitTicket(CapacityWaitTicket&& other) noexcept
    : control_(std::exchange(other.control_, nullptr)) {}

CapacityWaitTicket& CapacityWaitTicket::operator=(CapacityWaitTicket&& other) noexcept {
  if (this != &other) {
    detach();
    control_ = std::exchange(other.control_, nullptr);
  }
  return *this;
}

CapacityWaitTicket::~CapacityWaitTicket() { detach(); }

void CapacityWaitTicket::detach() {
  if (control_ == nullptr) return;
  if (!control_->completed) {
    control_->completed = true;
    if (control_->completion) {
      control_->completion(Result<void>::failure(
          channel_error(ErrorCode::cancelled, "capacity_wait_cancelled")));
    }
  }
  if (control_->manager != nullptr) {
    control_->manager->detach_waiter(control_->waiter_id);
  }
  delete control_;
  control_ = nullptr;
}

void CapacityWaitTicket::cancel() { detach(); }

std::uint32_t CapacityWaitTicket::channel_id() const noexcept {
  return control_ == nullptr ? 0U : control_->channel_id;
}

void CapacityWaitTicket::complete(Result<void> result) {
  if (control_ == nullptr || control_->completed) return;
  control_->completed = true;
  if (control_->completion) control_->completion(std::move(result));
}

SessionChannelManager::SessionChannelManager(ChannelBudgetConfig config, Limits limits)
    : config_(config), limits_(limits) {
  for (std::uint8_t klass = static_cast<std::uint8_t>(FrameClass::control);
       klass <= static_cast<std::uint8_t>(FrameClass::bulk); ++klass) {
    class_state_[static_cast<FrameClass>(klass)] =
        ClassQueue{.tokens = frame_class_weight(static_cast<FrameClass>(klass))};
  }
}

SessionChannelManager::~SessionChannelManager() {
  // Outstanding tickets outliving the manager must not call back into it:
  // fail them here; their own destruction then only frees the control block.
  while (!waiters_.empty()) {
    const auto waiter_id = waiters_.begin()->first;
    complete_waiter(
        waiter_id,
        Result<void>::failure(channel_error(ErrorCode::cancelled, "session_channels_closed")));
  }
}

Result<void> SessionChannelManager::open_channel(std::uint32_t channel_id,
                                                 ChannelDomain domain,
                                                 QueueFullPolicy policy,
                                                 std::size_t queued_frame_capacity,
                                                 std::size_t queued_byte_capacity) {
  if (channel_id == 0U || domain == ChannelDomain::control) {
    return Result<void>::failure(
        channel_error(ErrorCode::configuration, "business_channel_id_invalid"));
  }
  if (channels_.size() >= config_.max_open_channels && !channels_.contains(channel_id)) {
    return Result<void>::failure(
        channel_error(ErrorCode::resource_exhausted, "open_channel_limit"));
  }
  if (queued_frame_capacity == 0U || queued_frame_capacity > config_.max_channel_queued_frames) {
    return Result<void>::failure(
        channel_error(ErrorCode::configuration, "channel_frame_capacity_invalid"));
  }
  if (queued_byte_capacity == 0U || queued_byte_capacity > config_.max_channel_queued_bytes) {
    return Result<void>::failure(
        channel_error(ErrorCode::configuration, "channel_byte_capacity_invalid"));
  }
  if (channels_.contains(channel_id)) {
    return Result<void>::failure(channel_error(ErrorCode::configuration, "channel_id_in_use"));
  }
  ChannelState state;
  state.domain = domain;
  state.policy = policy;
  state.queued_frame_capacity = queued_frame_capacity;
  state.queued_byte_capacity = queued_byte_capacity;
  channels_.emplace(channel_id, std::move(state));
  return Result<void>::success();
}

Result<std::uint32_t> SessionChannelManager::allocate_channel(
    bool initiator_role, ChannelDomain domain, QueueFullPolicy policy,
    std::size_t queued_frame_capacity, std::size_t queued_byte_capacity) {
  // The session initiator owns odd channel ids, the responder even ones.
  for (std::uint32_t candidate = initiator_role ? 1U : 2U;
       candidate < 2U * config_.max_open_channels + 2U; candidate += 2U) {
    if (!channels_.contains(candidate)) {
      auto opened = open_channel(candidate, domain, policy, queued_frame_capacity,
                                 queued_byte_capacity);
      if (!opened) {
        return Result<std::uint32_t>::failure(*opened.error_if());
      }
      return Result<std::uint32_t>::success(candidate);
    }
  }
  return Result<std::uint32_t>::failure(
      channel_error(ErrorCode::resource_exhausted, "channel_id_space_exhausted"));
}

void SessionChannelManager::close_channel(std::uint32_t channel_id) {
  auto iterator = channels_.find(channel_id);
  if (iterator == channels_.end()) return;
  auto& channel = iterator->second;
  channel.open = false;
  // Fail this channel's capacity waits first: the channel is gone.
  auto waiters = std::move(channel.waiters);
  channel.waiters.clear();
  for (auto waiter_id : waiters) {
    complete_waiter(waiter_id,
                    Result<void>::failure(
                        channel_error(ErrorCode::cancelled, "channel_closed")));
  }
  // Drop queued frames belonging to this channel from every class queue.
  for (auto& [klass, queue] : class_queues_) {
    std::erase_if(queue, [&](const QueuedSendFrame& queued) {
      return queued.channel_id == channel_id;
    });
  }
  business_queued_frames_ -=
      std::min(business_queued_frames_, channel.queued_frames);
  business_queued_bytes_ -= std::min(business_queued_bytes_, channel.queued_bytes);
  channels_.erase(iterator);
}

void SessionChannelManager::close_all() {
  auto ids = std::vector<std::uint32_t>{};
  ids.reserve(channels_.size());
  for (const auto& [id, channel] : channels_) {
    if (channel.open) ids.push_back(id);
  }
  for (auto id : ids) close_channel(id);
}

bool SessionChannelManager::has_channel(std::uint32_t channel_id) const noexcept {
  return channels_.contains(channel_id);
}

std::optional<ChannelDomain> SessionChannelManager::channel_domain(
    std::uint32_t channel_id) const noexcept {
  auto iterator = channels_.find(channel_id);
  if (iterator == channels_.end()) return std::nullopt;
  return iterator->second.domain;
}

std::size_t SessionChannelManager::open_channel_count() const noexcept {
  return channels_.size();
}

std::vector<SessionChannelSnapshot> SessionChannelManager::channel_snapshots() const {
  std::vector<SessionChannelSnapshot> snapshots;
  snapshots.reserve(channels_.size());
  for (const auto& [id, channel] : channels_) {
    snapshots.push_back(
        SessionChannelSnapshot{.channel_id = id,
                               .domain = channel.domain,
                               .open = channel.open,
                               .stats = channel.stats});
  }
  return snapshots;
}

Result<EnqueueReceipt> SessionChannelManager::enqueue(std::uint32_t channel_id,
                                                      FrameClass klass, Frame frame) {
  if (klass == FrameClass::control) {
    return enqueue_control(channel_id, klass, std::move(frame));
  }
  auto iterator = channels_.find(channel_id);
  if (iterator == channels_.end() || !iterator->second.open) {
    return Result<EnqueueReceipt>::failure(
        channel_error(ErrorCode::protocol, "channel_not_open"));
  }
  return enqueue_business(iterator->second, channel_id, klass, std::move(frame));
}

Result<EnqueueReceipt> SessionChannelManager::enqueue_control(std::uint32_t channel_id,
                                                              FrameClass klass,
                                                              Frame&& frame) {
  if (control_queued_frames_ + 1U > config_.control_reserved_frames) {
    return Result<EnqueueReceipt>::failure(
        channel_error(ErrorCode::would_block, "control_reservation_full"));
  }
  const auto size = frame_wire_size(frame, limits_);
  if (control_queued_bytes_ + size > config_.control_reserved_bytes) {
    return Result<EnqueueReceipt>::failure(
        channel_error(ErrorCode::would_block, "control_reservation_full"));
  }
  control_queued_frames_ += 1U;
  control_queued_bytes_ += size;
  class_queues_[static_cast<std::uint8_t>(klass)].push_back(
      QueuedSendFrame{.channel_id = channel_id, .frame_class = klass, .frame = std::move(frame)});
  return Result<EnqueueReceipt>::success(EnqueueReceipt{.admitted = true});
}

Result<EnqueueReceipt> SessionChannelManager::enqueue_business(ChannelState& channel,
                                                               std::uint32_t channel_id,
                                                               FrameClass klass,
                                                               Frame&& frame) {
  const auto size = frame_wire_size(frame, limits_);
  EnqueueReceipt receipt;
  const bool per_channel_full =
      channel.queued_frames + 1U > channel.queued_frame_capacity ||
      channel.queued_bytes + size > channel.queued_byte_capacity;
  const bool per_peer_full =
      business_queued_frames_ + 1U > config_.per_peer_queued_frames ||
      business_queued_bytes_ + size > config_.per_peer_queued_bytes;
  if (per_peer_full) {
    // Dropping another channel's frames to satisfy this one would silently
    // break that channel's semantics; peer-budget exhaustion always rejects.
    channel.stats.rejected_frames += 1U;
    return Result<EnqueueReceipt>::failure(
        channel_error(ErrorCode::would_block, "per_peer_budget_full"));
  }
  // keep_latest expresses "newest frame supersedes all older ones": the
  // eviction runs on every enqueue, not only when the queue is full, so the
  // channel never carries more than the latest frame.
  if (per_channel_full || channel.policy == QueueFullPolicy::keep_latest) {
    switch (channel.policy) {
      case QueueFullPolicy::reject:
        channel.stats.rejected_frames += 1U;
        return Result<EnqueueReceipt>::failure(
            channel_error(ErrorCode::would_block, "channel_queue_full"));
      case QueueFullPolicy::drop_oldest: {
        if (channel.queued_frames == 0U) break;
        std::uint64_t dropped_bytes = 0U;
        bool dropped = false;
        for (auto& [klass_key, queue] : class_queues_) {
          for (auto entry = queue.begin(); entry != queue.end(); ++entry) {
            if (entry->channel_id == channel_id) {
              dropped_bytes = frame_wire_size(entry->frame, limits_);
              queue.erase(entry);
              dropped = true;
              break;
            }
          }
          if (dropped) break;
        }
        if (dropped) {
          charge_drop(channel, 1U, dropped_bytes);
          receipt.dropped_previous = true;
          receipt.dropped_frames = 1U;
        }
        break;
      }
      case QueueFullPolicy::keep_latest: {
        std::uint64_t dropped_frames = 0U;
        std::uint64_t dropped_bytes = 0U;
        for (auto& [klass_key, queue] : class_queues_) {
          for (auto entry = queue.begin(); entry != queue.end();) {
            if (entry->channel_id == channel_id) {
              dropped_bytes += frame_wire_size(entry->frame, limits_);
              entry = queue.erase(entry);
              ++dropped_frames;
            } else {
              ++entry;
            }
          }
        }
        if (dropped_frames > 0U) {
          charge_drop(channel, dropped_frames, dropped_bytes);
          receipt.dropped_previous = true;
          receipt.dropped_frames = dropped_frames;
        }
        break;
      }
    }
  }
  // Re-check after eviction: if the frame still does not fit, reject.
  if (channel.queued_frames + 1U > channel.queued_frame_capacity ||
      channel.queued_bytes + size > channel.queued_byte_capacity) {
    channel.stats.rejected_frames += 1U;
    return Result<EnqueueReceipt>::failure(
        channel_error(ErrorCode::would_block, "channel_queue_full"));
  }
  channel.queued_frames += 1U;
  channel.queued_bytes += size;
  channel.stats.queued_frames += 1U;
  channel.stats.queued_bytes += size;
  business_queued_frames_ += 1U;
  business_queued_bytes_ += size;
  class_queues_[static_cast<std::uint8_t>(klass)].push_back(
      QueuedSendFrame{.channel_id = channel_id, .frame_class = klass, .frame = std::move(frame)});
  receipt.admitted = true;
  return Result<EnqueueReceipt>::success(std::move(receipt));
}

void SessionChannelManager::charge_drop(ChannelState& channel, std::uint64_t frames,
                                        std::uint64_t bytes) {
  channel.queued_frames -= std::min<std::size_t>(channel.queued_frames, frames);
  channel.queued_bytes -= std::min<std::size_t>(channel.queued_bytes, bytes);
  channel.stats.dropped_frames += frames;
  channel.stats.dropped_bytes += bytes;
  business_queued_frames_ -= std::min(business_queued_frames_, frames);
  business_queued_bytes_ -= std::min(business_queued_bytes_, bytes);
}

std::optional<QueuedSendFrame> SessionChannelManager::next_to_send() {
  for (std::uint8_t klass = static_cast<std::uint8_t>(FrameClass::control);
       klass <= static_cast<std::uint8_t>(FrameClass::bulk); ++klass) {
    auto& queue = class_queues_[klass];
    if (queue.empty()) continue;
    auto& state = class_state_[static_cast<FrameClass>(klass)];
    if (state.tokens == 0U) continue;
    auto queued = std::move(queue.front());
    queue.pop_front();
    state.tokens -= 1U;
    const auto size = frame_wire_size(queued.frame, limits_);
    if (queued.frame_class == FrameClass::control) {
      control_queued_frames_ -= 1U;
      control_queued_bytes_ -= std::min(control_queued_bytes_, size);
    } else {
      auto iterator = channels_.find(queued.channel_id);
      if (iterator != channels_.end()) {
        auto& channel = iterator->second;
        channel.queued_frames -= 1U;
        channel.queued_bytes -= std::min(channel.queued_bytes, size);
        channel.stats.sent_frames += 1U;
        channel.stats.sent_bytes += size;
        if (!channel.waiters.empty()) notify_capacity(queued.channel_id);
      }
      business_queued_frames_ -= 1U;
      business_queued_bytes_ -= std::min(business_queued_bytes_, size);
    }
    return queued;
  }
  // Every class with pending frames is out of tokens: refill and retry once.
  // This is the anti-starvation bound — bulk waits at most one weighted round
  // behind control, and control preempts bulk whenever it has tokens.
  const bool any_pending =
      std::any_of(class_queues_.begin(), class_queues_.end(),
                  [](const auto& entry) { return !entry.second.empty(); });
  if (!any_pending) return std::nullopt;
  refill_tokens();
  return next_to_send();
}

void SessionChannelManager::refill_tokens() {
  for (auto& [klass, state] : class_state_) {
    state.tokens = frame_class_weight(klass);
  }
}

void SessionChannelManager::return_to_send(QueuedSendFrame queued) {
  const auto size = frame_wire_size(queued.frame, limits_);
  if (queued.frame_class == FrameClass::control) {
    control_queued_frames_ += 1U;
    control_queued_bytes_ += size;
  } else {
    auto iterator = channels_.find(queued.channel_id);
    if (iterator != channels_.end()) {
      auto& channel = iterator->second;
      channel.queued_frames += 1U;
      channel.queued_bytes += size;
    }
    business_queued_frames_ += 1U;
    business_queued_bytes_ += size;
  }
  class_queues_[static_cast<std::uint8_t>(queued.frame_class)].push_front(std::move(queued));
}

bool SessionChannelManager::has_sendable_frames() const noexcept {
  return std::any_of(class_queues_.begin(), class_queues_.end(),
                     [](const auto& entry) { return !entry.second.empty(); });
}

std::size_t SessionChannelManager::total_queued_frames() const noexcept {
  return business_queued_frames_ + control_queued_frames_;
}

std::size_t SessionChannelManager::total_queued_bytes() const noexcept {
  return business_queued_bytes_ + control_queued_bytes_;
}

std::size_t SessionChannelManager::control_queued_frames() const noexcept {
  return control_queued_frames_;
}

std::size_t SessionChannelManager::control_queued_bytes() const noexcept {
  return control_queued_bytes_;
}

const ChannelBudgetConfig& SessionChannelManager::budget_config() const noexcept {
  return config_;
}

Result<CapacityWaitTicket> SessionChannelManager::wait_for_capacity(
    std::uint32_t channel_id, CapacityWaitTicket::Completion completion) {
  auto iterator = channels_.find(channel_id);
  if (iterator == channels_.end() || !iterator->second.open) {
    return Result<CapacityWaitTicket>::failure(
        channel_error(ErrorCode::protocol, "channel_not_open"));
  }
  auto& channel = iterator->second;
  if (channel.queued_frames < channel.queued_frame_capacity &&
      channel.queued_bytes < channel.queued_byte_capacity &&
      business_queued_frames_ < config_.per_peer_queued_frames) {
    // Capacity already exists; complete synchronously through an inert ticket
    // so the callback contract stays identical.
    CapacityWaitTicket immediate{channel_id, std::move(completion)};
    immediate.complete(Result<void>::success());
    return Result<CapacityWaitTicket>::success(std::move(immediate));
  }
  if (waiters_.size() >= waiter_capacity_) {
    return Result<CapacityWaitTicket>::failure(
        channel_error(ErrorCode::resource_exhausted, "capacity_waiter_limit"));
  }
  const auto waiter_id = next_waiter_id_++;
  auto ticket = CapacityWaitTicket(channel_id, std::move(completion));
  ticket.control_->waiter_id = waiter_id;
  ticket.control_->manager = this;
  waiters_.emplace(waiter_id, WaiterEntry{.ticket_control = ticket.control_});
  channel.waiters.push_back(waiter_id);
  return Result<CapacityWaitTicket>::success(std::move(ticket));
}

void SessionChannelManager::notify_capacity(std::uint32_t channel_id) {
  auto iterator = channels_.find(channel_id);
  if (iterator == channels_.end()) return;
  auto& channel = iterator->second;
  // Complete waiters while capacity for at least one more frame remains.
  while (!channel.waiters.empty() && channel.queued_frames < channel.queued_frame_capacity &&
         channel.queued_bytes < channel.queued_byte_capacity) {
    const auto waiter_id = channel.waiters.front();
    channel.waiters.erase(channel.waiters.begin());
    complete_waiter(waiter_id, Result<void>::success());
    channel.stats.capacity_waits_completed += 1U;
  }
}

void SessionChannelManager::complete_waiter(std::uint64_t waiter_id, Result<void> result) {
  auto waiter = waiters_.find(waiter_id);
  if (waiter == waiters_.end()) return;
  auto* control = waiter->second.ticket_control;
  waiters_.erase(waiter);
  if (control == nullptr) return;
  control->manager = nullptr;
  control->completed = true;
  if (control->completion) control->completion(std::move(result));
}

void SessionChannelManager::detach_waiter(std::uint64_t waiter_id) {
  waiters_.erase(waiter_id);
  for (auto& [id, channel] : channels_) {
    std::erase(channel.waiters, waiter_id);
  }
}

const Limits& SessionChannelManager::limits() const noexcept { return limits_; }

}  // namespace heyaki::session
