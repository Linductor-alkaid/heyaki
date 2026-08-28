#pragma once

// Session-level logical channels, budgets, and weighted send scheduling
// (M5-02..M5-06). One SessionChannelManager lives inside each PeerSession.
//
// Layout (architecture 7.3/9.2, wire protocol 2/3):
//   * channel 0 is the control channel; session, pairing, and liveness frames
//     ride it and are charged to a reserved control budget that bulk business
//     traffic can never consume.
//   * business frames ride non-zero logical channels; each channel belongs to
//     exactly one domain. The session initiator allocates odd channel ids and
//     the responder even ids, so both sides open channels without collisions
//     or extra negotiation.
//   * every queue is bounded by frames AND bytes; a full queue applies its
//     domain-chosen policy (reject / drop-oldest / keep-latest) and stays
//     observable. Silent loss is never an option.
//   * weighted scheduling picks control/interactive before standard before
//     bulk with a deficit round, so control survives file/event floods and
//     bulk still makes progress under sustained control load (no starvation).

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/limits.hpp>
#include <heyaki/wire.hpp>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <vector>

namespace heyaki::session {

enum class ChannelDomain : std::uint8_t {
  control = 0,
  message,
  rpc,
  event,
  file,
  shell,
  stream,
};

[[nodiscard]] std::string_view channel_domain_name(ChannelDomain domain) noexcept;
// True for frame types that belong on channel 0.
[[nodiscard]] bool is_control_domain_frame_type(std::uint8_t frame_type) noexcept;
// The domain a business frame type belongs to; nullopt for control/pairing
// frames (they are not bound to a business channel).
[[nodiscard]] std::optional<ChannelDomain> frame_type_domain(std::uint8_t frame_type);

// Scheduling classes in priority order. Weighted round-robin weights live in
// the scheduler; class order only defines priority.
enum class FrameClass : std::uint8_t {
  control = 0,
  interactive = 1,
  standard = 2,
  bulk = 3,
};

// Default class for a frame type when the caller has no domain-specific
// knowledge (shell data is interactive, file chunks and event items are bulk,
// window updates/resets/fins are control-class even on business channels).
[[nodiscard]] FrameClass default_frame_class(std::uint8_t frame_type) noexcept;

// M5-03: peer-level budgets. Validation failure at session start is a
// configuration error, never a silent clamp.
struct ChannelBudgetConfig {
  // Maximum simultaneously open logical business channels.
  std::size_t max_open_channels{16U};
  // Total business frames queued for this peer across all channels.
  std::size_t per_peer_queued_frames{1024U};
  // Total business bytes queued for this peer across all channels.
  std::size_t per_peer_queued_bytes{8U * 1024U * 1024U};
  // Control-class frames are charged here, never to the business budget.
  std::size_t control_reserved_frames{64U};
  std::size_t control_reserved_bytes{64U * 1024U};
  // Upper bound for per-channel queue configuration.
  std::size_t max_channel_queued_frames{1024U};
  std::size_t max_channel_queued_bytes{8U * 1024U * 1024U};
};

[[nodiscard]] Result<void> validate_channel_budget_config(
    const ChannelBudgetConfig& config);

// M5-05: full-queue semantics chosen per channel by the owning service.
enum class QueueFullPolicy : std::uint8_t {
  // Reject with would_block; callers may wait_for_capacity.
  reject,
  // Evict the oldest queued frame of the same channel (counted), then admit.
  drop_oldest,
  // The newest frame supersedes all older queued frames of the channel.
  keep_latest,
};

[[nodiscard]] std::string_view queue_full_policy_name(QueueFullPolicy policy) noexcept;

struct ChannelQueueStats {
  std::uint64_t queued_frames{};
  std::uint64_t queued_bytes{};
  std::uint64_t sent_frames{};
  std::uint64_t sent_bytes{};
  std::uint64_t dropped_frames{};
  std::uint64_t dropped_bytes{};
  std::uint64_t rejected_frames{};
  std::uint64_t capacity_waits_completed{};
};

struct SessionChannelSnapshot {
  std::uint32_t channel_id{};
  ChannelDomain domain{ChannelDomain::message};
  bool open{false};
  ChannelQueueStats stats;
};

struct QueuedSendFrame {
  std::uint32_t channel_id{};
  FrameClass frame_class{FrameClass::standard};
  Frame frame;
};

struct EnqueueReceipt {
  bool admitted{false};
  bool dropped_previous{false};
  std::uint64_t dropped_frames{};
};

// Cancellable capacity wait (M5-05). A ticket is one pending callback; it
// completes exactly once, either with success when the channel has capacity
// for one more frame or with a cancelled/failed error. The ticket owns its
// state: destroying or cancelling it deregisters from the manager.
class SessionChannelManager;

class CapacityWaitTicket {
 public:
  using Completion = std::function<void(Result<void>)>;

  CapacityWaitTicket() = default;
  // Registers nothing by itself; used as a null ticket.
  explicit CapacityWaitTicket(std::uint32_t channel_id, Completion completion);
  ~CapacityWaitTicket();

  CapacityWaitTicket(CapacityWaitTicket&&) noexcept;
  CapacityWaitTicket& operator=(CapacityWaitTicket&&) noexcept;
  CapacityWaitTicket(const CapacityWaitTicket&) = delete;
  CapacityWaitTicket& operator=(const CapacityWaitTicket&) = delete;

  void cancel();
  [[nodiscard]] bool active() const noexcept { return control_ != nullptr; }
  [[nodiscard]] std::uint32_t channel_id() const noexcept;

 private:
  friend class SessionChannelManager;
  struct Control {
    std::uint32_t channel_id{};
    std::uint64_t waiter_id{};
    Completion completion;
    bool completed{false};
    SessionChannelManager* manager{nullptr};
  };

  explicit CapacityWaitTicket(Control* control);
  void detach();
  void complete(Result<void> result);

  Control* control_{nullptr};
};

class SessionChannelManager {
 public:
  SessionChannelManager(ChannelBudgetConfig config, Limits limits = {});
  ~SessionChannelManager();

  SessionChannelManager(const SessionChannelManager&) = delete;
  SessionChannelManager& operator=(const SessionChannelManager&) = delete;

  // Opens a logical channel with an explicit id (must be non-zero, unused,
  // and within the open-channel budget).
  [[nodiscard]] Result<void> open_channel(std::uint32_t channel_id, ChannelDomain domain,
                                          QueueFullPolicy policy,
                                          std::size_t queued_frame_capacity,
                                          std::size_t queued_byte_capacity);
  // Allocates the next free id with the parity for `initiator_role` and opens
  // the channel on it.
  [[nodiscard]] Result<std::uint32_t> allocate_channel(bool initiator_role,
                                                       ChannelDomain domain,
                                                       QueueFullPolicy policy,
                                                       std::size_t queued_frame_capacity,
                                                       std::size_t queued_byte_capacity);

  // M5-06: local close of one logical channel. Drops only that channel's
  // queued frames and fails only that channel's capacity waits; the session
  // and its other channels are unaffected.
  void close_channel(std::uint32_t channel_id);
  void close_all();

  [[nodiscard]] bool has_channel(std::uint32_t channel_id) const noexcept;
  [[nodiscard]] std::optional<ChannelDomain> channel_domain(
      std::uint32_t channel_id) const noexcept;
  [[nodiscard]] std::size_t open_channel_count() const noexcept;
  [[nodiscard]] std::vector<SessionChannelSnapshot> channel_snapshots() const;

  // Enqueues one frame for transmission.
  //   * control-class frames are charged against the control reservation and
  //     never against business budgets;
  //   * business frames are charged against the per-channel queue and the
  //     per-peer budget;
  //   * a full per-channel queue applies the channel policy; per-peer budget
  //     exhaustion always rejects with would_block.
  [[nodiscard]] Result<EnqueueReceipt> enqueue(std::uint32_t channel_id, FrameClass klass,
                                               Frame frame);

  // Weighted pick of the next frame to transmit. Control-class frames on any
  // channel preempt business traffic; within each class transmission rotates
  // across channels; the deficit round guarantees bulk progress.
  [[nodiscard]] std::optional<QueuedSendFrame> next_to_send();
  // Returns the frame to the queue head without transmitting it (used when
  // the underlying transport is not writable). Does not double-charge budgets.
  void return_to_send(QueuedSendFrame queued);

  [[nodiscard]] bool has_sendable_frames() const noexcept;
  [[nodiscard]] std::size_t total_queued_frames() const noexcept;
  [[nodiscard]] std::size_t total_queued_bytes() const noexcept;
  [[nodiscard]] std::size_t control_queued_frames() const noexcept;
  [[nodiscard]] std::size_t control_queued_bytes() const noexcept;
  [[nodiscard]] const ChannelBudgetConfig& budget_config() const noexcept;

  // Registers a cancellable wait for one frame of capacity on `channel_id`.
  // The callback fires when capacity appears (including after drops by
  // drop-oldest/keep_latest policies and channel closes report failure), or
  // immediately with would_block when the waiter capacity is itself exhausted.
  [[nodiscard]] Result<CapacityWaitTicket> wait_for_capacity(
      std::uint32_t channel_id, CapacityWaitTicket::Completion completion);

  [[nodiscard]] const Limits& limits() const noexcept;

 private:
  struct ChannelState {
    ChannelDomain domain{ChannelDomain::message};
    QueueFullPolicy policy{QueueFullPolicy::reject};
    std::size_t queued_frame_capacity{};
    std::size_t queued_byte_capacity{};
    std::size_t queued_frames{};
    std::size_t queued_bytes{};
    ChannelQueueStats stats;
    std::vector<std::uint64_t> waiters;
    bool open{true};
  };

  struct ClassQueue {
    // Transmission tokens for the weighted round: a class transmits while it
    // has tokens; when every class with pending frames is out of tokens all
    // classes refill, which bounds how long bulk waits behind control.
    std::size_t tokens{};
  };

  void charge_drop(ChannelState& channel, std::uint64_t frames, std::uint64_t bytes);
  [[nodiscard]] Result<EnqueueReceipt> enqueue_control(std::uint32_t channel_id,
                                                       FrameClass klass, Frame&& frame);
  [[nodiscard]] Result<EnqueueReceipt> enqueue_business(ChannelState& channel,
                                                        std::uint32_t channel_id,
                                                        FrameClass klass, Frame&& frame);
  void notify_capacity(std::uint32_t channel_id);
  // Completes and detaches one registered waiter. Raw control pointer: the
  // owning ticket keeps it alive until its own destructor runs.
  void complete_waiter(std::uint64_t waiter_id, Result<void> result);
  // Removes the registration of a cancelled or destroyed ticket without
  // invoking its callback.
  void detach_waiter(std::uint64_t waiter_id);
  void refill_tokens();

  friend class CapacityWaitTicket;

  ChannelBudgetConfig config_;
  Limits limits_;
  std::map<std::uint32_t, ChannelState> channels_;
  // Queued frames per class; each entry knows its channel.
  std::map<std::uint8_t, std::deque<QueuedSendFrame>> class_queues_;
  std::map<FrameClass, ClassQueue> class_state_;
  std::size_t business_queued_frames_{};
  std::size_t business_queued_bytes_{};
  std::size_t control_queued_frames_{};
  std::size_t control_queued_bytes_{};
  struct WaiterEntry {
    CapacityWaitTicket::Control* ticket_control{nullptr};
  };
  std::map<std::uint64_t, WaiterEntry> waiters_;
  std::uint64_t next_waiter_id_{1U};
  std::size_t waiter_capacity_{64U};
};

}  // namespace heyaki::session
