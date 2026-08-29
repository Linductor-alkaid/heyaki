#pragma once

// Point-to-point message service (M6-02..M6-06). One instance rides an
// authorized PeerSession: it sends MessageEnvelope frames on the bounded
// message channel, tracks peer_acked deliveries until ACK or TTL expiry,
// deduplicates inbound envelopes by message id inside a bounded TTL cache,
// checks the session's message.send scope before any handler runs, and
// dispatches inbound handlers through the executor-backed ServiceDispatch.
//
// Threading: every public method runs on the owning Node's strand. Dispatched
// handler tasks run on executor threads and only touch self-contained
// DispatchRecord state; results merge back on the strand through the shared
// anchor (nulled by the destructor), so a late task can never reach a
// destroyed service.

#include "peer_session.hpp"
#include "service_dispatch.hpp"

#include <heyaki/message.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <vector>

namespace heyaki {

// Scope a message sender must hold for inbound delivery to run.
inline constexpr std::string_view message_send_scope = "message.send";

struct MessageServiceConfig {
  // Bounded inbound dedup cache keyed by message id (M6-04).
  std::size_t dedup_capacity{512U};
  // Bounded sender-side peer_acked tracking.
  std::size_t pending_ack_capacity{256U};
  std::size_t channel_frame_capacity{256U};
  std::size_t channel_byte_capacity{1024U * 1024U};
};

class MessageService : public std::enable_shared_from_this<MessageService> {
 public:
  using InboundHandler = std::function<void(const MessageEnvelope&)>;
  using AckObserver =
      std::function<void(const MessageId&, MessageDeliveryEvent, std::optional<Error>)>;
  // Returns whether the peer's effective session scopes cover `scope`.
  using ScopeCheck = std::function<bool(std::string_view scope)>;

  MessageService(PeerSession& session, MessageServiceConfig config,
                 ServiceDispatch dispatch, ScopeCheck scope_check,
                 std::function<std::uint64_t()> wall_clock = {});
  ~MessageService();

  MessageService(const MessageService&) = delete;
  MessageService& operator=(const MessageService&) = delete;

  // Opens the logical message channel and installs the domain handler so
  // peer-initiated message channels are admitted (M5-14 pattern).
  [[nodiscard]] Result<void> attach();

  // Sends one envelope. best_effort completes at bounded-queue admission;
  // peer_acked additionally registers bounded ACK tracking. A zero
  // message_id is assigned here. Failure means the frame was NOT admitted.
  [[nodiscard]] Result<MessageId> send(MessageEnvelope envelope);

  void set_inbound_handler(InboundHandler handler);
  void set_ack_observer(AckObserver observer);

  // TTL maintenance: expires dedup entries and pending ACKs (firing ack
  // observers with ack_timeout) and merges finished dispatch records.
  // Called on send/receive paths and safe to call from a periodic timer.
  void prune();

  // Session loss: pending ACKs become session_closed events; the dedup cache
  // keeps expiring normally so memory stays bounded.
  void handle_session_closed();

  [[nodiscard]] MessageServiceStats stats();
  [[nodiscard]] std::size_t pending_acks() const noexcept { return pending_acks_.size(); }
  [[nodiscard]] std::size_t dedup_entries() const noexcept { return dedup_.size(); }
  [[nodiscard]] bool attached() const noexcept { return attached_; }
  // Frame entry point (also used by tests for direct injection).
  void handle_frame(const FrameView& frame);

 private:
  // Written only by the owning executor task; read by the strand after the
  // relaxed `done` store (same shared_ptr handoff, strand-merged).
  struct DispatchRecord {
    std::atomic<bool> done{false};
    std::atomic<std::uint64_t> completed{0U};
    std::atomic<std::uint64_t> exceptions{0U};
  };

  struct DedupEntry {
    std::uint64_t expires_at_unix_milliseconds{};
    std::vector<std::byte> envelope_digest;
  };
  struct PendingAck {
    std::uint64_t expires_at_unix_milliseconds{};
  };

  [[nodiscard]] std::uint64_t now() const;
  [[nodiscard]] Result<void> admit_frame(const FrameView& frame);
  void handle_inbound_message(const FrameView& frame);
  void handle_inbound_ack(const FrameView& frame);
  void deliver_to_handler(MessageEnvelope envelope);
  void send_ack_for(const MessageEnvelope& envelope, std::uint32_t channel_id);
  void observe_ack(const MessageId& id, MessageDeliveryEvent event,
                   std::optional<Error> error);
  void prune_expired();
  void merge_dispatch_records();

  PeerSession& session_;
  MessageServiceConfig config_;
  ServiceDispatch dispatch_;
  ScopeCheck scope_check_;
  std::function<std::uint64_t()> wall_clock_;
  InboundHandler inbound_handler_;
  AckObserver ack_observer_;
  std::map<MessageId, DedupEntry> dedup_;
  std::map<MessageId, PendingAck> pending_acks_;
  std::map<std::uint64_t, std::shared_ptr<DispatchRecord>> dispatch_records_;
  std::uint64_t next_dispatch_id_{1U};
  MessageServiceStats stats_;
  std::uint32_t channel_id_{};
  std::vector<std::uint32_t> owned_channels_;
  bool attached_{false};
};

}  // namespace heyaki
