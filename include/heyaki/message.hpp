#pragma once

// Point-to-point message protocol (M6-01..M6-04). MessageEnvelope and
// MessageAck follow the frozen heyaki.protocol.message.v1 schemas and ride the
// non-zero logical message channel of an authorized session. Two delivery
// modes exist (RULE-05): best_effort completes when the frame enters the
// bounded transport queue; peer_acked completes when the peer's protocol layer
// accepts the envelope after basic validation — an ACK never claims the
// handler ran or anything was persisted.

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/limits.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace heyaki {

// Mirrors heyaki.protocol.message.v1.DeliveryMode. Wire-stable.
enum class MessageDeliveryMode : std::uint32_t {
  best_effort = 1U,
  peer_acked = 2U,
};

[[nodiscard]] std::string_view message_delivery_mode_name(
    MessageDeliveryMode mode) noexcept;

inline constexpr std::size_t max_message_type_bytes = 128U;
inline constexpr std::size_t max_message_headers = 64U;
inline constexpr std::size_t max_message_header_name_bytes = 64U;
inline constexpr std::size_t max_message_header_value_bytes = 256U;
inline constexpr std::uint32_t min_message_ttl_milliseconds = 1U;
// Upper bound for both the send-side ack wait and the receive-side dedup
// retention of one message id.
inline constexpr std::uint32_t max_message_ttl_milliseconds = 600'000U;
inline constexpr std::uint32_t default_message_ttl_milliseconds = 30'000U;

struct MessageHeader {
  std::string name;
  std::vector<std::byte> value;
};

struct MessageEnvelope {
  // Non-zero 16-byte id; assigned by the sender, used for TTL dedup and ACK
  // matching. A zero id here means "assign a fresh random id on send".
  MessageId message_id;
  std::string type;
  std::uint32_t schema_version{1U};
  std::uint32_t ttl_milliseconds{default_message_ttl_milliseconds};
  MessageDeliveryMode delivery_mode{MessageDeliveryMode::best_effort};
  std::vector<MessageHeader> headers;
  std::vector<std::byte> payload;
  // Metadata only; receivers never treat it as trustworthy time.
  std::optional<std::uint64_t> wall_time_unix_milliseconds;
};

// Structural validation shared by the send and receive paths (M6-01): type,
// schema version, TTL window, delivery mode, header shape/count, and payload
// size against Limits::max_message_bytes. The frame-level size check happens
// in the wire layer; this is the envelope-domain contract.
[[nodiscard]] Result<void> validate_message_envelope(const MessageEnvelope& envelope,
                                                     const Limits& limits = {});

[[nodiscard]] Result<std::vector<std::byte>> encode_message_envelope(
    const MessageEnvelope& envelope, const Limits& limits = {});
[[nodiscard]] Result<MessageEnvelope> parse_message_envelope(
    std::span<const std::byte> payload, const Limits& limits = {});

// Mirrors heyaki.protocol.message.v1.MessageAck. protocol_accepted is the
// peer's basic envelope validation verdict only (M6-03).
struct MessageAckBody {
  MessageId message_id;
  bool protocol_accepted{false};
};

[[nodiscard]] Result<std::vector<std::byte>> encode_message_ack(
    const MessageAckBody& ack);
[[nodiscard]] Result<MessageAckBody> parse_message_ack(
    std::span<const std::byte> payload);

// Terminal lifecycle events for a sent message, surfaced through the ack
// observer. best_effort frames never leave the queued state.
enum class MessageDeliveryEvent : std::uint8_t {
  // peer_acked frame entered the bounded transport queue; waiting for ACK.
  queued,
  // The bounded transport queue rejected the frame (admission failure:
  // would_block, session loss, ...). Terminal for both modes.
  send_failed,
  // peer_acked frame was protocol-accepted by the peer.
  acked,
  // The peer's protocol layer rejected the envelope as invalid.
  peer_rejected,
  // The TTL expired without an ACK: the frame may or may not have been
  // delivered (RULE-05 keeps this distinct from acked).
  ack_timeout,
  // The session closed while an ACK was pending.
  session_closed,
};

[[nodiscard]] std::string_view message_delivery_event_name(
    MessageDeliveryEvent event) noexcept;

// Counters for one message service (M6-02..M6-04). Every drop, rejection,
// duplicate, and expiry is observable; nothing fails silently.
struct MessageServiceStats {
  // Send side.
  std::uint64_t sent_best_effort{};
  std::uint64_t sent_peer_acked{};
  std::uint64_t send_rejected{};
  std::uint64_t acked{};
  std::uint64_t ack_rejected{};
  std::uint64_t ack_timed_out{};
  std::uint64_t unknown_acks{};
  std::uint64_t acks_on_closed{};
  // Receive side.
  std::uint64_t received{};
  std::uint64_t invalid_envelopes{};
  std::uint64_t duplicates{};
  std::uint64_t dedup_expired{};
  std::uint64_t dedup_evictions{};
  std::uint64_t scope_rejected{};
  std::uint64_t acks_sent{};
  std::uint64_t ack_send_failures{};
  // Handler dispatch.
  std::uint64_t dispatched{};
  std::uint64_t dispatch_rejected{};
  std::uint64_t handler_completed{};
  std::uint64_t handler_exceptions{};
};

}  // namespace heyaki
