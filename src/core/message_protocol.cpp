// MessageEnvelope / MessageAck codec and envelope-domain validation
// (M6-01..M6-04) over the frozen heyaki.protocol.message.v1 schemas. Encoded
// through the shared minimal protobuf wire codec so the library keeps
// avoiding a generated lite-runtime dependency.

#include <heyaki/message.hpp>

#include "proto_codec.hpp"

#include <algorithm>
#include <array>

namespace heyaki {
namespace {

using proto_codec::ProtoField;
using proto_codec::ProtoReader;

constexpr std::uint32_t kDeliveryModeBestEffort = 1U;
constexpr std::uint32_t kDeliveryModePeerAcked = 2U;

// Stricter token rule for names that cross the wire as identifiers (message
// type, header keys): letters, digits, underscore, hyphen, dot.
bool name_token(std::string_view value) noexcept {
  for (const char character : value) {
    const bool lower = character >= 'a' && character <= 'z';
    const bool upper = character >= 'A' && character <= 'Z';
    const bool digit = character >= '0' && character <= '9';
    if (!lower && !upper && !digit && character != '_' && character != '-' &&
        character != '.') {
      return false;
    }
  }
  return true;
}

Error envelope_error(std::string_view detail) {
  return Error{ErrorCode::protocol, "message", std::string{detail}};
}

}  // namespace

std::string_view message_delivery_mode_name(MessageDeliveryMode mode) noexcept {
  switch (mode) {
    case MessageDeliveryMode::best_effort:
      return "best_effort";
    case MessageDeliveryMode::peer_acked:
      return "peer_acked";
  }
  return "unknown";
}

std::string_view message_delivery_event_name(MessageDeliveryEvent event) noexcept {
  switch (event) {
    case MessageDeliveryEvent::queued:
      return "queued";
    case MessageDeliveryEvent::send_failed:
      return "send_failed";
    case MessageDeliveryEvent::acked:
      return "acked";
    case MessageDeliveryEvent::peer_rejected:
      return "peer_rejected";
    case MessageDeliveryEvent::ack_timeout:
      return "ack_timeout";
    case MessageDeliveryEvent::session_closed:
      return "session_closed";
  }
  return "unknown";
}

Result<void> validate_message_envelope(const MessageEnvelope& envelope,
                                       const Limits& limits) {
  if (envelope.message_id.is_zero()) {
    return Result<void>::failure(envelope_error("message_id_missing"));
  }
  if (envelope.type.empty() || envelope.type.size() > max_message_type_bytes ||
      !name_token(envelope.type)) {
    return Result<void>::failure(envelope_error("message_type_invalid"));
  }
  if (envelope.schema_version == 0U) {
    return Result<void>::failure(envelope_error("schema_version_invalid"));
  }
  if (envelope.ttl_milliseconds < min_message_ttl_milliseconds ||
      envelope.ttl_milliseconds > max_message_ttl_milliseconds) {
    return Result<void>::failure(envelope_error("ttl_out_of_range"));
  }
  if (envelope.delivery_mode != MessageDeliveryMode::best_effort &&
      envelope.delivery_mode != MessageDeliveryMode::peer_acked) {
    return Result<void>::failure(envelope_error("delivery_mode_invalid"));
  }
  if (envelope.headers.size() > max_message_headers) {
    return Result<void>::failure(envelope_error("header_count_exceeded"));
  }
  for (const auto& header : envelope.headers) {
    if (header.name.empty() || header.name.size() > max_message_header_name_bytes ||
        !name_token(header.name)) {
      return Result<void>::failure(envelope_error("header_name_invalid"));
    }
    if (header.value.size() > max_message_header_value_bytes) {
      return Result<void>::failure(envelope_error("header_value_oversized"));
    }
  }
  if (envelope.payload.size() > limits.max_message_bytes) {
    return Result<void>::failure(envelope_error("payload_oversized"));
  }
  return Result<void>::success();
}

namespace {

void append_header_entry(std::vector<std::byte>& output, const MessageHeader& header) {
  // map<string, bytes> entry: nested message { string key = 1; bytes value = 2 }.
  std::vector<std::byte> entry;
  proto_codec::append_text(entry, 1U, header.name);
  proto_codec::append_bytes(entry, 2U, header.value);
  proto_codec::append_bytes(output, 6U, entry);
}

}  // namespace

Result<std::vector<std::byte>> encode_message_envelope(const MessageEnvelope& envelope,
                                                       const Limits& limits) {
  auto valid = validate_message_envelope(envelope, limits);
  if (!valid) {
    return Result<std::vector<std::byte>>::failure(*valid.error_if());
  }
  std::vector<std::byte> output;
  output.reserve(envelope.payload.size() + 64U);
  proto_codec::append_bytes(output, 1U, envelope.message_id.bytes());
  proto_codec::append_text(output, 2U, envelope.type);
  proto_codec::append_uint(output, 3U, envelope.schema_version);
  proto_codec::append_uint(output, 4U, envelope.ttl_milliseconds);
  proto_codec::append_uint(output, 5U, static_cast<std::uint32_t>(envelope.delivery_mode));
  for (const auto& header : envelope.headers) {
    append_header_entry(output, header);
  }
  proto_codec::append_bytes(output, 7U, envelope.payload);
  if (envelope.wall_time_unix_milliseconds.has_value()) {
    proto_codec::append_uint(output, 8U, *envelope.wall_time_unix_milliseconds);
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<MessageEnvelope> parse_message_envelope(std::span<const std::byte> payload,
                                               const Limits& limits) {
  if (payload.size() > limits.max_message_bytes) {
    return Result<MessageEnvelope>::failure(envelope_error("envelope_oversized"));
  }
  MessageEnvelope envelope;
  std::array<std::byte, 16> id_storage{};
  bool have_id = false;
  bool have_type = false;
  bool have_ttl = false;
  bool have_mode = false;
  bool have_schema = false;
  ProtoReader reader{payload};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<MessageEnvelope>::failure(*field.error_if());
    }
    const auto& value = *field.value_if();
    if (value.number == 1U && value.wire_type == 2U) {
      if (value.bytes.size() != id_storage.size()) {
        return Result<MessageEnvelope>::failure(envelope_error("message_id_field_invalid"));
      }
      std::copy(value.bytes.begin(), value.bytes.end(), id_storage.begin());
      envelope.message_id = MessageId{id_storage};
      have_id = true;
    } else if (value.number == 2U && value.wire_type == 2U) {
      envelope.type.assign(reader.text(value));
      have_type = true;
    } else if (value.number == 3U && value.wire_type == 0U) {
      envelope.schema_version = static_cast<std::uint32_t>(value.integer);
      have_schema = true;
    } else if (value.number == 4U && value.wire_type == 0U) {
      envelope.ttl_milliseconds = static_cast<std::uint32_t>(value.integer);
      have_ttl = true;
    } else if (value.number == 5U && value.wire_type == 0U) {
      const auto mode = static_cast<std::uint32_t>(value.integer);
      if (mode == kDeliveryModeBestEffort) {
        envelope.delivery_mode = MessageDeliveryMode::best_effort;
      } else if (mode == kDeliveryModePeerAcked) {
        envelope.delivery_mode = MessageDeliveryMode::peer_acked;
      } else {
        return Result<MessageEnvelope>::failure(envelope_error("delivery_mode_invalid"));
      }
      have_mode = true;
    } else if (value.number == 6U && value.wire_type == 2U) {
      if (envelope.headers.size() >= max_message_headers) {
        return Result<MessageEnvelope>::failure(envelope_error("header_count_exceeded"));
      }
      MessageHeader header;
      ProtoReader entry{value.bytes};
      bool have_key = false;
      while (!entry.done()) {
        auto entry_field = entry.next();
        if (!entry_field) {
          return Result<MessageEnvelope>::failure(*entry_field.error_if());
        }
        if (entry_field.value_if()->number == 1U && entry_field.value_if()->wire_type == 2U) {
          header.name.assign(entry.text(*entry_field.value_if()));
          have_key = true;
        } else if (entry_field.value_if()->number == 2U &&
                   entry_field.value_if()->wire_type == 2U) {
          header.value.assign(entry_field.value_if()->bytes.begin(),
                              entry_field.value_if()->bytes.end());
        }
      }
      if (!have_key) {
        return Result<MessageEnvelope>::failure(envelope_error("header_key_missing"));
      }
      envelope.headers.push_back(std::move(header));
    } else if (value.number == 7U && value.wire_type == 2U) {
      envelope.payload.assign(value.bytes.begin(), value.bytes.end());
    } else if (value.number == 8U && value.wire_type == 0U) {
      envelope.wall_time_unix_milliseconds = static_cast<std::int64_t>(value.integer);
    }
    // Unknown fields follow proto3 skipping rules.
  }
  if (!have_id || !have_type || !have_schema || !have_ttl || !have_mode) {
    return Result<MessageEnvelope>::failure(envelope_error("envelope_field_missing"));
  }
  auto valid = validate_message_envelope(envelope, limits);
  if (!valid) {
    return Result<MessageEnvelope>::failure(*valid.error_if());
  }
  return Result<MessageEnvelope>::success(std::move(envelope));
}

Result<std::vector<std::byte>> encode_message_ack(const MessageAckBody& ack) {
  if (ack.message_id.is_zero()) {
    return Result<std::vector<std::byte>>::failure(envelope_error("message_id_missing"));
  }
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, ack.message_id.bytes());
  proto_codec::append_uint(output, 2U, ack.protocol_accepted ? 1U : 0U);
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<MessageAckBody> parse_message_ack(std::span<const std::byte> payload) {
  MessageAckBody ack;
  std::array<std::byte, 16> id_storage{};
  bool have_id = false;
  ProtoReader reader{payload};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<MessageAckBody>::failure(*field.error_if());
    }
    const auto& value = *field.value_if();
    if (value.number == 1U && value.wire_type == 2U) {
      if (value.bytes.size() != id_storage.size()) {
        return Result<MessageAckBody>::failure(envelope_error("message_id_field_invalid"));
      }
      std::copy(value.bytes.begin(), value.bytes.end(), id_storage.begin());
      ack.message_id = MessageId{id_storage};
      have_id = true;
    } else if (value.number == 2U && value.wire_type == 0U) {
      ack.protocol_accepted = value.integer != 0U;
    }
  }
  if (!have_id) {
    return Result<MessageAckBody>::failure(envelope_error("message_id_field_missing"));
  }
  return Result<MessageAckBody>::success(ack);
}

}  // namespace heyaki
