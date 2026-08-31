// EventSubscribe / EventItem / EventUnsubscribe codec and topic-domain
// validation (M7-01..M7-03) over the frozen heyaki.protocol.event.v1 schemas.
// Encoded through the shared minimal protobuf wire codec so the library keeps
// avoiding a generated lite-runtime dependency.

#include <heyaki/event.hpp>

#include "proto_codec.hpp"

#include <algorithm>

namespace heyaki {
namespace {

using proto_codec::ProtoField;
using proto_codec::ProtoReader;

constexpr std::uint32_t kQosBestEffortLatest = 1U;
constexpr std::uint32_t kQosReliableLive = 2U;

Error event_error(std::string_view detail) {
  return Error{ErrorCode::protocol, "event", std::string{detail}};
}

bool subscription_id_zero(const EventSubscriptionId& id) noexcept {
  return std::all_of(id.begin(), id.end(),
                     [](std::byte value) { return value == std::byte{0}; });
}

bool event_id_zero(const EventId& id) noexcept {
  return std::all_of(id.begin(), id.end(),
                     [](std::byte value) { return value == std::byte{0}; });
}

bool topic_segment_token(std::string_view segment) noexcept {
  for (const char character : segment) {
    const bool lower = character >= 'a' && character <= 'z';
    const bool upper = character >= 'A' && character <= 'Z';
    const bool digit = character >= '0' && character <= '9';
    if (!lower && !upper && !digit && character != '_' && character != '-') {
      return false;
    }
  }
  return true;
}

}  // namespace

std::string_view event_qos_name(EventQos qos) noexcept {
  switch (qos) {
    case EventQos::best_effort_latest:
      return "best_effort_latest";
    case EventQos::reliable_live:
      return "reliable_live";
  }
  return "unknown";
}

bool valid_event_topic(std::string_view topic) noexcept {
  if (topic.empty() || topic.size() > max_event_topic_bytes) {
    return false;
  }
  std::size_t segments = 0U;
  std::size_t segment_start = 0U;
  for (std::size_t index = 0U; index <= topic.size(); ++index) {
    if (index == topic.size() || topic[index] == '.') {
      const auto segment = topic.substr(segment_start, index - segment_start);
      if (segment.empty() || segment.size() > max_event_topic_segment_bytes ||
          !topic_segment_token(segment)) {
        return false;
      }
      ++segments;
      if (segments > max_event_topic_segments) {
        return false;
      }
      segment_start = index + 1U;
    }
  }
  return true;
}

bool event_topic_matches(std::string_view pattern, bool prefix_match,
                         std::string_view topic) noexcept {
  if (pattern == topic) {
    return true;
  }
  if (!prefix_match) {
    return false;
  }
  // Segment-boundary prefix: "telemetry.cpu" matches "telemetry.cpu.load"
  // but not "telemetry.cpux".
  if (topic.size() <= pattern.size()) {
    return false;
  }
  if (topic.substr(0U, pattern.size()) != pattern) {
    return false;
  }
  return topic[pattern.size()] == '.';
}

namespace {

Result<EventQos> parse_qos(std::uint64_t value) {
  if (value == kQosBestEffortLatest) {
    return Result<EventQos>::success(EventQos::best_effort_latest);
  }
  if (value == kQosReliableLive) {
    return Result<EventQos>::success(EventQos::reliable_live);
  }
  return Result<EventQos>::failure(event_error("qos_invalid"));
}

Result<void> validate_event_payload_size(std::size_t payload_size,
                                         const Limits& limits) {
  if (payload_size > limits.max_event_payload_bytes) {
    return Result<void>::failure(event_error("payload_oversized"));
  }
  return Result<void>::success();
}

}  // namespace

Result<std::vector<std::byte>> encode_event_subscribe(const EventSubscribeBody& subscribe,
                                                      const Limits& limits) {
  if (subscription_id_zero(subscribe.subscription_id)) {
    return Result<std::vector<std::byte>>::failure(event_error("subscription_id_missing"));
  }
  if (!valid_event_topic(subscribe.topic)) {
    return Result<std::vector<std::byte>>::failure(event_error("topic_invalid"));
  }
  if (subscribe.qos != EventQos::best_effort_latest &&
      subscribe.qos != EventQos::reliable_live) {
    return Result<std::vector<std::byte>>::failure(event_error("qos_invalid"));
  }
  (void)limits;
  std::vector<std::byte> output;
  output.reserve(subscribe.topic.size() + 24U);
  proto_codec::append_bytes(output, 1U,
                            std::span<const std::byte>{
                                reinterpret_cast<const std::byte*>(subscribe.subscription_id.data()),
                                subscribe.subscription_id.size()});
  proto_codec::append_text(output, 2U, subscribe.topic);
  if (subscribe.prefix_match) {
    proto_codec::append_uint(output, 3U, 1U);
  }
  proto_codec::append_uint(output, 4U, static_cast<std::uint32_t>(subscribe.qos));
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<EventSubscribeBody> parse_event_subscribe(std::span<const std::byte> payload,
                                                 const Limits& limits) {
  (void)limits;
  EventSubscribeBody subscribe;
  bool have_id = false;
  bool have_topic = false;
  bool have_qos = false;
  ProtoReader reader{payload};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<EventSubscribeBody>::failure(*field.error_if());
    }
    const auto& value = *field.value_if();
    if (value.number == 1U && value.wire_type == 2U) {
      if (value.bytes.size() != subscribe.subscription_id.size()) {
        return Result<EventSubscribeBody>::failure(event_error("subscription_id_field_invalid"));
      }
      std::copy(value.bytes.begin(), value.bytes.end(), subscribe.subscription_id.begin());
      have_id = true;
    } else if (value.number == 2U && value.wire_type == 2U) {
      subscribe.topic.assign(reader.text(value));
      have_topic = true;
    } else if (value.number == 3U && value.wire_type == 0U) {
      subscribe.prefix_match = value.integer != 0U;
    } else if (value.number == 4U && value.wire_type == 0U) {
      auto qos = parse_qos(value.integer);
      if (!qos) {
        return Result<EventSubscribeBody>::failure(*qos.error_if());
      }
      subscribe.qos = *qos.value_if();
      have_qos = true;
    }
    // Unknown fields follow proto3 skipping rules.
  }
  if (!have_id || !have_topic || !have_qos) {
    return Result<EventSubscribeBody>::failure(event_error("subscribe_field_missing"));
  }
  if (subscription_id_zero(subscribe.subscription_id)) {
    return Result<EventSubscribeBody>::failure(event_error("subscription_id_missing"));
  }
  if (!valid_event_topic(subscribe.topic)) {
    return Result<EventSubscribeBody>::failure(event_error("topic_invalid"));
  }
  return Result<EventSubscribeBody>::success(std::move(subscribe));
}

Result<std::vector<std::byte>> encode_event_item(const EventItemBody& item,
                                                 const Limits& limits) {
  if (subscription_id_zero(item.subscription_id)) {
    return Result<std::vector<std::byte>>::failure(event_error("subscription_id_missing"));
  }
  if (event_id_zero(item.event_id)) {
    return Result<std::vector<std::byte>>::failure(event_error("event_id_missing"));
  }
  if (item.publisher_device_id.is_zero()) {
    return Result<std::vector<std::byte>>::failure(event_error("publisher_missing"));
  }
  if (item.schema_version == 0U) {
    return Result<std::vector<std::byte>>::failure(event_error("schema_version_invalid"));
  }
  if (item.qos != EventQos::best_effort_latest && item.qos != EventQos::reliable_live) {
    return Result<std::vector<std::byte>>::failure(event_error("qos_invalid"));
  }
  auto bounded = validate_event_payload_size(item.payload.size(), limits);
  if (!bounded) {
    return Result<std::vector<std::byte>>::failure(*bounded.error_if());
  }
  std::vector<std::byte> output;
  output.reserve(item.payload.size() + 96U);
  proto_codec::append_bytes(output, 1U,
                            std::span<const std::byte>{
                                reinterpret_cast<const std::byte*>(item.subscription_id.data()),
                                item.subscription_id.size()});
  proto_codec::append_bytes(
      output, 2U,
      std::span<const std::byte>{reinterpret_cast<const std::byte*>(item.event_id.data()),
                                 item.event_id.size()});
  proto_codec::append_bytes(output, 3U, item.publisher_device_id.bytes());
  proto_codec::append_uint(output, 4U, item.publisher_sequence);
  proto_codec::append_uint(output, 5U, item.schema_version);
  if (item.wall_time_unix_milliseconds.has_value()) {
    // int64 on the wire: two's complement varint of the signed value.
    proto_codec::append_uint(output, 6U,
                             static_cast<std::uint64_t>(*item.wall_time_unix_milliseconds));
  }
  proto_codec::append_uint(output, 7U, static_cast<std::uint32_t>(item.qos));
  proto_codec::append_bytes(output, 8U, item.payload);
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<EventItemBody> parse_event_item(std::span<const std::byte> payload,
                                       const Limits& limits) {
  EventItemBody item;
  bool have_subscription = false;
  bool have_event_id = false;
  bool have_publisher = false;
  bool have_sequence = false;
  bool have_schema = false;
  bool have_qos = false;
  ProtoReader reader{payload};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<EventItemBody>::failure(*field.error_if());
    }
    const auto& value = *field.value_if();
    if (value.number == 1U && value.wire_type == 2U) {
      if (value.bytes.size() != item.subscription_id.size()) {
        return Result<EventItemBody>::failure(event_error("subscription_id_field_invalid"));
      }
      std::copy(value.bytes.begin(), value.bytes.end(), item.subscription_id.begin());
      have_subscription = true;
    } else if (value.number == 2U && value.wire_type == 2U) {
      if (value.bytes.size() != item.event_id.size()) {
        return Result<EventItemBody>::failure(event_error("event_id_field_invalid"));
      }
      std::copy(value.bytes.begin(), value.bytes.end(), item.event_id.begin());
      have_event_id = true;
    } else if (value.number == 3U && value.wire_type == 2U) {
      if (value.bytes.size() != DeviceId::size_bytes) {
        return Result<EventItemBody>::failure(event_error("publisher_field_invalid"));
      }
      DeviceId::Storage storage{};
      std::copy(value.bytes.begin(), value.bytes.end(), storage.begin());
      item.publisher_device_id = DeviceId{storage};
      have_publisher = true;
    } else if (value.number == 4U && value.wire_type == 0U) {
      item.publisher_sequence = value.integer;
      have_sequence = true;
    } else if (value.number == 5U && value.wire_type == 0U) {
      if (value.integer == 0U || value.integer > 0xFFFFFFFFULL) {
        return Result<EventItemBody>::failure(event_error("schema_version_invalid"));
      }
      item.schema_version = static_cast<std::uint32_t>(value.integer);
      have_schema = true;
    } else if (value.number == 6U && value.wire_type == 0U) {
      item.wall_time_unix_milliseconds = static_cast<std::int64_t>(value.integer);
    } else if (value.number == 7U && value.wire_type == 0U) {
      auto qos = parse_qos(value.integer);
      if (!qos) {
        return Result<EventItemBody>::failure(*qos.error_if());
      }
      item.qos = *qos.value_if();
      have_qos = true;
    } else if (value.number == 8U && value.wire_type == 2U) {
      item.payload.assign(value.bytes.begin(), value.bytes.end());
    }
  }
  if (!have_subscription || !have_event_id || !have_publisher || !have_sequence ||
      !have_schema || !have_qos) {
    return Result<EventItemBody>::failure(event_error("item_field_missing"));
  }
  if (subscription_id_zero(item.subscription_id)) {
    return Result<EventItemBody>::failure(event_error("subscription_id_missing"));
  }
  if (event_id_zero(item.event_id)) {
    return Result<EventItemBody>::failure(event_error("event_id_missing"));
  }
  if (item.publisher_device_id.is_zero()) {
    return Result<EventItemBody>::failure(event_error("publisher_missing"));
  }
  auto bounded = validate_event_payload_size(item.payload.size(), limits);
  if (!bounded) {
    return Result<EventItemBody>::failure(*bounded.error_if());
  }
  return Result<EventItemBody>::success(std::move(item));
}

Result<std::vector<std::byte>> encode_event_unsubscribe(
    const EventUnsubscribeBody& unsubscribe) {
  if (subscription_id_zero(unsubscribe.subscription_id)) {
    return Result<std::vector<std::byte>>::failure(event_error("subscription_id_missing"));
  }
  std::vector<std::byte> output;
  proto_codec::append_bytes(
      output, 1U,
      std::span<const std::byte>{
          reinterpret_cast<const std::byte*>(unsubscribe.subscription_id.data()),
          unsubscribe.subscription_id.size()});
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<EventUnsubscribeBody> parse_event_unsubscribe(std::span<const std::byte> payload) {
  EventUnsubscribeBody unsubscribe;
  bool have_id = false;
  ProtoReader reader{payload};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<EventUnsubscribeBody>::failure(*field.error_if());
    }
    const auto& value = *field.value_if();
    if (value.number == 1U && value.wire_type == 2U) {
      if (value.bytes.size() != unsubscribe.subscription_id.size()) {
        return Result<EventUnsubscribeBody>::failure(event_error("subscription_id_field_invalid"));
      }
      std::copy(value.bytes.begin(), value.bytes.end(), unsubscribe.subscription_id.begin());
      have_id = true;
    }
  }
  if (!have_id) {
    return Result<EventUnsubscribeBody>::failure(event_error("unsubscribe_field_missing"));
  }
  if (subscription_id_zero(unsubscribe.subscription_id)) {
    return Result<EventUnsubscribeBody>::failure(event_error("subscription_id_missing"));
  }
  return Result<EventUnsubscribeBody>::success(std::move(unsubscribe));
}

}  // namespace heyaki
