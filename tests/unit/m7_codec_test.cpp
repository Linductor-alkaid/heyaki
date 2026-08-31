// M7 codec unit tests: event/file protobuf bodies, the raw FileChunk header,
// topic matching, logical-name safety, and the pull request body.

#include <heyaki/event.hpp>
#include <heyaki/file.hpp>
#include <heyaki/limits.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstring>

namespace heyaki {
namespace {

EventSubscriptionId filled_subscription_id(std::uint8_t seed) {
  EventSubscriptionId id{};
  for (std::size_t index = 0U; index < id.size(); ++index) {
    id[index] = static_cast<std::byte>(seed + index);
  }
  return id;
}

EventId filled_event_id(std::uint8_t seed) {
  EventId id{};
  for (std::size_t index = 0U; index < id.size(); ++index) {
    id[index] = static_cast<std::byte>(seed + index);
  }
  return id;
}

DeviceId filled_device_id(std::uint8_t seed) {
  DeviceId::Storage storage{};
  for (std::size_t index = 0U; index < storage.size(); ++index) {
    storage[index] = static_cast<std::byte>(seed + index * 3U);
  }
  return DeviceId{storage};
}

TEST(M7EventCodec, SubscribeRoundTrip) {
  EventSubscribeBody body;
  body.subscription_id = filled_subscription_id(0x21U);
  body.topic = "telemetry.cpu.load";
  body.prefix_match = true;
  body.qos = EventQos::reliable_live;
  auto encoded = encode_event_subscribe(body);
  ASSERT_TRUE(encoded);
  auto parsed = parse_event_subscribe(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->subscription_id, body.subscription_id);
  EXPECT_EQ(parsed.value_if()->topic, body.topic);
  EXPECT_TRUE(parsed.value_if()->prefix_match);
  EXPECT_EQ(parsed.value_if()->qos, EventQos::reliable_live);
}

TEST(M7EventCodec, SubscribeRejectsInvalidTopic) {
  EventSubscribeBody body;
  body.subscription_id = filled_subscription_id(1U);
  body.topic = "bad topic!";
  EXPECT_FALSE(encode_event_subscribe(body));
  body.topic = ".leading.dot";
  EXPECT_FALSE(encode_event_subscribe(body));
  body.topic = "trailing.";
  EXPECT_FALSE(encode_event_subscribe(body));
  body.topic = std::string(300U, 'a');
  EXPECT_FALSE(encode_event_subscribe(body));
}

TEST(M7EventCodec, SubscribeRequiresAllFields) {
  // Hand-rolled payload missing the qos field.
  std::vector<std::byte> payload;
  payload.push_back(std::byte{0x0A});  // field 1, wire 2
  payload.push_back(std::byte{16U});
  std::array<std::byte, 16U> id = filled_subscription_id(5U);
  payload.insert(payload.end(), id.begin(), id.end());
  EXPECT_FALSE(parse_event_subscribe(payload));
}

TEST(M7EventCodec, ItemRoundTripWithWallTime) {
  EventItemBody item;
  item.subscription_id = filled_subscription_id(0x31U);
  item.event_id = filled_event_id(0x41U);
  item.publisher_device_id = filled_device_id(0x51U);
  item.publisher_sequence = 42U;
  item.schema_version = 3U;
  item.wall_time_unix_milliseconds = -12345;
  item.qos = EventQos::best_effort_latest;
  item.payload = {std::byte{1}, std::byte{2}, std::byte{3}};
  auto encoded = encode_event_item(item);
  ASSERT_TRUE(encoded);
  auto parsed = parse_event_item(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->event_id, item.event_id);
  EXPECT_EQ(parsed.value_if()->publisher_sequence, 42U);
  EXPECT_EQ(parsed.value_if()->schema_version, 3U);
  ASSERT_TRUE(parsed.value_if()->wall_time_unix_milliseconds.has_value());
  EXPECT_EQ(*parsed.value_if()->wall_time_unix_milliseconds, -12345);
}

TEST(M7EventCodec, ItemRejectsOversizedPayload) {
  EventItemBody item;
  item.subscription_id = filled_subscription_id(1U);
  item.event_id = filled_event_id(2U);
  item.publisher_device_id = filled_device_id(3U);
  item.publisher_sequence = 1U;
  item.payload.assign(Limits{}.max_event_payload_bytes + 1U, std::byte{0});
  EXPECT_FALSE(encode_event_item(item));
}

TEST(M7EventCodec, UnsubscribeRoundTrip) {
  EventUnsubscribeBody body;
  body.subscription_id = filled_subscription_id(0x77U);
  auto encoded = encode_event_unsubscribe(body);
  ASSERT_TRUE(encoded);
  auto parsed = parse_event_unsubscribe(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->subscription_id, body.subscription_id);
  EventUnsubscribeBody zero;
  EXPECT_FALSE(encode_event_unsubscribe(zero));
}

TEST(M7TopicMatching, ExactAndPrefixBoundaries) {
  EXPECT_TRUE(valid_event_topic("telemetry.cpu.load"));
  EXPECT_FALSE(valid_event_topic(""));
  EXPECT_FALSE(valid_event_topic("telemetry..cpu"));
  EXPECT_FALSE(valid_event_topic("telemetry."));
  EXPECT_FALSE(valid_event_topic("telemetry.cpu!"));

  EXPECT_TRUE(event_topic_matches("telemetry.cpu", false, "telemetry.cpu"));
  EXPECT_FALSE(event_topic_matches("telemetry.cpu", false, "telemetry.cpu.load"));
  EXPECT_TRUE(event_topic_matches("telemetry.cpu", true, "telemetry.cpu.load"));
  EXPECT_FALSE(event_topic_matches("telemetry.cpu", true, "telemetry.cpux"));
  EXPECT_TRUE(event_topic_matches("telemetry.cpu", true, "telemetry.cpu"));
  EXPECT_TRUE(event_topic_matches("telemetry", true, "telemetry.cpu"));
}

TransferId filled_transfer_id(std::uint8_t seed) {
  TransferId::Storage storage{};
  for (std::size_t index = 0U; index < storage.size(); ++index) {
    storage[index] = static_cast<std::byte>(seed + index * 5U);
  }
  return TransferId{storage};
}

TEST(M7FileCodec, ManifestRoundTrip) {
  FileManifestBody manifest;
  manifest.transfer_id = filled_transfer_id(0x11U);
  manifest.logical_name = "inbox/docs/report.txt";
  manifest.size = 12345U;
  manifest.blake3.assign(32U, std::byte{0xAB});
  manifest.chunk_size = 8192U;
  auto encoded = encode_file_manifest(manifest);
  ASSERT_TRUE(encoded);
  auto parsed = parse_file_manifest(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->transfer_id, manifest.transfer_id);
  EXPECT_EQ(parsed.value_if()->logical_name, manifest.logical_name);
  EXPECT_EQ(parsed.value_if()->size, 12345U);
  EXPECT_EQ(parsed.value_if()->chunk_size, 8192U);
  EXPECT_FALSE(parsed.value_if()->zstd_compressed);
}

TEST(M7FileCodec, ManifestRequiresExpandedSizeWhenCompressed) {
  FileManifestBody manifest;
  manifest.transfer_id = filled_transfer_id(1U);
  manifest.logical_name = "inbox/a.bin";
  manifest.size = 100U;
  manifest.blake3.assign(32U, std::byte{1});
  manifest.chunk_size = 4096U;
  manifest.zstd_compressed = true;
  EXPECT_FALSE(encode_file_manifest(manifest));
  manifest.expanded_size = Limits{}.max_expanded_file_bytes + 1U;
  EXPECT_FALSE(encode_file_manifest(manifest));
  manifest.expanded_size = 200U;
  EXPECT_TRUE(encode_file_manifest(manifest));
}

TEST(M7FileCodec, ManifestBoundsChunkSizeAndDigest) {
  FileManifestBody manifest;
  manifest.transfer_id = filled_transfer_id(2U);
  manifest.logical_name = "inbox/a";
  manifest.size = 100U;
  manifest.chunk_size = 1024U;  // below min_file_chunk_size
  manifest.blake3.assign(32U, std::byte{2});
  EXPECT_FALSE(encode_file_manifest(manifest));
  manifest.chunk_size = 4096U;
  manifest.blake3.assign(31U, std::byte{2});
  EXPECT_FALSE(encode_file_manifest(manifest));
}

TEST(M7FileCodec, AcceptRejectsUnorderedIndices) {
  FileAcceptBody accept;
  accept.transfer_id = filled_transfer_id(3U);
  accept.present_chunk_indices = {5U, 3U};
  auto encoded = encode_file_accept(accept);
  ASSERT_TRUE(encoded);
  EXPECT_FALSE(parse_file_accept(*encoded.value_if()));
  accept.present_chunk_indices = {1U, 2U, 4U};
  encoded = encode_file_accept(accept);
  ASSERT_TRUE(encoded);
  auto parsed = parse_file_accept(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->present_chunk_indices,
            (std::vector<std::uint64_t>{1U, 2U, 4U}));
}

TEST(M7FileCodec, RejectAndCompleteValidateSafeDetail) {
  FileRejectBody reject;
  reject.transfer_id = filled_transfer_id(4U);
  reject.status = StableStatus::resource_exhausted;
  reject.safe_detail = "quota_exceeded";
  auto encoded = encode_file_reject(reject);
  ASSERT_TRUE(encoded);
  auto parsed = parse_file_reject(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->status, StableStatus::resource_exhausted);

  reject.safe_detail = "not a safe token!";
  EXPECT_FALSE(encode_file_reject(reject));
  reject.safe_detail = "ok";
  reject.status = StableStatus::ok;  // ok is not a rejection status
  EXPECT_FALSE(encode_file_reject(reject));

  FileCompleteBody complete;
  complete.transfer_id = filled_transfer_id(5U);
  complete.status = StableStatus::ok;
  encoded = encode_file_complete(complete);
  ASSERT_TRUE(encoded);
  auto done = parse_file_complete(*encoded.value_if());
  ASSERT_TRUE(done);
  EXPECT_EQ(done.value_if()->status, StableStatus::ok);
  complete.status = StableStatus::unspecified;
  EXPECT_FALSE(encode_file_complete(complete));
}

TEST(M7FileCodec, ChunkHeaderRoundTrip) {
  FileChunkHeader header;
  header.transfer_id = filled_transfer_id(0x63U);
  header.offset = 0x0102030405060708ULL;
  header.data_length = 4U;
  header.blake3.fill(std::byte{0xCD});
  const std::vector<std::byte> data{std::byte{9}, std::byte{8}, std::byte{7},
                                    std::byte{6}};
  auto payload = encode_file_chunk(header, data);
  ASSERT_EQ(payload.size(), file_chunk_header_bytes + data.size());
  auto parsed = parse_file_chunk(payload);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->header.transfer_id, header.transfer_id);
  EXPECT_EQ(parsed.value_if()->header.offset, header.offset);
  EXPECT_EQ(parsed.value_if()->header.data_length, 4U);
  EXPECT_EQ(parsed.value_if()->header.blake3, header.blake3);
  EXPECT_EQ(parsed.value_if()->data.size(), 4U);
  EXPECT_EQ(parsed.value_if()->data[0], std::byte{9});

  // Truncated and length-mismatched headers are protocol errors.
  payload.resize(payload.size() - 1U);
  EXPECT_FALSE(parse_file_chunk(payload));
  auto mismatched = encode_file_chunk(header, data);
  mismatched[28U - 1U] = std::byte{0};  // corrupt data_length byte region
  // (offset bytes are 16..23, length 24..27)
  mismatched = encode_file_chunk(header, data);
  mismatched[24U] = std::byte{5};  // declared length != real data size
  EXPECT_FALSE(parse_file_chunk(mismatched));
}

TEST(M7FileCodec, LogicalNameSafety) {
  EXPECT_TRUE(safe_logical_file_name("readme.txt"));
  EXPECT_TRUE(safe_logical_file_name("docs/2026/report (final).txt"));
  EXPECT_FALSE(safe_logical_file_name(""));                       // empty
  EXPECT_FALSE(safe_logical_file_name("/etc/passwd"));            // absolute
  EXPECT_FALSE(safe_logical_file_name("C:/windows/system32"));    // drive
  EXPECT_FALSE(safe_logical_file_name("a/../b"));                 // parent
  EXPECT_FALSE(safe_logical_file_name("a/./b"));                  // dot segment
  EXPECT_FALSE(safe_logical_file_name("a//b"));                   // empty segment
  EXPECT_FALSE(safe_logical_file_name("back\\slash"));            // backslash
  EXPECT_FALSE(safe_logical_file_name(std::string{"nul\0byte", 8}));  // NUL
  EXPECT_FALSE(safe_logical_file_name("a/b\x01c"));               // control byte
  EXPECT_FALSE(safe_logical_file_name("CON"));                    // device name
  EXPECT_FALSE(safe_logical_file_name("com1.out"));               // COM1 + ext
  EXPECT_FALSE(safe_logical_file_name("LPT9"));                   // LPT device
  EXPECT_FALSE(safe_logical_file_name("trailing."));              // trailing dot
  EXPECT_FALSE(safe_logical_file_name("trailing "));              // trailing space
  EXPECT_FALSE(safe_logical_file_name(std::string(600U, 'a')));   // too long

  EXPECT_TRUE(safe_logical_root_name("inbox"));
  EXPECT_TRUE(safe_logical_root_name("media-2"));
  EXPECT_FALSE(safe_logical_root_name(""));
  EXPECT_FALSE(safe_logical_root_name("in/box"));
  EXPECT_FALSE(safe_logical_root_name("CON"));
}

TEST(M7FileCodec, PullRequestRoundTrip) {
  FilePullRequestBody request;
  request.transfer_id = filled_transfer_id(0x88U);
  request.root = "inbox";
  request.logical_name = "docs/report.txt";
  auto encoded = encode_file_pull_request(request);
  ASSERT_TRUE(encoded);
  auto parsed = parse_file_pull_request(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->transfer_id, request.transfer_id);
  EXPECT_EQ(parsed.value_if()->root, "inbox");
  EXPECT_EQ(parsed.value_if()->logical_name, request.logical_name);

  request.logical_name = "../escape";
  EXPECT_FALSE(encode_file_pull_request(request));
}

}  // namespace
}  // namespace heyaki
