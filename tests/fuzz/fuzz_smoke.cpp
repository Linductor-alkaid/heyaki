#include "fuzz_targets.hpp"

#include <heyaki/event.hpp>
#include <heyaki/file.hpp>
#include <heyaki/message.hpp>
#include <heyaki/rpc.hpp>
#include <heyaki/shell.hpp>
#include "m1_golden_vectors.hpp"

#include <heyaki/lan_protocol.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/session_protocol.hpp>
#include <heyaki/signaling_protocol.hpp>
#include <heyaki/wire.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

std::vector<std::byte> bytes_from_text(std::string_view text) {
  return {reinterpret_cast<const std::byte*>(text.data()),
          reinterpret_cast<const std::byte*>(text.data()) + text.size()};
}

std::vector<std::byte> bytes_from_hex(std::string_view hex) {
  std::vector<std::byte> output;
  if (hex.size() % 2U != 0U) {
    return output;
  }
  const auto nibble = [](char value) -> int {
    if (value >= '0' && value <= '9') {
      return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
      return value - 'a' + 10;
    }
    return -1;
  };
  output.reserve(hex.size() / 2U);
  for (std::size_t index = 0U; index < hex.size(); index += 2U) {
    const int high = nibble(hex[index]);
    const int low = nibble(hex[index + 1U]);
    if (high < 0 || low < 0) {
      return {};
    }
    output.push_back(static_cast<std::byte>(static_cast<unsigned int>((high << 4) | low)));
  }
  return output;
}

bool write_seed(const std::filesystem::path& directory, std::string_view name,
                std::span<const std::byte> bytes) {
  std::filesystem::create_directories(directory);
  std::ofstream output{directory / name, std::ios::binary | std::ios::trunc};
  output.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(output);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: heyaki_fuzz_smoke <corpus-directory>\n";
    return 2;
  }

  const std::filesystem::path corpus_root{argv[1]};
  const auto valid = bytes_from_hex(heyaki::test_vectors::frame_hex);
  if (valid.empty()) {
    std::cerr << "invalid golden frame vector\n";
    return 1;
  }

  auto truncated = valid;
  truncated.pop_back();
  auto duplicate = valid;
  duplicate.insert(duplicate.end(), valid.begin(), valid.end());
  auto unknown_optional = valid;
  unknown_optional[1] = std::byte{0x7fU};
  auto unknown_required = unknown_optional;
  unknown_required[2] = std::byte{heyaki::frame_flag_required};
  const std::vector<std::byte> oversize{std::byte{0x81U}, std::byte{0x80U},
                                        std::byte{0x80U}, std::byte{0x01U}};
  heyaki::Frame boundary_frame{
      .type = static_cast<std::uint8_t>(heyaki::FrameType::message),
      .flags = 0U,
      .channel_id = 1U,
      .message_id = heyaki::MessageId{heyaki::MessageId::Storage{std::byte{1U}}},
      .payload = std::vector<std::byte>(heyaki::Limits{}.max_message_bytes, std::byte{0xa5U})};
  const auto boundary_result = heyaki::encode_frame(boundary_frame);
  if (!boundary_result) {
    std::cerr << "cannot encode boundary seed\n";
    return 1;
  }

  const std::vector parser_seeds{
      std::pair{std::string_view{"golden-frame"}, valid},
      std::pair{std::string_view{"truncated-frame"}, truncated},
      std::pair{std::string_view{"duplicate-frame"}, duplicate},
      std::pair{std::string_view{"unknown-optional-frame"}, unknown_optional},
      std::pair{std::string_view{"unknown-required-frame"}, unknown_required},
      std::pair{std::string_view{"maximum-message"}, *boundary_result.value_if()},
      std::pair{std::string_view{"oversize-length"}, oversize},
  };
  for (const auto& [name, seed] : parser_seeds) {
    heyaki::fuzz::frame_parser(seed);
    if (!write_seed(corpus_root / "frame-parser", name, seed)) {
      std::cerr << "cannot write parser seed " << name << '\n';
      return 1;
    }
  }

  const auto presence_identity = heyaki::create_identity();
  if (!presence_identity) {
    std::cerr << "cannot create LAN presence seed identity\n";
    return 1;
  }
  heyaki::EndpointId::Storage presence_endpoint{};
  presence_endpoint[0] = std::byte{0x11U};
  heyaki::LanPresence presence;
  presence.endpoint_id = heyaki::EndpointId{presence_endpoint};
  presence.boot_nonce[0] = std::byte{0x21U};
  presence.sequence = 1U;
  presence.tls_signaling_port = 49190U;
  const auto signed_presence =
      heyaki::sign_lan_presence(presence, *presence_identity.value_if());
  const auto lan_datagram =
      signed_presence
          ? heyaki::encode_lan_presence_datagram(presence)
          : heyaki::Result<std::vector<std::byte>>::failure(
                *signed_presence.error_if());
  if (!lan_datagram) {
    std::cerr << "cannot encode LAN presence seed\n";
    return 1;
  }
  auto truncated_lan = *lan_datagram.value_if();
  truncated_lan.pop_back();
  auto unknown_lan = *lan_datagram.value_if();
  unknown_lan[5U] = std::byte{0x7fU};
  auto oversized_lan = *lan_datagram.value_if();
  oversized_lan.resize(heyaki::max_lan_datagram_bytes + 1U, std::byte{0U});
  const std::vector lan_seeds{
      std::pair{std::string_view{"signed-presence"}, *lan_datagram.value_if()},
      std::pair{std::string_view{"truncated-presence"}, truncated_lan},
      std::pair{std::string_view{"unknown-type"}, unknown_lan},
      std::pair{std::string_view{"oversized-datagram"}, oversized_lan},
  };
  for (const auto& [name, seed] : lan_seeds) {
    heyaki::fuzz::lan_datagram_parser(seed);
    const auto parsed = heyaki::parse_lan_datagram(seed);
    if (parsed.status == heyaki::LanDatagramParseStatus::parsed && parsed.datagram) {
      heyaki::fuzz::lan_presence_parser(parsed.datagram->payload);
    }
    if (!write_seed(corpus_root / "lan-datagram-parser", name, seed)) {
      std::cerr << "cannot write LAN datagram seed " << name << '\n';
      return 1;
    }
  }

  heyaki::RequestId::Storage signaling_request_bytes{};
  signaling_request_bytes[0] = std::byte{0x71U};
  const heyaki::LanSignalingFrame signaling_frame{
      heyaki::LanSignalingMessageKind::signed_offer,
      heyaki::RequestId{signaling_request_bytes},
      {std::byte{0x01U}, std::byte{0x02U}, std::byte{0x03U}}};
  const auto encoded_signaling =
      heyaki::encode_lan_signaling_frame(signaling_frame);
  if (!encoded_signaling) {
    std::cerr << "cannot encode LAN signaling frame seed\n";
    return 1;
  }
  auto truncated_signaling = *encoded_signaling.value_if();
  truncated_signaling.pop_back();
  auto trailing_signaling = *encoded_signaling.value_if();
  trailing_signaling.push_back(std::byte{0U});
  auto unknown_signaling = *encoded_signaling.value_if();
  unknown_signaling[heyaki::lan_signaling_frame_header_bytes] = std::byte{0x7fU};
  auto zero_request_signaling = *encoded_signaling.value_if();
  std::fill_n(zero_request_signaling.begin() +
                  static_cast<std::ptrdiff_t>(
                      heyaki::lan_signaling_frame_header_bytes + 1U),
              heyaki::RequestId::size_bytes, std::byte{0U});
  const std::vector<std::byte> oversized_signaling_length{
      std::byte{0x00U}, std::byte{0x01U}, std::byte{0x00U}, std::byte{0x12U}};
  const std::vector signaling_seeds{
      std::pair{std::string_view{"signed-offer"},
                *encoded_signaling.value_if()},
      std::pair{std::string_view{"truncated-frame"}, truncated_signaling},
      std::pair{std::string_view{"trailing-bytes"}, trailing_signaling},
      std::pair{std::string_view{"unknown-kind"}, unknown_signaling},
      std::pair{std::string_view{"zero-request"}, zero_request_signaling},
      std::pair{std::string_view{"oversized-length"},
                oversized_signaling_length},
  };
  for (const auto& [name, seed] : signaling_seeds) {
    heyaki::fuzz::lan_signaling_frame_parser(seed);
    if (!write_seed(corpus_root / "lan-signaling-frame-parser", name, seed)) {
      std::cerr << "cannot write LAN signaling seed " << name << '\n';
      return 1;
    }
  }

  const auto signaling_identity = heyaki::create_identity();
  if (!signaling_identity) {
    std::cerr << "cannot create signed signaling seed identity\n";
    return 1;
  }
  heyaki::EndpointId::Storage initiator_endpoint{};
  initiator_endpoint[0] = std::byte{0x11U};
  heyaki::DeviceId::Storage responder_device{};
  responder_device[0] = std::byte{0x22U};
  heyaki::EndpointId::Storage responder_endpoint{};
  responder_endpoint[0] = std::byte{0x33U};
  heyaki::RequestId::Storage seed_request{};
  seed_request[0] = std::byte{0x44U};
  heyaki::SessionId::Storage seed_session{};
  seed_session[0] = std::byte{0x55U};
  heyaki::SignedOffer seed_offer;
  seed_offer.binding.initiator.device_id = signaling_identity.value_if()->device_id();
  seed_offer.binding.initiator.endpoint_id = heyaki::EndpointId{initiator_endpoint};
  seed_offer.binding.responder.device_id = heyaki::DeviceId{responder_device};
  seed_offer.binding.responder.endpoint_id = heyaki::EndpointId{responder_endpoint};
  seed_offer.binding.request_id = heyaki::RequestId{seed_request};
  seed_offer.binding.session_id = heyaki::SessionId{seed_session};
  seed_offer.binding.initiator_nonce = heyaki::SignalingNonce{};
  seed_offer.binding.initiator_nonce[0] = std::byte{0x66U};
  seed_offer.binding.expires_unix_milliseconds = 1'700'000'000'000ULL;
  seed_offer.sdp = {std::byte{'v'}, std::byte{'='}, std::byte{'0'}};
  seed_offer.dtls_fingerprint = heyaki::DtlsFingerprint{};
  seed_offer.dtls_fingerprint[0] = std::byte{0x77U};
  if (!heyaki::sign_signed_offer(seed_offer, *signaling_identity.value_if())) {
    std::cerr << "cannot sign signed offer seed\n";
    return 1;
  }
  const auto encoded_seed_offer = heyaki::encode_signed_offer(seed_offer);
  if (!encoded_seed_offer) {
    std::cerr << "cannot encode signed offer seed\n";
    return 1;
  }
  auto truncated_offer = *encoded_seed_offer.value_if();
  truncated_offer.pop_back();
  const std::vector<std::pair<std::string_view, std::vector<std::byte>>> offer_seeds{
      std::pair{std::string_view{"signed-offer"}, *encoded_seed_offer.value_if()},
      std::pair{std::string_view{"truncated-offer"}, truncated_offer},
  };
  for (const auto& [name, seed] : offer_seeds) {
    heyaki::fuzz::signed_offer_parser(seed);
    heyaki::fuzz::signed_answer_parser(seed);
    heyaki::fuzz::signed_candidate_parser(seed);
    heyaki::fuzz::signed_session_hello_parser(seed);
    if (!write_seed(corpus_root / "signed-signaling-parser", name, seed)) {
      std::cerr << "cannot write signed signaling seed " << name << '\n';
      return 1;
    }
  }

  const auto hello_sender = heyaki::create_identity();
  const auto hello_peer = heyaki::create_identity();
  if (!hello_sender || !hello_peer) {
    std::cerr << "cannot create LAN hello seed identities\n";
    return 1;
  }
  heyaki::EndpointId::Storage hello_sender_endpoint{};
  hello_sender_endpoint[0] = std::byte{0x21U};
  heyaki::EndpointId::Storage hello_peer_endpoint{};
  hello_peer_endpoint[0] = std::byte{0x22U};
  heyaki::LanHello hello;
  hello.role = heyaki::LanHelloRole::initiator;
  hello.sender_endpoint_id = heyaki::EndpointId{hello_sender_endpoint};
  hello.peer_device_id = hello_peer.value_if()->device_id();
  hello.peer_endpoint_id = heyaki::EndpointId{hello_peer_endpoint};
  hello.initiator_nonce[0] = std::byte{0x31U};
  hello.sender_tls_certificate_sha256[0] = std::byte{0x41U};
  hello.observed_peer_tls_certificate_sha256[0] = std::byte{0x42U};
  hello.sender_boot_nonce[0] = std::byte{0x51U};
  const auto signed_hello =
      heyaki::sign_lan_hello(hello, *hello_sender.value_if());
  const auto encoded_hello =
      signed_hello ? heyaki::encode_lan_hello(hello)
                   : heyaki::Result<std::vector<std::byte>>::failure(
                         *signed_hello.error_if());
  if (!encoded_hello) {
    std::cerr << "cannot encode LAN hello seed\n";
    return 1;
  }
  auto truncated_hello = *encoded_hello.value_if();
  truncated_hello.pop_back();
  auto unknown_hello = *encoded_hello.value_if();
  unknown_hello.insert(unknown_hello.end(),
                       {std::byte{0x70U}, std::byte{0x01U}});
  auto replaced_hello = *encoded_hello.value_if();
  replaced_hello[replaced_hello.size() / 2U] ^= std::byte{0x01U};
  const std::vector<std::byte> oversized_hello(
      heyaki::max_lan_datagram_payload_bytes + 1U, std::byte{0U});
  const std::vector hello_seeds{
      std::pair{std::string_view{"signed-hello"}, *encoded_hello.value_if()},
      std::pair{std::string_view{"truncated-hello"}, truncated_hello},
      std::pair{std::string_view{"unknown-field"}, unknown_hello},
      std::pair{std::string_view{"signature-conflict"}, replaced_hello},
      std::pair{std::string_view{"oversized-hello"}, oversized_hello},
  };
  for (const auto& [name, seed] : hello_seeds) {
    heyaki::fuzz::lan_hello_parser(seed);
    if (!write_seed(corpus_root / "lan-hello-parser", name, seed)) {
      std::cerr << "cannot write LAN hello seed " << name << '\n';
      return 1;
    }
  }

  const auto protobuf = bytes_from_hex(heyaki::test_vectors::protobuf_envelope_hex);
  auto truncated_protobuf = protobuf;
  truncated_protobuf.pop_back();
  auto unknown_protobuf = protobuf;
  unknown_protobuf.insert(unknown_protobuf.end(),
                          {std::byte{0x7aU}, std::byte{0x01U}, std::byte{0xffU}});
  const std::vector<std::byte> malformed_protobuf{
      std::byte{0x0aU}, std::byte{0xffU}, std::byte{0xffU},
      std::byte{0xffU}, std::byte{0xffU}, std::byte{0x0fU}};
  const std::vector protobuf_seeds{
      std::pair{std::string_view{"golden-envelope"}, protobuf},
      std::pair{std::string_view{"truncated-envelope"}, truncated_protobuf},
      std::pair{std::string_view{"unknown-field-envelope"}, unknown_protobuf},
      std::pair{std::string_view{"oversize-field-envelope"}, malformed_protobuf},
  };
  for (const auto& [name, seed] : protobuf_seeds) {
    heyaki::fuzz::protobuf_schema_parser(seed);
    if (!write_seed(corpus_root / "protobuf-parser", name, seed)) {
      std::cerr << "cannot write protobuf seed " << name << '\n';
      return 1;
    }
  }

  // M6 message/RPC payload seeds: valid bodies built through the public
  // codecs plus malformed/truncated variants.
  {
    heyaki::MessageEnvelope envelope;
    heyaki::MessageId::Storage id{};
    id[0] = std::byte{0x01U};
    envelope.message_id = heyaki::MessageId{id};
    envelope.type = "seed.tick";
    envelope.schema_version = 1U;
    envelope.ttl_milliseconds = 5'000U;
    envelope.delivery_mode = heyaki::MessageDeliveryMode::peer_acked;
    envelope.headers.push_back({"unit", {std::byte{9U}}});
    envelope.payload = {std::byte{0xDEU}, std::byte{0xADU}};
    const auto encoded_envelope = heyaki::encode_message_envelope(envelope);
    heyaki::RpcRequestBody request;
    heyaki::RequestId::Storage request_id{};
    request_id[1] = std::byte{0x02U};
    request.request_id = heyaki::RequestId{request_id};
    request.service = "seed";
    request.method = "echo";
    request.deadline_remaining_milliseconds = 2'500U;
    request.payload = {std::byte{0x01U}};
    const auto encoded_request = heyaki::encode_rpc_request(request);
    heyaki::RpcResponseBody response;
    response.request_id = request.request_id;
    response.status = heyaki::StableStatus::ok;
    response.safe_detail = "ok";
    response.payload = {std::byte{0x02U}};
    const auto encoded_response = heyaki::encode_rpc_response(response);
    const auto encoded_cancel =
        heyaki::encode_rpc_cancel(heyaki::RpcCancelBody{request.request_id});
    heyaki::MessageId::Storage ack_id{};
    ack_id[2] = std::byte{0x03U};
    const auto encoded_ack = heyaki::encode_message_ack(
        heyaki::MessageAckBody{heyaki::MessageId{ack_id}, true});
    std::vector<std::pair<std::string_view, std::vector<std::byte>>> m6_seeds;
    if (encoded_envelope) {
      auto truncated_m6 = *encoded_envelope.value_if();
      truncated_m6.pop_back();
      m6_seeds.emplace_back("message-envelope", *encoded_envelope.value_if());
      m6_seeds.emplace_back("message-envelope-truncated", std::move(truncated_m6));
    }
    if (encoded_request) {
      m6_seeds.emplace_back("rpc-request", *encoded_request.value_if());
    }
    if (encoded_response) {
      m6_seeds.emplace_back("rpc-response", *encoded_response.value_if());
    }
    if (encoded_cancel) {
      m6_seeds.emplace_back("rpc-cancel", *encoded_cancel.value_if());
    }
    if (encoded_ack) {
      m6_seeds.emplace_back("message-ack", *encoded_ack.value_if());
    }
    m6_seeds.emplace_back("garbage", std::vector<std::byte>(24U, std::byte{0xFFU}));
    for (const auto& [name, seed] : m6_seeds) {
      heyaki::fuzz::m6_service_payload_parser(seed);
      if (!write_seed(corpus_root / "m6-service-payload", name, seed)) {
        std::cerr << "cannot write M6 seed " << name << '\n';
        return 1;
      }
    }
  }

  // M7 event/file seeds (subscribe/item/unsubscribe, manifest/accept/reject/
  // complete, pull request, raw chunk header).
  {
    heyaki::EventSubscriptionId subscription_id{};
    for (std::size_t index = 0U; index < subscription_id.size(); ++index) {
      subscription_id[index] = static_cast<std::byte>(0x40U + index);
    }
    heyaki::EventId event_id{};
    for (std::size_t index = 0U; index < event_id.size(); ++index) {
      event_id[index] = static_cast<std::byte>(0x50U + index);
    }
    const auto encoded_subscribe = heyaki::encode_event_subscribe(
        heyaki::EventSubscribeBody{subscription_id, "telemetry.cpu", true,
                                   heyaki::EventQos::reliable_live});
    const auto encoded_unsubscribe = heyaki::encode_event_unsubscribe(
        heyaki::EventUnsubscribeBody{subscription_id});
    heyaki::EventItemBody item;
    item.subscription_id = subscription_id;
    item.event_id = event_id;
    heyaki::DeviceId::Storage device{};
    for (std::size_t index = 0U; index < device.size(); ++index) {
      device[index] = static_cast<std::byte>(0x60U + index);
    }
    item.publisher_device_id = heyaki::DeviceId{device};
    item.publisher_sequence = 7U;
    item.schema_version = 1U;
    item.qos = heyaki::EventQos::best_effort_latest;
    item.payload = {std::byte{1}, std::byte{2}, std::byte{3}};
    const auto encoded_item = heyaki::encode_event_item(item);

    heyaki::TransferId::Storage transfer{};
    for (std::size_t index = 0U; index < transfer.size(); ++index) {
      transfer[index] = static_cast<std::byte>(0x70U + index);
    }
    const heyaki::TransferId transfer_id{transfer};
    heyaki::FileManifestBody manifest;
    manifest.transfer_id = transfer_id;
    manifest.logical_name = "inbox/report.txt";
    manifest.size = 12'345U;
    manifest.blake3.assign(32U, std::byte{0xAB});
    manifest.chunk_size = 8'192U;
    const auto encoded_manifest = heyaki::encode_file_manifest(manifest);
    const auto encoded_accept = heyaki::encode_file_accept(
        heyaki::FileAcceptBody{transfer_id, {1U, 3U}});
    const auto encoded_reject = heyaki::encode_file_reject(
        heyaki::FileRejectBody{transfer_id, heyaki::StableStatus::resource_exhausted,
                               "root_quota"});
    const auto encoded_complete = heyaki::encode_file_complete(
        heyaki::FileCompleteBody{transfer_id, heyaki::StableStatus::ok, {}});
    const auto encoded_pull = heyaki::encode_file_pull_request(
        heyaki::FilePullRequestBody{transfer_id, "inbox", "report.txt"});
    heyaki::FileChunkHeader chunk_header;
    chunk_header.transfer_id = transfer_id;
    chunk_header.offset = 8'192U;
    chunk_header.data_length = 4U;
    chunk_header.blake3.fill(std::byte{0xCD});
    const std::vector<std::byte> chunk_data{std::byte{9}, std::byte{8}, std::byte{7},
                                            std::byte{6}};
    const auto encoded_chunk = heyaki::encode_file_chunk(chunk_header, chunk_data);

    std::vector<std::pair<std::string_view, std::vector<std::byte>>> m7_seeds;
    if (encoded_subscribe) m7_seeds.emplace_back("event-subscribe", *encoded_subscribe.value_if());
    if (encoded_item) m7_seeds.emplace_back("event-item", *encoded_item.value_if());
    if (encoded_unsubscribe) {
      m7_seeds.emplace_back("event-unsubscribe", *encoded_unsubscribe.value_if());
    }
    if (encoded_manifest) m7_seeds.emplace_back("file-manifest", *encoded_manifest.value_if());
    if (encoded_accept) m7_seeds.emplace_back("file-accept", *encoded_accept.value_if());
    if (encoded_reject) m7_seeds.emplace_back("file-reject", *encoded_reject.value_if());
    if (encoded_complete) {
      m7_seeds.emplace_back("file-complete", *encoded_complete.value_if());
    }
    if (encoded_pull) m7_seeds.emplace_back("file-pull", *encoded_pull.value_if());
    m7_seeds.emplace_back("file-chunk", encoded_chunk);
    auto truncated_chunk = encoded_chunk;
    truncated_chunk.pop_back();
    m7_seeds.emplace_back("file-chunk-truncated", std::move(truncated_chunk));
    for (const auto& [name, seed] : m7_seeds) {
      heyaki::fuzz::m7_service_payload_parser(seed);
      if (!write_seed(corpus_root / "m7-service-payload", name, seed)) {
        std::cerr << "cannot write M7 seed " << name << '\n';
        return 1;
      }
    }

    // M8 seeds: valid shell bodies, raw ShellData slices, and hostile VT
    // input (OSC clipboard/title, DCS, invalid UTF-8, oversized sequences).
    std::vector<std::pair<std::string, std::vector<std::byte>>> m8_seeds;
    {
      heyaki::ShellOpenBody open;
      open.shell_id = heyaki::ShellId{[] { heyaki::ShellId::Storage b{}; b[0] = std::byte{7}; return b; }()};
      open.profile = "maintenance";
      open.terminal_type = "xterm";
      open.columns = 80U;
      open.rows = 24U;
      open.locale = "C";
      if (auto encoded = heyaki::encode_shell_open(open)) {
        m8_seeds.emplace_back("shell-open", *encoded.value_if());
      }
    }
    {
      heyaki::ShellDataHeader header;
      header.shell_id = heyaki::ShellId{[] { heyaki::ShellId::Storage b{}; b[0] = std::byte{7}; return b; }()};
      header.offset = 0U;
      const std::string text = "echo hello";
      header.data_length = static_cast<std::uint32_t>(text.size());
      if (auto encoded = heyaki::encode_shell_data(
              header,
              {reinterpret_cast<const std::byte*>(text.data()), text.size()})) {
        m8_seeds.emplace_back("shell-data", *encoded.value_if());
      }
    }
    m8_seeds.emplace_back(
        "vt-osc-clipboard",
        bytes_from_text(std::string{"\x1b]52;c;base64,x"} + "\a" + "after"));
    m8_seeds.emplace_back("vt-osc-title",
                          bytes_from_text(std::string{"\x1b]0;title"} + "\a" + "x"));
    m8_seeds.emplace_back("vt-csi-storm", bytes_from_text("\x1b[1;2;3;4;5;6;7;8;9mA"));
    m8_seeds.emplace_back("vt-invalid-utf8", bytes_from_text("\xff\xfe\x80"));
    for (const auto& [name, seed] : m8_seeds) {
      heyaki::fuzz::m8_shell_frame_parser(seed);
      heyaki::fuzz::m8_vt_terminal_parser(seed);
      if (!write_seed(corpus_root / "m8-shell", name, seed)) {
        std::cerr << "cannot write M8 seed " << name << '\n';
        return 1;
      }
    }
  }

  std::vector<std::vector<std::byte>> state_seeds;
  for (std::uint8_t domain = 0U; domain < 9U; ++domain) {
    state_seeds.push_back({static_cast<std::byte>(domain), std::byte{0U}, std::byte{1U},
                           std::byte{2U}, std::byte{3U}, std::byte{4U}, std::byte{5U},
                           std::byte{6U}, std::byte{7U}});
  }
  for (std::size_t index = 0U; index < state_seeds.size(); ++index) {
    heyaki::fuzz::protocol_state_machines(state_seeds[index]);
    const auto name = "domain-" + std::to_string(index);
    if (!write_seed(corpus_root / "protocol-state", name, state_seeds[index])) {
      std::cerr << "cannot write state seed " << name << '\n';
      return 1;
    }
  }

  const std::vector<std::vector<std::byte>> connection_state_seeds{
      {std::byte{10U}, std::byte{1U}, std::byte{4U}, std::byte{8U}, std::byte{1U},
       std::byte{2U}, std::byte{9U}, std::byte{15U}, std::byte{1U}, std::byte{5U},
       std::byte{9U}, std::byte{12U}, std::byte{1U}, std::byte{3U}, std::byte{9U},
       std::byte{12U}, std::byte{1U}, std::byte{4U}, std::byte{12U}, std::byte{18U},
       std::byte{1U}, std::byte{5U}, std::byte{12U}, std::byte{14U}, std::byte{1U},
       std::byte{6U}, std::byte{12U}, std::byte{11U}, std::byte{1U}, std::byte{7U},
       std::byte{12U}, std::byte{9U}, std::byte{1U}, std::byte{8U}, std::byte{12U},
       std::byte{7U}},
      {std::byte{2U}, std::byte{1U}, std::byte{65U}, std::byte{2U}, std::byte{0U},
       std::byte{0U}, std::byte{1U}, std::byte{129U}, std::byte{0U}, std::byte{8U},
       std::byte{1U}, std::byte{1U}, std::byte{0U}},
  };
  for (std::size_t index = 0U; index < connection_state_seeds.size(); ++index) {
    heyaki::fuzz::connection_attempt_state_machine(connection_state_seeds[index]);
    const auto name = "connection-state-" + std::to_string(index);
    if (!write_seed(corpus_root / "connection-attempt-state", name,
                    connection_state_seeds[index])) {
      std::cerr << "cannot write connection state seed " << name << '\n';
      return 1;
    }
  }

  const std::vector<std::vector<std::byte>> lan_state_seeds{
      {std::byte{1U}, std::byte{1U}, std::byte{1U}, std::byte{1U},
       std::byte{1U}, std::byte{0U}, std::byte{1U}, std::byte{1U},
       std::byte{1U}, std::byte{0U}, std::byte{1U}, std::byte{0U}},
      {std::byte{1U}, std::byte{1U}, std::byte{1U}, std::byte{3U},
       std::byte{1U}, std::byte{0U}, std::byte{1U}, std::byte{1U},
       std::byte{1U}, std::byte{2U}, std::byte{1U}, std::byte{0U}},
      {std::byte{1U}, std::byte{1U}, std::byte{1U}, std::byte{1U},
       std::byte{1U}, std::byte{0U}, std::byte{1U}, std::byte{1U},
       std::byte{2U}, std::byte{1U}, std::byte{1U}, std::byte{0U}},
      {std::byte{1U}, std::byte{1U}, std::byte{1U}, std::byte{1U},
       std::byte{1U}, std::byte{0U}, std::byte{0U}, std::byte{0U},
       std::byte{0U}, std::byte{0U}, std::byte{0U}, std::byte{255U}},
      {std::byte{1U}, std::byte{1U}, std::byte{1U}, std::byte{1U},
       std::byte{1U}, std::byte{0U}, std::byte{1U}, std::byte{2U},
       std::byte{1U}, std::byte{1U}, std::byte{2U}, std::byte{0U},
       std::byte{1U}, std::byte{3U}, std::byte{1U}, std::byte{1U},
       std::byte{3U}, std::byte{0U}, std::byte{1U}, std::byte{4U},
       std::byte{1U}, std::byte{1U}, std::byte{4U}, std::byte{0U},
       std::byte{1U}, std::byte{5U}, std::byte{1U}, std::byte{1U},
       std::byte{5U}, std::byte{0U}, std::byte{1U}, std::byte{6U},
       std::byte{1U}, std::byte{1U}, std::byte{6U}, std::byte{0U},
       std::byte{1U}, std::byte{7U}, std::byte{1U}, std::byte{1U},
       std::byte{7U}, std::byte{0U}, std::byte{1U}, std::byte{8U},
       std::byte{1U}, std::byte{1U}, std::byte{8U}, std::byte{0U},
       std::byte{1U}, std::byte{9U}, std::byte{1U}, std::byte{1U},
       std::byte{9U}, std::byte{0U}},
  };
  for (std::size_t index = 0U; index < lan_state_seeds.size(); ++index) {
    heyaki::fuzz::lan_directory_state_machine(lan_state_seeds[index]);
    const auto name = "lan-state-" + std::to_string(index);
    if (!write_seed(corpus_root / "lan-directory-state", name,
                    lan_state_seeds[index])) {
      std::cerr << "cannot write LAN state seed " << name << '\n';
      return 1;
    }
  }
  return 0;
}
