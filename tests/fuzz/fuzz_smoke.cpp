#include "fuzz_targets.hpp"
#include "m1_golden_vectors.hpp"

#include <heyaki/lan_protocol.hpp>
#include <heyaki/protocol.hpp>
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
  return 0;
}
