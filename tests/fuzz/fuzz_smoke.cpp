#include "fuzz_targets.hpp"
#include "m1_golden_vectors.hpp"

#include <heyaki/wire.hpp>

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
