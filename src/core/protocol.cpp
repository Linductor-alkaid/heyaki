#include <heyaki/protocol.hpp>

#include <algorithm>
#include <limits>

namespace heyaki {
namespace {

Result<NegotiatedProtocol> negotiation_error(const char* detail) {
  return Result<NegotiatedProtocol>::failure(Error{ErrorCode::protocol, "negotiation", detail});
}

std::uint64_t capabilities_for_version(ProtocolVersion version) noexcept {
  if (version.major != current_protocol_version.major) {
    return 0U;
  }
  if (version.minor == 0U) {
    return protocol_1_0_capability_bits;
  }
  return version.minor == 1U ? protocol_1_1_capability_bits
                             : protocol_1_2_capability_bits;
}

}  // namespace

LanDatagramParseResult parse_lan_datagram(std::span<const std::byte> bytes) noexcept {
  if (bytes.size() < lan_datagram_header_bytes) {
    return {.status = LanDatagramParseStatus::incomplete, .datagram = std::nullopt};
  }
  if (bytes.size() > max_lan_datagram_bytes ||
      !std::equal(lan_datagram_magic.begin(), lan_datagram_magic.end(), bytes.begin()) ||
      bytes[4U] != static_cast<std::byte>(lan_datagram_envelope_version)) {
    return {.status = LanDatagramParseStatus::malformed, .datagram = std::nullopt};
  }

  const auto payload_size =
      (static_cast<std::size_t>(std::to_integer<std::uint8_t>(bytes[6U])) << 8U) |
      std::to_integer<std::uint8_t>(bytes[7U]);
  if (payload_size != bytes.size() - lan_datagram_header_bytes) {
    return {.status = LanDatagramParseStatus::malformed, .datagram = std::nullopt};
  }
  if (bytes[5U] != static_cast<std::byte>(LanDatagramType::presence)) {
    return {.status = LanDatagramParseStatus::unsupported, .datagram = std::nullopt};
  }
  return {
      .status = LanDatagramParseStatus::parsed,
      .datagram = LanDatagramView{
          .type = LanDatagramType::presence,
          .payload = bytes.subspan(lan_datagram_header_bytes),
      },
  };
}

Result<std::vector<std::byte>> encode_lan_datagram(
    LanDatagramType type, std::span<const std::byte> payload) {
  if (type != LanDatagramType::presence) {
    return Result<std::vector<std::byte>>::failure(
        Error{ErrorCode::protocol, "lan_discovery", "unsupported_datagram_type"});
  }
  if (payload.size() > max_lan_datagram_payload_bytes ||
      payload.size() > std::numeric_limits<std::uint16_t>::max()) {
    return Result<std::vector<std::byte>>::failure(
        Error{ErrorCode::resource_exhausted, "lan_discovery", "datagram_too_large"});
  }

  std::vector<std::byte> output;
  output.reserve(lan_datagram_header_bytes + payload.size());
  output.insert(output.end(), lan_datagram_magic.begin(), lan_datagram_magic.end());
  output.push_back(static_cast<std::byte>(lan_datagram_envelope_version));
  output.push_back(static_cast<std::byte>(type));
  output.push_back(static_cast<std::byte>((payload.size() >> 8U) & 0xffU));
  output.push_back(static_cast<std::byte>(payload.size() & 0xffU));
  output.insert(output.end(), payload.begin(), payload.end());
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<NegotiatedProtocol> negotiate_protocol(const ProtocolHello& local,
                                              const ProtocolHello& remote) {
  if (((local.required.bits | remote.required.bits) & ~known_capability_bits) != 0U) {
    return negotiation_error("unknown_required_capability");
  }
  if (!local.supported.contains(local.required) || !remote.supported.contains(remote.required)) {
    return negotiation_error("invalid_required_capabilities");
  }
  if (local.version.major != remote.version.major) {
    return negotiation_error("incompatible_major_version");
  }
  const ProtocolVersion negotiated_version{
      .major = local.version.major,
      .minor = std::min(local.version.minor, remote.version.minor),
  };
  const CapabilitySet negotiated_capabilities{
      .bits = local.supported.bits & remote.supported.bits &
              capabilities_for_version(negotiated_version),
  };
  if (!negotiated_capabilities.contains(local.required) ||
      !negotiated_capabilities.contains(remote.required)) {
    return negotiation_error("required_capability_unavailable");
  }

  return Result<NegotiatedProtocol>::success(
      {.version = negotiated_version, .capabilities = negotiated_capabilities});
}

}  // namespace heyaki
