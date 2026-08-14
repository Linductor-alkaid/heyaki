#include <heyaki/signing.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <vector>

namespace heyaki {
namespace {

void append_uint16(std::vector<std::byte>& output, std::uint16_t value) {
  output.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
  output.push_back(static_cast<std::byte>(value & 0xffU));
}

void append_uint32(std::vector<std::byte>& output, std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    output.push_back(static_cast<std::byte>((value >> static_cast<unsigned int>(shift)) & 0xffU));
  }
}

void append_uint64(std::vector<std::byte>& output, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    output.push_back(static_cast<std::byte>((value >> static_cast<unsigned int>(shift)) & 0xffU));
  }
}

template <typename Id>
std::vector<std::byte> id_bytes(const Id& value) {
  return {value.bytes().begin(), value.bytes().end()};
}

Result<std::vector<std::byte>> canonical_error(const char* detail) {
  return Result<std::vector<std::byte>>::failure(Error{ErrorCode::protocol, "signing", detail});
}

}  // namespace

std::string_view signing_domain_separator(SigningDomain domain) noexcept {
  switch (domain) {
    case SigningDomain::enrollment:
      return "heyaki.enrollment.v1";
    case SigningDomain::endpoint_record:
      return "heyaki.endpoint-record.v1";
    case SigningDomain::service_manifest:
      return "heyaki.service-manifest.v1";
    case SigningDomain::offer:
      return "heyaki.offer.v1";
    case SigningDomain::answer:
      return "heyaki.answer.v1";
    case SigningDomain::candidate:
      return "heyaki.candidate.v1";
    case SigningDomain::session_hello:
      return "heyaki.session-hello.v1";
    case SigningDomain::trust_grant:
      return "heyaki.trust-grant.v1";
  }
  return "heyaki.invalid.v1";
}

Result<std::vector<std::byte>> canonicalize_for_signature(
    SigningDomain domain, std::span<const CanonicalField> fields) {
  const auto separator = signing_domain_separator(domain);
  if (separator.size() > std::numeric_limits<std::uint8_t>::max() ||
      fields.size() > std::numeric_limits<std::uint16_t>::max()) {
    return canonical_error("canonical_header_too_large");
  }

  std::size_t total_size = 4U + 1U + 1U + separator.size() + 2U;
  std::uint16_t previous_number = 0U;
  for (const auto& field : fields) {
    if (field.number == 0U || field.number <= previous_number) {
      return canonical_error("fields_not_strictly_ordered");
    }
    const auto remaining =
        max_canonical_signing_bytes - std::min(total_size, max_canonical_signing_bytes);
    if (field.value.size() > std::numeric_limits<std::uint32_t>::max() ||
        field.value.size() > remaining) {
      return canonical_error("canonical_object_too_large");
    }
    total_size += 2U + 4U + field.value.size();
    if (total_size > max_canonical_signing_bytes) {
      return canonical_error("canonical_object_too_large");
    }
    previous_number = field.number;
  }

  std::vector<std::byte> output;
  output.reserve(total_size);
  constexpr std::array magic{std::byte{'H'}, std::byte{'Y'}, std::byte{'S'}, std::byte{'G'}};
  output.insert(output.end(), magic.begin(), magic.end());
  output.push_back(std::byte{1U});
  output.push_back(static_cast<std::byte>(separator.size()));
  for (const char character : separator) {
    output.push_back(static_cast<std::byte>(character));
  }
  append_uint16(output, static_cast<std::uint16_t>(fields.size()));
  for (const auto& field : fields) {
    append_uint16(output, field.number);
    append_uint32(output, static_cast<std::uint32_t>(field.value.size()));
    output.insert(output.end(), field.value.begin(), field.value.end());
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

std::vector<std::byte> canonical_uint16(std::uint16_t value) {
  std::vector<std::byte> output;
  output.reserve(2U);
  append_uint16(output, value);
  return output;
}

std::vector<std::byte> canonical_uint32(std::uint32_t value) {
  std::vector<std::byte> output;
  output.reserve(4U);
  append_uint32(output, value);
  return output;
}

std::vector<std::byte> canonical_uint64(std::uint64_t value) {
  std::vector<std::byte> output;
  output.reserve(8U);
  append_uint64(output, value);
  return output;
}

std::vector<std::byte> canonical_bytes(const DeviceId& value) { return id_bytes(value); }
std::vector<std::byte> canonical_bytes(const EndpointId& value) { return id_bytes(value); }
std::vector<std::byte> canonical_bytes(const SessionId& value) { return id_bytes(value); }

}  // namespace heyaki
