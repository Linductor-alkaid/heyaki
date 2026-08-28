#include <heyaki/signing.hpp>

#include <sodium/crypto_hash_sha256.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
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

using FieldRule = std::optional<std::size_t>;
constexpr FieldRule variable = std::nullopt;
constexpr std::array enrollment_rules{FieldRule{32U}, FieldRule{16U}, FieldRule{32U},
                                      FieldRule{32U}, FieldRule{32U}, variable,
                                      FieldRule{4U},  FieldRule{4U},  FieldRule{8U},
                                      FieldRule{8U},  FieldRule{8U}};
constexpr std::array enrollment_record_rules{FieldRule{32U}, FieldRule{16U}, FieldRule{32U},
                                             variable, FieldRule{8U}, FieldRule{8U}};
constexpr std::array relay_login_rules{
    FieldRule{32U}, FieldRule{16U}, FieldRule{32U}, FieldRule{32U},
    FieldRule{32U}, variable,      FieldRule{4U},  FieldRule{4U},
    FieldRule{8U},  FieldRule{8U}, FieldRule{8U},  FieldRule{8U}};
constexpr std::array endpoint_record_rules{FieldRule{32U}, FieldRule{16U}, variable,
                                           FieldRule{8U}, FieldRule{32U}, FieldRule{8U}};
constexpr std::array service_manifest_rules{FieldRule{32U}, FieldRule{16U}, FieldRule{8U},
                                            FieldRule{32U}, FieldRule{8U}};
constexpr std::array offer_rules{FieldRule{32U}, FieldRule{16U}, FieldRule{32U},
                                 FieldRule{16U}, FieldRule{16U}, FieldRule{16U},
                                 FieldRule{32U}, FieldRule{8U},  variable,
                                 FieldRule{32U}};
constexpr std::array answer_rules{FieldRule{32U}, FieldRule{16U}, FieldRule{32U},
                                  FieldRule{16U}, FieldRule{16U}, FieldRule{16U},
                                  FieldRule{32U}, FieldRule{32U}, FieldRule{8U},
                                  variable, FieldRule{32U}};
constexpr std::array candidate_rules{FieldRule{32U}, FieldRule{16U}, FieldRule{32U},
                                     FieldRule{16U}, FieldRule{16U}, FieldRule{16U},
                                     FieldRule{32U}, FieldRule{32U}, FieldRule{8U},
                                     FieldRule{4U}, variable, FieldRule{32U}, variable,
                                     FieldRule{32U}};
constexpr std::array lan_presence_rules{
    FieldRule{4U},  FieldRule{4U},  FieldRule{8U},  FieldRule{8U},
    FieldRule{32U}, FieldRule{32U}, FieldRule{16U}, FieldRule{32U},
    FieldRule{8U},  FieldRule{2U},  FieldRule{4U}};
constexpr std::array lan_hello_rules{
    FieldRule{4U},  FieldRule{32U}, FieldRule{16U}, FieldRule{32U},
    FieldRule{16U}, FieldRule{32U}, FieldRule{32U}, FieldRule{32U},
    FieldRule{32U}, FieldRule{32U}, FieldRule{32U}, FieldRule{4U},
    FieldRule{4U},  FieldRule{8U},  FieldRule{8U},  FieldRule{4U}};
constexpr std::array session_hello_rules{FieldRule{32U}, FieldRule{16U}, FieldRule{32U},
                                         FieldRule{16U}, FieldRule{16U}, FieldRule{8U},
                                         FieldRule{32U}, FieldRule{32U}, FieldRule{32U},
                                         FieldRule{4U},  FieldRule{4U},  FieldRule{8U},
                                         FieldRule{8U},  FieldRule{8U}};
constexpr std::array trust_grant_required_rules{FieldRule{16U}, FieldRule{32U}, FieldRule{32U},
                                                variable, FieldRule{8U}, FieldRule{8U}};

bool is_printable_ascii(std::span<const std::byte> value, std::size_t minimum,
                        std::size_t maximum) noexcept {
  if (value.size() < minimum || value.size() > maximum) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](std::byte character) {
    const auto byte = std::to_integer<std::uint8_t>(character);
    return byte >= 0x20U && byte <= 0x7eU;
  });
}

bool is_nonempty_utf8(std::span<const std::byte> value) noexcept {
  if (value.empty()) {
    return false;
  }

  std::size_t index = 0U;
  while (index < value.size()) {
    const auto first = std::to_integer<std::uint8_t>(value[index]);
    if (first <= 0x7fU) {
      ++index;
      continue;
    }

    std::size_t continuation_count = 0U;
    std::uint8_t second_minimum = 0x80U;
    std::uint8_t second_maximum = 0xbfU;
    if (first >= 0xc2U && first <= 0xdfU) {
      continuation_count = 1U;
    } else if (first >= 0xe0U && first <= 0xefU) {
      continuation_count = 2U;
      if (first == 0xe0U) {
        second_minimum = 0xa0U;
      } else if (first == 0xedU) {
        second_maximum = 0x9fU;
      }
    } else if (first >= 0xf0U && first <= 0xf4U) {
      continuation_count = 3U;
      if (first == 0xf0U) {
        second_minimum = 0x90U;
      } else if (first == 0xf4U) {
        second_maximum = 0x8fU;
      }
    } else {
      return false;
    }

    if (value.size() - index <= continuation_count) {
      return false;
    }
    const auto second = std::to_integer<std::uint8_t>(value[index + 1U]);
    if (second < second_minimum || second > second_maximum) {
      return false;
    }
    for (std::size_t offset = 2U; offset <= continuation_count; ++offset) {
      const auto continuation = std::to_integer<std::uint8_t>(value[index + offset]);
      if (continuation < 0x80U || continuation > 0xbfU) {
        return false;
      }
    }
    index += continuation_count + 1U;
  }
  return true;
}

bool has_canonical_domain(std::span<const std::byte> value,
                          std::string_view expected_domain) noexcept {
  constexpr std::size_t fixed_prefix_size = 6U;
  if (value.size() < fixed_prefix_size + expected_domain.size() + 2U ||
      value[0] != std::byte{'H'} || value[1] != std::byte{'Y'} ||
      value[2] != std::byte{'S'} || value[3] != std::byte{'G'} ||
      value[4] != std::byte{1U} ||
      std::to_integer<std::size_t>(value[5]) != expected_domain.size()) {
    return false;
  }
  return std::equal(expected_domain.begin(), expected_domain.end(), value.begin() + 6U,
                    [](char expected, std::byte actual) {
                      return static_cast<std::byte>(expected) == actual;
                    });
}

std::uint16_t read_uint16(std::span<const std::byte> value, std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(value[offset])) << 8U) |
      std::to_integer<std::uint8_t>(value[offset + 1U]));
}

bool is_canonical_scope_list(std::span<const std::byte> value) noexcept {
  if (value.size() < 2U) {
    return false;
  }

  const auto count = read_uint16(value, 0U);
  if (count > 256U) {
    return false;
  }

  std::size_t offset = 2U;
  std::span<const std::byte> previous;
  for (std::uint16_t index = 0U; index < count; ++index) {
    if (offset > value.size() || value.size() - offset < 2U) {
      return false;
    }
    const auto length = read_uint16(value, offset);
    offset += 2U;
    if (length == 0U || length > 256U || offset > value.size() ||
        value.size() - offset < length) {
      return false;
    }

    const auto scope = value.subspan(offset, length);
    for (const auto character : scope) {
      const auto byte = std::to_integer<std::uint8_t>(character);
      if (byte < 0x20U || byte > 0x7eU) {
        return false;
      }
    }
    if (!previous.empty() &&
        !std::lexicographical_compare(
            previous.begin(), previous.end(), scope.begin(), scope.end(),
            [](std::byte lhs, std::byte rhs) {
              return std::to_integer<std::uint8_t>(lhs) <
                     std::to_integer<std::uint8_t>(rhs);
            })) {
      return false;
    }
    previous = scope;
    offset += length;
  }
  return offset == value.size();
}

template <std::size_t N>
bool matches_rules(std::span<const CanonicalField> fields,
                   const std::array<FieldRule, N>& rules) noexcept {
  if (fields.size() != rules.size()) {
    return false;
  }
  for (std::size_t index = 0U; index < rules.size(); ++index) {
    if (fields[index].number != index + 1U ||
        (rules[index].has_value() && fields[index].value.size() != *rules[index])) {
      return false;
    }
  }
  return true;
}

bool matches_field_shape(SigningDomain domain, std::span<const CanonicalField> fields) noexcept {
  switch (domain) {
    case SigningDomain::enrollment:
      return matches_rules(fields, enrollment_rules) && is_nonempty_utf8(fields[5U].value);
    case SigningDomain::enrollment_record:
      return matches_rules(fields, enrollment_record_rules) &&
             is_nonempty_utf8(fields[3U].value);
    case SigningDomain::relay_login:
      return matches_rules(fields, relay_login_rules) &&
             is_nonempty_utf8(fields[5U].value);
    case SigningDomain::endpoint_record:
      return matches_rules(fields, endpoint_record_rules) &&
             is_nonempty_utf8(fields[2U].value);
    case SigningDomain::service_manifest:
      return matches_rules(fields, service_manifest_rules);
    case SigningDomain::offer:
      return matches_rules(fields, offer_rules);
    case SigningDomain::answer:
      return matches_rules(fields, answer_rules);
    case SigningDomain::candidate:
      return matches_rules(fields, candidate_rules) && !fields[10U].value.empty() &&
             is_printable_ascii(fields[12U].value, 4U, 256U);
    case SigningDomain::lan_presence:
      return matches_rules(fields, lan_presence_rules);
    case SigningDomain::lan_hello:
      return matches_rules(fields, lan_hello_rules);
    case SigningDomain::session_hello:
      return matches_rules(fields, session_hello_rules);
    case SigningDomain::trust_grant: {
      if (fields.size() != 7U && fields.size() != 8U) {
        return false;
      }
      for (std::size_t index = 0U; index < trust_grant_required_rules.size(); ++index) {
        if (fields[index].number != index + 1U ||
            (trust_grant_required_rules[index].has_value() &&
             fields[index].value.size() != *trust_grant_required_rules[index])) {
          return false;
        }
      }
      if (!is_canonical_scope_list(fields[3U].value)) {
        return false;
      }
      if (fields.size() == 8U &&
          (fields[6U].number != 7U || fields[6U].value.size() != 8U)) {
        return false;
      }
      const auto nonce_index = fields.size() == 8U ? 7U : 6U;
      return fields[nonce_index].number == 8U && fields[nonce_index].value.size() == 32U;
    }
  }
  return false;
}

}  // namespace

std::string_view signing_domain_separator(SigningDomain domain) noexcept {
  switch (domain) {
    case SigningDomain::enrollment:
      return "heyaki.enrollment.v1";
    case SigningDomain::enrollment_record:
      return "heyaki.enrollment-record.v1";
    case SigningDomain::relay_login:
      return "heyaki.relay-login.v1";
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
    case SigningDomain::lan_presence:
      return "heyaki.lan-presence.v1";
    case SigningDomain::lan_hello:
      return "heyaki.lan-hello.v1";
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
  if (separator == "heyaki.invalid.v1") {
    return canonical_error("invalid_signing_domain");
  }
  if (!matches_field_shape(domain, fields)) {
    return canonical_error("invalid_signed_field_shape");
  }
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

Result<SignalingTranscriptSha256> hash_signaling_transcript(
    std::span<const std::byte> canonical_offer, std::span<const std::byte> canonical_answer) {
  if (canonical_offer.empty() || canonical_answer.empty()) {
    return Result<SignalingTranscriptSha256>::failure(
        Error{ErrorCode::protocol, "signing", "empty_signaling_transcript"});
  }
  if (canonical_offer.size() > max_canonical_signing_bytes ||
      canonical_answer.size() > max_canonical_signing_bytes) {
    return Result<SignalingTranscriptSha256>::failure(
        Error{ErrorCode::protocol, "signing", "signaling_transcript_too_large"});
  }
  if (!has_canonical_domain(canonical_offer, "heyaki.offer.v1") ||
      !has_canonical_domain(canonical_answer, "heyaki.answer.v1")) {
    return Result<SignalingTranscriptSha256>::failure(
        Error{ErrorCode::protocol, "signing", "invalid_signaling_transcript_domain"});
  }

  constexpr std::string_view domain{"heyaki.signaling-transcript.v1"};
  const auto offer_length = canonical_uint32(static_cast<std::uint32_t>(canonical_offer.size()));
  const auto answer_length = canonical_uint32(static_cast<std::uint32_t>(canonical_answer.size()));
  crypto_hash_sha256_state state{};
  SignalingTranscriptSha256 output{};
  if (crypto_hash_sha256_init(&state) != 0 ||
      crypto_hash_sha256_update(
          &state, reinterpret_cast<const unsigned char*>(domain.data()), domain.size()) != 0 ||
      crypto_hash_sha256_update(
          &state, reinterpret_cast<const unsigned char*>(offer_length.data()),
          offer_length.size()) != 0 ||
      crypto_hash_sha256_update(
          &state, reinterpret_cast<const unsigned char*>(canonical_offer.data()),
          canonical_offer.size()) != 0 ||
      crypto_hash_sha256_update(
          &state, reinterpret_cast<const unsigned char*>(answer_length.data()),
          answer_length.size()) != 0 ||
      crypto_hash_sha256_update(
          &state, reinterpret_cast<const unsigned char*>(canonical_answer.data()),
          canonical_answer.size()) != 0 ||
      crypto_hash_sha256_final(&state, reinterpret_cast<unsigned char*>(output.data())) != 0) {
    return Result<SignalingTranscriptSha256>::failure(
        Error{ErrorCode::internal, "signing", "sha256_failed"});
  }
  return Result<SignalingTranscriptSha256>::success(output);
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
std::vector<std::byte> canonical_bytes(const RequestId& value) { return id_bytes(value); }
std::vector<std::byte> canonical_bytes(const TransferId& value) { return id_bytes(value); }
std::vector<std::byte> canonical_bytes(const GrantId& value) { return id_bytes(value); }

}  // namespace heyaki
