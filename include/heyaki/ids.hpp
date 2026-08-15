#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace heyaki {

enum class IdentifierKind : std::uint8_t {
  device,
  endpoint,
  session,
  operation,
  message,
  request,
  transfer,
  grant,
};

template <IdentifierKind Kind, std::size_t Size>
class Identifier {
 public:
  using Storage = std::array<std::byte, Size>;
  static constexpr IdentifierKind kind = Kind;
  static constexpr std::size_t size_bytes = Size;

  constexpr Identifier() noexcept = default;
  explicit constexpr Identifier(Storage bytes) noexcept : bytes_(bytes) {}

  [[nodiscard]] constexpr const Storage& bytes() const noexcept { return bytes_; }
  [[nodiscard]] constexpr bool is_zero() const noexcept {
    for (const auto value : bytes_) {
      if (value != std::byte{0}) {
        return false;
      }
    }
    return true;
  }

  friend constexpr bool operator==(const Identifier&, const Identifier&) noexcept = default;
  friend constexpr auto operator<=>(const Identifier&, const Identifier&) noexcept = default;

 private:
  Storage bytes_{};
};

using DeviceId = Identifier<IdentifierKind::device, 32>;
using EndpointId = Identifier<IdentifierKind::endpoint, 16>;
using SessionId = Identifier<IdentifierKind::session, 16>;
using OperationId = Identifier<IdentifierKind::operation, 16>;
using MessageId = Identifier<IdentifierKind::message, 16>;
using RequestId = Identifier<IdentifierKind::request, 16>;
using TransferId = Identifier<IdentifierKind::transfer, 16>;
using GrantId = Identifier<IdentifierKind::grant, 16>;

enum class IdentifierDecodeError : std::uint8_t {
  none,
  invalid_prefix,
  invalid_length,
  invalid_character,
  non_canonical,
};

template <typename Id>
struct IdentifierDecodeResult {
  std::optional<Id> value;
  IdentifierDecodeError error{IdentifierDecodeError::none};

  [[nodiscard]] explicit constexpr operator bool() const noexcept { return value.has_value(); }
};

[[nodiscard]] std::string to_string(const DeviceId& id);
[[nodiscard]] std::string to_string(const EndpointId& id);
[[nodiscard]] std::string to_string(const SessionId& id);
[[nodiscard]] std::string to_string(const OperationId& id);
[[nodiscard]] std::string to_string(const MessageId& id);
[[nodiscard]] std::string to_string(const RequestId& id);
[[nodiscard]] std::string to_string(const TransferId& id);
[[nodiscard]] std::string to_string(const GrantId& id);

[[nodiscard]] IdentifierDecodeResult<DeviceId> parse_device_id(std::string_view text);
[[nodiscard]] IdentifierDecodeResult<EndpointId> parse_endpoint_id(std::string_view text);
[[nodiscard]] IdentifierDecodeResult<SessionId> parse_session_id(std::string_view text);
[[nodiscard]] IdentifierDecodeResult<OperationId> parse_operation_id(std::string_view text);
[[nodiscard]] IdentifierDecodeResult<MessageId> parse_message_id(std::string_view text);
[[nodiscard]] IdentifierDecodeResult<RequestId> parse_request_id(std::string_view text);
[[nodiscard]] IdentifierDecodeResult<TransferId> parse_transfer_id(std::string_view text);
[[nodiscard]] IdentifierDecodeResult<GrantId> parse_grant_id(std::string_view text);

[[nodiscard]] std::string_view identifier_decode_error_name(IdentifierDecodeError error) noexcept;

}  // namespace heyaki
