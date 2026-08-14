#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/limits.hpp>
#include <heyaki/operation.hpp>
#include <heyaki/protocol.hpp>
#include <heyaki/security.hpp>
#include <heyaki/time.hpp>

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <type_traits>

namespace {

static_assert(!std::is_same_v<heyaki::DeviceId, heyaki::EndpointId>);
static_assert(!std::is_convertible_v<heyaki::EndpointId, heyaki::SessionId>);
static_assert(heyaki::DeviceId::size_bytes == 32U);
static_assert(heyaki::EndpointId::size_bytes == 16U);

template <typename T>
concept HasWritableCodeField = requires(T value) {
  value.code = heyaki::ErrorCode::internal;
};

template <typename T>
concept HasWritableSafeDetailField = requires(T value) {
  value.safe_detail = "untrusted";
};

template <typename T>
concept HasWritableComponentField = requires(T value) {
  value.component = "untrusted";
};

static_assert(!HasWritableCodeField<heyaki::Error>);
static_assert(!HasWritableSafeDetailField<heyaki::Error>);
static_assert(!HasWritableComponentField<heyaki::Error>);

template <typename Id>
Id sequential_id() {
  typename Id::Storage storage{};
  for (std::size_t index = 0U; index < storage.size(); ++index) {
    storage[index] = static_cast<std::byte>(index);
  }
  return Id{storage};
}

TEST(Identifiers, RoundTripEveryStrongType) {
  const auto endpoint = sequential_id<heyaki::EndpointId>();
  const auto session = sequential_id<heyaki::SessionId>();
  const auto operation = sequential_id<heyaki::OperationId>();
  const auto message = sequential_id<heyaki::MessageId>();
  const auto request = sequential_id<heyaki::RequestId>();
  const auto transfer = sequential_id<heyaki::TransferId>();

  EXPECT_EQ(*heyaki::parse_endpoint_id(heyaki::to_string(endpoint)).value, endpoint);
  EXPECT_EQ(*heyaki::parse_session_id(heyaki::to_string(session)).value, session);
  EXPECT_EQ(*heyaki::parse_operation_id(heyaki::to_string(operation)).value, operation);
  EXPECT_EQ(*heyaki::parse_message_id(heyaki::to_string(message)).value, message);
  EXPECT_EQ(*heyaki::parse_request_id(heyaki::to_string(request)).value, request);
  EXPECT_EQ(*heyaki::parse_transfer_id(heyaki::to_string(transfer)).value, transfer);
}

TEST(Identifiers, RejectNonCanonicalAndMalformedText) {
  const auto id = sequential_id<heyaki::EndpointId>();
  auto upper = heyaki::to_string(id);
  upper[5] = 'A';
  EXPECT_EQ(heyaki::parse_endpoint_id(upper).error,
            heyaki::IdentifierDecodeError::non_canonical);
  EXPECT_EQ(heyaki::parse_endpoint_id("hy1_invalid").error,
            heyaki::IdentifierDecodeError::invalid_prefix);

  auto bad_character = heyaki::to_string(id);
  bad_character.back() = '8';
  EXPECT_EQ(heyaki::parse_endpoint_id(bad_character).error,
            heyaki::IdentifierDecodeError::invalid_character);

  auto bad_padding = heyaki::to_string(id);
  bad_padding.back() = 'b';
  EXPECT_EQ(heyaki::parse_endpoint_id(bad_padding).error,
            heyaki::IdentifierDecodeError::non_canonical);
}

TEST(Errors, EveryStableCodeHasAStableName) {
  constexpr std::array codes{
      heyaki::ErrorCode::configuration,        heyaki::ErrorCode::identity,
      heyaki::ErrorCode::authentication,       heyaki::ErrorCode::permission,
      heyaki::ErrorCode::not_registered,       heyaki::ErrorCode::enrollment_revoked,
      heyaki::ErrorCode::profile_locked,       heyaki::ErrorCode::pairing_required,
      heyaki::ErrorCode::pairing_denied,       heyaki::ErrorCode::pairing_rate_limited,
      heyaki::ErrorCode::peer_offline,         heyaki::ErrorCode::endpoint_offline,
      heyaki::ErrorCode::signaling,            heyaki::ErrorCode::nat_traversal,
      heyaki::ErrorCode::relay_unavailable,    heyaki::ErrorCode::transport,
      heyaki::ErrorCode::protocol,             heyaki::ErrorCode::timeout,
      heyaki::ErrorCode::cancelled,            heyaki::ErrorCode::would_block,
      heyaki::ErrorCode::resource_exhausted,   heyaki::ErrorCode::remote_error,
      heyaki::ErrorCode::outcome_unknown,      heyaki::ErrorCode::internal,
  };
  for (const auto code : codes) {
    EXPECT_FALSE(heyaki::error_code_name(code).empty());
    EXPECT_NE(heyaki::error_code_name(code), "unknown");
  }
}

TEST(Limits, DefaultsPassAndUnsafeValuesFail) {
  const heyaki::Limits defaults;
  EXPECT_TRUE(heyaki::validate_limits(defaults));

  auto invalid = defaults;
  invalid.max_frame_bytes = 0U;
  const auto result = heyaki::validate_limits(invalid);
  ASSERT_FALSE(result);
  ASSERT_NE(result.error_if(), nullptr);
  EXPECT_EQ(result.error_if()->code(), heyaki::ErrorCode::configuration);
  EXPECT_EQ(result.error_if()->safe_detail(), "max_frame_bytes");

  invalid = defaults;
  invalid.max_expanded_file_bytes = 0U;
  EXPECT_FALSE(heyaki::validate_limits(invalid));
}

TEST(Time, WireTimeoutUsesReceiverMonotonicClockAndLocalClamp) {
  const auto received_at = heyaki::MonotonicClock::time_point{std::chrono::seconds{100}};
  const auto deadline = heyaki::deadline_from_wire_timeout(
      5000U, heyaki::RelativeTimeout{std::chrono::milliseconds{1200}}, received_at);
  EXPECT_EQ(deadline.value(), received_at + std::chrono::milliseconds{1200});
  EXPECT_FALSE(deadline.expired(received_at));
  EXPECT_TRUE(deadline.expired(deadline.value()));
}

TEST(Operation, TerminalTransitionsAreExplicitAndEpochBound) {
  heyaki::OperationStatus pending{.id = sequential_id<heyaki::OperationId>(),
                                  .epoch = heyaki::SessionEpoch{7U},
                                  .state = heyaki::OperationState::pending,
                                  .error = std::nullopt};
  auto cancelled = heyaki::transition_operation(pending, heyaki::OperationState::cancelled);
  ASSERT_TRUE(cancelled);
  ASSERT_NE(cancelled.value_if(), nullptr);
  EXPECT_EQ(cancelled.value_if()->state, heyaki::OperationState::cancelled);
  ASSERT_TRUE(cancelled.value_if()->error.has_value());
  EXPECT_EQ(cancelled.value_if()->error->code(), heyaki::ErrorCode::cancelled);

  auto illegal =
      heyaki::transition_operation(*cancelled.value_if(), heyaki::OperationState::success);
  EXPECT_FALSE(illegal);
  EXPECT_EQ(illegal.error_if()->code(), heyaki::ErrorCode::protocol);
  ASSERT_TRUE(pending.epoch.next().has_value());
  EXPECT_EQ(pending.epoch.next()->value(), 8U);
}

TEST(Protocol, NegotiatesMinorAndRejectsMissingRequiredCapability) {
  const heyaki::ProtocolHello local{
      .version = {1U, 2U},
      .supported = {.bits = static_cast<std::uint64_t>(heyaki::Capability::session) |
                            static_cast<std::uint64_t>(heyaki::Capability::message)},
      .required = {.bits = static_cast<std::uint64_t>(heyaki::Capability::session)}};
  auto remote = local;
  remote.version.minor = 1U;
  auto negotiated = heyaki::negotiate_protocol(local, remote);
  ASSERT_TRUE(negotiated);
  EXPECT_EQ(negotiated.value_if()->version, (heyaki::ProtocolVersion{1U, 1U}));

  remote.supported.bits = static_cast<std::uint64_t>(heyaki::Capability::message);
  remote.required.bits = remote.supported.bits;
  EXPECT_FALSE(heyaki::negotiate_protocol(local, remote));
}

TEST(Protocol, IgnoresUnknownOptionalCapabilitiesAndRejectsUnknownRequiredOnes) {
  constexpr std::uint64_t unknown_capability = 1ULL << 63U;
  const auto session = static_cast<std::uint64_t>(heyaki::Capability::session);
  const heyaki::ProtocolHello local{.version = {1U, 0U},
                                    .supported = {.bits = session | unknown_capability},
                                    .required = {.bits = session}};
  const auto optional = heyaki::negotiate_protocol(local, local);
  ASSERT_TRUE(optional);
  EXPECT_EQ(optional.value_if()->capabilities.bits, session);

  auto required = local;
  required.required.bits |= unknown_capability;
  const auto rejected = heyaki::negotiate_protocol(local, required);
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "unknown_required_capability");
}

TEST(Protocol, PreservesSchemaVersionWidth) {
  const heyaki::ProtocolHello local{.version = {70000U, 80000U},
                                    .supported = {.bits = 0U},
                                    .required = {.bits = 0U}};
  const auto negotiated = heyaki::negotiate_protocol(local, local);
  ASSERT_TRUE(negotiated);
  EXPECT_EQ(negotiated.value_if()->version, local.version);
}

TEST(Security, SensitiveClassesAreAlwaysRedacted) {
  EXPECT_EQ(heyaki::value_for_log(heyaki::LogDataClass::operational, "queue_full"),
            "queue_full");
  EXPECT_EQ(heyaki::value_for_log(heyaki::LogDataClass::identifier, "hy1_example"),
            "hy1_example");
  for (const auto data_class : {heyaki::LogDataClass::secret_key, heyaki::LogDataClass::token,
                                heyaki::LogDataClass::password, heyaki::LogDataClass::verifier,
                                heyaki::LogDataClass::payload,
                                heyaki::LogDataClass::terminal_content}) {
    EXPECT_EQ(heyaki::value_for_log(data_class, "must-not-escape"), "[REDACTED]");
  }
  EXPECT_TRUE(heyaki::validate_security_policy({}, {}));
  EXPECT_TRUE(heyaki::is_safe_detail_token("queue_full"));
  EXPECT_TRUE(heyaki::is_safe_detail_token("transport.timeout"));
  EXPECT_FALSE(heyaki::is_safe_detail_token("remote text"));
  EXPECT_FALSE(heyaki::is_safe_detail_token("line\nfeed"));
  EXPECT_FALSE(heyaki::is_safe_detail_token(""));
  EXPECT_TRUE(heyaki::is_safe_detail_token(heyaki::Error{}.safe_detail()));
  const heyaki::Error sanitized{heyaki::ErrorCode::remote_error, "peer", "remote text"};
  EXPECT_EQ(sanitized.safe_detail(), "invalid_safe_detail");
  EXPECT_EQ(sanitized.component(), "peer");

  const heyaki::Error sanitized_component{heyaki::ErrorCode::remote_error, "peer component",
                                          "remote_error"};
  EXPECT_EQ(sanitized_component.component(), "invalid_component");
}

TEST(Security, RejectsPoliciesBelowThreatModelBaseline) {
  auto password = heyaki::PasswordSecurityPolicy{};
  password.minimum_unicode_scalars = 15U;
  EXPECT_FALSE(heyaki::validate_security_policy({}, password));

  password = heyaki::PasswordSecurityPolicy{};
  password.argon2_minimum_memory_kib = 32U * 1024U;
  EXPECT_FALSE(heyaki::validate_security_policy({}, password));

  auto replay = heyaki::ReplayCachePolicy{};
  replay.per_peer_capacity = replay.capacity + 1U;
  EXPECT_FALSE(heyaki::validate_security_policy(replay, {}));

  replay = heyaki::ReplayCachePolicy{};
  --replay.ttl_milliseconds;
  EXPECT_FALSE(heyaki::validate_security_policy(replay, {}));
}

TEST(Security, SignedExpiryHasFixedFutureAndClockSkewBounds) {
  constexpr std::uint64_t now = 1'700'000'000'000ULL;
  EXPECT_TRUE(heyaki::validate_signed_expiry(now, now));
  EXPECT_TRUE(heyaki::validate_signed_expiry(
      now - heyaki::maximum_expiry_clock_skew_milliseconds, now));
  EXPECT_TRUE(heyaki::validate_signed_expiry(
      now + heyaki::maximum_signed_validity_milliseconds, now));
  EXPECT_FALSE(heyaki::validate_signed_expiry(
      now - heyaki::maximum_expiry_clock_skew_milliseconds - 1U, now));
  EXPECT_FALSE(heyaki::validate_signed_expiry(
      now + heyaki::maximum_signed_validity_milliseconds + 1U, now));

  EXPECT_TRUE(heyaki::validate_signed_expiry(0U, 0U));
  EXPECT_TRUE(heyaki::validate_signed_expiry(
      std::numeric_limits<std::uint64_t>::max(),
      std::numeric_limits<std::uint64_t>::max()));
}

}  // namespace
