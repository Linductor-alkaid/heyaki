#pragma once

// M6 test harness: a loopback PeerSession pair with mutual trust and
// controllable service dispatch. Tests drive frames explicitly through
// pump(), control executor timing through manual task queues, and advance
// wall clocks deterministically for TTL/deadline behavior.

#include "m4_support.hpp"
#include "message_service.hpp"
#include "peer_session.hpp"
#include "rpc_service.hpp"

#include <heyaki/identity.hpp>
#include <heyaki/rpc.hpp>
#include <heyaki/signaling_protocol.hpp>
#include <heyaki/signing.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace heyaki::test {

inline constexpr std::uint64_t m6_now = 1'700'000'000'000U;

// Manual executor double: admission always succeeds and the test decides
// when queued tasks run (the deterministic stand-in for the pinned executor).
struct ManualDispatch {
  std::deque<std::function<void()>> tasks;
  bool admit{true};

  ServiceDispatch dispatcher() {
    return [this](std::string_view, std::function<void()> task) {
      if (!admit) {
        return Result<void>::failure(
            Error{ErrorCode::resource_exhausted, "test", "dispatch_rejected"});
      }
      tasks.push_back(std::move(task));
      return Result<void>::success();
    };
  }

  void run_all() {
    std::size_t guard = 0U;
    while (!tasks.empty() && guard++ < 1000U) {
      auto task = std::move(tasks.front());
      tasks.pop_front();
      task();
    }
  }

  [[nodiscard]] bool has_pending() const noexcept { return !tasks.empty(); }
};

// Manual strand poster double mirroring the Node's strand.
struct ManualPoster {
  std::deque<std::function<void()>> posts;

  RpcService::StrandPoster poster() {
    return [this](std::function<void()> task) { posts.push_back(std::move(task)); };
  }

  void run_all() {
    std::size_t guard = 0U;
    while (!posts.empty() && guard++ < 1000U) {
      auto task = std::move(posts.front());
      posts.pop_front();
      task();
    }
  }

  [[nodiscard]] bool has_pending() const noexcept { return !posts.empty(); }
};

template <typename Storage, std::size_t Size = sizeof(Storage)>
Storage m6_filled(std::uint8_t seed) {
  Storage storage{};
  auto* bytes = reinterpret_cast<std::uint8_t*>(&storage);
  for (std::size_t index = 0U; index < Size; ++index) {
    bytes[index] = static_cast<std::uint8_t>(seed + index);
  }
  return storage;
}

inline ProtocolHello m6_protocol() {
  return {.version = current_protocol_version,
          .supported = {protocol_1_2_capability_bits},
          .required = {static_cast<std::uint64_t>(Capability::session)}};
}

// One loopback session pair with both sides authorized and M6 services
// attached. The left side acts as the client by default; the right side as
// the server. Scopes, service configs, and attachment are configurable
// through Options before the sessions are built.
struct M6ServicePair {
  struct Options {
    std::vector<std::string> left_scopes;
    std::vector<std::string> right_scopes;
    MessageServiceConfig left_message;
    MessageServiceConfig right_message;
    RpcServiceConfig left_rpc;
    RpcServiceConfig right_rpc;
    bool attach_message{true};
    bool attach_rpc{true};
  };

  LoopbackTransportPair pair;
  Result<IdentityKeyPair> left_identity{create_identity()};
  Result<IdentityKeyPair> right_identity{create_identity()};
  std::vector<std::string> left_scopes{"message.send", "rpc.device.read",
                                       "rpc.device.configure", "stream.open"};
  std::vector<std::string> right_scopes{"message.send", "rpc.device.read",
                                        "rpc.device.configure", "stream.open"};
  std::uint64_t left_clock = m6_now;
  std::uint64_t right_clock = m6_now;

  ManualDispatch left_dispatch;
  ManualDispatch right_dispatch;
  ManualPoster left_poster;
  ManualPoster right_poster;

  std::shared_ptr<PeerSession> left;
  std::shared_ptr<PeerSession> right;
  std::shared_ptr<ServiceRegistry> left_registry = std::make_shared<ServiceRegistry>();
  std::shared_ptr<ServiceRegistry> right_registry = std::make_shared<ServiceRegistry>();
  std::shared_ptr<MessageService> left_messages;
  std::shared_ptr<MessageService> right_messages;
  std::shared_ptr<RpcService> left_rpc;
  std::shared_ptr<RpcService> right_rpc;

  explicit M6ServicePair() : M6ServicePair(Options{}) {}
  explicit M6ServicePair(Options options) {
    if (!options.left_scopes.empty()) left_scopes = std::move(options.left_scopes);
    if (!options.right_scopes.empty()) right_scopes = std::move(options.right_scopes);
    EXPECT_TRUE(left_identity && right_identity);
    pair.connect();
    transport::ChannelOptions control_options;
    pair.left().async_open_channel(transport::ChannelKind::control, control_options,
                                   [](Result<transport::TransportChannel*>) {});
    pair.right().async_open_channel(transport::ChannelKind::control, control_options,
                                    [](Result<transport::TransportChannel*>) {});
    build_sessions();
    attach_services(options);
  }

  [[nodiscard]] DeviceEndpointKey left_key() const {
    return {left_identity.value_if()->device_id(), m6_filled<EndpointId>(0x20U)};
  }
  [[nodiscard]] DeviceEndpointKey right_key() const {
    return {right_identity.value_if()->device_id(), m6_filled<EndpointId>(0x40U)};
  }

  void build_sessions() {
    const auto session_id = m6_filled<SessionId>(0x60U);
    const auto initiator_nonce =
        m6_filled<std::array<std::byte, signaling_nonce_bytes>>(0x10U);
    const auto responder_nonce =
        m6_filled<std::array<std::byte, signaling_nonce_bytes>>(0x30U);
    const auto transcript =
        m6_filled<std::array<std::byte, signaling_transcript_sha256_bytes>>(0x50U);
    auto left_transport = std::shared_ptr<transport::TransportSession>(
        &pair.left(), [](transport::TransportSession*) {});
    auto right_transport = std::shared_ptr<transport::TransportSession>(
        &pair.right(), [](transport::TransportSession*) {});
    VerifiedSessionBinding left_binding{
        {right_key(), left_key(), session_id, 1U, initiator_nonce, responder_nonce,
         transcript},
        {},
        "peer-ufrag",
        true};
    VerifiedSessionBinding right_binding{
        {left_key(), right_key(), session_id, 1U, initiator_nonce, responder_nonce,
         transcript},
        {},
        "peer-ufrag",
        false};

    auto left_created = PeerSession::create_verified(
        {.transport = left_transport,
         .binding = left_binding,
         .local_identity = &*left_identity.value_if(),
         .peer_public_key = right_identity.value_if()->public_key(),
         .local_protocol = m6_protocol(),
         .expires_unix_milliseconds = m6_now + 60'000U,
         .now_unix_milliseconds = m6_now,
         .observer = {},
         .timeline = {},
         .clock = {},
         .trust_authorizer = [this](std::uint64_t) {
           SessionAuthorization authorization;
           authorization.trusted = true;
           authorization.scopes = left_scopes;
           authorization.pairing_allowed = true;
           return Result<SessionAuthorization>::success(authorization);
         },
         .wall_clock = [this] { return left_clock; }});
    ASSERT_TRUE(left_created);
    left = *left_created.value_if();

    auto right_created = PeerSession::create_verified(
        {.transport = right_transport,
         .binding = right_binding,
         .local_identity = &*right_identity.value_if(),
         .peer_public_key = left_identity.value_if()->public_key(),
         .local_protocol = m6_protocol(),
         .expires_unix_milliseconds = m6_now + 60'000U,
         .now_unix_milliseconds = m6_now,
         .observer = {},
         .timeline = {},
         .clock = {},
         .trust_authorizer = [this](std::uint64_t) {
           SessionAuthorization authorization;
           authorization.trusted = true;
           authorization.scopes = right_scopes;
           authorization.pairing_allowed = true;
           return Result<SessionAuthorization>::success(authorization);
         },
         .wall_clock = [this] { return right_clock; }});
    ASSERT_TRUE(right_created);
    right = *right_created.value_if();
    ASSERT_TRUE(left->start());
    ASSERT_TRUE(right->start());
    pump();
    ASSERT_TRUE(left->authenticated());
    ASSERT_TRUE(right->authenticated());
  }

  void attach_services(const Options& options) {
    if (options.attach_message) {
      left_messages = std::make_shared<MessageService>(
          *left, options.left_message, left_dispatch.dispatcher(),
          [session = left](std::string_view scope) {
            for (const auto& granted : session->authorized_scopes()) {
              if (trust_scope_covers(granted, scope)) return true;
            }
            return false;
          },
          [this] { return left_clock; });
      ASSERT_TRUE(left_messages->attach());
      right_messages = std::make_shared<MessageService>(
          *right, options.right_message, right_dispatch.dispatcher(),
          [session = right](std::string_view scope) {
            for (const auto& granted : session->authorized_scopes()) {
              if (trust_scope_covers(granted, scope)) return true;
            }
            return false;
          },
          [this] { return right_clock; });
      ASSERT_TRUE(right_messages->attach());
    }

    if (options.attach_rpc) {
      left_rpc = std::make_shared<RpcService>(
          *left, options.left_rpc, left_registry, left_dispatch.dispatcher(),
          [session = left](std::string_view scope) {
            for (const auto& granted : session->authorized_scopes()) {
              if (trust_scope_covers(granted, scope)) return true;
            }
            return false;
          },
          left_poster.poster(), [this] { return left_clock; });
      ASSERT_TRUE(left_rpc->attach());
      right_rpc = std::make_shared<RpcService>(
          *right, options.right_rpc, right_registry, right_dispatch.dispatcher(),
          [session = right](std::string_view scope) {
            for (const auto& granted : session->authorized_scopes()) {
              if (trust_scope_covers(granted, scope)) return true;
            }
            return false;
          },
          right_poster.poster(), [this] { return right_clock; });
      ASSERT_TRUE(right_rpc->attach());
    }
    pump();
  }

  // Delivers every queued frame in both directions.
  void pump() {
    for (int round = 0; round < 8; ++round) {
      pair.left().pump();
      pair.right().pump();
    }
  }

  // Runs executor tasks, posted completions, and frame delivery to quiescence.
  void cycle() {
    for (int round = 0; round < 8; ++round) {
      left_dispatch.run_all();
      right_dispatch.run_all();
      left_poster.run_all();
      right_poster.run_all();
      pump();
    }
  }

  [[nodiscard]] std::uint32_t message_channel_of(const PeerSession& side) const {
    for (const auto& snapshot : side.channels().channel_snapshots()) {
      if (snapshot.domain == session::ChannelDomain::message) return snapshot.channel_id;
    }
    return 0U;
  }

  [[nodiscard]] std::uint32_t rpc_channel_of(const PeerSession& side) const {
    for (const auto& snapshot : side.channels().channel_snapshots()) {
      if (snapshot.domain == session::ChannelDomain::rpc) return snapshot.channel_id;
    }
    return 0U;
  }

  // Injects one raw frame from `from` to `to` over the given channel.
  void inject_frame(PeerSession& from, std::uint32_t channel_id, std::uint8_t type,
                    std::span<const std::byte> payload) {
    Frame frame;
    frame.type = type;
    frame.channel_id = channel_id;
    frame.payload.assign(payload.begin(), payload.end());
    ASSERT_TRUE(from.send_frame(channel_id, session::FrameClass::standard,
                                std::move(frame)));
    pump();
  }

  [[nodiscard]] MessageEnvelope make_envelope(
      std::string type = "test.ping", MessageDeliveryMode mode =
                                         MessageDeliveryMode::best_effort,
      std::vector<std::byte> payload = {std::byte{1}, std::byte{2}, std::byte{3}},
      std::uint32_t ttl_milliseconds = 30'000U) const {
    MessageId::Storage id_bytes{};
    for (std::size_t index = 0U; index < id_bytes.size(); ++index) {
      id_bytes[index] = static_cast<std::byte>((index * 7U + next_envelope_seed) & 0xFFU);
    }
    ++next_envelope_seed;
    MessageEnvelope envelope;
    envelope.message_id = MessageId{id_bytes};
    envelope.type = std::move(type);
    envelope.schema_version = 1U;
    envelope.ttl_milliseconds = ttl_milliseconds;
    envelope.delivery_mode = mode;
    envelope.payload = std::move(payload);
    return envelope;
  }

 private:
  mutable std::uint8_t next_envelope_seed{0x11U};
};

}  // namespace heyaki::test
