// M9-11 parameter freeze: every frozen default and hard upper bound in
// docs/operations/parameter-freeze.md is pinned here. Changing a default or a
// cap must update that document and this test in the same commit — the test
// fails on drift, the document explains the measurement basis.

#include "m8_support.hpp"

#include "byte_stream.hpp"
#include "file_store.hpp"
#include "relay_config.hpp"
#include "relay_rate_limiter.hpp"
#include "session_channels.hpp"
#include "relay_wss_client.hpp"
#include "signaling_coordinator.hpp"

#include <heyaki/error.hpp>
#include <heyaki/file.hpp>
#include <heyaki/gateway.hpp>
#include <heyaki/identity.hpp>
#include <heyaki/node.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/runtime.hpp>
#include <heyaki/shell.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace heyaki::test {
namespace {

using namespace std::chrono_literals;

namespace defaults {

RelayNodeConfig relay_node() {
  RelayNodeConfig config;
  config.relay_url = "wss://relay.example";
  config.tenant = "tenant";
  return config;
}

RelayServerConfig relay_server() {
  RelayServerConfig config;
  config.tls_certificate_file = "cert.pem";
  config.tls_private_key_file = "key.pem";
  return config;
}

}  // namespace defaults

// ---------------------------------------------------------------------------
// Frozen defaults.
// ---------------------------------------------------------------------------

TEST(M9ParameterFreeze, RuntimeDefaultsAreFrozen) {
  const RuntimeConfig config;
  EXPECT_EQ(config.callback_capacity, 1024U);
  EXPECT_EQ(config.shutdown_hook_capacity, 64U);
  EXPECT_EQ(config.executor_queue_capacity, 1024U);
  EXPECT_EQ(config.executor_min_threads, 2U);
  EXPECT_EQ(config.executor_max_threads, 4U);
  EXPECT_EQ(config.worker_start_timeout, 1000ms);
  EXPECT_EQ(config.callback_drain_timeout, 2000ms);
  EXPECT_EQ(config.producer_stop_timeout, 2000ms);
  EXPECT_EQ(config.service_cancel_timeout, 3000ms);
  EXPECT_EQ(config.peer_close_timeout, 3000ms);
  EXPECT_EQ(config.relay_unregister_timeout, 2000ms);
  EXPECT_EQ(config.operation_drain_timeout, 5000ms);
  EXPECT_EQ(config.worker_stop_timeout, 2000ms);
  EXPECT_EQ(config.persistence_flush_timeout, 2000ms);
  EXPECT_EQ(config.executor_drain_timeout, 5000ms);
  EXPECT_EQ(config.shell_command_capacity, 128U);
  EXPECT_EQ(config.shell_event_capacity, 256U);
  EXPECT_EQ(config.shell_worker_stop_timeout, 5000ms);
}

TEST(M9ParameterFreeze, RelayClientDefaultsAreFrozen) {
  const RelayNodeConfig config;
  EXPECT_TRUE(config.enabled);
  EXPECT_EQ(config.connect_timeout, 5000ms);
  EXPECT_EQ(config.handshake_timeout, 5000ms);
  EXPECT_EQ(config.close_timeout, 2000ms);
  EXPECT_EQ(config.heartbeat_interval, 15000ms);
  EXPECT_EQ(config.lease_duration, 45000ms);
  EXPECT_EQ(config.missed_heartbeat_limit, 3U);
  EXPECT_EQ(config.minimum_backoff, 1000ms);
  EXPECT_EQ(config.maximum_backoff, 60000ms);
  EXPECT_EQ(config.poll_interval, 100ms);
  EXPECT_EQ(config.receive_capacity, 64U);
  EXPECT_EQ(config.send_capacity, 64U);
}

TEST(M9ParameterFreeze, ServiceDefaultsAreFrozen) {
  const MessageServiceConfig message;
  EXPECT_EQ(message.dedup_capacity, 512U);
  EXPECT_EQ(message.pending_ack_capacity, 256U);
  EXPECT_EQ(message.channel_frame_capacity, 256U);
  EXPECT_EQ(message.channel_byte_capacity, 1024U * 1024U);

  const EventServiceConfig event;
  EXPECT_EQ(event.subscriber_queue_items, 256U);
  EXPECT_EQ(event.max_subscriptions_per_peer, 64U);
  EXPECT_EQ(event.channel_frame_capacity, 256U);
  EXPECT_EQ(event.channel_byte_capacity, 2U * 1024U * 1024U);

  const RpcServiceConfig rpc;
  EXPECT_EQ(rpc.max_concurrent_server_calls, 16U);
  EXPECT_EQ(rpc.result_cache_entries, 64U);
  EXPECT_EQ(rpc.result_cache_bytes, 256U * 1024U);
  EXPECT_EQ(rpc.max_pending_client_calls, 64U);
  EXPECT_EQ(rpc.channel_frame_capacity, 256U);
  EXPECT_EQ(rpc.channel_byte_capacity, 1024U * 1024U);

  const FileServiceConfig file;
  EXPECT_EQ(file.max_concurrent_sends, 2U);
  EXPECT_EQ(file.send_window_bytes, 2U * 1024U * 1024U);
  EXPECT_EQ(file.channel_frame_capacity, 256U);
  EXPECT_EQ(file.channel_byte_capacity, 8U * 1024U * 1024U);

  const ShellServiceConfig shell;
  EXPECT_EQ(shell.channel_frame_capacity, 128U);
  EXPECT_EQ(shell.channel_byte_capacity, 512U * 1024U);
  EXPECT_EQ(shell.max_output_window_bytes, 256U * 1024U);
  EXPECT_EQ(shell.max_retained_terminal, 64U);
}

TEST(M9ParameterFreeze, SessionAndStreamDefaultsAreFrozen) {
  const session::ChannelBudgetConfig budgets;
  EXPECT_EQ(budgets.max_open_channels, 16U);
  EXPECT_EQ(budgets.per_peer_queued_frames, 1024U);
  EXPECT_EQ(budgets.per_peer_queued_bytes, 8U * 1024U * 1024U);
  EXPECT_EQ(budgets.control_reserved_frames, 64U);
  EXPECT_EQ(budgets.control_reserved_bytes, 64U * 1024U);
  EXPECT_EQ(budgets.max_channel_queued_frames, 1024U);
  EXPECT_EQ(budgets.max_channel_queued_bytes, 8U * 1024U * 1024U);

  const ByteStreamLimits stream;
  EXPECT_EQ(stream.max_data_chunk_bytes, 16U * 1024U);
  EXPECT_EQ(stream.default_receive_window_bytes, 256U * 1024U);
  EXPECT_EQ(stream.default_receive_window_frames, 64U);
  EXPECT_EQ(stream.max_concurrent_streams, 16U);
  EXPECT_EQ(stream.pending_write_bytes, 512U * 1024U);
  EXPECT_EQ(stream.max_pending_reads, 16U);
  EXPECT_EQ(stream.max_pending_writes, 16U);

  const SignalingCoordinatorConfig signaling;
  EXPECT_EQ(signaling.max_pending_attempts, 64U);
  EXPECT_EQ(signaling.max_inbound_attempts, 64U);
  EXPECT_EQ(signaling.attempt_ttl, 15000ms);
  EXPECT_EQ(signaling.max_candidates_per_attempt, 128U);
  EXPECT_EQ(signaling.inbound_rate_window, 1000ms);
  EXPECT_EQ(signaling.inbound_rate_limit, 32U);
  EXPECT_EQ(signaling.rate_key_capacity, 256U);
  EXPECT_EQ(signaling.signaling_validity_milliseconds, 30000U);
}

TEST(M9ParameterFreeze, LanDefaultsAreFrozen) {
  const LanConfiguration lan;
  EXPECT_EQ(lan.interface_capacity, 32U);
  EXPECT_EQ(lan.directory_capacity, 4096U);
  EXPECT_EQ(lan.trusted_directory_reserve, 128U);
  EXPECT_EQ(lan.per_interface_directory_capacity, 1024U);
  EXPECT_EQ(lan.per_source_presence_capacity, 64U);
  EXPECT_EQ(lan.unknown_identity_capacity, 512U);
  EXPECT_EQ(lan.replay_capacity, 8192U);
  EXPECT_EQ(lan.diagnostic_capacity, 1024U);
  EXPECT_EQ(lan.provisional_connection_capacity, 64U);
  EXPECT_EQ(lan.per_source_provisional_capacity, 8U);
  EXPECT_EQ(lan.provisional_accept_rate_per_second, 64U);
  EXPECT_EQ(lan.per_source_provisional_rate, 16U);
  EXPECT_EQ(lan.pending_signaling_capacity, 128U);
  EXPECT_EQ(lan.auto_connect_capacity, 16U);
  EXPECT_EQ(lan.announcement_rate_per_second, 32U);
  EXPECT_EQ(lan.per_source_announcement_rate, 8U);
  EXPECT_EQ(lan.announcement_interval, 5000ms);
  EXPECT_EQ(lan.presence_lease, 15000ms);
  EXPECT_EQ(lan.announcement_jitter, 500ms);
  EXPECT_EQ(lan.interface_refresh_interval, 5000ms);
  EXPECT_EQ(lan.handshake_timeout, 5000ms);
  EXPECT_EQ(lan.hello_timeout, 3000ms);
  EXPECT_EQ(lan.route_preference_delay, 250ms);
  EXPECT_EQ(lan.shutdown_timeout, 2000ms);
}

TEST(M9ParameterFreeze, ShellAndFileRootDefaultsAreFrozen) {
  const ShellProfileConfig profile;
  EXPECT_EQ(profile.max_concurrent_sessions, 1U);
  EXPECT_EQ(profile.idle_timeout, 600000ms);
  EXPECT_EQ(profile.absolute_timeout, 3600000ms);
  EXPECT_EQ(profile.terminate_grace, 5000ms);
  EXPECT_EQ(profile.max_output_bytes, 64U * 1024U * 1024U);
  EXPECT_EQ(profile.max_output_pending_bytes, 256U * 1024U);
  EXPECT_EQ(profile.max_input_pending_bytes, 64U * 1024U);

  const FileRootConfig root;
  EXPECT_EQ(root.max_file_bytes, 1ULL * 1024ULL * 1024ULL * 1024ULL);
  EXPECT_EQ(root.max_total_bytes, 8ULL * 1024ULL * 1024ULL * 1024ULL);
  EXPECT_EQ(root.max_concurrent_receives, 2U);
}

TEST(M9ParameterFreeze, RelayServerDefaultsAreFrozen) {
  const RelayServerConfig config;
  EXPECT_EQ(config.listen_port, 8443U);
  EXPECT_EQ(config.max_connections, 1024U);
  EXPECT_EQ(config.handshake_timeout, 5000ms);
  EXPECT_EQ(config.shutdown_timeout, 2000ms);
  EXPECT_EQ(config.control_write_queue_frames, 64U);
  EXPECT_EQ(config.control_write_queue_bytes, 1024U * 1024U);
  EXPECT_EQ(config.success_log_period, 100U);
  EXPECT_EQ(config.endpoint_query_max_results, 256U);
  EXPECT_EQ(config.signaling_rate_per_second, 32U);
  EXPECT_EQ(config.lease.capacity, 4096U);
  EXPECT_EQ(config.lease.per_device_endpoint_capacity, 64U);
  EXPECT_EQ(config.lease.per_tenant_device_capacity, 4096U);
  EXPECT_EQ(config.lease.default_lease, 45000ms);
  EXPECT_EQ(config.lease.maximum_lease, 120000ms);
  EXPECT_EQ(config.endpoint_directory.capacity, 4096U);
  EXPECT_EQ(config.endpoint_directory.maximum_ttl, 300000ms);
}

// M10-04 gateway profile freeze (docs/operations/parameter-freeze.md §6a):
// serving-side defaults and hard caps. Changing any value must update the
// freeze table and this test in the same commit.

TEST(M9ParameterFreeze, GatewayProfileDefaultsAreFrozen) {
  const GatewayProfileConfig profile;
  EXPECT_EQ(profile.max_concurrent_streams_per_session, 8U);
  EXPECT_EQ(profile.max_concurrent_streams_per_profile, 16U);
  EXPECT_EQ(profile.max_profile_bytes, 2ULL * 1024ULL * 1024ULL * 1024ULL);
  EXPECT_EQ(profile.max_profile_bytes_per_second, 16U * 1024U * 1024U);
  EXPECT_EQ(profile.stream_idle_timeout, 300000ms);
  EXPECT_EQ(profile.stream_max_duration, 3600000ms);
  EXPECT_EQ(profile.dial_deadline, 10000ms);
  EXPECT_FALSE(profile.allow_internet);
  EXPECT_EQ(profile.confirm, GatewayConfirmMode::never);
  // A fresh profile states no targets/policy until configured.
  EXPECT_TRUE(profile.allowed_cidrs.empty());
  EXPECT_TRUE(profile.denied_cidrs.empty());
  EXPECT_TRUE(profile.allowed_ports.empty());
}

TEST(M9ParameterFreeze, GatewayHardCapsAndLimitsAreFrozen) {
  EXPECT_EQ(max_gateway_profile_bytes_hard, 1ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL);
  EXPECT_EQ(max_gateway_profile_bytes_per_second_hard, 256ULL * 1024ULL * 1024ULL);
  EXPECT_EQ(max_gateway_stream_idle_timeout, 3600000ms);
  EXPECT_EQ(max_gateway_stream_duration, 86400000ms);
  EXPECT_EQ(max_gateway_dial_deadline, 30000ms);
  EXPECT_EQ(default_gateway_dial_deadline, 10000ms);
  EXPECT_EQ(hard_max_concurrent_gateway_streams, 64U);
  EXPECT_EQ(default_max_concurrent_gateway_streams, 8U);
  EXPECT_EQ(max_gateway_profiles_per_endpoint, 16U);
  EXPECT_EQ(max_gateway_profiles_per_endpoint_hard, 64U);
  EXPECT_EQ(max_gateway_host_bytes, 253U);
  EXPECT_EQ(max_gateway_profile_bytes, 64U);
}

TEST(M9ParameterFreeze, GatewayProfileCapsRejectOversized) {
  auto profile = [] {
    GatewayProfileConfig config;
    config.name = "office";
    config.allowed_cidrs = {GatewayCidr{.address = GatewayIp{}, .prefix_bits = 8}};
    config.allowed_ports = {{.low = 1U, .high = 65535U}};
    return config;
  };
  ASSERT_TRUE(validate_gateway_profile(profile()));

  auto config = profile();
  config.max_concurrent_streams_per_session =
      hard_max_concurrent_gateway_streams + 1U;
  EXPECT_FALSE(validate_gateway_profile(config));
  config = profile();
  config.max_concurrent_streams_per_profile =
      hard_max_concurrent_gateway_streams + 1U;
  EXPECT_FALSE(validate_gateway_profile(config));
  config = profile();
  config.max_profile_bytes = max_gateway_profile_bytes_hard + 1U;
  EXPECT_FALSE(validate_gateway_profile(config));
  config = profile();
  config.max_profile_bytes_per_second =
      max_gateway_profile_bytes_per_second_hard + 1U;
  EXPECT_FALSE(validate_gateway_profile(config));
  config = profile();
  config.stream_idle_timeout = max_gateway_stream_idle_timeout + 1ms;
  EXPECT_FALSE(validate_gateway_profile(config));
  config = profile();
  config.stream_max_duration = max_gateway_stream_duration + 1ms;
  EXPECT_FALSE(validate_gateway_profile(config));
  config = profile();
  config.dial_deadline = max_gateway_dial_deadline + 1ms;
  EXPECT_FALSE(validate_gateway_profile(config));
}

// ---------------------------------------------------------------------------
// Hard upper bounds (M9-11): every cap rejects one past the bound.
// ---------------------------------------------------------------------------

TEST(M9ParameterFreeze, RuntimeCapsRejectOversized) {
  RuntimeConfig config;
  ASSERT_TRUE(validate_config(config));

  config.callback_capacity = 65537U;
  EXPECT_FALSE(validate_config(config));
  config = RuntimeConfig{};
  config.executor_queue_capacity = 65537U;
  EXPECT_FALSE(validate_config(config));
  config = RuntimeConfig{};
  config.executor_min_threads = 65U;
  EXPECT_FALSE(validate_config(config));
  config = RuntimeConfig{};
  config.executor_max_threads = 257U;
  EXPECT_FALSE(validate_config(config));
  config = RuntimeConfig{};
  config.worker_start_timeout = 600001ms;
  EXPECT_FALSE(validate_config(config));
  config = RuntimeConfig{};
  config.executor_drain_timeout = 600001ms;
  EXPECT_FALSE(validate_config(config));
  config = RuntimeConfig{};
  config.shell_event_capacity = 65537U;
  EXPECT_FALSE(validate_config(config));
}

TEST(M9ParameterFreeze, RelayClientCapsRejectOversized) {
  auto config = defaults::relay_node();
  ASSERT_TRUE(validate_relay_node_config(config));

  config.connect_timeout = 60001ms;
  EXPECT_FALSE(validate_relay_node_config(config));
  config = defaults::relay_node();
  config.heartbeat_interval = 120001ms;
  EXPECT_FALSE(validate_relay_node_config(config));
  config = defaults::relay_node();
  config.maximum_backoff = 3600001ms;
  EXPECT_FALSE(validate_relay_node_config(config));
  config = defaults::relay_node();
  config.minimum_backoff = 600001ms;
  EXPECT_FALSE(validate_relay_node_config(config));
  config = defaults::relay_node();
  config.receive_capacity = 65537U;
  EXPECT_FALSE(validate_relay_node_config(config));

  RelayWssClientConfig wss;
  wss.receive_capacity = 65537U;
  EXPECT_FALSE(RelayWssClient::create(wss, nullptr));
  wss = RelayWssClientConfig{};
  wss.handshake_timeout = 60001ms;
  EXPECT_FALSE(RelayWssClient::create(wss, nullptr));
}

TEST(M9ParameterFreeze, SessionAndStreamCapsRejectOversized) {
  session::ChannelBudgetConfig budgets;
  ASSERT_TRUE(session::validate_channel_budget_config(budgets));
  budgets.per_peer_queued_frames = 65537U;
  EXPECT_FALSE(session::validate_channel_budget_config(budgets));
  budgets = session::ChannelBudgetConfig{};
  budgets.per_peer_queued_bytes = 256U * 1024U * 1024U + 1U;
  EXPECT_FALSE(session::validate_channel_budget_config(budgets));
  budgets = session::ChannelBudgetConfig{};
  budgets.max_channel_queued_frames = 65537U;
  EXPECT_FALSE(session::validate_channel_budget_config(budgets));

  ByteStreamLimits stream;
  ASSERT_TRUE(validate_byte_stream_limits(stream));
  stream.default_receive_window_frames = 65537U;
  EXPECT_FALSE(validate_byte_stream_limits(stream));
  stream = ByteStreamLimits{};
  stream.max_concurrent_streams = 1025U;
  EXPECT_FALSE(validate_byte_stream_limits(stream));
  stream = ByteStreamLimits{};
  stream.pending_write_bytes = 64U * 1024U * 1024U + 1U;
  EXPECT_FALSE(validate_byte_stream_limits(stream));
  stream = ByteStreamLimits{};
  stream.max_pending_writes = 4097U;
  EXPECT_FALSE(validate_byte_stream_limits(stream));
}

TEST(M9ParameterFreeze, SignalingCoordinatorCapsRejectOversized) {
  auto identity = create_identity();
  ASSERT_TRUE(identity);
  auto config = SignalingCoordinatorConfig{};
  config.local = DeviceEndpointKey{identity.value_if()->device_id(),
                                   m6_filled<EndpointId>(0x20U)};
  config.identity = identity.value_if();
  auto delegate = std::make_shared<SignalingDelegate>();
  ASSERT_TRUE(SignalingCoordinator::create(config, delegate));

  config.attempt_ttl = 600001ms;
  EXPECT_FALSE(SignalingCoordinator::create(config, delegate));
  config = SignalingCoordinatorConfig{};
  config.local = DeviceEndpointKey{identity.value_if()->device_id(),
                                   m6_filled<EndpointId>(0x20U)};
  config.identity = identity.value_if();
  config.max_pending_attempts = 65537U;
  EXPECT_FALSE(SignalingCoordinator::create(config, delegate));
  config = SignalingCoordinatorConfig{};
  config.local = DeviceEndpointKey{identity.value_if()->device_id(),
                                   m6_filled<EndpointId>(0x20U)};
  config.identity = identity.value_if();
  config.inbound_rate_limit = 100001U;
  EXPECT_FALSE(SignalingCoordinator::create(config, delegate));
}

TEST(M9ParameterFreeze, ShellProfileCapsRejectOversized) {
  auto profile = [] {
    ShellProfileConfig config;
    config.name = "bench";
    // argv[0] must satisfy the host grammar (P2-F1): slash roots on POSIX,
    // drive roots on Windows. This suite never spawns real children.
#if defined(_WIN32)
    config.argv = {"C:\\Windows\\System32\\cmd.exe"};
#else
    config.argv = {"/bin/sh"};
#endif
    return config;
  };
  ASSERT_TRUE(validate_shell_profile(profile()));

  auto config = profile();
  config.idle_timeout = 86400001ms;
  EXPECT_FALSE(validate_shell_profile(config));
  config = profile();
  config.absolute_timeout = 604800001ms;
  EXPECT_FALSE(validate_shell_profile(config));
  config = profile();
  config.max_output_bytes = 1024U * 1024U * 1024U + 1U;
  EXPECT_FALSE(validate_shell_profile(config));
  config = profile();
  config.max_input_pending_bytes = 1024U * 1024U + 1U;
  EXPECT_FALSE(validate_shell_profile(config));
}

TEST(M9ParameterFreeze, RelayServerCapsRejectOversized) {
  auto config = defaults::relay_server();
  ASSERT_TRUE(validate_relay_server_config(config));

  config = defaults::relay_server();
  config.control_write_queue_frames = 65537U;
  EXPECT_FALSE(validate_relay_server_config(config));
  config = defaults::relay_server();
  config.lease.per_device_endpoint_capacity = 65537U;
  EXPECT_FALSE(validate_relay_server_config(config));
  config = defaults::relay_server();
  config.rate_limits.ip.capacity = 1000001U;
  EXPECT_FALSE(validate_relay_server_config(config));
}

// ---------------------------------------------------------------------------
// Service-level caps (enforced in attach): construct each service with one
// oversized knob and expect a configuration failure before channel open.
// ---------------------------------------------------------------------------

M6ServicePair bare_session_pair() {
  M6ServicePair::Options options;
  options.attach_message = false;
  options.attach_rpc = false;
  return M6ServicePair(options);
}

TEST(M9ParameterFreeze, ServiceAttachCapsRejectOversized) {
  auto pair = bare_session_pair();
  auto identity = create_identity();
  ASSERT_TRUE(identity);
  const auto device_id = identity.value_if()->device_id();
  ManualDispatch general;
  ManualBlockingDispatch blocking;
  ManualPoster poster;
  auto book = std::make_shared<FileTransferBook>();
  executor::comm::Topic<LocalEventMessage> topic{"heyaki-m9-freeze-topic"};

  // Message: byte queue above the 256 MiB cap.
  MessageServiceConfig message;
  message.channel_byte_capacity = 256U * 1024U * 1024U + 1U;
  MessageService message_service(*pair.left, pair.left_key(), message,
                                 general.dispatcher(), pair.scope_check(pair.left),
                                 [] { return 0U; });
  auto attached = message_service.attach();
  ASSERT_FALSE(attached);
  EXPECT_EQ(attached.error_if()->code(), ErrorCode::configuration);

  // RPC: server concurrency above the 4096 cap.
  RpcServiceConfig rpc;
  rpc.max_concurrent_server_calls = 4097U;
  auto registry = std::make_shared<ServiceRegistry>();
  RpcService rpc_service(*pair.left, pair.left_key(), rpc, registry,
                         pair.left_rpc_dispatch.dispatcher(),
                         pair.scope_check(pair.left), poster.poster(),
                         [] { return 0U; });
  attached = rpc_service.attach();
  ASSERT_FALSE(attached);
  EXPECT_EQ(attached.error_if()->code(), ErrorCode::configuration);

  // Event: subscriber queue above the 65536 cap.
  EventServiceConfig event;
  event.subscriber_queue_items = 65537U;
  EventService event_service(*pair.left, pair.left_key(), device_id, event,
                             general.dispatcher(), pair.scope_check(pair.left),
                             topic, [] { return 0U; });
  attached = event_service.attach();
  ASSERT_FALSE(attached);
  EXPECT_EQ(attached.error_if()->code(), ErrorCode::configuration);

  // File: send window above the 256 MiB cap.
  FileServiceConfig file;
  file.send_window_bytes = 256U * 1024U * 1024U + 1U;
  FileService file_service(*pair.left, pair.left_key(), file, book,
                           general.dispatcher(), blocking.dispatcher(),
                           pair.scope_check(pair.left), poster.poster(),
                           [] { return 0U; });
  attached = file_service.attach();
  ASSERT_FALSE(attached);
  EXPECT_EQ(attached.error_if()->code(), ErrorCode::configuration);
}

TEST(M9ParameterFreeze, ShellServiceAttachCapRejectsOversized) {
  auto pair = bare_session_pair();
  ShellServiceConfig shell;
  shell.max_output_window_bytes = 64U * 1024U * 1024U + 1U;
  auto pty = std::make_shared<ManualPtyDispatcher>();
  ShellService shell_service(*pair.left, pair.left_key(), shell, pty,
                             pair.scope_check(pair.left), [] { return 0U; });
  auto attached = shell_service.attach();
  ASSERT_FALSE(attached);
  EXPECT_EQ(attached.error_if()->code(), ErrorCode::configuration);
}

// ---------------------------------------------------------------------------
// Orphan staging sweep (M9-11 decision item from the Round 8 fault matrix).
// ---------------------------------------------------------------------------

std::filesystem::path make_sweep_root(const std::string& name) {
  const auto root = std::filesystem::temp_directory_path() /
                    ("heyaki-m9-freeze-" + name + "-" +
                     std::to_string(std::chrono::steady_clock::now()
                                        .time_since_epoch()
                                        .count()));
  std::filesystem::create_directories(root);
  return root;
}

std::string staging_hex(unsigned char seed) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string text(32U, '0');
  for (std::size_t index = 0U; index < text.size(); ++index) {
    text[index] = digits[(seed + static_cast<unsigned char>(index)) % 16U];
  }
  return text;
}

TEST(M9ParameterFreeze, StagingSweepRemovesOnlyStaleLeftovers) {
  const auto root = make_sweep_root("sweep");
  const auto stale_time = std::filesystem::file_time_type::clock::now() - 25h;

  const auto stale_part = root / ("report.heyaki-" + staging_hex(0x1F) + ".part");
  const auto stale_state = root / ("report.heyaki-" + staging_hex(0x1F) + ".state");
  const auto fresh_part = root / ("video.heyaki-" + staging_hex(0x2E) + ".part");
  const auto kept_plain = root / "photo.jpg";
  const auto kept_nonhex = root / ("doc.heyaki-" + std::string(32U, 'z') + ".part");
  const auto kept_suffix = root / ("doc.heyaki-" + staging_hex(0x3D) + ".tmp");
  const auto kept_short = root / "doc.heyaki-abc.part";

  for (const auto& path : {stale_part, stale_state, fresh_part, kept_plain,
                           kept_nonhex, kept_suffix, kept_short}) {
    std::ofstream output(path, std::ios::binary);
    output << "x";
  }
  const auto kept_dir = root / ("dir.heyaki-" + staging_hex(0x4C) + ".part");
  std::filesystem::create_directory(kept_dir);
  for (const auto& path :
       {stale_part, stale_state, kept_plain, kept_nonhex, kept_suffix,
        kept_short}) {
    std::filesystem::last_write_time(path, stale_time);
  }
  std::filesystem::last_write_time(kept_dir, stale_time);

  const auto swept = file_store::sweep_stale_staging(root, 24h);
  ASSERT_TRUE(swept);
  EXPECT_EQ(*swept.value_if(), 2U);
  EXPECT_FALSE(std::filesystem::exists(stale_part));
  EXPECT_FALSE(std::filesystem::exists(stale_state));
  EXPECT_TRUE(std::filesystem::exists(fresh_part));
  EXPECT_TRUE(std::filesystem::exists(kept_plain));
  EXPECT_TRUE(std::filesystem::exists(kept_nonhex));
  EXPECT_TRUE(std::filesystem::exists(kept_suffix));
  EXPECT_TRUE(std::filesystem::exists(kept_short));
  EXPECT_TRUE(std::filesystem::exists(kept_dir));
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

TEST(M9ParameterFreeze, StagingSweepFailsOnMissingRoot) {
  const auto missing =
      std::filesystem::temp_directory_path() / "heyaki-m9-freeze-missing";
  std::error_code ec;
  std::filesystem::remove_all(missing, ec);
  const auto swept = file_store::sweep_stale_staging(missing, 24h);
  EXPECT_FALSE(swept);
}

TEST(M9ParameterFreeze, FileServiceAttachPostsStagingSweep) {
  auto pair = bare_session_pair();
  const auto root = make_sweep_root("attach");
  ManualDispatch general;
  ManualBlockingDispatch blocking;
  ManualPoster poster;
  auto book = std::make_shared<FileTransferBook>();

  FileServiceConfig file;
  FileRootConfig inbox;
  inbox.name = "inbox";
  inbox.directory = root;
  file.receive_roots = {inbox};
  FileService file_service(*pair.left, pair.left_key(), file, book,
                           general.dispatcher(), blocking.dispatcher(),
                           pair.scope_check(pair.left), poster.poster(),
                           [] { return 0U; });
  ASSERT_TRUE(file_service.attach());
  // The sweep is fire-and-forget on the blocking worker; the test double
  // records the admission, which is the attach-side contract.
  EXPECT_EQ(blocking.tasks.size(), 1U);
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

}  // namespace
}  // namespace heyaki::test
