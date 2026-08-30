// M6 unary RPC tests: service registry and method descriptors (M6-07),
// request/response/cancel frames with relative deadlines (M6-08), bounded
// executor admission and exception containment (M6-09), cooperative
// cancellation and late-result races (M6-10), the at-most-once result cache
// (M6-11), session-loss outcomes (M6-12), and streaming-unimplemented
// (M6-13). Executor timing is controlled through the manual queues so
// deadline/cancel races are deterministic.

#include "m6_support.hpp"

#include <heyaki/rpc.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <optional>
#include <stdexcept>
#include <vector>

namespace heyaki {
namespace {

std::vector<std::byte> copy_payload(const RpcCallContext& context) {
  return std::vector<std::byte>(context.payload().begin(), context.payload().end());
}

RpcHandlerResult echo_result(std::vector<std::byte> payload) {
  return RpcHandlerResult{StableStatus::ok, std::move(payload), "ok"};
}

namespace {
// Injects one raw RPC_REQUEST from the left side with full control over the
// wire body (schema version, request id, payload bytes).
void inject_request(test::M6ServicePair& harness, const RpcRequestBody& body) {
  auto encoded = encode_rpc_request(body);
  ASSERT_TRUE(encoded);
  harness.inject_frame(*harness.left, harness.rpc_channel_of(*harness.left),
                       static_cast<std::uint8_t>(FrameType::rpc_request),
                       *encoded.value_if());
}
}  // namespace

TEST(M6RpcProtocolTest, RequestResponseCancelCodecRoundTrip) {
  RpcRequestBody request;
  RequestId::Storage id{};
  id[1] = std::byte{0x33};
  request.request_id = RequestId{id};
  request.service = "device";
  request.method = "read";
  request.schema_version = 3U;
  request.deadline_remaining_milliseconds = 2500U;
  request.idempotency_key = std::vector<std::byte>{std::byte{7}};
  request.metadata.push_back({"channel", {std::byte{1}}});
  request.payload = {std::byte{0xAA}};

  auto encoded = encode_rpc_request(request);
  ASSERT_TRUE(encoded);
  auto parsed = parse_rpc_request(*encoded.value_if());
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value_if()->request_id, request.request_id);
  EXPECT_EQ(parsed.value_if()->service, "device");
  EXPECT_EQ(parsed.value_if()->method, "read");
  EXPECT_EQ(parsed.value_if()->schema_version, 3U);
  EXPECT_EQ(parsed.value_if()->deadline_remaining_milliseconds, 2500U);
  ASSERT_TRUE(parsed.value_if()->idempotency_key.has_value());
  EXPECT_EQ(*parsed.value_if()->idempotency_key, *request.idempotency_key);
  EXPECT_EQ(parsed.value_if()->payload, request.payload);

  RpcResponseBody response;
  response.request_id = request.request_id;
  response.status = StableStatus::ok;
  response.safe_detail = "ok";
  response.payload = {std::byte{9}};
  auto encoded_response = encode_rpc_response(response);
  ASSERT_TRUE(encoded_response);
  auto parsed_response = parse_rpc_response(*encoded_response.value_if());
  ASSERT_TRUE(parsed_response);
  EXPECT_EQ(parsed_response.value_if()->status, StableStatus::ok);
  EXPECT_EQ(parsed_response.value_if()->payload, response.payload);

  // Unsafe details are rejected at encode time (they would cross to peers).
  response.safe_detail = "not safe!";
  EXPECT_FALSE(encode_rpc_response(response));

  auto encoded_cancel = encode_rpc_cancel(RpcCancelBody{request.request_id});
  ASSERT_TRUE(encoded_cancel);
  auto parsed_cancel = parse_rpc_cancel(*encoded_cancel.value_if());
  ASSERT_TRUE(parsed_cancel);
  EXPECT_EQ(parsed_cancel.value_if()->request_id, request.request_id);

  EXPECT_FALSE(parse_rpc_request({}));
  const std::vector<std::byte> garbage(10U, std::byte{0x7F});
  EXPECT_FALSE(parse_rpc_request(garbage));
}

TEST(M6RpcRegistryTest, RegisterLookupUnregisterAndValidation) {
  ServiceRegistry registry;
  EXPECT_TRUE(registry.register_method(
      RpcMethodDescriptor{"device", "read", 1U, "rpc.device.read", false},
      [](const RpcCallContext&) { return echo_result({}); }));
  EXPECT_EQ(registry.registered_methods(), 1U);
  EXPECT_TRUE(registry.lookup("device", "read").has_value());
  EXPECT_FALSE(registry.lookup("device", "write").has_value());
  EXPECT_FALSE(registry.lookup("other", "read").has_value());

  // Duplicate registration is refused.
  EXPECT_FALSE(registry.register_method(
      RpcMethodDescriptor{"device", "read", 2U, "rpc.device.read", false},
      [](const RpcCallContext&) { return echo_result({}); }));

  // Invalid descriptors never register.
  EXPECT_FALSE(registry.register_method(
      RpcMethodDescriptor{"", "read", 1U, "rpc.device.read", false},
      [](const RpcCallContext&) { return echo_result({}); }));
  EXPECT_FALSE(registry.register_method(
      RpcMethodDescriptor{"device", "", 1U, "rpc.device.read", false},
      [](const RpcCallContext&) { return echo_result({}); }));
  EXPECT_FALSE(registry.register_method(
      RpcMethodDescriptor{"device", "read", 0U, "rpc.device.read", false},
      [](const RpcCallContext&) { return echo_result({}); }));
  EXPECT_FALSE(registry.register_method(RpcMethodDescriptor{"device", "read", 1U, "", false},
                                        nullptr));

  const auto summaries = registry.methods();
  ASSERT_EQ(summaries.size(), 1U);
  EXPECT_EQ(summaries[0].service, "device");
  EXPECT_EQ(summaries[0].required_scope, "rpc.device.read");

  EXPECT_TRUE(registry.unregister_method("device", "read"));
  EXPECT_FALSE(registry.unregister_method("device", "read"));
}

TEST(M6RpcServiceTest, UnaryCallSucceedsEndToEnd) {
  test::M6ServicePair harness;
  std::atomic<int> executions{0};
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "echo", 1U, "rpc.device.read", false},
      [&executions](const RpcCallContext& context) {
        ++executions;
        return echo_result(copy_payload(context));
      }));

  std::vector<Result<RpcCallOutcome>> results;
  auto started = harness.left_rpc->call(
      "device", "echo", {std::byte{0x42}}, RpcCallOptions{},
      [&results](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) {
        results.push_back(std::move(outcome));
      });
  ASSERT_TRUE(started);
  harness.cycle();

  ASSERT_EQ(results.size(), 1U);
  ASSERT_TRUE(results.front());
  EXPECT_EQ(results.front().value_if()->status, StableStatus::ok);
  EXPECT_EQ(results.front().value_if()->payload,
            std::vector<std::byte>{std::byte{0x42}});
  EXPECT_EQ(executions.load(), 1);
  EXPECT_EQ(harness.right_rpc->stats().handlers_executed, 1U);
  EXPECT_EQ(harness.left_rpc->stats().calls_started, 1U);
  EXPECT_EQ(harness.left_rpc->stats().responses_matched, 1U);
  // Exactly one completion and one response frame.
  EXPECT_EQ(results.size(), 1U);
  EXPECT_EQ(harness.right_rpc->stats().responses_sent, 1U);
}

TEST(M6RpcServiceTest, UnknownMethodAnswersUnimplemented) {
  test::M6ServicePair harness;
  std::vector<Result<RpcCallOutcome>> results;
  ASSERT_TRUE(harness.left_rpc->call(
      "device", "nope", {}, RpcCallOptions{},
      [&results](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) { results.push_back(std::move(outcome)); }));
  harness.cycle();
  ASSERT_EQ(results.size(), 1U);
  ASSERT_TRUE(results.front());
  EXPECT_EQ(results.front().value_if()->status, StableStatus::unimplemented);
  EXPECT_EQ(results.front().value_if()->safe_detail, "method_unknown");
  EXPECT_EQ(harness.right_rpc->stats().unimplemented_answers, 1U);
  EXPECT_EQ(harness.right_rpc->stats().handlers_executed, 0U);
}

TEST(M6RpcServiceTest, StreamingMethodsStayUnimplemented) {
  test::M6ServicePair harness;
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "watch", 1U, "rpc.device.read", true},
      [](const RpcCallContext&) { return echo_result({}); }));

  std::vector<Result<RpcCallOutcome>> results;
  ASSERT_TRUE(harness.left_rpc->call(
      "device", "watch", {}, RpcCallOptions{},
      [&results](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) { results.push_back(std::move(outcome)); }));
  harness.cycle();
  ASSERT_EQ(results.size(), 1U);
  ASSERT_TRUE(results.front());
  EXPECT_EQ(results.front().value_if()->status, StableStatus::unimplemented);
  EXPECT_EQ(results.front().value_if()->safe_detail, "streaming_unimplemented");
  EXPECT_EQ(harness.right_rpc->stats().handlers_executed, 0U);
}

TEST(M6RpcServiceTest, SchemaTooNewRejectedBeforeHandler) {
  test::M6ServicePair harness;
  std::atomic<int> executions{0};
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "echo", 1U, "rpc.device.read", false},
      [&executions](const RpcCallContext&) {
        ++executions;
        return echo_result({});
      }));

  // Hand-built v2 request against a v1 descriptor: rejected with a stable
  // failed_precondition before the handler runs.
  RpcRequestBody body;
  RequestId::Storage id{};
  id[9] = std::byte{0xE1};
  body.request_id = RequestId{id};
  body.service = "device";
  body.method = "echo";
  body.schema_version = 2U;
  body.deadline_remaining_milliseconds = 5000U;
  inject_request(harness, body);

  EXPECT_EQ(executions.load(), 0);
  EXPECT_EQ(harness.right_rpc->stats().schema_rejected, 1U);
  EXPECT_EQ(harness.right_rpc->stats().handlers_executed, 0U);
  EXPECT_EQ(harness.right_rpc->stats().responses_sent, 1U);
}

TEST(M6RpcServiceTest, ScopeMissingAnswersPermissionDenied) {
  test::M6ServicePair::Options options;
  options.right_scopes = {"message.send"};  // no rpc.device.read
  test::M6ServicePair harness{options};
  std::atomic<int> executions{0};
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "configure", 1U, "rpc.device.configure", false},
      [&executions](const RpcCallContext&) {
        ++executions;
        return echo_result({});
      }));

  std::vector<Result<RpcCallOutcome>> results;
  ASSERT_TRUE(harness.left_rpc->call(
      "device", "configure", {}, RpcCallOptions{},
      [&results](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) { results.push_back(std::move(outcome)); }));
  harness.cycle();
  ASSERT_EQ(results.size(), 1U);
  ASSERT_TRUE(results.front());
  EXPECT_EQ(results.front().value_if()->status, StableStatus::permission_denied);
  EXPECT_EQ(executions.load(), 0);
  EXPECT_EQ(harness.right_rpc->stats().scope_rejected, 1U);
}

TEST(M6RpcServiceTest, ConcurrencyLimitAnswersResourceExhausted) {
  test::M6ServicePair::Options options;
  options.right_rpc.max_concurrent_server_calls = 1U;
  test::M6ServicePair harness{options};
  std::atomic<int> executions{0};
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "slow", 1U, "rpc.device.read", false},
      [&executions](const RpcCallContext&) {
        ++executions;
        return echo_result({});
      }));

  // The first request occupies the only executing slot from admission until
  // its (still queued) task completes; the executor queue is not drained.
  std::vector<Result<RpcCallOutcome>> first_results;
  ASSERT_TRUE(harness.left_rpc->call(
      "device", "slow", {}, RpcCallOptions{},
      [&first_results](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) {
        first_results.push_back(std::move(outcome));
      }));
  harness.pump();
  ASSERT_EQ(harness.right_rpc->executing_calls(), 1U);
  ASSERT_TRUE(harness.right_dispatch.has_pending());

  std::vector<Result<RpcCallOutcome>> second_results;
  ASSERT_TRUE(harness.left_rpc->call(
      "device", "slow", {}, RpcCallOptions{},
      [&second_results](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) {
        second_results.push_back(std::move(outcome));
      }));
  harness.pump();
  ASSERT_EQ(second_results.size(), 1U);
  ASSERT_TRUE(second_results.front());
  EXPECT_EQ(second_results.front().value_if()->status, StableStatus::resource_exhausted);
  EXPECT_EQ(second_results.front().value_if()->safe_detail, "concurrency_limit");
  EXPECT_EQ(harness.right_rpc->stats().concurrency_rejected, 1U);
  EXPECT_EQ(executions.load(), 0U);

  // Draining the executor completes the first call normally.
  harness.cycle();
  EXPECT_EQ(executions.load(), 1U);
  ASSERT_EQ(first_results.size(), 1U);
  EXPECT_EQ(first_results.front().value_if()->status, StableStatus::ok);
}

TEST(M6RpcServiceTest, DispatchRejectionAnswersResourceExhausted) {
  test::M6ServicePair harness;
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "echo", 1U, "rpc.device.read", false},
      [](const RpcCallContext&) { return echo_result({}); }));
  harness.right_dispatch.admit = false;

  std::vector<Result<RpcCallOutcome>> results;
  ASSERT_TRUE(harness.left_rpc->call(
      "device", "echo", {}, RpcCallOptions{},
      [&results](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) { results.push_back(std::move(outcome)); }));
  harness.pump();
  ASSERT_EQ(results.size(), 1U);
  ASSERT_TRUE(results.front());
  EXPECT_EQ(results.front().value_if()->status, StableStatus::resource_exhausted);
  EXPECT_EQ(results.front().value_if()->safe_detail, "dispatch_rejected");
  EXPECT_EQ(harness.right_rpc->stats().dispatch_rejected, 1U);
  EXPECT_EQ(harness.right_rpc->stats().handlers_executed, 0U);
}

TEST(M6RpcServiceTest, HandlerExceptionMapsToSafeInternal) {
  test::M6ServicePair harness;
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "boom", 1U, "rpc.device.read", false},
      [](const RpcCallContext&) -> RpcHandlerResult {
        throw std::runtime_error("secret detail");
      }));

  std::vector<Result<RpcCallOutcome>> results;
  ASSERT_TRUE(harness.left_rpc->call(
      "device", "boom", {}, RpcCallOptions{},
      [&results](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) { results.push_back(std::move(outcome)); }));
  harness.cycle();
  ASSERT_EQ(results.size(), 1U);
  ASSERT_TRUE(results.front());
  EXPECT_EQ(results.front().value_if()->status, StableStatus::internal);
  EXPECT_EQ(results.front().value_if()->safe_detail, "handler_exception");
  EXPECT_EQ(harness.right_rpc->stats().handler_exceptions, 1U);
}

TEST(M6RpcServiceTest, CooperativeCancelReachesHandler) {
  test::M6ServicePair harness;
  std::atomic<bool> observed_cancel{false};
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "wait", 1U, "rpc.device.read", false},
      [&observed_cancel](const RpcCallContext& context) {
        observed_cancel.store(context.cancelled());
        return RpcHandlerResult{StableStatus::cancelled, {}, "observed_cancel"};
      }));

  std::vector<Result<RpcCallOutcome>> results;
  RequestId request_id;
  auto started = harness.left_rpc->call(
      "device", "wait", {}, RpcCallOptions{},
      [&results](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) { results.push_back(std::move(outcome)); });
  ASSERT_TRUE(started);
  request_id = *started.value_if();
  harness.pump();
  ASSERT_TRUE(harness.right_dispatch.has_pending());

  // Cancel before the queued task runs: the RPC_CANCEL flag is already set
  // when the handler starts (cooperative, not preemptive).
  ASSERT_TRUE(harness.left_rpc->cancel(request_id));
  harness.pump();
  harness.right_dispatch.run_all();
  harness.right_poster.run_all();
  harness.pump();

  ASSERT_EQ(results.size(), 1U);
  ASSERT_TRUE(results.front());
  EXPECT_EQ(results.front().value_if()->status, StableStatus::cancelled);
  EXPECT_TRUE(observed_cancel.load());
  EXPECT_EQ(harness.left_rpc->stats().cancels_sent, 1U);
}

TEST(M6RpcServiceTest, DeadlineWhileExecutingAnswersAndDropsLateResult) {
  test::M6ServicePair harness;
  std::atomic<bool> handler_finished{false};
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "slow", 1U, "rpc.device.read", false},
      [&handler_finished](const RpcCallContext& context) {
        // Simulate work that outlives the deadline without observing it.
        (void)context;
        handler_finished.store(true);
        return echo_result({std::byte{0xFF}});
      }));

  std::vector<Result<RpcCallOutcome>> results;
  RpcCallOptions options;
  options.deadline_remaining_milliseconds = 1000U;
  ASSERT_TRUE(harness.left_rpc->call(
      "device", "slow", {}, options,
      [&results](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) { results.push_back(std::move(outcome)); }));
  harness.pump();
  ASSERT_TRUE(harness.right_dispatch.has_pending());

  // The handler RUNS to completion inside the deadline (the executor task
  // finishes and posts its result), but the deadline expires before the
  // posted completion reaches the service: prune answers deadline_exceeded
  // and the late handler result is dropped (M6-10 race).
  harness.right_dispatch.run_all();
  ASSERT_TRUE(handler_finished.load());
  ASSERT_TRUE(harness.right_poster.has_pending());

  harness.right_clock += 1001U;
  harness.right_rpc->prune();
  harness.right_poster.run_all();
  harness.pump();

  EXPECT_EQ(harness.right_rpc->stats().handler_deadline_exceeded, 1U);
  EXPECT_EQ(harness.right_rpc->stats().late_results_dropped, 1U);
  harness.cycle();
  ASSERT_EQ(results.size(), 1U);
  ASSERT_TRUE(results.front());
  EXPECT_EQ(results.front().value_if()->status, StableStatus::deadline_exceeded);
  // Exactly one response was sent despite handler completion.
  EXPECT_EQ(harness.right_rpc->stats().responses_sent, 1U);
}

TEST(M6RpcServiceTest, DuplicateRequestReplaysCachedResultWithoutRerun) {
  test::M6ServicePair harness;
  std::atomic<int> executions{0};
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "once", 1U, "rpc.device.read", false},
      [&executions](const RpcCallContext& context) {
        ++executions;
        return echo_result(copy_payload(context));
      }));

  std::vector<Result<RpcCallOutcome>> results;
  RequestId request_id;
  auto started = harness.left_rpc->call(
      "device", "once", {std::byte{0x11}}, RpcCallOptions{},
      [&results](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) { results.push_back(std::move(outcome)); });
  ASSERT_TRUE(started);
  request_id = *started.value_if();
  harness.cycle();
  ASSERT_EQ(executions.load(), 1);

  // Rebuild and resend the identical request bytes (including the deadline
  // the original call used): cached replay, no second execution (M6-11).
  RpcRequestBody body;
  body.request_id = request_id;
  body.service = "device";
  body.method = "once";
  body.schema_version = 1U;
  body.deadline_remaining_milliseconds = RpcCallOptions{}.deadline_remaining_milliseconds;
  body.payload = {std::byte{0x11}};
  inject_request(harness, body);

  EXPECT_EQ(executions.load(), 1);
  EXPECT_EQ(harness.right_rpc->stats().replayed_responses, 1U);
  EXPECT_EQ(harness.right_rpc->stats().responses_sent, 2U);
}

TEST(M6RpcServiceTest, DuplicateWhileExecutingDoesNotStartTwice) {
  test::M6ServicePair harness;
  std::atomic<int> executions{0};
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "once", 1U, "rpc.device.read", false},
      [&executions](const RpcCallContext& context) {
        ++executions;
        return echo_result(copy_payload(context));
      }));

  RpcRequestBody body;
  RequestId::Storage id{};
  id[4] = std::byte{0x5C};
  body.request_id = RequestId{id};
  body.service = "device";
  body.method = "once";
  body.schema_version = 1U;
  body.deadline_remaining_milliseconds = 5000U;
  body.payload = {std::byte{0x22}};

  inject_request(harness, body);
  inject_request(harness, body);
  // Second identical frame arrived while the first is queued (executing):
  // counted as duplicate, exactly one execution when the task runs.
  EXPECT_EQ(harness.right_rpc->stats().duplicate_requests, 1U);
  harness.right_dispatch.run_all();
  harness.right_poster.run_all();
  harness.pump();
  EXPECT_EQ(executions.load(), 1);
}

TEST(M6RpcServiceTest, SessionLossNonIdempotentIsOutcomeUnknown) {
  test::M6ServicePair harness;
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "slow", 1U, "rpc.device.read", false},
      [](const RpcCallContext& context) {
        (void)context;
        return echo_result({});
      }));

  std::vector<Result<RpcCallOutcome>> results;
  ASSERT_TRUE(harness.left_rpc->call(
      "device", "slow", {}, RpcCallOptions{},
      [&results](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) { results.push_back(std::move(outcome)); }));
  harness.pump();
  ASSERT_EQ(harness.left_rpc->pending_calls(), 1U);

  // The transport dies after the request was admitted: the outcome is
  // unknown — the library never retries a non-idempotent call (M6-12).
  harness.left->close(transport::CloseReason::transport_failed);
  harness.left_rpc->handle_session_closed();
  ASSERT_EQ(results.size(), 1U);
  ASSERT_TRUE(results.front());
  EXPECT_EQ(results.front().value_if()->status, StableStatus::outcome_unknown);
  EXPECT_EQ(results.front().value_if()->safe_detail, "session_lost_non_idempotent");
  EXPECT_EQ(harness.left_rpc->stats().outcome_unknown_calls, 1U);
  EXPECT_EQ(harness.left_rpc->pending_calls(), 0U);

  // A late response from a resurrected peer is counted, never delivered.
  FrameView late;
  late.type = static_cast<std::uint8_t>(FrameType::rpc_response);
  late.channel_id = harness.rpc_channel_of(*harness.left);
  RequestId::Storage late_id{};
  late_id[2] = std::byte{0x9B};
  RpcResponseBody response;
  response.request_id = RequestId{late_id};
  response.status = StableStatus::ok;
  response.safe_detail = "ok";
  auto encoded = encode_rpc_response(response);
  ASSERT_TRUE(encoded);
  late.payload = *encoded.value_if();
  harness.left_rpc->handle_frame(late);
  EXPECT_EQ(harness.left_rpc->stats().responses_unknown, 1U);
}

TEST(M6RpcServiceTest, IdempotentRetryResubmitsAcrossSessions) {
  test::M6ServicePair harness;
  std::atomic<int> executions{0};
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "safe", 1U, "rpc.device.read", false},
      [&executions](const RpcCallContext& context) {
        ++executions;
        return echo_result(copy_payload(context));
      }));

  std::vector<Result<RpcCallOutcome>> results;
  RpcCallOptions options;
  options.idempotent = true;
  options.retry_on_reconnect = true;
  options.deadline_remaining_milliseconds = 60'000U;
  auto started = harness.left_rpc->call(
      "device", "safe", {std::byte{0x33}}, options,
      [&results](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) { results.push_back(std::move(outcome)); });
  ASSERT_TRUE(started);
  harness.pump();

  harness.left->close(transport::CloseReason::transport_failed);
  harness.left_rpc->handle_session_closed();
  auto retryables = harness.left_rpc->take_retryable_calls();
  ASSERT_EQ(retryables.size(), 1U);
  EXPECT_TRUE(results.empty());  // completion still pending

  // A NEW session/service pair (fresh transport), same request id, remaining
  // deadline preserved: policy-driven retry; re-execution is permitted
  // because the call is explicitly idempotent (the at-most-once window in
  // M6-11 is per session).
  test::M6ServicePair second_harness;
  ASSERT_TRUE(second_harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "safe", 1U, "rpc.device.read", false},
      [&executions](const RpcCallContext& context) {
        ++executions;
        return echo_result(copy_payload(context));
      }));
  retryables.front().deadline_unix_milliseconds = second_harness.left_clock + 30'000U;
  auto resubmitted = second_harness.left_rpc->resubmit(std::move(retryables.front()));
  ASSERT_TRUE(resubmitted);
  second_harness.cycle();

  ASSERT_EQ(results.size(), 1U);
  ASSERT_TRUE(results.front());
  EXPECT_EQ(results.front().value_if()->status, StableStatus::ok);
  EXPECT_EQ(results.front().value_if()->payload, std::vector<std::byte>{std::byte{0x33}});
}

TEST(M6RpcServiceTest, LocalDeadlineExpiresPendingCall) {
  test::M6ServicePair harness;
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "slow", 1U, "rpc.device.read", false},
      [](const RpcCallContext&) { return echo_result({}); }));

  std::vector<Result<RpcCallOutcome>> results;
  RpcCallOptions options;
  options.deadline_remaining_milliseconds = 700U;
  ASSERT_TRUE(harness.left_rpc->call(
      "device", "slow", {}, options,
      [&results](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) { results.push_back(std::move(outcome)); }));
  harness.pump();

  harness.left_clock += 701U;
  harness.left_rpc->prune();
  ASSERT_EQ(results.size(), 1U);
  ASSERT_TRUE(results.front());
  EXPECT_EQ(results.front().value_if()->status, StableStatus::deadline_exceeded);
  EXPECT_EQ(harness.left_rpc->stats().local_deadline_exceeded, 1U);

  // The server's eventual response lands on a finished call: counted unknown.
  harness.cycle();
  EXPECT_EQ(harness.left_rpc->pending_calls(), 0U);
}

TEST(M6RpcServiceTest, PendingCapacityIsBounded) {
  test::M6ServicePair::Options options;
  options.left_rpc.max_pending_client_calls = 1U;
  test::M6ServicePair harness{options};
  ASSERT_TRUE(harness.right_registry->register_method(
      RpcMethodDescriptor{"device", "slow", 1U, "rpc.device.read", false},
      [](const RpcCallContext& context) {
        (void)context;
        return echo_result({});
      }));

  std::vector<Result<RpcCallOutcome>> first;
  ASSERT_TRUE(harness.left_rpc->call(
      "device", "slow", {}, RpcCallOptions{},
      [&first](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) { first.push_back(std::move(outcome)); }));
  harness.pump();
  ASSERT_EQ(harness.left_rpc->pending_calls(), 1U);

  std::vector<Result<RpcCallOutcome>> second;
  auto started = harness.left_rpc->call(
      "device", "slow", {}, RpcCallOptions{},
      [&second](const heyaki::DeviceEndpointKey&, Result<RpcCallOutcome> outcome) { second.push_back(std::move(outcome)); });
  EXPECT_FALSE(started);
  ASSERT_EQ(second.size(), 1U);
  EXPECT_FALSE(second.front());
  EXPECT_EQ(second.front().error_if()->code(), ErrorCode::resource_exhausted);
  EXPECT_EQ(harness.left_rpc->stats().calls_admission_rejected, 1U);
}

TEST(M6RpcServiceTest, CancelUnknownRequestFails) {
  test::M6ServicePair harness;
  const auto cancelled =
      harness.left_rpc->cancel(RequestId{RequestId::Storage{std::byte{1}}});
  EXPECT_FALSE(cancelled);
  EXPECT_EQ(cancelled.error_if()->code(), ErrorCode::not_registered);
}

}  // namespace
}  // namespace heyaki
