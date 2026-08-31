#include "rpc_service.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <utility>

namespace heyaki {
namespace {

RequestId random_request_id() {
  RequestId::Storage bytes{};
  do {
    randombytes_buf(bytes.data(), bytes.size());
  } while (RequestId{bytes}.is_zero());
  return RequestId{bytes};
}

std::vector<std::byte> payload_digest(std::span<const std::byte> encoded) {
  std::array<unsigned char, 32> digest{};
  crypto_hash_sha256(digest.data(), reinterpret_cast<const unsigned char*>(encoded.data()),
                     encoded.size());
  std::vector<std::byte> output(digest.size());
  for (std::size_t index = 0U; index < digest.size(); ++index) {
    output[index] = static_cast<std::byte>(digest[index]);
  }
  return output;
}

Error rpc_service_error(ErrorCode code, std::string_view detail) {
  return Error{code, "rpc", std::string{detail}};
}

std::string sanitize_detail(std::string detail) {
  if (!is_safe_detail_token(detail)) {
    return "handler_detail_invalid";
  }
  return detail;
}

}  // namespace

RpcService::RpcService(PeerSession& session, DeviceEndpointKey peer,
                       RpcServiceConfig config,
                       const std::shared_ptr<ServiceRegistry>& registry,
                       CancellableServiceDispatch dispatch, ScopeCheck scope_check,
                       StrandPoster poster, std::function<std::uint64_t()> wall_clock)
    : session_(session),
      peer_(std::move(peer)),
      config_(config),
      registry_(registry),
      dispatch_(std::move(dispatch)),
      scope_check_(std::move(scope_check)),
      poster_(std::move(poster)),
      wall_clock_(std::move(wall_clock)) {}

RpcService::~RpcService() {
  session_.set_domain_handler(session::ChannelDomain::rpc, DomainFrameHandler{});
  for (const auto channel : owned_channels_) {
    session_.close_business_channel(channel);
  }
  // Executing handlers keep running cooperatively; their posted completions
  // find a dead weak reference and are dropped, never touching dead state.
}

std::uint64_t RpcService::now() const {
  if (wall_clock_) return wall_clock_();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

Result<void> RpcService::attach() {
  if (attached_) {
    return Result<void>::success();
  }
  if (config_.max_concurrent_server_calls == 0U ||
      config_.max_pending_client_calls == 0U || config_.channel_frame_capacity == 0U ||
      config_.channel_byte_capacity == 0U || config_.result_cache_bytes == 0U) {
    return Result<void>::failure(
        rpc_service_error(ErrorCode::configuration, "rpc_config_invalid"));
  }
  if (!registry_ || !dispatch_ || !poster_) {
    return Result<void>::failure(
        rpc_service_error(ErrorCode::configuration, "rpc_dependencies_missing"));
  }
  auto weak = weak_from_this();
  auto opened = session_.open_business_channel(
      session::ChannelDomain::rpc, session::QueueFullPolicy::reject,
      config_.channel_frame_capacity, config_.channel_byte_capacity,
      [weak](const FrameView& frame) {
        if (auto self = weak.lock()) self->handle_frame(frame);
      });
  if (!opened) return Result<void>::failure(*opened.error_if());
  channel_id_ = *opened.value_if();
  owned_channels_.push_back(channel_id_);
  session_.set_domain_handler(
      session::ChannelDomain::rpc,
      [weak](const FrameView& frame) -> Result<void> {
        auto self = weak.lock();
        if (!self) {
          return Result<void>::failure(
              rpc_service_error(ErrorCode::cancelled, "service_detached"));
        }
        return self->admit_frame(frame);
      });
  attached_ = true;
  return Result<void>::success();
}

Result<RequestId> RpcService::call(std::string service, std::string method,
                                   std::vector<std::byte> payload,
                                   RpcCallOptions options,
                                   Completion completion, RequestId request_id) {
  if (!attached_) {
    return Result<RequestId>::failure(
        rpc_service_error(ErrorCode::configuration, "service_not_attached"));
  }
  if (!completion) {
    return Result<RequestId>::failure(
        rpc_service_error(ErrorCode::configuration, "completion_missing"));
  }
  if (options.retry_on_reconnect && !options.idempotent) {
    return Result<RequestId>::failure(
        rpc_service_error(ErrorCode::configuration, "retry_requires_idempotent"));
  }
  RpcRequestBody request;
  request.request_id =
      request_id.is_zero() ? random_request_id() : request_id;
  request.service = std::move(service);
  request.method = std::move(method);
  request.schema_version = 1U;
  request.deadline_remaining_milliseconds = options.deadline_remaining_milliseconds;
  request.idempotency_key = options.idempotency_key;
  request.metadata = options.metadata;
  request.payload = std::move(payload);
  return submit_call(std::move(request), options.idempotent, options.retry_on_reconnect,
                     std::move(completion));
}

Result<RequestId> RpcService::resubmit(RetryableCall call) {
  if (!attached_) {
    return Result<RequestId>::failure(
        rpc_service_error(ErrorCode::configuration, "service_not_attached"));
  }
  const auto remaining =
      call.deadline_unix_milliseconds > now() ? call.deadline_unix_milliseconds - now()
                                              : 0U;
  if (remaining == 0U) {
    ++stats_.outcome_unknown_calls;
    call.completion(peer_, Result<RpcCallOutcome>::success(
        RpcCallOutcome{StableStatus::outcome_unknown, "retry_deadline_expired", {}}));
    return Result<RequestId>::success(call.request.request_id);
  }
  if (call.request.deadline_remaining_milliseconds > remaining) {
    call.request.deadline_remaining_milliseconds = static_cast<std::uint32_t>(remaining);
  }
  return submit_call(std::move(call.request), true, true, std::move(call.completion));
}

Result<RequestId> RpcService::submit_call(RpcRequestBody request, bool idempotent,
                                          bool retry_on_reconnect,
                                          Completion completion) {
  const auto id = request.request_id;
  auto encoded = encode_rpc_request(request, session_.channels().limits());
  if (!encoded) {
    ++stats_.calls_admission_rejected;
    completion(peer_, Result<RpcCallOutcome>::failure(*encoded.error_if()));
    return Result<RequestId>::failure(*encoded.error_if());
  }
  if (pending_.size() >= config_.max_pending_client_calls) {
    ++stats_.calls_admission_rejected;
    const auto error =
        rpc_service_error(ErrorCode::resource_exhausted, "pending_call_capacity");
    completion(peer_, Result<RpcCallOutcome>::failure(error));
    return Result<RequestId>::failure(error);
  }
  if (pending_.contains(id)) {
    ++stats_.calls_admission_rejected;
    const auto error = rpc_service_error(ErrorCode::configuration, "request_id_in_use");
    completion(peer_, Result<RpcCallOutcome>::failure(error));
    return Result<RequestId>::failure(error);
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::rpc_request);
  frame.channel_id = channel_id_;
  frame.payload = std::move(*encoded.value_if());
  const auto sent =
      session_.send_frame(channel_id_, session::FrameClass::standard, std::move(frame));
  if (!sent) {
    // Admission failure: the request never left this device, so the outcome
    // is deterministic (this is NOT outcome_unknown).
    ++stats_.calls_admission_rejected;
    completion(peer_, Result<RpcCallOutcome>::failure(*sent.error_if()));
    return Result<RequestId>::failure(*sent.error_if());
  }
  PendingCall pending;
  pending.deadline_unix_milliseconds =
      now() + request.deadline_remaining_milliseconds;
  pending.idempotent = idempotent;
  pending.retry_on_reconnect = retry_on_reconnect;
  pending.completion = std::move(completion);
  pending.request = std::move(request);
  pending_.emplace(id, std::move(pending));
  ++stats_.calls_started;
  return Result<RequestId>::success(id);
}

Result<void> RpcService::cancel(const RequestId& request_id) {
  const auto pending = pending_.find(request_id);
  if (pending == pending_.end()) {
    return Result<void>::failure(
        rpc_service_error(ErrorCode::not_registered, "request_not_pending"));
  }
  // Cooperative: the peer's handler observes RPC_CANCEL if still running;
  // the local call finishes immediately and any late response is counted
  // rather than delivered (M6-10).
  auto encoded = encode_rpc_cancel(RpcCancelBody{request_id});
  if (encoded) {
    Frame frame;
    frame.type = static_cast<std::uint8_t>(FrameType::rpc_cancel);
    frame.channel_id = channel_id_;
    frame.payload = std::move(*encoded.value_if());
    if (session_.send_frame(channel_id_, session::FrameClass::control, std::move(frame))) {
      ++stats_.cancels_sent;
    }
  }
  complete_pending(
      request_id,
      Result<RpcCallOutcome>::success(
          RpcCallOutcome{StableStatus::cancelled, "cancelled_locally", {}}));
  return Result<void>::success();
}

void RpcService::prune() {
  prune_client_deadlines();
  prune_executing_deadlines();
}

void RpcService::handle_session_closed() {
  // Server side: executing calls never emit a response now; their late
  // handler results are dropped when they post back to a dead service.
  for (auto& [id, call] : executing_) {
    call->phase.store(1U, std::memory_order_release);
    // Queued handler tasks terminate at the executor instead of running into
    // the dead-session check; running ones receive the cooperative request.
    if (call->cancel_request) {
      (void)call->cancel_request();
    }
  }
  executing_.clear();
  // Client side (M6-12): non-idempotent calls become outcome_unknown and the
  // library never retries automatically; idempotent calls that opted in are
  // handed back for policy-driven resubmission on a future session.
  std::map<RequestId, PendingCall> pending;
  pending.swap(pending_);
  for (auto& [id, entry] : pending) {
    if (entry.idempotent && entry.retry_on_reconnect) {
      RetryableCall retryable;
      retryable.request = std::move(entry.request);
      retryable.deadline_unix_milliseconds = entry.deadline_unix_milliseconds;
      retryable.cancel_requested = entry.cancel_requested;
      retryable.completion = std::move(entry.completion);
      retryable_.push_back(std::move(retryable));
      ++stats_.retryable_handled;
      continue;
    }
    ++stats_.outcome_unknown_calls;
    auto completion = std::move(entry.completion);
    const auto detail = entry.idempotent ? "session_lost_idempotent_no_retry"
                                         : "session_lost_non_idempotent";
    completion(peer_, Result<RpcCallOutcome>::success(
        RpcCallOutcome{StableStatus::outcome_unknown, detail, {}}));
  }
}

std::vector<RpcService::RetryableCall> RpcService::take_retryable_calls() {
  return std::move(retryable_);
}

void RpcService::handle_frame(const FrameView& frame) {
  (void)admit_frame(frame);
}

Result<void> RpcService::admit_frame(const FrameView& frame) {
  if (!attached_) {
    return Result<void>::failure(
        rpc_service_error(ErrorCode::configuration, "service_not_attached"));
  }
  const auto type = static_cast<FrameType>(frame.type);
  if (type == FrameType::rpc_request) {
    if (!session_.has_business_channel(frame.channel_id)) {
      auto weak = weak_from_this();
      auto adopted = session_.adopt_business_channel(
          frame.channel_id, session::ChannelDomain::rpc,
          session::QueueFullPolicy::reject, config_.channel_frame_capacity,
          config_.channel_byte_capacity,
          [weak](const FrameView& inbound) {
            if (auto self = weak.lock()) self->handle_frame(inbound);
          });
      if (!adopted) return Result<void>::failure(*adopted.error_if());
      owned_channels_.push_back(*adopted.value_if());
    }
    handle_request(frame);
    return Result<void>::success();
  }
  if (type == FrameType::rpc_response || type == FrameType::rpc_cancel) {
    if (!session_.has_business_channel(frame.channel_id)) {
      return Result<void>::failure(
          rpc_service_error(ErrorCode::protocol, "rpc_channel_unknown"));
    }
    if (type == FrameType::rpc_response) {
      handle_response(frame);
    } else {
      handle_cancel(frame);
    }
    return Result<void>::success();
  }
  return Result<void>::failure(
      rpc_service_error(ErrorCode::protocol, "rpc_domain_frame_unknown"));
}

void RpcService::handle_request(const FrameView& frame) {
  ++stats_.requests_received;
  auto parsed = parse_rpc_request(frame.payload, session_.channels().limits());
  if (!parsed) {
    // Malformed service frames close only their logical channel (wire 6.2).
    ++stats_.invalid_requests;
    session_.fail_business_channel(frame.channel_id,
                                   transport::CloseReason::protocol_error);
    return;
  }
  const auto& request = *parsed.value_if();
  const auto digest = payload_digest(frame.payload);

  // At-most-once window (M6-11): terminal results replay, executing requests
  // never start twice, and conflicting bytes close the channel.
  if (const auto cached = result_cache_.find(request.request_id);
      cached != result_cache_.end()) {
    if (cached->second.request_digest == digest) {
      ++stats_.replayed_responses;
      Frame replay;
      replay.type = static_cast<std::uint8_t>(FrameType::rpc_response);
      replay.channel_id = frame.channel_id;
      replay.payload = cached->second.encoded_response;
      if (session_.send_frame(frame.channel_id, session::FrameClass::standard,
                              std::move(replay))) {
        ++stats_.responses_sent;
      } else {
        ++stats_.response_send_failures;
      }
      return;
    }
    ++stats_.conflicting_requests;
    session_.fail_business_channel(frame.channel_id,
                                   transport::CloseReason::protocol_error);
    return;
  }
  if (const auto running = executing_.find(request.request_id);
      running != executing_.end()) {
    if (running->second->request_digest == digest) {
      // Identical retransmission while executing: exactly one execution.
      ++stats_.duplicate_requests;
      return;
    }
    ++stats_.conflicting_requests;
    session_.fail_business_channel(frame.channel_id,
                                   transport::CloseReason::protocol_error);
    return;
  }

  // Handler-front rejections (M6 exit criteria): nothing below dispatches a
  // handler before these gates pass.
  const auto method = registry_->lookup(request.service, request.method);
  if (!method.has_value()) {
    ++stats_.unimplemented_answers;
    answer_offline(frame.channel_id, request.request_id, digest,
                   StableStatus::unimplemented, "method_unknown");
    return;
  }
  if (method->first.streaming) {
    // v1 ships unary only; streaming stays explicitly unimplemented (M6-13).
    ++stats_.unimplemented_answers;
    answer_offline(frame.channel_id, request.request_id, digest,
                   StableStatus::unimplemented, "streaming_unimplemented");
    return;
  }
  if (request.schema_version > method->first.schema_version) {
    ++stats_.schema_rejected;
    answer_offline(frame.channel_id, request.request_id, digest,
                   StableStatus::failed_precondition, "schema_too_new");
    return;
  }
  if (request.payload.size() > session_.channels().limits().max_rpc_payload_bytes) {
    ++stats_.oversized_rejected;
    answer_offline(frame.channel_id, request.request_id, digest,
                   StableStatus::resource_exhausted, "payload_oversized");
    return;
  }
  if (!method->first.handler_enforced_scope &&
      (!scope_check_ || !scope_check_(method->first.required_scope))) {
    ++stats_.scope_rejected;
    answer_offline(frame.channel_id, request.request_id, digest,
                   StableStatus::permission_denied, "scope_denied");
    return;
  }
  if (executing_.size() >= config_.max_concurrent_server_calls) {
    ++stats_.concurrency_rejected;
    answer_offline(frame.channel_id, request.request_id, digest,
                   StableStatus::resource_exhausted, "concurrency_limit");
    return;
  }
  start_server_call(frame, request, digest);
}

void RpcService::answer_offline(std::uint32_t channel_id, const RequestId& id,
                                const std::vector<std::byte>& request_digest,
                                StableStatus status, std::string detail) {
  RpcResponseBody response;
  response.request_id = id;
  response.status = status;
  response.safe_detail = std::move(detail);
  auto encoded = encode_rpc_response(response, session_.channels().limits());
  if (!encoded) {
    ++stats_.response_send_failures;
    return;
  }
  cache_result(id, *encoded.value_if(), request_digest);
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::rpc_response);
  frame.channel_id = channel_id;
  frame.payload = std::move(*encoded.value_if());
  if (session_.send_frame(channel_id, session::FrameClass::standard, std::move(frame))) {
    ++stats_.responses_sent;
  } else {
    ++stats_.response_send_failures;
  }
}

void RpcService::start_server_call(const FrameView& frame, const RpcRequestBody& request,
                                   std::vector<std::byte> digest) {
  auto method = registry_->lookup(request.service, request.method);
  if (!method.has_value()) {
    ++stats_.unimplemented_answers;
    answer_offline(frame.channel_id, request.request_id, digest,
                   StableStatus::unimplemented, "method_unknown");
    return;
  }
  auto call = std::make_shared<ServerCallState>();
  call->request_id = request.request_id;
  call->channel_id = frame.channel_id;
  call->request = request;
  call->request_digest = std::move(digest);
  call->deadline_unix_milliseconds = now() + request.deadline_remaining_milliseconds;
  executing_.emplace(call->request_id, call);

  auto task_handler = method->second;
  auto weak = weak_from_this();
  const auto calling_peer = peer_;
  const auto dispatched = dispatch_(
      "heyaki-rpc-handler",
      [weak, call, task_handler = std::move(task_handler),
       calling_peer](executor::StopToken token) mutable {
        if (call->phase.load(std::memory_order_acquire) != 0U) {
          return;  // Session died before the task started.
        }
        if (token.stop_requested()) {
          // The executor accepted the cancel after the task began executing:
          // answer cancelled here; the phase CAS keeps exactly one response.
          if (auto self = weak.lock()) {
            self->post_finish(
                call, RpcHandlerResult{StableStatus::cancelled, {},
                                       "cancelled_after_start"},
                true);
          }
          return;
        }
        if (auto self = weak.lock()) {
          // Deadline from the received relative value: a queued task that
          // outlived it answers deadline_exceeded without running (M6-10).
          if (self->now() >= call->deadline_unix_milliseconds) {
            self->post_finish(
                call, RpcHandlerResult{StableStatus::deadline_exceeded, {},
                                       "deadline_before_start"},
                false);
            return;
          }
        }
        RpcCallContext context{call->request_id, call->request.payload,
                               call->request.metadata,
                               call->deadline_unix_milliseconds, call->cancel_requested,
                               calling_peer};
        RpcHandlerResult result;
        try {
          result = task_handler(context);
        } catch (...) {
          // Handler exceptions never leak details to the peer (M6-09).
          call->handler_exception = true;
          result = RpcHandlerResult{StableStatus::internal, {}, "handler_exception"};
        }
        if (auto self = weak.lock()) {
          self->post_finish(call, std::move(result), true);
        }
      });
  if (!dispatched) {
    executing_.erase(call->request_id);
    ++stats_.dispatch_rejected;
    answer_offline(call->channel_id, call->request_id, call->request_digest,
                   StableStatus::resource_exhausted, "dispatch_rejected");
    return;
  }
  call->cancel_request = std::move(*dispatched.value_if());
  ++stats_.handlers_executed;
}

void RpcService::post_finish(const std::shared_ptr<ServerCallState>& call,
                             RpcHandlerResult result, bool handler_ran) {
  auto weak = weak_from_this();
  poster_([weak, call, result = std::move(result), handler_ran]() mutable {
    if (auto self = weak.lock()) {
      self->finish_server_call(call, std::move(result), handler_ran);
    }
    // A dead service drops the late result: no channel exists to answer on.
  });
}

void RpcService::finish_server_call(std::shared_ptr<ServerCallState> call,
                                    RpcHandlerResult handler_result, bool handler_ran) {
  const auto running = executing_.find(call->request_id);
  if (running == executing_.end() ||
      call->phase.load(std::memory_order_acquire) != 0U) {
    // Terminal already emitted (deadline/cancel race): the late result never
    // enters the finished request (M6-10).
    ++stats_.late_results_dropped;
    return;
  }
  RpcResponseBody response;
  response.request_id = call->request_id;
  response.status = handler_result.status;
  response.safe_detail = sanitize_detail(std::move(handler_result.safe_detail));
  response.payload = std::move(handler_result.payload);
  if (response.status == StableStatus::cancelled) {
    ++stats_.handler_cancelled;
  }
  if (!handler_ran && response.status == StableStatus::deadline_exceeded) {
    ++stats_.handler_deadline_exceeded;
  }
  if (call->handler_exception) {
    ++stats_.handler_exceptions;
  }
  answer(*call, std::move(response));
}

void RpcService::answer(ServerCallState& call, RpcResponseBody response) {
  std::uint8_t expected = 0U;
  if (!call.phase.compare_exchange_strong(expected, 1U)) {
    ++stats_.late_results_dropped;
    return;
  }
  auto encoded = encode_rpc_response(response, session_.channels().limits());
  if (!encoded) {
    // An unencodable response degrades to a safe internal error; still
    // terminal, still exactly one response.
    response.payload.clear();
    response.status = StableStatus::internal;
    response.safe_detail = "response_encode_failed";
    encoded = encode_rpc_response(response, session_.channels().limits());
    if (!encoded) {
      executing_.erase(call.request_id);
      return;
    }
  }
  cache_result(call.request_id, *encoded.value_if(), call.request_digest);
  executing_.erase(call.request_id);
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::rpc_response);
  frame.channel_id = call.channel_id;
  frame.payload = std::move(*encoded.value_if());
  if (session_.send_frame(call.channel_id, session::FrameClass::standard,
                          std::move(frame))) {
    ++stats_.responses_sent;
  } else {
    ++stats_.response_send_failures;
  }
}

void RpcService::cache_result(const RequestId& id, const std::vector<std::byte>& encoded,
                              const std::vector<std::byte>& request_digest) {
  const std::size_t bytes = encoded.size() + request_digest.size();
  if (bytes > config_.result_cache_bytes) {
    return;  // Too large to cache: one response must not evict everything.
  }
  while (result_cache_.size() >= config_.result_cache_entries ||
         result_cache_bytes_ + bytes > config_.result_cache_bytes) {
    if (result_cache_.empty()) {
      return;
    }
    result_cache_bytes_ -= result_cache_.begin()->second.bytes;
    result_cache_.erase(result_cache_.begin());
  }
  result_cache_[id] = CachedResult{encoded, request_digest, bytes};
  result_cache_bytes_ += bytes;
}

void RpcService::handle_response(const FrameView& frame) {
  auto parsed = parse_rpc_response(frame.payload, session_.channels().limits());
  if (!parsed) {
    ++stats_.invalid_requests;
    return;
  }
  const auto pending = pending_.find(parsed.value_if()->request_id);
  if (pending == pending_.end()) {
    // Late or unknown response: counted, never delivered to a finished call.
    ++stats_.responses_unknown;
    return;
  }
  RpcCallOutcome outcome;
  outcome.status = parsed.value_if()->status;
  outcome.safe_detail = parsed.value_if()->safe_detail;
  outcome.payload = std::move(parsed.value_if()->payload);
  complete_pending(parsed.value_if()->request_id,
                   Result<RpcCallOutcome>::success(std::move(outcome)));
}

void RpcService::handle_cancel(const FrameView& frame) {
  auto parsed = parse_rpc_cancel(frame.payload);
  if (!parsed) {
    ++stats_.invalid_requests;
    return;
  }
  const auto running = executing_.find(parsed.value_if()->request_id);
  if (running == executing_.end()) {
    return;  // Cancel for an unknown/terminal request: ignore (wire 6.2).
  }
  auto& call = *running->second;
  // Handler-facing cooperative stop flag (public RpcCallContext polling).
  call.cancel_requested->store(true, std::memory_order_release);
  if (!call.cancel_request) {
    return;  // Injected dispatch double without an executor handle.
  }
  const auto response = call.cancel_request();
  if (response.result == executor::TaskCancellationResult::RequestedBeforeStart) {
    // The executor terminated the still-queued task: it never runs, so this
    // side emits the terminal cancelled response itself (M6-10 exactly-once).
    finish_server_call(running->second,
                       RpcHandlerResult{StableStatus::cancelled, {},
                                        "cancelled_before_start"},
                       true);
  }
  // RequestedRunning/AlreadyRequested: the running handler observes the flag
  // and answers cancelled itself; AlreadyCompleted keeps the wire "ignore"
  // rule (any in-flight late result drops on the phase CAS).
}

void RpcService::complete_pending(const RequestId& id, Result<RpcCallOutcome> outcome) {
  const auto pending = pending_.find(id);
  if (pending == pending_.end()) {
    return;
  }
  auto completion = std::move(pending->second.completion);
  pending_.erase(pending);
  ++stats_.responses_matched;
  completion(peer_, std::move(outcome));
}

void RpcService::prune_client_deadlines() {
  const auto current = now();
  for (auto entry = pending_.begin(); entry != pending_.end();) {
    if (entry->second.deadline_unix_milliseconds <= current) {
      ++stats_.local_deadline_exceeded;
      auto completion = std::move(entry->second.completion);
      entry = pending_.erase(entry);
      completion(peer_, Result<RpcCallOutcome>::success(
          RpcCallOutcome{StableStatus::deadline_exceeded, "local_deadline", {}}));
    } else {
      ++entry;
    }
  }
}

void RpcService::prune_executing_deadlines() {
  const auto current = now();
  for (auto& [id, call] : executing_) {
    std::uint8_t expected = 0U;
    if (call->deadline_unix_milliseconds <= current &&
        call->phase.compare_exchange_strong(expected, 1U)) {
      // The deadline fired while the handler still runs: answer now without
      // pretending the code was killed (M6-10); the late result is dropped
      // by finish_server_call. The executor cancel still reaches the task
      // lifecycle (queued tasks terminate; running ones may observe the
      // token) while the handler-facing flag stays untouched, preserving
      // the "keeps running cooperatively" wire semantics.
      if (call->cancel_request) {
        (void)call->cancel_request();
      }
      ++stats_.handler_deadline_exceeded;
      RpcResponseBody response;
      response.request_id = id;
      response.status = StableStatus::deadline_exceeded;
      response.safe_detail = "deadline_while_executing";
      auto encoded = encode_rpc_response(response, session_.channels().limits());
      if (encoded) {
        cache_result(id, *encoded.value_if(), call->request_digest);
        Frame frame;
        frame.type = static_cast<std::uint8_t>(FrameType::rpc_response);
        frame.channel_id = call->channel_id;
        frame.payload = std::move(*encoded.value_if());
        if (session_.send_frame(call->channel_id, session::FrameClass::standard,
                                std::move(frame))) {
          ++stats_.responses_sent;
        } else {
          ++stats_.response_send_failures;
        }
      }
    }
  }
  for (auto entry = executing_.begin(); entry != executing_.end();) {
    if (entry->second->phase.load(std::memory_order_acquire) != 0U) {
      entry = executing_.erase(entry);
    } else {
      ++entry;
    }
  }
}

}  // namespace heyaki
