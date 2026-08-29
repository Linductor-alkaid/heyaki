#pragma once

// Unary RPC service (M6-07..M6-13). One instance rides an authorized
// PeerSession and plays both roles:
//   * server: validates inbound RPC_REQUEST against the ServiceRegistry
//     (unknown → unimplemented, streaming → unimplemented, schema too new →
//     failed_precondition, oversized → resource_exhausted, scope missing →
//     permission_denied), enforces a bounded executing-set, dispatches the
//     handler through the executor, enforces cooperative cancellation and
//     relative deadlines, emits exactly one terminal RPC_RESPONSE per
//     request, and caches recent terminal results for at-most-once
//     execution inside a bounded window;
//   * client: tracks pending calls by request id, honors local deadlines and
//     cancellation, and on session loss completes non-idempotent calls with
//     outcome_unknown — the library never retries automatically; explicitly
//     idempotent calls opted into retry are handed back for policy-driven
//     resubmission on a future session (M6-12).
//
// Threading: public methods run on the owning Node's strand. Handler tasks
// run on executor threads and communicate back through ServerCallState
// (self-contained shared state) plus a strand poster; late results are
// dropped after the request reached a terminal state (M6-10).

#include "peer_session.hpp"
#include "service_dispatch.hpp"

#include <heyaki/rpc.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <vector>

namespace heyaki {

struct RpcServiceConfig {
  // Bounded server executing-set (M6-09): requests beyond it answer
  // resource_exhausted before any handler runs.
  std::size_t max_concurrent_server_calls{16U};
  // Bounded at-most-once result cache (M6-11).
  std::size_t result_cache_entries{64U};
  std::size_t result_cache_bytes{256U * 1024U};
  // Bounded client pending-call table.
  std::size_t max_pending_client_calls{64U};
  std::size_t channel_frame_capacity{256U};
  std::size_t channel_byte_capacity{1024U * 1024U};
};

// Terminal outcome handed to the caller's completion is the public
// RpcCallOutcome; call options are the public RpcCallOptions.

class RpcService : public std::enable_shared_from_this<RpcService> {
 public:
  using Completion = std::function<void(Result<RpcCallOutcome>)>;
  using ScopeCheck = std::function<bool(std::string_view scope)>;
  // Posts one unit of work back onto the owning strand.
  using StrandPoster = std::function<void(std::function<void()> task)>;

  // A pending idempotent call handed back on session loss for policy-driven
  // resubmission with the SAME request id (the peer's result cache keeps the
  // execution at-most-once).
  struct RetryableCall {
    RpcRequestBody request;
    std::uint64_t deadline_unix_milliseconds{};
    bool cancel_requested{false};
    Completion completion;
  };

  RpcService(PeerSession& session, RpcServiceConfig config,
             const std::shared_ptr<ServiceRegistry>& registry,
             ServiceDispatch dispatch, ScopeCheck scope_check, StrandPoster poster,
             std::function<std::uint64_t()> wall_clock = {});
  ~RpcService();

  RpcService(const RpcService&) = delete;
  RpcService& operator=(const RpcService&) = delete;

  [[nodiscard]] Result<void> attach();

  // Client side: starts one unary call; `completion` fires exactly once with
  // the terminal outcome (ok / peer status / cancelled / deadline_exceeded /
  // outcome_unknown / admission failure). A non-zero `request_id` overrides
  // the generated one (the Node assigns ids synchronously so callers can
  // cancel before the strand admits the call).
  [[nodiscard]] Result<RequestId> call(std::string service, std::string method,
                                       std::vector<std::byte> payload,
                                       RpcCallOptions options,
                                       Completion completion,
                                       RequestId request_id = RequestId{});
  // Best-effort cooperative cancel of one pending call: sends RPC_CANCEL and
  // completes the call locally with cancelled; a late response is counted,
  // never delivered to the finished call (M6-10).
  [[nodiscard]] Result<void> cancel(const RequestId& request_id);

  // Server-side resubmission of a RetryableCall on a new session.
  [[nodiscard]] Result<RequestId> resubmit(RetryableCall call);

  // TTL/deadline maintenance: expires client deadlines and executing server
  // calls whose deadline passed (they answer deadline_exceeded while their
  // handler keeps running cooperatively; its late result is dropped).
  void prune();

  // Session loss (M6-12): every pending call completes — non-idempotent with
  // outcome_unknown; idempotent+retry calls move to the retryable list;
  // executing server calls finish without a response (the peer sees its own
  // outcome rules).
  void handle_session_closed();
  [[nodiscard]] std::vector<RetryableCall> take_retryable_calls();
  // Frame entry point (also used by tests for direct injection).
  void handle_frame(const FrameView& frame);

  [[nodiscard]] RpcServiceStats stats() const noexcept { return stats_; }
  [[nodiscard]] std::size_t pending_calls() const noexcept { return pending_.size(); }
  [[nodiscard]] std::size_t executing_calls() const noexcept { return executing_.size(); }
  [[nodiscard]] bool attached() const noexcept { return attached_; }

 private:
  // Self-contained per-request server state shared with the executor task.
  struct ServerCallState {
    RequestId request_id;
    std::uint32_t channel_id{};
    RpcRequestBody request;
    std::uint64_t deadline_unix_milliseconds{};
    std::vector<std::byte> request_digest;
    std::shared_ptr<std::atomic<bool>> cancel_requested =
        std::make_shared<std::atomic<bool>>(false);
    bool handler_exception{false};
    // phase: 0 = executing, 1 = terminal (exactly one terminal response).
    std::atomic<std::uint8_t> phase{0U};
  };

  struct PendingCall {
    RpcRequestBody request;
    std::uint64_t deadline_unix_milliseconds{};
    bool idempotent{false};
    bool retry_on_reconnect{false};
    bool cancel_requested{false};
    Completion completion;
  };

  struct CachedResult {
    std::vector<std::byte> encoded_response;
    std::vector<std::byte> request_digest;
    std::size_t bytes{};
  };

  [[nodiscard]] std::uint64_t now() const;
  [[nodiscard]] Result<void> admit_frame(const FrameView& frame);
  void handle_request(const FrameView& frame);
  void handle_response(const FrameView& frame);
  void handle_cancel(const FrameView& frame);
  [[nodiscard]] Result<RequestId> submit_call(RpcRequestBody request, bool idempotent,
                                              bool retry_on_reconnect,
                                              Completion completion);
  void complete_pending(const RequestId& id, Result<RpcCallOutcome> outcome);
  // Sends one terminal (or rejection) response and caches it for the
  // at-most-once window.
  void answer_offline(std::uint32_t channel_id, const RequestId& id,
                      const std::vector<std::byte>& request_digest, StableStatus status,
                      std::string detail);
  void answer(ServerCallState& call, RpcResponseBody response);
  void send_response(std::uint32_t channel_id, RpcResponseBody response);
  void cache_result(const RequestId& id, const std::vector<std::byte>& encoded,
                    const std::vector<std::byte>& request_digest);
  void start_server_call(const FrameView& frame, const RpcRequestBody& request,
                         std::vector<std::byte> digest);
  void post_finish(const std::shared_ptr<ServerCallState>& call,
                   RpcHandlerResult result, bool handler_ran);
  void finish_server_call(std::shared_ptr<ServerCallState> call,
                          RpcHandlerResult handler_result, bool handler_ran);
  void prune_client_deadlines();
  void prune_executing_deadlines();

  PeerSession& session_;
  RpcServiceConfig config_;
  std::shared_ptr<ServiceRegistry> registry_;
  ServiceDispatch dispatch_;
  ScopeCheck scope_check_;
  StrandPoster poster_;
  std::function<std::uint64_t()> wall_clock_;
  std::map<RequestId, PendingCall> pending_;
  std::map<RequestId, std::shared_ptr<ServerCallState>> executing_;
  std::map<RequestId, CachedResult> result_cache_;
  std::size_t result_cache_bytes_{};
  std::vector<RetryableCall> retryable_;
  RpcServiceStats stats_;
  std::uint32_t channel_id_{};
  std::vector<std::uint32_t> owned_channels_;
  bool attached_{false};
};

}  // namespace heyaki
