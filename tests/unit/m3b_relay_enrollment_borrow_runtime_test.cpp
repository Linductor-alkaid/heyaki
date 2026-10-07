// Issue #20 regression: the enrollment WSS exchange must be able to borrow a
// host Runtime (RelayEnrollmentWssTransportConfig::runtime_borrowed) so the
// exchange's transport work runs on the host runtime's executor and enters its
// lifecycle view: a host shutdown ends an in-flight exchange in bounded time
// instead of leaving an unmonitored owned runtime behind. A null borrow keeps
// the original owned-runtime fallback (the exchange builds its own runtime
// from RuntimeConfig and fails on its own timeouts).
//
// Threading discipline (AGENTS.md): every concurrent path here runs through
// the pinned executor via heyaki::Runtime context submission. The test thread
// only performs synchronous waits (operation/future waits, yield polling); no
// std::thread/std::async is used.

#include <heyaki/identity.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/relay_enrollment_client.hpp>
#include <heyaki/runtime.hpp>

#include <boost/asio/ip/tcp.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace heyaki {
namespace {

using namespace std::chrono_literals;

constexpr auto borrow_in_flight_wait = 5s;
constexpr auto borrow_bounded_end = 10s;

bool wait_until(const std::function<bool()>& predicate,
                std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    std::this_thread::yield();
  }
  return predicate();
}

RuntimeSecurityContext test_security_context() {
  return RuntimeSecurityContext{.application_id = "org.heyaki.m3b-borrow-test",
                                .peer_id = std::nullopt,
                                .endpoint_id = std::nullopt,
                                .authorization_scope = "relay.enroll.test",
                                .epoch = SessionEpoch{1U}};
}

EndpointId make_endpoint_id() {
  EndpointId::Storage bytes{};
  bytes[0] = std::byte{0x42U};
  return EndpointId{bytes};
}

std::uint64_t now_milliseconds() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

// A listener that accepts TCP connections (the kernel backlog completes the
// handshake) but never speaks TLS: the client's handshake stays in flight
// until its own deadline. This keeps an enrollment exchange in flight without
// any TLS fixture.
class HangingListener {
 public:
  HangingListener()
      : acceptor_{io_, boost::asio::ip::tcp::endpoint{
                           boost::asio::ip::address_v4::loopback(), 0U}} {
    port_ = acceptor_.local_endpoint().port();
  }

  HangingListener(const HangingListener&) = delete;
  HangingListener& operator=(const HangingListener&) = delete;

  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }

  void close() {
    boost::system::error_code ignored;
    acceptor_.close(ignored);
  }

 private:
  boost::asio::io_context io_;
  boost::asio::ip::tcp::acceptor acceptor_;
  std::uint16_t port_{0U};
};

TEST(M3BRelayEnrollmentBorrowRuntimeTest,
     HostShutdownEndsInFlightBorrowedExchangeBounded) {
  HangingListener listener;
  ASSERT_NE(listener.port(), 0U);

  RuntimeConfig host_config;
  host_config.worker_name = "heyaki-m3b-borrow-host";
  host_config.callback_drain_timeout = 1s;
  host_config.worker_stop_timeout = 1s;
  host_config.operation_drain_timeout = 2s;
  host_config.executor_drain_timeout = 3s;
  auto host = Runtime::create_owned(host_config);
  ASSERT_TRUE(host) << host.error_if()->safe_detail();
  auto context = host.value_if()->create_context(RuntimeContextKind::relay,
                                                 "relay-enroll-borrow");
  ASSERT_TRUE(context) << context.error_if()->safe_detail();

  RelayEnrollmentWssTransportConfig transport;
  transport.relay_url = "wss://127.0.0.1:" + std::to_string(listener.port());
  transport.tls_verify_peer = false;
  transport.connect_timeout = 2s;
  transport.handshake_timeout = 4s;
  transport.close_timeout = 1s;
  transport.runtime = RuntimeConfig{};
  transport.runtime_borrowed = host.value_if();

  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto endpoint = make_endpoint_id();
  ASSERT_FALSE(endpoint.is_zero());

  // The borrowed runtime must outlive the exchange (header contract), so the
  // exchange handler is always joined before the test locals (and the host
  // runtime) unwind — including on an early gtest assertion return.
  std::atomic<bool> exchange_started{false};
  std::atomic<bool> exchange_finished{false};
  std::atomic<bool> exchange_failed{false};
  std::atomic<int> exchange_error_code{-1};
  struct ExchangeJoinGuard {
    std::atomic<bool>& finished;
    ~ExchangeJoinGuard() {
      (void)wait_until([&] { return finished.load(std::memory_order_acquire); },
                       std::chrono::milliseconds{15000});
    }
  } join_guard{exchange_finished};

  auto handler = [&](const RuntimeSecurityContext&) {
    exchange_started.store(true, std::memory_order_release);
    auto exchanged = enroll_relay_over_wss(
        transport, *identity.value_if(), endpoint, "tenant-a",
        "TEST-ONLY-borrow-runtime-token-0123", now_milliseconds());
    if (!exchanged) {
      exchange_failed.store(true, std::memory_order_release);
      exchange_error_code.store(
          static_cast<int>(exchanged.error_if()->code()),
          std::memory_order_release);
    }
    exchange_finished.store(true, std::memory_order_release);
    return exchanged ? Result<void>::success()
                     : Result<void>::failure(*exchanged.error_if());
  };

  auto operation = context.value_if()->submit(
      test_security_context(), [] { return Result<void>::success(); }, handler);
  ASSERT_TRUE(operation) << operation.error_if()->safe_detail();

  // The exchange must start before the shutdown so the cancellation path is
  // exercised on an in-flight exchange, not on a queued task.
  ASSERT_TRUE(wait_until(
      [&] { return exchange_started.load(std::memory_order_acquire); },
      borrow_in_flight_wait))
      << "borrowed enrollment exchange never started";

  // Borrow visibility: the submission is observable in the host runtime's
  // lifecycle counters while the exchange runs inside its view.
  // (callbacks_completed only advances on terminal operation state, so it is
  // asserted after the operation resolves, below.)
  ASSERT_TRUE(wait_until(
      [&] {
        return host.value_if()->snapshot().callbacks_accepted >= 1U;
      },
      2s))
      << "host runtime never accounted the enrollment submission";
  const auto borrowed_view = host.value_if()->snapshot();
  EXPECT_GE(borrowed_view.callbacks_accepted, 1U);
  EXPECT_GE(borrowed_view.outstanding_operations, 1U);
  EXPECT_EQ(borrowed_view.phase, RuntimePhase::running);

  // Still in flight when the host begins shutting down.
  auto in_flight = operation.value_if()->try_status();
  ASSERT_TRUE(in_flight) << in_flight.error_if()->safe_detail();
  ASSERT_FALSE(in_flight.value_if()->has_value())
      << "exchange finished before the host shutdown could interrupt it";

  const auto shutdown_started = std::chrono::steady_clock::now();
  const auto report = host.value_if()->shutdown();
  const auto shutdown_elapsed =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - shutdown_started);
  EXPECT_EQ(report.final_phase, RuntimePhase::stopped);

  // Bounded end: the enrollment operation must resolve within the bound even
  // though its transport was in flight when the host runtime shut down.
  const auto end_deadline = shutdown_started + borrow_bounded_end;
  auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_deadline - std::chrono::steady_clock::now());
  if (remaining.count() < 0) {
    remaining = 0ms;
  }
  auto status = operation.value_if()->wait_for(remaining);
  ASSERT_TRUE(status)
      << "enrollment operation did not end within "
      << borrow_bounded_end.count()
      << "ms of host shutdown: " << status.error_if()->safe_detail();
  EXPECT_TRUE(status.value_if()->state == OperationState::cancelled ||
              status.value_if()->state == OperationState::error)
      << "unexpected operation state: "
      << operation_state_name(status.value_if()->state);

  // The whole submission lifecycle (accepted and completed) is now visible in
  // the host runtime's counters: the exchange ran inside the host's view and
  // its cancellation was accounted there.
  const auto final_view = host.value_if()->snapshot();
  EXPECT_GE(final_view.callbacks_accepted, 1U);
  EXPECT_GE(final_view.callbacks_completed, 1U);
  EXPECT_EQ(final_view.phase, RuntimePhase::stopped);

  // The exchange itself must also finish (its handler never blocks past its
  // own transport deadlines) and must report a failure, not a success.
  EXPECT_TRUE(wait_until(
      [&] { return exchange_finished.load(std::memory_order_acquire); },
      borrow_bounded_end))
      << "enrollment handler did not finish after host shutdown";
  EXPECT_TRUE(exchange_failed.load(std::memory_order_acquire))
      << "enrollment against a TLS-less listener unexpectedly succeeded";
  const auto recorded_code = exchange_error_code.load(std::memory_order_acquire);
  RecordProperty("enroll_error_code", std::to_string(recorded_code));
  RecordProperty("shutdown_elapsed_ms", std::to_string(shutdown_elapsed.count()));

  listener.close();
}

TEST(M3BRelayEnrollmentBorrowRuntimeTest,
     NullBorrowKeepsOwnedRuntimeFallbackFailingFast) {
  // A port that nothing listens on: the owned-runtime fallback must still
  // complete its failure path quickly (connection refused), proving the
  // default (runtime_borrowed == nullptr) behavior is preserved.
  boost::asio::io_context io;
  boost::asio::ip::tcp::acceptor port_probe{
      io, boost::asio::ip::tcp::endpoint{boost::asio::ip::tcp::v4(), 0U}};
  const auto port = port_probe.local_endpoint().port();
  port_probe.close();
  ASSERT_NE(port, 0U);

  RelayEnrollmentWssTransportConfig transport;
  transport.relay_url = "wss://127.0.0.1:" + std::to_string(port);
  transport.tls_verify_peer = false;
  transport.connect_timeout = 2s;
  transport.handshake_timeout = 2s;
  transport.close_timeout = 1s;
  transport.runtime = RuntimeConfig{};
  // runtime_borrowed left defaulted to nullptr.

  auto identity = create_identity();
  ASSERT_TRUE(identity) << identity.error_if()->safe_detail();
  const auto endpoint = make_endpoint_id();
  ASSERT_FALSE(endpoint.is_zero());

  const auto started = std::chrono::steady_clock::now();
  auto exchanged = enroll_relay_over_wss(
      transport, *identity.value_if(), endpoint, "tenant-a",
      "TEST-ONLY-owned-fallback-token-0123", now_milliseconds());
  const auto elapsed = std::chrono::steady_clock::now() - started;

  ASSERT_FALSE(exchanged)
      << "enrollment against a closed port unexpectedly succeeded: "
      << "relay handed out a result";
  EXPECT_LE(elapsed, 5s)
      << "owned-runtime fallback failed slowly instead of fast on refusal";
  RecordProperty("fallback_error_code",
                 std::to_string(static_cast<int>(exchanged.error_if()->code())));
}

}  // namespace
}  // namespace heyaki
