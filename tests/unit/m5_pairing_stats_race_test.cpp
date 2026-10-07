// Issue #21 regression: PairingServiceStats audit counters are written with no
// common lock - session callbacks drive audit() on the node strand while
// public Node methods (rotate_authorization_password, revoke_grant) increment
// on the caller's own thread, and the Node metrics expiry tick reads every
// counter from the worker thread (Node::Impl::metrics_strand). The counters
// must therefore be atomic: concurrent rotate work against a concurrent
// metrics-style reader must stay data-race-free under ThreadSanitizer and
// keep exact totals (no lost increments, monotonic reader snapshots).

#include "pairing_service.hpp"

#include <heyaki/identity.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/runtime.hpp>

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

using namespace std::chrono_literals;

constexpr std::uint64_t kNow = 1'700'000'000'000U;

// Issue reproduces the rotate-vs-metrics overlap: 384 rotate-and-revoke
// cycles (within the 256..512 band) give the reader a wide window.
constexpr std::size_t kRotations = 384U;
// Two readers snapshot from the node worker thread; one context per reader
// because a context strand serializes its own submissions.
constexpr std::size_t kReaderCount = 2U;
// Reader loops run until the writer finishes (shared stop flag); the
// iteration cap only bounds a pathological hang.
constexpr std::size_t kMaxReaderIterations = 20'000'000U;
// Bounded snapshot retention: monotonicity is checked inline every iteration,
// only the first snapshots are kept for post-run re-verification.
constexpr std::size_t kMaxStoredSnapshots = 200'000U;

// Lock-free mirror of the ten PairingServiceStats counters, loaded exactly the
// way Node::Impl::metrics_strand reads them (relaxed loads of every field).
struct StatsSnapshot {
  std::uint64_t attempts{};
  std::uint64_t granted{};
  std::uint64_t denied_password{};
  std::uint64_t denied_policy{};
  std::uint64_t denied_backoff{};
  std::uint64_t grant_accepted{};
  std::uint64_t grant_rejected{};
  std::uint64_t grant_revoked{};
  std::uint64_t password_rotated{};
  std::uint64_t grants_revoked{};
};

StatsSnapshot snapshot_pairing_stats(const PairingServiceStats& stats) {
  StatsSnapshot snapshot;
  snapshot.attempts = stats.attempts.load(std::memory_order_relaxed);
  snapshot.granted = stats.granted.load(std::memory_order_relaxed);
  snapshot.denied_password = stats.denied_password.load(std::memory_order_relaxed);
  snapshot.denied_policy = stats.denied_policy.load(std::memory_order_relaxed);
  snapshot.denied_backoff = stats.denied_backoff.load(std::memory_order_relaxed);
  snapshot.grant_accepted = stats.grant_accepted.load(std::memory_order_relaxed);
  snapshot.grant_rejected = stats.grant_rejected.load(std::memory_order_relaxed);
  snapshot.grant_revoked = stats.grant_revoked.load(std::memory_order_relaxed);
  snapshot.password_rotated = stats.password_rotated.load(std::memory_order_relaxed);
  snapshot.grants_revoked = stats.grants_revoked.load(std::memory_order_relaxed);
  return snapshot;
}

RuntimeSecurityContext test_security_context() {
  return RuntimeSecurityContext{.application_id = "org.heyaki.stats-race-test",
                                .peer_id = std::nullopt,
                                .endpoint_id = std::nullopt,
                                .authorization_scope = "test",
                                .epoch = SessionEpoch{1U}};
}

PairingRequestBody pairing_request(std::string_view password,
                                   std::uint32_t sequence) {
  PairingRequestBody body;
  RequestId::Storage bytes{};
  bytes[0] = static_cast<std::byte>(sequence & 0xFFU);
  bytes[1] = std::byte{0xA5U};
  body.request_id = RequestId{bytes};
  body.nonce = PairingNonce{};
  body.nonce[0] = static_cast<std::byte>((sequence + 1U) & 0xFFU);
  body.nonce[1] = std::byte{0x5AU};
  body.password_utf8 = std::string{password};
  body.requested_scopes = {"message.send"};
  return body;
}

struct PairingStatsRaceTest : public ::testing::Test {
  void SetUp() override {
    root = std::filesystem::temp_directory_path() /
           ("heyaki-m5-stats-race-" + std::to_string(::testing::UnitTest::GetInstance()
                                                      ->random_seed()));
    std::filesystem::create_directories(root);
    // ProfileStore enforces owner-only directory permissions.
    std::filesystem::permissions(root, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    // Disable the OS secret backend like every other profile test: its
    // glib-internal allocator trips ThreadSanitizer and adds nothing here.
    ProfileOpenOptions open_options;
    open_options.secret_backend.prefer_os_backend = false;
    auto target = ProfileStore::create(root / "target.sqlite", open_options);
    ASSERT_TRUE(target);
    target_store.emplace(std::move(*target.value_if()));

    auto init_verifier =
        create_password_verifier("target-password", PasswordHashParameters{});
    ASSERT_TRUE(init_verifier);
    PairingPolicy policy;
    policy.default_scopes = {"message.send"};
    LocalProfileInitialization initialization;
    initialization.application_id = "com.example.test";
    initialization.password_verifier = std::move(*init_verifier.value_if());
    initialization.password_generation = 1U;
    initialization.pairing_policy = policy;
    ASSERT_TRUE(target_store->initialize_local(initialization));

    // One precomputed verifier is reused for every rotation: rotate_password
    // only persists the verifier bytes and bumps the generation, so the same
    // verifier value is valid for each cycle.
    auto verifier =
        create_password_verifier("race-rotation-password", PasswordHashParameters{});
    ASSERT_TRUE(verifier);
    rotation_verifier = std::move(*verifier.value_if());

    auto identity = target_store->load_identity();
    ASSERT_TRUE(identity);
    PairingServiceConfig config{
        .profile = &*target_store,
        .identity = std::move(*identity.value_if())};
    config.wall_clock = [this] { return wall_clock; };
    // The audit sink is invoked from whichever thread drives audit(): in this
    // file that is a concurrent writer, so the sink itself must be
    // thread-safe (mutex-protected vector plus atomic funnel counters).
    config.audit_sink = [this](const PairingAuditEvent& event) {
      record_audit(event);
    };
    service = std::make_unique<PairingService>(std::move(config));

    for (auto& sink : reader_snapshots) {
      sink = std::make_shared<std::vector<StatsSnapshot>>();
    }
  }

  void TearDown() override {
    // Always unwind in the safe order, including on mid-test assertion
    // failure: signal the readers, drain every submitted operation, shut the
    // executor runtime down, and only then destroy the service and store.
    stop_readers.store(true, std::memory_order_relaxed);
    for (const auto& operation : inflight) {
      (void)operation.wait_for(30s);
    }
    if (runtime) {
      (void)runtime->shutdown();
    }
    service.reset();
    target_store.reset();
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
  }

  void record_audit(const PairingAuditEvent& event) {
    {
      std::lock_guard<std::mutex> guard{audit_mutex};
      audit_events.push_back(event);
    }
    switch (event.kind) {
      case PairingAuditKind::password_rotated:
        audited_password_rotated.fetch_add(1U, std::memory_order_relaxed);
        break;
      case PairingAuditKind::grants_revoked:
        audited_grants_revoked.fetch_add(1U, std::memory_order_relaxed);
        break;
      default:
        break;
    }
  }

  std::vector<PairingAuditEvent> audited_events() const {
    std::lock_guard<std::mutex> guard{audit_mutex};
    return audit_events;
  }

  std::filesystem::path root;
  std::optional<ProfileStore> target_store;
  std::unique_ptr<PairingService> service;
  std::optional<PasswordVerifier> rotation_verifier;
  std::uint64_t wall_clock = kNow;

  std::atomic<bool> stop_readers{false};
  std::atomic<std::size_t> rotation_failures{0};
  std::atomic<std::size_t> generation_gaps{0};
  std::atomic<std::size_t> monotonic_violations{0};
  std::atomic<std::uint64_t> audited_password_rotated{0};
  std::atomic<std::uint64_t> audited_grants_revoked{0};
  // Overlap proof: readers spin from before the writer starts until after it
  // finishes, so while both run their thread ids must differ. Equality would
  // mean the work serialized onto one thread and reproduced no race window.
  std::atomic<std::thread::id> writer_thread_id{};
  std::array<std::atomic<std::thread::id>, kReaderCount> reader_thread_ids{};
  mutable std::mutex audit_mutex;
  std::vector<PairingAuditEvent> audit_events;
  std::array<std::shared_ptr<std::vector<StatsSnapshot>>, kReaderCount>
      reader_snapshots;

  // Declared last so it is destroyed first; TearDown already drains and
  // shuts the runtime down before the service and store die.
  std::optional<Runtime> runtime;
  std::vector<RuntimeOperation> inflight;
};

// Core issue #21 reproduction: a caller-thread writer runs
// rotate_password_and_revoke_grants in a loop while node-strand readers
// snapshot every stats counter the way the Node metrics expiry tick does.
// The writer work runs as the Runtime user handler so it executes on the
// executor task pool - the same non-strand "integration caller thread" shape
// the issue reports - while the readers run as context state callbacks on the
// node worker thread. Assertions afterwards: exact atomic totals, zero audit
// loss, monotonic reader snapshots, no TSAN report.
TEST_F(PairingStatsRaceTest, ConcurrentRotationAndStatsSnapshotStaysExact) {
  RuntimeConfig runtime_config;
  runtime_config.worker_name = "heyaki-stats-race";
  // The single asio worker plus the file-io worker occupy two executor
  // threads; four minimum keeps the writer handler on its own thread next to
  // the two readers on the worker thread.
  runtime_config.executor_min_threads = 4U;
  runtime_config.executor_max_threads = 6U;
  auto created = Runtime::create_owned(runtime_config);
  ASSERT_TRUE(created) << created.error_if()->safe_detail();
  runtime.emplace(std::move(*created.value_if()));

  auto writer_context =
      runtime->create_context(RuntimeContextKind::node, "stats-writer");
  ASSERT_TRUE(writer_context) << writer_context.error_if()->safe_detail();

  // Writer: the rotation loop runs in the user-handler phase, which the
  // Runtime dispatches onto the executor task pool - the caller-thread shape
  // of the public Node rotate/revoke API. The state phase stays empty: it
  // would serialize with the readers on the single node worker thread.
  const auto* verifier = &*rotation_verifier;
  auto writer_submitted = writer_context.value_if()->submit(
      test_security_context(),
      [] { return Result<void>::success(); },
      [this, verifier](const RuntimeSecurityContext&) -> Result<void> {
        writer_thread_id.store(std::this_thread::get_id(),
                               std::memory_order_relaxed);
        std::uint64_t last_generation = 0U;
        bool primed = false;
        for (std::size_t index = 0U; index < kRotations; ++index) {
          auto rotated = service->rotate_password_and_revoke_grants(*verifier);
          if (!rotated) {
            rotation_failures.fetch_add(1U, std::memory_order_relaxed);
            return Result<void>::failure(
                Error{ErrorCode::internal, "test", "rotation_failed"});
          }
          // Each successful call bumps the profile password generation by
          // exactly one, even while readers race the counters. The first
          // result primes the expectation (it continues the profile's own
          // initial generation).
          const auto generation = *rotated.value_if();
          if (primed && generation != last_generation + 1U) {
            generation_gaps.fetch_add(1U, std::memory_order_relaxed);
          }
          last_generation = generation;
          primed = true;
        }
        return Result<void>::success();
      });
  ASSERT_TRUE(writer_submitted) << writer_submitted.error_if()->safe_detail();
  inflight.push_back(std::move(*writer_submitted.value_if()));

  // Readers: snapshot all ten counters in a loop on the node worker thread,
  // exactly the metrics_strand read shape. Each reader runs on its own
  // peer_session context (a context strand serializes itself). Loops end via
  // the shared stop flag once the writer finishes, with a hard iteration cap
  // as a hang backstop. Snapshot storage follows the m2 runtime test
  // pattern: results are read from the main thread only after wait_for
  // reported success.
  for (std::size_t index = 0U; index < kReaderCount; ++index) {
    auto reader_context = runtime->create_context(RuntimeContextKind::peer_session,
                                                  "stats-reader-" +
                                                      std::to_string(index));
    ASSERT_TRUE(reader_context) << reader_context.error_if()->safe_detail();
    const auto reader_index = index;
    auto sink = reader_snapshots[reader_index];
    auto reader_submitted = reader_context.value_if()->submit(
        test_security_context(),
        [this, reader_index, sink]() -> Result<void> {
          reader_thread_ids[reader_index].store(std::this_thread::get_id(),
                                                std::memory_order_relaxed);
          const auto& stats = service->stats();
          std::uint64_t last_rotated = 0U;
          for (std::size_t iteration = 0U; iteration < kMaxReaderIterations;
               ++iteration) {
            if (stop_readers.load(std::memory_order_relaxed)) {
              break;
            }
            const auto snapshot = snapshot_pairing_stats(stats);
            // password_rotated only ever increments: any snapshot sequence
            // must be monotonic non-decreasing.
            if (snapshot.password_rotated < last_rotated) {
              monotonic_violations.fetch_add(1U, std::memory_order_relaxed);
            }
            last_rotated = snapshot.password_rotated;
            if (sink->size() < kMaxStoredSnapshots) {
              sink->push_back(snapshot);
            }
            if ((iteration % 128U) == 0U) {
              std::this_thread::yield();
            }
          }
          return Result<void>::success();
        });
    ASSERT_TRUE(reader_submitted) << reader_submitted.error_if()->safe_detail();
    inflight.push_back(std::move(*reader_submitted.value_if()));
  }
  ASSERT_EQ(inflight.size(), 1U + kReaderCount);

  // Wait for the writer to finish every rotation.
  const auto writer_status = inflight[0].wait_for(120s);
  ASSERT_TRUE(writer_status) << writer_status.error_if()->safe_detail();
  EXPECT_EQ(writer_status.value_if()->state, OperationState::success);
  EXPECT_EQ(rotation_failures.load(), 0U);
  EXPECT_EQ(generation_gaps.load(), 0U);

  // Stop the readers and collect them.
  stop_readers.store(true, std::memory_order_relaxed);
  for (std::size_t index = 1U; index < inflight.size(); ++index) {
    const auto reader_status = inflight[index].wait_for(30s);
    ASSERT_TRUE(reader_status) << reader_status.error_if()->safe_detail();
    EXPECT_EQ(reader_status.value_if()->state, OperationState::success);
  }

  // Exact totals: every rotate_password_and_revoke_grants call audits
  // password_rotated AND grants_revoked exactly once (the revoke audit fires
  // even when zero grants are below the new generation), so the atomic
  // counters must show no lost increments.
  const auto& stats = service->stats();
  EXPECT_EQ(stats.password_rotated.load(), kRotations);
  EXPECT_EQ(stats.grants_revoked.load(), kRotations);
  EXPECT_EQ(stats.attempts.load(), 0U);
  EXPECT_EQ(stats.granted.load(), 0U);
  EXPECT_EQ(stats.denied_password.load(), 0U);
  EXPECT_EQ(stats.denied_policy.load(), 0U);
  EXPECT_EQ(stats.denied_backoff.load(), 0U);
  EXPECT_EQ(stats.grant_accepted.load(), 0U);
  EXPECT_EQ(stats.grant_rejected.load(), 0U);
  EXPECT_EQ(stats.grant_revoked.load(), 0U);

  // The audit funnel observed the same totals through the thread-safe sink.
  EXPECT_EQ(audited_password_rotated.load(), kRotations);
  EXPECT_EQ(audited_grants_revoked.load(), kRotations);
  EXPECT_EQ(audited_events().size(), 2U * kRotations);

  // Reader snapshots: monotonic password_rotated, never above the total.
  EXPECT_EQ(monotonic_violations.load(), 0U);
  // Overlap proof: the readers were demonstrably alive on distinct threads
  // while the writer rotated (they only stop after the writer completes).
  const auto writer_id = writer_thread_id.load(std::memory_order_relaxed);
  EXPECT_NE(writer_id, std::thread::id{});
  for (const auto& reader_id_atomic : reader_thread_ids) {
    const auto reader_id = reader_id_atomic.load(std::memory_order_relaxed);
    EXPECT_NE(reader_id, std::thread::id{});
    EXPECT_NE(reader_id, writer_id)
        << "writer and reader serialized onto one thread";
  }
  for (const auto& sink : reader_snapshots) {
    bool monotonic = true;
    bool bounded = true;
    std::uint64_t previous = 0U;
    for (const auto& snapshot : *sink) {
      if (snapshot.password_rotated < previous) {
        monotonic = false;
      }
      if (snapshot.password_rotated > kRotations) {
        bounded = false;
      }
      previous = snapshot.password_rotated;
    }
    EXPECT_TRUE(monotonic) << "reader snapshot password_rotated regressed";
    EXPECT_TRUE(bounded) << "reader snapshot observed an impossible total";
  }
}

// Deterministic single-threaded cross-check that every audit kind lands in
// exactly the counter the audit funnel documents (complements the existing
// m5_pairing_service_test coverage, which only pins denied_policy).
TEST_F(PairingStatsRaceTest, DeterministicSequenceCountsEveryAuditKind) {
  auto peer_identity = create_identity();
  ASSERT_TRUE(peer_identity) << peer_identity.error_if()->safe_detail();
  const auto peer = peer_identity.value_if()->device_id();
  const auto peer_key = peer_identity.value_if()->public_key();

  // Wrong password: attempt + denied_password.
  auto denied = service->evaluate(pairing_request("wrong", 1U), peer, peer_key);
  ASSERT_TRUE(denied);
  EXPECT_EQ(denied.value_if()->status, StableStatus::unauthenticated);

  // Correct password: attempt + granted, one grant issued.
  auto paired = service->evaluate(pairing_request("target-password", 2U), peer,
                                  peer_key);
  ASSERT_TRUE(paired);
  EXPECT_EQ(paired.value_if()->status, StableStatus::ok);
  ASSERT_TRUE(paired.value_if()->grant.has_value());
  const auto grant_id = paired.value_if()->grant->grant_id;

  // Explicit revocation: grant_revoked.
  ASSERT_TRUE(service->revoke_grant(grant_id));

  // Rotate only: password_rotated.
  auto rotated = service->rotate_password(*rotation_verifier);
  ASSERT_TRUE(rotated);

  // Rotate and revoke with zero outstanding grants: still audits
  // password_rotated and grants_revoked.
  auto rotated_and_revoked =
      service->rotate_password_and_revoke_grants(*rotation_verifier);
  ASSERT_TRUE(rotated_and_revoked);

  // Audit-only approval rejection: denied_policy.
  RequestId::Storage rejected_bytes{};
  rejected_bytes[0] = std::byte{0x33U};
  service->record_approval_rejected(peer, RequestId{rejected_bytes});

  const auto& stats = service->stats();
  EXPECT_EQ(stats.attempts.load(), 2U);
  EXPECT_EQ(stats.granted.load(), 1U);
  EXPECT_EQ(stats.denied_password.load(), 1U);
  EXPECT_EQ(stats.denied_policy.load(), 1U);
  EXPECT_EQ(stats.grant_revoked.load(), 1U);
  EXPECT_EQ(stats.password_rotated.load(), 2U);
  EXPECT_EQ(stats.grants_revoked.load(), 1U);
  EXPECT_EQ(stats.denied_backoff.load(), 0U);
  EXPECT_EQ(stats.grant_accepted.load(), 0U);
  EXPECT_EQ(stats.grant_rejected.load(), 0U);

  EXPECT_EQ(audited_events().size(), 9U);
}

}  // namespace
}  // namespace heyaki
