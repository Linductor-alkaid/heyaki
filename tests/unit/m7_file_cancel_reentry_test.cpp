// Issue #16 regression: a FileService call whose send fails mid-call runs the
// Node's session teardown reentrantly (send -> pump -> physical send failure
// -> PeerSession::fail -> notify -> Node observer -> handle_session_closed,
// which clears senders_/receivers_ while the caller is still on the stack).
// The fixed contract: every entry point retires its state (terminal flag,
// book entry, map erase) and captures event payloads BEFORE the send, and
// only revalidates by stable TransferId afterwards — no pointer or reference
// into senders_/receivers_ may be touched after a send.
//
// The harness replays the Node observer through the M6/M7 session observers:
// when the left PeerSession reports `closed`, the observer calls
// FileService::handle_session_closed synchronously, exactly like the Node.
// The failing send itself is produced deterministically: the loopback file
// channel is closed WITHOUT touching the session state, so the PeerSession
// stays authenticated and its next physical send fails synchronously with
// "channel_closed" (never would_block).

#include "m7_support.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

using test::M7ServicePair;

std::vector<std::string> file_scopes() {
  return {"message.send",    "rpc.device.read", "rpc.device.configure",
          "stream.open",     "event.subscribe:*",
          "file.push:inbox", "file.pull:inbox"};
}

M7ServicePair::Options file_options() {
  M7ServicePair::Options options;
  options.left_scopes = file_scopes();
  options.right_scopes = file_scopes();
  options.left_file.receive_roots.push_back(
      FileRootConfig{.name = "inbox",
                     .directory = {},
                     .max_file_bytes = 64ULL * 1024ULL * 1024ULL,
                     .max_total_bytes = 128ULL * 1024ULL * 1024ULL,
                     .max_concurrent_receives = 2U});
  options.right_file = options.left_file;
  return options;
}

// Installs the Node-style synchronous teardown replay on the left side.
// `teardown_slot` must point at a variable declared BEFORE the harness: the
// observer also fires during session bring-up, while the FileService does not
// exist yet (the slot still holds nullptr, guarded below).
void install_left_teardown_replay(M7ServicePair::Options& options,
                                  FileService** teardown_slot) {
  options.left_session_observer =
      [teardown_slot](const PeerSessionDiagnostics& diagnostics) {
        if (diagnostics.state == PeerSessionState::closed &&
            *teardown_slot != nullptr) {
          (*teardown_slot)->handle_session_closed();
        }
      };
}

struct FileEventLog {
  std::vector<FileTransferEvent> events;

  std::size_t count_of(const TransferId& id, FileTransferPhase phase) const {
    return static_cast<std::size_t>(std::count_if(
        events.begin(), events.end(),
        [&](const FileTransferEvent& event) {
          return event.transfer_id == id && event.phase == phase;
        }));
  }
  std::size_t terminal_count(const TransferId& id) const {
    return count_of(id, FileTransferPhase::committed) +
           count_of(id, FileTransferPhase::failed) +
           count_of(id, FileTransferPhase::cancelled);
  }
  std::optional<FileTransferEvent> last_of(const TransferId& id,
                                           FileTransferPhase phase) const {
    std::optional<FileTransferEvent> found;
    for (const auto& event : events) {
      if (event.transfer_id == id && event.phase == phase) {
        found = event;
      }
    }
    return found;
  }
  void dump(const char* tag) const {
    for (const auto& event : events) {
      std::printf(
          "%s phase=%s bytes=%llu/%llu detail=%s\n", tag,
          std::string{file_transfer_phase_name(event.phase)}.c_str(),
          static_cast<unsigned long long>(event.bytes_done),
          static_cast<unsigned long long>(event.bytes_total),
          event.error.has_value()
              ? std::string{event.error->safe_detail()}.c_str()
              : "-");
    }
  }
};

void install_left_log(M7ServicePair& harness, FileEventLog& log) {
  harness.left_file_sinks.events = [&log](const DeviceEndpointKey&,
                                          const FileTransferEvent& event) {
    log.events.push_back(event);
  };
}

// Drives the push through probe -> manifest on the sender side only: the
// FILE_MANIFEST frames stay queued in the loopback transport (no pump), so
// the receiver provably never answers and the offer deadline is armed.
void run_sender_probe_and_manifest(M7ServicePair& harness) {
  harness.left_general.run_all();
  harness.left_blocking.run_all();
  harness.left_poster.run_all();
}

// Two pushes (4096 bytes each) whose manifests were sent but never answered:
// both transfers sit in the offered phase with the deadline armed. Asserts
// the offered events so a broken scenario fails here, not downstream.
struct TwoOfferedPushes {
  TransferId a;
  TransferId b;
};

TwoOfferedPushes push_two_unanswered(M7ServicePair& harness, FileEventLog& log) {
  const auto source_a = M7ServicePair::make_source_file(
      harness.left_root_dir.path, "a.bin", 4096U, 0x1AU);
  auto pushed_a = harness.left_files->push_file("inbox", "a.bin", source_a);
  EXPECT_TRUE(pushed_a);
  const auto source_b = M7ServicePair::make_source_file(
      harness.left_root_dir.path, "b.bin", 4096U, 0x2BU);
  auto pushed_b = harness.left_files->push_file("inbox", "b.bin", source_b);
  EXPECT_TRUE(pushed_b);
  if (!pushed_a || !pushed_b) {
    return {};
  }
  run_sender_probe_and_manifest(harness);
  EXPECT_EQ(log.count_of(*pushed_a.value_if(), FileTransferPhase::offered), 1U);
  EXPECT_EQ(log.count_of(*pushed_b.value_if(), FileTransferPhase::offered), 1U);
  EXPECT_EQ(log.terminal_count(*pushed_a.value_if()), 0U);
  EXPECT_EQ(log.terminal_count(*pushed_b.value_if()), 0U);
  return TwoOfferedPushes{*pushed_a.value_if(), *pushed_b.value_if()};
}

// 1: the reported UAF main path. cancel_transfer sends its abort frame
// through a file channel that just died; the send fails synchronously inside
// pump() and the observer teardown clears senders_ BEFORE cancel_transfer
// returns. The fixed contract: A retires with exactly one cancelled terminal
// (its book entry erased, never resurrected by the reentrant close), B is
// parked as paused in the book by the teardown, and both stale-id control
// calls report transfer_unknown without emitting anything.
TEST(M7FileCancelReentry, CancelSurvivesSynchronousSessionTeardown) {
  FileService* left_files_raw = nullptr;  // must precede the harness
  M7ServicePair::Options options = file_options();
  options.left_file.offer_timeout_milliseconds = 50U;
  install_left_teardown_replay(options, &left_files_raw);
  M7ServicePair harness(std::move(options));
  left_files_raw = harness.left_files.get();
  FileEventLog left_log;
  install_left_log(harness, left_log);

  const auto ids = push_two_unanswered(harness, left_log);
  const auto id_a = ids.a;
  const auto id_b = ids.b;

  // Kill the left file physical channel only: the session stays
  // authenticated, the next physical send fails with "channel_closed".
  harness.m6.pair.left().close_channels(transport::ChannelKind::file,
                                        transport::CloseReason::protocol_error);

  // send_abort -> send_frame -> pump -> physical failure -> fail -> notify ->
  // observer -> handle_session_closed, all inside this call.
  const auto cancelled = harness.left_files->cancel_transfer(id_a);
  ASSERT_TRUE(cancelled)
      << "cancel_transfer must survive the synchronous teardown";
  if (left_log.terminal_count(id_a) != 1U) {
    left_log.dump("cancel-reentry");
  }

  // A: exactly one cancelled terminal carrying the manifest size; the
  // reentrant close must not add a paused event for the retired transfer.
  EXPECT_EQ(left_log.count_of(id_a, FileTransferPhase::cancelled), 1U);
  EXPECT_EQ(left_log.count_of(id_a, FileTransferPhase::paused), 0U);
  EXPECT_EQ(left_log.terminal_count(id_a), 1U);
  const auto cancel_event = left_log.last_of(id_a, FileTransferPhase::cancelled);
  ASSERT_TRUE(cancel_event.has_value());
  EXPECT_EQ(cancel_event->bytes_total, 4096U);
  EXPECT_EQ(cancel_event->bytes_done, 0U);
  EXPECT_FALSE(cancel_event->error.has_value());

  // B: parked by the reentrant teardown (transport / "session_closed"),
  // still unterminal.
  EXPECT_EQ(left_log.count_of(id_b, FileTransferPhase::paused), 1U);
  EXPECT_EQ(left_log.terminal_count(id_b), 0U);
  const auto paused_event = left_log.last_of(id_b, FileTransferPhase::paused);
  ASSERT_TRUE(paused_event.has_value());
  ASSERT_TRUE(paused_event->error.has_value());
  EXPECT_EQ(paused_event->error->code(), ErrorCode::transport);
  EXPECT_EQ(paused_event->error->safe_detail(), "session_closed");

  // Book: A is gone (cancel erased it before the send; the teardown must not
  // resurrect it), B is parked as paused for the next session.
  const auto& book = harness.left_book->entries();
  EXPECT_EQ(book.find(id_a), book.end());
  const auto entry_b = book.find(id_b);
  ASSERT_NE(entry_b, book.end());
  EXPECT_EQ(entry_b->second.phase, FileTransferPhase::paused);
  EXPECT_EQ(entry_b->second.bytes_total, 4096U);

  const auto stats = harness.left_files->stats();
  EXPECT_EQ(stats.sender_cancelled, 1U);
  EXPECT_EQ(stats.sender_failed, 0U);
  EXPECT_EQ(stats.sender_committed, 0U);

  // The retired transfer is unknown: a second cancel reports transfer_unknown
  // and neither emits events nor moves stats.
  const auto events_before = left_log.events.size();
  const auto stats_before = harness.left_files->stats();
  const auto again = harness.left_files->cancel_transfer(id_a);
  ASSERT_FALSE(again);
  EXPECT_EQ(again.error_if()->code(), ErrorCode::peer_offline);
  EXPECT_EQ(again.error_if()->safe_detail(), "transfer_unknown");

  // B only survives inside the book (senders_ was cleared reentrantly), so a
  // resume on this session's service is transfer_unknown too.
  const auto resumed = harness.left_files->resume_transfer(id_b);
  ASSERT_FALSE(resumed);
  EXPECT_EQ(resumed.error_if()->code(), ErrorCode::peer_offline);
  EXPECT_EQ(resumed.error_if()->safe_detail(), "transfer_unknown");

  EXPECT_EQ(left_log.events.size(), events_before);
  const auto stats_after = harness.left_files->stats();
  EXPECT_EQ(stats_after.sender_cancelled, stats_before.sender_cancelled);
  EXPECT_EQ(stats_after.sender_failed, stats_before.sender_failed);
  EXPECT_EQ(stats_after.sender_committed, stats_before.sender_committed);
}

// 2: the receiving side's write-dispatch-rejection path across the same
// reentrant teardown. With the blocking write dispatch refusing admission,
// the first chunk hash finishes and fail_receive fires (resource_exhausted /
// "write_dispatch_rejected"); its abort send rides the freshly closed channel
// and tears the session down synchronously inside the same call stack.
//
// KNOWN REMAINING DEFECT (same class as issue #16, NOT yet fixed): on this
// path FileService still dereferences the retired ReceiverState —
//   * file_service.cpp fail_receive: send_abort(receive.transfer_id, ...)
//     reads the transfer id AFTER receivers_.erase() freed the node, and
//   * file_service.cpp finish_chunk_hash: pump_validate(*receive) runs after
//     dispatch_chunk_write may have failed the receive reentrantly.
// Both reads return stale bytes on a plain build (the test passes) and are
// reported as heap-use-after-free by ASAN/valgrind or a freed-memory poison
// pass. This test is the reproducer.
TEST(M7FileCancelReentry, WriteDispatchRejectionAbortsAcrossReentrantTeardown) {
  FileService* left_files_raw = nullptr;  // must precede the harness
  M7ServicePair::Options options = file_options();
  install_left_teardown_replay(options, &left_files_raw);
  M7ServicePair harness(std::move(options));
  left_files_raw = harness.left_files.get();
  FileEventLog left_log;
  install_left_log(harness, left_log);

  // The receiver-side (left) blocking write dispatch will be rejected.
  harness.left_blocking.admit = false;

  const auto source = M7ServicePair::make_source_file(
      harness.right_root_dir.path, "inbound.bin", 4096U, 0x3CU);
  auto pushed = harness.right_files->push_file("inbox", "inbound.bin", source);
  ASSERT_TRUE(pushed);
  const auto id = *pushed.value_if();

  // Drive the SENDER side (right) plus frame delivery until its journey is
  // done: manifest -> left accept (the left channel is still open, so the
  // accept send succeeds) -> chunk + complete delivered to the left. The
  // left's chunk-hash task stays queued in left_general and must not run.
  for (int round = 0; round < 32; ++round) {
    harness.right_general.run_all();
    harness.right_blocking.run_all();
    harness.right_poster.run_all();
    harness.m6.pump();
    if (!harness.right_general.has_pending() &&
        !harness.right_blocking.has_pending() &&
        !harness.right_poster.has_pending() &&
        harness.m6.pair.left().buffered_amount() == 0U &&
        harness.m6.pair.right().buffered_amount() == 0U) {
      break;
    }
  }

  // Scenario sanity: the offer crossed, the accept went out, exactly one
  // chunk plus the verdict request reached the left, and the left's hash task
  // is still pending.
  const auto right_stats = harness.right_files->stats();
  EXPECT_EQ(right_stats.manifests_sent, 1U);
  EXPECT_EQ(right_stats.chunks_sent, 1U);
  EXPECT_EQ(right_stats.completes_sent, 1U);
  const auto left_stats = harness.left_files->stats();
  EXPECT_EQ(left_stats.manifests_received, 1U);
  EXPECT_EQ(left_stats.accepts_sent, 1U);
  EXPECT_EQ(left_stats.chunks_received, 1U);
  ASSERT_TRUE(harness.left_general.has_pending())
      << "the chunk hash task should be queued on the receiver";

  // Kill the left file channel: the receiver's abort send will fail
  // synchronously inside the same call stack.
  harness.m6.pair.left().close_channels(transport::ChannelKind::file,
                                        transport::CloseReason::protocol_error);

  // Hash task -> poster -> finish_chunk_hash -> dispatch_chunk_write rejected
  // (admit=false) -> fail_receive -> emit -> cleanup -> erase -> send_abort ->
  // pump failure -> fail -> notify -> observer -> handle_session_closed.
  harness.left_general.run_all();
  harness.left_poster.run_all();
  if (left_log.events.size() != 2U) {
    left_log.dump("write-dispatch-reject");
  }

  // The receiver's event stream is exact: one transferring progress event
  // from the (successful) accept, then exactly one failed terminal.
  ASSERT_EQ(left_log.events.size(), 2U)
      << "unexpected receiver event stream";
  const auto& accepted = left_log.events.front();
  EXPECT_EQ(accepted.transfer_id, id);
  EXPECT_EQ(accepted.phase, FileTransferPhase::transferring);
  const auto& failed = left_log.events.back();
  EXPECT_EQ(failed.transfer_id, id);
  EXPECT_EQ(failed.phase, FileTransferPhase::failed);
  ASSERT_TRUE(failed.error.has_value());
  // The StableStatus::resource_exhausted rides the abort frame to the peer;
  // the local event error carries the safe detail (the service emits its
  // internal error code for receive failures — observed contract).
  EXPECT_EQ(failed.error->safe_detail(), "write_dispatch_rejected");
  EXPECT_EQ(failed.bytes_total, 4096U);
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::cancelled), 0U);
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::committed), 0U);
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::paused), 0U);
  EXPECT_EQ(left_log.terminal_count(id), 1U);

  EXPECT_GE(harness.left_files->stats().partial_cleanups, 1U);
  // Nothing was committed to disk.
  EXPECT_FALSE(std::filesystem::exists(harness.left_root_dir.path / "inbox" /
                                       "inbound.bin"));
}

// 3: after the reentrant teardown the expiry tick must stay silent. A was
// cancelled (sender state and book entry erased), B survives only as a paused
// book entry without a deadline: prune() finds no sender state for either and
// must not emit anything nor resurrect A.
TEST(M7FileCancelReentry, PruneAfterReentrantTeardownStaysSilent) {
  FileService* left_files_raw = nullptr;  // must precede the harness
  M7ServicePair::Options options = file_options();
  options.left_file.offer_timeout_milliseconds = 50U;
  install_left_teardown_replay(options, &left_files_raw);
  M7ServicePair harness(std::move(options));
  left_files_raw = harness.left_files.get();
  FileEventLog left_log;
  install_left_log(harness, left_log);

  const auto ids = push_two_unanswered(harness, left_log);
  const auto id_a = ids.a;
  const auto id_b = ids.b;

  harness.m6.pair.left().close_channels(transport::ChannelKind::file,
                                        transport::CloseReason::protocol_error);
  const auto cancelled = harness.left_files->cancel_transfer(id_a);
  ASSERT_TRUE(cancelled);
  const auto events_after_cancel = left_log.events.size();
  ASSERT_EQ(left_log.terminal_count(id_a), 1U);
  ASSERT_EQ(left_log.count_of(id_b, FileTransferPhase::paused), 1U);

  // Well past the 50 ms offer window: the deadline can only fire through
  // senders_, which the teardown emptied.
  harness.m6.left_clock += 1000U;
  harness.left_files->prune();
  harness.left_files->prune();

  EXPECT_EQ(left_log.events.size(), events_after_cancel)
      << "prune must stay silent after the reentrant teardown";
  EXPECT_EQ(left_log.terminal_count(id_a), 1U);
  EXPECT_EQ(left_log.terminal_count(id_b), 0U);
  EXPECT_EQ(harness.left_files->stats().sender_failed, 0U);
  const auto& book = harness.left_book->entries();
  EXPECT_EQ(book.find(id_a), book.end());
  const auto entry_b = book.find(id_b);
  ASSERT_NE(entry_b, book.end());
  EXPECT_EQ(entry_b->second.phase, FileTransferPhase::paused);
}

}  // namespace
}  // namespace heyaki
