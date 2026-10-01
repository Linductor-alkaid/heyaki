// Issue #13 regression: a push whose FILE_MANIFEST is never answered
// (receiver policy off, an old peer, lost frames) used to stall in the
// offered phase forever. The bounded offer window (FileServiceConfig
// .offer_timeout_milliseconds) must resolve it with exactly one failed
// terminal (timeout / "offer_expired" / deadline_exceeded), hold every byte
// behind the accepted gate until FILE_ACCEPT, ignore late frames after the
// deadline, keep cancel/deadline races single-terminal, keep session loss a
// pause (never a deadline failure), and re-arm the window on resume.
//
// The harness runs on manual clocks: the manifest is sent by running only the
// LEFT side's blocking worker and poster (no pump), so the frame stays queued
// and the receiver provably never answers; prune() on the advanced clock is
// the deadline check the node's expiry tick performs in production.

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
// FILE_MANIFEST frame stays queued in the loopback transport (no pump), so
// the receiver provably never answers and the deadline is armed.
void run_sender_probe_and_manifest(M7ServicePair& harness) {
  harness.left_general.run_all();
  harness.left_blocking.run_all();
  harness.left_poster.run_all();
}

// Assertion helpers for the exact deadline terminal (issue #13 contract).
void expect_deadline_terminal(const FileEventLog& log, const TransferId& id,
                              std::uint64_t expected_total) {
  const auto failed = log.last_of(id, FileTransferPhase::failed);
  ASSERT_TRUE(failed.has_value()) << "no failed terminal event";
  ASSERT_TRUE(failed->error.has_value()) << "failed event carries no error";
  EXPECT_EQ(failed->error->code(), ErrorCode::timeout);
  EXPECT_EQ(failed->error->safe_detail(), "offer_expired");
  ASSERT_TRUE(failed->error->underlying_code().has_value());
  EXPECT_EQ(*failed->error->underlying_code(),
            static_cast<std::int64_t>(StableStatus::deadline_exceeded));
  EXPECT_EQ(*failed->error->underlying_code(), 3);
  EXPECT_EQ(failed->bytes_total, expected_total);
}

bool staging_leftovers(const std::filesystem::path& root) {
  if (!std::filesystem::exists(root)) {
    return false;
  }
  for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
    if (entry.path().filename().string().find(".heyaki-") != std::string::npos) {
      return true;
    }
  }
  return false;
}

// 1: an unanswered manifest resolves after the configured window with exactly
// one failed terminal (timeout / offer_expired / deadline_exceeded = 3); the
// book entry is removed and later prune ticks stay silent.
TEST(M7FileOffer, OfferDeadlineFiresExactlyOneFailedTerminal) {
  M7ServicePair::Options options = file_options();
  options.left_file.offer_timeout_milliseconds = 5'000U;
  M7ServicePair harness(std::move(options));
  FileEventLog left_log;
  install_left_log(harness, left_log);

  const auto source = M7ServicePair::make_source_file(
      harness.left_root_dir.path, "offer.bin", 50'000U, 0x11U);
  auto pushed = harness.left_files->push_file("inbox", "offer/one.bin", source);
  ASSERT_TRUE(pushed);
  const auto id = *pushed.value_if();

  // No clock advance, no prune: the transfer stays unterminal.
  run_sender_probe_and_manifest(harness);
  EXPECT_EQ(left_log.terminal_count(id), 0U);
  EXPECT_EQ(harness.left_files->stats().manifests_sent, 1U);
  EXPECT_EQ(harness.left_files->stats().chunks_sent, 0U);
  EXPECT_EQ(harness.left_files->stats().completes_sent, 0U);
  // No pump happened: the receiver has seen nothing at all.
  EXPECT_EQ(harness.right_files->stats().manifests_received, 0U);

  // Past the window, the very first prune fires the single terminal.
  harness.m6.left_clock += 6'000U;
  harness.left_files->prune();
  EXPECT_EQ(left_log.terminal_count(id), 1U);
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::failed), 1U);
  expect_deadline_terminal(left_log, id, 50'000U);
  EXPECT_TRUE(harness.left_book->entries().empty());
  EXPECT_EQ(harness.left_files->stats().sender_failed, 1U);
  EXPECT_EQ(harness.left_files->stats().sender_committed, 0U);

  // The transfer is gone: further ticks emit nothing new.
  harness.m6.left_clock += 60'000U;
  harness.left_files->prune();
  harness.left_files->prune();
  EXPECT_EQ(left_log.terminal_count(id), 1U);
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::failed), 1U);
  EXPECT_EQ(harness.left_files->stats().sender_failed, 1U);
}

// 2: the accepted gate — before FILE_ACCEPT no byte is read, staged, or sent,
// even when the maintenance tick (prune) services the sender; afterwards the
// normal happy path still commits.
TEST(M7FileOffer, AcceptedGateWithholdsChunksUntilFileAccept) {
  M7ServicePair::Options options = file_options();
  options.left_file.offer_timeout_milliseconds = 5'000U;
  M7ServicePair harness(std::move(options));
  FileEventLog left_log;
  install_left_log(harness, left_log);

  const auto source = M7ServicePair::make_source_file(
      harness.left_root_dir.path, "gate.bin", 80'000U, 0x22U);
  auto pushed = harness.left_files->push_file("inbox", "gate/two.bin", source);
  ASSERT_TRUE(pushed);
  const auto id = *pushed.value_if();
  run_sender_probe_and_manifest(harness);

  const auto left_stats = harness.left_files->stats();
  EXPECT_EQ(left_stats.manifests_sent, 1U);
  EXPECT_EQ(left_stats.chunks_sent, 0U);
  EXPECT_EQ(left_stats.completes_sent, 0U);

  // A maintenance tick BEFORE the deadline: the unaccepted sender must not
  // dispatch a single read (the gate); without the gate start_next_read
  // would queue a blocking read here.
  harness.left_files->prune();
  EXPECT_FALSE(harness.left_blocking.has_pending())
      << "prune dispatched a read for an unaccepted transfer";
  EXPECT_EQ(harness.left_files->stats().chunks_sent, 0U);

  // One tick short of the deadline: still offered, still no bytes.
  harness.m6.left_clock += 4'999U;
  harness.left_files->prune();
  EXPECT_EQ(left_log.terminal_count(id), 0U);
  EXPECT_FALSE(harness.left_blocking.has_pending());

  // The manifest crosses; the receiver sees the offer, still zero bytes.
  harness.m6.pump();
  EXPECT_EQ(harness.right_files->stats().manifests_received, 1U);
  EXPECT_EQ(harness.right_files->stats().chunks_received, 0U);
  EXPECT_EQ(harness.left_files->stats().chunks_sent, 0U);
  EXPECT_EQ(harness.left_files->stats().completes_sent, 0U);

  // The gate does not harm the happy path: the run completes.
  harness.cycle();
  const auto final_path = harness.right_root_dir.path / "inbox" / "gate" / "two.bin";
  ASSERT_TRUE(std::filesystem::exists(final_path));
  EXPECT_EQ(M7ServicePair::read_file_bytes(final_path),
            M7ServicePair::read_file_bytes(source));
  EXPECT_EQ(harness.left_files->stats().sender_committed, 1U);
  EXPECT_GT(harness.left_files->stats().chunks_sent, 0U);
  EXPECT_EQ(harness.right_files->stats().committed, 1U);
}

// 3: after the deadline terminal, a late FILE_ACCEPT / FILE_CHUNK /
// FILE_COMPLETE(ok) for the dead transfer id is processed (and counted as
// stray traffic) but revives nothing: no new event, no commit, no bytes on
// disk, no frames sent. The frames enter through FileService::handle_frame
// directly — the receiver provably never saw the manifest (the loopback
// pump would deliver it and create a receiver state of its own), matching
// the issue #13 shape where the refusing end never answered at all.
TEST(M7FileOffer, LateFramesAfterDeadlineCannotReviveTransfer) {
  M7ServicePair::Options options = file_options();
  options.left_file.offer_timeout_milliseconds = 5'000U;
  M7ServicePair harness(std::move(options));
  FileEventLog left_log;
  install_left_log(harness, left_log);

  const auto source = M7ServicePair::make_source_file(
      harness.left_root_dir.path, "late.bin", 50'000U, 0x33U);
  auto pushed = harness.left_files->push_file("inbox", "late/three.bin", source);
  ASSERT_TRUE(pushed);
  const auto id = *pushed.value_if();
  run_sender_probe_and_manifest(harness);
  harness.m6.left_clock += 6'000U;
  harness.left_files->prune();
  ASSERT_EQ(left_log.count_of(id, FileTransferPhase::failed), 1U);

  const auto events_before = left_log.events.size();
  const auto left_before = harness.left_files->stats();
  const auto right_before = harness.right_files->stats();
  const auto channel = harness.file_channel_of(harness.left_session());
  const auto deliver = [&](FrameType type, std::span<const std::byte> payload) {
    FrameView frame;
    frame.type = static_cast<std::uint8_t>(type);
    frame.channel_id = channel;
    frame.payload = payload;
    harness.left_files->handle_frame(frame);
  };

  // Late FILE_ACCEPT.
  FileAcceptBody accept;
  accept.transfer_id = id;
  auto encoded_accept = encode_file_accept(accept);
  ASSERT_TRUE(encoded_accept);
  deliver(FrameType::file_accept, *encoded_accept.value_if());

  // Late FILE_CHUNK (well-formed header + plausible data).
  FileChunkHeader header;
  header.transfer_id = id;
  header.offset = 0U;
  header.data_length = 8U;
  header.blake3.fill(std::byte{0x5AU});
  const std::vector<std::byte> data(8U, std::byte{0x3CU});
  deliver(FrameType::file_chunk, encode_file_chunk(header, data));

  // Late FILE_COMPLETE(ok).
  FileCompleteBody complete;
  complete.transfer_id = id;
  complete.status = StableStatus::ok;
  auto encoded_complete = encode_file_complete(complete);
  ASSERT_TRUE(encoded_complete);
  deliver(FrameType::file_complete, *encoded_complete.value_if());
  // No cycle()/pump here: the injected frames were already delivered through
  // handle_frame, and pumping would cross the still-queued manifest to the
  // untouched receiver side.

  // The frames were processed (counted as stray/replayed traffic)…
  const auto left_after = harness.left_files->stats();
  EXPECT_GT(left_after.accepts_received, left_before.accepts_received);
  EXPECT_GT(left_after.duplicate_chunks, left_before.duplicate_chunks);
  // …but the transfer stayed dead: no new events, no bytes, no commit.
  EXPECT_EQ(left_log.events.size(), events_before);
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::committed), 0U);
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::transferring), 0U);
  EXPECT_EQ(left_after.chunks_sent, left_before.chunks_sent);
  EXPECT_EQ(left_after.completes_sent, left_before.completes_sent);
  EXPECT_EQ(left_after.sender_committed, left_before.sender_committed);
  EXPECT_EQ(harness.right_files->stats().manifests_received,
            right_before.manifests_received);
  EXPECT_EQ(harness.right_files->stats().chunks_received,
            right_before.chunks_received);
  EXPECT_EQ(harness.right_files->stats().committed, 0U);
  EXPECT_FALSE(std::filesystem::exists(harness.right_root_dir.path / "inbox" /
                                       "late" / "three.bin"));
  EXPECT_FALSE(staging_leftovers(harness.right_root_dir.path));
}

// 4a: cancel wins the race — a cancel before the deadline produces exactly
// one cancelled terminal, and the later deadline produces nothing.
TEST(M7FileOffer, CancelBeforeDeadlinePreemptsExpiry) {
  M7ServicePair::Options options = file_options();
  options.left_file.offer_timeout_milliseconds = 5'000U;
  M7ServicePair harness(std::move(options));
  FileEventLog left_log;
  install_left_log(harness, left_log);

  const auto source = M7ServicePair::make_source_file(
      harness.left_root_dir.path, "race-a.bin", 50'000U, 0x44U);
  auto pushed = harness.left_files->push_file("inbox", "race/a.bin", source);
  ASSERT_TRUE(pushed);
  const auto id = *pushed.value_if();
  run_sender_probe_and_manifest(harness);

  ASSERT_TRUE(harness.left_files->cancel_transfer(id));
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::cancelled), 1U);
  EXPECT_EQ(left_log.terminal_count(id), 1U);
  EXPECT_TRUE(harness.left_book->entries().empty());

  // The deadline can no longer fire a second terminal.
  harness.m6.left_clock += 60'000U;
  harness.left_files->prune();
  harness.left_files->prune();
  EXPECT_EQ(left_log.terminal_count(id), 1U);
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::failed), 0U);
  EXPECT_EQ(harness.left_files->stats().sender_cancelled, 1U);
  EXPECT_EQ(harness.left_files->stats().sender_failed, 0U);

  // Cancelling again is transfer_unknown, never a second terminal.
  const auto again = harness.left_files->cancel_transfer(id);
  ASSERT_FALSE(again);
  EXPECT_EQ(again.error_if()->code(), ErrorCode::peer_offline);
  EXPECT_EQ(again.error_if()->safe_detail(), "transfer_unknown");
  EXPECT_EQ(left_log.terminal_count(id), 1U);
}

// 4b: deadline wins the race — after the failed terminal, cancel reports
// transfer_unknown and the event stream still holds exactly one terminal.
TEST(M7FileOffer, CancelAfterDeadlineLeavesSingleTerminal) {
  M7ServicePair::Options options = file_options();
  options.left_file.offer_timeout_milliseconds = 5'000U;
  M7ServicePair harness(std::move(options));
  FileEventLog left_log;
  install_left_log(harness, left_log);

  const auto source = M7ServicePair::make_source_file(
      harness.left_root_dir.path, "race-b.bin", 50'000U, 0x55U);
  auto pushed = harness.left_files->push_file("inbox", "race/b.bin", source);
  ASSERT_TRUE(pushed);
  const auto id = *pushed.value_if();
  run_sender_probe_and_manifest(harness);

  harness.m6.left_clock += 6'000U;
  harness.left_files->prune();
  EXPECT_EQ(left_log.terminal_count(id), 1U);
  expect_deadline_terminal(left_log, id, 50'000U);

  const auto cancelled = harness.left_files->cancel_transfer(id);
  ASSERT_FALSE(cancelled);
  EXPECT_EQ(cancelled.error_if()->code(), ErrorCode::peer_offline);
  EXPECT_EQ(cancelled.error_if()->safe_detail(), "transfer_unknown");
  EXPECT_EQ(left_log.terminal_count(id), 1U);
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::cancelled), 0U);
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::failed), 1U);
  EXPECT_EQ(harness.left_files->stats().sender_cancelled, 0U);
  EXPECT_EQ(harness.left_files->stats().sender_failed, 1U);
}

// 5: a session close before FILE_ACCEPT parks the sender as paused in the
// book (not failed); the paused entry carries no deadline, so prune on the
// retired service never turns it into a terminal.
TEST(M7FileOffer, SessionCloseBeforeAcceptPausesWithoutDeadline) {
  M7ServicePair::Options options = file_options();
  options.left_file.offer_timeout_milliseconds = 5'000U;
  M7ServicePair harness(std::move(options));
  FileEventLog left_log;
  install_left_log(harness, left_log);

  const auto source = M7ServicePair::make_source_file(
      harness.left_root_dir.path, "close.bin", 50'000U, 0x66U);
  auto pushed = harness.left_files->push_file("inbox", "close/five.bin", source);
  ASSERT_TRUE(pushed);
  const auto id = *pushed.value_if();
  run_sender_probe_and_manifest(harness);

  harness.left_files->handle_session_closed();
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::paused), 1U);
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::failed), 0U);
  const auto entry = harness.left_book->entries().find(id);
  ASSERT_NE(entry, harness.left_book->entries().end());
  EXPECT_EQ(entry->second.phase, FileTransferPhase::paused);

  // The deadline state died with the SenderState: pruning the old service
  // well past the window changes nothing.
  harness.m6.left_clock += 60'000U;
  harness.left_files->prune();
  harness.left_files->prune();
  EXPECT_EQ(left_log.terminal_count(id), 0U);
  const auto still = harness.left_book->entries().find(id);
  ASSERT_NE(still, harness.left_book->entries().end());
  EXPECT_EQ(still->second.phase, FileTransferPhase::paused);
  EXPECT_EQ(harness.left_files->stats().sender_failed, 0U);
}

// 6: resume re-arms the offer window — a pause longer than the original
// window followed by a resume does not expire on the next tick; the transfer
// only fails once the NEW window lapses unanswered.
TEST(M7FileOffer, ResumeRearmsOfferDeadline) {
  M7ServicePair::Options options = file_options();
  options.left_file.offer_timeout_milliseconds = 5'000U;
  M7ServicePair harness(std::move(options));
  FileEventLog left_log;
  install_left_log(harness, left_log);

  const auto source = M7ServicePair::make_source_file(
      harness.left_root_dir.path, "resume.bin", 50'000U, 0x77U);
  auto pushed = harness.left_files->push_file("inbox", "resume/six.bin", source);
  ASSERT_TRUE(pushed);
  const auto id = *pushed.value_if();
  run_sender_probe_and_manifest(harness);

  ASSERT_TRUE(harness.left_files->pause_transfer(id));
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::paused), 1U);

  // Past the ORIGINAL deadline, then resume: the window restarts.
  harness.m6.left_clock += 10'000U;
  ASSERT_TRUE(harness.left_files->resume_transfer(id));
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::transferring), 1U);

  harness.left_files->prune();
  EXPECT_EQ(left_log.terminal_count(id), 0U);
  const auto entry = harness.left_book->entries().find(id);
  ASSERT_NE(entry, harness.left_book->entries().end());
  EXPECT_EQ(entry->second.phase, FileTransferPhase::transferring);

  // The NEW window lapses: exactly one failed terminal, after the resume.
  harness.m6.left_clock += 6'000U;
  harness.left_files->prune();
  EXPECT_EQ(left_log.terminal_count(id), 1U);
  EXPECT_EQ(left_log.count_of(id, FileTransferPhase::failed), 1U);
  expect_deadline_terminal(left_log, id, 50'000U);
  EXPECT_TRUE(harness.left_book->entries().empty());
}

}  // namespace
}  // namespace heyaki
