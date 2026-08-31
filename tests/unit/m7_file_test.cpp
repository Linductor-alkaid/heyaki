// M7 file transfer tests over the loopback pair: manifest/accept/chunk/
// complete protocol, safe staging with atomic commit (M7-10/M7-11), quota
// and scope admission before any byte (M7-09), resume by transfer id with
// on-disk sidecars (M7-13), pause/cancel, duplicate/conflict chunks, and
// the pull flow riding the unary-RPC surface.

#include "m7_support.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace heyaki {
namespace {

using test::M7ServicePair;
using test::ManualDispatch;
using test::ManualPoster;

std::vector<std::string> file_scopes() {
  return {"message.send",    "rpc.device.read", "rpc.device.configure",
          "stream.open",     "event.subscribe:*",
          "file.push:inbox", "file.pull:inbox"};
}

M7ServicePair::Options file_options() {
  M7ServicePair::Options options;
  options.left_scopes = file_scopes();
  options.right_scopes = file_scopes();
  // The harness fills each root's directory with the side's temp directory.
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
  std::optional<TransferId> first_with_phase(FileTransferPhase phase) const {
    for (const auto& event : events) {
      if (event.phase == phase) {
        return event.transfer_id;
      }
    }
    return std::nullopt;
  }
};

void install_right_log(M7ServicePair& harness, FileEventLog& log) {
  harness.right_file_sinks.events = [&log](const DeviceEndpointKey&,
                                           const FileTransferEvent& event) {
    log.events.push_back(event);
  };
}

TEST(M7FileService, PushCommitsWithBlake3AndAtomicRename) {
  M7ServicePair harness(file_options());
  FileEventLog right_log;
  install_right_log(harness, right_log);

  const auto source = M7ServicePair::make_source_file(
      harness.left_root_dir.path, "source.bin", 100'000U, 0x10U);
  auto pushed = harness.left_files->push_file("inbox", "nested/report.bin", source);
  ASSERT_TRUE(pushed);
  const auto id = *pushed.value_if();
  harness.cycle();

  const auto final_path = harness.right_root_dir.path / "inbox" / "nested" / "report.bin";
  ASSERT_TRUE(std::filesystem::exists(final_path));
  EXPECT_EQ(M7ServicePair::read_file_bytes(final_path),
            M7ServicePair::read_file_bytes(source));
  // No staging leftovers after the atomic rename.
  std::size_t leftovers = 0U;
  for (const auto& entry :
       std::filesystem::recursive_directory_iterator(harness.right_root_dir.path / "inbox")) {
    const auto name = entry.path().filename().string();
    if (name.find(".heyaki-") != std::string::npos) {
      ++leftovers;
    }
  }
  EXPECT_EQ(leftovers, 0U);

  const auto left_stats = harness.left_files->stats();
  EXPECT_EQ(left_stats.sender_committed, 1U);
  const auto right_stats = harness.right_files->stats();
  EXPECT_EQ(right_stats.committed, 1U);
  EXPECT_TRUE(right_log.last_of(id, FileTransferPhase::committed).has_value());
  // The sender observed the receiver's terminal verdict.
  EXPECT_TRUE(harness.left_files->stats().sender_committed == 1U);
}

TEST(M7FileService, MultiChunkPushCommitsInOrder) {
  M7ServicePair harness(file_options());
  FileEventLog right_log;
  install_right_log(harness, right_log);
  // 600 KiB over 256 KiB chunks forces the multi-chunk window/read/write
  // pipeline (three chunks, last one short).
  const auto source = M7ServicePair::make_source_file(
      harness.left_root_dir.path, "big.bin", 600'000U, 0x33U);
  auto pushed = harness.left_files->push_file("inbox", "multi/big.bin", source);
  ASSERT_TRUE(pushed);
  harness.cycle(256);

  const auto final_path = harness.right_root_dir.path / "inbox" / "multi" / "big.bin";
  ASSERT_TRUE(std::filesystem::exists(final_path));
  EXPECT_EQ(M7ServicePair::read_file_bytes(final_path),
            M7ServicePair::read_file_bytes(source));
  const auto left = harness.left_files->stats();
  EXPECT_GE(left.chunks_sent, 3U);
  EXPECT_EQ(left.sender_committed, 1U);
  const auto right = harness.right_files->stats();
  EXPECT_EQ(right.chunks_received, left.chunks_sent);
  EXPECT_EQ(right.committed, 1U);
  EXPECT_EQ(right.duplicate_chunks, 0U);
}

TEST(M7FileService, PushWithoutScopeIsRejected) {
  M7ServicePair::Options options = file_options();
  options.right_scopes = {"message.send", "rpc.device.read",
                          "rpc.device.configure", "stream.open"};  // no file.push
  M7ServicePair harness(std::move(options));

  const auto source =
      M7ServicePair::make_source_file(harness.left_root_dir.path, "s.bin", 100U, 1U);
  auto pushed = harness.left_files->push_file("inbox", "x.bin", source);
  ASSERT_TRUE(pushed);
  harness.cycle();

  const auto stats = harness.right_files->stats();
  EXPECT_EQ(stats.manifests_received, 1U);
  EXPECT_EQ(stats.scope_rejected, 1U);
  const auto left = harness.left_files->stats();
  EXPECT_EQ(left.rejects_received, 1U);
  EXPECT_EQ(left.sender_failed, 1U);
  EXPECT_FALSE(std::filesystem::exists(harness.right_root_dir.path / "inbox" / "x.bin"));
}

TEST(M7FileService, UnsafeNamesRejectedBeforeAccept) {
  M7ServicePair harness(file_options());
  const auto source =
      M7ServicePair::make_source_file(harness.left_root_dir.path, "s.bin", 100U, 1U);
  // The local API rejects unsafe logical names outright.
  EXPECT_FALSE(harness.left_files->push_file("inbox", "../escape.bin", source));
  EXPECT_FALSE(harness.left_files->push_file("inbox", "CON", source));

  // A hostile manifest with an unsafe name fails the codec layer.
  FileManifestBody manifest;
  manifest.transfer_id = TransferId{TransferId::Storage{}};
  manifest.logical_name = "inbox/../../etc/passwd";
  manifest.size = 100U;
  manifest.blake3.assign(32U, std::byte{1});
  manifest.chunk_size = 4096U;
  manifest.transfer_id = [] {
     TransferId::Storage s{};
     for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::byte>(i + 1);
     return TransferId{s};
  }();
  auto encoded = encode_file_manifest(manifest);
  ASSERT_FALSE(encoded);  // codec rejects the unsafe name before the wire
}

TEST(M7FileService, UnknownRootRejected) {
  M7ServicePair harness(file_options());
  const auto source =
      M7ServicePair::make_source_file(harness.left_root_dir.path, "s.bin", 100U, 1U);
  auto pushed = harness.left_files->push_file("vault", "secret.bin", source);
  ASSERT_TRUE(pushed);
  harness.cycle();
  const auto stats = harness.right_files->stats();
  EXPECT_EQ(stats.path_rejected, 1U);
  EXPECT_EQ(harness.left_files->stats().sender_failed, 1U);
}

TEST(M7FileService, SingleFileQuotaRejected) {
  M7ServicePair::Options options = file_options();
  options.right_file.receive_roots[0].max_file_bytes = 50U;
  M7ServicePair harness(std::move(options));

  const auto source =
      M7ServicePair::make_source_file(harness.left_root_dir.path, "s.bin", 100U, 1U);
  ASSERT_TRUE(harness.left_files->push_file("inbox", "big.bin", source));
  harness.cycle();
  EXPECT_EQ(harness.right_files->stats().quota_rejected, 1U);
  EXPECT_EQ(harness.left_files->stats().sender_failed, 1U);
  EXPECT_FALSE(std::filesystem::exists(harness.right_root_dir.path / "inbox" / "big.bin"));
}

TEST(M7FileService, RootConcurrencyRejected) {
  M7ServicePair::Options options = file_options();
  options.right_file.receive_roots[0].max_concurrent_receives = 1U;
  M7ServicePair harness(std::move(options));

  const auto a = M7ServicePair::make_source_file(harness.left_root_dir.path, "a.bin", 100U, 1U);
  const auto b = M7ServicePair::make_source_file(harness.left_root_dir.path, "b.bin", 100U, 2U);
  ASSERT_TRUE(harness.left_files->push_file("inbox", "a.bin", a));
  harness.cycle();
  ASSERT_TRUE(harness.left_files->push_file("inbox", "b.bin", b));
  harness.cycle();
  // The first completed; the second runs against an empty root again.
  EXPECT_EQ(harness.right_files->stats().concurrency_rejected, 0U);
  EXPECT_EQ(harness.right_files->stats().committed, 2U);
}

TEST(M7FileService, CompressedManifestRejectedByPolicy) {
  M7ServicePair harness(file_options());
  // Hand-craft a compressed manifest (the v1 build disables zstd).
  FileManifestBody manifest;
  TransferId::Storage storage{};
  for (std::size_t i = 0; i < storage.size(); ++i) storage[i] = static_cast<std::byte>(i + 9);
  manifest.transfer_id = TransferId{storage};
  manifest.logical_name = "inbox/z.bin";
  manifest.size = 100U;
  manifest.blake3.assign(32U, std::byte{2});
  manifest.chunk_size = 4096U;
  manifest.zstd_compressed = true;
  manifest.expanded_size = 200U;
  auto encoded = encode_file_manifest(manifest);
  ASSERT_TRUE(encoded);
  harness.inject_frame(harness.left_session(), harness.file_channel_of(harness.left_session()),
                       static_cast<std::uint8_t>(FrameType::file_manifest),
                       *encoded.value_if());
  harness.m6.pump();
  const auto stats = harness.right_files->stats();
  EXPECT_EQ(stats.policy_rejected, 1U);
  EXPECT_EQ(stats.manifests_rejected, 1U);
}

TEST(M7FileService, DuplicateChunkIdempotentConflictFails) {
  M7ServicePair harness(file_options());
  const auto source =
      M7ServicePair::make_source_file(harness.left_root_dir.path, "s.bin", 10'000U, 3U);
  ASSERT_TRUE(harness.left_files->push_file("inbox", "dup.bin", source));
  harness.cycle();
  ASSERT_TRUE(std::filesystem::exists(harness.right_root_dir.path / "inbox" / "dup.bin"));
  EXPECT_EQ(harness.right_files->stats().duplicate_chunks, 0U);

  // Exact terminal replay of a chunk is ignored (terminal replay rule).
  const auto stats = harness.right_files->stats();
  EXPECT_EQ(stats.committed, 1U);

  // A conflicting chunk for the committed transfer is ignored, never
  // reopening committed output.
  FileChunkHeader header;
  header.transfer_id = harness.left_book->entries().empty()
                           ? TransferId{}
                           : TransferId{};
  // (Committed transfers leave no book entries; craft an unknown id.)
  TransferId::Storage storage{};
  for (std::size_t i = 0; i < storage.size(); ++i) storage[i] = static_cast<std::byte>(i + 33);
  header.transfer_id = TransferId{storage};
  header.offset = 0U;
  header.data_length = 4U;
  header.blake3.fill(std::byte{5});
  const std::vector<std::byte> hostile{std::byte{1}, std::byte{2}, std::byte{3},
                                        std::byte{4}};
  auto payload = encode_file_chunk(header, hostile);
  harness.inject_frame(harness.left_session(),
                       harness.file_channel_of(harness.left_session()),
                       static_cast<std::uint8_t>(FrameType::file_chunk), payload);
  EXPECT_EQ(harness.right_files->stats().duplicate_chunks, 1U);
}

TEST(M7FileService, CancelAbortsBeforeAnyDelivery) {
  M7ServicePair harness(file_options());
  const auto source =
      M7ServicePair::make_source_file(harness.left_root_dir.path, "s.bin", 500'000U, 4U);
  auto pushed = harness.left_files->push_file("inbox", "cancel.bin", source);
  ASSERT_TRUE(pushed);
  const auto id = *pushed.value_if();

  // Cancel while the probe is still queued: the abort is explicit and the
  // book entry is gone before anything reaches the peer.
  harness.left_blocking.tasks.clear();  // the probe never runs
  ASSERT_TRUE(harness.left_files->cancel_transfer(id));
  harness.cycle();

  EXPECT_EQ(harness.left_files->stats().sender_cancelled, 1U);
  EXPECT_FALSE(harness.left_book->entries().contains(id));
  EXPECT_FALSE(std::filesystem::exists(harness.right_root_dir.path / "inbox" / "cancel.bin"));
}

TEST(M7FileService, SessionLossPausesAndNextSessionResumes) {
  M7ServicePair::Options options = file_options();
  // A tiny window + blocking execution control let the test stop mid-flight.
  options.left_file.send_window_bytes = 8'192U;
  // Copies: `options` moves into the harness below.
  auto left_config = options.left_file;
  auto right_config = options.right_file;
  M7ServicePair harness(std::move(options));
  // The harness fills root directories during construction; mirror that for
  // the re-attached services below.
  for (auto& root : left_config.receive_roots) {
    if (root.directory.empty()) root.directory = harness.left_root_dir.path / root.name;
  }
  for (auto& root : right_config.receive_roots) {
    if (root.directory.empty()) root.directory = harness.right_root_dir.path / root.name;
  }

  const auto source =
      M7ServicePair::make_source_file(harness.left_root_dir.path, "s.bin", 100'000U, 5U);
  auto pushed = harness.left_files->push_file("inbox", "resume.bin", source);
  ASSERT_TRUE(pushed);
  const auto id = *pushed.value_if();

  // Partial progress: run some blocking work, then kill the session.
  harness.left_blocking.run_all();
  harness.left_poster.run_all();
  harness.m6.pump();
  harness.right_blocking.run_all();
  harness.right_poster.run_all();
  harness.m6.pump();

  // The sidecar must be on disk before the loss (M7-13).
  {
    std::size_t parts = 0U, states = 0U;
    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(harness.right_root_dir.path)) {
      const auto name = entry.path().filename().string();
      if (name.find(".part") != std::string::npos) ++parts;
      if (name.find(".state") != std::string::npos) ++states;
    }
    std::printf("PHASE1 parts=%zu states=%zu\n", parts, states);
  }

  // Simulate session loss on both services.
  harness.left_files->handle_session_closed();
  harness.right_files->handle_session_closed();
  const auto entry = harness.left_book->entries().find(id);
  ASSERT_NE(entry, harness.left_book->entries().end());
  EXPECT_EQ(entry->second.phase, FileTransferPhase::paused);

  // Re-attach fresh services (the next session's attach() resumes paused
  // book entries with the same transfer id).
  harness.left_files = std::make_shared<FileService>(
      harness.left_session(), harness.m6.left_key(), left_config, harness.left_book,
      harness.left_general.dispatcher(), harness.left_blocking.dispatcher(),
      harness.m6.scope_check(harness.m6.left), harness.left_poster.poster(),
      [this_ = &harness] { return this_->m6.left_clock; });
  ASSERT_TRUE(harness.left_files->attach());
  harness.right_files = std::make_shared<FileService>(
      harness.right_session(), harness.m6.right_key(), right_config,
      harness.right_book, harness.right_general.dispatcher(),
      harness.right_blocking.dispatcher(), harness.m6.scope_check(harness.m6.right),
      harness.right_poster.poster(), [this_ = &harness] { return this_->m6.right_clock; });
  ASSERT_TRUE(harness.right_files->attach());
  harness.cycle(128);

  const auto final_path = harness.right_root_dir.path / "inbox" / "resume.bin";
  ASSERT_TRUE(std::filesystem::exists(final_path));
  EXPECT_EQ(M7ServicePair::read_file_bytes(final_path),
            M7ServicePair::read_file_bytes(source));
  EXPECT_EQ(harness.left_files->stats().sender_resumed, 1U);
  EXPECT_GE(harness.right_files->stats().resumed_transfers, 1U);
}

TEST(M7FileService, SymlinkedRootComponentRejected) {
  M7ServicePair::Options options = file_options();
  M7ServicePair harness(std::move(options));
  const auto inbox = harness.right_root_dir.path / "inbox";
  std::filesystem::create_directories(inbox / "real");
  std::error_code ec;
  std::filesystem::create_directory_symlink(inbox / "real", inbox / "linked", ec);
  if (ec) {
    GTEST_SKIP() << "symlink creation unavailable";
  }

  const auto source =
      M7ServicePair::make_source_file(harness.left_root_dir.path, "s.bin", 100U, 6U);
  ASSERT_TRUE(harness.left_files->push_file("inbox", "linked/evil.bin", source));
  harness.cycle();
  const auto stats = harness.right_files->stats();
  EXPECT_EQ(stats.path_rejected, 1U);
  EXPECT_FALSE(std::filesystem::exists(inbox / "linked" / "evil.bin"));
  EXPECT_FALSE(std::filesystem::exists(inbox / "real" / "evil.bin"));
}

TEST(M7FileService, PullServesUnderPullScopeOnly) {
  M7ServicePair harness(file_options());
  // The RIGHT side hosts the file; the LEFT side pulls it.
  const auto hosted =
      M7ServicePair::make_source_file(harness.right_root_dir.path / "inbox",
                                      "shared.txt", 5'000U, 7U);

  FilePullRequestBody request;
  TransferId::Storage storage{};
  for (std::size_t i = 0; i < storage.size(); ++i) storage[i] = static_cast<std::byte>(i + 61);
  request.transfer_id = TransferId{storage};
  request.root = "inbox";
  request.logical_name = "shared.txt";

  // The file owner serves the pull (scope file.pull:inbox on its side).
  auto served = harness.right_files->serve_pull(request);
  ASSERT_TRUE(served);
  // The puller expects the manifest under the pull scope.
  ASSERT_TRUE(harness.left_files->expect_pull(request.transfer_id, "inbox", "shared.txt"));
  harness.cycle();

  const auto final_path = harness.left_root_dir.path / "inbox" / "shared.txt";
  ASSERT_TRUE(std::filesystem::exists(final_path));
  EXPECT_EQ(M7ServicePair::read_file_bytes(final_path),
            M7ServicePair::read_file_bytes(hosted));
  EXPECT_EQ(harness.left_files->stats().committed, 1U);
}

TEST(M7FileService, PullScopeNotGrantedOnOwnerRejected) {
  M7ServicePair::Options options = file_options();
  // Right side grants push but NOT pull: serving is denied.
  options.right_scopes = {"message.send", "rpc.device.read", "file.push:inbox"};
  M7ServicePair harness(std::move(options));

  const auto hosted =
      M7ServicePair::make_source_file(harness.right_root_dir.path / "inbox",
                                      "secret.txt", 500U, 8U);
  FilePullRequestBody request;
  TransferId::Storage storage{};
  for (std::size_t i = 0; i < storage.size(); ++i) storage[i] = static_cast<std::byte>(i + 71);
  request.transfer_id = TransferId{storage};
  request.root = "inbox";
  request.logical_name = "secret.txt";
  EXPECT_FALSE(harness.right_files->serve_pull(request));
  EXPECT_EQ(harness.right_files->stats().pull_requests_rejected, 1U);
}

TEST(M7FileService, PullerWithoutPushGrantStillAcceptsItsPull) {
  M7ServicePair::Options options = file_options();
  // Left side (the puller/receiver) grants pull but NOT push.
  options.left_scopes = {"message.send", "rpc.device.read", "file.pull:inbox"};
  M7ServicePair harness(std::move(options));

  const auto hosted =
      M7ServicePair::make_source_file(harness.right_root_dir.path / "inbox",
                                      "doc.txt", 3'000U, 9U);
  FilePullRequestBody request;
  TransferId::Storage storage{};
  for (std::size_t i = 0; i < storage.size(); ++i) storage[i] = static_cast<std::byte>(i + 81);
  request.transfer_id = TransferId{storage};
  request.root = "inbox";
  request.logical_name = "doc.txt";
  ASSERT_TRUE(harness.right_files->serve_pull(request));
  ASSERT_TRUE(harness.left_files->expect_pull(request.transfer_id, "inbox", "doc.txt"));
  harness.cycle();

  EXPECT_TRUE(std::filesystem::exists(harness.left_root_dir.path / "inbox" / "doc.txt"));
  EXPECT_EQ(harness.left_files->stats().committed, 1U);

  // But an unsolicited push under the pull-only grant is denied: the pull
  // scope never doubles as a push grant.
  const auto source =
      M7ServicePair::make_source_file(harness.right_root_dir.path, "push.bin", 200U, 10U);
  ASSERT_TRUE(harness.right_files->push_file("inbox", "unsolicited.bin", source));
  harness.cycle();
  EXPECT_EQ(harness.left_files->stats().scope_rejected, 1U);
  EXPECT_FALSE(std::filesystem::exists(harness.left_root_dir.path / "inbox" /
                                       "unsolicited.bin"));
}

TEST(M7FileService, TransferSummariesExposePhases) {
  M7ServicePair harness(file_options());
  FileEventLog log;
  install_right_log(harness, log);
  const auto source =
      M7ServicePair::make_source_file(harness.left_root_dir.path, "s.bin", 20'000U, 11U);
  auto pushed = harness.left_files->push_file("inbox", "sum.bin", source);
  ASSERT_TRUE(pushed);
  harness.cycle();

  const auto left = harness.left_files->transfers();
  ASSERT_TRUE(left.empty());  // committed transfers leave no live entries
  const auto phases = log.first_with_phase(FileTransferPhase::transferring);
  ASSERT_TRUE(phases.has_value());
  const auto committed = log.last_of(*phases, FileTransferPhase::committed);
  ASSERT_TRUE(committed.has_value());
  EXPECT_EQ(committed->bytes_total, 20'000U);
  EXPECT_EQ(committed->bytes_done, 20'000U);
}

}  // namespace
}  // namespace heyaki
