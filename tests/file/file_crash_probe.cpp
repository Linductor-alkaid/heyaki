// M9-08 file-service crash probe: drives one real file transfer over the
// M7 loopback pair against a fixed state directory. The crash-matrix driver
// (RunFileCrashTest.cmake) runs `push` under HEYAKI_FILE_FAULT_POINT so the
// process dies mid-transfer at a named on-disk boundary, then runs `verify`
// in a fresh process to prove the recovery contract:
//   - the final file only ever appears at/after the commit rename (no
//     partial files are observable, whatever the crash point);
//   - after a crash, a fresh transfer of the same content commits
//     byte-identical with the BLAKE3 gate, and the crashed transfer's
//     staging leftovers neither block nor poison the root.
// Same-transfer-id resume across a session loss (sender book alive) is
// covered separately by M7FileService.SessionLossPausesAndNextSessionResumes;
// this probe owns the process-death half of the contract.

#include "m7_support.hpp"
#include "file_store.hpp"

#include <cstdio>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace heyaki {
namespace {

using test::M7ServicePair;

// Deterministic three-chunk source (256 KiB chunks) shared by both modes.
constexpr std::size_t probe_source_bytes = 610'000U;
constexpr std::uint8_t probe_source_seed = 0x5BU;

int probe_fail(const std::string& message) {
  std::cerr << "PROBE_FAILURE " << message << '\n';
  return 1;
}

std::filesystem::path make_probe_source(const std::filesystem::path& state_dir) {
  return M7ServicePair::make_source_file(state_dir, "crash-source.bin",
                                         probe_source_bytes, probe_source_seed);
}

M7ServicePair::Options probe_options(const std::filesystem::path& state_dir) {
  M7ServicePair::Options options;
  const std::vector<std::string> scopes = {
      "event.subscribe:*", "file.pull:inbox", "file.push:inbox",
      "message.send",      "rpc.device.read", "stream.open"};
  options.left_scopes = scopes;
  options.right_scopes = scopes;
  FileRootConfig left_root;
  left_root.name = "inbox";
  left_root.directory = state_dir / "left-inbox";
  left_root.max_file_bytes = 64ULL * 1024ULL * 1024ULL;
  left_root.max_total_bytes = 128ULL * 1024ULL * 1024ULL;
  left_root.max_concurrent_receives = 2U;
  options.left_file.receive_roots.push_back(left_root);
  FileRootConfig right_root = left_root;
  right_root.directory = state_dir / "right-inbox";
  options.right_file.receive_roots.push_back(right_root);
  return options;
}

std::filesystem::path probe_final_path(const std::filesystem::path& state_dir) {
  return state_dir / "right-inbox" / "crash" / "report.bin";
}

std::size_t probe_leftovers(const std::filesystem::path& root) {
  std::size_t leftovers = 0U;
  std::error_code ec;
  for (const auto& entry : std::filesystem::recursive_directory_iterator(root, ec)) {
    if (ec) {
      break;
    }
    const auto name = entry.path().filename().string();
    if (name.find(".heyaki-") != std::string::npos) {
      ++leftovers;
    }
  }
  return leftovers;
}

int run_push(const std::filesystem::path& state_dir) {
  const auto source = make_probe_source(state_dir);
  // Direct file_store use: this reference is what pulls the fault-injected
  // object ahead of heyaki::client's production copy during archive
  // resolution, and doubles as a sanity check on the deterministic source.
  const auto source_digest = file_store::blake3_file(source);
  if (!source_digest) {
    return probe_fail("source digest failed");
  }
  M7ServicePair harness(probe_options(state_dir));
  auto pushed = harness.left_files->push_file("inbox", "crash/report.bin", source);
  if (!pushed) {
    return probe_fail(std::string{"push admission failed: "} +
                      std::string{pushed.error_if()->safe_detail()});
  }
  harness.cycle(256);
  // Reaching this line means the requested fault point never fired: the
  // transfer finished (or stalled) without crossing the boundary.
  const auto final_path = probe_final_path(state_dir);
  std::printf("NO_CRASH committed=%d\n",
              static_cast<int>(std::filesystem::exists(final_path)));
  return 1;
}

int run_verify(const std::filesystem::path& state_dir, const std::string& point) {
  const auto source = make_probe_source(state_dir);
  const auto final_path = probe_final_path(state_dir);
  const bool after_rename =
      point == "commit.after_rename" || point == "commit.after_cleanup";
  const bool final_before = std::filesystem::exists(final_path);
  if (after_rename && !final_before) {
    return probe_fail("final file missing after a post-rename crash point: " + point);
  }
  if (!after_rename && final_before) {
    return probe_fail("final file observable before the rename crash point: " + point);
  }
  if (final_before) {
    // A crash after the rename may only leave the fully committed file.
    const auto committed = M7ServicePair::read_file_bytes(final_path);
    const auto expected = M7ServicePair::read_file_bytes(source);
    if (committed != expected) {
      return probe_fail("final file content mismatch after post-rename crash: " + point);
    }
  }
  const auto leftovers_before = probe_leftovers(state_dir / "right-inbox");

  // Recovery in a fresh process: the same content must commit again, and the
  // crashed transfer's staging must not block or corrupt the new one.
  M7ServicePair harness(probe_options(state_dir));
  auto pushed = harness.left_files->push_file("inbox", "crash/report.bin", source);
  if (!pushed) {
    return probe_fail(std::string{"recovery push failed: "} +
                      std::string{pushed.error_if()->safe_detail()});
  }
  harness.cycle(256);
  if (!std::filesystem::exists(final_path)) {
    return probe_fail("recovery push did not commit after crash at: " + point);
  }
  const auto recovered = M7ServicePair::read_file_bytes(final_path);
  const auto expected = M7ServicePair::read_file_bytes(source);
  if (recovered != expected) {
    return probe_fail("recovered file content mismatch after crash at: " + point);
  }
  const auto leftovers_after = probe_leftovers(state_dir / "right-inbox");
  if (leftovers_after != leftovers_before) {
    // The new transfer cleans its own staging at commit; a change means the
    // fresh run either leaked its own sidecars or disturbed the old ones.
    return probe_fail("leftover count changed across recovery: before=" +
                      std::to_string(leftovers_before) + " after=" +
                      std::to_string(leftovers_after) + " point=" + point);
  }
  std::printf("VERIFY_OK point=%s committed=1 leftovers=%zu\n", point.c_str(),
              leftovers_after);
  return 0;
}

}  // namespace
}  // namespace heyaki

int main(int argc, char** argv) {
  using namespace heyaki;
  if (argc == 3 && std::string_view{argv[1]} == "push") {
    return run_push(std::filesystem::path{argv[2]});
  }
  if (argc == 4 && std::string_view{argv[1]} == "verify") {
    return run_verify(std::filesystem::path{argv[2]}, std::string{argv[3]});
  }
  std::cerr << "usage: file_crash_probe push STATE_DIR\n"
            << "       file_crash_probe verify STATE_DIR POINT\n";
  return 2;
}
