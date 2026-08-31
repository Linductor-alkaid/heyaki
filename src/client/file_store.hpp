#pragma once

// Safe local file storage for the M7 file-transfer receive path. The wire
// protocol only ever carries logical roots and logical names; this module
// maps them onto the filesystem with symlink-race-resistant platform APIs
// (M7-10): the root must be a real (non-symlink) directory, every created
// path component is checked against symlink substitution, the temp file is
// created with O_CREAT|O_EXCL|O_NOFOLLOW semantics, and the final commit is
// an atomic rename inside the same directory. Chunk writes are positional so
// duplicated or reordered chunks cannot corrupt unrelated ranges.
//
// All functions block; callers run them on the executor-managed blocking
// I/O worker (BlockingDispatch), never on the network strand.

#include <heyaki/error.hpp>
#include <heyaki/file.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace heyaki::file_store {

using Digest = std::array<std::byte, file_blake3_bytes>;

// In-memory BLAKE3 of a byte range (the "bounded CPU work" half of M7-12:
// hashing data that is already in memory).
[[nodiscard]] Digest blake3_bytes(std::span<const std::byte> data);

// Opens `path` with O_RDONLY|O_NOFOLLOW-equivalent semantics for reading a
// push source. Fails when the path is missing, unreadable, or not a regular
// file.
struct SourceFile {
  std::uint64_t size{};
  std::filesystem::path path;
};
[[nodiscard]] Result<SourceFile> open_source(const std::filesystem::path& path);

// Reads up to `length` bytes at `offset`; the returned vector is short only
// at end of file. Fails on partial reads at interior offsets.
[[nodiscard]] Result<std::vector<std::byte>> read_source_range(const std::filesystem::path& path,
                                                               std::uint64_t offset,
                                                               std::size_t length);

// Streams one file through BLAKE3 without loading it into memory.
[[nodiscard]] Result<Digest> blake3_file(const std::filesystem::path& path);

// A receive-side staging file plus its sidecar state, both in the final
// file's directory so the commit is an atomic rename.
struct StagingFile {
  std::filesystem::path temp_path;
  std::filesystem::path state_path;
  std::filesystem::path final_path;
};

// Resolves a logical (root directory, path-relative name) pair to a staging
// file, creating missing intermediate directories. Rejects symlinked roots
// or components, unwritable directories, and unsafe names (the codec layer
// already rejects `..`, absolute paths, NUL, and Windows device names). The
// name is relative to `root_directory`: callers strip the root-selector
// segment from the wire's logical name first.
[[nodiscard]] Result<StagingFile> create_staging(const std::filesystem::path& root_directory,
                                                 const std::string& relative_name,
                                                 std::string_view transfer_hex);

// Positional write into the staging temp file.
[[nodiscard]] Result<void> write_staging_at(const std::filesystem::path& temp_path,
                                            std::uint64_t offset,
                                            std::span<const std::byte> data);

// Final commit: fsync the temp file, atomically rename it onto the final
// path, fsync the containing directory, then remove the sidecar state file.
[[nodiscard]] Result<void> commit_staging(const StagingFile& staging);

// Removes the temp and state files of an abandoned transfer.
[[nodiscard]] Result<void> discard_staging(const StagingFile& staging);

// Sidecar persistence (M7-13): the receiver's durable resume record next to
// the temp file. `bitmap` has one byte per chunk (0/1).
struct ResumeState {
  TransferId transfer_id{};
  std::uint64_t size{};
  std::uint32_t chunk_size{};
  Digest blake3{};
  std::vector<std::uint8_t> chunk_bitmap;
};
[[nodiscard]] Result<void> write_resume_state(const std::filesystem::path& state_path,
                                              const ResumeState& state);
[[nodiscard]] Result<ResumeState> read_resume_state(const std::filesystem::path& state_path);

}  // namespace heyaki::file_store
