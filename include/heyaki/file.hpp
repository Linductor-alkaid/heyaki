#pragma once

// Resumable file transfer wire bodies (M7-08..M7-15). FileManifest/
// FileAccept/FileReject/FileComplete follow the frozen heyaki.protocol.file.v1
// protobuf schemas; FileChunk is deliberately NOT protobuf — it rides a raw
// 60-byte header (wire protocol 2.1):
//
//   FileChunk := transfer_id:ID16 | offset:U64 | data_length:U32 |
//                blake3:32 bytes | data:data_length
//
// The protocol exchanges logical roots and file names only; the receiving side
// maps them through its own configured root directories and enforces quotas
// before any byte is accepted (M7-09). v1 delivers single-file push and pull
// with pause, cancel, and resume by transfer id.

#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/limits.hpp>
#include <heyaki/pairing_protocol.hpp>

#include <array>
#include <cstddef>
#include <filesystem>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace heyaki {

struct FileRootConfig {
  // Logical root name exposed on the wire ("inbox").
  std::string name;
  // Local directory the root maps to; must exist and not be a symlink.
  std::filesystem::path directory;
  // Per-file quota (checked against the manifest size before acceptance).
  std::uint64_t max_file_bytes{1024ULL * 1024ULL * 1024ULL};
  // Total quota for concurrently reserved receive transfers in this root.
  std::uint64_t max_total_bytes{8ULL * 1024ULL * 1024ULL * 1024ULL};
  // Concurrent receive transfers allowed in this root.
  std::size_t max_concurrent_receives{2U};
};

// ---- Transfer lifecycle surfaces (M7) ----

// Transfer phases surfaced through the event observer and diagnostics.
enum class FileTransferPhase : std::uint8_t {
  probing,      // sender: reading size/digest on the blocking worker
  offered,      // manifest sent / received, waiting for accept
  transferring, // chunks in flight
  verifying,    // receiver: whole-file digest + fsync + rename
  paused,       // disconnected or locally paused; resumable by transfer id
  committed,    // terminal success
  failed,       // terminal failure (the event error carries the reason)
  cancelled,    // terminal local cancellation
};

enum class FileTransferDirection : std::uint8_t {
  push,  // this side sends
  pull,  // this side receives into a root it asked to pull from
};

struct FileTransferEvent {
  TransferId transfer_id;
  FileTransferDirection direction{FileTransferDirection::push};
  FileTransferPhase phase{FileTransferPhase::probing};
  std::string root;
  std::string logical_name;
  std::uint64_t bytes_done{0U};
  std::uint64_t bytes_total{0U};
  std::optional<Error> error;
};

struct FileTransferSummary {
  TransferId transfer_id;
  FileTransferDirection direction{FileTransferDirection::push};
  FileTransferPhase phase{FileTransferPhase::probing};
  std::string root;
  std::string logical_name;
  std::uint64_t bytes_done{0U};
  std::uint64_t bytes_total{0U};
  bool sender_role{true};
};

[[nodiscard]] std::string_view file_transfer_phase_name(FileTransferPhase phase) noexcept;


inline constexpr std::size_t file_blake3_bytes = 32U;
// transfer_id(16) + offset(8) + data_length(4) + blake3(32), big-endian.
inline constexpr std::size_t file_chunk_header_bytes = 60U;
inline constexpr std::uint32_t min_file_chunk_size = 4096U;
inline constexpr std::size_t max_logical_name_bytes = 512U;
inline constexpr std::size_t max_file_name_segments = 32U;
inline constexpr std::size_t max_logical_root_name_bytes = 64U;

[[nodiscard]] std::string_view file_status_name(StableStatus status) noexcept;

struct FileManifestBody {
  TransferId transfer_id;
  std::string logical_name;
  std::uint64_t size{};
  std::vector<std::byte> blake3;  // exactly file_blake3_bytes
  std::uint32_t chunk_size{};
  bool zstd_compressed{false};
  std::optional<std::uint64_t> expanded_size;
};

[[nodiscard]] Result<std::vector<std::byte>> encode_file_manifest(
    const FileManifestBody& manifest, const Limits& limits = {});
[[nodiscard]] Result<FileManifestBody> parse_file_manifest(std::span<const std::byte> payload,
                                                           const Limits& limits = {});

// Chunk indices already present at the receiver, enabling resume by bitmap
// (M7-13). Indices are dense (chunk i covers bytes [i*chunk_size,
// min((i+1)*chunk_size, size))).
struct FileAcceptBody {
  TransferId transfer_id;
  std::vector<std::uint64_t> present_chunk_indices;
};

[[nodiscard]] Result<std::vector<std::byte>> encode_file_accept(const FileAcceptBody& accept);
[[nodiscard]] Result<FileAcceptBody> parse_file_accept(std::span<const std::byte> payload);

struct FileRejectBody {
  TransferId transfer_id;
  StableStatus status{StableStatus::unspecified};
  std::string safe_detail;
};

[[nodiscard]] Result<std::vector<std::byte>> encode_file_reject(const FileRejectBody& reject);
[[nodiscard]] Result<FileRejectBody> parse_file_reject(std::span<const std::byte> payload);

struct FileCompleteBody {
  TransferId transfer_id;
  StableStatus status{StableStatus::ok};
  std::string safe_detail;
};

[[nodiscard]] Result<std::vector<std::byte>> encode_file_complete(
    const FileCompleteBody& complete);
[[nodiscard]] Result<FileCompleteBody> parse_file_complete(std::span<const std::byte> payload);

// Raw FileChunk header (M7-11): offset/length/digest frame the data slice.
struct FileChunkHeader {
  TransferId transfer_id;
  std::uint64_t offset{};
  std::uint32_t data_length{};
  std::array<std::byte, file_blake3_bytes> blake3{};
};

// Encodes header + data into one frame payload (exactly header bytes + data).
[[nodiscard]] std::vector<std::byte> encode_file_chunk(const FileChunkHeader& header,
                                                       std::span<const std::byte> data);
// Parses a chunk payload. The returned data span aliases `payload`.
struct ParsedFileChunk {
  FileChunkHeader header;
  std::span<const std::byte> data;
};
[[nodiscard]] Result<ParsedFileChunk> parse_file_chunk(std::span<const std::byte> payload,
                                                       const Limits& limits = {});

// True when `name` is a safe logical file name: relative, non-empty, no
// absolute-path prefixes, no '..' or '.' segments, no empty segments, no
// backslashes, no control bytes, bounded depth/length, no Windows device
// names (CON/PRN/AUX/NUL/COM1-9/LPT1-9 with any extension), and no trailing
// dots or spaces in any segment (M7-10).
[[nodiscard]] bool safe_logical_file_name(std::string_view name) noexcept;

// True when `root` is a safe logical root name (single name token).
[[nodiscard]] bool safe_logical_root_name(std::string_view root) noexcept;

// Pull request body riding the frozen unary-RPC surface as service
// "heyaki.file", method "pull" (the v1 frame registry has no dedicated pull
// frame; a pull asks the file owner to start a sender-role transfer with the
// caller-provided transfer id).
struct FilePullRequestBody {
  TransferId transfer_id;
  std::string root;
  std::string logical_name;
};

[[nodiscard]] Result<std::vector<std::byte>> encode_file_pull_request(
    const FilePullRequestBody& request);
[[nodiscard]] Result<FilePullRequestBody> parse_file_pull_request(
    std::span<const std::byte> payload);

// Counters for one file service (M7-09..M7-14): every rejection, resume,
// termination, and failure mode is observable.
struct FileServiceStats {
  // Sender role.
  std::uint64_t pushes_started{};
  std::uint64_t manifests_sent{};
  std::uint64_t accepts_received{};
  std::uint64_t rejects_received{};
  std::uint64_t chunks_sent{};
  std::uint64_t chunk_send_deferred{};  // would_block: stayed in the bounded window
  std::uint64_t completes_sent{};
  std::uint64_t sender_committed{};     // receiver verdict ok
  std::uint64_t sender_failed{};
  std::uint64_t sender_cancelled{};
  std::uint64_t sender_paused{};
  std::uint64_t sender_resumed{};
  std::uint64_t read_failures{};
  std::uint64_t pull_requests_received{};
  std::uint64_t pull_requests_rejected{};
  // Receiver role.
  std::uint64_t manifests_received{};
  std::uint64_t manifests_rejected{};   // scope/quota/path/policy denials
  std::uint64_t scope_rejected{};
  std::uint64_t quota_rejected{};
  std::uint64_t path_rejected{};
  std::uint64_t policy_rejected{};      // compression unsupported, chunk size, ...
  std::uint64_t concurrency_rejected{};
  std::uint64_t accepts_sent{};
  std::uint64_t resumed_transfers{};    // accepted with a non-empty present set
  std::uint64_t chunks_received{};
  std::uint64_t duplicate_chunks{};
  std::uint64_t conflicting_chunks{};   // same offset, different bytes: transfer failed
  std::uint64_t chunk_hash_failures{};
  std::uint64_t write_failures{};
  std::uint64_t verifies_started{};
  std::uint64_t committed{};            // BLAKE3 ok, fsync, atomic rename done
  std::uint64_t commit_failures{};
  std::uint64_t receiver_cancelled{};
  std::uint64_t partial_cleanups{};     // temp/state files removed after failure
};

// Sums every counter (used by NodeServiceDiagnostics aggregation).
inline void accumulate(FileServiceStats& total, const FileServiceStats& delta) {
  total.pushes_started += delta.pushes_started;
  total.manifests_sent += delta.manifests_sent;
  total.accepts_received += delta.accepts_received;
  total.rejects_received += delta.rejects_received;
  total.chunks_sent += delta.chunks_sent;
  total.chunk_send_deferred += delta.chunk_send_deferred;
  total.completes_sent += delta.completes_sent;
  total.sender_committed += delta.sender_committed;
  total.sender_failed += delta.sender_failed;
  total.sender_cancelled += delta.sender_cancelled;
  total.sender_paused += delta.sender_paused;
  total.sender_resumed += delta.sender_resumed;
  total.read_failures += delta.read_failures;
  total.pull_requests_received += delta.pull_requests_received;
  total.pull_requests_rejected += delta.pull_requests_rejected;
  total.manifests_received += delta.manifests_received;
  total.manifests_rejected += delta.manifests_rejected;
  total.scope_rejected += delta.scope_rejected;
  total.quota_rejected += delta.quota_rejected;
  total.path_rejected += delta.path_rejected;
  total.policy_rejected += delta.policy_rejected;
  total.concurrency_rejected += delta.concurrency_rejected;
  total.accepts_sent += delta.accepts_sent;
  total.resumed_transfers += delta.resumed_transfers;
  total.chunks_received += delta.chunks_received;
  total.duplicate_chunks += delta.duplicate_chunks;
  total.conflicting_chunks += delta.conflicting_chunks;
  total.chunk_hash_failures += delta.chunk_hash_failures;
  total.write_failures += delta.write_failures;
  total.verifies_started += delta.verifies_started;
  total.committed += delta.committed;
  total.commit_failures += delta.commit_failures;
  total.receiver_cancelled += delta.receiver_cancelled;
  total.partial_cleanups += delta.partial_cleanups;
}

}  // namespace heyaki
