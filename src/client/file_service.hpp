#pragma once

// Resumable file transfer service (M7-08..M7-15), one instance per authorized
// PeerSession, with sender-role transfer records held in a shared
// FileTransferBook that outlives sessions (M7-13: a disconnect pauses the
// transfer; the next session re-sends the manifest with the same transfer id
// and the receiver's on-disk sidecar turns FILE_ACCEPT into a resume bitmap).
//
// Roles:
//   * Sender: probe the source on the blocking I/O worker (size + streamed
//     BLAKE3), send FILE_MANIFEST, then stream bounded-window FILE_CHUNK
//     frames (bulk class; control/RPC budgets are never consumed by file
//     traffic — M7-14). FILE_COMPLETE(ok) from the receiver is the terminal
//     commit verdict.
//   * Receiver: on FILE_MANIFEST check the file.push:<root> (or file.pull:
//     <root> for a locally initiated pull) scope, root mapping, logical-name
//     safety, quotas, and policy BEFORE any byte is accepted (M7-09); stage
//     chunks into an O_NOFOLLOW temp file, verify the whole-file BLAKE3,
//     fsync, and atomically rename (M7-11).
//   * Pull rides the frozen unary-RPC surface as service "heyaki.file",
//     method "pull": the puller allocates the transfer id, the file owner
//     validates file.pull:<root> and starts a sender-role transfer back.
//
// Threading: every public method runs on the owning Node's strand. Blocking
// file I/O runs through BlockingDispatch (executor-managed blocking worker,
// M7-12); in-memory chunk hashing and resume bookkeeping run through
// ServiceDispatch; completions merge back through the StrandPoster.

#include "file_store.hpp"
#include "peer_session.hpp"
#include "service_dispatch.hpp"

#include <heyaki/file.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace heyaki {

// Scope checked on the RECEIVING end before any byte is accepted (M7-09):
// file.push:<root> for a peer-initiated push, file.pull:<root> when the data
// answers a locally initiated pull. The file owner additionally enforces
// file.pull:<root> before serving a pull request.
[[nodiscard]] std::string file_push_scope(std::string_view root);
[[nodiscard]] std::string file_pull_scope(std::string_view root);

struct FileServiceConfig {
  // Accepted receive roots; pushes/pulls into unknown roots are rejected.
  std::vector<FileRootConfig> receive_roots;
  // Per-peer cumulative received-byte quota; 0 disables the user quota.
  std::uint64_t max_peer_receive_bytes{0U};
  // Max sender-role transfers in flight toward this peer.
  std::size_t max_concurrent_sends{2U};
  // Bounded sender staging window in bytes (M7-14): chunk frames wait here
  // when the file channel is full instead of blocking other services.
  std::size_t send_window_bytes{2U * 1024U * 1024U};
  std::size_t channel_frame_capacity{256U};
  std::size_t channel_byte_capacity{8U * 1024U * 1024U};
};

// Transfer lifecycle phases/events/summaries live in the public
// <heyaki/file.hpp>.

// Sender-role records shared across sessions for one peer (M7-13). Owned by
// the Node; the FileService for each new session resumes `paused` entries by
// re-sending their manifests after attach.
class FileTransferBook {
 public:
  struct Entry {
    TransferId transfer_id;
    std::string root;
    std::string logical_name;
    std::filesystem::path source_path;
    FileTransferPhase phase{FileTransferPhase::probing};
    std::uint64_t bytes_done{0U};
    std::uint64_t bytes_total{0U};
    // Chunk indices the receiver confirmed present (resume bitmap).
    std::set<std::uint64_t> present_chunks;
  };

  [[nodiscard]] const std::map<TransferId, Entry>& entries() const noexcept {
    return entries_;
  }
  [[nodiscard]] std::map<TransferId, Entry>& mutable_entries() noexcept { return entries_; }
  [[nodiscard]] std::size_t active_sends() const noexcept;

 private:
  std::map<TransferId, Entry> entries_;
};

class FileService : public std::enable_shared_from_this<FileService> {
 public:
  // Transfer notifications leave through a function-pointer sink (the M6
  // closure-free notification pattern); the context outlives every service.
  using EventSink = void (*)(void* context, const DeviceEndpointKey& peer,
                             const FileTransferEvent& event);
  using ScopeCheck = std::function<bool(std::string_view scope)>;
  using StrandPoster = std::function<void(std::function<void()> task)>;

  FileService(PeerSession& session, DeviceEndpointKey peer, FileServiceConfig config,
              std::shared_ptr<FileTransferBook> book, ServiceDispatch dispatch,
              BlockingDispatch blocking_dispatch, ScopeCheck scope_check,
              StrandPoster poster, std::function<std::uint64_t()> wall_clock = {});
  ~FileService();

  FileService(const FileService&) = delete;
  FileService& operator=(const FileService&) = delete;

  // Opens the logical file channel, installs the domain handler, and resumes
  // every paused book transfer (re-manifest with the same transfer id).
  [[nodiscard]] Result<void> attach();

  // ---- Sender role ----
  // Starts pushing `source_path` into the peer's logical root under
  // `logical_name`. A zero `transfer_id` is assigned here; a caller-provided
  // id resumes a prior transfer on the receiver (M7-13).
  [[nodiscard]] Result<TransferId> push_file(std::string root, std::string logical_name,
                                             std::filesystem::path source_path,
                                             TransferId transfer_id = {});

  // Registers a pending pull under this transfer id (the Node sends the
  // heyaki.file/pull RPC); the incoming manifest for it is accepted under
  // the file.pull:<root> scope.
  [[nodiscard]] Result<void> expect_pull(TransferId transfer_id, std::string root,
                                         std::string logical_name);
  // Drops a pending pull whose RPC failed, surfacing one terminal failed
  // event (nothing was transferred).
  void fail_pending_pull(const TransferId& id, std::string_view safe_detail);

  // ---- Pull serving (runs on the file owner's side) ----
  // Handles a validated heyaki.file/pull request by starting a sender-role
  // transfer back to the peer. Enforces file.pull:<root> on the source root.
  [[nodiscard]] Result<TransferId> serve_pull(const FilePullRequestBody& request);

  // ---- Control ----
  [[nodiscard]] Result<void> pause_transfer(const TransferId& id);
  [[nodiscard]] Result<void> resume_transfer(const TransferId& id);
  [[nodiscard]] Result<void> cancel_transfer(const TransferId& id);

  void set_event_sink(EventSink sink, void* context);

  // Sends staged chunk frames while the channel admits them; merges finished
  // records. Safe from a periodic timer.
  void prune();

  // Session loss: sender transfers pause inside the book (resumed by the
  // next session's attach); receive transfers keep their on-disk sidecars
  // and are rebuilt from the next manifest.
  void handle_session_closed();

  [[nodiscard]] FileServiceStats stats();
  [[nodiscard]] std::vector<FileTransferSummary> transfers() const;
  [[nodiscard]] bool attached() const noexcept { return attached_; }
  // Frame entry point (also used by tests for direct injection).
  void handle_frame(const FrameView& frame);

 private:
  // Self-contained record written by executor tasks, merged on the strand.
  struct ProbeRecord {
    std::atomic<bool> done{false};
    bool ok{false};
    std::uint64_t size{};
    file_store::Digest digest{};
    std::string failure_detail;
  };
  struct ChunkReadRecord {
    std::atomic<bool> done{false};
    bool ok{false};
    std::uint64_t offset{};
    std::vector<std::byte> data;
    file_store::Digest digest{};
    std::string failure_detail;
  };

  struct SenderState {
    TransferId transfer_id;
    std::string root;
    std::string logical_name;
    std::filesystem::path source_path;
    FileManifestBody manifest;
    std::set<std::uint64_t> present_chunks;
    std::uint64_t next_read_chunk{0U};
    std::uint64_t chunk_count{0U};
    // Encoded FILE_CHUNK payloads staged between the reader and channel
    // admission (bounded by send_window_bytes — M7-14).
    std::deque<std::pair<std::uint64_t, std::vector<std::byte>>> window;
    std::uint64_t window_bytes{0U};
    std::uint64_t bytes_admitted{0U};
    bool probe_in_flight{false};
    bool read_in_flight{false};
    bool complete_sent{false};
    bool paused{false};
    bool terminal{false};
    std::shared_ptr<ProbeRecord> probe;
    std::shared_ptr<ChunkReadRecord> read;
  };

  struct PendingChunk {
    std::uint64_t offset{};
    std::vector<std::byte> data;
  };

  struct ReceiverState {
    TransferId transfer_id;
    FileManifestBody manifest;
    std::string root;  // resolved logical root name
    bool pull_initiated{false};
    std::filesystem::path temp_path;
    std::filesystem::path state_path;
    std::filesystem::path final_path;
    std::vector<std::uint8_t> chunk_bitmap;
    std::uint64_t present_count{0U};
    std::uint64_t bytes_received{0U};
    std::uint64_t chunk_count{0U};
    // Validated chunks waiting for the blocking writer (FIFO per transfer).
    std::deque<PendingChunk> write_queue;
    // Raw chunks waiting for the in-memory digest check (general CPU task).
    std::deque<PendingChunk> validate_queue;
    bool write_in_flight{false};
    bool hash_in_flight{false};
    bool verifying{false};
    bool complete_received{false};
    bool terminal{false};
    // Last accepted (offset, length, digest) for duplicate/conflict rules.
    std::map<std::uint64_t, std::pair<std::uint32_t, file_store::Digest>> accepted;
  };

  struct PendingPull {
    std::string root;
    std::string logical_name;
  };

  [[nodiscard]] std::uint64_t now() const;
  [[nodiscard]] Result<void> admit_frame(const FrameView& frame);
  void handle_inbound_manifest(const FrameView& frame);
  void handle_inbound_accept(const FrameView& frame);
  void handle_inbound_reject(const FrameView& frame);
  void handle_inbound_chunk(const FrameView& frame);
  void handle_inbound_complete(const FrameView& frame);

  void start_probe(SenderState& sender);
  void finish_probe(SenderState& sender);
  void start_next_read(SenderState& sender);
  void finish_read(SenderState& sender);
  void finish_send_hash(const TransferId& id, std::uint64_t offset,
                        std::vector<std::byte> data, const file_store::Digest& digest);
  void drain_window(SenderState& sender);

  void accept_transfer(ReceiverState& receive);
  void reject_transfer(const TransferId& id, StableStatus status,
                       std::string_view safe_detail);
  void pump_validate(ReceiverState& receive);
  void finish_chunk_hash(const TransferId& id, std::uint64_t offset,
                         std::vector<std::byte> data, const file_store::Digest& digest,
                         const file_store::Digest& expected);
  void dispatch_chunk_write(ReceiverState& receive);
  void finish_chunk_write(const TransferId& id, std::uint64_t offset, bool ok,
                          std::vector<std::uint8_t> bitmap, std::string_view detail);
  void maybe_start_verify(ReceiverState& receive);
  void start_verify(ReceiverState& receive);
  void finish_verify(const TransferId& id, bool ok, std::string_view detail);
  void complete_transfer(SenderState& sender, StableStatus status,
                         std::string_view safe_detail);
  void fail_transfer(SenderState& sender, StableStatus status, std::string_view safe_detail);
  void fail_receive(ReceiverState& receive, StableStatus status, std::string_view safe_detail);
  void cleanup_receive(ReceiverState& receive);
  void emit_event(FileTransferEvent event);
  void send_manifest(const SenderState& sender);
  void send_abort(const TransferId& id, StableStatus status, std::string_view safe_detail);
  void send_complete(const TransferId& id, StableStatus status, std::string_view safe_detail);
  [[nodiscard]] SenderState* sender_of(const TransferId& id);
  [[nodiscard]] ReceiverState* receiver_of(const TransferId& id);
  [[nodiscard]] const FileRootConfig* root_config(std::string_view root) const;

  PeerSession& session_;
  DeviceEndpointKey peer_;
  FileServiceConfig config_;
  std::shared_ptr<FileTransferBook> book_;
  ServiceDispatch dispatch_;
  BlockingDispatch blocking_dispatch_;
  ScopeCheck scope_check_;
  StrandPoster poster_;
  std::function<std::uint64_t()> wall_clock_;
  EventSink event_sink_{};
  void* event_context_{};
  std::map<TransferId, SenderState> senders_;
  std::map<TransferId, ReceiverState> receivers_;
  std::map<TransferId, PendingPull> pending_pulls_;
  std::map<std::string, std::uint64_t> peer_received_bytes_;
  FileServiceStats stats_;
  std::uint32_t channel_id_{};
  std::vector<std::uint32_t> owned_channels_;
  bool attached_{false};
};

}  // namespace heyaki
