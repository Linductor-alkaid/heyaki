#include "file_service.hpp"

#include <sodium.h>

#include <algorithm>
#include <utility>

namespace heyaki {
namespace {

Error file_service_error(ErrorCode code, std::string_view detail) {
  return Error{code, "file", std::string{detail}};
}

std::string transfer_hex(const TransferId& id) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string text;
  text.reserve(id.size_bytes * 2U);
  for (const auto value : id.bytes()) {
    const auto bits = static_cast<unsigned char>(value);
    text.push_back(digits[bits >> 4U]);
    text.push_back(digits[bits & 0x0FU]);
  }
  return text;
}

TransferId random_transfer_id() {
  TransferId::Storage bytes{};
  do {
    randombytes_buf(bytes.data(), bytes.size());
  } while (TransferId{bytes}.is_zero());
  return TransferId{bytes};
}

// The frozen manifest schema has no separate root field: the first logical
// name segment selects the receiver's configured root (M7-09).
std::string_view root_segment_of(std::string_view logical_name) noexcept {
  const auto slash = logical_name.find('/');
  return slash == std::string_view::npos ? logical_name : logical_name.substr(0U, slash);
}

std::string join_logical_name(std::string_view root, std::string_view name) {
  std::string joined;
  joined.reserve(root.size() + name.size() + 1U);
  joined.append(root);
  joined.push_back('/');
  joined.append(name);
  return joined;
}

std::uint64_t chunk_count_of(std::uint64_t size, std::uint32_t chunk_size) noexcept {
  return (size + chunk_size - 1ULL) / chunk_size;
}

// The pinned libjuice/usrsctp line empirically caps a single SCTP user
// message at 65535 bytes regardless of the SDP-advertised max-message-size
// (M7 e2e: a 65536-byte frame entered the send queue but never arrived). Chunk
// frames therefore stay under that bound even when the transport reports a
// larger limit; a transport with honest limit reporting tightens this
// through the session's negotiated max_message_bytes anyway.
constexpr std::uint64_t kEmpiricalSctpMessageCap = 60U * 1024U;

}  // namespace

std::string file_push_scope(std::string_view root) {
  std::string scope{"file.push:"};
  scope.append(root);
  return scope;
}

std::string file_pull_scope(std::string_view root) {
  std::string scope{"file.pull:"};
  scope.append(root);
  return scope;
}

std::size_t FileTransferBook::active_sends() const noexcept {
  std::size_t active = 0U;
  for (const auto& [id, entry] : entries_) {
    if (entry.phase != FileTransferPhase::committed &&
        entry.phase != FileTransferPhase::failed &&
        entry.phase != FileTransferPhase::cancelled) {
      ++active;
    }
  }
  return active;
}

FileService::FileService(PeerSession& session, DeviceEndpointKey peer,
                         FileServiceConfig config, std::shared_ptr<FileTransferBook> book,
                         ServiceDispatch dispatch, BlockingDispatch blocking_dispatch,
                         ScopeCheck scope_check, StrandPoster poster,
                         std::function<std::uint64_t()> wall_clock)
    : session_(session),
      peer_(std::move(peer)),
      config_(std::move(config)),
      book_(std::move(book)),
      dispatch_(std::move(dispatch)),
      blocking_dispatch_(std::move(blocking_dispatch)),
      scope_check_(std::move(scope_check)),
      poster_(std::move(poster)),
      wall_clock_(std::move(wall_clock)) {
  if (!book_) {
    book_ = std::make_shared<FileTransferBook>();
  }
}

FileService::~FileService() {
  session_.set_domain_handler(session::ChannelDomain::file, DomainFrameHandler{});
  for (const auto channel : owned_channels_) {
    session_.close_business_channel(channel);
  }
}

std::uint64_t FileService::now() const {
  if (wall_clock_) return wall_clock_();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

Result<void> FileService::attach() {
  if (attached_) {
    return Result<void>::success();
  }
  if (config_.send_window_bytes == 0U || config_.max_concurrent_sends == 0U ||
      config_.channel_frame_capacity == 0U || config_.channel_byte_capacity == 0U) {
    return Result<void>::failure(
        file_service_error(ErrorCode::configuration, "file_config_invalid"));
  }
  for (const auto& root : config_.receive_roots) {
    if (!safe_logical_root_name(root.name) || root.directory.empty()) {
      return Result<void>::failure(
          file_service_error(ErrorCode::configuration, "file_root_invalid"));
    }
  }
  if (!dispatch_ || !blocking_dispatch_ || !poster_) {
    return Result<void>::failure(
        file_service_error(ErrorCode::configuration, "dispatch_missing"));
  }
  auto weak = weak_from_this();
  auto opened = session_.open_business_channel(
      session::ChannelDomain::file, session::QueueFullPolicy::reject,
      config_.channel_frame_capacity, config_.channel_byte_capacity,
      [weak](const FrameView& frame) {
        if (auto self = weak.lock()) self->handle_frame(frame);
      });
  if (!opened) return Result<void>::failure(*opened.error_if());
  channel_id_ = *opened.value_if();
  owned_channels_.push_back(channel_id_);
  session_.set_domain_handler(
      session::ChannelDomain::file,
      [weak](const FrameView& frame) -> Result<void> {
        auto self = weak.lock();
        if (!self) {
          return Result<void>::failure(
              file_service_error(ErrorCode::cancelled, "service_detached"));
        }
        return self->admit_frame(frame);
      });
  attached_ = true;

  // Resume every paused book transfer on this fresh session (M7-13): the
  // same transfer id re-manifests and the receiver's sidecar answers with
  // the resume bitmap. Frames from the retired session cannot reach this
  // one (wire protocol 2.2 old-epoch exclusion).
  std::vector<TransferId> paused_ids;
  for (const auto& [id, entry] : book_->entries()) {
    if (entry.phase == FileTransferPhase::paused) {
      paused_ids.push_back(id);
    }
  }
  for (const auto& id : paused_ids) {
    const auto entry = book_->entries().at(id);
    SenderState sender;
    sender.transfer_id = entry.transfer_id;
    sender.root = entry.root;
    sender.logical_name = entry.logical_name;
    sender.source_path = entry.source_path;
    sender.present_chunks = entry.present_chunks;
    senders_[id] = std::move(sender);
    book_->mutable_entries()[id].phase = FileTransferPhase::probing;
    ++stats_.sender_resumed;
    emit_event({id, FileTransferDirection::push, FileTransferPhase::probing, entry.root,
                entry.logical_name, entry.bytes_done, entry.bytes_total, std::nullopt});
    start_probe(senders_[id]);
  }
  return Result<void>::success();
}

Result<TransferId> FileService::push_file(std::string root, std::string logical_name,
                                          std::filesystem::path source_path,
                                          TransferId transfer_id) {
  if (!attached_) {
    return Result<TransferId>::failure(
        file_service_error(ErrorCode::configuration, "service_not_attached"));
  }
  if (!safe_logical_root_name(root) || !safe_logical_file_name(logical_name)) {
    return Result<TransferId>::failure(
        file_service_error(ErrorCode::protocol, "logical_name_invalid"));
  }
  if (book_->active_sends() >= config_.max_concurrent_sends) {
    return Result<TransferId>::failure(
        file_service_error(ErrorCode::resource_exhausted, "send_concurrency_limit"));
  }
  if (transfer_id.is_zero()) {
    transfer_id = random_transfer_id();
  } else if (senders_.contains(transfer_id) || book_->entries().contains(transfer_id)) {
    return Result<TransferId>::failure(
        file_service_error(ErrorCode::protocol, "transfer_id_in_use"));
  }
  SenderState sender;
  sender.transfer_id = transfer_id;
  sender.root = std::move(root);
  sender.logical_name = std::move(logical_name);
  sender.source_path = std::move(source_path);
  senders_[transfer_id] = std::move(sender);
  FileTransferBook::Entry entry;
  entry.transfer_id = transfer_id;
  entry.root = senders_[transfer_id].root;
  entry.logical_name = senders_[transfer_id].logical_name;
  entry.source_path = senders_[transfer_id].source_path;
  entry.phase = FileTransferPhase::probing;
  book_->mutable_entries()[transfer_id] = std::move(entry);
  ++stats_.pushes_started;
  emit_event({transfer_id, FileTransferDirection::push, FileTransferPhase::probing,
              senders_[transfer_id].root, senders_[transfer_id].logical_name, 0U, 0U,
              std::nullopt});
  start_probe(senders_[transfer_id]);
  return Result<TransferId>::success(transfer_id);
}

Result<void> FileService::expect_pull(TransferId transfer_id, std::string root,
                                      std::string logical_name) {
  if (!attached_) {
    return Result<void>::failure(
        file_service_error(ErrorCode::configuration, "service_not_attached"));
  }
  if (transfer_id.is_zero() || !safe_logical_root_name(root) ||
      !safe_logical_file_name(logical_name)) {
    return Result<void>::failure(file_service_error(ErrorCode::protocol, "pull_fields_invalid"));
  }
  pending_pulls_[transfer_id] = PendingPull{std::move(root), std::move(logical_name)};
  return Result<void>::success();
}

void FileService::fail_pending_pull(const TransferId& id, std::string_view safe_detail) {
  const auto pending = pending_pulls_.find(id);
  if (pending == pending_pulls_.end()) {
    return;
  }
  PendingPull pull = pending->second;
  pending_pulls_.erase(pending);
  emit_event({id, FileTransferDirection::pull, FileTransferPhase::failed, pull.root,
              pull.logical_name, 0U, 0U,
              Error{ErrorCode::remote_error, "file", std::string{safe_detail}}});
}

Result<TransferId> FileService::serve_pull(const FilePullRequestBody& request) {
  if (!attached_) {
    return Result<TransferId>::failure(
        file_service_error(ErrorCode::configuration, "service_not_attached"));
  }
  ++stats_.pull_requests_received;
  // The file owner enforces file.pull:<root> on the SOURCE root before
  // anything is read (M7-09): a puller may only read roots it was granted.
  if (!scope_check_ || !scope_check_(file_pull_scope(request.root))) {
    ++stats_.pull_requests_rejected;
    ++stats_.scope_rejected;
    return Result<TransferId>::failure(
        file_service_error(ErrorCode::permission, "pull_scope_denied"));
  }
  if (root_config(request.root) == nullptr) {
    ++stats_.pull_requests_rejected;
    return Result<TransferId>::failure(file_service_error(ErrorCode::peer_offline, "root_unknown"));
  }
  const std::filesystem::path source =
      root_config(request.root)->directory / std::filesystem::path{request.logical_name};
  auto pushed = push_file(request.root, request.logical_name, source, request.transfer_id);
  if (!pushed) {
    ++stats_.pull_requests_rejected;
    return Result<TransferId>::failure(*pushed.error_if());
  }
  return pushed;
}

Result<void> FileService::pause_transfer(const TransferId& id) {
  if (auto* sender = sender_of(id)) {
    if (sender->terminal) {
      return Result<void>::failure(
          file_service_error(ErrorCode::protocol, "transfer_terminal"));
    }
    sender->paused = true;
    ++stats_.sender_paused;
    auto entry = book_->mutable_entries().find(id);
    if (entry != book_->mutable_entries().end()) {
      entry->second.phase = FileTransferPhase::paused;
      entry->second.bytes_done = sender->bytes_admitted;
      entry->second.present_chunks = sender->present_chunks;
    }
    emit_event({id, FileTransferDirection::push, FileTransferPhase::paused, sender->root,
                sender->logical_name, sender->bytes_admitted, sender->manifest.size,
                std::nullopt});
    return Result<void>::success();
  }
  return Result<void>::failure(file_service_error(ErrorCode::peer_offline, "transfer_unknown"));
}

Result<void> FileService::resume_transfer(const TransferId& id) {
  auto* sender = sender_of(id);
  if (sender == nullptr) {
    return Result<void>::failure(file_service_error(ErrorCode::peer_offline, "transfer_unknown"));
  }
  if (sender->terminal) {
    return Result<void>::failure(
        file_service_error(ErrorCode::protocol, "transfer_terminal"));
  }
  if (!sender->paused) {
    return Result<void>::success();
  }
  sender->paused = false;
  ++stats_.sender_resumed;
  auto entry = book_->mutable_entries().find(id);
  if (entry != book_->mutable_entries().end()) {
    entry->second.phase = FileTransferPhase::transferring;
  }
  emit_event({id, FileTransferDirection::push, FileTransferPhase::transferring,
              sender->root, sender->logical_name, sender->bytes_admitted,
              sender->manifest.size, std::nullopt});
  drain_window(*sender);
  start_next_read(*sender);
  return Result<void>::success();
}

Result<void> FileService::cancel_transfer(const TransferId& id) {
  if (auto* sender = sender_of(id)) {
    if (!sender->terminal) {
      send_abort(id, StableStatus::cancelled, "local_cancel");
      sender->terminal = true;
      ++stats_.sender_cancelled;
      book_->mutable_entries().erase(id);
      emit_event({id, FileTransferDirection::push, FileTransferPhase::cancelled, sender->root,
                  sender->logical_name, sender->bytes_admitted, sender->manifest.size,
                  std::nullopt});
    }
    senders_.erase(id);
    return Result<void>::success();
  }
  if (auto* receive = receiver_of(id)) {
    if (!receive->terminal) {
      receive->terminal = true;
      ++stats_.receiver_cancelled;
      cleanup_receive(*receive);
      emit_event({id, FileTransferDirection::pull, FileTransferPhase::cancelled,
                  receive->root, receive->manifest.logical_name, receive->bytes_received,
                  receive->manifest.size, std::nullopt});
    }
    receivers_.erase(id);
    return Result<void>::success();
  }
  return Result<void>::failure(file_service_error(ErrorCode::peer_offline, "transfer_unknown"));
}

void FileService::set_event_sink(EventSink sink, void* context) {
  event_sink_ = sink;
  event_context_ = context;
}

void FileService::prune() {
  for (auto& [id, sender] : senders_) {
    if (!sender.terminal && !sender.paused) {
      drain_window(sender);
      start_next_read(sender);
    }
  }
}

void FileService::handle_session_closed() {
  // Sender role: park in-flight transfers in the book as paused; the next
  // session's attach() re-manifests them with the same transfer id.
  for (auto& [id, sender] : senders_) {
    if (sender.terminal) {
      continue;
    }
    auto entry = book_->mutable_entries().find(id);
    if (entry != book_->mutable_entries().end()) {
      entry->second.phase = FileTransferPhase::paused;
      entry->second.present_chunks = sender.present_chunks;
      entry->second.bytes_done = sender.bytes_admitted;
    }
    emit_event({id, FileTransferDirection::push, FileTransferPhase::paused, sender.root,
                sender.logical_name, sender.bytes_admitted, sender.manifest.size,
                Error{ErrorCode::transport, "file", "session_closed"}});
  }
  senders_.clear();
  // Receiver role: the on-disk sidecars survive (M7-13); the in-memory
  // states are rebuilt from the next manifest with the same transfer id.
  receivers_.clear();
  pending_pulls_.clear();
}

void FileService::handle_frame(const FrameView& frame) {
  (void)admit_frame(frame);
}

Result<void> FileService::admit_frame(const FrameView& frame) {
  if (!attached_) {
    return Result<void>::failure(
        file_service_error(ErrorCode::configuration, "service_not_attached"));
  }
  const std::uint8_t type = frame.type;
  if (type == static_cast<std::uint8_t>(FrameType::file_manifest) ||
      type == static_cast<std::uint8_t>(FrameType::file_chunk)) {
    if (!session_.has_business_channel(frame.channel_id)) {
      auto weak = weak_from_this();
      auto adopted = session_.adopt_business_channel(
          frame.channel_id, session::ChannelDomain::file,
          session::QueueFullPolicy::reject, config_.channel_frame_capacity,
          config_.channel_byte_capacity,
          [weak](const FrameView& inbound) {
            if (auto self = weak.lock()) self->handle_frame(inbound);
          });
      if (!adopted) return Result<void>::failure(*adopted.error_if());
      owned_channels_.push_back(*adopted.value_if());
    }
  }
  if (type == static_cast<std::uint8_t>(FrameType::file_manifest)) {
    handle_inbound_manifest(frame);
    return Result<void>::success();
  }
  if (type == static_cast<std::uint8_t>(FrameType::file_accept)) {
    handle_inbound_accept(frame);
    return Result<void>::success();
  }
  if (type == static_cast<std::uint8_t>(FrameType::file_reject)) {
    handle_inbound_reject(frame);
    return Result<void>::success();
  }
  if (type == static_cast<std::uint8_t>(FrameType::file_chunk)) {
    handle_inbound_chunk(frame);
    return Result<void>::success();
  }
  if (type == static_cast<std::uint8_t>(FrameType::file_complete)) {
    handle_inbound_complete(frame);
    return Result<void>::success();
  }
  return Result<void>::failure(
      file_service_error(ErrorCode::protocol, "file_domain_frame_unknown"));
}

// ---- Sender role ----

void FileService::start_probe(SenderState& sender) {
  if (sender.probe_in_flight || sender.terminal) {
    return;
  }
  sender.probe_in_flight = true;
  sender.probe = std::make_shared<ProbeRecord>();
  auto weak = weak_from_this();
  const auto id = sender.transfer_id;
  const auto path = sender.source_path;
  // Co-owned for the same teardown-while-queued reason as the read record.
  auto record = sender.probe;
  const auto dispatched = blocking_dispatch_(
      "heyaki-file-probe", [weak, id, path, record](executor::StopToken stop) {
        bool ok = false;
        std::uint64_t size = 0U;
        file_store::Digest digest{};
        std::string detail;
        if (stop.stop_requested()) {
          detail = "probe_cancelled";
        } else if (auto source = file_store::open_source(path)) {
          size = source.value_if()->size;
          if (stop.stop_requested()) {
            detail = "probe_cancelled";
          } else if (auto hashed = file_store::blake3_file(path)) {
            digest = *hashed.value_if();
            ok = true;
          } else {
            detail = "probe_read_failed";
          }
        } else {
          detail = "source_open_failed";
        }
        record->size = size;
        record->digest = digest;
        record->failure_detail = std::move(detail);
        record->ok = ok;
        record->done.store(true, std::memory_order_release);
        if (auto self = weak.lock()) {
          self->poster_([weak, id]() {
            if (auto inner = weak.lock()) {
              if (auto* sender = inner->sender_of(id)) {
                inner->finish_probe(*sender);
              }
            }
          });
        }
      });
  if (!dispatched) {
    sender.probe_in_flight = false;
    sender.probe.reset();
    ++stats_.read_failures;
    fail_transfer(sender, StableStatus::resource_exhausted, "probe_dispatch_rejected");
  }
}

void FileService::finish_probe(SenderState& sender) {
  if (!sender.probe_in_flight || sender.terminal) {
    return;
  }
  sender.probe_in_flight = false;
  if (!sender.probe->done.load(std::memory_order_acquire)) {
    return;
  }
  if (!sender.probe->ok) {
    sender.probe.reset();
    ++stats_.read_failures;
    fail_transfer(sender, StableStatus::not_found, "probe_failed");
    return;
  }
  sender.manifest.transfer_id = sender.transfer_id;
  // Logical name on the wire is "<root>/<name>" (the receiver resolves the
  // root from the first segment).
  sender.manifest.logical_name = join_logical_name(sender.root, sender.logical_name);
  sender.manifest.size = sender.probe->size;
  sender.manifest.blake3.assign(sender.probe->digest.begin(), sender.probe->digest.end());
  const auto limits = session_.channels().limits();
  // Chunk frames (60-byte header + data) must fit the NEGOTIATED transport
  // message size, not just the configured request (M7-08: negotiated chunk
  // sizing). Falls back to the frame limit before the channel exists.
  const std::uint64_t transport_cap =
      std::min<std::uint64_t>(session_.max_message_bytes(session::ChannelDomain::file),
                              kEmpiricalSctpMessageCap) -
      file_chunk_header_bytes;
  const std::uint64_t bounded = std::min<std::uint64_t>(
      std::min<std::uint64_t>(limits.max_file_chunk_bytes, transport_cap),
      std::max<std::uint64_t>(min_file_chunk_size, sender.probe->size));
  if (bounded < min_file_chunk_size) {
    sender.probe.reset();
    fail_transfer(sender, StableStatus::failed_precondition, "chunk_size_unusable");
    return;
  }
  sender.manifest.chunk_size = static_cast<std::uint32_t>(bounded);
  sender.manifest.zstd_compressed = false;
  sender.chunk_count = chunk_count_of(sender.manifest.size, sender.manifest.chunk_size);
  sender.probe.reset();
  send_manifest(sender);
}

void FileService::send_manifest(const SenderState& sender) {
  auto encoded = encode_file_manifest(sender.manifest, session_.channels().limits());
  if (!encoded) {
    fail_transfer(const_cast<SenderState&>(sender), StableStatus::internal,
                  "manifest_encode_failed");
    return;
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::file_manifest);
  frame.channel_id = channel_id_;
  frame.payload = std::move(*encoded.value_if());
  if (!session_.send_frame(channel_id_, session::FrameClass::standard, std::move(frame))) {
    fail_transfer(const_cast<SenderState&>(sender), StableStatus::unavailable,
                  "manifest_send_failed");
    return;
  }
  ++stats_.manifests_sent;
  auto entry = book_->mutable_entries().find(sender.transfer_id);
  if (entry != book_->mutable_entries().end()) {
    entry->second.phase = FileTransferPhase::offered;
    entry->second.bytes_total = sender.manifest.size;
  }
  emit_event({sender.transfer_id, FileTransferDirection::push, FileTransferPhase::offered,
              sender.root, sender.logical_name, 0U, sender.manifest.size, std::nullopt});
}

void FileService::handle_inbound_accept(const FrameView& frame) {
  auto parsed = parse_file_accept(frame.payload);
  if (!parsed) {
    session_.fail_business_channel(frame.channel_id,
                                   transport::CloseReason::protocol_error);
    return;
  }
  const auto& body = *parsed.value_if();
  auto* sender = sender_of(body.transfer_id);
  if (sender == nullptr || sender->terminal) {
    // Terminal replay after commit: ignored and counted (wire 6.3).
    ++stats_.accepts_received;
    return;
  }
  ++stats_.accepts_received;
  for (const auto index : body.present_chunk_indices) {
    if (index >= sender->chunk_count) {
      fail_transfer(*sender, StableStatus::protocol_error, "accept_index_invalid");
      return;
    }
  }
  sender->present_chunks.clear();
  sender->present_chunks.insert(body.present_chunk_indices.begin(),
                                body.present_chunk_indices.end());
  auto entry = book_->mutable_entries().find(sender->transfer_id);
  if (entry != book_->mutable_entries().end()) {
    entry->second.phase = FileTransferPhase::transferring;
    entry->second.present_chunks = sender->present_chunks;
  }
  emit_event({sender->transfer_id, FileTransferDirection::push,
              FileTransferPhase::transferring, sender->root, sender->logical_name,
              sender->bytes_admitted, sender->manifest.size, std::nullopt});
  start_next_read(*sender);
}

void FileService::start_next_read(SenderState& sender) {
  if (sender.terminal || sender.paused || sender.read_in_flight ||
      sender.probe_in_flight || sender.manifest.size == 0U) {
    return;
  }
  const auto chunk_size = sender.manifest.chunk_size;
  while (sender.next_read_chunk < sender.chunk_count &&
         sender.present_chunks.contains(sender.next_read_chunk)) {
    // The receiver already has this chunk (resume bitmap): skip it.
    ++sender.next_read_chunk;
  }
  if (sender.next_read_chunk >= sender.chunk_count) {
    drain_window(sender);
    return;
  }
  const auto index = sender.next_read_chunk;
  const auto offset = index * chunk_size;
  const auto length = static_cast<std::size_t>(
      std::min<std::uint64_t>(chunk_size, sender.manifest.size - offset));
  if (sender.window_bytes + length > config_.send_window_bytes &&
      !sender.window.empty()) {
    // Bounded window is full (M7-14): the reader waits for the channel to
    // drain instead of buffering the whole file.
    return;
  }
  sender.read_in_flight = true;
  sender.read = std::make_shared<ChunkReadRecord>();
  auto weak = weak_from_this();
  const auto id = sender.transfer_id;
  const auto path = sender.source_path;
  // Co-own the record: the sender may be torn down (session loss, cancel)
  // while this task sits queued; the copy keeps the handoff valid and the
  // strand drops its own reference after merging.
  auto record = sender.read;
  const auto dispatched = blocking_dispatch_(
      "heyaki-file-read", [weak, id, path, offset, length, record](executor::StopToken stop) {
        std::vector<std::byte> data;
        bool ok = false;
        std::string detail;
        if (stop.stop_requested()) {
          detail = "read_cancelled";
        } else if (auto read = file_store::read_source_range(path, offset, length)) {
          data = std::move(*read.value_if());
          if (data.size() == length) {
            ok = true;
          } else {
            detail = "read_short";
          }
        } else {
          detail = "read_failed";
        }
        record->data = std::move(data);
        record->failure_detail = std::move(detail);
        record->ok = ok;
        record->done.store(true, std::memory_order_release);
        if (auto self = weak.lock()) {
          self->poster_([weak, id]() {
            if (auto inner = weak.lock()) {
              if (auto* sender = inner->sender_of(id)) {
                inner->finish_read(*sender);
              }
            }
          });
        }
      });
  if (!dispatched) {
    sender.read_in_flight = false;
    sender.read.reset();
    ++stats_.read_failures;
    fail_transfer(sender, StableStatus::resource_exhausted, "read_dispatch_rejected");
  }
}

void FileService::finish_read(SenderState& sender) {
  if (!sender.read_in_flight || sender.terminal) {
    return;
  }
  if (!sender.read->done.load(std::memory_order_acquire)) {
    return;
  }
  auto data = std::move(sender.read->data);
  const bool ok = sender.read->ok;
  const auto offset = sender.next_read_chunk * sender.manifest.chunk_size;
  const auto length = static_cast<std::uint32_t>(
      std::min<std::uint64_t>(sender.manifest.chunk_size,
                              sender.manifest.size - offset));
  sender.read.reset();
  sender.read_in_flight = false;
  if (!ok || data.size() != length) {
    ++stats_.read_failures;
    fail_transfer(sender, StableStatus::unavailable, "read_failed");
    return;
  }
  // Chunk digest on an ordinary executor task (M7-12: bounded CPU work off
  // the network strand), merged back through the poster.
  auto weak = weak_from_this();
  const auto id = sender.transfer_id;
  const auto index = sender.next_read_chunk;
  ++sender.next_read_chunk;
  const auto moved = std::make_shared<std::vector<std::byte>>(std::move(data));
  auto dispatched = dispatch_(
      "heyaki-file-chunk-hash",
      [weak, id, offset, moved]() {
        const auto digest = file_store::blake3_bytes(*moved);
        if (auto self = weak.lock()) {
          self->poster_([weak, id, offset, digest, moved]() {
            if (auto inner = weak.lock()) {
              inner->finish_send_hash(id, offset, std::move(*moved), digest);
            }
          });
        }
      });
  if (!dispatched) {
    ++stats_.read_failures;
    fail_transfer(sender, StableStatus::resource_exhausted, "hash_dispatch_rejected");
    return;
  }
  (void)index;
}

void FileService::finish_send_hash(const TransferId& id, std::uint64_t offset,
                                   std::vector<std::byte> data,
                                   const file_store::Digest& digest) {
  auto* sender = sender_of(id);
  if (sender == nullptr || sender->terminal) {
    return;
  }
  FileChunkHeader header;
  header.transfer_id = id;
  header.offset = offset;
  header.data_length = static_cast<std::uint32_t>(data.size());
  header.blake3 = digest;
  auto payload = encode_file_chunk(header, data);
  const std::uint64_t data_bytes = data.size();
  sender->window.emplace_back(offset, std::move(payload));
  sender->window_bytes += data_bytes + file_chunk_header_bytes;
  drain_window(*sender);
  start_next_read(*sender);
}

void FileService::drain_window(SenderState& sender) {
  while (!sender.window.empty()) {
    auto& entry = sender.window.front();
    Frame frame;
    frame.type = static_cast<std::uint8_t>(FrameType::file_chunk);
    frame.channel_id = channel_id_;
    frame.payload = entry.second;  // copied until admission
    const auto data_bytes = entry.second.size() > file_chunk_header_bytes
                                ? entry.second.size() - file_chunk_header_bytes
                                : 0U;
    const auto sent = session_.send_frame(channel_id_, session::FrameClass::bulk,
                                          std::move(frame));
    if (!sent) {
      // Channel queue full (would_block): the chunk stays staged in the
      // bounded window; prune() retries. Control/RPC frames keep their own
      // classes and budgets, so file backpressure never blocks them
      // (M7-14).
      ++stats_.chunk_send_deferred;
      return;
    }
    sender.window.pop_front();
    sender.window_bytes -= data_bytes + file_chunk_header_bytes;
    sender.bytes_admitted += data_bytes;
    ++stats_.chunks_sent;
  }
  if (sender.next_read_chunk >= sender.chunk_count && !sender.complete_sent &&
      !sender.terminal) {
    // Every chunk is admitted into the transport queue: the receiver's
    // FILE_COMPLETE verdict is the terminal commit answer.
    sender.complete_sent = true;
    send_complete(sender.transfer_id, StableStatus::ok, "");
    ++stats_.completes_sent;
    auto entry = book_->mutable_entries().find(sender.transfer_id);
    if (entry != book_->mutable_entries().end()) {
      entry->second.bytes_done = sender.bytes_admitted;
    }
    emit_event({sender.transfer_id, FileTransferDirection::push,
                FileTransferPhase::verifying, sender.root, sender.logical_name,
                sender.bytes_admitted, sender.manifest.size, std::nullopt});
  }
}

void FileService::handle_inbound_reject(const FrameView& frame) {
  auto parsed = parse_file_reject(frame.payload);
  if (!parsed) {
    session_.fail_business_channel(frame.channel_id,
                                   transport::CloseReason::protocol_error);
    return;
  }
  const auto& body = *parsed.value_if();
  ++stats_.rejects_received;
  if (auto* sender = sender_of(body.transfer_id)) {
    if (sender->terminal) {
      return;
    }
    if (body.status == StableStatus::cancelled) {
      sender->terminal = true;
      ++stats_.sender_cancelled;
      book_->mutable_entries().erase(body.transfer_id);
      emit_event({body.transfer_id, FileTransferDirection::push,
                  FileTransferPhase::cancelled, sender->root, sender->logical_name,
                  sender->bytes_admitted, sender->manifest.size,
                  Error{ErrorCode::cancelled, "file", body.safe_detail}});
      senders_.erase(body.transfer_id);
    } else {
      fail_transfer(*sender, body.status, "peer_rejected");
    }
    return;
  }
  if (auto* receive = receiver_of(body.transfer_id)) {
    // Sender-side abort of an in-flight transfer: explicit terminal; the
    // staged bytes are cleaned per policy.
    if (receive->terminal) {
      return;
    }
    fail_receive(*receive, body.status, "peer_aborted");
    return;
  }
  if (pending_pulls_.contains(body.transfer_id)) {
    // The file owner refused to serve the pull (scope/policy); nothing was
    // transferred.
    fail_pending_pull(body.transfer_id, "pull_refused");
  }
}

void FileService::handle_inbound_complete(const FrameView& frame) {
  auto parsed = parse_file_complete(frame.payload);
  if (!parsed) {
    session_.fail_business_channel(frame.channel_id,
                                   transport::CloseReason::protocol_error);
    return;
  }
  const auto& body = *parsed.value_if();
  if (auto* sender = sender_of(body.transfer_id)) {
    // Receiver's terminal verdict for a push this side started.
    if (sender->terminal) {
      return;
    }
    complete_transfer(*sender, body.status, body.safe_detail);
    return;
  }
  auto* receive = receiver_of(body.transfer_id);
  if (receive == nullptr || receive->terminal) {
    // Terminal replay after commit: ignored and counted (wire 6.3).
    return;
  }
  if (receive->verifying) {
    return;
  }
  // Sender signals "all chunks sent". Verifying starts only after every
  // chunk actually exists here (wire 6.3); early complete is a protocol
  // failure of the transfer.
  receive->complete_received = true;
  // Account for chunks popped from the queues into the in-flight digest
  // check and blocking write; they exist but are not yet in the bitmap.
  const std::uint64_t accounted =
      receive->present_count + static_cast<std::uint64_t>(receive->write_queue.size()) +
      static_cast<std::uint64_t>(receive->validate_queue.size()) +
      (receive->hash_in_flight ? 1U : 0U) + (receive->write_in_flight ? 1U : 0U);
  if (accounted < receive->chunk_count) {
    fail_receive(*receive, StableStatus::protocol_error, "complete_early");
    return;
  }
  if (!receive->write_in_flight && receive->write_queue.empty() &&
      receive->validate_queue.empty() && !receive->hash_in_flight) {
    start_verify(*receive);
  }
}

void FileService::complete_transfer(SenderState& sender, StableStatus status,
                                    std::string_view safe_detail) {
  sender.terminal = true;
  if (status == StableStatus::ok) {
    ++stats_.sender_committed;
    book_->mutable_entries().erase(sender.transfer_id);
    emit_event({sender.transfer_id, FileTransferDirection::push,
                FileTransferPhase::committed, sender.root, sender.logical_name,
                sender.bytes_admitted, sender.manifest.size, std::nullopt});
  } else {
    ++stats_.sender_failed;
    book_->mutable_entries().erase(sender.transfer_id);
    emit_event({sender.transfer_id, FileTransferDirection::push,
                FileTransferPhase::failed, sender.root, sender.logical_name,
                sender.bytes_admitted, sender.manifest.size,
                Error{ErrorCode::internal, "file", std::string{safe_detail}}});
  }
  senders_.erase(sender.transfer_id);
}

void FileService::fail_transfer(SenderState& sender, StableStatus status,
                                std::string_view safe_detail) {
  if (sender.terminal) {
    return;
  }
  sender.terminal = true;
  ++stats_.sender_failed;
  book_->mutable_entries().erase(sender.transfer_id);
  emit_event({sender.transfer_id, FileTransferDirection::push, FileTransferPhase::failed,
              sender.root, sender.logical_name, sender.bytes_admitted,
              sender.manifest.size,
              Error{ErrorCode::internal, "file", std::string{safe_detail},
                    static_cast<std::int64_t>(status)}});
  senders_.erase(sender.transfer_id);
}

// ---- Receiver role ----

void FileService::handle_inbound_manifest(const FrameView& frame) {
  ++stats_.manifests_received;
  auto parsed = parse_file_manifest(frame.payload, session_.channels().limits());
  if (!parsed) {
    ++stats_.manifests_rejected;
    ++stats_.policy_rejected;
    session_.fail_business_channel(frame.channel_id,
                                   transport::CloseReason::protocol_error);
    return;
  }
  auto manifest = std::move(*parsed.value_if());
  if (receivers_.contains(manifest.transfer_id) ||
      senders_.contains(manifest.transfer_id)) {
    // One transfer id binds exactly one live transfer.
    ++stats_.manifests_rejected;
    reject_transfer(manifest.transfer_id, StableStatus::already_exists, "transfer_in_use");
    return;
  }

  // Root resolution (M7-09): the first logical-name segment selects the
  // configured root; everything is checked before any byte is accepted.
  const std::string root{root_segment_of(manifest.logical_name)};
  const auto* root_entry = root_config(root);
  if (root_entry == nullptr) {
    ++stats_.manifests_rejected;
    ++stats_.path_rejected;
    reject_transfer(manifest.transfer_id, StableStatus::not_found, "root_unknown");
    return;
  }

  // Direction scope (M7-09): a manifest is only acceptable under the pull
  // scope while its pending pull is registered; everything else needs the
  // push scope for that root.
  bool pull_initiated = false;
  const auto pending = pending_pulls_.find(manifest.transfer_id);
  if (pending != pending_pulls_.end() &&
      join_logical_name(pending->second.root, pending->second.logical_name) ==
          manifest.logical_name) {
    pull_initiated = true;
  }
  const std::string scope =
      pull_initiated ? file_pull_scope(root) : file_push_scope(root);
  if (!scope_check_ || !scope_check_(scope)) {
    ++stats_.manifests_rejected;
    ++stats_.scope_rejected;
    reject_transfer(manifest.transfer_id, StableStatus::permission_denied, "scope_denied");
    return;
  }

  // Policy gate (M7-15): compression stays off unless the build feature is
  // enabled; the codec already bounds expanded_size.
  if (manifest.zstd_compressed) {
    ++stats_.manifests_rejected;
    ++stats_.policy_rejected;
    reject_transfer(manifest.transfer_id, StableStatus::unimplemented,
                    "compression_unsupported");
    return;
  }

  // Quotas (M7-09): single file, root total (active reservations), root
  // concurrency, and the per-peer cumulative budget.
  if (manifest.size > root_entry->max_file_bytes) {
    ++stats_.manifests_rejected;
    ++stats_.quota_rejected;
    reject_transfer(manifest.transfer_id, StableStatus::resource_exhausted, "file_too_large");
    return;
  }
  std::uint64_t in_root = 0U;
  std::size_t root_active = 0U;
  for (const auto& [id, receive] : receivers_) {
    if (receive.root == root && !receive.terminal) {
      in_root += receive.manifest.size;
      ++root_active;
    }
  }
  if (in_root + manifest.size > root_entry->max_total_bytes) {
    ++stats_.manifests_rejected;
    ++stats_.quota_rejected;
    reject_transfer(manifest.transfer_id, StableStatus::resource_exhausted, "root_quota");
    return;
  }
  if (root_active >= root_entry->max_concurrent_receives) {
    ++stats_.manifests_rejected;
    ++stats_.concurrency_rejected;
    reject_transfer(manifest.transfer_id, StableStatus::resource_exhausted,
                    "root_concurrency");
    return;
  }
  if (config_.max_peer_receive_bytes > 0U) {
    std::uint64_t peer_total = 0U;
    for (const auto& [peer_root, bytes] : peer_received_bytes_) {
      (void)peer_root;
      peer_total += bytes;
    }
    if (peer_total + manifest.size > config_.max_peer_receive_bytes) {
      ++stats_.manifests_rejected;
      ++stats_.quota_rejected;
      reject_transfer(manifest.transfer_id, StableStatus::resource_exhausted, "peer_quota");
      return;
    }
  }

  ReceiverState receive;
  receive.transfer_id = manifest.transfer_id;
  receive.manifest = manifest;
  receive.root = root;
  receive.pull_initiated = pull_initiated;
  receive.chunk_count = chunk_count_of(manifest.size, manifest.chunk_size);
  receive.chunk_bitmap.assign(static_cast<std::size_t>(receive.chunk_count), 0U);

  // The logical name is "<root>/<relative path>"; the root selector maps to
  // the configured directory and the remainder stays inside it.
  const std::string relative_name{manifest.logical_name.substr(root.size() + 1U)};
  auto staging = file_store::create_staging(root_entry->directory, relative_name,
                                            transfer_hex(manifest.transfer_id));
  if (!staging) {
    ++stats_.manifests_rejected;
    ++stats_.path_rejected;
    reject_transfer(manifest.transfer_id, StableStatus::permission_denied, "staging_denied");
    return;
  }
  receive.temp_path = staging.value_if()->temp_path;
  receive.state_path = staging.value_if()->state_path;
  receive.final_path = staging.value_if()->final_path;

  // Resume (M7-13): an existing sidecar for this exact transfer restores the
  // present-chunk bitmap; a mismatched sidecar refuses the transfer instead
  // of overwriting committed output.
  auto resumed = file_store::read_resume_state(receive.state_path);
  if (resumed) {
    const auto& state = *resumed.value_if();
    if (state.transfer_id != manifest.transfer_id || state.size != manifest.size ||
        state.chunk_size != manifest.chunk_size ||
        !std::equal(state.blake3.begin(), state.blake3.end(), manifest.blake3.begin())) {
      ++stats_.manifests_rejected;
      reject_transfer(manifest.transfer_id, StableStatus::already_exists,
                      "resume_state_mismatch");
      return;
    }
    receive.chunk_bitmap = state.chunk_bitmap;
    receive.present_count = static_cast<std::uint64_t>(
        std::count(receive.chunk_bitmap.begin(), receive.chunk_bitmap.end(), 1U));
    receive.bytes_received = receive.present_count * manifest.chunk_size;
    ++stats_.resumed_transfers;
  }

  receivers_[manifest.transfer_id] = std::move(receive);
  accept_transfer(receivers_[manifest.transfer_id]);
  if (pull_initiated) {
    pending_pulls_.erase(manifest.transfer_id);
  }
}

void FileService::accept_transfer(ReceiverState& receive) {
  FileAcceptBody accept;
  accept.transfer_id = receive.transfer_id;
  for (std::uint64_t index = 0U; index < receive.chunk_count; ++index) {
    if (receive.chunk_bitmap[static_cast<std::size_t>(index)] != 0U) {
      accept.present_chunk_indices.push_back(index);
    }
  }
  auto encoded = encode_file_accept(accept);
  if (!encoded) {
    fail_receive(receive, StableStatus::internal, "accept_encode_failed");
    return;
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::file_accept);
  frame.channel_id = channel_id_;
  frame.payload = std::move(*encoded.value_if());
  if (!session_.send_frame(channel_id_, session::FrameClass::standard, std::move(frame))) {
    fail_receive(receive, StableStatus::unavailable, "accept_send_failed");
    return;
  }
  ++stats_.accepts_sent;
  // Persist the sidecar so a crash mid-transfer resumes by transfer id.
  file_store::ResumeState state;
  state.transfer_id = receive.transfer_id;
  state.size = receive.manifest.size;
  state.chunk_size = receive.manifest.chunk_size;
  std::copy(receive.manifest.blake3.begin(), receive.manifest.blake3.end(),
            state.blake3.begin());
  state.chunk_bitmap = receive.chunk_bitmap;
  auto path = receive.state_path;
  (void)blocking_dispatch_(
      "heyaki-file-state", [path, state = std::move(state)](executor::StopToken) mutable {
        (void)file_store::write_resume_state(path, state);
      });
  emit_event({receive.transfer_id,
              receive.pull_initiated ? FileTransferDirection::pull
                                     : FileTransferDirection::push,
              FileTransferPhase::transferring, receive.root,
              receive.manifest.logical_name, 0U, receive.manifest.size, std::nullopt});
}

void FileService::reject_transfer(const TransferId& id, StableStatus status,
                                  std::string_view safe_detail) {
  FileRejectBody reject;
  reject.transfer_id = id;
  reject.status = status;
  reject.safe_detail = std::string{safe_detail};
  auto encoded = encode_file_reject(reject);
  if (!encoded) {
    return;
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::file_reject);
  frame.channel_id = channel_id_;
  frame.payload = std::move(*encoded.value_if());
  // Bulk class: this frame may follow queued chunks and must never preempt
  // them (the weighted scheduler sends standard ahead of bulk).
  (void)session_.send_frame(channel_id_, session::FrameClass::bulk, std::move(frame));
}

void FileService::handle_inbound_chunk(const FrameView& frame) {
  auto parsed = parse_file_chunk(frame.payload, session_.channels().limits());
  if (!parsed) {
    ++stats_.conflicting_chunks;
    session_.fail_business_channel(frame.channel_id,
                                   transport::CloseReason::protocol_error);
    return;
  }
  auto chunk = std::move(*parsed.value_if());
  auto* receive = receiver_of(chunk.header.transfer_id);
  if (receive == nullptr || receive->terminal) {
    // Unknown transfer or terminal replay: ignored and counted (wire 6.3).
    ++stats_.duplicate_chunks;
    return;
  }
  const auto& manifest = receive->manifest;
  const auto chunk_size = manifest.chunk_size;
  if (chunk.header.offset % chunk_size != 0U) {
    ++stats_.conflicting_chunks;
    fail_receive(*receive, StableStatus::protocol_error, "chunk_misaligned");
    return;
  }
  const auto index = chunk.header.offset / chunk_size;
  if (index >= receive->chunk_count ||
      chunk.header.offset + chunk.data.size() > manifest.size) {
    ++stats_.conflicting_chunks;
    fail_receive(*receive, StableStatus::protocol_error, "chunk_out_of_range");
    return;
  }
  const std::uint64_t remainder = manifest.size - chunk.header.offset;
  const auto expected =
      static_cast<std::uint32_t>(std::min<std::uint64_t>(chunk_size, remainder));
  if (chunk.data.size() != expected) {
    ++stats_.conflicting_chunks;
    fail_receive(*receive, StableStatus::protocol_error, "chunk_length_invalid");
    return;
  }
  const auto known = receive->accepted.find(chunk.header.offset);
  if (known != receive->accepted.end()) {
    if (known->second.first == chunk.data.size() &&
        std::equal(known->second.second.begin(), known->second.second.end(),
                   chunk.header.blake3.begin())) {
      // Byte-stable duplicate: idempotent (wire 6.3).
      ++stats_.duplicate_chunks;
      return;
    }
    ++stats_.conflicting_chunks;
    fail_receive(*receive, StableStatus::internal, "chunk_conflict");
    return;
  }
  receive->accepted.emplace(
      chunk.header.offset,
      std::make_pair(static_cast<std::uint32_t>(chunk.data.size()), chunk.header.blake3));
  PendingChunk pending;
  pending.offset = chunk.header.offset;
  pending.data.assign(chunk.data.begin(), chunk.data.end());
  receive->validate_queue.push_back(std::move(pending));
  ++stats_.chunks_received;
  pump_validate(*receive);
}

void FileService::pump_validate(ReceiverState& receive) {
  if (receive.hash_in_flight || receive.terminal || receive.validate_queue.empty()) {
    return;
  }
  receive.hash_in_flight = true;
  auto pending = std::move(receive.validate_queue.front());
  receive.validate_queue.pop_front();
  const auto offset = pending.offset;
  const auto expected = receive.accepted.at(offset).second;
  auto weak = weak_from_this();
  const auto id = receive.transfer_id;
  auto moved = std::make_shared<std::vector<std::byte>>(std::move(pending.data));
  // In-memory digest check (M7-12: bounded CPU work on an ordinary executor
  // task, never the network strand).
  auto dispatched = dispatch_(
      "heyaki-file-chunk-hash",
      [weak, id, offset, expected, moved]() {
        const auto digest = file_store::blake3_bytes(*moved);
        if (auto self = weak.lock()) {
          self->poster_([weak, id, offset, digest, expected, moved]() {
            if (auto inner = weak.lock()) {
              inner->finish_chunk_hash(id, offset, std::move(*moved), digest, expected);
            }
          });
        }
      });
  if (!dispatched) {
    receive.hash_in_flight = false;
    ++stats_.write_failures;
    fail_receive(receive, StableStatus::resource_exhausted, "hash_dispatch_rejected");
  }
}

void FileService::finish_chunk_hash(const TransferId& id, std::uint64_t offset,
                                    std::vector<std::byte> data,
                                    const file_store::Digest& digest,
                                    const file_store::Digest& expected) {
  auto* receive = receiver_of(id);
  if (receive == nullptr || receive->terminal) {
    return;
  }
  receive->hash_in_flight = false;
  if (digest != expected) {
    ++stats_.chunk_hash_failures;
    fail_receive(*receive, StableStatus::internal, "chunk_hash_mismatch");
    return;
  }
  PendingChunk ready;
  ready.offset = offset;
  ready.data = std::move(data);
  receive->write_queue.push_back(std::move(ready));
  dispatch_chunk_write(*receive);
  pump_validate(*receive);
}

void FileService::dispatch_chunk_write(ReceiverState& receive) {
  if (receive.write_in_flight || receive.terminal || receive.write_queue.empty()) {
    maybe_start_verify(receive);
    return;
  }
  receive.write_in_flight = true;
  auto pending = std::move(receive.write_queue.front());
  receive.write_queue.pop_front();
  const auto offset = pending.offset;
  auto weak = weak_from_this();
  const auto id = receive.transfer_id;
  const auto temp_path = receive.temp_path;
  const auto state_path = receive.state_path;
  // The blocking task writes the chunk, updates a private bitmap copy, and
  // rewrites the sidecar so a crash resumes exactly at this chunk.
  file_store::ResumeState state;
  state.transfer_id = receive.transfer_id;
  state.size = receive.manifest.size;
  state.chunk_size = receive.manifest.chunk_size;
  std::copy(receive.manifest.blake3.begin(), receive.manifest.blake3.end(),
            state.blake3.begin());
  state.chunk_bitmap = receive.chunk_bitmap;
  const auto chunk_index = offset / receive.manifest.chunk_size;
  if (state.chunk_bitmap.size() > static_cast<std::size_t>(chunk_index)) {
    state.chunk_bitmap[static_cast<std::size_t>(chunk_index)] = 1U;
  }
  auto moved = std::make_shared<std::vector<std::byte>>(std::move(pending.data));
  auto dispatched = blocking_dispatch_(
      "heyaki-file-write",
      [weak, id, offset, temp_path, state_path, state = std::move(state), moved](
          executor::StopToken stop) {
        bool ok = false;
        std::string detail;
        if (stop.stop_requested()) {
          detail = "write_cancelled";
        } else if (file_store::write_staging_at(temp_path, offset, *moved)) {
          if (stop.stop_requested()) {
            detail = "write_cancelled";
          } else if (file_store::write_resume_state(state_path, state)) {
            ok = true;
          } else {
            detail = "state_write_failed";
          }
        } else {
          detail = "write_failed";
        }
        if (auto self = weak.lock()) {
          self->poster_([weak, id, offset, ok, detail = std::move(detail),
                         bitmap = state.chunk_bitmap]() {
            if (auto inner = weak.lock()) {
              inner->finish_chunk_write(id, offset, ok, bitmap, detail);
            }
          });
        }
      });
  if (!dispatched) {
    receive.write_in_flight = false;
    ++stats_.write_failures;
    fail_receive(receive, StableStatus::resource_exhausted, "write_dispatch_rejected");
  }
}

void FileService::finish_chunk_write(const TransferId& id, std::uint64_t offset, bool ok,
                                     std::vector<std::uint8_t> bitmap,
                                     std::string_view detail) {
  auto* receive = receiver_of(id);
  if (receive == nullptr || receive->terminal) {
    return;
  }
  receive->write_in_flight = false;
  if (!ok) {
    ++stats_.write_failures;
    fail_receive(*receive, StableStatus::unavailable, detail);
    return;
  }
  receive->chunk_bitmap = std::move(bitmap);
  ++receive->present_count;
  receive->bytes_received += std::min<std::uint64_t>(
      receive->manifest.chunk_size, receive->manifest.size - offset);
  emit_event({id,
              receive->pull_initiated ? FileTransferDirection::pull
                                      : FileTransferDirection::push,
              FileTransferPhase::transferring, receive->root,
              receive->manifest.logical_name, receive->bytes_received,
              receive->manifest.size, std::nullopt});
  maybe_start_verify(*receive);
  dispatch_chunk_write(*receive);
}

void FileService::maybe_start_verify(ReceiverState& receive) {
  if (receive.terminal || receive.verifying || !receive.complete_received ||
      receive.present_count < receive.chunk_count || receive.write_in_flight ||
      receive.hash_in_flight || !receive.write_queue.empty() ||
      !receive.validate_queue.empty()) {
    return;
  }
  start_verify(receive);
}

void FileService::start_verify(ReceiverState& receive) {
  receive.verifying = true;
  ++stats_.verifies_started;
  auto weak = weak_from_this();
  const auto id = receive.transfer_id;
  const auto temp_path = receive.temp_path;
  file_store::Digest expected{};
  std::copy(receive.manifest.blake3.begin(), receive.manifest.blake3.end(),
            expected.begin());
  auto staging = file_store::StagingFile{receive.temp_path, receive.state_path,
                                         receive.final_path};
  auto dispatched = blocking_dispatch_(
      "heyaki-file-verify",
      [weak, id, temp_path, expected, staging = std::move(staging)](
          executor::StopToken stop) {
        bool ok = false;
        std::string detail;
        if (stop.stop_requested()) {
          detail = "verify_cancelled";
        } else if (auto digest = file_store::blake3_file(temp_path)) {
          if (*digest.value_if() != expected) {
            detail = "hash_mismatch";
          } else if (file_store::commit_staging(staging)) {
            ok = true;
          } else {
            detail = "commit_failed";
          }
        } else {
          detail = "verify_read_failed";
        }
        if (auto self = weak.lock()) {
          self->poster_([weak, id, ok, detail = std::move(detail)]() {
            if (auto inner = weak.lock()) {
              inner->finish_verify(id, ok, detail);
            }
          });
        }
      });
  if (!dispatched) {
    receive.verifying = false;
    ++stats_.commit_failures;
    fail_receive(receive, StableStatus::resource_exhausted, "verify_dispatch_rejected");
  }
}

void FileService::finish_verify(const TransferId& id, bool ok, std::string_view detail) {
  auto* receive = receiver_of(id);
  if (receive == nullptr || receive->terminal) {
    return;
  }
  receive->terminal = true;
  receive->verifying = false;
  if (ok) {
    ++stats_.committed;
    peer_received_bytes_[receive->root] += receive->manifest.size;
    emit_event({id,
                receive->pull_initiated ? FileTransferDirection::pull
                                        : FileTransferDirection::push,
                FileTransferPhase::committed, receive->root,
                receive->manifest.logical_name, receive->manifest.size,
                receive->manifest.size, std::nullopt});
    // The sender's terminal commit verdict (wire 6.3 verifying -> committed).
    send_complete(id, StableStatus::ok, "");
    receivers_.erase(id);
    return;
  }
  ++stats_.commit_failures;
  emit_event({id,
              receive->pull_initiated ? FileTransferDirection::pull
                                      : FileTransferDirection::push,
              FileTransferPhase::failed, receive->root, receive->manifest.logical_name,
              receive->bytes_received, receive->manifest.size,
              Error{ErrorCode::internal, "file", std::string{detail}}});
  send_complete(id, StableStatus::internal, std::string{detail}.substr(0, 31));
  cleanup_receive(*receive);
  receivers_.erase(id);
}

void FileService::fail_receive(ReceiverState& receive, StableStatus status,
                               std::string_view safe_detail) {
  if (receive.terminal) {
    return;
  }
  receive.terminal = true;
  emit_event({receive.transfer_id,
              receive.pull_initiated ? FileTransferDirection::pull
                                     : FileTransferDirection::push,
              FileTransferPhase::failed, receive.root, receive.manifest.logical_name,
              receive.bytes_received, receive.manifest.size,
              Error{ErrorCode::internal, "file", std::string{safe_detail}}});
  send_abort(receive.transfer_id, status, safe_detail);
  cleanup_receive(receive);
  receivers_.erase(receive.transfer_id);
}

void FileService::cleanup_receive(ReceiverState& receive) {
  ++stats_.partial_cleanups;
  auto staging = file_store::StagingFile{receive.temp_path, receive.state_path,
                                         receive.final_path};
  const auto state_path = receive.state_path;
  const auto temp_path = receive.temp_path;
  (void)blocking_dispatch_(
      "heyaki-file-cleanup", [temp_path, state_path](executor::StopToken) {
        (void)file_store::discard_staging(file_store::StagingFile{temp_path, state_path, {}});
      });
}

void FileService::emit_event(FileTransferEvent event) {
  if (event_sink_ != nullptr) {
    event_sink_(event_context_, peer_, event);
  }
}

void FileService::send_abort(const TransferId& id, StableStatus status,
                             std::string_view safe_detail) {
  FileRejectBody reject;
  reject.transfer_id = id;
  reject.status = status;
  reject.safe_detail = std::string{safe_detail}.substr(0, 31);
  auto encoded = encode_file_reject(reject);
  if (!encoded) {
    return;
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::file_reject);
  frame.channel_id = channel_id_;
  frame.payload = std::move(*encoded.value_if());
  // Bulk class: this frame may follow queued chunks and must never preempt
  // them (the weighted scheduler sends standard ahead of bulk).
  (void)session_.send_frame(channel_id_, session::FrameClass::bulk, std::move(frame));
}

void FileService::send_complete(const TransferId& id, StableStatus status,
                                std::string_view safe_detail) {
  FileCompleteBody complete;
  complete.transfer_id = id;
  complete.status = status;
  if (!safe_detail.empty()) {
    complete.safe_detail = std::string{safe_detail}.substr(0, 31);
  }
  auto encoded = encode_file_complete(complete);
  if (!encoded) {
    return;
  }
  Frame frame;
  frame.type = static_cast<std::uint8_t>(FrameType::file_complete);
  frame.channel_id = channel_id_;
  frame.payload = std::move(*encoded.value_if());
  // Bulk class: this frame may follow queued chunks and must never preempt
  // them (the weighted scheduler sends standard ahead of bulk).
  (void)session_.send_frame(channel_id_, session::FrameClass::bulk, std::move(frame));
}

FileService::SenderState* FileService::sender_of(const TransferId& id) {
  const auto entry = senders_.find(id);
  return entry == senders_.end() ? nullptr : &entry->second;
}

FileService::ReceiverState* FileService::receiver_of(const TransferId& id) {
  const auto entry = receivers_.find(id);
  return entry == receivers_.end() ? nullptr : &entry->second;
}

const FileRootConfig* FileService::root_config(std::string_view root) const {
  for (const auto& entry : config_.receive_roots) {
    if (entry.name == root) {
      return &entry;
    }
  }
  return nullptr;
}

FileServiceStats FileService::stats() {
  return stats_;
}

std::vector<FileTransferSummary> FileService::transfers() const {
  std::vector<FileTransferSummary> summaries;
  summaries.reserve(senders_.size() + receivers_.size());
  for (const auto& [id, sender] : senders_) {
    FileTransferPhase phase = sender.paused ? FileTransferPhase::paused
                              : sender.complete_sent ? FileTransferPhase::verifying
                              : sender.manifest.size == 0U
                                  ? FileTransferPhase::probing
                                  : (sender.present_chunks.empty() &&
                                             sender.bytes_admitted == 0U
                                         ? FileTransferPhase::offered
                                         : FileTransferPhase::transferring);
    summaries.push_back(FileTransferSummary{id, FileTransferDirection::push, phase,
                                            sender.root, sender.logical_name,
                                            sender.bytes_admitted, sender.manifest.size,
                                            true});
  }
  for (const auto& [id, receive] : receivers_) {
    FileTransferPhase phase = receive.verifying ? FileTransferPhase::verifying
                              : receive.terminal ? FileTransferPhase::failed
                                                 : FileTransferPhase::transferring;
    summaries.push_back(FileTransferSummary{id,
                                            receive.pull_initiated
                                                ? FileTransferDirection::pull
                                                : FileTransferDirection::push,
                                            phase, receive.root,
                                            receive.manifest.logical_name,
                                            receive.bytes_received, receive.manifest.size,
                                            false});
  }
  return summaries;
}

}  // namespace heyaki
