// Issue #15 regression (M5-34 / HEY-20261002-001), post-fix semantics.
//
// Service-level cases (loopback PeerSession pair, manual clocks): an
// AUTHENTICATED pair where side A mounts the basic communication services
// (message + file) and side B mounts NO business service at all, covering:
//
//   1. message rejection -> push: a peer_acked text message fails bounded
//      (ack-TTL) while the session body stays healthy; a small file push on
//      the same session terminals bounded through the offer deadline with
//      exactly one failed terminal;
//   2. control baseline: B mounts the file service but its scope_check
//      refuses -> FILE_REJECT terminals the transfer (the "refused" family);
//   3. session snapshot forensics: silent drops never move either
//      PeerSession out of authenticated/active and never close a channel;
//   4. park semantics at the FileService level: session teardown while
//      offered parks the sender as paused with NO terminal; the retired
//      service reports transfer_unknown (the Node-level book fallback is
//      covered by the Node tests below);
//   5. same-session follow-ups: re-push after a terminal, transfer-id reuse,
//      live pause + cancel;
//   6. reconnection: a fresh session's FileService attach() resumes the
//      parked entry against a silent peer (deadline terminal) and against a
//      serving peer (commit).
//
// Node-level cases (real two-node LAN pair, harness adapted from
// m5_basic_communication_test.cpp): A runs with basic communication enabled,
// B with basic communication DISABLED (B's pairing_restricted session takes
// business violations on A's frames):
//
//   7. push to the silent receiver terminals through the offer deadline
//      (exactly one failed terminal) while both session snapshots stay
//      pairing_restricted;
//   8. a push whose offer is still pending, followed by a session end
//      (Node::close_lan), parks the transfer as paused in the transfer book;
//      the parked transfer is VISIBLE through Node::file_transfers (the
//      issue #15 fix) and CANCELLABLE through Node::cancel_file_transfer
//      with exactly one terminal cancelled event; the book entry disappears
//      and a second cancel reports transfer_unknown;
//   9. the full message-refusal sequence: message fails bounded (ack-TTL),
//      the push parks after the session end, and the parked cancel works —
//      every step of the issue's sequence terminates in bounded time.

#include "m7_support.hpp"

#include <heyaki/file.hpp>
#include <heyaki/lan_protocol.hpp>
#include <heyaki/message.hpp>
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <kairo/comm.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>


namespace heyaki {
namespace {

using test::ManualBlockingDispatch;
using test::M7TempDir;
using test::M6ServicePair;

std::vector<std::byte> text_bytes(std::string_view text) {
  auto bytes = std::vector<std::byte>{};
  bytes.reserve(text.size());
  for (const char character : text) {
    bytes.push_back(static_cast<std::byte>(character));
  }
  return bytes;
}

// ---- recorders ------------------------------------------------------------

struct AckRecord {
  MessageId message_id;
  MessageDeliveryEvent event{MessageDeliveryEvent::queued};
  std::optional<Error> error;
};

class AckLog {
 public:
  void bind(MessageService& service) { service.set_ack_sink(&sink, this); }

  [[nodiscard]] std::vector<AckRecord> for_message(const MessageId& id) const {
    std::vector<AckRecord> matched;
    for (const auto& record : records_) {
      if (record.message_id == id) matched.push_back(record);
    }
    return matched;
  }
  [[nodiscard]] std::size_t count_of(const MessageId& id,
                                     MessageDeliveryEvent event) const {
    const auto matched = for_message(id);  // one materialization: begin/end must
                                           // come from the same container
    return static_cast<std::size_t>(
        std::count_if(matched.begin(), matched.end(),
                      [&](const AckRecord& record) { return record.event == event; }));
  }

 private:
  std::vector<AckRecord> records_;

 private:
  static void sink(void* context, const DeviceEndpointKey&, const MessageId& id,
                   MessageDeliveryEvent event, std::optional<Error> error) {
    static_cast<AckLog*>(context)->records_.push_back(
        AckRecord{id, event, std::move(error)});
  }
};

class FileEventLog {
 public:
  void bind(FileService& service) { service.set_event_sink(&sink, this); }

  [[nodiscard]] std::size_t count_of(const TransferId& id,
                                     FileTransferPhase phase) const {
    return static_cast<std::size_t>(std::count_if(
        events.begin(), events.end(), [&](const FileTransferEvent& event) {
          return event.transfer_id == id && event.phase == phase;
        }));
  }
  [[nodiscard]] std::size_t terminal_count(const TransferId& id) const {
    return count_of(id, FileTransferPhase::committed) +
           count_of(id, FileTransferPhase::failed) +
           count_of(id, FileTransferPhase::cancelled);
  }
  [[nodiscard]] std::optional<FileTransferEvent> last_of(
      const TransferId& id, FileTransferPhase phase) const {
    std::optional<FileTransferEvent> found;
    for (const auto& event : events) {
      if (event.transfer_id == id && event.phase == phase) found = event;
    }
    return found;
  }
  [[nodiscard]] std::string sequence_of(const TransferId& id) const {
    std::string sequence;
    for (const auto& event : events) {
      if (event.transfer_id != id) continue;
      if (!sequence.empty()) sequence.push_back(',');
      sequence.append(std::string{file_transfer_phase_name(event.phase)});
    }
    return sequence;
  }

  std::vector<FileTransferEvent> events;

 private:
  static void sink(void* context, const DeviceEndpointKey&,
                   const FileTransferEvent& event) {
    static_cast<FileEventLog*>(context)->events.push_back(event);
  }
};

// ---- asymmetric harness: services mounted per side ------------------------

struct Issue15Pair {
  struct Options {
    std::vector<std::string> left_scopes{"message.send"};
    std::vector<std::string> right_scopes{"message.send"};
    std::uint64_t offer_timeout_milliseconds{5'000U};
    std::size_t max_concurrent_sends{2U};
    // Mount a FileService on the right side (control variant).
    bool right_file{false};
    std::shared_ptr<FileTransferBook> book;
  };

  M7TempDir left_dir;
  M7TempDir right_dir;
  M6ServicePair::Options m6_optionsFor() const {
    M6ServicePair::Options options;
    options.attach_message = false;
    options.attach_rpc = false;
    options.left_scopes = scopes_left;
    options.right_scopes = scopes_right;
    return options;
  }
  // Kept out of the M6 options struct so the member init order stays simple.
  std::vector<std::string> scopes_left;
  std::vector<std::string> scopes_right;

  M6ServicePair m6;
  ManualBlockingDispatch left_blocking;
  ManualBlockingDispatch right_blocking;
  test::ManualPoster left_file_poster;
  test::ManualPoster right_file_poster;
  std::shared_ptr<FileTransferBook> book;

  std::shared_ptr<MessageService> left_messages;
  std::shared_ptr<FileService> left_files;
  std::shared_ptr<FileService> right_files;
  FileServiceConfig left_file_config;
  FileServiceConfig right_file_config;

  explicit Issue15Pair(Options options)
      : scopes_left(std::move(options.left_scopes)),
        scopes_right(std::move(options.right_scopes)),
        m6(m6_optionsFor()),
        book(options.book ? std::move(options.book)
                          : std::make_shared<FileTransferBook>()) {
    left_file_config.offer_timeout_milliseconds = options.offer_timeout_milliseconds;
    left_file_config.max_concurrent_sends = options.max_concurrent_sends;
    right_file_config.offer_timeout_milliseconds = options.offer_timeout_milliseconds;
    right_file_config.receive_roots.push_back(FileRootConfig{
        .name = "inbox",
        .directory = right_dir.path / "inbox",
        .max_file_bytes = 64ULL * 1024ULL * 1024ULL,
        .max_total_bytes = 128ULL * 1024ULL * 1024ULL,
        .max_concurrent_receives = 2U});
    std::filesystem::create_directories(right_dir.path / "inbox");
    // The loopback double only delivers an inbound frame when the RECEIVING
    // LoopbackSession holds a physical channel of the same kind
    // (m4_support.hpp LoopbackSession::pump). In production the responder
    // ADOPTS the initiator's physical channels (PeerSession channel_handler_
    // -> adopt_physical_channel) even when no business service is mounted;
    // emulate that adoption so A's frames actually reach B's
    // handle_business_frame silent drop+count path instead of being swallowed
    // by the test transport.
    transport::ChannelOptions channel_options;
    m6.pair.right().async_open_channel(transport::ChannelKind::message, channel_options,
                                       [](Result<transport::TransportChannel*>) {});
    if (!options.right_file) {
      m6.pair.right().async_open_channel(transport::ChannelKind::file, channel_options,
                                         [](Result<transport::TransportChannel*>) {});
    }
  }

  [[nodiscard]] DeviceEndpointKey left_key() const { return m6.left_key(); }
  [[nodiscard]] DeviceEndpointKey right_key() const { return m6.right_key(); }
  [[nodiscard]] PeerSession& left_session() { return *m6.left; }
  [[nodiscard]] PeerSession& right_session() { return *m6.right; }

  void attach_left_message() {
    left_messages = std::make_shared<MessageService>(
        *m6.left, m6.left_key(), MessageServiceConfig{}, m6.left_dispatch.dispatcher(),
        m6.scope_check(m6.left), [this] { return m6.left_clock; });
    ASSERT_TRUE(left_messages->attach());
    m6.pump();
  }

  void make_left_file() {
    if (!left_files) {
      left_files = std::make_shared<FileService>(
          *m6.left, m6.left_key(), left_file_config, book,
          m6.left_dispatch.dispatcher(), left_blocking.dispatcher(),
          m6.scope_check(m6.left), left_file_poster.poster(),
          [this] { return m6.left_clock; });
    }
  }

  void attach_left_file() {
    make_left_file();
    ASSERT_TRUE(left_files->attach());
    m6.pump();
  }

  void attach_right_file() {
    right_files = std::make_shared<FileService>(
        *m6.right, m6.right_key(), right_file_config,
        std::make_shared<FileTransferBook>(), m6.right_dispatch.dispatcher(),
        right_blocking.dispatcher(), m6.scope_check(m6.right),
        right_file_poster.poster(), [this] { return m6.right_clock; });
    ASSERT_TRUE(right_files->attach());
    m6.pump();
  }

  void pump() { m6.pump(); }

  // Runs every executor flavor (general CPU, blocking I/O, strand posts) and
  // frame delivery to quiescence.
  void cycle(int rounds = 64) {
    for (int round = 0; round < rounds; ++round) {
      m6.left_dispatch.run_all();
      m6.right_dispatch.run_all();
      left_blocking.run_all();
      right_blocking.run_all();
      left_file_poster.run_all();
      right_file_poster.run_all();
      m6.pump();
      if (pending_work() == 0U && round > 2) {
        m6.pump();
        return;
      }
    }
  }

  // Sender-side probe + manifest only (no cross-pump): mirrors the m7 offer
  // test helper. Follow with pump() to actually put the manifest on the wire.
  void run_sender_probe_and_manifest() {
    left_blocking.run_all();
    left_file_poster.run_all();
  }

  [[nodiscard]] std::size_t pending_work() const {
    return m6.left_dispatch.tasks.size() + m6.right_dispatch.tasks.size() +
           left_blocking.has_pending() + right_blocking.has_pending() +
           left_file_poster.posts.size() + right_file_poster.posts.size();
  }

  [[nodiscard]] std::uint32_t file_channel_of(const PeerSession& side) const {
    for (const auto& snapshot : side.channels().channel_snapshots()) {
      if (snapshot.domain == session::ChannelDomain::file) return snapshot.channel_id;
    }
    return 0U;
  }
  [[nodiscard]] std::uint32_t message_channel_of(const PeerSession& side) const {
    for (const auto& snapshot : side.channels().channel_snapshots()) {
      if (snapshot.domain == session::ChannelDomain::message) return snapshot.channel_id;
    }
    return 0U;
  }

  static std::filesystem::path make_source(const std::filesystem::path& dir,
                                           std::string_view name, std::size_t size,
                                           std::uint8_t seed) {
    return test::M7ServicePair::make_source_file(dir, name, size, seed);
  }
};

std::string state_name(PeerSessionState state) {
  switch (state) {
    case PeerSessionState::idle: return "idle";
    case PeerSessionState::pairing_restricted: return "pairing_restricted";
    case PeerSessionState::authenticating: return "authenticating";
    case PeerSessionState::authenticated: return "authenticated";
    case PeerSessionState::active: return "active";
    case PeerSessionState::closed: return "closed";
  }
  return "unknown";
}

std::string error_text(const std::optional<Error>& error) {
  if (!error.has_value()) return "-";
  return std::string{error->safe_detail()};
}

// ---------------------------------------------------------------------------
// 1 + 3: authenticated session, B mounts NOTHING. The message frame and the
// FILE_MANIFEST both take the silent drop+count path (peer_session.cpp
// handle_business_frame: unknown logical channel, no domain handler ->
// business_frames_rejected++, session state untouched). The message resolves
// through the ack-TTL; the file resolves through the offer deadline with a
// FAILED terminal (not paused) because the session never dies.
// ---------------------------------------------------------------------------
TEST(M7Issue15Repro, SilentDropMessageFailsByAckTtlAndFileFailsByOfferDeadline) {
  Issue15Pair::Options options;
  options.offer_timeout_milliseconds = 5'000U;
  Issue15Pair harness(options);
  FileEventLog files;
  AckLog acks;
  harness.attach_left_message();
  harness.attach_left_file();
  acks.bind(*harness.left_messages);
  files.bind(*harness.left_files);

  // Baseline snapshot after the services mounted: opening business channels
  // moves A to active (peer_session.cpp:1178-1181) while B — with no services
  // — stays authenticated. That "stuck at authenticated" shape is itself one
  // of the issue #15 observations about side B.
  ASSERT_EQ(harness.left_session().diagnostics().state, PeerSessionState::active);
  ASSERT_EQ(harness.right_session().diagnostics().state, PeerSessionState::authenticated);
  RecordProperty("left_state_initial", state_name(harness.left_session().diagnostics().state));
  RecordProperty("right_state_initial", state_name(harness.right_session().diagnostics().state));

  // ---- 1a: A -> B peer_acked text message, ttl 2000 ms ----
  auto envelope = harness.m6.make_envelope("text", MessageDeliveryMode::peer_acked,
                                           text_bytes("hello"), 2'000U);
  const auto sent = harness.left_messages->send(envelope);
  ASSERT_TRUE(sent) << sent.error_if()->safe_detail();
  const auto message_id = *sent.value_if();
  harness.pump();  // frame crosses; B has no message domain handler

  // B silently dropped the frame: counted, no session state change, no
  // logical channel ever adopted on B.
  EXPECT_EQ(harness.right_session().diagnostics().business_frames_rejected, 1U)
      << "B must count the dropped message frame (drop+count path)";
  EXPECT_EQ(harness.right_session().diagnostics().state, PeerSessionState::authenticated)
      << "the silent drop must not move B out of authenticated";
  EXPECT_EQ(harness.message_channel_of(harness.right_session()), 0U)
      << "B never opened or adopted a message channel (no service mounted)";
  EXPECT_NE(harness.message_channel_of(harness.left_session()), 0U)
      << "A's message channel must survive the silent drop";
  EXPECT_EQ(acks.count_of(message_id, MessageDeliveryEvent::acked), 0U);
  EXPECT_EQ(acks.count_of(message_id, MessageDeliveryEvent::queued), 1U);

  // The bounded failure: ack-TTL expiry on A's side.
  harness.m6.left_clock += 2'001U;
  harness.left_messages->prune();
  EXPECT_EQ(acks.count_of(message_id, MessageDeliveryEvent::ack_timeout), 1U)
      << "the unanswered peer_acked message must terminal via ack-TTL";
  const auto timeout_records = acks.for_message(message_id);
  ASSERT_FALSE(timeout_records.empty());
  const auto* timeout_event = &timeout_records.back();
  ASSERT_TRUE(timeout_event->error.has_value());
  RecordProperty("message_terminal_event", "ack_timeout");
  RecordProperty("message_terminal_error", error_text(timeout_event->error));
  EXPECT_EQ(timeout_event->error->code(), ErrorCode::timeout);
  EXPECT_EQ(timeout_event->error->safe_detail(), "ack_ttl_expired");
  EXPECT_EQ(harness.left_messages->stats().ack_timed_out, 1U);

  // ---- 1b: A pushes a small file on the SAME session ----
  const auto source = Issue15Pair::make_source(harness.left_dir.path, "push-one.bin",
                                               50'000U, 0x21U);
  const auto pushed = harness.left_files->push_file("inbox", "offer/one.bin", source);
  ASSERT_TRUE(pushed) << pushed.error_if()->safe_detail()
                      << " (public push admission must succeed)";
  const auto id = *pushed.value_if();
  harness.run_sender_probe_and_manifest();
  harness.pump();  // manifest crosses; B has no file domain handler

  // Event sequence so far and the exact book state while offered.
  RecordProperty("file_events_before_deadline", files.sequence_of(id));
  EXPECT_EQ(files.count_of(id, FileTransferPhase::probing), 1U);
  EXPECT_EQ(files.count_of(id, FileTransferPhase::offered), 1U);
  EXPECT_EQ(files.terminal_count(id), 0U);
  const auto book_entry = harness.book->entries().find(id);
  ASSERT_NE(book_entry, harness.book->entries().end());
  EXPECT_EQ(book_entry->second.phase, FileTransferPhase::offered);

  // B silently dropped the manifest too; A's stats show zero accepts.
  EXPECT_EQ(harness.right_session().diagnostics().business_frames_rejected, 2U)
      << "message + manifest frames were both silently dropped on B";
  EXPECT_EQ(harness.left_files->stats().accepts_received, 0U);
  EXPECT_EQ(harness.right_session().diagnostics().state, PeerSessionState::authenticated);

  // Session-body forensics while the offer is parked (claim 3): neither side
  // moved out of authenticated/active, no channel was closed anywhere, and
  // B's only observable reaction is the reject counter.
  RecordProperty("left_state_while_offered",
                 state_name(harness.left_session().diagnostics().state));
  RecordProperty("right_state_while_offered",
                 state_name(harness.right_session().diagnostics().state));
  EXPECT_NE(harness.left_session().diagnostics().state, PeerSessionState::closed);
  EXPECT_NE(harness.right_session().diagnostics().state, PeerSessionState::closed);
  EXPECT_NE(harness.file_channel_of(harness.left_session()), 0U)
      << "the silent drop must not close A's file logical channel";
  EXPECT_EQ(harness.file_channel_of(harness.right_session()), 0U)
      << "B still has no file channel";
  EXPECT_FALSE(harness.left_session().diagnostics().last_error.has_value());
  EXPECT_FALSE(harness.right_session().diagnostics().last_error.has_value());

  // The offer deadline is the bounded failure: exactly one failed terminal,
  // timeout / "offer_expired" / deadline_exceeded (=3). Post-fix contract
  // (issue #15): on a LIVE session the transfer resolves offered -> FAILED;
  // the paused shape Aki observed requires the session to actually die
  // first (teardown tests below, Node tests at the bottom).
  harness.m6.left_clock += 6'000U;
  harness.left_files->prune();
  RecordProperty("file_events_after_deadline", files.sequence_of(id));
  RecordProperty("offer_window_ms", options.offer_timeout_milliseconds);
  EXPECT_EQ(files.terminal_count(id), 1U)
      << "the offer deadline must fire exactly one terminal";
  EXPECT_EQ(files.count_of(id, FileTransferPhase::failed), 1U);
  EXPECT_EQ(files.count_of(id, FileTransferPhase::paused), 0U)
      << "with the session alive the transfer must not present as paused";
  const auto failed = files.last_of(id, FileTransferPhase::failed);
  ASSERT_TRUE(failed.has_value());
  ASSERT_TRUE(failed->error.has_value());
  RecordProperty("file_terminal_error", error_text(failed->error));
  EXPECT_EQ(failed->error->code(), ErrorCode::timeout);
  EXPECT_EQ(failed->error->safe_detail(), "offer_expired");
  ASSERT_TRUE(failed->error->underlying_code().has_value());
  EXPECT_EQ(*failed->error->underlying_code(),
            static_cast<std::int64_t>(StableStatus::deadline_exceeded));
  EXPECT_TRUE(harness.book->entries().empty()) << "terminal failure erases the book entry";

  // The deadline failure sends nothing to B (fail_transfer never aborts).
  EXPECT_EQ(harness.right_session().diagnostics().business_frames_rejected, 2U);

  // Cancelling after the terminal: transfer_unknown, no second terminal.
  const auto cancelled = harness.left_files->cancel_transfer(id);
  ASSERT_FALSE(cancelled);
  EXPECT_EQ(cancelled.error_if()->code(), ErrorCode::peer_offline);
  EXPECT_EQ(cancelled.error_if()->safe_detail(), "transfer_unknown");
  EXPECT_EQ(files.terminal_count(id), 1U);

  // Session-body forensics after everything: A stays active (it mounted
  // services), B stays authenticated (it never did) — neither ever closed.
  RecordProperty("left_state_final", state_name(harness.left_session().diagnostics().state));
  RecordProperty("right_state_final", state_name(harness.right_session().diagnostics().state));
  EXPECT_EQ(harness.right_session().diagnostics().state, PeerSessionState::authenticated);
  EXPECT_EQ(harness.left_session().diagnostics().state, PeerSessionState::active);
}

// ---------------------------------------------------------------------------
// 2: control baseline — B mounts the file service but its session scopes do
// NOT include file.push:inbox (the "policy off" refusal shape). The manifest
// is explicitly refused with FILE_REJECT and A's transfer terminals; nothing
// is silently dropped. This proves the harness constructs both the refusal
// and the silent-drop paths.
// ---------------------------------------------------------------------------
TEST(M7Issue15Repro, ScopeDeniedPeerRejectsManifestAndTransferTerminals) {
  Issue15Pair::Options options;
  options.right_file = true;  // B serves files but will refuse the scope
  Issue15Pair harness(options);
  FileEventLog files;
  harness.attach_left_file();
  harness.attach_right_file();
  files.bind(*harness.left_files);

  // B mounted its file service, so B is active too; its granted scopes hold
  // only message.send: scope_check refuses file.push:inbox
  // (permission_denied / "scope_denied").
  ASSERT_EQ(harness.right_session().diagnostics().state, PeerSessionState::active);

  const auto source = Issue15Pair::make_source(harness.left_dir.path, "push-two.bin",
                                               50'000U, 0x22U);
  const auto pushed = harness.left_files->push_file("inbox", "offer/two.bin", source);
  ASSERT_TRUE(pushed);
  const auto id = *pushed.value_if();
  harness.cycle();  // probe -> manifest -> FILE_REJECT -> failed

  RecordProperty("file_events", files.sequence_of(id));
  EXPECT_EQ(files.terminal_count(id), 1U)
      << "an explicit FILE_REJECT must terminal the transfer";
  EXPECT_EQ(files.count_of(id, FileTransferPhase::failed), 1U);
  EXPECT_EQ(files.count_of(id, FileTransferPhase::paused), 0U);
  const auto failed = files.last_of(id, FileTransferPhase::failed);
  ASSERT_TRUE(failed.has_value());
  ASSERT_TRUE(failed->error.has_value());
  RecordProperty("file_terminal_error", error_text(failed->error));
  EXPECT_EQ(failed->error->safe_detail(), "peer_rejected");
  ASSERT_TRUE(failed->error->underlying_code().has_value());
  EXPECT_EQ(*failed->error->underlying_code(),
            static_cast<std::int64_t>(StableStatus::permission_denied));

  // The refusal was explicit on the serving side, not a silent drop.
  const auto right_stats = harness.right_files->stats();
  EXPECT_EQ(right_stats.manifests_received, 1U);
  EXPECT_EQ(right_stats.manifests_rejected, 1U);
  EXPECT_EQ(right_stats.scope_rejected, 1U);
  EXPECT_EQ(right_stats.accepts_sent, 0U);
  EXPECT_EQ(harness.right_session().diagnostics().business_frames_rejected, 0U)
      << "a served domain frame is handled, never counted as a violation";
  EXPECT_TRUE(harness.book->entries().empty());
  EXPECT_FALSE(std::filesystem::exists(harness.right_dir.path / "inbox" / "offer" /
                                       "two.bin"));

  // The explicit refusal does not hurt the session body either: both sides
  // carry mounted services, so both sit in active.
  EXPECT_EQ(harness.right_session().diagnostics().state, PeerSessionState::active);
  EXPECT_NE(harness.file_channel_of(harness.left_session()), 0U);
  EXPECT_NE(harness.file_channel_of(harness.right_session()), 0U);
}

// ---------------------------------------------------------------------------
// 4 (+ 2-claim shape): the session dies WHILE the push sits offered. Node
// teardown_peer_services (node.cpp:4214-4221) then calls
// FileService::handle_session_closed, which parks the sender in the book as
// paused (file_service.cpp:479-501). That reproduces Aki's exact diagnostic
// shape: offered=1, paused=1, terminal=0, linked=0.
//
// FileService-level semantics (this test): the RETIRED service itself no
// longer knows the id (SenderState cleared by handle_session_closed), so its
// cancel reports transfer_unknown and its prune can never terminal the
// entry. The issue #15 fix moves the parked cancel/visibility up to the Node
// (book fallback in cancel_file_transfer_strand / file_transfers_strand);
// the Node-level regression tests at the bottom of this file pin THAT
// contract.
// ---------------------------------------------------------------------------
TEST(M7Issue15Repro, TeardownWhileOfferedParksPausedWithoutTerminalAndCancelMisses) {
  Issue15Pair::Options options;
  options.offer_timeout_milliseconds = 5'000U;
  Issue15Pair harness(options);
  FileEventLog files;
  harness.attach_left_file();
  files.bind(*harness.left_files);

  const auto source = Issue15Pair::make_source(harness.left_dir.path, "push-three.bin",
                                               50'000U, 0x23U);
  const auto pushed = harness.left_files->push_file("inbox", "offer/three.bin", source);
  ASSERT_TRUE(pushed);
  const auto id = *pushed.value_if();
  harness.run_sender_probe_and_manifest();
  harness.pump();  // manifest crosses; B silently drops it

  ASSERT_EQ(files.count_of(id, FileTransferPhase::offered), 1U);
  ASSERT_EQ(files.terminal_count(id), 0U);
  ASSERT_EQ(harness.left_files->stats().accepts_received, 0U);

  // The session ends (transport loss / violation path / expiry — anything
  // that runs the Node teardown). Reproduce exactly what the Node calls.
  harness.left_files->handle_session_closed();

  RecordProperty("file_events", files.sequence_of(id));
  EXPECT_EQ(files.count_of(id, FileTransferPhase::paused), 1U);
  EXPECT_EQ(files.terminal_count(id), 0U)
      << "a parked transfer carries NO terminal — offered=1 paused=1 terminal=0";
  const auto paused = files.last_of(id, FileTransferPhase::paused);
  ASSERT_TRUE(paused.has_value());
  ASSERT_TRUE(paused->error.has_value());
  RecordProperty("paused_event_error", error_text(paused->error));
  EXPECT_EQ(paused->error->code(), ErrorCode::transport);
  EXPECT_EQ(paused->error->safe_detail(), "session_closed");
  const auto entry = harness.book->entries().find(id);
  ASSERT_NE(entry, harness.book->entries().end());
  EXPECT_EQ(entry->second.phase, FileTransferPhase::paused);
  EXPECT_EQ(entry->second.bytes_total, 50'000U);

  // The parked entry has no deadline: the retired service's prune can never
  // terminal it, however long the clock runs.
  harness.m6.left_clock += 60'000U;
  harness.left_files->prune();
  harness.left_files->prune();
  EXPECT_EQ(files.terminal_count(id), 0U)
      << "a parked book entry must not resolve through the retired service";
  ASSERT_NE(harness.book->entries().find(id), harness.book->entries().end());

  // Cancelling the parked transfer on the retired service: the SenderState
  // was cleared by handle_session_closed, so the id is unknown there.
  const auto retired_cancel = harness.left_files->cancel_transfer(id);
  ASSERT_FALSE(retired_cancel);
  RecordProperty("retired_service_cancel_error", std::string{retired_cancel.error_if()->safe_detail()});
  EXPECT_EQ(retired_cancel.error_if()->code(), ErrorCode::peer_offline);
  EXPECT_EQ(retired_cancel.error_if()->safe_detail(), "transfer_unknown");
  // Nothing was sent to B and nothing further happened to the entry.
  EXPECT_EQ(harness.right_session().diagnostics().business_frames_rejected, 1U)
      << "the failed cancel must not emit any frame toward the peer";
  EXPECT_EQ(files.events.size(), 3U)  // probing + offered + paused, nothing more
      << "a rejected cancel must not emit further transfer events";
  EXPECT_NE(harness.book->entries().find(id), harness.book->entries().end())
      << "the parked entry survives the failed cancel attempt";

  // Node-public-API (post-fix): with the session gone the service is erased
  // from file_services[peer], and cancel_file_transfer_strand falls back to
  // transfer_books[peer]: the parked entry stays visible through
  // Node::file_transfers and cancellable through Node::cancel_file_transfer
  // (one terminal cancelled event). Those contracts are pinned by the
  // Node-level tests below (ParkedTransferVisibleAndCancellable /
  // MessageRefusalThenPush); this service-level test keeps the retired
  // service's own transfer_unknown semantics.

  // The park happened purely at the service/teardown layer: the PeerSession
  // objects in this harness are untouched (in production the Node session
  // snapshot follows the transport/observer, not the book).
  EXPECT_NE(harness.left_session().diagnostics().state, PeerSessionState::closed);
  EXPECT_NE(harness.right_session().diagnostics().state, PeerSessionState::closed);
}

// ---------------------------------------------------------------------------
// 5: same-session follow-ups. (a) After a terminal the session stays fully
// usable and transfer ids are reusable. (b) On a LIVE session a locally
// paused transfer can still be cancelled (sender state exists), which is the
// contrast that isolates the book-only-parked gap.
// ---------------------------------------------------------------------------
TEST(M7Issue15Repro, SameSessionPushesAfterTerminalAndLivePauseCancel) {
  Issue15Pair::Options options;
  options.offer_timeout_milliseconds = 3'000U;
  options.max_concurrent_sends = 8U;
  Issue15Pair harness(options);
  FileEventLog files;
  harness.attach_left_file();
  files.bind(*harness.left_files);

  // (a) push #1 fails through the offer deadline.
  const auto source1 = Issue15Pair::make_source(harness.left_dir.path, "follow-a.bin",
                                                50'000U, 0x24U);
  const auto pushed1 = harness.left_files->push_file("inbox", "offer/a.bin", source1);
  ASSERT_TRUE(pushed1);
  const auto id1 = *pushed1.value_if();
  harness.run_sender_probe_and_manifest();
  harness.pump();
  harness.m6.left_clock += 4'000U;
  harness.left_files->prune();
  ASSERT_EQ(files.count_of(id1, FileTransferPhase::failed), 1U);
  ASSERT_TRUE(harness.book->entries().empty());

  // push #2 with a fresh id on the same session: admitted, offered, fails the
  // same way. The silent-drop peer does not poison the session.
  const auto source2 = Issue15Pair::make_source(harness.left_dir.path, "follow-b.bin",
                                                50'000U, 0x25U);
  const auto pushed2 = harness.left_files->push_file("inbox", "offer/b.bin", source2);
  ASSERT_TRUE(pushed2) << "a follow-up push on the same session must be admitted";
  const auto id2 = *pushed2.value_if();
  EXPECT_NE(id1, id2);
  harness.run_sender_probe_and_manifest();
  harness.pump();
  EXPECT_EQ(files.count_of(id2, FileTransferPhase::offered), 1U);

  // push #3 reusing transfer id #1 (terminal): REUSABLE — the book entry was
  // erased with the failed terminal, so the id is admitted as a brand-new
  // transfer. Observed semantics (issue #15 interest): no "already terminal"
  // guard exists at push time; a parked (book-held) id IS refused below.
  const auto pushed3 =
      harness.left_files->push_file("inbox", "offer/a-again.bin", source1, id1);
  RecordProperty("same_id_push_after_terminal",
                 pushed3 ? std::string{"admitted_as_new_transfer"}
                         : std::string{pushed3.error_if()->safe_detail()});
  ASSERT_TRUE(pushed3);
  EXPECT_EQ(*pushed3.value_if(), id1);
  EXPECT_EQ(harness.book->entries().count(id1), 1U);

  // (b) live pause then cancel: works, emits exactly one cancelled terminal
  // and one abort frame (which B drops silently, like everything else).
  const auto source4 = Issue15Pair::make_source(harness.left_dir.path, "follow-c.bin",
                                                50'000U, 0x26U);
  const auto pushed4 = harness.left_files->push_file("inbox", "offer/c.bin", source4);
  ASSERT_TRUE(pushed4);
  const auto id4 = *pushed4.value_if();
  harness.run_sender_probe_and_manifest();
  harness.pump();
  ASSERT_TRUE(harness.left_files->pause_transfer(id4));
  EXPECT_EQ(files.count_of(id4, FileTransferPhase::paused), 1U);
  const auto paused_entry = harness.book->entries().find(id4);
  ASSERT_NE(paused_entry, harness.book->entries().end());
  EXPECT_EQ(paused_entry->second.phase, FileTransferPhase::paused);

  const auto rejected = harness.left_files->push_file("inbox", "offer/c-again.bin",
                                                      source4, id4);
  ASSERT_FALSE(rejected);
  RecordProperty("same_id_push_while_parked_live", std::string{rejected.error_if()->safe_detail()});
  EXPECT_EQ(rejected.error_if()->safe_detail(), "transfer_id_in_use");

  const auto cancelled = harness.left_files->cancel_transfer(id4);
  ASSERT_TRUE(cancelled) << "a live paused transfer must remain cancellable";
  EXPECT_EQ(files.count_of(id4, FileTransferPhase::cancelled), 1U);
  EXPECT_EQ(files.terminal_count(id4), 1U);
  EXPECT_TRUE(harness.book->entries().find(id4) == harness.book->entries().end())
      << "cancel erased the paused book entry";
  // The abort frame crossed and was silently dropped on B (message + four
  // manifests + abort... exact count: id1 manifest, id2 manifest, id4
  // manifest, id4 abort; id3 never went on the wire).
  EXPECT_EQ(harness.right_session().diagnostics().business_frames_rejected, 4U);

  // After the cancel the id is free again.
  const auto reused = harness.left_files->push_file("inbox", "offer/c2.bin", source4, id4);
  RecordProperty("same_id_push_after_cancel",
                 reused ? std::string{"admitted_as_new_transfer"}
                        : std::string{reused.error_if()->safe_detail()});
  ASSERT_TRUE(reused);
}

// ---------------------------------------------------------------------------
// 6a: reconnection with a silent peer — the fresh session's attach() resumes
// the parked entry (re-manifest, same id) and, against a peer that still
// drops everything, the resumed transfer finally terminals through the offer
// deadline on the NEW session.
// ---------------------------------------------------------------------------
TEST(M7Issue15Repro, FreshSessionAttachResumesParkedEntryThenDeadlineFails) {
  auto book = std::make_shared<FileTransferBook>();

  Issue15Pair::Options first_options;
  first_options.book = book;
  first_options.offer_timeout_milliseconds = 5'000U;
  Issue15Pair first(first_options);
  FileEventLog first_log;
  first.attach_left_file();
  first_log.bind(*first.left_files);

  const auto source = Issue15Pair::make_source(first.left_dir.path, "resume-a.bin",
                                               50'000U, 0x27U);
  const auto pushed = first.left_files->push_file("inbox", "offer/resume-a.bin", source);
  ASSERT_TRUE(pushed);
  const auto id = *pushed.value_if();
  first.run_sender_probe_and_manifest();
  first.pump();
  ASSERT_EQ(first_log.count_of(id, FileTransferPhase::offered), 1U);
  first.left_files->handle_session_closed();  // session 1 dies while offered
  ASSERT_EQ(first_log.count_of(id, FileTransferPhase::paused), 1U);
  ASSERT_EQ(book->entries().count(id), 1U);

  // Session 2: same book, B again mounts nothing.
  Issue15Pair::Options second_options;
  second_options.book = book;
  second_options.offer_timeout_milliseconds = 5'000U;
  Issue15Pair second(second_options);
  FileEventLog second_log;
  // Bind the log BEFORE attach: attach() emits the resume probing event.
  second.make_left_file();
  second_log.bind(*second.left_files);
  second.attach_left_file();

  // attach() resumed the paused entry: probing event, same id, book moved.
  RecordProperty("resume_events", second_log.sequence_of(id));
  EXPECT_EQ(second_log.count_of(id, FileTransferPhase::probing), 1U)
      << "attach must resume the paused entry with a probing event";
  EXPECT_EQ(second.left_files->stats().sender_resumed, 1U);
  const auto resumed_entry = book->entries().find(id);
  ASSERT_NE(resumed_entry, book->entries().end());
  EXPECT_EQ(resumed_entry->second.phase, FileTransferPhase::probing);

  // The resumed manifest crosses and is silently dropped again; the NEW
  // session's offer deadline terminals the entry.
  second.run_sender_probe_and_manifest();
  second.pump();
  EXPECT_EQ(second_log.count_of(id, FileTransferPhase::offered), 1U);
  second.m6.left_clock += 6'000U;
  second.left_files->prune();
  RecordProperty("resume_final_events", second_log.sequence_of(id));
  EXPECT_EQ(second_log.count_of(id, FileTransferPhase::failed), 1U);
  EXPECT_EQ(second_log.terminal_count(id), 1U);
  EXPECT_TRUE(book->entries().empty())
      << "the parked entry terminalized on the new session";
  EXPECT_EQ(second.left_files->stats().sender_failed, 1U);
}

// ---------------------------------------------------------------------------
// 6b: reconnection with a serving peer — the resumed entry re-manifests, the
// new peer accepts, and the transfer commits end to end (M7-13 resume path).
// ---------------------------------------------------------------------------
TEST(M7Issue15Repro, FreshSessionAttachResumesParkedEntryAndCommits) {
  auto book = std::make_shared<FileTransferBook>();

  Issue15Pair::Options first_options;
  first_options.book = book;
  first_options.offer_timeout_milliseconds = 5'000U;
  Issue15Pair first(first_options);
  FileEventLog first_log;
  first.attach_left_file();
  first_log.bind(*first.left_files);

  const auto source = Issue15Pair::make_source(first.left_dir.path, "resume-b.bin",
                                               80'000U, 0x28U);
  const std::vector<std::byte> original = test::M7ServicePair::read_file_bytes(source);
  const auto pushed = first.left_files->push_file("inbox", "offer/resume-b.bin", source);
  ASSERT_TRUE(pushed);
  const auto id = *pushed.value_if();
  first.run_sender_probe_and_manifest();
  first.pump();
  ASSERT_EQ(first_log.count_of(id, FileTransferPhase::offered), 1U);
  first.left_files->handle_session_closed();
  ASSERT_EQ(book->entries().count(id), 1U);

  // Session 2: B now serves files and grants file.push:inbox.
  Issue15Pair::Options second_options;
  second_options.book = book;
  second_options.offer_timeout_milliseconds = 5'000U;
  second_options.right_file = true;
  second_options.right_scopes = {"message.send", "file.push:inbox", "file.pull:inbox"};
  Issue15Pair second(second_options);
  FileEventLog second_log;
  // Bind the log BEFORE attach: attach() emits the resume probing event.
  second.make_left_file();
  second_log.bind(*second.left_files);
  second.attach_left_file();
  second.attach_right_file();

  second.cycle();
  RecordProperty("resume_events", second_log.sequence_of(id));
  EXPECT_EQ(second_log.count_of(id, FileTransferPhase::probing), 1U);
  EXPECT_EQ(second_log.count_of(id, FileTransferPhase::committed), 1U)
      << "the resumed transfer must commit against a serving peer";
  EXPECT_EQ(second_log.terminal_count(id), 1U);
  EXPECT_TRUE(book->entries().empty());
  EXPECT_EQ(second.left_files->stats().sender_committed, 1U);
  const auto landed = second.right_dir.path / "inbox" / "offer" / "resume-b.bin";
  ASSERT_TRUE(std::filesystem::exists(landed));
  EXPECT_EQ(test::M7ServicePair::read_file_bytes(landed), original);
}

// ---------------------------------------------------------------------------
// Node-level harness (adapted from m5_basic_communication_test.cpp): a real
// two-node LAN pair. A (first) runs with basic communication ENABLED, B
// (second) with basic communication DISABLED — B's pairing_restricted session
// takes business violations on A's message/file frames, which is the
// issue #15 refusing-receiver shape at the Node level.
// ---------------------------------------------------------------------------

constexpr const char* kIssue15ApplicationId = "com.example.m7-issue15";
constexpr std::string_view kIssue15InboxRoot = "inbox";

bool environment_requires_lan_interfaces() {
  const char* value = std::getenv("HEYAKI_REQUIRE_LAN_INTERFACES");
  return value != nullptr && std::string_view{value} == "1";
}

LanConfiguration issue15_fast_lan_only() {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  return configuration;
}

FileRootConfig issue15_inbox_root(const std::filesystem::path& directory) {
  FileRootConfig root;
  root.name = std::string{kIssue15InboxRoot};
  root.directory = directory;
  root.max_file_bytes = 1024U * 1024U;
  root.max_total_bytes = 4U * 1024U * 1024U;
  root.max_concurrent_receives = 2U;
  return root;
}

// Per-test state directory under the CTest-provided state root.
class Issue15StateDir {
 public:
  Issue15StateDir() {
    const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
    path_ = std::filesystem::path{HEYAKI_M7_ISSUE15_TEST_STATE_DIR} /
            (std::string{"issue15-"} + info->name());
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
    std::filesystem::create_directories(path_);
    std::filesystem::permissions(path_.parent_path(),
                                 std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    std::filesystem::permissions(path_, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
  }
  ~Issue15StateDir() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }
  Issue15StateDir(const Issue15StateDir&) = delete;
  Issue15StateDir& operator=(const Issue15StateDir&) = delete;
  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

 private:
  std::filesystem::path path_;
};

class NodeFileEventRecorder {
 public:
  void attach(Node& node) {
    node.set_file_event_observer(
        [this](const DeviceEndpointKey&, const FileTransferEvent& event) {
          const std::lock_guard<std::mutex> guard{mutex_};
          events_.push_back(event);
        });
  }
  [[nodiscard]] std::size_t count_of(const TransferId& id,
                                     FileTransferPhase phase) const {
    const std::lock_guard<std::mutex> guard{mutex_};
    return static_cast<std::size_t>(std::count_if(
        events_.begin(), events_.end(), [&](const FileTransferEvent& event) {
          return event.transfer_id == id && event.phase == phase;
        }));
  }
  [[nodiscard]] std::size_t terminal_count(const TransferId& id) const {
    const std::lock_guard<std::mutex> guard{mutex_};
    std::size_t terminals = 0U;
    for (const auto& event : events_) {
      if (event.transfer_id != id) continue;
      if (event.phase == FileTransferPhase::committed ||
          event.phase == FileTransferPhase::failed ||
          event.phase == FileTransferPhase::cancelled) {
        ++terminals;
      }
    }
    return terminals;
  }
  [[nodiscard]] std::optional<FileTransferEvent> last_of(
      const TransferId& id, FileTransferPhase phase) const {
    const std::lock_guard<std::mutex> guard{mutex_};
    std::optional<FileTransferEvent> found;
    for (const auto& event : events_) {
      if (event.transfer_id == id && event.phase == phase) found = event;
    }
    return found;
  }
  [[nodiscard]] std::size_t total() const {
    const std::lock_guard<std::mutex> guard{mutex_};
    return events_.size();
  }

 private:
  mutable std::mutex mutex_;
  std::vector<FileTransferEvent> events_;
};

class NodeAckRecorder {
 public:
  void attach(Node& node) {
    node.set_message_ack_observer(
        [this](const DeviceEndpointKey&, const MessageId& message_id,
               MessageDeliveryEvent event, std::optional<Error>) {
          const std::lock_guard<std::mutex> guard{mutex_};
          events_.push_back(AckRecord{message_id, event, std::nullopt});
        });
  }
  [[nodiscard]] bool has_event_for(const MessageId& id,
                                   MessageDeliveryEvent event) const {
    const std::lock_guard<std::mutex> guard{mutex_};
    return std::any_of(events_.begin(), events_.end(),
                       [&](const AckRecord& record) {
                         return record.message_id == id && record.event == event;
                       });
  }

 private:
  mutable std::mutex mutex_;
  std::vector<AckRecord> events_;
};

struct Issue15NodePair {
  std::optional<ProfileStore> first_store;
  std::optional<ProfileStore> second_store;
  std::optional<Node> first;
  std::optional<Node> second;
  DeviceEndpointKey first_key;
  DeviceEndpointKey second_key;
};

Result<ProfileStore> issue15_profile(const std::filesystem::path& sqlite_path) {
  ProfileOpenOptions options;
  options.secret_backend.prefer_os_backend = false;
  auto profile = ProfileStore::create(sqlite_path, options);
  if (!profile) {
    return profile;
  }
  PasswordVerifier verifier{.format_version = 1U,
                            .parameters = PasswordHashParameters{},
                            .encoded = "$argon2id$v=19$m=65536,t=2,p=1$test$test"};
  PairingPolicy policy{};
  policy.default_scopes = {};
  LocalProfileInitialization initialization{
      .application_id = kIssue15ApplicationId,
      .password_verifier = std::move(verifier),
      .password_generation = 1U,
      .pairing_policy = policy,
      .lan = issue15_fast_lan_only()};
  auto initialized = profile.value_if()->initialize_local(initialization);
  if (!initialized) {
    return Result<ProfileStore>::failure(*initialized.error_if());
  }
  return profile;
}

NodeConfig issue15_node_config(ProfileStore& store, bool basic,
                               std::vector<FileRootConfig> roots,
                               std::chrono::milliseconds file_offer_timeout) {
  return NodeConfig{.profile = &store,
                    .runtime = nullptr,
                    .application_id = kIssue15ApplicationId,
                    .lan_override = issue15_fast_lan_only(),
                    .runtime_config = RuntimeConfig{},
                    .signaling_validator = {},
                    .signaling_handler = {},
                    .relay_override = std::nullopt,
                    .path_policy_override = std::nullopt,
                    .pairing_failure_threshold = 0U,
                    .pairing_backoff_base = std::chrono::milliseconds{0},
                    .pairing_backoff_max = std::chrono::milliseconds{0},
                    .pairing_grant_ttl_milliseconds = 0U,
                    .basic_communication = basic,
                    .pairing_deadline = std::chrono::milliseconds{0},
                    .event_subscriber_queue_items = 0U,
                    .event_max_subscriptions_per_peer = 0U,
                    .file_receive_roots = std::move(roots),
                    .file_max_peer_receive_bytes = 0U,
                    .file_offer_timeout = file_offer_timeout,
                    .shell_profiles = {},
                    .gateway_profiles = {},
                    .gateway_confirm_sink = {}};
}

template <typename Predicate>
bool issue15_wait_until(Predicate&& predicate, std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  kairo::comm::PhaseGate poll{"issue15-poll"};
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    (void)poll.wait_for(1U, std::chrono::milliseconds{2});
  }
  return predicate();
}

bool issue15_discovered(const Node& node, const DeviceEndpointKey& peer) {
  const auto entries = node.endpoints();
  return std::any_of(entries.begin(), entries.end(),
                     [&](const auto& entry) { return entry.key == peer; });
}

std::optional<NodePeerSessionSnapshot> issue15_latest_session(
    const Node& node, const DeviceEndpointKey& peer) {
  const auto sessions = node.peer_sessions();
  std::optional<NodePeerSessionSnapshot> live;
  std::optional<NodePeerSessionSnapshot> closed;
  for (const auto& session : sessions) {
    if (session.peer != peer) continue;
    if (session.state != NodePeerSessionState::closed && !live.has_value()) {
      live = session;
    }
    if (session.state == NodePeerSessionState::closed) {
      closed = session;
    }
  }
  return live.has_value() ? live : closed;
}

// Brings up the grant-less LAN pair: A (first) basic communication ON, B
// (second) basic communication OFF. Both sessions land pairing_restricted.
// Returns false when the environment cannot host the pair.
bool issue15_establish_pair(Issue15NodePair& pair, const std::filesystem::path& root,
                            std::chrono::milliseconds first_file_offer_timeout) {
  auto first_profile = issue15_profile(root / "initiator" / "profile.sqlite");
  auto second_profile = issue15_profile(root / "target" / "profile.sqlite");
  if (!first_profile || !second_profile) {
    return false;
  }
  pair.first_store.emplace(std::move(*first_profile.value_if()));
  pair.second_store.emplace(std::move(*second_profile.value_if()));

  std::filesystem::create_directories(root / "first-inbox");
  std::filesystem::create_directories(root / "second-inbox");
  auto first_node = Node::create(issue15_node_config(
      *pair.first_store, true, {issue15_inbox_root(root / "first-inbox")},
      first_file_offer_timeout));
  auto second_node = Node::create(issue15_node_config(
      *pair.second_store, false, {issue15_inbox_root(root / "second-inbox")},
      std::chrono::milliseconds{0}));
  if (!first_node || !second_node) {
    return false;
  }
  pair.first.emplace(std::move(*first_node.value_if()));
  pair.second.emplace(std::move(*second_node.value_if()));
  if (pair.first.value().snapshot().interfaces.empty() ||
      pair.second.value().snapshot().interfaces.empty()) {
    return false;
  }
  pair.first_key = DeviceEndpointKey{pair.first.value().snapshot().device_id,
                                     pair.first.value().snapshot().endpoint_id};
  pair.second_key = DeviceEndpointKey{pair.second.value().snapshot().device_id,
                                      pair.second.value().snapshot().endpoint_id};

  if (!issue15_wait_until(
          [&] {
            return issue15_discovered(pair.first.value(), pair.second_key) &&
                   issue15_discovered(pair.second.value(), pair.first_key);
          },
          std::chrono::milliseconds{8000})) {
    return false;
  }
  if (!pair.first.value().connect_lan(pair.second_key)) {
    return false;
  }
  return issue15_wait_until(
      [&] {
        const auto left = issue15_latest_session(pair.first.value(), pair.second_key);
        const auto right =
            issue15_latest_session(pair.second.value(), pair.first_key);
        return left.has_value() &&
               left->state == NodePeerSessionState::pairing_restricted &&
               right.has_value() &&
               right->state == NodePeerSessionState::pairing_restricted;
      },
      std::chrono::seconds{12});
}

std::filesystem::path issue15_write_source(const std::filesystem::path& root,
                                           std::string_view name,
                                           std::size_t size) {
  const auto path = root / std::filesystem::path{name};
  std::ofstream stream{path, std::ios::binary | std::ios::trunc};
  for (std::size_t index = 0U; index < size; ++index) {
    const auto byte = static_cast<char>((index * 13U + 0x41U) & 0xFFU);
    stream.write(&byte, 1);
  }
  return path;
}

// Node-level fixture: guarantees both nodes are shut down on EVERY exit
// path (including ASSERT aborts) before the Node objects are destroyed, and
// the recorders are fixture members declared BEFORE the pair so they are
// destroyed AFTER the nodes — a live Node whose observer still points at a
// destroyed recorder is a use-after-free.
class M7Issue15NodeTest : public ::testing::Test {
 protected:
  void TearDown() override {
    if (pair.first.has_value()) {
      (void)pair.first.value().shutdown();
    }
    if (pair.second.has_value()) {
      (void)pair.second.value().shutdown();
    }
  }

  NodeFileEventRecorder first_files;
  NodeAckRecorder first_acks;
  Issue15StateDir state;
  Issue15NodePair pair;
};

// 7: the offer deadline terminals a push into the silent receiver with
// exactly one failed terminal while BOTH session snapshots stay
// pairing_restricted (the bounded "failed" acceptance of issue #15).
TEST_F(M7Issue15NodeTest, NodeLevelOfferDeadlineTerminalsSilentReceiverPush) {
  if (!issue15_establish_pair(pair, state.path(), std::chrono::milliseconds{700})) {
    if (environment_requires_lan_interfaces()) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  first_files.attach(pair.first.value());

  const auto source = issue15_write_source(state.path(), "deadline-source.bin", 50'000U);
  const auto pushed = pair.first.value().push_file(
      pair.second_key, std::string{kIssue15InboxRoot}, "regression/deadline.bin",
      source);
  ASSERT_TRUE(pushed) << pushed.error_if()->safe_detail();
  const auto id = *pushed.value_if();

  // Exactly one failed terminal inside the window plus tick slack.
  ASSERT_TRUE(issue15_wait_until(
                  [&] { return first_files.terminal_count(id) > 0U; },
                  std::chrono::seconds{3}))
      << "the unanswered push must terminal bounded (offer deadline)";
  EXPECT_EQ(first_files.terminal_count(id), 1U)
      << "the offer deadline must fire exactly one terminal";
  const auto failed = first_files.last_of(id, FileTransferPhase::failed);
  ASSERT_TRUE(failed.has_value());
  ASSERT_TRUE(failed->error.has_value());
  RecordProperty("file_events", std::string("probing,offered,failed"));
  RecordProperty("file_terminal_error", error_text(failed->error));
  EXPECT_EQ(failed->error->code(), ErrorCode::timeout);
  EXPECT_EQ(failed->error->safe_detail(), "offer_expired");
  ASSERT_TRUE(failed->error->underlying_code().has_value());
  EXPECT_EQ(*failed->error->underlying_code(),
            static_cast<std::int64_t>(StableStatus::deadline_exceeded));

  // Sender-side accepted gate: manifest only, zero bytes left the sender.
  const bool stats_settled = issue15_wait_until(
      [&] {
        const auto stats = pair.first.value().service_diagnostics().file;
        return stats.manifests_sent == 1U && stats.chunks_sent == 0U &&
               stats.completes_sent == 0U && stats.sender_failed == 1U;
      },
      std::chrono::seconds{2});
  EXPECT_TRUE(stats_settled) << "initiator file stats never settled";

  // Both session snapshots stay pairing_restricted: the session body is
  // healthy — the transfer resolved on its own bounded window.
  const auto first_session =
      issue15_latest_session(pair.first.value(), pair.second_key);
  ASSERT_TRUE(first_session.has_value());
  EXPECT_EQ(first_session->state, NodePeerSessionState::pairing_restricted);
  const auto second_session =
      issue15_latest_session(pair.second.value(), pair.first_key);
  ASSERT_TRUE(second_session.has_value());
  EXPECT_EQ(second_session->state, NodePeerSessionState::pairing_restricted);

  // Terminal transfer: nothing parked, nothing visible (book entry erased).
  EXPECT_TRUE(pair.first.value().file_transfers(pair.second_key).empty());

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// 8 (the fix): a push whose offer is still pending, then the session ends
// (Node::close_lan — the harness-provided deterministic session teardown).
// The transfer parks paused in the transfer book; post-fix it stays VISIBLE
// through Node::file_transfers and CANCELLABLE through
// Node::cancel_file_transfer with exactly one terminal cancelled event; the
// book entry disappears and a second cancel reports transfer_unknown.
// Pre-fix, file_transfers returned {} and cancel returned
// peer_offline/"peer_session_missing".
TEST_F(M7Issue15NodeTest, NodeLevelParkedTransferVisibleAndCancellableAfterSessionEnd) {
  // Offer timeout 0 keeps the service default (30 s): the deadline must NOT
  // fire during the test — the session end is the bounded resolver here.
  if (!issue15_establish_pair(pair, state.path(), std::chrono::milliseconds{0})) {
    if (environment_requires_lan_interfaces()) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  first_files.attach(pair.first.value());

  const auto source = issue15_write_source(state.path(), "parked-source.bin", 50'000U);
  const auto pushed = pair.first.value().push_file(
      pair.second_key, std::string{kIssue15InboxRoot}, "regression/parked.bin",
      source);
  ASSERT_TRUE(pushed) << pushed.error_if()->safe_detail();
  const auto id = *pushed.value_if();

  ASSERT_TRUE(issue15_wait_until(
                  [&] { return first_files.count_of(id, FileTransferPhase::offered) == 1U; },
                  std::chrono::seconds{10}))
      << "the push must reach the offered phase";
  EXPECT_EQ(first_files.terminal_count(id), 0U);

  // While the session is alive the live service reports the transfer.
  const auto live_transfers = pair.first.value().file_transfers(pair.second_key);
  ASSERT_EQ(live_transfers.size(), 1U);
  EXPECT_EQ(live_transfers.front().transfer_id, id);
  EXPECT_EQ(live_transfers.front().phase, FileTransferPhase::offered);

  // Force the session end deterministically: shut the refusing peer's node
  // down — its transports close, A's session dies, and A's Node tears the
  // peer services down (the handle_session_closed park path). close_lan only
  // retires the signaling TLS connection and leaves an established
  // PeerSession untouched (measured: the session snapshot stayed
  // pairing_restricted for 6+ s with zero further file events), so it is NOT
  // a session-end forcing function here.
  const auto peer_down = pair.second.value().shutdown();
  ASSERT_TRUE(peer_down.stopped) << "peer shutdown failed";

  // The session ends -> teardown parks the offered sender as paused.
  ASSERT_TRUE(issue15_wait_until(
                  [&] { return first_files.count_of(id, FileTransferPhase::paused) == 1U; },
                  std::chrono::seconds{10}))
      << "the session end must park the offered transfer as paused";
  EXPECT_EQ(first_files.terminal_count(id), 0U)
      << "the park must not terminal the transfer";
  const auto paused = first_files.last_of(id, FileTransferPhase::paused);
  ASSERT_TRUE(paused.has_value());
  ASSERT_TRUE(paused->error.has_value());
  RecordProperty("paused_event_error", error_text(paused->error));
  EXPECT_EQ(paused->error->code(), ErrorCode::transport);
  EXPECT_EQ(paused->error->safe_detail(), "session_closed");
  const auto first_session =
      issue15_latest_session(pair.first.value(), pair.second_key);
  ASSERT_TRUE(first_session.has_value());
  EXPECT_EQ(first_session->state, NodePeerSessionState::closed);

  // THE FIX: the parked transfer is visible through the public API.
  const auto parked = pair.first.value().file_transfers(pair.second_key);
  ASSERT_EQ(parked.size(), 1U)
      << "the parked book entry must be visible through file_transfers";
  RecordProperty("parked_summary_phase",
                 std::string{file_transfer_phase_name(parked.front().phase)});
  EXPECT_EQ(parked.front().transfer_id, id);
  EXPECT_EQ(parked.front().direction, FileTransferDirection::push);
  EXPECT_EQ(parked.front().phase, FileTransferPhase::paused);
  EXPECT_EQ(parked.front().root, std::string{kIssue15InboxRoot});
  EXPECT_EQ(parked.front().logical_name, "regression/parked.bin");
  EXPECT_EQ(parked.front().bytes_done, 0U);
  EXPECT_EQ(parked.front().bytes_total, 50'000U);
  EXPECT_TRUE(parked.front().sender_role);

  // THE FIX: the parked transfer is cancellable; the cancel retires the book
  // entry and reports exactly one terminal cancelled event.
  const auto cancelled = pair.first.value().cancel_file_transfer(pair.second_key, id);
  ASSERT_TRUE(cancelled) << cancelled.error_if()->safe_detail();
  EXPECT_EQ(first_files.terminal_count(id), 1U);
  EXPECT_EQ(first_files.count_of(id, FileTransferPhase::cancelled), 1U);
  const auto cancelled_event = first_files.last_of(id, FileTransferPhase::cancelled);
  ASSERT_TRUE(cancelled_event.has_value());
  EXPECT_FALSE(cancelled_event->error.has_value())
      << "the parked cancel carries the FileService cancelled-event shape";
  EXPECT_EQ(cancelled_event->direction, FileTransferDirection::push);
  EXPECT_EQ(cancelled_event->root, std::string{kIssue15InboxRoot});
  EXPECT_EQ(cancelled_event->logical_name, "regression/parked.bin");
  EXPECT_EQ(cancelled_event->bytes_total, 50'000U);

  // The book entry is gone.
  EXPECT_TRUE(pair.first.value().file_transfers(pair.second_key).empty());

  // A second cancel is transfer_unknown, never a second terminal.
  const auto again = pair.first.value().cancel_file_transfer(pair.second_key, id);
  ASSERT_FALSE(again);
  RecordProperty("second_cancel_error", std::string{again.error_if()->safe_detail()});
  EXPECT_EQ(again.error_if()->code(), ErrorCode::peer_offline);
  EXPECT_EQ(again.error_if()->safe_detail(), "transfer_unknown");
  EXPECT_EQ(first_files.terminal_count(id), 1U);
  EXPECT_EQ(first_files.total(), 4U)  // probing, offered, paused, cancelled
      << "no further events may follow the parked cancel";

  // The session is gone: a fresh push is refused locally and bounded.
  const auto pushed_again = pair.first.value().push_file(
      pair.second_key, std::string{kIssue15InboxRoot}, "regression/after-close.bin",
      source);
  ASSERT_FALSE(pushed_again);
  EXPECT_EQ(pushed_again.error_if()->code(), ErrorCode::peer_offline);
  EXPECT_EQ(pushed_again.error_if()->safe_detail(), "peer_session_missing");

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// 9: the full issue #15 sequence on one pair — message refusal fails bounded
// (ack-TTL), the follow-up push parks when the session ends, and the parked
// cancel works. Every step terminates in bounded time.
TEST_F(M7Issue15NodeTest, NodeLevelMessageRefusalThenPushEveryStepBounded) {
  if (!issue15_establish_pair(pair, state.path(), std::chrono::milliseconds{0})) {
    if (environment_requires_lan_interfaces()) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  first_acks.attach(pair.first.value());
  first_files.attach(pair.first.value());

  // Step 1: A -> B text message. B (basic communication disabled) never ACKs;
  // the message resolves through the bounded ack-TTL.
  MessageEnvelope outbound;
  outbound.type = "text";
  outbound.delivery_mode = MessageDeliveryMode::peer_acked;
  outbound.ttl_milliseconds = 1000U;
  outbound.payload = text_bytes("issue15 message refusal");
  const auto sent = pair.first.value().send_message(pair.second_key, outbound);
  ASSERT_TRUE(sent) << sent.error_if()->safe_detail();
  ASSERT_TRUE(issue15_wait_until(
                  [&] {
                    return first_acks.has_event_for(*sent.value_if(),
                                                    MessageDeliveryEvent::ack_timeout);
                  },
                  std::chrono::seconds{6}))
      << "the refused message must terminal bounded via ack-TTL";
  EXPECT_FALSE(first_acks.has_event_for(*sent.value_if(),
                                        MessageDeliveryEvent::acked));

  // The session bodies are still alive after the message refusal.
  const auto first_session =
      issue15_latest_session(pair.first.value(), pair.second_key);
  ASSERT_TRUE(first_session.has_value());
  EXPECT_EQ(first_session->state, NodePeerSessionState::pairing_restricted);
  const auto second_session =
      issue15_latest_session(pair.second.value(), pair.first_key);
  ASSERT_TRUE(second_session.has_value());
  EXPECT_EQ(second_session->state, NodePeerSessionState::pairing_restricted);

  // Step 2: the follow-up push is admitted while the session is alive.
  const auto source = issue15_write_source(state.path(), "after-msg-source.bin",
                                           50'000U);
  const auto pushed = pair.first.value().push_file(
      pair.second_key, std::string{kIssue15InboxRoot}, "regression/after-msg.bin",
      source);
  ASSERT_TRUE(pushed) << pushed.error_if()->safe_detail();
  const auto id = *pushed.value_if();
  ASSERT_TRUE(issue15_wait_until(
                  [&] { return first_files.count_of(id, FileTransferPhase::offered) == 1U; },
                  std::chrono::seconds{10}));

  // Step 3: the session ends (peer node shutdown — the deterministic
  // teardown force; close_lan does not end an established session); the push
  // parks paused without a terminal.
  const auto peer_down = pair.second.value().shutdown();
  ASSERT_TRUE(peer_down.stopped) << "peer shutdown failed";
  ASSERT_TRUE(issue15_wait_until(
                  [&] { return first_files.count_of(id, FileTransferPhase::paused) == 1U; },
                  std::chrono::seconds{10}));
  EXPECT_EQ(first_files.terminal_count(id), 0U);

  // Step 4: the parked transfer is visible and cancellable (the fix).
  const auto parked = pair.first.value().file_transfers(pair.second_key);
  ASSERT_EQ(parked.size(), 1U);
  EXPECT_EQ(parked.front().transfer_id, id);
  EXPECT_EQ(parked.front().phase, FileTransferPhase::paused);
  const auto cancelled = pair.first.value().cancel_file_transfer(pair.second_key, id);
  ASSERT_TRUE(cancelled) << cancelled.error_if()->safe_detail();
  EXPECT_EQ(first_files.count_of(id, FileTransferPhase::cancelled), 1U);
  EXPECT_EQ(first_files.terminal_count(id), 1U);
  EXPECT_TRUE(pair.first.value().file_transfers(pair.second_key).empty());
  const auto again = pair.first.value().cancel_file_transfer(pair.second_key, id);
  ASSERT_FALSE(again);
  EXPECT_EQ(again.error_if()->safe_detail(), "transfer_unknown");

  RecordProperty("message_terminal_event", "ack_timeout");
  RecordProperty("file_events", std::string("probing,offered,paused,cancelled"));

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  // The peer node was already shut down mid-test (double shutdown is a
  // no-op report).
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

}  // namespace
}  // namespace heyaki
