#pragma once

// M7 test harness: extends the M6 loopback session pair with the event and
// file services. Tests drive frames explicitly through pump(), control
// executor timing through manual task queues (general CPU, blocking file
// I/O, strand posts), and use per-test temporary root directories so file
// transfers touch real (sandboxed) filesystems.

#include "m6_support.hpp"
#include "event_service.hpp"
#include "file_service.hpp"
#include "peer_session.hpp"

#include <executor/comm/topic.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace heyaki::test {

// Manual blocking-I/O dispatch double: the deterministic stand-in for the
// runtime's dedicated file worker (M7-12). Tasks run only when the test
// calls run_all(); cooperative cancellation mirrors the queued-stop shape.
struct ManualBlockingDispatch {
  struct Entry {
    std::function<void(executor::StopToken)> task;
    bool done{false};
    bool cancel_requested{false};
  };
  std::deque<std::shared_ptr<Entry>> tasks;
  bool admit{true};

  BlockingDispatch dispatcher() {
    return [this](std::string_view, CancellableTask task) {
      if (!admit) {
        return Result<TaskCancelRequest>::failure(
            Error{ErrorCode::resource_exhausted, "test", "dispatch_rejected"});
      }
      auto entry = std::make_shared<Entry>();
      entry->task = std::move(task);
      tasks.push_back(entry);
      return Result<TaskCancelRequest>::success(
          [entry]() -> executor::TaskCancellationResponse {
            entry->cancel_requested = true;
            return {executor::TaskCancellationResult::RequestedRunning};
          });
    };
  }

  void run_all() {
    std::size_t guard = 0U;
    while (!tasks.empty() && guard++ < 1000U) {
      auto entry = std::move(tasks.front());
      tasks.pop_front();
      if (entry->done) {
        continue;
      }
      entry->done = true;
      executor::StopSource source;
      if (entry->cancel_requested) {
        source.request_stop();
      }
      entry->task(source.get_token());
    }
  }

  [[nodiscard]] bool has_pending() const noexcept {
    return std::any_of(tasks.begin(), tasks.end(),
                       [](const auto& entry) { return !entry->done; });
  }
};

// Per-test temporary directory (auto-removed).
struct M7TempDir {
  std::filesystem::path path;

  M7TempDir() {
    std::random_device device;
    std::string name = "heyaki-m7-" + std::to_string(device()) + "-" +
                       std::to_string(::getpid());
    path = std::filesystem::temp_directory_path() / name;
    std::filesystem::create_directories(path);
  }
  ~M7TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }
  M7TempDir(const M7TempDir&) = delete;
  M7TempDir& operator=(const M7TempDir&) = delete;
};

// One M7 service pair on top of the M6 loopback pair: event + file services
// attached on both sides with injectable configs, scopes, and temp roots.
struct M7ServicePair {
  struct Options {
    std::vector<std::string> left_scopes;
    std::vector<std::string> right_scopes;
    EventServiceConfig left_event;
    EventServiceConfig right_event;
    FileServiceConfig left_file;
    FileServiceConfig right_file;
  };

  M7TempDir left_root_dir;
  M7TempDir right_root_dir;
  M6ServicePair m6;
  ManualDispatch left_general;
  ManualDispatch right_general;
  ManualBlockingDispatch left_blocking;
  ManualBlockingDispatch right_blocking;
  ManualPoster left_poster;
  ManualPoster right_poster;

  std::shared_ptr<EventService> left_events;
  std::shared_ptr<EventService> right_events;
  std::shared_ptr<FileService> left_files;
  std::shared_ptr<FileService> right_files;
  std::shared_ptr<FileTransferBook> left_book = std::make_shared<FileTransferBook>();
  std::shared_ptr<FileTransferBook> right_book = std::make_shared<FileTransferBook>();
  executor::comm::Topic<LocalEventMessage> left_local_topic{"heyaki-test-left"};
  executor::comm::Topic<LocalEventMessage> right_local_topic{"heyaki-test-right"};

  struct EventSinkContext {
    std::function<void(const DeviceEndpointKey&, std::string_view, const EventItemBody&)>
        inbound;
  };
  struct FileSinkContext {
    std::function<void(const DeviceEndpointKey&, const FileTransferEvent&)> events;
  };
  EventSinkContext left_event_sinks;
  EventSinkContext right_event_sinks;
  FileSinkContext left_file_sinks;
  FileSinkContext right_file_sinks;

  explicit M7ServicePair() : M7ServicePair(Options{}) {}

  explicit M7ServicePair(Options options)
      : m6([&] {
           // Scopes freeze at session creation: hand them to the M6 pair's
           // constructor instead of mutating after the fact.
           M6ServicePair::Options m6_options;
           if (!options.left_scopes.empty()) {
             m6_options.left_scopes = options.left_scopes;
           }
           if (!options.right_scopes.empty()) {
             m6_options.right_scopes = options.right_scopes;
           }
           return M6ServicePair(std::move(m6_options));
         }()) {
    // Both sides share the default event/file config unless overridden; the
    // default roots map "inbox" into each side's temp directory.
    // Empty root lists get the default "inbox" root; roots a test pre-seeded
    // keep their quotas and only get their directory filled in.
    auto fill_roots = [&](FileServiceConfig& config, const M7TempDir& dir) {
      if (config.receive_roots.empty()) {
        config.receive_roots.push_back(FileRootConfig{
            .name = "inbox",
            .directory = {},
            .max_file_bytes = 64ULL * 1024ULL * 1024ULL,
            .max_total_bytes = 128ULL * 1024ULL * 1024ULL,
            .max_concurrent_receives = 2U});
      }
      for (auto& root : config.receive_roots) {
        if (root.directory.empty()) {
          root.directory = dir.path / root.name;
        }
      }
    };
    fill_roots(options.left_file, left_root_dir);
    fill_roots(options.right_file, right_root_dir);
    for (const auto& root : options.left_file.receive_roots) {
      std::filesystem::create_directories(root.directory);
    }
    for (const auto& root : options.right_file.receive_roots) {
      std::filesystem::create_directories(root.directory);
    }

    attach_m7(std::move(options));
  }

  [[nodiscard]] DeviceEndpointKey left_key() const { return m6.left_key(); }
  [[nodiscard]] DeviceEndpointKey right_key() const { return m6.right_key(); }
  [[nodiscard]] PeerSession& left_session() { return *m6.left; }
  [[nodiscard]] PeerSession& right_session() { return *m6.right; }

  void attach_m7(const Options& options) {
    left_events = std::make_shared<EventService>(
        *m6.left, m6.left_key(), m6.left_identity.value_if()->device_id(),
        options.left_event, left_general.dispatcher(), m6.scope_check(m6.left),
        left_local_topic, [this] { return m6.left_clock; });
    left_events->set_inbound_sink(&sink_event_inbound, &left_event_sinks);
    ASSERT_TRUE(left_events->attach());
    right_events = std::make_shared<EventService>(
        *m6.right, m6.right_key(), m6.right_identity.value_if()->device_id(),
        options.right_event, right_general.dispatcher(), m6.scope_check(m6.right),
        right_local_topic, [this] { return m6.right_clock; });
    right_events->set_inbound_sink(&sink_event_inbound, &right_event_sinks);
    ASSERT_TRUE(right_events->attach());

    left_files = std::make_shared<FileService>(
        *m6.left, m6.left_key(), options.left_file, left_book,
        left_general.dispatcher(), left_blocking.dispatcher(), m6.scope_check(m6.left),
        left_poster.poster(), [this] { return m6.left_clock; });
    left_files->set_event_sink(&sink_file_event, &left_file_sinks);
    ASSERT_TRUE(left_files->attach());
    right_files = std::make_shared<FileService>(
        *m6.right, m6.right_key(), options.right_file, right_book,
        right_general.dispatcher(), right_blocking.dispatcher(),
        m6.scope_check(m6.right), right_poster.poster(), [this] { return m6.right_clock; });
    right_files->set_event_sink(&sink_file_event, &right_file_sinks);
    ASSERT_TRUE(right_files->attach());
    m6.pump();
  }

  static void sink_event_inbound(void* context, const DeviceEndpointKey& peer,
                                 std::string_view pattern, const EventItemBody& item) {
    auto& sinks = *static_cast<EventSinkContext*>(context);
    if (sinks.inbound) sinks.inbound(peer, pattern, item);
  }

  static void sink_file_event(void* context, const DeviceEndpointKey& peer,
                              const FileTransferEvent& event) {
    auto& sinks = *static_cast<FileSinkContext*>(context);
    if (sinks.events) sinks.events(peer, event);
  }

  // Runs every executor flavor (general CPU, blocking I/O, strand posts) and
  // frame delivery until quiescence. File transfers need several
  // probe->manifest->accept->read->hash->write->complete round trips.
  void cycle(int rounds = 64) {
    for (int round = 0; round < rounds; ++round) {
      const auto before = pending_work();
      left_general.run_all();
      right_general.run_all();
      left_blocking.run_all();
      right_blocking.run_all();
      left_poster.run_all();
      right_poster.run_all();
      m6.pump();
      const auto after = pending_work();
      if (after == 0U && round > 2) {
        // Frames may still be in the loopback queues; one more pump round.
        m6.pump();
        return;
      }
      (void)before;
    }
  }

  [[nodiscard]] std::size_t pending_work() const {
    return left_general.tasks.size() + right_general.tasks.size() +
           left_blocking.has_pending() + right_blocking.has_pending() +
           left_poster.posts.size() + right_poster.posts.size();
  }

  [[nodiscard]] std::uint32_t event_channel_of(const PeerSession& side) const {
    for (const auto& snapshot : side.channels().channel_snapshots()) {
      if (snapshot.domain == session::ChannelDomain::event) return snapshot.channel_id;
    }
    return 0U;
  }

  [[nodiscard]] std::uint32_t file_channel_of(const PeerSession& side) const {
    for (const auto& snapshot : side.channels().channel_snapshots()) {
      if (snapshot.domain == session::ChannelDomain::file) return snapshot.channel_id;
    }
    return 0U;
  }

  void inject_frame(PeerSession& from, std::uint32_t channel_id, std::uint8_t type,
                    std::span<const std::byte> payload) {
    m6.inject_frame(from, channel_id, type, payload);
  }

  // Writes a source file and returns its path + content digest inputs.
  static std::filesystem::path make_source_file(const std::filesystem::path& dir,
                                                std::string_view name,
                                                std::size_t size, std::uint8_t seed) {
    std::filesystem::create_directories(dir);
    const auto path = dir / std::string{name};
    std::vector<std::byte> content(size);
    for (std::size_t index = 0U; index < size; ++index) {
      content[index] = static_cast<std::byte>(seed + index * 7U);
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(content.data()),
              static_cast<std::streamsize>(content.size()));
    return path;
  }

  static std::vector<std::byte> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::vector<char> raw{std::istreambuf_iterator<char>(in),
                          std::istreambuf_iterator<char>()};
    std::vector<std::byte> bytes(raw.size());
    for (std::size_t index = 0U; index < raw.size(); ++index) {
      bytes[index] = static_cast<std::byte>(raw[index]);
    }
    return bytes;
  }
};

}  // namespace heyaki::test
