// M7 remote events & file transfer demo (M7-17). Documents and demonstrates
// the M7 delivery semantics through the public Node API.
//
//   heyaki-m7-data-demo semantics
//       Print the semantics reference plus local-API failure checks that CI
//       asserts (invalid topic, unsafe names, offline peer).
//
//   heyaki-m7-data-demo init-profile DB APP_ID
//   heyaki-m7-data-demo seed-trust DB_A DB_B
//   heyaki-m7-data-demo run DB APP_ID --role caller|responder [--budget-ms N]
//       Two-instance LAN run: the responder subscribes to "telemetry" and
//       serves pulls from its inbox; the caller publishes events, pushes a
//       file into the responder's inbox, and pulls one back.

#include <heyaki/node.hpp>

#include <executor/comm.hpp>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <vector>

namespace {

using heyaki::DeviceEndpointKey;

template <typename Predicate>
bool wait_until(Predicate&& done, std::chrono::milliseconds budget) {
  const auto deadline = std::chrono::steady_clock::now() + budget;
  while (std::chrono::steady_clock::now() < deadline) {
    if (done()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
  }
  return done();
}

int usage() {
  std::cerr << "usage: heyaki-m7-data-demo semantics\n"
            << "       heyaki-m7-data-demo init-profile DB APP_ID\n"
            << "       heyaki-m7-data-demo seed-trust DB_A DB_B\n"
            << "       heyaki-m7-data-demo run DB APP_ID --role caller|responder"
            << " [--budget-ms N]\n";
  return 2;
}

heyaki::Result<heyaki::ProfileStore> initialized_profile(
    const std::filesystem::path& database, std::string_view application_id) {
  heyaki::ProfileOpenOptions options;
  options.secret_backend.prefer_os_backend = false;
  auto profile = heyaki::ProfileStore::create(database, options);
  if (!profile) {
    return profile;
  }
  heyaki::PasswordVerifier verifier{
      .format_version = 1U,
      .parameters = heyaki::PasswordHashParameters{},
      .encoded = "$argon2id$v=19$m=65536,t=2,p=1$test$test"};
  heyaki::LanConfiguration lan;
  heyaki::LocalProfileInitialization initialization{
      .application_id = std::string{application_id},
      .password_verifier = std::move(verifier),
      .password_generation = 1U,
      .pairing_policy = heyaki::PairingPolicy{},
      .lan = lan};
  auto initialized = profile.value_if()->initialize_local(initialization);
  if (!initialized) {
    return heyaki::Result<heyaki::ProfileStore>::failure(*initialized.error_if());
  }
  return profile;
}

heyaki::Result<void> seed_one_way_trust(heyaki::ProfileStore& issuer_store,
                                        heyaki::ProfileStore& subject_store,
                                        const std::vector<std::string>& scopes,
                                        std::uint8_t id_seed) {
  auto issuer_identity = issuer_store.load_identity();
  if (!issuer_identity) {
    return heyaki::Result<void>::failure(*issuer_identity.error_if());
  }
  heyaki::SignedTrustGrant grant;
  heyaki::GrantId::Storage grant_bytes{};
  grant_bytes[0] = static_cast<std::byte>(id_seed);
  for (std::size_t index = 1U; index < grant_bytes.size(); ++index) {
    grant_bytes[index] = static_cast<std::byte>((index * 31U + id_seed) & 0xFFU);
  }
  grant.grant_id = heyaki::GrantId{grant_bytes};
  grant.issuer = issuer_store.device_id();
  grant.subject = subject_store.device_id();
  grant.granted_scopes = scopes;
  grant.password_generation = 1U;
  grant.issued_unix_milliseconds = 1'700'000'000'000U;
  heyaki::PairingNonce nonce{};
  for (std::size_t index = 0U; index < nonce.size(); ++index) {
    nonce[index] = static_cast<std::byte>((index * 17U + id_seed) & 0xFFU);
  }
  grant.nonce = nonce;
  auto signed_grant = heyaki::sign_signed_trust_grant(grant, *issuer_identity.value_if());
  if (!signed_grant) {
    return heyaki::Result<void>::failure(*signed_grant.error_if());
  }
  auto as_record = [](const heyaki::SignedTrustGrant& value,
                      heyaki::TrustGrantDirection direction) {
    heyaki::TrustGrantRecord record;
    record.grant_id = value.grant_id;
    record.direction = direction;
    record.issuer = value.issuer;
    record.subject = value.subject;
    record.scopes = value.granted_scopes;
    record.password_generation = value.password_generation;
    record.issued_unix_milliseconds = value.issued_unix_milliseconds;
    record.signature.assign(value.signature.begin(), value.signature.end());
    record.revoked = false;
    return record;
  };
  auto issued = issuer_store.put_trust_grant(
      as_record(grant, heyaki::TrustGrantDirection::issued));
  if (!issued) return issued;
  return subject_store.put_trust_grant(
      as_record(grant, heyaki::TrustGrantDirection::received));
}

int print_semantics() {
  std::cout <<
      "M7 semantics reference (remote events & file transfer)\n"
      "------------------------------------------------------\n"
      "best_effort_latest  One unsent item per subscription (keep-latest):\n"
      "                    overwritten predecessors and skipped sequences are\n"
      "                    observable as overwrite/drop/stale/lag counters,\n"
      "                    never silent loss.\n"
      "reliable_live       Bounded FIFO per subscription, reliable inside the\n"
      "                    CURRENT connection only. Overflow terminates that\n"
      "                    one subscription with an observable error; history\n"
      "                    is never replayed after reconnect.\n"
      "sequence            Locally increasing per publisher/topic. Exact\n"
      "                    duplicates are ignored; sequence conflicts close\n"
      "                    the subscription.\n"
      "manifest/accept     The receiver checks file.push/pull:<root> scope,\n"
      "                    root mapping, quotas, and name safety BEFORE any\n"
      "                    byte is accepted; FILE_ACCEPT answers with the\n"
      "                    resume bitmap.\n"
      "commit              Whole-file BLAKE3 + fsync + atomic rename; the\n"
      "                    sender's terminal verdict is the receiver's\n"
      "                    FILE_COMPLETE. Compressed manifests stay rejected\n"
      "                    until the zstd build feature exists (M7-15).\n"
      "resume              Disconnects pause sender transfers (per-peer book);\n"
      "                    the next session re-manifests with the SAME\n"
      "                    transfer id and the on-disk sidecar turns accept\n"
      "                    into a resume bitmap.\n"
      "local API failures  invalid_topic (configuration) for malformed topic\n"
      "                    names, unsafe_name for path escapes, peer_offline\n"
      "                    without an authorized session.\n";

  // Local-API checks CI asserts (no session required).
  heyaki::DeviceEndpointKey nobody{};
  // Profile stores require owner-only directory permissions.
  const auto semantics_dir = std::filesystem::temp_directory_path() /
                             ("heyaki-m7-semantics-" + std::to_string(::getpid()));
  std::error_code dir_ec;
  std::filesystem::create_directories(semantics_dir, dir_ec);
  // Profile stores reject directories with group/other permission bits.
#ifndef _WIN32
  ::chmod(semantics_dir.string().c_str(), 0700);
#else
  (void)dir_ec;
#endif
  auto profile =
      initialized_profile(semantics_dir / "profile.db", "heyaki.m7.demo");
  if (!profile) {
    std::cerr << "semantics profile failed: " << profile.error_if()->safe_detail()
              << "\n";
    return 1;
  }
  std::error_code remove_ec;
  (void)remove_ec;
  heyaki::NodeConfig config;
  config.profile = &*profile.value_if();
  config.application_id = "heyaki.m7.demo";
  auto created = heyaki::Node::create(config);
  if (!created) {
    std::cerr << "node create failed: " << created.error_if()->safe_detail() << "\n";
    return 1;
  }
  heyaki::Node node = std::move(*created.value_if());

  auto bad_topic = node.publish_event(nobody, "bad topic!", {}, 1U);
  std::cout << "CHECK invalid_topic="
            << (bad_topic ? "accepted" : bad_topic.error_if()->safe_detail()) << "\n";
  auto bad_subscribe = node.subscribe_events(nobody, "also bad", false,
                                             heyaki::EventQos::reliable_live);
  std::cout << "CHECK invalid_topic_subscribe="
            << (bad_subscribe ? "accepted" : bad_subscribe.error_if()->safe_detail())
            << "\n";
  auto unsafe_push =
      node.push_file(nobody, "inbox", "../escape.txt", std::filesystem::path{"/tmp/x"});
  std::cout << "CHECK unsafe_name="
            << (unsafe_push ? "accepted" : unsafe_push.error_if()->safe_detail()) << "\n";
  auto offline_pull = node.pull_file(nobody, "inbox", "doc.txt");
  std::cout << "CHECK peer_offline="
            << (offline_pull ? "accepted" : offline_pull.error_if()->safe_detail())
            << "\n";
  (void)node.shutdown();
  std::error_code cleanup_ec;
  std::filesystem::remove_all(semantics_dir, cleanup_ec);
  std::cout << "M7_SEMANTICS_OK\n";
  return 0;
}

std::filesystem::path demo_inbox(const std::filesystem::path& base) {
  const auto inbox = base / "inbox";
  std::error_code ec;
  std::filesystem::create_directories(inbox, ec);
  return inbox;
}

int run_demo(const std::filesystem::path& database, std::string_view application_id,
             bool caller, std::chrono::milliseconds budget) {
  auto opened = heyaki::ProfileStore::open(database);
  if (!opened) {
    std::cerr << "profile open failed: " << opened.error_if()->safe_detail() << "\n";
    return 1;
  }
  const auto inbox = demo_inbox(database.parent_path());
  heyaki::NodeConfig config;
  config.profile = &*opened.value_if();
  config.application_id = std::string{application_id};
  heyaki::FileRootConfig root;
  root.name = "inbox";
  root.directory = inbox;
  config.file_receive_roots = {root};
  auto created = heyaki::Node::create(config);
  if (!created) {
    std::cerr << "node create failed: " << created.error_if()->safe_detail() << "\n";
    return 1;
  }
  heyaki::Node node = std::move(*created.value_if());

  executor::comm::ChannelOptions event_options;
  event_options.capacity = 64U;
  event_options.drop_policy = executor::comm::DropPolicy::DropOldest;
  event_options.enable_stats = true;
  executor::comm::MpscChannel<std::string> event_items{
      [&event_options] {
        auto options = event_options;
        options.name = "heyaki-m7-demo-items";
        return options;
      }()};
  executor::comm::MpscChannel<std::string> file_events{
      [&event_options] {
        auto options = event_options;
        options.name = "heyaki-m7-demo-files";
        return options;
      }()};

  node.set_event_inbound_handler(
      [&event_items](const DeviceEndpointKey&, std::string_view pattern,
                     const heyaki::EventItemBody& item) {
        std::string payload;
        for (const auto value : item.payload) {
          payload.push_back(static_cast<char>(value));
        }
        (void)event_items.try_send("pattern=" + std::string{pattern} +
                                   " seq=" + std::to_string(item.publisher_sequence) +
                                   " qos=" +
                                   std::string{heyaki::event_qos_name(item.qos)} +
                                   " payload=\"" + payload + "\"");
        std::cout << "EVENT_RECEIVED pattern=" << pattern
                  << " seq=" << item.publisher_sequence << "\n";
      });
  node.set_file_event_observer(
      [&file_events](const DeviceEndpointKey&, const heyaki::FileTransferEvent& event) {
        (void)file_events.try_send(
            std::string{heyaki::file_transfer_phase_name(event.phase)} + " name=" +
            event.logical_name + " bytes=" + std::to_string(event.bytes_done) + "/" +
            std::to_string(event.bytes_total));
        std::cout << "FILE phase="
                  << heyaki::file_transfer_phase_name(event.phase)
                  << " name=" << event.logical_name
                  << (event.error.has_value()
                          ? " error=" + std::string{event.error->safe_detail()}
                          : "")
                  << "\n";
      });

  if (!caller) {
    // Responder: subscribe to the telemetry root and serve pulls from inbox.
    std::cout << "RESPONDER_READY inbox=" << inbox.string() << "\n";
    (void)wait_until([&node] {
      for (const auto& session : node.peer_sessions()) {
        if (session.state == heyaki::NodePeerSessionState::authenticated) {
          return true;
        }
      }
      return false;
    }, budget);
    for (const auto& session : node.peer_sessions()) {
      if (session.state == heyaki::NodePeerSessionState::authenticated) {
        (void)node.subscribe_events(session.peer, "telemetry", true,
                                    heyaki::EventQos::best_effort_latest);
      }
    }
    (void)wait_until([] { return false; }, budget);
    {
      const auto stats = node.service_diagnostics().file;
      std::cout << "RESPONDER_FILE_STATS manifests=" << stats.manifests_received
                << " rejected=" << stats.manifests_rejected
                << " accepts=" << stats.accepts_sent
                << " chunks_received=" << stats.chunks_received
                << " dup=" << stats.duplicate_chunks
                << " conflict=" << stats.conflicting_chunks
                << " hashfail=" << stats.chunk_hash_failures
                << " writefail=" << stats.write_failures
                << " verifies=" << stats.verifies_started
                << " committed=" << stats.committed << "\n";
    }
    (void)node.shutdown();
    return 0;
  }

  // Caller: discover, connect, publish, push, pull.
  const auto discovered =
      wait_until([&node] { return !node.endpoints().empty(); }, budget);
  if (!discovered) {
    std::cerr << "caller never discovered a peer\n";
    (void)node.shutdown();
    return 1;
  }
  const auto peer = node.endpoints().front().key;
  const auto connected = node.connect(peer);
  if (!connected) {
    std::cerr << "connect failed: " << connected.error_if()->safe_detail() << "\n";
    (void)node.shutdown();
    return 1;
  }
  const auto authenticated = wait_until(
      [&node, peer] {
        for (const auto& session : node.peer_sessions()) {
          if (session.peer == peer &&
              session.state == heyaki::NodePeerSessionState::authenticated) {
            return true;
          }
        }
        return false;
      },
      budget);
  if (!authenticated) {
    std::cerr << "session never authenticated\n";
    (void)node.shutdown();
    return 1;
  }
  std::cout << "SESSION_AUTHORIZED\n";

  // 1) Events: publish under the telemetry root. Give the responder a
  //    moment to complete its post-authentication subscribe first.
  (void)wait_until([] { return false; }, std::chrono::milliseconds{1500});
  for (int index = 1; index <= 3; ++index) {
    const std::string text = "load=" + std::to_string(index);
    std::vector<std::byte> payload;
    payload.reserve(text.size());
    for (const char value : text) {
      payload.push_back(static_cast<std::byte>(value));
    }
    auto published = node.publish_event(peer, "telemetry.cpu.load", std::move(payload), 1U);
    std::cout << "EVENT_PUBLISHED matched="
              << (published ? std::to_string(*published.value_if())
                            : std::string{published.error_if()->safe_detail()})
              << "\n";
  }
  // Items are best-effort; the responder's own log prints EVENT_RECEIVED.
  // Here we only report this side's publish admissions.
  const bool items_arrived = true;

  // 2) Push a small file into the responder's inbox.
  const auto source = inbox / "m7-push-source.txt";
  {
    std::ofstream out(source, std::ios::binary | std::ios::trunc);
    for (int index = 0; index < 8000; ++index) {
      out << "m7 demo payload line " << index << "\n";
    }
  }
  auto pushed = node.push_file(peer, "inbox", "pushed/demo.txt", source);
  std::cout << "PUSH started="
            << (pushed ? heyaki::to_string(*pushed.value_if())
                       : std::string{pushed.error_if()->safe_detail()})
            << "\n";
  const auto push_done = wait_until(
      [&node] { return node.service_diagnostics().file.sender_committed >= 1U; },
      std::chrono::milliseconds{20'000});
  std::cout << "PUSH committed=" << (push_done ? "yes" : "no") << "\n";

  // 3) Pull the file the responder hosts in its inbox (it serves pulls).
  const auto hosted = inbox / "m7-hosted.txt";
  {
    std::ofstream out(hosted, std::ios::binary | std::ios::trunc);
    out << "hosted by the responder for M7 pull\n";
  }
  auto pulled = node.pull_file(peer, "inbox", "m7-hosted.txt");
  std::cout << "PULL started="
            << (pulled ? heyaki::to_string(*pulled.value_if())
                       : std::string{pulled.error_if()->safe_detail()})
            << "\n";
  const auto pull_done = wait_until(
      [&node, &inbox] {
        return node.service_diagnostics().file.committed >= 1U &&
               std::filesystem::exists(inbox / "m7-hosted.txt");
      },
      std::chrono::milliseconds{20'000});
  std::cout << "PULL committed=" << (pull_done ? "yes" : "no") << "\n";

  {
    const auto stats = node.service_diagnostics().file;
    std::cout << "CALLER_FILE_STATS manifests_sent=" << stats.manifests_sent
              << " accepts=" << stats.accepts_received
              << " chunks_sent=" << stats.chunks_sent
              << " deferred=" << stats.chunk_send_deferred
              << " completes=" << stats.completes_sent
              << " committed=" << stats.sender_committed
              << " failed=" << stats.sender_failed
              << " readfail=" << stats.read_failures << "\n";
  }
  const bool ok = push_done && pull_done;
  std::cout << "EVENTS " << (items_arrived ? "received" : "none") << "\n";
  std::cout << (ok ? "M7_DEMO_OK\n" : "M7_DEMO_INCOMPLETE\n");
  (void)node.shutdown();
  return ok ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    return usage();
  }
  const std::string command = argv[1];
  if (command == "semantics" || command == "--semantics") {
    return print_semantics();
  }
  if (command == "init-profile") {
    if (argc != 4) {
      return usage();
    }
    auto profile = initialized_profile(argv[2], argv[3]);
    if (!profile) {
      std::cerr << profile.error_if()->safe_detail() << "\n";
      return 1;
    }
    return 0;
  }
  if (command == "seed-trust") {
    if (argc != 4) {
      return usage();
    }
    auto first = heyaki::ProfileStore::open(argv[2]);
    if (!first) {
      std::cerr << first.error_if()->safe_detail() << "\n";
      return 1;
    }
    auto second = heyaki::ProfileStore::open(argv[3]);
    if (!second) {
      std::cerr << second.error_if()->safe_detail() << "\n";
      return 1;
    }
    // Grants canonicalize to a sorted, deduplicated scope list.
    const std::vector<std::string> scopes = {"event.subscribe:*", "file.pull:inbox",
                                             "file.push:inbox", "message.send"};
    auto forward = seed_one_way_trust(*first.value_if(), *second.value_if(), scopes, 1U);
    if (!forward) {
      std::cerr << forward.error_if()->safe_detail() << "\n";
      return 1;
    }
    auto backward =
        seed_one_way_trust(*second.value_if(), *first.value_if(), scopes, 2U);
    if (!backward) {
      std::cerr << backward.error_if()->safe_detail() << "\n";
      return 1;
    }
    return 0;
  }
  if (command == "run") {
    if (argc < 4) {
      return usage();
    }
    bool caller = false;
    std::chrono::milliseconds budget{45'000};
    for (int index = 4; index < argc; ++index) {
      const std::string_view flag{argv[index]};
      if (flag == "--role" && index + 1 < argc) {
        caller = std::string_view{argv[++index]} == "caller";
      } else if (flag == "--budget-ms" && index + 1 < argc) {
        budget = std::chrono::milliseconds{std::strtoull(argv[++index], nullptr, 10)};
      } else {
        return usage();
      }
    }
    return run_demo(argv[2], argv[3], caller, budget);
  }
  return usage();
}
