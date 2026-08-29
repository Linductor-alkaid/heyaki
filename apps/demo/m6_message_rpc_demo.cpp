// M6 message/RPC semantics demo (M6-16). Documents and demonstrates the
// differences between admission, transport completion, protocol ACK, handler
// success, and outcome_unknown using the public Node API:
//
//   heyaki-m6-message-rpc-demo semantics
//       Prints the semantic reference; used as the CI smoke mode.
//   heyaki-m6-message-rpc-demo init-profile DB APP_ID
//   heyaki-m6-message-rpc-demo seed-trust FIRST_DB SECOND_DB
//   heyaki-m6-message-rpc-demo run DB APP_ID --role caller|responder
//
// The caller waits for LAN discovery of the responder, connects (seeded
// trust authorizes the session), sends one best_effort and one peer_acked
// message, and completes one unary RPC plus one deliberately-unknown call.

#include <heyaki/message.hpp>
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/rpc.hpp>
#include <heyaki/trust_grant.hpp>

#include <executor/comm.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

using heyaki::Error;
using heyaki::ErrorCode;

bool wait_until(const std::function<bool()>& predicate,
                std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  executor::comm::PhaseGate poll{"heyaki-m6-demo-poll"};
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    (void)poll.wait_for(1U, std::chrono::milliseconds{20});
  }
  return predicate();
}

int print_semantics() {
  std::cout <<
      "M6 semantics reference (message vs unary RPC)\n"
      "------------------------------------------------\n"
      "admission        send()/call() returned success: the frame/request\n"
      "                 entered a BOUNDED queue. Nothing has left the device\n"
      "                 yet; best_effort messages complete HERE.\n"
      "completion       For peer_acked messages: the peer's protocol layer\n"
      "                 validated the envelope (MESSAGE_ACK). For RPC: the\n"
      "                 terminal RPC_RESPONSE arrived with a stable status.\n"
      "ACK              Protocol-level only: it never claims the message\n"
      "                 handler ran, succeeded, or that anything persisted.\n"
      "handler success  The application handler returned; for RPC the\n"
      "                 response status is `ok` (1). A handler exception maps\n"
      "                 to a safe `internal` (11) with no detail leakage.\n"
      "outcome_unknown  The transport was lost after a NON-idempotent request\n"
      "                 was admitted: whether it executed is unknowable, the\n"
      "                 library NEVER retries automatically. Only explicitly\n"
      "                 idempotent calls may opt into policy-driven retry on\n"
      "                 a future session.\n"
      "deadline/cancel  Deadlines are relative on the wire and cooperative on\n"
      "                 the handler: nothing is killed, late results are\n"
      "                 dropped, exactly one terminal response is sent.\n"
      "streaming        v1 ships unary only; streaming methods answer\n"
      "                 `unimplemented` (12) instead of half-built semantics.\n";
  return 0;
}

int usage() {
  std::cerr << "usage: heyaki-m6-message-rpc-demo semantics\n"
            << "       heyaki-m6-message-rpc-demo init-profile DB APP_ID\n"
            << "       heyaki-m6-message-rpc-demo seed-trust FIRST_DB SECOND_DB\n"
            << "       heyaki-m6-message-rpc-demo run DB APP_ID --role caller|responder"
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
  // The demo never runs password pairing (trust is pre-seeded), so a fixed
  // verifier placeholder is sufficient for local readiness.
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

void register_demo_service(heyaki::Node& node) {
  heyaki::RpcMethodDescriptor echo;
  echo.service = "heyaki.demo";
  echo.method = "echo";
  echo.schema_version = 1U;
  echo.required_scope = "rpc.device.read";
  auto registered = node.register_rpc_method(
      echo, [](const heyaki::RpcCallContext& context) {
        return heyaki::RpcHandlerResult{
            heyaki::StableStatus::ok,
            std::vector<std::byte>(context.payload().begin(), context.payload().end()),
            "ok"};
      });
  if (!registered) {
    std::cerr << "echo registration failed: " << registered.error_if()->safe_detail()
              << "\n";
  }
}

int run_demo(const std::filesystem::path& database, std::string_view application_id,
             bool caller, std::chrono::milliseconds budget) {
  auto opened = heyaki::ProfileStore::open(database);
  if (!opened) {
    std::cerr << "profile open failed: " << opened.error_if()->safe_detail() << "\n";
    return 1;
  }
  heyaki::NodeConfig config;
  config.profile = &*opened.value_if();
  config.application_id = std::string{application_id};
  auto created = heyaki::Node::create(config);
  if (!created) {
    std::cerr << "node create failed: " << created.error_if()->safe_detail() << "\n";
    return 1;
  }
  heyaki::Node node = std::move(*created.value_if());
  register_demo_service(node);

  std::mutex events_mutex;
  std::vector<std::string> delivery_events;
  std::vector<std::string> inbound;
  std::vector<std::string> rpc_results;
  std::atomic<std::uint64_t> rpc_index{0U};

  node.set_message_inbound_handler(
      [&events_mutex, &inbound](const heyaki::DeviceEndpointKey&,
                                const heyaki::MessageEnvelope& envelope) {
        std::scoped_lock lock{events_mutex};
        inbound.push_back(envelope.type);
        std::cout << "MESSAGE_RECEIVED type=" << envelope.type << " ttl="
                  << envelope.ttl_milliseconds << " mode="
                  << heyaki::message_delivery_mode_name(envelope.delivery_mode)
                  << "\n";
      });
  node.set_message_ack_observer(
      [&events_mutex, &delivery_events](const heyaki::DeviceEndpointKey&,
                                        const heyaki::MessageId&,
                                        heyaki::MessageDeliveryEvent event,
                                        std::optional<Error> error) {
        std::scoped_lock lock{events_mutex};
        delivery_events.push_back(
            std::string{heyaki::message_delivery_event_name(event)});
        std::cout << "DELIVERY event=" << heyaki::message_delivery_event_name(event)
                  << (error ? std::string{" detail="} +
                                   std::string{error->safe_detail()}
                            : std::string{})
                  << "\n";
      });

  if (!caller) {
    // Responder: serve until the budget expires.
    std::cout << "RESPONDER_READY\n";
    const auto ok = wait_until([] { return false; }, budget);
    (void)ok;
    (void)node.shutdown();
    return 0;
  }

  // Caller: wait for LAN discovery of the responder, connect, and exercise
  // the service semantics through the public API.
  const auto discovered = wait_until(
      [&node] { return !node.endpoints().empty(); }, budget);
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

  // 1) best_effort: completion == bounded-queue admission.
  heyaki::MessageEnvelope best_effort;
  best_effort.type = "demo.semantics";
  best_effort.delivery_mode = heyaki::MessageDeliveryMode::best_effort;
  best_effort.ttl_milliseconds = 30'000U;
  best_effort.payload = {std::byte{0x62}, std::byte{0x65}};
  auto sent = node.send_message(peer, best_effort);
  std::cout << "SEMANTIC admission best_effort="
            << (sent ? "admitted" : sent.error_if()->safe_detail()) << "\n";

  // 2) peer_acked: admission, then a protocol-level ACK (never a handler
  //    claim). The responder prints MESSAGE_RECEIVED for the handler side.
  heyaki::MessageEnvelope acked = best_effort;
  acked.delivery_mode = heyaki::MessageDeliveryMode::peer_acked;
  sent = node.send_message(peer, acked);
  std::cout << "SEMANTIC admission peer_acked="
            << (sent ? "admitted" : sent.error_if()->safe_detail()) << "\n";
  const auto ack_arrived = wait_until(
      [&events_mutex, &delivery_events] {
        std::scoped_lock lock{events_mutex};
        for (const auto& event : delivery_events) {
          if (event == "acked") return true;
        }
        return false;
      },
      std::chrono::milliseconds{10'000});
  std::cout << "SEMANTIC completion peer_acked="
            << (ack_arrived ? "acked (protocol-level only)" : "ack_timeout")
            << "\n";

  // 3) Unary RPC success (handler ran, status ok).
  const std::uint64_t echo_index = ++rpc_index;
  auto started = node.call_rpc(
      peer, "heyaki.demo", "echo", {std::byte{0x70}, std::byte{0x6F}},
      heyaki::RpcCallOptions{},
      [&events_mutex, &rpc_results, echo_index](
          const heyaki::DeviceEndpointKey&,
          heyaki::Result<heyaki::RpcCallOutcome> outcome) {
        std::scoped_lock lock{events_mutex};
        if (outcome) {
          rpc_results.push_back("index=" + std::to_string(echo_index) +
                                " status=" +
                                std::to_string(static_cast<int>((*outcome.value_if()).status)) +
                                " detail=" + std::string{(*outcome.value_if()).safe_detail});
        } else {
          rpc_results.push_back("index=" + std::to_string(echo_index) +
                                " local_error=" +
                                std::string{outcome.error_if()->safe_detail()});
        }
      });
  std::cout << "SEMANTIC rpc admission="
            << (started ? "admitted" : started.error_if()->safe_detail()) << "\n";
  const auto echo_done = wait_until(
      [&events_mutex, &rpc_results] {
        std::scoped_lock lock{events_mutex};
        return !rpc_results.empty();
      },
      std::chrono::milliseconds{10'000});
  {
    std::scoped_lock lock{events_mutex};
    for (const auto& result : rpc_results) {
      std::cout << "SEMANTIC rpc completion " << result << "\n";
    }
  }
  if (!echo_done) {
    std::cerr << "echo rpc never completed\n";
    (void)node.shutdown();
    return 1;
  }

  // 4) Structured failure before any handler: unknown method.
  const std::uint64_t missing_index = ++rpc_index;
  (void)node.call_rpc(
      peer, "heyaki.demo", "does-not-exist", {},
      heyaki::RpcCallOptions{},
      [&events_mutex, &rpc_results, missing_index](
          const heyaki::DeviceEndpointKey&,
          heyaki::Result<heyaki::RpcCallOutcome> outcome) {
        std::scoped_lock lock{events_mutex};
        rpc_results.push_back(
            "index=" + std::to_string(missing_index) + " status=" +
            std::to_string(outcome ? static_cast<int>((*outcome.value_if()).status)
                                   : -1));
      });
  wait_until(
      [&events_mutex, &rpc_results] {
        std::scoped_lock lock{events_mutex};
        return rpc_results.size() >= 2U;
      },
      std::chrono::milliseconds{10'000});
  {
    std::scoped_lock lock{events_mutex};
    if (rpc_results.size() >= 2U) {
      std::cout << "SEMANTIC unknown method -> " << rpc_results[1]
                << " (12 = unimplemented)\n";
    }
  }

  std::cout << "M6_DEMO_OK\n";
  (void)node.shutdown();
  return 0;
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
    const std::vector<std::string> scopes = {"message.send", "rpc.device.read"};
    auto forward = seed_one_way_trust(*first.value_if(), *second.value_if(), scopes, 1U);
    if (!forward) {
      std::cerr << forward.error_if()->safe_detail() << "\n";
      return 1;
    }
    auto backward = seed_one_way_trust(*second.value_if(), *first.value_if(), scopes, 2U);
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
