#include <heyaki/identity.hpp>
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <executor/comm.hpp>

#include "relay_database.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace std::chrono_literals;

constexpr std::string_view demo_password = "heyaki-m3b-demo-password";

heyaki::Result<void> init_profile(
    const std::filesystem::path& database, const std::vector<std::string>& app_ids) {
  auto profile = std::filesystem::exists(database)
                      ? heyaki::ProfileStore::open(database)
                      : heyaki::ProfileStore::create(database);
  if (!profile) {
    return heyaki::Result<void>::failure(*profile.error_if());
  }
  auto readiness = profile.value_if()->local_readiness(app_ids.front());
  if (!readiness) {
    return heyaki::Result<void>::failure(*readiness.error_if());
  }
  if (!readiness.value_if()->ready()) {
    auto verifier = heyaki::create_password_verifier(demo_password, {});
    if (!verifier) {
      return heyaki::Result<void>::failure(*verifier.error_if());
    }
    heyaki::LocalProfileInitialization initialization;
    initialization.application_id = app_ids.front();
    initialization.password_verifier = std::move(*verifier.value_if());
    initialization.password_generation = 1U;
    initialization.pairing_policy = heyaki::PairingPolicy{};
    initialization.lan = heyaki::LanConfiguration{};
    auto initialized = profile.value_if()->initialize_local(initialization);
    if (!initialized) {
      return heyaki::Result<void>::failure(*initialized.error_if());
    }
  }
  auto identity = profile.value_if()->load_identity();
  if (!identity) {
    return heyaki::Result<void>::failure(*identity.error_if());
  }
  std::cout << "DEVICE=" << heyaki::to_string(identity.value_if()->device_id()) << '\n';
  const auto& public_key = identity.value_if()->public_key();
  std::cout << "PUBLIC_KEY_HEX=";
  for (const auto byte : public_key) {
    const auto value = std::to_integer<unsigned int>(byte);
    std::cout << "0123456789abcdef"[(value >> 4U) & 0x0fU]
              << "0123456789abcdef"[value & 0x0fU];
  }
  std::cout << '\n';
  for (const auto& app_id : app_ids) {
    auto endpoint = profile.value_if()->endpoint_for(app_id);
    if (!endpoint) {
      return heyaki::Result<void>::failure(*endpoint.error_if());
    }
    std::cout << "APP_ENDPOINT_" << app_id << '='
              << heyaki::to_string(*endpoint.value_if()) << '\n';
  }
  return heyaki::Result<void>::success();
}

heyaki::Result<void> seed_token(const std::filesystem::path& database,
                                std::string_view tenant, std::string_view token,
                                std::uint64_t expiry, std::uint64_t uses = 1U) {
  auto opened = heyaki::RelayDatabase::open(database);
  if (!opened) {
    return heyaki::Result<void>::failure(*opened.error_if());
  }
  auto created = opened.value_if()->create_bootstrap_token(
      std::string{tenant}, token, expiry, uses);
  if (!created) {
    return heyaki::Result<void>::failure(*created.error_if());
  }
  return heyaki::Result<void>::success();
}

bool wait_until(const std::function<bool()>& predicate,
                std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  executor::comm::PhaseGate poll{"heyaki-m3b-relay-demo-poll"};
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    (void)poll.wait_for(1U, std::chrono::milliseconds{1});
  }
  return predicate();
}

heyaki::Result<void> run_node(const std::filesystem::path& database,
                              std::string_view app_id,
                              std::chrono::milliseconds hold_for) {
  auto profile = heyaki::ProfileStore::open(database);
  if (!profile) {
    return heyaki::Result<void>::failure(*profile.error_if());
  }
  heyaki::LanConfiguration lan;
  lan.enabled = false;
  heyaki::NodeConfig config;
  config.profile = profile.value_if();
  config.application_id = std::string{app_id};
  config.lan_override = lan;
  auto node = heyaki::Node::create(std::move(config));
  if (!node) {
    return heyaki::Result<void>::failure(*node.error_if());
  }
  const auto ready = wait_until(
      [&] {
        const auto snapshot = node.value_if()->snapshot();
        return snapshot.relay.state == heyaki::RelayNodeState::ready;
      },
      std::min<std::chrono::milliseconds>(hold_for, 5000ms));
  const auto snapshot = node.value_if()->snapshot();
  std::cout << "DEVICE=" << heyaki::to_string(snapshot.device_id) << '\n';
  std::cout << "ENDPOINT=" << heyaki::to_string(snapshot.endpoint_id) << '\n';
  std::cout << "RELAY=" << heyaki::relay_node_state_name(snapshot.relay.state) << '\n';
  std::cout << "RELAY_URL=" << snapshot.relay.relay_url << '\n';
  std::cout << "TENANT=" << snapshot.relay.tenant << '\n';
  if (ready) {
    const auto deadline = std::chrono::steady_clock::now() + hold_for;
    while (std::chrono::steady_clock::now() < deadline) {
      executor::comm::PhaseGate poll{"heyaki-m3b-relay-demo-hold"};
      (void)poll.wait_for(1U, std::chrono::milliseconds{1});
    }
  }
  const auto shutdown = node.value_if()->shutdown();
  if (!shutdown.stopped) {
    return heyaki::Result<void>::failure(
        heyaki::Error{heyaki::ErrorCode::timeout, "m3b_relay_demo",
                      "node_shutdown_timeout"});
  }
  if (!ready) {
    return heyaki::Result<void>::failure(
        heyaki::Error{heyaki::ErrorCode::relay_unavailable, "m3b_relay_demo",
                      "relay_not_ready"});
  }
  return heyaki::Result<void>::success();
}

std::uint64_t parse_u64(std::string_view text) {
  std::uint64_t value = 0U;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      return 0U;
    }
    value = value * 10U + static_cast<std::uint64_t>(character - '0');
  }
  return value;
}

int usage() {
  std::cerr << "usage:\n"
            << "  heyaki-m3b-relay-demo init-profile DB APP_ID [APP_ID...]\n"
            << "  heyaki-m3b-relay-demo seed-token DB TENANT TOKEN EXPIRY_UNIX_MS [USES]\n"
            << "  heyaki-m3b-relay-demo run DB APP_ID HOLD_MILLISECONDS\n";
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    return usage();
  }
  const std::string command = argv[1];
  if (command == "init-profile") {
    if (argc < 4) {
      return usage();
    }
    std::vector<std::string> app_ids;
    for (int index = 3; index < argc; ++index) {
      app_ids.emplace_back(argv[index]);
    }
    auto result = init_profile(argv[2], app_ids);
    if (!result) {
      std::cerr << heyaki::error_code_name(result.error_if()->code()) << ':'
                << result.error_if()->safe_detail() << '\n';
      return 1;
    }
    return 0;
  }
  if (command == "seed-token") {
    if (argc != 6 && argc != 7) {
      return usage();
    }
    const auto expiry = parse_u64(argv[5]);
    if (expiry == 0U) {
      return usage();
    }
    const auto uses = argc == 7 ? parse_u64(argv[6]) : 1U;
    if (uses == 0U) {
      return usage();
    }
    auto result = seed_token(argv[2], argv[3], argv[4], expiry, uses);
    if (!result) {
      std::cerr << heyaki::error_code_name(result.error_if()->code()) << ':'
                << result.error_if()->safe_detail() << '\n';
      return 1;
    }
    return 0;
  }
  if (command == "run") {
    if (argc != 5) {
      return usage();
    }
    const auto hold = std::chrono::milliseconds{parse_u64(argv[4])};
    if (hold.count() <= 0) {
      return usage();
    }
    auto result = run_node(argv[2], argv[3], hold);
    if (!result) {
      std::cerr << heyaki::error_code_name(result.error_if()->code()) << ':'
                << result.error_if()->safe_detail() << '\n';
      return 1;
    }
    return 0;
  }
  return usage();
}
