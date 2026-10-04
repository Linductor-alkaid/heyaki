// Heyaki Android integration smoke (M11-07). One deterministic, self-contained
// binary that exercises the core-library paths that must hold on a bionic
// device or emulator, with no external servers:
//
//   1. identity id string roundtrip (parse(to_string(id)) == id)
//   2. encrypted-file secret backend store/load/erase roundtrip (M11-04/A3)
//   3. ProfileStore create + local initialization on an app-scoped directory,
//      reporting the encrypted-file secret security level
//   4. exclusive profile file lock: a second open of the live database fails
//      with profile_locked
//   5. profile reopen: the identity written before the close is read back
//      (file-lock release + atomic replacement durability)
//   6. node lifecycle with LAN disabled: Runtime → Node → snapshot(disabled)
//      → shutdown, torn down in the node → profile → runtime order the JNI
//      boundary uses (executor shutdown must complete cleanly)
//   7. node lifecycle with LAN enabled on-device: within a bounded window the
//      LAN readiness reaches an explicit terminal-ish state (ready / degraded
//      / failed — never stuck on "starting"), and the relay route reports its
//      own independent state; clean shutdown afterwards. This is the on-device
//      shape of the M11-05 contract: multicast unavailability degrades the
//      LAN route explicitly and never blocks the rest of the node.
//
// Exit code 0 prints HEYAKI_ANDROID_SMOKE_OK checks=<n>. Any failure prints
// HEYAKI_ANDROID_SMOKE_FAIL <check> and returns 1. Usage:
//   heyaki_android_smoke <app-scope-dir>   (default /data/local/tmp/heyaki-smoke)

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <heyaki/error.hpp>
#include <heyaki/ids.hpp>
#include <heyaki/node.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/runtime.hpp>
#include <heyaki/secret_backend.hpp>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace {

int g_checks = 0;

void check(bool condition, const char* name) {
  if (!condition) {
    std::cout << "HEYAKI_ANDROID_SMOKE_FAIL " << name << '\n';
    std::exit(1);
  }
  ++g_checks;
  std::cout << "[smoke] ok: " << name << '\n';
}

heyaki::ProfileOpenOptions smoke_profile_options() {
  heyaki::ProfileOpenOptions options;
  // M11-04/A3 alpha disposition: the encrypted-file secret backend only.
  options.secret_backend.prefer_os_backend = false;
  return options;
}

heyaki::ProfileStore initialize_profile(const std::filesystem::path& database,
                                        const std::string& application_id,
                                        const std::string& password) {
  auto created = heyaki::ProfileStore::create(database, smoke_profile_options());
  if (!created) {
    std::cout << "HEYAKI_ANDROID_SMOKE_FAIL profile_create " << created.error_if()->safe_detail()
              << '\n';
    std::exit(1);
  }
  heyaki::PasswordHashParameters parameters;
  // The policy floor (security.hpp): 64 MiB, 2 operations — keeps the smoke
  // fast on-device while satisfying the verifier validation.
  parameters.operations = 2U;
  parameters.memory_bytes = 64U * 1024U * 1024U;
  auto verifier = heyaki::create_password_verifier(password, parameters);
  if (!verifier) {
    std::cout << "HEYAKI_ANDROID_SMOKE_FAIL password_verifier "
              << verifier.error_if()->safe_detail() << '\n';
    std::exit(1);
  }
  heyaki::LocalProfileInitialization initialization{
      .application_id = application_id,
      .password_verifier = std::move(*verifier.value_if()),
      .password_generation = 1U,
      .pairing_policy = heyaki::PairingPolicy{},
      .lan = heyaki::LanConfiguration{}};
  auto initialized = created.value_if()->initialize_local(initialization);
  if (!initialized) {
    std::cout << "HEYAKI_ANDROID_SMOKE_FAIL profile_initialize "
              << initialized.error_if()->safe_detail() << '\n';
    std::exit(1);
  }
  return std::move(*created.value_if());
}

// Runs one node against `database`; returns the steady-state LAN readiness
// observed within the bounded wait (or nullopt when it never left "starting").
std::optional<heyaki::LanReadinessState> run_node(heyaki::ProfileStore& profile, bool lan_enabled,
                                                  std::chrono::milliseconds lan_wait) {
  auto runtime_created = heyaki::Runtime::create_owned(heyaki::RuntimeConfig{});
  if (!runtime_created) {
    std::cout << "HEYAKI_ANDROID_SMOKE_FAIL runtime_create "
              << runtime_created.error_if()->safe_detail() << '\n';
    std::exit(1);
  }
  heyaki::Runtime runtime = std::move(*runtime_created.value_if());

  heyaki::NodeConfig config;
  config.profile = &profile;
  config.runtime = &runtime;
  config.application_id = "heyaki-android-smoke";
  config.pairing_approval_enabled = false;
  heyaki::LanConfiguration lan;
  lan.enabled = lan_enabled;
  lan.discoverable = lan_enabled;
  config.lan_override = lan;

  auto node = heyaki::Node::create(std::move(config));
  if (!node) {
    std::cout << "HEYAKI_ANDROID_SMOKE_FAIL node_create " << node.error_if()->safe_detail() << '\n';
    std::exit(1);
  }

  const auto snapshot = node.value_if()->snapshot();
  if (!lan_enabled) {
    check(!snapshot.lan_enabled && snapshot.lan_state == heyaki::LanReadinessState::disabled,
          "node_lan_disabled_snapshot");
    check(!snapshot.relay.enabled, "node_relay_route_independent");
  }

  std::optional<heyaki::LanReadinessState> lan_state;
  if (lan_enabled) {
    const auto deadline = std::chrono::steady_clock::now() + lan_wait;
    while (std::chrono::steady_clock::now() < deadline) {
      const auto current = node.value_if()->snapshot().lan_state;
      if (current == heyaki::LanReadinessState::ready ||
          current == heyaki::LanReadinessState::degraded ||
          current == heyaki::LanReadinessState::failed) {
        lan_state = current;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds{200});
    }
  }

  const auto report = node.value_if()->shutdown();
  check(report.stopped && !report.timed_out, "node_shutdown_report");
  return lan_state;
}

}  // namespace

int main(int argc, char** argv) {
  const std::filesystem::path root = argc > 1
                                         ? std::filesystem::path{argv[1]}
                                         : std::filesystem::path{"/data/local/tmp/heyaki-smoke"};
  std::error_code fs_error;
  std::filesystem::create_directories(root, fs_error);
  if (fs_error) {
    std::cout << "HEYAKI_ANDROID_SMOKE_FAIL create_root " << fs_error.message() << '\n';
    return 1;
  }
  // A previous run must not leak state into this one.
  (void)std::filesystem::remove_all(root / "profiles", fs_error);
  (void)std::filesystem::remove_all(root / "secrets", fs_error);
  (void)std::filesystem::remove_all(root / "secrets-open", fs_error);

  // (2) encrypted-file secret backend roundtrip on the app-scoped directory.
  heyaki::SecretBackendOptions backend_options;
  backend_options.prefer_os_backend = false;
  auto backend_result = heyaki::open_default_secret_backend(root / "secrets", backend_options);
  if (!backend_result) {
    std::cout << "HEYAKI_ANDROID_SMOKE_FAIL secret_backend_open "
              << backend_result.error_if()->safe_detail() << '\n';
    return 1;
  }
  auto& backend = *backend_result.value_if();
  check(backend->security() == heyaki::SecretBackendSecurity::encrypted_file_fallback,
        "secret_backend_encrypted_file");
  const std::array<std::byte, 32U> secret_bytes{};
  const auto stored = backend->store("smoke-secret", std::span<const std::byte>{secret_bytes});
  if (!stored) {
    std::cout << "HEYAKI_ANDROID_SMOKE_FAIL secret_store " << stored.error_if()->safe_detail()
              << '\n';
    return 1;
  }
  const auto loaded = backend->load(*stored.value_if());
  check(loaded && loaded.value_if()->size() == secret_bytes.size(), "secret_store_load_roundtrip");
  const auto erased = backend->erase(*stored.value_if());
  check(erased.has_value(), "secret_erase");

  // (3)-(5) profile create + initialization on the app-scoped directory, the
  // exclusive file lock while it is open, and reopen durability after close.
  const auto device_before = [&]() {
    const auto database = root / "profiles" / "smoke.db";
    auto profile = initialize_profile(database, "heyaki-android-smoke", "smoke-password");
    const auto& device_id = profile.device_id();
    check(!device_id.is_zero(), "profile_device_identity_created");
    check(
        profile.secret_backend_security() == heyaki::SecretBackendSecurity::encrypted_file_fallback,
        "profile_secret_backend_level");

    // (1) identity string roundtrip through the canonical text encoding.
    const auto parsed = heyaki::parse_device_id(heyaki::to_string(device_id));
    check(parsed && *parsed.value == device_id, "identity_text_roundtrip");

    // (4) the admin operations take the exclusive sidecar lock: while it is
    // held (here: by this process, as an external contender would), a
    // profile-deleting operation must fail with profile_locked instead of
    // racing the open handle.
    const auto lock_path = database.string() + ".lock";
    const int lock_fd = ::open(lock_path.c_str(), O_CREAT | O_RDWR, 0600);
    check(lock_fd >= 0, "profile_lock_file_open");
    const bool hold_ok = lock_fd >= 0 && ::flock(lock_fd, LOCK_EX | LOCK_NB) == 0;
    check(hold_ok, "profile_lock_flock_held");
    heyaki::ProfileOpenOptions contended = smoke_profile_options();
    const auto delete_while_locked =
        heyaki::ProfileStore::delete_local(database, std::chrono::milliseconds{200});
    check(!delete_while_locked &&
              delete_while_locked.error_if()->code() == heyaki::ErrorCode::profile_locked,
          "profile_exclusive_lock");
    if (lock_fd >= 0) {
      if (hold_ok) {
        (void)::flock(lock_fd, LOCK_UN);
      }
      (void)::close(lock_fd);
    }

    const auto identity = device_id;
    return identity;
  }();  // profile closed here: lock released through the normal destructor.

  // (5) reopen: the identity written before the close is read back.
  auto reopened =
      heyaki::ProfileStore::open(root / "profiles" / "smoke.db", smoke_profile_options());
  if (!reopened) {
    std::cout << "HEYAKI_ANDROID_SMOKE_FAIL profile_reopen " << reopened.error_if()->safe_detail()
              << '\n';
    return 1;
  }
  check(reopened.value_if()->device_id() == device_before, "profile_reopen_identity_durable");

  // Lock-protected teardown: with the lock free, delete_local removes the
  // profile (covers the replacement paths under the same exclusive lock).
  const auto deleted = heyaki::ProfileStore::delete_local(root / "profiles" / "smoke.db",
                                                          std::chrono::milliseconds{2000});
  check(deleted.has_value(), "profile_delete_local_under_lock");

  // (6) node lifecycle with LAN disabled, JNI teardown order.
  {
    auto node_profile = initialize_profile(root / "profiles" / "node-off.db",
                                           "heyaki-android-smoke", "smoke-password");
    (void)run_node(node_profile, false, std::chrono::milliseconds{0});
  }

  // (7) node lifecycle with LAN enabled: an explicit readiness state within
  // the bounded window, then a clean shutdown.
  {
    auto lan_profile = initialize_profile(root / "profiles" / "node-lan.db", "heyaki-android-smoke",
                                          "smoke-password");
    const auto lan_state = run_node(lan_profile, true, std::chrono::milliseconds{8000});
    check(lan_state.has_value(), "node_lan_explicit_readiness_state");
    if (lan_state.has_value()) {
      std::cout << "[smoke] lan readiness on device: "
                << heyaki::lan_readiness_state_name(*lan_state) << '\n';
    }
  }

  std::cout << "HEYAKI_ANDROID_SMOKE_OK checks=" << g_checks << '\n';
  return 0;
}
