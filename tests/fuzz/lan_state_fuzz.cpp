#include "fuzz_targets.hpp"

#include <heyaki/identity.hpp>
#include <heyaki/lan_directory.hpp>
#include <heyaki/lan_protocol.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <span>
#include <string>

namespace heyaki::fuzz {
namespace {

LanConfiguration fuzz_configuration() {
  LanConfiguration configuration;
  configuration.directory_capacity = 8U;
  configuration.trusted_directory_reserve = 2U;
  configuration.per_interface_directory_capacity = 4U;
  configuration.per_source_presence_capacity = 4U;
  configuration.unknown_identity_capacity = 6U;
  configuration.replay_capacity = 8U;
  configuration.diagnostic_capacity = 8U;
  configuration.announcement_rate_per_second = 64U;
  configuration.per_source_announcement_rate = 16U;
  return configuration;
}

void assert_directory_invariants(const EndpointDirectory& directory,
                                 const LanConfiguration& configuration,
                                 std::chrono::steady_clock::time_point now) {
  const auto diagnostics = directory.diagnostics();
  const auto snapshot = directory.snapshot(now);
  if (diagnostics.current_entries > configuration.directory_capacity ||
      diagnostics.peak_entries > configuration.directory_capacity ||
      diagnostics.replay_entries > configuration.replay_capacity ||
      diagnostics.source_rate_entries > configuration.per_source_presence_capacity ||
      diagnostics.diagnostic_history_size > configuration.diagnostic_capacity ||
      snapshot.size() > diagnostics.current_entries) {
    std::abort();
  }
  for (std::size_t index = 0U; index < snapshot.size(); ++index) {
    const auto& entry = snapshot[index];
    if (entry.key.device_id.is_zero() || entry.key.endpoint_id.is_zero() ||
        (!entry.lan && !entry.relay) ||
        (entry.lan && (entry.lan->tls_signaling_port == 0U ||
                       entry.lan->ttl.count() <= 0))) {
      std::abort();
    }
    if (std::any_of(snapshot.begin() + static_cast<std::ptrdiff_t>(index + 1U),
                    snapshot.end(), [&](const auto& candidate) {
                      return candidate.key == entry.key;
                    })) {
      std::abort();
    }
  }
}

}  // namespace

void lan_directory_state_machine(std::span<const std::byte> input) {
  const auto identity = create_identity();
  const auto configuration = fuzz_configuration();
  auto directory = EndpointDirectory::create(configuration);
  if (!identity || !directory) {
    std::abort();
  }

  auto now = std::chrono::steady_clock::now();
  for (std::size_t offset = 0U; offset < input.size(); offset += 6U) {
    const auto byte = [&](std::size_t relative) {
      const auto index = offset + relative;
      return index < input.size() ? std::to_integer<unsigned int>(input[index]) : 0U;
    };
    const auto operation = byte(0U) % 5U;
    now += std::chrono::milliseconds{byte(5U) % 41U};
    if (operation == 0U) {
      now += std::chrono::milliseconds{byte(4U) * 20U};
      directory.value_if()->expire(now);
      assert_directory_invariants(*directory.value_if(), configuration, now);
      continue;
    }

    LanPresence presence;
    EndpointId::Storage endpoint_bytes{};
    endpoint_bytes[0] = static_cast<std::byte>((byte(1U) % 12U) + 1U);
    presence.endpoint_id = EndpointId{endpoint_bytes};
    presence.boot_nonce[0] = static_cast<std::byte>((byte(2U) % 6U) + 1U);
    presence.sequence = (byte(3U) % 12U) + 1U;
    presence.tls_signaling_port = static_cast<std::uint16_t>(49190U + (byte(1U) % 32U));
    presence.lease = std::chrono::milliseconds{1000U + (byte(4U) % 200U)};
    if (!sign_lan_presence(presence, *identity.value_if())) {
      std::abort();
    }

    const auto source = "192.0.2." + std::to_string((byte(4U) % 6U) + 1U);
    const auto interface_name = "fuzz" + std::to_string(byte(2U) % 6U);
    const bool trusted = operation == 4U;
    (void)directory.value_if()->observe_lan(presence, source, interface_name,
                                            trusted, now);
    assert_directory_invariants(*directory.value_if(), configuration, now);
  }
}

}  // namespace heyaki::fuzz
