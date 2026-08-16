#pragma once

#include <heyaki/error.hpp>
#include <heyaki/runtime.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace heyaki {

inline constexpr std::size_t relay_tls_pin_bytes = 32U;
using RelayTlsPin = std::array<std::byte, relay_tls_pin_bytes>;

struct RelayWssClientConfig {
  std::string url{"wss://127.0.0.1:8443/health"};
  std::optional<RelayTlsPin> relay_pin;
  std::optional<std::filesystem::path> tls_ca_file;
  bool tls_verify_peer{true};
  std::size_t receive_capacity{64U};
  std::size_t send_capacity{64U};
  std::chrono::milliseconds connect_timeout{5000};
  std::chrono::milliseconds handshake_timeout{5000};
  std::chrono::milliseconds close_timeout{2000};
  RuntimeConfig runtime;
};

enum class RelayWssState : std::uint8_t {
  disconnected,
  connecting,
  ready,
  closing,
  failed,
};

struct RelayWssMessage {
  bool text{false};
  std::vector<std::byte> payload;
};

struct RelayWssSnapshot {
  RelayWssState state{RelayWssState::disconnected};
  std::string host;
  std::string port;
  std::string path;
  std::uint64_t messages_received{};
  std::uint64_t messages_sent{};
  std::uint64_t receive_rejected{};
  std::uint64_t send_rejected{};
  std::uint64_t bytes_received{};
  std::uint64_t bytes_sent{};
  std::optional<Error> last_error;
};

class RelayWssClient {
 public:
  struct Impl;

  RelayWssClient(RelayWssClient&&) noexcept;
  RelayWssClient& operator=(RelayWssClient&&) noexcept;
  ~RelayWssClient();

  RelayWssClient(const RelayWssClient&) = delete;
  RelayWssClient& operator=(const RelayWssClient&) = delete;

  [[nodiscard]] static Result<RelayWssClient> create(RelayWssClientConfig config,
                                                     Runtime* runtime = nullptr);

  [[nodiscard]] Result<void> connect(std::chrono::milliseconds timeout =
                                         std::chrono::milliseconds{5000});
  [[nodiscard]] Result<void> send(std::span<const std::byte> payload);
  [[nodiscard]] Result<RelayWssMessage> receive(
      std::chrono::milliseconds timeout = std::chrono::milliseconds{5000});
  [[nodiscard]] Result<void> close(std::chrono::milliseconds timeout =
                                       std::chrono::milliseconds{2000});
  [[nodiscard]] RelayWssSnapshot snapshot() const;

 private:
  explicit RelayWssClient(std::shared_ptr<Impl> impl) noexcept;

  std::shared_ptr<Impl> impl_;
};

[[nodiscard]] std::string_view relay_wss_state_name(RelayWssState state) noexcept;

}  // namespace heyaki
