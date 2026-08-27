#include "relay_config.hpp"

#include <heyaki/error.hpp>
#include <heyaki/relay_wss_control.hpp>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace heyaki {
namespace {

constexpr std::size_t max_relay_config_file_bytes = 64U * 1024U;

Error config_error(const char* detail, std::optional<std::int64_t> line = std::nullopt) {
  return Error{ErrorCode::configuration, "relay_config", detail, line};
}

bool is_printable_ascii(std::string_view value) noexcept {
  return std::all_of(value.begin(), value.end(), [](unsigned char character) {
    return character >= 0x20U && character <= 0x7eU;
  });
}

std::string_view trim(std::string_view value) noexcept {
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
    value.remove_prefix(1U);
  }
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
    value.remove_suffix(1U);
  }
  return value;
}

Result<std::uint64_t> parse_u64(std::string_view text, const char* detail,
                                std::int64_t line) {
  if (text.empty() || text.size() > 20U) {
    return Result<std::uint64_t>::failure(config_error(detail, line));
  }
  std::uint64_t value = 0U;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      return Result<std::uint64_t>::failure(config_error(detail, line));
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) {
      return Result<std::uint64_t>::failure(config_error(detail, line));
    }
    value = value * 10U + digit;
  }
  return Result<std::uint64_t>::success(value);
}

Result<std::uint16_t> parse_port(std::string_view text, std::int64_t line) {
  auto parsed = parse_u64(text, "relay_config_port_invalid", line);
  if (!parsed || *parsed.value_if() == 0U || *parsed.value_if() > 65535U) {
    return Result<std::uint16_t>::failure(config_error("relay_config_port_invalid", line));
  }
  return Result<std::uint16_t>::success(static_cast<std::uint16_t>(*parsed.value_if()));
}

bool valid_health_path(std::string_view value) noexcept {
  if (value.empty() || value.front() != '/' || value.size() > 128U ||
      !is_printable_ascii(value)) {
    return false;
  }
  return std::none_of(value.begin(), value.end(), [](unsigned char character) {
    return character == ' ' || character == '?' || character == '#';
  });
}

Result<bool> parse_bool(std::string_view text, const char* detail,
                        std::int64_t line) {
  if (text == "true" || text == "1") {
    return Result<bool>::success(true);
  }
  if (text == "false" || text == "0") {
    return Result<bool>::success(false);
  }
  return Result<bool>::failure(config_error(detail, line));
}

bool valid_listen_address(std::string_view value) noexcept {
  return !value.empty() && value.size() <= 253U && is_printable_ascii(value) &&
         std::none_of(value.begin(), value.end(), [](unsigned char character) {
           return std::isspace(character) != 0;
         });
}

}  // namespace

Result<void> validate_relay_server_config(const RelayServerConfig& config) {
  if (!valid_listen_address(config.listen_address) ||
      config.tls_certificate_file.empty() || config.tls_private_key_file.empty() ||
      config.database_file.empty() ||
      !valid_health_path(config.health_path) ||
      config.health_path == relay_wss_control_path || config.max_connections == 0U ||
      config.max_connections > 65536U ||
      config.handshake_timeout.count() < 100 || config.handshake_timeout.count() > 60000 ||
      config.shutdown_timeout.count() < 100 || config.shutdown_timeout.count() > 60000 ||
      config.control_write_queue_frames == 0U ||
      config.control_write_queue_bytes < max_relay_wss_control_frame_bytes ||
      config.control_write_queue_bytes > 64U * 1024U * 1024U ||
      config.lease.capacity == 0U || config.lease.capacity > 65536U ||
      config.lease.per_device_endpoint_capacity == 0U ||
      config.lease.per_tenant_device_capacity == 0U ||
      config.lease.default_lease.count() < 1000 ||
      config.lease.maximum_lease < config.lease.default_lease ||
      config.lease.maximum_lease > std::chrono::milliseconds{120000} ||
      config.endpoint_directory.capacity == 0U ||
      config.endpoint_directory.capacity > 65536U ||
      config.endpoint_directory.maximum_ttl <= std::chrono::milliseconds{0} ||
      config.endpoint_directory.maximum_ttl > std::chrono::milliseconds{5 * 60 * 1000} ||
      config.endpoint_query_max_results == 0U ||
      config.endpoint_query_max_results > 4096U ||
      config.signaling_rate_per_second == 0U ||
      config.signaling_rate_per_second > 1024U) {
    return Result<void>::failure(config_error("relay_config_invalid"));
  }
  return Result<void>::success();
}

Result<RelayServerConfig> load_relay_config_file(
    const std::filesystem::path& config_file) {
  std::error_code error;
  const auto size = std::filesystem::file_size(config_file, error);
  if (error) {
    return Result<RelayServerConfig>::failure(
        config_error("relay_config_file_unreadable",
                     static_cast<std::int64_t>(error.value())));
  }
  if (size > max_relay_config_file_bytes) {
    return Result<RelayServerConfig>::failure(
        config_error("relay_config_file_too_large"));
  }

  std::ifstream input(config_file, std::ios::binary);
  if (!input) {
    return Result<RelayServerConfig>::failure(
        config_error("relay_config_file_unreadable", errno));
  }
  std::string contents(static_cast<std::size_t>(size), '\0');
  if (!contents.empty()) {
    input.read(contents.data(), static_cast<std::streamsize>(contents.size()));
  }
  if (!input && !input.eof()) {
    return Result<RelayServerConfig>::failure(
        config_error("relay_config_file_unreadable"));
  }

  RelayServerConfig config;
  std::optional<std::string_view> listen_address;
  std::optional<std::uint16_t> listen_port;
  std::optional<std::filesystem::path> certificate_file;
  std::optional<std::filesystem::path> private_key_file;
  std::optional<std::filesystem::path> database_file;
  std::optional<std::string> health_path;
  std::optional<std::size_t> max_connections;
  std::optional<std::chrono::milliseconds> handshake_timeout;
  std::optional<std::chrono::milliseconds> shutdown_timeout;
  std::optional<std::chrono::milliseconds> lease_default;
  std::optional<std::chrono::milliseconds> lease_maximum;
  std::optional<std::size_t> lease_capacity;
  std::optional<std::size_t> lease_per_device_capacity;
  std::optional<std::size_t> lease_per_tenant_capacity;
  std::optional<std::size_t> endpoint_directory_capacity;
  std::optional<std::size_t> endpoint_query_max_results;
  std::optional<std::size_t> signaling_rate_per_second;
  std::optional<bool> close_revoked_sessions;
  std::optional<bool> expose_application_id;
  std::optional<bool> expose_record_generation;
  std::optional<bool> expose_manifest_sha256;
  std::optional<bool> expose_manifest_generation;

  std::size_t offset = 0U;
  std::int64_t line_number = 1;
  while (offset < contents.size()) {
    const auto newline = contents.find('\n', offset);
    auto line = std::string_view{contents}.substr(
        offset, newline == std::string::npos ? std::string::npos : newline - offset);
    offset = newline == std::string::npos ? contents.size() : newline + 1U;
    if (!line.empty() && line.back() == '\r') {
      line.remove_suffix(1U);
    }

    const auto trimmed = trim(line);
    if (trimmed.empty() || trimmed.front() == '#') {
      ++line_number;
      continue;
    }
    if (trimmed.find('\0') != std::string_view::npos) {
      return Result<RelayServerConfig>::failure(
          config_error("relay_config_line_invalid", line_number));
    }
    const auto separator = trimmed.find('=');
    if (separator == std::string_view::npos || separator == 0U ||
        separator + 1U >= trimmed.size()) {
      return Result<RelayServerConfig>::failure(
          config_error("relay_config_line_invalid", line_number));
    }
    const auto key = trim(trimmed.substr(0U, separator));
    const auto value = trim(trimmed.substr(separator + 1U));
    if (key.empty() || value.empty() || !is_printable_ascii(key) || !is_printable_ascii(value)) {
      return Result<RelayServerConfig>::failure(
          config_error("relay_config_line_invalid", line_number));
    }

    if (key == "listen_address") {
      if (listen_address) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      config.listen_address = std::string{value};
      listen_address = config.listen_address;
    } else if (key == "listen_port") {
      if (listen_port) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed = parse_port(value, line_number);
      if (!parsed) {
        return Result<RelayServerConfig>::failure(*parsed.error_if());
      }
      config.listen_port = *parsed.value_if();
      listen_port = config.listen_port;
    } else if (key == "tls_certificate_file") {
      if (certificate_file) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      std::filesystem::path path{std::string{value}};
      if (path.is_relative()) {
        path = config_file.parent_path() / path;
      }
      config.tls_certificate_file = std::move(path);
      certificate_file = config.tls_certificate_file;
    } else if (key == "tls_private_key_file") {
      if (private_key_file) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      std::filesystem::path path{std::string{value}};
      if (path.is_relative()) {
        path = config_file.parent_path() / path;
      }
      config.tls_private_key_file = std::move(path);
      private_key_file = config.tls_private_key_file;
    } else if (key == "database_file") {
      if (database_file) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      std::filesystem::path path{std::string{value}};
      if (path != ":memory:" && path.is_relative()) {
        path = config_file.parent_path() / path;
      }
      config.database_file = std::move(path);
      database_file = config.database_file;
    } else if (key == "health_path") {
      if (health_path) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      config.health_path = std::string{value};
      health_path = config.health_path;
    } else if (key == "max_connections") {
      if (max_connections) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed = parse_u64(value, "relay_config_max_connections_invalid", line_number);
      if (!parsed || *parsed.value_if() > 65536U) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_max_connections_invalid", line_number));
      }
      config.max_connections = static_cast<std::size_t>(*parsed.value_if());
      max_connections = config.max_connections;
    } else if (key == "handshake_timeout_milliseconds") {
      if (handshake_timeout) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed =
          parse_u64(value, "relay_config_handshake_timeout_invalid", line_number);
      if (!parsed || *parsed.value_if() > 60000U) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_handshake_timeout_invalid", line_number));
      }
      config.handshake_timeout = std::chrono::milliseconds{*parsed.value_if()};
      handshake_timeout = config.handshake_timeout;
    } else if (key == "lease_default_milliseconds") {
      if (lease_default) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed = parse_u64(value, "relay_config_lease_default_invalid", line_number);
      if (!parsed || *parsed.value_if() > 120000U) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_lease_default_invalid", line_number));
      }
      config.lease.default_lease = std::chrono::milliseconds{*parsed.value_if()};
      lease_default = config.lease.default_lease;
    } else if (key == "lease_maximum_milliseconds") {
      if (lease_maximum) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed = parse_u64(value, "relay_config_lease_maximum_invalid", line_number);
      if (!parsed || *parsed.value_if() > 120000U) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_lease_maximum_invalid", line_number));
      }
      config.lease.maximum_lease = std::chrono::milliseconds{*parsed.value_if()};
      lease_maximum = config.lease.maximum_lease;
    } else if (key == "lease_capacity") {
      if (lease_capacity) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed = parse_u64(value, "relay_config_lease_capacity_invalid", line_number);
      if (!parsed || *parsed.value_if() > 65536U) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_lease_capacity_invalid", line_number));
      }
      config.lease.capacity = static_cast<std::size_t>(*parsed.value_if());
      lease_capacity = config.lease.capacity;
    } else if (key == "lease_per_device_endpoint_capacity") {
      if (lease_per_device_capacity) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed = parse_u64(value, "relay_config_per_device_capacity_invalid", line_number);
      if (!parsed || *parsed.value_if() > 65536U) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_per_device_capacity_invalid", line_number));
      }
      config.lease.per_device_endpoint_capacity = static_cast<std::size_t>(*parsed.value_if());
      lease_per_device_capacity = config.lease.per_device_endpoint_capacity;
    } else if (key == "lease_per_tenant_device_capacity") {
      if (lease_per_tenant_capacity) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed = parse_u64(value, "relay_config_per_tenant_capacity_invalid", line_number);
      if (!parsed || *parsed.value_if() > 65536U) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_per_tenant_capacity_invalid", line_number));
      }
      config.lease.per_tenant_device_capacity = static_cast<std::size_t>(*parsed.value_if());
      lease_per_tenant_capacity = config.lease.per_tenant_device_capacity;
    } else if (key == "endpoint_directory_capacity") {
      if (endpoint_directory_capacity) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed = parse_u64(value, "relay_config_endpoint_directory_capacity_invalid",
                              line_number);
      if (!parsed || *parsed.value_if() > 65536U) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_endpoint_directory_capacity_invalid", line_number));
      }
      config.endpoint_directory.capacity = static_cast<std::size_t>(*parsed.value_if());
      endpoint_directory_capacity = config.endpoint_directory.capacity;
    } else if (key == "endpoint_query_max_results") {
      if (endpoint_query_max_results) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed = parse_u64(value, "relay_config_endpoint_query_max_invalid", line_number);
      if (!parsed || *parsed.value_if() > 4096U) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_endpoint_query_max_invalid", line_number));
      }
      config.endpoint_query_max_results = static_cast<std::size_t>(*parsed.value_if());
      endpoint_query_max_results = config.endpoint_query_max_results;
    } else if (key == "signaling_rate_per_second") {
      if (signaling_rate_per_second) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed =
          parse_u64(value, "relay_config_signaling_rate_invalid", line_number);
      if (!parsed || *parsed.value_if() == 0U || *parsed.value_if() > 1024U) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_signaling_rate_invalid", line_number));
      }
      config.signaling_rate_per_second = static_cast<std::size_t>(*parsed.value_if());
      signaling_rate_per_second = config.signaling_rate_per_second;
    } else if (key == "close_revoked_sessions") {
      if (close_revoked_sessions) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed = parse_bool(value, "relay_config_close_revoked_invalid", line_number);
      if (!parsed) {
        return Result<RelayServerConfig>::failure(*parsed.error_if());
      }
      config.close_revoked_sessions = *parsed.value_if();
      close_revoked_sessions = config.close_revoked_sessions;
    } else if (key == "endpoint_expose_application_id") {
      if (expose_application_id) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed = parse_bool(value, "relay_config_expose_application_invalid", line_number);
      if (!parsed) {
        return Result<RelayServerConfig>::failure(*parsed.error_if());
      }
      config.endpoint_exposure.expose_application_id = *parsed.value_if();
      expose_application_id = config.endpoint_exposure.expose_application_id;
    } else if (key == "endpoint_expose_record_generation") {
      if (expose_record_generation) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed = parse_bool(value, "relay_config_expose_record_generation_invalid", line_number);
      if (!parsed) {
        return Result<RelayServerConfig>::failure(*parsed.error_if());
      }
      config.endpoint_exposure.expose_record_generation = *parsed.value_if();
      expose_record_generation = config.endpoint_exposure.expose_record_generation;
    } else if (key == "endpoint_expose_manifest_sha256") {
      if (expose_manifest_sha256) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed = parse_bool(value, "relay_config_expose_manifest_sha256_invalid", line_number);
      if (!parsed) {
        return Result<RelayServerConfig>::failure(*parsed.error_if());
      }
      config.endpoint_exposure.expose_manifest_sha256 = *parsed.value_if();
      expose_manifest_sha256 = config.endpoint_exposure.expose_manifest_sha256;
    } else if (key == "endpoint_expose_manifest_generation") {
      if (expose_manifest_generation) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed = parse_bool(value, "relay_config_expose_manifest_generation_invalid",
                               line_number);
      if (!parsed) {
        return Result<RelayServerConfig>::failure(*parsed.error_if());
      }
      config.endpoint_exposure.expose_manifest_generation = *parsed.value_if();
      expose_manifest_generation = config.endpoint_exposure.expose_manifest_generation;
    } else if (key == "shutdown_timeout_milliseconds") {
      if (shutdown_timeout) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_duplicate_key", line_number));
      }
      auto parsed =
          parse_u64(value, "relay_config_shutdown_timeout_invalid", line_number);
      if (!parsed || *parsed.value_if() > 60000U) {
        return Result<RelayServerConfig>::failure(
            config_error("relay_config_shutdown_timeout_invalid", line_number));
      }
      config.shutdown_timeout = std::chrono::milliseconds{*parsed.value_if()};
      shutdown_timeout = config.shutdown_timeout;
    } else {
      return Result<RelayServerConfig>::failure(
          config_error("relay_config_unknown_key", line_number));
    }
    ++line_number;
  }

  auto valid = validate_relay_server_config(config);
  if (!valid) {
    return Result<RelayServerConfig>::failure(*valid.error_if());
  }
  std::error_code existence_error;
  const bool certificate_exists =
      std::filesystem::is_regular_file(config.tls_certificate_file, existence_error);
  if (existence_error || !certificate_exists) {
    return Result<RelayServerConfig>::failure(
        config_error("relay_config_certificate_missing",
                     existence_error ? std::optional<std::int64_t>{existence_error.value()}
                                     : std::nullopt));
  }
  const bool key_exists =
      std::filesystem::is_regular_file(config.tls_private_key_file, existence_error);
  if (existence_error || !key_exists) {
    return Result<RelayServerConfig>::failure(
        config_error("relay_config_private_key_missing",
                     existence_error ? std::optional<std::int64_t>{existence_error.value()}
                                     : std::nullopt));
  }
  return Result<RelayServerConfig>::success(std::move(config));
}

}  // namespace heyaki
