#include <heyaki/node.hpp>

#include "runtime_access.hpp"
#include "connection_attempt.hpp"
#include "peer_session.hpp"
#include "relay_signaling_route.hpp"
#include "relay_wss_client.hpp"
#include "signaling_coordinator.hpp"
#include "../relay/relay_endpoint.hpp"
#include "../relay/relay_login.hpp"
#include "../transport/webrtc/webrtc_transport_session.hpp"

#include <heyaki/relay_wss_control.hpp>

#include <executor/comm.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/multicast.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/write.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <sodium.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <future>
#include <limits>
#include <random>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#ifdef _WIN32
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace heyaki {
namespace {

using boost::asio::ip::tcp;
using boost::asio::ip::udp;
using SteadyTime = std::chrono::steady_clock::time_point;

constexpr auto multicast_readiness_timeout = std::chrono::milliseconds{1500};

struct InterfaceBinding {
  std::string name;
  std::uint32_t index{};
  LanInterfaceFamily family{LanInterfaceFamily::ipv4};
  std::string address;
  boost::asio::ip::address asio_address;

  friend bool operator==(const InterfaceBinding& left,
                         const InterfaceBinding& right) noexcept {
    return left.name == right.name && left.index == right.index &&
           left.family == right.family && left.address == right.address;
  }
};

struct InterfaceScanResult {
  std::vector<InterfaceBinding> bindings;
  std::optional<Error> error;
};

Error node_error(ErrorCode code, const char* detail,
                 std::optional<std::int64_t> underlying = std::nullopt) {
  return {code, "node", detail, underlying};
}

NodeConnectionStage public_connection_stage(ConnectionStage stage) noexcept {
  switch (stage) {
    case ConnectionStage::idle:
      return NodeConnectionStage::idle;
    case ConnectionStage::resolving_endpoint:
      return NodeConnectionStage::resolving_endpoint;
    case ConnectionStage::signaling:
      return NodeConnectionStage::signaling;
    case ConnectionStage::gathering:
      return NodeConnectionStage::gathering;
    case ConnectionStage::checking:
      return NodeConnectionStage::checking;
    case ConnectionStage::transport_connected:
      return NodeConnectionStage::transport_connected;
    case ConnectionStage::authenticating:
      return NodeConnectionStage::authenticating;
    case ConnectionStage::authenticated:
      return NodeConnectionStage::authenticated;
    case ConnectionStage::closed:
      return NodeConnectionStage::closed;
  }
  return NodeConnectionStage::closed;
}

NodeDataPathKind public_data_path(transport::DataPathKind path) noexcept {
  switch (path) {
    case transport::DataPathKind::unknown:
      return NodeDataPathKind::unknown;
    case transport::DataPathKind::direct_host:
      return NodeDataPathKind::direct_host;
    case transport::DataPathKind::direct_srflx:
      return NodeDataPathKind::direct_srflx;
    case transport::DataPathKind::turn_udp:
      return NodeDataPathKind::turn_udp;
    case transport::DataPathKind::turn_tcp:
      return NodeDataPathKind::turn_tcp;
    case transport::DataPathKind::turn_tls:
      return NodeDataPathKind::turn_tls;
  }
  return NodeDataPathKind::unknown;
}

Error discovery_error(ErrorCode code, const char* detail,
                      const boost::system::error_code& error = {}) {
  return {code, "lan_discovery", detail,
          error ? std::optional<std::int64_t>{error.value()} : std::nullopt};
}

Error tls_error(ErrorCode code, const char* detail,
                const boost::system::error_code& error = {}) {
  return {code, "lan_tls", detail,
          error ? std::optional<std::int64_t>{error.value()} : std::nullopt};
}

bool is_multicast_readiness_error(const Error& error) {
  return error.safe_detail() == "presence_send_failed" ||
         error.safe_detail() == "multicast_probe_timed_out";
}

std::uint64_t unix_milliseconds_now() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
}

bool preference_matches(const InterfaceBinding& binding,
                        const std::vector<std::string>& preferences) {
  if (preferences.empty()) {
    return true;
  }
  const auto index = std::to_string(binding.index);
  return std::any_of(preferences.begin(), preferences.end(), [&](const std::string& preference) {
    return preference == binding.name || preference == binding.address || preference == index;
  });
}

#ifdef _WIN32
Result<std::vector<InterfaceBinding>> enumerate_interfaces(
    const LanConfiguration& configuration) {
  ULONG size = 16U * 1024U;
  std::vector<unsigned char> storage(size);
  auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
  ULONG result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                                     GAA_FLAG_SKIP_DNS_SERVER,
                                      nullptr, adapters, &size);
  if (result == ERROR_BUFFER_OVERFLOW && size <= 1024U * 1024U) {
    storage.resize(size);
    adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
    result = GetAdaptersAddresses(AF_UNSPEC,
                                  GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                      GAA_FLAG_SKIP_DNS_SERVER,
                                  nullptr, adapters, &size);
  }
  if (result != NO_ERROR) {
    return Result<std::vector<InterfaceBinding>>::failure(
        node_error(ErrorCode::transport, "interface_enumeration_failed", result));
  }
  std::vector<InterfaceBinding> output;
  for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
    if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
        adapter->IfType == IF_TYPE_TUNNEL) {
      continue;
    }
    const std::string name = adapter->AdapterName != nullptr ? adapter->AdapterName : "adapter";
    for (auto* unicast = adapter->FirstUnicastAddress; unicast != nullptr;
         unicast = unicast->Next) {
      const auto* socket_address = unicast->Address.lpSockaddr;
      if (socket_address == nullptr) {
        continue;
      }
      std::array<char, INET6_ADDRSTRLEN> text{};
      InterfaceBinding binding;
      binding.name = name;
      if (socket_address->sa_family == AF_INET) {
        const auto* address = reinterpret_cast<const sockaddr_in*>(socket_address);
        if (InetNtopA(AF_INET, const_cast<IN_ADDR*>(&address->sin_addr), text.data(),
                      static_cast<DWORD>(text.size())) == nullptr) {
          continue;
        }
        binding.index = adapter->IfIndex;
        binding.family = LanInterfaceFamily::ipv4;
      } else if (socket_address->sa_family == AF_INET6) {
        const auto* address = reinterpret_cast<const sockaddr_in6*>(socket_address);
        if (InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&address->sin6_addr), text.data(),
                      static_cast<DWORD>(text.size())) == nullptr) {
          continue;
        }
        binding.index = adapter->Ipv6IfIndex;
        binding.family = LanInterfaceFamily::ipv6;
      } else {
        continue;
      }
      binding.address = text.data();
      boost::system::error_code parsed_error;
      binding.asio_address = boost::asio::ip::make_address(binding.address, parsed_error);
      if (!parsed_error && preference_matches(binding, configuration.interface_preferences)) {
        output.push_back(std::move(binding));
      }
    }
  }
  std::sort(output.begin(), output.end(), [](const auto& left, const auto& right) {
    return std::tie(left.name, left.family, left.address) <
           std::tie(right.name, right.family, right.address);
  });
  output.erase(std::unique(output.begin(), output.end()), output.end());
  return Result<std::vector<InterfaceBinding>>::success(std::move(output));
}
#else
Result<std::vector<InterfaceBinding>> enumerate_interfaces(
    const LanConfiguration& configuration) {
  ifaddrs* addresses = nullptr;
  if (::getifaddrs(&addresses) != 0) {
    return Result<std::vector<InterfaceBinding>>::failure(
        node_error(ErrorCode::transport, "interface_enumeration_failed", errno));
  }
  std::vector<InterfaceBinding> output;
  for (auto* current = addresses; current != nullptr; current = current->ifa_next) {
    if (current->ifa_addr == nullptr || current->ifa_name == nullptr ||
        (current->ifa_flags & IFF_UP) == 0U || (current->ifa_flags & IFF_MULTICAST) == 0U ||
        (current->ifa_flags & IFF_LOOPBACK) != 0U) {
      continue;
    }
    const int family = current->ifa_addr->sa_family;
    if (family != AF_INET && family != AF_INET6) {
      continue;
    }
    std::array<char, INET6_ADDRSTRLEN> text{};
    const void* source = family == AF_INET
                             ? static_cast<const void*>(&reinterpret_cast<sockaddr_in*>(
                                                            current->ifa_addr)
                                                            ->sin_addr)
                             : static_cast<const void*>(&reinterpret_cast<sockaddr_in6*>(
                                                            current->ifa_addr)
                                                            ->sin6_addr);
    if (::inet_ntop(family, source, text.data(), text.size()) == nullptr) {
      continue;
    }
    InterfaceBinding binding;
    binding.name = current->ifa_name;
    binding.index = ::if_nametoindex(current->ifa_name);
    binding.family = family == AF_INET ? LanInterfaceFamily::ipv4 : LanInterfaceFamily::ipv6;
    binding.address = text.data();
    boost::system::error_code parsed_error;
    binding.asio_address = boost::asio::ip::make_address(binding.address, parsed_error);
    if (binding.index != 0U && !parsed_error &&
        preference_matches(binding, configuration.interface_preferences)) {
      output.push_back(std::move(binding));
    }
  }
  ::freeifaddrs(addresses);
  std::sort(output.begin(), output.end(), [](const auto& left, const auto& right) {
    return std::tie(left.name, left.family, left.address) <
           std::tie(right.name, right.family, right.address);
  });
  output.erase(std::unique(output.begin(), output.end()), output.end());
  return Result<std::vector<InterfaceBinding>>::success(std::move(output));
}
#endif

bool verify_any_certificate(bool, boost::asio::ssl::verify_context&) { return true; }

Result<TlsCertificateFingerprint> configure_boot_certificate(
    boost::asio::ssl::context& context) {
  EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1");
  if (key == nullptr) {
    return Result<TlsCertificateFingerprint>::failure(
        node_error(ErrorCode::internal, "tls_key_generation_failed"));
  }
  X509* certificate = X509_new();
  if (certificate == nullptr) {
    EVP_PKEY_free(key);
    return Result<TlsCertificateFingerprint>::failure(
        node_error(ErrorCode::internal, "tls_certificate_generation_failed"));
  }
  std::array<unsigned char, 8U> serial_bytes{};
  std::uint64_t serial = 1U;
  if (RAND_bytes(serial_bytes.data(), static_cast<int>(serial_bytes.size())) == 1) {
    std::memcpy(&serial, serial_bytes.data(), serial_bytes.size());
    serial &= (std::numeric_limits<std::uint64_t>::max)() >> 1U;
    serial = std::max<std::uint64_t>(serial, 1U);
  }
  bool configured = X509_set_version(certificate, 2L) == 1 &&
                    ASN1_INTEGER_set_uint64(X509_get_serialNumber(certificate), serial) == 1 &&
                    X509_gmtime_adj(X509_getm_notBefore(certificate), -60L) != nullptr &&
                    X509_gmtime_adj(X509_getm_notAfter(certificate), 24L * 60L * 60L) != nullptr &&
                    X509_set_pubkey(certificate, key) == 1;
  X509_NAME* name = X509_get_subject_name(certificate);
  configured = configured && name != nullptr &&
               X509_NAME_add_entry_by_txt(
                   name, "CN", MBSTRING_ASC,
                   reinterpret_cast<const unsigned char*>("heyaki-boot"), -1, -1, 0) == 1 &&
               X509_set_issuer_name(certificate, name) == 1;
  X509_EXTENSION* constraints = X509V3_EXT_conf_nid(
      nullptr, nullptr, NID_basic_constraints, const_cast<char*>("critical,CA:FALSE"));
  if (constraints != nullptr) {
    configured = configured && X509_add_ext(certificate, constraints, -1) == 1;
    X509_EXTENSION_free(constraints);
  } else {
    configured = false;
  }
  configured = configured && X509_sign(certificate, key, EVP_sha256()) > 0 &&
               SSL_CTX_use_certificate(context.native_handle(), certificate) == 1 &&
               SSL_CTX_use_PrivateKey(context.native_handle(), key) == 1 &&
               SSL_CTX_check_private_key(context.native_handle()) == 1;
  TlsCertificateFingerprint fingerprint{};
  unsigned int fingerprint_size = 0U;
  configured = configured &&
               X509_digest(certificate, EVP_sha256(),
                           reinterpret_cast<unsigned char*>(fingerprint.data()),
                           &fingerprint_size) == 1 &&
               fingerprint_size == fingerprint.size();
  X509_free(certificate);
  EVP_PKEY_free(key);
  if (!configured) {
    return Result<TlsCertificateFingerprint>::failure(
        node_error(ErrorCode::internal, "tls_certificate_configuration_failed"));
  }
  return Result<TlsCertificateFingerprint>::success(fingerprint);
}

Result<TlsCertificateFingerprint> peer_certificate_fingerprint(SSL* ssl) {
  X509* certificate = SSL_get1_peer_certificate(ssl);
  if (certificate == nullptr) {
    return Result<TlsCertificateFingerprint>::failure(
        tls_error(ErrorCode::authentication, "peer_certificate_missing"));
  }
  TlsCertificateFingerprint fingerprint{};
  unsigned int size = 0U;
  const bool digested = X509_digest(
                            certificate, EVP_sha256(),
                            reinterpret_cast<unsigned char*>(fingerprint.data()), &size) == 1 &&
                        size == fingerprint.size();
  X509_free(certificate);
  if (!digested) {
    return Result<TlsCertificateFingerprint>::failure(
        tls_error(ErrorCode::internal, "peer_certificate_digest_failed"));
  }
  return Result<TlsCertificateFingerprint>::success(fingerprint);
}

executor::comm::ChannelOptions scan_channel_options() {
  executor::comm::ChannelOptions options;
  options.capacity = 1U;
  options.name = "heyaki-interface-scan";
  return options;
}

executor::comm::ChannelOptions signaling_channel_options(std::size_t capacity,
                                                         std::string name) {
  executor::comm::ChannelOptions options;
  options.capacity = capacity;
  options.name = std::move(name);
  return options;
}

RuntimeShutdownCompletion ready_shutdown_completion(Result<void> result) {
  auto promise = std::make_shared<std::promise<Result<void>>>();
  auto future = promise->get_future().share();
  promise->set_value(std::move(result));
  return future;
}

std::vector<std::byte> frame_hello(std::span<const std::byte> payload) {
  std::vector<std::byte> output;
  if (payload.size() > std::numeric_limits<std::uint16_t>::max()) {
    return output;
  }
  output.reserve(payload.size() + 2U);
  const auto size = static_cast<std::uint16_t>(payload.size());
  output.push_back(static_cast<std::byte>((size >> 8U) & 0xffU));
  output.push_back(static_cast<std::byte>(size & 0xffU));
  output.insert(output.end(), payload.begin(), payload.end());
  return output;
}

Result<void> validate_signaling_message_shape(const LanSignalingMessage& message) {
  if (message.peer.device_id.is_zero() || message.peer.endpoint_id.is_zero()) {
    return Result<void>::failure(tls_error(ErrorCode::protocol,
                                           "signaling_message_invalid"));
  }
  return validate_lan_signaling_frame(
      LanSignalingFrame{message.kind, message.request_id, message.payload});
}

bool is_signed_signaling_kind(LanSignalingMessageKind kind) noexcept {
  return kind == LanSignalingMessageKind::signed_offer ||
         kind == LanSignalingMessageKind::signed_answer ||
         kind == LanSignalingMessageKind::signed_candidate;
}

}  // namespace

static std::string relay_control_url(std::string relay_url) {
  while (relay_url.size() > 1U && relay_url.back() == '/') {
    relay_url.pop_back();
  }
  if (relay_url.ends_with(relay_wss_control_path)) {
    return relay_url;
  }
  relay_url.append(relay_wss_control_path);
  return relay_url;
}

Result<void> validate_relay_node_config(const RelayNodeConfig& config) {
  if (!config.enabled) {
    return Result<void>::success();
  }
  if (config.relay_url.empty() || config.relay_url.size() > 2048U ||
      config.tenant.empty() || config.tenant.size() > 128U ||
      (config.relay_pin && config.relay_pin->size() != relay_tls_pin_bytes) ||
      config.enrollment_generation == 0U ||
      config.connect_timeout.count() <= 0 || config.handshake_timeout.count() <= 0 ||
      config.close_timeout.count() <= 0 || config.heartbeat_interval.count() < 1000 ||
      config.lease_duration.count() < 1000 ||
      config.lease_duration > std::chrono::milliseconds{120000} ||
      config.missed_heartbeat_limit == 0U || config.missed_heartbeat_limit > 64U ||
      config.minimum_backoff.count() < 100 || config.maximum_backoff < config.minimum_backoff ||
      config.poll_interval.count() < 10 || config.poll_interval.count() > 1000 ||
      config.receive_capacity == 0U || config.send_capacity == 0U) {
    return Result<void>::failure(
        node_error(ErrorCode::configuration, "relay_node_config_invalid"));
  }
  return Result<void>::success();
}

bool is_relay_security_error(const Error& error) noexcept {
  return error.code() == ErrorCode::authentication ||
         error.code() == ErrorCode::enrollment_revoked ||
         error.code() == ErrorCode::permission;
}

class Node::Impl : public std::enable_shared_from_this<Node::Impl> {
 public:
  class LanCoordinatorRoute final : public SignalingRoute {
   public:
    explicit LanCoordinatorRoute(Impl& owner) : owner_(owner) {}

    [[nodiscard]] SignalingRouteKind kind() const noexcept override {
      return SignalingRouteKind::lan;
    }

    [[nodiscard]] Result<void> send(const SignalingEnvelope& message) override {
      return owner_.send_coordinator_envelope(message);
    }

   private:
    Impl& owner_;
  };

  struct PeerAttempt {
    NodePeerSessionSnapshot snapshot;
    IdentityPublicKey peer_public_key{};
    std::shared_ptr<ConnectionAttemptTimeline> timeline;
    std::shared_ptr<transport::webrtc::WebRtcTransportSession> transport;
    std::shared_ptr<PeerSession> session;
    std::deque<std::vector<std::byte>> pending_local_candidates;
    std::deque<std::vector<std::byte>> pending_remote_candidates;
    bool candidate_signing_ready{false};
    bool remote_description_ready{false};
    bool retiring{false};
  };

  struct DiscoverySocket : public std::enable_shared_from_this<DiscoverySocket> {
    DiscoverySocket(boost::asio::strand<boost::asio::any_io_executor> executor,
                    InterfaceBinding binding)
        : socket(std::move(executor)), binding(std::move(binding)) {}

    udp::socket socket;
    InterfaceBinding binding;
    udp::endpoint multicast_endpoint;
    udp::endpoint sender_endpoint;
    std::array<std::byte, max_lan_datagram_bytes + 1U> receive_buffer{};
    bool multicast_verified{false};
  };

  struct ConnectCommand {
    DeviceEndpointKey peer;
    SignalingRouteKind route{SignalingRouteKind::lan};
  };

  struct SendCommand {
    LanSignalingMessage message;
  };

  struct CloseCommand {
    DeviceEndpointKey peer;
  };

  using SignalingCommand = std::variant<ConnectCommand, SendCommand, CloseCommand>;

  struct SignalingCallbackResult {
    std::uint64_t connection_id{};
    bool outbound{false};
    LanSignalingMessage message;
    std::optional<Error> error;
  };

  struct TlsConnection : public std::enable_shared_from_this<TlsConnection> {
    TlsConnection(std::weak_ptr<Impl> owner, std::uint64_t id, tcp::socket socket,
                  boost::asio::ssl::context& context, std::string remote_address,
                  bool inbound)
        : owner(std::move(owner)), id(id), stream(std::move(socket), context),
          timer(stream.get_executor()), remote_address(std::move(remote_address)),
          inbound(inbound) {}

    void start_server() {
      auto current = owner.lock();
      if (!current) {
        return;
      }
      arm_timeout(current->lan.handshake_timeout, "tls_handshake_timeout");
      auto self = shared_from_this();
      stream.async_handshake(boost::asio::ssl::stream_base::server,
                             [self](const boost::system::error_code& error) {
        auto current_owner = self->owner.lock();
        if (!current_owner) {
          return;
        }
        if (error) {
          current_owner->connection_failed(self->id, "tls_handshake_failed", error, false);
          return;
        }
        auto fingerprint = peer_certificate_fingerprint(self->stream.native_handle());
        if (!fingerprint) {
          current_owner->connection_failed(self->id, "peer_certificate_invalid", {}, false);
          return;
        }
        self->peer_fingerprint = *fingerprint.value_if();
        current_owner->connection_state_changed(
            self, LanSignalingConnectionState::provisional_tls);
        self->arm_timeout(current_owner->lan.hello_timeout, "lan_hello_timeout");
        self->read_hello([self](Result<LanHello> hello) {
          if (auto hello_owner = self->owner.lock()) {
            hello_owner->handle_initial_hello(self, std::move(hello));
          }
        });
      });
    }

    void start_client(tcp::endpoint endpoint) {
      auto current = owner.lock();
      if (!current) {
        return;
      }
      arm_timeout(current->lan.handshake_timeout, "tls_connect_timeout");
      auto self = shared_from_this();
      stream.lowest_layer().async_connect(
          endpoint, [self](const boost::system::error_code& connect_error) {
            auto current_owner = self->owner.lock();
            if (!current_owner) {
              return;
            }
            if (connect_error) {
              current_owner->connection_failed(self->id, "tls_connect_failed",
                                                connect_error, false);
              return;
            }
            current_owner->connection_state_changed(
                self, LanSignalingConnectionState::provisional_tls);
            self->stream.async_handshake(
                boost::asio::ssl::stream_base::client,
                [self](const boost::system::error_code& handshake_error) {
                  auto handshake_owner = self->owner.lock();
                  if (!handshake_owner) {
                    return;
                  }
                  if (handshake_error) {
                    handshake_owner->connection_failed(
                        self->id, "tls_handshake_failed", handshake_error, false);
                    return;
                  }
                  auto fingerprint =
                      peer_certificate_fingerprint(self->stream.native_handle());
                  if (!fingerprint) {
                    handshake_owner->connection_failed(
                        self->id, "peer_certificate_invalid", {}, false);
                    return;
                  }
                  self->peer_fingerprint = *fingerprint.value_if();
                  handshake_owner->handle_client_tls_ready(self);
                });
          });
    }

    void arm_timeout(std::chrono::milliseconds timeout, const char* detail) {
      timer.expires_after(timeout);
      auto self = shared_from_this();
      timer.async_wait([self, detail](const boost::system::error_code& error) {
        if (!error) {
          if (auto timeout_owner = self->owner.lock()) {
            timeout_owner->connection_failed(self->id, detail, {}, true);
          }
        }
      });
    }

    void read_signaling(std::function<void(Result<LanSignalingMessage>)> completion) {
      auto self = shared_from_this();
      boost::asio::async_read(
          stream,
          boost::asio::buffer(signaling_frame.data(),
                              lan_signaling_frame_header_bytes),
          [self, completion = std::move(completion)](const boost::system::error_code& error,
                                                      std::size_t) mutable {
            if (error) {
              completion(Result<LanSignalingMessage>::failure(
                  tls_error(error == boost::asio::error::eof ? ErrorCode::cancelled
                                                             : ErrorCode::signaling,
                            "signaling_header_read_failed", error)));
              return;
            }
            const auto size =
                (static_cast<std::size_t>(std::to_integer<std::uint8_t>(
                     self->signaling_frame[0]))
                 << 24U) |
                (static_cast<std::size_t>(std::to_integer<std::uint8_t>(
                     self->signaling_frame[1]))
                 << 16U) |
                (static_cast<std::size_t>(std::to_integer<std::uint8_t>(
                     self->signaling_frame[2]))
                 << 8U) |
                static_cast<std::size_t>(std::to_integer<std::uint8_t>(
                    self->signaling_frame[3]));
            if (size < lan_signaling_frame_fixed_body_bytes ||
                size > max_lan_signaling_body_bytes) {
              completion(Result<LanSignalingMessage>::failure(
                  tls_error(ErrorCode::protocol, "signaling_length_invalid")));
              return;
            }
            self->signaling_body_size = size;
            boost::asio::async_read(
                self->stream,
                boost::asio::buffer(
                    self->signaling_frame.data() + lan_signaling_frame_header_bytes,
                    size),
                [self, completion = std::move(completion)](
                    const boost::system::error_code& body_error, std::size_t) mutable {
                  if (body_error) {
                    completion(Result<LanSignalingMessage>::failure(
                        tls_error(ErrorCode::signaling, "signaling_body_read_failed",
                                  body_error)));
                    return;
                  }
                  auto parsed = parse_lan_signaling_frame(
                      std::span<const std::byte>{
                          self->signaling_frame.data(),
                          lan_signaling_frame_header_bytes +
                              self->signaling_body_size});
                  if (!parsed) {
                    completion(Result<LanSignalingMessage>::failure(
                        *parsed.error_if()));
                    return;
                  }
                  if (!self->peer) {
                    completion(Result<LanSignalingMessage>::failure(
                        tls_error(ErrorCode::protocol, "signaling_frame_invalid")));
                    return;
                  }
                  LanSignalingMessage message;
                  message.peer = *self->peer;
                  message.kind = parsed.value_if()->kind;
                  message.request_id = parsed.value_if()->request_id;
                  message.payload = std::move(parsed.value_if()->payload);
                  completion(Result<LanSignalingMessage>::success(
                      std::move(message)));
                });
          });
    }

    void write_signaling(const LanSignalingMessage& message,
                         std::function<void(Result<void>)> completion) {
      auto encoded = encode_lan_signaling_frame(
          LanSignalingFrame{message.kind, message.request_id, message.payload});
      if (!encoded) {
        completion(Result<void>::failure(*encoded.error_if()));
        return;
      }
      write_buffer = std::move(*encoded.value_if());
      auto self = shared_from_this();
      boost::asio::async_write(
          stream, boost::asio::buffer(write_buffer),
          [self, completion = std::move(completion)](
              const boost::system::error_code& error, std::size_t) mutable {
            if (error) {
              completion(Result<void>::failure(
                  tls_error(ErrorCode::signaling, "signaling_write_failed", error)));
              return;
            }
            completion(Result<void>::success());
          });
    }

    void read_hello(std::function<void(Result<LanHello>)> completion) {
      auto self = shared_from_this();
      boost::asio::async_read(
          stream, boost::asio::buffer(header),
          [self, completion = std::move(completion)](const boost::system::error_code& error,
                                                      std::size_t) mutable {
            if (error) {
              completion(Result<LanHello>::failure(
                  tls_error(ErrorCode::signaling, "hello_header_read_failed", error)));
              return;
            }
            const auto size = static_cast<std::size_t>(
                (std::to_integer<std::uint16_t>(self->header[0]) << 8U) |
                std::to_integer<std::uint16_t>(self->header[1]));
            if (size == 0U || size > self->body.size()) {
              completion(Result<LanHello>::failure(
                  tls_error(ErrorCode::protocol, "hello_length_invalid")));
              return;
            }
            self->body_size = size;
            boost::asio::async_read(
                self->stream, boost::asio::buffer(self->body.data(), size),
                [self, completion = std::move(completion)](
                    const boost::system::error_code& body_error, std::size_t) mutable {
                  if (body_error) {
                    completion(Result<LanHello>::failure(
                        tls_error(ErrorCode::signaling, "hello_body_read_failed", body_error)));
                    return;
                  }
                  completion(parse_lan_hello(
                      std::span<const std::byte>{self->body.data(), self->body_size}));
                });
          });
    }

    void write_hello(const LanHello& hello, std::function<void(Result<void>)> completion) {
      auto payload = encode_lan_hello(hello);
      if (!payload) {
        completion(Result<void>::failure(*payload.error_if()));
        return;
      }
      auto framed = frame_hello(*payload.value_if());
      if (framed.empty()) {
        completion(Result<void>::failure(tls_error(ErrorCode::protocol, "hello_length_invalid")));
        return;
      }
      write_buffer = std::move(framed);
      auto self = shared_from_this();
      boost::asio::async_write(
          stream, boost::asio::buffer(write_buffer),
          [self, completion = std::move(completion)](const boost::system::error_code& error,
                                                      std::size_t) mutable {
            if (error) {
              completion(Result<void>::failure(
                  tls_error(ErrorCode::signaling, "hello_write_failed", error)));
              return;
            }
            completion(Result<void>::success());
          });
    }

    void close() {
      boost::system::error_code ignored;
      try {
        (void)timer.cancel();
      } catch (...) {
      }
      stream.lowest_layer().cancel(ignored);
      stream.lowest_layer().shutdown(tcp::socket::shutdown_both, ignored);
      stream.lowest_layer().close(ignored);
    }

    std::weak_ptr<Impl> owner;
    std::uint64_t id{};
    boost::asio::ssl::stream<tcp::socket> stream;
    boost::asio::steady_timer timer;
    std::string remote_address;
    TlsCertificateFingerprint peer_fingerprint{};
    bool authenticated{false};
    bool inbound{true};
    LanSignalingConnectionState state{LanSignalingConnectionState::connecting};
    std::optional<DeviceEndpointKey> peer;
    DeviceEndpointKey expected_peer;
    LanBootNonce expected_peer_boot_nonce{};
    LanHello initial_hello;
    LanHandshakeNonce initiator_nonce{};
    LanHandshakeNonce responder_nonce{};
    std::array<std::byte, 2U> header{};
    std::array<std::byte, max_lan_datagram_payload_bytes> body{};
    std::size_t body_size{};
    std::array<std::byte, max_lan_signaling_frame_bytes> signaling_frame{};
    std::size_t signaling_body_size{};
    std::vector<std::byte> write_buffer;
    std::deque<LanSignalingMessage> outbound_messages;
    bool outbound_busy{false};
    bool inbound_callback_in_flight{false};
  };

  struct AcceptRate {
    SteadyTime window_start;
    SteadyTime last_seen;
    std::size_t count{};
  };

  enum class AcceptRateOutcome : std::uint8_t {
    admitted,
    global_rate_limited,
    source_rate_limited,
    source_state_capacity_full,
  };

  enum class RelayLoginPhase : std::uint8_t {
    disabled,
    connecting,
    awaiting_challenge,
    awaiting_login,
    ready,
    failed,
    stopped,
  };

  Impl(ProfileStore& profile, std::optional<Runtime> owned_runtime, Runtime* borrowed_runtime,
       std::string application_id, LanConfiguration lan, IdentityKeyPair identity,
       EndpointId endpoint_id, EndpointDirectory directory,
       boost::asio::any_io_executor executor, std::set<DeviceId> trusted_devices,
       LanSignalingValidator signaling_validator,
       LanSignalingHandler signaling_handler,
       std::optional<RelayNodeConfig> relay_override)
      : profile(profile), owned_runtime(std::move(owned_runtime)),
        runtime(this->owned_runtime ? &*this->owned_runtime : borrowed_runtime),
        application_id(std::move(application_id)), lan(std::move(lan)),
        identity(std::move(identity)), endpoint_id(endpoint_id), boot_nonce(make_boot_nonce()),
        directory(std::move(directory)), strand(boost::asio::make_strand(std::move(executor))),
        announce_timer(strand), expiry_timer(strand), interface_timer(strand),
        readiness_timer(strand), relay_poll_timer(strand), relay_heartbeat_timer(strand),
        relay_reconnect_timer(strand),
        scan_results(scan_channel_options()), snapshots(NodeSnapshot{}, "heyaki-node-snapshot"),
        endpoint_snapshots(std::vector<EndpointDirectoryEntrySnapshot>{},
                           "heyaki-endpoint-snapshot"),
        signaling_commands(signaling_channel_options(this->lan.pending_signaling_capacity,
                                                      "heyaki-lan-signaling-commands")),
        signaling_results(signaling_channel_options(this->lan.pending_signaling_capacity,
                                                     "heyaki-lan-signaling-results")),
        signaling_snapshots(std::vector<LanSignalingConnectionSnapshot>{},
                            "heyaki-lan-signaling-snapshot"),
        peer_session_snapshots(std::vector<NodePeerSessionSnapshot>{},
                               "heyaki-peer-session-snapshot"),
        stopped("heyaki-node-stopped"), trusted_devices(std::move(trusted_devices)),
        signaling_validator(std::move(signaling_validator)),
        signaling_handler(std::move(signaling_handler)),
        relay_override(std::move(relay_override)) {}

  static LanBootNonce make_boot_nonce() {
    LanBootNonce value{};
    randombytes_buf(value.data(), value.size());
    return value;
  }

  Result<void> initialize() {
    NodeSnapshot initial;
    initial.local_initialized = true;
    initial.device_id = identity.device_id();
    initial.endpoint_id = endpoint_id;
    initial.connectivity_mode = lan.connectivity_mode;
    initial.lan_enabled = lan.enabled && lan.connectivity_mode != ConnectivityMode::relay_only;
    initial.discoverable = lan.discoverable;
    initial.lan_state = initial.lan_enabled ? LanReadinessState::starting
                                           : LanReadinessState::disabled;
    snapshots.publish(initial);
    endpoint_snapshots.publish({});
    signaling_snapshots.publish({});
    peer_session_snapshots.publish({});

    const auto relay_initialized = initialize_relay();
    if (!relay_initialized) {
      update_snapshot([&](NodeSnapshot& snapshot) {
        snapshot.relay.enabled = true;
        snapshot.relay.state = RelayNodeState::failed;
        snapshot.relay.last_error = *relay_initialized.error_if();
      });
      if (relay_override && relay_override->enabled) {
        return relay_initialized;
      }
    }

    auto sessions_initialized = initialize_session_coordinator();
    if (!sessions_initialized) return sessions_initialized;

    if (!initial.lan_enabled) {
      return register_shutdown_hooks();
    }
    auto tls = initialize_tls();
    if (!tls) {
      update_snapshot([&](NodeSnapshot& snapshot) {
        snapshot.lan_state = LanReadinessState::failed;
        snapshot.last_error = *tls.error_if();
      });
      if (lan.connectivity_mode == ConnectivityMode::lan_only) {
        return tls;
      }
    }
    auto interfaces = enumerate_interfaces(lan);
    if (!interfaces) {
      update_snapshot([&](NodeSnapshot& snapshot) {
        snapshot.lan_state = LanReadinessState::failed;
        snapshot.last_error = *interfaces.error_if();
      });
      if (lan.connectivity_mode == ConnectivityMode::lan_only) {
        return Result<void>::failure(*interfaces.error_if());
      }
    } else if (interfaces.value_if()->size() > lan.interface_capacity) {
      const auto error = discovery_error(ErrorCode::resource_exhausted,
                                         "interface_capacity_exhausted");
      update_snapshot([&](NodeSnapshot& snapshot) {
        snapshot.lan_state = LanReadinessState::failed;
        snapshot.last_error = error;
      });
      if (lan.connectivity_mode == ConnectivityMode::lan_only) {
        return Result<void>::failure(error);
      }
    } else {
      current_bindings = *interfaces.value_if();
      open_discovery_sockets(current_bindings);
    }
    const auto hook = register_shutdown_hooks();
    if (!hook) {
      return hook;
    }
    const auto state = snapshots.load().value;
    if (!state.tls.listener_ready || joined_socket_count() == 0U) {
      update_snapshot([&](NodeSnapshot& snapshot) {
        snapshot.lan_state = LanReadinessState::failed;
        if (!snapshot.last_error) {
          snapshot.last_error = discovery_error(ErrorCode::transport,
                                                "lan_no_ready_interface");
        }
      });
      if (lan.connectivity_mode == ConnectivityMode::lan_only) {
        return Result<void>::failure(
            discovery_error(ErrorCode::transport, "lan_no_ready_interface"));
      }
    } else {
      update_lan_readiness();
    }
    return Result<void>::success();
  }

  void begin() {
    begin_relay();
    schedule_expiry();
    if (!snapshots.load().value.lan_enabled) {
      publish_resource_snapshot();
      return;
    }
    start_accept();
    for (const auto& socket : discovery_sockets) {
      start_receive(socket);
    }
    arm_multicast_readiness_timeout();
    announce_now();
    schedule_interface_refresh();
    publish_resource_snapshot();
  }

  Result<void> initialize_relay() {
    if (relay_override) {
      relay = *relay_override;
    } else {
      auto enrollments = profile.relay_enrollments();
      if (!enrollments) {
        return Result<void>::failure(*enrollments.error_if());
      }
      const auto found = std::find_if(
          enrollments.value_if()->begin(), enrollments.value_if()->end(),
          [](const RelayEnrollmentRecord& enrollment) {
            return enrollment.auto_connect && !enrollment.revoked;
          });
      if (found == enrollments.value_if()->end()) {
        relay.enabled = false;
        relay_phase = RelayLoginPhase::disabled;
        return Result<void>::success();
      }
      relay.enabled = true;
      relay.relay_url = found->relay_url;
      relay.relay_pin = found->relay_pin;
      relay.tenant = found->tenant;
      relay.enrollment_generation = found->enrollment_generation;
      if (relay.relay_pin) {
        relay.tls_verify_peer = false;
      }
    }
    auto valid = validate_relay_node_config(relay);
    if (!valid) {
      return valid;
    }
    if (!relay.enabled) {
      relay_phase = RelayLoginPhase::disabled;
      return Result<void>::success();
    }
    relay_phase = RelayLoginPhase::connecting;
    update_snapshot([&](NodeSnapshot& snapshot) {
      snapshot.relay.enabled = true;
      snapshot.relay.relay_url = relay.relay_url;
      snapshot.relay.tenant = relay.tenant;
      snapshot.relay.enrollment_generation = relay.enrollment_generation;
      snapshot.relay.state = RelayNodeState::starting;
    });
    return Result<void>::success();
  }

  void begin_relay() {
    if (!relay.enabled) {
      return;
    }
    schedule_relay_poll();
    start_relay_connect();
  }

  void start_relay_connect() {
    if (!relay.enabled || relay_phase == RelayLoginPhase::failed ||
        relay_phase == RelayLoginPhase::stopped) {
      return;
    }
    relay_phase = RelayLoginPhase::connecting;
    relay_challenge.reset();
    relay_client.reset();

    RelayWssClientConfig config;
    config.url = relay_control_url(relay.relay_url);
    if (relay.relay_pin) {
      RelayTlsPin pin{};
      if (relay.relay_pin->size() != pin.size()) {
        relay_failed(node_error(ErrorCode::configuration, "relay_pin_invalid"), true);
        return;
      }
      std::copy_n(relay.relay_pin->begin(), pin.size(), pin.begin());
      config.relay_pin = pin;
    }
    config.tls_ca_file = relay.tls_ca_file;
    config.tls_verify_peer = relay.tls_verify_peer;
    config.receive_capacity = relay.receive_capacity;
    config.send_capacity = relay.send_capacity;
    config.connect_timeout = relay.connect_timeout;
    config.handshake_timeout = relay.handshake_timeout;
    config.close_timeout = relay.close_timeout;
    config.runtime = RuntimeConfig{};
    auto client = RelayWssClient::create(std::move(config), runtime);
    if (!client) {
      relay_failed(*client.error_if(), is_relay_security_error(*client.error_if()));
      return;
    }
    relay_client.emplace(std::move(*client.value_if()));
    auto started = relay_client->start_connect();
    if (!started) {
      relay_failed(*started.error_if(), is_relay_security_error(*started.error_if()));
      return;
    }
    update_snapshot([](NodeSnapshot& snapshot) {
      snapshot.relay.state = RelayNodeState::starting;
      snapshot.relay.last_error.reset();
    });
    schedule_relay_poll();
  }

  void schedule_relay_poll() {
    if (relay_poll_timer_active || !relay.enabled ||
        relay_phase == RelayLoginPhase::failed ||
        relay_phase == RelayLoginPhase::stopped) {
      return;
    }
    relay_poll_timer_active = true;
    relay_poll_timer.expires_after(relay.poll_interval);
    auto weak = weak_from_this();
    relay_poll_timer.async_wait([weak](const boost::system::error_code& error) {
      if (!error) {
        if (auto self = weak.lock()) {
          self->relay_poll_timer_active = false;
          self->relay_poll();
        }
      } else if (auto self = weak.lock()) {
        self->relay_poll_timer_active = false;
      }
    });
  }

  void relay_poll() {
    if (!relay.enabled || relay_phase == RelayLoginPhase::failed ||
        relay_phase == RelayLoginPhase::stopped ||
        relay_phase == RelayLoginPhase::disabled || !relay_client) {
      return;
    }
    if (relay_phase == RelayLoginPhase::connecting) {
      const auto snapshot = relay_client->snapshot();
      if (snapshot.state == RelayWssState::ready) {
        relay_phase = RelayLoginPhase::awaiting_challenge;
        auto sent = send_relay_control(RelayWssControlType::login_challenge);
        if (!sent) {
          relay_failed(*sent.error_if(), false);
          return;
        }
      } else if (snapshot.state == RelayWssState::failed) {
        const auto error = snapshot.last_error.value_or(
            Error{ErrorCode::relay_unavailable, "relay", "relay_connect_failed"});
        relay_failed(error, is_relay_security_error(error));
        return;
      }
      schedule_relay_poll();
      return;
    }

    RelayWssMessage message;
    while (true) {
      auto received = relay_client->try_receive(message);
      if (!received) {
        relay_failed(*received.error_if(), false);
        return;
      }
      if (*received.value_if() == RelayWssReceiveStatus::closed) {
        const auto snapshot = relay_client->snapshot();
        const auto error = snapshot.last_error.value_or(
            Error{ErrorCode::relay_unavailable, "relay", "relay_connection_closed"});
        relay_failed(error, is_relay_security_error(error));
        return;
      }
      if (*received.value_if() == RelayWssReceiveStatus::empty) {
        break;
      }
      handle_relay_message(message);
      if (relay_phase == RelayLoginPhase::failed ||
          relay_phase == RelayLoginPhase::connecting) {
        return;
      }
    }

    const auto snapshot = relay_client->snapshot();
    if (snapshot.state == RelayWssState::failed ||
        snapshot.state == RelayWssState::disconnected) {
      const auto error = snapshot.last_error.value_or(
          Error{ErrorCode::relay_unavailable, "relay", "relay_connection_lost"});
      relay_failed(error, is_relay_security_error(error));
      return;
    }
    schedule_relay_poll();
  }

  void handle_relay_message(const RelayWssMessage& message) {
    if (message.text) {
      relay_failed(node_error(ErrorCode::protocol, "relay_control_text_frame"), true);
      return;
    }
    auto frame = parse_relay_wss_control_frame(message.payload);
    if (!frame) {
      relay_failed(*frame.error_if(), true);
      return;
    }
    const auto type = frame.value_if()->type;
    if (type == RelayWssControlType::control_error) {
      auto remote = parse_relay_wss_control_error(frame.value_if()->payload);
      if (!remote) {
        relay_failed(*remote.error_if(), true);
        return;
      }
      const Error error{remote.value_if()->code, "relay", remote.value_if()->safe_detail};
      relay_failed(error, is_relay_security_error(error));
      return;
    }
    if (relay_phase == RelayLoginPhase::awaiting_challenge) {
      if (type != RelayWssControlType::login_challenge_response) {
        relay_failed(node_error(ErrorCode::protocol, "relay_login_challenge_expected"), true);
        return;
      }
      auto challenge = parse_enrollment_challenge(frame.value_if()->payload);
      if (!challenge) {
        relay_failed(*challenge.error_if(), true);
        return;
      }
      relay_challenge = std::move(*challenge.value_if());
      RelayLoginRequest request;
      request.device_id = identity.device_id();
      request.endpoint_id = endpoint_id;
      request.identity_public_key = identity.public_key();
      request.challenge_nonce = relay_challenge->nonce;
      request.tenant = relay.tenant;
      request.enrollment_generation = relay.enrollment_generation;
      request.protocol_version = current_protocol_version;
      request.supported.bits = known_capability_bits;
      request.required.bits = static_cast<std::uint64_t>(Capability::enrollment);
      const auto now = unix_milliseconds_now();
      request.expires_unix_milliseconds =
          std::min(now + 30U * 1000U,
                   relay_challenge->expires_unix_milliseconds - 1U);
      auto signed_request =
          sign_relay_login_request(request, relay_challenge->relay_id, identity);
      if (!signed_request) {
        relay_failed(*signed_request.error_if(), true);
        return;
      }
      auto encoded = encode_relay_login_request(request);
      if (!encoded) {
        relay_failed(*encoded.error_if(), true);
        return;
      }
      relay_phase = RelayLoginPhase::awaiting_login;
      auto sent = send_relay_control(RelayWssControlType::login_request,
                                     *encoded.value_if());
      if (!sent) {
        relay_failed(*sent.error_if(), false);
      }
      return;
    }
    if (relay_phase == RelayLoginPhase::awaiting_login) {
      if (type != RelayWssControlType::login_result) {
        relay_failed(node_error(ErrorCode::protocol, "relay_login_result_expected"), true);
        return;
      }
      auto result = parse_relay_wss_login_result(frame.value_if()->payload);
      if (!result) {
        relay_failed(*result.error_if(), true);
        return;
      }
      if (result.value_if()->tenant != relay.tenant) {
        relay_failed(node_error(ErrorCode::authentication, "relay_login_tenant_mismatch"),
                     true);
        return;
      }
      relay_phase = RelayLoginPhase::ready;
      relay_lease_generation = 0U;
      relay_lease_deadline =
          std::chrono::steady_clock::now() +
          std::chrono::milliseconds{result.value_if()->lease_milliseconds};
      relay_heartbeats_missed = 0U;
      relay_heartbeat_pending = false;
      relay_reconnect_attempt = 0U;
      relay_backoff = relay.minimum_backoff;
      update_snapshot([&](NodeSnapshot& snapshot) {
        snapshot.relay.state = RelayNodeState::ready;
        snapshot.relay.enrollment_generation =
            result.value_if()->enrollment_generation;
        snapshot.relay.lease_generation = relay_lease_generation;
        snapshot.relay.last_error.reset();
      });
      relay_heartbeat_tick();
      return;
    }
    if (relay_phase == RelayLoginPhase::ready &&
        type == RelayWssControlType::heartbeat_ack) {
      auto ack = parse_relay_wss_heartbeat_ack(frame.value_if()->payload);
      if (!ack) {
        relay_failed(*ack.error_if(), true);
        return;
      }
      relay_lease_generation = ack.value_if()->lease_generation;
      relay_lease_deadline =
          std::chrono::steady_clock::now() +
          std::chrono::milliseconds{ack.value_if()->granted_lease_milliseconds};
      relay_heartbeats_missed = 0U;
      relay_heartbeat_pending = false;
      update_snapshot([&](NodeSnapshot& snapshot) {
        snapshot.relay.lease_generation = relay_lease_generation;
      });
      auto refreshed = publish_and_query_relay_endpoints();
      if (!refreshed) {
        relay_failed(*refreshed.error_if(), false);
      }
      return;
    }
    if (relay_phase == RelayLoginPhase::ready &&
        type == RelayWssControlType::endpoint_publish_ack) {
      auto ack = parse_relay_wss_endpoint_publish_ack(frame.value_if()->payload);
      if (!ack || ack.value_if()->record_generation != relay_record_generation) {
        relay_failed(ack ? node_error(ErrorCode::protocol,
                                      "relay_publish_generation_mismatch")
                         : *ack.error_if(), true);
      } else {
        auto query = encode_relay_wss_endpoint_query(RelayWssEndpointQuery{});
        if (!query) {
          relay_failed(*query.error_if(), true);
          return;
        }
        auto sent = send_relay_control(RelayWssControlType::endpoint_query,
                                       *query.value_if());
        if (!sent) relay_failed(*sent.error_if(), false);
      }
      return;
    }
    if (relay_phase == RelayLoginPhase::ready &&
        type == RelayWssControlType::endpoint_query_result) {
      auto result = parse_relay_wss_endpoint_query_result(frame.value_if()->payload);
      if (!result) {
        relay_failed(*result.error_if(), true);
        return;
      }
      auto admitted = admit_relay_endpoints(*result.value_if());
      if (!admitted) {
        record_signaling_error(*admitted.error_if());
      }
      return;
    }
    if (relay_phase == RelayLoginPhase::ready &&
        type == RelayWssControlType::signaling_deliver) {
      auto envelope = RelaySignalingRoute::decode_delivery(frame.value_if()->payload);
      if (!envelope || !coordinator) {
        record_signaling_error(envelope
            ? node_error(ErrorCode::cancelled, "relay_coordinator_unavailable")
            : *envelope.error_if());
        return;
      }
      auto handled = coordinator->handle_message(*envelope.value_if(),
                                                 SignalingRouteKind::relay);
      if (!handled) record_signaling_error(*handled.error_if());
      return;
    }
    if (relay_phase == RelayLoginPhase::ready) {
      relay_failed(node_error(ErrorCode::protocol, "relay_unexpected_control_frame"), true);
    }
  }

  void relay_failed(Error error, bool security_error) {
    if (relay_phase == RelayLoginPhase::stopped ||
        relay_phase == RelayLoginPhase::disabled) {
      return;
    }
    relay_client.reset();
    std::vector<RequestId> relay_attempts;
    for (const auto& [request_id, attempt] : peer_attempts) {
      if (attempt.snapshot.signaling_route == SignalingRouteKind::relay) {
        relay_attempts.push_back(request_id);
      }
    }
    for (const auto request_id : relay_attempts) {
      fail_peer_attempt(request_id, error);
    }
    relay_heartbeat_pending = false;
    (void)relay_heartbeat_timer.cancel();
    relay_heartbeat_timer_active = false;
    if (security_error) {
      relay_phase = RelayLoginPhase::failed;
      (void)relay_poll_timer.cancel();
      relay_poll_timer_active = false;
      update_snapshot([&](NodeSnapshot& snapshot) {
        snapshot.relay.state = RelayNodeState::failed;
        snapshot.relay.last_error = std::move(error);
      });
      return;
    }
    relay_phase = RelayLoginPhase::connecting;
    ++relay_reconnect_count;
    schedule_relay_reconnect();
    update_snapshot([&](NodeSnapshot& snapshot) {
      snapshot.relay.state = RelayNodeState::degraded;
      snapshot.relay.last_error = std::move(error);
      snapshot.relay.reconnect_count = relay_reconnect_count;
      snapshot.relay.backoff = relay_backoff;
    });
  }

  void schedule_relay_reconnect() {
    if (relay_phase != RelayLoginPhase::connecting || !relay.enabled) {
      return;
    }
    relay_reconnect_timer.cancel();
    std::uint64_t base = static_cast<std::uint64_t>(relay_backoff.count());
    if (relay_reconnect_attempt > 0U) {
      base = std::min<std::uint64_t>(
          static_cast<std::uint64_t>(relay.maximum_backoff.count()),
          base * 2U);
    }
    base = std::max<std::uint64_t>(
        static_cast<std::uint64_t>(relay.minimum_backoff.count()), base);
    std::uint64_t jitter = 0U;
    if (base > 0U) {
      const auto cap = base / 4U;
      jitter = cap == 0U ? 0U : static_cast<std::uint64_t>(randombytes_uniform(
                                    static_cast<std::uint32_t>(cap + 1U)));
    }
    relay_backoff = std::chrono::milliseconds{
        static_cast<std::int64_t>(std::min<std::uint64_t>(
            static_cast<std::uint64_t>(relay.maximum_backoff.count()),
            base + jitter))};
    ++relay_reconnect_attempt;
    relay_reconnect_timer.expires_after(relay_backoff);
    auto weak = weak_from_this();
    relay_reconnect_timer.async_wait([weak](const boost::system::error_code& error) {
      if (!error) {
        if (auto self = weak.lock()) {
          self->start_relay_connect();
        }
      }
    });
  }

  void arm_relay_heartbeat() {
    if (relay_phase != RelayLoginPhase::ready || relay_heartbeat_timer_active) {
      return;
    }
    relay_heartbeat_timer_active = true;
    relay_heartbeat_timer.expires_after(relay.heartbeat_interval);
    auto weak = weak_from_this();
    relay_heartbeat_timer.async_wait([weak](const boost::system::error_code& error) {
      if (auto self = weak.lock()) {
        self->relay_heartbeat_timer_active = false;
        if (!error) {
          self->relay_heartbeat_tick();
        }
      }
    });
  }

  void relay_heartbeat_tick() {
    if (relay_phase != RelayLoginPhase::ready) {
      return;
    }
    if (relay_heartbeat_pending) {
      ++relay_heartbeats_missed;
      update_snapshot([&](NodeSnapshot& snapshot) {
        snapshot.relay.heartbeats_missed = relay_heartbeats_missed;
      });
    }
    if (relay_heartbeats_missed >= relay.missed_heartbeat_limit) {
      relay_failed(Error{ErrorCode::relay_unavailable, "relay",
                         "relay_heartbeat_lost"},
                   false);
      return;
    }
    RelayWssHeartbeatRequest request;
    request.lease_milliseconds =
        static_cast<std::uint32_t>(relay.lease_duration.count());
    auto encoded = encode_relay_wss_heartbeat_request(request);
    if (!encoded) {
      relay_failed(*encoded.error_if(), true);
      return;
    }
    auto sent = send_relay_control(RelayWssControlType::heartbeat,
                                   *encoded.value_if());
    if (!sent) {
      relay_failed(*sent.error_if(), false);
      return;
    }
    relay_heartbeat_pending = true;
    ++relay_heartbeats_sent;
    update_snapshot([&](NodeSnapshot& snapshot) {
      snapshot.relay.heartbeats_sent = relay_heartbeats_sent;
    });
    arm_relay_heartbeat();
  }

  void stop_relay() {
    if (relay_phase == RelayLoginPhase::stopped ||
        relay_phase == RelayLoginPhase::disabled) {
      relay_client.reset();
      return;
    }
    relay_phase = RelayLoginPhase::stopped;
    (void)relay_poll_timer.cancel();
    (void)relay_heartbeat_timer.cancel();
    (void)relay_reconnect_timer.cancel();
    relay_poll_timer_active = false;
    relay_heartbeat_timer_active = false;
    relay_challenge.reset();
    if (relay_client) {
      (void)relay_client->start_close();
      relay_client.reset();
    }
    update_snapshot([](NodeSnapshot& snapshot) {
      snapshot.relay.state = RelayNodeState::stopped;
    });
  }

  Result<void> send_relay_control(RelayWssControlType type,
                                  std::span<const std::byte> payload = {}) {
    if (!relay_client) {
      return Result<void>::failure(
          node_error(ErrorCode::cancelled, "relay_client_unavailable"));
    }
    auto frame = encode_relay_wss_control_frame(type, payload);
    if (!frame) {
      return Result<void>::failure(*frame.error_if());
    }
    return relay_client->send(*frame.value_if());
  }

  Result<void> publish_and_query_relay_endpoints() {
    RelayEndpointRecord record;
    record.endpoint = RelayEndpointKey{identity.device_id(), endpoint_id};
    record.application_id = application_id;
    record.record_generation = ++relay_record_generation;
    if (crypto_hash_sha256(reinterpret_cast<unsigned char*>(record.manifest_sha256.data()),
                           reinterpret_cast<const unsigned char*>(application_id.data()),
                           application_id.size()) != 0) {
      return Result<void>::failure(
          node_error(ErrorCode::internal, "relay_manifest_hash_failed"));
    }
    record.expires_unix_milliseconds = unix_milliseconds_now() + 60'000U;
    auto signed_record = sign_relay_endpoint_record(record, identity);
    if (!signed_record) return signed_record;
    auto record_bytes = encode_relay_endpoint_record(record);
    if (!record_bytes) return Result<void>::failure(*record_bytes.error_if());
    RelayWssEndpointPublish publish;
    publish.endpoint_record = std::move(*record_bytes.value_if());
    auto publish_bytes = encode_relay_wss_endpoint_publish(publish);
    if (!publish_bytes) return Result<void>::failure(*publish_bytes.error_if());
    return send_relay_control(RelayWssControlType::endpoint_publish,
                              *publish_bytes.value_if());
  }

  Result<void> admit_relay_endpoints(const RelayWssEndpointQueryResult& result) {
    const auto now_wall = unix_milliseconds_now();
    const auto now_steady = std::chrono::steady_clock::now();
    for (const auto& publication : result.endpoints) {
      if (publication.device_id == identity.device_id() &&
          publication.endpoint_id == endpoint_id) {
        continue;
      }
      if (!publication.endpoint_record || !publication.identity_public_key ||
          !publication.lease_expires_unix_milliseconds) {
        return Result<void>::failure(
            node_error(ErrorCode::authentication, "relay_endpoint_proof_missing"));
      }
      auto derived = derive_device_id(*publication.identity_public_key);
      if (!derived || *derived.value_if() != publication.device_id) {
        return Result<void>::failure(
            node_error(ErrorCode::authentication, "relay_endpoint_identity_mismatch"));
      }
      auto record = parse_relay_endpoint_record(*publication.endpoint_record);
      if (!record || record.value_if()->endpoint.device_id != publication.device_id ||
          record.value_if()->endpoint.endpoint_id != publication.endpoint_id) {
        return Result<void>::failure(record
            ? node_error(ErrorCode::authentication, "relay_endpoint_record_mismatch")
            : *record.error_if());
      }
      RelayDeviceRecord device{.device_id = publication.device_id,
                               .public_key = *publication.identity_public_key,
                               .tenant = relay.tenant,
                               .display_name = {},
                               .enrollment_generation = 1U,
                               .status = RelayDeviceStatus::active,
                               .created_unix_milliseconds = 0U,
                               .updated_unix_milliseconds = 0U};
      auto verified = validate_relay_endpoint_record(*record.value_if(), device, now_wall);
      if (!verified) return verified;
      const auto expires = std::min(record.value_if()->expires_unix_milliseconds,
                                    *publication.lease_expires_unix_milliseconds);
      if (expires <= now_wall) continue;
      const auto lease = std::chrono::milliseconds{static_cast<std::int64_t>(
          std::min<std::uint64_t>(expires - now_wall, 24U * 60U * 60U * 1000U))};
      const DeviceEndpointKey key{publication.device_id, publication.endpoint_id};
      auto stored = directory.upsert_relay(
          key, *publication.identity_public_key, relay.relay_url,
          trusted_devices.contains(publication.device_id), lease, now_steady);
      if (!stored) return stored;
    }
    publish_directory();
    return Result<void>::success();
  }

  Result<void> initialize_tls() {
    try {
      tls_context = std::make_unique<boost::asio::ssl::context>(
          boost::asio::ssl::context::tls);
      SSL_CTX* native = tls_context->native_handle();
      if (SSL_CTX_set_min_proto_version(native, TLS1_3_VERSION) != 1 ||
          SSL_CTX_set_max_proto_version(native, TLS1_3_VERSION) != 1 ||
          SSL_CTX_set_ciphersuites(native,
                                   "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
                                   "TLS_AES_128_GCM_SHA256") != 1) {
        return Result<void>::failure(tls_error(ErrorCode::configuration,
                                               "tls13_configuration_failed"));
      }
      SSL_CTX_set_options(native, SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION |
                                      SSL_OP_NO_RENEGOTIATION);
      tls_context->set_verify_mode(boost::asio::ssl::verify_peer |
                                   boost::asio::ssl::verify_fail_if_no_peer_cert);
      tls_context->set_verify_callback(verify_any_certificate);
      auto fingerprint = configure_boot_certificate(*tls_context);
      if (!fingerprint) {
        return Result<void>::failure(*fingerprint.error_if());
      }
      certificate_fingerprint = *fingerprint.value_if();
      acceptor = std::make_unique<tcp::acceptor>(strand);
      boost::system::error_code error;
      acceptor->open(tcp::v6(), error);
      if (!error) {
        acceptor->set_option(boost::asio::socket_base::reuse_address(true), error);
      }
      if (!error) {
        acceptor->set_option(boost::asio::ip::v6_only(false), error);
      }
      if (!error) {
        acceptor->bind(tcp::endpoint(tcp::v6(), 0U), error);
      }
      if (!error) {
        acceptor->listen(static_cast<int>(std::min<std::size_t>(
                             lan.provisional_connection_capacity,
                             static_cast<std::size_t>((std::numeric_limits<int>::max)()))),
                         error);
      }
      if (error) {
        return Result<void>::failure(tls_error(ErrorCode::transport,
                                               "tls_listener_start_failed", error));
      }
      const auto port = acceptor->local_endpoint(error).port();
      if (error || port == 0U) {
        return Result<void>::failure(tls_error(ErrorCode::transport,
                                               "tls_listener_endpoint_failed", error));
      }
      update_snapshot([&](NodeSnapshot& snapshot) {
        snapshot.tls.listener_ready = true;
        snapshot.tls.listen_port = port;
        snapshot.tls.certificate_sha256 = certificate_fingerprint;
      });
      return Result<void>::success();
    } catch (...) {
      return Result<void>::failure(
          tls_error(ErrorCode::internal, "tls_listener_exception"));
    }
  }

  void open_discovery_sockets(const std::vector<InterfaceBinding>& bindings) {
    close_discovery_sockets();
    std::vector<LanInterfaceSnapshot> interfaces;
    interfaces.reserve(bindings.size());
    for (const auto& binding : bindings) {
      LanInterfaceSnapshot snapshot{.name = binding.name,
                                    .index = binding.index,
                                    .family = binding.family,
                                    .address = binding.address,
                                    .joined = false,
                                    .multicast_verified = false,
                                    .error = std::nullopt};
      auto state = std::make_shared<DiscoverySocket>(strand, binding);
      boost::system::error_code error;
      const bool ipv4 = binding.family == LanInterfaceFamily::ipv4;
      state->socket.open(ipv4 ? udp::v4() : udp::v6(), error);
      if (!error) {
        state->socket.set_option(boost::asio::socket_base::reuse_address(true), error);
      }
      if (!error && !ipv4) {
        state->socket.set_option(boost::asio::ip::v6_only(true), error);
      }
      if (!error) {
        state->socket.bind(udp::endpoint(ipv4 ? udp::v4() : udp::v6(),
                                        lan_discovery_udp_port),
                           error);
      }
      if (!error && ipv4) {
        const auto group = boost::asio::ip::make_address_v4(lan_discovery_ipv4_group, error);
        if (!error) {
          state->socket.set_option(boost::asio::ip::multicast::join_group(
                                       group, binding.asio_address.to_v4()),
                                   error);
        }
        if (!error) {
          state->socket.set_option(boost::asio::ip::multicast::outbound_interface(
                                       binding.asio_address.to_v4()),
                                   error);
        }
        state->multicast_endpoint = udp::endpoint(group, lan_discovery_udp_port);
      } else if (!error) {
        auto group = boost::asio::ip::make_address_v6(lan_discovery_ipv6_group, error);
        if (!error) {
          state->socket.set_option(
              boost::asio::ip::multicast::join_group(group, binding.index), error);
        }
        if (!error) {
          state->socket.set_option(
              boost::asio::ip::multicast::outbound_interface(binding.index), error);
        }
        group.scope_id(binding.index);
        state->multicast_endpoint = udp::endpoint(group, lan_discovery_udp_port);
      }
      if (!error) {
        state->socket.set_option(
            boost::asio::ip::multicast::hops(lan_discovery_hop_limit), error);
      }
      if (!error) {
        state->socket.set_option(boost::asio::ip::multicast::enable_loopback(true), error);
      }
      if (error) {
        snapshot.error = discovery_error(ErrorCode::transport,
                                         "multicast_join_failed", error);
        boost::system::error_code ignored;
        state->socket.close(ignored);
      } else {
        snapshot.joined = true;
        discovery_sockets.push_back(std::move(state));
      }
      interfaces.push_back(std::move(snapshot));
    }
    update_snapshot([&](NodeSnapshot& snapshot) { snapshot.interfaces = std::move(interfaces); });
    peak_discovery_sockets =
        std::max(peak_discovery_sockets, discovery_sockets.size());
    multicast_probe_timed_out = false;
    publish_resource_snapshot();
  }

  void close_discovery_sockets() {
    for (const auto& socket : discovery_sockets) {
      boost::system::error_code ignored;
      socket->socket.cancel(ignored);
      socket->socket.close(ignored);
    }
    discovery_sockets.clear();
    publish_resource_snapshot();
  }

  std::size_t joined_socket_count() const noexcept { return discovery_sockets.size(); }

  bool all_multicast_sockets_verified() const noexcept {
    return std::all_of(discovery_sockets.begin(), discovery_sockets.end(),
                       [](const auto& socket) {
                         return socket->multicast_verified;
                       });
  }

  static bool same_interface(const LanInterfaceSnapshot& snapshot,
                             const InterfaceBinding& binding) noexcept {
    return snapshot.name == binding.name && snapshot.index == binding.index &&
           snapshot.family == binding.family && snapshot.address == binding.address;
  }

  static bool same_network_interface(const InterfaceBinding& left,
                                     const InterfaceBinding& right) noexcept {
    return left.index == right.index && left.family == right.family;
  }

  void update_lan_readiness() {
    if (producers_stopped) {
      return;
    }
    update_snapshot([&](NodeSnapshot& snapshot) {
      if (!snapshot.lan_enabled) {
        snapshot.lan_state = LanReadinessState::disabled;
        return;
      }
      if (!snapshot.tls.listener_ready || discovery_sockets.empty()) {
        snapshot.lan_state = LanReadinessState::failed;
        if (!snapshot.last_error) {
          snapshot.last_error = discovery_error(ErrorCode::transport,
                                                "lan_no_ready_interface");
        }
        return;
      }
      const bool join_degraded = std::any_of(
          snapshot.interfaces.begin(), snapshot.interfaces.end(),
          [](const LanInterfaceSnapshot& interface) { return !interface.joined; });
      if (lan.discoverable && !all_multicast_sockets_verified()) {
        snapshot.lan_state = multicast_probe_timed_out
                                 ? LanReadinessState::degraded
                                 : LanReadinessState::starting;
        if (multicast_probe_timed_out) {
          snapshot.last_error = discovery_error(ErrorCode::transport,
                                                "multicast_probe_timed_out");
        }
        return;
      }
      snapshot.lan_state = join_degraded ? LanReadinessState::degraded
                                         : LanReadinessState::ready;
      if (snapshot.last_error && is_multicast_readiness_error(*snapshot.last_error)) {
        snapshot.last_error.reset();
      }
    });
  }

  void mark_multicast_verified(const std::shared_ptr<DiscoverySocket>& socket) {
    if (socket->multicast_verified) {
      return;
    }
    for (const auto& candidate : discovery_sockets) {
      if (same_network_interface(candidate->binding, socket->binding)) {
        candidate->multicast_verified = true;
      }
    }
    update_snapshot([&](NodeSnapshot& snapshot) {
      for (auto& interface : snapshot.interfaces) {
        if (interface.index == socket->binding.index &&
            interface.family == socket->binding.family) {
          interface.multicast_verified = true;
          if (interface.error && is_multicast_readiness_error(*interface.error)) {
            interface.error.reset();
          }
        }
      }
    });
    if (all_multicast_sockets_verified()) {
      multicast_probe_timed_out = false;
      readiness_timer_active = false;
      try {
        (void)readiness_timer.cancel();
      } catch (...) {
      }
    }
    update_lan_readiness();
    publish_resource_snapshot();
  }

  void arm_multicast_readiness_timeout() {
    readiness_timer_active = false;
    try {
      (void)readiness_timer.cancel();
    } catch (...) {
    }
    multicast_probe_timed_out = false;
    if (producers_stopped || !lan.discoverable || discovery_sockets.empty()) {
      update_lan_readiness();
      publish_resource_snapshot();
      return;
    }
    readiness_timer_active = true;
    readiness_timer.expires_after(multicast_readiness_timeout);
    auto weak = weak_from_this();
    readiness_timer.async_wait([weak](const boost::system::error_code& error) {
      auto self = weak.lock();
      if (!self) {
        return;
      }
      self->readiness_timer_active = false;
      if (!error && !self->producers_stopped &&
          !self->all_multicast_sockets_verified()) {
        self->multicast_probe_timed_out = true;
        const auto probe_error = discovery_error(ErrorCode::transport,
                                                 "multicast_probe_timed_out");
        self->update_snapshot([&](NodeSnapshot& snapshot) {
          for (auto& interface : snapshot.interfaces) {
            const auto socket = std::find_if(
                self->discovery_sockets.begin(), self->discovery_sockets.end(),
                [&](const auto& candidate) {
                  return same_interface(interface, candidate->binding);
                });
            if (socket != self->discovery_sockets.end() &&
                !(*socket)->multicast_verified) {
              interface.error = probe_error;
            }
          }
        });
        self->update_lan_readiness();
      }
      self->publish_resource_snapshot();
    });
    update_lan_readiness();
    publish_resource_snapshot();
  }

  void start_receive(const std::shared_ptr<DiscoverySocket>& socket) {
    auto weak = weak_from_this();
    socket->socket.async_receive_from(
        boost::asio::buffer(socket->receive_buffer), socket->sender_endpoint,
        [weak, socket](const boost::system::error_code& error, std::size_t size) {
          auto self = weak.lock();
          if (!self || self->producers_stopped) {
            return;
          }
          if (error) {
            if (error != boost::asio::error::operation_aborted) {
              self->update_snapshot([&](NodeSnapshot& snapshot) {
                ++snapshot.datagrams_rejected;
                snapshot.last_error = discovery_error(ErrorCode::transport,
                                                      "multicast_receive_failed", error);
              });
              self->start_receive(socket);
            }
            return;
          }
          self->handle_datagram(socket, size);
          self->start_receive(socket);
        });
  }

  void handle_datagram(const std::shared_ptr<DiscoverySocket>& socket, std::size_t size) {
    update_snapshot([](NodeSnapshot& snapshot) { ++snapshot.datagrams_received; });
    if (size > max_lan_datagram_bytes) {
      update_snapshot([](NodeSnapshot& snapshot) { ++snapshot.datagrams_rejected; });
      return;
    }
    auto presence = parse_lan_presence_datagram(
        std::span<const std::byte>{socket->receive_buffer.data(), size});
    if (!presence) {
      update_snapshot([&](NodeSnapshot& snapshot) {
        ++snapshot.datagrams_rejected;
        snapshot.last_error = *presence.error_if();
      });
      return;
    }
    if (presence.value_if()->device_id == identity.device_id() &&
        presence.value_if()->endpoint_id == endpoint_id &&
        presence.value_if()->boot_nonce == boot_nonce) {
      mark_multicast_verified(socket);
      return;
    }
    const bool trusted = trusted_devices.contains(presence.value_if()->device_id);
    auto observed = directory.observe_lan(
        *presence.value_if(), socket->sender_endpoint.address().to_string(),
        socket->binding.name, trusted, std::chrono::steady_clock::now());
    if (!observed) {
      update_snapshot([&](NodeSnapshot& snapshot) {
        ++snapshot.datagrams_rejected;
        snapshot.last_error = *observed.error_if();
        snapshot.directory = directory.diagnostics();
      });
      return;
    }
    publish_directory();
    const auto peer = observed.value_if()->key;
    if (trusted && lan.auto_connect_trusted &&
        is_lan_offer_owner(local_key(), peer) &&
        auto_connect_connections.size() < lan.auto_connect_capacity) {
      start_outbound_connection(peer, true);
    }
  }

  void announce_now() {
    if (producers_stopped || !lan.discoverable || discovery_sockets.empty() ||
        !snapshots.load().value.tls.listener_ready) {
      schedule_announcement();
      return;
    }
    LanPresence presence;
    presence.endpoint_id = endpoint_id;
    presence.boot_nonce = boot_nonce;
    presence.sequence = ++announcement_sequence;
    presence.tls_signaling_port = snapshots.load().value.tls.listen_port;
    presence.lease = lan.presence_lease;
    auto signed_presence = sign_lan_presence(presence, identity);
    auto datagram = signed_presence ? encode_lan_presence_datagram(presence)
                                    : Result<std::vector<std::byte>>::failure(
                                          *signed_presence.error_if());
    if (!datagram) {
      update_snapshot([&](NodeSnapshot& snapshot) {
        snapshot.last_error = *datagram.error_if();
      });
      schedule_announcement();
      return;
    }
    auto bytes = std::make_shared<std::vector<std::byte>>(std::move(*datagram.value_if()));
    auto weak = weak_from_this();
    for (const auto& socket : discovery_sockets) {
      socket->socket.async_send_to(
          boost::asio::buffer(*bytes), socket->multicast_endpoint,
          [weak, bytes, socket](const boost::system::error_code& error, std::size_t) {
            if (auto self = weak.lock()) {
              if (self->producers_stopped) {
                return;
              }
              if (error) {
                self->update_snapshot([&](NodeSnapshot& snapshot) {
                  snapshot.lan_state = LanReadinessState::degraded;
                  snapshot.last_error = discovery_error(ErrorCode::transport,
                                                        "presence_send_failed", error);
                  const auto interface = std::find_if(
                      snapshot.interfaces.begin(), snapshot.interfaces.end(),
                      [&](const LanInterfaceSnapshot& candidate) {
                        return same_interface(candidate, socket->binding);
                      });
                  if (interface != snapshot.interfaces.end()) {
                    interface->error = snapshot.last_error;
                  }
                });
              } else {
                self->update_snapshot(
                    [](NodeSnapshot& snapshot) { ++snapshot.announcements_sent; });
              }
            }
          });
    }
    schedule_announcement();
  }

  void schedule_announcement() {
    if (producers_stopped) {
      return;
    }
    announce_timer_active = true;
    const auto jitter = static_cast<std::uint32_t>(lan.announcement_jitter.count());
    const auto random = jitter == 0U ? 0U : randombytes_uniform(jitter * 2U + 1U);
    const auto offset = static_cast<std::int64_t>(random) - static_cast<std::int64_t>(jitter);
    const auto delay = std::max<std::int64_t>(1, lan.announcement_interval.count() + offset);
    announce_timer.expires_after(std::chrono::milliseconds{delay});
    auto weak = weak_from_this();
    announce_timer.async_wait([weak](const boost::system::error_code& error) {
      if (!error) {
        if (auto self = weak.lock()) {
          self->announce_now();
        }
      } else if (auto self = weak.lock(); self && !self->producers_stopped) {
        self->announce_timer_active = false;
        self->publish_resource_snapshot();
      }
    });
  }

  void check_peer_transport_failures() {
    for (auto iterator = peer_attempts.begin(); iterator != peer_attempts.end();
         ++iterator) {
      if (!iterator->second.transport || iterator->second.session ||
          iterator->second.retiring) {
        continue;
      }
      // PeerSession owns the transport state handler once it exists; before
      // that only this bounded tick observes ICE/transport failure, so a
      // failed attempt terminates explicitly instead of waiting for the
      // coordinator TTL.
      const auto snapshot = iterator->second.transport->snapshot();
      if (snapshot.state == transport::TransportState::failed && snapshot.error) {
        fail_peer_attempt(iterator->first, *snapshot.error);
      }
    }
  }

  void schedule_expiry() {
    if (producers_stopped) {
      return;
    }
    expiry_timer_active = true;
    expiry_timer.expires_after(std::chrono::milliseconds{500});
    auto weak = weak_from_this();
    expiry_timer.async_wait([weak](const boost::system::error_code& error) {
      if (!error) {
        if (auto self = weak.lock()) {
          const auto now = std::chrono::steady_clock::now();
          self->directory.expire(now);
          if (self->coordinator) self->coordinator->expire(now);
          self->check_peer_transport_failures();
          self->publish_directory();
          self->schedule_expiry();
        }
      } else if (auto self = weak.lock(); self && !self->producers_stopped) {
        self->expiry_timer_active = false;
        self->publish_resource_snapshot();
      }
    });
  }

  void schedule_interface_refresh() {
    if (producers_stopped) {
      return;
    }
    interface_timer_active = true;
    interface_timer.expires_after(lan.interface_refresh_interval);
    auto weak = weak_from_this();
    interface_timer.async_wait([weak](const boost::system::error_code& error) {
      if (!error) {
        if (auto self = weak.lock()) {
          self->request_interface_scan();
        }
      } else if (auto self = weak.lock(); self && !self->producers_stopped) {
        self->interface_timer_active = false;
        self->publish_resource_snapshot();
      }
    });
  }

  Result<void> request_interface_scan() {
    if (producers_stopped || interface_scan_in_flight) {
      return Result<void>::success();
    }
    interface_scan_in_flight = true;
    publish_resource_snapshot();
    auto weak = weak_from_this();
    auto dispatched = detail::RuntimeAccess::dispatch_general(
        *runtime, "heyaki-interface-scan", [weak] {
          auto self = weak.lock();
          if (!self) {
            return;
          }
          InterfaceScanResult result;
          auto scanned = enumerate_interfaces(self->lan);
          if (scanned) {
            result.bindings = std::move(*scanned.value_if());
          } else {
            result.error = *scanned.error_if();
          }
          const bool admitted = self->scan_results.try_send(std::move(result));
          boost::asio::post(self->strand, [weak, admitted] {
            if (auto current = weak.lock()) {
              current->finish_interface_scan(admitted);
            }
          });
        });
    if (!dispatched) {
      interface_scan_in_flight = false;
      update_snapshot([&](NodeSnapshot& snapshot) {
        snapshot.last_error = *dispatched.error_if();
      });
      schedule_interface_refresh();
      publish_resource_snapshot();
      return dispatched;
    }
    return Result<void>::success();
  }

  void finish_interface_scan(bool admitted) {
    interface_scan_in_flight = false;
    if (producers_stopped) {
      publish_resource_snapshot();
      maybe_stopped();
      return;
    }
    if (!admitted) {
      update_snapshot([](NodeSnapshot& snapshot) {
        snapshot.last_error = discovery_error(ErrorCode::resource_exhausted,
                                              "interface_scan_result_rejected");
      });
      schedule_interface_refresh();
      publish_resource_snapshot();
      return;
    }
    InterfaceScanResult result;
    if (!scan_results.try_receive(result)) {
      update_snapshot([](NodeSnapshot& snapshot) {
        snapshot.last_error = discovery_error(ErrorCode::internal,
                                              "interface_scan_result_missing");
      });
      schedule_interface_refresh();
      publish_resource_snapshot();
      return;
    }
    if (result.error) {
      update_snapshot([&](NodeSnapshot& snapshot) {
        snapshot.lan_state = LanReadinessState::degraded;
        snapshot.last_error = result.error;
      });
    } else if (result.bindings.size() > lan.interface_capacity) {
      update_snapshot([](NodeSnapshot& snapshot) {
        snapshot.lan_state = LanReadinessState::degraded;
        snapshot.last_error = discovery_error(ErrorCode::resource_exhausted,
                                              "interface_capacity_exhausted");
      });
    } else if (result.bindings != current_bindings) {
      current_bindings = std::move(result.bindings);
      open_discovery_sockets(current_bindings);
      for (const auto& socket : discovery_sockets) {
        start_receive(socket);
      }
      arm_multicast_readiness_timeout();
      announce_now();
      update_lan_readiness();
    }
    schedule_interface_refresh();
    publish_resource_snapshot();
  }

  void start_accept() {
    if (producers_stopped || !acceptor || !acceptor->is_open()) {
      return;
    }
    auto socket = std::make_shared<tcp::socket>(strand);
    auto weak = weak_from_this();
    acceptor->async_accept(*socket, [weak, socket](const boost::system::error_code& error) {
      auto self = weak.lock();
      if (!self || self->producers_stopped) {
        return;
      }
      if (error) {
        if (error != boost::asio::error::operation_aborted) {
          self->update_snapshot([&](NodeSnapshot& snapshot) {
            ++snapshot.tls.rejected;
            snapshot.last_error = tls_error(ErrorCode::transport,
                                            "tls_accept_failed", error);
          });
        }
      } else {
        self->admit_connection(std::move(*socket));
      }
      self->start_accept();
    });
  }

  AcceptRateOutcome admit_accept_rate(const std::string& address,
                                      SteadyTime now) {
    if (global_accept_window + std::chrono::seconds{1} <= now) {
      global_accept_window = now;
      global_accept_count = 0U;
    }
    if (global_accept_count >= lan.provisional_accept_rate_per_second) {
      return AcceptRateOutcome::global_rate_limited;
    }
    for (auto iterator = accept_rates.begin(); iterator != accept_rates.end();) {
      if (iterator->second.last_seen + std::chrono::seconds{2} <= now) {
        iterator = accept_rates.erase(iterator);
      } else {
        ++iterator;
      }
    }
    auto iterator = accept_rates.find(address);
    if (iterator == accept_rates.end()) {
      if (accept_rates.size() >= lan.provisional_connection_capacity) {
        return AcceptRateOutcome::source_state_capacity_full;
      }
      iterator = accept_rates.emplace(address, AcceptRate{now, now, 0U}).first;
    }
    auto& rate = iterator->second;
    if (rate.window_start + std::chrono::seconds{1} <= now) {
      rate.window_start = now;
      rate.count = 0U;
    }
    rate.last_seen = now;
    if (rate.count >= lan.per_source_provisional_rate) {
      return AcceptRateOutcome::source_rate_limited;
    }
    ++global_accept_count;
    ++rate.count;
    return AcceptRateOutcome::admitted;
  }

  void admit_connection(tcp::socket socket) {
    boost::system::error_code endpoint_error;
    const auto remote = socket.remote_endpoint(endpoint_error);
    const auto address = endpoint_error ? std::string{"unknown"}
                                        : remote.address().to_string();
    const auto now = std::chrono::steady_clock::now();
    const auto source_count = static_cast<std::size_t>(std::count_if(
        connections.begin(), connections.end(), [&](const auto& item) {
          return item.second->remote_address == address && !item.second->authenticated;
        }));
    auto rate_outcome = AcceptRateOutcome::admitted;
    if (connections.size() < lan.provisional_connection_capacity &&
        source_count < lan.per_source_provisional_capacity) {
      rate_outcome = admit_accept_rate(address, now);
    }
    const char* rejection_detail = nullptr;
    bool rate_limited = false;
    if (connections.size() >= lan.provisional_connection_capacity) {
      rejection_detail = "provisional_connection_capacity_full";
    } else if (source_count >= lan.per_source_provisional_capacity) {
      rejection_detail = "source_provisional_capacity_full";
    } else if (rate_outcome == AcceptRateOutcome::global_rate_limited) {
      rejection_detail = "provisional_accept_rate_limited";
      rate_limited = true;
    } else if (rate_outcome == AcceptRateOutcome::source_rate_limited) {
      rejection_detail = "source_provisional_rate_limited";
      rate_limited = true;
    } else if (rate_outcome == AcceptRateOutcome::source_state_capacity_full) {
      rejection_detail = "provisional_source_state_capacity_full";
    }
    if (rejection_detail != nullptr) {
      boost::system::error_code ignored;
      socket.close(ignored);
      update_snapshot([&](NodeSnapshot& snapshot) {
        ++snapshot.tls.rejected;
        if (rate_limited) {
          ++snapshot.tls.rate_limited;
        } else {
          ++snapshot.tls.capacity_rejected;
        }
        snapshot.last_error = tls_error(ErrorCode::resource_exhausted,
                                        rejection_detail);
      });
      return;
    }
    const auto id = ++next_connection_id;
    auto connection = std::make_shared<TlsConnection>(weak_from_this(), id, std::move(socket),
                                                      *tls_context, address, true);
    connections.emplace(id, connection);
    update_tls_counts([&](LanTlsSnapshot& tls) { ++tls.accepted; });
    publish_signaling_connections();
    connection->start_server();
  }

  DeviceEndpointKey local_key() const noexcept {
    return DeviceEndpointKey{identity.device_id(), endpoint_id};
  }

  std::optional<IdentityPublicKey> peer_identity(DeviceEndpointKey peer) const {
    const auto entries = directory.snapshot();
    const auto iterator = std::find_if(entries.begin(), entries.end(),
                                       [&](const auto& entry) {
                                         return entry.key == peer &&
                                                (entry.lan.has_value() ||
                                                 entry.relay.has_value());
                                       });
    if (iterator == entries.end()) return std::nullopt;
    return iterator->lan ? iterator->lan->identity_public_key
                         : iterator->relay->identity_public_key;
  }

  NodePeerSessionSnapshot peer_session_snapshot(const PeerAttempt& attempt) const {
    auto snapshot = attempt.snapshot;
    if (attempt.timeline) {
      snapshot.connection_stage =
          public_connection_stage(attempt.timeline->stage());
    }
    if (attempt.transport) {
      const auto transport = attempt.transport->snapshot();
      snapshot.data_path = public_data_path(transport.path.data_path);
      snapshot.selected_candidate = transport.path.selected_candidate;
      snapshot.rtt = transport.path.rtt;
      snapshot.buffered_amount = transport.buffered_amount;
      if (!snapshot.error && transport.error) snapshot.error = transport.error;
    }
    return snapshot;
  }

  void publish_peer_sessions() {
    std::vector<NodePeerSessionSnapshot> published;
    published.reserve(peer_attempts.size() + finished_peer_sessions.size());
    for (const auto& [request_id, attempt] : peer_attempts) {
      (void)request_id;
      published.push_back(peer_session_snapshot(attempt));
    }
    published.insert(published.end(), finished_peer_sessions.begin(),
                     finished_peer_sessions.end());
    peer_session_snapshots.publish(std::move(published));
  }

  Result<void> initialize_session_coordinator() {
    if (signaling_validator || signaling_handler ||
        (!lan.enabled && !relay.enabled)) {
      return Result<void>::success();
    }
    coordinator_delegate = std::make_shared<SignalingDelegate>();
    coordinator_delegate->peer_identity = [this](const DeviceEndpointKey& peer) {
      return peer_identity(peer);
    };
    coordinator_delegate->on_inbound_connect =
        [this](const SignalingAttemptSnapshot& snapshot) {
          return admit_inbound_attempt(snapshot);
        };
    coordinator_delegate->on_outbound_accepted =
        [this](const SignalingAttemptSnapshot& snapshot) {
          auto started = start_webrtc_transport(snapshot, true, std::nullopt);
          if (!started) fail_peer_attempt(snapshot.request_id, *started.error_if());
        };
    coordinator_delegate->on_verified_offer =
        [this](const SignalingAttemptSnapshot& snapshot, const SignedOffer& offer) {
          auto started = start_webrtc_transport(snapshot, false, offer.sdp);
          if (!started) fail_peer_attempt(snapshot.request_id, *started.error_if());
        };
    coordinator_delegate->on_verified_answer =
        [this](const SignalingAttemptSnapshot& snapshot, const SignedAnswer& answer,
               const SignalingTranscriptSha256&) {
          auto iterator = peer_attempts.find(snapshot.request_id);
          if (iterator == peer_attempts.end() || !iterator->second.transport) {
            fail_peer_attempt(snapshot.request_id,
                              node_error(ErrorCode::internal,
                                         "peer_transport_missing_for_answer"));
            return;
          }
          iterator->second.candidate_signing_ready = true;
          auto candidates_sent = flush_local_candidates(snapshot.request_id);
          if (!candidates_sent) {
            fail_peer_attempt(snapshot.request_id, *candidates_sent.error_if());
            return;
          }
          auto applied = apply_remote_description(snapshot.request_id, answer.sdp,
                                                  "answer");
          if (!applied) {
            fail_peer_attempt(snapshot.request_id, *applied.error_if());
            return;
          }
          auto session = start_verified_peer_session(snapshot.request_id);
          if (!session) fail_peer_attempt(snapshot.request_id, *session.error_if());
        };
    coordinator_delegate->on_verified_candidate =
        [this](const SignalingAttemptSnapshot& snapshot,
               const SignedCandidate& candidate) {
          auto iterator = peer_attempts.find(snapshot.request_id);
          if (iterator == peer_attempts.end() || !iterator->second.transport) {
            fail_peer_attempt(snapshot.request_id,
                              node_error(ErrorCode::internal,
                                         "peer_transport_missing_for_candidate"));
            return;
          }
          if (!iterator->second.remote_description_ready) {
            if (iterator->second.pending_remote_candidates.size() >= 128U) {
              fail_peer_attempt(snapshot.request_id,
                                node_error(ErrorCode::resource_exhausted,
                                           "pending_remote_candidate_capacity_full"));
              return;
            }
            iterator->second.pending_remote_candidates.push_back(candidate.candidate);
            return;
          }
          auto applied = iterator->second.transport->add_remote_candidate(
              candidate.candidate);
          if (!applied) fail_peer_attempt(snapshot.request_id, *applied.error_if());
        };
    coordinator_delegate->on_attempt_error =
        [this](const SignalingAttemptSnapshot& snapshot, const Error& error) {
          fail_peer_attempt(snapshot.request_id, error);
        };

    SignalingCoordinatorConfig config;
    config.local = local_key();
    config.identity = &identity;
    config.max_pending_attempts = lan.pending_signaling_capacity;
    config.max_inbound_attempts = lan.pending_signaling_capacity;
    config.max_candidates_per_attempt = 128U;
    auto created = SignalingCoordinator::create(config, coordinator_delegate);
    if (!created) return Result<void>::failure(*created.error_if());
    coordinator.emplace(std::move(*created.value_if()));
    if (lan.enabled && lan.connectivity_mode != ConnectivityMode::relay_only) {
      lan_coordinator_route = std::make_unique<LanCoordinatorRoute>(*this);
      coordinator->attach_route(lan_coordinator_route.get());
    }
    if (relay.enabled && lan.connectivity_mode != ConnectivityMode::lan_only) {
      relay_coordinator_route = std::make_unique<RelaySignalingRoute>(
          local_key(), [this](std::span<const std::byte> frame) {
            if (relay_phase != RelayLoginPhase::ready || !relay_client) {
              return Result<void>::failure(
                  node_error(ErrorCode::relay_unavailable, "relay_route_not_ready"));
            }
            return relay_client->send(frame);
          });
      coordinator->attach_route(relay_coordinator_route.get());
    }
    return Result<void>::success();
  }

  bool admit_inbound_attempt(const SignalingAttemptSnapshot& snapshot) {
    if (peers_closed || peer_attempts.size() >= lan.pending_signaling_capacity ||
        peer_attempt_by_endpoint.contains(snapshot.peer)) {
      return false;
    }
    auto public_key = peer_identity(snapshot.peer);
    if (!public_key) return false;
    PeerAttempt attempt;
    attempt.snapshot.peer = snapshot.peer;
    attempt.snapshot.request_id = snapshot.request_id;
    attempt.snapshot.session_id = snapshot.session_id;
    attempt.snapshot.signaling_route = snapshot.route;
    attempt.snapshot.state = NodePeerSessionState::signaling;
    attempt.snapshot.initiator = false;
    attempt.peer_public_key = *public_key;
    attempt.timeline = std::make_shared<ConnectionAttemptTimeline>();
    auto resolved = attempt.timeline->transition(ConnectionStage::resolving_endpoint,
                                                  "node", "inbound_peer_resolved");
    if (!resolved) return false;
    auto signaling = attempt.timeline->transition(ConnectionStage::signaling,
                                                   "signaling", "connect_accepted");
    if (!signaling) return false;
    peer_attempt_by_endpoint.emplace(snapshot.peer, snapshot.request_id);
    peer_attempts.emplace(snapshot.request_id, std::move(attempt));
    publish_peer_sessions();
    return true;
  }

  Result<void> begin_peer_attempt(
      DeviceEndpointKey peer,
      std::optional<SignalingRouteKind> required_route = std::nullopt) {
    if (!coordinator || peers_closed || producers_stopped) {
      return Result<void>::failure(
          node_error(ErrorCode::cancelled, "peer_session_admission_closed"));
    }
    if (peer_attempt_by_endpoint.contains(peer)) return Result<void>::success();
    if (peer_attempts.size() >= lan.pending_signaling_capacity) {
      return Result<void>::failure(
          node_error(ErrorCode::resource_exhausted, "peer_attempt_capacity_full"));
    }
    auto public_key = peer_identity(peer);
    if (!public_key) {
      return Result<void>::failure(
          node_error(ErrorCode::authentication, "peer_identity_unavailable"));
    }
    const auto entries = directory.snapshot();
    const auto endpoint = std::find_if(entries.begin(), entries.end(),
                                       [&](const auto& entry) { return entry.key == peer; });
    const bool lan_available = endpoint != entries.end() && endpoint->lan.has_value() &&
                               lan_coordinator_route != nullptr;
    const bool relay_available = endpoint != entries.end() && endpoint->relay.has_value() &&
                                 relay_coordinator_route != nullptr &&
                                 relay_phase == RelayLoginPhase::ready;
    auto selected = required_route
        ? Result<SignalingRouteKind>::success(*required_route)
        : select_signaling_route(lan.connectivity_mode, lan_available, relay_available);
    if (!selected) return Result<void>::failure(*selected.error_if());
    if ((*selected.value_if() == SignalingRouteKind::lan && !lan_available) ||
        (*selected.value_if() == SignalingRouteKind::relay && !relay_available)) {
      return Result<void>::failure(node_error(
          *selected.value_if() == SignalingRouteKind::relay
              ? ErrorCode::relay_unavailable : ErrorCode::endpoint_offline,
          "selected_signaling_route_unavailable"));
    }
    auto request = coordinator->begin_attempt(peer, *selected.value_if());
    if (!request) return Result<void>::failure(*request.error_if());
    PeerAttempt attempt;
    attempt.snapshot.peer = peer;
    attempt.snapshot.request_id = *request.value_if();
    attempt.snapshot.signaling_route = *selected.value_if();
    attempt.snapshot.state = NodePeerSessionState::signaling;
    attempt.snapshot.initiator = true;
    attempt.peer_public_key = *public_key;
    attempt.timeline = std::make_shared<ConnectionAttemptTimeline>();
    auto resolved = attempt.timeline->transition(ConnectionStage::resolving_endpoint,
                                                  "node", "endpoint_selected");
    if (!resolved) return Result<void>::failure(*resolved.error_if());
    auto signaling = attempt.timeline->transition(ConnectionStage::signaling,
                                                   "signaling", "connect_requested");
    if (!signaling) return Result<void>::failure(*signaling.error_if());
    peer_attempt_by_endpoint.emplace(peer, *request.value_if());
    peer_attempts.emplace(*request.value_if(), std::move(attempt));
    publish_peer_sessions();
    return Result<void>::success();
  }

  Result<void> send_coordinator_envelope(const SignalingEnvelope& envelope) {
    LanSignalingMessage message{.peer = envelope.peer,
                                .kind = envelope.kind,
                                .request_id = envelope.request_id,
                                .payload = envelope.payload};
    auto valid = validate_signaling_message_shape(message);
    if (!valid) return valid;
    return queue_outbound_message(std::move(message));
  }

  transport::webrtc::RuntimeDispatcher peer_dispatcher() {
    auto weak = weak_from_this();
    return [weak](std::string_view, std::function<Result<void>()> task) {
      auto self = weak.lock();
      if (!self || self->peers_closed) {
        return Result<void>::failure(
            node_error(ErrorCode::cancelled, "peer_dispatch_closed"));
      }
      try {
        boost::asio::post(self->strand,
                          [weak, task = std::move(task)]() mutable {
                            if (auto current = weak.lock(); current && !current->peers_closed) {
                              auto completed = task();
                              if (!completed) {
                                current->record_signaling_error(*completed.error_if());
                              }
                            }
                          });
      } catch (...) {
        return Result<void>::failure(
            node_error(ErrorCode::internal, "peer_dispatch_failed"));
      }
      return Result<void>::success();
    };
  }

  Result<void> start_webrtc_transport(
      const SignalingAttemptSnapshot& snapshot, bool offerer,
      std::optional<std::vector<std::byte>> remote_offer) {
    auto iterator = peer_attempts.find(snapshot.request_id);
    if (iterator == peer_attempts.end() || iterator->second.transport) {
      return Result<void>::failure(
          node_error(ErrorCode::signaling, "peer_attempt_transport_conflict"));
    }
    transport::webrtc::WebRtcTransportConfig config;
    config.offerer = offerer;
    config.signaling_path = snapshot.route == SignalingRouteKind::relay
                                ? transport::SignalingPathKind::relay
                                : transport::SignalingPathKind::lan;
    config.candidates.allow_ipv6_host = path_policy.allow_ipv6_host;
    config.candidates.allow_ipv4_host = path_policy.allow_ipv4_host;
    config.candidates.allow_server_reflexive = path_policy.allow_server_reflexive;
    config.candidates.allow_turn_udp = path_policy.allow_turn_udp;
    config.candidates.allow_turn_tcp = path_policy.allow_turn_tcp;
    config.candidates.allow_turn_tls = path_policy.allow_turn_tls;
    config.candidates.relay_only = path_policy.force_turn_data_path;
    config.ice_servers.reserve(path_policy.ice_servers.size());
    for (const auto& server : path_policy.ice_servers) {
      transport::webrtc::IceServerConfig mapped;
      switch (server.kind) {
        case NodeIceServerKind::stun:
          mapped.kind = transport::webrtc::IceServerKind::stun;
          break;
        case NodeIceServerKind::turn_udp:
          mapped.kind = transport::webrtc::IceServerKind::turn_udp;
          break;
        case NodeIceServerKind::turn_tcp:
          mapped.kind = transport::webrtc::IceServerKind::turn_tcp;
          break;
        case NodeIceServerKind::turn_tls:
          mapped.kind = transport::webrtc::IceServerKind::turn_tls;
          break;
      }
      mapped.hostname = server.hostname;
      mapped.port = server.port;
      mapped.username = server.username;
      mapped.credential = server.credential;
      config.ice_servers.push_back(std::move(mapped));
    }

    auto weak = weak_from_this();
    const auto request_id = snapshot.request_id;
    transport::webrtc::WebRtcSignalingHandler signaling;
    signaling.on_local_description =
        [weak, request_id](std::vector<std::byte> sdp, std::string type,
                           DtlsFingerprint fingerprint) {
          auto self = weak.lock();
          if (!self || !self->coordinator) return;
          Result<void> sent = type == "offer"
                                  ? self->coordinator->send_local_offer(
                                        request_id, sdp, fingerprint)
                                  : self->coordinator->send_local_answer(
                                        request_id, sdp, fingerprint);
          if (!sent) {
            self->fail_peer_attempt(request_id, *sent.error_if());
            return;
          }
          auto iterator = self->peer_attempts.find(request_id);
          if (iterator == self->peer_attempts.end()) return;
          if (type == "answer") {
            iterator->second.candidate_signing_ready = true;
          }
          auto candidates_sent = self->flush_local_candidates(request_id);
          if (!candidates_sent) {
            self->fail_peer_attempt(request_id, *candidates_sent.error_if());
            return;
          }
          if (type == "answer") {
            auto started = self->start_verified_peer_session(request_id);
            if (!started) self->fail_peer_attempt(request_id, *started.error_if());
          }
        };
    signaling.on_local_candidate =
        [weak, request_id](std::vector<std::byte> candidate) {
          auto self = weak.lock();
          if (!self || !self->coordinator) return;
          auto iterator = self->peer_attempts.find(request_id);
          if (iterator == self->peer_attempts.end()) return;
          if (!iterator->second.candidate_signing_ready) {
            if (iterator->second.pending_local_candidates.size() >= 128U) {
              self->fail_peer_attempt(
                  request_id,
                  node_error(ErrorCode::resource_exhausted,
                             "pending_local_candidate_capacity_full"));
              return;
            }
            iterator->second.pending_local_candidates.push_back(std::move(candidate));
            return;
          }
          auto sent = self->coordinator->send_local_candidate(request_id, candidate);
          if (!sent) self->fail_peer_attempt(request_id, *sent.error_if());
        };
    auto created = transport::webrtc::WebRtcTransportSession::create(
        config, peer_dispatcher(), std::move(signaling));
    if (!created) return Result<void>::failure(*created.error_if());
    iterator->second.transport = *created.value_if();
    iterator->second.snapshot.state = NodePeerSessionState::transport_connecting;
    publish_peer_sessions();
    if (offerer) {
      transport::ChannelOptions control_options;
      control_options.priority = transport::ChannelPriority::control;
      control_options.send_queue_bytes = 64U * 1024U;
      control_options.max_message_bytes = 64U * 1024U;
      auto prepared =
          iterator->second.transport->prepare_channel(transport::ChannelKind::control,
                                                      control_options);
      if (!prepared) return prepared;
    }
    if (remote_offer) {
      auto applied = apply_remote_description(snapshot.request_id, *remote_offer,
                                              "offer");
      if (!applied) return applied;
    }
    return iterator->second.transport->start();
  }

  Result<void> flush_local_candidates(RequestId request_id) {
    auto iterator = peer_attempts.find(request_id);
    if (iterator == peer_attempts.end() || !coordinator) {
      return Result<void>::failure(
          node_error(ErrorCode::signaling, "peer_attempt_unknown"));
    }
    if (!iterator->second.candidate_signing_ready) {
      return Result<void>::success();
    }
    while (!iterator->second.pending_local_candidates.empty()) {
      auto candidate = std::move(iterator->second.pending_local_candidates.front());
      iterator->second.pending_local_candidates.pop_front();
      auto sent = coordinator->send_local_candidate(request_id, candidate);
      if (!sent) return sent;
    }
    return Result<void>::success();
  }

  Result<void> apply_remote_description(RequestId request_id,
                                        std::span<const std::byte> sdp,
                                        std::string_view type) {
    auto iterator = peer_attempts.find(request_id);
    if (iterator == peer_attempts.end() || !iterator->second.transport) {
      return Result<void>::failure(
          node_error(ErrorCode::internal, "peer_transport_missing_for_description"));
    }
    auto applied = iterator->second.transport->set_remote_description(sdp, type);
    if (!applied) return applied;
    iterator->second.remote_description_ready = true;
    while (!iterator->second.pending_remote_candidates.empty()) {
      auto candidate =
          std::move(iterator->second.pending_remote_candidates.front());
      iterator->second.pending_remote_candidates.pop_front();
      auto added = iterator->second.transport->add_remote_candidate(candidate);
      if (!added) return added;
    }
    return Result<void>::success();
  }

  Result<void> start_verified_peer_session(RequestId request_id) {
    auto iterator = peer_attempts.find(request_id);
    if (iterator == peer_attempts.end() || !iterator->second.transport ||
        iterator->second.session) {
      return Result<void>::failure(
          node_error(ErrorCode::signaling, "peer_session_start_conflict"));
    }
    auto binding = coordinator->verified_session_binding(request_id, 1U);
    if (!binding) return Result<void>::failure(*binding.error_if());
    iterator->second.snapshot.session_id = binding.value_if()->expectation.session_id;
    iterator->second.snapshot.state = NodePeerSessionState::authenticating;
    const auto expires = unix_milliseconds_now() + 60'000U;
    auto weak = weak_from_this();
    auto session = PeerSession::create_verified(
        {.transport = iterator->second.transport,
         .binding = *binding.value_if(),
         .local_identity = &identity,
         .peer_public_key = iterator->second.peer_public_key,
         .local_protocol = {.version = current_protocol_version,
                            .supported = {protocol_1_1_capability_bits},
                            .required = {static_cast<std::uint64_t>(Capability::session)}},
         .expires_unix_milliseconds = expires,
         .now_unix_milliseconds = unix_milliseconds_now(),
         .observer = [weak, request_id](const PeerSessionDiagnostics& diagnostics) {
           if (auto self = weak.lock()) {
             self->peer_session_changed(request_id, diagnostics);
           }
         },
         .timeline = iterator->second.timeline,
         .clock = {}});
    if (!session) return Result<void>::failure(*session.error_if());
    iterator->second.session = *session.value_if();
    publish_peer_sessions();
    return iterator->second.session->start();
  }

  void peer_session_changed(RequestId request_id,
                            const PeerSessionDiagnostics& diagnostics) {
    auto iterator = peer_attempts.find(request_id);
    if (iterator == peer_attempts.end()) return;
    // A retiring attempt already carries its root-cause error; late
    // close-cascade diagnostics (for example a pending channel open failing
    // with transport_closed) must not overwrite it.
    if (!iterator->second.retiring && diagnostics.last_error) {
      iterator->second.snapshot.error = diagnostics.last_error;
    }
    switch (diagnostics.state) {
      case PeerSessionState::idle:
        break;
      case PeerSessionState::authenticating:
        iterator->second.snapshot.state = NodePeerSessionState::authenticating;
        break;
      case PeerSessionState::authenticated:
        iterator->second.snapshot.state = NodePeerSessionState::authenticated;
        if (coordinator) {
          (void)coordinator->cancel_attempt(request_id,
                                            std::chrono::steady_clock::now());
        }
        close_peer(iterator->second.snapshot.peer);
        break;
      case PeerSessionState::pairing_restricted:
        iterator->second.snapshot.state = NodePeerSessionState::authenticating;
        break;
      case PeerSessionState::closed:
        iterator->second.snapshot.state = NodePeerSessionState::closed;
        if (!peers_closed && !iterator->second.retiring) {
          const auto error = diagnostics.last_error.value_or(
              node_error(ErrorCode::transport, "peer_session_closed"));
          fail_peer_attempt(request_id, error);
          return;
        }
        break;
    }
    publish_peer_sessions();
  }

  void fail_peer_attempt(RequestId request_id, Error error) {
    auto iterator = peer_attempts.find(request_id);
    if (iterator == peer_attempts.end()) {
      record_signaling_error(error);
      return;
    }
    if (iterator->second.retiring) return;
    iterator->second.retiring = true;
    iterator->second.snapshot.state = NodePeerSessionState::closed;
    iterator->second.snapshot.error = error;
    if (coordinator) {
      (void)coordinator->cancel_attempt(request_id,
                                        std::chrono::steady_clock::now());
    }
    if (iterator->second.session) {
      iterator->second.session->close(transport::CloseReason::protocol_error);
    } else if (iterator->second.transport) {
      iterator->second.transport->close(transport::CloseReason::protocol_error);
    }
    const auto peer = iterator->second.snapshot.peer;
    auto completed = peer_session_snapshot(iterator->second);
    peer_attempt_by_endpoint.erase(peer);
    peer_attempts.erase(iterator);
    finished_peer_sessions.push_back(std::move(completed));
    while (finished_peer_sessions.size() > lan.diagnostic_capacity) {
      finished_peer_sessions.pop_front();
    }
    record_signaling_error(error);
    publish_peer_sessions();
  }

  std::optional<LanEndpointSnapshot> find_lan_endpoint(DeviceEndpointKey peer) {
    const auto entries = directory.snapshot();
    const auto iterator = std::find_if(entries.begin(), entries.end(),
                                       [&](const auto& entry) {
                                         return entry.key == peer && entry.lan.has_value();
                                       });
    return iterator == entries.end() ? std::nullopt : iterator->lan;
  }

  LanSignalingConnectionSnapshot connection_snapshot(
      const TlsConnection& connection, std::optional<Error> error = std::nullopt) const {
    LanSignalingConnectionSnapshot snapshot;
    snapshot.peer = connection.peer.value_or(connection.expected_peer);
    snapshot.state = connection.state;
    snapshot.inbound = connection.inbound;
    snapshot.local_offer_owner =
        !snapshot.peer.device_id.is_zero() &&
        is_lan_offer_owner(local_key(), snapshot.peer);
    snapshot.address = connection.remote_address;
    snapshot.error = std::move(error);
    return snapshot;
  }

  void publish_signaling_connections() {
    std::vector<LanSignalingConnectionSnapshot> published;
    published.reserve(connections.size() + finished_signaling.size());
    for (const auto& [id, connection] : connections) {
      (void)id;
      published.push_back(connection_snapshot(*connection));
    }
    published.insert(published.end(), finished_signaling.begin(),
                     finished_signaling.end());
    signaling_snapshots.publish(std::move(published));
    publish_resource_snapshot();
  }

  void connection_state_changed(const std::shared_ptr<TlsConnection>& connection,
                                LanSignalingConnectionState state) {
    if (!connections.contains(connection->id)) {
      return;
    }
    connection->state = state;
    publish_signaling_connections();
  }

  void retire_connection(const std::shared_ptr<TlsConnection>& connection,
                         LanSignalingConnectionState state,
                         std::optional<Error> error = std::nullopt) {
    if (!connections.contains(connection->id)) {
      return;
    }
    connection->state = state;
    if (connection->peer) {
      const auto active = active_connections.find(*connection->peer);
      if (active != active_connections.end() && active->second == connection->id) {
        active_connections.erase(active);
      }
    }
    const auto automatic = auto_connect_connections.find(connection->expected_peer);
    if (automatic != auto_connect_connections.end() &&
        automatic->second == connection->id) {
      auto_connect_connections.erase(automatic);
    }
    connection->close();
    finished_signaling.push_back(connection_snapshot(*connection, std::move(error)));
    while (finished_signaling.size() > lan.diagnostic_capacity) {
      finished_signaling.pop_front();
    }
    connections.erase(connection->id);
    update_tls_counts([](LanTlsSnapshot&) {});
    publish_signaling_connections();
  }

  void record_signaling_error(const Error& error) {
    update_snapshot([&](NodeSnapshot& snapshot) { snapshot.last_error = error; });
  }

  void start_outbound_connection(DeviceEndpointKey peer, bool automatic = false,
                                 SignalingRouteKind route = SignalingRouteKind::lan) {
    if (producers_stopped || peers_closed) {
      record_signaling_error(
          tls_error(ErrorCode::cancelled, "signaling_admission_closed"));
      return;
    }
    if (peer == local_key() || peer.device_id.is_zero() || peer.endpoint_id.is_zero()) {
      record_signaling_error(
          tls_error(ErrorCode::configuration, "signaling_peer_invalid"));
      return;
    }
    if (route == SignalingRouteKind::relay) {
      auto begun = begin_peer_attempt(peer, route);
      if (!begun) record_signaling_error(*begun.error_if());
      return;
    }
    const bool already_connecting = std::any_of(
        connections.begin(), connections.end(), [&](const auto& item) {
          return item.second->expected_peer == peer ||
                 (item.second->peer && *item.second->peer == peer);
        });
    if (already_connecting) {
      return;
    }
    const auto lan_endpoint = find_lan_endpoint(peer);
    if (!lan_endpoint) {
      record_signaling_error(
          tls_error(ErrorCode::endpoint_offline, "lan_endpoint_unavailable"));
      return;
    }
    if (connections.size() >= lan.provisional_connection_capacity) {
      record_signaling_error(tls_error(ErrorCode::resource_exhausted,
                                       "provisional_connection_capacity_full"));
      return;
    }
    boost::system::error_code address_error;
    auto address = boost::asio::ip::make_address(lan_endpoint->address, address_error);
    if (address_error || lan_endpoint->tls_signaling_port == 0U) {
      record_signaling_error(
          tls_error(ErrorCode::protocol, "lan_endpoint_address_invalid", address_error));
      return;
    }
    const auto id = ++next_connection_id;
    auto connection = std::make_shared<TlsConnection>(
        weak_from_this(), id, tcp::socket{strand}, *tls_context,
        lan_endpoint->address, false);
    connection->expected_peer = peer;
    connection->expected_peer_boot_nonce = lan_endpoint->boot_nonce;
    connections.emplace(id, connection);
    if (automatic) {
      auto_connect_connections[peer] = id;
    }
    update_tls_counts([](LanTlsSnapshot&) {});
    publish_signaling_connections();
    connection->start_client(
        tcp::endpoint{address, lan_endpoint->tls_signaling_port});
  }

  bool presence_matches(const LanHello& hello) {
    const DeviceEndpointKey key{hello.sender_device_id, hello.sender_endpoint_id};
    const auto entries = directory.snapshot();
    const auto iterator = std::find_if(entries.begin(), entries.end(), [&](const auto& entry) {
      return entry.key == key && entry.lan &&
             entry.lan->boot_nonce == hello.sender_boot_nonce;
    });
    return iterator != entries.end();
  }

  bool initial_hello_matches(const std::shared_ptr<TlsConnection>& connection,
                             const LanHello& hello) {
    return hello.role == LanHelloRole::initiator &&
           hello.peer_device_id == identity.device_id() &&
           hello.peer_endpoint_id == endpoint_id &&
           hello.sender_tls_certificate_sha256 == connection->peer_fingerprint &&
           hello.observed_peer_tls_certificate_sha256 == certificate_fingerprint &&
           std::all_of(hello.responder_nonce.begin(), hello.responder_nonce.end(),
                       [](std::byte value) { return value == std::byte{0}; }) &&
           presence_matches(hello);
  }

  void handle_initial_hello(const std::shared_ptr<TlsConnection>& connection,
                            Result<LanHello> hello) {
    if (!hello || !initial_hello_matches(connection, *hello.value_if())) {
      connection_failed(connection->id, "initial_hello_invalid", {}, false, true);
      return;
    }
    connection->initial_hello = *hello.value_if();
    connection->expected_peer = DeviceEndpointKey{hello.value_if()->sender_device_id,
                                                  hello.value_if()->sender_endpoint_id};
    connection->expected_peer_boot_nonce = hello.value_if()->sender_boot_nonce;
    randombytes_buf(connection->responder_nonce.data(), connection->responder_nonce.size());
    connection->arm_timeout(std::min(lan.hello_timeout, hello.value_if()->expiry),
                            "lan_hello_timeout");
    LanHello response;
    response.role = LanHelloRole::responder;
    response.sender_endpoint_id = endpoint_id;
    response.peer_device_id = hello.value_if()->sender_device_id;
    response.peer_endpoint_id = hello.value_if()->sender_endpoint_id;
    response.initiator_nonce = hello.value_if()->initiator_nonce;
    response.responder_nonce = connection->responder_nonce;
    response.sender_tls_certificate_sha256 = certificate_fingerprint;
    response.observed_peer_tls_certificate_sha256 = connection->peer_fingerprint;
    response.sender_boot_nonce = boot_nonce;
    response.expiry = std::min(lan.hello_timeout,
                               std::chrono::milliseconds{max_lan_hello_expiry_milliseconds});
    auto signed_response = sign_lan_hello(response, identity);
    if (!signed_response) {
      connection_failed(connection->id, "response_hello_sign_failed", {}, false, true);
      return;
    }
    connection->write_hello(response, [connection](Result<void> written) {
      if (auto owner = connection->owner.lock()) {
        if (!written) {
          owner->connection_failed(connection->id, "response_hello_write_failed", {}, false,
                                   true);
          return;
        }
        connection->read_hello([connection](Result<LanHello> final_hello) {
          if (auto current = connection->owner.lock()) {
            current->handle_final_hello(connection, std::move(final_hello));
          }
        });
      }
    });
  }

  void handle_final_hello(const std::shared_ptr<TlsConnection>& connection,
                          Result<LanHello> hello) {
    const auto& initial = connection->initial_hello;
    const bool matches = hello && hello.value_if()->role == LanHelloRole::initiator &&
                         hello.value_if()->sender_device_id == initial.sender_device_id &&
                         hello.value_if()->sender_endpoint_id == initial.sender_endpoint_id &&
                         hello.value_if()->peer_device_id == identity.device_id() &&
                         hello.value_if()->peer_endpoint_id == endpoint_id &&
                         hello.value_if()->initiator_nonce == initial.initiator_nonce &&
                         hello.value_if()->responder_nonce == connection->responder_nonce &&
                         hello.value_if()->sender_tls_certificate_sha256 ==
                             connection->peer_fingerprint &&
                         hello.value_if()->observed_peer_tls_certificate_sha256 ==
                             certificate_fingerprint &&
                         hello.value_if()->sender_boot_nonce == initial.sender_boot_nonce &&
                         presence_matches(*hello.value_if());
    if (!matches) {
      connection_failed(connection->id, "final_hello_invalid", {}, false, true);
      return;
    }
    authenticate_connection(
        connection,
        DeviceEndpointKey{initial.sender_device_id, initial.sender_endpoint_id});
  }

  void handle_client_tls_ready(const std::shared_ptr<TlsConnection>& connection) {
    if (!connections.contains(connection->id)) {
      return;
    }
    connection->arm_timeout(lan.hello_timeout, "lan_hello_timeout");
    randombytes_buf(connection->initiator_nonce.data(),
                    connection->initiator_nonce.size());
    LanHello initial;
    initial.role = LanHelloRole::initiator;
    initial.sender_endpoint_id = endpoint_id;
    initial.peer_device_id = connection->expected_peer.device_id;
    initial.peer_endpoint_id = connection->expected_peer.endpoint_id;
    initial.initiator_nonce = connection->initiator_nonce;
    initial.sender_tls_certificate_sha256 = certificate_fingerprint;
    initial.observed_peer_tls_certificate_sha256 = connection->peer_fingerprint;
    initial.sender_boot_nonce = boot_nonce;
    initial.expiry = std::min(
        lan.hello_timeout,
        std::chrono::milliseconds{max_lan_hello_expiry_milliseconds});
    auto signed_initial = sign_lan_hello(initial, identity);
    if (!signed_initial) {
      connection_failed(connection->id, "initial_hello_sign_failed", {}, false, true);
      return;
    }
    connection->initial_hello = initial;
    connection->write_hello(initial, [connection](Result<void> written) {
      auto owner = connection->owner.lock();
      if (!owner) {
        return;
      }
      if (!written) {
        owner->connection_failed(connection->id, "initial_hello_write_failed", {}, false,
                                 true);
        return;
      }
      connection->read_hello([connection](Result<LanHello> response) {
        if (auto response_owner = connection->owner.lock()) {
          response_owner->handle_response_hello(connection, std::move(response));
        }
      });
    });
  }

  void handle_response_hello(const std::shared_ptr<TlsConnection>& connection,
                             Result<LanHello> response) {
    const bool responder_nonce_nonzero =
        response && std::any_of(response.value_if()->responder_nonce.begin(),
                                response.value_if()->responder_nonce.end(),
                                [](std::byte value) { return value != std::byte{0}; });
    const bool matches =
        response && responder_nonce_nonzero &&
        response.value_if()->role == LanHelloRole::responder &&
        response.value_if()->sender_device_id == connection->expected_peer.device_id &&
        response.value_if()->sender_endpoint_id == connection->expected_peer.endpoint_id &&
        response.value_if()->peer_device_id == identity.device_id() &&
        response.value_if()->peer_endpoint_id == endpoint_id &&
        response.value_if()->initiator_nonce == connection->initiator_nonce &&
        response.value_if()->sender_tls_certificate_sha256 ==
            connection->peer_fingerprint &&
        response.value_if()->observed_peer_tls_certificate_sha256 ==
            certificate_fingerprint &&
        response.value_if()->sender_boot_nonce ==
            connection->expected_peer_boot_nonce &&
        presence_matches(*response.value_if());
    if (!matches) {
      connection_failed(connection->id, "response_hello_invalid", {}, false, true);
      return;
    }
    connection->responder_nonce = response.value_if()->responder_nonce;
    LanHello final_hello = connection->initial_hello;
    final_hello.responder_nonce = connection->responder_nonce;
    auto signed_final = sign_lan_hello(final_hello, identity);
    if (!signed_final) {
      connection_failed(connection->id, "final_hello_sign_failed", {}, false, true);
      return;
    }
    connection->write_hello(final_hello, [connection](Result<void> written) {
      auto owner = connection->owner.lock();
      if (!owner) {
        return;
      }
      if (!written) {
        owner->connection_failed(connection->id, "final_hello_write_failed", {}, false,
                                 true);
        return;
      }
      owner->authenticate_connection(connection, connection->expected_peer);
    });
  }

  void authenticate_connection(const std::shared_ptr<TlsConnection>& connection,
                               DeviceEndpointKey peer) {
    if (!connections.contains(connection->id)) {
      return;
    }
    connection->peer = peer;
    const auto existing = active_connections.find(peer);
    if (existing != active_connections.end() && existing->second != connection->id) {
      auto existing_connection = connections.find(existing->second);
      if (existing_connection != connections.end()) {
        const bool local_owner = is_lan_offer_owner(local_key(), peer);
        const bool candidate_preferred = connection->inbound != local_owner;
        const bool existing_preferred =
            existing_connection->second->inbound != local_owner;
        const Error arbitration = tls_error(ErrorCode::cancelled,
                                            "duplicate_signaling_arbitrated");
        if (!candidate_preferred || existing_preferred) {
          retire_connection(connection, LanSignalingConnectionState::closed,
                            arbitration);
          return;
        }
        retire_connection(existing_connection->second,
                          LanSignalingConnectionState::closed, arbitration);
      }
    }
    try {
      (void)connection->timer.cancel();
    } catch (...) {
    }
    connection->authenticated = true;
    connection->state = LanSignalingConnectionState::authenticated;
    active_connections[peer] = connection->id;
    update_tls_counts([](LanTlsSnapshot&) {});
    publish_signaling_connections();
    start_signaling_read(connection);
    if (coordinator && is_lan_offer_owner(local_key(), peer)) {
      auto begun = begin_peer_attempt(peer);
      if (!begun) record_signaling_error(*begun.error_if());
    }
  }

  void start_signaling_read(const std::shared_ptr<TlsConnection>& connection) {
    if (!connections.contains(connection->id) || !connection->authenticated ||
        connection->inbound_callback_in_flight || peers_closed) {
      return;
    }
    connection->read_signaling([connection](Result<LanSignalingMessage> message) {
      auto owner = connection->owner.lock();
      if (!owner) {
        return;
      }
      if (!message) {
        const auto error = *message.error_if();
        if (error.code() == ErrorCode::cancelled) {
          owner->retire_connection(connection, LanSignalingConnectionState::closed);
        } else {
          owner->signaling_failed(connection->id, error);
        }
        return;
      }
      connection->inbound_callback_in_flight = true;
      owner->dispatch_signaling_callback(connection, std::move(*message.value_if()), false);
    });
  }

  void dispatch_signaling_callback(const std::shared_ptr<TlsConnection>& connection,
                                   LanSignalingMessage message, bool outbound) {
    if (coordinator && !signaling_validator && !signaling_handler) {
      if (outbound) {
        write_outbound_message(connection, message);
        return;
      }
      SignalingEnvelope envelope{.peer = message.peer,
                                 .kind = message.kind,
                                 .request_id = message.request_id,
                                 .payload = std::move(message.payload)};
      auto handled = coordinator->handle_message(envelope, SignalingRouteKind::lan);
      connection->inbound_callback_in_flight = false;
      if (!handled) {
        signaling_failed(connection->id, *handled.error_if());
        return;
      }
      start_signaling_read(connection);
      return;
    }
    const auto connection_id = connection->id;
    ++signaling_callbacks_in_flight;
    publish_resource_snapshot();
    auto weak = weak_from_this();
    auto validator = signaling_validator;
    auto handler = signaling_handler;
    auto dispatched = detail::RuntimeAccess::dispatch_general(
        *runtime, outbound ? "heyaki-lan-signaling-validate"
                           : "heyaki-lan-signaling-deliver",
        [weak, connection_id, outbound, message = std::move(message),
         validator = std::move(validator), handler = std::move(handler)]() mutable {
          auto self = weak.lock();
          if (!self) {
            return;
          }
          SignalingCallbackResult result;
          result.connection_id = connection_id;
          result.outbound = outbound;
          result.message = std::move(message);
          try {
            if (is_signed_signaling_kind(result.message.kind)) {
              if (!validator) {
                result.error = tls_error(ErrorCode::authentication,
                                         "signaling_validator_missing");
              } else {
                auto validated = validator(result.message);
                if (!validated) {
                  result.error = *validated.error_if();
                }
              }
            }
            if (!result.error && !outbound) {
              if (!handler) {
                result.error = tls_error(ErrorCode::signaling,
                                         "signaling_handler_missing");
              } else {
                auto handled = handler(result.message);
                if (!handled) {
                  result.error = *handled.error_if();
                }
              }
            }
          } catch (...) {
            result.error = tls_error(ErrorCode::internal,
                                     "signaling_callback_exception");
          }
          const bool admitted = self->signaling_results.try_send(std::move(result));
          boost::asio::post(self->strand, [weak, connection_id, admitted] {
            if (auto current = weak.lock()) {
              current->signaling_callback_completed();
              if (!admitted) {
                if (!current->peers_closed) {
                  current->signaling_failed(
                      connection_id,
                      tls_error(ErrorCode::resource_exhausted,
                                "signaling_result_capacity_full"));
                }
                return;
              }
              current->drain_signaling_results();
            }
          });
        });
    if (!dispatched) {
      signaling_callback_completed();
      signaling_failed(connection_id, *dispatched.error_if());
    }
  }

  void signaling_callback_completed() {
    if (signaling_callbacks_in_flight > 0U) {
      --signaling_callbacks_in_flight;
    }
    publish_resource_snapshot();
    maybe_stopped();
  }

  void drain_signaling_results() {
    SignalingCallbackResult result;
    std::size_t drained = 0U;
    while (drained < lan.pending_signaling_capacity &&
           signaling_results.try_receive(result)) {
      ++drained;
      auto iterator = connections.find(result.connection_id);
      if (iterator == connections.end()) {
        continue;
      }
      auto connection = iterator->second;
      if (result.error) {
        signaling_failed(result.connection_id, *result.error);
        continue;
      }
      if (result.outbound) {
        write_outbound_message(connection, result.message);
      } else {
        connection->inbound_callback_in_flight = false;
        start_signaling_read(connection);
      }
    }
  }

  Result<void> queue_outbound_message(LanSignalingMessage message) {
    const auto active = active_connections.find(message.peer);
    if (active == active_connections.end()) {
      const auto error =
          tls_error(ErrorCode::would_block, "lan_signaling_not_authenticated");
      record_signaling_error(error);
      return Result<void>::failure(error);
    }
    auto iterator = connections.find(active->second);
    if (iterator == connections.end()) {
      active_connections.erase(active);
      const auto error =
          tls_error(ErrorCode::would_block, "lan_signaling_not_authenticated");
      record_signaling_error(error);
      return Result<void>::failure(error);
    }
    std::size_t pending = 0U;
    for (const auto& [id, connection] : connections) {
      (void)id;
      pending += connection->outbound_messages.size();
    }
    if (pending >= lan.pending_signaling_capacity) {
      const auto error = tls_error(ErrorCode::resource_exhausted,
                                   "pending_signaling_capacity_full");
      record_signaling_error(error);
      return Result<void>::failure(error);
    }
    iterator->second->outbound_messages.push_back(std::move(message));
    process_next_outbound(iterator->second);
    return Result<void>::success();
  }

  void process_next_outbound(const std::shared_ptr<TlsConnection>& connection) {
    if (!connections.contains(connection->id) || connection->outbound_busy ||
        connection->outbound_messages.empty()) {
      return;
    }
    connection->outbound_busy = true;
    const auto message = connection->outbound_messages.front();
    if (is_signed_signaling_kind(message.kind) && signaling_validator) {
      dispatch_signaling_callback(connection, message, true);
    } else {
      write_outbound_message(connection, message);
    }
  }

  void write_outbound_message(const std::shared_ptr<TlsConnection>& connection,
                              const LanSignalingMessage& message) {
    if (!connections.contains(connection->id)) {
      return;
    }
    connection->write_signaling(message, [connection](Result<void> written) {
      auto owner = connection->owner.lock();
      if (!owner || !owner->connections.contains(connection->id)) {
        return;
      }
      if (!written) {
        owner->signaling_failed(connection->id, *written.error_if());
        return;
      }
      if (!connection->outbound_messages.empty()) {
        connection->outbound_messages.pop_front();
      }
      connection->outbound_busy = false;
      owner->process_next_outbound(connection);
    });
  }

  void close_peer(DeviceEndpointKey peer) {
    std::vector<std::uint64_t> matching;
    for (const auto& [id, connection] : connections) {
      if (connection->expected_peer == peer ||
          (connection->peer && *connection->peer == peer)) {
        matching.push_back(id);
      }
    }
    for (const auto id : matching) {
      auto iterator = connections.find(id);
      if (iterator != connections.end()) {
        retire_connection(iterator->second, LanSignalingConnectionState::closed);
      }
    }
  }

  void drain_signaling_commands() {
    SignalingCommand command;
    std::size_t drained = 0U;
    while (drained < lan.pending_signaling_capacity &&
           signaling_commands.try_receive(command)) {
      ++drained;
      std::visit(
          [this](auto&& value) {
            using Command = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<Command, ConnectCommand>) {
              start_outbound_connection(value.peer, false, value.route);
            } else if constexpr (std::is_same_v<Command, SendCommand>) {
              (void)queue_outbound_message(std::move(value.message));
            } else {
              close_peer(value.peer);
            }
          },
          std::move(command));
    }
    if (!signaling_commands.empty()) {
      auto weak = weak_from_this();
      boost::asio::post(strand, [weak] {
        if (auto self = weak.lock()) {
          self->drain_signaling_commands();
        }
      });
    }
    publish_resource_snapshot();
  }

  void signaling_failed(std::uint64_t id, const Error& error) {
    auto iterator = connections.find(id);
    if (iterator == connections.end()) {
      return;
    }
    const auto peer = iterator->second->peer.value_or(iterator->second->expected_peer);
    const auto active_attempt = peer_attempt_by_endpoint.find(peer);
    if (active_attempt != peer_attempt_by_endpoint.end()) {
      const auto attempt = peer_attempts.find(active_attempt->second);
      if (attempt != peer_attempts.end() && !attempt->second.session) {
        fail_peer_attempt(active_attempt->second, error);
      }
    }
    record_signaling_error(error);
    retire_connection(iterator->second, LanSignalingConnectionState::failed, error);
  }

  void connection_failed(std::uint64_t id, const char* detail,
                         const boost::system::error_code& error, bool timeout,
                         bool hello_rejected = false) {
    auto iterator = connections.find(id);
    if (iterator == connections.end()) {
      return;
    }
    auto connection = iterator->second;
    const auto failure = tls_error(timeout ? ErrorCode::timeout : ErrorCode::signaling,
                                   detail, error);
    update_snapshot([&](NodeSnapshot& snapshot) {
      if (timeout) {
        ++snapshot.tls.timed_out;
      } else if (hello_rejected) {
        ++snapshot.tls.hello_rejected;
      } else {
        ++snapshot.tls.handshake_failed;
      }
      snapshot.last_error = failure;
    });
    retire_connection(connection, LanSignalingConnectionState::failed, failure);
  }

  void refresh_tls_counts(LanTlsSnapshot& tls) const {
    tls.authenticated_connections = static_cast<std::size_t>(std::count_if(
        connections.begin(), connections.end(),
        [](const auto& item) { return item.second->authenticated; }));
    tls.provisional_connections = connections.size() - tls.authenticated_connections;
  }

  template <typename Writer>
  void update_tls_counts(Writer&& writer) {
    update_snapshot([&](NodeSnapshot& snapshot) {
      std::forward<Writer>(writer)(snapshot.tls);
      refresh_tls_counts(snapshot.tls);
    });
    peak_signaling_connections =
        std::max(peak_signaling_connections, connections.size());
    publish_resource_snapshot();
  }

  void publish_directory() {
    endpoint_snapshots.publish(directory.snapshot());
    update_snapshot([&](NodeSnapshot& snapshot) {
      snapshot.directory = directory.diagnostics();
    });
  }

  void publish_resource_snapshot() {
    const auto scan_stats = scan_results.stats();
    const auto command_stats = signaling_commands.stats();
    const auto result_stats = signaling_results.stats();
    std::size_t pending_outbound = 0U;
    for (const auto& [id, connection] : connections) {
      (void)id;
      pending_outbound += connection->outbound_messages.size();
    }
    const std::size_t active_timers =
        static_cast<std::size_t>(announce_timer_active) +
        static_cast<std::size_t>(expiry_timer_active) +
        static_cast<std::size_t>(interface_timer_active) +
        static_cast<std::size_t>(readiness_timer_active);
    peak_active_timers = std::max(peak_active_timers, active_timers);
    peak_signaling_connections =
        std::max(peak_signaling_connections, connections.size());
    update_snapshot([&](NodeSnapshot& snapshot) {
      snapshot.resources = LanResourceSnapshot{
          .discovery_sockets = discovery_sockets.size(),
          .peak_discovery_sockets = peak_discovery_sockets,
          .tls_listener_open = acceptor && acceptor->is_open(),
          .active_timers = active_timers,
          .peak_active_timers = peak_active_timers,
          .signaling_connections = connections.size(),
          .peak_signaling_connections = peak_signaling_connections,
          .signaling_callbacks_in_flight = signaling_callbacks_in_flight,
          .interface_scan_in_flight = interface_scan_in_flight,
          .interface_scan_result_depth = scan_stats.current_depth,
          .interface_scan_result_peak_depth = scan_stats.peak_depth,
          .signaling_command_depth = command_stats.current_depth,
          .signaling_command_peak_depth = command_stats.peak_depth,
          .signaling_result_depth = result_stats.current_depth,
          .signaling_result_peak_depth = result_stats.peak_depth,
          .pending_outbound_messages = pending_outbound};
    });
  }

  template <typename Writer>
  void update_snapshot(Writer&& writer) {
    auto current = snapshots.load().value;
    std::forward<Writer>(writer)(current);
    snapshots.publish(std::move(current));
  }

  Result<void> register_shutdown_hooks() {
    auto weak = weak_from_this();
    auto producers = runtime->register_shutdown_hook(RuntimeShutdownHook{
        .stage = RuntimeShutdownStage::stop_producers,
        .name = "lan-stop-producers",
        .begin = [weak]() -> Result<RuntimeShutdownCompletion> {
          auto self = weak.lock();
          if (!self) {
            return Result<RuntimeShutdownCompletion>::success(
                ready_shutdown_completion(Result<void>::success()));
          }
          return self->begin_shutdown_stage(true);
        }});
    if (!producers) {
      return producers;
    }
    auto peers = runtime->register_shutdown_hook(RuntimeShutdownHook{
        .stage = RuntimeShutdownStage::close_peers,
        .name = "lan-close-signaling",
        .begin = [weak]() -> Result<RuntimeShutdownCompletion> {
          auto self = weak.lock();
          if (!self) {
            return Result<RuntimeShutdownCompletion>::success(
                ready_shutdown_completion(Result<void>::success()));
          }
          return self->begin_shutdown_stage(false);
        }});
    return peers;
  }

  Result<RuntimeShutdownCompletion> begin_shutdown_stage(bool stop_producers_stage) {
    auto promise = std::make_shared<std::promise<Result<void>>>();
    auto future = promise->get_future().share();
    auto weak = weak_from_this();
    try {
      boost::asio::post(strand, [weak, promise, stop_producers_stage] {
        if (auto self = weak.lock()) {
          if (stop_producers_stage) {
            self->stop_producers();
            promise->set_value(Result<void>::success());
          } else {
            self->close_peers();
            if (self->stopped.current_phase() >= 1U) {
              promise->set_value(Result<void>::success());
            } else {
              self->shutdown_completions.push_back(promise);
            }
          }
        } else {
          promise->set_value(Result<void>::success());
        }
      });
    } catch (...) {
      return Result<RuntimeShutdownCompletion>::failure(
          node_error(ErrorCode::internal, "shutdown_schedule_failed"));
    }
    return Result<RuntimeShutdownCompletion>::success(std::move(future));
  }

  void stop_producers() {
    if (producers_stopped) {
      return;
    }
    producers_stopped = true;
    scan_results.close();
    signaling_commands.close();
    InterfaceScanResult discarded_scan;
    while (scan_results.try_receive(discarded_scan)) {
    }
    SignalingCommand discarded_command;
    while (signaling_commands.try_receive(discarded_command)) {
    }
    stop_relay();
    boost::system::error_code ignored;
    try {
      (void)announce_timer.cancel();
      (void)expiry_timer.cancel();
      (void)interface_timer.cancel();
      (void)readiness_timer.cancel();
    } catch (...) {
    }
    announce_timer_active = false;
    expiry_timer_active = false;
    interface_timer_active = false;
    readiness_timer_active = false;
    close_discovery_sockets();
    if (acceptor) {
      acceptor->cancel(ignored);
      acceptor->close(ignored);
    }
    update_snapshot([](NodeSnapshot& snapshot) {
      snapshot.tls.listener_ready = false;
      snapshot.lan_state = LanReadinessState::stopped;
    });
    publish_resource_snapshot();
    maybe_stopped();
  }

  void close_peers() {
    if (peers_closed) {
      return;
    }
    peers_closed = true;
    for (auto& [request_id, attempt] : peer_attempts) {
      (void)request_id;
      if (attempt.session) {
        attempt.session->close(transport::CloseReason::local_shutdown);
      } else if (attempt.transport) {
        attempt.transport->close(transport::CloseReason::local_shutdown);
      }
      attempt.snapshot.state = NodePeerSessionState::closed;
    }
    publish_peer_sessions();
    signaling_results.close();
    SignalingCallbackResult discarded_result;
    while (signaling_results.try_receive(discarded_result)) {
    }
    std::vector<std::uint64_t> connection_ids;
    connection_ids.reserve(connections.size());
    for (const auto& [id, connection] : connections) {
      (void)connection;
      connection_ids.push_back(id);
    }
    for (const auto id : connection_ids) {
      auto iterator = connections.find(id);
      if (iterator != connections.end()) {
        retire_connection(iterator->second, LanSignalingConnectionState::closed);
      }
    }
    active_connections.clear();
    publish_resource_snapshot();
    maybe_stopped();
  }

  void maybe_stopped() {
    if (producers_stopped && peers_closed && !interface_scan_in_flight &&
        signaling_callbacks_in_flight == 0U) {
      (void)stopped.advance_to(1U);
      for (const auto& completion : shutdown_completions) {
        completion->set_value(Result<void>::success());
      }
      shutdown_completions.clear();
    }
  }

  Result<void> request_stop() {
    if (stopped.current_phase() >= 1U) {
      return Result<void>::success();
    }
    auto weak = weak_from_this();
    try {
      boost::asio::post(strand, [weak] {
        if (auto self = weak.lock()) {
          self->stop_producers();
          self->close_peers();
        }
      });
    } catch (...) {
      return Result<void>::failure(node_error(ErrorCode::internal,
                                              "shutdown_schedule_failed"));
    }
    return Result<void>::success();
  }

  Result<void> submit_signaling_command(SignalingCommand command) {
    if (!signaling_commands.try_send(std::move(command))) {
      return Result<void>::failure(
          tls_error(signaling_commands.is_closed() ? ErrorCode::cancelled
                                                   : ErrorCode::resource_exhausted,
                    signaling_commands.is_closed() ? "signaling_admission_closed"
                                                   : "signaling_command_capacity_full"));
    }
    auto weak = weak_from_this();
    try {
      boost::asio::post(strand, [weak] {
        if (auto self = weak.lock()) {
          self->drain_signaling_commands();
        }
      });
    } catch (...) {
      return Result<void>::failure(
          tls_error(ErrorCode::internal, "signaling_schedule_failed"));
    }
    return Result<void>::success();
  }

  ProfileStore& profile;
  std::optional<Runtime> owned_runtime;
  Runtime* runtime;
  std::string application_id;
  LanConfiguration lan;
  PeerPathPolicy path_policy;
  IdentityKeyPair identity;
  EndpointId endpoint_id;
  LanBootNonce boot_nonce{};
  EndpointDirectory directory;
  boost::asio::strand<boost::asio::any_io_executor> strand;
  std::unique_ptr<boost::asio::ssl::context> tls_context;
  std::unique_ptr<tcp::acceptor> acceptor;
  TlsCertificateFingerprint certificate_fingerprint{};
  std::vector<InterfaceBinding> current_bindings;
  std::vector<std::shared_ptr<DiscoverySocket>> discovery_sockets;
  boost::asio::steady_timer announce_timer;
  boost::asio::steady_timer expiry_timer;
  boost::asio::steady_timer interface_timer;
  boost::asio::steady_timer readiness_timer;
  boost::asio::steady_timer relay_poll_timer;
  boost::asio::steady_timer relay_heartbeat_timer;
  boost::asio::steady_timer relay_reconnect_timer;
  RelayNodeConfig relay;
  std::optional<RelayWssClient> relay_client;
  std::optional<EnrollmentChallenge> relay_challenge;
  RelayLoginPhase relay_phase{RelayLoginPhase::disabled};
  SteadyTime relay_lease_deadline{};
  std::uint64_t relay_lease_generation{};
  std::uint64_t relay_record_generation{};
  std::uint64_t relay_heartbeats_sent{};
  std::uint64_t relay_heartbeats_missed{};
  bool relay_heartbeat_pending{false};
  std::uint64_t relay_reconnect_count{};
  std::size_t relay_reconnect_attempt{};
  std::chrono::milliseconds relay_backoff{1000};
  bool relay_poll_timer_active{false};
  bool relay_heartbeat_timer_active{false};
  executor::comm::MpscChannel<InterfaceScanResult> scan_results;
  executor::comm::DoubleBuffer<NodeSnapshot> snapshots;
  executor::comm::DoubleBuffer<std::vector<EndpointDirectoryEntrySnapshot>> endpoint_snapshots;
  executor::comm::MpscChannel<SignalingCommand> signaling_commands;
  executor::comm::MpscChannel<SignalingCallbackResult> signaling_results;
  executor::comm::DoubleBuffer<std::vector<LanSignalingConnectionSnapshot>> signaling_snapshots;
  executor::comm::DoubleBuffer<std::vector<NodePeerSessionSnapshot>> peer_session_snapshots;
  executor::comm::PhaseGate stopped;
  std::set<DeviceId> trusted_devices;
  LanSignalingValidator signaling_validator;
  LanSignalingHandler signaling_handler;
  std::shared_ptr<SignalingDelegate> coordinator_delegate;
  std::optional<SignalingCoordinator> coordinator;
  std::unique_ptr<LanCoordinatorRoute> lan_coordinator_route;
  std::unique_ptr<RelaySignalingRoute> relay_coordinator_route;
  std::map<RequestId, PeerAttempt> peer_attempts;
  std::map<DeviceEndpointKey, RequestId> peer_attempt_by_endpoint;
  std::deque<NodePeerSessionSnapshot> finished_peer_sessions;
  std::optional<RelayNodeConfig> relay_override;
  std::map<std::uint64_t, std::shared_ptr<TlsConnection>> connections;
  std::map<DeviceEndpointKey, std::uint64_t> active_connections;
  std::map<DeviceEndpointKey, std::uint64_t> auto_connect_connections;
  std::deque<LanSignalingConnectionSnapshot> finished_signaling;
  std::map<std::string, AcceptRate> accept_rates;
  std::vector<std::shared_ptr<std::promise<Result<void>>>> shutdown_completions;
  SteadyTime global_accept_window{std::chrono::steady_clock::now()};
  std::size_t global_accept_count{};
  std::uint64_t next_connection_id{};
  std::uint64_t announcement_sequence{};
  std::size_t peak_discovery_sockets{};
  std::size_t peak_active_timers{};
  std::size_t peak_signaling_connections{};
  std::size_t signaling_callbacks_in_flight{};
  bool announce_timer_active{false};
  bool expiry_timer_active{false};
  bool interface_timer_active{false};
  bool readiness_timer_active{false};
  bool multicast_probe_timed_out{false};
  bool interface_scan_in_flight{false};
  bool producers_stopped{false};
  bool peers_closed{false};
};

Node::Node(std::shared_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
Node::Node(Node&&) noexcept = default;
Node& Node::operator=(Node&& other) noexcept {
  if (this != &other) {
    (void)shutdown();
    impl_ = std::move(other.impl_);
  }
  return *this;
}
Node::~Node() { (void)shutdown(); }

Result<Node> Node::create(NodeConfig config) {
  if (config.profile == nullptr || config.application_id.empty()) {
    return Result<Node>::failure(node_error(ErrorCode::configuration,
                                            "invalid_node_configuration"));
  }
  auto readiness = config.profile->local_readiness(config.application_id);
  if (!readiness) {
    return Result<Node>::failure(*readiness.error_if());
  }
  if (!readiness.value_if()->ready()) {
    return Result<Node>::failure(node_error(ErrorCode::not_registered,
                                            "local_profile_not_initialized"));
  }
  auto lan = config.lan_override ? Result<LanConfiguration>::success(*config.lan_override)
                                 : config.profile->lan_configuration();
  if (!lan) {
    return Result<Node>::failure(*lan.error_if());
  }
  auto valid_lan = validate_lan_configuration(*lan.value_if());
  if (!valid_lan) {
    return Result<Node>::failure(*valid_lan.error_if());
  }
  auto path_policy =
      config.path_policy_override
          ? Result<PeerPathPolicy>::success(*config.path_policy_override)
          : default_peer_path_policy(lan.value_if()->connectivity_mode);
  if (!path_policy) {
    return Result<Node>::failure(*path_policy.error_if());
  }
  auto valid_path_policy = validate_peer_path_policy(
      *path_policy.value_if(), lan.value_if()->connectivity_mode);
  if (!valid_path_policy) {
    return Result<Node>::failure(*valid_path_policy.error_if());
  }
  auto identity = config.profile->load_identity();
  if (!identity) {
    return Result<Node>::failure(*identity.error_if());
  }
  auto endpoint = config.profile->endpoint_for(config.application_id);
  if (!endpoint) {
    return Result<Node>::failure(*endpoint.error_if());
  }
  auto directory = EndpointDirectory::create(*lan.value_if());
  if (!directory) {
    return Result<Node>::failure(*directory.error_if());
  }
  std::optional<Runtime> owned_runtime;
  Runtime* runtime = config.runtime;
  if (runtime == nullptr) {
    auto created = Runtime::create_owned(config.runtime_config);
    if (!created) {
      return Result<Node>::failure(*created.error_if());
    }
    owned_runtime.emplace(std::move(*created.value_if()));
    runtime = &*owned_runtime;
  }
  auto executor = detail::RuntimeAccess::io_executor(*runtime);
  if (!executor) {
    if (owned_runtime) {
      (void)owned_runtime->shutdown();
    }
    return Result<Node>::failure(*executor.error_if());
  }
  auto trusted = config.profile->trusted_devices(unix_milliseconds_now());
  if (!trusted) {
    if (owned_runtime) {
      (void)owned_runtime->shutdown();
    }
    return Result<Node>::failure(*trusted.error_if());
  }
  std::set<DeviceId> trusted_set(trusted.value_if()->begin(), trusted.value_if()->end());
  auto impl = std::make_shared<Impl>(
      *config.profile, std::move(owned_runtime), config.runtime, std::move(config.application_id),
      std::move(*lan.value_if()), std::move(*identity.value_if()), *endpoint.value_if(),
      std::move(*directory.value_if()), std::move(*executor.value_if()),
      std::move(trusted_set), std::move(config.signaling_validator),
      std::move(config.signaling_handler), std::move(config.relay_override));
  impl->path_policy = std::move(*path_policy.value_if());
  auto initialized = impl->initialize();
  if (!initialized) {
    if (impl->owned_runtime) {
      (void)impl->owned_runtime->shutdown();
    }
    return Result<Node>::failure(*initialized.error_if());
  }
  auto weak = std::weak_ptr<Node::Impl>{impl};
  try {
    boost::asio::post(impl->strand, [weak] {
      if (auto self = weak.lock()) {
        self->begin();
      }
    });
  } catch (...) {
    if (impl->owned_runtime) {
      (void)impl->owned_runtime->shutdown();
    }
    return Result<Node>::failure(node_error(ErrorCode::internal,
                                            "node_begin_post_failed"));
  }
  return Result<Node>::success(Node{std::move(impl)});
}

NodeSnapshot Node::snapshot() const {
  return impl_ ? impl_->snapshots.load().value : NodeSnapshot{};
}

std::vector<EndpointDirectoryEntrySnapshot> Node::endpoints() const {
  return impl_ ? impl_->endpoint_snapshots.load().value
               : std::vector<EndpointDirectoryEntrySnapshot>{};
}

std::vector<LanSignalingConnectionSnapshot> Node::signaling_connections() const {
  return impl_ ? impl_->signaling_snapshots.load().value
               : std::vector<LanSignalingConnectionSnapshot>{};
}

std::vector<NodePeerSessionSnapshot> Node::peer_sessions() const {
  return impl_ ? impl_->peer_session_snapshots.load().value
               : std::vector<NodePeerSessionSnapshot>{};
}

Result<void> Node::refresh_interfaces() {
  if (!impl_) {
    return Result<void>::failure(node_error(ErrorCode::cancelled, "node_not_running"));
  }
  auto weak = std::weak_ptr<Impl>{impl_};
  try {
    boost::asio::post(impl_->strand, [weak] {
      if (auto self = weak.lock()) {
        (void)self->request_interface_scan();
      }
    });
  } catch (...) {
    return Result<void>::failure(node_error(ErrorCode::internal,
                                            "interface_refresh_schedule_failed"));
  }
  return Result<void>::success();
}

Result<void> Node::connect_lan(DeviceEndpointKey peer) {
  if (!impl_) {
    return Result<void>::failure(node_error(ErrorCode::cancelled, "node_not_running"));
  }
  const auto state = impl_->snapshots.load().value;
  if (!state.lan_enabled || state.connectivity_mode == ConnectivityMode::relay_only) {
    return Result<void>::failure(
        tls_error(ErrorCode::configuration, "lan_route_disabled"));
  }
  if (peer.device_id.is_zero() || peer.endpoint_id.is_zero() ||
      peer == impl_->local_key()) {
    return Result<void>::failure(
        tls_error(ErrorCode::configuration, "signaling_peer_invalid"));
  }
  const auto entries = impl_->endpoint_snapshots.load().value;
  const bool available = std::any_of(entries.begin(), entries.end(), [&](const auto& entry) {
    return entry.key == peer && entry.lan.has_value();
  });
  if (!available) {
    return Result<void>::failure(
        tls_error(ErrorCode::endpoint_offline, "lan_endpoint_unavailable"));
  }
  return impl_->submit_signaling_command(
      Impl::ConnectCommand{peer, SignalingRouteKind::lan});
}

Result<void> Node::connect(DeviceEndpointKey peer) {
  if (!impl_) {
    return Result<void>::failure(node_error(ErrorCode::cancelled, "node_not_running"));
  }
  if (peer.device_id.is_zero() || peer.endpoint_id.is_zero() ||
      peer == impl_->local_key()) {
    return Result<void>::failure(
        node_error(ErrorCode::configuration, "signaling_peer_invalid"));
  }
  const auto entries = impl_->endpoint_snapshots.load().value;
  const auto endpoint = std::find_if(entries.begin(), entries.end(),
                                     [&](const auto& entry) {
                                       return entry.key == peer;
                                     });
  const bool lan_available = endpoint != entries.end() && endpoint->lan.has_value();
  const auto state = impl_->snapshots.load().value;
  const bool relay_available = endpoint != entries.end() && endpoint->relay.has_value() &&
                               state.relay.state == RelayNodeState::ready;
  auto route = select_signaling_route(state.connectivity_mode, lan_available,
                                      relay_available);
  if (!route) return Result<void>::failure(*route.error_if());
  return impl_->submit_signaling_command(
      Impl::ConnectCommand{peer, *route.value_if()});
}

Result<void> Node::send_lan_signaling(LanSignalingMessage message) {
  if (!impl_) {
    return Result<void>::failure(node_error(ErrorCode::cancelled, "node_not_running"));
  }
  auto valid = validate_signaling_message_shape(message);
  if (!valid) {
    return valid;
  }
  if (is_signed_signaling_kind(message.kind) && !impl_->signaling_validator) {
    return Result<void>::failure(
        tls_error(ErrorCode::authentication, "signaling_validator_missing"));
  }
  const auto connections = impl_->signaling_snapshots.load().value;
  const bool authenticated =
      std::any_of(connections.begin(), connections.end(), [&](const auto& connection) {
        return connection.peer == message.peer &&
               connection.state == LanSignalingConnectionState::authenticated;
      });
  if (!authenticated) {
    return Result<void>::failure(
        tls_error(ErrorCode::would_block, "lan_signaling_not_authenticated"));
  }
  return impl_->submit_signaling_command(Impl::SendCommand{std::move(message)});
}

Result<void> Node::close_lan(DeviceEndpointKey peer) {
  if (!impl_) {
    return Result<void>::failure(node_error(ErrorCode::cancelled, "node_not_running"));
  }
  if (peer.device_id.is_zero() || peer.endpoint_id.is_zero()) {
    return Result<void>::failure(
        tls_error(ErrorCode::configuration, "signaling_peer_invalid"));
  }
  return impl_->submit_signaling_command(Impl::CloseCommand{peer});
}

NodeShutdownReport Node::shutdown() {
  NodeShutdownReport report;
  if (!impl_) {
    report.stopped = true;
    return report;
  }
  const auto timeout = impl_->lan.shutdown_timeout;
  if (impl_->owned_runtime) {
    (void)impl_->owned_runtime->shutdown();
  } else {
    (void)impl_->request_stop();
  }
  report.stopped = static_cast<bool>(impl_->stopped.wait_for(1U, timeout));
  report.timed_out = !report.stopped;
  report.final_resources = impl_->snapshots.load().value.resources;
  impl_.reset();
  return report;
}

std::string_view lan_readiness_state_name(LanReadinessState state) noexcept {
  switch (state) {
    case LanReadinessState::disabled:
      return "disabled";
    case LanReadinessState::starting:
      return "starting";
    case LanReadinessState::ready:
      return "ready";
    case LanReadinessState::degraded:
      return "degraded";
    case LanReadinessState::failed:
      return "failed";
    case LanReadinessState::stopped:
      return "stopped";
  }
  return "failed";
}

std::string_view relay_node_state_name(RelayNodeState state) noexcept {
  switch (state) {
    case RelayNodeState::disabled:
      return "disabled";
    case RelayNodeState::starting:
      return "starting";
    case RelayNodeState::ready:
      return "ready";
    case RelayNodeState::degraded:
      return "degraded";
    case RelayNodeState::failed:
      return "failed";
    case RelayNodeState::stopped:
      return "stopped";
  }
  return "unknown";
}

std::string_view node_peer_session_state_name(NodePeerSessionState state) noexcept {
  switch (state) {
    case NodePeerSessionState::signaling:
      return "signaling";
    case NodePeerSessionState::transport_connecting:
      return "transport_connecting";
    case NodePeerSessionState::authenticating:
      return "authenticating";
    case NodePeerSessionState::authenticated:
      return "authenticated";
    case NodePeerSessionState::closed:
      return "closed";
  }
  return "closed";
}

std::string_view signaling_route_kind_name(SignalingRouteKind kind) noexcept {
  switch (kind) {
    case SignalingRouteKind::lan:
      return "lan";
    case SignalingRouteKind::relay:
      return "relay";
  }
  return "unknown";
}

std::string_view node_connection_stage_name(NodeConnectionStage stage) noexcept {
  switch (stage) {
    case NodeConnectionStage::idle:
      return "idle";
    case NodeConnectionStage::resolving_endpoint:
      return "resolving_endpoint";
    case NodeConnectionStage::signaling:
      return "signaling";
    case NodeConnectionStage::gathering:
      return "gathering";
    case NodeConnectionStage::checking:
      return "checking";
    case NodeConnectionStage::transport_connected:
      return "transport_connected";
    case NodeConnectionStage::authenticating:
      return "authenticating";
    case NodeConnectionStage::authenticated:
      return "authenticated";
    case NodeConnectionStage::closed:
      return "closed";
  }
  return "closed";
}

std::string_view node_data_path_kind_name(NodeDataPathKind kind) noexcept {
  switch (kind) {
    case NodeDataPathKind::unknown:
      return "unknown";
    case NodeDataPathKind::direct_host:
      return "direct_host";
    case NodeDataPathKind::direct_srflx:
      return "direct_srflx";
    case NodeDataPathKind::turn_udp:
      return "turn_udp";
    case NodeDataPathKind::turn_tcp:
      return "turn_tcp";
    case NodeDataPathKind::turn_tls:
      return "turn_tls";
  }
  return "unknown";
}

bool is_lan_offer_owner(DeviceEndpointKey local, DeviceEndpointKey peer) noexcept {
  return local != peer && local < peer;
}

namespace {

constexpr std::size_t maximum_ice_servers{8U};
constexpr std::size_t maximum_ice_server_hostname_bytes{255U};
constexpr std::size_t maximum_ice_server_credential_bytes{256U};

bool turn_server_kind(NodeIceServerKind kind) noexcept {
  return kind == NodeIceServerKind::turn_udp || kind == NodeIceServerKind::turn_tcp ||
         kind == NodeIceServerKind::turn_tls;
}

Error path_policy_error(const char* detail) {
  return Error{ErrorCode::configuration, "peer_path_policy", detail};
}

}  // namespace

Result<PeerPathPolicy> default_peer_path_policy(ConnectivityMode mode) noexcept {
  PeerPathPolicy policy;
  switch (mode) {
    case ConnectivityMode::automatic:
    case ConnectivityMode::relay_only:
      return Result<PeerPathPolicy>::success(std::move(policy));
    case ConnectivityMode::lan_only:
      policy.allow_server_reflexive = false;
      policy.allow_turn_udp = false;
      return Result<PeerPathPolicy>::success(std::move(policy));
  }
  return Result<PeerPathPolicy>::failure(
      path_policy_error("connectivity_mode_invalid"));
}

Result<void> validate_peer_path_policy(const PeerPathPolicy& policy,
                                       ConnectivityMode mode) {
  if (mode != ConnectivityMode::automatic && mode != ConnectivityMode::relay_only &&
      mode != ConnectivityMode::lan_only) {
    return Result<void>::failure(path_policy_error("connectivity_mode_invalid"));
  }
  if (!policy.allow_ipv6_host && !policy.allow_ipv4_host &&
      !policy.allow_server_reflexive && !policy.allow_turn_udp &&
      !policy.allow_turn_tcp && !policy.allow_turn_tls) {
    return Result<void>::failure(path_policy_error("no_candidate_class_allowed"));
  }
  if (mode == ConnectivityMode::lan_only) {
    if (!policy.ice_servers.empty()) {
      return Result<void>::failure(
          path_policy_error("lan_only_disallows_ice_servers"));
    }
    if (policy.allow_server_reflexive) {
      return Result<void>::failure(
          path_policy_error("lan_only_disallows_reflexive_candidates"));
    }
    if (policy.allow_turn_udp || policy.allow_turn_tcp || policy.allow_turn_tls ||
        policy.force_turn_data_path) {
      return Result<void>::failure(path_policy_error("lan_only_disallows_turn"));
    }
  }
  if (policy.allow_turn_tcp || policy.allow_turn_tls) {
    return Result<void>::failure(path_policy_error("tcp_turn_backend_not_verified"));
  }
  const bool any_turn_class =
      policy.allow_turn_udp || policy.allow_turn_tcp || policy.allow_turn_tls;
  const bool has_turn_server = std::any_of(
      policy.ice_servers.begin(), policy.ice_servers.end(), [](const auto& server) {
        return turn_server_kind(server.kind);
      });
  if (policy.force_turn_data_path && (!any_turn_class || !has_turn_server)) {
    return Result<void>::failure(
        path_policy_error("forced_turn_requires_turn_class_and_server"));
  }
  if (policy.ice_servers.size() > maximum_ice_servers) {
    return Result<void>::failure(path_policy_error("ice_server_capacity_exceeded"));
  }
  for (const auto& server : policy.ice_servers) {
    if (server.hostname.empty() ||
        server.hostname.size() > maximum_ice_server_hostname_bytes ||
        server.port == 0U ||
        server.username.size() > maximum_ice_server_credential_bytes ||
        server.credential.size() > maximum_ice_server_credential_bytes) {
      return Result<void>::failure(path_policy_error("ice_server_fields_invalid"));
    }
    if (server.kind == NodeIceServerKind::stun) {
      if (!server.username.empty() || !server.credential.empty()) {
        return Result<void>::failure(
            path_policy_error("stun_server_disallows_credentials"));
      }
      continue;
    }
    if (server.kind != NodeIceServerKind::turn_udp &&
        server.kind != NodeIceServerKind::turn_tcp &&
        server.kind != NodeIceServerKind::turn_tls) {
      return Result<void>::failure(path_policy_error("ice_server_kind_invalid"));
    }
    if (server.username.empty() || server.credential.empty()) {
      return Result<void>::failure(path_policy_error("turn_server_requires_credentials"));
    }
  }
  return Result<void>::success();
}

Result<SignalingRouteKind> select_signaling_route(
    ConnectivityMode mode, bool lan_available, bool relay_available) noexcept {
  if (mode == ConnectivityMode::lan_only) {
    if (lan_available) {
      return Result<SignalingRouteKind>::success(SignalingRouteKind::lan);
    }
    return Result<SignalingRouteKind>::failure(
        Error{ErrorCode::endpoint_offline, "signaling_route",
              "lan_endpoint_unavailable"});
  }
  if (mode == ConnectivityMode::relay_only) {
    if (relay_available) {
      return Result<SignalingRouteKind>::success(SignalingRouteKind::relay);
    }
    return Result<SignalingRouteKind>::failure(
        Error{ErrorCode::relay_unavailable, "signaling_route",
              "relay_route_unavailable"});
  }
  if (lan_available) {
    return Result<SignalingRouteKind>::success(SignalingRouteKind::lan);
  }
  if (relay_available) {
    return Result<SignalingRouteKind>::success(SignalingRouteKind::relay);
  }
  return Result<SignalingRouteKind>::failure(
      Error{ErrorCode::peer_offline, "signaling_route",
            "no_signaling_route_available"});
}

}  // namespace heyaki
