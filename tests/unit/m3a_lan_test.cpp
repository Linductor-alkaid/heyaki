#include <heyaki/identity.hpp>
#include <heyaki/lan_directory.hpp>
#include <heyaki/lan_protocol.hpp>
#include <heyaki/node.hpp>

#include "m5_support.hpp"
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <executor/comm.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/multicast.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/write.hpp>

#include <gtest/gtest.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#if defined(__linux__)
#include <cerrno>
#include <cstring>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace heyaki {
namespace {

class M3aNodeTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M3A_TEST_STATE_DIR} / "node";
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
    std::filesystem::create_directories(root_);
  }

  void TearDown() override {
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
  }

  Result<ProfileStore> initialized_profile(std::string_view name,
                                           std::string_view application_id,
                                           const LanConfiguration& lan) {
    ProfileOpenOptions options;
    options.secret_backend.prefer_os_backend = false;
    auto profile = ProfileStore::create(root_ / std::string{name} / "profile.sqlite", options);
    if (!profile) {
      return profile;
    }
    PasswordVerifier verifier{.format_version = 1U,
                              .parameters = PasswordHashParameters{},
                              .encoded = "$argon2id$v=19$m=65536,t=2,p=1$test$test"};
    LocalProfileInitialization initialization{
        .application_id = std::string{application_id},
        .password_verifier = std::move(verifier),
        .password_generation = 1U,
        .pairing_policy = PairingPolicy{},
        .lan = lan};
    auto initialized = profile.value_if()->initialize_local(initialization);
    if (!initialized) {
      return Result<ProfileStore>::failure(*initialized.error_if());
    }
    return profile;
  }

  template <typename Predicate>
  bool wait_until(Predicate&& predicate, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    executor::comm::PhaseGate poll{"m3a-test-poll"};
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
        return true;
      }
      (void)poll.wait_for(1U, std::chrono::milliseconds{1});
    }
    return predicate();
  }

  std::filesystem::path root_;
};

bool environment_enabled(const char* name) {
  const char* value = std::getenv(name);
  return value != nullptr && std::string_view{value} == "1";
}

std::optional<std::size_t> environment_size(const char* name) {
  const char* value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    return std::nullopt;
  }
  try {
    return static_cast<std::size_t>(std::stoull(value));
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<std::string> environment_string(const char* name) {
  const char* value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    return std::nullopt;
  }
  return std::string{value};
}

bool is_multicast_unavailable_detail(std::string_view detail) {
  return detail == "presence_send_failed" ||
         detail == "multicast_probe_timed_out";
}

std::size_t joined_interface_count(const NodeSnapshot& snapshot) {
  return static_cast<std::size_t>(std::count_if(
      snapshot.interfaces.begin(), snapshot.interfaces.end(),
      [](const LanInterfaceSnapshot& interface) { return interface.joined; }));
}

#if defined(__linux__)
Result<void> set_test_interface_state(std::string_view interface_name,
                                      bool enabled) {
  if (interface_name.empty() || interface_name.size() >= IFNAMSIZ) {
    return Result<void>::failure(
        Error{ErrorCode::configuration, "test", "interface_name_invalid"});
  }
  const int socket_handle = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (socket_handle < 0) {
    return Result<void>::failure(
        Error{ErrorCode::transport, "test", "interface_socket_failed", errno});
  }
  ifreq request{};
  std::memcpy(request.ifr_name, interface_name.data(), interface_name.size());
  if (::ioctl(socket_handle, SIOCGIFFLAGS, &request) != 0) {
    const auto error = errno;
    (void)::close(socket_handle);
    return Result<void>::failure(
        Error{ErrorCode::transport, "test", "interface_flags_read_failed", error});
  }
  if (enabled) {
    request.ifr_flags = static_cast<short>(request.ifr_flags | IFF_UP);
  } else {
    request.ifr_flags = static_cast<short>(request.ifr_flags & ~IFF_UP);
  }
  if (::ioctl(socket_handle, SIOCSIFFLAGS, &request) != 0) {
    const auto error = errno;
    (void)::close(socket_handle);
    return Result<void>::failure(
        Error{ErrorCode::transport, "test", "interface_flags_write_failed", error});
  }
  (void)::close(socket_handle);
  return Result<void>::success();
}
#endif

struct TestTlsCertificate {
  TlsCertificateFingerprint fingerprint{};
};

Result<TestTlsCertificate> configure_test_tls_certificate(
    boost::asio::ssl::context& context) {
  using PkeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
  using Pkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
  using Certificate = std::unique_ptr<X509, decltype(&X509_free)>;

  PkeyContext key_context{EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr),
                          EVP_PKEY_CTX_free};
  EVP_PKEY* generated_key = nullptr;
  if (!key_context || EVP_PKEY_keygen_init(key_context.get()) != 1 ||
      EVP_PKEY_keygen(key_context.get(), &generated_key) != 1) {
    return Result<TestTlsCertificate>::failure(
        Error{ErrorCode::internal, "test", "tls_test_key_generation_failed"});
  }
  Pkey key{generated_key, EVP_PKEY_free};
  Certificate certificate{X509_new(), X509_free};
  if (!certificate || X509_set_version(certificate.get(), 2L) != 1 ||
      ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1L) != 1 ||
      X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60L) == nullptr ||
      X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600L) == nullptr ||
      X509_set_pubkey(certificate.get(), key.get()) != 1) {
    return Result<TestTlsCertificate>::failure(
        Error{ErrorCode::internal, "test", "tls_test_certificate_failed"});
  }
  auto* subject = X509_get_subject_name(certificate.get());
  static constexpr unsigned char common_name[] = "heyaki-m3a-test";
  if (subject == nullptr ||
      X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, common_name, -1,
                                 -1, 0) != 1 ||
      X509_set_issuer_name(certificate.get(), subject) != 1 ||
      X509_sign(certificate.get(), key.get(), nullptr) <= 0) {
    return Result<TestTlsCertificate>::failure(
        Error{ErrorCode::internal, "test", "tls_test_certificate_sign_failed"});
  }

  SSL_CTX* native = context.native_handle();
  if (SSL_CTX_set_min_proto_version(native, TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_max_proto_version(native, TLS1_3_VERSION) != 1 ||
      SSL_CTX_use_certificate(native, certificate.get()) != 1 ||
      SSL_CTX_use_PrivateKey(native, key.get()) != 1 ||
      SSL_CTX_check_private_key(native) != 1) {
    return Result<TestTlsCertificate>::failure(
        Error{ErrorCode::internal, "test", "tls_test_context_failed"});
  }
  context.set_verify_mode(boost::asio::ssl::verify_peer);
  context.set_verify_callback(
      [](bool, boost::asio::ssl::verify_context&) { return true; });

  TestTlsCertificate output;
  unsigned int digest_size = 0U;
  if (X509_digest(certificate.get(), EVP_sha256(),
                  reinterpret_cast<unsigned char*>(output.fingerprint.data()),
                  &digest_size) != 1 ||
      digest_size != output.fingerprint.size()) {
    return Result<TestTlsCertificate>::failure(
        Error{ErrorCode::internal, "test", "tls_test_fingerprint_failed"});
  }
  return Result<TestTlsCertificate>::success(output);
}

Result<void> send_test_hello(boost::asio::ssl::context& context,
                             std::uint16_t port, const LanHello& hello) {
  auto encoded = encode_lan_hello(hello);
  if (!encoded || encoded.value_if()->size() > 0xffffU) {
    return Result<void>::failure(
        Error{ErrorCode::protocol, "test", "tls_test_hello_encode_failed"});
  }
  std::vector<std::byte> framed;
  framed.reserve(encoded.value_if()->size() + 2U);
  const auto size = static_cast<std::uint16_t>(encoded.value_if()->size());
  framed.push_back(static_cast<std::byte>((size >> 8U) & 0xffU));
  framed.push_back(static_cast<std::byte>(size & 0xffU));
  framed.insert(framed.end(), encoded.value_if()->begin(), encoded.value_if()->end());

  try {
    boost::asio::io_context io;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream{io, context};
    stream.lowest_layer().connect(
        {boost::asio::ip::make_address_v6("::1"), port});
    stream.handshake(boost::asio::ssl::stream_base::client);
    boost::asio::write(stream, boost::asio::buffer(framed));
    boost::system::error_code ignored;
    stream.lowest_layer().close(ignored);
  } catch (...) {
    return Result<void>::failure(
        Error{ErrorCode::signaling, "test", "tls_test_hello_send_failed"});
  }
  return Result<void>::success();
}

NodeConfig node_config(ProfileStore& profile, std::string application_id,
                       LanSignalingValidator validator = {},
                       LanSignalingHandler handler = {}, Runtime* runtime = nullptr) {
  return NodeConfig{.profile = &profile,
                    .runtime = runtime,
                    .application_id = std::move(application_id),
                    .lan_override = std::nullopt,
                    .runtime_config = RuntimeConfig{},
                    .signaling_validator = std::move(validator),
                    .signaling_handler = std::move(handler),
                    .relay_override = std::nullopt,
                    .path_policy_override = std::nullopt,
                        .pairing_failure_threshold = 0U,
                        .pairing_backoff_base = std::chrono::milliseconds{0},
                        .pairing_backoff_max = std::chrono::milliseconds{0},
                        .pairing_grant_ttl_milliseconds = 0U,
                        .event_subscriber_queue_items = 0U,
                        .event_max_subscriptions_per_peer = 0U,
                        .file_receive_roots = {},
                        .file_max_peer_receive_bytes = 0U};
}

RequestId request_id(std::uint8_t tag) {
  RequestId::Storage bytes{};
  bytes[0] = static_cast<std::byte>(tag);
  return RequestId{bytes};
}

bool has_authenticated_connection(const Node& node, DeviceEndpointKey peer) {
  const auto connections = node.signaling_connections();
  return std::any_of(connections.begin(), connections.end(), [&](const auto& connection) {
    return connection.peer == peer &&
           connection.state == LanSignalingConnectionState::authenticated;
  });
}

Result<void> trust_peer(ProfileStore& profile, const DeviceId& peer,
                        std::uint8_t tag) {
  GrantId::Storage grant_bytes{};
  grant_bytes[0] = static_cast<std::byte>(tag);
  const auto now = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
  return profile.put_trust_grant(
      TrustGrantRecord{.grant_id = GrantId{grant_bytes},
                       .direction = TrustGrantDirection::issued,
                       .issuer = profile.device_id(),
                       .subject = peer,
                       .scopes = {"pairing.connect"},
                       .password_generation = 1U,
                       .issued_unix_milliseconds = now,
                       .expires_unix_milliseconds = now + 60'000U,
                       .signature = std::vector<std::byte>(64U,
                                                           std::byte{0x5aU}),
                       .revoked = false});
}

TEST(SignalingRouteTest, SelectsLanFirstAndReportsUnavailableModes) {
  auto automatic_lan =
      select_signaling_route(ConnectivityMode::automatic, true, true);
  ASSERT_TRUE(automatic_lan);
  EXPECT_EQ(*automatic_lan.value_if(), SignalingRouteKind::lan);

  auto automatic_relay =
      select_signaling_route(ConnectivityMode::automatic, false, true);
  ASSERT_TRUE(automatic_relay);
  EXPECT_EQ(*automatic_relay.value_if(), SignalingRouteKind::relay);

  auto lan_only =
      select_signaling_route(ConnectivityMode::lan_only, false, true);
  ASSERT_FALSE(lan_only);
  EXPECT_EQ(lan_only.error_if()->code(), ErrorCode::endpoint_offline);

  auto relay_only =
      select_signaling_route(ConnectivityMode::relay_only, true, false);
  ASSERT_FALSE(relay_only);
  EXPECT_EQ(relay_only.error_if()->code(), ErrorCode::relay_unavailable);

  auto no_route =
      select_signaling_route(ConnectivityMode::automatic, false, false);
  ASSERT_FALSE(no_route);
  EXPECT_EQ(no_route.error_if()->code(), ErrorCode::peer_offline);
}

TEST(SignalingRouteTest, OfferOwnerUsesTheCompleteEndpointTuple) {
  DeviceId::Storage device_bytes{};
  device_bytes[0] = std::byte{1U};
  EndpointId::Storage first_endpoint_bytes{};
  first_endpoint_bytes[0] = std::byte{1U};
  EndpointId::Storage second_endpoint_bytes{};
  second_endpoint_bytes[0] = std::byte{2U};
  const DeviceEndpointKey first{DeviceId{device_bytes},
                                EndpointId{first_endpoint_bytes}};
  const DeviceEndpointKey second{DeviceId{device_bytes},
                                 EndpointId{second_endpoint_bytes}};

  EXPECT_TRUE(is_lan_offer_owner(first, second));
  EXPECT_FALSE(is_lan_offer_owner(second, first));
  EXPECT_FALSE(is_lan_offer_owner(first, first));
}

LanPresence signed_presence(const IdentityKeyPair& identity, std::uint8_t endpoint_tag,
                            std::uint8_t boot_tag, std::uint64_t sequence,
                            std::chrono::milliseconds lease = std::chrono::milliseconds{15000}) {
  LanPresence presence;
  EndpointId::Storage endpoint{};
  endpoint[0] = static_cast<std::byte>(endpoint_tag);
  presence.endpoint_id = EndpointId{endpoint};
  presence.boot_nonce[0] = static_cast<std::byte>(boot_tag);
  presence.sequence = sequence;
  presence.tls_signaling_port = 49190U;
  presence.lease = lease;
  EXPECT_TRUE(sign_lan_presence(presence, identity));
  return presence;
}

LanConfiguration constrained_configuration() {
  LanConfiguration configuration;
  configuration.directory_capacity = 3U;
  configuration.trusted_directory_reserve = 1U;
  configuration.per_interface_directory_capacity = 3U;
  configuration.per_source_presence_capacity = 3U;
  configuration.unknown_identity_capacity = 2U;
  configuration.replay_capacity = 8U;
  configuration.diagnostic_capacity = 4U;
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  return configuration;
}

TEST(EndpointDirectoryTest, PreservesTrustedCapacityAndBoundsDiagnostics) {
  auto directory = EndpointDirectory::create(constrained_configuration());
  ASSERT_TRUE(directory) << directory.error_if()->safe_detail();
  auto first = create_identity();
  auto second = create_identity();
  auto third = create_identity();
  ASSERT_TRUE(first && second && third);
  const auto now = std::chrono::steady_clock::now();

  EXPECT_TRUE(directory.value_if()->observe_lan(
      signed_presence(*first.value_if(), 1U, 1U, 1U), "192.0.2.1", "eth0", false, now));
  EXPECT_TRUE(directory.value_if()->observe_lan(
      signed_presence(*second.value_if(), 2U, 2U, 1U), "192.0.2.2", "eth0", false, now));
  auto untrusted_full = directory.value_if()->observe_lan(
      signed_presence(*third.value_if(), 3U, 3U, 1U), "192.0.2.3", "eth0", false, now);
  ASSERT_FALSE(untrusted_full);
  EXPECT_EQ(untrusted_full.error_if()->code(), ErrorCode::resource_exhausted);
  EXPECT_EQ(untrusted_full.error_if()->safe_detail(), "untrusted_directory_capacity_full");

  auto trusted = directory.value_if()->observe_lan(
      signed_presence(*third.value_if(), 3U, 3U, 2U), "192.0.2.3", "eth0", true, now);
  ASSERT_TRUE(trusted) << trusted.error_if()->safe_detail();
  EXPECT_EQ(directory.value_if()->snapshot(now).size(), 3U);
  EXPECT_LE(directory.value_if()->diagnostic_history().size(), 4U);
  const auto diagnostics = directory.value_if()->diagnostics();
  EXPECT_EQ(diagnostics.current_entries, 3U);
  EXPECT_EQ(diagnostics.capacity_rejected, 1U);
}

TEST(EndpointDirectoryTest, RejectsSequenceAndRetiredBootReplay) {
  LanConfiguration configuration;
  configuration.per_source_announcement_rate = 32U;
  auto directory = EndpointDirectory::create(configuration);
  auto identity = create_identity();
  ASSERT_TRUE(directory && identity);
  const auto now = std::chrono::steady_clock::now();

  auto initial = signed_presence(*identity.value_if(), 4U, 1U, 10U);
  ASSERT_TRUE(directory.value_if()->observe_lan(initial, "192.0.2.4", "eth0", false, now));
  auto duplicate = directory.value_if()->observe_lan(
      initial, "192.0.2.4", "eth0", false, now + std::chrono::milliseconds{1});
  ASSERT_TRUE(duplicate);
  EXPECT_EQ(duplicate.value_if()->outcome, DirectoryObservationOutcome::duplicate);

  auto lower = directory.value_if()->observe_lan(
      signed_presence(*identity.value_if(), 4U, 1U, 9U), "192.0.2.4", "eth0", false,
      now + std::chrono::milliseconds{2});
  ASSERT_FALSE(lower);
  EXPECT_EQ(lower.error_if()->safe_detail(), "presence_sequence_replay");

  ASSERT_TRUE(directory.value_if()->observe_lan(
      signed_presence(*identity.value_if(), 4U, 2U, 1U), "192.0.2.4", "eth0", false,
      now + std::chrono::milliseconds{3}));
  auto retired = directory.value_if()->observe_lan(
      signed_presence(*identity.value_if(), 4U, 1U, 11U), "192.0.2.4", "eth0", false,
      now + std::chrono::milliseconds{4});
  ASSERT_FALSE(retired);
  EXPECT_EQ(retired.error_if()->safe_detail(), "presence_boot_replay");
  EXPECT_EQ(directory.value_if()->diagnostics().replay_rejected, 2U);
}

TEST(EndpointDirectoryTest, RejectsSameSequenceWithDifferentSignedFields) {
  LanConfiguration configuration;
  configuration.per_source_announcement_rate = 32U;
  auto directory = EndpointDirectory::create(configuration);
  auto identity = create_identity();
  ASSERT_TRUE(directory && identity);
  const auto now = std::chrono::steady_clock::now();

  auto initial = signed_presence(*identity.value_if(), 8U, 8U, 1U);
  ASSERT_TRUE(directory.value_if()->observe_lan(
      initial, "192.0.2.8", "eth0", false, now));
  auto conflicting = initial;
  conflicting.tls_signaling_port = 49191U;
  ASSERT_TRUE(sign_lan_presence(conflicting, *identity.value_if()));
  auto rejected = directory.value_if()->observe_lan(
      conflicting, "192.0.2.8", "eth0", false,
      now + std::chrono::milliseconds{1});
  ASSERT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->safe_detail(), "presence_sequence_conflict");
  EXPECT_EQ(directory.value_if()->diagnostics().conflict_rejected, 1U);
}

TEST(EndpointDirectoryTest, DoesNotEvictLiveRetiredBootReplayState) {
  LanConfiguration configuration;
  configuration.per_source_announcement_rate = 32U;
  auto directory = EndpointDirectory::create(configuration);
  auto identity = create_identity();
  ASSERT_TRUE(directory && identity);
  const auto now = std::chrono::steady_clock::now();

  for (std::uint8_t boot = 1U; boot <= 5U; ++boot) {
    ASSERT_TRUE(directory.value_if()->observe_lan(
        signed_presence(*identity.value_if(), 9U, boot, 1U),
        "192.0.2.9", "eth0", false,
        now + std::chrono::milliseconds{boot}));
  }
  auto history_full = directory.value_if()->observe_lan(
      signed_presence(*identity.value_if(), 9U, 6U, 1U),
      "192.0.2.9", "eth0", false,
      now + std::chrono::milliseconds{6});
  ASSERT_FALSE(history_full);
  EXPECT_EQ(history_full.error_if()->safe_detail(),
            "presence_boot_history_full");

  auto retired_replay = directory.value_if()->observe_lan(
      signed_presence(*identity.value_if(), 9U, 1U, 2U),
      "192.0.2.9", "eth0", false,
      now + std::chrono::milliseconds{7});
  ASSERT_FALSE(retired_replay);
  EXPECT_EQ(retired_replay.error_if()->safe_detail(), "presence_boot_replay");
}

TEST(EndpointDirectoryTest, LanExpiryDoesNotDeleteRelayPresence) {
  auto directory = EndpointDirectory::create(LanConfiguration{});
  auto identity = create_identity();
  ASSERT_TRUE(directory && identity);
  const auto now = std::chrono::steady_clock::now();
  auto presence = signed_presence(*identity.value_if(), 5U, 5U, 1U,
                                  std::chrono::milliseconds{1000});
  ASSERT_TRUE(directory.value_if()->observe_lan(
      presence, "192.0.2.5", "eth0", true, now));
  const DeviceEndpointKey key{presence.device_id, presence.endpoint_id};
  ASSERT_TRUE(directory.value_if()->upsert_relay(
      key, presence.identity_public_key, "wss://relay.example.invalid", true,
      std::chrono::seconds{30}, now));

  directory.value_if()->expire(now + std::chrono::seconds{2});
  auto after_lan_expiry = directory.value_if()->snapshot(now + std::chrono::seconds{2});
  ASSERT_EQ(after_lan_expiry.size(), 1U);
  EXPECT_FALSE(after_lan_expiry.front().lan.has_value());
  EXPECT_TRUE(after_lan_expiry.front().relay.has_value());
  EXPECT_TRUE(after_lan_expiry.front().trusted);

  directory.value_if()->expire(now + std::chrono::seconds{31});
  EXPECT_TRUE(directory.value_if()->snapshot(now + std::chrono::seconds{31}).empty());
}

TEST(EndpointDirectoryTest, RejectsIdentityConflictAcrossLanAndRelayHints) {
  auto directory = EndpointDirectory::create(LanConfiguration{});
  auto identity = create_identity();
  auto other = create_identity();
  ASSERT_TRUE(directory && identity && other);
  const auto now = std::chrono::steady_clock::now();
  auto presence = signed_presence(*identity.value_if(), 6U, 6U, 1U);
  const DeviceEndpointKey key{presence.device_id, presence.endpoint_id};
  ASSERT_TRUE(directory.value_if()->upsert_relay(
      key, other.value_if()->public_key(), "wss://relay.example.invalid", false,
      std::chrono::seconds{30}, now));
  EXPECT_FALSE(directory.value_if()->observe_lan(
      presence, "192.0.2.6", "eth0", false, now));
  EXPECT_EQ(directory.value_if()->diagnostics().conflict_rejected, 1U);
}

TEST(EndpointDirectoryTest, RateAndPerSourceLimitsAreExplicit) {
  LanConfiguration configuration;
  configuration.per_source_announcement_rate = 1U;
  configuration.announcement_rate_per_second = 2U;
  auto directory = EndpointDirectory::create(configuration);
  auto first = create_identity();
  auto second = create_identity();
  ASSERT_TRUE(directory && first && second);
  const auto now = std::chrono::steady_clock::now();

  ASSERT_TRUE(directory.value_if()->observe_lan(
      signed_presence(*first.value_if(), 6U, 6U, 1U), "192.0.2.6", "eth0", false, now));
  auto limited = directory.value_if()->observe_lan(
      signed_presence(*second.value_if(), 7U, 7U, 1U), "192.0.2.6", "eth0", false, now);
  ASSERT_FALSE(limited);
  EXPECT_EQ(limited.error_if()->safe_detail(), "presence_rate_limited");
  EXPECT_EQ(directory.value_if()->diagnostics().rate_rejected, 1U);
}

TEST(EndpointDirectoryTest, GlobalAnnouncementRateIsExplicit) {
  LanConfiguration configuration;
  configuration.per_source_announcement_rate = 2U;
  configuration.announcement_rate_per_second = 2U;
  auto directory = EndpointDirectory::create(configuration);
  auto first = create_identity();
  auto second = create_identity();
  auto third = create_identity();
  ASSERT_TRUE(directory && first && second && third);
  const auto now = std::chrono::steady_clock::now();

  ASSERT_TRUE(directory.value_if()->observe_lan(
      signed_presence(*first.value_if(), 10U, 10U, 1U),
      "192.0.2.10", "eth0", false, now));
  ASSERT_TRUE(directory.value_if()->observe_lan(
      signed_presence(*second.value_if(), 11U, 11U, 1U),
      "192.0.2.11", "eth0", false, now));
  auto limited = directory.value_if()->observe_lan(
      signed_presence(*third.value_if(), 12U, 12U, 1U),
      "192.0.2.12", "eth0", false, now);
  ASSERT_FALSE(limited);
  EXPECT_EQ(limited.error_if()->safe_detail(), "presence_rate_limited");
  EXPECT_EQ(directory.value_if()->diagnostics().rate_rejected, 1U);
}

TEST_F(M3aNodeTest, NodeRequiresLocalInitializationAndValidControlCapacity) {
  ProfileOpenOptions options;
  options.secret_backend.prefer_os_backend = false;
  auto profile = ProfileStore::create(root_ / "uninitialized" / "profile.sqlite", options);
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  auto uninitialized =
      Node::create(node_config(*profile.value_if(), "com.example.node"));
  ASSERT_FALSE(uninitialized);
  EXPECT_EQ(uninitialized.error_if()->code(), ErrorCode::not_registered);
  EXPECT_EQ(uninitialized.error_if()->safe_detail(), "local_profile_not_initialized");

  LanConfiguration relay_only;
  relay_only.connectivity_mode = ConnectivityMode::relay_only;
  relay_only.enabled = false;
  auto ready_profile = initialized_profile("invalid-capacity", "com.example.node", relay_only);
  ASSERT_TRUE(ready_profile) << ready_profile.error_if()->safe_detail();
  auto invalid = relay_only;
  invalid.pending_signaling_capacity = 0U;
  auto invalid_config = node_config(*ready_profile.value_if(), "com.example.node");
  invalid_config.lan_override = invalid;
  auto invalid_node = Node::create(std::move(invalid_config));
  ASSERT_FALSE(invalid_node);
  EXPECT_EQ(invalid_node.error_if()->code(), ErrorCode::configuration);
}

TEST_F(M3aNodeTest, RelayOnlyNodeIsLocallyReadyWithoutLanOrEnrollment) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::relay_only;
  configuration.enabled = false;
  auto profile = initialized_profile("relay-only", "com.example.node", configuration);
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();

  auto node = Node::create(node_config(*profile.value_if(), "com.example.node"));
  ASSERT_TRUE(node) << node.error_if()->safe_detail();
  const auto snapshot = node.value_if()->snapshot();
  EXPECT_TRUE(snapshot.local_initialized);
  EXPECT_FALSE(snapshot.lan_enabled);
  EXPECT_EQ(snapshot.lan_state, LanReadinessState::disabled);
  EXPECT_FALSE(snapshot.tls.listener_ready);
  const auto shutdown = node.value_if()->shutdown();
  EXPECT_TRUE(shutdown.stopped);
  EXPECT_FALSE(shutdown.timed_out);
}

TEST_F(M3aNodeTest, ProvisionalTlsIsPerSourceRateLimitedAndTimesOut) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.provisional_connection_capacity = 2U;
  configuration.per_source_provisional_capacity = 2U;
  configuration.provisional_accept_rate_per_second = 2U;
  configuration.per_source_provisional_rate = 1U;
  configuration.handshake_timeout = std::chrono::milliseconds{200};
  configuration.hello_timeout = std::chrono::milliseconds{100};
  auto profile = initialized_profile("provisional-pressure", "com.example.node",
                                     configuration);
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();

  auto node = Node::create(node_config(*profile.value_if(), "com.example.node"));
  if (!node && node.error_if()->safe_detail() == "lan_no_ready_interface") {
    if (environment_enabled("HEYAKI_REQUIRE_LAN_INTERFACES")) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  ASSERT_TRUE(node) << node.error_if()->safe_detail();
  const auto port = node.value_if()->snapshot().tls.listen_port;
  ASSERT_NE(port, 0U);

  boost::asio::io_context io;
  boost::asio::ip::tcp::socket first{io};
  boost::asio::ip::tcp::socket second{io};
  const boost::asio::ip::tcp::endpoint listener{
      boost::asio::ip::make_address_v6("::1"), port};
  ASSERT_NO_THROW(first.connect(listener));
  ASSERT_TRUE(wait_until(
      [&] {
        return node.value_if()->snapshot().tls.provisional_connections == 1U;
      },
      std::chrono::seconds{1}));

  ASSERT_NO_THROW(second.connect(listener));
  EXPECT_TRUE(wait_until(
      [&] {
        const auto snapshot = node.value_if()->snapshot();
        return snapshot.tls.rejected >= 1U &&
               snapshot.tls.rate_limited >= 1U && snapshot.last_error &&
               snapshot.last_error->safe_detail() ==
                   "source_provisional_rate_limited";
      },
      std::chrono::seconds{1}));
  EXPECT_TRUE(wait_until(
      [&] {
        const auto tls = node.value_if()->snapshot().tls;
        return tls.timed_out >= 1U && tls.provisional_connections == 0U;
      },
      std::chrono::seconds{1}));

  boost::system::error_code ignored;
  first.close(ignored);
  second.close(ignored);
  const auto shutdown = node.value_if()->shutdown();
  EXPECT_TRUE(shutdown.stopped);
  EXPECT_FALSE(shutdown.timed_out);
}

TEST_F(M3aNodeTest, TwoLanNodesDiscoverEachOtherWithoutRelay) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::automatic;
  configuration.announcement_interval = std::chrono::milliseconds{200};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  auto first_profile = initialized_profile("first", "com.example.first", configuration);
  auto second_profile = initialized_profile("second", "com.example.second", configuration);
  ASSERT_TRUE(first_profile && second_profile);

  auto first = Node::create(
      node_config(*first_profile.value_if(), "com.example.first"));
  auto second = Node::create(
      node_config(*second_profile.value_if(), "com.example.second"));
  ASSERT_TRUE(first) << first.error_if()->safe_detail();
  ASSERT_TRUE(second) << second.error_if()->safe_detail();
  const auto first_snapshot = first.value_if()->snapshot();
  const auto second_snapshot = second.value_if()->snapshot();
  ASSERT_TRUE(first_snapshot.tls.listener_ready);
  ASSERT_TRUE(second_snapshot.tls.listener_ready);
  const auto first_joined = std::count_if(
      first_snapshot.interfaces.begin(), first_snapshot.interfaces.end(),
      [](const LanInterfaceSnapshot& interface) { return interface.joined; });
  const auto second_joined = std::count_if(
      second_snapshot.interfaces.begin(), second_snapshot.interfaces.end(),
      [](const LanInterfaceSnapshot& interface) { return interface.joined; });
  if (first_joined == 0 || second_joined == 0) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    if (environment_enabled("HEYAKI_REQUIRE_LAN_INTERFACES")) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  EXPECT_TRUE(wait_until(
      [&] {
        return !first.value_if()->endpoints().empty() &&
               !second.value_if()->endpoints().empty();
      },
      std::chrono::seconds{4}));
  ASSERT_EQ(first.value_if()->endpoints().size(), 1U);
  ASSERT_EQ(second.value_if()->endpoints().size(), 1U);
  EXPECT_EQ(first.value_if()->endpoints().front().key.device_id,
            second_profile.value_if()->device_id());
  EXPECT_EQ(second.value_if()->endpoints().front().key.device_id,
            first_profile.value_if()->device_id());
  EXPECT_FALSE(first.value_if()->endpoints().front().trusted);
  EXPECT_FALSE(second.value_if()->endpoints().front().trusted);

  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
}

TEST_F(M3aNodeTest, NetworkTopologyMatchesExpectedInterfaces) {
  const auto expected_ipv4 = environment_size("HEYAKI_EXPECT_IPV4_INTERFACES");
  const auto expected_ipv6 = environment_size("HEYAKI_EXPECT_IPV6_INTERFACES");
  if (!expected_ipv4 && !expected_ipv6) {
    GTEST_SKIP() << "Network topology expectations are not configured";
  }

  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.discoverable = false;
  auto profile = initialized_profile("topology", "com.example.topology",
                                     configuration);
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  auto node = Node::create(
      node_config(*profile.value_if(), "com.example.topology"));
  ASSERT_TRUE(node) << node.error_if()->safe_detail();
  const auto snapshot = node.value_if()->snapshot();
  const auto count_family = [&](LanInterfaceFamily family) {
    return static_cast<std::size_t>(std::count_if(
        snapshot.interfaces.begin(), snapshot.interfaces.end(),
        [&](const auto& interface) {
          return interface.joined && interface.family == family;
        }));
  };
  if (expected_ipv4) {
    EXPECT_EQ(count_family(LanInterfaceFamily::ipv4), *expected_ipv4);
  }
  if (expected_ipv6) {
    EXPECT_EQ(count_family(LanInterfaceFamily::ipv6), *expected_ipv6);
  }
  EXPECT_EQ(snapshot.lan_state, LanReadinessState::ready);
  EXPECT_TRUE(node.value_if()->shutdown().stopped);
}

TEST_F(M3aNodeTest, RefreshesSocketsAfterInterfaceSwitch) {
  const char* interface_value = std::getenv("HEYAKI_SWITCH_INTERFACE");
  if (interface_value == nullptr || *interface_value == '\0') {
    GTEST_SKIP() << "Interface switch target is not configured";
  }
#if !defined(__linux__)
  GTEST_SKIP() << "Interface switching test is Linux-only";
#else
  const std::string interface_name{interface_value};
  ASSERT_TRUE(std::all_of(interface_name.begin(), interface_name.end(),
                          [](unsigned char character) {
                            return std::isalnum(character) != 0 ||
                                   character == '_' || character == '-' ||
                                   character == '.';
                          }));

  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.discoverable = false;
  configuration.interface_refresh_interval = std::chrono::seconds{30};
  auto profile = initialized_profile("interface-switch", "com.example.switch",
                                     configuration);
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  auto node = Node::create(
      node_config(*profile.value_if(), "com.example.switch"));
  ASSERT_TRUE(node) << node.error_if()->safe_detail();
  const auto initial_snapshot = node.value_if()->snapshot();
  ASSERT_TRUE(std::any_of(
      initial_snapshot.interfaces.begin(), initial_snapshot.interfaces.end(),
      [&](const auto& interface) {
        return interface.name == interface_name && interface.joined;
      }));

  ASSERT_TRUE(set_test_interface_state(interface_name, false));
  ASSERT_TRUE(node.value_if()->refresh_interfaces());
  const bool removed = wait_until(
      [&] {
        const auto snapshot = node.value_if()->snapshot();
        return std::none_of(snapshot.interfaces.begin(), snapshot.interfaces.end(),
                            [&](const auto& interface) {
                              return interface.name == interface_name;
                            });
      },
      std::chrono::seconds{2});

  EXPECT_TRUE(set_test_interface_state(interface_name, true));
  ASSERT_TRUE(node.value_if()->refresh_interfaces());
  const bool restored = wait_until(
      [&] {
        const auto snapshot = node.value_if()->snapshot();
        return std::any_of(snapshot.interfaces.begin(), snapshot.interfaces.end(),
                           [&](const auto& interface) {
                             return interface.name == interface_name && interface.joined;
                           });
      },
      std::chrono::seconds{2});
  EXPECT_TRUE(removed);
  EXPECT_TRUE(restored);
  EXPECT_EQ(node.value_if()->snapshot().lan_state, LanReadinessState::ready);
  EXPECT_TRUE(node.value_if()->shutdown().stopped);
#endif
}

TEST_F(M3aNodeTest, ThreeEndpointsIncludeTwoFromTheSameDevice) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  auto shared_profile = initialized_profile(
      "shared-device", "com.example.shared.first", configuration);
  auto remote_profile = initialized_profile(
      "remote-device", "com.example.remote", configuration);
  ASSERT_TRUE(shared_profile && remote_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*shared_profile.value_if(),
                                              *remote_profile.value_if(),
                                              {"m4.test"}));
  auto second_endpoint =
      shared_profile.value_if()->endpoint_for("com.example.shared.second");
  ASSERT_TRUE(second_endpoint) << second_endpoint.error_if()->safe_detail();

  auto first = Node::create(node_config(*shared_profile.value_if(),
                                        "com.example.shared.first"));
  auto second = Node::create(node_config(*shared_profile.value_if(),
                                         "com.example.shared.second"));
  auto remote = Node::create(node_config(*remote_profile.value_if(),
                                         "com.example.remote"));
  ASSERT_TRUE(first && second && remote);
  if (joined_interface_count(first.value_if()->snapshot()) == 0U ||
      joined_interface_count(second.value_if()->snapshot()) == 0U ||
      joined_interface_count(remote.value_if()->snapshot()) == 0U) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    (void)remote.value_if()->shutdown();
    if (environment_enabled("HEYAKI_REQUIRE_LAN_INTERFACES")) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  ASSERT_TRUE(wait_until(
      [&] {
        return first.value_if()->endpoints().size() == 2U &&
               second.value_if()->endpoints().size() == 2U &&
               remote.value_if()->endpoints().size() == 2U;
      },
      std::chrono::seconds{4}));
  const auto remote_entries = remote.value_if()->endpoints();
  std::set<EndpointId> shared_endpoints;
  for (const auto& entry : remote_entries) {
    if (entry.key.device_id == shared_profile.value_if()->device_id()) {
      shared_endpoints.insert(entry.key.endpoint_id);
    }
  }
  EXPECT_EQ(shared_endpoints.size(), 2U);
  EXPECT_TRUE(shared_endpoints.contains(*second_endpoint.value_if()));
  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
  EXPECT_TRUE(remote.value_if()->shutdown().stopped);
}

TEST_F(M3aNodeTest, BlockedMulticastFailsPeerLookupAndShutdowns) {
  if (!environment_enabled("HEYAKI_EXPECT_MULTICAST_BLOCKED")) {
    GTEST_SKIP() << "Blocked multicast topology is not configured";
  }
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.announcement_interval = std::chrono::milliseconds{50};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  auto first_profile = initialized_profile("blocked-first", "com.example.blocked.first",
                                           configuration);
  auto second_profile = initialized_profile("blocked-second", "com.example.blocked.second",
                                            configuration);
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));
  auto first = Node::create(node_config(*first_profile.value_if(),
                                        "com.example.blocked.first"));
  auto second = Node::create(node_config(*second_profile.value_if(),
                                         "com.example.blocked.second"));
  ASSERT_TRUE(first && second);
  ASSERT_GT(joined_interface_count(first.value_if()->snapshot()), 0U);
  ASSERT_GT(joined_interface_count(second.value_if()->snapshot()), 0U);

  ASSERT_TRUE(wait_until(
      [&] {
        return first.value_if()->snapshot().lan_state ==
                   LanReadinessState::degraded &&
               second.value_if()->snapshot().lan_state ==
                   LanReadinessState::degraded;
      },
      std::chrono::seconds{4}));
  const auto first_blocked = first.value_if()->snapshot();
  const auto second_blocked = second.value_if()->snapshot();
  const auto has_multicast_failure = [](const NodeSnapshot& snapshot) {
    return snapshot.last_error &&
           is_multicast_unavailable_detail(snapshot.last_error->safe_detail()) &&
           std::any_of(snapshot.interfaces.begin(), snapshot.interfaces.end(),
                       [](const LanInterfaceSnapshot& interface) {
                         return interface.joined && !interface.multicast_verified &&
                                interface.error &&
                                is_multicast_unavailable_detail(
                                    interface.error->safe_detail());
                       });
  };
  EXPECT_TRUE(has_multicast_failure(first_blocked));
  EXPECT_TRUE(has_multicast_failure(second_blocked));
  EXPECT_TRUE(first.value_if()->endpoints().empty());
  EXPECT_TRUE(second.value_if()->endpoints().empty());
  const auto unavailable = first.value_if()->connect_lan(
      DeviceEndpointKey{second.value_if()->snapshot().device_id,
                        second.value_if()->snapshot().endpoint_id});
  ASSERT_FALSE(unavailable);
  EXPECT_EQ(unavailable.error_if()->code(), ErrorCode::endpoint_offline);
  EXPECT_EQ(unavailable.error_if()->safe_detail(), "lan_endpoint_unavailable");

  const auto started = std::chrono::steady_clock::now();
  const auto first_shutdown = first.value_if()->shutdown();
  const auto second_shutdown = second.value_if()->shutdown();
  EXPECT_TRUE(first_shutdown.stopped);
  EXPECT_TRUE(second_shutdown.stopped);
  EXPECT_EQ(first_shutdown.final_resources.discovery_sockets, 0U);
  EXPECT_FALSE(first_shutdown.final_resources.tls_listener_open);
  EXPECT_EQ(first_shutdown.final_resources.active_timers, 0U);
  EXPECT_EQ(first_shutdown.final_resources.signaling_connections, 0U);
  EXPECT_EQ(second_shutdown.final_resources.discovery_sockets, 0U);
  EXPECT_FALSE(second_shutdown.final_resources.tls_listener_open);
  EXPECT_EQ(second_shutdown.final_resources.active_timers, 0U);
  EXPECT_EQ(second_shutdown.final_resources.signaling_connections, 0U);
  EXPECT_LT(std::chrono::steady_clock::now() - started,
            std::chrono::seconds{2});
}

TEST_F(M3aNodeTest, ApIsolationFailsDiscoveryWithinBudget) {
  if (!environment_enabled("HEYAKI_EXPECT_AP_ISOLATION")) {
    GTEST_SKIP() << "AP isolation topology is not configured";
  }
  const auto first_interface =
      environment_string("HEYAKI_AP_ISOLATION_FIRST_INTERFACE");
  const auto second_interface =
      environment_string("HEYAKI_AP_ISOLATION_SECOND_INTERFACE");
  ASSERT_TRUE(first_interface && second_interface);

  LanConfiguration first_configuration;
  first_configuration.connectivity_mode = ConnectivityMode::lan_only;
  first_configuration.interface_preferences = {*first_interface};
  first_configuration.announcement_interval = std::chrono::milliseconds{50};
  first_configuration.announcement_jitter = std::chrono::milliseconds{0};
  first_configuration.presence_lease = std::chrono::milliseconds{1000};
  first_configuration.announcement_rate_per_second = 100U;
  first_configuration.per_source_announcement_rate = 100U;
  auto second_configuration = first_configuration;
  second_configuration.interface_preferences = {*second_interface};
  auto first_profile = initialized_profile("isolated-first", "com.example.isolated.first",
                                           first_configuration);
  auto second_profile = initialized_profile("isolated-second", "com.example.isolated.second",
                                            second_configuration);
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));
  auto first = Node::create(node_config(*first_profile.value_if(),
                                        "com.example.isolated.first"));
  auto second = Node::create(node_config(*second_profile.value_if(),
                                         "com.example.isolated.second"));
  ASSERT_TRUE(first && second);
  ASSERT_EQ(joined_interface_count(first.value_if()->snapshot()), 1U);
  ASSERT_EQ(joined_interface_count(second.value_if()->snapshot()), 1U);

  ASSERT_TRUE(wait_until(
      [&] {
        return first.value_if()->snapshot().lan_state ==
                   LanReadinessState::degraded &&
               second.value_if()->snapshot().lan_state ==
                   LanReadinessState::degraded;
      },
      std::chrono::seconds{4}));
  EXPECT_TRUE(first.value_if()->endpoints().empty());
  EXPECT_TRUE(second.value_if()->endpoints().empty());
  ASSERT_TRUE(first.value_if()->snapshot().last_error);
  ASSERT_TRUE(second.value_if()->snapshot().last_error);
  EXPECT_TRUE(is_multicast_unavailable_detail(
      first.value_if()->snapshot().last_error->safe_detail()));
  EXPECT_TRUE(is_multicast_unavailable_detail(
      second.value_if()->snapshot().last_error->safe_detail()));

  const auto unavailable = first.value_if()->connect_lan(
      DeviceEndpointKey{second.value_if()->snapshot().device_id,
                        second.value_if()->snapshot().endpoint_id});
  ASSERT_FALSE(unavailable);
  EXPECT_EQ(unavailable.error_if()->code(), ErrorCode::endpoint_offline);
  const auto started = std::chrono::steady_clock::now();
  const auto first_shutdown = first.value_if()->shutdown();
  const auto second_shutdown = second.value_if()->shutdown();
  EXPECT_TRUE(first_shutdown.stopped);
  EXPECT_TRUE(second_shutdown.stopped);
  EXPECT_EQ(first_shutdown.final_resources.discovery_sockets, 0U);
  EXPECT_FALSE(first_shutdown.final_resources.tls_listener_open);
  EXPECT_EQ(first_shutdown.final_resources.active_timers, 0U);
  EXPECT_EQ(second_shutdown.final_resources.discovery_sockets, 0U);
  EXPECT_FALSE(second_shutdown.final_resources.tls_listener_open);
  EXPECT_EQ(second_shutdown.final_resources.active_timers, 0U);
  EXPECT_LT(std::chrono::steady_clock::now() - started,
            std::chrono::seconds{2});
}

TEST_F(M3aNodeTest, RejectsForgedMulticastFloodWithinBounds) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.discoverable = false;
  configuration.directory_capacity = 4U;
  configuration.trusted_directory_reserve = 1U;
  configuration.per_interface_directory_capacity = 4U;
  configuration.per_source_presence_capacity = 4U;
  configuration.unknown_identity_capacity = 3U;
  configuration.replay_capacity = 8U;
  configuration.diagnostic_capacity = 8U;
  configuration.announcement_rate_per_second = 8U;
  configuration.per_source_announcement_rate = 4U;
  auto profile = initialized_profile("multicast-flood", "com.example.flood",
                                     configuration);
  ASSERT_TRUE(profile) << profile.error_if()->safe_detail();
  auto node = Node::create(node_config(*profile.value_if(), "com.example.flood"));
  ASSERT_TRUE(node) << node.error_if()->safe_detail();

  const auto snapshot = node.value_if()->snapshot();
  const auto interface = std::find_if(
      snapshot.interfaces.begin(), snapshot.interfaces.end(),
      [](const auto& candidate) {
        return candidate.joined && candidate.family == LanInterfaceFamily::ipv4;
      });
  if (interface == snapshot.interfaces.end()) {
    (void)node.value_if()->shutdown();
    GTEST_SKIP() << "No IPv4 multicast-capable interface";
  }
  const auto attacker = create_identity();
  ASSERT_TRUE(attacker) << attacker.error_if()->safe_detail();

  boost::asio::io_context io;
  boost::asio::ip::udp::socket socket{io};
  socket.open(boost::asio::ip::udp::v4());
  socket.set_option(boost::asio::ip::multicast::outbound_interface(
      boost::asio::ip::make_address_v4(interface->address)));
  socket.set_option(boost::asio::ip::multicast::enable_loopback(true));
  const boost::asio::ip::udp::endpoint destination{
      boost::asio::ip::make_address_v4(lan_discovery_ipv4_group),
      lan_discovery_udp_port};
  for (std::uint8_t tag = 1U; tag <= 32U; ++tag) {
    auto presence = signed_presence(*attacker.value_if(), tag, 1U, 1U,
                                    std::chrono::milliseconds{1000});
    auto datagram = encode_lan_presence_datagram(presence);
    ASSERT_TRUE(datagram) << datagram.error_if()->safe_detail();
    socket.send_to(boost::asio::buffer(*datagram.value_if()), destination);
  }

  ASSERT_TRUE(wait_until(
      [&] {
        const auto current = node.value_if()->snapshot();
        return current.datagrams_received >= 4U &&
               current.datagrams_rejected >= 1U;
      },
      std::chrono::seconds{2}));
  const auto after = node.value_if()->snapshot();
  EXPECT_LE(after.directory.current_entries, configuration.directory_capacity);
  EXPECT_LE(after.directory.replay_entries, configuration.replay_capacity);
  EXPECT_LE(after.directory.source_rate_entries,
            configuration.per_source_presence_capacity);
  EXPECT_LE(after.directory.diagnostic_history_size,
            configuration.diagnostic_capacity);
  EXPECT_GT(after.directory.capacity_rejected + after.directory.rate_rejected, 0U);
  EXPECT_TRUE(node.value_if()->shutdown().stopped);
}

TEST_F(M3aNodeTest, RejectsRelayedHelloAndCertificateSubstitution) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{2000};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  auto victim_profile = initialized_profile("mitm-victim", "com.example.victim",
                                            configuration);
  auto peer_profile = initialized_profile("mitm-peer", "com.example.peer",
                                          configuration);
  ASSERT_TRUE(victim_profile && peer_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*victim_profile.value_if(),
                                              *peer_profile.value_if(),
                                              {"m4.test"}));
  auto victim = Node::create(node_config(*victim_profile.value_if(),
                                         "com.example.victim"));
  auto peer = Node::create(node_config(*peer_profile.value_if(),
                                       "com.example.peer"));
  ASSERT_TRUE(victim && peer);
  if (joined_interface_count(victim.value_if()->snapshot()) == 0U ||
      joined_interface_count(peer.value_if()->snapshot()) == 0U) {
    (void)victim.value_if()->shutdown();
    (void)peer.value_if()->shutdown();
    if (environment_enabled("HEYAKI_REQUIRE_LAN_INTERFACES")) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  ASSERT_TRUE(wait_until(
      [&] { return victim.value_if()->endpoints().size() == 1U; },
      std::chrono::seconds{4}));

  const auto victim_snapshot = victim.value_if()->snapshot();
  const auto peer_snapshot = peer.value_if()->snapshot();
  const auto peer_hint = victim.value_if()->endpoints().front();
  ASSERT_TRUE(peer_hint.lan.has_value());
  auto peer_identity = peer_profile.value_if()->load_identity();
  ASSERT_TRUE(peer_identity) << peer_identity.error_if()->safe_detail();
  EXPECT_TRUE(peer.value_if()->shutdown().stopped);

  boost::asio::ssl::context client_context{boost::asio::ssl::context::tls_client};
  const auto substitute_certificate =
      configure_test_tls_certificate(client_context);
  ASSERT_TRUE(substitute_certificate)
      << substitute_certificate.error_if()->safe_detail();

  LanHello relayed;
  relayed.role = LanHelloRole::initiator;
  relayed.sender_endpoint_id = peer_snapshot.endpoint_id;
  relayed.peer_device_id = victim_snapshot.device_id;
  relayed.peer_endpoint_id = victim_snapshot.endpoint_id;
  relayed.initiator_nonce[0] = std::byte{0x11U};
  relayed.sender_tls_certificate_sha256 =
      peer_snapshot.tls.certificate_sha256;
  relayed.observed_peer_tls_certificate_sha256 =
      victim_snapshot.tls.certificate_sha256;
  relayed.sender_boot_nonce = peer_hint.lan->boot_nonce;
  relayed.expiry = std::chrono::milliseconds{1000};
  ASSERT_TRUE(sign_lan_hello(relayed, *peer_identity.value_if()));
  ASSERT_TRUE(send_test_hello(client_context, victim_snapshot.tls.listen_port,
                              relayed));
  ASSERT_TRUE(wait_until(
      [&] { return victim.value_if()->snapshot().tls.hello_rejected >= 1U; },
      std::chrono::seconds{2}));

  LanHello substituted = relayed;
  substituted.initiator_nonce[0] = std::byte{0x12U};
  substituted.sender_tls_certificate_sha256 =
      substitute_certificate.value_if()->fingerprint;
  substituted.observed_peer_tls_certificate_sha256[0] ^= std::byte{0x01U};
  ASSERT_TRUE(sign_lan_hello(substituted, *peer_identity.value_if()));
  ASSERT_TRUE(send_test_hello(client_context, victim_snapshot.tls.listen_port,
                              substituted));
  ASSERT_TRUE(wait_until(
      [&] { return victim.value_if()->snapshot().tls.hello_rejected >= 2U; },
      std::chrono::seconds{2}));
  EXPECT_EQ(victim.value_if()->snapshot().tls.authenticated_connections, 0U);
  EXPECT_TRUE(victim.value_if()->shutdown().stopped);
}

TEST_F(M3aNodeTest, AuthenticatesLanTlsAndForwardsBoundedControlMessages) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  auto first_profile = initialized_profile("signal-first", "com.example.first",
                                           configuration);
  auto second_profile = initialized_profile("signal-second", "com.example.second",
                                            configuration);
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));

  std::atomic<std::uint64_t> accepted{0U};
  std::atomic<std::uint64_t> requested{0U};
  std::atomic<std::uint64_t> validated{0U};
  std::atomic<std::uint64_t> signed_received{0U};
  std::atomic<Node*> second_node{nullptr};
  auto validator = [&](const LanSignalingMessage& message) {
    validated.fetch_add(1U, std::memory_order_relaxed);
    if (message.payload == std::vector<std::byte>{std::byte{0x42U}}) {
      return Result<void>::success();
    }
    return Result<void>::failure(
        Error{ErrorCode::authentication, "test", "signed_signal_invalid"});
  };
  auto first_handler = [&](const LanSignalingMessage& message) {
    if (message.kind == LanSignalingMessageKind::connect_accept) {
      accepted.fetch_add(1U, std::memory_order_relaxed);
    }
    return Result<void>::success();
  };
  auto second_handler = [&](const LanSignalingMessage& message) {
    if (message.kind == LanSignalingMessageKind::signed_offer) {
      signed_received.fetch_add(1U, std::memory_order_relaxed);
      return Result<void>::success();
    }
    if (message.kind != LanSignalingMessageKind::connect_request) {
      return Result<void>::success();
    }
    requested.fetch_add(1U, std::memory_order_relaxed);
    auto* node = second_node.load(std::memory_order_acquire);
    if (node == nullptr) {
      return Result<void>::failure(
          Error{ErrorCode::internal, "test", "second_node_unavailable"});
    }
    return node->send_lan_signaling(
        LanSignalingMessage{.peer = message.peer,
                            .kind = LanSignalingMessageKind::connect_accept,
                            .request_id = message.request_id,
                            .payload = {}});
  };

  auto first = Node::create(node_config(*first_profile.value_if(),
                                        "com.example.first", validator,
                                        first_handler));
  auto second = Node::create(node_config(*second_profile.value_if(),
                                         "com.example.second", validator,
                                         second_handler));
  ASSERT_TRUE(first && second);
  second_node.store(second.value_if(), std::memory_order_release);
  if (first.value_if()->snapshot().interfaces.empty() ||
      second.value_if()->snapshot().interfaces.empty()) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    if (environment_enabled("HEYAKI_REQUIRE_LAN_INTERFACES")) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  ASSERT_TRUE(wait_until(
      [&] {
        return first.value_if()->endpoints().size() == 1U &&
               second.value_if()->endpoints().size() == 1U;
      },
      std::chrono::seconds{4}));
  const auto peer = first.value_if()->endpoints().front().key;
  auto unauthenticated = first.value_if()->send_lan_signaling(
      LanSignalingMessage{.peer = peer,
                          .kind = LanSignalingMessageKind::signed_offer,
                          .request_id = request_id(2U),
                          .payload = {std::byte{0x42U}}});
  ASSERT_FALSE(unauthenticated);
  EXPECT_EQ(unauthenticated.error_if()->code(), ErrorCode::would_block);
  ASSERT_TRUE(first.value_if()->connect_lan(peer));
  ASSERT_TRUE(wait_until(
      [&] {
        const auto first_connections = first.value_if()->signaling_connections();
        const auto second_connections = second.value_if()->signaling_connections();
        const auto authenticated = [](const auto& connection) {
          return connection.state == LanSignalingConnectionState::authenticated;
        };
        return std::count_if(first_connections.begin(), first_connections.end(),
                             authenticated) == 1 &&
               std::count_if(second_connections.begin(), second_connections.end(),
                             authenticated) == 1;
      },
      std::chrono::seconds{4}));

  ASSERT_TRUE(first.value_if()->send_lan_signaling(
      LanSignalingMessage{.peer = peer,
                          .kind = LanSignalingMessageKind::connect_request,
                          .request_id = request_id(1U),
                          .payload = {}}));
  const bool forwarded = wait_until(
      [&] {
        return requested.load(std::memory_order_relaxed) == 1U &&
               accepted.load(std::memory_order_relaxed) == 1U;
      },
      std::chrono::seconds{2});
  const auto first_after = first.value_if()->snapshot();
  const auto second_after = second.value_if()->snapshot();
  const auto first_signal_after = first.value_if()->signaling_connections();
  const auto second_signal_after = second.value_if()->signaling_connections();
  EXPECT_TRUE(forwarded)
      << "requested=" << requested.load(std::memory_order_relaxed)
      << " accepted=" << accepted.load(std::memory_order_relaxed)
      << " first_error="
      << (first_after.last_error ? first_after.last_error->safe_detail() : "none")
      << " second_error="
      << (second_after.last_error ? second_after.last_error->safe_detail() : "none")
      << " first_connections=" << first_signal_after.size()
      << " first_state="
      << (first_signal_after.empty()
              ? -1
              : static_cast<int>(first_signal_after.front().state))
      << " first_signal_error="
      << (first_signal_after.empty() || !first_signal_after.front().error
              ? "none"
              : first_signal_after.front().error->safe_detail())
      << " second_connections=" << second_signal_after.size()
      << " second_state="
      << (second_signal_after.empty()
              ? -1
              : static_cast<int>(second_signal_after.front().state))
      << " second_signal_error="
      << (second_signal_after.empty() || !second_signal_after.front().error
              ? "none"
              : second_signal_after.front().error->safe_detail());

  ASSERT_TRUE(first.value_if()->send_lan_signaling(
      LanSignalingMessage{.peer = peer,
                          .kind = LanSignalingMessageKind::signed_offer,
                          .request_id = request_id(3U),
                          .payload = {std::byte{0x42U}}}));
  EXPECT_TRUE(wait_until(
      [&] {
        return validated.load(std::memory_order_relaxed) == 2U &&
               signed_received.load(std::memory_order_relaxed) == 1U;
      },
      std::chrono::seconds{2}));

  ASSERT_TRUE(first.value_if()->send_lan_signaling(
      LanSignalingMessage{.peer = peer,
                          .kind = LanSignalingMessageKind::signed_candidate,
                          .request_id = request_id(4U),
                          .payload = {std::byte{0x41U}}}));
  EXPECT_TRUE(wait_until(
      [&] {
        const auto connections = first.value_if()->signaling_connections();
        return std::any_of(connections.begin(), connections.end(),
                           [](const auto& connection) {
                             return connection.state ==
                                        LanSignalingConnectionState::failed &&
                                    connection.error &&
                                    connection.error->safe_detail() ==
                                        "signed_signal_invalid";
                           });
      },
      std::chrono::seconds{2}));

  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
}

TEST_F(M3aNodeTest, NodeAutomaticallyAssemblesAuthenticatedWebRtcPeerSession) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  auto first_profile = initialized_profile("m4-node-first", "com.example.m4.first",
                                           configuration);
  auto second_profile = initialized_profile("m4-node-second", "com.example.m4.second",
                                            configuration);
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));

  auto first = Node::create(
      node_config(*first_profile.value_if(), "com.example.m4.first"));
  auto second = Node::create(
      node_config(*second_profile.value_if(), "com.example.m4.second"));
  ASSERT_TRUE(first && second);
  const auto first_node = first.value_if()->snapshot();
  const auto second_node = second.value_if()->snapshot();
  if (first_node.interfaces.empty() || second_node.interfaces.empty()) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    if (environment_enabled("HEYAKI_REQUIRE_LAN_INTERFACES")) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  ASSERT_TRUE(wait_until(
      [&] {
        return first.value_if()->endpoints().size() == 1U &&
               second.value_if()->endpoints().size() == 1U;
      },
      std::chrono::seconds{4}));
  const auto peer = first.value_if()->endpoints().front().key;
  ASSERT_TRUE(first.value_if()->connect_lan(peer));
  const bool authenticated = wait_until(
      [&] {
        const auto first_sessions = first.value_if()->peer_sessions();
        const auto second_sessions = second.value_if()->peer_sessions();
        return first_sessions.size() == 1U && second_sessions.size() == 1U &&
               first_sessions.front().state == NodePeerSessionState::authenticated &&
               second_sessions.front().state == NodePeerSessionState::authenticated;
      },
      std::chrono::seconds{10});
  const auto first_sessions = first.value_if()->peer_sessions();
  const auto second_sessions = second.value_if()->peer_sessions();
  ASSERT_TRUE(authenticated)
      << "first_node_error="
      << (first.value_if()->snapshot().last_error
              ? first.value_if()->snapshot().last_error->safe_detail()
              : "none")
      << " second_node_error="
      << (second.value_if()->snapshot().last_error
              ? second.value_if()->snapshot().last_error->safe_detail()
              : "none")
      << " first_sessions=" << first_sessions.size()
      << " second_sessions=" << second_sessions.size();
  ASSERT_EQ(first_sessions.size(), 1U);
  ASSERT_EQ(second_sessions.size(), 1U);
  EXPECT_EQ(first_sessions.front().session_id, second_sessions.front().session_id);
  EXPECT_EQ(first_sessions.front().request_id, second_sessions.front().request_id);
  EXPECT_NE(first_sessions.front().initiator, second_sessions.front().initiator);
  EXPECT_FALSE(first_sessions.front().error);
  EXPECT_FALSE(second_sessions.front().error);
  EXPECT_EQ(first_sessions.front().signaling_route, SignalingRouteKind::lan);
  EXPECT_EQ(first_sessions.front().connection_stage,
            NodeConnectionStage::authenticated);
  EXPECT_EQ(second_sessions.front().connection_stage,
            NodeConnectionStage::authenticated);
  EXPECT_EQ(first_sessions.front().data_path, NodeDataPathKind::direct_host);
  EXPECT_EQ(second_sessions.front().data_path, NodeDataPathKind::direct_host);
  EXPECT_FALSE(first_sessions.front().selected_candidate.empty());
  EXPECT_FALSE(second_sessions.front().selected_candidate.empty());
  EXPECT_EQ(node_peer_session_state_name(first_sessions.front().state),
            "authenticated");
  EXPECT_EQ(node_connection_stage_name(first_sessions.front().connection_stage),
            "authenticated");
  EXPECT_EQ(node_data_path_kind_name(first_sessions.front().data_path),
            "direct_host");

  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
  EXPECT_TRUE(first.value_if()->peer_sessions().empty());
  EXPECT_TRUE(second.value_if()->peer_sessions().empty());
}

TEST_F(M3aNodeTest, AuthenticatedSessionReestablishesNewPhysicalSessionAfterLoss) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.auto_connect_trusted = true;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  auto first_profile =
      initialized_profile("reconnect-first", "com.example.reconnect.first",
                          configuration);
  auto second_profile =
      initialized_profile("reconnect-second", "com.example.reconnect.second",
                          configuration);
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));
  ASSERT_TRUE(trust_peer(*first_profile.value_if(),
                         second_profile.value_if()->device_id(), 1U));
  ASSERT_TRUE(trust_peer(*second_profile.value_if(),
                         first_profile.value_if()->device_id(), 2U));

  auto first = Node::create(
      node_config(*first_profile.value_if(), "com.example.reconnect.first"));
  auto second = Node::create(
      node_config(*second_profile.value_if(), "com.example.reconnect.second"));
  ASSERT_TRUE(first && second);
  std::optional<Node> second_node{std::move(*second.value_if())};
  const auto first_snapshot = first.value_if()->snapshot();
  const auto second_snapshot = second_node->snapshot();
  if (first_snapshot.interfaces.empty() || second_snapshot.interfaces.empty()) {
    (void)first.value_if()->shutdown();
    (void)second_node->shutdown();
    if (environment_enabled("HEYAKI_REQUIRE_LAN_INTERFACES")) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  const auto second_key = DeviceEndpointKey{second_node->snapshot().device_id,
                                            second_node->snapshot().endpoint_id};
  const auto first_key = DeviceEndpointKey{first.value_if()->snapshot().device_id,
                                           first.value_if()->snapshot().endpoint_id};
  const auto discovered = [](const Node& node, const DeviceEndpointKey& peer) {
    const auto entries = node.endpoints();
    return std::any_of(entries.begin(), entries.end(),
                       [&](const auto& entry) { return entry.key == peer; });
  };
  ASSERT_TRUE(wait_until(
      [&] {
        return discovered(*first.value_if(), second_key) &&
               discovered(*second_node, first_key);
      },
      std::chrono::seconds{15}));
  ASSERT_TRUE(first.value_if()->connect_lan(second_key));
  // The 20 s budget flaked on a loaded ASan runner (run 32546019506): the
  // full re-signaling after peer destruction plus the WebRTC handshake can
  // exceed it under sanitizer overhead, so match the widened relay budgets.
  ASSERT_TRUE(wait_until(
      [&] {
        const auto first_sessions = first.value_if()->peer_sessions();
        const auto second_sessions = second_node->peer_sessions();
        const auto authenticated = [](const NodePeerSessionSnapshot& session) {
          return session.state == NodePeerSessionState::authenticated;
        };
        return std::any_of(first_sessions.begin(), first_sessions.end(),
                           authenticated) &&
               std::any_of(second_sessions.begin(), second_sessions.end(),
                           authenticated);
      },
      std::chrono::seconds{35}));
  const auto first_sessions = first.value_if()->peer_sessions();
  const auto first_authenticated = std::find_if(
      first_sessions.begin(), first_sessions.end(),
      [](const NodePeerSessionSnapshot& session) {
        return session.state == NodePeerSessionState::authenticated;
      });
  ASSERT_NE(first_authenticated, first_sessions.end());
  const auto original_request_id = first_authenticated->request_id;
  const auto original_session_id = first_authenticated->session_id;

  // Destroy the peer entirely: the authenticated association is lost, so the
  // local session must reach an explicit closed state with an error rather
  // than pretending the connection still exists.
  EXPECT_TRUE(second_node->shutdown().stopped);
  second_node.reset();
  ASSERT_TRUE(wait_until(
      [&] {
        const auto sessions = first.value_if()->peer_sessions();
        return std::any_of(sessions.begin(), sessions.end(),
                           [&](const NodePeerSessionSnapshot& session) {
                             return session.request_id == original_request_id &&
                                    session.state == NodePeerSessionState::closed &&
                                    session.error.has_value();
                           });
      },
      std::chrono::seconds{5}));

  // Restart the peer from the same profile: identical DeviceId/EndpointId but
  // a new boot nonce and TLS port. The relationship must return as a NEW
  // physical session with fresh request and session IDs.
  auto second_again = Node::create(
      node_config(*second_profile.value_if(), "com.example.reconnect.second"));
  ASSERT_TRUE(second_again);
  const auto restored = wait_until(
      [&] {
        const auto sessions = first.value_if()->peer_sessions();
        return std::any_of(
            sessions.begin(), sessions.end(),
            [&](const NodePeerSessionSnapshot& session) {
              return session.state == NodePeerSessionState::authenticated &&
                     session.request_id != original_request_id &&
                     session.session_id != original_session_id;
            });
      },
      std::chrono::seconds{15});
  ASSERT_TRUE(restored)
      << "node did not re-establish a new physical session after peer restart";
  ASSERT_TRUE(wait_until(
      [&] {
        const auto sessions = second_again.value_if()->peer_sessions();
        return std::any_of(sessions.begin(), sessions.end(),
                           [](const NodePeerSessionSnapshot& session) {
                             return session.state ==
                                    NodePeerSessionState::authenticated;
                           });
      },
      std::chrono::seconds{10}));
  const auto reestablished = first.value_if()->peer_sessions();
  const auto new_session = std::find_if(
      reestablished.begin(), reestablished.end(),
      [](const NodePeerSessionSnapshot& session) {
        return session.state == NodePeerSessionState::authenticated;
      });
  ASSERT_NE(new_session, reestablished.end());
  EXPECT_EQ(new_session->request_id, second_again.value_if()
                                        ->peer_sessions()
                                        .front()
                                        .request_id);
  // The lost session stays in diagnostics as an explicit closed failure: the
  // re-establishment is a new physical session, not lossless migration.
  const auto lost_session = std::find_if(
      reestablished.begin(), reestablished.end(),
      [&](const NodePeerSessionSnapshot& session) {
        return session.request_id == original_request_id;
      });
  ASSERT_NE(lost_session, reestablished.end());
  EXPECT_EQ(lost_session->state, NodePeerSessionState::closed);
  EXPECT_TRUE(lost_session->error.has_value());

  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second_again.value_if()->shutdown().stopped);
}

TEST_F(M3aNodeTest, ThreeLanNodesEstablishAuthenticatedHostDataChannels) {
  // M4 Connectivity MVP exit condition: with relay/STUN/TURN entirely absent
  // (lan_only configures no ICE server and host-only candidates), three
  // devices on one LAN discover the correct endpoints and build authenticated
  // DataChannels over host candidates for every pair.
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  auto first_profile =
      initialized_profile("mesh-first", "com.example.mesh.first", configuration);
  auto second_profile =
      initialized_profile("mesh-second", "com.example.mesh.second", configuration);
  auto third_profile =
      initialized_profile("mesh-third", "com.example.mesh.third", configuration);
  ASSERT_TRUE(first_profile && second_profile && third_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *third_profile.value_if(),
                                              {"m4.test"}));
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*second_profile.value_if(),
                                              *third_profile.value_if(),
                                              {"m4.test"}));

  auto first = Node::create(node_config(*first_profile.value_if(),
                                        "com.example.mesh.first"));
  auto second = Node::create(node_config(*second_profile.value_if(),
                                         "com.example.mesh.second"));
  auto third = Node::create(node_config(*third_profile.value_if(),
                                        "com.example.mesh.third"));
  ASSERT_TRUE(first && second && third);
  const bool interfaces_missing =
      first.value_if()->snapshot().interfaces.empty() ||
      second.value_if()->snapshot().interfaces.empty() ||
      third.value_if()->snapshot().interfaces.empty();
  if (interfaces_missing) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    (void)third.value_if()->shutdown();
    if (environment_enabled("HEYAKI_REQUIRE_LAN_INTERFACES")) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  // Each device must discover the other two specific endpoints; other LAN
  // tests may announce concurrently on the same multicast group, so exact
  // directory sizes are not asserted.
  const auto discovered = [](const Node& node, const DeviceEndpointKey& peer) {
    const auto entries = node.endpoints();
    return std::any_of(entries.begin(), entries.end(),
                       [&](const auto& entry) { return entry.key == peer; });
  };
  const auto second_key = DeviceEndpointKey{
      second.value_if()->snapshot().device_id,
      second.value_if()->snapshot().endpoint_id};
  const auto third_key = DeviceEndpointKey{third.value_if()->snapshot().device_id,
                                           third.value_if()->snapshot().endpoint_id};
  ASSERT_TRUE(wait_until(
      [&] {
        return discovered(*first.value_if(), second_key) &&
               discovered(*first.value_if(), third_key) &&
               discovered(*second.value_if(),
                          DeviceEndpointKey{first.value_if()->snapshot().device_id,
                                            first.value_if()->snapshot().endpoint_id}) &&
               discovered(*second.value_if(), third_key) &&
               discovered(*third.value_if(),
                          DeviceEndpointKey{first.value_if()->snapshot().device_id,
                                            first.value_if()->snapshot().endpoint_id}) &&
               discovered(*third.value_if(), second_key);
      },
      std::chrono::seconds{6}));

  const auto first_key = DeviceEndpointKey{first.value_if()->snapshot().device_id,
                                           first.value_if()->snapshot().endpoint_id};

  // Establish all three pairings; every logical pair must reach mutual
  // authenticated state over a direct host data path with its own session.
  ASSERT_TRUE(first.value_if()->connect_lan(second_key));
  ASSERT_TRUE(first.value_if()->connect_lan(third_key));
  ASSERT_TRUE(second.value_if()->connect_lan(third_key));

  const auto authenticated_sessions_for = [](const Node& node,
                                             DeviceEndpointKey peer) {
    const auto sessions = node.peer_sessions();
    return std::count_if(sessions.begin(), sessions.end(),
                         [&](const NodePeerSessionSnapshot& session) {
                           return session.peer == peer &&
                                  session.state ==
                                      NodePeerSessionState::authenticated;
                         });
  };
  ASSERT_TRUE(wait_until(
      [&] {
        return authenticated_sessions_for(*first.value_if(), second_key) == 1U &&
               authenticated_sessions_for(*first.value_if(), third_key) == 1U &&
               authenticated_sessions_for(*second.value_if(), first_key) == 1U &&
               authenticated_sessions_for(*second.value_if(), third_key) == 1U &&
               authenticated_sessions_for(*third.value_if(), first_key) == 1U &&
               authenticated_sessions_for(*third.value_if(), second_key) == 1U;
      },
      std::chrono::seconds{15}));

  const auto assert_host_session = [&](const Node& node,
                                       DeviceEndpointKey peer) {
    const auto sessions = node.peer_sessions();
    const auto session = std::find_if(
        sessions.begin(), sessions.end(), [&](const NodePeerSessionSnapshot& item) {
          return item.peer == peer &&
                 item.state == NodePeerSessionState::authenticated;
        });
    ASSERT_NE(session, sessions.end());
    EXPECT_EQ(session->data_path, NodeDataPathKind::direct_host);
    EXPECT_FALSE(session->selected_candidate.empty());
    EXPECT_FALSE(session->error.has_value());
  };
  assert_host_session(*first.value_if(), second_key);
  assert_host_session(*first.value_if(), third_key);
  assert_host_session(*second.value_if(), first_key);
  assert_host_session(*second.value_if(), third_key);
  assert_host_session(*third.value_if(), first_key);
  assert_host_session(*third.value_if(), second_key);

  // Each pairing owns a distinct session: no cross-wiring between the three
  // simultaneous attempts.
  const auto first_sessions = first.value_if()->peer_sessions();
  std::vector<SessionId> first_session_ids;
  for (const auto& session : first_sessions) {
    if (session.state == NodePeerSessionState::authenticated) {
      first_session_ids.push_back(session.session_id);
    }
  }
  ASSERT_EQ(first_session_ids.size(), 2U);
  EXPECT_NE(first_session_ids[0], first_session_ids[1]);

  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
  EXPECT_TRUE(third.value_if()->shutdown().stopped);
}

TEST_F(M3aNodeTest, RepeatedAssociationLossCyclesStayBounded) {
  // M4 leak evidence for the session layer: repeated loss/re-establishment
  // cycles must drain signaling connections, keep one merged directory entry
  // per peer endpoint, and bound the diagnostic session history.
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.auto_connect_trusted = true;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  auto first_profile = initialized_profile("cycle-first", "com.example.cycle.first",
                                           configuration);
  auto second_profile = initialized_profile("cycle-second", "com.example.cycle.second",
                                            configuration);
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));
  ASSERT_TRUE(trust_peer(*first_profile.value_if(),
                         second_profile.value_if()->device_id(), 1U));
  ASSERT_TRUE(trust_peer(*second_profile.value_if(),
                         first_profile.value_if()->device_id(), 2U));

  auto first = Node::create(
      node_config(*first_profile.value_if(), "com.example.cycle.first"));
  ASSERT_TRUE(first);
  const auto first_state = first.value_if()->snapshot();
  if (first_state.interfaces.empty()) {
    (void)first.value_if()->shutdown();
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  std::optional<Node> peer_node;
  const auto start_peer = [&]() {
    auto second = Node::create(
        node_config(*second_profile.value_if(), "com.example.cycle.second"));
    EXPECT_TRUE(second);
    peer_node.emplace(std::move(*second.value_if()));
  };
  const auto stop_peer = [&]() {
    ASSERT_TRUE(peer_node.has_value());
    EXPECT_TRUE(peer_node->shutdown().stopped);
    peer_node.reset();
  };

  constexpr std::size_t kCycles = 5U;
  std::optional<SessionId> previous_session;
  for (std::size_t cycle = 0U; cycle < kCycles; ++cycle) {
    start_peer();
    ASSERT_TRUE(peer_node.has_value());
    const auto peer_state = peer_node->snapshot();
    if (peer_state.interfaces.empty()) {
      stop_peer();
      (void)first.value_if()->shutdown();
      GTEST_SKIP() << "No multicast-capable non-loopback interface";
    }
    const auto peer_key = DeviceEndpointKey{peer_state.device_id,
                                            peer_state.endpoint_id};
    const auto discovered = [&](const Node& node, const DeviceEndpointKey& key) {
      const auto entries = node.endpoints();
      return std::any_of(entries.begin(), entries.end(),
                         [&](const auto& entry) { return entry.key == key; });
    };
    ASSERT_TRUE(wait_until(
        [&] { return discovered(*first.value_if(), peer_key); },
        std::chrono::seconds{4}))
        << "cycle " << cycle << ": peer not discovered";
    if (cycle == 0U) {
      ASSERT_TRUE(first.value_if()->connect_lan(peer_key));
    }
    ASSERT_TRUE(wait_until(
        [&] {
          const auto sessions = first.value_if()->peer_sessions();
          return std::any_of(sessions.begin(), sessions.end(),
                             [&](const NodePeerSessionSnapshot& session) {
                               return session.state ==
                                          NodePeerSessionState::authenticated &&
                                      (!previous_session ||
                                       session.session_id != *previous_session);
                             });
        },
        std::chrono::seconds{12}))
        << "cycle " << cycle << ": no fresh authenticated session";
    const auto sessions = first.value_if()->peer_sessions();
    const auto active = std::find_if(
        sessions.begin(), sessions.end(),
        [](const NodePeerSessionSnapshot& session) {
          return session.state == NodePeerSessionState::authenticated;
        });
    ASSERT_NE(active, sessions.end());
    previous_session = active->session_id;

    // The peer endpoint stays a single merged entry across boot nonce changes.
    const auto entries = first.value_if()->endpoints();
    EXPECT_EQ(std::count_if(entries.begin(), entries.end(),
                            [&](const auto& entry) {
                              return entry.key == peer_key;
                            }),
              1U)
        << "cycle " << cycle << ": directory entry duplicated";

    stop_peer();
    ASSERT_TRUE(wait_until(
        [&] {
          const auto current = first.value_if()->peer_sessions();
          return std::any_of(current.begin(), current.end(),
                             [&](const NodePeerSessionSnapshot& session) {
                               return session.session_id == *previous_session &&
                                      session.state ==
                                          NodePeerSessionState::closed &&
                                      session.error.has_value();
                             });
        },
        std::chrono::seconds{5}))
        << "cycle " << cycle << ": lost session did not reach terminal state";
    // Failed immediate re-establishment attempts must drain: no live TLS
    // signaling connections linger while the peer is gone, and the
    // coordinator holds no open attempts between cycles.
    ASSERT_TRUE(wait_until(
        [&] {
          return first.value_if()->snapshot().resources.signaling_connections ==
                     0U &&
                 first.value_if()
                         ->snapshot()
                         .session_coordinator.current_attempts == 0U;
        },
        std::chrono::seconds{5}))
        << "cycle " << cycle << ": signaling connections did not drain";
    // The replay guard is bounded: entries accumulate only within capacity
    // across every loss/re-establishment round.
    const auto coordinator_state =
        first.value_if()->snapshot().session_coordinator;
    EXPECT_LE(coordinator_state.replay_current_entries, 4096U);
    EXPECT_LE(coordinator_state.peak_attempts, 8U);
  }

  // Diagnostic history stays bounded by the cycle count plus one active try.
  const auto final_sessions = first.value_if()->peer_sessions();
  EXPECT_LE(final_sessions.size(), kCycles * 2U + 1U);
  const auto closed_with_error = std::count_if(
      final_sessions.begin(), final_sessions.end(),
      [](const NodePeerSessionSnapshot& session) {
        return session.state == NodePeerSessionState::closed &&
               session.error.has_value();
      });
  EXPECT_EQ(closed_with_error, kCycles);
  EXPECT_TRUE(first.value_if()->shutdown().stopped);
}

TEST_F(M3aNodeTest, TrustedAutoConnectUsesOnlyTheTupleOfferOwner) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.auto_connect_trusted = true;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  auto first_profile = initialized_profile("auto-first", "com.example.first",
                                           configuration);
  auto second_profile = initialized_profile("auto-second", "com.example.second",
                                            configuration);
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));
  ASSERT_TRUE(trust_peer(*first_profile.value_if(),
                         second_profile.value_if()->device_id(), 1U));
  ASSERT_TRUE(trust_peer(*second_profile.value_if(),
                         first_profile.value_if()->device_id(), 2U));

  auto signaling_handler = [](const LanSignalingMessage&) {
    return Result<void>::success();
  };
  auto first = Node::create(
      node_config(*first_profile.value_if(), "com.example.first", {},
                  signaling_handler));
  auto second = Node::create(
      node_config(*second_profile.value_if(), "com.example.second", {},
                  signaling_handler));
  ASSERT_TRUE(first && second);
  const auto first_snapshot = first.value_if()->snapshot();
  const auto second_snapshot = second.value_if()->snapshot();
  if (std::none_of(first_snapshot.interfaces.begin(), first_snapshot.interfaces.end(),
                   [](const auto& interface) { return interface.joined; }) ||
      std::none_of(second_snapshot.interfaces.begin(), second_snapshot.interfaces.end(),
                   [](const auto& interface) { return interface.joined; })) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    if (environment_enabled("HEYAKI_REQUIRE_LAN_INTERFACES")) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  ASSERT_TRUE(wait_until(
      [&] {
        const auto first_connections = first.value_if()->signaling_connections();
        const auto second_connections = second.value_if()->signaling_connections();
        const auto authenticated = [](const auto& connection) {
          return connection.state == LanSignalingConnectionState::authenticated;
        };
        return std::count_if(first_connections.begin(), first_connections.end(),
                             authenticated) == 1 &&
               std::count_if(second_connections.begin(), second_connections.end(),
                             authenticated) == 1;
      },
      std::chrono::seconds{4}));

  const auto first_key = DeviceEndpointKey{first_snapshot.device_id,
                                           first_snapshot.endpoint_id};
  const auto second_key = DeviceEndpointKey{second_snapshot.device_id,
                                            second_snapshot.endpoint_id};
  const bool first_owner = is_lan_offer_owner(first_key, second_key);
  const auto first_connections = first.value_if()->signaling_connections();
  const auto second_connections = second.value_if()->signaling_connections();
  const auto first_active = std::find_if(
      first_connections.begin(), first_connections.end(), [](const auto& connection) {
        return connection.state == LanSignalingConnectionState::authenticated;
      });
  const auto second_active = std::find_if(
      second_connections.begin(), second_connections.end(), [](const auto& connection) {
        return connection.state == LanSignalingConnectionState::authenticated;
      });
  ASSERT_NE(first_active, first_connections.end());
  ASSERT_NE(second_active, second_connections.end());
  EXPECT_EQ(first_active->inbound, !first_owner);
  EXPECT_EQ(second_active->inbound, first_owner);
  EXPECT_EQ(first_active->local_offer_owner, first_owner);
  EXPECT_EQ(second_active->local_offer_owner, !first_owner);

  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
}

TEST_F(M3aNodeTest, RepeatedConnectCloseRemainsBounded) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.announcement_interval = std::chrono::milliseconds{50};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{5};
  configuration.diagnostic_capacity = 8U;
  configuration.provisional_connection_capacity = 8U;
  configuration.per_source_provisional_capacity = 8U;
  configuration.provisional_accept_rate_per_second = 100U;
  configuration.per_source_provisional_rate = 100U;
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  auto first_profile = initialized_profile("stress-first", "com.example.stress.first",
                                           configuration);
  auto second_profile = initialized_profile("stress-second", "com.example.stress.second",
                                            configuration);
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));
  auto signaling_handler = [](const LanSignalingMessage&) {
    return Result<void>::success();
  };
  auto first = Node::create(node_config(*first_profile.value_if(),
                                        "com.example.stress.first", {},
                                        signaling_handler));
  auto second = Node::create(node_config(*second_profile.value_if(),
                                         "com.example.stress.second", {},
                                         signaling_handler));
  ASSERT_TRUE(first && second);
  if (joined_interface_count(first.value_if()->snapshot()) == 0U ||
      joined_interface_count(second.value_if()->snapshot()) == 0U) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    if (environment_enabled("HEYAKI_REQUIRE_LAN_INTERFACES")) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  ASSERT_TRUE(wait_until(
      [&] {
        return first.value_if()->endpoints().size() == 1U &&
               second.value_if()->endpoints().size() == 1U;
      },
      std::chrono::seconds{4}));
  const auto peer = first.value_if()->endpoints().front().key;
  const DeviceEndpointKey local{
      first.value_if()->snapshot().device_id,
      first.value_if()->snapshot().endpoint_id};

  for (std::size_t cycle = 0U; cycle < 12U; ++cycle) {
    ASSERT_TRUE(first.value_if()->connect_lan(peer));
    ASSERT_TRUE(wait_until(
        [&] {
          return has_authenticated_connection(*first.value_if(), peer) &&
                 has_authenticated_connection(*second.value_if(), local);
        },
        std::chrono::seconds{2}));
    ASSERT_TRUE(first.value_if()->close_lan(peer));
    ASSERT_TRUE(wait_until(
        [&] {
          return !has_authenticated_connection(*first.value_if(), peer) &&
                 !has_authenticated_connection(*second.value_if(), local);
        },
        std::chrono::seconds{2}));
  }

  const auto first_connections = first.value_if()->signaling_connections();
  const auto second_connections = second.value_if()->signaling_connections();
  EXPECT_LE(first_connections.size(), configuration.diagnostic_capacity);
  EXPECT_LE(second_connections.size(), configuration.diagnostic_capacity);
  EXPECT_EQ(first.value_if()->snapshot().tls.provisional_connections, 0U);
  EXPECT_EQ(first.value_if()->snapshot().tls.authenticated_connections, 0U);
  EXPECT_EQ(second.value_if()->snapshot().tls.provisional_connections, 0U);
  EXPECT_EQ(second.value_if()->snapshot().tls.authenticated_connections, 0U);
  EXPECT_TRUE(first.value_if()->shutdown().stopped);
  EXPECT_TRUE(second.value_if()->shutdown().stopped);
}

TEST_F(M3aNodeTest, LanLifecyclePressureRemainsBounded) {
  const std::size_t cycles =
      environment_size("HEYAKI_M3A_STRESS_CYCLES").value_or(8U);
  const std::size_t epochs =
      environment_size("HEYAKI_M3A_STRESS_EPOCHS").value_or(2U);
  ASSERT_GE(cycles, 1U);
  ASSERT_LE(cycles, 256U);
  ASSERT_GE(epochs, 1U);
  ASSERT_LE(epochs, 4U);

  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.announcement_interval = std::chrono::milliseconds{50};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::milliseconds{100};
  configuration.diagnostic_capacity = 8U;
  configuration.directory_capacity = 32U;
  configuration.trusted_directory_reserve = 1U;
  configuration.per_interface_directory_capacity = 32U;
  configuration.per_source_presence_capacity = 32U;
  configuration.unknown_identity_capacity = 31U;
  configuration.replay_capacity = 32U;
  configuration.provisional_connection_capacity = 8U;
  configuration.per_source_provisional_capacity = 8U;
  configuration.pending_signaling_capacity = 8U;
  configuration.auto_connect_capacity = 8U;
  configuration.provisional_accept_rate_per_second = 1000U;
  configuration.per_source_provisional_rate = 1000U;
  configuration.announcement_rate_per_second = 1000U;
  configuration.per_source_announcement_rate = 1000U;

  auto first_profile = initialized_profile("lifecycle-first",
                                           "com.example.lifecycle.first",
                                           configuration);
  auto second_profile = initialized_profile("lifecycle-second",
                                            "com.example.lifecycle.second",
                                            configuration);
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));

  RuntimeConfig runtime_configuration;
  runtime_configuration.shutdown_hook_capacity = 32U;
  runtime_configuration.executor_queue_capacity = 64U;
  runtime_configuration.executor_min_threads = 2U;
  runtime_configuration.executor_max_threads = 4U;
  runtime_configuration.worker_name = "heyaki-m3a-pressure";
  auto runtime = Runtime::create_owned(runtime_configuration);
  ASSERT_TRUE(runtime) << runtime.error_if()->safe_detail();

  executor::comm::PhaseGate delivered{"m3a-pressure-delivered"};
  auto first_handler = [](const LanSignalingMessage&) {
    return Result<void>::success();
  };
  auto second_handler = [&](const LanSignalingMessage&) {
    (void)delivered.advance_to(delivered.current_phase() + 1U);
    return Result<void>::success();
  };
  auto first = Node::create(node_config(*first_profile.value_if(),
                                        "com.example.lifecycle.first", {},
                                        first_handler, runtime.value_if()));
  ASSERT_TRUE(first) << first.error_if()->safe_detail();
  if (joined_interface_count(first.value_if()->snapshot()) == 0U) {
    (void)first.value_if()->shutdown();
    (void)runtime.value_if()->shutdown();
    if (environment_enabled("HEYAKI_REQUIRE_LAN_INTERFACES")) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  std::optional<std::size_t> running_backend_count;
  std::uint64_t expected_deliveries = 0U;
  for (std::size_t epoch = 0U; epoch < epochs; ++epoch) {
    auto second = Node::create(node_config(*second_profile.value_if(),
                                           "com.example.lifecycle.second", {},
                                           second_handler, runtime.value_if()));
    ASSERT_TRUE(second) << second.error_if()->safe_detail();
    ASSERT_GT(joined_interface_count(second.value_if()->snapshot()), 0U);
    ASSERT_TRUE(wait_until(
        [&] {
          return first.value_if()->snapshot().lan_state ==
                     LanReadinessState::ready &&
                 second.value_if()->snapshot().lan_state ==
                     LanReadinessState::ready &&
                 first.value_if()->endpoints().size() == 1U &&
                 second.value_if()->endpoints().size() == 1U;
        },
        std::chrono::seconds{4}));

    const auto first_key = DeviceEndpointKey{
        first.value_if()->snapshot().device_id,
        first.value_if()->snapshot().endpoint_id};
    const auto second_key = DeviceEndpointKey{
        second.value_if()->snapshot().device_id,
        second.value_if()->snapshot().endpoint_id};
    const bool first_offer_owner = is_lan_offer_owner(first_key, second_key);
    for (std::size_t cycle = 0U; cycle < cycles; ++cycle) {
      const bool cross_connect = cycle % 4U <= 1U;
      const bool cancel_while_connecting = cycle % 4U == 0U;
      if (cross_connect || first_offer_owner) {
        ASSERT_TRUE(first.value_if()->connect_lan(second_key));
      }
      if (cross_connect || !first_offer_owner) {
        ASSERT_TRUE(second.value_if()->connect_lan(first_key));
      }
      if (cancel_while_connecting) {
        ASSERT_TRUE(first.value_if()->close_lan(second_key));
        ASSERT_TRUE(second.value_if()->close_lan(first_key));
        executor::comm::PhaseGate cancellation_window{"m3a-pressure-cancel"};
        (void)cancellation_window.wait_for(1U, std::chrono::milliseconds{10});
        ASSERT_TRUE(first.value_if()->close_lan(second_key));
        ASSERT_TRUE(second.value_if()->close_lan(first_key));
      } else {
        ASSERT_TRUE(wait_until(
            [&] {
              return has_authenticated_connection(*first.value_if(), second_key) &&
                     has_authenticated_connection(*second.value_if(), first_key);
            },
            std::chrono::seconds{2}));
        if (!cross_connect) {
          ++expected_deliveries;
          ASSERT_TRUE(first.value_if()->send_lan_signaling(
              LanSignalingMessage{
                  .peer = second_key,
                  .kind = LanSignalingMessageKind::connect_request,
                  .request_id = request_id(static_cast<std::uint8_t>(
                      cycle % 255U + 1U)),
                  .payload = {}}));
          ASSERT_TRUE(delivered.wait_for(expected_deliveries,
                                         std::chrono::seconds{2}));
        }
        ASSERT_TRUE(first.value_if()->close_lan(second_key));
        ASSERT_TRUE(second.value_if()->close_lan(first_key));
      }
      ASSERT_TRUE(wait_until(
          [&] {
            const auto first_tls = first.value_if()->snapshot().tls;
            const auto second_tls = second.value_if()->snapshot().tls;
            return first_tls.provisional_connections == 0U &&
                   first_tls.authenticated_connections == 0U &&
                   second_tls.provisional_connections == 0U &&
                   second_tls.authenticated_connections == 0U;
          },
          std::chrono::seconds{2}));

      for (const auto* node : {first.value_if(), second.value_if()}) {
        const auto snapshot = node->snapshot();
        EXPECT_LE(snapshot.resources.discovery_sockets,
                  configuration.interface_capacity);
        EXPECT_LE(snapshot.resources.peak_discovery_sockets,
                  configuration.interface_capacity);
        EXPECT_LE(snapshot.resources.active_timers, 4U);
        EXPECT_LE(snapshot.resources.peak_active_timers, 4U);
        EXPECT_LE(snapshot.resources.signaling_connections,
                  configuration.provisional_connection_capacity);
        EXPECT_LE(snapshot.resources.peak_signaling_connections,
                  configuration.provisional_connection_capacity);
        EXPECT_LE(snapshot.resources.signaling_command_depth,
                  configuration.pending_signaling_capacity);
        EXPECT_LE(snapshot.resources.signaling_command_peak_depth,
                  configuration.pending_signaling_capacity);
        EXPECT_LE(snapshot.resources.signaling_result_depth,
                  configuration.pending_signaling_capacity);
        EXPECT_LE(snapshot.resources.signaling_result_peak_depth,
                  configuration.pending_signaling_capacity);
        EXPECT_LE(snapshot.resources.pending_outbound_messages,
                  configuration.pending_signaling_capacity);
        EXPECT_LE(snapshot.directory.current_entries,
                  configuration.directory_capacity);
        EXPECT_LE(snapshot.directory.peak_entries,
                  configuration.directory_capacity);
        EXPECT_LE(snapshot.directory.replay_entries,
                  configuration.replay_capacity);
        EXPECT_LE(snapshot.directory.source_rate_entries,
                  configuration.per_source_presence_capacity);
        const auto signaling_connections = node->signaling_connections();
        const auto finished_signaling = static_cast<std::size_t>(std::count_if(
            signaling_connections.begin(), signaling_connections.end(),
            [](const LanSignalingConnectionSnapshot& connection) {
              return connection.state == LanSignalingConnectionState::closed ||
                     connection.state == LanSignalingConnectionState::failed;
            }));
        EXPECT_LE(finished_signaling, configuration.diagnostic_capacity);
        EXPECT_LE(signaling_connections.size() - finished_signaling,
                  configuration.provisional_connection_capacity);
        EXPECT_LE(signaling_connections.size(),
                  configuration.diagnostic_capacity +
                      configuration.provisional_connection_capacity);
      }

      const auto runtime_snapshot = runtime.value_if()->snapshot();
      EXPECT_TRUE(runtime_snapshot.worker_ready);
      EXPECT_TRUE(runtime_snapshot.worker_running);
      EXPECT_FALSE(runtime_snapshot.executor_snapshot_partial);
      // M7 added the dedicated file I/O worker next to the asio worker.
      EXPECT_EQ(runtime_snapshot.executor_blocking_io_count, 2U);
      EXPECT_LE(runtime_snapshot.executor_active_task_count,
                runtime_configuration.executor_max_threads);
      EXPECT_LE(runtime_snapshot.executor_queued_task_count,
                runtime_configuration.executor_queue_capacity);
      EXPECT_EQ(runtime_snapshot.executor_submit_rejected_count, 0U);
      EXPECT_EQ(runtime_snapshot.executor_task_exception_count, 0U);
      if (!running_backend_count && cycle > 0U) {
        running_backend_count = runtime_snapshot.executor_running_backend_count;
      } else if (running_backend_count) {
        EXPECT_EQ(runtime_snapshot.executor_running_backend_count,
                  *running_backend_count);
      }
    }

    const auto second_shutdown = second.value_if()->shutdown();
    ASSERT_TRUE(second_shutdown.stopped);
    EXPECT_FALSE(second_shutdown.timed_out);
    EXPECT_EQ(second_shutdown.final_resources.discovery_sockets, 0U);
    EXPECT_FALSE(second_shutdown.final_resources.tls_listener_open);
    EXPECT_EQ(second_shutdown.final_resources.active_timers, 0U);
    EXPECT_EQ(second_shutdown.final_resources.signaling_connections, 0U);
    EXPECT_EQ(second_shutdown.final_resources.signaling_callbacks_in_flight, 0U);
    EXPECT_FALSE(second_shutdown.final_resources.interface_scan_in_flight);
    EXPECT_EQ(second_shutdown.final_resources.interface_scan_result_depth, 0U);
    EXPECT_EQ(second_shutdown.final_resources.signaling_command_depth, 0U);
    EXPECT_EQ(second_shutdown.final_resources.signaling_result_depth, 0U);
    EXPECT_EQ(second_shutdown.final_resources.pending_outbound_messages, 0U);

    ASSERT_TRUE(wait_until(
        [&] {
          const auto snapshot = first.value_if()->snapshot();
          return first.value_if()->endpoints().empty() &&
                 snapshot.directory.expired >= epoch + 1U;
        },
        std::chrono::seconds{3}));
    ASSERT_TRUE(wait_until(
        [&] {
          return first.value_if()->snapshot().directory.replay_entries == 0U;
        },
        std::chrono::seconds{4}));
  }

  const auto first_shutdown = first.value_if()->shutdown();
  ASSERT_TRUE(first_shutdown.stopped);
  EXPECT_FALSE(first_shutdown.timed_out);
  EXPECT_EQ(first_shutdown.final_resources.discovery_sockets, 0U);
  EXPECT_FALSE(first_shutdown.final_resources.tls_listener_open);
  EXPECT_EQ(first_shutdown.final_resources.active_timers, 0U);
  EXPECT_EQ(first_shutdown.final_resources.signaling_connections, 0U);
  EXPECT_EQ(first_shutdown.final_resources.signaling_callbacks_in_flight, 0U);
  EXPECT_FALSE(first_shutdown.final_resources.interface_scan_in_flight);
  EXPECT_EQ(first_shutdown.final_resources.interface_scan_result_depth, 0U);
  EXPECT_EQ(first_shutdown.final_resources.signaling_command_depth, 0U);
  EXPECT_EQ(first_shutdown.final_resources.signaling_result_depth, 0U);
  EXPECT_EQ(first_shutdown.final_resources.pending_outbound_messages, 0U);

  ASSERT_TRUE(wait_until(
      [&] {
        const auto snapshot = runtime.value_if()->snapshot();
        return snapshot.outstanding_operations == 0U &&
               snapshot.executor_active_task_count == 0U &&
               snapshot.executor_queued_task_count == 0U;
      },
      std::chrono::seconds{2}));
  const auto before_runtime_shutdown = runtime.value_if()->snapshot();
  EXPECT_TRUE(before_runtime_shutdown.worker_running);
  EXPECT_EQ(before_runtime_shutdown.executor_blocking_io_count, 2U);
  EXPECT_EQ(before_runtime_shutdown.executor_submit_rejected_count, 0U);
  EXPECT_EQ(before_runtime_shutdown.executor_task_exception_count, 0U);
  const auto runtime_shutdown = runtime.value_if()->shutdown();
  EXPECT_EQ(runtime_shutdown.final_phase, RuntimePhase::stopped);
  EXPECT_FALSE(runtime_shutdown.callback_drain_timed_out);
  EXPECT_FALSE(runtime_shutdown.operation_drain_timed_out);
  EXPECT_FALSE(runtime_shutdown.worker_stop_timed_out);
  EXPECT_FALSE(runtime_shutdown.executor_drain_timed_out);
  EXPECT_TRUE(runtime_shutdown.incomplete_operations.empty());
  const auto stopped_runtime = runtime.value_if()->snapshot();
  EXPECT_EQ(stopped_runtime.phase, RuntimePhase::stopped);
  EXPECT_FALSE(stopped_runtime.worker_running);
  EXPECT_EQ(stopped_runtime.outstanding_operations, 0U);
  EXPECT_EQ(stopped_runtime.executor_active_task_count, 0U);
  EXPECT_EQ(stopped_runtime.executor_queued_task_count, 0U);
}

TEST_F(M3aNodeTest, ShutdownDrainsPendingSignalingHandlerWithinBudget) {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  auto first_profile = initialized_profile("shutdown-first", "com.example.first",
                                           configuration);
  auto second_profile = initialized_profile("shutdown-second", "com.example.second",
                                            configuration);
  ASSERT_TRUE(first_profile && second_profile);
  ASSERT_TRUE(heyaki::test::seed_mutual_trust(*first_profile.value_if(),
                                              *second_profile.value_if(),
                                              {"m4.test"}));

  executor::comm::PhaseGate handler_entered{"m3a-handler-entered"};
  executor::comm::PhaseGate handler_release{"m3a-handler-release"};
  auto blocking_handler = [&](const LanSignalingMessage&) {
    (void)handler_entered.advance_to(1U);
    (void)handler_release.wait_for(1U, std::chrono::milliseconds{200});
    return Result<void>::success();
  };
  auto first = Node::create(
      node_config(*first_profile.value_if(), "com.example.first"));
  auto second = Node::create(node_config(*second_profile.value_if(),
                                         "com.example.second", {},
                                         blocking_handler));
  ASSERT_TRUE(first && second);
  const auto first_snapshot = first.value_if()->snapshot();
  const auto second_snapshot = second.value_if()->snapshot();
  if (std::none_of(first_snapshot.interfaces.begin(), first_snapshot.interfaces.end(),
                   [](const auto& interface) { return interface.joined; }) ||
      std::none_of(second_snapshot.interfaces.begin(), second_snapshot.interfaces.end(),
                   [](const auto& interface) { return interface.joined; })) {
    (void)first.value_if()->shutdown();
    (void)second.value_if()->shutdown();
    if (environment_enabled("HEYAKI_REQUIRE_LAN_INTERFACES")) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  ASSERT_TRUE(wait_until(
      [&] {
        return first.value_if()->endpoints().size() == 1U &&
               second.value_if()->endpoints().size() == 1U;
      },
      std::chrono::seconds{4}));
  const auto peer = first.value_if()->endpoints().front().key;
  ASSERT_TRUE(first.value_if()->connect_lan(peer));
  ASSERT_TRUE(wait_until(
      [&] { return has_authenticated_connection(*first.value_if(), peer); },
      std::chrono::seconds{4}));
  ASSERT_TRUE(first.value_if()->send_lan_signaling(
      LanSignalingMessage{.peer = peer,
                          .kind = LanSignalingMessageKind::connect_request,
                          .request_id = request_id(5U),
                          .payload = {}}));
  ASSERT_TRUE(handler_entered.wait_for(1U, std::chrono::seconds{2}));

  const auto started = std::chrono::steady_clock::now();
  const auto shutdown = second.value_if()->shutdown();
  const auto elapsed = std::chrono::steady_clock::now() - started;
  EXPECT_TRUE(shutdown.stopped)
      << "callbacks=" << shutdown.final_resources.signaling_callbacks_in_flight
      << " scan=" << shutdown.final_resources.interface_scan_in_flight
      << " sockets=" << shutdown.final_resources.discovery_sockets
      << " timers=" << shutdown.final_resources.active_timers
      << " connections=" << shutdown.final_resources.signaling_connections;
  EXPECT_FALSE(shutdown.timed_out)
      << "callbacks=" << shutdown.final_resources.signaling_callbacks_in_flight
      << " scan=" << shutdown.final_resources.interface_scan_in_flight;
  EXPECT_LT(elapsed, std::chrono::seconds{2});
  EXPECT_TRUE(first.value_if()->shutdown().stopped);
}

}  // namespace
}  // namespace heyaki
