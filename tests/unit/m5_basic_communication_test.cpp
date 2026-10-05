// HEY-20260930-003 (issue #4): opt-in basic communication on identity-verified,
// device-untrusted sessions. Node-level dual-instance tests over a real
// two-node LAN pair (harness modeled on m5_node_pairing_test.cpp) plus
// session-level wire tests over the loopback pair (modeled on
// m5_session_test.cpp, but building sessions through PeerSession::create so
// the basic-communication config fields are actually in force).
//
// Contracts under test:
//   - with the policy opted in on both ends, text messages and file pushes
//     into the configured receive roots flow WITHOUT any TrustGrant, while
//     the session stays pairing_restricted, the snapshot reports the policy
//     scopes (policy_scopes) disjoint from the grant set (authorized_scopes),
//     and neither TrustStore gains a record;
//   - a single-sided opt-in fails explicitly on the disabled end and never
//     delivers frames;
//   - RPC, events, shell, byte streams, and the gateway stay grant-only on
//     basic sessions;
//   - a successful pairing supersedes the policy (grant scopes replace
//     policy scopes; basic_communication clears);
//   - pushes into roots the serving side never configured fail without any
//     byte landing on disk;
//   - session level: basic sessions admit message/file domain frames, count
//     other domains as business violations, refuse non-basic send/open/adopt
//     with session_not_authorized, clear the policy state on pairing upgrade,
//     and fall back to the legacy pairing requirement when Capability::message
//     (or every basic-eligible capability) is not negotiated.

#include <heyaki/event.hpp>
#include <heyaki/file.hpp>
#include <heyaki/gateway.hpp>
#include <heyaki/lan_protocol.hpp>
#include <heyaki/message.hpp>
#include <heyaki/node.hpp>
#include <heyaki/pairing_protocol.hpp>
#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>
#include <heyaki/rpc.hpp>
#include <heyaki/trust_grant.hpp>

#include "m4_support.hpp"
#include "peer_session.hpp"

#include <kairo/comm.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace heyaki {
namespace {

constexpr std::uint64_t kNow = 1'700'000'000'000U;
constexpr const char* kApplicationId = "com.example.m5-basic-comm";
constexpr std::string_view kTargetPassword = "target-password";
constexpr std::string_view kInboxRoot = "inbox";

template <typename Storage, std::size_t Size = sizeof(Storage)>
Storage filled(std::uint8_t seed) {
  Storage storage{};
  auto* bytes = reinterpret_cast<std::uint8_t*>(&storage);
  for (std::size_t index = 0U; index < Size; ++index) {
    bytes[index] = static_cast<std::uint8_t>(seed + index);
  }
  return storage;
}

template <std::size_t Size>
std::array<std::byte, Size> filled_array(std::uint8_t seed) {
  std::array<std::byte, Size> value{};
  for (std::size_t index = 0U; index < Size; ++index) {
    value[index] = static_cast<std::byte>(seed + index);
  }
  return value;
}

std::vector<std::byte> text_bytes(std::string_view text) {
  auto bytes = std::vector<std::byte>{};
  bytes.reserve(text.size());
  for (const char character : text) {
    bytes.push_back(static_cast<std::byte>(character));
  }
  return bytes;
}

std::string file_content(const std::filesystem::path& path) {
  std::ifstream reader{path, std::ios::binary};
  return std::string{std::istreambuf_iterator<char>{reader},
                     std::istreambuf_iterator<char>{}};
}

bool directory_empty(const std::filesystem::path& directory) {
  if (!std::filesystem::exists(directory)) {
    return true;
  }
  return std::filesystem::is_empty(directory);
}

bool environment_requires_lan_interfaces() {
  const char* value = std::getenv("HEYAKI_REQUIRE_LAN_INTERFACES");
  return value != nullptr && std::string_view{value} == "1";
}

LanConfiguration fast_lan_only() {
  LanConfiguration configuration;
  configuration.connectivity_mode = ConnectivityMode::lan_only;
  configuration.announcement_interval = std::chrono::milliseconds{100};
  configuration.announcement_jitter = std::chrono::milliseconds{0};
  configuration.presence_lease = std::chrono::milliseconds{1000};
  configuration.interface_refresh_interval = std::chrono::seconds{2};
  configuration.announcement_rate_per_second = 100U;
  configuration.per_source_announcement_rate = 100U;
  return configuration;
}

FileRootConfig inbox_root(const std::filesystem::path& directory) {
  FileRootConfig root;
  root.name = std::string{kInboxRoot};
  root.directory = directory;
  root.max_file_bytes = 1024U * 1024U;
  root.max_total_bytes = 4U * 1024U * 1024U;
  root.max_concurrent_receives = 2U;
  return root;
}

// ---- thread-safe recorders (observers run on the node's strand) ----

struct RecordedAck {
  DeviceEndpointKey peer;
  MessageId message_id;
  MessageDeliveryEvent event{MessageDeliveryEvent::queued};
};

class AckRecorder {
 public:
  void attach(Node& node) {
    node.set_message_ack_observer(
        [this](const DeviceEndpointKey& peer, const MessageId& message_id,
               MessageDeliveryEvent event, std::optional<Error>) {
          RecordedAck recorded;
          recorded.peer = peer;
          recorded.message_id = message_id;
          recorded.event = event;
          const std::lock_guard<std::mutex> guard{mutex_};
          events_.push_back(std::move(recorded));
        });
  }

  [[nodiscard]] std::vector<RecordedAck> for_message(const MessageId& id) const {
    const std::lock_guard<std::mutex> guard{mutex_};
    auto matched = std::vector<RecordedAck>{};
    for (const auto& event : events_) {
      if (event.message_id == id) matched.push_back(event);
    }
    return matched;
  }

  [[nodiscard]] bool has_terminal_for(const MessageId& id) const {
    for (const auto& event : for_message(id)) {
      if (event.event != MessageDeliveryEvent::queued) return true;
    }
    return false;
  }

  [[nodiscard]] bool has_event_for(const MessageId& id,
                                   MessageDeliveryEvent event) const {
    for (const auto& recorded : for_message(id)) {
      if (recorded.event == event) return true;
    }
    return false;
  }

 private:
  mutable std::mutex mutex_;
  std::vector<RecordedAck> events_;
};

class InboundRecorder {
 public:
  void attach(Node& node) {
    node.set_message_inbound_handler(
        [this](const DeviceEndpointKey& peer, const MessageEnvelope& envelope) {
          const std::lock_guard<std::mutex> guard{mutex_};
          peers_.push_back(peer);
          types_.push_back(envelope.type);
          payloads_.push_back(envelope.payload);
        });
  }

  [[nodiscard]] std::size_t size() const {
    const std::lock_guard<std::mutex> guard{mutex_};
    return types_.size();
  }

  [[nodiscard]] bool contains(std::string_view type) const {
    const std::lock_guard<std::mutex> guard{mutex_};
    return std::any_of(types_.begin(), types_.end(),
                       [&](const auto& entry) { return entry == type; });
  }

  [[nodiscard]] std::vector<std::byte> payload_of(std::string_view type) const {
    const std::lock_guard<std::mutex> guard{mutex_};
    for (std::size_t index = 0U; index < types_.size(); ++index) {
      if (types_[index] == type) return payloads_[index];
    }
    return {};
  }

  [[nodiscard]] bool received_from(const DeviceEndpointKey& peer) const {
    const std::lock_guard<std::mutex> guard{mutex_};
    return std::any_of(peers_.begin(), peers_.end(),
                       [&](const auto& entry) { return entry == peer; });
  }

 private:
  mutable std::mutex mutex_;
  std::vector<DeviceEndpointKey> peers_;
  std::vector<std::string> types_;
  std::vector<std::vector<std::byte>> payloads_;
};

struct RecordedFileEvent {
  TransferId transfer_id;
  FileTransferPhase phase{FileTransferPhase::probing};
};

class FileEventRecorder {
 public:
  void attach(Node& node) {
    node.set_file_event_observer(
        [this](const DeviceEndpointKey&, const FileTransferEvent& event) {
          RecordedFileEvent recorded;
          recorded.transfer_id = event.transfer_id;
          recorded.phase = event.phase;
          const std::lock_guard<std::mutex> guard{mutex_};
          events_.push_back(std::move(recorded));
        });
  }

  [[nodiscard]] std::vector<RecordedFileEvent> for_transfer(
      const TransferId& id) const {
    const std::lock_guard<std::mutex> guard{mutex_};
    auto matched = std::vector<RecordedFileEvent>{};
    for (const auto& event : events_) {
      if (event.transfer_id == id) matched.push_back(event);
    }
    return matched;
  }

  [[nodiscard]] bool reached_phase(const TransferId& id,
                                   FileTransferPhase phase) const {
    for (const auto& event : for_transfer(id)) {
      if (event.phase == phase) return true;
    }
    return false;
  }

  [[nodiscard]] bool reached_any_of(const TransferId& id,
                                    std::initializer_list<FileTransferPhase>
                                        phases) const {
    for (const auto& event : for_transfer(id)) {
      for (const auto phase : phases) {
        if (event.phase == phase) return true;
      }
    }
    return false;
  }

  [[nodiscard]] bool any_committed() const {
    const std::lock_guard<std::mutex> guard{mutex_};
    return std::any_of(events_.begin(), events_.end(), [](const auto& event) {
      return event.phase == FileTransferPhase::committed;
    });
  }

  [[nodiscard]] std::size_t size() const {
    const std::lock_guard<std::mutex> guard{mutex_};
    return events_.size();
  }

 private:
  mutable std::mutex mutex_;
  std::vector<RecordedFileEvent> events_;
};

// Full-fidelity recorder for the issue #13 deadline contract: the error
// code/detail/status of the failed terminal matter, not just the phase.
class FullFileEventRecorder {
 public:
  void attach(Node& node) {
    node.set_file_event_observer(
        [this](const DeviceEndpointKey&, const FileTransferEvent& event) {
          const std::lock_guard<std::mutex> guard{mutex_};
          events_.push_back(event);
        });
  }

  [[nodiscard]] std::vector<FileTransferEvent> for_transfer(
      const TransferId& id) const {
    const std::lock_guard<std::mutex> guard{mutex_};
    auto matched = std::vector<FileTransferEvent>{};
    for (const auto& event : events_) {
      if (event.transfer_id == id) matched.push_back(event);
    }
    return matched;
  }

  [[nodiscard]] std::size_t terminal_count(const TransferId& id) const {
    const std::lock_guard<std::mutex> guard{mutex_};
    std::size_t terminals = 0U;
    for (const auto& event : events_) {
      if (event.transfer_id != id) continue;
      if (event.phase == FileTransferPhase::committed ||
          event.phase == FileTransferPhase::failed ||
          event.phase == FileTransferPhase::cancelled) {
        ++terminals;
      }
    }
    return terminals;
  }

  [[nodiscard]] std::optional<FileTransferEvent> failed_for(
      const TransferId& id) const {
    const std::lock_guard<std::mutex> guard{mutex_};
    std::optional<FileTransferEvent> found;
    for (const auto& event : events_) {
      if (event.transfer_id == id && event.phase == FileTransferPhase::failed) {
        found = event;
      }
    }
    return found;
  }

 private:
  mutable std::mutex mutex_;
  std::vector<FileTransferEvent> events_;
};

// ---- node-level LAN harness (A) ----

struct BasicNodePair {
  std::optional<ProfileStore> first_store;   // initiator (A)
  std::optional<ProfileStore> second_store;  // responder / target (B)
  std::optional<Node> first;
  std::optional<Node> second;
  DeviceEndpointKey first_key;
  DeviceEndpointKey second_key;
};

class M5BasicCommunicationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_M5_BASIC_COMM_TEST_STATE_DIR} /
            ("basic-" + std::to_string(
                            ::testing::UnitTest::GetInstance()->random_seed()));
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
    std::filesystem::create_directories(root_);
    std::filesystem::permissions(root_.parent_path(),
                                 std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    std::filesystem::permissions(root_, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
  }

  void TearDown() override {
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
  }

  Result<ProfileStore> initialized_profile(
      const std::string& name, std::optional<std::string_view> password,
      const std::vector<std::string>& policy_scopes) {
    ProfileOpenOptions options;
    options.secret_backend.prefer_os_backend = false;
    auto profile = ProfileStore::create(root_ / name / "profile.sqlite", options);
    if (!profile) {
      return profile;
    }
    PasswordVerifier verifier{.format_version = 1U,
                              .parameters = PasswordHashParameters{},
                              .encoded = "$argon2id$v=19$m=65536,t=2,p=1$test$test"};
    if (password.has_value()) {
      auto created = create_password_verifier(*password, PasswordHashParameters{});
      if (!created) {
        return Result<ProfileStore>::failure(*created.error_if());
      }
      verifier = std::move(*created.value_if());
    }
    PairingPolicy policy{};
    policy.default_scopes = policy_scopes;
    LocalProfileInitialization initialization{
        .application_id = kApplicationId,
        .password_verifier = std::move(verifier),
        .password_generation = 1U,
        .pairing_policy = policy,
        .lan = fast_lan_only()};
    auto initialized = profile.value_if()->initialize_local(initialization);
    if (!initialized) {
      return Result<ProfileStore>::failure(*initialized.error_if());
    }
    return profile;
  }

  struct PairOptions {
    bool first_basic{true};
    bool second_basic{true};
    bool second_password{false};
    std::vector<std::string> second_policy{};
    std::vector<ShellProfileConfig> second_shell_profiles{};
    // Issue #13 offer window on the INITIATOR; zero keeps the service
    // default of 30 s.
    std::chrono::milliseconds first_file_offer_timeout{std::chrono::milliseconds{0}};
  };

  static NodeConfig node_config(ProfileStore& store, bool basic,
                                std::vector<FileRootConfig> roots,
                                std::vector<ShellProfileConfig> shell_profiles,
                                std::chrono::milliseconds file_offer_timeout =
                                    std::chrono::milliseconds{0}) {
    return NodeConfig{.profile = &store,
                      .runtime = nullptr,
                      .application_id = kApplicationId,
                      .lan_override = fast_lan_only(),
                      .runtime_config = RuntimeConfig{},
                      .signaling_validator = {},
                      .signaling_handler = {},
                      .relay_override = std::nullopt,
                      .path_policy_override = std::nullopt,
                      .pairing_failure_threshold = 0U,
                      .pairing_backoff_base = std::chrono::milliseconds{0},
                      .pairing_backoff_max = std::chrono::milliseconds{0},
                      .pairing_grant_ttl_milliseconds = 0U,
                      .basic_communication = basic,
                      .pairing_deadline = std::chrono::milliseconds{0},
                      .event_subscriber_queue_items = 0U,
                      .event_max_subscriptions_per_peer = 0U,
                      .file_receive_roots = std::move(roots),
                      .file_max_peer_receive_bytes = 0U,
                      .file_offer_timeout = file_offer_timeout,
                      .shell_profiles = std::move(shell_profiles),
                      .gateway_profiles = {},
                      .gateway_confirm_sink = {}};
  }

  // Brings up a grant-less LAN pair whose sessions land in
  // pairing_restricted on both ends. Returns false when the environment
  // cannot host the pair.
  bool establish_pair(BasicNodePair& pair, const PairOptions& options) {
    auto first_profile = initialized_profile("basic-initiator", std::nullopt, {});
    auto second_profile = initialized_profile(
        "basic-target",
        options.second_password ? std::optional<std::string_view>{kTargetPassword}
                                : std::nullopt,
        options.second_policy);
    if (!first_profile || !second_profile) {
      return false;
    }
    pair.first_store.emplace(std::move(*first_profile.value_if()));
    pair.second_store.emplace(std::move(*second_profile.value_if()));

    std::filesystem::create_directories(root_ / "first-inbox");
    std::filesystem::create_directories(root_ / "second-inbox");
    auto first_node = Node::create(node_config(
        *pair.first_store, options.first_basic,
        {inbox_root(root_ / "first-inbox")}, {}, options.first_file_offer_timeout));
    auto second_node = Node::create(node_config(
        *pair.second_store, options.second_basic,
        {inbox_root(root_ / "second-inbox")}, options.second_shell_profiles));
    if (!first_node || !second_node) {
      return false;
    }
    pair.first.emplace(std::move(*first_node.value_if()));
    pair.second.emplace(std::move(*second_node.value_if()));
    if (pair.first.value().snapshot().interfaces.empty() ||
        pair.second.value().snapshot().interfaces.empty()) {
      return false;
    }
    pair.first_key = DeviceEndpointKey{pair.first.value().snapshot().device_id,
                                       pair.first.value().snapshot().endpoint_id};
    pair.second_key =
        DeviceEndpointKey{pair.second.value().snapshot().device_id,
                          pair.second.value().snapshot().endpoint_id};

    if (!wait_until(
            [&] {
              return discovered(pair.first.value(), pair.second_key) &&
                     discovered(pair.second.value(), pair.first_key);
            },
            std::chrono::milliseconds{8000})) {
      return false;
    }
    if (!pair.first.value().connect_lan(pair.second_key)) {
      return false;
    }
    return wait_until(
        [&] {
          const auto left = latest_session_for(pair.first.value(), pair.second_key);
          const auto right =
              latest_session_for(pair.second.value(), pair.first_key);
          return left.has_value() &&
                 left->state == NodePeerSessionState::pairing_restricted &&
                 right.has_value() &&
                 right->state == NodePeerSessionState::pairing_restricted;
        },
        std::chrono::seconds{12});
  }

  template <typename Predicate>
  bool wait_until(Predicate&& predicate, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    kairo::comm::PhaseGate poll{"m5-basic-comm-poll"};
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
        return true;
      }
      (void)poll.wait_for(1U, std::chrono::milliseconds{2});
    }
    return predicate();
  }

  static bool discovered(const Node& node, const DeviceEndpointKey& peer) {
    const auto entries = node.endpoints();
    return std::any_of(entries.begin(), entries.end(),
                       [&](const auto& entry) { return entry.key == peer; });
  }

  static std::optional<NodePeerSessionSnapshot> latest_session_for(
      const Node& node, const DeviceEndpointKey& peer) {
    const auto sessions = node.peer_sessions();
    std::optional<NodePeerSessionSnapshot> live;
    std::optional<NodePeerSessionSnapshot> closed;
    for (const auto& session : sessions) {
      if (session.peer != peer) continue;
      if (session.state != NodePeerSessionState::closed && !live.has_value()) {
        live = session;
      }
      if (session.state == NodePeerSessionState::closed) {
        closed = session;
      }
    }
    return live.has_value() ? live : closed;
  }

  [[nodiscard]] std::filesystem::path second_inbox_dir() const {
    return root_ / "second-inbox";
  }

  std::filesystem::path write_source(std::string_view name,
                                     std::string_view content) const {
    const auto path = root_ / std::filesystem::path{name};
    std::ofstream stream{path, std::ios::binary | std::ios::trunc};
    stream.write(content.data(), static_cast<std::streamsize>(content.size()));
    return path;
  }

  std::filesystem::path root_;
};

// A1: with the policy opted in on BOTH ends, text messages flow in both
// directions and a file push into the peer's configured "inbox" root lands
// on disk - all without any TrustGrant. Both sessions stay
// pairing_restricted with policy_scopes exactly {message.send,
// file.push:inbox}, empty authorized_scopes, and both TrustStores stay
// empty: the policy never mints grants.
TEST_F(M5BasicCommunicationTest, BasicPolicyCarriesMessagesAndFilesWithoutTrust) {
  BasicNodePair pair;
  if (!establish_pair(pair, PairOptions{})) {
    if (environment_requires_lan_interfaces()) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  AckRecorder first_acks;
  first_acks.attach(pair.first.value());
  AckRecorder second_acks;
  second_acks.attach(pair.second.value());
  InboundRecorder first_inbound;
  first_inbound.attach(pair.first.value());
  InboundRecorder second_inbound;
  second_inbound.attach(pair.second.value());
  FileEventRecorder first_files;
  first_files.attach(pair.first.value());

  // Snapshot contract on BOTH ends: policy capabilities, not grants.
  for (const auto* node : {&pair.first.value(), &pair.second.value()}) {
    const auto session = latest_session_for(
        *node, node == &pair.first.value() ? pair.second_key : pair.first_key);
    ASSERT_TRUE(session.has_value());
    EXPECT_EQ(session->state, NodePeerSessionState::pairing_restricted);
    EXPECT_TRUE(session->pairing_restricted);
    EXPECT_TRUE(session->basic_communication)
        << "basic_communication must be reported on the restricted session";
    EXPECT_EQ(session->policy_scopes,
              (std::vector<std::string>{"message.send", "file.push:inbox"}));
    EXPECT_TRUE(session->authorized_scopes.empty());
  }

  // Neither store holds any grant: the policy never issues one.
  const auto first_grants = pair.first.value().trust_grants_for(pair.second_key);
  ASSERT_TRUE(first_grants);
  EXPECT_TRUE(first_grants.value_if()->empty());
  const auto second_grants =
      pair.second.value().trust_grants_for(pair.first_key);
  ASSERT_TRUE(second_grants);
  EXPECT_TRUE(second_grants.value_if()->empty());

  // A -> B text message with protocol-level ACK.
  MessageEnvelope outbound;
  outbound.type = "text";
  outbound.delivery_mode = MessageDeliveryMode::peer_acked;
  outbound.payload = text_bytes("hello from initiator");
  const auto sent = pair.first.value().send_message(pair.second_key, outbound);
  ASSERT_TRUE(sent) << sent.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] {
        return second_inbound.contains("text") &&
               first_acks.has_terminal_for(*sent.value_if());
      },
      std::chrono::seconds{10}));
  EXPECT_TRUE(first_acks.has_event_for(*sent.value_if(),
                                       MessageDeliveryEvent::acked))
      << "message was never acked on the basic session";
  EXPECT_EQ(second_inbound.payload_of("text"), text_bytes("hello from initiator"));

  // B -> A text message: the policy is symmetric.
  MessageEnvelope reply;
  reply.type = "reply";
  reply.delivery_mode = MessageDeliveryMode::peer_acked;
  reply.payload = text_bytes("hello from target");
  const auto reply_sent = pair.second.value().send_message(pair.first_key, reply);
  ASSERT_TRUE(reply_sent) << reply_sent.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] {
        return first_inbound.contains("reply") &&
               second_acks.has_terminal_for(*reply_sent.value_if());
      },
      std::chrono::seconds{10}));
  EXPECT_TRUE(second_acks.has_event_for(*reply_sent.value_if(),
                                        MessageDeliveryEvent::acked));
  EXPECT_TRUE(first_inbound.received_from(pair.second_key));

  // A pushes a file into B's configured "inbox" root; it must land on disk.
  const std::string content = "basic-communication file payload";
  const auto source = write_source("push-source.bin", content);
  const auto pushed = pair.first.value().push_file(
      pair.second_key, std::string{kInboxRoot}, "reports/hello.bin", source);
  ASSERT_TRUE(pushed) << pushed.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] {
        return first_files.reached_phase(*pushed.value_if(),
                                         FileTransferPhase::committed);
      },
      std::chrono::seconds{15}));
  const auto landed = second_inbox_dir() / "reports" / "hello.bin";
  ASSERT_TRUE(std::filesystem::exists(landed));
  EXPECT_EQ(file_content(landed), content);

  // The file exchange minted no grants either.
  const auto first_grants_after =
      pair.first.value().trust_grants_for(pair.second_key);
  ASSERT_TRUE(first_grants_after);
  EXPECT_TRUE(first_grants_after.value_if()->empty());
  const auto second_grants_after =
      pair.second.value().trust_grants_for(pair.first_key);
  ASSERT_TRUE(second_grants_after);
  EXPECT_TRUE(second_grants_after.value_if()->empty());

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// A2a: the INITIATOR runs with the policy off while the target opted in.
// The initiator's own API surface must reject the exchange immediately
// (peer_offline / peer_session_missing), and the target must neither receive
// a message nor accept a file byte.
TEST_F(M5BasicCommunicationTest, InitiatorPolicyOffRejectsBasicExchange) {
  BasicNodePair pair;
  PairOptions options;
  options.first_basic = false;
  options.second_basic = true;
  if (!establish_pair(pair, options)) {
    if (environment_requires_lan_interfaces()) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  InboundRecorder second_inbound;
  second_inbound.attach(pair.second.value());
  FileEventRecorder second_files;
  second_files.attach(pair.second.value());

  MessageEnvelope outbound;
  outbound.type = "text";
  outbound.delivery_mode = MessageDeliveryMode::peer_acked;
  outbound.payload = text_bytes("should never arrive");
  const auto sent = pair.first.value().send_message(pair.second_key, outbound);
  ASSERT_FALSE(sent);
  EXPECT_EQ(sent.error_if()->code(), ErrorCode::peer_offline);
  EXPECT_EQ(sent.error_if()->safe_detail(), "peer_session_missing");

  const auto source = write_source("blocked.bin", "no bytes");
  const auto pushed = pair.first.value().push_file(
      pair.second_key, std::string{kInboxRoot}, "blocked.bin", source);
  ASSERT_FALSE(pushed);
  EXPECT_EQ(pushed.error_if()->code(), ErrorCode::peer_offline);
  EXPECT_EQ(pushed.error_if()->safe_detail(), "peer_session_missing");

  // No frame of either exchange reached the target.
  (void)wait_until([] { return false; }, std::chrono::milliseconds{300});
  EXPECT_EQ(second_inbound.size(), 0U);
  EXPECT_EQ(second_files.size(), 0U);
  EXPECT_TRUE(directory_empty(second_inbox_dir()));

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// A2b: the TARGET runs with the policy off while the initiator opted in.
// Whatever the local admission shape is (synchronous rejection, or queued
// followed by a terminal non-acked delivery outcome), the exchange must fail
// explicitly and never deliver: no inbound message, no committed transfer,
// no byte on the target's disk, and no grant on either side.
TEST_F(M5BasicCommunicationTest, TargetPolicyOffDropsFramesWithoutDelivery) {
  BasicNodePair pair;
  PairOptions options;
  options.first_basic = true;
  options.second_basic = false;
  if (!establish_pair(pair, options)) {
    if (environment_requires_lan_interfaces()) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  AckRecorder first_acks;
  first_acks.attach(pair.first.value());
  InboundRecorder second_inbound;
  second_inbound.attach(pair.second.value());
  FileEventRecorder first_files;
  first_files.attach(pair.first.value());
  FileEventRecorder second_files;
  second_files.attach(pair.second.value());

  MessageEnvelope outbound;
  outbound.type = "text";
  outbound.delivery_mode = MessageDeliveryMode::peer_acked;
  // The rejected end closes the violating physical channel and never ACKs;
  // the pending message then resolves through the existing M6 semantics:
  // an ack_timeout terminal bound by the envelope TTL. Keep TTL (3 s) well
  // inside the wait window (6 s) so the contract is explicit, not a hang.
  outbound.ttl_milliseconds = 3000U;
  outbound.payload = text_bytes("target must not receive this");
  const auto sent = pair.first.value().send_message(pair.second_key, outbound);
  if (sent) {
    ASSERT_TRUE(wait_until(
        [&] {
          return first_acks.has_event_for(*sent.value_if(),
                                          MessageDeliveryEvent::ack_timeout);
        },
        std::chrono::seconds{6}));
    EXPECT_FALSE(first_acks.has_event_for(*sent.value_if(),
                                          MessageDeliveryEvent::acked));
  } else {
    EXPECT_EQ(sent.error_if()->code(), ErrorCode::peer_offline);
    EXPECT_EQ(sent.error_if()->safe_detail(), "peer_session_missing");
  }

  const auto source = write_source("blocked.bin", "no bytes");
  const auto pushed = pair.first.value().push_file(
      pair.second_key, std::string{kInboxRoot}, "blocked.bin", source);
  if (pushed) {
    // Locally admitted; the serving side (policy off) counts the manifest
    // as a business violation and never accepts. Unlike the message domain
    // there is no TTL-bounded terminal for a refused push: the transfer
    // stalls unaccepted. The deterministic contract is therefore that it
    // NEVER commits and no byte lands on the serving side; a
    // non-committed terminal (paused/failed/cancelled) may still arrive
    // with the transport teardown and is welcome but not required.
    (void)wait_until(
        [&] {
          return first_files.reached_any_of(
              *pushed.value_if(), {FileTransferPhase::failed,
                                   FileTransferPhase::cancelled,
                                   FileTransferPhase::paused});
        },
        std::chrono::milliseconds{1500});
    EXPECT_FALSE(first_files.reached_phase(*pushed.value_if(),
                                           FileTransferPhase::committed));
  } else {
    EXPECT_EQ(pushed.error_if()->code(), ErrorCode::peer_offline);
    EXPECT_EQ(pushed.error_if()->safe_detail(), "peer_session_missing");
  }

  (void)wait_until([] { return false; }, std::chrono::milliseconds{300});
  EXPECT_EQ(second_inbound.size(), 0U);
  EXPECT_FALSE(second_files.any_committed());
  EXPECT_TRUE(directory_empty(second_inbox_dir()));

  // A one-sided policy never minted grants anywhere.
  const auto first_grants = pair.first.value().trust_grants_for(pair.second_key);
  ASSERT_TRUE(first_grants);
  EXPECT_TRUE(first_grants.value_if()->empty());
  const auto second_grants =
      pair.second.value().trust_grants_for(pair.first_key);
  ASSERT_TRUE(second_grants);
  EXPECT_TRUE(second_grants.value_if()->empty());

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// A2c (issue #13): the target's policy-off rejection used to leave a locally
// admitted push stalled in the offered phase forever. With a short
// NodeConfig::file_offer_timeout on the initiator, the unanswered push must
// resolve with EXACTLY ONE failed terminal (timeout / "offer_expired" /
// deadline_exceeded = 3). The accepted gate keeps every byte behind the
// accept: the initiator never sends a chunk or a complete, the target's
// session sees no second violation (it survives, still pairing_restricted),
// and no byte lands anywhere on the target.
TEST_F(M5BasicCommunicationTest, OfferTimeoutFailsUnansweredPushOnce) {
  BasicNodePair pair;
  PairOptions options;
  options.first_basic = true;
  options.second_basic = false;
  options.first_file_offer_timeout = std::chrono::milliseconds{700};
  if (!establish_pair(pair, options)) {
    if (environment_requires_lan_interfaces()) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  FullFileEventRecorder first_files;
  first_files.attach(pair.first.value());
  FileEventRecorder second_files;
  second_files.attach(pair.second.value());

  const auto source = write_source("blocked.bin", "no bytes");
  const auto pushed = pair.first.value().push_file(
      pair.second_key, std::string{kInboxRoot}, "blocked.bin", source);
  // Locally admitted: this is exactly the issue #13 scenario (the refusing
  // receiver cannot answer, so the local window must bound the offer).
  ASSERT_TRUE(pushed) << pushed.error_if()->safe_detail();
  const auto id = *pushed.value_if();

  // One failed terminal inside the window plus one maintenance tick, well
  // under the 3 s wait.
  ASSERT_TRUE(wait_until(
      [&] { return first_files.terminal_count(id) > 0U; },
      std::chrono::seconds{3}));
  EXPECT_EQ(first_files.terminal_count(id), 1U)
      << "the offer deadline must fire exactly one terminal";
  const auto failed = first_files.failed_for(id);
  ASSERT_TRUE(failed.has_value());
  ASSERT_TRUE(failed->error.has_value());
  EXPECT_EQ(failed->error->code(), ErrorCode::timeout);
  EXPECT_EQ(failed->error->safe_detail(), "offer_expired");
  ASSERT_TRUE(failed->error->underlying_code().has_value());
  EXPECT_EQ(*failed->error->underlying_code(),
            static_cast<std::int64_t>(StableStatus::deadline_exceeded));

  // Accepted gate on the initiator: manifest only, zero chunk/complete
  // frames ever left the sender. service_diagnostics() returns the snapshot
  // published by the periodic maintenance tick (DoubleBuffer), which lags
  // the live FileService by up to one 500 ms tick: the event observer above
  // sees the terminal before the snapshot carries its counters, so poll
  // until the snapshot settles instead of reading it once.
  const bool first_stats_settled = wait_until(
      [&] {
        const auto stats = pair.first.value().service_diagnostics().file;
        return stats.manifests_sent == 1U && stats.chunks_sent == 0U &&
               stats.completes_sent == 0U && stats.sender_failed == 1U &&
               stats.sender_committed == 0U;
      },
      std::chrono::seconds{2});
  EXPECT_TRUE(first_stats_settled) << "initiator file stats never settled: "
                                   << "manifests_sent="
                                   << pair.first.value().service_diagnostics().file.manifests_sent
                                   << " chunks_sent="
                                   << pair.first.value().service_diagnostics().file.chunks_sent
                                   << " completes_sent="
                                   << pair.first.value().service_diagnostics().file.completes_sent
                                   << " sender_failed="
                                   << pair.first.value().service_diagnostics().file.sender_failed
                                   << " sender_committed="
                                   << pair.first.value().service_diagnostics().file.sender_committed;

  // The target saw no bytes and never committed; its session took exactly
  // one violation (the manifest) and survived it - no second violation ever
  // arrived to fail the session.
  (void)wait_until([] { return false; }, std::chrono::milliseconds{300});
  EXPECT_FALSE(second_files.any_committed());
  EXPECT_TRUE(directory_empty(second_inbox_dir()));
  const auto second_session =
      latest_session_for(pair.second.value(), pair.first_key);
  ASSERT_TRUE(second_session.has_value());
  EXPECT_EQ(second_session->state, NodePeerSessionState::pairing_restricted);

  // A one-sided policy never minted grants anywhere.
  const auto first_grants = pair.first.value().trust_grants_for(pair.second_key);
  ASSERT_TRUE(first_grants);
  EXPECT_TRUE(first_grants.value_if()->empty());
  const auto second_grants =
      pair.second.value().trust_grants_for(pair.first_key);
  ASSERT_TRUE(second_grants);
  EXPECT_TRUE(second_grants.value_if()->empty());

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// A3: on basic sessions the policy covers message and file ONLY. RPC calls,
// event subscriptions/publishes, byte streams, gateway dials, and shell
// opens all fail explicitly against a target that registered/configured
// each of them - they would have worked for an authorized session.
TEST_F(M5BasicCommunicationTest,
       BasicSessionsKeepRpcEventsStreamsShellGatewayGrantOnly) {
  BasicNodePair pair;
  PairOptions options;
  ShellProfileConfig shell_profile;
  shell_profile.name = "dbg";
#ifdef _WIN32
  // Windows shell-profile validation requires a drive-absolute executable;
  // the profile is never launched here, only admitted.
  shell_profile.argv = {"C:\\Windows\\System32\\cmd.exe"};
#else
  shell_profile.argv = {"/bin/cat"};
#endif
  shell_profile.working_directory = root_;
  shell_profile.max_concurrent_sessions = 1U;
  options.second_shell_profiles = {shell_profile};
  if (!establish_pair(pair, options)) {
    if (environment_requires_lan_interfaces()) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  // A real server-side method exists on the target: isolation, not absence.
  std::size_t handler_calls = 0U;
  const auto registered = pair.second.value().register_rpc_method(
      {.service = "t",
       .method = "echo",
       .schema_version = 1U,
       .required_scope = "message.send",
       .streaming = false,
       .handler_enforced_scope = false},
      [&handler_calls](const RpcCallContext&) {
        ++handler_calls;
        return RpcHandlerResult{};
      });
  ASSERT_TRUE(registered) << registered.error_if()->safe_detail();

  // RPC: the call is refused synchronously and deterministically. Observed
  // shape: the pre-strand gate in Node::call_rpc returns the peer_offline
  // rejection and does NOT invoke the completion on this local path (only
  // strand-admitted calls fire it). If a completion ever fires it must
  // still be a failure, never a result.
  std::optional<Result<RpcCallOutcome>> rpc_completion;
  const auto rpc_call = pair.first.value().call_rpc(
      pair.second_key, "t", "echo", text_bytes("ping"), RpcCallOptions{},
      [&](const DeviceEndpointKey&, Result<RpcCallOutcome> outcome) {
        rpc_completion = std::move(outcome);
      });
  ASSERT_FALSE(rpc_call);
  EXPECT_EQ(rpc_call.error_if()->code(), ErrorCode::peer_offline);
  EXPECT_EQ(rpc_call.error_if()->safe_detail(), "peer_session_missing");
  if (rpc_completion.has_value()) {
    EXPECT_EQ(rpc_completion->value_if(), nullptr)
        << "the RPC completion must carry the local rejection";
  }
  EXPECT_EQ(handler_calls, 0U);

  // Events: subscribe and publish both fail on the grant-less session.
  const auto subscribed = pair.first.value().subscribe_events(
      pair.second_key, "telemetry.cpu", false, EventQos::best_effort_latest);
  ASSERT_FALSE(subscribed);
  EXPECT_EQ(subscribed.error_if()->code(), ErrorCode::peer_offline);
  EXPECT_EQ(subscribed.error_if()->safe_detail(), "peer_session_missing");
  const auto published = pair.first.value().publish_event(
      pair.second_key, "telemetry.cpu", text_bytes("payload"), 1U);
  ASSERT_FALSE(published);
  EXPECT_EQ(published.error_if()->code(), ErrorCode::peer_offline);
  EXPECT_EQ(published.error_if()->safe_detail(), "peer_session_missing");

  // Byte streams: never on a basic session.
  const auto stream = pair.first.value().open_byte_stream(pair.second_key);
  ASSERT_FALSE(stream);
  EXPECT_EQ(stream.error_if()->code(), ErrorCode::pairing_required);
  EXPECT_EQ(stream.error_if()->safe_detail(), "session_not_authorized");

  // Gateway: never on a basic session.
  const auto gateway = pair.first.value().open_gateway_stream(
      pair.second_key,
      GatewayConnect{.host = "example.com", .port = 443U, .profile = "net"});
  ASSERT_FALSE(gateway);
  EXPECT_EQ(gateway.error_if()->code(), ErrorCode::pairing_required);
  EXPECT_EQ(gateway.error_if()->safe_detail(), "session_not_authorized");

  // Shell: the profile exists on the target, yet the open fails - shell is
  // grant-only regardless of configuration.
  const auto shell = pair.first.value().open_shell(pair.second_key, "dbg");
  ASSERT_FALSE(shell);
  EXPECT_EQ(shell.error_if()->code(), ErrorCode::peer_offline);
  EXPECT_EQ(shell.error_if()->safe_detail(), "peer_session_missing");
  EXPECT_TRUE(pair.second.value().shell_audit_records().empty());

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// A4: a successful password pairing supersedes the policy. After the
// upgrade both sessions are authenticated, report the grant scopes (no
// policy scopes, no basic_communication flag), and message/file keep working
// through the GRANT path.
TEST_F(M5BasicCommunicationTest, PairingSupersedesBasicPolicy) {
  BasicNodePair pair;
  PairOptions options;
  options.second_password = true;
  options.second_policy = {"message.send", "file.push:inbox"};
  if (!establish_pair(pair, options)) {
    if (environment_requires_lan_interfaces()) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }

  std::optional<std::vector<std::string>> pairing_scopes;
  std::mutex pairing_mutex;
  pair.first.value().set_pairing_observer(
      [&](const DeviceEndpointKey&, const NodePairingOutcome& outcome) {
        if (const auto* scopes = outcome.value_if()) {
          const std::lock_guard<std::mutex> guard{pairing_mutex};
          pairing_scopes = *scopes;
        }
      });

  const auto admitted = pair.first.value().pair_peer(
      pair.second_key, kTargetPassword, {"message.send", "file.push:inbox"});
  ASSERT_TRUE(admitted) << admitted.error_if()->safe_detail();
  ASSERT_TRUE(wait_until([&] { return pairing_scopes.has_value(); },
                         std::chrono::seconds{15}));

  // Both ends upgraded; the grant replaced the policy on both snapshots.
  ASSERT_TRUE(wait_until(
      [&] {
        const auto left = latest_session_for(pair.first.value(), pair.second_key);
        const auto right =
            latest_session_for(pair.second.value(), pair.first_key);
        return left.has_value() &&
               left->state == NodePeerSessionState::authenticated &&
               right.has_value() &&
               right->state == NodePeerSessionState::authenticated;
      },
      std::chrono::seconds{10}));
  for (const auto* node : {&pair.first.value(), &pair.second.value()}) {
    const auto session = latest_session_for(
        *node, node == &pair.first.value() ? pair.second_key : pair.first_key);
    ASSERT_TRUE(session.has_value());
    EXPECT_EQ(session->state, NodePeerSessionState::authenticated);
    EXPECT_FALSE(session->basic_communication);
    EXPECT_TRUE(session->policy_scopes.empty());
    EXPECT_EQ(session->authorized_scopes,
              (std::vector<std::string>{"file.push:inbox", "message.send"}));
  }
  // The scopes came from the grant, not the policy: both stores now hold
  // the record the pairing minted.
  const auto issued = pair.second.value().trust_grants_for(pair.first_key);
  ASSERT_TRUE(issued);
  EXPECT_FALSE(issued.value_if()->empty());
  const auto received = pair.first.value().trust_grants_for(pair.second_key);
  ASSERT_TRUE(received);
  EXPECT_FALSE(received.value_if()->empty());

  // Grant path keeps message and file working.
  AckRecorder first_acks;
  first_acks.attach(pair.first.value());
  InboundRecorder second_inbound;
  second_inbound.attach(pair.second.value());
  MessageEnvelope envelope;
  envelope.type = "text";
  envelope.delivery_mode = MessageDeliveryMode::peer_acked;
  envelope.payload = text_bytes("post-pairing message");
  const auto sent = pair.first.value().send_message(pair.second_key, envelope);
  ASSERT_TRUE(sent) << sent.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] {
        return second_inbound.contains("text") &&
               first_acks.has_terminal_for(*sent.value_if());
      },
      std::chrono::seconds{10}));

  FileEventRecorder first_files;
  first_files.attach(pair.first.value());
  const std::string content = "post-pairing file payload";
  const auto source = write_source("post-pairing.bin", content);
  const auto pushed = pair.first.value().push_file(
      pair.second_key, std::string{kInboxRoot}, "hello.bin", source);
  ASSERT_TRUE(pushed) << pushed.error_if()->safe_detail();
  ASSERT_TRUE(wait_until(
      [&] {
        return first_files.reached_phase(*pushed.value_if(),
                                         FileTransferPhase::committed);
      },
      std::chrono::seconds{15}));
  EXPECT_EQ(file_content(second_inbox_dir() / "hello.bin"), content);

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// A5: the policy whitelist is per configured receive root. A push into a
// root the serving side never configured fails explicitly (root/scope
// rejection) and no byte lands anywhere.
TEST_F(M5BasicCommunicationTest, PushToUnconfiguredRootFailsWithoutSideEffects) {
  BasicNodePair pair;
  if (!establish_pair(pair, PairOptions{})) {
    if (environment_requires_lan_interfaces()) {
      FAIL() << "Required LAN interface is unavailable";
    }
    GTEST_SKIP() << "No multicast-capable non-loopback interface";
  }
  FileEventRecorder first_files;
  first_files.attach(pair.first.value());
  FileEventRecorder second_files;
  second_files.attach(pair.second.value());

  const auto source = write_source("vault-attempt.bin", "secret");
  const auto pushed = pair.first.value().push_file(
      pair.second_key, "vault", "secret.bin", source);
  if (pushed) {
    // Locally admitted; the serving side must reject the unknown root and
    // the transfer must end failed without ever committing.
    ASSERT_TRUE(wait_until(
        [&] {
          return first_files.reached_any_of(
              *pushed.value_if(), {FileTransferPhase::failed,
                                   FileTransferPhase::cancelled,
                                   FileTransferPhase::paused});
        },
        std::chrono::seconds{10}));
    EXPECT_FALSE(first_files.reached_phase(*pushed.value_if(),
                                           FileTransferPhase::committed));
  } else {
    EXPECT_EQ(pushed.error_if()->code(), ErrorCode::peer_offline);
    EXPECT_EQ(pushed.error_if()->safe_detail(), "peer_session_missing");
  }

  (void)wait_until([] { return false; }, std::chrono::milliseconds{300});
  EXPECT_FALSE(second_files.any_committed());
  EXPECT_TRUE(directory_empty(second_inbox_dir()));

  EXPECT_TRUE(pair.first.value().shutdown().stopped);
  EXPECT_TRUE(pair.second.value().shutdown().stopped);
}

// ---- session-level harness (B) ----
//
// The m5_session_test harness builds sessions through
// PeerSession::create_verified, which does not forward the basic-communication
// config fields. These tests therefore mirror that harness but call
// PeerSession::create directly so config_.basic_communication is in force.

struct BasicSideOptions {
  bool basic{true};
  std::vector<std::string> scopes{"message.send", "file.push:inbox"};
  std::uint64_t supported_bits{protocol_1_2_capability_bits};
};

struct BasicSessionPair {
  test::LoopbackTransportPair pair;
  Result<IdentityKeyPair> left_identity{create_identity()};
  Result<IdentityKeyPair> right_identity{create_identity()};
  PasswordVerifier verifier;
  std::uint64_t initiator_wall_clock = kNow;
  std::uint64_t target_wall_clock = kNow;
  std::shared_ptr<PeerSession> left;
  std::shared_ptr<PeerSession> right;

  BasicSessionPair(BasicSideOptions left_options, BasicSideOptions right_options) {
    EXPECT_TRUE(left_identity && right_identity);
    auto created_verifier =
        create_password_verifier("target-password", PasswordHashParameters{});
    EXPECT_TRUE(created_verifier);
    verifier = std::move(*created_verifier.value_if());
    pair.connect();
    transport::ChannelOptions control_options;
    pair.left().async_open_channel(transport::ChannelKind::control, control_options,
                                   [](Result<transport::TransportChannel*>) {});
    pair.right().async_open_channel(transport::ChannelKind::control, control_options,
                                    [](Result<transport::TransportChannel*>) {});
    build_left(left_options);
    build_right(right_options);
  }

  [[nodiscard]] DeviceEndpointKey left_key() const {
    return {left_identity.value_if()->device_id(), filled<EndpointId>(0x21U)};
  }
  [[nodiscard]] DeviceEndpointKey right_key() const {
    return {right_identity.value_if()->device_id(), filled<EndpointId>(0x41U)};
  }

  void pump_all(int rounds = 8) {
    for (int round = 0; round < rounds; ++round) {
      pair.left().pump();
      pair.right().pump();
    }
  }

 private:
  static ProtocolHello side_protocol(std::uint64_t supported_bits) {
    return {.version = current_protocol_version,
            .supported = {supported_bits},
            .required = {static_cast<std::uint64_t>(Capability::session)}};
  }

  void build_left(const BasicSideOptions& options) {
    const auto session_id = filled<SessionId>(0x61U);
    const auto initiator_nonce = filled_array<signaling_nonce_bytes>(0x11U);
    const auto responder_nonce = filled_array<signaling_nonce_bytes>(0x31U);
    const auto transcript =
        filled_array<signaling_transcript_sha256_bytes>(0x51U);
    const SessionHelloExpectation expectation{right_key(), left_key(), session_id,
                                              1U, initiator_nonce,
                                              responder_nonce, transcript};
    SignedSessionHello local;
    local.sender = expectation.peer;
    local.peer = expectation.sender;
    local.session_id = expectation.session_id;
    local.session_epoch = expectation.session_epoch;
    local.initiator_nonce = expectation.initiator_nonce;
    local.responder_nonce = expectation.responder_nonce;
    local.signaling_transcript_sha256 = expectation.signaling_transcript_sha256;
    const auto protocol = side_protocol(options.supported_bits);
    local.protocol_version = protocol.version;
    local.supported = protocol.supported;
    local.required = protocol.required;
    local.expires_unix_milliseconds = kNow + 60'000U;
    auto signed_hello = sign_signed_session_hello(local, *left_identity.value_if());
    ASSERT_TRUE(signed_hello);

    auto timeline = std::make_shared<ConnectionAttemptTimeline>();
    EXPECT_TRUE(timeline->transition(ConnectionStage::resolving_endpoint, "test",
                                     "endpoint_selected"));
    EXPECT_TRUE(timeline->transition(ConnectionStage::signaling, "test",
                                     "attempt_accepted"));
    auto created = PeerSession::create(
        {.transport = std::shared_ptr<transport::TransportSession>(
             &pair.left(), [](transport::TransportSession*) {}),
         .local_hello = std::move(local),
         .expectation = expectation,
         .peer_public_key = right_identity.value_if()->public_key(),
         .local_protocol = protocol,
         .now_unix_milliseconds = kNow,
         .initiator = true,
         .observer = {},
         .timeline = timeline,
         .clock = {},
         .trust_authorizer =
             [](std::uint64_t) {
               SessionAuthorization authorization;
               authorization.trusted = false;
               authorization.pairing_allowed = true;
               return Result<SessionAuthorization>::success(authorization);
             },
         .pairing_evaluator = {},
         .pairing_result_sink =
             [this](const PairingResultBody& result, const RequestId&,
                    const PairingNonce& pending_nonce,
                    const std::vector<std::string>& requested_scopes) {
               if (!result.grant.has_value()) {
                 return Result<void>::failure(
                     Error{ErrorCode::authentication, "m5_basic_test",
                           "result_without_grant"});
               }
               const auto& grant = *result.grant;
               if (grant.nonce != pending_nonce ||
                   grant.issuer != right_identity.value_if()->device_id() ||
                   grant.subject != left_identity.value_if()->device_id()) {
                 return Result<void>::failure(
                     Error{ErrorCode::authentication, "m5_basic_test",
                           "grant_binding"});
               }
               auto verified = verify_signed_trust_grant(
                   grant,
                   std::span<const std::byte>{
                       right_identity.value_if()->public_key().data(),
                       right_identity.value_if()->public_key().size()},
                   initiator_wall_clock);
               if (!verified) return verified;
               for (const auto& scope : grant.granted_scopes) {
                 if (std::find(requested_scopes.begin(), requested_scopes.end(),
                               scope) == requested_scopes.end()) {
                   return Result<void>::failure(
                       Error{ErrorCode::authentication, "m5_basic_test",
                             "scope_overreach"});
                 }
               }
               return Result<void>::success();
             },
         .pairing_deadline = std::chrono::milliseconds{60000},
         .basic_communication = options.basic,
         .basic_communication_scopes = options.scopes,
         .wall_clock = [this] { return initiator_wall_clock; }});
    ASSERT_TRUE(created);
    left = *created.value_if();
  }

  void build_right(const BasicSideOptions& options) {
    const auto session_id = filled<SessionId>(0x61U);
    const auto initiator_nonce = filled_array<signaling_nonce_bytes>(0x11U);
    const auto responder_nonce = filled_array<signaling_nonce_bytes>(0x31U);
    const auto transcript =
        filled_array<signaling_transcript_sha256_bytes>(0x51U);
    const SessionHelloExpectation expectation{left_key(), right_key(), session_id,
                                              1U, initiator_nonce,
                                              responder_nonce, transcript};
    SignedSessionHello local;
    local.sender = expectation.peer;
    local.peer = expectation.sender;
    local.session_id = expectation.session_id;
    local.session_epoch = expectation.session_epoch;
    local.initiator_nonce = expectation.initiator_nonce;
    local.responder_nonce = expectation.responder_nonce;
    local.signaling_transcript_sha256 = expectation.signaling_transcript_sha256;
    const auto protocol = side_protocol(options.supported_bits);
    local.protocol_version = protocol.version;
    local.supported = protocol.supported;
    local.required = protocol.required;
    local.expires_unix_milliseconds = kNow + 60'000U;
    auto signed_hello =
        sign_signed_session_hello(local, *right_identity.value_if());
    ASSERT_TRUE(signed_hello);

    auto timeline = std::make_shared<ConnectionAttemptTimeline>();
    EXPECT_TRUE(timeline->transition(ConnectionStage::resolving_endpoint, "test",
                                     "endpoint_selected"));
    EXPECT_TRUE(timeline->transition(ConnectionStage::signaling, "test",
                                     "attempt_accepted"));
    auto created = PeerSession::create(
        {.transport = std::shared_ptr<transport::TransportSession>(
             &pair.right(), [](transport::TransportSession*) {}),
         .local_hello = std::move(local),
         .expectation = expectation,
         .peer_public_key = left_identity.value_if()->public_key(),
         .local_protocol = protocol,
         .now_unix_milliseconds = kNow,
         .initiator = false,
         .observer = {},
         .timeline = timeline,
         .clock = {},
         .trust_authorizer =
             [](std::uint64_t) {
               SessionAuthorization authorization;
               authorization.trusted = false;
               authorization.pairing_allowed = true;
               return Result<SessionAuthorization>::success(authorization);
             },
         .pairing_evaluator =
             [this](const PairingRequestBody& request) {
               auto verified = verify_password(request.password_utf8, verifier);
               if (!verified) {
                 return Result<PairingResultBody>::failure(*verified.error_if());
               }
               PairingResultBody result;
               result.request_id = request.request_id;
               if (!*verified.value_if()) {
                 result.status = StableStatus::unauthenticated;
                 return Result<PairingResultBody>::success(result);
               }
               const std::vector<std::string> policy_scopes = {"message.send",
                                                               "file.push:inbox"};
               auto adjudication = adjudicate_trust_scopes(
                   request.requested_scopes, policy_scopes, std::nullopt);
               if (!adjudication.authorized) {
                 result.status = StableStatus::permission_denied;
                 return Result<PairingResultBody>::success(result);
               }
               SignedTrustGrant grant;
               grant.grant_id = GrantId{filled<GrantId::Storage>(0x78U)};
               grant.issuer = right_identity.value_if()->device_id();
               grant.subject = left_identity.value_if()->device_id();
               grant.granted_scopes = adjudication.allowed_scopes;
               grant.password_generation = 1U;
               grant.issued_unix_milliseconds = target_wall_clock;
               grant.nonce = request.nonce;
               auto signed_grant =
                   sign_signed_trust_grant(grant, *right_identity.value_if());
               if (!signed_grant) {
                 return Result<PairingResultBody>::failure(
                     *signed_grant.error_if());
               }
               result.status = StableStatus::ok;
               result.grant = std::move(grant);
               return Result<PairingResultBody>::success(result);
             },
         .pairing_deadline = std::chrono::milliseconds{60000},
         .basic_communication = options.basic,
         .basic_communication_scopes = options.scopes,
         .wall_clock = [this] { return target_wall_clock; }});
    ASSERT_TRUE(created);
    right = *created.value_if();
  }
};

// Sends `frame` from the RIGHT transport through a fresh channel of `kind`
// so the LEFT session's handler receives it on a live channel object of
// that kind (the same injection path real transport bytes take).
void inject_frame(BasicSessionPair& harness, transport::ChannelKind kind,
                  Frame frame) {
  auto encoded = encode_frame(frame);
  ASSERT_TRUE(encoded);
  transport::ChannelOptions options;
  harness.pair.right().async_open_channel(
      kind, options, [&](Result<transport::TransportChannel*> channel) {
        ASSERT_TRUE(channel);
        (void)(*channel.value_if())->send(*encoded.value_if());
      });
  harness.pair.right().pump();
  harness.pair.left().pump();
}

// B1: on a basic session a message-domain frame is accepted (the registered
// handler runs, no violation counting), while rpc- and shell-domain frames
// take the note_business_violation path: the first closes only the offending
// channel, the second fails the session.
TEST(M5BasicSession, BasicSessionAdmitsMessageFramesAndViolatesOtherDomains) {
  BasicSessionPair harness{BasicSideOptions{}, BasicSideOptions{}};
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  ASSERT_TRUE(harness.left->pairing_restricted());
  ASSERT_TRUE(harness.left->basic_communication_active());
  EXPECT_TRUE(harness.left->basic_domain_allowed(session::ChannelDomain::message));
  EXPECT_TRUE(harness.left->basic_domain_allowed(session::ChannelDomain::file));
  EXPECT_FALSE(harness.left->basic_domain_allowed(session::ChannelDomain::rpc));
  EXPECT_TRUE(harness.left->policy_scope_covers("message.send"));
  EXPECT_TRUE(harness.left->policy_scope_covers("file.push:inbox"));
  EXPECT_FALSE(harness.left->policy_scope_covers("shell.open:x"));
  EXPECT_TRUE(harness.left->authorized_scopes().empty());

  // A message-domain logical channel on the basic session opens and carries
  // a frame end to end. The initiator owns the channel id; the responder
  // opens its own channel of the same domain (the receiving vehicle) and
  // admits the peer-initiated id through its message-domain handler - the
  // M5-14 domain-admission pattern the services use.
  std::vector<FrameType> right_received;
  const auto left_channel = harness.left->open_business_channel(
      session::ChannelDomain::message, session::QueueFullPolicy::reject, 8U,
      4096U, [](const FrameView&) {});
  ASSERT_TRUE(left_channel) << left_channel.error_if()->safe_detail();
  const auto right_channel = harness.right->open_business_channel(
      session::ChannelDomain::message, session::QueueFullPolicy::reject, 8U,
      4096U, [](const FrameView&) {});
  ASSERT_TRUE(right_channel) << right_channel.error_if()->safe_detail();
  harness.right->set_domain_handler(
      session::ChannelDomain::message,
      [&](const FrameView& frame) -> Result<void> {
        right_received.push_back(static_cast<FrameType>(frame.type));
        return Result<void>::success();
      });
  harness.pump_all();

  MessageEnvelope envelope;
  envelope.message_id = filled<MessageId>(0x9U);
  envelope.type = "text";
  envelope.payload = text_bytes("session-level payload");
  auto encoded_envelope = encode_message_envelope(envelope);
  ASSERT_TRUE(encoded_envelope);
  Frame message_frame;
  message_frame.type = static_cast<std::uint8_t>(FrameType::message);
  message_frame.channel_id = *left_channel.value_if();
  message_frame.message_id = filled<MessageId>(0x3U);
  message_frame.payload = *encoded_envelope.value_if();
  const auto frame_sent = harness.left->send_frame(
      *left_channel.value_if(), session::FrameClass::standard,
      std::move(message_frame));
  ASSERT_TRUE(frame_sent) << frame_sent.error_if()->safe_detail();
  harness.pump_all();
  ASSERT_EQ(right_received.size(), 1U);
  EXPECT_EQ(right_received.front(), FrameType::message);
  EXPECT_EQ(harness.left->diagnostics().business_frames_rejected, 0U);
  EXPECT_TRUE(harness.left->pairing_restricted());

  // An rpc-domain frame on the message channel is a business violation:
  // counted, offending channel closed, session still alive.
  Frame rpc_frame;
  rpc_frame.type = static_cast<std::uint8_t>(FrameType::rpc_request);
  rpc_frame.flags = frame_flag_required;
  rpc_frame.channel_id = 9U;
  rpc_frame.message_id = filled<MessageId>(0x4U);
  rpc_frame.payload.assign(8U, std::byte{0});
  inject_frame(harness, transport::ChannelKind::message, std::move(rpc_frame));
  EXPECT_EQ(harness.left->diagnostics().business_frames_rejected, 1U);
  EXPECT_TRUE(harness.left->pairing_restricted());

  // A shell-domain frame is the second violation and fails the session.
  const auto second_channel = harness.left->open_business_channel(
      session::ChannelDomain::file, session::QueueFullPolicy::reject, 8U,
      4096U, [](const FrameView&) {});
  ASSERT_TRUE(second_channel) << second_channel.error_if()->safe_detail();
  harness.pump_all();
  Frame shell_frame;
  shell_frame.type = static_cast<std::uint8_t>(FrameType::shell_open);
  shell_frame.flags = frame_flag_required;
  shell_frame.channel_id = 9U;
  shell_frame.message_id = filled<MessageId>(0x5U);
  shell_frame.payload.assign(4U, std::byte{0});
  inject_frame(harness, transport::ChannelKind::file, std::move(shell_frame));
  const auto left_state = harness.left->diagnostics();
  EXPECT_EQ(left_state.state, PeerSessionState::closed);
  ASSERT_TRUE(left_state.last_error.has_value());
  EXPECT_EQ(left_state.last_error->code(), ErrorCode::permission);
  EXPECT_EQ(left_state.last_error->safe_detail(), "business_frames_not_authorized");
  EXPECT_EQ(left_state.business_frames_rejected, 2U);
  // The RIGHT session never accepted anything and stays restricted.
  EXPECT_TRUE(harness.right->pairing_restricted());
}

// B2: a basic session refuses to SEND or open/adopt any non-basic domain:
// session_not_authorized, deterministic, and the session stays alive.
TEST(M5BasicSession, BasicSessionRefusesNonBasicDomainSendsAndChannels) {
  BasicSessionPair harness{BasicSideOptions{}, BasicSideOptions{}};
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  ASSERT_TRUE(harness.left->pairing_restricted());
  ASSERT_TRUE(harness.left->basic_communication_active());

  Frame rpc_frame;
  rpc_frame.type = static_cast<std::uint8_t>(FrameType::rpc_request);
  rpc_frame.channel_id = 3U;
  rpc_frame.message_id = filled<MessageId>(0x6U);
  rpc_frame.payload.assign(8U, std::byte{0});
  const auto rpc_sent = harness.left->send_frame(
      3U, session::FrameClass::standard, std::move(rpc_frame));
  ASSERT_FALSE(rpc_sent);
  EXPECT_EQ(rpc_sent.error_if()->code(), ErrorCode::pairing_required);
  EXPECT_EQ(rpc_sent.error_if()->safe_detail(), "session_not_authorized");

  Frame shell_frame;
  shell_frame.type = static_cast<std::uint8_t>(FrameType::shell_open);
  shell_frame.channel_id = 4U;
  shell_frame.message_id = filled<MessageId>(0x7U);
  shell_frame.payload.assign(4U, std::byte{0});
  const auto shell_sent = harness.left->send_frame(
      4U, session::FrameClass::interactive, std::move(shell_frame));
  ASSERT_FALSE(shell_sent);
  EXPECT_EQ(shell_sent.error_if()->safe_detail(), "session_not_authorized");

  Frame stream_frame;
  stream_frame.type = static_cast<std::uint8_t>(FrameType::stream_open);
  stream_frame.flags = frame_flag_required;
  stream_frame.channel_id = 5U;
  stream_frame.message_id = filled<MessageId>(0x8U);
  stream_frame.payload.assign(16U, std::byte{0});
  const auto stream_sent = harness.left->send_frame(
      5U, session::FrameClass::bulk, std::move(stream_frame));
  ASSERT_FALSE(stream_sent);
  EXPECT_EQ(stream_sent.error_if()->safe_detail(), "session_not_authorized");

  const auto rpc_open = harness.left->open_business_channel(
      session::ChannelDomain::rpc, session::QueueFullPolicy::reject, 4U, 4096U,
      [](const FrameView&) {});
  ASSERT_FALSE(rpc_open);
  EXPECT_EQ(rpc_open.error_if()->safe_detail(), "session_not_authorized");
  const auto shell_open = harness.left->open_business_channel(
      session::ChannelDomain::shell, session::QueueFullPolicy::reject, 4U,
      4096U, [](const FrameView&) {});
  ASSERT_FALSE(shell_open);
  EXPECT_EQ(shell_open.error_if()->safe_detail(), "session_not_authorized");
  const auto adopted = harness.left->adopt_business_channel(
      7U, session::ChannelDomain::rpc, session::QueueFullPolicy::reject, 4U,
      4096U, [](const FrameView&) {});
  ASSERT_FALSE(adopted);
  EXPECT_EQ(adopted.error_if()->safe_detail(), "session_not_authorized");

  // Every refusal was local: the session is untouched.
  EXPECT_TRUE(harness.left->pairing_restricted());
  EXPECT_FALSE(harness.left->diagnostics().last_error.has_value());
}

// B3: a successful pairing upgrade replaces the policy: diagnostics clear
// basic_communication and policy_scopes, and the grant scopes drive the
// session from then on.
TEST(M5BasicSession, PairingUpgradeClearsBasicPolicyState) {
  BasicSessionPair harness{BasicSideOptions{}, BasicSideOptions{}};
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  ASSERT_TRUE(harness.left->pairing_restricted());
  ASSERT_TRUE(harness.left->basic_communication_active());
  ASSERT_FALSE(harness.left->diagnostics().policy_scopes.empty());

  const auto submitted = harness.left->submit_pairing_request(
      RequestId{filled<RequestId::Storage>(0xB7U)}, "target-password",
      {"message.send"});
  ASSERT_TRUE(submitted) << submitted.error_if()->safe_detail();
  harness.pump_all();

  ASSERT_TRUE(harness.left->authenticated());
  ASSERT_TRUE(harness.right->authenticated());
  const auto left_state = harness.left->diagnostics();
  EXPECT_FALSE(left_state.basic_communication);
  EXPECT_TRUE(left_state.policy_scopes.empty());
  EXPECT_EQ(left_state.authorized_scopes,
            std::vector<std::string>{"message.send"});
  const auto right_state = harness.right->diagnostics();
  EXPECT_FALSE(right_state.basic_communication);
  EXPECT_TRUE(right_state.policy_scopes.empty());
  EXPECT_EQ(right_state.authorized_scopes,
            std::vector<std::string>{"message.send"});
  EXPECT_FALSE(harness.left->basic_domain_allowed(session::ChannelDomain::message));
  EXPECT_FALSE(harness.left->policy_scope_covers("message.send"));

  // The grant path now carries message frames (the policy no longer does).
  const auto channel = harness.left->open_business_channel(
      session::ChannelDomain::message, session::QueueFullPolicy::reject, 4U,
      4096U, [](const FrameView&) {});
  ASSERT_TRUE(channel) << channel.error_if()->safe_detail();
}

// B4: with the policy enabled but Capability::message NOT negotiated, the
// session falls back to the legacy restricted path: pairing stays available,
// no policy scopes are in force, and the session does not fail.
TEST(M5BasicSession, BasicWithoutMessageCapabilityKeepsPairingPath) {
  const std::uint64_t no_message_bits =
      protocol_1_2_capability_bits &
      ~static_cast<std::uint64_t>(Capability::message);
  BasicSessionPair harness{
      BasicSideOptions{.basic = true,
                       .scopes = {"message.send"},
                       .supported_bits = no_message_bits},
      BasicSideOptions{.basic = true,
                       .scopes = {"message.send"},
                       .supported_bits = protocol_1_2_capability_bits}};
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  ASSERT_TRUE(harness.left->pairing_restricted());
  EXPECT_FALSE(harness.left->basic_communication_active());
  EXPECT_TRUE(harness.left->diagnostics().policy_scopes.empty());
  EXPECT_FALSE(harness.left->diagnostics().last_error.has_value());
  EXPECT_TRUE(harness.right->pairing_restricted());
  EXPECT_FALSE(harness.right->basic_communication_active());

  // The legacy pairing path is intact on the fallback session.
  const auto submitted = harness.left->submit_pairing_request(
      RequestId{filled<RequestId::Storage>(0xC4U)}, "target-password",
      {"message.send"});
  ASSERT_TRUE(submitted) << submitted.error_if()->safe_detail();
  harness.pump_all();
  EXPECT_TRUE(harness.left->authenticated());
  EXPECT_TRUE(harness.right->authenticated());
  EXPECT_EQ(harness.left->authorized_scopes(),
            std::vector<std::string>{"message.send"});
}

// B5: with the policy enabled but neither Capability::message nor
// Capability::pairing negotiated, the session fails closed with the stable
// pairing_capability_absent outcome (RULE-03).
TEST(M5BasicSession, BasicWithoutAnyEligibleCapabilityFailsClosed) {
  const std::uint64_t no_basic_bits =
      protocol_1_2_capability_bits &
      ~(static_cast<std::uint64_t>(Capability::message) |
        static_cast<std::uint64_t>(Capability::pairing));
  BasicSessionPair harness{
      BasicSideOptions{.basic = true,
                       .scopes = {"message.send"},
                       .supported_bits = no_basic_bits},
      BasicSideOptions{.basic = true,
                       .scopes = {"message.send"},
                       .supported_bits = protocol_1_2_capability_bits}};
  ASSERT_TRUE(harness.left->start());
  ASSERT_TRUE(harness.right->start());
  harness.pump_all();
  const auto left_state = harness.left->diagnostics();
  EXPECT_EQ(left_state.state, PeerSessionState::closed);
  ASSERT_TRUE(left_state.last_error.has_value());
  EXPECT_EQ(left_state.last_error->code(), ErrorCode::pairing_denied);
  EXPECT_EQ(left_state.last_error->safe_detail(), "pairing_capability_absent");
  const auto right_state = harness.right->diagnostics();
  EXPECT_EQ(right_state.state, PeerSessionState::closed);
  ASSERT_TRUE(right_state.last_error.has_value());
  EXPECT_EQ(right_state.last_error->safe_detail(), "pairing_capability_absent");
}

}  // namespace
}  // namespace heyaki
