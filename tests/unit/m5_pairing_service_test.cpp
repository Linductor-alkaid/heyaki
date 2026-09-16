// M5 pairing service tests against real ProfileStore state: password
// verification with policy scope intersection (M5-09), per-source failure
// backoff (M5-10), grant issuance and session authorization (M5-11/M5-12),
// revocation and rotation modes (M5-13).

#include "pairing_service.hpp"

#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

namespace heyaki {
namespace {

constexpr std::uint64_t kNow = 1'700'000'000'000U;

struct PairingServiceTest : public ::testing::Test {
  std::filesystem::path root;
  std::optional<ProfileStore> target_store;
  std::optional<ProfileStore> initiator_store;
  std::unique_ptr<PairingService> service;
  std::uint64_t wall_clock = kNow;
  std::vector<PairingAuditKind> audits;
  std::vector<PairingAuditEvent> audit_events;

  void SetUp() override {
    root = std::filesystem::temp_directory_path() /
           ("heyaki-m5-pairing-" + std::to_string(::testing::UnitTest::GetInstance()
                                                      ->random_seed()));
    std::filesystem::create_directories(root);
    // ProfileStore enforces owner-only directory permissions.
    std::filesystem::permissions(root, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    // Disable the OS secret backend like every other profile test: its
    // glib-internal allocator trips ThreadSanitizer and adds nothing here.
    ProfileOpenOptions open_options;
    open_options.secret_backend.prefer_os_backend = false;
    auto target = ProfileStore::create(root / "target.sqlite", open_options);
    ASSERT_TRUE(target);
    target_store.emplace(std::move(*target.value_if()));
    auto initiator = ProfileStore::create(root / "initiator.sqlite", open_options);
    ASSERT_TRUE(initiator);
    initiator_store.emplace(std::move(*initiator.value_if()));

    auto verifier =
        create_password_verifier("target-password", PasswordHashParameters{});
    ASSERT_TRUE(verifier);
    auto policy = PairingPolicy{};
    policy.default_scopes = {"message.send", "stream.open"};
    LocalProfileInitialization initialization;
    initialization.application_id = "com.example.test";
    initialization.password_verifier = std::move(*verifier.value_if());
    initialization.password_generation = 1U;
    initialization.pairing_policy = policy;
    ASSERT_TRUE(target_store->initialize_local(initialization));
    ASSERT_TRUE(initiator_store->initialize_local(initialization));

    auto target_identity = target_store->load_identity();
    ASSERT_TRUE(target_identity);
    PairingServiceConfig config{
        .profile = &*target_store,
        .identity = std::move(*target_identity.value_if())};
    config.failure_threshold = 2U;
    config.backoff_base = std::chrono::milliseconds{1000};
    config.backoff_max = std::chrono::milliseconds{4000};
    config.wall_clock = [this] { return wall_clock; };
    config.audit_sink = [this](const PairingAuditEvent& event) {
      audits.push_back(event.kind);
      audit_events.push_back(event);
    };
    service = std::make_unique<PairingService>(std::move(config));
  }

  void TearDown() override {
    service.reset();
    target_store.reset();
    initiator_store.reset();
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
  }

  PairingRequestBody request(std::string_view password,
                             std::vector<std::string> scopes) {
    PairingRequestBody body;
    RequestId::Storage bytes{};
    bytes[0] = static_cast<std::byte>((request_sequence += 1U) & 0xFFU);
    bytes[1] = std::byte{1U};
    body.request_id = RequestId{bytes};
    body.nonce = PairingNonce{};
    body.nonce[0] = static_cast<std::byte>((request_sequence += 1U) & 0xFFU);
    body.nonce[1] = std::byte{2U};
    body.password_utf8 = std::string{password};
    body.requested_scopes = std::move(scopes);
    return body;
  }

  std::uint32_t request_sequence = 0U;
};

TEST_F(PairingServiceTest, CorrectPasswordGrantsPolicyIntersection) {
  auto evaluated = service->evaluate(
      request("target-password", {"message.send", "shell.open:x"}),
      initiator_store->device_id(), initiator_store->identity_public_key());
  ASSERT_TRUE(evaluated);
  const auto& result = *evaluated.value_if();
  EXPECT_EQ(result.status, StableStatus::ok);
  ASSERT_TRUE(result.grant.has_value());
  EXPECT_EQ(result.grant->granted_scopes, std::vector<std::string>{"message.send"});
  EXPECT_EQ(result.grant->subject, initiator_store->device_id());
  EXPECT_EQ(result.grant->issuer, target_store->device_id());

  // Session authorization sees the issued grant (M5-12).
  auto authorization = service->authorize(initiator_store->device_id(), wall_clock);
  ASSERT_TRUE(authorization);
  EXPECT_TRUE(authorization.value_if()->trusted);
  EXPECT_EQ(authorization.value_if()->scopes,
            std::vector<std::string>{"message.send"});
}

TEST_F(PairingServiceTest, WrongPasswordCountsFailuresAndBacksOff) {
  const auto peer = initiator_store->device_id();
  for (int attempt = 0; attempt < 2; ++attempt) {
    auto denied = service->evaluate(request("wrong", {"message.send"}), peer,
                                    initiator_store->identity_public_key());
    ASSERT_TRUE(denied);
    EXPECT_EQ(denied.value_if()->status, StableStatus::unauthenticated);
  }
  // The failure threshold is reached: further attempts rate-limit BEFORE
  // password verification, without a permanent lockout.
  auto throttled =
      service->evaluate(request("target-password", {"message.send"}), peer,
                        initiator_store->identity_public_key());
  ASSERT_TRUE(throttled);
  EXPECT_EQ(throttled.value_if()->status, StableStatus::resource_exhausted);

  // After the backoff window a correct password succeeds and clears failures.
  wall_clock += 2000U;
  auto recovery = service->evaluate(request("target-password", {"message.send"}), peer,
                                    initiator_store->identity_public_key());
  ASSERT_TRUE(recovery);
  EXPECT_EQ(recovery.value_if()->status, StableStatus::ok);
  auto authorization = service->authorize(peer, wall_clock);
  ASSERT_TRUE(authorization);
  EXPECT_TRUE(authorization.value_if()->trusted);
}

TEST_F(PairingServiceTest, RevokedGrantNoLongerAuthorizesTheSession) {
  const auto peer = initiator_store->device_id();
  auto evaluated = service->evaluate(request("target-password", {"message.send"}), peer,
                                    initiator_store->identity_public_key());
  ASSERT_TRUE(evaluated && evaluated.value_if()->grant.has_value());
  ASSERT_TRUE(service->authorize(peer, wall_clock).value_if()->trusted);

  // The initiator stores its received grant; revoking on the target must
  // close the session authorization even though the peer still holds the
  // grant bytes (exit condition: stale grants cannot restore access).
  const auto grant_id = evaluated.value_if()->grant->grant_id;
  const auto& issued = *evaluated.value_if()->grant;
  auto stored = initiator_store->put_trust_grant(
      TrustGrantRecord{.grant_id = grant_id,
                       .direction = TrustGrantDirection::received,
                       .issuer = target_store->device_id(),
                       .subject = peer,
                       .scopes = {"message.send"},
                       .password_generation = 1U,
                       .issued_unix_milliseconds = wall_clock,
                       .signature = std::vector<std::byte>(issued.signature.begin(),
                                                           issued.signature.end()),
                       .revoked = false});
  ASSERT_TRUE(stored);
  ASSERT_TRUE(service->revoke_grant(grant_id));

  auto authorization = service->authorize(peer, wall_clock);
  ASSERT_TRUE(authorization);
  EXPECT_FALSE(authorization.value_if()->trusted);
}

TEST_F(PairingServiceTest, RotationModesSplitGrantFate) {
  const auto peer = initiator_store->device_id();
  auto first = service->evaluate(request("target-password", {"message.send"}), peer,
                                 initiator_store->identity_public_key());
  ASSERT_TRUE(first && first.value_if()->grant.has_value());

  // Mode 1: rotate only. The grant stays valid; the new verifier answers the
  // next pairing attempt.
  auto rotated_verifier =
      create_password_verifier("rotated-password", PasswordHashParameters{});
  ASSERT_TRUE(rotated_verifier);
  auto rotated = service->rotate_password(*rotated_verifier.value_if());
  ASSERT_TRUE(rotated);
  EXPECT_EQ(*rotated.value_if(), 2U);
  auto still_trusted = service->authorize(peer, wall_clock);
  ASSERT_TRUE(still_trusted);
  EXPECT_TRUE(still_trusted.value_if()->trusted);

  // Old password can no longer create new trust; new one can.
  auto old_password = service->evaluate(request("target-password", {"message.send"}),
                                        peer, initiator_store->identity_public_key());
  ASSERT_TRUE(old_password);
  EXPECT_EQ(old_password.value_if()->status, StableStatus::unauthenticated);
  auto new_password = service->evaluate(request("rotated-password", {"message.send"}),
                                        peer, initiator_store->identity_public_key());
  ASSERT_TRUE(new_password);
  EXPECT_EQ(new_password.value_if()->status, StableStatus::ok);

  // Mode 2: rotate and revoke. Grants from older generations die.
  auto second_verifier =
      create_password_verifier("final-password", PasswordHashParameters{});
  ASSERT_TRUE(second_verifier);
  auto rotated_and_revoked =
      service->rotate_password_and_revoke_grants(*second_verifier.value_if());
  ASSERT_TRUE(rotated_and_revoked);
  auto authorization = service->authorize(peer, wall_clock);
  ASSERT_TRUE(authorization);
  EXPECT_FALSE(authorization.value_if()->trusted);
}

TEST_F(PairingServiceTest, InitiatorSideAcceptsOnlyWellBoundedGrants) {
  const auto peer = initiator_store->device_id();
  auto evaluated = service->evaluate(request("target-password", {"message.send"}), peer,
                                    initiator_store->identity_public_key());
  ASSERT_TRUE(evaluated && evaluated.value_if()->grant.has_value());
  const auto& result = *evaluated.value_if();

  // Rebind the pairing service to the INITIATOR profile to verify grants as
  // the connecting device would.
  auto initiator_identity = initiator_store->load_identity();
  ASSERT_TRUE(initiator_identity);
  PairingServiceConfig config{
      .profile = &*initiator_store,
      .identity = std::move(*initiator_identity.value_if())};
  config.wall_clock = [this] { return wall_clock; };
  PairingService verifier{std::move(config)};

  // Wrong pending nonce or overreaching scopes are rejected.
  PairingNonce wrong_nonce{};
  wrong_nonce[3] = std::byte{9U};
  auto bad_nonce = verifier.accept_grant(result, result.request_id, wrong_nonce,
                                         target_store->device_id(),
                                         target_store->identity_public_key(),
                                         {"message.send"});
  ASSERT_FALSE(bad_nonce);
  auto overreach = verifier.accept_grant(
      result, result.request_id, result.grant->nonce, target_store->device_id(),
      target_store->identity_public_key(), {"event.subscribe"});
  ASSERT_FALSE(overreach);
  // The properly bound grant verifies under the issuer's key and persists.
  auto accepted =
      verifier.accept_grant(result, result.request_id, result.grant->nonce,
                             target_store->device_id(), target_store->identity_public_key(),
                             {"message.send"});
  ASSERT_TRUE(accepted);
  auto grants = verifier.grants_for_peer(target_store->device_id(), wall_clock);
  ASSERT_TRUE(grants);
  ASSERT_EQ(grants.value_if()->size(), 1U);
  EXPECT_EQ((*grants.value_if())[0].direction, TrustGrantDirection::received);
}

// M9-15 security regression: the per-source backoff must double with every
// failure past the threshold and clamp at backoff_max — a linear or unclamped
// schedule would let a patient guesser outrun the delay or lock the target out
// permanently.
TEST_F(PairingServiceTest, BackoffProgressionDoublesPerFailureAndClampsAtMax) {
  const auto peer = initiator_store->device_id();
  const auto key = initiator_store->identity_public_key();
  const auto wrong = [&](std::uint64_t now) {
    wall_clock = now;
    auto evaluated = service->evaluate(request("wrong", {"message.send"}), peer, key);
    EXPECT_TRUE(evaluated);
    EXPECT_EQ(evaluated.value_if()->status, StableStatus::unauthenticated);
  };
  // A blocked probe uses the CORRECT password: if it were verified the status
  // would be ok, so resource_exhausted proves the gate fires before any
  // expensive verification (and records no new failure).
  const auto blocked_at = [&](std::uint64_t now) {
    wall_clock = now;
    auto evaluated =
        service->evaluate(request("target-password", {"message.send"}), peer, key);
    if (!evaluated) {
      return false;
    }
    return evaluated.value_if()->status == StableStatus::resource_exhausted;
  };

  // Two failures reach the threshold: the window is base * 2^0.
  wrong(kNow);
  wrong(kNow);
  const std::uint64_t first_failure = kNow;
  EXPECT_TRUE(blocked_at(first_failure + 999U));
  // Window open: a wrong password fails freely and doubles the next window.
  wrong(first_failure + 1000U);
  const std::uint64_t third_failure = first_failure + 1000U;

  // Failure three doubles to base * 2^1.
  EXPECT_TRUE(blocked_at(third_failure + 1999U));
  wrong(third_failure + 2000U);
  const std::uint64_t fourth_failure = third_failure + 2000U;

  // Failure four doubles to base * 2^2 = backoff_max.
  EXPECT_TRUE(blocked_at(fourth_failure + 3999U));
  wrong(fourth_failure + 4000U);
  const std::uint64_t fifth_failure = fourth_failure + 4000U;

  // Failure five would double past the cap: the window stays at backoff_max.
  EXPECT_TRUE(blocked_at(fifth_failure + 3999U));
  EXPECT_FALSE(blocked_at(fifth_failure + 4000U));
  wall_clock = fifth_failure + 4000U;
  auto recovered =
      service->evaluate(request("target-password", {"message.send"}), peer, key);
  ASSERT_TRUE(recovered);
  EXPECT_EQ(recovered.value_if()->status, StableStatus::ok);
  // A successful verification clears the source's failure state entirely.
  wall_clock += 1U;
  auto immediate =
      service->evaluate(request("target-password", {"message.send"}), peer, key);
  ASSERT_TRUE(immediate);
  EXPECT_EQ(immediate.value_if()->status, StableStatus::ok);
}

// M9-15 security regression: guessing pressure from one source must not throttle
// an independent source — the failure table is keyed per peer, and there is no
// global lockout an attacker could trip to deny pairing to everyone else.
TEST_F(PairingServiceTest, IndependentSourcePairsWhileAnotherSourceIsThrottled) {
  const auto noisy = initiator_store->device_id();
  const auto noisy_key = initiator_store->identity_public_key();
  for (int attempt = 0; attempt < 2; ++attempt) {
    auto denied = service->evaluate(request("wrong", {"message.send"}), noisy,
                                    noisy_key);
    ASSERT_TRUE(denied);
    EXPECT_EQ(denied.value_if()->status, StableStatus::unauthenticated);
  }
  auto throttled = service->evaluate(request("target-password", {"message.send"}),
                                     noisy, noisy_key);
  ASSERT_TRUE(throttled);
  EXPECT_EQ(throttled.value_if()->status, StableStatus::resource_exhausted);

  // A different device pairs successfully at the same instant.
  auto quiet = create_identity();
  ASSERT_TRUE(quiet) << quiet.error_if()->safe_detail();
  auto paired = service->evaluate(request("target-password", {"message.send"}),
                                  quiet.value_if()->device_id(),
                                  quiet.value_if()->public_key());
  ASSERT_TRUE(paired);
  EXPECT_EQ(paired.value_if()->status, StableStatus::ok);
  ASSERT_TRUE(paired.value_if()->grant.has_value());
  EXPECT_EQ(paired.value_if()->grant->subject, quiet.value_if()->device_id());
}

// M9-15 security regression: a grant whose signature does not verify under the
// issuer's key must be refused by the initiator-side acceptor — a tampered or
// third-party-forged grant never enters the local TrustStore.
TEST_F(PairingServiceTest, TamperedGrantSignatureIsRejectedByInitiatorAcceptor) {
  const auto peer = initiator_store->device_id();
  auto evaluated = service->evaluate(request("target-password", {"message.send"}), peer,
                                     initiator_store->identity_public_key());
  ASSERT_TRUE(evaluated && evaluated.value_if()->grant.has_value());
  auto result = *evaluated.value_if();

  auto initiator_identity = initiator_store->load_identity();
  ASSERT_TRUE(initiator_identity);
  PairingServiceConfig config{
      .profile = &*initiator_store,
      .identity = std::move(*initiator_identity.value_if())};
  config.wall_clock = [this] { return wall_clock; };
  PairingService verifier{std::move(config)};

  // Flip one signature byte: the canonical object no longer verifies.
  auto tampered = result;
  tampered.grant->signature[0] ^= std::byte{0x01U};
  auto rejected = verifier.accept_grant(tampered, result.request_id,
                                        result.grant->nonce,
                                        target_store->device_id(),
                                        target_store->identity_public_key(),
                                        {"message.send"});
  EXPECT_FALSE(rejected);
  EXPECT_EQ(rejected.error_if()->code(), ErrorCode::authentication);

  // Nothing from the forgery attempt persisted.
  auto grants = verifier.grants_for_peer(target_store->device_id(), wall_clock);
  ASSERT_TRUE(grants);
  EXPECT_TRUE(grants.value_if()->empty());
}

// M9-15 security regression: the pairing password exists only inside the
// verification boundary — audit events and every profile artifact on disk
// (SQLite database, secret backend files) must never contain the password
// literal, on either the wrong-password guessing path or the accepted path.
TEST_F(PairingServiceTest, PasswordLiteralNeverReachesAuditOrProfileBytes) {
  // This profile's verifier is for "target-password"; a different literal is
  // the guessing path where a leak would surface.
  const std::string foreign{"hunter-password-DO-NOT-LEAK-7f3a"};
  const auto peer = initiator_store->device_id();
  const auto key = initiator_store->identity_public_key();
  // One guessing failure (below the backoff threshold) then the accepted path:
  // both audit trails must stay free of the literals.
  auto denied = service->evaluate(request(foreign, {"message.send"}), peer, key);
  ASSERT_TRUE(denied);
  EXPECT_EQ(denied.value_if()->status, StableStatus::unauthenticated);
  auto accepted =
      service->evaluate(request("target-password", {"message.send"}), peer, key);
  ASSERT_TRUE(accepted);
  EXPECT_EQ(accepted.value_if()->status, StableStatus::ok);

  for (const auto& event : audit_events) {
    const std::string_view detail{event.detail};
    EXPECT_EQ(detail.find(foreign), std::string_view::npos);
    EXPECT_EQ(detail.find("target-password"), std::string_view::npos);
    EXPECT_EQ(detail.find("argon2"), std::string_view::npos);
  }
  std::error_code ignored;
  for (const auto& entry :
       std::filesystem::recursive_directory_iterator(root, ignored)) {
    if (!entry.is_regular_file()) {
      continue;
    }
    std::ifstream input{entry.path(), std::ios::binary};
    const std::string bytes{std::istreambuf_iterator<char>{input},
                            std::istreambuf_iterator<char>{}};
    EXPECT_EQ(bytes.find(foreign), std::string::npos)
        << "password literal leaked into " << entry.path();
  }
}


}  // namespace
}  // namespace heyaki
