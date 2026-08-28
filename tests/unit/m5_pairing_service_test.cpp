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

  void SetUp() override {
    root = std::filesystem::temp_directory_path() /
           ("heyaki-m5-pairing-" + std::to_string(::testing::UnitTest::GetInstance()
                                                      ->random_seed()));
    std::filesystem::create_directories(root);
    // ProfileStore enforces owner-only directory permissions.
    std::filesystem::permissions(root, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    auto target = ProfileStore::create(root / "target.sqlite");
    ASSERT_TRUE(target);
    target_store.emplace(std::move(*target.value_if()));
    auto initiator = ProfileStore::create(root / "initiator.sqlite");
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

}  // namespace
}  // namespace heyaki
