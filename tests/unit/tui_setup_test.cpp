#include "local_setup.hpp"

#include <heyaki/password.hpp>
#include <heyaki/profile_store.hpp>

#include <gtest/gtest.h>

#include <deque>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace heyaki::tui {
namespace {

constexpr std::string_view application_id{"org.heyaki.tui"};
constexpr std::string_view valid_password{"correct horse battery staple"};

class TuiSetupTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = std::filesystem::path{HEYAKI_TUI_TEST_STATE_DIR} /
            ::testing::UnitTest::GetInstance()->current_test_info()->name();
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
  }

  void TearDown() override {
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
  }

  [[nodiscard]] std::filesystem::path profile_path() const {
    return root_ / "profile.sqlite";
  }

  [[nodiscard]] static ProfileOpenOptions profile_options() {
    ProfileOpenOptions options;
    options.secret_backend.prefer_os_backend = false;
    return options;
  }

 private:
  std::filesystem::path root_;
};

TEST_F(TuiSetupTest, RetriesMismatchAndPasswordPolicyErrorsBeforeReturningSetup) {
  std::deque<Result<std::string>> inputs;
  inputs.push_back(Result<std::string>::success("first password"));
  inputs.push_back(Result<std::string>::success("different password"));
  inputs.push_back(Result<std::string>::success("short"));
  inputs.push_back(Result<std::string>::success("short"));
  inputs.push_back(Result<std::string>::success(std::string{valid_password}));
  inputs.push_back(Result<std::string>::success(std::string{valid_password}));
  std::vector<std::string> prompts;
  std::vector<std::string> retryable_errors;

  auto setup = read_local_profile_initialization(
      application_id,
      [&](std::string_view prompt) {
        prompts.emplace_back(prompt);
        EXPECT_FALSE(inputs.empty());
        auto input = std::move(inputs.front());
        inputs.pop_front();
        return input;
      },
      [&](const Error& error) {
        retryable_errors.emplace_back(error.safe_detail());
      });

  ASSERT_TRUE(setup) << setup.error_if()->safe_detail();
  EXPECT_TRUE(inputs.empty());
  EXPECT_EQ(prompts, (std::vector<std::string>{
                         "password (minimum 8 Unicode characters): ",
                         "confirm password: ",
                         "password (minimum 8 Unicode characters): ",
                         "confirm password: ",
                         "password (minimum 8 Unicode characters): ",
                         "confirm password: "}));
  EXPECT_EQ(retryable_errors,
            (std::vector<std::string>{"password_confirmation_mismatch",
                                      "password_too_short"}));
  EXPECT_EQ(setup.value_if()->application_id, application_id);
  auto matches = verify_password(valid_password,
                                 setup.value_if()->password_verifier);
  ASSERT_TRUE(matches) << matches.error_if()->safe_detail();
  EXPECT_TRUE(*matches.value_if());
}

TEST_F(TuiSetupTest, StopsRetryingWhenSecretInputIsCancelled) {
  std::size_t reads = 0U;
  auto setup = read_local_profile_initialization(
      application_id, [&](std::string_view) {
        ++reads;
        return Result<std::string>::failure(
            Error{ErrorCode::cancelled, "tui", "input_closed"});
      });

  ASSERT_FALSE(setup);
  EXPECT_EQ(setup.error_if()->code(), ErrorCode::cancelled);
  EXPECT_EQ(setup.error_if()->safe_detail(), "input_closed");
  EXPECT_EQ(reads, 1U);
}

TEST_F(TuiSetupTest, ReopensAndCompletesAnIncompleteProfile) {
  DeviceId device_id;
  {
    auto created = ProfileStore::create(profile_path(), profile_options());
    ASSERT_TRUE(created) << created.error_if()->safe_detail();
    device_id = created.value_if()->device_id();
    auto readiness = created.value_if()->local_readiness(application_id);
    ASSERT_TRUE(readiness) << readiness.error_if()->safe_detail();
    EXPECT_FALSE(readiness.value_if()->ready());
  }

  auto reopened = ProfileStore::open(profile_path(), profile_options());
  ASSERT_TRUE(reopened) << reopened.error_if()->safe_detail();
  EXPECT_EQ(reopened.value_if()->device_id(), device_id);
  std::deque<std::string> inputs{std::string{valid_password},
                                 std::string{valid_password}};
  auto setup = read_local_profile_initialization(
      application_id, [&](std::string_view) {
        auto input = std::move(inputs.front());
        inputs.pop_front();
        return Result<std::string>::success(std::move(input));
      });
  ASSERT_TRUE(setup) << setup.error_if()->safe_detail();

  auto initialized = reopened.value_if()->initialize_local(*setup.value_if());
  ASSERT_TRUE(initialized) << initialized.error_if()->safe_detail();
  auto readiness = reopened.value_if()->local_readiness(application_id);
  ASSERT_TRUE(readiness) << readiness.error_if()->safe_detail();
  EXPECT_TRUE(readiness.value_if()->ready());
}

}  // namespace
}  // namespace heyaki::tui
