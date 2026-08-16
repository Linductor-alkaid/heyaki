#pragma once

#include <heyaki/profile_store.hpp>

#include <functional>
#include <string>
#include <string_view>

namespace heyaki::tui {

using SecretReader = std::function<Result<std::string>(std::string_view)>;
using SetupErrorObserver = std::function<void(const Error&)>;

[[nodiscard]] Result<LocalProfileInitialization> read_local_profile_initialization(
    std::string_view application_id, const SecretReader& read_secret,
    const SetupErrorObserver& retryable_error = {});

}  // namespace heyaki::tui
