#include <heyaki/profile_store.hpp>

#include <filesystem>
#include <iostream>
#include <string_view>

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: heyaki-m2-profile-demo <profile-directory>\n";
    return 2;
  }

  const auto database = std::filesystem::path{argv[1]} / "profile.sqlite";
  auto profile = std::filesystem::exists(database) ? heyaki::ProfileStore::open(database)
                                                   : heyaki::ProfileStore::create(database);
  if (!profile) {
    std::cerr << heyaki::error_code_name(profile.error_if()->code()) << ':'
              << profile.error_if()->safe_detail() << '\n';
    return 1;
  }

  auto tui_endpoint = profile.value_if()->endpoint_for("org.heyaki.tui");
  auto demo_endpoint = profile.value_if()->endpoint_for("org.heyaki.m2-demo");
  if (!tui_endpoint || !demo_endpoint) {
    const auto* error = tui_endpoint ? demo_endpoint.error_if() : tui_endpoint.error_if();
    std::cerr << heyaki::error_code_name(error->code()) << ':' << error->safe_detail() << '\n';
    return 1;
  }

  std::cout << "device=" << heyaki::to_string(profile.value_if()->device_id()) << '\n'
            << "org.heyaki.tui=" << heyaki::to_string(*tui_endpoint.value_if()) << '\n'
            << "org.heyaki.m2-demo=" << heyaki::to_string(*demo_endpoint.value_if()) << '\n';
  return 0;
}
