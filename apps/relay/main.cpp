#include <heyaki/version.hpp>

#include <iostream>
#include <string_view>

int main(int argc, char** argv) {
  const auto info = heyaki::build_info();
  if (argc == 2 && std::string_view{argv[1]} == "--version") {
    std::cout << "heyaki-relay " << info.version << " (" << info.commit << ")\n";
    return 0;
  }
  std::cout << "heyaki-relay: M0 build baseline; runtime is not implemented yet\n";
  return 0;
}

