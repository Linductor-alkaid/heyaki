#include <heyaki/version.hpp>

int main() {
  return heyaki::build_info().version.empty() ? 1 : 0;
}

