#include <heyaki/version.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: heyaki_fuzz_smoke <corpus-directory>\n";
    return 2;
  }

  const std::filesystem::path corpus_dir{argv[1]};
  std::filesystem::create_directories(corpus_dir);
  const auto seed_path = corpus_dir / "m0-version.seed";
  std::ofstream seed{seed_path, std::ios::binary | std::ios::trunc};
  if (!seed) {
    std::cerr << "cannot create fuzz smoke seed: " << seed_path << '\n';
    return 1;
  }
  seed << heyaki::build_info().version;
  return seed ? 0 : 1;
}

