// Validates an extracted ```heyaki-relay-config doc block through the real
// parser + validator (M9-16). The doc samples use relative certificate
// paths, which the relay resolves against the config file's directory, so
// the check copies the config into a scratch directory and materializes the
// referenced files (existence is all load_relay_config_file requires).
#include "relay_config.hpp"

#include <heyaki/error.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace {

bool touch(const std::filesystem::path& path) {
  std::error_code error;
  std::filesystem::create_directories(path.parent_path(), error);
  if (error) {
    return false;
  }
  std::ofstream output{path, std::ios::binary};
  return static_cast<bool>(output);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "usage: heyaki-doc-relay-config-check <config> <work-dir>\n";
    return 2;
  }
  const std::filesystem::path extracted{argv[1]};
  const std::filesystem::path work_dir{argv[2]};

  std::ifstream input{extracted, std::ios::binary};
  if (!input) {
    std::cerr << "extracted config missing: " << extracted.string() << "\n";
    return 1;
  }
  std::string contents((std::istreambuf_iterator<char>{input}),
                       std::istreambuf_iterator<char>{});

  const auto config_path = work_dir / "relay.conf";
  {
    std::ofstream output{config_path, std::ios::binary | std::ios::trunc};
    output << contents;
    if (!output) {
      std::cerr << "failed to stage config copy\n";
      return 1;
    }
  }

  // First pass on a stub with missing certificate files must be rejected
  // with the documented error - this pins the load-time existence check.
  {
    const auto missing = heyaki::load_relay_config_file(config_path);
    if (missing) {
      std::cerr << "config with missing certificates must not load\n";
      return 1;
    }
    const auto* error = missing.error_if();
    if (error->component() != "relay_config" ||
        (error->safe_detail() != "relay_config_certificate_missing" &&
         error->safe_detail() != "relay_config_private_key_missing")) {
      std::cerr << "unexpected error for missing certificates: "
                << error->safe_detail() << "\n";
      return 1;
    }
  }

  // Materialize every referenced relative path as an empty stub. The config
  // grammar keeps paths on their own lines; scan for the three path keys.
  std::size_t offset = 0U;
  while (offset < contents.size()) {
    const auto newline = contents.find('\n', offset);
    const auto line = contents.substr(
        offset, newline == std::string::npos ? std::string::npos : newline - offset);
    offset = newline == std::string::npos ? contents.size() : newline + 1U;
    for (const std::string key : {"tls_certificate_file", "tls_private_key_file",
                                  "database_file"}) {
      const auto prefix = key + " = ";
      if (line.rfind(prefix, 0U) != 0U) {
        continue;
      }
      auto value = line.substr(prefix.size());
      while (!value.empty() && (value.back() == '\r' || value.back() == ' ')) {
        value.pop_back();
      }
      if (value.empty() || value == ":memory:") {
        continue;
      }
      const std::filesystem::path referenced{value};
      if (referenced.is_absolute()) {
        continue;
      }
      if (!touch(work_dir / referenced)) {
        std::cerr << "failed to stage referenced path: " << value << "\n";
        return 1;
      }
    }
  }

  const auto loaded = heyaki::load_relay_config_file(config_path);
  if (!loaded) {
    const auto* error = loaded.error_if();
    std::cerr << "doc relay config failed to load: "
              << heyaki::error_code_name(error->code()) << " "
              << error->safe_detail() << "\n";
    return 1;
  }
  const auto& config = *loaded.value_if();
  std::cout << "listen_port=" << config.listen_port
            << " database=" << config.database_file.string() << "\n";
  return 0;
}
