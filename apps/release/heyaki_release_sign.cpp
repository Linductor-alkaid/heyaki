// heyaki-release-sign: release artifact signing for M9-14.
//
// The v1 release procedure signs the content of a release bundle (binaries,
// SBOM, license manifest) with an offline-held Ed25519 key through the pinned
// libsodium:
//
//   keygen <secret-key> <public-key>
//       Generate an Ed25519 keypair. The secret key file is created with
//       owner-only permissions; generate it on the signing host, not in the
//       release working tree.
//   manifest <root-dir> <manifest-out>
//       Walk root-dir deterministically (regular files only, byte-wise sorted
//       POSIX relative paths, symlinks skipped) and write a manifest of
//       SHA-256 digests.
//   sign <manifest> <secret-key>
//       Detached Ed25519 signature over the manifest bytes, written next to
//       it as <manifest>.sig.
//   verify <manifest> <public-key> <signature>
//       Verify the manifest signature only.
//   check <manifest> <root-dir>
//       Re-hash root-dir against the manifest; missing, extra, or modified
//       files fail. A release consumer runs verify then check.
//
// The tool is a single-shot synchronous CLI: it owns no concurrent work, so
// nothing here needs an executor context.

#include <sodium.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace fs = std::filesystem;

int usage() {
  std::cerr << "usage:\n"
            << "  heyaki-release-sign keygen <secret-key-out> <public-key-out>\n"
            << "  heyaki-release-sign manifest <root-dir> <manifest-out>\n"
            << "  heyaki-release-sign sign <manifest> <secret-key>\n"
            << "  heyaki-release-sign verify <manifest> <public-key> <signature>\n"
            << "  heyaki-release-sign check <manifest> <root-dir>\n";
  return 2;
}

int fail(int code, std::string_view message) {
  std::cerr << "heyaki-release-sign: " << message << '\n';
  return code;
}

char hex_digit(unsigned value) {
  const auto digit = static_cast<unsigned char>(value & 0x0FU);
  return static_cast<char>(digit < 10U ? ('0' + digit) : ('a' + (digit - 10U)));
}

std::string to_hex(const unsigned char* bytes, std::size_t count) {
  std::string out;
  out.reserve(count * 2U);
  for (std::size_t index = 0; index < count; ++index) {
    out.push_back(hex_digit(bytes[index] >> 4U));
    out.push_back(hex_digit(bytes[index]));
  }
  return out;
}

int hex_value(char digit) {
  if (digit >= '0' && digit <= '9') {
    return digit - '0';
  }
  if (digit >= 'a' && digit <= 'f') {
    return digit - 'a' + 10;
  }
  if (digit >= 'A' && digit <= 'F') {
    return digit - 'A' + 10;
  }
  return -1;
}

std::optional<std::vector<unsigned char>> from_hex(std::string_view text) {
  if (text.size() % 2U != 0U) {
    return std::nullopt;
  }
  std::vector<unsigned char> out;
  out.reserve(text.size() / 2U);
  for (std::size_t index = 0; index < text.size(); index += 2U) {
    const int high = hex_value(text[index]);
    const int low = hex_value(text[index + 1U]);
    if (high < 0 || low < 0) {
      return std::nullopt;
    }
    const auto byte = static_cast<unsigned char>((high << 4) | low);
    out.push_back(byte);
  }
  return out;
}

std::optional<std::vector<unsigned char>> read_file_bytes(const fs::path& path) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    std::cerr << "heyaki-release-sign: cannot open " << path.string() << '\n';
    return std::nullopt;
  }
  const auto end = input.tellg();
  if (end < 0) {
    return std::nullopt;
  }
  const auto size = static_cast<std::size_t>(end);
  input.seekg(0, std::ios::beg);
  std::vector<unsigned char> bytes(size);
  if (size > 0U) {
    input.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(size));
    if (!input) {
      std::cerr << "heyaki-release-sign: short read from " << path.string() << '\n';
      return std::nullopt;
    }
  }
  return bytes;
}

bool write_file_bytes(const fs::path& path, const unsigned char* bytes,
                      std::size_t count) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) {
    std::cerr << "heyaki-release-sign: cannot create " << path.string() << '\n';
    return false;
  }
  if (count > 0U) {
    output.write(reinterpret_cast<const char*>(bytes),
                 static_cast<std::streamsize>(count));
  }
  output.flush();
  if (!output) {
    std::cerr << "heyaki-release-sign: short write to " << path.string() << '\n';
    return false;
  }
  return true;
}

std::optional<std::string> read_key_file(const fs::path& path, std::size_t expected_bytes) {
  const auto bytes = read_file_bytes(path);
  if (!bytes.has_value()) {
    return std::nullopt;
  }
  const std::string text((*bytes).begin(), (*bytes).end());
  std::string trimmed;
  trimmed.reserve(text.size());
  for (const char digit : text) {
    if (digit != '\n' && digit != '\r') {
      trimmed.push_back(digit);
    }
  }
  auto key = from_hex(trimmed);
  if (!key.has_value() || (*key).size() != expected_bytes) {
    std::cerr << "heyaki-release-sign: " << path.string()
              << " is not a " << expected_bytes << "-byte hex key\n";
    return std::nullopt;
  }
  return std::string(trimmed);
}

std::optional<std::string> sha256_hex(const fs::path& path) {
  const auto bytes = read_file_bytes(path);
  if (!bytes.has_value()) {
    return std::nullopt;
  }
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  if (crypto_hash_sha256_update(&state, (*bytes).data(), (*bytes).size()) != 0) {
    return std::nullopt;
  }
  unsigned char digest[crypto_hash_sha256_BYTES];
  if (crypto_hash_sha256_final(&state, digest) != 0) {
    return std::nullopt;
  }
  return to_hex(digest, sizeof digest);
}

std::optional<std::vector<std::string>> bundle_files(const fs::path& root) {
  std::error_code error;
  const auto root_status = fs::symlink_status(root, error);
  if (error || !fs::is_directory(root_status)) {
    std::cerr << "heyaki-release-sign: not a directory: " << root.string() << '\n';
    return std::nullopt;
  }
  std::vector<std::string> files;
  fs::recursive_directory_iterator iterator(root, fs::directory_options::none, error);
  if (error) {
    std::cerr << "heyaki-release-sign: cannot walk " << root.string() << ": "
              << error.message() << '\n';
    return std::nullopt;
  }
  for (const fs::directory_entry& entry : iterator) {
    std::error_code entry_error;
    if (entry.is_symlink(entry_error)) {
      // Symlinks are excluded so a manifest can never be made to cover a file
      // outside the bundle through a rewritten link target.
      continue;
    }
    if (!entry.is_regular_file(entry_error)) {
      continue;
    }
    if (entry_error) {
      std::cerr << "heyaki-release-sign: stat failed for "
                << entry.path().string() << ": " << entry_error.message() << '\n';
      return std::nullopt;
    }
    auto relative = fs::relative(entry.path(), root, entry_error);
    if (entry_error) {
      std::cerr << "heyaki-release-sign: relative failed for "
                << entry.path().string() << ": " << entry_error.message() << '\n';
      return std::nullopt;
    }
    std::string generic = relative.generic_string();
    if (generic == "." || generic.find("..") != std::string::npos) {
      std::cerr << "heyaki-release-sign: refusing unsafe relative path "
                << generic << '\n';
      return std::nullopt;
    }
    files.push_back(std::move(generic));
  }
  std::sort(files.begin(), files.end());
  return files;
}

int command_keygen(const fs::path& secret_out, const fs::path& public_out) {
  unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
  unsigned char secret_key[crypto_sign_SECRETKEYBYTES];
  if (crypto_sign_keypair(public_key, secret_key) != 0) {
    return fail(2, "key generation failed");
  }
  const std::string secret_hex =
      to_hex(secret_key, crypto_sign_SECRETKEYBYTES);
  const std::string public_hex = to_hex(public_key, crypto_sign_PUBLICKEYBYTES);
  if (!write_file_bytes(secret_out,
                        reinterpret_cast<const unsigned char*>(secret_hex.data()),
                        secret_hex.size())) {
    return 2;
  }
  if (!write_file_bytes(public_out,
                        reinterpret_cast<const unsigned char*>(public_hex.data()),
                        public_hex.size())) {
    return 2;
  }
  // Owner-only permissions for the secret key (POSIX; a no-op refinement on
  // Windows where std::filesystem maps the write bit only).
  std::error_code error;
  fs::permissions(secret_out,
                  fs::perms::owner_read | fs::perms::owner_write,
                  fs::perm_options::replace, error);
  if (error) {
    std::cerr << "heyaki-release-sign: warning: could not restrict permissions "
                 "on " << secret_out.string() << ": " << error.message() << '\n';
  }
  unsigned char fingerprint[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(fingerprint, public_key, sizeof public_key);
  std::cout << "RELEASE_KEY_ID " << to_hex(fingerprint, sizeof fingerprint).substr(0U, 16U)
            << '\n';
  return 0;
}

struct ManifestEntry {
  std::string digest;
  std::string path;
};

// Parses the manifest format strictly: header line, count line, and
// byte-wise-sorted "SHA256 <64 hex> <path>" entries. Any deviation is an
// error so a signature can only ever be created over an unambiguous file
// list.
std::optional<std::vector<ManifestEntry>> parse_manifest(
    const std::vector<unsigned char>& bytes) {
  const std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  const auto first_newline = text.find('\n');
  if (first_newline == std::string::npos ||
      text.substr(0U, first_newline) != "heyaki-release-manifest/1") {
    std::cerr << "heyaki-release-sign: manifest header missing\n";
    return std::nullopt;
  }
  std::size_t cursor = first_newline + 1U;
  const auto count_newline = text.find('\n', cursor);
  if (count_newline == std::string::npos) {
    std::cerr << "heyaki-release-sign: manifest file count line missing\n";
    return std::nullopt;
  }
  const std::string count_text = text.substr(cursor, count_newline - cursor);
  if (count_text.empty() ||
      count_text.find_first_not_of("0123456789") != std::string::npos) {
    std::cerr << "heyaki-release-sign: manifest file count is not a number\n";
    return std::nullopt;
  }
  unsigned long long declared_count = 0ULL;
  for (const char digit : count_text) {
    declared_count = declared_count * 10ULL +
                     static_cast<unsigned long long>(digit - '0');
    if (declared_count > text.size()) {
      // Every entry needs more bytes than its own digit count; a larger
      // declared count is corruption, and this bound also rules out overflow.
      std::cerr << "heyaki-release-sign: manifest file count exceeds file size\n";
      return std::nullopt;
    }
  }
  cursor = count_newline + 1U;
  std::vector<ManifestEntry> entries;
  while (cursor < text.size()) {
    const auto newline = text.find('\n', cursor);
    if (newline == std::string::npos) {
      std::cerr << "heyaki-release-sign: manifest entry missing newline\n";
      return std::nullopt;
    }
    const std::string line = text.substr(cursor, newline - cursor);
    cursor = newline + 1U;
    constexpr std::string_view prefix = "SHA256 ";
    if (line.size() <= prefix.size() + 64U + 1U ||
        line.compare(0U, prefix.size(), prefix) != 0) {
      std::cerr << "heyaki-release-sign: malformed manifest line: " << line << '\n';
      return std::nullopt;
    }
    ManifestEntry entry;
    entry.digest = line.substr(prefix.size(), 64U);
    if (from_hex(entry.digest) == std::nullopt) {
      std::cerr << "heyaki-release-sign: digest is not hex: " << line << '\n';
      return std::nullopt;
    }
    entry.path = line.substr(prefix.size() + 64U + 1U);
    if (entry.path.empty() || entry.path.front() == '/' ||
        entry.path.find("..") != std::string::npos) {
      std::cerr << "heyaki-release-sign: unsafe manifest path: " << line << '\n';
      return std::nullopt;
    }
    if (!entries.empty() && !(entries.back().path < entry.path)) {
      std::cerr << "heyaki-release-sign: manifest entries are not sorted at: "
                << entry.path << '\n';
      return std::nullopt;
    }
    entries.push_back(std::move(entry));
  }
  if (static_cast<unsigned long long>(entries.size()) != declared_count) {
    std::cerr << "heyaki-release-sign: manifest declares " << declared_count
              << " files but lists " << entries.size() << '\n';
    return std::nullopt;
  }
  return entries;
}

int command_manifest(const fs::path& root, const fs::path& manifest_out) {
  const auto files = bundle_files(root);
  if (!files.has_value()) {
    return 2;
  }
  std::string manifest = "heyaki-release-manifest/1\n";
  manifest += std::to_string((*files).size());
  manifest += "\n";
  for (const std::string& file : *files) {
    const auto digest = sha256_hex(root / fs::path(file));
    if (!digest.has_value()) {
      return 2;
    }
    manifest += "SHA256 ";
    manifest += *digest;
    manifest += " ";
    manifest += file;
    manifest += "\n";
  }
  if (!write_file_bytes(manifest_out,
                        reinterpret_cast<const unsigned char*>(manifest.data()),
                        manifest.size())) {
    return 2;
  }
  std::cout << "MANIFEST_OK " << (*files).size() << " files -> "
            << manifest_out.string() << '\n';
  return 0;
}

int command_sign(const fs::path& manifest, const fs::path& secret_key_path) {
  const auto secret_hex =
      read_key_file(secret_key_path, crypto_sign_SECRETKEYBYTES);
  if (!secret_hex.has_value()) {
    return 2;
  }
  const auto secret = from_hex(*secret_hex);
  const auto bytes = read_file_bytes(manifest);
  if (!bytes.has_value()) {
    return 2;
  }
  unsigned char signature[crypto_sign_BYTES];
  if (crypto_sign_detached(signature, nullptr,
                           (*bytes).data(), (*bytes).size(), (*secret).data()) != 0) {
    return fail(2, "signing failed");
  }
  const fs::path signature_path = manifest.string() + ".sig";
  if (!write_file_bytes(signature_path, signature, sizeof signature)) {
    return 2;
  }
  unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
  unsigned char fingerprint[crypto_hash_sha256_BYTES];
  crypto_sign_ed25519_sk_to_pk(public_key, (*secret).data());
  crypto_hash_sha256(fingerprint, public_key, sizeof public_key);
  std::cout << "SIGN_OK " << signature_path.string() << " key "
            << to_hex(fingerprint, sizeof fingerprint).substr(0U, 16U) << '\n';
  return 0;
}

int command_verify(const fs::path& manifest, const fs::path& public_key_path,
                   const fs::path& signature_path) {
  const auto public_hex =
      read_key_file(public_key_path, crypto_sign_PUBLICKEYBYTES);
  if (!public_hex.has_value()) {
    return 2;
  }
  const auto public_key = from_hex(*public_hex);
  const auto signature = read_file_bytes(signature_path);
  if (!signature.has_value()) {
    return 2;
  }
  if ((*signature).size() != crypto_sign_BYTES) {
    std::cerr << "heyaki-release-sign: signature must be exactly "
              << crypto_sign_BYTES << " bytes\n";
    return 2;
  }
  const auto bytes = read_file_bytes(manifest);
  if (!bytes.has_value()) {
    return 2;
  }
  if (crypto_sign_verify_detached((*signature).data(), (*bytes).data(),
                                  (*bytes).size(), (*public_key).data()) != 0) {
    std::cerr << "heyaki-release-sign: SIGNATURE_INVALID " << manifest.string()
              << '\n';
    return 1;
  }
  std::cout << "SIGNATURE_VALID " << manifest.string() << '\n';
  return 0;
}

int command_check(const fs::path& manifest, const fs::path& root) {
  const auto bytes = read_file_bytes(manifest);
  if (!bytes.has_value()) {
    return 2;
  }
  const auto entries = parse_manifest(*bytes);
  if (!entries.has_value()) {
    return 2;
  }
  const auto files = bundle_files(root);
  if (!files.has_value()) {
    return 2;
  }
  int mismatches = 0;
  std::size_t index = 0U;
  for (const std::string& file : *files) {
    while (index < (*entries).size() && (*entries)[index].path < file) {
      std::cerr << "CHECK_MISSING_FILE " << (*entries)[index].path << '\n';
      ++mismatches;
      ++index;
    }
    if (index < (*entries).size() && (*entries)[index].path == file) {
      const auto digest = sha256_hex(root / fs::path(file));
      if (!digest.has_value()) {
        ++mismatches;
      } else if (*digest != (*entries)[index].digest) {
        std::cerr << "CHECK_DIGEST_MISMATCH " << file << '\n';
        ++mismatches;
      }
      ++index;
    } else {
      std::cerr << "CHECK_EXTRA_FILE " << file << '\n';
      ++mismatches;
    }
  }
  while (index < (*entries).size()) {
    std::cerr << "CHECK_MISSING_FILE " << (*entries)[index].path << '\n';
    ++mismatches;
    ++index;
  }
  if (mismatches > 0) {
    std::cerr << "heyaki-release-sign: CHECK_FAILED " << mismatches
              << " mismatch(es) against " << manifest.string() << '\n';
    return 1;
  }
  std::cout << "CHECK_OK " << (*entries).size() << " files match "
            << manifest.string() << '\n';
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    return usage();
  }
  if (sodium_init() < 0) {
    return fail(2, "libsodium initialization failed");
  }
  const std::string command = argv[1];
  if (command == "keygen" && argc == 4) {
    return command_keygen(fs::path(argv[2]), fs::path(argv[3]));
  }
  if (command == "manifest" && argc == 4) {
    return command_manifest(fs::path(argv[2]), fs::path(argv[3]));
  }
  if (command == "sign" && argc == 4) {
    return command_sign(fs::path(argv[2]), fs::path(argv[3]));
  }
  if (command == "verify" && argc == 5) {
    return command_verify(fs::path(argv[2]), fs::path(argv[3]), fs::path(argv[4]));
  }
  if (command == "check" && argc == 4) {
    return command_check(fs::path(argv[2]), fs::path(argv[3]));
  }
  return usage();
}
