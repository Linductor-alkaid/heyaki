#include <heyaki/secret_backend.hpp>

#include <heyaki/identity.hpp>

#include <sodium.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace heyaki {
namespace {

constexpr std::array<std::byte, 5U> secret_magic{
    std::byte{'H'}, std::byte{'Y'}, std::byte{'S'}, std::byte{'1'}, std::byte{1U}};

Error storage_error(std::string detail, std::error_code error = {}) {
  const auto underlying = error ? std::optional<std::int64_t>{error.value()} : std::nullopt;
  return Error{ErrorCode::storage, "secret_backend", std::move(detail), underlying};
}

bool valid_label(std::string_view label) noexcept {
  if (label.empty() || label.size() > 64U) {
    return false;
  }
  for (const char character : label) {
    const bool lower = character >= 'a' && character <= 'z';
    const bool upper = character >= 'A' && character <= 'Z';
    const bool digit = character >= '0' && character <= '9';
    if (!lower && !upper && !digit && character != '-' && character != '_' && character != '.') {
      return false;
    }
  }
  return true;
}

bool valid_handle(std::string_view handle) noexcept {
  if (handle.empty() || handle.size() > 128U) {
    return false;
  }
  for (const char character : handle) {
    const bool lower = character >= 'a' && character <= 'z';
    const bool upper = character >= 'A' && character <= 'Z';
    const bool digit = character >= '0' && character <= '9';
    if (!lower && !upper && !digit && character != '-' && character != '_' && character != '.') {
      return false;
    }
  }
  return true;
}

std::filesystem::path parent_directory_for(const std::filesystem::path& path) {
  return path.parent_path().empty() ? std::filesystem::path{"."} : path.parent_path();
}

std::string random_token() {
  std::array<unsigned char, 16U> bytes{};
  randombytes_buf(bytes.data(), bytes.size());
  constexpr char alphabet[] = "0123456789abcdef";
  std::string output;
  output.reserve(bytes.size() * 2U);
  for (const auto byte : bytes) {
    output.push_back(alphabet[(byte >> 4U) & 0x0fU]);
    output.push_back(alphabet[byte & 0x0fU]);
  }
  return output;
}

Result<void> ensure_private_directory(const std::filesystem::path& path) {
  std::error_code error;
  const bool existed = std::filesystem::exists(path, error);
  if (error) {
    return Result<void>::failure(storage_error("secret_directory_stat_failed", error));
  }
  std::filesystem::create_directories(path, error);
  if (error) {
    return Result<void>::failure(storage_error("create_secret_directory_failed", error));
  }
#ifndef _WIN32
  struct stat status {};
  if (::stat(path.c_str(), &status) != 0) {
    return Result<void>::failure(Error{ErrorCode::profile_permissions, "secret_backend",
                                       "secret_directory_stat_failed", errno});
  }
  if (existed && (status.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    return Result<void>::failure(Error{ErrorCode::profile_permissions, "secret_backend",
                                       "secret_directory_permissions_too_wide"});
  }
  if (!existed && ::chmod(path.c_str(), S_IRWXU) != 0) {
    return Result<void>::failure(Error{ErrorCode::profile_permissions, "secret_backend",
                                       "secret_directory_permission_failed", errno});
  }
#endif
  return Result<void>::success();
}

Result<void> check_private_file(const std::filesystem::path& path) {
#ifndef _WIN32
  struct stat status {};
  if (::stat(path.c_str(), &status) != 0) {
    return Result<void>::failure(storage_error("secret_stat_failed",
                                                std::error_code{errno, std::generic_category()}));
  }
  if ((status.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    return Result<void>::failure(Error{ErrorCode::profile_permissions, "secret_backend",
                                       "secret_file_permissions_too_wide"});
  }
#else
  (void)path;
#endif
  return Result<void>::success();
}

Result<std::vector<std::byte>> read_file(const std::filesystem::path& path) {
  const auto permissions = check_private_file(path);
  if (!permissions) {
    return Result<std::vector<std::byte>>::failure(*permissions.error_if());
  }
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    return Result<std::vector<std::byte>>::failure(storage_error("secret_open_failed"));
  }
  const auto size = input.tellg();
  if (size < 0 || static_cast<std::uint64_t>(size) > 1024U * 1024U) {
    return Result<std::vector<std::byte>>::failure(
        Error{ErrorCode::profile_corrupt, "secret_backend", "secret_file_size_invalid"});
  }
  std::vector<std::byte> bytes(static_cast<std::size_t>(size));
  input.seekg(0);
  input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  if (!input && !bytes.empty()) {
    sodium_memzero(bytes.data(), bytes.size());
    return Result<std::vector<std::byte>>::failure(storage_error("secret_read_failed"));
  }
  return Result<std::vector<std::byte>>::success(std::move(bytes));
}

Result<void> atomic_write(const std::filesystem::path& path,
                          std::span<const std::byte> bytes) {
  const auto temporary = path.string() + ".tmp." + random_token();
#ifdef _WIN32
  HANDLE output = CreateFileW(std::filesystem::path{temporary}.wstring().c_str(), GENERIC_WRITE, 0,
                              nullptr, CREATE_NEW, FILE_ATTRIBUTE_HIDDEN, nullptr);
  if (output == INVALID_HANDLE_VALUE) {
    return Result<void>::failure(
        Error{ErrorCode::storage, "secret_backend", "secret_temp_open_failed",
              static_cast<std::int64_t>(GetLastError())});
  }
  std::size_t offset = 0U;
  while (offset < bytes.size()) {
    const auto remaining = std::min<std::size_t>(bytes.size() - offset, MAXDWORD);
    DWORD written = 0U;
    if (WriteFile(output, bytes.data() + offset, static_cast<DWORD>(remaining), &written, nullptr) ==
            FALSE ||
        written == 0U) {
      const auto error = GetLastError();
      CloseHandle(output);
      DeleteFileW(std::filesystem::path{temporary}.wstring().c_str());
      return Result<void>::failure(
          Error{ErrorCode::storage, "secret_backend", "secret_temp_write_failed",
                static_cast<std::int64_t>(error)});
    }
    offset += written;
  }
  if (FlushFileBuffers(output) == FALSE) {
    const auto error = GetLastError();
    CloseHandle(output);
    DeleteFileW(std::filesystem::path{temporary}.wstring().c_str());
    return Result<void>::failure(
        Error{ErrorCode::storage, "secret_backend", "secret_temp_flush_failed",
              static_cast<std::int64_t>(error)});
  }
  CloseHandle(output);
  if (MoveFileExW(std::filesystem::path{temporary}.wstring().c_str(), path.wstring().c_str(),
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
    const auto error = GetLastError();
    DeleteFileW(std::filesystem::path{temporary}.wstring().c_str());
    return Result<void>::failure(
        Error{ErrorCode::storage, "secret_backend", "secret_atomic_replace_failed",
              static_cast<std::int64_t>(error)});
  }
#else
  const int output = ::open(temporary.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
                            S_IRUSR | S_IWUSR);
  if (output < 0) {
    return Result<void>::failure(
        Error{ErrorCode::storage, "secret_backend", "secret_temp_open_failed", errno});
  }
  std::size_t offset = 0U;
  while (offset < bytes.size()) {
    const auto written = ::write(output, bytes.data() + offset, bytes.size() - offset);
    if (written <= 0) {
      const int error = errno;
      (void)::close(output);
      std::error_code ignored;
      std::filesystem::remove(temporary, ignored);
      return Result<void>::failure(
          Error{ErrorCode::storage, "secret_backend", "secret_temp_write_failed", error});
    }
    offset += static_cast<std::size_t>(written);
  }
  if (::fsync(output) != 0) {
    const int error = errno;
    (void)::close(output);
    std::error_code ignored;
    std::filesystem::remove(temporary, ignored);
    return Result<void>::failure(
        Error{ErrorCode::storage, "secret_backend", "secret_temp_flush_failed", error});
  }
  (void)::close(output);
  if (::rename(temporary.c_str(), path.c_str()) != 0) {
    const int error = errno;
    std::error_code ignored;
    std::filesystem::remove(temporary, ignored);
    return Result<void>::failure(
        Error{ErrorCode::storage, "secret_backend", "secret_atomic_replace_failed", error});
  }
  const int directory =
      ::open(parent_directory_for(path).c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (directory < 0) {
    return Result<void>::failure(
        Error{ErrorCode::storage, "secret_backend", "secret_directory_flush_failed", errno});
  }
  const int flushed = ::fsync(directory);
  const int flush_error = errno;
  (void)::close(directory);
  if (flushed != 0) {
    return Result<void>::failure(Error{ErrorCode::storage, "secret_backend",
                                       "secret_directory_flush_failed", flush_error});
  }
#endif
  return Result<void>::success();
}

class FileSecretBackend final : public SecretBackend {
 public:
  static Result<std::shared_ptr<SecretBackend>> open(const std::filesystem::path& root,
                                                     bool create_if_missing) {
    auto backend = std::shared_ptr<FileSecretBackend>(
        new FileSecretBackend(root, create_if_missing));
    const auto ready = backend->load_or_create_master_key();
    if (!ready) {
      return Result<std::shared_ptr<SecretBackend>>::failure(*ready.error_if());
    }
    return Result<std::shared_ptr<SecretBackend>>::success(std::move(backend));
  }

  ~FileSecretBackend() override { sodium_memzero(master_key_.data(), master_key_.size()); }

  [[nodiscard]] SecretBackendSecurity security() const noexcept override {
    return SecretBackendSecurity::encrypted_file_fallback;
  }

  Result<SecretHandle> store(std::string_view label,
                             std::span<const std::byte> secret) override {
    if (!valid_label(label) || secret.empty() || secret.size() > 64U * 1024U) {
      return Result<SecretHandle>::failure(
          Error{ErrorCode::configuration, "secret_backend", "invalid_secret_input"});
    }
    const std::string handle = std::string{label} + "-" + random_token();
    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce{};
    randombytes_buf(nonce.data(), nonce.size());
    std::vector<std::byte> encoded(secret_magic.size() + nonce.size() + secret.size() +
                                   crypto_aead_xchacha20poly1305_ietf_ABYTES);
    std::copy(secret_magic.begin(), secret_magic.end(), encoded.begin());
    std::copy(nonce.begin(), nonce.end(),
              reinterpret_cast<unsigned char*>(encoded.data() + secret_magic.size()));
    unsigned long long cipher_size = 0U;
    auto* cipher = reinterpret_cast<unsigned char*>(
        encoded.data() + secret_magic.size() + nonce.size());
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            cipher, &cipher_size, reinterpret_cast<const unsigned char*>(secret.data()),
            secret.size(), reinterpret_cast<const unsigned char*>(secret_magic.data()),
            secret_magic.size(), nullptr, nonce.data(), master_key_.data()) != 0) {
      sodium_memzero(encoded.data(), encoded.size());
      return Result<SecretHandle>::failure(
          Error{ErrorCode::internal, "secret_backend", "secret_encrypt_failed"});
    }
    encoded.resize(secret_magic.size() + nonce.size() + static_cast<std::size_t>(cipher_size));
    const auto written = atomic_write(root_ / (handle + ".secret"), encoded);
    sodium_memzero(encoded.data(), encoded.size());
    if (!written) {
      return Result<SecretHandle>::failure(*written.error_if());
    }
    return Result<SecretHandle>::success(SecretHandle{handle});
  }

  Result<std::vector<std::byte>> load(const SecretHandle& handle) const override {
    if (!valid_handle(handle.value)) {
      return Result<std::vector<std::byte>>::failure(
          Error{ErrorCode::secret_unavailable, "secret_backend", "invalid_secret_handle"});
    }
    auto encoded = read_file(root_ / (handle.value + ".secret"));
    if (!encoded) {
      if (encoded.error_if()->code() == ErrorCode::profile_permissions) {
        return Result<std::vector<std::byte>>::failure(*encoded.error_if());
      }
      return Result<std::vector<std::byte>>::failure(Error{
          ErrorCode::secret_unavailable, "secret_backend", "secret_not_available",
          encoded.error_if()->underlying_code()});
    }
    const std::size_t header_size = secret_magic.size() +
                                    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    if (encoded.value_if()->size() < header_size + crypto_aead_xchacha20poly1305_ietf_ABYTES ||
        !std::equal(secret_magic.begin(), secret_magic.end(), encoded.value_if()->begin())) {
      sodium_memzero(encoded.value_if()->data(), encoded.value_if()->size());
      return Result<std::vector<std::byte>>::failure(
          Error{ErrorCode::profile_corrupt, "secret_backend", "secret_format_invalid"});
    }
    const auto* nonce = reinterpret_cast<const unsigned char*>(
        encoded.value_if()->data() + secret_magic.size());
    const auto* cipher = reinterpret_cast<const unsigned char*>(
        encoded.value_if()->data() + header_size);
    const std::size_t cipher_size = encoded.value_if()->size() - header_size;
    std::vector<std::byte> plain(cipher_size - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long plain_size = 0U;
    const int decrypted = crypto_aead_xchacha20poly1305_ietf_decrypt(
        reinterpret_cast<unsigned char*>(plain.data()), &plain_size, nullptr, cipher, cipher_size,
        reinterpret_cast<const unsigned char*>(secret_magic.data()), secret_magic.size(), nonce,
        master_key_.data());
    sodium_memzero(encoded.value_if()->data(), encoded.value_if()->size());
    if (decrypted != 0) {
      sodium_memzero(plain.data(), plain.size());
      return Result<std::vector<std::byte>>::failure(
          Error{ErrorCode::profile_corrupt, "secret_backend", "secret_authentication_failed"});
    }
    plain.resize(static_cast<std::size_t>(plain_size));
    return Result<std::vector<std::byte>>::success(std::move(plain));
  }

  Result<void> erase(const SecretHandle& handle) override {
    if (!valid_handle(handle.value)) {
      return Result<void>::failure(
          Error{ErrorCode::secret_unavailable, "secret_backend", "invalid_secret_handle"});
    }
    std::error_code error;
    const bool removed = std::filesystem::remove(root_ / (handle.value + ".secret"), error);
    if (error) {
      return Result<void>::failure(storage_error("secret_delete_failed", error));
    }
    if (!removed) {
      return Result<void>::failure(
          Error{ErrorCode::secret_unavailable, "secret_backend", "secret_not_available"});
    }
    return Result<void>::success();
  }

 private:
  FileSecretBackend(std::filesystem::path root, bool create_if_missing)
      : root_(std::move(root)), create_if_missing_(create_if_missing) {}

  Result<void> load_or_create_master_key() {
    const auto initialized = initialize_crypto();
    if (!initialized) {
      return initialized;
    }
    std::error_code root_error;
    const bool root_exists = std::filesystem::exists(root_, root_error);
    if (root_error) {
      return Result<void>::failure(storage_error("secret_directory_stat_failed", root_error));
    }
    if (!root_exists && !create_if_missing_) {
      return Result<void>::failure(
          Error{ErrorCode::secret_unavailable, "secret_backend", "secret_store_missing"});
    }
    const auto directory = ensure_private_directory(root_);
    if (!directory) {
      return directory;
    }
    const auto key_path = root_ / "master.key";
    std::error_code exists_error;
    const bool exists = std::filesystem::exists(key_path, exists_error);
    if (exists_error) {
      return Result<void>::failure(storage_error("master_key_stat_failed", exists_error));
    }
    if (exists) {
      auto key = read_file(key_path);
      if (!key || key.value_if()->size() != master_key_.size()) {
        return Result<void>::failure(
            Error{ErrorCode::secret_unavailable, "secret_backend", "master_key_invalid"});
      }
      std::memcpy(master_key_.data(), key.value_if()->data(), master_key_.size());
      sodium_memzero(key.value_if()->data(), key.value_if()->size());
      return Result<void>::success();
    }
    if (!create_if_missing_) {
      return Result<void>::failure(
          Error{ErrorCode::secret_unavailable, "secret_backend", "master_key_missing"});
    }
    randombytes_buf(master_key_.data(), master_key_.size());
    const auto written = atomic_write(
        key_path, std::as_bytes(std::span{master_key_.data(), master_key_.size()}));
    if (!written) {
      sodium_memzero(master_key_.data(), master_key_.size());
      return written;
    }
    return Result<void>::success();
  }

  std::filesystem::path root_;
  bool create_if_missing_;
  std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> master_key_{};
};

#ifdef _WIN32
class DpapiSecretBackend final : public SecretBackend {
 public:
  explicit DpapiSecretBackend(std::filesystem::path root) : root_(std::move(root)) {}

  [[nodiscard]] SecretBackendSecurity security() const noexcept override {
    return SecretBackendSecurity::os_protected;
  }

  Result<SecretHandle> store(std::string_view label,
                             std::span<const std::byte> secret) override {
    if (!valid_label(label) || secret.empty() || secret.size() > 64U * 1024U) {
      return Result<SecretHandle>::failure(
          Error{ErrorCode::configuration, "secret_backend", "invalid_secret_input"});
    }
    DATA_BLOB input{static_cast<DWORD>(secret.size()),
                    reinterpret_cast<BYTE*>(const_cast<std::byte*>(secret.data()))};
    DATA_BLOB output{};
    if (CryptProtectData(&input, L"Heyaki identity", nullptr, nullptr, nullptr,
                         CRYPTPROTECT_UI_FORBIDDEN, &output) == FALSE) {
      return Result<SecretHandle>::failure(
          Error{ErrorCode::secret_unavailable, "secret_backend", "dpapi_protect_failed",
                static_cast<std::int64_t>(GetLastError())});
    }
    const std::string handle = std::string{label} + "-" + random_token();
    const auto bytes = std::span{reinterpret_cast<const std::byte*>(output.pbData),
                                 static_cast<std::size_t>(output.cbData)};
    const auto written = atomic_write(root_ / (handle + ".secret"), bytes);
    LocalFree(output.pbData);
    if (!written) {
      return Result<SecretHandle>::failure(*written.error_if());
    }
    return Result<SecretHandle>::success(SecretHandle{handle});
  }

  Result<std::vector<std::byte>> load(const SecretHandle& handle) const override {
    if (!valid_handle(handle.value)) {
      return Result<std::vector<std::byte>>::failure(
          Error{ErrorCode::secret_unavailable, "secret_backend", "invalid_secret_handle"});
    }
    auto encrypted = read_file(root_ / (handle.value + ".secret"));
    if (!encrypted) {
      if (encrypted.error_if()->code() == ErrorCode::profile_permissions) {
        return Result<std::vector<std::byte>>::failure(*encrypted.error_if());
      }
      return Result<std::vector<std::byte>>::failure(Error{
          ErrorCode::secret_unavailable, "secret_backend", "secret_not_available",
          encrypted.error_if()->underlying_code()});
    }
    DATA_BLOB input{static_cast<DWORD>(encrypted.value_if()->size()),
                    reinterpret_cast<BYTE*>(encrypted.value_if()->data())};
    DATA_BLOB output{};
    if (CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
                           CRYPTPROTECT_UI_FORBIDDEN, &output) == FALSE) {
      const auto error = GetLastError();
      sodium_memzero(encrypted.value_if()->data(), encrypted.value_if()->size());
      return Result<std::vector<std::byte>>::failure(
          Error{ErrorCode::secret_unavailable, "secret_backend", "dpapi_unprotect_failed",
                static_cast<std::int64_t>(error)});
    }
    std::vector<std::byte> plain(output.cbData);
    std::copy_n(reinterpret_cast<const std::byte*>(output.pbData), output.cbData, plain.begin());
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
    sodium_memzero(encrypted.value_if()->data(), encrypted.value_if()->size());
    return Result<std::vector<std::byte>>::success(std::move(plain));
  }

  Result<void> erase(const SecretHandle& handle) override {
    if (!valid_handle(handle.value)) {
      return Result<void>::failure(
          Error{ErrorCode::secret_unavailable, "secret_backend", "invalid_secret_handle"});
    }
    std::error_code error;
    const bool removed = std::filesystem::remove(root_ / (handle.value + ".secret"), error);
    if (error) {
      return Result<void>::failure(storage_error("secret_delete_failed", error));
    }
    if (!removed) {
      return Result<void>::failure(
          Error{ErrorCode::secret_unavailable, "secret_backend", "secret_not_available"});
    }
    return Result<void>::success();
  }

 private:
  std::filesystem::path root_;
};
#endif

}  // namespace

Result<std::shared_ptr<SecretBackend>> open_default_secret_backend(
    const std::filesystem::path& root, const SecretBackendOptions& options) {
  const auto initialized = initialize_crypto();
  if (!initialized) {
    return Result<std::shared_ptr<SecretBackend>>::failure(*initialized.error_if());
  }
  std::error_code root_error;
  const bool root_exists = std::filesystem::exists(root, root_error);
  if (root_error) {
    return Result<std::shared_ptr<SecretBackend>>::failure(
        storage_error("secret_directory_stat_failed", root_error));
  }
  if (!root_exists && !options.create_if_missing) {
    return Result<std::shared_ptr<SecretBackend>>::failure(
        Error{ErrorCode::secret_unavailable, "secret_backend", "secret_store_missing"});
  }
  const auto directory = ensure_private_directory(root);
  if (!directory) {
    return Result<std::shared_ptr<SecretBackend>>::failure(*directory.error_if());
  }
#ifdef _WIN32
  return Result<std::shared_ptr<SecretBackend>>::success(
      std::make_shared<DpapiSecretBackend>(root));
#else
  if (!options.allow_encrypted_file_fallback) {
    return Result<std::shared_ptr<SecretBackend>>::failure(
        Error{ErrorCode::secret_backend_degraded, "secret_backend",
              "os_secret_store_unavailable"});
  }
  return FileSecretBackend::open(root, options.create_if_missing);
#endif
}

}  // namespace heyaki
