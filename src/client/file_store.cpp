// Safe local file storage implementation (M7-10/M7-11). POSIX path uses
// open/pread/pwrite/fsync/rename with O_NOFOLLOW and per-component symlink
// checks; the Windows path uses the CRT plus MoveFileEx for the atomic
// replace and reparse-point checks in place of O_NOFOLLOW. All functions
// block and run on the executor-managed blocking I/O worker.

#include "file_store.hpp"

#include <blake3.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace heyaki::file_store {
namespace {

Error store_error(ErrorCode code, std::string_view detail) {
  return Error{code, "file_store", std::string{detail}};
}

constexpr std::size_t stream_block_bytes = 256U * 1024U;

#ifdef _WIN32

// Windows: reject reparse points (symlinks/junctions) before every open and
// create; MoveFileEx provides the atomic replace.
bool path_is_reparse_point(const std::wstring& wide) noexcept {
  const DWORD attributes = GetFileAttributesW(wide.c_str());
  return attributes == INVALID_FILE_ATTRIBUTES ||
         (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U;
}

// GitHub Windows runners instrument new files with Defender: sharing
// violations on freshly created files are transient, not real conflicts.
// Bounded retry on the sharing/access errors instead of failing transfers.
template <typename Try>
auto retry_sharing_violation(Try&& attempt) -> decltype(attempt()) {
  for (int tries = 0; tries < 10; ++tries) {
    const auto handle = attempt();
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
      return handle;
    }
    const DWORD error = GetLastError();
    if (error != ERROR_SHARING_VIOLATION && error != ERROR_ACCESS_DENIED) {
      return handle;
    }
    ::Sleep(50);
  }
  return attempt();
}

std::wstring wide_of(const std::filesystem::path& path) { return path.wstring(); }

Result<void> ensure_directory_real(const std::filesystem::path& directory) {
  std::error_code ec;
  const auto status = std::filesystem::symlink_status(directory, ec);
  // A missing path reports not_found AND ENOENT in `ec` (same as POSIX):
  // branch on the type, not on `ec`, or fresh subdirectories fail.
  if (status.type() == std::filesystem::file_type::not_found) {
    std::error_code mkdir_ec;
    std::filesystem::create_directory(directory, mkdir_ec);
    if (mkdir_ec) {
      return Result<void>::failure(store_error(ErrorCode::transport, "mkdir_failed"));
    }
  } else if (ec || !std::filesystem::is_directory(status)) {
    return Result<void>::failure(store_error(ErrorCode::protocol, "root_not_directory"));
  }
  if (path_is_reparse_point(wide_of(directory))) {
    return Result<void>::failure(store_error(ErrorCode::permission, "symlink_component"));
  }
  return Result<void>::success();
}

#else  // POSIX

Result<void> ensure_directory_real(const std::filesystem::path& directory) {
  std::error_code ec;
  const auto status = std::filesystem::symlink_status(directory, ec);
  // A missing path reports type::not_found AND ENOENT in `ec`; only other
  // probe failures are real errors here.
  if (status.type() == std::filesystem::file_type::not_found) {
    std::error_code mkdir_ec;
    std::filesystem::create_directory(directory, mkdir_ec);
    if (mkdir_ec) {
      return Result<void>::failure(store_error(ErrorCode::transport, "mkdir_failed"));
    }
  } else if (!std::filesystem::is_directory(status)) {
    return Result<void>::failure(store_error(ErrorCode::protocol, "root_not_directory"));
  }
  // A symlinked directory component can pivot the final path outside the
  // configured root (M7-10): reject before any file is created inside it.
  struct ::stat probe {};
  const std::string native = directory.string();
  if (::lstat(native.c_str(), &probe) != 0 || S_ISLNK(probe.st_mode) ||
      !S_ISDIR(probe.st_mode)) {
    return Result<void>::failure(store_error(ErrorCode::permission, "symlink_component"));
  }
  return Result<void>::success();
}

int open_no_follow(const std::string& native, int flags, mode_t mode) noexcept {
#ifdef O_NOFOLLOW
  return ::open(native.c_str(), flags | O_CLOEXEC | O_NOFOLLOW, mode);
#else
  return ::open(native.c_str(), flags | O_CLOEXEC, mode);
#endif
}

#endif  // platform

}  // namespace

Digest blake3_bytes(std::span<const std::byte> data) {
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, data.data(), data.size());
  Digest digest{};
  blake3_hasher_finalize(&hasher, reinterpret_cast<std::uint8_t*>(digest.data()),
                         digest.size());
  return digest;
}

Result<SourceFile> open_source(const std::filesystem::path& path) {
#ifdef _WIN32
  const std::wstring wide = wide_of(path);
  if (path_is_reparse_point(wide)) {
    return Result<SourceFile>::failure(
        store_error(ErrorCode::permission, "symlink_component"));
  }
  WIN32_FILE_ATTRIBUTE_DATA info {};
  if (!GetFileAttributesExW(wide.c_str(), GetFileExInfoStandard, &info)) {
    return Result<SourceFile>::failure(store_error(ErrorCode::peer_offline, "source_open_failed"));
  }
  if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) {
    return Result<SourceFile>::failure(
        store_error(ErrorCode::protocol, "source_not_regular"));
  }
  const std::uint64_t size =
      (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32U) | info.nFileSizeLow;
  return Result<SourceFile>::success(SourceFile{size, path});
#else
  struct ::stat probe {};
  const std::string native = path.string();
  if (::lstat(native.c_str(), &probe) != 0) {
    return Result<SourceFile>::failure(store_error(ErrorCode::peer_offline, "source_open_failed"));
  }
  if (S_ISLNK(probe.st_mode)) {
    return Result<SourceFile>::failure(
        store_error(ErrorCode::permission, "symlink_component"));
  }
  if (!S_ISREG(probe.st_mode)) {
    return Result<SourceFile>::failure(
        store_error(ErrorCode::protocol, "source_not_regular"));
  }
  const int fd = open_no_follow(native, O_RDONLY, 0U);
  if (fd < 0) {
    return Result<SourceFile>::failure(store_error(ErrorCode::peer_offline, "source_open_failed"));
  }
  struct ::stat opened {};
  if (::fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode)) {
    ::close(fd);
    return Result<SourceFile>::failure(
        store_error(ErrorCode::protocol, "source_not_regular"));
  }
  ::close(fd);
  return Result<SourceFile>::success(SourceFile{static_cast<std::uint64_t>(opened.st_size), path});
#endif
}

Result<std::vector<std::byte>> read_source_range(const std::filesystem::path& path,
                                                 std::uint64_t offset, std::size_t length) {
#ifdef _WIN32
  HANDLE file = retry_sharing_violation([&] {
    return CreateFileW(wide_of(path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  });
  if (file == INVALID_HANDLE_VALUE) {
    return Result<std::vector<std::byte>>::failure(
        store_error(ErrorCode::transport, "source_read_failed"));
  }
  LARGE_INTEGER position{};
  position.QuadPart = static_cast<LONG64>(offset);
  std::vector<std::byte> output(length);
  std::size_t done = 0U;
  while (done < length) {
    DWORD chunk = 0U;
    const DWORD want =
        static_cast<DWORD>(std::min<std::size_t>(length - done, 64U * 1024U * 1024U));
    if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN) ||
        !ReadFile(file, output.data() + done, want, &chunk, nullptr)) {
      CloseHandle(file);
      return Result<std::vector<std::byte>>::failure(
          store_error(ErrorCode::transport, "source_read_failed"));
    }
    if (chunk == 0U) break;  // end of file
    done += chunk;
    position.QuadPart += static_cast<LONG64>(chunk);
  }
  CloseHandle(file);
  output.resize(done);
  return Result<std::vector<std::byte>>::success(std::move(output));
#else
  const int fd = open_no_follow(path.string(), O_RDONLY, 0U);
  if (fd < 0) {
    return Result<std::vector<std::byte>>::failure(
        store_error(ErrorCode::peer_offline, "source_read_failed"));
  }
  std::vector<std::byte> output(length);
  std::size_t done = 0U;
  while (done < length) {
    const ssize_t got = ::pread(fd, output.data() + done, length - done,
                                static_cast<off_t>(offset + done));
    if (got < 0) {
      ::close(fd);
      return Result<std::vector<std::byte>>::failure(
          store_error(ErrorCode::transport, "source_read_failed"));
    }
    if (got == 0) break;  // end of file
    done += static_cast<std::size_t>(got);
  }
  ::close(fd);
  output.resize(done);
  return Result<std::vector<std::byte>>::success(std::move(output));
#endif
}

Result<Digest> blake3_file(const std::filesystem::path& path) {
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  auto opened = open_source(path);
  if (!opened) {
    return Result<Digest>::failure(*opened.error_if());
  }
  std::uint64_t offset = 0U;
  const std::uint64_t size = opened.value_if()->size;
  std::vector<std::byte> block(stream_block_bytes);
  while (offset < size) {
    const auto want =
        static_cast<std::size_t>(std::min<std::uint64_t>(stream_block_bytes, size - offset));
    auto read = read_source_range(path, offset, want);
    if (!read) {
      return Result<Digest>::failure(*read.error_if());
    }
    if (read.value_if()->size() != want) {
      return Result<Digest>::failure(store_error(ErrorCode::internal, "source_read_short"));
    }
    blake3_hasher_update(&hasher, read.value_if()->data(), read.value_if()->size());
    offset += want;
  }
  Digest digest{};
  blake3_hasher_finalize(&hasher, reinterpret_cast<std::uint8_t*>(digest.data()),
                         digest.size());
  return Result<Digest>::success(digest);
}

Result<StagingFile> create_staging(const std::filesystem::path& root_directory,
                                   const std::string& logical_name,
                                   std::string_view transfer_hex) {
  auto root_ok = ensure_directory_real(root_directory);
  if (!root_ok) {
    return Result<StagingFile>::failure(*root_ok.error_if());
  }
  // Build the final path one component at a time, checking every created
  // component against symlink substitution before files are placed inside.
  std::filesystem::path current = root_directory;
  std::size_t segment_start = 0U;
  std::vector<std::string_view> segments;
  for (std::size_t index = 0U; index <= logical_name.size(); ++index) {
    if (index == logical_name.size() || logical_name[index] == '/') {
      const auto segment = std::string_view{logical_name}.substr(segment_start,
                                                                 index - segment_start);
      if (!segment.empty()) segments.push_back(segment);
      segment_start = index + 1U;
    }
  }
  if (segments.empty()) {
    return Result<StagingFile>::failure(store_error(ErrorCode::protocol, "logical_name_invalid"));
  }
  for (std::size_t index = 0U; index + 1U < segments.size(); ++index) {
    current /= std::string{segments[index]};
    auto made = ensure_directory_real(current);
    if (!made) {
      return Result<StagingFile>::failure(*made.error_if());
    }
  }
  StagingFile staging;
  staging.final_path = current / std::string{segments.back()};
  staging.temp_path = staging.final_path;
  staging.temp_path += ".heyaki-" + std::string{transfer_hex} + ".part";
  staging.state_path = staging.final_path;
  staging.state_path += ".heyaki-" + std::string{transfer_hex} + ".state";
  return Result<StagingFile>::success(std::move(staging));
}

Result<void> write_staging_at(const std::filesystem::path& temp_path, std::uint64_t offset,
                              std::span<const std::byte> data) {
#ifdef _WIN32
  // OPEN_ALWAYS keeps an existing staging file from a resumed transfer; the
  // positional write only touches this chunk's range.
  HANDLE file = retry_sharing_violation([&] {
    return CreateFileW(wide_of(temp_path).c_str(), FILE_GENERIC_WRITE, FILE_SHARE_READ,
                       nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  });
  if (file == INVALID_HANDLE_VALUE) {
    return Result<void>::failure(store_error(ErrorCode::transport, "staging_write_failed"));
  }
  LARGE_INTEGER position{};
  position.QuadPart = static_cast<LONG64>(offset);
  std::size_t done = 0U;
  while (done < data.size()) {
    DWORD chunk = 0U;
    const DWORD want =
        static_cast<DWORD>(std::min<std::size_t>(data.size() - done, 64U * 1024U * 1024U));
    if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN) ||
        !WriteFile(file, data.data() + done, want, &chunk, nullptr)) {
      CloseHandle(file);
      return Result<void>::failure(store_error(ErrorCode::transport, "staging_write_failed"));
    }
    if (chunk == 0U) {
      CloseHandle(file);
      return Result<void>::failure(store_error(ErrorCode::internal, "staging_write_short"));
    }
    done += chunk;
    position.QuadPart += static_cast<LONG64>(chunk);
  }
  CloseHandle(file);
  return Result<void>::success();
#else
  // O_CREAT (never O_TRUNC): a resumed transfer keeps earlier chunk ranges;
  // the positional write cannot disturb them. open_no_follow rejects a
  // pre-planted symlink at the staging path.
  const int fd = open_no_follow(temp_path.string(), O_WRONLY | O_CREAT, 0600);
  if (fd < 0) {
    return Result<void>::failure(store_error(ErrorCode::transport, "staging_open_failed"));
  }
  std::size_t done = 0U;
  while (done < data.size()) {
    const ssize_t put = ::pwrite(fd, data.data() + done, data.size() - done,
                                 static_cast<off_t>(offset + done));
    if (put <= 0) {
      ::close(fd);
      return Result<void>::failure(store_error(ErrorCode::transport, "staging_write_failed"));
    }
    done += static_cast<std::size_t>(put);
  }
  ::close(fd);
  return Result<void>::success();
#endif
}

namespace {

Result<void> remove_quietly(const std::filesystem::path& path) {
  std::error_code ec;
  std::filesystem::remove(path, ec);
  if (ec) {
    return Result<void>::failure(store_error(ErrorCode::internal, "remove_failed"));
  }
  return Result<void>::success();
}

}  // namespace

Result<void> commit_staging(const StagingFile& staging) {
#ifdef _WIN32
  bool moved = false;
  for (int tries = 0; tries < 10 && !moved; ++tries) {
    moved = MoveFileExW(wide_of(staging.temp_path).c_str(),
                        wide_of(staging.final_path).c_str(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
    if (!moved && (GetLastError() == ERROR_SHARING_VIOLATION ||
                   GetLastError() == ERROR_ACCESS_DENIED)) {
      ::Sleep(50);
      continue;
    }
    break;
  }
  if (!moved) {
    return Result<void>::failure(store_error(ErrorCode::internal, "commit_rename_failed"));
  }
#else
  std::error_code ec;
  // rename() over an existing target is atomic on POSIX; the temp file lives
  // in the same directory so the rename cannot cross filesystems.
  std::filesystem::rename(staging.temp_path, staging.final_path, ec);
  if (ec) {
    return Result<void>::failure(store_error(ErrorCode::internal, "commit_rename_failed"));
  }
  const int dir_fd = ::open(staging.final_path.parent_path().string().c_str(),
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dir_fd >= 0) {
    ::fsync(dir_fd);
    ::close(dir_fd);
  }
#endif
  return remove_quietly(staging.state_path);
}

Result<void> discard_staging(const StagingFile& staging) {
  (void)remove_quietly(staging.temp_path);
  return remove_quietly(staging.state_path);
}

namespace {

// Sidecar layout: magic "HYFT" (4) | version U32 (4) | id (16) | size U64
// (8) | chunk U32 (4) | blake3 (32) | count U32 (4) | bitmap (count bytes).
constexpr std::size_t resume_header_bytes = 4U + 4U + 16U + 8U + 4U + 32U + 4U;

void put_u32(std::vector<std::byte>& out, std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    out.push_back(static_cast<std::byte>((value >> shift) & 0xFFU));
  }
}

void put_u64(std::vector<std::byte>& out, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    out.push_back(static_cast<std::byte>((value >> shift) & 0xFFU));
  }
}

std::uint32_t get_u32(const std::byte* bytes) {
  std::uint32_t value = 0U;
  for (std::size_t index = 0U; index < 4U; ++index) {
    value = (value << 8U) | static_cast<std::uint8_t>(bytes[index]);
  }
  return value;
}

std::uint64_t get_u64(const std::byte* bytes) {
  std::uint64_t value = 0U;
  for (std::size_t index = 0U; index < 8U; ++index) {
    value = (value << 8U) | static_cast<std::uint8_t>(bytes[index]);
  }
  return value;
}

Result<std::vector<std::byte>> read_small_file(const std::filesystem::path& path) {
#ifdef _WIN32
  HANDLE file = retry_sharing_violation([&] {
    return CreateFileW(wide_of(path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  });
  if (file == INVALID_HANDLE_VALUE) {
    return Result<std::vector<std::byte>>::failure(
        store_error(ErrorCode::peer_offline, "state_read_failed"));
  }
  std::vector<std::byte> output;
  std::array<std::byte, 4096U> block{};
  for (;;) {
    DWORD got = 0U;
    if (!ReadFile(file, block.data(), static_cast<DWORD>(block.size()), &got, nullptr)) {
      CloseHandle(file);
      return Result<std::vector<std::byte>>::failure(
          store_error(ErrorCode::transport, "state_read_failed"));
    }
    if (got == 0U) break;
    output.insert(output.end(), block.begin(), block.begin() + got);
    if (output.size() > 8U * 1024U * 1024U) {
      CloseHandle(file);
      return Result<std::vector<std::byte>>::failure(
          store_error(ErrorCode::resource_exhausted, "state_oversized"));
    }
  }
  CloseHandle(file);
  return Result<std::vector<std::byte>>::success(std::move(output));
#else
  const int fd = open_no_follow(path.string(), O_RDONLY, 0U);
  if (fd < 0) {
    return Result<std::vector<std::byte>>::failure(
        store_error(ErrorCode::peer_offline, "state_read_failed"));
  }
  std::vector<std::byte> output;
  std::array<std::byte, 4096U> block{};
  for (;;) {
    const ssize_t got = ::read(fd, block.data(), block.size());
    if (got < 0) {
      ::close(fd);
      return Result<std::vector<std::byte>>::failure(
          store_error(ErrorCode::transport, "state_read_failed"));
    }
    if (got == 0) break;
    output.insert(output.end(), block.begin(), block.begin() + got);
    if (output.size() > 8U * 1024U * 1024U) {
      ::close(fd);
      return Result<std::vector<std::byte>>::failure(
          store_error(ErrorCode::resource_exhausted, "state_oversized"));
    }
  }
  ::close(fd);
  return Result<std::vector<std::byte>>::success(std::move(output));
#endif
}

Result<void> write_small_file(const std::filesystem::path& path,
                              std::span<const std::byte> data) {
#ifdef _WIN32
  // OPEN_ALWAYS in write_staging_at never truncates, so remove first to keep
  // state rewrites exact.
  std::error_code ec;
  std::filesystem::remove(path, ec);
#else
  std::error_code ec;
  (void)ec;
#endif
  auto written = write_staging_at(path, 0U, data);
  if (!written) {
    return written;
  }
#ifdef _WIN32
  return Result<void>::success();
#else
  // Truncate to the exact state length on resume rewrites, durably.
  const int fd = open_no_follow(path.string(), O_WRONLY, 0600);
  if (fd >= 0) {
    if (::ftruncate(fd, static_cast<off_t>(data.size())) != 0) {
      ::close(fd);
      return Result<void>::failure(store_error(ErrorCode::internal, "state_truncate_failed"));
    }
    ::fsync(fd);
    ::close(fd);
  }
  return Result<void>::success();
#endif
}

}  // namespace

Result<void> write_resume_state(const std::filesystem::path& state_path,
                                const ResumeState& state) {
  if (state.chunk_bitmap.size() > 0xFFFFFFF0U) {
    return Result<void>::failure(store_error(ErrorCode::resource_exhausted, "state_oversized"));
  }
  std::vector<std::byte> encoded;
  encoded.reserve(resume_header_bytes + state.chunk_bitmap.size());
  encoded.push_back(std::byte{'H'});
  encoded.push_back(std::byte{'Y'});
  encoded.push_back(std::byte{'F'});
  encoded.push_back(std::byte{'T'});
  put_u32(encoded, 1U);
  const auto& id = state.transfer_id.bytes();
  encoded.insert(encoded.end(), id.begin(), id.end());
  put_u64(encoded, state.size);
  put_u32(encoded, state.chunk_size);
  encoded.insert(encoded.end(), state.blake3.begin(), state.blake3.end());
  put_u32(encoded, static_cast<std::uint32_t>(state.chunk_bitmap.size()));
  for (const auto bit : state.chunk_bitmap) {
    encoded.push_back(static_cast<std::byte>(bit != 0U ? 1U : 0U));
  }
  return write_small_file(state_path, encoded);
}

Result<ResumeState> read_resume_state(const std::filesystem::path& state_path) {
  auto raw = read_small_file(state_path);
  if (!raw) {
    return Result<ResumeState>::failure(*raw.error_if());
  }
  const auto& bytes = *raw.value_if();
  if (bytes.size() < resume_header_bytes || bytes[0] != std::byte{'H'} ||
      bytes[1] != std::byte{'Y'} || bytes[2] != std::byte{'F'} ||
      bytes[3] != std::byte{'T'}) {
    return Result<ResumeState>::failure(store_error(ErrorCode::protocol, "state_magic_invalid"));
  }
  if (get_u32(bytes.data() + 4U) != 1U) {
    return Result<ResumeState>::failure(store_error(ErrorCode::protocol, "state_version_invalid"));
  }
  ResumeState state;
  TransferId::Storage id{};
  std::copy(bytes.begin() + 8U, bytes.begin() + 24U, id.begin());
  state.transfer_id = TransferId{id};
  state.size = get_u64(bytes.data() + 24U);
  state.chunk_size = get_u32(bytes.data() + 32U);
  std::copy(bytes.begin() + 36U, bytes.begin() + 68U, state.blake3.begin());
  const auto count = get_u32(bytes.data() + 68U);
  if (bytes.size() != resume_header_bytes + count) {
    return Result<ResumeState>::failure(store_error(ErrorCode::protocol, "state_length_invalid"));
  }
  state.chunk_bitmap.resize(count);
  for (std::size_t index = 0U; index < count; ++index) {
    state.chunk_bitmap[index] = bytes[resume_header_bytes + index] != std::byte{0} ? 1U : 0U;
  }
  if (state.transfer_id.is_zero() || state.size == 0U ||
      state.chunk_size < min_file_chunk_size) {
    return Result<ResumeState>::failure(store_error(ErrorCode::protocol, "state_fields_invalid"));
  }
  return Result<ResumeState>::success(std::move(state));
}

}  // namespace heyaki::file_store
