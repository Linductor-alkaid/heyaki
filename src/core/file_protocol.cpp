// FileManifest / FileAccept / FileReject / FileComplete codec, raw FileChunk
// framing, logical-name safety checks, and the pull-request body (M7-08..M7-15)
// over the frozen heyaki.protocol.file.v1 schemas. Protobuf bodies go through
// the shared minimal wire codec; the chunk header stays raw per wire
// protocol 2.1 so the per-chunk layout stays allocation-free and fixed-size.

#include <heyaki/file.hpp>

#include "proto_codec.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace heyaki {
namespace {

using proto_codec::ProtoField;
using proto_codec::ProtoReader;

Error file_error(std::string_view detail) {
  return Error{ErrorCode::protocol, "file", std::string{detail}};
}

void append_big_u64(std::vector<std::byte>& output, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    output.push_back(static_cast<std::byte>((value >> shift) & 0xFFU));
  }
}

void append_big_u32(std::vector<std::byte>& output, std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    output.push_back(static_cast<std::byte>((value >> shift) & 0xFFU));
  }
}

std::uint64_t read_big_u64(const std::byte* bytes) {
  std::uint64_t value = 0U;
  for (std::size_t index = 0U; index < 8U; ++index) {
    value = (value << 8U) | static_cast<std::uint8_t>(bytes[index]);
  }
  return value;
}

std::uint32_t read_big_u32(const std::byte* bytes) {
  std::uint32_t value = 0U;
  for (std::size_t index = 0U; index < 4U; ++index) {
    value = (value << 8U) | static_cast<std::uint8_t>(bytes[index]);
  }
  return value;
}

bool windows_device_segment(std::string_view segment) noexcept {
  // Windows reserves CON/PRN/AUX/NUL and COM1-9/LPT1-9 with any extension.
  auto stem = segment;
  const auto dot = segment.find('.');
  if (dot != std::string_view::npos) {
    stem = segment.substr(0U, dot);
  }
  auto iequals = [stem](std::string_view name) {
    if (stem.size() != name.size()) return false;
    for (std::size_t index = 0U; index < name.size(); ++index) {
      const char left = stem[index] | 0x20U;  // ASCII lowercase
      const char right = name[index] | 0x20U;
      if (left != right) return false;
    }
    return true;
  };
  if (iequals("CON") || iequals("PRN") || iequals("AUX") || iequals("NUL")) {
    return true;
  }
  if (stem.size() == 4U) {
    const bool com = (stem[0U] | 0x20U) == 'c' && (stem[1U] | 0x20U) == 'o' &&
                     (stem[2U] | 0x20U) == 'm';
    const bool lpt = (stem[0U] | 0x20U) == 'l' && (stem[1U] | 0x20U) == 'p' &&
                     (stem[2U] | 0x20U) == 't';
    const char digit = stem[3U];
    if ((com || lpt) && digit >= '1' && digit <= '9') {
      return true;
    }
  }
  return false;
}

bool name_segment_token(std::string_view segment) noexcept {
  for (const char character : segment) {
    const bool lower = character >= 'a' && character <= 'z';
    const bool upper = character >= 'A' && character <= 'Z';
    const bool digit = character >= '0' && character <= '9';
    if (!lower && !upper && !digit && character != '_' && character != '-' &&
        character != '.' && character != ' ' && character != '(' && character != ')') {
      return false;
    }
  }
  return true;
}

}  // namespace

std::string_view file_status_name(StableStatus status) noexcept {
  switch (status) {
    case StableStatus::ok:
      return "ok";
    case StableStatus::cancelled:
      return "cancelled";
    case StableStatus::deadline_exceeded:
      return "deadline_exceeded";
    case StableStatus::unauthenticated:
      return "unauthenticated";
    case StableStatus::permission_denied:
      return "permission_denied";
    case StableStatus::not_found:
      return "not_found";
    case StableStatus::already_exists:
      return "already_exists";
    case StableStatus::resource_exhausted:
      return "resource_exhausted";
    case StableStatus::failed_precondition:
      return "failed_precondition";
    case StableStatus::unavailable:
      return "unavailable";
    case StableStatus::internal:
      return "internal";
    case StableStatus::unimplemented:
      return "unimplemented";
    case StableStatus::protocol_error:
      return "protocol_error";
    case StableStatus::outcome_unknown:
      return "outcome_unknown";
    case StableStatus::unspecified:
      break;
  }
  return "unspecified";
}

std::string_view file_transfer_phase_name(FileTransferPhase phase) noexcept {
  switch (phase) {
    case FileTransferPhase::probing:
      return "probing";
    case FileTransferPhase::offered:
      return "offered";
    case FileTransferPhase::transferring:
      return "transferring";
    case FileTransferPhase::verifying:
      return "verifying";
    case FileTransferPhase::paused:
      return "paused";
    case FileTransferPhase::committed:
      return "committed";
    case FileTransferPhase::failed:
      return "failed";
    case FileTransferPhase::cancelled:
      return "cancelled";
  }
  return "unknown";
}

bool safe_logical_file_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > max_logical_name_bytes) {
    return false;
  }
  if (name.front() == '/' || name.front() == '\\') {
    return false;  // absolute path
  }
  if (name.find('\0') != std::string_view::npos) {
    return false;  // NUL
  }
  for (const char character : name) {
    const bool printable = character >= 0x20 && character <= 0x7E;
    if (!printable && character != '\0') {
      return false;  // control bytes (NUL already rejected above)
    }
    if (character == '\\') {
      return false;  // backslash: never a valid logical separator
    }
  }
  std::size_t segments = 0U;
  std::size_t segment_start = 0U;
  for (std::size_t index = 0U; index <= name.size(); ++index) {
    if (index == name.size() || name[index] == '/') {
      const auto segment = name.substr(segment_start, index - segment_start);
      if (segment.empty() || segment == "." || segment == "..") {
        return false;
      }
      if (segment.back() == '.' || segment.back() == ' ') {
        return false;  // trailing dot/space: reserved on Windows
      }
      if (!name_segment_token(segment)) {
        return false;
      }
      if (windows_device_segment(segment)) {
        return false;
      }
      ++segments;
      if (segments > max_file_name_segments) {
        return false;
      }
      segment_start = index + 1U;
    }
  }
  return true;
}

bool safe_logical_root_name(std::string_view root) noexcept {
  if (root.empty() || root.size() > max_logical_root_name_bytes) {
    return false;
  }
  return name_segment_token(root) && root.find('/') == std::string_view::npos &&
         !windows_device_segment(root);
}

namespace {

Result<void> validate_manifest_shape(const FileManifestBody& manifest,
                                     const Limits& limits) {
  if (manifest.transfer_id.is_zero()) {
    return Result<void>::failure(file_error("transfer_id_missing"));
  }
  if (!safe_logical_file_name(manifest.logical_name)) {
    return Result<void>::failure(file_error("logical_name_invalid"));
  }
  if (manifest.size == 0U || manifest.size > limits.max_file_bytes) {
    return Result<void>::failure(file_error("size_out_of_range"));
  }
  if (manifest.blake3.size() != file_blake3_bytes) {
    return Result<void>::failure(file_error("blake3_field_invalid"));
  }
  if (manifest.chunk_size < min_file_chunk_size ||
      manifest.chunk_size > limits.max_file_chunk_bytes) {
    return Result<void>::failure(file_error("chunk_size_out_of_range"));
  }
  if (manifest.zstd_compressed) {
    if (!manifest.expanded_size.has_value()) {
      return Result<void>::failure(file_error("expanded_size_missing"));
    }
    if (*manifest.expanded_size > limits.max_expanded_file_bytes) {
      return Result<void>::failure(file_error("expanded_size_out_of_range"));
    }
  }
  return Result<void>::success();
}

}  // namespace

Result<std::vector<std::byte>> encode_file_manifest(const FileManifestBody& manifest,
                                                    const Limits& limits) {
  auto valid = validate_manifest_shape(manifest, limits);
  if (!valid) {
    return Result<std::vector<std::byte>>::failure(*valid.error_if());
  }
  std::vector<std::byte> output;
  output.reserve(manifest.logical_name.size() + 96U);
  proto_codec::append_bytes(output, 1U, manifest.transfer_id.bytes());
  proto_codec::append_text(output, 2U, manifest.logical_name);
  proto_codec::append_uint(output, 3U, manifest.size);
  proto_codec::append_bytes(output, 4U, manifest.blake3);
  proto_codec::append_uint(output, 5U, manifest.chunk_size);
  if (manifest.zstd_compressed) {
    proto_codec::append_uint(output, 6U, 1U);
  }
  if (manifest.expanded_size.has_value()) {
    proto_codec::append_uint(output, 7U, *manifest.expanded_size);
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<FileManifestBody> parse_file_manifest(std::span<const std::byte> payload,
                                             const Limits& limits) {
  FileManifestBody manifest;
  bool have_id = false;
  bool have_name = false;
  bool have_size = false;
  bool have_blake3 = false;
  bool have_chunk = false;
  ProtoReader reader{payload};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<FileManifestBody>::failure(*field.error_if());
    }
    const auto& value = *field.value_if();
    if (value.number == 1U && value.wire_type == 2U) {
      if (value.bytes.size() != TransferId::size_bytes) {
        return Result<FileManifestBody>::failure(file_error("transfer_id_field_invalid"));
      }
      TransferId::Storage storage{};
      std::copy(value.bytes.begin(), value.bytes.end(), storage.begin());
      manifest.transfer_id = TransferId{storage};
      have_id = true;
    } else if (value.number == 2U && value.wire_type == 2U) {
      manifest.logical_name.assign(reader.text(value));
      have_name = true;
    } else if (value.number == 3U && value.wire_type == 0U) {
      manifest.size = value.integer;
      have_size = true;
    } else if (value.number == 4U && value.wire_type == 2U) {
      manifest.blake3.assign(value.bytes.begin(), value.bytes.end());
      have_blake3 = true;
    } else if (value.number == 5U && value.wire_type == 0U) {
      if (value.integer > 0xFFFFFFFFULL) {
        return Result<FileManifestBody>::failure(file_error("chunk_size_out_of_range"));
      }
      manifest.chunk_size = static_cast<std::uint32_t>(value.integer);
      have_chunk = true;
    } else if (value.number == 6U && value.wire_type == 0U) {
      manifest.zstd_compressed = value.integer != 0U;
    } else if (value.number == 7U && value.wire_type == 0U) {
      manifest.expanded_size = value.integer;
    }
  }
  if (!have_id || !have_name || !have_size || !have_blake3 || !have_chunk) {
    return Result<FileManifestBody>::failure(file_error("manifest_field_missing"));
  }
  auto valid = validate_manifest_shape(manifest, limits);
  if (!valid) {
    return Result<FileManifestBody>::failure(*valid.error_if());
  }
  return Result<FileManifestBody>::success(std::move(manifest));
}

Result<std::vector<std::byte>> encode_file_accept(const FileAcceptBody& accept) {
  if (accept.transfer_id.is_zero()) {
    return Result<std::vector<std::byte>>::failure(file_error("transfer_id_missing"));
  }
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, accept.transfer_id.bytes());
  for (const auto index : accept.present_chunk_indices) {
    proto_codec::append_uint(output, 2U, index);
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<FileAcceptBody> parse_file_accept(std::span<const std::byte> payload) {
  FileAcceptBody accept;
  bool have_id = false;
  ProtoReader reader{payload};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<FileAcceptBody>::failure(*field.error_if());
    }
    const auto& value = *field.value_if();
    if (value.number == 1U && value.wire_type == 2U) {
      if (value.bytes.size() != TransferId::size_bytes) {
        return Result<FileAcceptBody>::failure(file_error("transfer_id_field_invalid"));
      }
      TransferId::Storage storage{};
      std::copy(value.bytes.begin(), value.bytes.end(), storage.begin());
      accept.transfer_id = TransferId{storage};
      have_id = true;
    } else if (value.number == 2U && value.wire_type == 0U) {
      // A manifest bounds the index space; past-maximum indices are a
      // protocol violation, not a silent clamp.
      if (!accept.present_chunk_indices.empty() &&
          value.integer < accept.present_chunk_indices.back()) {
        return Result<FileAcceptBody>::failure(file_error("chunk_indices_unordered"));
      }
      accept.present_chunk_indices.push_back(value.integer);
    }
  }
  if (!have_id) {
    return Result<FileAcceptBody>::failure(file_error("accept_field_missing"));
  }
  return Result<FileAcceptBody>::success(std::move(accept));
}

namespace {

Result<void> validate_reject_shape(const TransferId& id, StableStatus status,
                                   const std::string& safe_detail) {
  if (id.is_zero()) {
    return Result<void>::failure(file_error("transfer_id_missing"));
  }
  if (status == StableStatus::unspecified || status == StableStatus::ok) {
    return Result<void>::failure(file_error("status_invalid"));
  }
  if (!safe_detail.empty() && !is_safe_detail_token(safe_detail)) {
    return Result<void>::failure(file_error("safe_detail_invalid"));
  }
  return Result<void>::success();
}

}  // namespace

Result<std::vector<std::byte>> encode_file_reject(const FileRejectBody& reject) {
  auto valid = validate_reject_shape(reject.transfer_id, reject.status, reject.safe_detail);
  if (!valid) {
    return Result<std::vector<std::byte>>::failure(*valid.error_if());
  }
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, reject.transfer_id.bytes());
  proto_codec::append_uint(output, 2U, static_cast<std::uint32_t>(reject.status));
  proto_codec::append_text(output, 3U, reject.safe_detail);
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<FileRejectBody> parse_file_reject(std::span<const std::byte> payload) {
  FileRejectBody reject;
  bool have_id = false;
  bool have_status = false;
  ProtoReader reader{payload};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<FileRejectBody>::failure(*field.error_if());
    }
    const auto& value = *field.value_if();
    if (value.number == 1U && value.wire_type == 2U) {
      if (value.bytes.size() != TransferId::size_bytes) {
        return Result<FileRejectBody>::failure(file_error("transfer_id_field_invalid"));
      }
      TransferId::Storage storage{};
      std::copy(value.bytes.begin(), value.bytes.end(), storage.begin());
      reject.transfer_id = TransferId{storage};
      have_id = true;
    } else if (value.number == 2U && value.wire_type == 0U) {
      reject.status = static_cast<StableStatus>(value.integer);
      have_status = true;
    } else if (value.number == 3U && value.wire_type == 2U) {
      reject.safe_detail.assign(reader.text(value));
    }
  }
  if (!have_id || !have_status) {
    return Result<FileRejectBody>::failure(file_error("reject_field_missing"));
  }
  auto valid = validate_reject_shape(reject.transfer_id, reject.status, reject.safe_detail);
  if (!valid) {
    return Result<FileRejectBody>::failure(*valid.error_if());
  }
  return Result<FileRejectBody>::success(std::move(reject));
}

Result<std::vector<std::byte>> encode_file_complete(const FileCompleteBody& complete) {
  if (complete.transfer_id.is_zero()) {
    return Result<std::vector<std::byte>>::failure(file_error("transfer_id_missing"));
  }
  if (complete.status == StableStatus::unspecified) {
    return Result<std::vector<std::byte>>::failure(file_error("status_invalid"));
  }
  if (!complete.safe_detail.empty() && !is_safe_detail_token(complete.safe_detail)) {
    return Result<std::vector<std::byte>>::failure(file_error("safe_detail_invalid"));
  }
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, complete.transfer_id.bytes());
  proto_codec::append_uint(output, 2U, static_cast<std::uint32_t>(complete.status));
  if (!complete.safe_detail.empty()) {
    proto_codec::append_text(output, 3U, complete.safe_detail);
  }
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<FileCompleteBody> parse_file_complete(std::span<const std::byte> payload) {
  FileCompleteBody complete;
  bool have_id = false;
  bool have_status = false;
  ProtoReader reader{payload};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<FileCompleteBody>::failure(*field.error_if());
    }
    const auto& value = *field.value_if();
    if (value.number == 1U && value.wire_type == 2U) {
      if (value.bytes.size() != TransferId::size_bytes) {
        return Result<FileCompleteBody>::failure(file_error("transfer_id_field_invalid"));
      }
      TransferId::Storage storage{};
      std::copy(value.bytes.begin(), value.bytes.end(), storage.begin());
      complete.transfer_id = TransferId{storage};
      have_id = true;
    } else if (value.number == 2U && value.wire_type == 0U) {
      complete.status = static_cast<StableStatus>(value.integer);
      have_status = true;
    } else if (value.number == 3U && value.wire_type == 2U) {
      complete.safe_detail.assign(reader.text(value));
    }
  }
  if (!have_id || !have_status) {
    return Result<FileCompleteBody>::failure(file_error("complete_field_missing"));
  }
  if (complete.status == StableStatus::unspecified ||
      (!complete.safe_detail.empty() && !is_safe_detail_token(complete.safe_detail))) {
    return Result<FileCompleteBody>::failure(file_error("status_invalid"));
  }
  return Result<FileCompleteBody>::success(std::move(complete));
}

std::vector<std::byte> encode_file_chunk(const FileChunkHeader& header,
                                         std::span<const std::byte> data) {
  std::vector<std::byte> output;
  output.reserve(file_chunk_header_bytes + data.size());
  const auto& id = header.transfer_id.bytes();
  output.insert(output.end(), id.begin(), id.end());
  append_big_u64(output, header.offset);
  append_big_u32(output, static_cast<std::uint32_t>(data.size()));
  output.insert(output.end(), header.blake3.begin(), header.blake3.end());
  output.insert(output.end(), data.begin(), data.end());
  return output;
}

Result<ParsedFileChunk> parse_file_chunk(std::span<const std::byte> payload,
                                         const Limits& limits) {
  if (payload.size() < file_chunk_header_bytes) {
    return Result<ParsedFileChunk>::failure(file_error("chunk_header_truncated"));
  }
  ParsedFileChunk parsed;
  TransferId::Storage id_storage{};
  std::copy(payload.begin(), payload.begin() + TransferId::size_bytes, id_storage.begin());
  parsed.header.transfer_id = TransferId{id_storage};
  if (parsed.header.transfer_id.is_zero()) {
    return Result<ParsedFileChunk>::failure(file_error("transfer_id_missing"));
  }
  parsed.header.offset = read_big_u64(payload.data() + 16U);
  parsed.header.data_length = read_big_u32(payload.data() + 24U);
  std::copy(payload.begin() + 28U, payload.begin() + 60U, parsed.header.blake3.begin());
  const auto data = payload.subspan(file_chunk_header_bytes);
  if (parsed.header.data_length != data.size()) {
    return Result<ParsedFileChunk>::failure(file_error("chunk_length_mismatch"));
  }
  if (data.size() > limits.max_file_chunk_bytes) {
    return Result<ParsedFileChunk>::failure(file_error("chunk_oversized"));
  }
  parsed.data = data;
  return Result<ParsedFileChunk>::success(std::move(parsed));
}

Result<std::vector<std::byte>> encode_file_pull_request(const FilePullRequestBody& request) {
  if (request.transfer_id.is_zero()) {
    return Result<std::vector<std::byte>>::failure(file_error("transfer_id_missing"));
  }
  if (!safe_logical_root_name(request.root)) {
    return Result<std::vector<std::byte>>::failure(file_error("root_invalid"));
  }
  if (!safe_logical_file_name(request.logical_name)) {
    return Result<std::vector<std::byte>>::failure(file_error("logical_name_invalid"));
  }
  // Nested message { bytes transfer_id = 1; string root = 2; string name = 3 }
  // carried inside the opaque RPC payload.
  std::vector<std::byte> output;
  proto_codec::append_bytes(output, 1U, request.transfer_id.bytes());
  proto_codec::append_text(output, 2U, request.root);
  proto_codec::append_text(output, 3U, request.logical_name);
  return Result<std::vector<std::byte>>::success(std::move(output));
}

Result<FilePullRequestBody> parse_file_pull_request(std::span<const std::byte> payload) {
  FilePullRequestBody request;
  bool have_id = false;
  bool have_root = false;
  bool have_name = false;
  ProtoReader reader{payload};
  while (!reader.done()) {
    auto field = reader.next();
    if (!field) {
      return Result<FilePullRequestBody>::failure(*field.error_if());
    }
    const auto& value = *field.value_if();
    if (value.number == 1U && value.wire_type == 2U) {
      if (value.bytes.size() != TransferId::size_bytes) {
        return Result<FilePullRequestBody>::failure(file_error("transfer_id_field_invalid"));
      }
      TransferId::Storage storage{};
      std::copy(value.bytes.begin(), value.bytes.end(), storage.begin());
      request.transfer_id = TransferId{storage};
      have_id = true;
    } else if (value.number == 2U && value.wire_type == 2U) {
      request.root.assign(reader.text(value));
      have_root = true;
    } else if (value.number == 3U && value.wire_type == 2U) {
      request.logical_name.assign(reader.text(value));
      have_name = true;
    }
  }
  if (!have_id || !have_root || !have_name) {
    return Result<FilePullRequestBody>::failure(file_error("pull_field_missing"));
  }
  if (request.transfer_id.is_zero() || !safe_logical_root_name(request.root) ||
      !safe_logical_file_name(request.logical_name)) {
    return Result<FilePullRequestBody>::failure(file_error("pull_fields_invalid"));
  }
  return Result<FilePullRequestBody>::success(std::move(request));
}

}  // namespace heyaki
