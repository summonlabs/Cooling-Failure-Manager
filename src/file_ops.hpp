// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Narrow native file system and locking primitives. Not installed.

#ifndef DCCP_COOLING_FAILURE_MANAGER_SRC_FILE_OPS_HPP
#define DCCP_COOLING_FAILURE_MANAGER_SRC_FILE_OPS_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/result.hpp"

namespace dccp::cooling_failure_manager::internal {

struct PathInfo {
  bool exists = false;
  bool is_directory = false;
  bool is_regular = false;
  bool is_reparse_point = false;
  std::uint64_t size = 0;
};

/// Validates the spelling of a path: length, UTF-8, no NUL, no control
/// characters, no parent-directory component, no empty component, no Windows
/// device name, no reserved character inside a component, no UNC or device
/// prefix, and no colon outside the drive prefix. Does not touch the file
/// system.
Result<void> validate_path_spelling(std::string_view path);

/// Rejects a path whose existing components include a reparse point.
Result<void> verify_no_reparse_ancestors(const std::string& path);

/// Canonicalizes the store root for the lifetime of a store handle: absolute,
/// spelled with the platform separator, duplicate separators collapsed and no
/// trailing separator. A root that is relative, that is the file system root
/// itself, that contains a parent-directory component, that exceeds
/// limits::kMaxStorePathBytes, or that is or resolves through a symbolic link,
/// junction or other reparse point is refused, so that two processes cannot
/// obtain different locks for the same logical store.
Result<std::string> canonicalize_store_root(std::string_view root);

Result<PathInfo> inspect_path(const std::string& path);

Result<bool> path_exists(const std::string& path);

/// Size of an existing regular file. A missing path, a directory and a reparse
/// point are refused.
Result<std::uint64_t> file_size(const std::string& path);

Result<void> create_directory(const std::string& path);

/// create_directory applied to every component in turn, so that a store root
/// can be created below directories that do not exist yet.
Result<void> create_directories(const std::string& path);

/// Names only (no paths), sorted byte-wise. The directory must exist. A name
/// that would not be usable as a single ASCII path component is refused, and no
/// entry is ever followed.
Result<std::vector<std::string>> list_directory(const std::string& path);

/// Reads a whole file, refusing anything larger than max_bytes and refusing a
/// directory or a reparse point. A file that shrinks or grows between the size
/// check and the read is reported, never silently truncated.
Result<std::string> read_file(const std::string& path, std::size_t max_bytes);

/// Creates or truncates a file and writes every byte. When durable is set the
/// content is flushed to the storage device before returning.
Result<void> write_file(const std::string& path, std::string_view bytes, bool durable);

/// Atomically replaces the target with the already written file staged. When
/// durable is set the replacement is ordered through the storage device.
Result<void> atomic_replace(const std::string& target, const std::string& staged, bool durable);

/// Renames the file named by the first path to the name given by the second,
/// inside one directory, replacing an existing target. Both paths must name the
/// same directory: a move across directories is an atomic_replace and is
/// deliberately not offered here.
Result<void> rename_within_directory(const std::string& from, const std::string& to, bool durable);

Result<void> remove_file(const std::string& path);

/// Removes a directory only when it holds no entry. A directory that is already
/// gone is not an error, so cleanup paths are idempotent.
Result<void> remove_directory_if_empty(const std::string& path);

/// Flushes a directory entry change where the platform supports it.
Result<void> flush_directory(const std::string& path, bool durable);

Result<std::uint64_t> remove_directory_contents(const std::string& path, bool remove_directory);

/// Exclusive, non-blocking advisory lock on a file, released by the operating
/// system when the holding process dies. Move only.
class FileLock {
 public:
  FileLock() noexcept = default;
  ~FileLock();
  FileLock(FileLock&& other) noexcept;
  FileLock& operator=(FileLock&& other) noexcept;
  FileLock(const FileLock&) = delete;
  FileLock& operator=(const FileLock&) = delete;

  /// Acquires the lock; returns StoreLocked when another live holder owns it.
  /// The owner text is diagnostic content written into the lock file and is
  /// bounded to 256 bytes.
  static Result<FileLock> acquire(const std::string& path, std::string_view owner_text);

  Result<void> release();
  bool held() const noexcept;

 private:
#if defined(_WIN32)
  void* handle_ = nullptr;
#else
  int descriptor_ = -1;
#endif
};

/// Non-interactive process self-termination used by the documented fault
/// injection points. Never routes through the CRT abort path, so no Windows
/// Error Reporting dialog can appear.
[[noreturn]] void terminate_process_now(int code);

/// True when the configured fault selector matches this occurrence of the
/// stage. The selector is a stage name, optionally suffixed with "#n" to fire on
/// the n-th occurrence; "any" matches every stage.
bool fault_selected(bool enabled, const char* stage);

/// Fault injection point: when selected, terminates the process immediately.
void fault_point(bool enabled, const char* stage);

/// Name of the requested fault stage (COOLING_FAILURE_MANAGER_FAULT_STAGE),
/// empty when unset. Consulted only when fault injection is explicitly enabled.
std::string fault_stage_name();

}  // namespace dccp::cooling_failure_manager::internal

#endif  // DCCP_COOLING_FAILURE_MANAGER_SRC_FILE_OPS_HPP
