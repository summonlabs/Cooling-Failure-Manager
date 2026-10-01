// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Native file system and locking primitives for the durable store. Not
// installed: every entry point is internal.
//
// ---------------------------------------------------------------------------
// WHY these primitives are written by hand
// ---------------------------------------------------------------------------
// A store is identified by the canonical spelling of its root. The lock file,
// the manifest, the generation files and the staging area are all reached by
// joining that root with a fixed name, so two processes that name the same
// logical store must derive the same string, and no name may be rewritten
// silently by the platform on the way to the file system. Rather than rely on
// a standard library wrapper, whose normalization, symlink and error
// behaviour differs per implementation and per library version, the checks are
// written out here and the native calls are made with the flags that forbid
// following a reparse point.
//
// ---------------------------------------------------------------------------
// Exactly which spellings are refused, and why
// ---------------------------------------------------------------------------
//   1. Empty, longer than limits::kMaxStorePathBytes bytes, not valid UTF-8,
//      or containing NUL or any other control byte: such a spelling cannot be
//      converted to the wide form faithfully, and a filename with a control
//      byte cannot be rendered in a diagnostic. (PathInvalid)
//   2. A leading double separator, which Win32 reads as a UNC path
//      (double backslash server share) or as a device namespace path
//      (double backslash question mark, double backslash dot). Both are
//      refused on every platform: a device namespace path disables the normal
//      path parsing, so every spelling check below would become meaningless,
//      and a UNC path names a share rather than a directory of this machine.
//      (PathUnsafeName)
//   3. On Windows, a colon anywhere other than index 1 behind an ASCII
//      letter. A second colon opens an alternate data stream, so a write to
//      "manifest:evil" would silently target a stream of the manifest and a
//      later read of "manifest" would not see it. (PathUnsafeName)
//      On POSIX, any colon is refused for the same portability reason as the
//      reserved characters below.
//   4. On Windows, a leading separator with no drive prefix: that spelling is
//      relative to the current directory of the current drive, which is a
//      per-process and per-drive state and therefore cannot be part of a
//      store identity. (PathInvalid)
//   5. A drive prefix alone ("C:") or a drive-relative spelling ("C:store"):
//      both depend on the per-drive current directory. A bare file system
//      root ("C:\" or "/") is refused as well, because a store root must be a
//      directory below a root and no store entry may sit at a file system
//      root. (PathInvalid)
//   6. An empty component: a duplicate separator, or a trailing separator.
//      Win32 accepts both and collapses them, so accepting them here would
//      mean that two different strings name one store root while a third
//      string that a caller believes equal does not. The single exception is
//      canonicalize_store_root, which is the entry point that accepts an
//      operator-supplied root and normalizes exactly these two shapes; it ends
//      by re-validating the normalized result with the strict rules.
//      (PathInvalid)
//   7. A "." or ".." component. (PathTraversal, subject is the component) A
//      parent component would let a caller escape the directory it named, so
//      it is refused instead of being resolved.
//   8. A Windows device name as any component, with any extension: CON, PRN,
//      AUX, NUL, COM1..COM9, LPT1..LPT9. Win32 resolves those names to
//      devices regardless of the directory they appear in and regardless of
//      an extension, so "NUL.txt" is not a file in the store but the null
//      device; a write there succeeds and loses the bytes, and a read returns
//      nothing. Comparison is case-insensitive because Win32 file names are.
//      The rule is applied on POSIX too: such a name is legal there but the
//      store could not be opened by a Windows process. (PathUnsafeName)
//   9. A component containing one of the characters Win32 reserves:
//      less than, greater than, double quote, vertical bar, question mark,
//      asterisk. They cannot be created on Windows and the question mark and
//      asterisk are wildcards to the search APIs, so a name containing them
//      could make a listing match entries the caller never named.
//      (PathUnsafeName)
//  10. A component that ends in a dot or a space. Win32 strips trailing dots
//      and spaces from every component before it reaches the file system, so
//      "manifest." and "manifest" would name one file while a caller believed
//      it had two, and a listing would return a name that cannot be opened by
//      the spelling that produced it. Refused on POSIX as well, because such
//      a store could not be moved to Windows. (PathUnsafeName)
//
// ---------------------------------------------------------------------------
// Durability
// ---------------------------------------------------------------------------
// Durability is never assumed. write_file flushes the file itself when asked,
// atomic_replace asks the move to be write-through, and flush_directory is a
// documented no-op on Windows, which has no directory fsync primitive: the
// ordering of a Windows directory entry change is requested with
// MOVEFILE_WRITE_THROUGH on the rename, not claimed afterwards. On POSIX
// flush_directory fsyncs the directory. No function in this file reports
// durability it did not establish.
//
// ---------------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------------
// FileLock takes a non-blocking exclusive advisory lock on a byte range in a
// file that is opened with a permissive share mode. The share mode is not the
// exclusion mechanism: a read-only observer must still be able to open the
// lock file and read the owner text while a writer holds the lock, so on
// Windows the locked byte sits beyond the owner text (a byte-range lock is
// enforced against reads through any other handle) and on POSIX the flock is
// advisory and does not affect reads at all. The kernel
// releases the lock when the handle or descriptor is closed, which includes
// process death, so an abruptly terminated writer cannot leave the store
// locked. Handles are created without inheritance and POSIX descriptors are
// opened close-on-exec, so a child process never inherits a held lock.

#include "file_ops.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Fallbacks for the rare POSIX system that does not define one of these. A
// zero flag means the protection it asks for is not available on that system;
// the lstat checks above still refuse a symbolic link and a non-regular file
// before the descriptor is used.
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#endif

namespace dccp::cooling_failure_manager::internal {
namespace {

/// The separator the canonical form is spelled with. Both slash characters are
/// separators in a spelling on every platform, so that one string is
/// interpreted identically here and on a machine with a different separator.
constexpr char kSeparator =
#if defined(_WIN32)
    '\\';
#else
    '/';
#endif

/// Longest diagnostic owner text written into a lock file.
constexpr std::size_t kMaxLockOwnerBytes = 256;

/// Longest path fragment carried as an error subject. Only an over-long
/// spelling is clamped: every other refusal happens after the length bound, so
/// its subject is the complete path the caller supplied.
constexpr std::size_t kMaxErrorSubjectBytes = 256;

/// Largest single read or write request, so that a large file never needs one
/// unbounded request and a huge length can never be turned into one
/// allocation-sized system call.
constexpr std::size_t kIoChunkBytes = 1u << 20;

/// Defensive bound on the recursion depth of remove_directory_contents. A
/// store tree is two or three levels deep; a deeper tree is foreign content
/// and is refused rather than followed to an unbounded depth.
constexpr std::uint64_t kMaxRemovalDepth = 64;

/// Exit code of a selected fault point. Non-zero so that a test harness and a
/// supervisor can tell an injected fault from a clean exit.
constexpr int kFaultTerminationCode = 91;

/// Environment variable holding the fault selector. Consulted once per call,
/// and only when a caller explicitly enables injection.
constexpr const char* const kFaultStageVariable = "COOLING_FAILURE_MANAGER_FAULT_STAGE";

bool is_separator(char character) noexcept { return character == '/' || character == '\\'; }

bool is_ascii_alpha(char character) noexcept {
  return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z');
}

/// ASCII case-insensitive comparison. Win32 file names are case-insensitive,
/// so every name rule has to be applied the same way to both cases.
bool equals_ignore_case(std::string_view lhs, std::string_view rhs) noexcept {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  for (std::size_t index = 0; index < lhs.size(); ++index) {
    char left = lhs[index];
    char right = rhs[index];
    if (left >= 'A' && left <= 'Z') {
      left = static_cast<char>(left - 'A' + 'a');
    }
    if (right >= 'A' && right <= 'Z') {
      right = static_cast<char>(right - 'A' + 'a');
    }
    if (left != right) {
      return false;
    }
  }
  return true;
}

/// Characters Win32 refuses in a file name (rule 9 in the file header).
bool is_reserved_component_character(char character) noexcept {
  switch (character) {
    case '<':
    case '>':
    case '"':
    case '|':
    case '?':
    case '*':
      return true;
    default:
      return false;
  }
}

/// True when the component names a Windows device (rule 8 in the file header).
/// The comparison is made on the part before the first dot, because Win32
/// resolves such a name to the device whatever extension follows it.
bool is_device_name(std::string_view component) noexcept {
  std::string_view stem = component;
  const std::size_t dot = stem.find('.');
  if (dot != std::string_view::npos) {
    stem = stem.substr(0, dot);
  }
  static constexpr std::string_view kNames[] = {"con",  "prn",  "aux",  "nul",  "com1", "com2", "com3", "com4",
                                                "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3",
                                                "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"};
  for (const std::string_view name : kNames) {
    if (equals_ignore_case(stem, name)) {
      return true;
    }
  }
  return false;
}

std::string subject_of(std::string_view path) {
  if (path.size() <= kMaxErrorSubjectBytes) {
    return std::string(path);
  }
  return std::string(path.substr(0, kMaxErrorSubjectBytes));
}

/// Checks one component against rules 7 to 10 of the file header.
Result<void> check_component(std::string_view component) {
  if (component == "." || component == "..") {
    return Error(ErrorCode::PathTraversal,
                 "a current-directory or parent-directory component would escape the named directory")
        .with_subject(std::string(component));
  }
  if (is_device_name(component)) {
    return Error(ErrorCode::PathUnsafeName, "the component names a Windows device, not a store entry")
        .with_subject(std::string(component));
  }
  for (const char character : component) {
    if (is_reserved_component_character(character)) {
      return Error(ErrorCode::PathUnsafeName, "the component contains a character Windows reserves")
          .with_subject(std::string(component));
    }
  }
  if (component.back() == '.' || component.back() == ' ') {
    return Error(ErrorCode::PathUnsafeName,
                 "the component ends with a dot or a space, which Windows strips before the file system sees it")
        .with_subject(std::string(component));
  }
  return ok();
}

/// A spelling decomposed into the root marker and its components.
struct SpellingParts {
  /// "X:" on Windows or "/" on POSIX for a spelling that starts at a file
  /// system root, empty for a relative spelling.
  std::string root;
  std::vector<std::string_view> components;
};

/// Checks a spelling completely and splits it. allow_redundant_separators is
/// set only by canonicalize_store_root, which accepts an operator-supplied
/// root and normalizes a duplicate or trailing separator instead of refusing
/// it; every other caller uses the strict form.
Result<SpellingParts> parse_spelling(std::string_view path, bool allow_redundant_separators) {
  if (path.empty()) {
    return Error(ErrorCode::PathInvalid, "the path must not be empty");
  }
  if (path.size() > limits::kMaxStorePathBytes) {
    return Error(ErrorCode::PathInvalid, "the path exceeds the configured byte bound")
        .with_subject(subject_of(path))
        .with_detail("bound=" + std::to_string(limits::kMaxStorePathBytes));
  }
  // is_valid_utf8 rejects an embedded NUL, an overlong encoding, a surrogate
  // and a truncated sequence, so it covers the encoding rule completely.
  if (!is_valid_utf8(path)) {
    return Error(ErrorCode::PathInvalid, "the path is not valid UTF-8 or contains NUL");
  }
  for (const char character : path) {
    const unsigned char byte = static_cast<unsigned char>(character);
    if (byte < 0x20 || byte == 0x7F) {
      return Error(ErrorCode::PathInvalid, "the path contains a control character");
    }
  }

  const bool leading_separator = is_separator(path[0]);
  if (leading_separator && path.size() >= 2 && is_separator(path[1])) {
    return Error(ErrorCode::PathUnsafeName,
                 "a leading double separator denotes a UNC or device path, which a store never uses")
        .with_subject(subject_of(path));
  }

#if defined(_WIN32)
  const std::size_t colon = path.find(':');
  if (colon != std::string_view::npos) {
    if (colon != 1 || !is_ascii_alpha(path[0])) {
      return Error(ErrorCode::PathUnsafeName, "only a drive-letter prefix may contain a colon")
          .with_subject(subject_of(path));
    }
    if (path.find(':', colon + 1) != std::string_view::npos) {
      return Error(ErrorCode::PathUnsafeName,
                   "a second colon would select an alternate data stream instead of the named file")
          .with_subject(subject_of(path));
    }
  }
#else
  if (path.find(':') != std::string_view::npos) {
    return Error(ErrorCode::PathUnsafeName, "a colon cannot appear in a portable store name")
        .with_subject(subject_of(path));
  }
#endif

  SpellingParts parts;
  std::size_t index = 0;
#if defined(_WIN32)
  if (leading_separator) {
    return Error(ErrorCode::PathInvalid,
                 "a leading separator without a drive prefix is relative to the current drive of this process")
        .with_subject(subject_of(path));
  }
  if (path.size() >= 2 && is_ascii_alpha(path[0]) && path[1] == ':') {
    if (path.size() == 2) {
      return Error(ErrorCode::PathInvalid, "a drive prefix alone names no directory").with_subject(subject_of(path));
    }
    if (!is_separator(path[2])) {
      return Error(ErrorCode::PathInvalid,
                   "a drive-relative spelling depends on a per-drive current directory and cannot identify a store")
          .with_subject(subject_of(path));
    }
    parts.root.assign(path.substr(0, 2));
    index = 3;
    if (index == path.size()) {
      return Error(ErrorCode::PathInvalid, "a file system root cannot be a store path").with_subject(subject_of(path));
    }
  }
#else
  if (leading_separator) {
    parts.root.assign(1, kSeparator);
    index = 1;
    if (index == path.size()) {
      return Error(ErrorCode::PathInvalid, "a file system root cannot be a store path").with_subject(subject_of(path));
    }
  }
#endif

  bool first_component = true;
  while (index < path.size()) {
    std::size_t separators = 0;
    while (index < path.size() && is_separator(path[index])) {
      ++index;
      ++separators;
    }
    if (index == path.size()) {
      if (separators > 0 && !allow_redundant_separators) {
        return Error(ErrorCode::PathInvalid, "the path must not end with a separator").with_subject(subject_of(path));
      }
      break;
    }
    if (separators > 1 && !allow_redundant_separators) {
      return Error(ErrorCode::PathInvalid, "the path contains an empty component").with_subject(subject_of(path));
    }
    const std::size_t start = index;
    while (index < path.size() && !is_separator(path[index])) {
      ++index;
    }
    const std::string_view component = path.substr(start, index - start);
    CFM_TRYV(check_component(component));
    parts.components.push_back(component);
    first_component = false;
  }
  (void)first_component;
  if (parts.components.empty()) {
    return Error(ErrorCode::PathInvalid, "the path names no component").with_subject(subject_of(path));
  }
  return parts;
}

/// Appends one component to a growing prefix, inserting the canonical
/// separator only where one is missing, so a root marker ("C:" or "/") is
/// extended correctly.
void append_path_component(std::string& prefix, std::string_view component) {
  if (!prefix.empty() && prefix.back() != kSeparator) {
    prefix.push_back(kSeparator);
  }
  prefix.append(component);
}

/// Directory portion of a validated spelling: everything before the last
/// separator. Used to keep a replacement inside one directory.
std::string parent_directory_of(std::string_view path) {
  const std::size_t separator = path.find_last_of("/\\");
  if (separator == std::string_view::npos) {
    return std::string(".");
  }
  if (separator == 0) {
    return std::string(1, path[0]);
  }
#if defined(_WIN32)
  if (separator == 2 && is_ascii_alpha(path[0]) && path[1] == ':') {
    return std::string(path.substr(0, 3));
  }
#endif
  return std::string(path.substr(0, separator));
}

/// Re-spells every separator with the canonical character so that two
/// spellings of one directory compare equal.
std::string with_platform_separator(std::string_view path) {
  std::string out;
  out.reserve(path.size());
  for (const char character : path) {
    out.push_back(is_separator(character) ? kSeparator : character);
  }
  return out;
}

/// True when two validated spellings name entries of one directory. The
/// comparison is case-insensitive on Windows because Windows resolves a path
/// case-insensitively, and a purely textual comparison would refuse a
/// legitimate replacement that was spelled with a different case.
bool same_directory(std::string_view lhs, std::string_view rhs) {
  const std::string left = with_platform_separator(parent_directory_of(lhs));
  const std::string right = with_platform_separator(parent_directory_of(rhs));
#if defined(_WIN32)
  return equals_ignore_case(left, right);
#else
  return left == right;
#endif
}

/// True when a name read from a directory is usable as a single path
/// component: printable ASCII without a separator, a colon, a reserved
/// character or a control character, not the current or parent directory, not
/// a device name, and not ending in a dot or a space. The library only ever
/// creates such names, so anything else is foreign content and is refused
/// instead of being carried into a path.
bool is_safe_entry_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > limits::kMaxStorePathBytes) {
    return false;
  }
  if (name == "." || name == "..") {
    return false;
  }
  for (const char character : name) {
    const unsigned char byte = static_cast<unsigned char>(character);
    if (byte < 0x20 || byte > 0x7E) {
      return false;  // control byte, NUL or a non-ASCII byte
    }
    if (is_separator(character) || character == ':') {
      return false;  // separator, drive qualifier or alternate data stream
    }
    if (is_reserved_component_character(character)) {
      return false;
    }
  }
  if (name.back() == '.' || name.back() == ' ') {
    return false;  // Windows strips a trailing dot or space
  }
  return !is_device_name(name);
}

/// Diagnostic owner text for a lock file: at most kMaxLockOwnerBytes bytes of
/// valid UTF-8 without control bytes, truncated at a code point boundary. The
/// text is diagnostic only, so a hostile or over-long value is sanitized
/// rather than being allowed to fail a lock acquisition.
std::string sanitize_owner_text(std::string_view raw) {
  std::string out;
  out.reserve(std::min<std::size_t>(raw.size(), kMaxLockOwnerBytes));
  std::size_t index = 0;
  while (index < raw.size()) {
    const unsigned char byte = static_cast<unsigned char>(raw[index]);
    if (byte < 0x20 || byte == 0x7F) {
      out.push_back('?');
      ++index;
      continue;
    }
    if (byte < 0x80) {
      if (out.size() + 1 > kMaxLockOwnerBytes) {
        break;
      }
      out.push_back(static_cast<char>(byte));
      ++index;
      continue;
    }
    std::size_t width = 0;
    if (byte >= 0xC2 && byte <= 0xDF) {
      width = 2;
    } else if (byte >= 0xE0 && byte <= 0xEF) {
      width = 3;
    } else if (byte >= 0xF0 && byte <= 0xF4) {
      width = 4;
    }
    if (width == 0 || index + width > raw.size() || !is_valid_utf8(raw.substr(index, width))) {
      out.push_back('?');
      ++index;
      continue;
    }
    if (out.size() + width > kMaxLockOwnerBytes) {
      break;  // never split a sequence: the truncation point is a boundary
    }
    out.append(raw.substr(index, width));
    index += width;
  }
  return out;
}

#if defined(_WIN32)

std::string windows_error_text(const char* what, DWORD error) {
  return std::string(what) + " failed with GetLastError=" + std::to_string(error);
}

/// Offset of the single byte the exclusive lock covers. It is far beyond the
/// owner text on purpose: a Windows byte-range lock is enforced against every
/// other handle, including one in the same process, so a lock that covered
/// byte zero would make the owner text unreadable with ERROR_LOCK_VIOLATION
/// exactly while the lock is held, and an observer could no longer see who
/// holds the store. Locking a range beyond the end of the file is allowed and
/// excludes just as well.
constexpr DWORD kLockRangeOffset = 0x7FFFFFFFu;

bool is_wide_separator(wchar_t character) noexcept { return character == L'\\' || character == L'/'; }

/// Converts a validated UTF-8 spelling to the wide form. A conversion failure
/// means the spelling is not valid UTF-8, which the spelling checks already
/// refuse; it is reported as PathInvalid rather than assumed away.
Result<std::wstring> to_wide(std::string_view text) {
  if (text.empty()) {
    return std::wstring();
  }
  const int length = static_cast<int>(text.size());
  const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, nullptr, 0);
  if (size <= 0) {
    return Error(ErrorCode::PathInvalid, "the path is not valid UTF-8");
  }
  std::wstring wide(static_cast<std::size_t>(size), L'\0');
  const int written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, wide.data(), size);
  if (written != size) {
    return Error(ErrorCode::PathInvalid, "the path is not valid UTF-8");
  }
  return wide;
}

/// Converts a wide name back to UTF-8. An empty result means the name could
/// not be represented, which every caller treats as a refusal: a listing
/// refuses it as an unusable name and canonicalization re-validates the
/// result.
std::string from_wide(const std::wstring& wide) {
  if (wide.empty()) {
    return std::string();
  }
  const int length = static_cast<int>(wide.size());
  const int size = WideCharToMultiByte(CP_UTF8, 0, wide.data(), length, nullptr, 0, nullptr, nullptr);
  if (size <= 0) {
    return std::string();
  }
  std::string narrow(static_cast<std::size_t>(size), '\0');
  WideCharToMultiByte(CP_UTF8, 0, wide.data(), length, narrow.data(), size, nullptr, nullptr);
  return narrow;
}

/// The absolute, OS-normalized form of a validated absolute spelling. The
/// result still has to be collapsed and re-validated: GetFullPathNameW
/// converts the separators and removes a trailing one for a path below a root,
/// but it does not promise the exact shape this file's canonical form needs.
Result<std::wstring> absolute_wide_spelling(const std::wstring& wide) {
  const DWORD required = GetFullPathNameW(wide.c_str(), 0, nullptr, nullptr);
  if (required == 0) {
    const DWORD error = GetLastError();
    return Error(ErrorCode::PathInvalid, windows_error_text("GetFullPathName", error));
  }
  std::wstring buffer(static_cast<std::size_t>(required), L'\0');
  const DWORD written = GetFullPathNameW(wide.c_str(), required, buffer.data(), nullptr);
  if (written == 0 || written >= required) {
    const DWORD error = GetLastError();
    return Error(ErrorCode::PathInvalid, windows_error_text("GetFullPathName", error));
  }
  buffer.resize(static_cast<std::size_t>(written));
  return buffer;
}

/// Collapses separator runs and drops a trailing separator, leaving the root
/// form "X:\" intact.
void normalize_wide_separators(std::wstring& text) {
  std::wstring collapsed;
  collapsed.reserve(text.size());
  for (const wchar_t character : text) {
    if (is_wide_separator(character)) {
      if (!collapsed.empty() && collapsed.back() == L'\\') {
        continue;
      }
      collapsed.push_back(L'\\');
      continue;
    }
    collapsed.push_back(character);
  }
  if (collapsed.size() > 3 && collapsed.back() == L'\\') {
    collapsed.pop_back();
  }
  text.swap(collapsed);
}

#else

std::string posix_error_text(const char* what, int error) {
  return std::string(what) + " failed with errno=" + std::to_string(error);
}

#endif

}  // namespace

Result<void> validate_path_spelling(std::string_view path) {
  CFM_TRYV(parse_spelling(path, false));
  return ok();
}

Result<PathInfo> inspect_path(const std::string& path) {
  CFM_TRYV(validate_path_spelling(path));
  PathInfo info;
#if defined(_WIN32)
  CFM_TRY(wide, to_wide(path));
  // FindFirstFileW reports the attributes of the entry itself and does not
  // follow the final reparse point, and it still reports an entry whose
  // reparse target does not exist; GetFileAttributesW would report a dangling
  // symbolic link or junction as absent and would hide the very substitution
  // this function exists to detect. The search pattern cannot contain a
  // wildcard here, because the spelling checks refuse one.
  WIN32_FIND_DATAW data{};
  const HANDLE handle = FindFirstFileW(wide.c_str(), &data);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      return info;  // absent, which is not a failure for an inspection
    }
    return Error(ErrorCode::IoError, windows_error_text("FindFirstFile", error)).with_subject(path);
  }
  FindClose(handle);
  info.exists = true;
  info.is_directory = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  info.is_reparse_point = (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
  // A junction has both attributes set: it is marked as a directory and as a
  // reparse point. Callers must refuse a reparse point before they treat an
  // entry as a directory.
  info.is_regular = !info.is_directory && !info.is_reparse_point;
  if (info.is_regular) {
    info.size = (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32) | static_cast<std::uint64_t>(data.nFileSizeLow);
  }
#else
  struct stat status {};
  if (lstat(path.c_str(), &status) != 0) {
    const int error = errno;
    if (error == ENOENT || error == ENOTDIR) {
      return info;
    }
    return Error(ErrorCode::IoError, posix_error_text("lstat", error)).with_subject(path);
  }
  info.exists = true;
  info.is_directory = S_ISDIR(status.st_mode) != 0;
  info.is_reparse_point = S_ISLNK(status.st_mode) != 0;
  info.is_regular = S_ISREG(status.st_mode) != 0;
  if (info.is_regular) {
    info.size = static_cast<std::uint64_t>(status.st_size);
  }
#endif
  return info;
}

Result<void> verify_no_reparse_ancestors(const std::string& path) {
  CFM_TRY(parts, parse_spelling(path, false));
  std::string prefix = parts.root;
  for (const std::string_view component : parts.components) {
    append_path_component(prefix, component);
    CFM_TRY(info, inspect_path(prefix));
    if (!info.exists) {
      // Nothing further down exists, so nothing further down can be
      // substituted, and the caller may create the rest.
      return ok();
    }
    if (info.is_reparse_point) {
      return Error(ErrorCode::PathTraversal,
                   "a path component is a symbolic link, junction, mount point or other reparse point")
          .with_subject(prefix);
    }
    if (!info.is_directory) {
      // The contract assigns PathTraversal to this function: a component that
      // is not a directory cannot be traversed to reach the rest of the path.
      return Error(ErrorCode::PathTraversal, "a path component is not a directory, so the path cannot be traversed")
          .with_subject(prefix);
    }
  }
  return ok();
}

Result<std::string> canonicalize_store_root(std::string_view root) {
  // Redundant and trailing separators are accepted here and normalized below,
  // because this is the entry point that receives an operator-supplied root;
  // every other entry point requires the strict spelling.
  CFM_TRY(parts, parse_spelling(root, true));
  if (parts.root.empty()) {
    // A relative root is refused rather than resolved against the current
    // directory: the current directory is a per-process value, so two
    // processes that name the same logical store would derive two different
    // canonical roots and therefore two different lock files.
    return Error(ErrorCode::PathInvalid,
                 "the store root must be absolute, because a relative root names a different store in every process")
        .with_subject(subject_of(root));
  }
#if defined(_WIN32)
  CFM_TRY(wide, to_wide(root));
  CFM_TRY(absolute, absolute_wide_spelling(wide));
  normalize_wide_separators(absolute);
  const std::string canonical = from_wide(absolute);
  if (canonical.empty()) {
    return Error(ErrorCode::PathInvalid, "the store root could not be represented as UTF-8")
        .with_subject(subject_of(root));
  }
#else
  std::string canonical = parts.root;
  for (const std::string_view component : parts.components) {
    append_path_component(canonical, component);
  }
#endif
  // The normalized result must satisfy the strict rules, and it must still fit
  // the bound: normalization can only shorten this spelling, but the check is
  // made on the value that is actually returned.
  CFM_TRYV(validate_path_spelling(canonical));
  if (canonical.size() > limits::kMaxStorePathBytes) {
    return Error(ErrorCode::PathInvalid, "the canonical store root exceeds the configured byte bound")
        .with_subject(subject_of(canonical))
        .with_detail("bound=" + std::to_string(limits::kMaxStorePathBytes));
  }
  // This also resolves the final component: a root that already exists and is
  // itself a reparse point is refused, so a store can never be opened through
  // a link planted at its own path.
  CFM_TRYV(verify_no_reparse_ancestors(canonical));
  return canonical;
}

Result<bool> path_exists(const std::string& path) {
  CFM_TRY(info, inspect_path(path));
  return info.exists;
}

Result<std::uint64_t> file_size(const std::string& path) {
  CFM_TRYV(validate_path_spelling(path));
  CFM_TRY(info, inspect_path(path));
  if (!info.exists) {
    return Error(ErrorCode::StoreNotFound, "the file does not exist").with_subject(path);
  }
  if (info.is_reparse_point) {
    return Error(ErrorCode::PathTraversal, "the path is a symbolic link, junction or other reparse point")
        .with_subject(path);
  }
  if (!info.is_regular) {
    return Error(ErrorCode::PathNotRegular, "the path is not a regular file").with_subject(path);
  }
  return info.size;
}

Result<void> create_directory(const std::string& path) {
  CFM_TRYV(validate_path_spelling(path));
  CFM_TRY(existing, inspect_path(path));
  if (existing.exists) {
    if (existing.is_reparse_point) {
      return Error(ErrorCode::PathTraversal, "the directory is a symbolic link, junction or other reparse point")
          .with_subject(path);
    }
    if (!existing.is_directory) {
      return Error(ErrorCode::StoreNotEmpty, "a non-directory entry already occupies the directory path")
          .with_subject(path);
    }
    return ok();  // already a directory: creating it is idempotent
  }
#if defined(_WIN32)
  CFM_TRY(wide, to_wide(path));
  if (CreateDirectoryW(wide.c_str(), nullptr) == 0) {
    const DWORD error = GetLastError();
    if (error == ERROR_ALREADY_EXISTS) {
      return ok();  // a concurrent creator won the race and made the directory
    }
    return Error(ErrorCode::IoError, windows_error_text("CreateDirectory", error)).with_subject(path);
  }
#else
  if (mkdir(path.c_str(), 0755) != 0 && errno != EEXIST) {
    const int error = errno;
    return Error(ErrorCode::IoError, posix_error_text("mkdir", error)).with_subject(path);
  }
#endif
  return ok();
}

Result<void> create_directories(const std::string& path) {
  CFM_TRY(parts, parse_spelling(path, false));
  std::string prefix = parts.root;
  for (const std::string_view component : parts.components) {
    append_path_component(prefix, component);
    // create_directory refuses an existing reparse point, so a store root can
    // never be created through a link planted in the middle of the path.
    CFM_TRYV(create_directory(prefix));
  }
  return ok();
}

Result<std::vector<std::string>> list_directory(const std::string& path) {
  CFM_TRYV(validate_path_spelling(path));
  CFM_TRY(info, inspect_path(path));
  if (!info.exists) {
    return Error(ErrorCode::StoreNotFound, "the directory does not exist").with_subject(path);
  }
  if (info.is_reparse_point) {
    return Error(ErrorCode::PathTraversal, "the directory is a symbolic link, junction or other reparse point")
        .with_subject(path);
  }
  if (!info.is_directory) {
    return Error(ErrorCode::PathNotRegular, "the path is not a directory").with_subject(path);
  }
  std::vector<std::string> names;
#if defined(_WIN32)
  CFM_TRY(wide, to_wide(path));
  // The spelling was validated, so it does not end with a separator and the
  // search pattern is exactly this directory and its entries.
  std::wstring pattern = wide;
  pattern.push_back(L'\\');
  pattern.push_back(L'*');
  WIN32_FIND_DATAW data{};
  const HANDLE handle = FindFirstFileW(pattern.c_str(), &data);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      return Error(ErrorCode::StoreNotFound, "the directory disappeared before it could be listed")
          .with_subject(path);
    }
    return Error(ErrorCode::IoError, windows_error_text("FindFirstFile", error)).with_subject(path);
  }
  bool more = true;
  while (more) {
    const std::wstring wide_name(data.cFileName);
    if (wide_name == L"." || wide_name == L"..") {
      // The two dot entries denote the directory itself and its parent, not
      // entries of it, so they are skipped rather than refused.
    } else {
      const std::string name = from_wide(wide_name);
      if (!is_safe_entry_name(name)) {
        FindClose(handle);
        return Error(ErrorCode::PathUnsafeName, "a directory entry name is not usable as a single path component")
            .with_subject(name)
            .with_detail(path);
      }
      names.push_back(name);
    }
    if (FindNextFileW(handle, &data) != 0) {
      continue;
    }
    const DWORD error = GetLastError();
    FindClose(handle);
    if (error != ERROR_NO_MORE_FILES) {
      // A listing that stopped early would silently hide entries, so it is
      // reported instead of returned.
      return Error(ErrorCode::IoError, windows_error_text("FindNextFile", error)).with_subject(path);
    }
    more = false;
  }
#else
  DIR* directory = opendir(path.c_str());
  if (directory == nullptr) {
    const int error = errno;
    if (error == ENOENT || error == ENOTDIR) {
      return Error(ErrorCode::StoreNotFound, "the directory disappeared before it could be listed")
          .with_subject(path);
    }
    return Error(ErrorCode::IoError, posix_error_text("opendir", error)).with_subject(path);
  }
  int readdir_error = 0;
  for (;;) {
    // errno is cleared immediately before each call, because readdir reports
    // the end of the directory and a failure with the same return value.
    errno = 0;
    dirent* entry = readdir(directory);
    if (entry == nullptr) {
      readdir_error = errno;
      break;
    }
    const std::string name(entry->d_name);
    if (name == "." || name == "..") {
      continue;
    }
    if (!is_safe_entry_name(name)) {
      closedir(directory);
      return Error(ErrorCode::PathUnsafeName, "a directory entry name is not usable as a single path component")
          .with_subject(name)
          .with_detail(path);
    }
    names.push_back(name);
  }
  closedir(directory);
  if (readdir_error != 0) {
    return Error(ErrorCode::IoError, posix_error_text("readdir", readdir_error)).with_subject(path);
  }
#endif
  // Byte-wise order is established here and never taken from the file system,
  // whose order is unspecified and differs between platforms.
  std::sort(names.begin(), names.end());
  return names;
}

Result<std::string> read_file(const std::string& path, std::size_t max_bytes) {
  CFM_TRYV(validate_path_spelling(path));
  CFM_TRY(inspected, inspect_path(path));
  if (!inspected.exists) {
    return Error(ErrorCode::StoreNotFound, "the file does not exist").with_subject(path);
  }
  if (inspected.is_reparse_point) {
    return Error(ErrorCode::PathTraversal, "the file is a symbolic link, junction or other reparse point")
        .with_subject(path);
  }
  if (!inspected.is_regular) {
    return Error(ErrorCode::PathNotRegular, "the path is not a regular file").with_subject(path);
  }
  if (inspected.size > max_bytes) {
    // Refused before any buffer is sized from the file system value.
    return Error(ErrorCode::LimitExceeded, "the file is larger than the caller's bound")
        .with_subject(path)
        .with_detail("size=" + std::to_string(inspected.size))
        .with_detail("bound=" + std::to_string(max_bytes));
  }
#if defined(_WIN32)
  CFM_TRY(wide, to_wide(path));
  // One handle for the whole read. FILE_FLAG_OPEN_REPARSE_POINT means a link
  // that replaced the file between the inspection and this open is opened as a
  // link, not followed, and the attribute check below then refuses it.
  const HANDLE handle =
      CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
                  nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      return Error(ErrorCode::StoreNotFound, "the file disappeared before it could be opened").with_subject(path);
    }
    return Error(ErrorCode::IoError, windows_error_text("CreateFile", error)).with_subject(path);
  }
  BY_HANDLE_FILE_INFORMATION handle_info{};
  if (GetFileInformationByHandle(handle, &handle_info) == 0) {
    const DWORD error = GetLastError();
    CloseHandle(handle);
    return Error(ErrorCode::IoError, windows_error_text("GetFileInformationByHandle", error)).with_subject(path);
  }
  if ((handle_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
    CloseHandle(handle);
    return Error(ErrorCode::PathTraversal, "the file became a symbolic link or reparse point before it was opened")
        .with_subject(path);
  }
  if ((handle_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
    CloseHandle(handle);
    return Error(ErrorCode::PathNotRegular, "the path became a directory before it was opened").with_subject(path);
  }
  const std::uint64_t size =
      (static_cast<std::uint64_t>(handle_info.nFileSizeHigh) << 32) | static_cast<std::uint64_t>(handle_info.nFileSizeLow);
  if (size > max_bytes) {
    CloseHandle(handle);
    return Error(ErrorCode::LimitExceeded, "the file grew past the caller's bound before it was read")
        .with_subject(path)
        .with_detail("size=" + std::to_string(size))
        .with_detail("bound=" + std::to_string(max_bytes));
  }
  // The buffer is sized from the length the handle reports and the bound was
  // checked first, so a huge file cannot be allocated blindly.
  std::string content(static_cast<std::size_t>(size), '\0');
  std::size_t total = 0;
  while (total < content.size()) {
    const DWORD request = static_cast<DWORD>(std::min<std::size_t>(content.size() - total, kIoChunkBytes));
    DWORD read = 0;
    if (ReadFile(handle, content.data() + total, request, &read, nullptr) == 0) {
      const DWORD error = GetLastError();
      CloseHandle(handle);
      return Error(ErrorCode::IoError, windows_error_text("ReadFile", error)).with_subject(path);
    }
    if (read == 0) {
      CloseHandle(handle);
      return Error(ErrorCode::IoError, "the file shrank while it was read, so the content is incomplete")
          .with_subject(path);
    }
    total += read;
  }
  char probe_byte = 0;
  DWORD probe = 0;
  if (ReadFile(handle, &probe_byte, 1, &probe, nullptr) == 0) {
    const DWORD error = GetLastError();
    CloseHandle(handle);
    return Error(ErrorCode::IoError, windows_error_text("ReadFile", error)).with_subject(path);
  }
  CloseHandle(handle);
  if (probe != 0) {
    return Error(ErrorCode::IoError, "the file grew while it was read, so the content is not the inspected length")
        .with_subject(path);
  }
  return content;
#else
  const int descriptor = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (descriptor < 0) {
    const int error = errno;
    if (error == ENOENT || error == ENOTDIR) {
      return Error(ErrorCode::StoreNotFound, "the file disappeared before it could be opened").with_subject(path);
    }
    if (error == ELOOP) {
      return Error(ErrorCode::PathTraversal, "the file is a symbolic link").with_subject(path);
    }
    return Error(ErrorCode::IoError, posix_error_text("open", error)).with_subject(path);
  }
  struct stat status {};
  if (fstat(descriptor, &status) != 0) {
    const int error = errno;
    close(descriptor);
    return Error(ErrorCode::IoError, posix_error_text("fstat", error)).with_subject(path);
  }
  if (S_ISLNK(status.st_mode)) {
    close(descriptor);
    return Error(ErrorCode::PathTraversal, "the file became a symbolic link before it was opened").with_subject(path);
  }
  if (!S_ISREG(status.st_mode)) {
    close(descriptor);
    return Error(ErrorCode::PathNotRegular, "the path became a non-regular file before it was opened")
        .with_subject(path);
  }
  const std::uint64_t size = static_cast<std::uint64_t>(status.st_size);
  if (size > max_bytes) {
    close(descriptor);
    return Error(ErrorCode::LimitExceeded, "the file grew past the caller's bound before it was read")
        .with_subject(path)
        .with_detail("size=" + std::to_string(size))
        .with_detail("bound=" + std::to_string(max_bytes));
  }
  std::string content(static_cast<std::size_t>(size), '\0');
  std::size_t total = 0;
  while (total < content.size()) {
    const std::size_t request = std::min<std::size_t>(content.size() - total, kIoChunkBytes);
    const ssize_t read = ::read(descriptor, content.data() + total, request);
    if (read < 0) {
      const int error = errno;
      if (error == EINTR) {
        continue;
      }
      close(descriptor);
      return Error(ErrorCode::IoError, posix_error_text("read", error)).with_subject(path);
    }
    if (read == 0) {
      close(descriptor);
      return Error(ErrorCode::IoError, "the file shrank while it was read, so the content is incomplete")
          .with_subject(path);
    }
    total += static_cast<std::size_t>(read);
  }
  char probe_byte = 0;
  ssize_t probe = 0;
  do {
    probe = ::read(descriptor, &probe_byte, 1);
  } while (probe < 0 && errno == EINTR);
  if (probe < 0) {
    const int error = errno;
    close(descriptor);
    return Error(ErrorCode::IoError, posix_error_text("read", error)).with_subject(path);
  }
  if (probe != 0) {
    close(descriptor);
    return Error(ErrorCode::IoError, "the file grew while it was read, so the content is not the inspected length")
        .with_subject(path);
  }
  close(descriptor);
  return content;
#endif
}

Result<void> write_file(const std::string& path, std::string_view bytes, bool durable) {
  CFM_TRYV(validate_path_spelling(path));
  CFM_TRY(existing, inspect_path(path));
  if (existing.exists) {
    if (existing.is_reparse_point) {
      return Error(ErrorCode::PathTraversal, "the file is a symbolic link, junction or other reparse point")
          .with_subject(path);
    }
    if (!existing.is_regular) {
      return Error(ErrorCode::PathNotRegular, "the path is not a regular file").with_subject(path);
    }
  }
#if defined(_WIN32)
  CFM_TRY(wide, to_wide(path));
  // The share mode keeps a concurrent reader able to open the file. A write is
  // not allowed to become invisible to readers merely because it is happening.
  const HANDLE handle = CreateFileW(wide.c_str(), GENERIC_WRITE | GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    if (error == ERROR_PATH_NOT_FOUND) {
      return Error(ErrorCode::StoreNotFound, "the directory of the file does not exist")
          .with_subject(path)
          .with_detail("a missing directory is not created here; create_directories does that");
    }
    return Error(ErrorCode::IoError, windows_error_text("CreateFile", error)).with_subject(path);
  }
  const char* cursor = bytes.data();
  std::size_t remaining = bytes.size();
  while (remaining > 0) {
    // Chunked only because a single request is a 32-bit length; each request
    // must be satisfied completely, so a short write is never treated as
    // progress and success is never claimed for bytes that did not go out.
    const DWORD request = static_cast<DWORD>(std::min<std::size_t>(remaining, kIoChunkBytes));
    DWORD written = 0;
    if (WriteFile(handle, cursor, request, &written, nullptr) == 0) {
      const DWORD error = GetLastError();
      CloseHandle(handle);
      return Error(ErrorCode::IoError, windows_error_text("WriteFile", error)).with_subject(path);
    }
    if (written != request) {
      CloseHandle(handle);
      return Error(ErrorCode::IoError, "WriteFile wrote fewer bytes than it was given, so the file is incomplete")
          .with_subject(path)
          .with_detail("requested=" + std::to_string(request))
          .with_detail("written=" + std::to_string(written));
    }
    cursor += written;
    remaining -= written;
  }
  if (durable && FlushFileBuffers(handle) == 0) {
    const DWORD error = GetLastError();
    CloseHandle(handle);
    return Error(ErrorCode::IoError, windows_error_text("FlushFileBuffers", error))
        .with_subject(path)
        .with_detail("durability was requested and could not be established");
  }
  CloseHandle(handle);
  return ok();
#else
  const int descriptor = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
  if (descriptor < 0) {
    const int error = errno;
    if (error == ELOOP) {
      return Error(ErrorCode::PathTraversal, "the file is a symbolic link").with_subject(path);
    }
    return Error(ErrorCode::IoError, posix_error_text("open", error)).with_subject(path);
  }
  std::size_t total = 0;
  while (total < bytes.size()) {
    // A POSIX write may legitimately stop at a short count, so the loop keeps
    // making progress; only a failing or non-advancing write is an error.
    const ssize_t written = ::write(descriptor, bytes.data() + total, bytes.size() - total);
    if (written < 0) {
      const int error = errno;
      if (error == EINTR) {
        continue;
      }
      close(descriptor);
      return Error(ErrorCode::IoError, posix_error_text("write", error)).with_subject(path);
    }
    if (written == 0) {
      close(descriptor);
      return Error(ErrorCode::IoError, "write made no progress, so the file is incomplete").with_subject(path);
    }
    total += static_cast<std::size_t>(written);
  }
  if (durable && fsync(descriptor) != 0) {
    const int error = errno;
    close(descriptor);
    return Error(ErrorCode::IoError, posix_error_text("fsync", error))
        .with_subject(path)
        .with_detail("durability was requested and could not be established");
  }
  close(descriptor);
  return ok();
#endif
}

Result<void> atomic_replace(const std::string& target, const std::string& staged, bool durable) {
  CFM_TRYV(validate_path_spelling(target));
  CFM_TRYV(validate_path_spelling(staged));
  if (!same_directory(target, staged)) {
    // A move between directories, and therefore between volumes, is not an
    // atomic replacement; the caller has to stage the file beside its target.
    return Error(ErrorCode::InvalidArgument, "an atomic replacement must stay inside one directory")
        .with_subject(target)
        .with_detail(staged);
  }
  CFM_TRY(staged_info, inspect_path(staged));
  if (!staged_info.exists) {
    return Error(ErrorCode::StoreNotFound, "the staged file does not exist").with_subject(staged);
  }
  if (staged_info.is_reparse_point) {
    return Error(ErrorCode::PathTraversal, "the staged file is a symbolic link, junction or other reparse point")
        .with_subject(staged);
  }
  if (!staged_info.is_regular) {
    return Error(ErrorCode::PathNotRegular, "the staged path is not a regular file").with_subject(staged);
  }
  CFM_TRY(target_info, inspect_path(target));
  if (target_info.exists) {
    if (target_info.is_reparse_point) {
      return Error(ErrorCode::PathTraversal, "the replacement target is a symbolic link, junction or other reparse point")
          .with_subject(target);
    }
    if (!target_info.is_regular) {
      return Error(ErrorCode::PathNotRegular, "the replacement target is not a regular file").with_subject(target);
    }
  }
#if defined(_WIN32)
  CFM_TRY(wide_target, to_wide(target));
  CFM_TRY(wide_staged, to_wide(staged));
  DWORD flags = MOVEFILE_REPLACE_EXISTING;
  if (durable) {
    // MOVEFILE_WRITE_THROUGH is the only ordering primitive Windows offers for
    // a directory entry change; there is no directory fsync to call later.
    flags |= MOVEFILE_WRITE_THROUGH;
  }
  if (MoveFileExW(wide_staged.c_str(), wide_target.c_str(), flags) == 0) {
    const DWORD error = GetLastError();
    return Error(ErrorCode::IoError, windows_error_text("MoveFileEx", error))
        .with_subject(target)
        .with_detail("staged=" + staged);
  }
  return ok();
#else
  if (rename(staged.c_str(), target.c_str()) != 0) {
    const int error = errno;
    return Error(ErrorCode::IoError, posix_error_text("rename", error))
        .with_subject(target)
        .with_detail("staged=" + staged);
  }
  if (durable) {
    CFM_TRYV(flush_directory(parent_directory_of(target), true));
  }
  return ok();
#endif
}

Result<void> rename_within_directory(const std::string& from, const std::string& to, bool durable) {
  CFM_TRYV(validate_path_spelling(from));
  CFM_TRYV(validate_path_spelling(to));
  if (!same_directory(from, to)) {
    return Error(ErrorCode::InvalidArgument, "a rename must stay inside one directory").with_subject(to).with_detail(from);
  }
  CFM_TRY(source_info, inspect_path(from));
  if (!source_info.exists) {
    return Error(ErrorCode::StoreNotFound, "the rename source does not exist").with_subject(from);
  }
  if (source_info.is_reparse_point) {
    return Error(ErrorCode::PathTraversal, "the rename source is a symbolic link, junction or other reparse point")
        .with_subject(from);
  }
  if (!source_info.is_regular) {
    return Error(ErrorCode::PathNotRegular, "the rename source is not a regular file").with_subject(from);
  }
  CFM_TRY(target_info, inspect_path(to));
  if (target_info.exists) {
    if (target_info.is_reparse_point) {
      return Error(ErrorCode::PathTraversal, "the rename target is a symbolic link, junction or other reparse point")
          .with_subject(to);
    }
    if (!target_info.is_regular) {
      return Error(ErrorCode::PathNotRegular, "the rename target is not a regular file").with_subject(to);
    }
  }
#if defined(_WIN32)
  CFM_TRY(wide_from, to_wide(from));
  CFM_TRY(wide_to, to_wide(to));
  DWORD flags = MOVEFILE_REPLACE_EXISTING;
  if (durable) {
    flags |= MOVEFILE_WRITE_THROUGH;
  }
  if (MoveFileExW(wide_from.c_str(), wide_to.c_str(), flags) == 0) {
    const DWORD error = GetLastError();
    return Error(ErrorCode::IoError, windows_error_text("MoveFileEx", error)).with_subject(to).with_detail(from);
  }
  return ok();
#else
  if (rename(from.c_str(), to.c_str()) != 0) {
    const int error = errno;
    return Error(ErrorCode::IoError, posix_error_text("rename", error)).with_subject(to).with_detail(from);
  }
  if (durable) {
    CFM_TRYV(flush_directory(parent_directory_of(to), true));
  }
  return ok();
#endif
}

Result<void> remove_file(const std::string& path) {
  CFM_TRYV(validate_path_spelling(path));
  CFM_TRY(info, inspect_path(path));
  if (!info.exists) {
    return ok();  // cleanup is idempotent: an absent file is already removed
  }
  if (info.is_reparse_point) {
    // Removing a link would remove the link rather than its target, so it is
    // not dangerous by itself; it is still refused because a reparse point
    // inside a store is foreign content, and every other primitive in this
    // file refuses it. Reporting it lets the operator see it.
    return Error(ErrorCode::PathTraversal, "refusing to remove a symbolic link, junction or other reparse point")
        .with_subject(path);
  }
  if (!info.is_regular) {
    return Error(ErrorCode::PathNotRegular, "refusing to remove a non-regular file").with_subject(path);
  }
#if defined(_WIN32)
  CFM_TRY(wide, to_wide(path));
  if (DeleteFileW(wide.c_str()) == 0) {
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      return ok();  // a concurrent removal already succeeded
    }
    return Error(ErrorCode::IoError, windows_error_text("DeleteFile", error)).with_subject(path);
  }
#else
  if (unlink(path.c_str()) != 0) {
    const int error = errno;
    if (error != ENOENT) {
      return Error(ErrorCode::IoError, posix_error_text("unlink", error)).with_subject(path);
    }
  }
#endif
  return ok();
}

Result<void> remove_directory_if_empty(const std::string& path) {
  CFM_TRYV(validate_path_spelling(path));
  CFM_TRY(info, inspect_path(path));
  if (!info.exists) {
    return ok();  // cleanup is idempotent: an absent directory is already removed
  }
  if (info.is_reparse_point) {
    return Error(ErrorCode::PathTraversal, "the directory is a symbolic link, junction or other reparse point")
        .with_subject(path);
  }
  if (!info.is_directory) {
    return Error(ErrorCode::PathNotRegular, "the path is not a directory").with_subject(path);
  }
#if defined(_WIN32)
  CFM_TRY(wide, to_wide(path));
  if (RemoveDirectoryW(wide.c_str()) == 0) {
    const DWORD error = GetLastError();
    if (error == ERROR_DIR_NOT_EMPTY) {
      return Error(ErrorCode::StoreNotEmpty, "the directory is not empty").with_subject(path);
    }
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      return ok();  // a concurrent removal already succeeded
    }
    return Error(ErrorCode::IoError, windows_error_text("RemoveDirectory", error)).with_subject(path);
  }
#else
  if (rmdir(path.c_str()) != 0) {
    const int error = errno;
    if (error == ENOTEMPTY || error == EEXIST) {
      return Error(ErrorCode::StoreNotEmpty, "the directory is not empty").with_subject(path);
    }
    if (error != ENOENT) {
      return Error(ErrorCode::IoError, posix_error_text("rmdir", error)).with_subject(path);
    }
  }
#endif
  return ok();
}

Result<void> flush_directory(const std::string& path, bool durable) {
  if (!durable) {
    return ok();  // nothing was asked to be ordered, so nothing is claimed
  }
  CFM_TRYV(validate_path_spelling(path));
#if defined(_WIN32)
  // Windows has no directory fsync primitive, and inventing one by opening the
  // directory would establish nothing. The ordering of a directory entry
  // change is requested where the change is made, with MOVEFILE_WRITE_THROUGH
  // in atomic_replace, or with FlushFileBuffers on the file itself in
  // write_file. This call therefore reports success without touching the file
  // system, and the store documents that a Windows directory entry is ordered
  // only to the extent the replacement call ordered it.
  (void)path;
  return ok();
#else
  const int descriptor = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (descriptor < 0) {
    const int error = errno;
    if (error == ENOENT || error == ENOTDIR) {
      return Error(ErrorCode::StoreNotFound, "the directory does not exist").with_subject(path);
    }
    return Error(ErrorCode::IoError, posix_error_text("open", error)).with_subject(path);
  }
  const int result = fsync(descriptor);
  const int error = errno;
  close(descriptor);
  if (result != 0) {
    return Error(ErrorCode::IoError, posix_error_text("fsync", error))
        .with_subject(path)
        .with_detail("durability was requested and could not be established");
  }
  return ok();
#endif
}

namespace {

/// Removes the contents of one directory, descending into real subdirectories,
/// and returns the number of regular files removed. Any reparse point below
/// the directory refuses the whole call.
Result<std::uint64_t> remove_contents_of(const std::string& directory, std::uint64_t depth) {
  if (depth > kMaxRemovalDepth) {
    return Error(ErrorCode::LimitExceeded, "the directory tree is deeper than a store tree can be")
        .with_subject(directory)
        .with_detail("bound=" + std::to_string(kMaxRemovalDepth));
  }
  CFM_TRY(names, list_directory(directory));
  std::uint64_t removed = 0;
  for (const std::string& name : names) {
    std::string entry = directory;
    append_path_component(entry, name);
    CFM_TRY(info, inspect_path(entry));
    if (info.is_reparse_point) {
      return Error(ErrorCode::PathTraversal,
                   "a store entry is a symbolic link, junction or other reparse point, so nothing below it is removed")
          .with_subject(entry);
    }
    if (info.is_directory) {
      CFM_TRY(nested, remove_contents_of(entry, depth + 1));
      removed += nested;
      CFM_TRYV(remove_directory_if_empty(entry));
      continue;
    }
    if (!info.is_regular) {
      return Error(ErrorCode::PathNotRegular, "a store entry is neither a regular file nor a directory")
          .with_subject(entry);
    }
    CFM_TRYV(remove_file(entry));
    ++removed;
  }
  return removed;
}

}  // namespace

Result<std::uint64_t> remove_directory_contents(const std::string& path, bool remove_directory) {
  CFM_TRYV(validate_path_spelling(path));
  CFM_TRY(info, inspect_path(path));
  if (!info.exists) {
    // Idempotent cleanup: there is nothing left to remove, so nothing failed.
    return std::uint64_t{0};
  }
  if (info.is_reparse_point) {
    return Error(ErrorCode::PathTraversal, "the directory is a symbolic link, junction or other reparse point")
        .with_subject(path);
  }
  if (!info.is_directory) {
    return Error(ErrorCode::PathNotRegular, "the path is not a directory").with_subject(path);
  }
  // A reparse point anywhere below refuses the whole call instead of being
  // skipped: skipping would leave entries behind that the caller believes
  // removed, and following one would let a link redirect a removal outside the
  // store. Refusing keeps the count that is returned exact.
  CFM_TRY(removed, remove_contents_of(path, 0));
  if (remove_directory) {
    CFM_TRYV(remove_directory_if_empty(path));
  }
  return removed;
}

// ---------------------------------------------------------------------------
// FileLock
// ---------------------------------------------------------------------------
//
// Exclusion is established by the kernel lock, never by the share mode or by
// an exclusive open: a read-only observer has to be able to open the lock file
// to read the owner text while a writer holds the lock.
//
// Re-entry: acquire() is a static function and always constructs a fresh,
// unheld lock, so there is no way to re-acquire on a held object through this
// interface, and nothing to deadlock on. The one reachable re-entry shape is
// assigning the result of acquire() onto an existing FileLock: move assignment
// releases the lock that object already held before it adopts the new one, so
// no handle is leaked. A second lock taken on the same file by this process
// through a second FileLock object, or by another process, fails immediately
// with StoreLocked (LOCKFILE_FAIL_IMMEDIATELY on Windows, LOCK_NB on POSIX)
// rather than blocking, and the failed attempt closes the handle or descriptor
// it opened before returning, so no lock is leaked by the failure.
//
// If the interface ever grew a member acquire that found the object already
// holding a lock, the correct answer would be ErrorCode::InternalError: the
// caller would have asked for two locks through one object, which the class
// cannot represent. No such path exists today.

#if defined(_WIN32)

FileLock::~FileLock() { (void)release(); }

FileLock::FileLock(FileLock&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }

FileLock& FileLock::operator=(FileLock&& other) noexcept {
  if (this != &other) {
    (void)release();
    handle_ = other.handle_;
    other.handle_ = nullptr;
  }
  return *this;
}

Result<FileLock> FileLock::acquire(const std::string& path, std::string_view owner_text) {
  CFM_TRYV(validate_path_spelling(path));
  const std::string owner = sanitize_owner_text(owner_text);
  CFM_TRY(existing, inspect_path(path));
  if (existing.exists) {
    if (existing.is_reparse_point) {
      return Error(ErrorCode::PathTraversal, "the lock file is a symbolic link, junction or other reparse point")
          .with_subject(path);
    }
    if (!existing.is_regular) {
      return Error(ErrorCode::PathNotRegular, "the lock path is not a regular file").with_subject(path);
    }
  }
  CFM_TRY(wide, to_wide(path));
  // No sharing attribute is passed, so the handle is not inheritable and a
  // child process cannot inherit the held lock. The share mode admits readers
  // and writers; the byte-range lock below is what excludes.
  const HANDLE handle = CreateFileW(wide.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                                    nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      return Error(ErrorCode::StoreNotFound, "the lock file could not be created because its directory is missing")
          .with_subject(path);
    }
    return Error(ErrorCode::IoError, windows_error_text("CreateFile", error)).with_subject(path);
  }
  OVERLAPPED overlapped{};
  overlapped.Offset = kLockRangeOffset;
  if (LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped) == 0) {
    const DWORD error = GetLastError();
    CloseHandle(handle);
    if (error == ERROR_LOCK_VIOLATION) {
      return Error(ErrorCode::StoreLocked, "another live holder owns the store lock").with_subject(path);
    }
    return Error(ErrorCode::IoError, windows_error_text("LockFileEx", error)).with_subject(path);
  }
  FileLock lock;
  lock.handle_ = handle;
  // The owner text is written after the lock is taken, so the content of the
  // file always belongs to the holder, and it is truncated first so that a
  // longer previous text cannot be mistaken for this holder's.
  LARGE_INTEGER origin{};
  if (SetFilePointerEx(handle, origin, nullptr, FILE_BEGIN) == 0 || SetEndOfFile(handle) == 0) {
    const DWORD error = GetLastError();
    CloseHandle(handle);  // releases the kernel lock
    lock.handle_ = nullptr;
    return Error(ErrorCode::IoError, windows_error_text("truncating the lock file", error))
        .with_subject(path)
        .with_detail("the lock was released because the owner text could not be written");
  }
  if (!owner.empty()) {
    DWORD written = 0;
    if (WriteFile(handle, owner.data(), static_cast<DWORD>(owner.size()), &written, nullptr) == 0) {
      const DWORD error = GetLastError();
      CloseHandle(handle);
      return Error(ErrorCode::IoError, windows_error_text("writing the lock owner text", error))
          .with_subject(path)
          .with_detail("the lock was released because the owner text could not be written");
    }
    if (written != owner.size()) {
      CloseHandle(handle);
      return Error(ErrorCode::IoError, "the lock owner text was written only in part")
          .with_subject(path)
          .with_detail("the lock was released because the owner text could not be written");
    }
  }
  if (FlushFileBuffers(handle) == 0) {
    const DWORD error = GetLastError();
    CloseHandle(handle);
    return Error(ErrorCode::IoError, windows_error_text("FlushFileBuffers on the lock file", error))
        .with_subject(path)
        .with_detail("the lock was released because the owner text could not be established");
  }
  return lock;
}

Result<void> FileLock::release() {
  if (handle_ == nullptr) {
    return ok();  // already released, which is not an error
  }
  const HANDLE handle = static_cast<HANDLE>(handle_);
  OVERLAPPED overlapped{};
  overlapped.Offset = kLockRangeOffset;
  const BOOL unlocked = UnlockFileEx(handle, 0, 1, 0, &overlapped);
  const DWORD error = GetLastError();
  // The handle is closed either way, and closing it releases the lock even if
  // the explicit unlock failed, so a failure here can never leave the lock
  // held by this process.
  CloseHandle(handle);
  handle_ = nullptr;
  if (unlocked == 0 && error != ERROR_NOT_LOCKED) {
    return Error(ErrorCode::IoError, windows_error_text("UnlockFileEx", error));
  }
  return ok();
}

bool FileLock::held() const noexcept { return handle_ != nullptr; }

#else

FileLock::~FileLock() { (void)release(); }

FileLock::FileLock(FileLock&& other) noexcept : descriptor_(other.descriptor_) { other.descriptor_ = -1; }

FileLock& FileLock::operator=(FileLock&& other) noexcept {
  if (this != &other) {
    (void)release();
    descriptor_ = other.descriptor_;
    other.descriptor_ = -1;
  }
  return *this;
}

Result<FileLock> FileLock::acquire(const std::string& path, std::string_view owner_text) {
  CFM_TRYV(validate_path_spelling(path));
  const std::string owner = sanitize_owner_text(owner_text);
  CFM_TRY(existing, inspect_path(path));
  if (existing.exists) {
    if (existing.is_reparse_point) {
      return Error(ErrorCode::PathTraversal, "the lock file is a symbolic link or other reparse point")
          .with_subject(path);
    }
    if (!existing.is_regular) {
      return Error(ErrorCode::PathNotRegular, "the lock path is not a regular file").with_subject(path);
    }
  }
  // O_CLOEXEC keeps a child process from inheriting the held lock, which would
  // otherwise outlive the parent that took it.
  const int descriptor = open(path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (descriptor < 0) {
    const int error = errno;
    if (error == ENOENT || error == ENOTDIR) {
      return Error(ErrorCode::StoreNotFound, "the lock file could not be created because its directory is missing")
          .with_subject(path);
    }
    if (error == ELOOP) {
      return Error(ErrorCode::PathTraversal, "the lock file is a symbolic link").with_subject(path);
    }
    return Error(ErrorCode::IoError, posix_error_text("open", error)).with_subject(path);
  }
  if (flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
    const int error = errno;
    close(descriptor);
    if (error == EWOULDBLOCK || error == EAGAIN) {
      return Error(ErrorCode::StoreLocked, "another live holder owns the store lock").with_subject(path);
    }
    return Error(ErrorCode::IoError, posix_error_text("flock", error)).with_subject(path);
  }
  FileLock lock;
  lock.descriptor_ = descriptor;
  if (ftruncate(descriptor, 0) != 0) {
    const int error = errno;
    close(descriptor);  // releases the lock
    return Error(ErrorCode::IoError, posix_error_text("truncating the lock file", error))
        .with_subject(path)
        .with_detail("the lock was released because the owner text could not be written");
  }
  std::size_t written_total = 0;
  while (written_total < owner.size()) {
    const ssize_t written = pwrite(descriptor, owner.data() + written_total, owner.size() - written_total,
                                   static_cast<off_t>(written_total));
    if (written < 0) {
      const int error = errno;
      if (error == EINTR) {
        continue;
      }
      close(descriptor);
      return Error(ErrorCode::IoError, posix_error_text("writing the lock owner text", error))
          .with_subject(path)
          .with_detail("the lock was released because the owner text could not be written");
    }
    if (written == 0) {
      close(descriptor);
      return Error(ErrorCode::IoError, "writing the lock owner text made no progress")
          .with_subject(path)
          .with_detail("the lock was released because the owner text could not be written");
    }
    written_total += static_cast<std::size_t>(written);
  }
  if (fsync(descriptor) != 0) {
    const int error = errno;
    close(descriptor);
    return Error(ErrorCode::IoError, posix_error_text("fsync on the lock file", error))
        .with_subject(path)
        .with_detail("the lock was released because the owner text could not be established");
  }
  return lock;
}

Result<void> FileLock::release() {
  if (descriptor_ < 0) {
    return ok();  // already released, which is not an error
  }
  int unlocked = 0;
  do {
    unlocked = flock(descriptor_, LOCK_UN);
  } while (unlocked != 0 && errno == EINTR);
  const int error = errno;
  // The descriptor is closed either way, and closing it releases the lock even
  // if the explicit unlock failed.
  close(descriptor_);
  descriptor_ = -1;
  if (unlocked != 0) {
    return Error(ErrorCode::IoError, posix_error_text("flock(LOCK_UN)", error));
  }
  return ok();
}

bool FileLock::held() const noexcept { return descriptor_ >= 0; }

#endif

void terminate_process_now(int code) {
#if defined(_WIN32)
  // TerminateProcess is immediate and non-interactive: it cannot raise a
  // Windows Error Reporting dialog, unlike the CRT abort path, which can
  // present one and block a test or a supervisor.
  (void)TerminateProcess(GetCurrentProcess(), static_cast<UINT>(code));
  // Reached only if termination did not happen; ExitProcess still avoids the
  // CRT teardown path.
  (void)ExitProcess(static_cast<UINT>(code));
#else
  _exit(code);
#endif
}

std::string fault_stage_name() {
#if defined(_WIN32)
  DWORD required = GetEnvironmentVariableA(kFaultStageVariable, nullptr, 0);
  for (int attempt = 0; attempt < 4 && required > 0; ++attempt) {
    std::string value(static_cast<std::size_t>(required), '\0');
    const DWORD written = GetEnvironmentVariableA(kFaultStageVariable, value.data(), required);
    if (written == 0) {
      return std::string();  // unset, or emptied between the two calls
    }
    if (written < required) {
      value.resize(static_cast<std::size_t>(written));
      return value;
    }
    // The variable grew between the two calls; re-read it with the larger size
    // rather than returning a truncated selector, which could name a stage the
    // caller never asked for.
    required = written;
  }
  return std::string();
#else
  const char* const raw = std::getenv(kFaultStageVariable);
  return raw == nullptr ? std::string() : std::string(raw);
#endif
}

bool fault_selected(bool enabled, const char* stage) {
  if (!enabled || stage == nullptr || *stage == '\0') {
    return false;
  }
  const std::string selector = fault_stage_name();
  if (selector.empty()) {
    return false;
  }
  std::string_view wanted(selector);
  bool has_occurrence = false;
  std::uint64_t occurrence = 1;
  const std::size_t hash = selector.find('#');
  if (hash != std::string::npos) {
    wanted = std::string_view(selector).substr(0, hash);
    const std::string_view digits = std::string_view(selector).substr(hash + 1);
    if (digits.empty()) {
      return false;  // a malformed selector never terminates a process
    }
    std::uint64_t value = 0;
    for (const char character : digits) {
      if (character < '0' || character > '9') {
        return false;
      }
      const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
      if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10u) {
        return false;  // an unrepresentable occurrence cannot be matched
      }
      value = value * 10u + digit;
    }
    if (value == 0) {
      return false;  // occurrences are counted from one
    }
    occurrence = value;
    has_occurrence = true;
  }
  if (wanted != std::string_view("any") && wanted != std::string_view(stage)) {
    return false;
  }
  // Counting is per stage and process local. It advances only for a stage the
  // selector names, so the same program with the same selector fires at the
  // same occurrence every run.
  static std::mutex counter_mutex;
  static std::map<std::string, std::uint64_t> counters;
  const std::lock_guard<std::mutex> guard(counter_mutex);
  const std::uint64_t seen = ++counters[std::string(stage)];
  if (!has_occurrence) {
    return true;  // a bare stage name fires on every occurrence of that stage
  }
  return seen == occurrence;
}

void fault_point(bool enabled, const char* stage) {
  if (fault_selected(enabled, stage)) {
    terminate_process_now(kFaultTerminationCode);
  }
}

}  // namespace dccp::cooling_failure_manager::internal
