// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "child_process.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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
#include <csignal>
#include <cstdlib>
#include <cwchar>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace ct_test {
namespace {

/// Environment entries that select a child role. The values are plain UTF-8
/// text; an argument may be empty but must not contain a NUL.
constexpr const char* kChildRoleName = "COOLING_FAILURE_MANAGER_TEST_CHILD_ROLE";
constexpr const char* kChildArgumentPrefix = "COOLING_FAILURE_MANAGER_TEST_CHILD_ARG_";

/// Bound on the number of arguments a role may be given, so that neither the
/// launcher nor the child searches an unbounded environment.
constexpr std::size_t kMaxChildArguments = 16;

#if defined(_WIN32)

Result<std::wstring> to_wide(const std::string& text) {
  if (text.empty()) {
    return std::wstring();
  }
  const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                                       nullptr, 0);
  if (size <= 0) {
    return Error(ErrorCode::InvalidUtf8, "child-process text is not valid UTF-8").with_subject(text.substr(0, 64));
  }
  std::wstring wide(static_cast<std::size_t>(size), L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), wide.data(), size);
  return wide;
}

std::string from_wide(const std::wstring& wide) {
  if (wide.empty()) {
    return std::string();
  }
  const int size = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr,
                                       nullptr);
  if (size <= 0) {
    return std::string();
  }
  std::string narrow(static_cast<std::size_t>(size), '\0');
  WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), narrow.data(), size, nullptr, nullptr);
  return narrow;
}

/// Quotes one argument for a CreateProcessW command line using the rules the C
/// runtime parses: backslashes are doubled before a quote and quotes escaped.
std::wstring quote_argument(const std::wstring& argument) {
  const bool needs_quotes = argument.empty() || argument.find(L' ') != std::wstring::npos ||
                            argument.find(L'\t') != std::wstring::npos ||
                            argument.find(L'"') != std::wstring::npos;
  if (!needs_quotes) {
    return argument;
  }
  std::wstring out;
  out.push_back(L'"');
  std::size_t backslashes = 0;
  for (const wchar_t character : argument) {
    if (character == L'\\') {
      ++backslashes;
      continue;
    }
    if (character == L'"') {
      out.append(backslashes * 2 + 1, L'\\');
      backslashes = 0;
      out.push_back(L'"');
      continue;
    }
    out.append(backslashes, L'\\');
    backslashes = 0;
    out.push_back(character);
  }
  out.append(backslashes * 2, L'\\');
  out.push_back(L'"');
  return out;
}

/// True when this block entry defines exactly this variable name. Entries that
/// begin with '=' are the hidden per-drive variables and never match.
bool entry_defines(const wchar_t* entry, const std::wstring& name) {
  if (entry[0] == L'=') {
    return false;
  }
  const wchar_t* equals = std::wcschr(entry, L'=');
  if (equals == nullptr || equals == entry) {
    return false;
  }
  const int length = static_cast<int>(equals - entry);
  if (static_cast<std::size_t>(length) != name.size()) {
    return false;
  }
  return CompareStringOrdinal(entry, length, name.c_str(), length, TRUE) == CSTR_EQUAL;
}

/// Reads one environment entry of this process. Returns false when the entry is
/// not defined at all, which is distinct from an entry defined as empty.
bool environment_value(const std::string& name, std::string* value) {
  const Result<std::wstring> wide_name = to_wide(name);
  if (!wide_name.has_value()) {
    return false;
  }
  SetLastError(ERROR_SUCCESS);
  const DWORD required = GetEnvironmentVariableW(wide_name.value().c_str(), nullptr, 0);
  if (required == 0) {
    if (GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
      return false;
    }
    value->clear();
    return true;
  }
  std::wstring buffer(static_cast<std::size_t>(required) + 1, L'\0');
  const DWORD written =
      GetEnvironmentVariableW(wide_name.value().c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
  if (written == 0 || static_cast<std::size_t>(written) >= buffer.size()) {
    return false;
  }
  buffer.resize(static_cast<std::size_t>(written));
  *value = from_wide(buffer);
  return true;
}

/// Builds the environment block of a child: every entry of this process except
/// the ones the caller overrides, then the overriding entries in the order they
/// were given. A name that appears twice keeps its first value, which is the
/// entry a lookup in the child resolves.
Result<std::wstring> build_environment_block(const std::vector<std::pair<std::string, std::string>>& extra) {
  std::vector<std::wstring> names;
  std::vector<std::wstring> entries;
  names.reserve(extra.size());
  entries.reserve(extra.size());
  for (const auto& entry : extra) {
    const Result<std::wstring> wide_name = to_wide(entry.first);
    if (!wide_name.has_value()) {
      return wide_name.error();
    }
    const Result<std::wstring> wide_value = to_wide(entry.second);
    if (!wide_value.has_value()) {
      return wide_value.error();
    }
    bool duplicate = false;
    for (const std::wstring& seen : names) {
      if (seen == wide_name.value()) {
        duplicate = true;
        break;
      }
    }
    if (duplicate) {
      continue;
    }
    names.push_back(wide_name.value());
    entries.push_back(wide_name.value() + L"=" + wide_value.value());
  }

  std::wstring block;
  LPWCH parent = GetEnvironmentStringsW();
  if (parent != nullptr) {
    for (const wchar_t* entry = parent; *entry != L'\0'; entry += std::wcslen(entry) + 1) {
      bool overridden = false;
      for (const std::wstring& name : names) {
        if (entry_defines(entry, name)) {
          overridden = true;
          break;
        }
      }
      if (overridden) {
        continue;
      }
      block.append(entry);
      block.push_back(L'\0');
    }
    FreeEnvironmentStringsW(parent);
  }
  for (const std::wstring& entry : entries) {
    block.append(entry);
    block.push_back(L'\0');
  }
  block.push_back(L'\0');
  return block;
}

#else

bool environment_value(const std::string& name, std::string* value) {
  const char* raw = std::getenv(name.c_str());
  if (raw == nullptr) {
    return false;
  }
  *value = raw;
  return true;
}

#endif

}  // namespace

// Windows uses a raw HANDLE pair; POSIX uses a descriptor plus a pid. The
// struct is defined once per platform so the header stays free of OS types.
struct ChildProcess::Impl {
#if defined(_WIN32)
  HANDLE process = nullptr;
  HANDLE thread = nullptr;
  HANDLE read_pipe = nullptr;
  unsigned long pid = 0;
  bool reaped = false;
  bool terminated = false;
  int exit_code = 0;
  std::string buffer;
#else
  int pid = 0;
  int read_descriptor = -1;
  bool reaped = false;
  bool terminated = false;
  int exit_code = 0;
  std::string buffer;
#endif
};

ChildProcess::ChildProcess() noexcept = default;

ChildProcess::~ChildProcess() {
  if (impl_ != nullptr) {
    if (running()) {
      (void)terminate();
      (void)collect();
    }
    delete impl_;
    impl_ = nullptr;
  }
}

ChildProcess::ChildProcess(ChildProcess&& other) noexcept : impl_(other.impl_) { other.impl_ = nullptr; }

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    this->~ChildProcess();
    impl_ = other.impl_;
    other.impl_ = nullptr;
  }
  return *this;
}

#if defined(_WIN32)

Result<ChildProcess> ChildProcess::spawn(const std::vector<std::string>& argv, const std::string& working_directory,
                                         const std::vector<std::pair<std::string, std::string>>& extra_environment) {
  if (argv.empty()) {
    return Error(ErrorCode::InvalidArgument, "spawn requires an executable path");
  }
  std::wstring command_line;
  for (std::size_t index = 0; index < argv.size(); ++index) {
    const Result<std::wstring> wide = to_wide(argv[index]);
    if (!wide.has_value()) {
      return wide.error();
    }
    if (index != 0) {
      command_line.push_back(L' ');
    }
    command_line.append(quote_argument(wide.value()));
  }

  // lpEnvironment is LPVOID rather than LPCWSTR in the platform interface, so
  // the block is handed over through a mutable pointer.
  std::wstring environment_storage;
  void* environment_pointer = nullptr;
  if (!extra_environment.empty()) {
    const Result<std::wstring> block = build_environment_block(extra_environment);
    if (!block.has_value()) {
      return block.error();
    }
    environment_storage = block.value();
    environment_pointer = environment_storage.data();
  }

  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;
  HANDLE read_pipe = nullptr;
  HANDLE write_pipe = nullptr;
  if (CreatePipe(&read_pipe, &write_pipe, &attributes, 0) == 0) {
    return Error(ErrorCode::IoError, "CreatePipe failed with GetLastError=" + std::to_string(GetLastError()));
  }
  SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = write_pipe;
  startup.hStdError = write_pipe;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  PROCESS_INFORMATION process_info{};

  std::wstring mutable_command = command_line;
  std::wstring mutable_directory;
  const wchar_t* directory_pointer = nullptr;
  if (!working_directory.empty()) {
    const Result<std::wstring> wide_directory = to_wide(working_directory);
    if (!wide_directory.has_value()) {
      CloseHandle(read_pipe);
      CloseHandle(write_pipe);
      return wide_directory.error();
    }
    mutable_directory = wide_directory.value();
    directory_pointer = mutable_directory.c_str();
  }
  const DWORD flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
  const BOOL created = CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, TRUE, flags,
                                      environment_pointer, directory_pointer, &startup, &process_info);
  if (created == 0) {
    const DWORD error = GetLastError();
    CloseHandle(read_pipe);
    CloseHandle(write_pipe);
    return Error(ErrorCode::IoError, "CreateProcess failed with GetLastError=" + std::to_string(error))
        .with_subject(argv.front());
  }
  CloseHandle(write_pipe);  // the child owns its own copy

  ChildProcess child;
  child.impl_ = new Impl();
  child.impl_->process = process_info.hProcess;
  child.impl_->thread = process_info.hThread;
  child.impl_->read_pipe = read_pipe;
  child.impl_->pid = process_info.dwProcessId;
  return child;
}

Result<int> ChildProcess::wait() {
  if (impl_ == nullptr) {
    return Error(ErrorCode::InvalidArgument, "no child process");
  }
  if (!impl_->reaped) {
    const DWORD status = WaitForSingleObject(impl_->process, INFINITE);
    if (status == WAIT_FAILED) {
      return Error(ErrorCode::IoError,
                   "WaitForSingleObject failed with GetLastError=" + std::to_string(GetLastError()));
    }
    DWORD exit_code = 0;
    if (GetExitCodeProcess(impl_->process, &exit_code) == 0) {
      return Error(ErrorCode::IoError,
                   "GetExitCodeProcess failed with GetLastError=" + std::to_string(GetLastError()));
    }
    impl_->exit_code = static_cast<int>(exit_code);
    impl_->reaped = true;
    if (impl_->thread != nullptr) {
      CloseHandle(impl_->thread);
      impl_->thread = nullptr;
    }
  }
  return impl_->exit_code;
}

Result<void> ChildProcess::terminate() {
  if (impl_ == nullptr) {
    return Error(ErrorCode::InvalidArgument, "no child process");
  }
  if (impl_->reaped) {
    return dccp::cooling_failure_manager::ok();
  }
  impl_->terminated = true;
  // TerminateProcess is immediate and never routes through the CRT abort path,
  // so it can never raise a Windows Error Reporting dialog.
  if (TerminateProcess(impl_->process, 97) == 0) {
    const DWORD error = GetLastError();
    if (error != ERROR_ACCESS_DENIED) {  // already gone
      return Error(ErrorCode::IoError, "TerminateProcess failed with GetLastError=" + std::to_string(error));
    }
  }
  return dccp::cooling_failure_manager::ok();
}

std::string ChildProcess::read_output() {
  if (impl_ == nullptr || impl_->read_pipe == nullptr) {
    return std::string();
  }
  std::string fresh;
  for (;;) {
    DWORD available = 0;
    if (PeekNamedPipe(impl_->read_pipe, nullptr, 0, nullptr, &available, nullptr) == 0 || available == 0) {
      break;
    }
    char buffer[4096];
    const DWORD request = available < sizeof(buffer) ? available : static_cast<DWORD>(sizeof(buffer));
    DWORD read = 0;
    if (ReadFile(impl_->read_pipe, buffer, request, &read, nullptr) == 0 || read == 0) {
      break;
    }
    fresh.append(buffer, static_cast<std::size_t>(read));
  }
  impl_->buffer.append(fresh);
  return fresh;
}

ChildResult ChildProcess::collect(bool force_terminate) {
  ChildResult result;
  if (impl_ == nullptr) {
    return result;
  }
  if (force_terminate && !impl_->reaped) {
    (void)terminate();
  }
  // Drain while the child runs, so a child whose answer is larger than the pipe
  // buffer can never block on a full pipe while this process blocks in wait():
  // that combination is a deadlock, and neither side is clock-bounded here.
  // The loop is bounded by the child's own termination, never by a deadline.
  while (!impl_->reaped) {
    (void)read_output();
    if (WaitForSingleObject(impl_->process, 0) == WAIT_OBJECT_0) {
      break;
    }
    Sleep(1);
  }
  (void)read_output();
  const Result<int> status = wait();
  if (status.has_value()) {
    result.exit_code = status.value();
    result.exited = true;
  }
  (void)read_output();
  result.terminated = impl_->terminated;
  result.output = impl_->buffer;
  return result;
}

bool ChildProcess::running() const noexcept { return impl_ != nullptr && !impl_->reaped; }

bool ChildProcess::has_exited() {
  if (impl_ == nullptr || impl_->reaped) {
    return true;
  }
  if (WaitForSingleObject(impl_->process, 0) != WAIT_OBJECT_0) {
    return false;
  }
  return wait().has_value();
}

unsigned long ChildProcess::process_id() const noexcept { return impl_ == nullptr ? 0 : impl_->pid; }

std::string current_executable_path() {
  std::wstring buffer(512, L'\0');
  for (;;) {
    const DWORD written = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (written == 0) {
      return std::string();
    }
    if (static_cast<std::size_t>(written) < buffer.size()) {
      buffer.resize(static_cast<std::size_t>(written));
      break;
    }
    buffer.resize(buffer.size() * 2);
  }
  return from_wide(buffer);
}

#else  // POSIX branch: structurally complete, unverified on this host.

Result<ChildProcess> ChildProcess::spawn(const std::vector<std::string>& argv, const std::string& working_directory,
                                         const std::vector<std::pair<std::string, std::string>>& extra_environment) {
  if (argv.empty()) {
    return Error(ErrorCode::InvalidArgument, "spawn requires an executable path");
  }
  int pipes[2] = {-1, -1};
  if (pipe(pipes) != 0) {
    return Error(ErrorCode::IoError, "pipe failed with errno=" + std::to_string(errno));
  }
  const pid_t pid = fork();
  if (pid < 0) {
    close(pipes[0]);
    close(pipes[1]);
    return Error(ErrorCode::IoError, "fork failed with errno=" + std::to_string(errno));
  }
  if (pid == 0) {
    close(pipes[0]);
    dup2(pipes[1], STDOUT_FILENO);
    dup2(pipes[1], STDERR_FILENO);
    close(pipes[1]);
    for (const auto& entry : extra_environment) {
      (void)setenv(entry.first.c_str(), entry.second.c_str(), 1);
    }
    if (!working_directory.empty() && chdir(working_directory.c_str()) != 0) {
      _exit(126);
    }
    std::vector<char*> raw;
    raw.reserve(argv.size() + 1);
    for (const std::string& argument : argv) {
      raw.push_back(const_cast<char*>(argument.c_str()));
    }
    raw.push_back(nullptr);
    execv(raw[0], raw.data());
    _exit(127);
  }
  close(pipes[1]);
  ChildProcess child;
  child.impl_ = new Impl();
  child.impl_->pid = static_cast<int>(pid);
  child.impl_->read_descriptor = pipes[0];
  return child;
}

Result<int> ChildProcess::wait() {
  if (impl_ == nullptr) {
    return Error(ErrorCode::InvalidArgument, "no child process");
  }
  if (!impl_->reaped) {
    int status = 0;
    if (waitpid(impl_->pid, &status, 0) < 0) {
      return Error(ErrorCode::IoError, "waitpid failed with errno=" + std::to_string(errno));
    }
    impl_->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    impl_->reaped = true;
  }
  return impl_->exit_code;
}

Result<void> ChildProcess::terminate() {
  if (impl_ == nullptr) {
    return Error(ErrorCode::InvalidArgument, "no child process");
  }
  if (impl_->reaped) {
    return dccp::cooling_failure_manager::ok();
  }
  impl_->terminated = true;
  if (kill(impl_->pid, SIGKILL) != 0 && errno != ESRCH) {
    return Error(ErrorCode::IoError, "kill failed with errno=" + std::to_string(errno));
  }
  return dccp::cooling_failure_manager::ok();
}

std::string ChildProcess::read_output() {
  if (impl_ == nullptr || impl_->read_descriptor < 0) {
    return std::string();
  }
  std::string fresh;
  char buffer[4096];
  for (;;) {
    const ssize_t read = ::read(impl_->read_descriptor, buffer, sizeof(buffer));
    if (read <= 0) {
      break;
    }
    fresh.append(buffer, static_cast<std::size_t>(read));
  }
  impl_->buffer.append(fresh);
  return fresh;
}

ChildResult ChildProcess::collect(bool force_terminate) {
  ChildResult result;
  if (impl_ == nullptr) {
    return result;
  }
  if (force_terminate && !impl_->reaped) {
    (void)terminate();
  }
  // read() on this branch is blocking and the parent closed the write end at
  // spawn, so this drains the pipe to EOF, which happens when the child exits.
  // Draining before reaping is what keeps a child whose answer is larger than
  // the pipe buffer from blocking on a full pipe while this process blocks in
  // waitpid: that combination is a deadlock, and nothing here is clock-bounded.
  (void)read_output();
  const Result<int> status = wait();
  if (status.has_value()) {
    result.exit_code = status.value();
    result.exited = true;
  }
  (void)read_output();
  result.terminated = impl_->terminated;
  result.output = impl_->buffer;
  return result;
}

bool ChildProcess::running() const noexcept { return impl_ != nullptr && !impl_->reaped; }

bool ChildProcess::has_exited() {
  if (impl_ == nullptr || impl_->reaped) {
    return true;
  }
  int status = 0;
  const pid_t result = waitpid(impl_->pid, &status, WNOHANG);
  if (result == 0) {
    return false;
  }
  if (result < 0) {
    impl_->reaped = true;
    return true;
  }
  impl_->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  impl_->reaped = true;
  return true;
}

unsigned long ChildProcess::process_id() const noexcept {
  return impl_ == nullptr ? 0 : static_cast<unsigned long>(impl_->pid);
}

std::string current_executable_path() {
  char buffer[4096];
  const ssize_t written = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
  if (written <= 0) {
    return std::string();
  }
  return std::string(buffer, static_cast<std::size_t>(written));
}

#endif

std::vector<std::string> child_command(const std::vector<std::string>& args) {
  std::vector<std::string> command;
  command.reserve(args.size() + 1);
  command.push_back(current_executable_path());
  command.insert(command.end(), args.begin(), args.end());
  return command;
}

const ChildInvocation& child_invocation() {
  static const ChildInvocation invocation = [] {
    ChildInvocation parsed;
    (void)environment_value(kChildRoleName, &parsed.role);
    for (std::size_t index = 0; index < kMaxChildArguments; ++index) {
      std::string value;
      if (!environment_value(std::string(kChildArgumentPrefix) + std::to_string(index), &value)) {
        break;
      }
      parsed.arguments.push_back(std::move(value));
    }
    return parsed;
  }();
  return invocation;
}

bool is_child_role(std::string_view role) { return child_invocation().role == role; }

Result<ChildProcess> spawn_child(const std::string& case_name, std::string_view role,
                                 const std::vector<std::string>& arguments,
                                 const std::vector<std::pair<std::string, std::string>>& extra_environment) {
  if (arguments.size() > kMaxChildArguments) {
    return Error(ErrorCode::InvalidArgument, "a child role accepts at most the documented number of arguments");
  }
  std::vector<std::pair<std::string, std::string>> environment;
  environment.reserve(extra_environment.size() + arguments.size() + 1);
  // The role and its arguments are added first and a repeated name keeps its
  // first value, so no caller-supplied entry can shadow the role.
  environment.emplace_back(kChildRoleName, std::string(role));
  for (std::size_t index = 0; index < arguments.size(); ++index) {
    environment.emplace_back(std::string(kChildArgumentPrefix) + std::to_string(index), arguments[index]);
  }
  for (const auto& entry : extra_environment) {
    environment.push_back(entry);
  }
  return ChildProcess::spawn(child_command({"--filter=" + case_name}), std::string(), environment);
}

}  // namespace ct_test
