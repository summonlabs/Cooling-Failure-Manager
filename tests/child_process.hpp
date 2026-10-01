// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Independent-process helper for the durability and crash-consistency suite.
// It uses only narrow native OS abstractions, blocks until a child exits (there
// is no timed wait in this file) and terminates a child only through
// TerminateProcess or SIGKILL, so no interactive error-reporting path - and in
// particular no Windows crash dialog - can ever be reached.
//
// Child roles. The test runner in tests/test_main.cpp is frozen and rejects
// every argument it does not define, so a child role cannot ride in a
// command-line argument. A child is therefore started as
//
//   <this executable> --filter=<child case name>
//
// and receives its role and arguments through its own environment
// (COOLING_FAILURE_MANAGER_TEST_CHILD_ROLE plus COOLING_FAILURE_MANAGER_TEST_CHILD_ARG_<n>).
// spawn_child() sets those entries for that child alone and never modifies the
// environment of the calling process. The child case itself inspects
// child_invocation() and returns immediately when it was not started in its
// role, so an ordinary full-suite run executes every child case as a no-op.

#ifndef COOLING_FAILURE_MANAGER_TESTS_CHILD_PROCESS_HPP
#define COOLING_FAILURE_MANAGER_TESTS_CHILD_PROCESS_HPP

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dccp/cooling_failure_manager/result.hpp"

namespace ct_test {

using dccp::cooling_failure_manager::Error;
using dccp::cooling_failure_manager::ErrorCode;
using dccp::cooling_failure_manager::Result;

struct ChildResult {
  int exit_code = 0;
  bool exited = false;      ///< the child exited on its own
  bool terminated = false;  ///< the parent killed it
  std::string output;       ///< merged stdout and stderr, in arrival order
};

/// One OS process started by this process. The child's standard output and
/// standard error are merged into a pipe that this object drains.
class ChildProcess {
 public:
  ChildProcess() noexcept;
  ~ChildProcess();
  ChildProcess(ChildProcess&& other) noexcept;
  ChildProcess& operator=(ChildProcess&& other) noexcept;
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  /// argv[0] is an executable path. An empty working directory inherits the
  /// parent's; extra environment entries are added for the child only, and an
  /// entry whose name the parent already defines replaces it.
  static Result<ChildProcess> spawn(const std::vector<std::string>& argv,
                                    const std::string& working_directory = std::string(),
                                    const std::vector<std::pair<std::string, std::string>>& extra_environment = {});

  /// Blocks until the child exits on its own and returns its exit code.
  Result<int> wait();

  /// Non-interactive forced termination. Idempotent. The child is never asked
  /// to shut down, so it cannot report an interactive error.
  Result<void> terminate();

  /// Drains everything the child has written so far without blocking.
  std::string read_output();

  /// Waits for the child to be gone (terminating it first when asked to) and
  /// returns the merged output and the exit status.
  ChildResult collect(bool force_terminate = false);

  bool running() const noexcept;
  unsigned long process_id() const noexcept;

  /// Non-blocking: has the child already exited? Reaps it when it has, so a
  /// caller can wait for readiness without any timed wait.
  bool has_exited();

 private:
  struct Impl;
  Impl* impl_ = nullptr;
};

/// Path of the currently running executable, UTF-8 encoded.
std::string current_executable_path();

/// The currently running executable plus the given arguments, ready for
/// spawn().
std::vector<std::string> child_command(const std::vector<std::string>& args);

/// The child role this process was started in, with its arguments. Both are
/// empty in the ordinary test run.
struct ChildInvocation {
  std::string role;
  std::vector<std::string> arguments;
};

const ChildInvocation& child_invocation();

/// True when this process was started in exactly this child role.
bool is_child_role(std::string_view role);

/// Starts this test executable as one child role. The child runs only the case
/// named by case_name (the runner's --filter= selection) and receives the role
/// and its arguments through its environment. extra_environment carries the
/// entries a role needs beyond its arguments, for example the documented
/// fault-injection selector.
Result<ChildProcess> spawn_child(const std::string& case_name, std::string_view role,
                                 const std::vector<std::string>& arguments = {},
                                 const std::vector<std::pair<std::string, std::string>>& extra_environment = {});

}  // namespace ct_test

#endif  // COOLING_FAILURE_MANAGER_TESTS_CHILD_PROCESS_HPP
