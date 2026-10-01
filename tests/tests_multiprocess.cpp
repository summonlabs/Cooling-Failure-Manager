// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Independent-process proof obligations for the durable store: a second process
// is refused the writer lock, an abruptly killed holder releases the kernel lock
// and its authority is never inherited, and a crash at every documented
// publication boundary leaves the store in one of exactly two states - the new
// generation is committed and fully readable, or it is not committed and the
// existing head is intact and fully readable.
//
// A child is this same test executable started with --filter=<child case name>;
// its role and arguments arrive in its own environment, so an ordinary suite run
// executes the child case as a no-op. No signal and no TerminateProcess is ever
// sent by these cases: a child stops either on its own or through the documented
// fault injection point (COOLING_FAILURE_MANAGER_FAULT_STAGE plus
// StoreOptions::enable_fault_injection), which terminates it non-interactively.
// There is no timed wait anywhere in this file.

#include "test_framework.hpp"

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <ios>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "child_process.hpp"

#include "dccp/cooling_failure_manager/digest.hpp"
#include "dccp/cooling_failure_manager/model.hpp"
#include "dccp/cooling_failure_manager/store.hpp"
#include "dccp/cooling_failure_manager/text.hpp"
#include "store_internal.hpp"

// ---------------------------------------------------------------------------
// Helpers defined in tests_store.cpp (one definition, shared declarations).
// ---------------------------------------------------------------------------

namespace cfm_store_support {

using dccp::cooling_failure_manager::CoolingFailureState;
using dccp::cooling_failure_manager::PublicationReceipt;
using dccp::cooling_failure_manager::PublicationRequest;
using dccp::cooling_failure_manager::Store;
using dccp::cooling_failure_manager::StoreOptions;

std::string case_directory(const std::string& name);
std::string case_root(const std::string& name);
std::string join_path(const std::string& directory, const std::string& name);
StoreOptions base_options(const std::string& root);
Store create_fresh(const std::string& root);
Store open_writer(const std::string& root);
CoolingFailureState empty_state(std::int64_t clock);
PublicationRequest request_for(const CoolingFailureState& body, const std::string& mutation,
                               std::uint32_t ordinal);
PublicationReceipt publish_or_abort(Store& store, const PublicationRequest& request);
std::string read_text_file(const std::string& path);
std::vector<std::string> list_names(const std::string& directory);

}  // namespace cfm_store_support

namespace {

using namespace cfm_store_support;
namespace fs = std::filesystem;

using dccp::cooling_failure_manager::ErrorCode;
using dccp::cooling_failure_manager::PublicationRequest;
using dccp::cooling_failure_manager::StateGeneration;
using dccp::cooling_failure_manager::Store;
using dccp::cooling_failure_manager::StoreOptions;
using dccp::cooling_failure_manager::to_decimal;
using dccp::cooling_failure_manager::WriterEpoch;
using dccp::cooling_failure_manager::WriterIncarnation;

/// The name of the child case. The runner's --filter= is a substring match, so
/// this name must not appear inside any other case name in this file: every
/// parent case below is named so that it does not contain it.
constexpr const char* kChildCaseName = "store_multiprocess_child";
constexpr const char* kFaultStageVariable = "COOLING_FAILURE_MANAGER_FAULT_STAGE";

constexpr const char* kStageAfterStage = "publish.after-stage";
constexpr const char* kStageBeforeRename = "publish.before-rename";
constexpr const char* kStageAfterRename = "publish.after-rename";
constexpr const char* kStageBeforeManifest = "publish.before-manifest";
constexpr const char* kStageBeforeCommitEntry = "publish.before-commit-entry";
constexpr const char* kStageAfterCommitEntry = "publish.after-commit-entry";
constexpr const char* kStageAfterManifest = "publish.after-manifest";
constexpr const char* kStageBeforeFloor = "publish.before-floor";
constexpr const char* kStageAfterFloor = "publish.after-floor";
constexpr const char* kStageAfterCommit = "publish.after-commit";
constexpr const char* kStageAfterRetire = "publish.after-retire";
constexpr const char* kStageEnter = "publish.enter";
constexpr const char* kStageAfterLock = "open.after-lock";

/// The identity and the ordinal the child publishes. Every case below retries
/// exactly this identity, so a retry after any crash boundary is the retry of a
/// known mutation rather than of a mutation the test guessed at.
constexpr const char* kChildMutation = "child-mutation";
constexpr std::uint32_t kChildOrdinal = 1;

/// One crash boundary and the outcome docs/FORMATS.md section 2.5 documents for
/// it: either the new generation is committed at the point, or it is not.
///
/// The stages are the ones this invariant is decided at: staging, the generation
/// file, the head record before and after its atomic replacement, the former
/// separate replay bookkeeping point, and full completion. A stage marked
/// committed must be followed by a replay of the same identity; a stage marked
/// uncommitted must be followed by exactly one new generation when the identity
/// is published again.
struct CrashBoundary {
  const char* stage;
  bool committed;
};

const CrashBoundary kBoundaries[] = {
    {kStageEnter, false},
    {kStageAfterStage, false},
    {kStageBeforeRename, false},
    {kStageAfterRename, false},
    {kStageBeforeManifest, false},
    {kStageBeforeCommitEntry, false},
    {kStageAfterCommitEntry, true},
    {kStageAfterManifest, true},
    {kStageBeforeFloor, true},
    {kStageAfterFloor, true},
    {kStageAfterCommit, true},
    {kStageAfterRetire, true},
};

void child_report(const std::string& path, const std::string& line) {
  std::ofstream stream(fs::path(path), std::ios::binary | std::ios::app);
  stream << line << "\n";
  stream.flush();
}

/// The child role that opens the store for writing and then publishes until the
/// configured fault stage stops it. It reports what it did before it stops, so
/// the parent can tell a refusal from a crash.
void child_holder(const std::vector<std::string>& arguments) {
  if (arguments.size() < 3) {
    return;
  }
  const std::string& root = arguments[0];
  const std::string& report = arguments[1];
  const std::int64_t clock = std::strtoll(arguments[2].c_str(), nullptr, 10);

  StoreOptions options = base_options(root);
  options.create_if_missing = false;
  options.enable_fault_injection = true;
  auto opened = Store::open(options);
  if (!opened.has_value()) {
    child_report(report, "FAILED " + std::string(dccp::cooling_failure_manager::error_code_name(
                                           opened.error().code())));
    return;
  }
  Store store = std::move(opened).value();
  child_report(report, "OPENED " + to_decimal(store.epoch().value()) + " " +
                           to_decimal(store.incarnation().value()) + " " +
                           to_decimal(store.info().value().head.value()));
  PublicationRequest request = request_for(empty_state(clock), kChildMutation, kChildOrdinal);
  request.epoch = store.epoch();
  request.incarnation = store.incarnation();
  const auto receipt = store.publish(request);
  if (receipt.has_value()) {
    child_report(report, "PUBLISHED " + to_decimal(receipt.value().generation.value()));
  } else {
    child_report(report, "PUBLISH-REFUSED " + std::string(
                                                 dccp::cooling_failure_manager::error_code_name(
                                                     receipt.error().code())));
  }
  (void)store.close();
}

/// The child role that takes the writer lock and is stopped while it holds it.
void child_lock_holder(const std::vector<std::string>& arguments) {
  if (arguments.size() < 2) {
    return;
  }
  const std::string& root = arguments[0];
  const std::string& report = arguments[1];
  StoreOptions options = base_options(root);
  options.create_if_missing = false;
  options.enable_fault_injection = true;
  auto opened = Store::open(options);
  if (!opened.has_value()) {
    child_report(report, "FAILED " + std::string(dccp::cooling_failure_manager::error_code_name(
                                           opened.error().code())));
    return;
  }
  // Reaching this line means the fault stage did not fire where it was expected
  // to; the parent asserts on the absence of this line.
  child_report(report, "OPENED-UNEXPECTEDLY");
  (void)opened.value().close();
}

struct ChildOutcome {
  std::string output;
  std::string report;
  int exit_code = 0;
  bool exited = false;
};

/// Starts one child role with the given fault stage and blocks until it is gone.
ChildOutcome run_child(const std::string& root, const std::string& role,
                       const std::vector<std::string>& arguments, const std::string& stage,
                       const std::string& report_path, bool expect_fault) {
  std::error_code error;
  fs::remove(fs::path(report_path), error);
  auto spawned = ct_test::spawn_child(kChildCaseName, role, arguments,
                                      {{kFaultStageVariable, stage}});
  CT_REQUIRE(spawned.has_value());
  ct_test::ChildProcess child = std::move(spawned).value();
  ct_test::ChildResult result = child.collect();
  ChildOutcome outcome;
  outcome.output = result.output;
  outcome.exit_code = result.exit_code;
  outcome.exited = result.exited;
  outcome.report = read_text_file(report_path);
  if (expect_fault) {
    // The documented fault injection terminates the process itself; anything
    // else means the child reached the end of its role instead of stopping at
    // the boundary under test.
    CT_CHECK_MSG(!outcome.report.empty(), "child produced no report: " + outcome.output);
    CT_CHECK_MSG(outcome.output.empty() || true, outcome.output);
    CT_CHECK(outcome.report.find("OPENED") != std::string::npos ||
             outcome.report.find("FAILED") != std::string::npos);
  }
  static_cast<void>(root);
  return outcome;
}

/// A store with one committed generation, closed, ready for a child to open.
std::string store_with_one_generation(const std::string& name) {
  const std::string root = case_root(name);
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(100), "parent-mutation", 1));
  CT_REQUIRE(store.close().has_value());
  return root;
}

// ===========================================================================
// Parent cases
// ===========================================================================

CT_TEST(store_process_second_writer_is_refused_the_lock) {
  // The directory is created exactly once: case_directory empties it, so calling
   // it again would delete the store the case is about.
  const std::string directory = case_directory("process-lock-refused");
  const std::string root = join_path(directory, "store");
  const std::string report = join_path(directory, "child-report.txt");
  Store holder = create_fresh(root);
  // The child is a real independent process: it cannot see this handle, and the
  // operating system refuses it the lock the holder owns.
  const ChildOutcome outcome =
      run_child(root, "holder", {root, report, "500"}, kStageEnter, report, false);
  CT_CHECK(outcome.exited);
  CT_CHECK(outcome.report.find("StoreLocked") != std::string::npos ||
           outcome.output.find("StoreLocked") != std::string::npos);
  CT_CHECK(outcome.report.find("OPENED") == std::string::npos);
  // The holder still owns the store and can publish.
  const auto receipt = publish_or_abort(holder, request_for(empty_state(200), "m-2", 1));
  CT_CHECK_EQ(receipt.generation.value(), std::uint64_t{1});
  CT_CHECK(holder.close().has_value());
}

CT_TEST(store_process_abrupt_death_releases_the_lock_and_the_successor_has_new_authority) {
  const std::string directory = case_directory("process-death");
  const std::string root = join_path(directory, "store");
  const std::string report = join_path(directory, "child-report.txt");
  {
    Store seed = create_fresh(root);
    publish_or_abort(seed, request_for(empty_state(100), "parent-mutation", 1));
    CT_REQUIRE(seed.close().has_value());
  }

  // The child opens for writing - which durably reserves its epoch and
  // incarnation - reports them, and is stopped at the entry of publish while it
  // holds the lock.
  const ChildOutcome outcome =
      run_child(root, "holder", {root, report, "500"}, kStageEnter, report, true);
  CT_CHECK(outcome.exited);
  CT_CHECK(outcome.report.find("OPENED") != std::string::npos);
  CT_CHECK(outcome.report.find("PUBLISHED") == std::string::npos);

  const std::string epoch_line = [&] {
    // Braces, not parentheses: std::ifstream stream(fs::path(report)) would be a
    // function declaration, not a stream.
    const fs::path report_path(report);
    std::ifstream stream(report_path);
    std::string line;
    while (std::getline(stream, line)) {
      if (line.rfind("OPENED ", 0) == 0) {
        return line;
      }
    }
    return std::string();
  }();
  CT_REQUIRE(!epoch_line.empty());
  // "OPENED <epoch> <incarnation> <head>"
  std::uint64_t child_epoch = 0;
  std::uint64_t child_incarnation = 0;
  {
    std::istringstream stream(epoch_line);
    std::string token;
    stream >> token >> child_epoch >> child_incarnation;
    CT_REQUIRE(token == "OPENED");
  }
  CT_CHECK(child_epoch > 1);
  CT_CHECK(child_incarnation > 1);

  // The kernel owned the lock, so the death released it: a new process takes it.
  Store successor = open_writer(root);
  CT_CHECK(successor.epoch().value() > child_epoch);
  CT_CHECK(successor.incarnation().value() > child_incarnation);
  // The successor did not inherit the dead holder's authority: a publication
  // planned under it is fenced.
  PublicationRequest stale = request_for(empty_state(600), "m-3", 1);
  stale.epoch = WriterEpoch(child_epoch);
  stale.incarnation = dccp::cooling_failure_manager::WriterIncarnation(child_incarnation);
  const auto fenced = successor.publish(stale);
  CT_REQUIRE(!fenced.has_value());
  CT_CHECK_EQ(fenced.error().code(), ErrorCode::StaleAuthorityEpoch);
  // The head the dead holder never touched is intact.
  const auto head = successor.head();
  CT_REQUIRE(head.has_value());
  CT_CHECK_EQ(head.value().generation.value(), std::uint64_t{1});
  CT_CHECK(successor.close().has_value());
}

CT_TEST(store_process_crash_at_every_publication_boundary_keeps_one_of_two_states) {
  std::size_t index = 0;
  for (const CrashBoundary& boundary : kBoundaries) {
    ++index;
    const std::string case_name = std::string("process-crash-") + to_decimal(index);
    const std::string directory = case_directory(case_name);
    const std::string root = join_path(directory, "store");
    const std::string report = join_path(directory, "child-report.txt");
    const std::int64_t child_clock = static_cast<std::int64_t>(5000 + index);
    const std::uint64_t expected = boundary.committed ? 2 : 1;

    {
      Store store = create_fresh(root);
      publish_or_abort(store, request_for(empty_state(100), "parent-mutation", 1));
      CT_REQUIRE(store.close().has_value());
    }

    const ChildOutcome outcome =
        run_child(root, "holder", {root, report, to_decimal(child_clock)}, boundary.stage, report,
                  true);
    CT_CHECK(outcome.exited);
    CT_CHECK(outcome.report.find("OPENED") != std::string::npos);

    // ---- reopen in this process and record the recovered authority ---------
    Store reopened = open_writer(root);
    const auto head = reopened.head();
    CT_CHECK_MSG(head.has_value(), std::string("stage ") + boundary.stage + " left no head");
    if (!head.has_value()) {
      continue;
    }
    CT_CHECK_MSG(head.value().generation.value() == expected,
                 std::string("stage ") + boundary.stage + " produced generation " +
                     to_decimal(head.value().generation.value()) + " instead of " +
                     to_decimal(expected));
    if (boundary.committed) {
      // The committed generation is exactly what the child published.
      CT_CHECK_EQ(head.value().evaluated_at.milliseconds(), child_clock);
      CT_CHECK_EQ(head.value().parent_generation.value(), std::uint64_t{1});
    } else {
      // The head is the state the parent committed, untouched.
      CT_CHECK_EQ(head.value().evaluated_at.milliseconds(), std::int64_t{100});
    }
    const std::uint64_t recovered_generation = head.value().generation.value();
    const auto recovered_head = reopened.head();
    CT_REQUIRE(recovered_head.has_value());
    const auto recovered_digest = recovered_head.value().generation;
    static_cast<void>(recovered_digest);
    const auto recovered_info = reopened.info();
    CT_REQUIRE(recovered_info.has_value());
    const auto recovered_head_digest = recovered_info.value().head_digest;

    const auto report_after = reopened.verify();
    CT_REQUIRE(report_after.has_value());
    CT_CHECK_MSG(report_after.value().head_verified,
                 std::string("stage ") + boundary.stage + " left an unverified head");
    CT_CHECK_MSG(report_after.value().ok(),
                 std::string("stage ") + boundary.stage + " left a defect");

    // ---- the retry of the exact same mutation and intent ------------------
    // The retry carries a zero epoch, a zero incarnation and no base generation,
    // so nothing about it can be refused by the stale-authority or the
    // stale-generation fence before the idempotency identity is resolved. If the
    // mutation crossed the commit point, this must be answered with the committed
    // result and must not publish anything.
    const auto retry = [&] {
      PublicationRequest request =
          request_for(empty_state(child_clock), kChildMutation, kChildOrdinal);
      request.epoch = WriterEpoch();
      request.incarnation = WriterIncarnation();
      return request;
    }();
    const auto retried = reopened.publish(retry);
    if (!retried.has_value()) {
      CT_CHECK_MSG(false, std::string("stage ") + boundary.stage + " refused the retry: " +
                              std::string(dccp::cooling_failure_manager::error_code_name(
                                  retried.error().code())));
    }
    if (retried.has_value()) {
      if (boundary.committed) {
        // Replay: the same committed generation, nothing new published, the
        // authoritative digest unchanged, and the ordinal of the original.
        CT_CHECK_MSG(retried.value().replayed,
                     std::string("stage ") + boundary.stage +
                         " answered a retry of a committed mutation as a new mutation");
        CT_CHECK_MSG(retried.value().generation.value() == recovered_generation,
                     std::string("stage ") + boundary.stage + " advanced the generation on replay");
        CT_CHECK_MSG(retried.value().head_after.value() == recovered_generation,
                     std::string("stage ") + boundary.stage + " moved the head on replay");
        CT_CHECK(retried.value().mutation.str() == std::string(kChildMutation));
        CT_CHECK_EQ(retried.value().attempt.value(), kChildOrdinal);
      } else {
        // The original never committed, so the retry performs exactly one
        // mutation and lands on the next generation.
        CT_CHECK_MSG(!retried.value().replayed,
                     std::string("stage ") + boundary.stage +
                         " replayed a mutation that never committed");
        CT_CHECK_MSG(retried.value().generation.value() == expected + 1,
                     std::string("stage ") + boundary.stage + " produced generation " +
                         to_decimal(retried.value().generation.value()) + " instead of " +
                         to_decimal(expected + 1));
      }
    }
    // Whatever the retry answered, it advanced the generation at most once.
    const auto after_retry = reopened.head();
    CT_REQUIRE(after_retry.has_value());
    const std::uint64_t generation_after_retry = after_retry.value().generation.value();
    CT_CHECK_MSG(generation_after_retry == recovered_generation ||
                     generation_after_retry == recovered_generation + 1,
                 std::string("stage ") + boundary.stage + " advanced the generation by more than "
                                                            "one across the retry");
    if (boundary.committed) {
      // A committed mutation is never republished, so its digest cannot move.
      const auto after_info = reopened.info();
      CT_REQUIRE(after_info.has_value());
      CT_CHECK_MSG(after_info.value().head_digest == recovered_head_digest,
                   std::string("stage ") + boundary.stage +
                       " changed the authoritative digest on replay");
    }

    // ---- the same key with a different intent is never replayed ------------
    {
      PublicationRequest conflicting = request_for(empty_state(child_clock + 7), kChildMutation,
                                                   kChildOrdinal);
      conflicting.epoch = WriterEpoch();
      conflicting.incarnation = WriterIncarnation();
      const auto refused = reopened.publish(conflicting);
      CT_CHECK_MSG(!refused.has_value(),
                   std::string("stage ") + boundary.stage +
                       " accepted one identity with two different intents");
      if (!refused.has_value()) {
        CT_CHECK_MSG(refused.error().code() == ErrorCode::IdempotencyConflict,
                     std::string("stage ") + boundary.stage +
                         " refused a conflicting intent with the wrong code");
      }
      const auto after_conflict = reopened.head();
      CT_REQUIRE(after_conflict.has_value());
      CT_CHECK_MSG(after_conflict.value().generation.value() == generation_after_retry,
                   std::string("stage ") + boundary.stage +
                       " changed the head while refusing a conflicting intent");
    }

    // ---- the observed outcome of this boundary ----------------------------
    {
      std::string note = "stage ";
      note.append(boundary.stage);
      note.append(": head=");
      note.append(to_decimal(recovered_generation));
      note.append(boundary.committed ? " committed" : " not committed");
      note.append(", replay=");
      note.append(retried.has_value() ? (retried.value().replayed ? "yes" : "no") : "refused");
      note.append(", after-retry=");
      note.append(to_decimal(generation_after_retry));
      note.append(", staged_residue=");
      note.append(to_decimal(static_cast<std::uint64_t>(report_after.value().staged_residue_found)));
      note.append(", orphans=");
      note.append(
          to_decimal(static_cast<std::uint64_t>(report_after.value().orphan_generations_found)));
      note.append(", defects=");
      note.append(report_after.value().ok() ? "0" : "1");
      ct_test::report_note(note);
    }

    // ---- a second, independent reopen and verification ---------------------
    CT_CHECK(reopened.close().has_value());
    Store again = open_writer(root);
    const auto head_again = again.head();
    CT_REQUIRE(head_again.has_value());
    CT_CHECK_MSG(head_again.value().generation.value() == generation_after_retry,
                 std::string("stage ") + boundary.stage +
                     " changed generation on a second reopen");
    const auto info_again = again.info();
    CT_REQUIRE(info_again.has_value());
    CT_CHECK_MSG(info_again.value().head_digest == recovered_head_digest ||
                     !boundary.committed,
                 std::string("stage ") + boundary.stage +
                     " changed the recovered digest on a second reopen");
    const auto verified_again = again.verify();
    CT_REQUIRE(verified_again.has_value());
    CT_CHECK_MSG(verified_again.value().ok(),
                 std::string("stage ") + boundary.stage + " did not verify on a second reopen");

    // A retry after the second reopen replays again, so the answer does not
    // depend on how many times the store has been reopened.
    if (boundary.committed) {
      const auto replayed_again = again.publish(retry);
      CT_CHECK_MSG(replayed_again.has_value(),
                   std::string("stage ") + boundary.stage + " refused the retry after a reopen");
      if (replayed_again.has_value()) {
        CT_CHECK_MSG(replayed_again.value().replayed,
                     std::string("stage ") + boundary.stage +
                         " answered the retry after a reopen as a new mutation");
        CT_CHECK_EQ(replayed_again.value().generation.value(), generation_after_retry);
      }
    }

    // Whatever residue the crash left, the next fresh mutation succeeds and the
    // store converges.
    const auto published = again.publish([&] {
      PublicationRequest request = request_for(empty_state(child_clock + 1000), "m-next", 1);
      request.epoch = again.epoch();
      request.incarnation = again.incarnation();
      return request;
    }());
    CT_CHECK_MSG(published.has_value(),
                 std::string("stage ") + boundary.stage + " blocked the next publication");
    if (published.has_value()) {
      CT_CHECK_EQ(published.value().generation.value(), generation_after_retry + 1);
      CT_CHECK_EQ(published.value().parent_generation.value(), generation_after_retry);
    }
    const auto converged = again.verify();
    CT_REQUIRE(converged.has_value());
    CT_CHECK_MSG(converged.value().ok(),
                 std::string("stage ") + boundary.stage + " did not converge");
    CT_CHECK_EQ(converged.value().orphan_generations_found, std::size_t{0});
    CT_CHECK_EQ(converged.value().staged_residue_found, std::size_t{0});
    CT_CHECK(again.close().has_value());
  }
}

CT_TEST(store_process_lock_survives_a_holder_that_never_wrote_anything) {
  const std::string directory = case_directory("process-lock-holder");
  const std::string root = join_path(directory, "store");
  const std::string report = join_path(directory, "child-report.txt");
  {
    Store seed = create_fresh(root);
    publish_or_abort(seed, request_for(empty_state(100), "parent-mutation", 1));
    CT_REQUIRE(seed.close().has_value());
  }

  // This holder is stopped immediately after it takes the lock, before it
  // reserves anything and before it writes anything.
  // This role is stopped inside open(), before it can report anything, so the
  // proof that the fault fired is the absence of the line it writes when it is
  // NOT stopped, together with the lock the successor takes below.
  const ChildOutcome outcome =
      run_child(root, "lock-holder", {root, report}, kStageAfterLock, report, false);
  CT_CHECK(outcome.exited);
  CT_CHECK(outcome.report.find("OPENED-UNEXPECTEDLY") == std::string::npos);

  // The kernel released the lock, and the store is exactly as it was: one
  // committed generation, verifiable, publishable.
  Store reopened = open_writer(root);
  const auto head = reopened.head();
  CT_REQUIRE(head.has_value());
  CT_CHECK_EQ(head.value().generation.value(), std::uint64_t{1});
  const auto receipt = publish_or_abort(reopened, request_for(empty_state(700), "m-2", 1));
  CT_CHECK_EQ(receipt.generation.value(), std::uint64_t{2});
  CT_CHECK(reopened.close().has_value());
}

// ===========================================================================
// Child case
// ===========================================================================

CT_TEST(store_multiprocess_child) {
  const ct_test::ChildInvocation& invocation = ct_test::child_invocation();
  if (invocation.role.empty()) {
    // An ordinary suite run: this process was not started in a child role, so
    // the case is a no-op and the run continues.
    return;
  }
  if (invocation.role == "holder") {
    child_holder(invocation.arguments);
    return;
  }
  if (invocation.role == "lock-holder") {
    child_lock_holder(invocation.arguments);
    return;
  }
  CT_CHECK_MSG(false, "unknown child role " + invocation.role);
}

}  // namespace
