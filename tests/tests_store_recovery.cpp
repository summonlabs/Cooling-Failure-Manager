// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Verification and recovery proof obligations: a healthy store verifies with
// every field true and no defect, a corrupt head record makes recovery adopt the
// retained previous publication exactly once, a doubly broken store refuses to
// recover, staged residue and orphan generations are reported and never
// adopted, the durable floor bounds every adoption, and in-flight attempts are
// reported, block a fresh publication and are reconciled explicitly.
//
// Two documented choices are asserted here because they are behaviour, not
// implementation detail:
//   * open() never adopts manifest.prev. A store whose head cannot be verified
//     is still returned as a handle - recover() has to be reachable - but it
//     serves nothing and publishes nothing until recover() adopts a
//     publication.
//   * recover() refuses with RecoveryUnavailable when manifest.prev is missing,
//     unreadable or byte-identical to manifest, because in each case nothing can
//     be adopted.

#include "test_framework.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "dccp/cooling_failure_manager/digest.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/model.hpp"
#include "dccp/cooling_failure_manager/store.hpp"
#include "dccp/cooling_failure_manager/text.hpp"
#include "store_internal.hpp"

// ---------------------------------------------------------------------------
// Helpers defined in tests_store.cpp (one definition, shared declarations).
// ---------------------------------------------------------------------------

namespace cfm_store_support {

using dccp::cooling_failure_manager::AttemptState;
using dccp::cooling_failure_manager::CoolingFailureState;
using dccp::cooling_failure_manager::PublicationReceipt;
using dccp::cooling_failure_manager::PublicationRequest;
using dccp::cooling_failure_manager::Store;
using dccp::cooling_failure_manager::StoreOptions;

std::string case_directory(const std::string& name);
std::string case_root(const std::string& name);
std::string join_path(const std::string& directory, const std::string& name);
StoreOptions base_options(const std::string& root);
StoreOptions read_only_options(const std::string& root);
Store create_fresh(const std::string& root);
Store open_writer(const std::string& root);
CoolingFailureState empty_state(std::int64_t clock);
CoolingFailureState state_with_attempt(const std::string& attempt_id, AttemptState state,
                                       std::int64_t clock);
PublicationRequest request_for(const CoolingFailureState& body, const std::string& mutation,
                               std::uint32_t ordinal);
PublicationReceipt publish_or_abort(Store& store, const PublicationRequest& request);
std::string read_text_file(const std::string& path);
void write_text_file(const std::string& path, std::string_view bytes);
bool file_exists(const std::string& path);
std::vector<std::string> list_names(const std::string& directory);

}  // namespace cfm_store_support

namespace {

using namespace cfm_store_support;
namespace fs = std::filesystem;

using dccp::cooling_failure_manager::AttemptOrdinal;
using dccp::cooling_failure_manager::AttemptState;
using dccp::cooling_failure_manager::AuthoritySet;
using dccp::cooling_failure_manager::digest_bytes;
using dccp::cooling_failure_manager::ErrorCode;
using dccp::cooling_failure_manager::MutationId;
using dccp::cooling_failure_manager::RecoveryOutcome;
using dccp::cooling_failure_manager::StateGeneration;
using dccp::cooling_failure_manager::StoreMode;
using dccp::cooling_failure_manager::StoreOpenState;
using dccp::cooling_failure_manager::VerifyFinding;
using dccp::cooling_failure_manager::VerifySeverity;
using dccp::cooling_failure_manager::WriterEpoch;
namespace internal = dccp::cooling_failure_manager::internal;

bool has_finding(const dccp::cooling_failure_manager::VerifyReport& report,
                 std::string_view code) {
  for (const VerifyFinding& finding : report.findings) {
    if (finding.code == code) {
      return true;
    }
  }
  return false;
}

/// Corrupts the committed head record so that it no longer decodes, leaving
/// manifest.prev untouched: the exact condition recovery exists for.
void corrupt_manifest(const std::string& root) {
  const std::string path = join_path(root, "manifest");
  std::string bytes = read_text_file(path);
  if (bytes.size() < 3) {
    return;
  }
  bytes[bytes.size() - 2] = bytes[bytes.size() - 2] == '0' ? '1' : '0';
  write_text_file(path, bytes);
}

void plant_staged_file(const std::string& root, const std::string& name,
                       std::string_view content) {
  write_text_file(join_path(join_path(root, "staging"), name), content);
}

std::string generation_path(const std::string& root, std::uint64_t generation) {
  return join_path(join_path(root, "generations"),
                   internal::generation_file_name(StateGeneration(generation)));
}

/// Builds a store with three committed generations and returns its root.
std::string three_generation_store(const std::string& name) {
  const std::string root = case_root(name);
  Store store = create_fresh(root);
  for (std::uint64_t generation = 1; generation <= 3; ++generation) {
    publish_or_abort(store, request_for(empty_state(static_cast<std::int64_t>(generation) * 100),
                                        "m-" + dccp::cooling_failure_manager::to_decimal(generation),
                                        1));
  }
  CT_REQUIRE(store.close().has_value());
  return root;
}

CT_TEST(store_verify_accepts_a_healthy_store_field_by_field) {
  const std::string root = three_generation_store("recovery-healthy");
  Store store = open_writer(root);
  const auto report = store.verify();
  CT_REQUIRE(report.has_value());
  CT_CHECK(report.value().ok());
  CT_CHECK(report.value().head_verified);
  CT_CHECK(report.value().manifest_verified);
  CT_CHECK(report.value().floor_verified);
  CT_CHECK(report.value().chain_verified);
  CT_CHECK(report.value().canonical_fixed_point_verified);
  CT_CHECK(!report.value().recovered_state);
  CT_CHECK(report.value().publication_allowed);
  CT_CHECK_EQ(report.value().store_id.str(), std::string("store-1"));
  CT_CHECK_EQ(report.value().head.value(), std::uint64_t{3});
  CT_CHECK_EQ(report.value().generations_present, std::size_t{3});
  CT_CHECK_EQ(report.value().generations_verified, std::size_t{3});
  CT_CHECK_EQ(report.value().staged_residue_found, std::size_t{0});
  CT_CHECK_EQ(report.value().orphan_generations_found, std::size_t{0});
  CT_CHECK_EQ(report.value().unreferenced_generations_found, std::size_t{0});
  CT_CHECK_EQ(report.value().quarantined_found, std::size_t{0});
  CT_CHECK_EQ(report.value().unresolved_attempts_found, std::size_t{0});
  CT_CHECK(report.value().findings.empty());

  // A shallow verification verifies only the head, and says so by counting.
  dccp::cooling_failure_manager::VerifyOptions shallow;
  shallow.deep = false;
  const auto shallow_report = store.verify(shallow);
  CT_REQUIRE(shallow_report.has_value());
  CT_CHECK(shallow_report.value().ok());
  CT_CHECK_EQ(shallow_report.value().generations_verified, std::size_t{1});

  // A healthy store recovers to NoAction and changes nothing.
  const auto recovery = store.recover();
  CT_REQUIRE(recovery.has_value());
  CT_CHECK_EQ(recovery.value().outcome, RecoveryOutcome::NoAction);
  CT_CHECK_EQ(recovery.value().head_after.value(), std::uint64_t{3});
  CT_CHECK_EQ(recovery.value().residue_removed, std::size_t{0});
  CT_CHECK(recovery.value().floor_respected);
  CT_CHECK(!recovery.value().steps.empty());
  CT_CHECK(store.close().has_value());
}

CT_TEST(store_recover_adopts_the_previous_publication_exactly_once) {
  const std::string root = case_root("recovery-adopt");
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(100), "m-1", 1));
  const auto second = publish_or_abort(store, request_for(empty_state(200), "m-2", 1));
  CT_CHECK(store.close().has_value());

  corrupt_manifest(root);
  // open() does not adopt: it returns a handle that serves nothing and
  // publishes nothing.
  Store broken = open_writer(root);
  CT_CHECK(broken.is_open());
  CT_CHECK_EQ(broken.open_state(), StoreOpenState::Reopened);
  CT_CHECK_EQ(broken.epoch().value(), std::uint64_t{0});
  const auto broken_info = broken.info();
  CT_REQUIRE(broken_info.has_value());
  CT_CHECK(!broken_info.value().publication_allowed);
  CT_CHECK_EQ(broken.head().error().code(), ErrorCode::HeadCorrupt);

  const auto recovery = broken.recover();
  CT_REQUIRE(recovery.has_value());
  CT_CHECK_EQ(recovery.value().outcome, RecoveryOutcome::AdoptedPrevious);
  // The previous committed publication becomes the head.
  CT_CHECK_EQ(recovery.value().head_after.value(), std::uint64_t{1});
  // The head record itself could not be read, so the generation that was the
  // head before the recovery is not knowable and is reported as generation 0
  // rather than guessed from damaged bytes.
  CT_CHECK(!recovery.value().head_before.published());
  CT_CHECK(!recovery.value().head_digest_after.is_zero());
  CT_CHECK(recovery.value().floor_respected);
  CT_CHECK(!recovery.value().steps.empty());
  CT_CHECK_EQ(broken.open_state(), StoreOpenState::Recovered);
  CT_CHECK(broken.epoch().value() != 0);

  // The adopted head is served and verifies again.
  const auto head = broken.head();
  CT_REQUIRE(head.has_value());
  CT_CHECK_EQ(head.value().generation.value(), std::uint64_t{1});
  const auto report = broken.verify();
  CT_REQUIRE(report.has_value());
  CT_CHECK(report.value().head_verified);
  CT_CHECK(report.value().recovered_state);
  CT_CHECK(report.value().publication_allowed);
  CT_CHECK(broken.info().value().publication_allowed);

  // A second recovery is NoAction: the head is healthy now, and recovery
  // changes nothing at all.
  const auto again = broken.recover();
  CT_REQUIRE(again.has_value());
  CT_CHECK_EQ(again.value().outcome, RecoveryOutcome::NoAction);
  CT_CHECK_EQ(again.value().head_after.value(), std::uint64_t{1});
  CT_CHECK_EQ(again.value().residue_removed, std::size_t{0});
  const auto after = broken.head();
  CT_REQUIRE(after.has_value());
  CT_CHECK_EQ(after.value().generation.value(), std::uint64_t{1});

  // Publishing from the recovered handle works and chains onto generation 1.
  const auto receipt = publish_or_abort(broken, request_for(empty_state(300), "m-3", 1));
  CT_CHECK_EQ(receipt.generation.value(), std::uint64_t{2});
  CT_CHECK_EQ(receipt.parent_generation.value(), std::uint64_t{1});
  CT_CHECK(broken.close().has_value());
}

CT_TEST(store_recover_refuses_when_nothing_can_be_adopted) {
  const std::string root = case_root("recovery-broken-previous");
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(100), "m-1", 1));
  publish_or_abort(store, request_for(empty_state(200), "m-2", 1));
  CT_CHECK(store.close().has_value());

  corrupt_manifest(root);
  // The previous publication is damaged as well: there is nothing to adopt, so
  // the call is an error and no report describes a store that is still broken.
  {
    const std::string previous = read_text_file(join_path(root, "manifest.prev"));
    CT_REQUIRE(!previous.empty());
    std::string damaged = previous;
    damaged[damaged.size() - 2] = damaged[damaged.size() - 2] == '0' ? '1' : '0';
    write_text_file(join_path(root, "manifest.prev"), damaged);
  }
  Store broken = open_writer(root);
  const auto recovery = broken.recover();
  CT_REQUIRE(!recovery.has_value());
  CT_CHECK_EQ(recovery.error().code(), ErrorCode::RecoveryUnavailable);
  // The store stays unusable: it neither serves a head nor publishes.
  CT_CHECK_EQ(broken.head().error().code(), ErrorCode::HeadCorrupt);
  CT_CHECK_EQ(broken.publish(request_for(empty_state(300), "m-3", 1)).error().code(),
              ErrorCode::RecoveryRequired);

  // A previous publication that is byte-identical to the current manifest would
  // adopt nothing, and is refused for exactly that reason.
  const std::string root_two = case_root("recovery-identical-previous");
  Store other = create_fresh(root_two);
  publish_or_abort(other, request_for(empty_state(100), "m-1", 1));
  CT_CHECK(other.close().has_value());
  const std::string manifest = read_text_file(join_path(root_two, "manifest"));
  CT_REQUIRE(!manifest.empty());
  std::string damaged = manifest;
  damaged[damaged.size() - 2] = damaged[damaged.size() - 2] == '0' ? '1' : '0';
  write_text_file(join_path(root_two, "manifest"), damaged);
  // Byte-identical to the damaged manifest: adopting it would adopt nothing.
  write_text_file(join_path(root_two, "manifest.prev"), damaged);
  Store identical = open_writer(root_two);
  const auto refused = identical.recover();
  CT_REQUIRE(!refused.has_value());
  CT_CHECK_EQ(refused.error().code(), ErrorCode::RecoveryUnavailable);
  CT_CHECK(identical.close().has_value());
  CT_CHECK(broken.close().has_value());
}

CT_TEST(store_recover_never_adopts_below_the_durable_floor) {
  const std::string root = case_root("recovery-floor");
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(100), "m-1", 1));
  publish_or_abort(store, request_for(empty_state(200), "m-2", 1));
  CT_CHECK(store.close().has_value());

  // Raise the durable floor above the retained previous publication. The floor
  // is the rollback guard: adopting generation 1 would roll the store back
  // below it, so recovery refuses rather than serving forbidden state.
  const std::string prefix = "dccp-cooling-failure-floor\t1\tfloor=2\tcount=2\t";
  write_text_file(join_path(root, "floor"), prefix + digest_bytes(prefix).to_hex() + "\n");
  corrupt_manifest(root);

  Store broken = open_writer(root);
  const auto recovery = broken.recover();
  CT_REQUIRE(!recovery.has_value());
  CT_CHECK_EQ(recovery.error().code(), ErrorCode::GenerationFloorViolation);
  CT_CHECK_EQ(broken.head().error().code(), ErrorCode::HeadCorrupt);
  CT_CHECK(broken.close().has_value());
}

CT_TEST(store_recovery_reports_and_removes_staged_residue) {
  const std::string root = case_root("recovery-staging");
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(100), "m-1", 1));
  CT_CHECK(store.close().has_value());

  plant_staged_file(root, "staged-2.tmp", "uncommitted content\n");
  plant_staged_file(root, "manifest.previous.staged", "uncommitted content\n");
  Store reopened = open_writer(root);
  const auto report = reopened.verify();
  CT_REQUIRE(report.has_value());
  CT_CHECK_EQ(report.value().staged_residue_found, std::size_t{2});
  CT_CHECK(has_finding(report.value(), "staging.residue"));
  // Staged content is never authoritative, so the head is still generation 1 and
  // the report is not a defect: nothing committed is missing or damaged.
  CT_CHECK(report.value().ok());
  const auto head = reopened.head();
  CT_REQUIRE(head.has_value());
  CT_CHECK_EQ(head.value().generation.value(), std::uint64_t{1});

  // The next successful publication removes the residue.
  publish_or_abort(reopened, request_for(empty_state(200), "m-2", 1));
  const auto after = reopened.verify();
  CT_REQUIRE(after.has_value());
  CT_CHECK_EQ(after.value().staged_residue_found, std::size_t{0});
  CT_CHECK(!has_finding(after.value(), "staging.residue"));
  CT_CHECK(list_names(join_path(root, "staging")).empty());
  CT_CHECK(reopened.close().has_value());
}

CT_TEST(store_recovery_reports_an_orphan_and_never_adopts_it) {
  const std::string root = case_root("recovery-orphan");
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(100), "m-1", 1));
  publish_or_abort(store, request_for(empty_state(200), "m-2", 1));
  CT_CHECK(store.close().has_value());

  // A generation file newer than the committed head is the residue of an
  // interrupted publication: it is reported, never adopted, and removed by the
  // next successful publication.
  write_text_file(generation_path(root, 3), read_text_file(generation_path(root, 2)));
  Store reopened = open_writer(root);
  const auto head = reopened.head();
  CT_REQUIRE(head.has_value());
  CT_CHECK_EQ(head.value().generation.value(), std::uint64_t{2});
  const auto report = reopened.verify();
  CT_REQUIRE(report.has_value());
  CT_CHECK_EQ(report.value().orphan_generations_found, std::size_t{1});
  CT_CHECK(has_finding(report.value(), "generation.orphan"));
  CT_CHECK(report.value().ok());

  // Publishing generation 3 replaces the orphan rather than adopting it.
  const auto receipt = publish_or_abort(reopened, request_for(empty_state(300), "m-3", 1));
  CT_CHECK_EQ(receipt.generation.value(), std::uint64_t{3});
  const auto repaired = reopened.head();
  CT_REQUIRE(repaired.has_value());
  CT_CHECK_EQ(repaired.value().generation.value(), std::uint64_t{3});
  CT_CHECK_EQ(repaired.value().evaluated_at.milliseconds(), std::int64_t{300});
  const auto after = reopened.verify();
  CT_REQUIRE(after.has_value());
  CT_CHECK_EQ(after.value().orphan_generations_found, std::size_t{0});
  CT_CHECK(after.value().ok());
  CT_CHECK(reopened.close().has_value());
}

CT_TEST(store_recovery_reports_unresolved_attempts_and_reconciles_them) {
  const std::string root = case_root("recovery-attempts");
  Store store = create_fresh(root);
  // An attempt that was solicited and never answered: the head carries it in
  // flight, which is exactly what a restart must not mistake for an outcome.
  const auto first = publish_or_abort(
      store, request_for(state_with_attempt("attempt-a", AttemptState::Solicited, 1000), "m-1", 1));
  CT_CHECK_EQ(first.generation.value(), std::uint64_t{1});

  const auto report = store.verify();
  CT_REQUIRE(report.has_value());
  CT_CHECK_EQ(report.value().unresolved_attempts_found, std::size_t{1});
  CT_CHECK(has_finding(report.value(), "attempt.unresolved"));
  // An unresolved attempt is a lifecycle condition, not damage.
  CT_CHECK(report.value().ok());
  CT_CHECK(report.value().head_verified);

  // A fresh publication that does not change the attempt is refused: an attempt
  // in flight must be resolved, never published over.
  const auto refused = store.publish([&] {
    PublicationRequest request =
        request_for(state_with_attempt("attempt-a", AttemptState::Solicited, 1001), "m-2", 1);
    request.epoch = store.epoch();
    request.incarnation = store.incarnation();
    return request;
  }());
  CT_REQUIRE(!refused.has_value());
  CT_CHECK_EQ(refused.error().code(), ErrorCode::AttemptOutstanding);

  // Explicit reconciliation records the unknown outcome and republishes.
  // The reconciliation carries its own mutation identity: it is a new
  // operation over the committed state, not a retry of the publication that left
  // the attempt in flight.
  const auto reconciled = store.reconcile_unresolved(
      AuthoritySet(), MutationId::parse("reconcile-1").value(), AttemptOrdinal(1));
  CT_REQUIRE(reconciled.has_value());
  CT_CHECK_EQ(reconciled.value(), std::size_t{1});
  const auto head = store.head();
  CT_REQUIRE(head.has_value());
  CT_CHECK_EQ(head.value().generation.value(), std::uint64_t{2});
  CT_REQUIRE(head.value().plans.size() == 1);
  CT_REQUIRE(head.value().plans.front().attempts.size() == 1);
  CT_CHECK_EQ(head.value().plans.front().attempts.front().state, AttemptState::Unresolved);
  CT_CHECK(head.value().plans.front().attempts.front().adopted_after_restart);
  // The reconciliation clock is the head state's evaluated_at: no newer clock
  // exists, and inventing one would date the record with a time no decision was
  // evaluated at.
  CT_CHECK_EQ(head.value().plans.front().attempts.front().updated_at.milliseconds(),
              std::int64_t{1000});
  CT_CHECK_EQ(head.value().unresolved_attempts.size(), std::size_t{1});

  const auto after = store.verify();
  CT_REQUIRE(after.has_value());
  CT_CHECK_EQ(after.value().unresolved_attempts_found, std::size_t{0});
  CT_CHECK(after.value().ok());

  // A fresh publication now succeeds: nothing is in flight.
  const auto accepted = publish_or_abort(store, request_for(empty_state(2000), "m-3", 1));
  CT_CHECK_EQ(accepted.generation.value(), std::uint64_t{3});

  // The reconciliation identity replays instead of reconciling twice, and it
  // reports the number its first execution published.
  const auto replayed = store.reconcile_unresolved(
      AuthoritySet(), MutationId::parse("reconcile-1").value(), AttemptOrdinal(1));
  CT_REQUIRE(replayed.has_value());
  CT_CHECK_EQ(replayed.value(), std::size_t{1});
  const auto still = store.info();
  CT_REQUIRE(still.has_value());
  CT_CHECK_EQ(still.value().head.value(), std::uint64_t{3});

  // With nothing in flight, a reconciliation publishes nothing at all and
  // reports zero.
  const auto nothing = store.reconcile_unresolved(
      AuthoritySet(), MutationId::parse("reconcile-2").value(), AttemptOrdinal(1));
  CT_REQUIRE(nothing.has_value());
  CT_CHECK_EQ(nothing.value(), std::size_t{0});
  const auto after_nothing = store.info();
  CT_REQUIRE(after_nothing.has_value());
  CT_CHECK_EQ(after_nothing.value().head.value(), std::uint64_t{3});
  CT_CHECK(store.close().has_value());

  // A read-only handle refuses to reconcile, and a store with no head reports
  // NotInitialized.
  Store reader = [&] {
    auto opened = dccp::cooling_failure_manager::Store::open(read_only_options(root));
    CT_REQUIRE(opened.has_value());
    // The Result is named so the value it holds outlives the return expression.
    dccp::cooling_failure_manager::Result<dccp::cooling_failure_manager::Store> store =
        std::move(opened);
    return std::move(store).value();
  }();
  const auto read_only_refused = reader.reconcile_unresolved(
      AuthoritySet(), MutationId::parse("m-5").value(), AttemptOrdinal(1));
  CT_REQUIRE(!read_only_refused.has_value());
  CT_CHECK_EQ(read_only_refused.error().code(), ErrorCode::StoreReadOnly);
  CT_CHECK(reader.close().has_value());

  const std::string empty_root = case_root("recovery-nothing");
  Store empty_store = create_fresh(empty_root);
  const auto not_initialized = empty_store.reconcile_unresolved(
      AuthoritySet(), MutationId::parse("m-6").value(), AttemptOrdinal(1));
  CT_REQUIRE(!not_initialized.has_value());
  CT_CHECK_EQ(not_initialized.error().code(), ErrorCode::NotInitialized);
  CT_CHECK(empty_store.close().has_value());
}

CT_TEST(store_recover_refuses_a_read_only_handle) {
  const std::string root = case_root("recovery-read-only");
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(100), "m-1", 1));
  CT_CHECK(store.close().has_value());
  corrupt_manifest(root);

  Store reader = [&] {
    auto opened = dccp::cooling_failure_manager::Store::open(read_only_options(root));
    CT_REQUIRE(opened.has_value());
    return std::move(opened).value();
  }();
  const auto refused = reader.recover();
  CT_REQUIRE(!refused.has_value());
  // An adoption that cannot be committed must never be reported as one.
  CT_CHECK_EQ(refused.error().code(), ErrorCode::StoreReadOnly);
  CT_CHECK(reader.close().has_value());
}

}  // namespace
