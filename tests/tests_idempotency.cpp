// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Idempotency proof obligations: a replay of an accepted attempt returns the
// recorded outcome and writes nothing, a replay with different content is a
// conflict, a replay is resolved before the authority fence, retention evicts
// the oldest record, and attempt ordinals may not go backwards.
//
// The helpers used here are the ones tests_store.cpp defines for this
// workstream; they are declared in the block below rather than in a new header,
// because the test tree is shared with other agents.

#include "test_framework.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dccp/cooling_failure_manager/digest.hpp"
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
Store create_fresh(const std::string& root);
Store open_writer(const std::string& root);
CoolingFailureState empty_state(std::int64_t clock);
CoolingFailureState state_with_attempt(const std::string& attempt_id, AttemptState state,
                                       std::int64_t clock);
PublicationRequest request_for(const CoolingFailureState& body, const std::string& mutation,
                               std::uint32_t ordinal);
PublicationReceipt publish_or_abort(Store& store, const PublicationRequest& request);
std::string read_text_file(const std::string& path);
std::vector<std::string> list_names(const std::string& directory);

}  // namespace cfm_store_support

namespace {

using namespace cfm_store_support;

using dccp::cooling_failure_manager::AttemptOrdinal;
using dccp::cooling_failure_manager::CommitSequence;
using dccp::cooling_failure_manager::ErrorCode;
using dccp::cooling_failure_manager::MutationId;
using dccp::cooling_failure_manager::StateGeneration;
using dccp::cooling_failure_manager::WriterEpoch;
using dccp::cooling_failure_manager::WriterIncarnation;
namespace internal = dccp::cooling_failure_manager::internal;

CT_TEST(store_idempotent_replay_returns_the_recorded_outcome_and_writes_nothing) {
  const std::string root = case_root("idempotency-replay");
  Store store = create_fresh(root);
  const CoolingFailureState body = empty_state(500);
  const auto first = publish_or_abort(store, request_for(body, "m-1", 1));
  CT_CHECK(!first.replayed);

  const std::string manifest_before = read_text_file(join_path(root, "manifest"));
  const std::vector<std::string> generations_before = list_names(join_path(root, "generations"));
  const auto history_before = store.history();
  CT_REQUIRE(history_before.has_value());

  const auto replay = store.publish([&] {
    PublicationRequest filled = request_for(body, "m-1", 1);
    filled.epoch = store.epoch();
    filled.incarnation = store.incarnation();
    return filled;
  }());
  CT_REQUIRE(replay.has_value());
  CT_CHECK(replay.value().replayed);
  // The recorded outcome is reported verbatim.
  CT_CHECK_EQ(replay.value().generation.value(), first.generation.value());
  CT_CHECK(replay.value().digest == first.digest);
  CT_CHECK_EQ(replay.value().commit_sequence.value(), first.commit_sequence.value());
  CT_CHECK_EQ(replay.value().parent_generation.value(), first.parent_generation.value());
  CT_CHECK_EQ(replay.value().mutation.str(), std::string("m-1"));
  CT_CHECK_EQ(replay.value().attempt.value(), std::uint32_t{1});
  CT_CHECK_EQ(replay.value().head_after.value(), std::uint64_t{1});
  CT_CHECK(replay.value().head_digest_after == first.digest);

  // Nothing was written: no new generation, no new manifest generation, no new
  // history entry.
  CT_CHECK_EQ(read_text_file(join_path(root, "manifest")), manifest_before);
  CT_CHECK_EQ(list_names(join_path(root, "generations")), generations_before);
  const auto history_after = store.history();
  CT_REQUIRE(history_after.has_value());
  CT_CHECK_EQ(history_after.value().size(), history_before.value().size());
  const auto info = store.info();
  CT_REQUIRE(info.has_value());
  CT_CHECK_EQ(info.value().head.value(), std::uint64_t{1});
  CT_CHECK_EQ(info.value().commit_sequence.value(), std::uint64_t{1});
  CT_CHECK_EQ(info.value().idempotency_records, std::size_t{1});

  // A third identical retry replays identically, and the record survives a
  // close and a reopen: the replay guarantee is durable, not in-memory.
  CT_CHECK(store.close().has_value());
  Store reopened = open_writer(root);
  PublicationRequest after_reopen = request_for(body, "m-1", 1);
  after_reopen.epoch = reopened.epoch();
  after_reopen.incarnation = reopened.incarnation();
  const auto replay_after_reopen = reopened.publish(after_reopen);
  CT_REQUIRE(replay_after_reopen.has_value());
  CT_CHECK(replay_after_reopen.value().replayed);
  CT_CHECK_EQ(replay_after_reopen.value().generation.value(), first.generation.value());
  CT_CHECK(replay_after_reopen.value().digest == first.digest);
  CT_CHECK(reopened.close().has_value());
}

CT_TEST(store_idempotent_replay_with_different_content_is_a_conflict) {
  const std::string root = case_root("idempotency-conflict");
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(500), "m-1", 1));

  // The same identity with content that is not the recorded content is a
  // conflict, never a second publication and never a replayed success.
  PublicationRequest different = request_for(empty_state(501), "m-1", 1);
  different.epoch = store.epoch();
  different.incarnation = store.incarnation();
  const auto refused = store.publish(different);
  CT_REQUIRE(!refused.has_value());
  CT_CHECK_EQ(refused.error().code(), ErrorCode::IdempotencyConflict);

  // A body that differs only in the generation the caller supplied is the same
  // request: the store ignores caller-supplied generations on both sides.
  CoolingFailureState same = empty_state(500);
  same.generation = StateGeneration(77);
  same.parent_generation = StateGeneration(76);
  PublicationRequest same_request = request_for(same, "m-1", 1);
  same_request.epoch = store.epoch();
  same_request.incarnation = store.incarnation();
  const auto replayed = store.publish(same_request);
  CT_REQUIRE(replayed.has_value());
  CT_CHECK(replayed.value().replayed);
  CT_CHECK_EQ(replayed.value().generation.value(), std::uint64_t{1});

  const auto info = store.info();
  CT_REQUIRE(info.has_value());
  CT_CHECK_EQ(info.value().head.value(), std::uint64_t{1});
  CT_CHECK(store.close().has_value());
}

CT_TEST(store_replay_is_resolved_before_the_authority_fence) {
  const std::string root = case_root("idempotency-before-fence");
  Store store = create_fresh(root);
  const CoolingFailureState body = empty_state(700);
  const auto first = publish_or_abort(store, request_for(body, "m-1", 1));
  CT_CHECK(store.close().has_value());

  // A successor holds a strictly newer epoch and incarnation, so the first
  // attempt's authority is stale - and its replay is still served, because a
  // lost response must never force the caller to plan the operation again.
  Store successor = open_writer(root);
  PublicationRequest replay = request_for(body, "m-1", 1);
  replay.epoch = WriterEpoch(1);
  replay.incarnation = WriterIncarnation(1);
  replay.base_generation = StateGeneration(999);
  const auto served = successor.publish(replay);
  CT_REQUIRE(served.has_value());
  CT_CHECK(served.value().replayed);
  CT_CHECK_EQ(served.value().generation.value(), first.generation.value());
  CT_CHECK(served.value().digest == first.digest);
  // The receipt reports the head as it stands now, which is the replayed
  // generation because nothing else was published.
  CT_CHECK_EQ(served.value().head_after.value(), std::uint64_t{1});

  // The same stale authority with different content is fenced: a fresh
  // publication is judged by the fence, a replay never is.
  PublicationRequest fresh = request_for(empty_state(701), "m-2", 1);
  fresh.epoch = WriterEpoch(1);
  fresh.incarnation = WriterIncarnation(1);
  const auto fenced = successor.publish(fresh);
  CT_REQUIRE(!fenced.has_value());
  CT_CHECK_EQ(fenced.error().code(), ErrorCode::StaleAuthorityEpoch);
  CT_CHECK(successor.close().has_value());
}

CT_TEST(store_idempotency_retention_evicts_the_oldest_records) {
  const std::string root = case_root("idempotency-retention");
  StoreOptions options = base_options(root);
  options.idempotency_retention = 2;
  auto created = dccp::cooling_failure_manager::Store::create(
      options, dccp::cooling_failure_manager::StoreId::parse("store-1").value());
  CT_REQUIRE(created.has_value());
  Store store = std::move(created).value();

  for (std::uint64_t index = 1; index <= 3; ++index) {
    publish_or_abort(store,
                     request_for(empty_state(static_cast<std::int64_t>(index)),
                                 "m-" + dccp::cooling_failure_manager::to_decimal(index), 1));
  }
  {
    const auto info = store.info();
    CT_REQUIRE(info.has_value());
    CT_CHECK_EQ(info.value().idempotency_records, std::size_t{2});
    CT_CHECK_EQ(list_names(join_path(root, "idem")).size(), std::size_t{2});
  }

  // The oldest record is gone, so a retry of the first mutation is a NEW
  // mutation. That is the documented behaviour of a bounded replay window, and
  // it is exactly why a caller that cannot know the window must use a fresh
  // identity rather than rely on replay.
  PublicationRequest first_again = request_for(empty_state(1), "m-1", 1);
  first_again.epoch = store.epoch();
  first_again.incarnation = store.incarnation();
  const auto republished = store.publish(first_again);
  CT_REQUIRE(republished.has_value());
  CT_CHECK(!republished.value().replayed);
  CT_CHECK_EQ(republished.value().generation.value(), std::uint64_t{4});

  // The newest record still replays, and the window is still respected.
  PublicationRequest newest = request_for(empty_state(3), "m-3", 1);
  newest.epoch = store.epoch();
  newest.incarnation = store.incarnation();
  const auto replayed = store.publish(newest);
  CT_REQUIRE(replayed.has_value());
  CT_CHECK(replayed.value().replayed);
  CT_CHECK_EQ(replayed.value().generation.value(), std::uint64_t{3});
  {
    const auto info = store.info();
    CT_REQUIRE(info.has_value());
    CT_CHECK_EQ(info.value().idempotency_records, std::size_t{2});
    // The record of the publication that just committed is never evicted, even
    // at the smallest useful window.
    CT_CHECK_EQ(info.value().head.value(), std::uint64_t{4});
  }
  CT_CHECK(store.close().has_value());
}

CT_TEST(store_attempt_ordinals_may_not_go_backwards) {
  const std::string root = case_root("idempotency-ordinals");
  Store store = create_fresh(root);
  const auto high = publish_or_abort(store, request_for(empty_state(10), "m-1", 5));
  CT_CHECK_EQ(high.generation.value(), std::uint64_t{1});

  // A lower ordinal of the same mutation identity is a reused identity: the
  // caller is describing an attempt that this mutation already moved past.
  PublicationRequest lower = request_for(empty_state(11), "m-1", 3);
  lower.epoch = store.epoch();
  lower.incarnation = store.incarnation();
  const auto refused = store.publish(lower);
  CT_REQUIRE(!refused.has_value());
  CT_CHECK_EQ(refused.error().code(), ErrorCode::IdempotencyConflict);

  // The same ordinal with the same content replays, and the same ordinal with
  // different content conflicts.
  PublicationRequest same = request_for(empty_state(10), "m-1", 5);
  same.epoch = store.epoch();
  same.incarnation = store.incarnation();
  const auto replayed = store.publish(same);
  CT_REQUIRE(replayed.has_value());
  CT_CHECK(replayed.value().replayed);

  PublicationRequest different = request_for(empty_state(12), "m-1", 5);
  different.epoch = store.epoch();
  different.incarnation = store.incarnation();
  const auto conflicted = store.publish(different);
  CT_REQUIRE(!conflicted.has_value());
  CT_CHECK_EQ(conflicted.error().code(), ErrorCode::IdempotencyConflict);

  // A higher ordinal is a new attempt of the same mutation, and it is a new
  // publication.
  PublicationRequest higher = request_for(empty_state(12), "m-1", 6);
  higher.epoch = store.epoch();
  higher.incarnation = store.incarnation();
  const auto accepted = store.publish(higher);
  CT_REQUIRE(accepted.has_value());
  CT_CHECK(!accepted.value().replayed);
  CT_CHECK_EQ(accepted.value().generation.value(), std::uint64_t{2});

  const auto info = store.info();
  CT_REQUIRE(info.has_value());
  CT_CHECK_EQ(info.value().idempotency_records, std::size_t{2});
  CT_CHECK(store.close().has_value());
}

CT_TEST(store_idempotency_record_identity_is_not_the_file_name) {
  // The record name is a digest of the identity, so two identities that share a
  // prefix cannot collide and no identity can reach the file system.
  const std::string root = case_root("idempotency-names");
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(1), "mutation", 1));
  publish_or_abort(store, request_for(empty_state(2), "mutation-2", 1));
  const std::vector<std::string> names = list_names(join_path(root, "idem"));
  CT_REQUIRE(names.size() == 2);
  CT_CHECK(names[0] != names[1]);
  for (const std::string& name : names) {
    CT_CHECK_EQ(name.size(), std::size_t{69});
    CT_CHECK_EQ(name.substr(0, 1), std::string("m"));
    CT_CHECK_EQ(name.substr(65), std::string(".dat"));
    CT_CHECK(name.find("mutation") == std::string::npos);
  }
  CT_CHECK(store.close().has_value());
}

}  // namespace
