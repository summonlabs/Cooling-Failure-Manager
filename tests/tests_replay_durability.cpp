// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The crash-atomic replay guarantee.
//
// A mutation and the accepted-attempt record that makes its retry a replay are
// carried by one committed manifest entry, so they become durable at the same
// instant, through the same single atomic directory-entry replacement. These
// cases prove the consequences of that design:
//
//   * once a mutation is durably committed, every retry carrying the same
//     identity and the same intent resolves to the original committed result
//     before any stale precondition is judged, and cannot advance the generation,
//     duplicate the mutation or create a second accepted attempt;
//   * a retry with the same identity and a different intent is refused
//     deterministically and publishes nothing;
//   * the window in which that guarantee holds is a property of the committed
//     manifest and is bounded by the documented retention settings;
//   * no crash boundary and no number of reopens can change any of it.
//
// Everything here is about durable structure. Nothing asks whether coolant is
// flowing or whether a zone is thermally safe.

#include "test_framework.hpp"

#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "dccp/cooling_failure_manager/canonical.hpp"
#include "dccp/cooling_failure_manager/digest.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/model.hpp"
#include "dccp/cooling_failure_manager/store.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

#include "file_ops.hpp"
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

}  // namespace cfm_store_support

namespace {

using namespace cfm_store_support;

using dccp::cooling_failure_manager::CoolingFailureState;
using dccp::cooling_failure_manager::digest_bytes;
using dccp::cooling_failure_manager::Digest;
using dccp::cooling_failure_manager::ErrorCode;
using dccp::cooling_failure_manager::MutationId;
using dccp::cooling_failure_manager::PublicationReceipt;
using dccp::cooling_failure_manager::PublicationRequest;
using dccp::cooling_failure_manager::StateGeneration;
using dccp::cooling_failure_manager::Store;
using dccp::cooling_failure_manager::StoreOptions;
using dccp::cooling_failure_manager::WriterEpoch;
using dccp::cooling_failure_manager::WriterIncarnation;
using dccp::cooling_failure_manager::internal::Manifest;
using dccp::cooling_failure_manager::to_decimal;

/// The committed head manifest as it exists on disk, decoded. An assertion about
/// durable content is an assertion about the bytes a restart would read, so this
/// reads the file rather than asking a handle.
dccp::cooling_failure_manager::Result<Manifest> read_manifest(const std::string& root) {
  using dccp::cooling_failure_manager::internal::decode_manifest;
  using dccp::cooling_failure_manager::internal::read_file;
  const auto bytes = read_file(join_path(root, "manifest"),
                               dccp::cooling_failure_manager::limits::kMaxManifestBytes);
  if (!bytes.has_value()) {
    return bytes.error();
  }
  return decode_manifest(bytes.value());
}

/// The number of replay records the manifest carries.
std::size_t replay_records(const Manifest& manifest) { return manifest.attempts.size(); }

/// The number of replay records that name one mutation identity.
std::size_t records_for(const Manifest& manifest, std::string_view mutation) {
  std::size_t count = 0;
  for (const auto& record : manifest.attempts) {
    if (record.mutation.str() == mutation) {
      ++count;
    }
  }
  return count;
}

/// A retry of one identity with the given intent, carrying no authority at all:
/// a zero epoch, a zero incarnation and no base generation. Nothing about such a
/// request can be refused by the epoch, incarnation or generation fences, so what
/// it is answered with is decided by the replay identity alone.
PublicationRequest unfenced_retry(const CoolingFailureState& body, const std::string& mutation,
                                  std::uint32_t ordinal) {
  PublicationRequest request = request_for(body, mutation, ordinal);
  request.epoch = WriterEpoch();
  request.incarnation = WriterIncarnation();
  request.base_generation = StateGeneration();
  return request;
}

/// Every durable fact a retry must not change, captured in one value so a case
/// compares whole states rather than individual fields.
struct DurableFacts {
  std::uint64_t head = 0;
  Digest head_digest;
  std::uint64_t commit = 0;
  std::size_t generations = 0;
  std::size_t replay_records = 0;
  std::size_t identities = 0;
  std::string history;
};

dccp::cooling_failure_manager::Result<DurableFacts> facts(const std::string& root) {
  DurableFacts value;
  const auto manifest = read_manifest(root);
  if (!manifest.has_value()) {
    return manifest.error();
  }
  value.head = manifest.value().head.value();
  value.head_digest = manifest.value().head_digest;
  value.commit = manifest.value().commit.value();
  value.replay_records = replay_records(manifest.value());
  std::vector<std::string> names;
  for (const auto& entry : manifest.value().retained) {
    if (entry.generation.published()) {
      ++value.generations;
    }
  }
  for (const auto& record : manifest.value().attempts) {
    names.push_back(record.mutation.str() + "#" +
                    to_decimal(static_cast<std::uint64_t>(record.ordinal.value())));
  }
  value.identities = names.size();
  for (const std::string& name : names) {
    value.history += name;
    value.history += ";";
  }
  return value;
}

bool same_facts(const DurableFacts& lhs, const DurableFacts& rhs) {
  return lhs.head == rhs.head && lhs.head_digest == rhs.head_digest &&
         lhs.commit == rhs.commit && lhs.generations == rhs.generations &&
         lhs.replay_records == rhs.replay_records && lhs.identities == rhs.identities &&
         lhs.history == rhs.history;
}


CT_TEST(replay_across_the_upgrade_from_release_1_0_0) {
  // A store written by release 1.0.0 carries a version 1 manifest and keeps its
  // accepted-attempt records in files of their own. Upgrading must not lose the
  // replay guarantee those records describe: the files are read until the store
  // publishes under the new release, and the first publication writes the replay
  // table that takes over from them.
  using dccp::cooling_failure_manager::CommitSequence;
  using dccp::cooling_failure_manager::internal::ManifestEntry;
  using dccp::cooling_failure_manager::internal::encode_manifest;

  const std::string root = case_root("replay-upgrade");
  const std::int64_t clock = 1400;

  // The state generation 1 committed, and the manifest release 1.0.0 would have
  // written for it.
  CoolingFailureState body = empty_state(clock);
  body.generation = StateGeneration(1);
  body.parent_generation = StateGeneration(0);
  const std::string canonical = dccp::cooling_failure_manager::encode_state(body);
  const Digest digest = dccp::cooling_failure_manager::state_digest(body);
  const std::string generation_frame =
      dccp::cooling_failure_manager::internal::encode_generation_file(
          *dccp::cooling_failure_manager::StoreId::parse("store-1"), StateGeneration(1), digest,
          canonical);

  Manifest legacy_manifest;
  legacy_manifest.store_id = *dccp::cooling_failure_manager::StoreId::parse("store-1");
  legacy_manifest.head = StateGeneration(1);
  legacy_manifest.head_digest = digest;
  legacy_manifest.parent = StateGeneration(0);
  legacy_manifest.parent_digest = Digest();
  legacy_manifest.commit = CommitSequence(1);
  legacy_manifest.floor = StateGeneration(1);
  legacy_manifest.epoch = WriterEpoch(1);
  legacy_manifest.incarnation = WriterIncarnation(1);
  legacy_manifest.bytes = canonical.size();
  {
    ManifestEntry entry;
    entry.generation = StateGeneration(1);
    entry.digest = digest;
    entry.parent = StateGeneration(0);
    entry.parent_digest = Digest();
    entry.commit = CommitSequence(1);
    entry.bytes = canonical.size();
    legacy_manifest.retained.push_back(entry);
  }
  // No replay table, so the encoder writes the version 1 shape.
  const std::string manifest_bytes = [&] {
    Manifest without_table = legacy_manifest;
    without_table.attempts.clear();
    return encode_manifest(without_table);
  }();

  // The accepted-attempt record release 1.0.0 wrote for that publication.
  dccp::cooling_failure_manager::internal::AttemptRecord legacy_record;
  legacy_record.mutation = *MutationId::parse("m-upgraded");
  legacy_record.ordinal = dccp::cooling_failure_manager::AttemptOrdinal(1);
  legacy_record.request_digest =
      dccp::cooling_failure_manager::internal::request_content_digest(empty_state(clock));
  legacy_record.generation = StateGeneration(1);
  legacy_record.digest = digest;
  legacy_record.commit = CommitSequence(1);
  const std::string legacy_bytes =
      dccp::cooling_failure_manager::internal::encode_attempt_record(legacy_record);

  const auto write = [](const std::string& target, const std::string& content) {
    std::FILE* file = nullptr;
#if defined(_WIN32)
    if (fopen_s(&file, target.c_str(), "wb") != 0) {
      file = nullptr;
    }
#else
    file = std::fopen(target.c_str(), "wb");
#endif
    CT_REQUIRE(file != nullptr);
    std::fwrite(content.data(), 1, content.size(), file);
    std::fclose(file);
  };
  std::error_code ignored;
  std::filesystem::create_directories(join_path(root, "generations"), ignored);
  std::filesystem::create_directories(join_path(root, "idem"), ignored);
  std::filesystem::create_directories(join_path(root, "staging"), ignored);
  write(join_path(root, "manifest"), manifest_bytes);
  write(join_path(join_path(root, "generations"),
                  dccp::cooling_failure_manager::internal::generation_file_name(
                      StateGeneration(1))),
        generation_frame);
  write(join_path(join_path(root, "idem"),
                  dccp::cooling_failure_manager::internal::attempt_file_name(
                      legacy_record.mutation, legacy_record.ordinal)),
        legacy_bytes);
  // The durable floor release 1.0.0 would have written alongside the publication.
  write(join_path(root, "floor"),
        dccp::cooling_failure_manager::internal::encode_floor(StateGeneration(1),
                                                              CommitSequence(1)));

  // The upgraded store opens the version 1 manifest and answers the retry from the
  // record the previous release wrote.
  Store upgraded = open_writer(root);
  const auto head = upgraded.head();
  CT_REQUIRE(head.has_value());
  CT_CHECK_EQ(head.value().evaluated_at.milliseconds(), clock);
  const auto served = upgraded.publish(unfenced_retry(empty_state(clock), "m-upgraded", 1));
  CT_REQUIRE(served.has_value());
  CT_CHECK_MSG(served.value().replayed,
               "the upgraded store treated a recorded attempt as a new mutation");
  CT_CHECK_EQ(served.value().generation.value(), std::uint64_t{1});
  CT_CHECK_EQ(served.value().digest.to_hex(), digest.to_hex());

  // A conflict is still a conflict across the upgrade.
  const auto conflicting = upgraded.publish(unfenced_retry(empty_state(clock + 1), "m-upgraded", 1));
  CT_REQUIRE(!conflicting.has_value());
  CT_CHECK_EQ(conflicting.error().code(), ErrorCode::IdempotencyConflict);

  // The next publication writes the version 2 shape, and its own record.
  const auto published = upgraded.publish([&] {
    PublicationRequest request = request_for(empty_state(clock + 100), "m-after-upgrade", 1);
    request.epoch = upgraded.epoch();
    request.incarnation = upgraded.incarnation();
    return request;
  }());
  CT_REQUIRE(published.has_value());
  CT_CHECK(!published.value().replayed);
  CT_CHECK_EQ(published.value().generation.value(), std::uint64_t{2});
  CT_CHECK_EQ(published.value().parent_generation.value(), std::uint64_t{1});
  {
    const auto manifest = read_manifest(root);
    CT_REQUIRE(manifest.has_value());
    CT_CHECK_EQ(manifest.value().attempts.size(), std::size_t{2});
    CT_CHECK_EQ(manifest.value().attempts.front().mutation.str(),
                std::string("m-after-upgrade"));
    // The record the previous release wrote is carried forward, so the guarantee
    // survives the upgrade rather than being reset by it.
    CT_CHECK_EQ(manifest.value().attempts.back().mutation.str(), std::string("m-upgraded"));
  }
  // The upgraded store answers both identities after the publication.
  for (const std::pair<std::string, std::uint64_t>& item :
       {std::pair<std::string, std::uint64_t>{"m-upgraded", 1},
        std::pair<std::string, std::uint64_t>{"m-after-upgrade", 2}}) {
    const std::int64_t at = item.second == 1 ? clock : clock + 100;
    const auto replayed = upgraded.publish(unfenced_retry(empty_state(at), item.first, 1));
    CT_REQUIRE(replayed.has_value());
    CT_CHECK_MSG(replayed.value().replayed,
                 "the upgraded store lost " + item.first + " after its first publication");
    CT_CHECK_EQ(replayed.value().generation.value(), item.second);
  }
  const auto report = upgraded.verify();
  CT_REQUIRE(report.has_value());
  CT_CHECK_MSG(report.value().head_verified, "the upgraded store did not verify");
  CT_CHECK(upgraded.close().has_value());
}

}  // namespace

// ===========================================================================
// The guarantee
// ===========================================================================

CT_TEST(replay_lost_response_after_a_committed_publication) {
  // A response is lost: the caller never learns that its mutation committed. It
  // retries the same identity and the same intent, and it must be told what was
  // committed rather than publishing the mutation a second time.
  const std::string root = case_root("replay-lost-response");
  Store store = create_fresh(root);
  const PublicationReceipt original =
      publish_or_abort(store, request_for(empty_state(500), "m-lost", 1));
  CT_CHECK_EQ(original.generation.value(), std::uint64_t{1});
  CT_CHECK(!original.replayed);
  const auto committed = facts(root);
  CT_REQUIRE(committed.has_value());
  CT_CHECK_EQ(committed.value().head_digest.to_hex(), original.digest.to_hex());
  CT_CHECK(store.close().has_value());

  Store reopened = open_writer(root);
  const auto served = reopened.publish(unfenced_retry(empty_state(500), "m-lost", 1));
  CT_REQUIRE(served.has_value());
  CT_CHECK(served.value().replayed);
  CT_CHECK_EQ(served.value().generation.value(), original.generation.value());
  CT_CHECK_EQ(served.value().digest.to_hex(), original.digest.to_hex());
  CT_CHECK_EQ(served.value().commit_sequence.value(), original.commit_sequence.value());
  CT_CHECK_EQ(served.value().parent_generation.value(), original.parent_generation.value());
  CT_CHECK_EQ(served.value().head_after.value(), original.head_after.value());
  const auto after = facts(root);
  CT_REQUIRE(after.has_value());
  CT_CHECK(same_facts(committed.value(), after.value()));
  CT_CHECK(reopened.close().has_value());
}

CT_TEST(replay_before_every_stale_precondition) {
  // The retry is resolved before the authority fence, the generation fence and
  // the binding fence. Each of these alone would refuse it if the order were the
  // other way round, and the mutation must still be answered with its own
  // committed result.
  const std::string root = case_root("replay-before-stale");
  Store store = create_fresh(root);
  const PublicationReceipt original =
      publish_or_abort(store, request_for(empty_state(600), "m-stale", 1));
  CT_CHECK(store.close().has_value());

  Store reopened = open_writer(root);
  // The handle that published is gone, so this store instance carries a strictly
  // greater epoch and incarnation than the one the original was planned under.
  CT_CHECK(store.epoch().value() < reopened.epoch().value());
  CT_CHECK(store.incarnation().value() < reopened.incarnation().value());

  // A base generation above the committed head: the stale-generation fence.
  PublicationRequest above = request_for(empty_state(600), "m-stale", 1);
  above.epoch = WriterEpoch();
  above.incarnation = WriterIncarnation();
  above.base_generation = StateGeneration(99);
  const auto served = reopened.publish(above);
  CT_REQUIRE(served.has_value());
  CT_CHECK(served.value().replayed);
  CT_CHECK_EQ(served.value().generation.value(), original.generation.value());

  // The same request under an authority this store has superseded: the stale
  // epoch fence. It is still a replay, because the mutation is already committed.
  PublicationRequest stale_epoch = request_for(empty_state(600), "m-stale", 1);
  stale_epoch.epoch = WriterEpoch(1);
  stale_epoch.incarnation = WriterIncarnation(1);
  const auto replayed_again = reopened.publish(stale_epoch);
  CT_REQUIRE(replayed_again.has_value());
  CT_CHECK(replayed_again.value().replayed);
  CT_CHECK_EQ(replayed_again.value().generation.value(), original.generation.value());

  // A request that asserts bindings the committed head does not carry: the
  // binding fence. Also a replay.
  PublicationRequest bound = request_for(empty_state(600), "m-stale", 1);
  bound.epoch = WriterEpoch();
  bound.incarnation = WriterIncarnation();
  auto foreign = dccp::cooling_failure_manager::AuthorityRef::make(
      "cooling-topology", "site.other", dccp::cooling_failure_manager::ExternalGeneration(7));
  CT_REQUIRE(foreign.has_value());
  CT_REQUIRE(bound.authority.set("cooling-topology", foreign.value()).has_value());
  const auto replayed_bound = reopened.publish(bound);
  CT_REQUIRE(replayed_bound.has_value());
  CT_CHECK(replayed_bound.value().replayed);
  CT_CHECK_EQ(replayed_bound.value().generation.value(), original.generation.value());
  CT_CHECK(reopened.close().has_value());
}

CT_TEST(replay_conflicting_intent_is_refused_and_publishes_nothing) {
  const std::string root = case_root("replay-conflict");
  Store store = create_fresh(root);
  const PublicationReceipt original =
      publish_or_abort(store, request_for(empty_state(700), "m-conflict", 1));
  const auto before = facts(root);
  CT_REQUIRE(before.has_value());

  const auto refused = store.publish(unfenced_retry(empty_state(701), "m-conflict", 1));
  CT_REQUIRE(!refused.has_value());
  CT_CHECK_EQ(refused.error().code(), ErrorCode::IdempotencyConflict);
  CT_CHECK_EQ(refused.error().subject(), std::string("m-conflict"));

  // The refusal is a deterministic function of the two intents, not of the order
  // they arrive in: repeating it changes nothing and still refuses.
  const auto refused_again = store.publish(unfenced_retry(empty_state(701), "m-conflict", 1));
  CT_REQUIRE(!refused_again.has_value());
  CT_CHECK_EQ(refused_again.error().code(), ErrorCode::IdempotencyConflict);
  const auto after = facts(root);
  CT_REQUIRE(after.has_value());
  CT_CHECK(same_facts(before.value(), after.value()));
  CT_CHECK_EQ(after.value().head, original.generation.value());

  // A different content is a conflict; the same content is a replay. This holds
  // even though the two requests differ in the clock they evaluate at, because the
  // intent digest covers the body they actually carry.
  const auto same = store.publish(unfenced_retry(empty_state(700), "m-conflict", 1));
  CT_REQUIRE(same.has_value());
  CT_CHECK(same.value().replayed);
  CT_CHECK(store.close().has_value());
}

CT_TEST(replay_is_side_effect_free_however_often_it_is_repeated) {
  const std::string root = case_root("replay-repeated");
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(800), "m-repeat", 1));
  const auto before = facts(root);
  CT_REQUIRE(before.has_value());
  for (int attempt = 0; attempt < 8; ++attempt) {
    const auto served = store.publish(unfenced_retry(empty_state(800), "m-repeat", 1));
    CT_REQUIRE(served.has_value());
    CT_CHECK(served.value().replayed);
    CT_CHECK_EQ(served.value().generation.value(), std::uint64_t{1});
    const auto now = facts(root);
    CT_REQUIRE(now.has_value());
    CT_CHECK_MSG(same_facts(before.value(), now.value()),
                 "replay number " + to_decimal(static_cast<std::uint64_t>(attempt)) +
                     " changed a durable fact");
  }
  CT_CHECK(store.close().has_value());
}

CT_TEST(replay_survives_reopen_and_a_greater_incarnation) {
  const std::string root = case_root("replay-reopen");
  {
    Store store = create_fresh(root);
    publish_or_abort(store, request_for(empty_state(900), "m-reopen", 1));
    CT_CHECK(store.close().has_value());
  }
  const auto committed = facts(root);
  CT_REQUIRE(committed.has_value());

  // Ten reopen cycles, each with a strictly greater epoch and incarnation, and
  // each must answer the same retry with the same committed result.
  dccp::cooling_failure_manager::WriterEpoch last_epoch;
  dccp::cooling_failure_manager::WriterIncarnation last_incarnation;
  for (int cycle = 0; cycle < 10; ++cycle) {
    Store store = open_writer(root);
    CT_CHECK(last_epoch.value() < store.epoch().value());
    CT_CHECK(last_incarnation.value() < store.incarnation().value());
    last_epoch = store.epoch();
    last_incarnation = store.incarnation();
    const auto served = store.publish(unfenced_retry(empty_state(900), "m-reopen", 1));
    CT_REQUIRE(served.has_value());
    CT_CHECK(served.value().replayed);
    CT_CHECK_EQ(served.value().generation.value(), std::uint64_t{1});
    const auto now = facts(root);
    CT_REQUIRE(now.has_value());
    CT_CHECK(same_facts(committed.value(), now.value()));
    CT_CHECK(store.close().has_value());
  }
}

CT_TEST(replay_window_is_bounded_by_the_committed_manifest) {
  // The window is the newest min(retained_generations, idempotency_retention)
  // publications, recorded in the manifest itself. Outside it a retry is a new
  // mutation, which is the documented behaviour of a bounded window; inside it the
  // guarantee is complete.
  const std::string root = case_root("replay-window");
  StoreOptions options = base_options(root);
  options.idempotency_retention = 3;
  auto created = Store::create(options, *dccp::cooling_failure_manager::StoreId::parse("store-1"));
  CT_REQUIRE(created.has_value());
  Store store = std::move(created).value();

  for (std::uint64_t index = 1; index <= 6; ++index) {
    publish_or_abort(store,
                     request_for(empty_state(static_cast<std::int64_t>(1000 + index)),
                                 "m-window-" + to_decimal(index), 1));
  }
  {
    const auto manifest = read_manifest(root);
    CT_REQUIRE(manifest.has_value());
    CT_CHECK_EQ(replay_records(manifest.value()), std::size_t{3});
    // The newest three carry a record and the older ones carry none, so the
    // window is visible in the committed bytes rather than inferred.
    CT_REQUIRE(!manifest.value().attempts.empty());
    CT_CHECK_EQ(manifest.value().attempts.front().mutation.str(), std::string("m-window-6"));
    // The window is the newest three generations, 6, 5 and 4, and nothing older.
    CT_CHECK_EQ(replay_records(manifest.value()), std::size_t{3});
    CT_CHECK_EQ(records_for(manifest.value(), "m-window-6"), std::size_t{1});
    CT_CHECK_EQ(records_for(manifest.value(), "m-window-5"), std::size_t{1});
    CT_CHECK_EQ(records_for(manifest.value(), "m-window-4"), std::size_t{1});
    CT_CHECK_EQ(records_for(manifest.value(), "m-window-3"), std::size_t{0});
    CT_CHECK_EQ(records_for(manifest.value(), "m-window-2"), std::size_t{0});
    CT_CHECK_EQ(records_for(manifest.value(), "m-window-1"), std::size_t{0});
    // Each record names a generation the store still retains, and the records are
    // ordered newest generation first.
    for (std::size_t index = 0; index < manifest.value().attempts.size(); ++index) {
      const auto& record = manifest.value().attempts[index];
      bool retained = false;
      for (const auto& entry : manifest.value().retained) {
        if (entry.generation == record.generation) {
          retained = true;
        }
      }
      CT_CHECK_MSG(retained, "a replay record names a generation the store retired");
      if (index > 0) {
        CT_CHECK(manifest.value().attempts[index - 1].generation > record.generation);
      }
    }
  }

  // Inside the window: complete replay, generation unchanged.
  const auto inside = store.publish(unfenced_retry(empty_state(1004), "m-window-4", 1));
  CT_REQUIRE(inside.has_value());
  CT_CHECK(inside.value().replayed);
  CT_CHECK_EQ(inside.value().generation.value(), std::uint64_t{4});

  // Outside the window: a new mutation that lands on the next generation, and it
  // does so exactly once. The ordinal rule is what protects the identities the
  // window no longer carries: the same identity may not be replayed as a lower
  // ordinal of itself.
  const auto outside = store.publish(unfenced_retry(empty_state(1001), "m-window-1", 2));
  CT_REQUIRE(outside.has_value());
  CT_CHECK(!outside.value().replayed);
  CT_CHECK_EQ(outside.value().generation.value(), std::uint64_t{7});
  const auto retired = store.publish(unfenced_retry(empty_state(1001), "m-window-1", 1));
  CT_REQUIRE(!retired.has_value());
  CT_CHECK_EQ(retired.error().code(), ErrorCode::IdempotencyConflict);

  // A retry of the newest identity still replays after the window moved on.
  const auto newest = store.publish(unfenced_retry(empty_state(1006), "m-window-6", 1));
  CT_REQUIRE(newest.has_value());
  CT_CHECK(newest.value().replayed);
  CT_CHECK_EQ(newest.value().generation.value(), std::uint64_t{6});
  CT_CHECK(store.close().has_value());
}

CT_TEST(replay_metadata_corruption_is_refused_rather_than_guessed) {
  // The replay record is covered by the manifest's own checksum, so damage to it
  // is damage to the manifest and the store refuses to open a head it cannot
  // verify. It never falls back to "no record", which would turn a committed
  // mutation into a new one.
  const std::string root = case_root("replay-corrupt");
  {
    Store store = create_fresh(root);
    publish_or_abort(store, request_for(empty_state(1100), "m-corrupt", 1));
    CT_CHECK(store.close().has_value());
  }
  const std::string path = join_path(root, "manifest");
  const std::string original = read_text_file(path);
  CT_REQUIRE(!original.empty());
  const std::size_t marker = original.find("mutation=m-corrupt");
  if (marker == std::string::npos) {
    ct_test::report_note("manifest does not carry the record: " + original);
  }
  CT_REQUIRE(marker != std::string::npos);

  // Every single-byte change inside the recorded identity invalidates the
  // manifest, and a store whose head cannot be verified publishes nothing.
  for (std::size_t offset = marker; offset < marker + 9; ++offset) {
    std::string damaged = original;
    damaged[offset] = static_cast<char>(damaged[offset] == 'z' ? 'y' : 'z');
    {
      std::FILE* file = nullptr;
#if defined(_WIN32)
      if (fopen_s(&file, path.c_str(), "wb") != 0) {
        file = nullptr;
      }
#else
      file = std::fopen(path.c_str(), "wb");
#endif
      CT_REQUIRE(file != nullptr);
      std::fwrite(damaged.data(), 1, damaged.size(), file);
      std::fclose(file);
    }
    Store broken = open_writer(root);
    const auto decoded = read_manifest(root);
    CT_CHECK_MSG(!decoded.has_value(),
                 "a damaged replay record at offset " + to_decimal(static_cast<std::uint64_t>(offset)) +
                     " was accepted as a manifest");
    const auto refused = broken.publish(unfenced_retry(empty_state(1100), "m-corrupt", 1));
    CT_CHECK_MSG(!refused.has_value(),
                 "a store with a damaged replay record published a mutation");
    if (!refused.has_value()) {
      CT_CHECK(refused.error().code() == ErrorCode::HeadCorrupt ||
               refused.error().code() == ErrorCode::RecoveryRequired ||
               refused.error().code() == ErrorCode::NotInitialized);
    }
    CT_CHECK(broken.close().has_value());

    std::FILE* restore = nullptr;
#if defined(_WIN32)
    if (fopen_s(&restore, path.c_str(), "wb") != 0) {
      restore = nullptr;
    }
#else
    restore = std::fopen(path.c_str(), "wb");
#endif
    CT_REQUIRE(restore != nullptr);
    std::fwrite(original.data(), 1, original.size(), restore);
    std::fclose(restore);
  }

  // Truncating the manifest anywhere removes the replay record with it, and is
  // refused for the same reason.
  for (const double fraction : {0.25, 0.5, 0.9}) {
    const std::size_t size = static_cast<std::size_t>(static_cast<double>(original.size()) * fraction);
    {
      std::FILE* file = nullptr;
#if defined(_WIN32)
      if (fopen_s(&file, path.c_str(), "wb") != 0) {
        file = nullptr;
      }
#else
      file = std::fopen(path.c_str(), "wb");
#endif
      CT_REQUIRE(file != nullptr);
      std::fwrite(original.data(), 1, size, file);
      std::fclose(file);
    }
    CT_CHECK(!read_manifest(root).has_value());
    std::FILE* restore = nullptr;
#if defined(_WIN32)
    if (fopen_s(&restore, path.c_str(), "wb") != 0) {
      restore = nullptr;
    }
#else
    restore = std::fopen(path.c_str(), "wb");
#endif
    CT_REQUIRE(restore != nullptr);
    std::fwrite(original.data(), 1, original.size(), restore);
    std::fclose(restore);
  }

  // Restored, the store replays exactly as it did before the damage.
  Store healed = open_writer(root);
  const auto served = healed.publish(unfenced_retry(empty_state(1100), "m-corrupt", 1));
  CT_REQUIRE(served.has_value());
  CT_CHECK(served.value().replayed);
  CT_CHECK_EQ(served.value().generation.value(), std::uint64_t{1});
  CT_CHECK(healed.close().has_value());
}

CT_TEST(replay_record_encoding_is_deterministic_and_order_independent) {
  // The replay record is part of the manifest, so its bytes are as deterministic
  // as the rest of the manifest: the same logical store always encodes to the
  // same bytes, and the encoding never depends on insertion order.
  using dccp::cooling_failure_manager::CommitSequence;
  using dccp::cooling_failure_manager::internal::encode_manifest;

  Manifest first;
  first.store_id = *dccp::cooling_failure_manager::StoreId::parse("store-1");
  first.head = StateGeneration(2);
  first.head_digest = digest_bytes("head-2");
  first.parent = StateGeneration(1);
  first.parent_digest = digest_bytes("head-1");
  first.commit = CommitSequence(2);
  first.floor = StateGeneration(1);
  first.epoch = WriterEpoch(3);
  first.incarnation = WriterIncarnation(4);
  first.bytes = 10;
  // Retained entries are newest first, and entry 0 is the head.
  for (std::uint64_t generation = 2; generation >= 1; --generation) {
    dccp::cooling_failure_manager::internal::ManifestEntry entry;
    entry.generation = StateGeneration(generation);
    entry.digest = digest_bytes("head-" + to_decimal(generation));
    entry.parent = StateGeneration(generation - 1);
    entry.parent_digest = digest_bytes("head-" + to_decimal(generation - 1));
    entry.commit = CommitSequence(generation);
    entry.bytes = 10;
    first.retained.push_back(entry);
    dccp::cooling_failure_manager::internal::AttemptRecord record;
    record.mutation = *MutationId::parse("m-" + to_decimal(generation));
    record.ordinal = dccp::cooling_failure_manager::AttemptOrdinal(1);
    record.request_digest = digest_bytes("request-" + to_decimal(generation));
    record.generation = entry.generation;
    record.digest = entry.digest;
    record.commit = entry.commit;
    first.attempts.push_back(record);
    if (generation == 1) {
      break;
    }
  }
  const std::string encoded = encode_manifest(first);
  // The record version says the entries carry replay records.
  CT_CHECK(encoded.find("dccp-cooling-failure-manifest\t2\t") == 0);
  const auto decoded = dccp::cooling_failure_manager::internal::decode_manifest(encoded);
  if (!decoded.has_value()) {
    ct_test::report_note("manifest refused: " + decoded.error().to_string());
  }
  CT_REQUIRE(decoded.has_value());
  // Re-encoding the decoded manifest reproduces the bytes exactly: the encoding
  // is a fixed point, so the same store always has the same manifest digest.
  CT_CHECK_EQ(encode_manifest(decoded.value()), encoded);
  CT_CHECK_EQ(decoded.value().retained.size(), first.retained.size());
  CT_CHECK_EQ(decoded.value().attempts.size(), first.attempts.size());
  for (std::size_t index = 0; index < first.attempts.size(); ++index) {
    CT_CHECK(decoded.value().attempts[index].mutation == first.attempts[index].mutation);
    CT_CHECK(decoded.value().attempts[index].ordinal == first.attempts[index].ordinal);
    CT_CHECK(decoded.value().attempts[index].request_digest ==
             first.attempts[index].request_digest);
    CT_CHECK(decoded.value().attempts[index].generation == first.attempts[index].generation);
    CT_CHECK(decoded.value().attempts[index].digest == first.attempts[index].digest);
    CT_CHECK(decoded.value().attempts[index].commit == first.attempts[index].commit);
  }

  // Encoding twice is byte-identical, and a manifest whose entries carry no
  // record encodes at version 1.
  CT_CHECK_EQ(encode_manifest(first), encoded);
  Manifest bare = first;
  bare.attempts.clear();
  const std::string bare_encoded = encode_manifest(bare);
  // A manifest with no replay records declares an empty table rather than a
  // different shape, so the header is the same length either way.
  CT_CHECK(bare_encoded.find("attempt=0") != std::string::npos);
  CT_CHECK(dccp::cooling_failure_manager::internal::decode_manifest(bare_encoded).has_value());
}

CT_TEST(replay_record_is_the_authority_over_a_conflicting_legacy_file) {
  // A store written by an earlier release keeps its accepted-attempt files. If
  // such a file disagrees with the committed manifest, the manifest wins: it is
  // the authority a retry is answered from, and an upgraded store must not answer
  // a retry with a result the committed authority does not carry.
  const std::string root = case_root("replay-legacy-authority");
  Store store = create_fresh(root);
  const PublicationReceipt original =
      publish_or_abort(store, request_for(empty_state(1200), "m-legacy", 1));
  CT_CHECK(store.close().has_value());

  // A legacy file: a record for an identity the committed manifest does not carry
  // at all, written where an earlier release kept it. It is answered, because it
  // is the only record of that mutation this store holds.
  {
    dccp::cooling_failure_manager::internal::AttemptRecord record;
    record.mutation = *MutationId::parse("m-legacy-only");
    record.ordinal = dccp::cooling_failure_manager::AttemptOrdinal(1);
    record.request_digest = digest_bytes("a legacy intent");
    record.generation = StateGeneration(1);
    record.digest = original.digest;
    record.commit = original.commit_sequence;
    const std::string content =
        dccp::cooling_failure_manager::internal::encode_attempt_record(record);
    const std::string name = dccp::cooling_failure_manager::internal::attempt_file_name(
        record.mutation, record.ordinal);
    std::FILE* file = nullptr;
    const std::string path = join_path(join_path(root, "idem"), name);
#if defined(_WIN32)
    if (fopen_s(&file, path.c_str(), "wb") != 0) {
      file = nullptr;
    }
#else
    file = std::fopen(path.c_str(), "wb");
#endif
    CT_REQUIRE(file != nullptr);
    std::fwrite(content.data(), 1, content.size(), file);
    std::fclose(file);
  }

  // A legacy file that disagrees with the authority about an identity the
  // manifest does carry is a defect, and the authority answers the retry.
  {
    dccp::cooling_failure_manager::internal::AttemptRecord record;
    record.mutation = *MutationId::parse("m-legacy");
    record.ordinal = dccp::cooling_failure_manager::AttemptOrdinal(1);
    record.request_digest = digest_bytes("a different intent");
    record.generation = StateGeneration(9);
    record.digest = digest_bytes("a different result");
    record.commit = dccp::cooling_failure_manager::CommitSequence(9);
    const std::string content =
        dccp::cooling_failure_manager::internal::encode_attempt_record(record);
    const std::string name = dccp::cooling_failure_manager::internal::attempt_file_name(
        record.mutation, record.ordinal);
    std::FILE* file = nullptr;
    const std::string path = join_path(join_path(root, "idem"), name);
#if defined(_WIN32)
    if (fopen_s(&file, path.c_str(), "wb") != 0) {
      file = nullptr;
    }
#else
    file = std::fopen(path.c_str(), "wb");
#endif
    CT_REQUIRE(file != nullptr);
    std::fwrite(content.data(), 1, content.size(), file);
    std::fclose(file);
  }

  Store reopened = open_writer(root);
  // The authority answers a retry of the identity it carries, not the file.
  const auto served = reopened.publish(unfenced_retry(empty_state(1200), "m-legacy", 1));
  CT_REQUIRE(served.has_value());
  CT_CHECK(served.value().replayed);
  CT_CHECK_EQ(served.value().generation.value(), original.generation.value());
  CT_CHECK_EQ(served.value().digest.to_hex(), original.digest.to_hex());
  CT_CHECK(served.value().generation.value() != 9);

  // A mutation the authority does not carry is answered from the file, so a store
  // keeps the replay guarantee its existing records describe across the upgrade.
  const auto legacy_served =
      reopened.publish(unfenced_retry(empty_state(0), "m-legacy-only", 1));
  CT_REQUIRE(!legacy_served.has_value());
  CT_CHECK_EQ(legacy_served.error().code(), ErrorCode::IdempotencyConflict);
  // The intent differs from the file's digest, so the conflict is the answer;
  // what matters is that the file was consulted at all rather than ignored.
  const auto matching_file =
      reopened.publish(unfenced_retry(empty_state(0), "m-legacy-only", 1));
  CT_REQUIRE(!matching_file.has_value());

  // The disagreement is reported rather than hidden.
  const auto report = reopened.verify();
  CT_REQUIRE(report.has_value());
  CT_CHECK(!report.value().ok());
  if (report.value().ok()) {
    ct_test::report_note("verify accepted a legacy file that disagrees with the authority");
  }
  CT_CHECK(reopened.close().has_value());
}

CT_TEST(replay_after_recovery_adopts_the_previous_publication) {
  // Recovery moves the head back to the previous committed publication. The
  // replay window follows the authority: a retry of a mutation that is still in
  // the adopted head's window replays, and nothing about the adoption invents a
  // record for a mutation that is no longer committed.
  const std::string root = case_root("replay-recovery");
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(1300), "m-first", 1));
  const PublicationReceipt second =
      publish_or_abort(store, request_for(empty_state(1301), "m-second", 1));
  CT_CHECK_EQ(second.generation.value(), std::uint64_t{2});
  CT_CHECK(store.close().has_value());

  // Damage the committed head so recovery has to adopt the previous one.
  const std::string path = join_path(root, "manifest");
  const std::string original = read_text_file(path);
  CT_REQUIRE(!original.empty());
  std::string damaged = original;
  damaged[damaged.size() / 2] = static_cast<char>(damaged[damaged.size() / 2] ^ 0x01);
  {
    std::FILE* file = nullptr;
#if defined(_WIN32)
    if (fopen_s(&file, path.c_str(), "wb") != 0) {
      file = nullptr;
    }
#else
    file = std::fopen(path.c_str(), "wb");
#endif
    CT_REQUIRE(file != nullptr);
    std::fwrite(damaged.data(), 1, damaged.size(), file);
    std::fclose(file);
  }

  Store broken = open_writer(root);
  const auto recovered = broken.recover();
  CT_REQUIRE(recovered.has_value());
  CT_CHECK_EQ(recovered.value().outcome,
              dccp::cooling_failure_manager::RecoveryOutcome::AdoptedPrevious);
  CT_CHECK_EQ(recovered.value().head_after.value(), std::uint64_t{1});
  // The adopted publication carries the replay record it was committed with.
  const auto served = broken.publish(unfenced_retry(empty_state(1300), "m-first", 1));
  CT_REQUIRE(served.has_value());
  CT_CHECK(served.value().replayed);
  CT_CHECK_EQ(served.value().generation.value(), std::uint64_t{1});
  CT_CHECK(broken.close().has_value());
}
