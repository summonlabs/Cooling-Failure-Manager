// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Durable store proof obligations: the internal encoders against their byte
// contract, lifecycle (create, open, close, reopen), publication of a chain of
// generations with the documented commit sequence, head/load/history,
// integrity failure detection, retention, and the authority fences.
//
// Every assertion is about durable structure. Nothing here asks whether a
// component is running, whether coolant is flowing or whether a zone is
// thermally safe.
//
// The helper block below is defined here and declared by the three sibling test
// translation units of this workstream, so no new header is added to a tree
// other agents own.

#include "test_framework.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <string>
#include <string_view>
#include <system_error>
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
#include <unistd.h>
#endif

#include "child_process.hpp"

#include "dccp/cooling_failure_manager/canonical.hpp"
#include "dccp/cooling_failure_manager/digest.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/model.hpp"
#include "dccp/cooling_failure_manager/store.hpp"
#include "dccp/cooling_failure_manager/text.hpp"
#include "store_internal.hpp"

namespace cfm_store_support {

namespace fs = std::filesystem;

using dccp::cooling_failure_manager::AttemptOrdinal;
using dccp::cooling_failure_manager::AttemptState;
using dccp::cooling_failure_manager::CoolingFailureState;
using dccp::cooling_failure_manager::CoolingScope;
using dccp::cooling_failure_manager::DecisionClock;
using dccp::cooling_failure_manager::Digest;
using dccp::cooling_failure_manager::EffectClass;
using dccp::cooling_failure_manager::ErrorCode;
using dccp::cooling_failure_manager::MutationId;
using dccp::cooling_failure_manager::PlanId;
using dccp::cooling_failure_manager::PlanLifecycle;
using dccp::cooling_failure_manager::PublicationReceipt;
using dccp::cooling_failure_manager::PublicationRequest;
using dccp::cooling_failure_manager::ResponseAction;
using dccp::cooling_failure_manager::ResponseAttempt;
using dccp::cooling_failure_manager::ResponsePlan;
using dccp::cooling_failure_manager::Result;
using dccp::cooling_failure_manager::ScopeId;
using dccp::cooling_failure_manager::ScopeKind;
using dccp::cooling_failure_manager::StateGeneration;
using dccp::cooling_failure_manager::Store;
using dccp::cooling_failure_manager::StoreId;
using dccp::cooling_failure_manager::StoreMode;
using dccp::cooling_failure_manager::StoreOptions;

/// Absolute path of a fresh scratch directory for one case.
///
/// The directory is derived from the running executable, so the suite never
/// depends on the working directory, and it is made unique per process and per
/// call so that two test executables - or two concurrent runs of this one - can
/// never share, empty or delete each other's store. The process id and the
/// counter are scratch isolation only: no test outcome depends on either, and
/// every path a case uses is absolute.
std::string case_directory(const std::string& name);

/// Absolute path of the store root of one case: a child of case_directory that
/// does not exist yet, ready for create_if_missing.
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
void flip_byte(const std::string& path, std::uint64_t offset);
void truncate_to(const std::string& path, std::uint64_t size);

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

std::string join_path(const std::string& directory, const std::string& name) {
  return (fs::path(directory) / name).string();
}

std::uint64_t next_scratch_index() {
  static std::uint64_t counter = 0;
  return ++counter;
}

unsigned long current_process_id() noexcept {
#if defined(_WIN32)
  return static_cast<unsigned long>(::GetCurrentProcessId());
#else
  return static_cast<unsigned long>(::getpid());
#endif
}

std::string case_directory(const std::string& name) {
  const fs::path base = fs::path(ct_test::current_executable_path()).parent_path() /
                        "cfm-store-tests" /
                        (name + "-" + std::to_string(current_process_id()) + "-" +
                         std::to_string(next_scratch_index()));
  std::error_code error;
  fs::remove_all(base, error);
  fs::create_directories(base, error);
  return base.string();
}

std::string case_root(const std::string& name) { return join_path(case_directory(name), "store"); }

StoreOptions base_options(const std::string& root) {
  StoreOptions options;
  options.root = root;
  options.mode = StoreMode::ReadWrite;
  options.create_if_missing = true;
  options.retained_generations = dccp::cooling_failure_manager::limits::kMaxRetainedGenerations;
  options.idempotency_retention =
      dccp::cooling_failure_manager::limits::kDefaultIdempotencyRetention;
  // Durability is established by one dedicated case; every other case runs
  // without device flushes so the suite stays fast, and asserts the resulting
  // NotDurable receipt rather than pretending otherwise.
  options.durable_flush = false;
  return options;
}

StoreOptions read_only_options(const std::string& root) {
  StoreOptions options = base_options(root);
  options.mode = StoreMode::ReadOnly;
  options.create_if_missing = false;
  return options;
}

Store create_fresh(const std::string& root) {
  StoreOptions options = base_options(root);
  auto created = Store::create(options, StoreId::parse("store-1").value());
  CT_REQUIRE(created.has_value());
  return std::move(created).value();
}

Store open_writer(const std::string& root) {
  StoreOptions options = base_options(root);
  auto opened = Store::open(options);
  CT_REQUIRE(opened.has_value());
  return std::move(opened).value();
}

CoolingFailureState empty_state(std::int64_t clock) {
  CoolingFailureState state;
  state.evaluated_at = DecisionClock(clock);
  return state;
}

CoolingFailureState state_with_attempt(const std::string& attempt_id, AttemptState state,
                                       std::int64_t clock) {
  CoolingFailureState body = empty_state(clock);
  CoolingScope scope;
  scope.id = ScopeId::parse("loop-a").value();
  scope.kind = ScopeKind::Loop;
  scope.display_name = "loop a";
  body.scopes.push_back(scope);

  ResponsePlan plan;
  plan.id = PlanId::parse("plan-a").value();
  plan.scope = scope.id;
  plan.lifecycle = PlanLifecycle::Solicited;
  plan.updated_at = DecisionClock(clock);

  ResponseAttempt attempt;
  attempt.id = dccp::cooling_failure_manager::AttemptId::parse(attempt_id).value();
  attempt.solicitation = MutationId::parse("solicit-a").value();
  attempt.attempt = AttemptOrdinal(1);
  attempt.action = ResponseAction::StartStandbyPump;
  attempt.effect_class = EffectClass::FlowRestored;
  attempt.state = state;
  attempt.solicited_at = DecisionClock(clock);
  attempt.updated_at = DecisionClock(clock);
  // An acknowledged or effect-observed attempt must carry its acknowledgement
  // clock; a planned one must not.
  if (state == AttemptState::Acknowledged || state == AttemptState::EffectObserved) {
    attempt.acknowledged_at = DecisionClock(clock);
  }
  plan.attempts.push_back(attempt);
  body.plans.push_back(plan);
  return body;
}

PublicationRequest request_for(const CoolingFailureState& body, const std::string& mutation,
                               std::uint32_t ordinal) {
  PublicationRequest request;
  request.mutation = MutationId::parse(mutation).value();
  request.attempt = AttemptOrdinal(ordinal);
  request.body = body;
  return request;
}

PublicationReceipt publish_or_abort(Store& store, const PublicationRequest& request) {
  PublicationRequest filled = request;
  // A zero epoch and a zero incarnation mean "unfenced"; these cases assert the
  // handle's own authority chain, so they use the handle values explicitly.
  if (filled.epoch.value() == 0) {
    filled.epoch = store.epoch();
  }
  if (filled.incarnation.value() == 0) {
    filled.incarnation = store.incarnation();
  }
  auto receipt = store.publish(filled);
  CT_REQUIRE(receipt.has_value());
  return receipt.value();
}

std::string read_text_file(const std::string& path) {
  std::ifstream stream(fs::path(path), std::ios::binary);
  std::string bytes;
  if (!stream) {
    return bytes;
  }
  stream.seekg(0, std::ios::end);
  const std::streamoff size = stream.tellg();
  stream.seekg(0, std::ios::beg);
  bytes.resize(static_cast<std::size_t>(size < 0 ? 0 : size));
  if (!bytes.empty()) {
    stream.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }
  return bytes;
}

void write_text_file(const std::string& path, std::string_view bytes) {
  std::ofstream stream(fs::path(path), std::ios::binary | std::ios::trunc);
  stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

bool file_exists(const std::string& path) {
  std::error_code error;
  return fs::exists(fs::path(path), error);
}

std::vector<std::string> list_names(const std::string& directory) {
  std::vector<std::string> names;
  std::error_code error;
  for (const fs::directory_entry& entry : fs::directory_iterator(fs::path(directory), error)) {
    names.push_back(entry.path().filename().string());
  }
  // Sorted explicitly: the suite never depends on directory enumeration order.
  std::sort(names.begin(), names.end());
  return names;
}

void flip_byte(const std::string& path, std::uint64_t offset) {
  std::fstream stream(fs::path(path), std::ios::binary | std::ios::in | std::ios::out);
  if (!stream) {
    return;
  }
  stream.seekg(static_cast<std::streamoff>(offset));
  char byte = 0;
  stream.read(&byte, 1);
  byte = static_cast<char>(byte ^ 0x01);
  stream.seekp(static_cast<std::streamoff>(offset));
  stream.write(&byte, 1);
}

void truncate_to(const std::string& path, std::uint64_t size) {
  std::error_code error;
  fs::resize_file(fs::path(path), size, error);
}

}  // namespace cfm_store_support

namespace {

using namespace cfm_store_support;
namespace internal = dccp::cooling_failure_manager::internal;

using dccp::cooling_failure_manager::decode_state;
using dccp::cooling_failure_manager::digest_bytes;
using dccp::cooling_failure_manager::encode_state;
using dccp::cooling_failure_manager::CommitSequence;
using dccp::cooling_failure_manager::ErrorCode;
using dccp::cooling_failure_manager::state_digest;
using dccp::cooling_failure_manager::StoreMode;
using dccp::cooling_failure_manager::StoreOpenState;
using dccp::cooling_failure_manager::to_hex;

/// Floor record text built from an exact prefix, so every field can be edited
/// without touching the rest of the record.
std::string floor_record(std::string_view prefix) {
  return std::string(prefix) + digest_bytes(prefix).to_hex() + "\n";
}

std::string hex_of(std::uint64_t value) {
  return dccp::cooling_failure_manager::to_decimal(value);
}

// ===========================================================================
// Internal encoders
// ===========================================================================

CT_TEST(store_internal_floor_record_round_trips_and_rejects_every_shape) {
  const std::string encoded = internal::encode_floor(StateGeneration(7), CommitSequence(3));
  CT_CHECK_EQ(encoded, floor_record("dccp-cooling-failure-floor\t1\tfloor=7\tcount=3\t"));
  const auto decoded = internal::decode_floor(encoded);
  CT_REQUIRE(decoded.has_value());
  CT_CHECK_EQ(decoded.value().value(), std::uint64_t{7});

  // A record that is not terminated, a record with trailing bytes, an empty
  // record and a two-line record are all truncations or shape violations.
  CT_CHECK_EQ(internal::decode_floor(encoded.substr(0, encoded.size() - 1)).error().code(),
              ErrorCode::TruncatedInput);
  CT_CHECK_EQ(internal::decode_floor(encoded + "x").error().code(), ErrorCode::TruncatedInput);
  CT_CHECK_EQ(internal::decode_floor("").error().code(), ErrorCode::TruncatedInput);
  // An extra LF is a second line, which this format does not have.
  CT_CHECK_EQ(internal::decode_floor(encoded + "\n").error().code(), ErrorCode::MalformedRecord);

  {
    std::string with_cr = encoded;
    with_cr[4] = '\r';
    CT_CHECK_EQ(internal::decode_floor(with_cr).error().code(), ErrorCode::MalformedRecord);
  }
  {
    std::string with_nul = encoded;
    with_nul[4] = '\0';
    CT_CHECK_EQ(internal::decode_floor(with_nul).error().code(), ErrorCode::MalformedRecord);
  }
  // A leading zero and an explicit plus are not canonical decimals.
  CT_CHECK_EQ(internal::decode_floor(floor_record("dccp-cooling-failure-floor\t1\tfloor=07\tcount=3\t"))
                  .error()
                  .code(),
              ErrorCode::MalformedNumber);
  CT_CHECK_EQ(internal::decode_floor(floor_record("dccp-cooling-failure-floor\t1\tfloor=+7\tcount=3\t"))
                  .error()
                  .code(),
              ErrorCode::MalformedNumber);
  // An empty numeric field is a non-canonical number, not a shape error.
  CT_CHECK_EQ(internal::decode_floor(floor_record("dccp-cooling-failure-floor\t1\tfloor=7\tcount=\t"))
                  .error()
                  .code(),
              ErrorCode::MalformedNumber);
  // Wrong format name and wrong version are version refusals, not shape errors.
  CT_CHECK_EQ(internal::decode_floor(floor_record("dccp-cooling-failure-floors\t1\tfloor=7\tcount=3\t"))
                  .error()
                  .code(),
              ErrorCode::UnsupportedSchemaVersion);
  CT_CHECK_EQ(internal::decode_floor(floor_record("dccp-cooling-failure-floor\t2\tfloor=7\tcount=3\t"))
                  .error()
                  .code(),
              ErrorCode::UnsupportedSchemaVersion);
  // A missing field, an extra field and a reordered field.
  CT_CHECK_EQ(internal::decode_floor(floor_record("dccp-cooling-failure-floor\t1\tfloor=7\t"))
                  .error()
                  .code(),
              ErrorCode::MalformedRecord);
  CT_CHECK_EQ(
      internal::decode_floor(floor_record("dccp-cooling-failure-floor\t1\tfloor=7\tcount=3\tx=1\t"))
          .error()
          .code(),
      ErrorCode::MalformedRecord);
  CT_CHECK_EQ(internal::decode_floor(floor_record("dccp-cooling-failure-floor\t1\tcount=3\tfloor=7\t"))
                  .error()
                  .code(),
              ErrorCode::MalformedRecord);
  // A flipped digest is a checksum failure, and so is an uppercase rendering.
  {
    std::string flipped = encoded;
    flipped[flipped.size() - 2] = flipped[flipped.size() - 2] == '0' ? '1' : '0';
    CT_CHECK_EQ(internal::decode_floor(flipped).error().code(), ErrorCode::DigestMismatch);
  }
  {
    std::string upper = floor_record("dccp-cooling-failure-floor\t1\tfloor=7\tcount=3\t");
    upper[upper.size() - 2] = 'A';
    CT_CHECK_EQ(internal::decode_floor(upper).error().code(), ErrorCode::MalformedRecord);
  }
}

CT_TEST(store_internal_generation_names_are_the_exact_inverse_of_the_parser) {
  CT_CHECK_EQ(internal::generation_file_name(StateGeneration(1)),
              std::string("g00000000000000000001.dat"));
  CT_CHECK_EQ(internal::generation_file_name(StateGeneration(10)),
              std::string("g00000000000000000010.dat"));
  CT_CHECK_EQ(internal::generation_file_name(StateGeneration(18446744073709551615ull)),
              std::string("g18446744073709551615.dat"));
  // Byte-wise ordering of the names is numeric ordering of the generations.
  CT_CHECK(internal::generation_file_name(StateGeneration(9)) <
           internal::generation_file_name(StateGeneration(10)));
  CT_CHECK(internal::generation_file_name(StateGeneration(99)) <
           internal::generation_file_name(StateGeneration(100)));

  for (const std::uint64_t value :
       {std::uint64_t{1}, std::uint64_t{2}, std::uint64_t{9}, std::uint64_t{10},
        std::uint64_t{999}, std::uint64_t{1000}, std::uint64_t{1234567890123456789ull},
        std::uint64_t{18446744073709551615ull}}) {
    const auto parsed = internal::parse_generation_file_name(
        internal::generation_file_name(StateGeneration(value)));
    CT_REQUIRE(parsed.has_value());
    CT_CHECK_EQ(parsed.value().value(), value);
  }

  CT_CHECK_EQ(internal::parse_generation_file_name("g1.dat").error().code(),
              ErrorCode::MalformedRecord);
  CT_CHECK_EQ(internal::parse_generation_file_name("g0000000000000000000.dat").error().code(),
              ErrorCode::MalformedRecord);
  CT_CHECK_EQ(internal::parse_generation_file_name("g000000000000000000001.dat").error().code(),
              ErrorCode::MalformedRecord);
  CT_CHECK_EQ(internal::parse_generation_file_name("G00000000000000000001.dat").error().code(),
              ErrorCode::MalformedRecord);
  CT_CHECK_EQ(internal::parse_generation_file_name("g00000000000000000001.DAT").error().code(),
              ErrorCode::MalformedRecord);
  CT_CHECK_EQ(internal::parse_generation_file_name("g00000000000000000001.dat.tmp").error().code(),
              ErrorCode::MalformedRecord);
  CT_CHECK_EQ(internal::parse_generation_file_name("g0000000000000000000a.dat").error().code(),
              ErrorCode::MalformedRecord);
  CT_CHECK_EQ(internal::parse_generation_file_name("").error().code(), ErrorCode::MalformedRecord);
  // Generation 0 is the empty-store sentinel: it never has a file.
  CT_CHECK_EQ(internal::parse_generation_file_name("g00000000000000000000.dat").error().code(),
              ErrorCode::MalformedRecord);
  // A 20-digit name above the 64-bit generation bound is refused, never wrapped.
  CT_CHECK_EQ(internal::parse_generation_file_name("g99999999999999999999.dat").error().code(),
              ErrorCode::LimitExceeded);
}

CT_TEST(store_internal_manifest_round_trips_and_rejects_every_shape) {
  internal::Manifest manifest;
  manifest.store_id = dccp::cooling_failure_manager::StoreId::parse("store-1").value();
  manifest.head = StateGeneration(3);
  manifest.head_digest = digest_bytes("head-3");
  manifest.parent = StateGeneration(2);
  manifest.parent_digest = digest_bytes("head-2");
  manifest.commit = CommitSequence(7);
  manifest.floor = StateGeneration(1);
  manifest.epoch = dccp::cooling_failure_manager::WriterEpoch(9);
  manifest.incarnation = dccp::cooling_failure_manager::WriterIncarnation(4);
  manifest.bytes = 123;
  for (std::size_t index = 0; index < 3; ++index) {
    internal::ManifestEntry entry;
    entry.generation = StateGeneration(3 - index);
    entry.digest = digest_bytes(std::string("head-") + hex_of(3 - index));
    entry.parent = StateGeneration(2 - index);
    entry.parent_digest = digest_bytes(std::string("head-") + hex_of(2 - index));
    entry.commit = CommitSequence(7 - index);
    entry.bytes = 123 + index;
    manifest.retained.push_back(entry);
  }
  // The header byte count has to agree with the head entry.
  const std::string encoded = internal::encode_manifest(manifest);
  const auto decoded = internal::decode_manifest(encoded);
  CT_REQUIRE(decoded.has_value());
  CT_CHECK_EQ(decoded.value().head.value(), std::uint64_t{3});
  CT_CHECK_EQ(decoded.value().retained.size(), std::size_t{3});
  CT_CHECK_EQ(decoded.value().retained.front().generation.value(), std::uint64_t{3});
  CT_CHECK_EQ(decoded.value().retained.back().generation.value(), std::uint64_t{1});
  CT_CHECK_EQ(internal::encode_manifest(decoded.value()), encoded);

  // An empty store carries exactly one all-zero sentinel entry.
  internal::Manifest fresh;
  fresh.store_id = dccp::cooling_failure_manager::StoreId::parse("store-1").value();
  fresh.epoch = dccp::cooling_failure_manager::WriterEpoch(1);
  fresh.incarnation = dccp::cooling_failure_manager::WriterIncarnation(1);
  fresh.retained.push_back(internal::ManifestEntry{});
  const std::string fresh_text = internal::encode_manifest(fresh);
  const auto fresh_decoded = internal::decode_manifest(fresh_text);
  CT_REQUIRE(fresh_decoded.has_value());
  CT_CHECK(!fresh_decoded.value().head.published());
  CT_CHECK_EQ(fresh_decoded.value().retained.size(), std::size_t{1});

  // A sentinel that carries anything at all is not "no state yet".
  {
    internal::Manifest wrong = fresh;
    wrong.retained.front().bytes = 1;
    CT_CHECK_EQ(internal::decode_manifest(internal::encode_manifest(wrong)).error().code(),
                ErrorCode::HeadCorrupt);
  }
  // Retained entry 0 must be the head, with the head digest.
  {
    internal::Manifest wrong = manifest;
    wrong.head = StateGeneration(4);
    CT_CHECK_EQ(internal::decode_manifest(internal::encode_manifest(wrong)).error().code(),
                ErrorCode::HeadCorrupt);
  }
  // A zero writer epoch is not a writer.
  {
    internal::Manifest wrong = manifest;
    wrong.epoch = dccp::cooling_failure_manager::WriterEpoch(0);
    CT_CHECK_EQ(internal::decode_manifest(internal::encode_manifest(wrong)).error().code(),
                ErrorCode::HeadCorrupt);
  }
  // The trailer count must agree with the retained lines.
  {
    const std::string edited = encoded.substr(0, encoded.rfind("count=")) + "count=2\t" +
                               encoded.substr(encoded.size() - 65);
    CT_CHECK_EQ(internal::decode_manifest(edited).error().code(), ErrorCode::CountMismatch);
  }
  // The header retained= count must agree with the retained lines.
  {
    std::string edited = encoded;
    const std::size_t position = edited.find("retained=3");
    CT_REQUIRE(position != std::string::npos);
    edited.replace(position, 10, "retained=4");
    CT_CHECK_EQ(internal::decode_manifest(edited).error().code(), ErrorCode::CountMismatch);
  }
  // The digest covers the header and every retained line, so a flipped digest
  // and an edited retained line are both checksum failures.
  {
    std::string flipped = encoded;
    flipped[flipped.size() - 2] = flipped[flipped.size() - 2] == '0' ? '1' : '0';
    CT_CHECK_EQ(internal::decode_manifest(flipped).error().code(), ErrorCode::DigestMismatch);
  }
  {
    // A retained line edited in a length-preserving way parses, and is then
    // refused by the digest that covers every retained line.
    std::string edited = encoded;
    const std::size_t position = edited.find("bytes=124");
    CT_REQUIRE(position != std::string::npos);
    edited.replace(position, 9, "bytes=125");
    CT_CHECK_EQ(internal::decode_manifest(edited).error().code(), ErrorCode::DigestMismatch);
  }
  {
    // An ordinal that is not its own index is a shape violation.
    std::string edited = encoded;
    const std::size_t position = edited.find("retained\tordinal=1");
    CT_REQUIRE(position != std::string::npos);
    edited.replace(position, 19, "retained\tordinal=2");
    CT_CHECK_EQ(internal::decode_manifest(edited).error().code(), ErrorCode::MalformedRecord);
  }
  {
    // A manifest that carries fewer retained lines than both of its counts
    // declare is a count disagreement, and the lines are what disagree.
    std::string edited = encoded;
    const std::size_t position = edited.find("retained\tordinal=2");
    CT_REQUIRE(position != std::string::npos);
    const std::size_t line_end = edited.find('\n', position);
    CT_REQUIRE(line_end != std::string::npos);
    edited.erase(position, line_end - position + 1);
    CT_CHECK_EQ(internal::decode_manifest(edited).error().code(), ErrorCode::CountMismatch);
  }
  // Shape refusals: a wrong name, a wrong version, CR, NUL, a missing tail.
  {
    std::string renamed = encoded;
    renamed.replace(0, std::string("dccp-cooling-failure-manifest").size(),
                    "dccp-cooling-failure-manifests");
    CT_CHECK_EQ(internal::decode_manifest(renamed).error().code(),
                ErrorCode::UnsupportedSchemaVersion);
  }
  {
    std::string reversioned = encoded;
    const std::size_t position = reversioned.find("\t1\t");
    CT_REQUIRE(position != std::string::npos);
    reversioned.replace(position, 3, "\t2\t");
    CT_CHECK_EQ(internal::decode_manifest(reversioned).error().code(),
                ErrorCode::UnsupportedSchemaVersion);
  }
  // A one-line manifest has no trailer, so it is a missing tail.
  CT_CHECK_EQ(internal::decode_manifest("dccp-cooling-failure-manifest\t1\n").error().code(),
              ErrorCode::TruncatedInput);
  CT_CHECK_EQ(internal::decode_manifest(encoded.substr(0, encoded.size() - 1)).error().code(),
              ErrorCode::TruncatedInput);
  CT_CHECK_EQ(internal::decode_manifest(encoded + "junk").error().code(),
              ErrorCode::TruncatedInput);
  CT_CHECK_EQ(internal::decode_manifest("").error().code(), ErrorCode::TruncatedInput);
  {
    std::string with_cr = encoded;
    with_cr[10] = '\r';
    CT_CHECK_EQ(internal::decode_manifest(with_cr).error().code(), ErrorCode::MalformedRecord);
  }
  {
    std::string with_nul = encoded;
    with_nul[10] = '\0';
    CT_CHECK_EQ(internal::decode_manifest(with_nul).error().code(), ErrorCode::MalformedRecord);
  }
  // A manifest that declares more retained generations than the bound is refused
  // before anything is allocated for them.
  {
    std::string edited = encoded;
    const std::size_t position = edited.find("retained=3");
    CT_REQUIRE(position != std::string::npos);
    edited.replace(position, 10, "retained=99");
    CT_CHECK_EQ(internal::decode_manifest(edited).error().code(), ErrorCode::LimitExceeded);
  }
  // A manifest larger than the documented bound is refused by size alone.
  CT_CHECK_EQ(internal::decode_manifest(
                  std::string(dccp::cooling_failure_manager::limits::kMaxManifestBytes + 1, 'x'))
                  .error()
                  .code(),
              ErrorCode::LimitExceeded);
}

CT_TEST(store_internal_attempt_records_round_trip_and_reject_every_shape) {
  internal::AttemptRecord record;
  record.mutation = MutationId::parse("mutation-a").value();
  record.ordinal = AttemptOrdinal(2);
  record.request_digest = digest_bytes("request-content");
  record.generation = StateGeneration(5);
  record.digest = digest_bytes("state-5");
  record.commit = CommitSequence(6);
  const std::string encoded = internal::encode_attempt_record(record);
  const auto decoded = internal::decode_attempt_record(encoded);
  CT_REQUIRE(decoded.has_value());
  CT_CHECK_EQ(decoded.value().mutation.str(), std::string("mutation-a"));
  CT_CHECK_EQ(decoded.value().ordinal.value(), std::uint32_t{2});
  CT_CHECK(decoded.value().request_digest == record.request_digest);
  CT_CHECK_EQ(decoded.value().generation.value(), std::uint64_t{5});
  CT_CHECK(decoded.value().digest == record.digest);
  CT_CHECK_EQ(decoded.value().commit.value(), std::uint64_t{6});
  CT_CHECK_EQ(internal::encode_attempt_record(decoded.value()), encoded);

  // The attempt file name is a pure function of the identity: one lowercase hex
  // digest, never the identity itself.
  const std::string name = internal::attempt_file_name(record.mutation, record.ordinal);
  CT_CHECK_EQ(name.size(), std::size_t{69});
  CT_CHECK_EQ(name.substr(0, 1), std::string("m"));
  CT_CHECK_EQ(name.substr(65), std::string(".dat"));
  for (std::size_t index = 1; index < 65; ++index) {
    const char digit = name[index];
    CT_CHECK((digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f'));
  }
  CT_CHECK_EQ(name, internal::attempt_file_name(record.mutation, record.ordinal));
  CT_CHECK(name != internal::attempt_file_name(record.mutation, AttemptOrdinal(3)));
  CT_CHECK(name != internal::attempt_file_name(MutationId::parse("mutation-b").value(),
                                               record.ordinal));
  // Shape refusals.
  CT_CHECK_EQ(internal::decode_attempt_record("").error().code(), ErrorCode::TruncatedInput);
  CT_CHECK_EQ(internal::decode_attempt_record(encoded.substr(0, encoded.size() - 1)).error().code(),
              ErrorCode::TruncatedInput);
  CT_CHECK_EQ(internal::decode_attempt_record(encoded + "x").error().code(),
              ErrorCode::TruncatedInput);
  {
    std::string with_cr = encoded;
    with_cr[3] = '\r';
    CT_CHECK_EQ(internal::decode_attempt_record(with_cr).error().code(),
                ErrorCode::MalformedRecord);
  }
  {
    std::string other = encoded;
    const std::size_t position = other.find("ordinal=2");
    CT_REQUIRE(position != std::string::npos);
    other.replace(position, 9, "ordinal=0");
    CT_CHECK_EQ(internal::decode_attempt_record(other).error().code(), ErrorCode::MalformedNumber);
  }
  {
    std::string other = encoded;
    const std::size_t position = other.find("generation=5");
    CT_REQUIRE(position != std::string::npos);
    other.replace(position, 12, "generation=0");
    CT_CHECK_EQ(internal::decode_attempt_record(other).error().code(), ErrorCode::MalformedRecord);
  }
  {
    std::string other = encoded;
    const std::size_t position = other.find("mutation=mutation-a");
    CT_REQUIRE(position != std::string::npos);
    other.replace(position, 19, "mutation=bad id!");
    CT_CHECK_EQ(internal::decode_attempt_record(other).error().code(),
                ErrorCode::MalformedIdentifier);
  }
  {
    // count must repeat the commit sequence; the count check runs before the
    // checksum, so an edited count is diagnosed as a count disagreement.
    std::string other = encoded;
    const std::size_t position = other.find("count=6");
    CT_REQUIRE(position != std::string::npos);
    other.replace(position, 7, "count=5");
    CT_CHECK_EQ(internal::decode_attempt_record(other).error().code(), ErrorCode::CountMismatch);
  }
  {
    std::string flipped = encoded;
    flipped[flipped.size() - 2] = flipped[flipped.size() - 2] == '0' ? '1' : '0';
    CT_CHECK_EQ(internal::decode_attempt_record(flipped).error().code(), ErrorCode::DigestMismatch);
  }
  CT_CHECK_EQ(internal::decode_attempt_record("dccp-cooling-failure-attempts\t1\n").error().code(),
              ErrorCode::UnsupportedSchemaVersion);
}

CT_TEST(store_internal_request_digest_ignores_the_assigned_generations) {
  // The store assigns the generation and the parent generation, so neither may
  // take part in the identity of the request: a retry of one logical operation
  // must produce the same digest whether or not its earlier attempt reached the
  // commit point.
  CoolingFailureState first = empty_state(1000);
  first.generation = StateGeneration(4);
  first.parent_generation = StateGeneration(3);
  CoolingFailureState second = empty_state(1000);
  second.generation = StateGeneration(9);
  second.parent_generation = StateGeneration(8);
  CT_CHECK(internal::request_content_digest(first) == internal::request_content_digest(second));

  CoolingFailureState different = empty_state(1001);
  different.generation = StateGeneration(4);
  different.parent_generation = StateGeneration(3);
  CT_CHECK(!(internal::request_content_digest(first) == internal::request_content_digest(different)));
}

// ===========================================================================
// Lifecycle
// ===========================================================================

CT_TEST(store_create_open_close_and_reopen) {
  const std::string root = case_root("lifecycle");
  Store store = create_fresh(root);
  CT_CHECK(store.is_open());
  const auto info = store.info();
  CT_REQUIRE(info.has_value());
  CT_CHECK_EQ(info.value().store_id.str(), std::string("store-1"));
  CT_CHECK_EQ(info.value().epoch.value(), std::uint64_t{1});
  CT_CHECK_EQ(info.value().incarnation.value(), std::uint64_t{1});
  CT_CHECK_EQ(info.value().open_state, StoreOpenState::Fresh);
  CT_CHECK_EQ(info.value().mode, StoreMode::ReadWrite);
  CT_CHECK_EQ(info.value().retained_generations, std::size_t{1});
  CT_CHECK(info.value().writable);
  CT_CHECK(info.value().publication_allowed);
  // The store reports the systems boundary it implements, so a caller cannot
  // mistake this component for a control system.
  CT_CHECK_EQ(info.value().boundary, std::string("dccp-cooling-failure-manager/1"));
  CT_CHECK_EQ(info.value().root, root);

  // A fresh store has no committed generation: head() says so instead of
  // inventing an empty state.
  const auto head = store.head();
  CT_REQUIRE(!head.has_value());
  CT_CHECK_EQ(head.error().code(), ErrorCode::HeadMissing);
  const auto loaded = store.load(StateGeneration(0));
  CT_REQUIRE(!loaded.has_value());
  CT_CHECK_EQ(loaded.error().code(), ErrorCode::GenerationNotRetained);

  // Closing releases the lock and is idempotent.
  CT_CHECK(store.close().has_value());
  CT_CHECK(!store.is_open());
  CT_CHECK(store.close().has_value());

  // Every operation on a closed handle is refused with StoreClosed.
  CT_CHECK_EQ(store.info().error().code(), ErrorCode::StoreClosed);
  CT_CHECK_EQ(store.head().error().code(), ErrorCode::StoreClosed);
  CT_CHECK_EQ(store.load(StateGeneration(1)).error().code(), ErrorCode::StoreClosed);
  CT_CHECK_EQ(store.history().error().code(), ErrorCode::StoreClosed);
  CT_CHECK_EQ(store.verify().error().code(), ErrorCode::StoreClosed);
  CT_CHECK_EQ(store.publish(request_for(empty_state(1), "m-1", 1)).error().code(),
              ErrorCode::StoreClosed);
  CT_CHECK_EQ(store.reconcile_unresolved(dccp::cooling_failure_manager::AuthoritySet(),
                                         MutationId::parse("m-1").value(), AttemptOrdinal(1))
                  .error()
                  .code(),
              ErrorCode::StoreClosed);

  // Reopening reserves the next epoch and incarnation, strictly above the ones
  // the creating handle held.
  Store reopened = open_writer(root);
  const auto reopened_info = reopened.info();
  CT_REQUIRE(reopened_info.has_value());
  CT_CHECK_EQ(reopened_info.value().open_state, StoreOpenState::Reopened);
  CT_CHECK(reopened_info.value().epoch.value() > info.value().epoch.value());
  CT_CHECK(reopened_info.value().incarnation.value() > info.value().incarnation.value());
  CT_CHECK(reopened_info.value().publication_allowed);
  CT_CHECK(reopened.close().has_value());
}

CT_TEST(store_create_refuses_an_existing_store_and_a_missing_root) {
  const std::string root = case_root("nonempty");
  Store store = create_fresh(root);
  CT_CHECK(store.close().has_value());
  // A directory that already holds a store is never initialized over.
  StoreOptions options = base_options(root);
  const auto refused = Store::create(options, StoreId::parse("store-2").value());
  CT_REQUIRE(!refused.has_value());
  CT_CHECK_EQ(refused.error().code(), ErrorCode::StoreNotEmpty);

  // A missing root with create_if_missing false is StoreNotFound, and nothing
  // is created.
  const std::string missing = join_path(case_directory("missing-root"), "absent");
  StoreOptions strict;
  strict.root = missing;
  strict.create_if_missing = false;
  const auto not_found = Store::create(strict, StoreId::parse("store-1").value());
  CT_REQUIRE(!not_found.has_value());
  CT_CHECK_EQ(not_found.error().code(), ErrorCode::StoreNotFound);
  CT_CHECK(!file_exists(missing));

  const auto open_missing = Store::open(strict);
  CT_REQUIRE(!open_missing.has_value());
  CT_CHECK_EQ(open_missing.error().code(), ErrorCode::StoreNotFound);
}

CT_TEST(store_exclusive_writer_lock_admits_one_writer_and_any_reader) {
  const std::string root = case_root("locking");
  Store writer = create_fresh(root);

  // A second writer in the same process is refused by the operating system.
  StoreOptions second_options = base_options(root);
  const auto second = Store::open(second_options);
  CT_REQUIRE(!second.has_value());
  CT_CHECK_EQ(second.error().code(), ErrorCode::StoreLocked);

  // A reader takes no lock and reserves no authority.
  auto reader_result = Store::open(read_only_options(root));
  CT_REQUIRE(reader_result.has_value());
  Store reader = std::move(reader_result).value();
  CT_CHECK(reader.is_open());
  const auto reader_info = reader.info();
  CT_REQUIRE(reader_info.has_value());
  CT_CHECK_EQ(reader_info.value().epoch.value(), std::uint64_t{0});
  CT_CHECK_EQ(reader_info.value().incarnation.value(), std::uint64_t{0});
  CT_CHECK_EQ(reader_info.value().mode, StoreMode::ReadOnly);
  CT_CHECK(!reader_info.value().writable);
  CT_CHECK(!reader_info.value().publication_allowed);
  const auto refused = reader.publish(request_for(empty_state(1), "m-read", 1));
  CT_REQUIRE(!refused.has_value());
  CT_CHECK_EQ(refused.error().code(), ErrorCode::StoreReadOnly);
  // Reading is allowed: the reader verifies the (empty) committed head.
  const auto reader_head = reader.head();
  CT_REQUIRE(!reader_head.has_value());
  CT_CHECK_EQ(reader_head.error().code(), ErrorCode::HeadMissing);
  CT_CHECK(reader.close().has_value());
  CT_CHECK(!reader.is_open());

  // Releasing the writer releases the lock for the next writer.
  CT_CHECK(writer.close().has_value());
  Store successor = open_writer(root);
  CT_CHECK(successor.is_open());
  CT_CHECK(successor.close().has_value());
}

// ===========================================================================
// Publication
// ===========================================================================

CT_TEST(store_publish_assigns_generations_and_chains_parents) {
  const std::string root = case_root("publish-chain");
  Store store = create_fresh(root);

  StateGeneration previous{};
  dccp::cooling_failure_manager::Digest previous_digest{};
  for (std::uint64_t generation = 1; generation <= 3; ++generation) {
    const auto receipt =
        publish_or_abort(store, request_for(empty_state(static_cast<std::int64_t>(generation) * 10),
                                            "m-" + hex_of(generation), 1));
    CT_CHECK_EQ(receipt.generation.value(), generation);
    CT_CHECK_EQ(receipt.commit_sequence.value(), generation);
    CT_CHECK_EQ(receipt.parent_generation.value(), previous.value());
    CT_CHECK(receipt.head_after == receipt.generation);
    CT_CHECK(receipt.head_digest_after == receipt.digest);
    CT_CHECK(!receipt.replayed);
    // durable_flush is off in this case: the store reports exactly that instead
    // of claiming a durability it did not establish.
    CT_CHECK_EQ(receipt.durability, dccp::cooling_failure_manager::PublicationDurability::NotDurable);

    const auto info = store.info();
    CT_REQUIRE(info.has_value());
    CT_CHECK_EQ(info.value().head.value(), generation);
    CT_CHECK(info.value().head_digest == receipt.digest);
    CT_CHECK_EQ(info.value().commit_sequence.value(), generation);
    previous = receipt.generation;
    previous_digest = receipt.digest;
  }

  // The chain is recorded in the manifest and re-derived from disk.
  const auto history = store.history();
  CT_REQUIRE(history.has_value());
  CT_CHECK_EQ(history.value().size(), std::size_t{3});
  CT_CHECK_EQ(history.value().front().generation.value(), std::uint64_t{3});
  CT_CHECK(history.value().front().is_head);
  CT_CHECK(history.value().front().chain_verified);
  CT_CHECK_EQ(history.value().front().parent_generation.value(), std::uint64_t{2});
  CT_CHECK(history.value().front().parent_digest == history.value()[1].digest);
  CT_CHECK_EQ(history.value().back().generation.value(), std::uint64_t{1});
  CT_CHECK(!history.value().back().is_head);

  // head() is exactly what was published, and load() returns the retained ones.
  const auto head = store.head();
  CT_REQUIRE(head.has_value());
  CT_CHECK_EQ(head.value().generation.value(), std::uint64_t{3});
  CT_CHECK_EQ(head.value().parent_generation.value(), std::uint64_t{2});
  CT_CHECK_EQ(head.value().evaluated_at.milliseconds(), std::int64_t{30});
  CT_CHECK(state_digest(head.value()) == previous_digest);
  for (std::uint64_t generation = 1; generation <= 3; ++generation) {
    const auto loaded = store.load(StateGeneration(generation));
    CT_REQUIRE(loaded.has_value());
    CT_CHECK_EQ(loaded.value().generation.value(), generation);
  }
  // Generation 0 is the empty-store sentinel, and the future is not a
  // generation this store committed.
  CT_CHECK_EQ(store.load(StateGeneration(0)).error().code(), ErrorCode::GenerationNotRetained);
  CT_CHECK_EQ(store.load(StateGeneration(4)).error().code(), ErrorCode::GenerationNotRetained);
  CT_CHECK(store.close().has_value());
}

CT_TEST(store_publish_reports_durable_only_with_a_successful_flush) {
  const std::string root = case_root("publish-durable");
  StoreOptions options = base_options(root);
  options.durable_flush = true;
  auto created = Store::create(options, StoreId::parse("store-1").value());
  CT_REQUIRE(created.has_value());
  Store store = std::move(created).value();
  const auto receipt = publish_or_abort(store, request_for(empty_state(5), "m-durable", 1));
  CT_CHECK_EQ(receipt.durability, dccp::cooling_failure_manager::PublicationDurability::Durable);
  // The durable head is readable after a close and a reopen, which is what the
  // durability claim buys.
  CT_CHECK(store.close().has_value());
  Store reopened = open_writer(root);
  const auto head = reopened.head();
  CT_REQUIRE(head.has_value());
  CT_CHECK_EQ(head.value().generation.value(), std::uint64_t{1});
  CT_CHECK(reopened.close().has_value());
}

CT_TEST(store_publish_is_deterministic_for_one_body_under_two_identities) {
  const std::string root = case_root("publish-determinism");
  Store store = create_fresh(root);
  const CoolingFailureState body = empty_state(44);
  const auto first = publish_or_abort(store, request_for(body, "m-one", 1));
  const auto second = publish_or_abort(store, request_for(body, "m-two", 1));

  // Two distinct mutations, two distinct generations: the store never confuses
  // "the same content" with "the same operation".
  CT_CHECK_EQ(first.generation.value(), std::uint64_t{1});
  CT_CHECK_EQ(second.generation.value(), std::uint64_t{2});
  CT_CHECK(!(first.digest == second.digest));
  const auto first_body = store.load(first.generation);
  const auto second_body = store.load(second.generation);
  CT_REQUIRE(first_body.has_value());
  CT_REQUIRE(second_body.has_value());
  CT_CHECK_EQ(first_body.value().evaluated_at.milliseconds(), std::int64_t{44});
  CT_CHECK_EQ(second_body.value().evaluated_at.milliseconds(), std::int64_t{44});
  // The request identity both attempts carry is the same, because it ignores the
  // generations the store assigned.
  CT_CHECK(internal::request_content_digest(first_body.value()) ==
           internal::request_content_digest(second_body.value()));
  CT_CHECK(store.close().has_value());
}

// ===========================================================================
// Integrity
// ===========================================================================

CT_TEST(store_detects_a_flipped_byte_in_the_head_generation_file) {
  const std::string root = case_root("integrity-flip");
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(9), "m-1", 1));
  CT_CHECK(store.close().has_value());

  const std::string generation_path = join_path(join_path(root, "generations"),
                                                internal::generation_file_name(StateGeneration(1)));
  CT_REQUIRE(file_exists(generation_path));
  // Flip a byte inside the body, past the header line.
  const std::string bytes = read_text_file(generation_path);
  CT_REQUIRE(bytes.size() > 200);
  flip_byte(generation_path, bytes.size() - 20);

  Store reopened = open_writer(root);
  const auto head = reopened.head();
  CT_REQUIRE(!head.has_value());
  // The head file is re-read and verified on every call: a payload whose digest
  // does not match is refused even though the manifest still points at it.
  CT_CHECK_EQ(head.error().code(), ErrorCode::DigestMismatch);
  const auto report = reopened.verify();
  CT_REQUIRE(report.has_value());
  CT_CHECK(!report.value().head_verified);
  CT_CHECK(!report.value().ok());
  CT_CHECK(!reopened.info().value().publication_allowed);
  CT_CHECK_EQ(reopened.publish(request_for(empty_state(10), "m-2", 1)).error().code(),
              ErrorCode::RecoveryRequired);
  CT_CHECK(reopened.close().has_value());
}

CT_TEST(store_detects_truncated_and_missing_generation_files) {
  // A file cut inside its header line has no header line at all.
  {
    const std::string root = case_root("integrity-truncated-header");
    Store store = create_fresh(root);
    publish_or_abort(store, request_for(empty_state(9), "m-1", 1));
    CT_CHECK(store.close().has_value());
    const std::string generation_path =
        join_path(join_path(root, "generations"),
                  internal::generation_file_name(StateGeneration(1)));
    const std::string whole = read_text_file(generation_path);
    CT_REQUIRE(whole.size() > 200);
    truncate_to(generation_path, 20);
    Store reopened = open_writer(root);
    const auto head = reopened.head();
    CT_REQUIRE(!head.has_value());
    CT_CHECK_EQ(head.error().code(), ErrorCode::TruncatedInput);
    const auto report = reopened.verify();
    CT_REQUIRE(report.has_value());
    CT_CHECK(!report.value().head_verified);
    CT_CHECK(!report.value().ok());
    CT_CHECK(reopened.close().has_value());
  }

  // A file cut inside its body loses the body terminator, which the decoder
  // refuses before it even looks at a digest.
  {
    const std::string root = case_root("integrity-truncated-body");
    Store store = create_fresh(root);
    publish_or_abort(store, request_for(empty_state(9), "m-1", 1));
    CT_CHECK(store.close().has_value());
    const std::string generation_path =
        join_path(join_path(root, "generations"),
                  internal::generation_file_name(StateGeneration(1)));
    const std::string whole = read_text_file(generation_path);
    CT_REQUIRE(whole.size() > 200);
    truncate_to(generation_path, whole.size() - 1);
    Store reopened = open_writer(root);
    const auto head = reopened.head();
    CT_REQUIRE(!head.has_value());
    CT_CHECK_EQ(head.error().code(), ErrorCode::TruncatedInput);
    CT_CHECK(reopened.close().has_value());
  }

  // A generation file that is gone cannot be served, and recover() refuses
  // because there is no retained previous publication to adopt.
  {
    const std::string root = case_root("integrity-missing-generation");
    Store store = create_fresh(root);
    publish_or_abort(store, request_for(empty_state(9), "m-1", 1));
    CT_CHECK(store.close().has_value());
    const std::string generation_path =
        join_path(join_path(root, "generations"),
                  internal::generation_file_name(StateGeneration(1)));
    const std::string whole = read_text_file(generation_path);
    std::error_code error;
    fs::remove(fs::path(generation_path), error);
    CT_REQUIRE(!file_exists(generation_path));

    Store reopened = open_writer(root);
    const auto head = reopened.head();
    CT_REQUIRE(!head.has_value());
    CT_CHECK_EQ(head.error().code(), ErrorCode::StoreNotFound);
    // The durable floor rose to generation 1 when that generation was committed,
    // so the only retained previous publication - the empty store - is below it
    // and is refused: recovery never rolls the store back past its own guard.
    const auto recovered = reopened.recover();
    CT_REQUIRE(!recovered.has_value());
    CT_CHECK_EQ(recovered.error().code(), ErrorCode::GenerationFloorViolation);
    CT_CHECK(reopened.close().has_value());

    // Putting the exact bytes back makes the store serve the head again: the
    // refusal was a read of durable state, never a mutation of it.
    write_text_file(generation_path, whole);
    Store restored = open_writer(root);
    const auto restored_head = restored.head();
    CT_REQUIRE(restored_head.has_value());
    CT_CHECK_EQ(restored_head.value().generation.value(), std::uint64_t{1});
    CT_CHECK(restored.close().has_value());
  }
}

CT_TEST(store_open_refuses_a_floor_above_the_head) {
  const std::string root = case_root("integrity-floor");
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(9), "m-1", 1));
  CT_CHECK(store.close().has_value());

  // A floor above the committed head is a rollback guard that forbids the state
  // the store is serving: it is refused outright, never repaired.
  const std::string floor_prefix = "dccp-cooling-failure-floor\t1\tfloor=5\tcount=1\t";
  write_text_file(join_path(root, "floor"),
                  floor_prefix + digest_bytes(floor_prefix).to_hex() + "\n");
  StoreOptions options = base_options(root);
  const auto opened = Store::open(options);
  CT_REQUIRE(!opened.has_value());
  CT_CHECK_EQ(opened.error().code(), ErrorCode::GenerationFloorViolation);
}

CT_TEST(store_open_refuses_a_manifest_that_cannot_be_trusted) {
  const std::string root = case_root("integrity-manifest");
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(9), "m-1", 1));
  const auto good_manifest = read_text_file(join_path(root, "manifest"));
  CT_REQUIRE(!good_manifest.empty());
  CT_CHECK(store.close().has_value());

  // A manifest whose checksum does not match is not a head record, so the
  // handle refuses to serve or publish until recover() adopts a publication.
  {
    const std::string manifest_path = join_path(root, "manifest");
    std::string damaged = good_manifest;
    damaged[damaged.size() - 2] = damaged[damaged.size() - 2] == '0' ? '1' : '0';
    write_text_file(manifest_path, damaged);
    Store opened = open_writer(root);
    const auto head = opened.head();
    CT_REQUIRE(!head.has_value());
    CT_CHECK_EQ(head.error().code(), ErrorCode::HeadCorrupt);
    CT_CHECK(!opened.info().value().publication_allowed);
    CT_CHECK_EQ(opened.publish(request_for(empty_state(10), "m-2", 1)).error().code(),
                ErrorCode::RecoveryRequired);
    CT_CHECK(opened.close().has_value());
    write_text_file(manifest_path, good_manifest);
  }

  // A manifest naming a generation that is not on disk cannot serve a head.
  {
    const std::string generation_path = join_path(join_path(root, "generations"),
                                                  internal::generation_file_name(StateGeneration(1)));
    const std::string bytes = read_text_file(generation_path);
    std::error_code error;
    fs::remove(fs::path(generation_path), error);
    CT_CHECK(!file_exists(generation_path));
    Store opened = open_writer(root);
    const auto head = opened.head();
    CT_REQUIRE(!head.has_value());
    CT_CHECK_EQ(head.error().code(), ErrorCode::StoreNotFound);
    CT_CHECK(!opened.info().value().publication_allowed);
    CT_CHECK(opened.close().has_value());
    write_text_file(generation_path, bytes);
  }

  // Restoring both records makes the store serve its head again: nothing was
  // repaired and nothing was rewritten, the records were simply put back.
  Store restored = open_writer(root);
  const auto head = restored.head();
  CT_REQUIRE(head.has_value());
  CT_CHECK_EQ(head.value().generation.value(), std::uint64_t{1});
  CT_CHECK(restored.close().has_value());
}

CT_TEST(store_refuses_a_generation_file_that_belongs_to_another_store) {
  // One case directory, derived once: case_directory empties it on every call,
  // so a second call would delete the store this case is about.
  const std::string directory = case_directory("integrity-foreign-store");
  const std::string root = join_path(directory, "store");
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(9), "m-1", 1));
  CT_CHECK(store.close().has_value());

  // A second store with its own identity, whose generation file is then planted
  // in the first store under the same generation number.
  const std::string other_root = join_path(directory, "other");
  StoreOptions other_options = base_options(other_root);
  auto other_created = Store::create(other_options, StoreId::parse("store-2").value());
  CT_REQUIRE(other_created.has_value());
  Store other = std::move(other_created).value();
  publish_or_abort(other, request_for(empty_state(11), "m-other", 1));
  CT_REQUIRE(other.close().has_value());

  const std::string foreign = read_text_file(
      join_path(join_path(other_root, "generations"),
                internal::generation_file_name(StateGeneration(1))));
  CT_REQUIRE(!foreign.empty());
  write_text_file(join_path(join_path(root, "generations"),
                            internal::generation_file_name(StateGeneration(1))),
                  foreign);

  Store reopened = open_writer(root);
  const auto head = reopened.head();
  CT_REQUIRE(!head.has_value());
  // The file verifies as a generation file, but it is not this store's
  // generation: an identity is never inferred from a file name.
  CT_CHECK_EQ(head.error().code(), ErrorCode::StoreMismatch);
  const auto report = reopened.verify();
  CT_REQUIRE(report.has_value());
  CT_CHECK(!report.value().ok());
  CT_CHECK(!report.value().head_verified);
  CT_CHECK(reopened.close().has_value());
}

CT_TEST(store_verify_reports_a_corrupt_retained_generation_deterministically) {
  const std::string root = case_root("integrity-retained");
  Store store = create_fresh(root);
  for (std::uint64_t generation = 1; generation <= 3; ++generation) {
    publish_or_abort(store, request_for(empty_state(static_cast<std::int64_t>(generation) * 10),
                                        "m-" + hex_of(generation), 1));
  }
  CT_CHECK(store.close().has_value());

  // Generation 2 is retained but no longer loadable: a deep verification reports
  // it and refuses to call the store healthy, while the head is untouched.
  const std::string damaged_path = join_path(join_path(root, "generations"),
                                             internal::generation_file_name(StateGeneration(2)));
  const std::string bytes = read_text_file(damaged_path);
  CT_REQUIRE(bytes.size() > 200);
  flip_byte(damaged_path, bytes.size() - 20);

  Store reopened = open_writer(root);
  const auto head = reopened.head();
  CT_REQUIRE(head.has_value());
  CT_CHECK_EQ(head.value().generation.value(), std::uint64_t{3});
  const auto report = reopened.verify();
  CT_REQUIRE(report.has_value());
  CT_CHECK(report.value().head_verified);
  CT_CHECK(!report.value().ok());
  CT_CHECK_EQ(report.value().generations_present, std::size_t{3});
  CT_CHECK_EQ(report.value().generations_verified, std::size_t{2});
  bool saw_unreadable = false;
  for (const dccp::cooling_failure_manager::VerifyFinding& finding : report.value().findings) {
    if (finding.code == "generation.unreadable" && finding.severity ==
                                                       dccp::cooling_failure_manager::VerifySeverity::Defect) {
      saw_unreadable = true;
    }
  }
  CT_CHECK(saw_unreadable);

  // The damaged generation is refused by load() as well, with the diagnosis the
  // file itself carries.
  const auto loaded = reopened.load(StateGeneration(2));
  CT_REQUIRE(!loaded.has_value());
  CT_CHECK_EQ(loaded.error().code(), ErrorCode::DigestMismatch);

  // Two verifications of one store produce the same findings in the same order.
  const auto again = reopened.verify();
  CT_REQUIRE(again.has_value());
  CT_REQUIRE(again.value().findings.size() == report.value().findings.size());
  for (std::size_t index = 0; index < report.value().findings.size(); ++index) {
    CT_CHECK_EQ(again.value().findings[index].code, report.value().findings[index].code);
    CT_CHECK_EQ(again.value().findings[index].subject, report.value().findings[index].subject);
    CT_CHECK_EQ(again.value().findings[index].severity, report.value().findings[index].severity);
  }
  CT_CHECK(reopened.close().has_value());
}

// ===========================================================================
// Retention
// ===========================================================================

CT_TEST(store_retention_retires_the_oldest_generations_and_keeps_the_chain) {
  const std::string root = case_root("retention");
  StoreOptions options = base_options(root);
  options.retained_generations = 2;
  auto created = Store::create(options, StoreId::parse("store-1").value());
  CT_REQUIRE(created.has_value());
  Store store = std::move(created).value();

  for (std::uint64_t generation = 1; generation <= 4; ++generation) {
    publish_or_abort(store, request_for(empty_state(static_cast<std::int64_t>(generation)),
                                        "m-" + hex_of(generation), 1));
  }

  // At most retained_generations whole generations survive, including the head.
  const std::vector<std::string> present = list_names(join_path(root, "generations"));
  CT_REQUIRE(present.size() == 2);
  CT_CHECK_EQ(present[0], internal::generation_file_name(StateGeneration(3)));
  CT_CHECK_EQ(present[1], internal::generation_file_name(StateGeneration(4)));

  // The manifest's retained chain matches the files on disk, and the retired
  // generations can no longer be loaded.
  const auto history = store.history();
  CT_REQUIRE(history.has_value());
  CT_CHECK_EQ(history.value().size(), std::size_t{2});
  CT_CHECK_EQ(history.value().front().generation.value(), std::uint64_t{4});
  CT_CHECK_EQ(history.value().back().generation.value(), std::uint64_t{3});
  CT_CHECK(history.value().front().chain_verified);
  CT_CHECK(history.value().back().chain_verified);
  CT_CHECK_EQ(store.load(StateGeneration(1)).error().code(), ErrorCode::GenerationNotRetained);
  CT_CHECK_EQ(store.load(StateGeneration(2)).error().code(), ErrorCode::GenerationNotRetained);
  CT_CHECK(store.load(StateGeneration(3)).has_value());
  CT_CHECK(store.load(StateGeneration(4)).has_value());

  // The durable floor advanced with the retention window: it is what makes the
  // retirement irreversible.
  const auto info = store.info();
  CT_REQUIRE(info.has_value());
  CT_CHECK_EQ(info.value().floor.value(), std::uint64_t{3});
  CT_CHECK_EQ(info.value().retained_generations, std::size_t{2});

  // A shallow verification of a healthy store reports no defect at all.
  dccp::cooling_failure_manager::VerifyOptions verify_options;
  verify_options.deep = true;
  const auto report = store.verify(verify_options);
  CT_REQUIRE(report.has_value());
  CT_CHECK(report.value().ok());
  CT_CHECK(report.value().head_verified);
  CT_CHECK(report.value().manifest_verified);
  CT_CHECK(report.value().floor_verified);
  CT_CHECK(report.value().chain_verified);
  CT_CHECK(report.value().canonical_fixed_point_verified);
  CT_CHECK_EQ(report.value().generations_present, std::size_t{2});
  CT_CHECK_EQ(report.value().generations_verified, std::size_t{2});
  CT_CHECK_EQ(report.value().unreferenced_generations_found, std::size_t{0});
  CT_CHECK_EQ(report.value().orphan_generations_found, std::size_t{0});
  CT_CHECK_EQ(report.value().staged_residue_found, std::size_t{0});
  CT_CHECK_EQ(report.value().quarantined_found, std::size_t{0});
  CT_CHECK_EQ(report.value().unresolved_attempts_found, std::size_t{0});
  CT_CHECK(report.value().publication_allowed);
  CT_CHECK(store.close().has_value());
}

// ===========================================================================
// Authority fencing
// ===========================================================================

CT_TEST(store_fences_stale_epoch_incarnation_and_base_generation) {
  const std::string root = case_root("fencing");
  Store store = create_fresh(root);
  publish_or_abort(store, request_for(empty_state(1), "m-1", 1));

  {
    PublicationRequest request = request_for(empty_state(2), "m-2", 1);
    request.epoch = dccp::cooling_failure_manager::WriterEpoch(store.epoch().value() + 100);
    request.incarnation = store.incarnation();
    const auto refused = store.publish(request);
    CT_REQUIRE(!refused.has_value());
    CT_CHECK_EQ(refused.error().code(), ErrorCode::StaleAuthorityEpoch);
  }
  {
    PublicationRequest request = request_for(empty_state(2), "m-3", 1);
    request.epoch = store.epoch();
    request.incarnation =
        dccp::cooling_failure_manager::WriterIncarnation(store.incarnation().value() + 100);
    const auto refused = store.publish(request);
    CT_REQUIRE(!refused.has_value());
    CT_CHECK_EQ(refused.error().code(), ErrorCode::StaleWriterIncarnation);
  }
  {
    // A base generation the store never committed describes state that does not
    // exist here; the direction of the fence is "must not exceed the head".
    PublicationRequest request = request_for(empty_state(2), "m-4", 1);
    request.epoch = store.epoch();
    request.incarnation = store.incarnation();
    request.base_generation = StateGeneration(2);
    const auto refused = store.publish(request);
    CT_REQUIRE(!refused.has_value());
    CT_CHECK_EQ(refused.error().code(), ErrorCode::StaleBaseGeneration);
  }
  // A zero epoch and a zero incarnation mean "unfenced" and are accepted.
  {
    PublicationRequest request = request_for(empty_state(2), "m-5", 1);
    const auto accepted = store.publish(request);
    CT_REQUIRE(accepted.has_value());
    CT_CHECK_EQ(accepted.value().generation.value(), std::uint64_t{2});
  }
  // A base below the head with different content is a new mutation over newer
  // state, and it is accepted.
  {
    PublicationRequest request = request_for(empty_state(3), "m-6", 1);
    request.epoch = store.epoch();
    request.incarnation = store.incarnation();
    request.base_generation = StateGeneration(1);
    const auto accepted = store.publish(request);
    CT_REQUIRE(accepted.has_value());
    CT_CHECK_EQ(accepted.value().generation.value(), std::uint64_t{3});
    CT_CHECK_EQ(accepted.value().parent_generation.value(), std::uint64_t{2});
  }
  CT_CHECK(store.close().has_value());
}

}  // namespace
