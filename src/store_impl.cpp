// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The durable store: OS-level single-writer exclusion, transactional
// publication with exactly one commit point, verification and conservative
// recovery.
//
// Decisions the public documentation leaves to the implementation are fixed
// here once and applied consistently everywhere:
//
//  * A fresh store has NO committed generation. Its manifest records head = 0,
//    a zero head digest, parent = 0, commit = 0, floor = 0 and exactly one
//    retained entry describing generation 0 with every field zero. That sentinel
//    is the only shape accepted as "no state yet": head() reports HeadMissing and
//    load() reports GenerationNotRetained for generation 0, and
//    head_verified is true for it only because every one of its fields is zero.
//  * open() NEVER adopts manifest.prev. When the committed head cannot be
//    verified, open() still returns a handle - recover() has to be reachable -
//    but that handle carries epoch 0, incarnation 0 and
//    publication_allowed == false, and head(), load() and history() keep failing
//    with HeadCorrupt while publish() fails with RecoveryRequired until
//    recover() adopts a publication. Authority is never reserved against an
//    unverified head, so the documented "reserve the next epoch before returning
//    the handle" holds for every handle that can actually publish.
//  * recover() refuses to adopt when manifest.prev is missing, unreadable or
//    byte-identical to manifest; all three are RecoveryUnavailable, because in
//    each case nothing can be adopted. Adoption below the durable floor is
//    GenerationFloorViolation. recover() on a read-only handle is StoreReadOnly:
//    an adoption that cannot be committed must never be reported as one. When
//    the head is healthy the call is NoAction and changes nothing at all.
//  * reconcile_unresolved() resolves its mutation identity first and reports the
//    number of attempts the recorded state carries as Unresolved with
//    adopted_after_restart set. A replay therefore reports exactly what the first
//    execution reported and never reconciles twice, even after the head moved on
//    and even when nothing is in flight any more. A first call that finds nothing
//    in flight publishes nothing at all and reports zero. A replay whose recorded
//    publication has since been retired is GenerationNotRetained: the number it
//    reported is no longer readable, and reporting zero would be a lie.
//  * The reconciliation clock is the head state's evaluated_at. A DecisionClock
//    belongs to one publication, and no newer authority exists, so restamping a
//    reconciled attempt with any other clock would invent an observation time.
//  * The base-generation fence refuses a base ABOVE the committed head
//    (StaleBaseGeneration). A base below the head is accepted, because the
//    mutation is then a new publication over newer state. docs/FORMATS.md
//    section 2.5 step 3 phrases the same fence the other way round ("must be >=
//    the committed head"); the workstream contract for this store fixes the
//    direction implemented here, which is the only one under which the
//    documented "a base generation below the head is accepted as a new mutation"
//    behaviour can hold.
//  * The accepted-attempt record of a publication is carried inside the retained
//    manifest entry that commits it, so the mutation and the identity that makes
//    its retry a replay become durable at the same instant, by the same single
//    atomic replacement. There is no longer any step after the commit point that
//    writes replay bookkeeping, and therefore no crash boundary at which a
//    mutation is committed while a retry of it would be mistaken for a new
//    mutation. The replay window is the newest min(retained_generations,
//    idempotency_retention) entries of the committed manifest, recorded in the
//    manifest itself; see docs/FORMATS.md section 2.2.
//  * A failure AFTER the commit point (the floor, retirement, cleanup) cannot
//    un-commit the head. It downgrades durability to NotDurable and is reported
//    through verify(); it never turns a committed publication into a failed
//    call, because that would invite a retry that publishes a second generation
//    for one logical mutation.
//
// Concurrency audit. A handle owns exactly one file lock. It is taken in
// create()/open() and released by close() and by the destructor; no other
// function in this translation unit acquires anything, so the lock is never
// re-acquired and cannot be acquired twice. No callback runs while it is held
// (there are no callbacks), no worker thread is created, started, joined or
// detached, and no state is shared between threads, so there is no lock
// ordering, no lock inversion and no shutdown ordering to get wrong. Every
// reference handed out (a decoded CoolingFailureState) owns its bytes: nothing
// returned aliases republished state, and no view outlives the lock.

#include "dccp/cooling_failure_manager/store.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dccp/cooling_failure_manager/canonical.hpp"
#include "dccp/cooling_failure_manager/digest.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/text.hpp"
#include "file_ops.hpp"
#include "store_files.hpp"
#include "store_internal.hpp"

namespace dccp::cooling_failure_manager {
namespace {

constexpr char kSeparator =
#if defined(_WIN32)
    '\\';
#else
    '/';
#endif

/// Directory holding generation files that recovery moved aside. It is created
/// on demand; its presence is reported by verify() and its content is never
/// adopted, never loaded and never counted as retained.
constexpr const char* kQuarantineDirectoryName = "quarantine";

/// Documented fault-injection stages of this store. Each one terminates the
/// process at a publication boundary so the crash behaviour of docs/FORMATS.md
/// section 2.5 can be proven with a real process.
///   open.after-lock          the writer lock is held, nothing was written
///   open.after-reserve       the next epoch and incarnation are durable
///   publish.enter            publish() entered, before its first read or write
///   publish.after-stage      the staged generation file is written and flushed
///   publish.before-rename    the staged file was read back and verified
///   publish.after-rename     the generation file is in generations/
///   publish.before-manifest  manifest.prev is durable, the head is not committed
///   publish.before-commit-entry  the head record is durable beside its target, not committed
///   publish.after-commit-entry   the head record was replaced: the commit point
///   publish.after-manifest   the in-memory head moved onto the committed record
///   publish.before-floor     the in-memory head moved, the floor is not written
///   publish.after-floor      the durable floor advanced
///   publish.after-commit     the whole publication is committed; nothing else is written
///   publish.after-retire     retirement and staging cleanup finished
constexpr const char* kFaultOpenAfterLock = "open.after-lock";
constexpr const char* kFaultOpenAfterReserve = "open.after-reserve";
constexpr const char* kFaultPublishEnter = "publish.enter";
constexpr const char* kFaultPublishAfterStage = "publish.after-stage";
constexpr const char* kFaultPublishBeforeRename = "publish.before-rename";
constexpr const char* kFaultPublishAfterRename = "publish.after-rename";
constexpr const char* kFaultPublishBeforeManifest = "publish.before-manifest";
constexpr const char* kFaultPublishAfterManifest = "publish.after-manifest";
constexpr const char* kFaultPublishBeforeFloor = "publish.before-floor";
constexpr const char* kFaultPublishAfterFloor = "publish.after-floor";
constexpr const char* kFaultPublishBeforeCommitEntry = "publish.before-commit-entry";
constexpr const char* kFaultPublishAfterCommitEntry = "publish.after-commit-entry";
constexpr const char* kFaultPublishAfterCommit = "publish.after-commit";
constexpr const char* kFaultPublishAfterRetire = "publish.after-retire";

std::string join(const std::string& root, std::string_view name) {
  std::string out = root;
  out.push_back(kSeparator);
  out.append(name);
  return out;
}

/// Stable finding codes. They are part of the verification report contract, so
/// an existing code is never renamed or repurposed.
constexpr std::string_view kFindingFloorMissing = "floor.missing";
constexpr std::string_view kFindingFloorUnreadable = "floor.unreadable";
constexpr std::string_view kFindingManifestMissing = "manifest.missing";
constexpr std::string_view kFindingManifestUnreadable = "manifest.unreadable";
constexpr std::string_view kFindingManifestHeadMismatch = "manifest.head.mismatch";
constexpr std::string_view kFindingFloorManifestMismatch = "floor.manifest.mismatch";
constexpr std::string_view kFindingFloorHeadViolation = "floor.head.violation";
constexpr std::string_view kFindingHeadMissing = "head.missing";
constexpr std::string_view kFindingHeadDigestMismatch = "head.digest.mismatch";
constexpr std::string_view kFindingHeadUnverified = "head.unverified";
constexpr std::string_view kFindingHeadStructureInvalid = "head.structure.invalid";
constexpr std::string_view kFindingHeadStoreMismatch = "head.store.mismatch";
constexpr std::string_view kFindingChainParentMismatch = "chain.parent.mismatch";
constexpr std::string_view kFindingChainGap = "chain.gap";
constexpr std::string_view kFindingGenerationFixedPoint = "generation.fixedpoint.mismatch";
constexpr std::string_view kFindingGenerationUnreadable = "generation.unreadable";
constexpr std::string_view kFindingGenerationNameInvalid = "generation.name.invalid";
constexpr std::string_view kFindingGenerationOrphan = "generation.orphan";
constexpr std::string_view kFindingGenerationUnreferenced = "generation.unreferenced";
constexpr std::string_view kFindingStagingResidue = "staging.residue";
constexpr std::string_view kFindingStagingUnreadable = "staging.unreadable";
constexpr std::string_view kFindingUnexpectedEntry = "store.entry.unexpected";
constexpr std::string_view kFindingQuarantine = "quarantine.present";
constexpr std::string_view kFindingAttemptUnresolved = "attempt.unresolved";
constexpr std::string_view kFindingIdempotencyUnreadable = "idempotency.unreadable";
constexpr std::string_view kFindingReplayDuplicate = "replay.duplicate";
constexpr std::string_view kFindingReplayInconsistent = "replay.inconsistent";

/// True when a directory entry name is one of this store's own staged names. A
/// staged name is derived from its target name and always ends in ".staged", so
/// it can never be mistaken for a generation file name, which ends in ".dat".
bool is_staged_name(std::string_view name) noexcept {
  return name.size() > 7 && name.substr(name.size() - 7) == ".staged";
}

/// True when an attempt is in flight: it was issued, or acknowledged, or an
/// effect was observed, and no outcome has been committed for it yet. Only these
/// three states block a fresh publication, because only they can still be
/// answered by a response this component has not recorded.
bool attempt_in_flight(AttemptState state) noexcept {
  return state == AttemptState::Solicited || state == AttemptState::Acknowledged ||
         state == AttemptState::EffectObserved;
}

/// True when a restart must record the attempt as Unresolved. Planned is
/// included: an attempt that was created but never issued cannot be assumed
/// issued, and cannot be assumed un-issued either once its owner is gone.
bool attempt_reconcilable(AttemptState state) noexcept {
  return state == AttemptState::Planned || attempt_in_flight(state);
}

const ResponseAttempt* find_attempt_in_state(const CoolingFailureState& state,
                                             const AttemptId& id) noexcept {
  for (const ResponsePlan& plan : state.plans) {
    for (const ResponseAttempt& attempt : plan.attempts) {
      if (attempt.id == id) {
        return &attempt;
      }
    }
  }
  return nullptr;
}

/// Attempts the state still holds in flight, in the canonical plan order.
std::vector<AttemptId> in_flight_attempts(const CoolingFailureState& state) {
  std::vector<AttemptId> ids;
  for (const ResponsePlan& plan : state.plans) {
    for (const ResponseAttempt& attempt : plan.attempts) {
      if (attempt_in_flight(attempt.state)) {
        ids.push_back(attempt.id);
      }
    }
  }
  return ids;
}

/// True when the candidate body either drops one of the in-flight attempts or
/// carries it in a different state. That is the documented condition under which
/// a publication is allowed while the head still holds in-flight attempts.
bool body_changes_any_attempt(const CoolingFailureState& body,
                              const std::vector<AttemptId>& ids) noexcept {
  for (const AttemptId& id : ids) {
    const ResponseAttempt* candidate = find_attempt_in_state(body, id);
    if (candidate == nullptr || !attempt_in_flight(candidate->state)) {
      return true;
    }
  }
  return false;
}

/// Attempts the state reports as adopted after a restart and still unresolved.
std::size_t count_adopted_unresolved(const CoolingFailureState& state) noexcept {
  std::size_t count = 0;
  for (const ResponsePlan& plan : state.plans) {
    for (const ResponseAttempt& attempt : plan.attempts) {
      if (attempt.state == AttemptState::Unresolved && attempt.adopted_after_restart) {
        ++count;
      }
    }
  }
  return count;
}

Result<void> validate_store_bounds(const StoreOptions& options) {
  if (options.retained_generations == 0 ||
      options.retained_generations > limits::kMaxRetainedGenerations) {
    return Error(ErrorCode::LimitExceeded,
                 "retained_generations must be between 1 and the documented bound");
  }
  if (options.idempotency_retention == 0 ||
      options.idempotency_retention > limits::kMaxIdempotencyRecords) {
    return Error(ErrorCode::LimitExceeded,
                 "idempotency_retention must be between 1 and the documented bound");
  }
  return ok();
}

/// Removes the staged generation file when the publication did not consume it.
/// Staged content is never authoritative, so leaving it behind would be safe but
/// untidy; the guard keeps the ordinary failure paths clean while a process death
/// leaves the residue that the crash tests assert on.
class StagedFileGuard {
 public:
  explicit StagedFileGuard(std::string path) : path_(std::move(path)) {}
  ~StagedFileGuard() {
    if (!consumed_ && !path_.empty()) {
      (void)internal::remove_file(path_);
    }
  }
  StagedFileGuard(const StagedFileGuard&) = delete;
  StagedFileGuard& operator=(const StagedFileGuard&) = delete;

  void consume() noexcept { consumed_ = true; }

 private:
  std::string path_;
  bool consumed_ = false;
};

}  // namespace

// ---------------------------------------------------------------------------
// Store::Impl
// ---------------------------------------------------------------------------

struct Store::Impl {
  ~Impl() {
    // The destructor must never throw. The lock is released here explicitly as
    // well as by FileLock's own destructor, so no path can leak it.
    if (lock.held()) {
      (void)lock.release();
    }
  }

  StoreOptions options;
  std::string root;
  std::string generations_path;
  std::string idempotency_path;
  std::string staging_path;
  std::string quarantine_path;
  internal::FileLock lock;
  /// The manifest this handle serves. It is the committed record read at open()
  /// and updated after each successful publication; every read of authoritative
  /// content re-reads and re-verifies the file instead of trusting it.
  internal::Manifest manifest;
  /// Authority of this handle, reserved durably in open() for a writable handle.
  /// Zero means "no authority was reserved", which is the case for every
  /// read-only handle and for a writable handle whose head could not be
  /// verified.
  WriterEpoch epoch{};
  WriterIncarnation incarnation{};
  bool open = false;
  bool writable = false;
  /// The manifest on disk decoded when this handle was opened (or repaired).
  bool manifest_readable = false;
  bool head_verified = false;
  StoreOpenState open_state = StoreOpenState::Reopened;
  /// Why the committed head is not verified. Diagnostics only; it is never
  /// parsed and never decides anything.
  std::string recovery_reason;

  std::string manifest_path() const { return join(root, internal::kManifestFileName); }
  std::string manifest_previous_path() const { return join(root, internal::kPreviousManifestFileName); }
  std::string floor_path() const { return join(root, internal::kFloorFileName); }
  std::string lock_path() const { return join(root, internal::kLockFileName); }

  Result<void> require_open() const {
    if (!open) {
      return Error(ErrorCode::StoreClosed, "store handle is closed");
    }
    return ok();
  }

  Result<void> require_writable() const {
    CFM_TRYV(require_open());
    if (!writable) {
      return Error(ErrorCode::StoreReadOnly, "store handle was opened read-only");
    }
    return ok();
  }

  /// The handle may serve and mutate state only when the committed head verified.
  Result<void> require_head() const {
    CFM_TRYV(require_open());
    if (!head_verified) {
      return Error(ErrorCode::RecoveryRequired,
                   "the committed head is not verified; recover() must adopt a publication "
                   "before this handle can serve or publish state")
          .with_detail(recovery_reason);
    }
    return ok();
  }

  /// Reads and decodes the durable floor. The floor is the rollback guard: a head
  /// below it is refused, so a floor that cannot be read is never replaced by
  /// "no floor at all".
  Result<StateGeneration> read_floor() const {
    const auto bytes = internal::read_file(floor_path(), limits::kMaxManifestBytes);
    if (!bytes.has_value()) {
      return Error(ErrorCode::IntegrityFailure,
                   "the durable generation floor is missing or unreadable")
          .with_detail(bytes.error().to_string());
    }
    return internal::decode_floor(bytes.value());
  }

  /// Publishes one record as its target through exactly one atomic
  /// directory-entry replacement. This is the commit step of every durable
  /// record the store owns: the head manifest, the floor, an accepted-attempt
  /// record and a generation file.
  ///
  /// The store owns its staging design, and the replacement primitive this store
  /// builds on guarantees a replacement only between two names inside one
  /// directory. The record is therefore written beside its target and the target
  /// is replaced with it, which is the common path and the one the header
  /// guarantees. When that replacement is refused, the record is written into the
  /// documented staging area as well and the replacement is completed by renaming
  /// the copy that already sits beside the target; the staging copy is removed
  /// once the replacement is durable. Neither copy survives a success, and the
  /// commit is one atomic directory-entry replacement on both paths.
  ///
  /// A crash can leave at most a "<target name>.staged" entry. It is never
  /// authoritative: verification reports it as staged residue and the next
  /// publication or recovery removes it.
  Result<void> publish_content(const std::string& target, std::string_view content,
                               std::size_t max_bytes, bool durable) {
    const std::string beside = target + ".staged";
    CFM_TRYV(internal::write_file(beside, content, durable));
    CFM_TRY(readback, internal::read_file(beside, max_bytes));
    if (readback != content) {
      (void)internal::remove_file(beside);
      return Error(ErrorCode::PublicationIncomplete,
                   "the staged copy does not match what was written")
          .with_subject(target);
    }
    const Result<void> replaced = internal::atomic_replace(target, beside, durable);
    if (replaced.has_value()) {
      return ok();
    }
    // Fallback: the documented staging area is used as well, and the replacement
    // is completed by renaming the copy that already sits beside the target.
    const std::size_t separator = target.find_last_of("/\\");
    const std::string name = separator == std::string::npos ? target : target.substr(separator + 1);
    const std::string staged = join(staging_path, name + ".staged");
    const Result<void> staging_written = internal::write_file(staged, content, durable);
    const Result<void> renamed = internal::rename_within_directory(beside, target, durable);
    if (renamed.has_value()) {
      (void)internal::remove_file(staged);
      return ok();
    }
    (void)internal::remove_file(beside);
    if (replaced.error().code() != ErrorCode::InvalidArgument) {
      return replaced.error();
    }
    if (!staging_written.has_value()) {
      return staging_written.error();
    }
    return renamed.error();
  }

  /// Durably writes the head record through a staging file and an atomic
  /// replacement. This is the commit point of a publication.
  /// Replaces the head manifest. When the caller is publishing a mutation, the
  /// two boundaries that bracket the commit are distinct fault stages, because
  /// the invariant this store guarantees is decided exactly between them: the
  /// replacement is one atomic directory-entry operation, so the head record is
  /// either entirely the previous publication or entirely the new one, and the
  /// replay record of the new publication is inside it either way. Reserving the
  /// writer epoch on open and committing a recovery also replace the manifest,
  /// but neither is the commit point of a mutation, so neither is instrumented.
  Result<void> write_manifest(const internal::Manifest& value, bool durable,
                              bool is_publication_commit) {
    const std::string content = internal::encode_manifest(value);
    if (content.size() > limits::kMaxManifestBytes) {
      return Error(ErrorCode::LimitExceeded, "manifest exceeds the documented bound");
    }
    if (is_publication_commit) {
      internal::fault_point(options.enable_fault_injection, kFaultPublishBeforeCommitEntry);
    }
    CFM_TRYV(publish_content(manifest_path(), content, limits::kMaxManifestBytes, durable));
    if (is_publication_commit) {
      internal::fault_point(options.enable_fault_injection, kFaultPublishAfterCommitEntry);
    }
    return ok();
  }

  /// Durably advances the floor. The floor is monotone: nothing here can lower
  /// it, and a request to lower it is refused instead of written.
  Result<void> write_floor(StateGeneration floor, CommitSequence count, bool durable) {
    if (floor < manifest.floor) {
      return Error(ErrorCode::GenerationFloorViolation,
                   "the generation floor is monotone and cannot decrease")
          .with_subject(to_decimal(floor.value()));
    }
    const std::string content = internal::encode_floor(floor, count);
    CFM_TRYV(publish_content(floor_path(), content, limits::kMaxManifestBytes, durable));
    return ok();
  }

  std::string generation_path(StateGeneration generation) const {
    return join(generations_path, internal::generation_file_name(generation));
  }

  /// Reads, verifies and decodes one generation file for a named store. Every
  /// read of authoritative content goes through here, so no path can serve a
  /// payload that was not integrity-checked in this call. The expected store is a
  /// parameter rather than a field because verification judges a manifest that is
  /// not necessarily the one this handle was opened with.
  Result<internal::GenerationFile> load_generation_for(StateGeneration generation,
                                                      const StoreId& expected_store) const {
    const std::string path = generation_path(generation);
    const auto bytes = internal::read_file(path, limits::kMaxGenerationFileBytes);
    if (!bytes.has_value()) {
      Error error = bytes.error();
      error.with_detail("while reading " + path);
      return error;
    }
    const auto decoded = internal::decode_generation_file(bytes.value());
    if (!decoded.has_value()) {
      Error error = decoded.error();
      error.with_detail("while reading " + path);
      return error;
    }
    if (decoded.value().store_id != expected_store) {
      return Error(ErrorCode::StoreMismatch, "generation file belongs to another store")
          .with_subject(decoded.value().store_id.str())
          .with_detail("this store is " + expected_store.str());
    }
    if (decoded.value().generation != generation) {
      return Error(ErrorCode::GenerationMismatch,
                   "generation file declares a different generation than its name")
          .with_subject(to_decimal(generation.value()));
    }
    return decoded.value();
  }

  /// Reads one generation file of the store this handle serves.
  Result<internal::GenerationFile> load_generation(StateGeneration generation) const {
    return load_generation_for(generation, manifest.store_id);
  }

  /// Verifies one committed publication completely: the file, its identity, its
  /// recorded digest, its structure and - through decode - its canonical fixed
  /// point. Used by open(), verify() and recover().
  Result<void> verify_publication(const internal::Manifest& value) const {
    if (!value.head.published()) {
      return ok();
    }
    CFM_TRY(file, load_generation_for(value.head, value.store_id));
    if (file.digest != value.head_digest) {
      return Error(ErrorCode::DigestMismatch,
                   "the committed head digest does not match the head generation file")
          .with_subject(to_decimal(value.head.value()));
    }
    CFM_TRYV(validate_structure(file.body));
    // The manifest records the byte size of the canonical body; the generation
    // file records it independently. A disagreement means one of the two records
    // was edited, so the head is not verified.
    const std::string canonical = encode_state(file.body);
    if (canonical.size() != value.bytes) {
      return Error(ErrorCode::CountMismatch,
                   "the committed head byte count does not match its canonical body")
          .with_subject("manifest " + to_decimal(value.bytes) + ", body " +
                        to_decimal(canonical.size()));
    }
    return ok();
  }

  /// Re-reads one generation file and re-encodes the payload it carries,
  /// comparing the result byte for byte with the body the file actually holds.
  /// This is the canonical fixed point check: a decoder that accepted a
  /// non-canonical spelling of a state would be caught here rather than at the
  /// next publication.
  Result<void> verify_canonical_fixed_point(StateGeneration generation) const {
    const std::string path = generation_path(generation);
    CFM_TRY(raw, internal::read_file(path, limits::kMaxGenerationFileBytes));
    const std::size_t header_end = raw.find('\n');
    if (header_end == std::string::npos) {
      return Error(ErrorCode::TruncatedInput, "generation file has no header line")
          .with_detail("while reading " + path);
    }
    CFM_TRY(file, internal::decode_generation_file(raw));
    const std::string_view body = std::string_view(raw).substr(header_end + 1);
    if (encode_state(file.body) != body) {
      return Error(ErrorCode::IntegrityFailure,
                   "the decoded payload does not re-encode to the bytes the file carries")
          .with_detail("while reading " + path);
    }
    return ok();
  }

  /// The verified head state. Only reachable when head_verified is set, and it
  /// re-reads and re-verifies the file on every call.
  Result<CoolingFailureState> head_state() const {
    CFM_TRYV(require_head());
    if (!manifest.head.published()) {
      return Error(ErrorCode::HeadMissing,
                   "the store holds no published state yet (generation 0)");
    }
    CFM_TRY(file, load_generation(manifest.head));
    if (file.digest != manifest.head_digest) {
      return Error(ErrorCode::DigestMismatch,
                   "the committed head digest does not match the head generation file");
    }
    CFM_TRYV(validate_structure(file.body));
    return file.body;
  }

  /// Every generation file present, as (generation, name), ascending by
  /// generation. A name that is not a canonical generation name is reported by
  /// verify() and skipped here, because retirement must never delete what it
  /// cannot name.
  Result<std::vector<std::pair<StateGeneration, std::string>>> list_generations() const {
    CFM_TRY(names, internal::list_directory(generations_path));
    std::vector<std::pair<StateGeneration, std::string>> present;
    for (const std::string& name : names) {
      const auto generation = internal::parse_generation_file_name(name);
      if (!generation.has_value()) {
        continue;
      }
      present.emplace_back(generation.value(), name);
    }
    std::sort(present.begin(), present.end(), [](const auto& lhs, const auto& rhs) {
      if (lhs.first != rhs.first) {
        return lhs.first < rhs.first;
      }
      return lhs.second < rhs.second;
    });
    return present;
  }

  /// The receipt of an attempt that was already accepted. It reports what was
  /// recorded and the head as it stands now; it never re-derives a generation and
  /// never writes anything.
  PublicationReceipt replay_receipt(const internal::AttemptRecord& record,
                                    const PublicationRequest& request) const {
    PublicationReceipt receipt;
    receipt.generation = record.generation;
    // Every publication reserves committed head + 1, so the parent of the
    // recorded generation is its immediate predecessor. The record does not
    // carry the parent itself, and this derivation is exact rather than
    // approximate: no publication can skip a generation number.
    receipt.parent_generation =
        record.generation.published() ? StateGeneration(record.generation.value() - 1)
                                      : StateGeneration();
    receipt.digest = record.digest;
    receipt.mutation = request.mutation;
    receipt.attempt = request.attempt;
    receipt.commit_sequence = record.commit;
    receipt.replayed = true;
    receipt.head_after = manifest.head;
    receipt.head_digest_after = manifest.head_digest;
    receipt.durability = options.durable_flush ? PublicationDurability::Durable
                                               : PublicationDurability::NotDurable;
    return receipt;
  }

  /// The accepted-attempt records the committed authority carries for one
  /// mutation identity, newest first. The table holds at most one record per
  /// identity, so this holds at most one.
  std::vector<internal::AttemptRecord> manifest_attempts_for(const MutationId& mutation) const {
    std::vector<internal::AttemptRecord> found;
    for (const internal::AttemptRecord& record : manifest.attempts) {
      if (record.mutation == mutation) {
        found.push_back(record);
      }
    }
    return found;
  }

  /// The accepted-attempt files of a store written by release 1.0.0, for one
  /// mutation identity, ordered by the file name so the answer never depends on
  /// directory enumeration order.
  Result<std::vector<internal::AttemptRecord>> legacy_attempts_for(
      const MutationId& mutation) const {
    std::vector<internal::AttemptRecord> found;
    CFM_TRY(names, internal::list_directory(idempotency_path));
    std::vector<std::string> ordered(names.begin(), names.end());
    std::sort(ordered.begin(), ordered.end());
    for (const std::string& name : ordered) {
      const auto bytes =
          internal::read_file(join(idempotency_path, name), limits::kMaxIdempotencyRecordBytes);
      if (!bytes.has_value()) {
        continue;
      }
      const auto record = internal::decode_attempt_record(bytes.value());
      if (!record.has_value()) {
        continue;
      }
      if (record.value().mutation == mutation) {
        found.push_back(record.value());
      }
    }
    return found;
  }

  /// The accepted-attempt record the committed authority carries for one
  /// identity, or a record whose mutation is empty when this store holds none.
  ///
  /// The manifest is the authority: it is where a publication records its own
  /// replay identity, so a mutation that crossed the commit point is found here
  /// however the process died afterwards. The accepted-attempt files of release
  /// 1.0.0 are consulted after it, for an identity the manifest does not carry at
  /// all. They are never consulted for an identity the manifest does carry, so an
  /// upgraded store is never answered from a superseded record, and a store that
  /// has not published since the upgrade is answered from the files alone.
  Result<internal::AttemptRecord> find_accepted_attempt(const MutationId& mutation,
                                                        const AttemptOrdinal& attempt) const {
    for (const internal::AttemptRecord& record : manifest_attempts_for(mutation)) {
      if (record.ordinal == attempt) {
        return record;
      }
    }
    if (!manifest_attempts_for(mutation).empty()) {
      // The identity is known to the authority and this ordinal is not one it
      // accepted, so the answer is "no record" rather than an older file's word.
      return internal::AttemptRecord{};
    }
    CFM_TRY(legacy, legacy_attempts_for(mutation));
    for (const internal::AttemptRecord& record : legacy) {
      if (record.ordinal == attempt) {
        return record;
      }
    }
    return internal::AttemptRecord{};
  }

  /// True when an accepted-attempt record for the same mutation but a strictly
  /// higher ordinal exists. Attempt ordinals are 1-based and must not go
  /// backwards: an ordinal below an accepted one is a reused identity, never a
  /// new attempt.
  ///
  /// The highest ordinal either source records is what the new ordinal must
  /// exceed. Both sources are consulted because an identity the authority carries
  /// may also have a record from before the upgrade, and the rule is about the
  /// identity rather than about which record is newer: an ordinal below any
  /// accepted ordinal is a reused identity whichever record carries it.
  Result<bool> has_accepted_newer_ordinal(const MutationId& mutation,
                                          const AttemptOrdinal& attempt) const {
    for (const internal::AttemptRecord& record : manifest_attempts_for(mutation)) {
      if (attempt < record.ordinal) {
        return true;
      }
    }
    CFM_TRY(legacy, legacy_attempts_for(mutation));
    for (const internal::AttemptRecord& record : legacy) {
      if (attempt < record.ordinal) {
        return true;
      }
    }
    return false;
  }

  /// Removes generation files that are outside the committed window: below the
  /// durable floor, or newer than the committed head (orphans of an interrupted
  /// publication). Orphans are never adopted, so they are removed here rather
  /// than left to be mistaken for state.
  Result<std::size_t> retire_outside_window(StateGeneration floor, StateGeneration head) {
    CFM_TRY(present, list_generations());
    std::size_t removed = 0;
    for (const auto& entry : present) {
      if (entry.first < floor || head < entry.first) {
        CFM_TRYV(internal::remove_file(join(generations_path, entry.second)));
        ++removed;
      }
    }
    return removed;
  }

  /// Removes staging residue: staged content is never authoritative, because a
  /// publication always writes a fresh staging file and renames it into place.
  /// Staged copies that a fallback placement left beside a target are removed
  /// too, so no uncommitted content survives a successful publication.
  Result<std::size_t> remove_staging_residue() {
    CFM_TRY(names, internal::list_directory(staging_path));
    std::size_t removed = 0;
    for (const std::string& name : names) {
      if (internal::remove_file(join(staging_path, name)).has_value()) {
        ++removed;
      }
    }
    const auto generations = internal::list_directory(generations_path);
    if (generations.has_value()) {
      for (const std::string& name : generations.value()) {
        if (is_staged_name(name) && internal::remove_file(join(generations_path, name)).has_value()) {
          ++removed;
        }
      }
    }
    const auto idem = internal::list_directory(idempotency_path);
    if (idem.has_value()) {
      for (const std::string& name : idem.value()) {
        if (is_staged_name(name) && internal::remove_file(join(idempotency_path, name)).has_value()) {
          ++removed;
        }
      }
    }
    // A staged copy the head record, the floor or the previous head record left
    // beside its target in the store root is residue too.
    const auto root_entries = internal::list_directory(root);
    if (root_entries.has_value()) {
      for (const std::string& name : root_entries.value()) {
        if (is_staged_name(name) && internal::remove_file(join(root, name)).has_value()) {
          ++removed;
        }
      }
    }
    return removed;
  }

  /// Bounds the accepted-attempt files of a store written by an earlier release.
  /// The authoritative replay window is the committed manifest, which needs no
  /// pruning: it is rewritten in full at every commit, so an entry that leaves
  /// the window simply stops carrying a record. A file that no longer decodes is
  /// left in place for verify() to report rather than deleted.
  Result<std::size_t> evict_legacy_attempt_records() {
    CFM_TRY(names, internal::list_directory(idempotency_path));
    if (names.size() <= options.idempotency_retention) {
      return 0;
    }
    std::vector<std::pair<CommitSequence, std::string>> ordered;
    ordered.reserve(names.size());
    for (const std::string& name : names) {
      const auto bytes =
          internal::read_file(join(idempotency_path, name), limits::kMaxIdempotencyRecordBytes);
      if (!bytes.has_value()) {
        continue;
      }
      const auto record = internal::decode_attempt_record(bytes.value());
      if (!record.has_value()) {
        continue;
      }
      ordered.emplace_back(record.value().commit, name);
    }
    // The eviction order is the commit sequence, with the file name as a
    // deterministic tie-break, so it never depends on directory enumeration.
    std::sort(ordered.begin(), ordered.end(), [](const auto& lhs, const auto& rhs) {
      if (lhs.first != rhs.first) {
        return lhs.first < rhs.first;
      }
      return lhs.second < rhs.second;
    });
    std::size_t kept = ordered.size();
    std::size_t evicted = 0;
    for (const auto& entry : ordered) {
      if (kept <= options.idempotency_retention) {
        break;
      }
      CFM_TRYV(internal::remove_file(join(idempotency_path, entry.second)));
      --kept;
      ++evicted;
    }
    return evicted;
  }

  /// Moves one generation file aside after recovery could not verify it. The
  /// content is preserved for diagnosis and can never be adopted again.
  Result<void> quarantine_generation(const std::string& name) {
    CFM_TRYV(internal::create_directory(quarantine_path));
    CFM_TRYV(internal::atomic_replace(join(quarantine_path, name),
                                      join(generations_path, name), false));
    return ok();
  }

  void add_finding(VerifyReport& report, VerifySeverity severity, std::string_view code,
                   std::string subject, std::string detail) const {
    VerifyFinding finding;
    finding.severity = severity;
    finding.code = std::string(code);
    finding.subject = std::move(subject);
    finding.detail = std::move(detail);
    report.findings.push_back(std::move(finding));
  }
};

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

std::string_view to_token(StoreMode mode) noexcept {
  switch (mode) {
    case StoreMode::ReadOnly:
      return "read-only";
    case StoreMode::ReadWrite:
      return "read-write";
  }
  return "invalid";
}

std::string_view to_token(StoreOpenState state) noexcept {
  switch (state) {
    case StoreOpenState::Fresh:
      return "fresh";
    case StoreOpenState::Reopened:
      return "reopened";
    case StoreOpenState::Recovered:
      return "recovered";
  }
  return "invalid";
}

std::string_view to_token(PublicationDurability durability) noexcept {
  switch (durability) {
    case PublicationDurability::Durable:
      return "durable";
    case PublicationDurability::NotDurable:
      return "not-durable";
  }
  return "invalid";
}

std::string_view to_token(VerifySeverity severity) noexcept {
  switch (severity) {
    case VerifySeverity::Info:
      return "info";
    case VerifySeverity::Warning:
      return "warning";
    case VerifySeverity::Defect:
      return "defect";
  }
  return "invalid";
}

std::string_view to_token(RecoveryOutcome outcome) noexcept {
  switch (outcome) {
    case RecoveryOutcome::NoAction:
      return "no-action";
    case RecoveryOutcome::AdoptedPrevious:
      return "adopted-previous";
  }
  return "invalid";
}

bool VerifyReport::ok() const noexcept {
  for (const VerifyFinding& finding : findings) {
    if (finding.severity == VerifySeverity::Defect) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

Store::Store() noexcept = default;
Store::~Store() = default;
Store::Store(Store&&) noexcept = default;
Store& Store::operator=(Store&&) noexcept = default;

Result<Store> Store::create(const StoreOptions& options, StoreId store_id) {
  if (store_id.empty()) {
    return Error(ErrorCode::InvalidArgument, "store identity must not be empty");
  }
  CFM_TRYV(validate_store_bounds(options));
  // The root is canonicalized for the lifetime of the handle: absolute, one
  // separator, no parent component and no reparse point on any existing
  // component, so two processes cannot obtain different locks for the same
  // logical store.
  CFM_TRY(canonical_root, internal::canonicalize_store_root(options.root));

  Store store;
  store.impl_ = std::make_unique<Impl>();
  Impl& impl = *store.impl_;
  impl.options = options;
  impl.root = canonical_root;
  impl.generations_path = join(impl.root, internal::kGenerationsDirectoryName);
  impl.idempotency_path = join(impl.root, internal::kIdempotencyDirectoryName);
  impl.staging_path = join(impl.root, internal::kStagingDirectoryName);
  impl.quarantine_path = join(impl.root, kQuarantineDirectoryName);
  impl.writable = options.mode == StoreMode::ReadWrite;

  CFM_TRY(root_info, internal::inspect_path(impl.root));
  if (root_info.exists && !root_info.is_directory) {
    return Error(ErrorCode::PathNotRegular, "the store root exists and is not a directory")
        .with_subject(impl.root);
  }
  if (!root_info.exists && !options.create_if_missing) {
    return Error(ErrorCode::StoreNotFound,
                 "the store root does not exist and create_if_missing is not set")
        .with_subject(impl.root);
  }
  CFM_TRYV(internal::create_directories(impl.root));

  // The writer lock is taken before anything durable is written, so a second
  // creator can neither interleave with the emptiness check nor initialize a
  // store that the first creator is already initializing.
  if (impl.writable) {
    CFM_TRY(lock, internal::FileLock::acquire(impl.lock_path(), "creator"));
    impl.lock = std::move(lock);
  }
  CFM_TRY(names, internal::list_directory(impl.root));
  for (const std::string& name : names) {
    if (name == internal::kLockFileName) {
      continue;
    }
    return Error(ErrorCode::StoreNotEmpty,
                 "the store directory already holds content and is never initialized over")
        .with_subject(name);
  }
  CFM_TRYV(internal::create_directory(impl.generations_path));
  CFM_TRYV(internal::create_directory(impl.idempotency_path));
  CFM_TRYV(internal::create_directory(impl.staging_path));

  // An empty store: no committed generation, no parent, no commit sequence, and
  // a writer that already holds epoch 1 so a mutation planned against epoch 0 is
  // always fenced.
  impl.manifest = internal::Manifest{};
  impl.manifest.store_id = store_id;
  impl.manifest.epoch = WriterEpoch(1);
  impl.manifest.incarnation = WriterIncarnation(1);
  internal::ManifestEntry sentinel;
  impl.manifest.retained.push_back(sentinel);
  // A read-only handle never holds authority, not even over the store it just
  // initialized: authority is reserved by the writer that will use it.
  impl.epoch = impl.writable ? WriterEpoch(1) : WriterEpoch();
  impl.incarnation = impl.writable ? WriterIncarnation(1) : WriterIncarnation();
  CFM_TRYV(impl.write_floor(StateGeneration(), CommitSequence(), options.durable_flush));
  CFM_TRYV(impl.write_manifest(impl.manifest, options.durable_flush, false));
  impl.open = true;
  impl.manifest_readable = true;
  impl.head_verified = true;
  impl.open_state = StoreOpenState::Fresh;
  return store;
}

Result<Store> Store::open(const StoreOptions& options) {
  CFM_TRYV(validate_store_bounds(options));
  CFM_TRY(canonical_root, internal::canonicalize_store_root(options.root));

  Store store;
  store.impl_ = std::make_unique<Impl>();
  Impl& impl = *store.impl_;
  impl.options = options;
  impl.root = canonical_root;
  impl.generations_path = join(impl.root, internal::kGenerationsDirectoryName);
  impl.idempotency_path = join(impl.root, internal::kIdempotencyDirectoryName);
  impl.staging_path = join(impl.root, internal::kStagingDirectoryName);
  impl.quarantine_path = join(impl.root, kQuarantineDirectoryName);
  impl.writable = options.mode == StoreMode::ReadWrite;

  CFM_TRY(root_info, internal::inspect_path(impl.root));
  if (!root_info.exists) {
    return Error(ErrorCode::StoreNotFound, "the store root does not exist").with_subject(impl.root);
  }
  if (!root_info.is_directory) {
    return Error(ErrorCode::PathNotRegular, "the store root is not a directory")
        .with_subject(impl.root);
  }
  if (impl.writable) {
    // Exactly one writer per store, enforced by the operating system and
    // released by the kernel when the holder dies.
    CFM_TRY(lock, internal::FileLock::acquire(impl.lock_path(), "writer"));
    impl.lock = std::move(lock);
    internal::fault_point(options.enable_fault_injection, kFaultOpenAfterLock);
  }

  // The floor is read first: a published head is never accepted without the
  // rollback guard that bounds it. A store that never published anything has
  // nothing to roll back, so a floor file that a torn initialization did not
  // reach is read as zero rather than treated as a corrupted guard.
  StateGeneration durable_floor{};
  const auto durable_floor_read = impl.read_floor();
  if (durable_floor_read.has_value()) {
    durable_floor = durable_floor_read.value();
  }

  const auto manifest_bytes = internal::read_file(impl.manifest_path(), limits::kMaxManifestBytes);
  if (!manifest_bytes.has_value()) {
    return Error(ErrorCode::StoreNotFound, "the store directory holds no manifest")
        .with_subject(impl.root)
        .with_detail(manifest_bytes.error().to_string());
  }
  bool manifest_readable = false;
  std::string reason;
  const auto decoded = internal::decode_manifest(manifest_bytes.value());
  if (decoded.has_value()) {
    impl.manifest = decoded.value();
    manifest_readable = true;
  } else {
    reason = decoded.error().to_string();
  }

  if (!durable_floor_read.has_value() && manifest_readable &&
      !impl.manifest.head.published()) {
    // Nothing was ever published, so there is no rollback to guard against.
    durable_floor = StateGeneration();
  } else if (!durable_floor_read.has_value()) {
    return Error(ErrorCode::IntegrityFailure,
                 "the durable generation floor is missing or unreadable while a published head "
                 "exists; the rollback guard cannot be established")
        .with_detail(durable_floor_read.error().to_string());
  }

  bool head_verified = false;
  if (manifest_readable) {
    // The effective floor is the larger of the durable floor and the floor the
    // committed manifest records; a head below either is a rollback.
    const StateGeneration effective_floor =
        impl.manifest.floor < durable_floor ? durable_floor : impl.manifest.floor;
    if (impl.manifest.head < effective_floor) {
      return Error(ErrorCode::GenerationFloorViolation,
                   "the committed head is below the durable generation floor; this state is a "
                   "rollback")
          .with_subject(to_decimal(impl.manifest.head.value()))
          .with_detail("floor " + to_decimal(effective_floor.value()));
    }
    impl.manifest.floor = effective_floor;
    const auto verified = impl.verify_publication(impl.manifest);
    if (verified.has_value()) {
      head_verified = true;
    } else {
      reason = verified.error().to_string();
    }
  }
  impl.manifest_readable = manifest_readable;
  impl.head_verified = head_verified;
  impl.recovery_reason = reason;

  if (impl.writable && head_verified) {
    // The next epoch and incarnation are reserved durably before the handle is
    // returned, so a successor can always tell that it inherited a store it did
    // not write.
    CFM_TRY(next_epoch, impl.manifest.epoch.next());
    CFM_TRY(next_incarnation, impl.manifest.incarnation.next());
    impl.manifest.epoch = next_epoch;
    impl.manifest.incarnation = next_incarnation;
    impl.epoch = next_epoch;
    impl.incarnation = next_incarnation;
    CFM_TRYV(impl.write_manifest(impl.manifest, options.durable_flush, false));
    internal::fault_point(options.enable_fault_injection, kFaultOpenAfterReserve);
  }
  impl.open = true;
  impl.open_state = StoreOpenState::Reopened;
  return store;
}

Result<void> Store::close() {
  if (impl_ == nullptr || !impl_->open) {
    return ok();
  }
  Impl& impl = *impl_;
  impl.open = false;
  impl.head_verified = false;
  const Result<void> released = impl.lock.release();
  if (!released.has_value()) {
    return released.error();
  }
  return ok();
}

bool Store::is_open() const noexcept { return impl_ != nullptr && impl_->open; }

// ---------------------------------------------------------------------------
// Observation
// ---------------------------------------------------------------------------

Result<StoreInfo> Store::info() const {
  if (impl_ == nullptr) {
    return Error(ErrorCode::NotInitialized, "store handle was never opened");
  }
  const Impl& impl = *impl_;
  CFM_TRYV(impl.require_open());
  StoreInfo info;
  info.store_id = impl.manifest.store_id;
  info.head = impl.manifest.head;
  info.head_digest = impl.manifest.head_digest;
  info.floor = impl.manifest.floor;
  info.commit_sequence = impl.manifest.commit;
  info.epoch = impl.epoch;
  info.incarnation = impl.incarnation;
  info.mode = impl.options.mode;
  info.open_state = impl.open_state;
  // The retained chain always carries at least the head entry, so an empty store
  // reports one retained entry: the all-zero generation 0 sentinel that stands
  // for "no state published yet". It is not a publication and is never loadable.
  info.retained_generations = impl.manifest.retained.size();
  // The number of identities a retry can be answered for: the replay records the
  // committed authority carries, plus the accepted-attempt files an earlier
  // release wrote for identities the authority does not carry. An identity
  // present in both is counted once, because both answer it with the same
  // committed result.
  std::size_t replayable = impl.manifest.attempts.size();
  const auto names = internal::list_directory(impl.idempotency_path);
  if (names.has_value()) {
    for (const std::string& name : names.value()) {
      const auto bytes = internal::read_file(join(impl.idempotency_path, name),
                                             limits::kMaxIdempotencyRecordBytes);
      if (!bytes.has_value()) {
        continue;
      }
      const auto record = internal::decode_attempt_record(bytes.value());
      if (!record.has_value()) {
        continue;
      }
      const bool already_counted =
          std::any_of(impl.manifest.attempts.begin(), impl.manifest.attempts.end(),
                      [&](const internal::AttemptRecord& carried) {
                        return carried.mutation == record.value().mutation &&
                               carried.ordinal == record.value().ordinal;
                      });
      if (!already_counted) {
        ++replayable;
      }
    }
  }
  info.idempotency_records = replayable;
  info.writable = impl.writable;
  info.publication_allowed = impl.writable && impl.open && impl.head_verified;
  info.root = impl.root;
  info.boundary = std::string(internal::store_boundary());
  return info;
}

StoreId Store::store_id() const noexcept {
  return impl_ == nullptr ? StoreId() : impl_->manifest.store_id;
}

WriterEpoch Store::epoch() const noexcept { return impl_ == nullptr ? WriterEpoch() : impl_->epoch; }

WriterIncarnation Store::incarnation() const noexcept {
  return impl_ == nullptr ? WriterIncarnation() : impl_->incarnation;
}

StoreMode Store::mode() const noexcept {
  return impl_ == nullptr ? StoreMode::ReadOnly : impl_->options.mode;
}

StoreOpenState Store::open_state() const noexcept {
  return impl_ == nullptr ? StoreOpenState::Reopened : impl_->open_state;
}

const std::string& Store::root() const noexcept {
  static const std::string empty;
  return impl_ == nullptr ? empty : impl_->root;
}

Result<CoolingFailureState> Store::head() const {
  if (impl_ == nullptr) {
    return Error(ErrorCode::NotInitialized, "store handle was never opened");
  }
  const Impl& impl = *impl_;
  CFM_TRYV(impl.require_open());
  if (!impl.manifest_readable) {
    // Without a head record there is no generation to re-read, so the diagnosis
    // is the head record itself rather than a file.
    return Error(ErrorCode::HeadCorrupt,
                 "the committed head record could not be read; recover() must adopt a publication")
        .with_detail(impl.recovery_reason);
  }
  if (!impl.manifest.head.published()) {
    return Error(ErrorCode::HeadMissing,
                 "the store holds no published state yet (generation 0)");
  }
  // The payload is re-read and re-verified on every call: this never returns a
  // cached body, and the diagnosis of a damaged publication is the damage the
  // file actually carries (a checksum failure, a truncation, a missing file)
  // rather than a generic refusal.
  CFM_TRY(file, impl.load_generation(impl.manifest.head));
  if (file.digest != impl.manifest.head_digest) {
    return Error(ErrorCode::DigestMismatch,
                 "the committed head digest does not match the head generation file")
        .with_subject(to_decimal(impl.manifest.head.value()));
  }
  CFM_TRYV(validate_structure(file.body));
  if (!impl.head_verified) {
    // The file is intact but the head record and the publication disagree (for
    // example on the recorded byte count), so the handle still refuses to serve
    // it as the authority.
    return Error(ErrorCode::HeadCorrupt,
                 "the committed head record and its publication do not agree")
        .with_detail(impl.recovery_reason);
  }
  return file.body;
}

Result<CoolingFailureState> Store::load(StateGeneration generation) const {
  if (impl_ == nullptr) {
    return Error(ErrorCode::NotInitialized, "store handle was never opened");
  }
  const Impl& impl = *impl_;
  CFM_TRYV(impl.require_open());
  if (!impl.manifest_readable) {
    // A generation number can only be judged against a head record and a
    // retained chain, so an unreadable manifest refuses every load.
    return Error(ErrorCode::HeadCorrupt,
                 "the committed head record could not be read; recover() must adopt a publication")
        .with_detail(impl.recovery_reason);
  }
  if (!generation.published()) {
    return Error(ErrorCode::GenerationNotRetained,
                 "generation 0 is the empty-store sentinel and is never a loadable publication");
  }
  if (impl.manifest.head < generation) {
    return Error(ErrorCode::GenerationNotRetained,
                 "the requested generation is newer than the committed head")
        .with_subject(to_decimal(generation.value()))
        .with_detail("head " + to_decimal(impl.manifest.head.value()));
  }
  bool retained = false;
  for (const internal::ManifestEntry& entry : impl.manifest.retained) {
    if (entry.generation == generation) {
      retained = true;
      break;
    }
  }
  if (!retained) {
    return Error(ErrorCode::GenerationNotRetained,
                 "the requested generation is not part of the retained chain")
        .with_subject(to_decimal(generation.value()));
  }
  CFM_TRY(file, impl.load_generation(generation));
  CFM_TRYV(validate_structure(file.body));
  return file.body;
}

Result<std::vector<HistoryEntry>> Store::history() const {
  if (impl_ == nullptr) {
    return Error(ErrorCode::NotInitialized, "store handle was never opened");
  }
  const Impl& impl = *impl_;
  CFM_TRYV(impl.require_open());
  if (!impl.manifest_readable) {
    return Error(ErrorCode::HeadCorrupt,
                 "the committed head record could not be read; recover() must adopt a publication")
        .with_detail(impl.recovery_reason);
  }
  std::vector<HistoryEntry> entries;
  entries.reserve(impl.manifest.retained.size());
  for (std::size_t index = 0; index < impl.manifest.retained.size(); ++index) {
    const internal::ManifestEntry& entry = impl.manifest.retained[index];
    HistoryEntry history;
    history.generation = entry.generation;
    history.digest = entry.digest;
    history.parent_generation = entry.parent;
    history.parent_digest = entry.parent_digest;
    history.commit_sequence = entry.commit;
    history.file_bytes = entry.bytes;
    history.is_head = index == 0;
    // chain_verified is set only for an entry whose file was re-read and verified
    // in this call and whose recorded parent is the next newer generation.
    bool verified = false;
    if (entry.generation.published()) {
      const auto file = impl.load_generation(entry.generation);
      verified = file.has_value() && file.value().digest == entry.digest &&
                 file.value().generation == entry.generation &&
                 file.value().store_id == impl.manifest.store_id;
    }
    if (verified && index > 0) {
      // The link is recorded on the newer entry: generation N names generation
      // N-1 as its parent. The oldest retained entry therefore verifies even when
      // its own parent has been retired, because the chain it belongs to is
      // checked from the newer side.
      const internal::ManifestEntry& newer = impl.manifest.retained[index - 1];
      verified = newer.parent == entry.generation && newer.parent_digest == entry.digest;
    }
    history.chain_verified = verified;
    entries.push_back(std::move(history));
  }
  return entries;
}

// ---------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------

Result<PublicationReceipt> Store::publish(const PublicationRequest& request) {
  if (impl_ == nullptr) {
    return Error(ErrorCode::NotInitialized, "store handle was never opened");
  }
  Impl& impl = *impl_;
  CFM_TRYV(impl.require_open());
  CFM_TRYV(impl.require_writable());
  internal::fault_point(impl.options.enable_fault_injection, kFaultPublishEnter);
  CFM_TRYV(impl.require_head());
  if (request.mutation.empty()) {
    return Error(ErrorCode::InvalidArgument,
                 "a publication request requires a mutation identity");
  }
  if (request.attempt.value() == 0) {
    return Error(ErrorCode::InvalidArgument,
                 "a publication request requires a 1-based attempt ordinal");
  }

  // ---- step 1: validate the body before anything at all is written --------
  CoolingFailureState body = request.body;
  CFM_TRYV(canonicalize(body));
  CFM_TRYV(validate_structure(body));
  const Digest content_digest = internal::request_content_digest(body);

  // ---- step 2: idempotency, resolved before any authority fence -----------
  // A retry of an already accepted attempt is answered from the committed
  // authority even when its epoch, its incarnation and its base generation have
  // all moved on. This ordering is what makes a lost response safe: the caller
  // can never be told that a committed mutation failed and then be forced to
  // plan it again. The accepted-attempt record is read from the committed
  // manifest, so it is subject to exactly the same durability as the mutation it
  // describes and there is no window in which one exists without the other.
  CFM_TRY(accepted, impl.find_accepted_attempt(request.mutation, request.attempt));
  if (!accepted.mutation.empty()) {
    if (accepted.request_digest != content_digest) {
      return Error(ErrorCode::IdempotencyConflict,
                   "the mutation identity and attempt ordinal were already used for different "
                   "content")
          .with_subject(request.mutation.str())
          .with_detail("ordinal " + to_decimal(static_cast<std::uint64_t>(request.attempt.value())));
    }
    return impl.replay_receipt(accepted, request);
  }
  // The record lives with the generation it committed, so finding it and finding
  // the mutation committed are the same act; the ordinal rule below still applies
  // to an identity whose exact ordinal is no longer inside the replay window.
  CFM_TRY(ordinal_behind, impl.has_accepted_newer_ordinal(request.mutation, request.attempt));
  if (ordinal_behind) {
    return Error(ErrorCode::IdempotencyConflict,
                 "an attempt ordinal must not go backwards for one mutation identity")
        .with_subject(request.mutation.str())
        .with_detail("ordinal " + to_decimal(static_cast<std::uint64_t>(request.attempt.value())) +
                     " is below an accepted ordinal");
  }

  // ---- step 3: authority fence -------------------------------------------
  if (request.epoch.value() != 0 && request.epoch != impl.epoch) {
    return Error(ErrorCode::StaleAuthorityEpoch,
                 "the request was planned under a superseded writer epoch")
        .with_subject(to_decimal(request.epoch.value()))
        .with_detail("current epoch " + to_decimal(impl.epoch.value()));
  }
  if (request.incarnation.value() != 0 && request.incarnation != impl.incarnation) {
    return Error(ErrorCode::StaleWriterIncarnation,
                 "the request was planned under a superseded writer incarnation")
        .with_subject(to_decimal(request.incarnation.value()))
        .with_detail("current incarnation " + to_decimal(impl.incarnation.value()));
  }
  // The base generation may not EXCEED the committed head: a caller that planned
  // against a generation this store never committed is describing state that does
  // not exist here. A base below the head is accepted and becomes a new mutation
  // over newer state.
  if (request.base_generation.published() && impl.manifest.head < request.base_generation) {
    return Error(ErrorCode::StaleBaseGeneration,
                 "the request was planned against a generation the store has not committed")
        .with_subject(to_decimal(request.base_generation.value()))
        .with_detail("committed head " + to_decimal(impl.manifest.head.value()));
  }

  // ---- step 4: in-flight attempts and the binding fence -------------------
  if (impl.manifest.head.published()) {
    // The head is re-read and re-verified, never taken from a cache: the gate
    // below must judge the committed state, not a stale copy of it.
    CFM_TRY(head_state, impl.head_state());
    const std::vector<AttemptId> in_flight = in_flight_attempts(head_state);
    if (!in_flight.empty() && !body_changes_any_attempt(body, in_flight)) {
      return Error(ErrorCode::AttemptOutstanding,
                   "the committed head still holds an in-flight attempt and the request changes "
                   "none of them; only explicit reconciliation may proceed")
          .with_subject(in_flight.front().str())
          .with_detail("in flight " + to_decimal(in_flight.size()));
    }
    // A non-empty authority set is an assertion about the bindings the mutation
    // was planned under; an empty set asserts nothing and is therefore unfenced,
    // exactly like a zero epoch and a zero base generation.
    if (!request.authority.empty() && request.authority != head_state.bindings) {
      return Error(ErrorCode::StaleDecision,
                   "the request asserts bindings the committed head does not carry")
          .with_subject(request.mutation.str());
    }
  }

  // ---- step 5: reserve the generation and the commit sequence ------------
  CFM_TRY(next_generation, impl.manifest.head.published()
                               ? impl.manifest.head.next()
                               : Result<StateGeneration>(
                                     StateGeneration(StateGeneration::kFirstPublished)));
  CFM_TRY(next_commit, impl.manifest.commit.next());
  body.generation = next_generation;
  body.parent_generation = impl.manifest.head;
  const std::string canonical_bytes = encode_state(body);
  if (canonical_bytes.size() > limits::kMaxGenerationBytes) {
    return Error(ErrorCode::LimitExceeded,
                 "the canonical body exceeds the documented generation bound")
        .with_subject(to_decimal(canonical_bytes.size()));
  }
  const Digest digest = state_digest(body);
  const std::string frame = internal::encode_generation_file(
      impl.manifest.store_id, next_generation, digest, canonical_bytes);
  if (frame.size() > limits::kMaxGenerationFileBytes) {
    return Error(ErrorCode::LimitExceeded,
                 "the generation file exceeds the documented bound")
        .with_subject(to_decimal(frame.size()));
  }

  // The retention window this publication establishes and the durable floor it
  // raises to are both known before the commit point, so the committed manifest
  // already records the window it leaves behind.
  const std::uint64_t retention =
      static_cast<std::uint64_t>(impl.options.retained_generations);
  std::uint64_t oldest_kept = 1;
  if (next_generation.value() >= retention) {
    oldest_kept = next_generation.value() - retention + 1;
  }
  const std::uint64_t floor_value =
      std::max<std::uint64_t>(impl.manifest.floor.value(), oldest_kept);
  const StateGeneration next_floor(floor_value);

  std::vector<internal::ManifestEntry> retained;
  retained.reserve(impl.manifest.retained.size() + 1);
  internal::ManifestEntry head_entry;
  head_entry.generation = next_generation;
  head_entry.digest = digest;
  head_entry.parent = impl.manifest.head;
  head_entry.parent_digest = impl.manifest.head_digest;
  head_entry.commit = next_commit;
  head_entry.bytes = canonical_bytes.size();
  retained.push_back(head_entry);
  for (const internal::ManifestEntry& entry : impl.manifest.retained) {
    // Only published generations enter the retained chain: the empty-store
    // sentinel is not a publication, and anything the new floor retires is
    // dropped here rather than recorded and then removed.
    if (entry.generation.published() && next_floor <= entry.generation &&
        entry.generation < next_generation) {
      retained.push_back(entry);
    }
  }

  // The replay table of the new manifest. It is rebuilt in full on every
  // publication from the records themselves rather than pruned out of the
  // retained chain, so an identity stays inside the window for exactly the
  // documented number of publications and a record is never lost by an entry
  // leaving the chain. The records an earlier release left in files are absorbed
  // here as well, so a store that upgrades keeps the replay guarantee its
  // existing records describe instead of losing it at the first publication.
  const std::size_t attempts_retained = static_cast<std::size_t>(std::max<std::uint64_t>(
      1, static_cast<std::uint64_t>(impl.options.idempotency_retention)));
  std::vector<internal::AttemptRecord> attempts;
  attempts.reserve(std::min<std::size_t>(attempts_retained, limits::kMaxIdempotencyRecords));
  internal::AttemptRecord own;
  own.mutation = request.mutation;
  own.ordinal = request.attempt;
  own.request_digest = content_digest;
  own.generation = next_generation;
  own.digest = digest;
  own.commit = next_commit;
  const auto still_retained = [&retained](const internal::AttemptRecord& record) {
    for (const internal::ManifestEntry& entry : retained) {
      if (entry.generation == record.generation) {
        return true;
      }
    }
    return false;
  };
  const auto already_carried = [](const std::vector<internal::AttemptRecord>& table,
                                  const internal::AttemptRecord& record) {
    for (const internal::AttemptRecord& item : table) {
      if (item.mutation == record.mutation && item.ordinal == record.ordinal &&
          item.generation == record.generation && item.digest == record.digest &&
          item.commit == record.commit) {
        return true;
      }
    }
    return false;
  };
  attempts.push_back(own);
  for (const internal::AttemptRecord& record : impl.manifest.attempts) {
    // Every accepted attempt keeps its own record, because its ordinal is what
    // makes it a distinct operation: a table that held only the newest attempt of
    // an identity would silently make an earlier accepted attempt unreplayable.
    // A record is only carried while the generation it names is still retained,
    // because replaying it means naming the state that publication committed.
    if (still_retained(record) && !already_carried(attempts, record)) {
      attempts.push_back(record);
    }
  }
  CFM_TRY(legacy_files, internal::list_directory(impl.idempotency_path));
  for (const std::string& name : legacy_files) {
    const auto bytes = internal::read_file(join(impl.idempotency_path, name),
                                           limits::kMaxIdempotencyRecordBytes);
    if (!bytes.has_value()) {
      continue;
    }
    const auto record = internal::decode_attempt_record(bytes.value());
    if (!record.has_value()) {
      // A record that does not decode is reported by verify() rather than
      // silently skipped, which is also why it is not carried here.
      continue;
    }
    if (still_retained(record.value()) && !already_carried(attempts, record.value())) {
      attempts.push_back(record.value());
    }
  }
  // Newest generation first, which is the order the format requires. The sort is
  // total: two records never share a generation, because a generation commits one
  // publication, and the identity is the tie-break that makes that structural
  // rather than assumed.
  std::sort(attempts.begin(), attempts.end(),
            [](const internal::AttemptRecord& lhs, const internal::AttemptRecord& rhs) {
              if (lhs.generation != rhs.generation) {
                return rhs.generation < lhs.generation;
              }
              if (!(lhs.mutation == rhs.mutation)) {
                return lhs.mutation.str() < rhs.mutation.str();
              }
              return lhs.ordinal.value() < rhs.ordinal.value();
            });
  if (attempts.size() > attempts_retained) {
    attempts.resize(attempts_retained);
  }

  if (retained.size() > limits::kMaxRetainedGenerations) {
    return Error(ErrorCode::InternalError, "retained chain exceeds the documented bound");
  }
  if (attempts.size() > limits::kMaxIdempotencyRecords ||
      attempts.size() > attempts_retained) {
    return Error(ErrorCode::InternalError, "replay table exceeds the documented bound");
  }

  internal::Manifest committed = impl.manifest;
  committed.head = next_generation;
  committed.head_digest = digest;
  committed.parent = impl.manifest.head;
  committed.parent_digest = impl.manifest.head_digest;
  committed.commit = next_commit;
  committed.floor = next_floor;
  committed.bytes = canonical_bytes.size();
  committed.retained = retained;
  committed.attempts = attempts;
  committed.epoch = impl.epoch;
  committed.incarnation = impl.incarnation;

  const bool durable = impl.options.durable_flush;
  bool every_flush_ok = durable;

  // ---- step 6: stage, flush, read back and re-verify ---------------------
  const std::string generation_path = impl.generation_path(next_generation);
  // The staged name is derived from the target name, so residue in generations/
  // is recognizable as this store's own uncommitted staging content rather than
  // mistaken for a generation.
  const std::string staged_path =
      join(impl.staging_path, internal::generation_file_name(next_generation) + ".staged");
  StagedFileGuard guard(staged_path);
  // A file already present under the reserved generation number can only be the
  // residue of an interrupted publication: the committed head is strictly below
  // it, so no committed manifest can reference it. docs/FORMATS.md section 2.5
  // requires the next successful publication to remove it, and it is never
  // adopted, so it is removed here rather than refused or overwritten in place.
  CFM_TRY(already_present, internal::path_exists(generation_path));
  if (already_present) {
    CFM_TRYV(internal::remove_file(generation_path));
  }
  CFM_TRYV(internal::write_file(staged_path, frame, durable));
  internal::fault_point(impl.options.enable_fault_injection, kFaultPublishAfterStage);
  CFM_TRY(readback, internal::read_file(staged_path, limits::kMaxGenerationFileBytes));
  if (readback != frame) {
    return Error(ErrorCode::PublicationIncomplete,
                 "the staged content does not match what was written");
  }
  CFM_TRY(readback_file, internal::decode_generation_file(readback));
  if (readback_file.digest != digest || readback_file.generation != next_generation) {
    return Error(ErrorCode::PublicationIncomplete,
                 "the staged content decodes to a different generation than the one reserved");
  }
  // The canonical fixed point is re-derived here, so a body that the decoder
  // accepted but that does not re-encode identically can never be committed.
  if (encode_state(readback_file.body) != canonical_bytes) {
    return Error(ErrorCode::IntegrityFailure,
                 "the staged body is not a fixed point of canonical re-encoding");
  }

  // ---- step 7: publish the generation file -------------------------------
  internal::fault_point(impl.options.enable_fault_injection, kFaultPublishBeforeRename);
  CFM_TRYV(impl.publish_content(generation_path, frame, limits::kMaxGenerationFileBytes, durable));
  guard.consume();
  // The documented staging copy is consumed by the publication: leaving it would
  // report residue on every healthy store.
  (void)internal::remove_file(staged_path);
  internal::fault_point(impl.options.enable_fault_injection, kFaultPublishAfterRename);

  // ---- step 8: retain the current manifest as the previous publication ---
  const auto current_manifest = internal::read_file(impl.manifest_path(), limits::kMaxManifestBytes);
  if (current_manifest.has_value()) {
    // Only a manifest that still parses is copied: the previous-publication slot
    // is the fallback recovery depends on, and damaged content must never be
    // promoted into it.
    if (internal::decode_manifest(current_manifest.value()).has_value()) {
      CFM_TRYV(impl.publish_content(impl.manifest_previous_path(), current_manifest.value(),
                                    limits::kMaxManifestBytes, durable));
    }
  }
  internal::fault_point(impl.options.enable_fault_injection, kFaultPublishBeforeManifest);

  // ---- step 9: the commit point ------------------------------------------
  // The durable replacement of the head manifest is the single point at which
  // this publication becomes visible. Everything before it is invisible;
  // everything after it cannot be undone.
  CFM_TRYV(impl.write_manifest(committed, durable, true));
  impl.manifest = committed;
  internal::fault_point(impl.options.enable_fault_injection, kFaultPublishAfterManifest);

  // ---- step 10: the durable floor ----------------------------------------
  internal::fault_point(impl.options.enable_fault_injection, kFaultPublishBeforeFloor);
  const Result<void> floor_written = impl.write_floor(next_floor, next_commit, durable);
  if (!floor_written.has_value()) {
    // The head is committed; a floor that could not be written only means the
    // rollback guard lags, which recovery re-derives. It is reported as degraded
    // durability rather than as a failed publication.
    every_flush_ok = false;
  }
  internal::fault_point(impl.options.enable_fault_injection, kFaultPublishAfterFloor);

  // No bookkeeping follows the commit point. The accepted-attempt record that
  // makes a retry of this mutation a replay was written by the same durable
  // replacement that committed the mutation, so there is no longer an interval in
  // which one exists without the other and nothing after this line can lose the
  // identity of what was just committed.
  internal::fault_point(impl.options.enable_fault_injection, kFaultPublishAfterCommit);

  // ---- step 11: retire and clean -----------------------------------------
  const Result<std::size_t> retired = impl.retire_outside_window(next_floor, next_generation);
  if (!retired.has_value()) {
    every_flush_ok = false;
  }
  const Result<std::size_t> residue = impl.remove_staging_residue();
  if (!residue.has_value()) {
    every_flush_ok = false;
  }
  // Records left by a release that kept them in files of their own are bounded
  // here; the authoritative window is the committed manifest, which needs no
  // pruning because it is rewritten in full on every publication.
  const Result<std::size_t> evicted = impl.evict_legacy_attempt_records();
  if (!evicted.has_value()) {
    every_flush_ok = false;
  }
  internal::fault_point(impl.options.enable_fault_injection, kFaultPublishAfterRetire);

  PublicationReceipt receipt;
  receipt.generation = next_generation;
  receipt.parent_generation = committed.parent;
  receipt.digest = digest;
  receipt.mutation = request.mutation;
  receipt.attempt = request.attempt;
  receipt.commit_sequence = next_commit;
  receipt.replayed = false;
  receipt.head_after = committed.head;
  receipt.head_digest_after = committed.head_digest;
  receipt.durability =
      every_flush_ok ? PublicationDurability::Durable : PublicationDurability::NotDurable;
  return receipt;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

Result<VerifyReport> Store::verify(const VerifyOptions& options) const {
  if (impl_ == nullptr) {
    return Error(ErrorCode::NotInitialized, "store handle was never opened");
  }
  const Impl& impl = *impl_;
  CFM_TRYV(impl.require_open());

  VerifyReport report;
  report.store_id = impl.manifest.store_id;
  report.head = impl.manifest.head;
  report.head_digest = impl.manifest.head_digest;
  report.recovered_state = impl.open_state == StoreOpenState::Recovered;

  // Findings are added in a fixed order - floor, manifest, chain, generations,
  // idempotency, staging, quarantine, attempts - and every directory-derived
  // group is ordered by name, so two verifications of one store produce the same
  // report in the same order.

  // ---- durable floor ------------------------------------------------------
  StateGeneration floor{};
  bool floor_read = false;
  const auto floor_bytes = internal::read_file(impl.floor_path(), limits::kMaxManifestBytes);
  if (!floor_bytes.has_value()) {
    impl.add_finding(report, VerifySeverity::Defect, kFindingFloorMissing, impl.floor_path(),
                     floor_bytes.error().to_string());
  } else {
    const auto decoded = internal::decode_floor(floor_bytes.value());
    if (!decoded.has_value()) {
      impl.add_finding(report, VerifySeverity::Defect, kFindingFloorUnreadable, impl.floor_path(),
                       decoded.error().to_string());
    } else {
      floor = decoded.value();
      floor_read = true;
      report.floor_verified = true;
    }
  }

  // ---- committed manifest -------------------------------------------------
  internal::Manifest manifest;
  bool manifest_readable = false;
  const auto manifest_bytes = internal::read_file(impl.manifest_path(), limits::kMaxManifestBytes);
  if (!manifest_bytes.has_value()) {
    impl.add_finding(report, VerifySeverity::Defect, kFindingManifestMissing,
                     impl.manifest_path(), manifest_bytes.error().to_string());
  } else {
    const auto decoded = internal::decode_manifest(manifest_bytes.value());
    if (!decoded.has_value()) {
      impl.add_finding(report, VerifySeverity::Defect, kFindingManifestUnreadable,
                       impl.manifest_path(), decoded.error().to_string());
    } else {
      manifest = decoded.value();
      manifest_readable = true;
      report.manifest_verified = true;
      report.store_id = manifest.store_id;
      report.head = manifest.head;
      report.head_digest = manifest.head_digest;
    }
  }

  bool fixed_point_ok = true;
  std::size_t generations_verified = 0;

  if (manifest_readable) {
    if (floor_read && manifest.floor != floor) {
      impl.add_finding(report, VerifySeverity::Warning, kFindingFloorManifestMismatch,
                       to_decimal(manifest.floor.value()),
                       "durable floor is " + to_decimal(floor.value()));
    }
    if (floor_read && manifest.head < floor) {
      impl.add_finding(report, VerifySeverity::Defect, kFindingFloorHeadViolation,
                       to_decimal(manifest.head.value()),
                       "durable floor is " + to_decimal(floor.value()));
    }
    // The retained chain: every consecutive pair must agree on the parent
    // generation and the parent digest, and the chain must be gap free.
    bool chain_ok = true;
    for (std::size_t index = 1; index < manifest.retained.size(); ++index) {
      const internal::ManifestEntry& newer = manifest.retained[index - 1];
      const internal::ManifestEntry& older = manifest.retained[index];
      if (newer.parent != older.generation || newer.parent_digest != older.digest) {
        chain_ok = false;
        impl.add_finding(report, VerifySeverity::Defect, kFindingChainParentMismatch,
                         "ordinal " + to_decimal(static_cast<std::uint64_t>(index - 1)),
                         "parent " + to_decimal(newer.parent.value()) + " is not generation " +
                             to_decimal(older.generation.value()));
      }
      if (older.generation.value() + 1u != newer.generation.value()) {
        chain_ok = false;
        impl.add_finding(report, VerifySeverity::Defect, kFindingChainGap,
                         "ordinal " + to_decimal(static_cast<std::uint64_t>(index)),
                         "generation " + to_decimal(older.generation.value()) +
                             " does not precede " + to_decimal(newer.generation.value()));
      }
    }
    report.chain_verified = chain_ok;

    if (!manifest.head.published()) {
      // No published state: decode_manifest proved the sentinel is all zero, so
      // "no state yet" is verified.
      report.head_verified = manifest.retained.size() == 1;
    } else {
      const auto verified = impl.verify_publication(manifest);
      if (verified.has_value()) {
        report.head_verified = true;
        ++generations_verified;
        if (options.verify_canonical_fixed_point) {
          const auto fixed = impl.verify_canonical_fixed_point(manifest.head);
          if (!fixed.has_value()) {
            fixed_point_ok = false;
            impl.add_finding(report, VerifySeverity::Defect, kFindingGenerationFixedPoint,
                             to_decimal(manifest.head.value()), fixed.error().to_string());
          }
        }
        const auto head_file = impl.load_generation_for(manifest.head, manifest.store_id);
        if (head_file.has_value()) {
          const std::vector<AttemptId> in_flight = in_flight_attempts(head_file.value().body);
          if (!in_flight.empty()) {
            report.unresolved_attempts_found = in_flight.size();
            impl.add_finding(report, VerifySeverity::Warning, kFindingAttemptUnresolved,
                             in_flight.front().str(),
                             "in flight " + to_decimal(in_flight.size()));
          }
        }
      } else {
        const Error& error = verified.error();
        impl.add_finding(report,
                         VerifySeverity::Defect,
                         error.code() == ErrorCode::DigestMismatch ? kFindingHeadDigestMismatch
                                                                   : kFindingHeadUnverified,
                         to_decimal(manifest.head.value()), error.to_string());
      }
    }

    // Deeper than the head: re-read and re-verify every other retained
    // generation when the caller asked for a deep verification.
    if (options.deep) {
      for (std::size_t index = 1; index < manifest.retained.size(); ++index) {
        const internal::ManifestEntry& entry = manifest.retained[index];
        if (!entry.generation.published()) {
          continue;
        }
        const auto file = impl.load_generation_for(entry.generation, manifest.store_id);
        if (!file.has_value()) {
          impl.add_finding(report, VerifySeverity::Defect, kFindingGenerationUnreadable,
                           internal::generation_file_name(entry.generation),
                           file.error().to_string());
          continue;
        }
        if (file.value().digest != entry.digest || file.value().generation != entry.generation ||
            file.value().store_id != manifest.store_id) {
          impl.add_finding(report, VerifySeverity::Defect, kFindingGenerationUnreadable,
                           internal::generation_file_name(entry.generation),
                           "the retained record does not agree with the file");
          continue;
        }
        const auto structure = validate_structure(file.value().body);
        if (!structure.has_value()) {
          impl.add_finding(report, VerifySeverity::Defect, kFindingHeadStructureInvalid,
                           internal::generation_file_name(entry.generation),
                           structure.error().to_string());
          continue;
        }
        if (options.verify_canonical_fixed_point) {
          const auto fixed = impl.verify_canonical_fixed_point(entry.generation);
          if (!fixed.has_value()) {
            fixed_point_ok = false;
            impl.add_finding(report, VerifySeverity::Defect, kFindingGenerationFixedPoint,
                             internal::generation_file_name(entry.generation),
                             fixed.error().to_string());
            continue;
          }
        }
        ++generations_verified;
      }
    }
  }
  report.generations_verified = generations_verified;

  // ---- every generation file present --------------------------------------
  const auto names = internal::list_directory(impl.generations_path);
  if (!names.has_value()) {
    impl.add_finding(report, VerifySeverity::Defect, kFindingGenerationUnreadable,
                     impl.generations_path, names.error().to_string());
  } else {
    report.generations_present = names.value().size();
    std::vector<std::pair<StateGeneration, std::string>> present;
    for (const std::string& name : names.value()) {
      if (is_staged_name(name)) {
        // A staged copy left beside a generation target is this store's own
        // uncommitted content, never a generation: it is residue, and it is
        // removed by the next successful publication or by recovery.
        ++report.staged_residue_found;
        impl.add_finding(report, VerifySeverity::Warning, kFindingStagingResidue, name,
                         "uncommitted staged content is never authoritative");
        continue;
      }
      const auto number = internal::parse_generation_file_name(name);
      if (!number.has_value()) {
        impl.add_finding(report, VerifySeverity::Defect, kFindingGenerationNameInvalid, name,
                         number.error().to_string());
        continue;
      }
      present.emplace_back(number.value(), name);
    }
    std::sort(present.begin(), present.end(), [](const auto& lhs, const auto& rhs) {
      if (lhs.first != rhs.first) {
        return lhs.first < rhs.first;
      }
      return lhs.second < rhs.second;
    });
    for (const auto& entry : present) {
      if (manifest_readable && manifest.head.published() && manifest.head < entry.first) {
        ++report.orphan_generations_found;
        impl.add_finding(report, VerifySeverity::Warning, kFindingGenerationOrphan, entry.second,
                         "newer than the committed head " + to_decimal(manifest.head.value()));
        continue;
      }
      bool referenced = false;
      if (manifest_readable) {
        for (const internal::ManifestEntry& retained_entry : manifest.retained) {
          if (retained_entry.generation == entry.first) {
            referenced = true;
            break;
          }
        }
      }
      if (!referenced) {
        ++report.unreferenced_generations_found;
        impl.add_finding(report, VerifySeverity::Warning, kFindingGenerationUnreferenced,
                         entry.second, "no retained entry names this generation");
      }
    }
  }

  // ---- the replay index carried by the committed manifest ----------------
  // The manifest is the authority, so its replay index is what a retry is
  // answered from. It is checked here in the order the retained chain is read: an
  // entry whose record does not belong to it, or two entries that claim the same
  // identity, would make the answer to a retry depend on which one was found
  // first.
  if (options.verify_idempotency) {
    std::vector<std::pair<MutationId, AttemptOrdinal>> seen;
    for (const internal::AttemptRecord& record : impl.manifest.attempts) {
      const std::string subject =
          record.mutation.str() + "#" +
          to_decimal(static_cast<std::uint64_t>(record.ordinal.value()));
      bool retained_generation = false;
      for (const internal::ManifestEntry& entry : impl.manifest.retained) {
        if (entry.generation == record.generation && entry.digest == record.digest &&
            entry.commit == record.commit) {
          retained_generation = true;
          break;
        }
      }
      if (!retained_generation) {
        impl.add_finding(report, VerifySeverity::Defect, kFindingReplayInconsistent, subject,
                         "the replay record does not name a retained generation");
      }
      if (record.request_digest.is_zero()) {
        impl.add_finding(report, VerifySeverity::Defect, kFindingReplayInconsistent, subject,
                         "the replay record carries no intent digest");
      }
      const bool duplicate =
          std::any_of(seen.begin(), seen.end(), [&](const std::pair<MutationId, AttemptOrdinal>& item) {
            return item.first == record.mutation && item.second == record.ordinal;
          });
      if (duplicate) {
        impl.add_finding(report, VerifySeverity::Defect, kFindingReplayDuplicate, subject,
                         "two replay records claim the same accepted attempt");
      }
      seen.emplace_back(record.mutation, record.ordinal);
    }
  }

  // ---- accepted-attempt files left by an earlier release ------------------
  if (options.verify_idempotency) {
    const auto records = internal::list_directory(impl.idempotency_path);
    if (!records.has_value()) {
      impl.add_finding(report, VerifySeverity::Defect, kFindingIdempotencyUnreadable,
                       impl.idempotency_path, records.error().to_string());
    } else {
      for (const std::string& name : records.value()) {
        if (is_staged_name(name)) {
          ++report.staged_residue_found;
          impl.add_finding(report, VerifySeverity::Warning, kFindingStagingResidue, name,
                           "uncommitted staged content is never authoritative");
          continue;
        }
        const auto bytes =
            internal::read_file(join(impl.idempotency_path, name), limits::kMaxIdempotencyRecordBytes);
        if (!bytes.has_value()) {
          impl.add_finding(report, VerifySeverity::Defect, kFindingIdempotencyUnreadable, name,
                           bytes.error().to_string());
          continue;
        }
        const auto record = internal::decode_attempt_record(bytes.value());
        if (!record.has_value()) {
          impl.add_finding(report, VerifySeverity::Defect, kFindingIdempotencyUnreadable, name,
                           record.error().to_string());
          continue;
        }
        // A legacy file is only consulted when the committed authority does not
        // already answer its identity. One that claims an identity the authority
        // does answer, with a different result, is a disagreement about what a
        // committed mutation returned; it is reported rather than resolved,
        // because either answer would be a guess about which record is the
        // mutation's.
        for (const internal::AttemptRecord& carried : impl.manifest.attempts) {
          if (!(carried.mutation == record.value().mutation) ||
              !(carried.ordinal == record.value().ordinal)) {
            continue;
          }
          if (carried.request_digest != record.value().request_digest ||
              carried.generation != record.value().generation ||
              carried.digest != record.value().digest ||
              carried.commit != record.value().commit) {
            impl.add_finding(report, VerifySeverity::Defect, kFindingReplayInconsistent, name,
                             "the accepted-attempt file disagrees with the record the committed "
                             "manifest carries for the same identity");
          }
        }
      }
    }
  }

  // ---- staging residue ----------------------------------------------------
  const auto staged = internal::list_directory(impl.staging_path);
  if (!staged.has_value()) {
    impl.add_finding(report, VerifySeverity::Defect, kFindingStagingUnreadable,
                     impl.staging_path, staged.error().to_string());
  } else {
    report.staged_residue_found = staged.value().size();
    if (!staged.value().empty()) {
      // One finding per staged entry, in the byte-wise order list_directory
      // returns, so the report is deterministic.
      for (const std::string& name : staged.value()) {
        impl.add_finding(report, VerifySeverity::Warning, kFindingStagingResidue, name,
                         "uncommitted staged content is never authoritative");
      }
    }
  }

  // ---- the store root -----------------------------------------------------
  // The root holds the fixed entries of the documented layout and nothing else.
  // Anything else is reported: staged content is counted as residue, any other
  // entry is named as unexpected. Neither is authoritative and neither is
  // removed by verification.
  const auto root_entries = internal::list_directory(impl.root);
  if (root_entries.has_value()) {
    for (const std::string& name : root_entries.value()) {
      if (name == internal::kLockFileName || name == internal::kFloorFileName ||
          name == internal::kManifestFileName ||
          name == internal::kPreviousManifestFileName ||
          name == internal::kGenerationsDirectoryName ||
          name == internal::kStagingDirectoryName ||
          name == internal::kIdempotencyDirectoryName || name == kQuarantineDirectoryName) {
        continue;
      }
      if (is_staged_name(name)) {
        ++report.staged_residue_found;
        impl.add_finding(report, VerifySeverity::Warning, kFindingStagingResidue, name,
                         "uncommitted staged content is never authoritative");
        continue;
      }
      impl.add_finding(report, VerifySeverity::Warning, kFindingUnexpectedEntry, name,
                       "the store root holds an entry the layout does not define");
    }
  }

  // ---- quarantine ---------------------------------------------------------
  const auto quarantine = internal::inspect_path(impl.quarantine_path);
  if (quarantine.has_value() && quarantine.value().exists && quarantine.value().is_directory) {
    const auto quarantined = internal::list_directory(impl.quarantine_path);
    if (quarantined.has_value() && !quarantined.value().empty()) {
      report.quarantined_found = quarantined.value().size();
      impl.add_finding(report, VerifySeverity::Info, kFindingQuarantine, impl.quarantine_path,
                       "content recovery moved aside: " + to_decimal(quarantined.value().size()));
    }
  }

  if (options.verify_canonical_fixed_point) {
    // Vacuously true when there was nothing to re-encode: the flag reports that
    // no verified payload contradicted its own canonical encoding. Without a
    // readable manifest there was no payload to verify at all, so it stays false
    // rather than claiming a check that never ran.
    report.canonical_fixed_point_verified = fixed_point_ok && manifest_readable;
  }
  report.publication_allowed =
      impl.writable && impl.open && report.head_verified && manifest_readable &&
      manifest.head == impl.manifest.head && manifest.head_digest == impl.manifest.head_digest;
  return report;
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

Result<RecoveryReport> Store::recover(const RecoveryOptions& options) {
  if (impl_ == nullptr) {
    return Error(ErrorCode::NotInitialized, "store handle was never opened");
  }
  Impl& impl = *impl_;
  CFM_TRYV(impl.require_open());
  // Adoption must be committed to be an adoption: a read-only handle would
  // report a head it cannot make durable.
  CFM_TRYV(impl.require_writable());

  RecoveryReport report;
  report.head_before = impl.manifest.head;
  report.floor_respected = true;

  // ---- the durable floor is read first; adoption below it is refused ------
  CFM_TRY(floor_value, impl.read_floor());
  report.steps.push_back("floor.read");

  // ---- is the committed head already valid? Everything is re-read ---------
  bool head_valid = false;
  std::string head_reason;
  std::string current_bytes;
  bool current_present = false;
  {
    const auto bytes = internal::read_file(impl.manifest_path(), limits::kMaxManifestBytes);
    if (!bytes.has_value()) {
      head_reason = bytes.error().to_string();
    } else {
      current_bytes = bytes.value();
      current_present = true;
      const auto decoded = internal::decode_manifest(current_bytes);
      if (!decoded.has_value()) {
        head_reason = decoded.error().to_string();
      } else {
        report.head_before = decoded.value().head;
        if (decoded.value().head < floor_value) {
          // A committed head below the durable floor is a rollback. Nothing may
          // be adopted to hide it, and no report may describe it as recovered.
          return Error(ErrorCode::GenerationFloorViolation,
                       "the committed head is below the durable generation floor and is refused")
              .with_subject(to_decimal(decoded.value().head.value()))
              .with_detail("floor " + to_decimal(floor_value.value()));
        }
        const auto verified = impl.verify_publication(decoded.value());
        if (verified.has_value()) {
          head_valid = true;
        } else {
          head_reason = verified.error().to_string();
        }
      }
    }
  }
  report.steps.push_back("manifest.read");

  if (head_valid) {
    // The head is healthy: recovery changes nothing at all, not even residue.
    report.outcome = RecoveryOutcome::NoAction;
    report.head_after = impl.manifest.head;
    report.head_digest_after = impl.manifest.head_digest;
    report.explanation = "the committed head verified; nothing was adopted and nothing changed";
    return report;
  }
  report.steps.push_back("head.unverified");

  // ---- adoption ------------------------------------------------------------
  if (!options.adopt_previous) {
    return Error(ErrorCode::RecoveryUnavailable,
                 "the committed head cannot be verified and adoption was not requested")
        .with_detail(head_reason);
  }
  const auto previous_bytes =
      internal::read_file(impl.manifest_previous_path(), limits::kMaxManifestBytes);
  if (!previous_bytes.has_value()) {
    return Error(ErrorCode::RecoveryUnavailable,
                 "the committed head cannot be verified and no retained previous publication "
                 "exists")
        .with_detail(head_reason);
  }
  if (current_present && current_bytes == previous_bytes.value()) {
    return Error(ErrorCode::RecoveryUnavailable,
                 "manifest.prev is byte-identical to manifest and would adopt nothing");
  }
  const auto previous = internal::decode_manifest(previous_bytes.value());
  if (!previous.has_value()) {
    return Error(ErrorCode::RecoveryUnavailable,
                 "the retained previous publication cannot be read and adoption is refused")
        .with_detail(previous.error().to_string());
  }
  report.steps.push_back("manifest.prev.read");

  const StateGeneration adopted_floor =
      previous.value().floor < floor_value ? floor_value : previous.value().floor;
  if (previous.value().head < adopted_floor) {
    return Error(ErrorCode::GenerationFloorViolation,
                 "the retained previous publication is below the durable generation floor")
        .with_subject(to_decimal(previous.value().head.value()))
        .with_detail("floor " + to_decimal(adopted_floor.value()));
  }
  if (previous.value().head.published()) {
    const auto verified = impl.verify_publication(previous.value());
    if (!verified.has_value()) {
      return Error(ErrorCode::RecoveryUnavailable,
                   "the retained previous publication could not be verified and is not adopted")
          .with_detail(verified.error().to_string());
    }
  }
  report.steps.push_back("manifest.prev.verified");

  // ---- adopt and commit the repaired head record --------------------------
  impl.manifest = previous.value();
  impl.manifest.floor = adopted_floor;
  // A retained entry the durable floor has retired is dropped from the repaired
  // record: the adopted manifest must not name a generation the floor forbids.
  // Only the oldest entries can be dropped, so the remaining chain stays
  // consecutive and the head entry is never touched.
  while (impl.manifest.retained.size() > 1 &&
         impl.manifest.retained.back().generation < adopted_floor) {
    impl.manifest.retained.pop_back();
  }
  CFM_TRY(next_epoch, impl.manifest.epoch.next());
  CFM_TRY(next_incarnation, impl.manifest.incarnation.next());
  impl.manifest.epoch = next_epoch;
  impl.manifest.incarnation = next_incarnation;
  impl.epoch = next_epoch;
  impl.incarnation = next_incarnation;
  CFM_TRYV(impl.write_manifest(impl.manifest, impl.options.durable_flush, false));
  impl.manifest_readable = true;
  impl.head_verified = true;
  impl.recovery_reason.clear();
  impl.open_state = StoreOpenState::Recovered;
  report.outcome = RecoveryOutcome::AdoptedPrevious;
  report.head_after = impl.manifest.head;
  report.head_digest_after = impl.manifest.head_digest;
  report.steps.push_back("manifest.committed");

  // ---- re-verify every retained generation --------------------------------
  if (options.deep_verify) {
    bool quarantined = false;
    for (const internal::ManifestEntry& entry : impl.manifest.retained) {
      if (!entry.generation.published()) {
        continue;
      }
      const auto file = impl.load_generation(entry.generation);
      if (file.has_value() && file.value().digest == entry.digest &&
          file.value().generation == entry.generation) {
        continue;
      }
      // Content the store cannot verify is moved aside, never deleted and never
      // adopted. It is reported by verify() as quarantined content.
      if (impl.quarantine_generation(internal::generation_file_name(entry.generation))
              .has_value()) {
        quarantined = true;
      }
    }
    report.steps.push_back("retained.reverified");
    if (quarantined) {
      report.steps.push_back("retained.quarantined");
    }
  }

  // ---- residue: staged content and orphans newer than the adopted head -----
  CFM_TRY(staging_removed, impl.remove_staging_residue());
  CFM_TRY(orphans_removed, impl.retire_outside_window(impl.manifest.floor, impl.manifest.head));
  report.residue_removed = staging_removed + orphans_removed;
  report.steps.push_back("residue.removed");
  report.explanation =
      "adopted the retained previous publication because the committed head could not be "
      "verified";
  return report;
}

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------

Result<std::size_t> Store::reconcile_unresolved(const AuthoritySet& authority,
                                                const MutationId& mutation,
                                                const AttemptOrdinal& attempt) {
  if (impl_ == nullptr) {
    return Error(ErrorCode::NotInitialized, "store handle was never opened");
  }
  Impl& impl = *impl_;
  CFM_TRYV(impl.require_open());
  CFM_TRYV(impl.require_writable());
  CFM_TRYV(impl.require_head());
  if (!impl.manifest.head.published()) {
    return Error(ErrorCode::NotInitialized,
                 "the store holds no published state, so there is nothing to reconcile");
  }
  if (mutation.empty()) {
    return Error(ErrorCode::InvalidArgument, "a reconciliation requires a mutation identity");
  }
  if (attempt.value() == 0) {
    return Error(ErrorCode::InvalidArgument, "a reconciliation requires a 1-based attempt ordinal");
  }

  // The reconciliation identity is resolved before anything else is derived, so
  // a repeated call replays the recorded reconciliation even when the head has
  // moved on and even when nothing is in flight any more. Without this, a retry
  // could silently reconcile a different state. The record is read from the
  // committed manifest, so a reconciliation that crossed the commit point is
  // recognised however the process died afterwards.
  CFM_TRY(accepted, impl.find_accepted_attempt(mutation, attempt));
  if (!accepted.mutation.empty()) {
    // The number reported is read from the state the recorded reconciliation
    // published, which is the number its first execution reported.
    CFM_TRY(replayed_state, impl.load_generation(accepted.generation));
    return count_adopted_unresolved(replayed_state.body);
  }

  CFM_TRY(head_state, impl.head_state());
  CoolingFailureState reconciled = head_state;
  std::size_t converted = 0;
  std::vector<AttemptId> adopted;
  for (ResponsePlan& plan : reconciled.plans) {
    for (ResponseAttempt& candidate : plan.attempts) {
      if (!attempt_reconcilable(candidate.state)) {
        continue;
      }
      adopted.push_back(candidate.id);
      // The outcome of an attempt whose owner stopped is unknown. It is recorded
      // as unknown and never redispatched, so a lost response can never cause a
      // second consequential action.
      candidate.state = AttemptState::Unresolved;
      candidate.adopted_after_restart = true;
      // The reconciliation clock is the head state's evaluated_at: a
      // DecisionClock belongs to one publication, and inventing a newer one here
      // would date the record with a clock no decision was evaluated at.
      candidate.updated_at = head_state.evaluated_at;
      ++converted;
    }
  }
  // The state's own list of attempts that survived a restart is kept in step with
  // the attempts this call marked: an attempt recorded as adopted after a restart
  // and still unresolved is exactly what that list names.
  for (const AttemptId& id : adopted) {
    bool listed = false;
    for (const AttemptId& existing : reconciled.unresolved_attempts) {
      if (existing == id) {
        listed = true;
        break;
      }
    }
    if (!listed) {
      reconciled.unresolved_attempts.push_back(id);
    }
  }

  if (converted == 0) {
    // Nothing is in flight. A reconciliation is not a heartbeat: publishing an
    // unchanged state would burn a generation for no state change, so the call
    // publishes nothing and reports zero converted attempts.
    return 0;
  }

  PublicationRequest request;
  request.authority = authority;
  request.epoch = impl.epoch;
  request.incarnation = impl.incarnation;
  request.base_generation = impl.manifest.head;
  request.mutation = mutation;
  request.attempt = attempt;
  request.body = std::move(reconciled);
  CFM_TRY(receipt, publish(request));
  // A replay must not reconcile twice, and it must report what the first
  // execution reported. The number is therefore read from the state the
  // publication actually produced - the state the generation file carries - and
  // never re-derived from the current head.
  CFM_TRY(published, impl.load_generation(receipt.generation));
  return count_adopted_unresolved(published.body);
}

}  // namespace dccp::cooling_failure_manager
