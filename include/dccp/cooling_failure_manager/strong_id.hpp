// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_COOLING_FAILURE_MANAGER_STRONG_ID_HPP
#define DCCP_COOLING_FAILURE_MANAGER_STRONG_ID_HPP

#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/result.hpp"

namespace dccp::cooling_failure_manager {

/// Identifier syntax (canonical form):
///   - 1..128 bytes;
///   - first and last byte are ASCII alphanumeric;
///   - interior bytes are ASCII alphanumeric or one of '.', '_', ':', '-'.
///
/// The grammar deliberately contains no whitespace, quoting, path separators or
/// non-ASCII bytes, so canonical encoding is escape-free and an identifier can
/// never smuggle a path, a control character or a look-alike into durable
/// state. Identifiers are case-sensitive and never normalized.
bool is_valid_identifier_syntax(std::string_view raw) noexcept;

/// Explains why an identifier was rejected (empty view when it is valid).
std::string_view identifier_syntax_help() noexcept;

/// Tag types selecting a distinct StrongId instantiation. Unrelated identities
/// are distinct C++ types and cannot be converted into one another, so a
/// cooling scope can never be passed where a response plan is expected.
struct ScopeIdTag {
  static constexpr std::string_view kind_name = "scope";
};
struct FailureIdTag {
  static constexpr std::string_view kind_name = "failure";
};
struct PlanIdTag {
  static constexpr std::string_view kind_name = "response-plan";
};
struct RestrictionIdTag {
  static constexpr std::string_view kind_name = "restriction";
};
struct RecoveryGateIdTag {
  static constexpr std::string_view kind_name = "recovery-gate";
};
struct SolicitationIdTag {
  static constexpr std::string_view kind_name = "solicitation";
};
struct AttemptIdTag {
  static constexpr std::string_view kind_name = "attempt";
};
struct ObservationIdTag {
  static constexpr std::string_view kind_name = "observation";
};
struct StoreIdTag {
  static constexpr std::string_view kind_name = "store";
};
struct MutationIdTag {
  static constexpr std::string_view kind_name = "mutation";
};

/// A validated, strongly typed identifier.
///
/// Construction only succeeds through parse(). The default-constructed value is
/// empty and exists only so identifiers can live in containers; an empty
/// identifier is never written to durable state and is rejected by every public
/// entry point that requires one.
template <class Tag>
class StrongId {
 public:
  using tag_type = Tag;

  StrongId() noexcept = default;

  /// Parses and validates untrusted text.
  static Result<StrongId> parse(std::string_view raw) {
    if (!is_valid_identifier_syntax(raw)) {
      return Error(ErrorCode::MalformedIdentifier,
                   "identifier does not match the canonical grammar (1..128 bytes, ASCII "
                   "alphanumeric first/last byte, interior [A-Za-z0-9._:-])")
          .with_subject(std::string(raw.substr(0, 160)));
    }
    return StrongId(std::string(raw));
  }

  bool empty() const noexcept { return value_.empty(); }
  std::string_view value() const noexcept { return value_; }
  const std::string& str() const noexcept { return value_; }

  friend bool operator==(const StrongId& lhs, const StrongId& rhs) noexcept = default;

  /// Byte-wise ordering, identical on every platform.
  friend std::strong_ordering operator<=>(const StrongId& lhs, const StrongId& rhs) noexcept {
    const int cmp = lhs.value_.compare(rhs.value_);
    return cmp < 0 ? std::strong_ordering::less
                   : (cmp > 0 ? std::strong_ordering::greater : std::strong_ordering::equal);
  }

 private:
  explicit StrongId(std::string value) : value_(std::move(value)) {}

  std::string value_;
};

using ScopeId = StrongId<ScopeIdTag>;
using FailureId = StrongId<FailureIdTag>;
using PlanId = StrongId<PlanIdTag>;
using RestrictionId = StrongId<RestrictionIdTag>;
using RecoveryGateId = StrongId<RecoveryGateIdTag>;
using SolicitationId = StrongId<SolicitationIdTag>;
using AttemptId = StrongId<AttemptIdTag>;
using ObservationId = StrongId<ObservationIdTag>;
using StoreId = StrongId<StoreIdTag>;

/// Caller-supplied idempotency key of one mutation and of one response
/// attempt. Deliberately distinct from every other identity so a mutation key
/// can never be passed where a scope or a plan is expected.
using MutationId = StrongId<MutationIdTag>;

// ---------------------------------------------------------------------------
// Counters that are semantically distinct and therefore distinct types
// ---------------------------------------------------------------------------

/// Monotonic generation counter of *published* cooling failure state.
///
/// Generation 0 means "no state published yet"; published generations start at
/// 1. Distinct from every other counter: mixing two of them requires an explicit
/// conversion and no arithmetic is implicit.
class StateGeneration {
 public:
  static constexpr std::uint64_t kFirstPublished = 1;

  constexpr StateGeneration() noexcept = default;
  explicit constexpr StateGeneration(std::uint64_t value) noexcept : value_(value) {}

  static Result<StateGeneration> parse(std::uint64_t value) { return StateGeneration(value); }

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool published() const noexcept { return value_ != 0; }

  /// Strictly increasing successor. Overflow is reported, never wrapped.
  Result<StateGeneration> next() const {
    if (value_ == UINT64_MAX) {
      return Error(ErrorCode::LimitExceeded, "state generation counter exhausted")
          .with_subject(std::to_string(value_));
    }
    return StateGeneration(value_ + 1);
  }

  friend constexpr bool operator==(const StateGeneration&, const StateGeneration&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const StateGeneration& lhs,
                                                    const StateGeneration& rhs) noexcept = default;

 private:
  std::uint64_t value_ = 0;
};

/// Revision of an in-memory, un-published decision draft.
///
/// A draft revision is *not* a generation: drafts have no durable identity, no
/// digest of record and no authority.
class DraftRevision {
 public:
  constexpr DraftRevision() noexcept = default;
  explicit constexpr DraftRevision(std::uint64_t value) noexcept : value_(value) {}

  constexpr std::uint64_t value() const noexcept { return value_; }

  Result<DraftRevision> next() const {
    if (value_ == UINT64_MAX) {
      return Error(ErrorCode::LimitExceeded, "draft revision counter exhausted");
    }
    return DraftRevision(value_ + 1);
  }

  friend constexpr bool operator==(const DraftRevision&, const DraftRevision&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const DraftRevision& lhs,
                                                    const DraftRevision& rhs) noexcept = default;

 private:
  std::uint64_t value_ = 0;
};

/// Durable mutation-authority epoch of a store.
///
/// Opening a store for mutation reserves the next epoch durably before any
/// mutation is accepted. A mutation planned under an older epoch is fenced and
/// rejected instead of being applied to state the caller no longer owns.
class WriterEpoch {
 public:
  constexpr WriterEpoch() noexcept = default;
  explicit constexpr WriterEpoch(std::uint64_t value) noexcept : value_(value) {}

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool valid() const noexcept { return value_ != 0; }

  static Result<WriterEpoch> parse(std::uint64_t value) { return WriterEpoch(value); }

  Result<WriterEpoch> next() const {
    if (value_ == UINT64_MAX) {
      return Error(ErrorCode::LimitExceeded, "writer epoch counter exhausted");
    }
    return WriterEpoch(value_ + 1);
  }

  friend constexpr bool operator==(const WriterEpoch&, const WriterEpoch&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const WriterEpoch& lhs,
                                                    const WriterEpoch& rhs) noexcept = default;

 private:
  std::uint64_t value_ = 0;
};

/// Incarnation of one concrete mutation-authority holder (one successful
/// open-for-write) within its epoch.
///
/// Durably assigned, strictly increasing within a store, and never derived from
/// a process id, a path, a clock or a random number, so it is reproducible in
/// tests and meaningless to an attacker.
class WriterIncarnation {
 public:
  constexpr WriterIncarnation() noexcept = default;
  explicit constexpr WriterIncarnation(std::uint64_t value) noexcept : value_(value) {}

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool valid() const noexcept { return value_ != 0; }

  Result<WriterIncarnation> next() const {
    if (value_ == UINT64_MAX) {
      return Error(ErrorCode::LimitExceeded, "writer incarnation counter exhausted");
    }
    return WriterIncarnation(value_ + 1);
  }

  friend constexpr bool operator==(const WriterIncarnation&, const WriterIncarnation&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const WriterIncarnation& lhs,
                                                    const WriterIncarnation& rhs) noexcept = default;

 private:
  std::uint64_t value_ = 0;
};

/// Ordinal of one attempt at a mutation or at a solicited cooling response,
/// starting at 1.
///
/// (MutationId, AttemptOrdinal) identifies one *attempt*: a first attempt and a
/// retry of it share the ordinal and are therefore replay, whereas an
/// intentional second attempt of the same shape must use a new MutationId.
class AttemptOrdinal {
 public:
  constexpr AttemptOrdinal() noexcept = default;
  explicit constexpr AttemptOrdinal(std::uint32_t value) noexcept : value_(value) {}

  static Result<AttemptOrdinal> parse(std::uint32_t value) {
    if (value == 0) {
      return Error(ErrorCode::InvalidArgument, "attempt ordinal is 1-based and must not be zero");
    }
    return AttemptOrdinal(value);
  }

  constexpr std::uint32_t value() const noexcept { return value_; }

  friend constexpr bool operator==(const AttemptOrdinal&, const AttemptOrdinal&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const AttemptOrdinal& lhs,
                                                    const AttemptOrdinal& rhs) noexcept = default;

 private:
  std::uint32_t value_ = 0;
};

/// Monotone commit sequence assigned by a store to each committed publication.
///
/// A persistence counter: assigned at the commit point of a publication and
/// never derived from, equal to, or interchangeable with a state generation.
class CommitSequence {
 public:
  constexpr CommitSequence() noexcept = default;
  explicit constexpr CommitSequence(std::uint64_t value) noexcept : value_(value) {}

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool committed() const noexcept { return value_ != 0; }

  Result<CommitSequence> next() const {
    if (value_ == UINT64_MAX) {
      return Error(ErrorCode::LimitExceeded, "commit sequence counter exhausted");
    }
    return CommitSequence(value_ + 1);
  }

  friend constexpr bool operator==(const CommitSequence&, const CommitSequence&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const CommitSequence& lhs,
                                                    const CommitSequence& rhs) noexcept = default;

 private:
  std::uint64_t value_ = 0;
};

/// Generation counter of an *external* binding (cooling topology, cooling
/// capacity, thermal zone, incident, failure domain, airflow/liquid-cooling
/// control plane, sensor registry, policy).
///
/// This library records the binding so a reference can be checked for staleness
/// by its owner; it never advances the counter itself and never treats a
/// binding as evidence of authority, health or capability.
class ExternalGeneration {
 public:
  constexpr ExternalGeneration() noexcept = default;
  explicit constexpr ExternalGeneration(std::uint64_t value) noexcept : value_(value) {}

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool bound() const noexcept { return value_ != 0; }

  static Result<ExternalGeneration> parse(std::uint64_t value) { return ExternalGeneration(value); }

  friend constexpr bool operator==(const ExternalGeneration&, const ExternalGeneration&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const ExternalGeneration& lhs,
                                                    const ExternalGeneration& rhs) noexcept = default;

 private:
  std::uint64_t value_ = 0;
};

/// Authority epoch of an adjacent supervision plane that this library is told
/// about (for example the epoch of the incident owner that authorized a
/// response). Recorded as provenance only: never interpreted as permission.
class AuthorityEpoch {
 public:
  constexpr AuthorityEpoch() noexcept = default;
  explicit constexpr AuthorityEpoch(std::uint64_t value) noexcept : value_(value) {}

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool bound() const noexcept { return value_ != 0; }

  friend constexpr bool operator==(const AuthorityEpoch&, const AuthorityEpoch&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const AuthorityEpoch& lhs,
                                                    const AuthorityEpoch& rhs) noexcept = default;

 private:
  std::uint64_t value_ = 0;
};

/// Generation of an *external observation* that a producer supplies as
/// evidence. Distinct from ExternalGeneration (a binding) and from
/// AuthorityEpoch (a supervision epoch): evidence generation identifies one
/// version of an observation stream owned by another component.
class EvidenceGeneration {
 public:
  constexpr EvidenceGeneration() noexcept = default;
  explicit constexpr EvidenceGeneration(std::uint64_t value) noexcept : value_(value) {}

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool bound() const noexcept { return value_ != 0; }

  friend constexpr bool operator==(const EvidenceGeneration&, const EvidenceGeneration&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const EvidenceGeneration& lhs,
                                                    const EvidenceGeneration& rhs) noexcept = default;

 private:
  std::uint64_t value_ = 0;
};

/// Sequence number of one observation owned by another component.
///
/// Recorded so that evidence for one scope can be ordered and checked for
/// out-of-order arrival. Never consumed as a permission, a measurement or an
/// operating state.
class ObservationSequence {
 public:
  constexpr ObservationSequence() noexcept = default;
  explicit constexpr ObservationSequence(std::uint64_t value) noexcept : value_(value) {}

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool present() const noexcept { return value_ != 0; }

  friend constexpr bool operator==(const ObservationSequence&, const ObservationSequence&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const ObservationSequence& lhs,
                                                    const ObservationSequence& rhs) noexcept = default;

 private:
  std::uint64_t value_ = 0;
};

/// Milliseconds on the caller-owned synthetic timeline of one decision. The
/// library never reads the host clock, so an explanation is reproducible from
/// its inputs alone.
class DecisionClock {
 public:
  constexpr DecisionClock() noexcept = default;
  explicit constexpr DecisionClock(std::int64_t milliseconds) noexcept : milliseconds_(milliseconds) {}

  static Result<DecisionClock> parse(std::int64_t milliseconds);

  constexpr std::int64_t milliseconds() const noexcept { return milliseconds_; }
  constexpr bool present() const noexcept { return milliseconds_ >= 0; }

  /// Checked elapsed time. A negative difference (the reference is in the
  /// future) is reported, never silently treated as zero.
  Result<std::int64_t> since(DecisionClock earlier) const;

  friend constexpr bool operator==(const DecisionClock&, const DecisionClock&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const DecisionClock& lhs,
                                                    const DecisionClock& rhs) noexcept = default;

 private:
  std::int64_t milliseconds_ = -1;
};

/// A bounded duration in milliseconds on the same synthetic timeline.
class DurationMilliseconds {
 public:
  constexpr DurationMilliseconds() noexcept = default;
  explicit constexpr DurationMilliseconds(std::int64_t milliseconds) noexcept
      : milliseconds_(milliseconds) {}

  static Result<DurationMilliseconds> parse(std::int64_t milliseconds);

  constexpr std::int64_t milliseconds() const noexcept { return milliseconds_; }
  constexpr bool zero() const noexcept { return milliseconds_ == 0; }

  friend constexpr bool operator==(const DurationMilliseconds&, const DurationMilliseconds&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const DurationMilliseconds& lhs,
                                                    const DurationMilliseconds& rhs) noexcept = default;

 private:
  std::int64_t milliseconds_ = 0;
};

}  // namespace dccp::cooling_failure_manager

namespace std {
template <class Tag>
struct hash<dccp::cooling_failure_manager::StrongId<Tag>> {
  std::size_t operator()(const dccp::cooling_failure_manager::StrongId<Tag>& id) const noexcept {
    return std::hash<std::string_view>{}(id.value());
  }
};
template <>
struct hash<dccp::cooling_failure_manager::StateGeneration> {
  std::size_t operator()(const dccp::cooling_failure_manager::StateGeneration& value) const noexcept {
    return std::hash<std::uint64_t>{}(value.value());
  }
};
template <>
struct hash<dccp::cooling_failure_manager::WriterEpoch> {
  std::size_t operator()(const dccp::cooling_failure_manager::WriterEpoch& value) const noexcept {
    return std::hash<std::uint64_t>{}(value.value());
  }
};
template <>
struct hash<dccp::cooling_failure_manager::WriterIncarnation> {
  std::size_t operator()(const dccp::cooling_failure_manager::WriterIncarnation& value) const noexcept {
    return std::hash<std::uint64_t>{}(value.value());
  }
};
}  // namespace std

#endif  // DCCP_COOLING_FAILURE_MANAGER_STRONG_ID_HPP
