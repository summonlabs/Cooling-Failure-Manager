// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_COOLING_FAILURE_MANAGER_RESULT_HPP
#define DCCP_COOLING_FAILURE_MANAGER_RESULT_HPP

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dccp::cooling_failure_manager {

/// Stable, machine-readable outcome codes.
///
/// These codes are part of the public contract. Existing values are never
/// renumbered or repurposed; new codes only extend the list. The textual name
/// returned by error_code_name() is equally stable.
enum class ErrorCode : std::uint16_t {
  Ok = 0,

  // ---- Input shape and encoding (untrusted data) -------------------------
  InvalidArgument,
  MalformedIdentifier,
  InvalidUtf8,
  TextTooLong,
  UnknownEnumToken,
  MissingField,
  DuplicateField,
  MalformedRecord,
  UnsupportedSchemaVersion,
  CountMismatch,
  TruncatedInput,
  DigestMismatch,
  LimitExceeded,
  EmptyInput,
  MalformedNumber,
  QuantityOutOfRange,
  TimestampOutOfRange,

  // ---- Boundary and domain shape ----------------------------------------
  EmptyFailureClassSet,
  DuplicateFailureClass,
  FailureClassConflict,
  FailureClassNotConfirmed,
  FailureClassUnsupportedForScope,
  EvidenceGap,
  EvidenceStale,
  EvidenceMissing,
  EvidenceConflicting,
  EvidenceNotCurrent,
  ObservationOutOfOrder,
  DuplicateIdentifier,
  ScopeNotFound,
  ScopeDuplicate,
  ScopeCycle,
  ScopeKindMismatch,
  FailureNotFound,
  FailureDuplicate,
  PlanNotFound,
  PlanDuplicate,
  PlanNotEligible,
  SolicitationNotFound,
  SolicitationDuplicate,
  AttemptNotFound,
  AttemptDuplicate,
  AttemptNotResolvable,
  AttemptAlreadyTerminal,
  AttemptOutstanding,
  RestrictionNotFound,
  RestrictionDuplicate,
  RecoveryGateFailed,
  RecoveryGateNotSatisfied,
  RecoveryDwellIncomplete,
  RecoveryHysteresisIncomplete,
  RecoveryAlreadyComplete,
  RecoveryNotInProgress,
  AcknowledgementInvalid,
  EffectClaimedWithoutEvidence,
  SharedSourceUnknown,

  // ---- Authority, generations and lifecycle ------------------------------
  GenerationMismatch,
  StaleBaseGeneration,
  StaleAuthorityEpoch,
  StaleWriterIncarnation,
  StaleDecision,
  StoreLocked,
  StoreClosed,
  StoreNotFound,
  StoreNotEmpty,
  StoreMismatch,
  StoreReadOnly,
  NotInitialized,
  GenerationAlreadyExists,
  GenerationNotRetained,
  GenerationFloorViolation,
  HeadMissing,
  HeadCorrupt,
  RecoveryRequired,
  RecoveryUnavailable,
  IntegrityFailure,
  PublicationIncomplete,
  IdempotencyConflict,
  IdempotencyEvicted,
  IoError,
  PathInvalid,
  PathTraversal,
  PathNotRegular,
  PathUnsafeName,
  InternalError,
};

/// Coarse classification of an ErrorCode.
enum class ErrorCategory : std::uint8_t {
  Ok = 0,
  Argument,     ///< caller-supplied or untrusted input was rejected
  Structure,    ///< the cooling failure state would be structurally invalid
  Evidence,     ///< the evidence is missing, stale or conflicting
  Authority,    ///< generation/epoch/incarnation precondition failed
  Persistence,  ///< durable state is missing, corrupt or unwritable
  Lifecycle,    ///< the store or an attempt is in the wrong state
  Limit,        ///< a configured bound was exceeded
  Internal,     ///< defect in the library
};

std::string_view error_code_name(ErrorCode code) noexcept;
ErrorCategory error_category(ErrorCode code) noexcept;
std::string_view error_category_name(ErrorCategory category) noexcept;

/// An error value: stable code, human explanation and optional subject.
class Error {
 public:
  Error() noexcept = default;

  Error(ErrorCode code, std::string message) : code_(code), message_(std::move(message)) {}

  ErrorCode code() const noexcept { return code_; }
  ErrorCategory category() const noexcept { return error_category(code_); }
  const std::string& message() const noexcept { return message_; }

  /// Identity of the object the error is about, when one exists.
  const std::string& subject() const noexcept { return subject_; }

  /// Non-fatal diagnostics attached to the error, in insertion order.
  const std::vector<std::string>& details() const noexcept { return details_; }

  Error& with_subject(std::string subject) {
    subject_ = std::move(subject);
    return *this;
  }

  Error& with_detail(std::string detail) {
    details_.push_back(std::move(detail));
    return *this;
  }

  bool ok() const noexcept { return code_ == ErrorCode::Ok; }

  /// "CODE: message" plus " [subject=...]" when a subject is present.
  std::string to_string() const;

 private:
  ErrorCode code_ = ErrorCode::Ok;
  std::string message_;
  std::string subject_;
  std::vector<std::string> details_;
};

/// Result of an operation that yields T or an Error.
///
/// The library never uses exceptions for expected failure modes; Result is the
/// only channel for them. value() throws std::logic_error only on programmer
/// error (dereferencing a failed Result).
template <class T>
class Result {
 public:
  Result(T value) : value_(std::move(value)) {}
  Result(Error error) : error_(normalize(std::move(error))) {}

  bool has_value() const noexcept { return value_.has_value(); }
  explicit operator bool() const noexcept { return has_value(); }

  T& value() & {
    require_value();
    return *value_;
  }
  const T& value() const& {
    require_value();
    return *value_;
  }
  T&& value() && {
    require_value();
    return std::move(*value_);
  }

  T& operator*() & { return value(); }
  const T& operator*() const& { return value(); }
  T* operator->() { return &value(); }
  const T* operator->() const { return &value(); }

  const Error& error() const noexcept { return error_; }

 private:
  static Error normalize(Error error) {
    if (error.ok()) {
      return Error(ErrorCode::InternalError, "result constructed without a value or an error");
    }
    return error;
  }

  void require_value() const {
    if (!value_.has_value()) {
      throw std::logic_error("cooling_failure_manager: Result has no value: " + error_.to_string());
    }
  }

  std::optional<T> value_;
  Error error_;
};

/// Result specialization for operations that produce no value.
template <>
class Result<void> {
 public:
  Result() noexcept = default;
  Result(Error error) : error_(normalize(std::move(error))) {}

  static Result success() noexcept { return Result(); }

  bool has_value() const noexcept { return error_.ok(); }
  explicit operator bool() const noexcept { return has_value(); }

  const Error& error() const noexcept { return error_; }

 private:
  static Error normalize(Error error) {
    if (error.ok()) {
      return Error(ErrorCode::InternalError, "result constructed without a value or an error");
    }
    return error;
  }

  Error error_;
};

inline Error make_error(ErrorCode code, std::string message) { return Error(code, std::move(message)); }

inline Result<void> ok() noexcept { return Result<void>(); }

}  // namespace dccp::cooling_failure_manager

/// Propagate a failed Result out of the current function.
#define CFM_TRY(value_name, expression)          \
  auto value_name##_cfm_result = (expression);   \
  if (!value_name##_cfm_result.has_value()) {    \
    return value_name##_cfm_result.error();      \
  }                                              \
  auto& value_name = *value_name##_cfm_result

/// Propagate a failed void Result out of the current function.
#define CFM_TRYV(expression)                 \
  do {                                       \
    auto cfm_result_ = (expression);         \
    if (!cfm_result_.has_value()) {          \
      return cfm_result_.error();            \
    }                                        \
  } while (false)

#endif  // DCCP_COOLING_FAILURE_MANAGER_RESULT_HPP
