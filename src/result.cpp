// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/cooling_failure_manager/result.hpp"

#include <cstddef>
#include <cstdint>
#include <iterator>

namespace dccp::cooling_failure_manager {
namespace {

/// One row of the single source of truth for ErrorCode names and categories.
struct Entry {
  ErrorCode code;
  std::string_view name;
  ErrorCategory category;
};

// The table below is the single source of truth for both the textual name and
// the coarse category of every ErrorCode. Rows are in the enumerator order of
// the header, which the compile-time checks underneath prove, so the table and
// the enumeration can never drift apart. Values are never renumbered or
// repurposed and a name is never renamed once published; a new code is appended
// inside the section of the codes it belongs to. The name is exactly the
// enumerator spelling, so a reader of a log line and a reader of the header see
// the same word.
//
// The category column is the coarse classification callers switch on. It is not
// a copy of the header's section comments: path codes and the generation-floor
// codes are categorised where the failure is observed rather than where the
// enumerator happens to be declared.
constexpr Entry kEntries[] = {
    {ErrorCode::Ok, "Ok", ErrorCategory::Ok},

    // ---- Input shape and encoding (untrusted data) -------------------------
    {ErrorCode::InvalidArgument, "InvalidArgument", ErrorCategory::Argument},
    {ErrorCode::MalformedIdentifier, "MalformedIdentifier", ErrorCategory::Argument},
    {ErrorCode::InvalidUtf8, "InvalidUtf8", ErrorCategory::Argument},
    {ErrorCode::TextTooLong, "TextTooLong", ErrorCategory::Argument},
    {ErrorCode::UnknownEnumToken, "UnknownEnumToken", ErrorCategory::Argument},
    {ErrorCode::MissingField, "MissingField", ErrorCategory::Argument},
    {ErrorCode::DuplicateField, "DuplicateField", ErrorCategory::Argument},
    {ErrorCode::MalformedRecord, "MalformedRecord", ErrorCategory::Argument},
    {ErrorCode::UnsupportedSchemaVersion, "UnsupportedSchemaVersion", ErrorCategory::Argument},
    {ErrorCode::CountMismatch, "CountMismatch", ErrorCategory::Argument},
    {ErrorCode::TruncatedInput, "TruncatedInput", ErrorCategory::Argument},
    {ErrorCode::DigestMismatch, "DigestMismatch", ErrorCategory::Argument},
    {ErrorCode::LimitExceeded, "LimitExceeded", ErrorCategory::Argument},
    {ErrorCode::EmptyInput, "EmptyInput", ErrorCategory::Argument},
    {ErrorCode::MalformedNumber, "MalformedNumber", ErrorCategory::Argument},
    {ErrorCode::QuantityOutOfRange, "QuantityOutOfRange", ErrorCategory::Argument},
    {ErrorCode::TimestampOutOfRange, "TimestampOutOfRange", ErrorCategory::Argument},

    // ---- Boundary and domain shape, with the evidence codes in place ------
    {ErrorCode::EmptyFailureClassSet, "EmptyFailureClassSet", ErrorCategory::Structure},
    {ErrorCode::DuplicateFailureClass, "DuplicateFailureClass", ErrorCategory::Structure},
    {ErrorCode::FailureClassConflict, "FailureClassConflict", ErrorCategory::Structure},
    {ErrorCode::FailureClassNotConfirmed, "FailureClassNotConfirmed", ErrorCategory::Structure},
    {ErrorCode::FailureClassUnsupportedForScope, "FailureClassUnsupportedForScope", ErrorCategory::Structure},
    {ErrorCode::EvidenceGap, "EvidenceGap", ErrorCategory::Evidence},
    {ErrorCode::EvidenceStale, "EvidenceStale", ErrorCategory::Evidence},
    {ErrorCode::EvidenceMissing, "EvidenceMissing", ErrorCategory::Evidence},
    {ErrorCode::EvidenceConflicting, "EvidenceConflicting", ErrorCategory::Evidence},
    {ErrorCode::EvidenceNotCurrent, "EvidenceNotCurrent", ErrorCategory::Evidence},
    {ErrorCode::ObservationOutOfOrder, "ObservationOutOfOrder", ErrorCategory::Evidence},
    {ErrorCode::DuplicateIdentifier, "DuplicateIdentifier", ErrorCategory::Structure},
    {ErrorCode::ScopeNotFound, "ScopeNotFound", ErrorCategory::Structure},
    {ErrorCode::ScopeDuplicate, "ScopeDuplicate", ErrorCategory::Structure},
    {ErrorCode::ScopeCycle, "ScopeCycle", ErrorCategory::Structure},
    {ErrorCode::ScopeKindMismatch, "ScopeKindMismatch", ErrorCategory::Structure},
    {ErrorCode::FailureNotFound, "FailureNotFound", ErrorCategory::Structure},
    {ErrorCode::FailureDuplicate, "FailureDuplicate", ErrorCategory::Structure},
    {ErrorCode::PlanNotFound, "PlanNotFound", ErrorCategory::Structure},
    {ErrorCode::PlanDuplicate, "PlanDuplicate", ErrorCategory::Structure},
    {ErrorCode::PlanNotEligible, "PlanNotEligible", ErrorCategory::Structure},
    {ErrorCode::SolicitationNotFound, "SolicitationNotFound", ErrorCategory::Structure},
    {ErrorCode::SolicitationDuplicate, "SolicitationDuplicate", ErrorCategory::Structure},
    {ErrorCode::AttemptNotFound, "AttemptNotFound", ErrorCategory::Structure},
    {ErrorCode::AttemptDuplicate, "AttemptDuplicate", ErrorCategory::Structure},
    {ErrorCode::AttemptNotResolvable, "AttemptNotResolvable", ErrorCategory::Structure},
    {ErrorCode::AttemptAlreadyTerminal, "AttemptAlreadyTerminal", ErrorCategory::Structure},
    {ErrorCode::AttemptOutstanding, "AttemptOutstanding", ErrorCategory::Structure},
    {ErrorCode::RestrictionNotFound, "RestrictionNotFound", ErrorCategory::Structure},
    {ErrorCode::RestrictionDuplicate, "RestrictionDuplicate", ErrorCategory::Structure},
    {ErrorCode::RecoveryGateFailed, "RecoveryGateFailed", ErrorCategory::Structure},
    {ErrorCode::RecoveryGateNotSatisfied, "RecoveryGateNotSatisfied", ErrorCategory::Structure},
    {ErrorCode::RecoveryDwellIncomplete, "RecoveryDwellIncomplete", ErrorCategory::Structure},
    {ErrorCode::RecoveryHysteresisIncomplete, "RecoveryHysteresisIncomplete", ErrorCategory::Structure},
    {ErrorCode::RecoveryAlreadyComplete, "RecoveryAlreadyComplete", ErrorCategory::Structure},
    {ErrorCode::RecoveryNotInProgress, "RecoveryNotInProgress", ErrorCategory::Structure},
    {ErrorCode::AcknowledgementInvalid, "AcknowledgementInvalid", ErrorCategory::Structure},
    {ErrorCode::EffectClaimedWithoutEvidence, "EffectClaimedWithoutEvidence", ErrorCategory::Structure},
    {ErrorCode::SharedSourceUnknown, "SharedSourceUnknown", ErrorCategory::Structure},

    // ---- Authority, generations and lifecycle ------------------------------
    {ErrorCode::GenerationMismatch, "GenerationMismatch", ErrorCategory::Authority},
    {ErrorCode::StaleBaseGeneration, "StaleBaseGeneration", ErrorCategory::Authority},
    {ErrorCode::StaleAuthorityEpoch, "StaleAuthorityEpoch", ErrorCategory::Authority},
    {ErrorCode::StaleWriterIncarnation, "StaleWriterIncarnation", ErrorCategory::Authority},
    {ErrorCode::StaleDecision, "StaleDecision", ErrorCategory::Authority},
    {ErrorCode::StoreLocked, "StoreLocked", ErrorCategory::Lifecycle},
    {ErrorCode::StoreClosed, "StoreClosed", ErrorCategory::Lifecycle},
    {ErrorCode::StoreNotFound, "StoreNotFound", ErrorCategory::Persistence},
    {ErrorCode::StoreNotEmpty, "StoreNotEmpty", ErrorCategory::Persistence},
    {ErrorCode::StoreMismatch, "StoreMismatch", ErrorCategory::Persistence},
    {ErrorCode::StoreReadOnly, "StoreReadOnly", ErrorCategory::Lifecycle},
    {ErrorCode::NotInitialized, "NotInitialized", ErrorCategory::Lifecycle},
    {ErrorCode::GenerationAlreadyExists, "GenerationAlreadyExists", ErrorCategory::Persistence},
    {ErrorCode::GenerationNotRetained, "GenerationNotRetained", ErrorCategory::Persistence},
    {ErrorCode::GenerationFloorViolation, "GenerationFloorViolation", ErrorCategory::Persistence},
    {ErrorCode::HeadMissing, "HeadMissing", ErrorCategory::Persistence},
    {ErrorCode::HeadCorrupt, "HeadCorrupt", ErrorCategory::Persistence},
    {ErrorCode::RecoveryRequired, "RecoveryRequired", ErrorCategory::Persistence},
    {ErrorCode::RecoveryUnavailable, "RecoveryUnavailable", ErrorCategory::Persistence},
    {ErrorCode::IntegrityFailure, "IntegrityFailure", ErrorCategory::Persistence},
    {ErrorCode::PublicationIncomplete, "PublicationIncomplete", ErrorCategory::Persistence},
    {ErrorCode::IdempotencyConflict, "IdempotencyConflict", ErrorCategory::Lifecycle},
    {ErrorCode::IdempotencyEvicted, "IdempotencyEvicted", ErrorCategory::Lifecycle},
    {ErrorCode::IoError, "IoError", ErrorCategory::Persistence},
    {ErrorCode::PathInvalid, "PathInvalid", ErrorCategory::Persistence},
    {ErrorCode::PathTraversal, "PathTraversal", ErrorCategory::Persistence},
    {ErrorCode::PathNotRegular, "PathNotRegular", ErrorCategory::Persistence},
    {ErrorCode::PathUnsafeName, "PathUnsafeName", ErrorCategory::Persistence},
    {ErrorCode::InternalError, "InternalError", ErrorCategory::Internal},
};

// NOTE: ErrorCategory::Limit exists so a caller can classify a bound it owns;
// no ErrorCode maps to it because LimitExceeded is reported for a rejected input
// shape or magnitude and therefore belongs to Argument.

/// Name of a code that is not an enumerator. It is deliberately not a legal
/// enumerator spelling, so a missing table row can never be mistaken for a real
/// code name.
constexpr std::string_view kUnknownName = "UnknownErrorCode";

constexpr const Entry* find_entry(ErrorCode code) noexcept {
  for (const Entry& entry : kEntries) {
    if (entry.code == code) {
      return &entry;
    }
  }
  return nullptr;
}

// Compile-time proofs over the table. They hold for every enumerator present in
// the header today and fail the build when a future enumerator is added without
// a name and a category, which is the only way the table can fall behind.

constexpr bool table_is_in_enum_order() noexcept {
  for (std::size_t index = 0; index < std::size(kEntries); ++index) {
    if (static_cast<std::size_t>(kEntries[index].code) != index) {
      return false;
    }
  }
  return true;
}

constexpr bool table_covers_every_enumerator() noexcept {
  // The enumerators are contiguous from Ok, so a table in enum order that ends
  // at the last declared enumerator names every one of them exactly once.
  return std::size(kEntries) == static_cast<std::size_t>(ErrorCode::InternalError) + 1u;
}

constexpr bool names_are_non_empty() noexcept {
  for (const Entry& entry : kEntries) {
    if (entry.name.empty()) {
      return false;
    }
  }
  return true;
}

constexpr bool names_are_unique() noexcept {
  for (std::size_t lhs = 0; lhs < std::size(kEntries); ++lhs) {
    for (std::size_t rhs = lhs + 1; rhs < std::size(kEntries); ++rhs) {
      if (kEntries[lhs].name == kEntries[rhs].name) {
        return false;
      }
    }
  }
  return true;
}

static_assert(table_is_in_enum_order(), "kEntries must be in ErrorCode enumerator order");
static_assert(table_covers_every_enumerator(), "kEntries must name every ErrorCode enumerator");
static_assert(names_are_non_empty(), "every ErrorCode name must be non-empty");
static_assert(names_are_unique(), "ErrorCode names must be unique");

}  // namespace

std::string_view error_code_name(ErrorCode code) noexcept {
  const Entry* entry = find_entry(code);
  return entry == nullptr ? kUnknownName : entry->name;
}

ErrorCategory error_category(ErrorCode code) noexcept {
  const Entry* entry = find_entry(code);
  // A value outside the enumeration is a defect in the library, never a
  // structural outcome, and is reported as such instead of crashing.
  return entry == nullptr ? ErrorCategory::Internal : entry->category;
}

std::string_view error_category_name(ErrorCategory category) noexcept {
  // Exhaustive without a default label: an enumerator added without a name is a
  // compile-time diagnostic instead of a silent fallback.
  switch (category) {
    case ErrorCategory::Ok:
      return "OK";
    case ErrorCategory::Argument:
      return "ARGUMENT";
    case ErrorCategory::Structure:
      return "STRUCTURE";
    case ErrorCategory::Evidence:
      return "EVIDENCE";
    case ErrorCategory::Authority:
      return "AUTHORITY";
    case ErrorCategory::Persistence:
      return "PERSISTENCE";
    case ErrorCategory::Lifecycle:
      return "LIFECYCLE";
    case ErrorCategory::Limit:
      return "LIMIT";
    case ErrorCategory::Internal:
      return "INTERNAL";
  }
  return "UNKNOWN";
}

std::string Error::to_string() const {
  std::string out(error_code_name(code_));
  out.append(": ");
  out.append(message_);
  if (!subject_.empty()) {
    out.append(" [subject=");
    out.append(subject_);
    out.push_back(']');
  }
  for (const std::string& detail : details_) {
    out.append(" [detail=");
    out.append(detail);
    out.push_back(']');
  }
  return out;
}

}  // namespace dccp::cooling_failure_manager
