// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/cooling_failure_manager/strong_id.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>

#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

namespace dccp::cooling_failure_manager {
namespace {

bool is_alphanumeric(char character) noexcept {
  return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'z') ||
         (character >= 'A' && character <= 'Z');
}

/// Interior bytes are ASCII alphanumeric or one of '.', '_', ':' and '-'. The
/// set is exactly the one is_ascii_token() accepts, so the identifier grammar
/// and the canonical token grammar have a single definition.
bool is_interior(char character) noexcept {
  return is_alphanumeric(character) || character == '.' || character == '_' || character == ':' ||
         character == '-';
}

/// Renders a signed value for an error subject without depending on any locale.
std::string decimal_subject(std::int64_t value) { return to_decimal(value); }

}  // namespace

bool is_valid_identifier_syntax(std::string_view raw) noexcept {
  if (raw.empty() || raw.size() > limits::kMaxIdentifierBytes) {
    return false;
  }
  // Both ends must be alphanumeric, so an identifier can never begin or end
  // with a separator that a path, a glob or a dotted-name reader would consume.
  if (!is_alphanumeric(raw.front()) || !is_alphanumeric(raw.back())) {
    return false;
  }
  for (const char character : raw) {
    if (!is_interior(character)) {
      return false;
    }
  }
  return true;
}

std::string_view identifier_syntax_help() noexcept {
  return "1..128 bytes; first and last byte ASCII alphanumeric; interior bytes ASCII alphanumeric or one "
         "of . _ : -";
}

Result<DecisionClock> DecisionClock::parse(std::int64_t milliseconds) {
  // -1 is the documented "absent clock" value. Everything below it is not an
  // absent clock but a value on no timeline this library accepts, and every
  // value above the year 2100 bound is outside the synthetic timeline too.
  if (milliseconds < -1 || milliseconds > limits::kMaxTimestampMilliseconds) {
    return Error(ErrorCode::TimestampOutOfRange,
                 "decision clock must be -1 (absent) or within 0..4102444800000 milliseconds")
        .with_subject(decimal_subject(milliseconds));
  }
  return DecisionClock(milliseconds);
}

Result<std::int64_t> DecisionClock::since(DecisionClock earlier) const {
  const std::int64_t now = milliseconds_;
  const std::int64_t reference = earlier.milliseconds_;
  // Subtraction overflow is checked before the subtraction itself: b < 0 makes
  // max + b safe, b > 0 makes min + b safe, and every other combination cannot
  // overflow.
  if ((reference < 0 && now > std::numeric_limits<std::int64_t>::max() + reference) ||
      (reference > 0 && now < std::numeric_limits<std::int64_t>::min() + reference)) {
    return Error(ErrorCode::LimitExceeded, "elapsed time does not fit in a signed 64-bit millisecond count")
        .with_subject(decimal_subject(now));
  }
  const std::int64_t elapsed = now - reference;
  if (elapsed < 0) {
    // A reference clock in the future is a caller defect, not a zero-length
    // interval, so it is reported instead of being clamped.
    return Error(ErrorCode::TimestampOutOfRange, "elapsed time is negative: the reference clock is later than this clock")
        .with_subject(decimal_subject(reference));
  }
  return elapsed;
}

Result<DurationMilliseconds> DurationMilliseconds::parse(std::int64_t milliseconds) {
  if (milliseconds < 0 || milliseconds > limits::kMaxWindowMilliseconds) {
    return Error(ErrorCode::QuantityOutOfRange,
                 "duration must be within 0..86400000 milliseconds (24 h)")
        .with_subject(decimal_subject(milliseconds));
  }
  return DurationMilliseconds(milliseconds);
}

}  // namespace dccp::cooling_failure_manager
