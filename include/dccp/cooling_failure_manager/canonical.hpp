// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_COOLING_FAILURE_MANAGER_CANONICAL_HPP
#define DCCP_COOLING_FAILURE_MANAGER_CANONICAL_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "dccp/cooling_failure_manager/model.hpp"
#include "dccp/cooling_failure_manager/result.hpp"

namespace dccp::cooling_failure_manager {

/// Canonical text encoding of cooling-failure state.
///
/// The encoding is a deterministic, versioned, line-oriented text form:
///
///   * one record per line, records separated by a single '\\n';
///   * records never contain a raw tab, '\\n' or NUL - every free-text field is
///     escaped;
///   * every table is emitted in the canonical order established by
///     canonicalize(), so two states that differ only in insertion order encode
///     to identical bytes;
///   * numbers are canonical decimal (no leading '+', no leading zeroes, no
///     exponent, no whitespace);
///   * the first line names the format and its version, so an incompatible file
///     is refused instead of misread;
///   * the last line is the record count and a digest over every preceding byte,
///     so truncation, duplication and reordering are all detected.
///
/// Decoding is strict: an unknown record name, a missing or extra field, a
/// count that disagrees with the body, a duplicate identity, an out-of-order
/// table, a bad digest or a bound violation is an error. The decoder never
/// repairs and never guesses.
std::string encode_state(const CoolingFailureState& state);

/// Decodes canonical text. On success the decoded state is verified against its
/// own digest and reported through a canonical fixed point re-encode.
Result<CoolingFailureState> decode_state(std::string_view text);

/// Digest of the canonical encoding of a state. Two states that encode to the
/// same bytes have equal digests; a state whose canonical form is not a fixed
/// point has no valid digest.
Digest state_digest(const CoolingFailureState& state);

/// The format identifier of the canonical encoding ("dccp-cooling-failure-state").
std::string_view canonical_format_name() noexcept;

/// The format version of the canonical encoding.
std::uint32_t canonical_format_version() noexcept;

/// Digest of an accepted-attempt record. Separate from state_digest so that a
/// record and a state can never be confused for one another.
Digest attempt_record_digest(std::string_view canonical_record);

}  // namespace dccp::cooling_failure_manager

#endif  // DCCP_COOLING_FAILURE_MANAGER_CANONICAL_HPP
