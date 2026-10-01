// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_COOLING_FAILURE_MANAGER_TEXT_HPP
#define DCCP_COOLING_FAILURE_MANAGER_TEXT_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/result.hpp"

namespace dccp::cooling_failure_manager {

/// Strict UTF-8 validation: rejects overlong encodings, surrogate code points,
/// code points above U+10FFFF, embedded NUL and truncated sequences.
bool is_valid_utf8(std::string_view raw) noexcept;

/// Printable display text: valid UTF-8, no control characters, no NUL.
bool is_valid_display_text(std::string_view raw, std::size_t max_bytes) noexcept;

/// Opaque external identity bytes (cooling topology scope references, thermal
/// zone references, incident references, failure-domain references, capacity
/// references, sensor references).
///
/// Those identities are owned by their own components. This library preserves
/// their bytes exactly: the only checks are length, UTF-8 validity, absence of
/// NUL and truncation of *this* library's storage - never case folding, Unicode
/// normalization or trimming, so a reference can never silently resolve to a
/// different object than the one the producer named.
bool is_valid_external_identity(std::string_view raw, std::size_t max_bytes) noexcept;

/// Escapes arbitrary bytes into a quoted, ASCII-only rendering for diagnostics
/// and for the canonical text inspection form. Round-trips exactly through
/// unescape_text().
std::string escape_text(std::string_view raw);
Result<std::string> unescape_text(std::string_view escaped, std::size_t max_bytes);

/// Lowercase ASCII helper used by the token grammar.
std::string ascii_lower(std::string_view raw);

/// True when every byte is ASCII [0-9A-Za-z._:-].
bool is_ascii_token(std::string_view raw) noexcept;

/// Compares two external identities by exact bytes.
bool external_identity_equal(std::string_view lhs, std::string_view rhs) noexcept;

/// Parses a canonical unsigned decimal integer. Rejects a leading '+', a
/// leading zero on a multi-digit value, whitespace, an empty string and
/// anything above max_value.
Result<std::uint64_t> parse_uint64(std::string_view text, std::uint64_t max_value);

/// Parses a canonical signed decimal integer (optional '-', no leading zero on
/// a multi-digit magnitude, no whitespace). The magnitude bound is checked
/// before negation so that INT64_MIN cannot be produced by an unchecked path.
Result<std::int64_t> parse_int64(std::string_view text, std::int64_t min_value, std::int64_t max_value);

/// Renders a value as canonical unsigned decimal text.
std::string to_decimal(std::uint64_t value);
std::string to_decimal(std::int64_t value);

/// True when the string is a canonical unsigned decimal rendering produced by
/// to_decimal(). Used by the strict decoder.
bool is_canonical_uint(std::string_view text) noexcept;
bool is_canonical_int(std::string_view text) noexcept;

/// Splits a canonical record line on a single tab and returns the fields.
/// Rejects an empty field list, a trailing tab and an embedded NUL.
Result<std::vector<std::string_view>> split_fields(std::string_view line, char separator);

}  // namespace dccp::cooling_failure_manager

#endif  // DCCP_COOLING_FAILURE_MANAGER_TEXT_HPP
