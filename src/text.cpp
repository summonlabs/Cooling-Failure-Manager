// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/cooling_failure_manager/text.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>

namespace dccp::cooling_failure_manager {
namespace {

// Decodes one UTF-8 sequence starting at index. Returns false for every
// malformed shape: overlong encodings, UTF-16 surrogates, values above
// U+10FFFF, truncated sequences and stray continuation bytes. The lead-byte
// ranges are the ones RFC 3629 defines, so C0/C1 and F5..FF are rejected
// before any continuation byte is examined.
bool decode_utf8(std::string_view raw, std::size_t index, std::uint32_t& code_point,
                 std::size_t& width) noexcept {
  const auto byte = [&](std::size_t offset) { return static_cast<std::uint8_t>(raw[index + offset]); };
  const std::size_t remaining = raw.size() - index;
  const std::uint8_t first = byte(0);

  if (first < 0x80) {
    code_point = first;
    width = 1;
    return true;
  }
  if (first < 0xC2) {
    return false;  // continuation byte, or an overlong two-byte lead (C0/C1)
  }
  if (first < 0xE0) {
    if (remaining < 2) {
      return false;
    }
    const std::uint8_t second = byte(1);
    if ((second & 0xC0) != 0x80) {
      return false;
    }
    code_point = (static_cast<std::uint32_t>(first & 0x1F) << 6) | (second & 0x3F);
    width = 2;
    return true;
  }
  if (first < 0xF0) {
    if (remaining < 3) {
      return false;
    }
    const std::uint8_t second = byte(1);
    const std::uint8_t third = byte(2);
    if ((second & 0xC0) != 0x80 || (third & 0xC0) != 0x80) {
      return false;
    }
    if (first == 0xE0 && second < 0xA0) {
      return false;  // overlong
    }
    if (first == 0xED && second > 0x9F) {
      return false;  // U+D800..U+DFFF
    }
    code_point = (static_cast<std::uint32_t>(first & 0x0F) << 12) |
                 (static_cast<std::uint32_t>(second & 0x3F) << 6) | (third & 0x3F);
    width = 3;
    return true;
  }
  if (first < 0xF5) {
    if (remaining < 4) {
      return false;
    }
    const std::uint8_t second = byte(1);
    const std::uint8_t third = byte(2);
    const std::uint8_t fourth = byte(3);
    if ((second & 0xC0) != 0x80 || (third & 0xC0) != 0x80 || (fourth & 0xC0) != 0x80) {
      return false;
    }
    if (first == 0xF0 && second < 0x90) {
      return false;  // overlong
    }
    if (first == 0xF4 && second > 0x8F) {
      return false;  // above U+10FFFF
    }
    code_point = (static_cast<std::uint32_t>(first & 0x07) << 18) |
                 (static_cast<std::uint32_t>(second & 0x3F) << 12) |
                 (static_cast<std::uint32_t>(third & 0x3F) << 6) | (fourth & 0x3F);
    width = 4;
    return true;
  }
  return false;  // F5..FF can never start a well-formed sequence
}

void append_hex_byte(std::string& out, std::uint8_t value) {
  constexpr char kHexDigits[] = "0123456789abcdef";
  out.push_back(kHexDigits[(value >> 4) & 0x0F]);
  out.push_back(kHexDigits[value & 0x0F]);
}

/// Decodes one lowercase hexadecimal digit. Uppercase digits are deliberately
/// rejected: escape_text() emits lowercase only, and a second spelling of the
/// same bytes would break the canonical fixed point the decoder relies on.
int lowercase_hex_value(char digit) noexcept {
  if (digit >= '0' && digit <= '9') {
    return digit - '0';
  }
  if (digit >= 'a' && digit <= 'f') {
    return digit - 'a' + 10;
  }
  return -1;
}

/// A canonical decimal magnitude is 1..20 ASCII digits with no leading zero
/// unless the whole magnitude is exactly "0". Signs, whitespace, separators and
/// every other byte are shape violations, never repaired.
bool is_canonical_magnitude(std::string_view digits) noexcept {
  if (digits.empty()) {
    return false;
  }
  if (digits.size() > 1 && digits.front() == '0') {
    return false;
  }
  for (const char character : digits) {
    if (character < '0' || character > '9') {
      return false;
    }
  }
  return true;
}

/// Accumulates a canonical magnitude. Returns false when the value does not fit
/// in 64 bits; the caller reports a bound violation, never a shape violation.
bool accumulate_magnitude(std::string_view digits, std::uint64_t& value) noexcept {
  constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
  std::uint64_t out = 0;
  for (const char character : digits) {
    const auto digit = static_cast<std::uint64_t>(character - '0');
    if (out > (kMax - digit) / 10u) {
      return false;
    }
    out = out * 10u + digit;
  }
  value = out;
  return true;
}

/// The subject of a rejected number is the offending text, truncated so that an
/// untrusted record cannot inflate the error value without bound.
std::string number_subject(std::string_view text) { return std::string(text.substr(0, 64)); }

}  // namespace

bool is_valid_utf8(std::string_view raw) noexcept {
  std::size_t index = 0;
  while (index < raw.size()) {
    std::uint32_t code_point = 0;
    std::size_t width = 0;
    if (!decode_utf8(raw, index, code_point, width)) {
      return false;
    }
    if (code_point == 0) {
      return false;  // an embedded NUL is never valid text
    }
    index += width;
  }
  return true;
}

bool is_valid_display_text(std::string_view raw, std::size_t max_bytes) noexcept {
  if (raw.size() > max_bytes) {
    return false;
  }
  std::size_t index = 0;
  while (index < raw.size()) {
    std::uint32_t code_point = 0;
    std::size_t width = 0;
    if (!decode_utf8(raw, index, code_point, width)) {
      return false;
    }
    // C0 controls (which include NUL), DEL and C1 controls are the entire set
    // of characters this predicate rejects beyond encoding validity. Every
    // other printable character is display text, whatever its script.
    if (code_point < 0x20 || code_point == 0x7F) {
      return false;
    }
    if (code_point >= 0x80 && code_point <= 0x9F) {
      return false;
    }
    index += width;
  }
  return true;
}

bool is_valid_external_identity(std::string_view raw, std::size_t max_bytes) noexcept {
  // Length and encoding only. Bytes are preserved exactly: no case folding, no
  // Unicode normalization, no trimming, so the reference can never resolve to a
  // different object than the one its producer named.
  if (raw.empty() || raw.size() > max_bytes) {
    return false;
  }
  return is_valid_utf8(raw);
}

std::string escape_text(std::string_view raw) {
  std::string out;
  out.reserve(raw.size() + 2);
  out.push_back('"');
  for (const char raw_byte : raw) {
    const auto byte = static_cast<std::uint8_t>(raw_byte);
    if (byte == '"') {
      out.append("\\\"");
    } else if (byte == '\\') {
      out.append("\\\\");
    } else if (byte >= 0x20 && byte <= 0x7E) {
      out.push_back(static_cast<char>(byte));
    } else {
      // Every byte outside printable ASCII - including tab, LF, CR, DEL and
      // every non-ASCII byte - is escaped, so the rendering is ASCII-only,
      // contains no line or field separator and is byte-deterministic.
      out.append("\\x");
      append_hex_byte(out, byte);
    }
  }
  out.push_back('"');
  return out;
}

Result<std::string> unescape_text(std::string_view escaped, std::size_t max_bytes) {
  if (escaped.empty()) {
    return Error(ErrorCode::TruncatedInput, "escaped text is empty");
  }
  if (escaped.front() != '"') {
    return Error(ErrorCode::MalformedRecord, "escaped text must start with a double quote");
  }
  if (escaped.size() < 2 || escaped.back() != '"') {
    return Error(ErrorCode::TruncatedInput, "escaped text is not terminated by a double quote");
  }
  std::string out;
  // The decoded bound is known, so the allocation is bounded by it rather than
  // by the size of the untrusted input.
  out.reserve(escaped.size() <= max_bytes ? escaped.size() : max_bytes);
  std::size_t index = 1;
  const std::size_t end = escaped.size() - 1;
  while (index < end) {
    // Checked on every iteration so the bound holds for literal bytes as well
    // as for escape sequences.
    if (out.size() > max_bytes) {
      return Error(ErrorCode::TextTooLong, "unescaped text exceeds the configured bound");
    }
    const char current = escaped[index];
    if (current != '\\') {
      const auto byte = static_cast<std::uint8_t>(current);
      if (byte < 0x20 || byte > 0x7E) {
        // escape_text() escapes every such byte, so a raw one is a second
        // spelling of the same text. Accepting it would let two different
        // encodings decode to one value and break the canonical fixed point.
        return Error(ErrorCode::MalformedRecord,
                     "escaped text contains an unescaped byte outside printable ASCII")
            .with_subject(std::string(escaped.substr(0, 64)));
      }
      out.push_back(current);
      ++index;
      continue;
    }
    if (index + 1 >= end) {
      return Error(ErrorCode::TruncatedInput, "escaped text ends with an incomplete escape");
    }
    const char marker = escaped[index + 1];
    index += 2;
    if (marker == '"') {
      out.push_back('"');
    } else if (marker == '\\') {
      out.push_back('\\');
    } else if (marker == 'x') {
      if (index + 2 > end) {
        return Error(ErrorCode::TruncatedInput, "escaped text ends with a truncated \\x escape");
      }
      const int high = lowercase_hex_value(escaped[index]);
      const int low = lowercase_hex_value(escaped[index + 1]);
      if (high < 0 || low < 0) {
        return Error(ErrorCode::MalformedRecord,
                     "escaped text has a \\x escape that is not two lowercase hex digits")
            .with_subject(std::string(escaped.substr(index, 2)));
      }
      out.push_back(static_cast<char>((high << 4) | low));
      index += 2;
    } else {
      // escape_text() produces only \", \\ and \xHH. Every other marker is an
      // unknown escape and is rejected rather than guessed at.
      return Error(ErrorCode::MalformedRecord, "escaped text has an unknown escape sequence")
          .with_subject(std::string(1, marker));
    }
  }
  if (out.size() > max_bytes) {
    return Error(ErrorCode::TextTooLong, "unescaped text exceeds the configured bound");
  }
  return out;
}

std::string ascii_lower(std::string_view raw) {
  std::string out(raw);
  for (char& character : out) {
    if (character >= 'A' && character <= 'Z') {
      character = static_cast<char>(character - 'A' + 'a');
    }
  }
  return out;
}

bool is_ascii_token(std::string_view raw) noexcept {
  if (raw.empty()) {
    return false;  // an empty byte string is not a token
  }
  for (const char character : raw) {
    const bool allowed = (character >= '0' && character <= '9') ||
                         (character >= 'a' && character <= 'z') ||
                         (character >= 'A' && character <= 'Z') || character == '.' ||
                         character == ':' || character == '_' || character == '-';
    if (!allowed) {
      return false;
    }
  }
  return true;
}

bool external_identity_equal(std::string_view lhs, std::string_view rhs) noexcept { return lhs == rhs; }

Result<std::uint64_t> parse_uint64(std::string_view text, std::uint64_t max_value) {
  if (!is_canonical_magnitude(text)) {
    return Error(ErrorCode::MalformedNumber,
                 "unsigned decimal text must be 1..20 digits with no sign, no leading zero, no "
                 "whitespace and no separator")
        .with_subject(number_subject(text));
  }
  std::uint64_t value = 0;
  if (!accumulate_magnitude(text, value)) {
    return Error(ErrorCode::LimitExceeded, "unsigned decimal text exceeds the 64-bit magnitude")
        .with_subject(number_subject(text));
  }
  if (value > max_value) {
    return Error(ErrorCode::LimitExceeded, "unsigned decimal text exceeds the permitted maximum")
        .with_subject(number_subject(text));
  }
  return value;
}

Result<std::int64_t> parse_int64(std::string_view text, std::int64_t min_value, std::int64_t max_value) {
  bool negative = false;
  std::string_view magnitude = text;
  if (!magnitude.empty() && magnitude.front() == '-') {
    negative = true;
    magnitude.remove_prefix(1);
  }
  if (!is_canonical_magnitude(magnitude) || (negative && magnitude == "0")) {
    // "-0" is not a canonical spelling of zero: it is a second rendering of a
    // value that already has one, so it is rejected as a shape violation.
    return Error(ErrorCode::MalformedNumber,
                 "signed decimal text must be an optional '-' followed by 1..20 digits with no "
                 "leading zero, no whitespace and no separator")
        .with_subject(number_subject(text));
  }
  std::uint64_t value = 0;
  if (!accumulate_magnitude(magnitude, value)) {
    return Error(ErrorCode::LimitExceeded, "signed decimal text exceeds the 64-bit magnitude")
        .with_subject(number_subject(text));
  }
  // The magnitude bound is checked before any negation, so INT64_MIN is
  // reachable only through the explicit case below and never through an
  // unchecked negation of an out-of-range magnitude.
  const std::uint64_t positive_limit =
      static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  const std::uint64_t negative_limit = positive_limit + 1u;
  if (value > (negative ? negative_limit : positive_limit)) {
    return Error(ErrorCode::LimitExceeded, "signed decimal text exceeds the 64-bit magnitude")
        .with_subject(number_subject(text));
  }
  const std::int64_t signed_value =
      negative ? (value == negative_limit ? std::numeric_limits<std::int64_t>::min()
                                          : -static_cast<std::int64_t>(value))
               : static_cast<std::int64_t>(value);
  if (signed_value < min_value || signed_value > max_value) {
    return Error(ErrorCode::LimitExceeded, "signed decimal text is outside the permitted range")
        .with_subject(number_subject(text));
  }
  return signed_value;
}

std::string to_decimal(std::uint64_t value) {
  // The digits are produced least-significant first, so the rendering is filled
  // from the back. Twenty digits is the worst case for a 64-bit magnitude.
  char digits[20];
  std::size_t count = 0;
  do {
    digits[count++] = static_cast<char>('0' + static_cast<int>(value % 10u));
    value /= 10u;
  } while (value != 0);
  std::string out(count, '0');
  for (std::size_t index = 0; index < count; ++index) {
    out[count - 1 - index] = digits[index];
  }
  return out;
}

std::string to_decimal(std::int64_t value) {
  if (value >= 0) {
    return to_decimal(static_cast<std::uint64_t>(value));
  }
  // Negating INT64_MIN in signed arithmetic is undefined, so the magnitude is
  // built in unsigned arithmetic: -(value + 1) + 1 is exact for every negative
  // value including INT64_MIN.
  const std::uint64_t magnitude = static_cast<std::uint64_t>(-(value + 1)) + 1u;
  std::string out = to_decimal(magnitude);
  out.insert(out.begin(), '-');
  return out;
}

bool is_canonical_uint(std::string_view text) noexcept {
  std::uint64_t value = 0;
  // A rendering produced by to_decimal() both has the canonical shape and fits
  // in 64 bits, so a syntactically canonical but oversized magnitude is not
  // canonical.
  return is_canonical_magnitude(text) && accumulate_magnitude(text, value);
}

bool is_canonical_int(std::string_view text) noexcept {
  bool negative = false;
  std::string_view magnitude = text;
  if (!magnitude.empty() && magnitude.front() == '-') {
    negative = true;
    magnitude.remove_prefix(1);
  }
  if (!is_canonical_magnitude(magnitude) || (negative && magnitude == "0")) {
    return false;
  }
  if (!negative) {
    std::uint64_t value = 0;
    return accumulate_magnitude(magnitude, value) &&
           value <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  }
  std::uint64_t value = 0;
  const std::uint64_t negative_limit =
      static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1u;
  return accumulate_magnitude(magnitude, value) && value <= negative_limit;
}

Result<std::vector<std::string_view>> split_fields(std::string_view line, char separator) {
  if (separator == '\0') {
    return Error(ErrorCode::InvalidArgument, "field separator must not be the NUL byte");
  }
  if (line.empty()) {
    return Error(ErrorCode::EmptyInput, "record line is empty");
  }
  if (line.find('\0') != std::string_view::npos) {
    return Error(ErrorCode::MalformedRecord, "record line contains an embedded NUL");
  }
  std::vector<std::string_view> fields;
  std::size_t start = 0;
  while (true) {
    const std::size_t position = line.find(separator, start);
    const std::size_t end = position == std::string_view::npos ? line.size() : position;
    if (end == start) {
      // Covers a leading separator, two adjacent separators and a trailing
      // separator: an empty field is never a valid field.
      return Error(ErrorCode::MalformedRecord, "record line contains an empty field")
          .with_subject(std::string(line.substr(0, 64)));
    }
    fields.push_back(line.substr(start, end - start));
    if (position == std::string_view::npos) {
      break;
    }
    start = position + 1;
  }
  return fields;
}

}  // namespace dccp::cooling_failure_manager
