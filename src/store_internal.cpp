// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Internal durable encoders and decoders of the cooling failure store.
//
// The byte-level contract is docs/FORMATS.md sections 2.1 to 2.4. Every record
// is an ASCII line terminated by exactly one LF (the generation file is a header
// line followed immediately by its body), fields are separated by exactly one
// TAB, and CR, NUL and trailing bytes are refused rather than tolerated.
//
//   floor
//     dccp-cooling-failure-floor TAB 1 TAB floor=<u64> TAB count=<commit> TAB <sha256> LF
//   manifest
//     dccp-cooling-failure-manifest TAB 1 TAB store=<id> TAB head=<u64> TAB
//       head_digest=<hex> TAB parent=<u64> TAB parent_digest=<hex> TAB commit=<u64> TAB
//       floor=<u64> TAB epoch=<u64> TAB incarnation=<u64> TAB bytes=<u64> TAB retained=<n> LF
//     retained TAB ordinal=<u32> TAB generation=<u64> TAB digest=<hex> TAB parent=<u64> TAB
//       parent_digest=<hex> TAB commit=<u64> TAB bytes=<u64> LF            (n lines, newest first)
//     count=<n> TAB <sha256 over every preceding byte> LF
//   generation
//     dccp-cooling-failure-generation TAB 1 TAB store=<id> TAB generation=<u64> TAB digest=<hex> TAB
//       bytes=<u64> TAB count=<body-line-count> TAB <sha256-of-body> LF <body>
//   accepted attempt
//     dccp-cooling-failure-attempt TAB 1 TAB mutation=<id> TAB ordinal=<u32> TAB request=<hex> TAB
//       generation=<u64> TAB digest=<hex> TAB commit=<u64> TAB count=<commit> TAB <sha256> LF
//
// Digest coverage is exactly what docs/FORMATS.md defines:
//   * the floor digest covers every byte up to and including the TAB before it,
//     so the whole line preceding the digest is covered;
//   * the manifest digest covers every byte up to and including the LF that
//     terminates the last retained line, so the trailer carrying the count and
//     the digest is deliberately outside the covered range;
//   * the generation digest covers the body bytes only, and the body starts
//     immediately after the LF that ends the header line;
//   * the attempt digest covers the whole record preceding the digest field.
//
// The redundant count fields are cross-checks, not decoration; a record edited
// in a length-preserving way is refused instead of being reinterpreted:
//   * the floor count is the commit sequence that established the floor;
//   * the manifest retained= field and the trailer count= field must agree;
//   * the generation count is the number of LF bytes in the body, so a body
//     replaced by different content of the same length is still refused;
//   * the attempt count repeats the commit sequence recorded by that record.
//
// Error routing. Every rejection uses the most specific code available, applied
// consistently across the three formats:
//   TruncatedInput            a missing tail: an empty record, a line without
//                             its terminating LF, a header without its body
//   UnsupportedSchemaVersion  a wrong format name or format version
//   MalformedRecord           a field that is not the exact expected shape,
//                             including CR, NUL, an extra LF, trailing bytes,
//                             an out-of-order or missing field and an ordinal
//                             that is not its own index
//   MalformedNumber           a decimal integer that is not canonical
//   MalformedIdentifier       an identity outside the canonical StrongId grammar
//   CountMismatch             a declared count or length disagrees with the
//                             bytes actually present
//   DigestMismatch            a checksum does not match its covered range
//   HeadCorrupt               a manifest that disagrees with itself
//   GenerationMismatch        a body whose generation is not the declared one
//   LimitExceeded             a record above its bound, or a decimal magnitude
//                             that would overflow the counter it is parsed into
//
// The decoders are strict and total: no default, no repair, no partial result,
// and no allocation that is not bounded before it happens.

#include "store_internal.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/canonical.hpp"
#include "dccp/cooling_failure_manager/digest.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

namespace dccp::cooling_failure_manager::internal {
namespace {

using ::dccp::cooling_failure_manager::digest_bytes;
using ::dccp::cooling_failure_manager::parse_uint64;
using ::dccp::cooling_failure_manager::split_fields;
using ::dccp::cooling_failure_manager::to_decimal;

constexpr char kFieldSeparator = '\t';
constexpr char kLineSeparator = '\n';

constexpr std::string_view kFloorRecordName = "dccp-cooling-failure-floor";
constexpr std::string_view kManifestRecordName = "dccp-cooling-failure-manifest";
constexpr std::string_view kGenerationRecordName = "dccp-cooling-failure-generation";
constexpr std::string_view kAttemptRecordName = "dccp-cooling-failure-attempt";
constexpr std::string_view kFormatVersion = "1";

/// Generation file name: "g" plus 20 zero-padded digits plus ".dat". The width
/// is exact so byte-wise ordering of the names is numeric ordering and so a
/// generation can never be spelled two ways.
constexpr std::size_t kGenerationNameDigits = 20;
constexpr std::string_view kGenerationNamePrefix = "g";
constexpr std::string_view kGenerationNameSuffix = ".dat";

/// Attempt file name: "m" plus 64 lowercase hex digits plus ".dat".
constexpr std::string_view kAttemptNamePrefix = "m";
constexpr std::string_view kAttemptNameSuffix = ".dat";

/// A record longer than this is refused before it is split or parsed. It is the
/// bound of the largest record this file defines and it is checked before any
/// other work, so a hostile length can never drive an allocation.
constexpr std::size_t kMaxRecordBytes = limits::kMaxGenerationFileBytes;

/// The stable banner of this component's durable boundary. It deliberately does
/// not carry the library version: a report names the boundary, not a release.
constexpr std::string_view kStoreBoundary = "dccp-cooling-failure-manager/1";

Error malformed(std::string message) {
  return Error(ErrorCode::MalformedRecord, std::move(message));
}

Error truncated(std::string message) {
  return Error(ErrorCode::TruncatedInput, std::move(message));
}

/// Reads a required "name=" field and returns its value. The field name is
/// checked exactly, so a reordered or renamed field is a shape violation rather
/// than a silently accepted value.
Result<std::string_view> field_value(std::string_view field, std::string_view name) {
  if (field.size() <= name.size() || field.substr(0, name.size()) != name ||
      field[name.size()] != '=') {
    return malformed("record field is not the expected " + std::string(name) +
                     "=<value> field")
        .with_subject(std::string(field.substr(0, 96)));
  }
  return field.substr(name.size() + 1);
}

Result<std::uint64_t> field_u64(std::string_view field, std::string_view name,
                                std::uint64_t max_value) {
  CFM_TRY(value_text, field_value(field, name));
  CFM_TRY(value, parse_uint64(value_text, max_value));
  return value;
}

Result<Digest> field_digest(std::string_view field, std::string_view name) {
  CFM_TRY(hex, field_value(field, name));
  CFM_TRY(digest, Digest::parse_hex(hex));
  return digest;
}

/// Reads the trailing digest field, which carries no name= prefix because the
/// digest is the last field of its record.
Result<Digest> trailing_digest(std::string_view field) {
  CFM_TRY(digest, Digest::parse_hex(field));
  return digest;
}

Result<StoreId> field_store_id(std::string_view field) {
  CFM_TRY(text, field_value(field, "store"));
  CFM_TRY(id, StoreId::parse(text));
  return id;
}

/// True when the text carries a byte the format forbids outright. CR is never
/// tolerated, and a NUL could otherwise terminate a field for a later consumer.
bool has_forbidden_byte(std::string_view text) {
  return text.find('\r') != std::string_view::npos || text.find('\0') != std::string_view::npos;
}

/// Splits one record into its TAB-separated fields.
Result<std::vector<std::string_view>> fields_of(std::string_view line) {
  if (line.empty()) {
    return truncated("record line is empty");
  }
  if (has_forbidden_byte(line)) {
    return malformed("record line contains a CR or a NUL byte");
  }
  return split_fields(line, kFieldSeparator);
}

/// Checks the record name and version header that every format shares.
Result<void> require_header(std::string_view field_name, std::string_view expected_name) {
  if (field_name != expected_name) {
    return Error(ErrorCode::UnsupportedSchemaVersion,
                 "record does not carry the expected format name")
        .with_subject(std::string(field_name.substr(0, 96)));
  }
  return ok();
}

Result<void> require_version(std::string_view field_version) {
  if (field_version != kFormatVersion) {
    return Error(ErrorCode::UnsupportedSchemaVersion, "record format version is not supported")
        .with_subject(std::string(field_version.substr(0, 32)));
  }
  return ok();
}

/// Version 2 of the manifest record carries the accepted-attempt record of each
/// retained generation, so a committed mutation and the identity that makes its
/// retry a replay cross the commit point together. Version 1 is still read: a
/// store written before the replay record lived in the manifest keeps every
/// accepted-attempt record it still holds, and its next publication writes
/// version 2.
constexpr std::string_view kManifestVersionWithReplay = "2";

Result<void> require_manifest_version(std::string_view field_version) {
  if (field_version != kFormatVersion && field_version != kManifestVersionWithReplay) {
    return Error(ErrorCode::UnsupportedSchemaVersion,
                 "manifest format version is not supported")
        .with_subject(std::string(field_version.substr(0, 32)));
  }
  return ok();
}

/// The number of LF bytes in a canonical body. The generation record declares it
/// so a body of the same length but different content is still refused.
std::uint64_t body_line_count(std::string_view body) {
  return static_cast<std::uint64_t>(std::count(body.begin(), body.end(), kLineSeparator));
}

}  // namespace

// ---------------------------------------------------------------------------
// Durable floor
// ---------------------------------------------------------------------------

std::string encode_floor(StateGeneration floor, CommitSequence count) {
  std::string out;
  out.reserve(160);
  out.append(kFloorRecordName);
  out.push_back(kFieldSeparator);
  out.append(kFormatVersion);
  out.push_back(kFieldSeparator);
  out.append("floor=").append(to_decimal(floor.value()));
  out.push_back(kFieldSeparator);
  out.append("count=").append(to_decimal(count.value()));
  out.push_back(kFieldSeparator);
  // The digest is computed into a local first: the evaluation order of a
  // chained append is unspecified, so the digest must never be an argument of an
  // expression that extends the same buffer.
  const std::string digest = digest_bytes(out).to_hex();
  out.append(digest);
  out.push_back(kLineSeparator);
  return out;
}

Result<StateGeneration> decode_floor(std::string_view text) {
  if (text.empty()) {
    return truncated("floor record is empty");
  }
  if (text.size() > kMaxRecordBytes) {
    return Error(ErrorCode::LimitExceeded, "floor record exceeds the documented bound");
  }
  if (text.back() != kLineSeparator) {
    return truncated("floor record is not terminated by an LF");
  }
  const std::string_view line = text.substr(0, text.size() - 1);
  if (line.find(kLineSeparator) != std::string_view::npos) {
    return malformed("floor record carries more than one line");
  }
  CFM_TRY(fields, fields_of(line));
  // The format name and version are judged first: a record that is not this
  // format at all is a version refusal, not a shape error of this format.
  if (fields.size() < 2) {
    return malformed("floor record must carry at least its format name and version");
  }
  CFM_TRYV(require_header(fields[0], kFloorRecordName));
  CFM_TRYV(require_version(fields[1]));
  if (fields.size() != 5) {
    return malformed("floor record must carry exactly name, version, floor, count and digest");
  }
  CFM_TRY(floor_value, field_u64(fields[2], "floor", UINT64_MAX));
  // The commit sequence that established the floor is decoded for its shape and
  // then dropped: it is durable accounting, never an input to a decision.
  CFM_TRY(ignored_count, field_u64(fields[3], "count", UINT64_MAX));
  static_cast<void>(ignored_count);
  CFM_TRY(expected, trailing_digest(fields[4]));
  // The digest covers every byte up to and including the TAB before it, so the
  // covered range is the whole line except the 64 digest characters themselves.
  if (line.size() <= Digest::kBytes * 2 + 1) {
    return malformed("floor record is too short to carry a digest and a covered field");
  }
  const std::string_view covered = line.substr(0, line.size() - Digest::kBytes * 2);
  if (digest_bytes(covered) != expected) {
    return Error(ErrorCode::DigestMismatch, "floor record checksum does not match its content");
  }
  return StateGeneration(floor_value);
}

// ---------------------------------------------------------------------------
// Head manifest
// ---------------------------------------------------------------------------

std::string encode_manifest(const Manifest& manifest) {
  std::string out;
  out.reserve(512 + manifest.retained.size() * 256);
  // A manifest declares its replay table in its header, so the record version is
  // always the one that has an attempt count.
  out.append(kManifestRecordName);
  out.push_back(kFieldSeparator);
  out.append(kManifestVersionWithReplay);
  out.push_back(kFieldSeparator);
  out.append("store=").append(manifest.store_id.str());
  out.push_back(kFieldSeparator);
  out.append("head=").append(to_decimal(manifest.head.value()));
  out.push_back(kFieldSeparator);
  out.append("head_digest=").append(manifest.head_digest.to_hex());
  out.push_back(kFieldSeparator);
  out.append("parent=").append(to_decimal(manifest.parent.value()));
  out.push_back(kFieldSeparator);
  out.append("parent_digest=").append(manifest.parent_digest.to_hex());
  out.push_back(kFieldSeparator);
  out.append("commit=").append(to_decimal(manifest.commit.value()));
  out.push_back(kFieldSeparator);
  out.append("floor=").append(to_decimal(manifest.floor.value()));
  out.push_back(kFieldSeparator);
  out.append("epoch=").append(to_decimal(manifest.epoch.value()));
  out.push_back(kFieldSeparator);
  out.append("incarnation=").append(to_decimal(manifest.incarnation.value()));
  out.push_back(kFieldSeparator);
  out.append("bytes=").append(to_decimal(manifest.bytes));
  out.push_back(kFieldSeparator);
  out.append("retained=").append(to_decimal(manifest.retained.size()));
  out.push_back(kFieldSeparator);
  out.append("attempt=").append(to_decimal(manifest.attempts.size()));
  out.push_back(kLineSeparator);
  for (std::size_t index = 0; index < manifest.retained.size(); ++index) {
    const ManifestEntry& entry = manifest.retained[index];
    out.append("retained");
    out.push_back(kFieldSeparator);
    out.append("ordinal=").append(to_decimal(static_cast<std::uint64_t>(index)));
    out.push_back(kFieldSeparator);
    out.append("generation=").append(to_decimal(entry.generation.value()));
    out.push_back(kFieldSeparator);
    out.append("digest=").append(entry.digest.to_hex());
    out.push_back(kFieldSeparator);
    out.append("parent=").append(to_decimal(entry.parent.value()));
    out.push_back(kFieldSeparator);
    out.append("parent_digest=").append(entry.parent_digest.to_hex());
    out.push_back(kFieldSeparator);
    out.append("commit=").append(to_decimal(entry.commit.value()));
    out.push_back(kFieldSeparator);
    out.append("bytes=").append(to_decimal(entry.bytes));
    out.push_back(kLineSeparator);
  }
  // The replay table, newest generation first. Every field is written, so a
  // record can be read without consulting the retained chain and a record that
  // names a generation the chain no longer holds is refused rather than silently
  // completed from it.
  for (const AttemptRecord& record : manifest.attempts) {
    out.append("attempt");
    out.push_back(kFieldSeparator);
    out.append("mutation=").append(record.mutation.str());
    out.push_back(kFieldSeparator);
    out.append("ordinal=").append(
        to_decimal(static_cast<std::uint64_t>(record.ordinal.value())));
    out.push_back(kFieldSeparator);
    out.append("request=").append(record.request_digest.to_hex());
    out.push_back(kFieldSeparator);
    out.append("generation=").append(to_decimal(record.generation.value()));
    out.push_back(kFieldSeparator);
    out.append("digest=").append(record.digest.to_hex());
    out.push_back(kFieldSeparator);
    out.append("commit=").append(to_decimal(record.commit.value()));
    out.push_back(kLineSeparator);
  }
  // The digest covers every preceding byte including the LF that terminates the
  // last retained line; the trailer that carries the digest is not covered.
  const std::size_t covered = out.size();
  out.append("count=").append(to_decimal(manifest.retained.size()));
  out.push_back(kFieldSeparator);
  out.append("attempt=").append(to_decimal(manifest.attempts.size()));
  out.push_back(kFieldSeparator);
  out.append(digest_bytes(std::string_view(out).substr(0, covered)).to_hex());
  out.push_back(kLineSeparator);
  return out;
}

Result<Manifest> decode_manifest(std::string_view text) {
  if (text.empty()) {
    return truncated("manifest is empty");
  }
  if (text.size() > limits::kMaxManifestBytes) {
    return Error(ErrorCode::LimitExceeded, "manifest exceeds the documented bound");
  }
  if (has_forbidden_byte(text)) {
    return malformed("manifest contains a CR or a NUL byte");
  }
  if (text.back() != kLineSeparator) {
    return truncated("manifest is not terminated by an LF");
  }
  // The trailer is the last line; everything before it - the header line and
  // every retained line - is the digest-covered range.
  const std::string_view without_final_lf = text.substr(0, text.size() - 1);
  const std::size_t trailer_start = without_final_lf.rfind(kLineSeparator);
  if (trailer_start == std::string_view::npos) {
    return truncated("manifest carries neither a retained line nor its count trailer");
  }
  const std::string_view covered = text.substr(0, trailer_start + 1);
  const std::string_view trailer = without_final_lf.substr(trailer_start + 1);
  // The covered range keeps the LF that terminates the last line before the
  // trailer; the line scanner below relies on every line being terminated.
  const std::string_view head_lines = text.substr(0, trailer_start + 1);

  // Lines of the covered range: the manifest header first, then the retained
  // entries, each terminated by exactly one LF.
  std::vector<std::string_view> lines;
  {
    std::size_t start = 0;
    while (start < head_lines.size()) {
      const std::size_t end = head_lines.find(kLineSeparator, start);
      if (end == std::string_view::npos) {
        return truncated("manifest line is not terminated by an LF");
      }
      if (end == start) {
        return malformed("manifest contains an empty line");
      }
      lines.push_back(head_lines.substr(start, end - start));
      start = end + 1;
    }
  }
  if (lines.size() < 2) {
    return truncated("manifest carries no retained entry line");
  }

  Manifest manifest;
  {
    CFM_TRY(header, fields_of(lines[0]));
    if (header.size() < 2) {
      return malformed("manifest header must carry at least its format name and version");
    }
    CFM_TRYV(require_header(header[0], kManifestRecordName));
    CFM_TRYV(require_manifest_version(header[1]));
    // A version 1 manifest declares no replay table and has thirteen fields; a
    // version 2 manifest declares it and has fourteen. The shape is decided by the
    // field count, so a record whose version and shape disagree is still read for
    // what it says rather than refused for saying it twice.
    const bool declares_attempts = header.size() == 14;
    if (header.size() != 13 && header.size() != 14) {
      return malformed(
          "manifest header must carry exactly name, version, store, head, head_digest, parent, "
          "parent_digest, commit, floor, epoch, incarnation, bytes and retained, plus attempt in "
          "version 2");
    }
    CFM_TRY(store_id, field_store_id(header[2]));
    manifest.store_id = std::move(store_id);
    CFM_TRY(head, field_u64(header[3], "head", UINT64_MAX));
    manifest.head = StateGeneration(head);
    CFM_TRY(head_digest, field_digest(header[4], "head_digest"));
    manifest.head_digest = head_digest;
    CFM_TRY(parent, field_u64(header[5], "parent", UINT64_MAX));
    manifest.parent = StateGeneration(parent);
    CFM_TRY(parent_digest, field_digest(header[6], "parent_digest"));
    manifest.parent_digest = parent_digest;
    CFM_TRY(commit, field_u64(header[7], "commit", UINT64_MAX));
    manifest.commit = CommitSequence(commit);
    CFM_TRY(floor, field_u64(header[8], "floor", UINT64_MAX));
    manifest.floor = StateGeneration(floor);
    CFM_TRY(epoch, field_u64(header[9], "epoch", UINT64_MAX));
    manifest.epoch = WriterEpoch(epoch);
    CFM_TRY(incarnation, field_u64(header[10], "incarnation", UINT64_MAX));
    manifest.incarnation = WriterIncarnation(incarnation);
    CFM_TRY(bytes, field_u64(header[11], "bytes", UINT64_MAX));
    manifest.bytes = bytes;
    CFM_TRY(retained_declared, field_u64(header[12], "retained", UINT64_MAX));
    std::uint64_t attempts_declared = 0;
    if (declares_attempts) {
      CFM_TRY(value, field_u64(header[13], "attempt", UINT64_MAX));
      attempts_declared = value;
      if (attempts_declared > limits::kMaxIdempotencyRecords) {
        return Error(ErrorCode::LimitExceeded,
                     "manifest declares more replay records than the documented bound")
            .with_subject(to_decimal(attempts_declared));
      }
    }
    if (retained_declared > limits::kMaxRetainedGenerations) {
      return Error(ErrorCode::LimitExceeded,
                   "manifest declares more retained generations than the documented bound")
          .with_subject(to_decimal(retained_declared));
    }
    if (retained_declared == 0) {
      return malformed("manifest must retain at least the head entry");
    }
    const std::size_t expected_entries = static_cast<std::size_t>(retained_declared);
    const std::size_t expected_attempts = static_cast<std::size_t>(attempts_declared);
    if (lines.size() - 1 != expected_entries + expected_attempts) {
      return Error(ErrorCode::CountMismatch,
                   "manifest retained= and attempt= do not match the lines it carries")
          .with_subject("declared " + to_decimal(retained_declared) + " retained and " +
                        to_decimal(attempts_declared) + " attempt, present " +
                        to_decimal(lines.size() - 1));
    }
    manifest.retained.reserve(expected_entries);
    for (std::size_t index = 0; index < expected_entries; ++index) {
      const std::string_view line = lines[index + 1];
      CFM_TRY(entry_fields, fields_of(line));
      if (entry_fields.size() != 8) {
        return malformed(
            "retained entry must carry exactly ordinal, generation, digest, parent, parent_digest, "
            "commit and bytes");
      }
      if (entry_fields[0] != "retained") {
        return malformed("retained entry does not start with the retained record name")
            .with_subject(std::string(entry_fields[0].substr(0, 96)));
      }
      CFM_TRY(ordinal, field_u64(entry_fields[1], "ordinal", UINT64_MAX));
      if (ordinal != index) {
        return malformed("retained entries must be numbered from 0 in the order they appear")
            .with_subject("expected ordinal " + to_decimal(index));
      }
      ManifestEntry entry;
      CFM_TRY(generation, field_u64(entry_fields[2], "generation", UINT64_MAX));
      entry.generation = StateGeneration(generation);
      CFM_TRY(digest, field_digest(entry_fields[3], "digest"));
      entry.digest = digest;
      CFM_TRY(entry_parent, field_u64(entry_fields[4], "parent", UINT64_MAX));
      entry.parent = StateGeneration(entry_parent);
      CFM_TRY(entry_parent_digest, field_digest(entry_fields[5], "parent_digest"));
      entry.parent_digest = entry_parent_digest;
      CFM_TRY(entry_commit, field_u64(entry_fields[6], "commit", UINT64_MAX));
      entry.commit = CommitSequence(entry_commit);
      CFM_TRY(entry_bytes, field_u64(entry_fields[7], "bytes", UINT64_MAX));
      entry.bytes = entry_bytes;
      manifest.retained.push_back(entry);
    }
    manifest.attempts.reserve(expected_attempts);
    for (std::size_t index = 0; index < expected_attempts; ++index) {
      const std::string_view line = lines[1 + expected_entries + index];
      CFM_TRY(attempt_fields, fields_of(line));
      if (attempt_fields.size() != 7) {
        return malformed(
            "manifest attempt record must carry exactly its name, mutation, ordinal, request, "
            "generation, digest and commit");
      }
      if (attempt_fields[0] != "attempt") {
        return malformed("manifest attempt record does not start with its record name")
            .with_subject(std::string(attempt_fields[0].substr(0, 96)));
      }
      CFM_TRY(mutation_text, field_value(attempt_fields[1], "mutation"));
      CFM_TRY(mutation, MutationId::parse(mutation_text));
      AttemptRecord record;
      record.mutation = std::move(mutation);
      CFM_TRY(ordinal, field_u64(attempt_fields[2], "ordinal", UINT32_MAX));
      if (ordinal == 0) {
        return Error(ErrorCode::MalformedNumber,
                     "a replay record carries a 1-based attempt ordinal")
            .with_subject("ordinal " + to_decimal(static_cast<std::uint64_t>(index)));
      }
      record.ordinal = AttemptOrdinal(static_cast<std::uint32_t>(ordinal));
      CFM_TRY(request, field_digest(attempt_fields[3], "request"));
      record.request_digest = request;
      if (record.request_digest.is_zero()) {
        return Error(ErrorCode::HeadCorrupt, "a replay record carries a zero intent digest")
            .with_subject(record.mutation.str());
      }
      CFM_TRY(generation, field_u64(attempt_fields[4], "generation", UINT64_MAX));
      if (generation == 0) {
        return malformed("a replay record must name a published generation")
            .with_subject(record.mutation.str());
      }
      record.generation = StateGeneration(generation);
      CFM_TRY(digest, field_digest(attempt_fields[5], "digest"));
      record.digest = digest;
      CFM_TRY(record_commit, field_u64(attempt_fields[6], "commit", UINT64_MAX));
      if (record_commit == 0) {
        return malformed("a replay record must name a committed sequence")
            .with_subject(record.mutation.str());
      }
      record.commit = CommitSequence(record_commit);
      manifest.attempts.push_back(record);
    }
  }

  {
    CFM_TRY(trailer_fields, fields_of(trailer));
    if (trailer_fields.size() != 3) {
      return malformed("manifest trailer must carry exactly count, attempt and the digest");
    }
    CFM_TRY(trailer_count, field_u64(trailer_fields[0], "count", UINT64_MAX));
    if (trailer_count != manifest.retained.size()) {
      return Error(ErrorCode::CountMismatch,
                   "manifest trailer count does not match the retained entries it covers")
          .with_subject("declared " + to_decimal(trailer_count) + ", present " +
                        to_decimal(manifest.retained.size()));
    }
    CFM_TRY(trailer_attempts, field_u64(trailer_fields[1], "attempt", UINT64_MAX));
    if (trailer_attempts != manifest.attempts.size()) {
      return Error(ErrorCode::CountMismatch,
                   "manifest trailer attempt count does not match the replay records present")
          .with_subject("declared " + to_decimal(trailer_attempts) + ", present " +
                        to_decimal(manifest.attempts.size()));
    }
    CFM_TRY(expected, trailing_digest(trailer_fields[2]));
    if (digest_bytes(covered) != expected) {
      return Error(ErrorCode::DigestMismatch, "manifest checksum does not match its content");
    }
  }

  // ---- self-consistency of the decoded record ------------------------------
  if (manifest.retained.empty()) {
    return malformed("manifest retains no entry");
  }
  if (manifest.retained.front().generation != manifest.head ||
      manifest.retained.front().digest != manifest.head_digest) {
    return Error(ErrorCode::HeadCorrupt,
                 "manifest retained entry 0 is not the head generation with the head digest");
  }
  if (manifest.epoch.value() == 0) {
    return Error(ErrorCode::HeadCorrupt, "manifest declares a zero writer epoch");
  }
  if (manifest.incarnation.value() == 0) {
    return Error(ErrorCode::HeadCorrupt, "manifest declares a zero writer incarnation");
  }
  if (manifest.head.published()) {
    if (manifest.head_digest.is_zero()) {
      return Error(ErrorCode::HeadCorrupt, "manifest declares a head without a digest");
    }
    if (!manifest.commit.committed()) {
      return Error(ErrorCode::HeadCorrupt, "manifest declares a head without a commit sequence");
    }
    if (manifest.retained.front().bytes != manifest.bytes) {
      return Error(ErrorCode::CountMismatch,
                   "manifest head byte count does not match the head retained entry")
          .with_subject("header " + to_decimal(manifest.bytes) + ", retained " +
                        to_decimal(manifest.retained.front().bytes));
    }
  } else {
    // An empty store has exactly one sentinel entry and every field of it is
    // zero. Open() reports head_verified for that shape only, so a sentinel that
    // carries anything at all is refused here rather than mistaken for a
    // publication.
    const ManifestEntry& sentinel = manifest.retained.front();
    const bool sentinel_zero = sentinel.digest.is_zero() && !sentinel.parent.published() &&
                               sentinel.parent_digest.is_zero() && !sentinel.commit.committed() &&
                               sentinel.bytes == 0;
    if (manifest.retained.size() != 1 || !sentinel_zero || !manifest.head_digest.is_zero() ||
        manifest.parent.published() || !manifest.parent_digest.is_zero() ||
        manifest.commit.committed() || manifest.bytes != 0) {
      return Error(ErrorCode::HeadCorrupt,
                   "empty manifest must carry one all-zero sentinel entry and no publication");
    }
  }
  for (std::size_t index = 1; index < manifest.retained.size(); ++index) {
    const ManifestEntry& newer = manifest.retained[index - 1];
    const ManifestEntry& older = manifest.retained[index];
    if (!(older.generation < newer.generation)) {
      return Error(ErrorCode::HeadCorrupt,
                   "manifest retained entries must be strictly ordered newest first")
          .with_subject("ordinal " + to_decimal(static_cast<std::uint64_t>(index)));
    }
    if (older.generation.published() && older.digest.is_zero()) {
      return Error(ErrorCode::HeadCorrupt,
                   "manifest retained entry names a published generation without a digest")
          .with_subject("ordinal " + to_decimal(static_cast<std::uint64_t>(index)));
    }
  }
  // The replay table is newest generation first, it names each identity and each
  // generation at most once, and every generation it names is still retained. A
  // record for a generation the chain no longer holds would be a replay answer
  // for a state this store cannot serve, so it is refused here rather than at the
  // retry that would discover it.
  for (std::size_t index = 0; index < manifest.attempts.size(); ++index) {
    const AttemptRecord& record = manifest.attempts[index];
    if (index > 0 && !(manifest.attempts[index - 1].generation > record.generation)) {
      return Error(ErrorCode::HeadCorrupt,
                   "manifest replay records must be strictly ordered newest first")
          .with_subject(record.mutation.str());
    }
    bool retained_generation = false;
    for (const ManifestEntry& entry : manifest.retained) {
      if (entry.generation == record.generation && entry.digest == record.digest &&
          entry.commit == record.commit) {
        retained_generation = true;
        break;
      }
    }
    if (!retained_generation) {
      return Error(ErrorCode::HeadCorrupt,
                   "manifest replay record does not name a retained generation")
          .with_subject(record.mutation.str());
    }
    for (std::size_t other = 0; other < manifest.attempts.size(); ++other) {
      if (other == index) {
        continue;
      }
      if (manifest.attempts[other].mutation == record.mutation &&
          manifest.attempts[other].ordinal == record.ordinal) {
        return Error(ErrorCode::HeadCorrupt,
                     "manifest carries two replay records for one accepted attempt")
            .with_subject(record.mutation.str());
      }
      if (manifest.attempts[other].generation == record.generation) {
        return Error(ErrorCode::HeadCorrupt,
                     "manifest carries two replay records for one generation")
            .with_subject(record.mutation.str());
      }
    }
  }
  return manifest;
}

// ---------------------------------------------------------------------------
// Generation file
// ---------------------------------------------------------------------------

std::string encode_generation_file(const StoreId& store_id, StateGeneration generation,
                                   const Digest& digest, std::string_view canonical_body) {
  std::string out;
  out.reserve(canonical_body.size() + 256);
  out.append(kGenerationRecordName);
  out.push_back(kFieldSeparator);
  out.append(kFormatVersion);
  out.push_back(kFieldSeparator);
  out.append("store=").append(store_id.str());
  out.push_back(kFieldSeparator);
  out.append("generation=").append(to_decimal(generation.value()));
  out.push_back(kFieldSeparator);
  out.append("digest=").append(digest.to_hex());
  out.push_back(kFieldSeparator);
  out.append("bytes=").append(to_decimal(canonical_body.size()));
  out.push_back(kFieldSeparator);
  out.append("count=").append(to_decimal(body_line_count(canonical_body)));
  out.push_back(kFieldSeparator);
  const std::string body_digest = digest_bytes(canonical_body).to_hex();
  out.append(body_digest);
  out.push_back(kLineSeparator);
  out.append(canonical_body);
  return out;
}

Result<GenerationFile> decode_generation_file(std::string_view text) {
  if (text.empty()) {
    return truncated("generation file is empty");
  }
  if (text.size() > limits::kMaxGenerationFileBytes) {
    return Error(ErrorCode::LimitExceeded, "generation file exceeds the documented bound");
  }
  if (has_forbidden_byte(text)) {
    return malformed("generation file contains a CR or a NUL byte");
  }
  const std::size_t header_end = text.find(kLineSeparator);
  if (header_end == std::string_view::npos) {
    return truncated("generation file has no header line");
  }
  const std::string_view header = text.substr(0, header_end);
  // The body begins immediately after the LF that ends the header line and ends
  // at end of file; an absent body is a truncation, not an empty state.
  const std::string_view body = text.substr(header_end + 1);
  if (body.empty()) {
    return truncated("generation file carries no body after its header line");
  }
  if (body.back() != kLineSeparator) {
    return truncated("generation body is not terminated by an LF");
  }

  GenerationFile file;
  {
    CFM_TRY(fields, fields_of(header));
    if (fields.size() < 2) {
      return malformed("generation header must carry at least its format name and version");
    }
    CFM_TRYV(require_header(fields[0], kGenerationRecordName));
    CFM_TRYV(require_version(fields[1]));
    if (fields.size() != 8) {
      return malformed(
          "generation header must carry exactly name, version, store, generation, digest, bytes, "
          "count and the body digest");
    }
    CFM_TRY(store_id, field_store_id(fields[2]));
    file.store_id = std::move(store_id);
    CFM_TRY(generation, field_u64(fields[3], "generation", UINT64_MAX));
    if (generation == 0) {
      return malformed(
          "generation 0 is the empty-store sentinel and never has a generation file");
    }
    file.generation = StateGeneration(generation);
    CFM_TRY(digest, field_digest(fields[4], "digest"));
    file.digest = digest;
    CFM_TRY(bytes, field_u64(fields[5], "bytes", UINT64_MAX));
    CFM_TRY(count, field_u64(fields[6], "count", UINT64_MAX));
    CFM_TRY(body_digest, trailing_digest(fields[7]));

    // The outer digest is a second, independent check over the body bytes only,
    // so a truncated or extended body is detected even when the header agrees
    // with itself.
    if (digest_bytes(body) != body_digest) {
      return Error(ErrorCode::DigestMismatch,
                   "generation body digest does not match the body actually present");
    }
    if (bytes != body.size()) {
      return Error(ErrorCode::CountMismatch,
                   "generation bytes= does not match the body length actually present")
          .with_subject("declared " + to_decimal(bytes) + ", present " +
                        to_decimal(body.size()));
    }
    if (count != body_line_count(body)) {
      return Error(ErrorCode::CountMismatch,
                   "generation count= does not match the body lines actually present")
          .with_subject("declared " + to_decimal(count) + ", present " +
                        to_decimal(body_line_count(body)));
    }
  }

  CFM_TRY(body_state, decode_state(body));
  if (body_state.generation != file.generation) {
    return Error(ErrorCode::GenerationMismatch,
                 "generation body declares a different generation than the file header")
        .with_subject("header " + to_decimal(file.generation.value()) + ", body " +
                      to_decimal(body_state.generation.value()));
  }
  if (state_digest(body_state) != file.digest) {
    return Error(ErrorCode::DigestMismatch,
                 "generation body does not carry the state digest the file header declares");
  }
  file.body = std::move(body_state);
  return file;
}

// ---------------------------------------------------------------------------
// Generation file names
// ---------------------------------------------------------------------------

std::string generation_file_name(StateGeneration generation) {
  std::string digits = to_decimal(generation.value());
  std::string out;
  out.reserve(kGenerationNamePrefix.size() + kGenerationNameDigits + kGenerationNameSuffix.size());
  out.append(kGenerationNamePrefix);
  // Zero padding to a fixed width makes byte-wise ordering of the names exactly
  // the numeric ordering of the generations they name.
  if (digits.size() < kGenerationNameDigits) {
    out.append(kGenerationNameDigits - digits.size(), '0');
  }
  out.append(digits);
  out.append(kGenerationNameSuffix);
  return out;
}

Result<StateGeneration> parse_generation_file_name(std::string_view name) {
  const std::size_t expected_size =
      kGenerationNamePrefix.size() + kGenerationNameDigits + kGenerationNameSuffix.size();
  // The length is checked first, so the suffix comparison below can never
  // index before the start of the name.
  if (name.size() != expected_size) {
    return malformed("generation file name must be g followed by 20 digits and .dat")
        .with_subject(std::string(name.substr(0, 96)));
  }
  if (name.substr(0, kGenerationNamePrefix.size()) != kGenerationNamePrefix ||
      name.substr(name.size() - kGenerationNameSuffix.size()) != kGenerationNameSuffix) {
    return malformed("generation file name must be g followed by 20 digits and .dat")
        .with_subject(std::string(name.substr(0, 96)));
  }
  std::uint64_t value = 0;
  for (std::size_t index = kGenerationNamePrefix.size();
       index < kGenerationNamePrefix.size() + kGenerationNameDigits; ++index) {
    const char character = name[index];
    if (character < '0' || character > '9') {
      return malformed("generation file name must carry 20 decimal digits")
          .with_subject(std::string(name.substr(0, 96)));
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
    // The magnitude is accumulated with a checked multiply, so a name that would
    // overflow the generation counter is refused instead of wrapping.
    if (value > (UINT64_MAX - digit) / 10u) {
      return Error(ErrorCode::LimitExceeded, "generation file name exceeds the generation bound")
          .with_subject(std::string(name.substr(0, 96)));
    }
    value = value * 10u + digit;
  }
  if (value == 0) {
    return malformed("generation 0 is the empty-store sentinel and has no generation file")
        .with_subject(std::string(name));
  }
  return StateGeneration(value);
}

// ---------------------------------------------------------------------------
// Accepted-attempt records
// ---------------------------------------------------------------------------

std::string encode_attempt_record(const AttemptRecord& record) {
  std::string out;
  out.reserve(512);
  out.append(kAttemptRecordName);
  out.push_back(kFieldSeparator);
  out.append(kFormatVersion);
  out.push_back(kFieldSeparator);
  out.append("mutation=").append(record.mutation.str());
  out.push_back(kFieldSeparator);
  out.append("ordinal=").append(to_decimal(static_cast<std::uint64_t>(record.ordinal.value())));
  out.push_back(kFieldSeparator);
  out.append("request=").append(record.request_digest.to_hex());
  out.push_back(kFieldSeparator);
  out.append("generation=").append(to_decimal(record.generation.value()));
  out.push_back(kFieldSeparator);
  out.append("digest=").append(record.digest.to_hex());
  out.push_back(kFieldSeparator);
  out.append("commit=").append(to_decimal(record.commit.value()));
  out.push_back(kFieldSeparator);
  out.append("count=").append(to_decimal(record.commit.value()));
  out.push_back(kFieldSeparator);
  const std::string digest = digest_bytes(out).to_hex();
  out.append(digest);
  out.push_back(kLineSeparator);
  return out;
}

Result<AttemptRecord> decode_attempt_record(std::string_view text) {
  if (text.empty()) {
    return truncated("accepted-attempt record is empty");
  }
  if (text.size() > limits::kMaxIdempotencyRecordBytes) {
    return Error(ErrorCode::LimitExceeded,
                 "accepted-attempt record exceeds the documented bound");
  }
  if (text.back() != kLineSeparator) {
    return truncated("accepted-attempt record is not terminated by an LF");
  }
  const std::string_view line = text.substr(0, text.size() - 1);
  if (line.find(kLineSeparator) != std::string_view::npos) {
    return malformed("accepted-attempt record carries more than one line");
  }
  CFM_TRY(fields, fields_of(line));
  if (fields.size() < 2) {
    return malformed("accepted-attempt record must carry at least its format name and version");
  }
  CFM_TRYV(require_header(fields[0], kAttemptRecordName));
  CFM_TRYV(require_version(fields[1]));
  if (fields.size() != 10) {
    return malformed(
        "accepted-attempt record must carry exactly name, version, mutation, ordinal, request, "
        "generation, digest, commit, count and the record digest");
  }
  AttemptRecord record;
  CFM_TRY(mutation_text, field_value(fields[2], "mutation"));
  CFM_TRY(mutation, MutationId::parse(mutation_text));
  record.mutation = std::move(mutation);
  CFM_TRY(ordinal, field_u64(fields[3], "ordinal", UINT32_MAX));
  if (ordinal == 0) {
    return Error(ErrorCode::MalformedNumber, "attempt ordinal is 1-based and must not be zero");
  }
  record.ordinal = AttemptOrdinal(static_cast<std::uint32_t>(ordinal));
  CFM_TRY(request, field_digest(fields[4], "request"));
  record.request_digest = request;
  CFM_TRY(generation, field_u64(fields[5], "generation", UINT64_MAX));
  if (generation == 0) {
    return malformed("accepted-attempt record must name a published generation");
  }
  record.generation = StateGeneration(generation);
  CFM_TRY(digest, field_digest(fields[6], "digest"));
  record.digest = digest;
  CFM_TRY(commit, field_u64(fields[7], "commit", UINT64_MAX));
  if (commit == 0) {
    return malformed("accepted-attempt record must name a committed sequence");
  }
  record.commit = CommitSequence(commit);
  CFM_TRY(count, field_u64(fields[8], "count", UINT64_MAX));
  if (count != commit) {
    return Error(ErrorCode::CountMismatch,
                 "accepted-attempt record count does not repeat its commit sequence")
        .with_subject("count " + to_decimal(count) + ", commit " + to_decimal(commit));
  }
  CFM_TRY(expected, trailing_digest(fields[9]));
  if (line.size() <= Digest::kBytes * 2 + 1) {
    return malformed("accepted-attempt record is too short to carry a digest");
  }
  if (digest_bytes(line.substr(0, line.size() - Digest::kBytes * 2)) != expected) {
    return Error(ErrorCode::DigestMismatch,
                 "accepted-attempt record checksum does not match its content");
  }
  return record;
}

std::string attempt_file_name(const MutationId& mutation, const AttemptOrdinal& ordinal) {
  // The name is a pure function of the identity: the mutation id is never
  // spelled into a path component, so no identity can collide with a reserved
  // file name and no identity can escape the idem directory.
  Sha256 hasher;
  hasher.update(mutation.str());
  hasher.update_byte(static_cast<std::uint8_t>(kFieldSeparator));
  hasher.update(to_decimal(static_cast<std::uint64_t>(ordinal.value())));
  const std::array<std::uint8_t, Sha256::kDigestBytes> bytes = hasher.finish();
  std::string out;
  out.reserve(kAttemptNamePrefix.size() + Digest::kBytes * 2 + kAttemptNameSuffix.size());
  out.append(kAttemptNamePrefix);
  out.append(to_hex(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size())));
  out.append(kAttemptNameSuffix);
  return out;
}

// ---------------------------------------------------------------------------
// Request content identity
// ---------------------------------------------------------------------------

Digest request_content_digest(const CoolingFailureState& body) {
  // The store assigns the generation and the parent generation, so neither may
  // take part in the identity of the *request*: a caller that retries the same
  // logical operation after an interrupted publication must produce the same
  // digest whether or not its earlier attempt reached the commit point. Both
  // fields are therefore zeroed on a copy before the canonical encoding, and the
  // digest covers that encoding byte for byte.
  CoolingFailureState normalized = body;
  normalized.generation = StateGeneration();
  normalized.parent_generation = StateGeneration();
  return digest_bytes(encode_state(normalized));
}

std::string_view store_boundary() noexcept { return kStoreBoundary; }

}  // namespace dccp::cooling_failure_manager::internal
