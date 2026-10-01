// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Internal durable encoders and decoders. Not installed.

#ifndef DCCP_COOLING_FAILURE_MANAGER_SRC_STORE_INTERNAL_HPP
#define DCCP_COOLING_FAILURE_MANAGER_SRC_STORE_INTERNAL_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "dccp/cooling_failure_manager/digest.hpp"
#include "dccp/cooling_failure_manager/model.hpp"
#include "dccp/cooling_failure_manager/result.hpp"
#include "dccp/cooling_failure_manager/store.hpp"
#include "dccp/cooling_failure_manager/strong_id.hpp"

namespace dccp::cooling_failure_manager::internal {

/// One retained-generation entry of a head manifest.
struct ManifestEntry {
  StateGeneration generation{};
  Digest digest{};
  StateGeneration parent{};
  Digest parent_digest{};
  CommitSequence commit{};
  std::uint64_t bytes = 0;
};

/// The decoded authoritative head record.
struct Manifest {
  StoreId store_id;
  StateGeneration head{};
  Digest head_digest{};
  StateGeneration parent{};
  Digest parent_digest{};
  CommitSequence commit{};
  StateGeneration floor{};
  WriterEpoch epoch{};
  WriterIncarnation incarnation{};
  std::uint64_t bytes = 0;
  /// Newest first; entries[0] is the head.
  std::vector<ManifestEntry> retained;
};

std::string encode_floor(StateGeneration floor, CommitSequence count);
Result<StateGeneration> decode_floor(std::string_view text);

std::string encode_manifest(const Manifest& manifest);
Result<Manifest> decode_manifest(std::string_view text);

/// Packs the whole generation file: header line plus canonical body.
std::string encode_generation_file(const StoreId& store_id, StateGeneration generation,
                                   const Digest& digest, std::string_view canonical_body);

/// The verified parts of a generation file.
struct GenerationFile {
  StoreId store_id;
  StateGeneration generation{};
  Digest digest{};
  CoolingFailureState body;
};

Result<GenerationFile> decode_generation_file(std::string_view text);

/// File name of a generation, zero padded so byte-wise ordering matches numeric
/// ordering.
std::string generation_file_name(StateGeneration generation);

/// The state generation named by a generation file name, or an error when the
/// name is not a canonical generation name.
Result<StateGeneration> parse_generation_file_name(std::string_view name);

/// One accepted-attempt record.
struct AttemptRecord {
  MutationId mutation;
  AttemptOrdinal ordinal;
  Digest request_digest{};
  StateGeneration generation{};
  Digest digest{};
  CommitSequence commit{};
};

std::string encode_attempt_record(const AttemptRecord& record);
Result<AttemptRecord> decode_attempt_record(std::string_view text);

/// File name of an accepted-attempt record; a pure function of the identity.
std::string attempt_file_name(const MutationId& mutation, const AttemptOrdinal& ordinal);

/// Digest of the canonical content of a publication request body, used to
/// decide whether a repeated (mutation, ordinal) is the same operation.
Digest request_content_digest(const CoolingFailureState& body);

/// The state's canonical boundary banner stored in a manifest-bounded report.
std::string_view store_boundary() noexcept;

}  // namespace dccp::cooling_failure_manager::internal

#endif  // DCCP_COOLING_FAILURE_MANAGER_SRC_STORE_INTERNAL_HPP
