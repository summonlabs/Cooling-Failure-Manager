// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_COOLING_FAILURE_MANAGER_LIMITS_HPP
#define DCCP_COOLING_FAILURE_MANAGER_LIMITS_HPP

#include <cstddef>
#include <cstdint>

namespace dccp::cooling_failure_manager::limits {

/// Every externally influenced size, count, quantity and duration is bounded
/// before it is used. The bounds below are the documented contract; exceeding
/// one is a LimitExceeded (or a shape) error, never a silent truncation and
/// never a wrapped counter.

// ---- Identity and free text (bytes) ---------------------------------------
inline constexpr std::size_t kMaxIdentifierBytes = 128;
inline constexpr std::size_t kMaxDisplayNameBytes = 192;
inline constexpr std::size_t kMaxExternalIdentityBytes = 512;
inline constexpr std::size_t kMaxExternalKindBytes = 64;
inline constexpr std::size_t kMaxProducerBytes = 128;
inline constexpr std::size_t kMaxSensorRefBytes = 128;
inline constexpr std::size_t kMaxWitnessBytes = 256;
inline constexpr std::size_t kMaxTextBytes = 1024;          // explanation / rationale text
inline constexpr std::size_t kMaxTokenBytes = 64;           // canonical enum token
inline constexpr std::size_t kMaxCanonicalStringBytes = 65535;

// ---- Table bounds ---------------------------------------------------------
inline constexpr std::size_t kMaxScopeCount = 65536;
inline constexpr std::size_t kMaxScopeDependencyCount = 262144;
inline constexpr std::size_t kMaxFailureCount = 65536;
inline constexpr std::size_t kMaxFailureClassCount = 16;
inline constexpr std::size_t kMaxObservationCount = 262144;
inline constexpr std::size_t kMaxObservationPerScope = 512;
inline constexpr std::size_t kMaxPlanEligibilityCount = 64;
inline constexpr std::size_t kMaxRestrictionCount = 64;
inline constexpr std::size_t kMaxRestrictionScopeCount = 512;
inline constexpr std::size_t kMaxRecoveryGateCount = 32;
inline constexpr std::size_t kMaxRecoveryDemandCount = 32;
inline constexpr std::size_t kMaxSolicitationCount = 64;
inline constexpr std::size_t kMaxAttemptCount = 32;
inline constexpr std::size_t kMaxAttemptSolicitations = 16;
inline constexpr std::size_t kMaxAttemptSetCount = 65536;
inline constexpr std::size_t kMaxJournalRecordCount = 262144;
inline constexpr std::size_t kMaxSharedSourceCount = 4096;
inline constexpr std::size_t kMaxDependencyDepth = 64;

// ---- Physical quantities --------------------------------------------------
/// Flow in millilitres per second. Zero is a measurement, never a placeholder
/// for "unknown": unknown flow is represented by an absent reading.
inline constexpr std::int64_t kMaxFlowMillilitresPerSecond = 1000000000;  // 1 000 000 L/min
/// Differential pressure in pascals.
inline constexpr std::int64_t kMaxPressurePascals = 100000000;  // 100 MPa
/// Absolute pressure in pascals.
inline constexpr std::int64_t kMaxAbsolutePressurePascals = 100000000;
/// Temperature in millidegrees Celsius.
inline constexpr std::int64_t kMinTemperatureMilliCelsius = -10000000;
inline constexpr std::int64_t kMaxTemperatureMilliCelsius = 10000000;
inline constexpr std::int64_t kMilliCelsiusPerCelsius = 1000;
/// Relative humidity in parts per million.
inline constexpr std::int64_t kMaxHumidityPartsPerMillion = 1000000;
/// Thermal capacity in watts.
inline constexpr std::int64_t kMaxThermalCapacityWatts = 1000000000000;  // 1 TW
inline constexpr std::int64_t kMaxThermalLoadWatts = 1000000000000;
/// Thermal margin in millikelvin.
inline constexpr std::int64_t kMinThermalMarginMilliKelvin = -100000000;
inline constexpr std::int64_t kMaxThermalMarginMilliKelvin = 100000000;

// ---- Time -----------------------------------------------------------------
/// Timestamps are milliseconds on one monotone synthetic timeline owned by the
/// caller. They are never read from the host clock: a decision must be
/// reproducible from its inputs alone.
inline constexpr std::int64_t kMaxTimestampMilliseconds = 4102444800000;  // 2100-01-01T00:00:00Z
/// Longest freshness window or dwell interval this library accepts.
inline constexpr std::int64_t kMaxWindowMilliseconds = 86400000;  // 24 h

// ---- Persistence ----------------------------------------------------------
inline constexpr std::size_t kMaxHistoryEntries = 64;
inline constexpr std::size_t kMaxIdempotencyRecords = 64;
inline constexpr std::size_t kMaxRetainedGenerations = 8;
inline constexpr std::size_t kMaxManifestBytes = 256u * 1024u;
inline constexpr std::size_t kMaxIdempotencyRecordBytes = 16u * 1024u;
inline constexpr std::size_t kMaxStorePathBytes = 4096;
inline constexpr std::size_t kMaxGenerationBytes = 64u * 1024u * 1024u;
inline constexpr std::size_t kMaxGenerationFileBytes = kMaxGenerationBytes + 65536u;
inline constexpr std::size_t kMaxJournalBytes = 32u * 1024u * 1024u;
inline constexpr std::size_t kDefaultIdempotencyRetention = 64;

// ---- Decision bounds ------------------------------------------------------
/// The number of distinct cooling failure classes that may be simultaneously
/// confirmed for one scope. The bound exists so a classification is always a
/// bounded, serially reproducible value.
inline constexpr std::size_t kMaxConfirmedClassesPerScope = 8;
/// Bound on the number of evidence gaps a single decision may report.
inline constexpr std::size_t kMaxEvidenceGapCount = 64;
inline constexpr std::size_t kMaxDecisionEntryCount = 4096;

}  // namespace dccp::cooling_failure_manager::limits

#endif  // DCCP_COOLING_FAILURE_MANAGER_LIMITS_HPP
