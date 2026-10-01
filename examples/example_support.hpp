// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Shared scaffolding for the Cooling Failure Manager examples.
//
// The examples are programs, not tests: each one prints what it decided and
// returns a non-zero status only when a check it makes about its own contract
// fails. The helpers here record SYNTHETIC observations into an observation set
// and wrap a durable store in a small journal. Nothing here contacts a real
// facility.

#ifndef COOLING_FAILURE_MANAGER_EXAMPLES_SUPPORT_HPP
#define COOLING_FAILURE_MANAGER_EXAMPLES_SUPPORT_HPP

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <system_error>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/canonical.hpp"
#include "dccp/cooling_failure_manager/classify.hpp"
#include "dccp/cooling_failure_manager/decision.hpp"
#include "dccp/cooling_failure_manager/digest.hpp"
#include "dccp/cooling_failure_manager/evidence.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/store.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

namespace cfm = dccp::cooling_failure_manager;

namespace example {

inline int failures = 0;

inline void check(bool condition, const char* what) {
  if (!condition) {
    std::printf("FAIL %s\n", what);
    ++failures;
  }
}

inline void note(std::string_view text) { std::printf("%s\n", std::string(text).c_str()); }

inline cfm::ScopeId must_scope(std::string_view text) { return *cfm::ScopeId::parse(text); }

inline cfm::ObservationId must_observation(std::string_view text) {
  return *cfm::ObservationId::parse(text);
}

inline cfm::DeclaredQuantity must_quantity(std::int64_t value, std::string_view unit) {
  return *cfm::DeclaredQuantity::make(value, unit);
}

/// Records one scalar observation on one channel.
inline void record(cfm::ObservationSet& set, std::string_view id, const cfm::ScopeId& scope,
                   cfm::ObservationChannel channel, std::int64_t value, std::string_view unit,
                   std::int64_t at, std::string_view producer) {
  cfm::Observation observation;
  observation.id = must_observation(id);
  observation.scope = scope;
  observation.channel = channel;
  observation.quantity = *cfm::Quantity::observed(value, unit, cfm::ObservationQuality::Good,
                                                 cfm::ObservationSequence(1));
  observation.observed_at = cfm::DecisionClock(at);
  observation.recorded_at = cfm::DecisionClock(at);
  observation.producer = std::string(producer);
  observation.sensor = std::string(producer) + ".sensor";
  observation.evidence_generation = cfm::EvidenceGeneration(1);
  check(set.add(observation).has_value(), "observation recorded");
}

/// Records a leak observation, which carries a state rather than a scalar.
inline void record_leak(cfm::ObservationSet& set, std::string_view id, const cfm::ScopeId& scope,
                        cfm::LeakState leak, std::int64_t at, std::string_view producer) {
  cfm::Observation observation;
  observation.id = must_observation(id);
  observation.scope = scope;
  observation.channel = cfm::ObservationChannel::LeakDetector;
  observation.leak = leak;
  observation.quantity = cfm::Quantity::indeterminate();
  observation.observed_at = cfm::DecisionClock(at);
  observation.recorded_at = cfm::DecisionClock(at);
  observation.producer = std::string(producer);
  observation.sensor = std::string(producer) + ".sensor";
  observation.evidence_generation = cfm::EvidenceGeneration(1);
  check(set.add(observation).has_value(), "leak observation recorded");
}

/// Records a discrete status reading: 0 normal, 1 degraded, 2 failed.
inline void record_status(cfm::ObservationSet& set, std::string_view id, const cfm::ScopeId& scope,
                          cfm::ObservationChannel channel, std::int64_t code, std::int64_t at,
                          std::string_view producer) {
  cfm::Observation observation;
  observation.id = must_observation(id);
  observation.scope = scope;
  observation.channel = channel;
  observation.quantity = *cfm::Quantity::observed(code, std::string_view(), cfm::ObservationQuality::Good,
                                                 cfm::ObservationSequence(1));
  observation.observed_at = cfm::DecisionClock(at);
  observation.recorded_at = cfm::DecisionClock(at);
  observation.producer = std::string(producer);
  observation.sensor = std::string(producer) + ".sensor";
  observation.evidence_generation = cfm::EvidenceGeneration(1);
  check(set.add(observation).has_value(), "status observation recorded");
}

/// A durable cooling-failure journal.
///
/// The store is the only authority: a decision is real once it has been published
/// as a generation, and every read goes back through the store, which re-verifies
/// the canonical image, its integrity digest and its structural validity.
class Journal {
 public:
  static cfm::Result<Journal> open(const std::string& root) {
    cfm::StoreOptions options;
    options.root = std::filesystem::absolute(root).lexically_normal().string();
    options.mode = cfm::StoreMode::ReadWrite;
    cfm::Result<cfm::Store> store = cfm::Store::open(options);
    if (!store.has_value()) {
      return store.error();
    }
    Journal journal;
    journal.store_ = std::move(store.value());
    return journal;
  }

  static cfm::Result<Journal> create(const std::string& root) {
    cfm::StoreOptions options;
    options.root = root;
    options.mode = cfm::StoreMode::ReadWrite;
    // The caller named a directory to journal into, and creating it is the
    // caller's decision: the store owns everything inside the directory and
    // nothing outside it. The root is resolved to an absolute path because a
    // relative root would name a different store in every process that used it.
    const std::string absolute = std::filesystem::absolute(root).lexically_normal().string();
    std::error_code ignored;
    std::filesystem::create_directories(absolute, ignored);
    cfm::Result<cfm::StoreId> id = cfm::StoreId::parse("example.journal");
    if (!id.has_value()) {
      return id.error();
    }
    cfm::Result<cfm::Store> store = cfm::Store::create(options, id.value());
    if (!store.has_value()) {
      return store.error();
    }
    Journal journal;
    journal.store_ = std::move(store.value());
    return journal;
  }

  cfm::Result<cfm::PublicationReceipt> append(const cfm::CoolingFailureState& state,
                                              std::string_view mutation, std::uint32_t ordinal) {
    cfm::PublicationRequest request;
    request.epoch = store_.epoch();
    request.incarnation = store_.incarnation();
    CFM_TRY(mutation_id, cfm::MutationId::parse(mutation));
    CFM_TRY(attempt, cfm::AttemptOrdinal::parse(ordinal));
    request.mutation = mutation_id;
    request.attempt = attempt;
    request.body = state;
    return store_.publish(request);
  }

  cfm::Result<cfm::StoreInfo> info() { return store_.info(); }
  cfm::Result<cfm::CoolingFailureState> head() { return store_.head(); }
  cfm::Result<std::vector<cfm::HistoryEntry>> history() { return store_.history(); }
  cfm::Result<cfm::VerifyReport> verify() { return store_.verify(cfm::VerifyOptions{}); }
  cfm::Result<void> close() { return store_.close(); }
  cfm::WriterEpoch epoch() const noexcept { return store_.epoch(); }
  cfm::WriterIncarnation incarnation() const noexcept { return store_.incarnation(); }

 private:
  Journal() = default;

  cfm::Store store_;
};

}  // namespace example

#endif  // COOLING_FAILURE_MANAGER_EXAMPLES_SUPPORT_HPP
