// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Benchmarks for the Cooling Failure Manager.
//
// Every benchmark reports COMPLETED USEFUL OPERATIONS per second, never the cost
// of submitting work: a decision benchmark counts a finished decision, a
// publication benchmark counts a fully committed and verified generation
// including its flushes and its read-back, and a recovery benchmark counts a
// finished gate evaluation. The durable figures therefore include the durability
// cost the library actually claims, on the storage device this program happens to
// run on.
//
// Provenance and scale are printed with every line, so no figure can be read
// without its context:
//   REAL      the operating system's own file system, processes and clock;
//   SYNTHETIC the cooling facility, its scopes and its sensor readings, which are
//             values this program wrote into memory.
//
// This program performs no work that is not measured, and it invents no
// before/after pair: each line is one configuration measured once.
//
// usage: cooling_failure_manager_benchmarks [iterations] [store-directory]

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <system_error>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/canonical.hpp"
#include "dccp/cooling_failure_manager/classify.hpp"
#include "dccp/cooling_failure_manager/decision.hpp"
#include "dccp/cooling_failure_manager/digest.hpp"
#include "dccp/cooling_failure_manager/evidence.hpp"
#include "dccp/cooling_failure_manager/recovery.hpp"
#include "dccp/cooling_failure_manager/store.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

namespace cfm = dccp::cooling_failure_manager;

namespace {

using Clock = std::chrono::steady_clock;

/// Monotone measurement of one benchmark body. The clock is read only around the
/// measured region, and the result is reported as operations per second together
/// with the total elapsed time, so a reader can see both the rate and the scale.
class Measurement {
 public:
  explicit Measurement(std::string name, std::string provenance, std::string scale)
      : name_(std::move(name)), provenance_(std::move(provenance)), scale_(std::move(scale)) {}

  void start() { begin_ = Clock::now(); }
  void stop(std::uint64_t operations) {
    const auto end = Clock::now();
    const double seconds = std::chrono::duration<double>(end - begin_).count();
    const double per_second = seconds > 0.0 ? static_cast<double>(operations) / seconds : 0.0;
    std::printf("%-42s %12.1f op/s  %8.3f s  %10llu ops  [%s; %s]\n", name_.c_str(), per_second,
                seconds, static_cast<unsigned long long>(operations), provenance_.c_str(),
                scale_.c_str());
    std::fflush(stdout);
  }

 private:
  std::string name_;
  std::string provenance_;
  std::string scale_;
  Clock::time_point begin_{};
};

std::string decimal(std::uint64_t value) { return cfm::to_decimal(value); }

cfm::ScopeId scope_of(std::size_t index) {
  return *cfm::ScopeId::parse("scope." + decimal(static_cast<std::uint64_t>(index)));
}

/// Builds a synthetic facility of the requested size: one plant, that many loops,
/// and one observation per loop on the channels the loops' rules witness.
cfm::CoolingFailureState build_facility(std::size_t loops, cfm::ObservationSet& observations,
                                       cfm::DecisionPolicy& policy) {
  policy.evidence_window = cfm::DurationMilliseconds(60000);
  policy.confirm_min_observations = 1;

  cfm::CoolingFailureState state;
  state.evaluated_at = cfm::DecisionClock(100000);

  cfm::CoolingScope plant;
  plant.id = *cfm::ScopeId::parse("plant.0");
  plant.kind = cfm::ScopeKind::Plant;
  plant.policy.envelope.declared_demand = *cfm::DeclaredQuantity::make(4000000, "W");
  plant.policy.envelope.min_flow = *cfm::DeclaredQuantity::make(50000, "mL/s");
  plant.policy.requirements = {
      {cfm::ObservationChannel::ChillerStatus, cfm::DurationMilliseconds(60000)},
      {cfm::ObservationChannel::ThermalCapacityMeter, cfm::DurationMilliseconds(60000)},
      {cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(60000)}};
  state.scopes.push_back(plant);

  for (std::size_t index = 0; index < loops; ++index) {
    cfm::CoolingScope loop;
    loop.id = scope_of(index);
    loop.kind = cfm::ScopeKind::Loop;
    loop.display_name = "Synthetic loop " + decimal(static_cast<std::uint64_t>(index));
    loop.policy.envelope.min_flow = *cfm::DeclaredQuantity::make(30000, "mL/s");
    loop.policy.envelope.min_differential_pressure = *cfm::DeclaredQuantity::make(50000, "Pa-dp");
    loop.policy.envelope.declared_demand = *cfm::DeclaredQuantity::make(2000000, "W");
    loop.policy.requirements = {
        {cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(60000)},
        {cfm::ObservationChannel::DifferentialPressure, cfm::DurationMilliseconds(60000)},
        {cfm::ObservationChannel::ThermalCapacityMeter, cfm::DurationMilliseconds(60000)}};
    loop.policy.recovery_dwell = cfm::DurationMilliseconds(300000);
    loop.policy.recovery_hysteresis = cfm::DurationMilliseconds(120000);
    loop.dependencies.push_back(
        cfm::ScopeDependency{plant.id, cfm::DependencyKind::SuppliesCoolant, 1000000});
    state.scopes.push_back(loop);

    // One loop in eight has lost its flow; the rest are healthy, so a benchmark
    // exercises both the confirming and the diverging path.
    const bool failed = (index % 8) == 0;
    const std::int64_t flow = failed ? 0 : 45000;
    const std::int64_t differential = failed ? 0 : 80000;
    const std::int64_t capacity = failed ? 100000 : 2400000;

    const auto add = [&](cfm::ObservationChannel channel, std::int64_t value, std::string_view unit) {
      cfm::Observation observation;
      observation.id = *cfm::ObservationId::parse("obs." + decimal(static_cast<std::uint64_t>(index)) +
                                                 "." + std::string(cfm::to_token(channel)));
      observation.scope = loop.id;
      observation.channel = channel;
      observation.quantity = *cfm::Quantity::observed(value, unit, cfm::ObservationQuality::Good,
                                                     cfm::ObservationSequence(1));
      observation.observed_at = cfm::DecisionClock(99000);
      observation.recorded_at = cfm::DecisionClock(99000);
      observation.producer = "synthetic-producer." + decimal(static_cast<std::uint64_t>(index));
      observation.sensor = observation.producer + ".sensor";
      observation.evidence_generation = cfm::EvidenceGeneration(1);
      if (!observations.add(observation).has_value()) {
        std::printf("benchmark setup failed to record an observation\n");
        std::exit(3);
      }
    };
    add(cfm::ObservationChannel::FlowMeter, flow, "mL/s");
    add(cfm::ObservationChannel::DifferentialPressure, differential, "Pa-dp");
    add(cfm::ObservationChannel::ThermalCapacityMeter, capacity, "W");
  }

  const auto add_plant = [&](cfm::ObservationChannel channel, std::int64_t value, std::string_view unit) {
    cfm::Observation observation;
    observation.id = *cfm::ObservationId::parse("obs.plant." + std::string(cfm::to_token(channel)));
    observation.scope = plant.id;
    observation.channel = channel;
    if (cfm::channel_unit(channel).empty()) {
      observation.quantity = *cfm::Quantity::observed(value, std::string_view(),
                                                     cfm::ObservationQuality::Good,
                                                     cfm::ObservationSequence(1));
    } else {
      observation.quantity = *cfm::Quantity::observed(value, unit, cfm::ObservationQuality::Good,
                                                     cfm::ObservationSequence(1));
    }
    observation.observed_at = cfm::DecisionClock(99000);
    observation.recorded_at = cfm::DecisionClock(99000);
    observation.producer = "synthetic-plant";
    observation.sensor = "synthetic-plant.sensor";
    observation.evidence_generation = cfm::EvidenceGeneration(1);
    if (!observations.add(observation).has_value()) {
      std::printf("benchmark setup failed to record a plant observation\n");
      std::exit(3);
    }
  };
  add_plant(cfm::ObservationChannel::ChillerStatus, 0, std::string_view());
  add_plant(cfm::ObservationChannel::ThermalCapacityMeter, 4000000, "W");
  add_plant(cfm::ObservationChannel::FlowMeter, 60000, "mL/s");
  return state;
}

}  // namespace

int main(int argc, char** argv) {
  std::uint64_t iterations = 2000;
  std::string store_root;
  if (argc > 1) {
    iterations = std::strtoull(argv[1], nullptr, 10);
    if (iterations == 0) {
      iterations = 1;
    }
  }
  if (argc > 2) {
    store_root = argv[2];
  }

  std::printf("Cooling Failure Manager benchmarks - one configuration per line, no before/after pairs.\n");
  std::printf("iterations per benchmark: %s\n\n", decimal(iterations).c_str());

  const std::size_t facility_size = 64;
  cfm::ObservationSet observations;
  cfm::DecisionPolicy policy;
  const cfm::CoolingFailureState facility = build_facility(facility_size, observations, policy);

  cfm::DecisionInput input;
  input.prior = &facility;
  input.observations = &observations;
  input.policy = policy;
  input.clock = cfm::DecisionClock(100000);

  // -------------------------------------------------------------------------
  // 1. Classification and plan derivation, end to end.
  // -------------------------------------------------------------------------
  {
    std::uint64_t completed = 0;
    std::uint64_t encoded_bytes = 0;
    Measurement measurement("decision.evaluate", "SYNTHETIC facility",
                            decimal(facility_size) + " loops, 3 channels each");
    measurement.start();
    for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
      cfm::Result<cfm::DecisionOutcome> outcome = cfm::evaluate(input);
      if (!outcome.has_value()) {
        std::printf("decision benchmark failed: %s\n", outcome.error().to_string().c_str());
        return 1;
      }
      ++completed;
      if (iteration == 0) {
        encoded_bytes = cfm::encode_state(outcome->state).size();
      }
    }
    measurement.stop(completed);
    std::printf("  canonical state size: %s bytes\n", decimal(encoded_bytes).c_str());
  }

  // -------------------------------------------------------------------------
  // 2. Canonical encoding and strict decoding, including the fixed-point check.
  // -------------------------------------------------------------------------
  cfm::Result<cfm::DecisionOutcome> evaluated = cfm::evaluate(input);
  if (!evaluated.has_value()) {
    std::printf("benchmark setup evaluation failed: %s\n", evaluated.error().to_string().c_str());
    return 1;
  }
  const cfm::CoolingFailureState& state = evaluated->state;
  const std::string canonical = cfm::encode_state(state);
  {
    std::uint64_t completed = 0;
    Measurement measurement("canonical.encode", "SYNTHETIC state",
                            decimal(canonical.size()) + " canonical bytes");
    measurement.start();
    for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
      const std::string encoded = cfm::encode_state(state);
      if (encoded.size() != canonical.size()) {
        std::printf("encoding is not deterministic\n");
        return 1;
      }
      ++completed;
    }
    measurement.stop(completed);
  }
  {
    std::uint64_t completed = 0;
    Measurement measurement("canonical.decode+validate", "SYNTHETIC state",
                            decimal(canonical.size()) + " canonical bytes");
    measurement.start();
    for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
      cfm::Result<cfm::CoolingFailureState> decoded = cfm::decode_state(canonical);
      if (!decoded.has_value()) {
        std::printf("decoding failed: %s\n", decoded.error().to_string().c_str());
        return 1;
      }
      ++completed;
    }
    measurement.stop(completed);
  }
  {
    std::uint64_t completed = 0;
    Measurement measurement("canonical.digest", "SYNTHETIC state",
                            decimal(canonical.size()) + " canonical bytes");
    measurement.start();
    for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
      const cfm::Digest digest = cfm::state_digest(state);
      if (digest.is_zero()) {
        std::printf("digest is zero\n");
        return 1;
      }
      ++completed;
    }
    measurement.stop(completed);
  }

  // -------------------------------------------------------------------------
  // 3. Evidence lookup: the most recent reading on a channel.
  // -------------------------------------------------------------------------
  {
    std::uint64_t completed = 0;
    const cfm::ScopeId probe_scope = scope_of(facility_size / 2);
    Measurement measurement("evidence.latest", "SYNTHETIC observations",
                            decimal(observations.size()) + " observations");
    measurement.start();
    for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
      for (cfm::ObservationChannel channel :
           {cfm::ObservationChannel::FlowMeter, cfm::ObservationChannel::DifferentialPressure,
            cfm::ObservationChannel::ThermalCapacityMeter}) {
        const cfm::Observation* observation = observations.latest(
            probe_scope, channel, cfm::DecisionClock(100000), policy.evidence_window);
        if (observation == nullptr) {
          std::printf("evidence lookup returned nothing\n");
          return 1;
        }
        ++completed;
      }
    }
    measurement.stop(completed);
  }

  // -------------------------------------------------------------------------
  // 4. Recovery gate evaluation: every gate over the whole demanded channel set.
  // -------------------------------------------------------------------------
  if (!state.decisions.empty()) {
    const cfm::ScopeDecision& decision = state.decisions.back();
    const cfm::CoolingScope* scope = cfm::find_scope(state, decision.scope);
    if (scope != nullptr) {
      cfm::Result<cfm::RecoveryRequirements> requirements =
          cfm::recovery_requirements(*scope, decision);
      if (requirements.has_value()) {
        requirements->state_snapshot = &state;
        requirements->stable_since = cfm::DecisionClock(99000);
        std::uint64_t completed = 0;
        Measurement measurement("recovery.evaluate", "SYNTHETIC evidence",
                                decimal(cfm::recovery_gate_count()) + " gates");
        measurement.start();
        for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
          cfm::Result<cfm::RecoveryAssessment> assessment = cfm::evaluate_recovery(
              *scope, decision, requirements.value(), observations, policy, cfm::DecisionClock(100000));
          if (!assessment.has_value()) {
            std::printf("recovery benchmark failed: %s\n", assessment.error().to_string().c_str());
            return 1;
          }
          ++completed;
        }
        measurement.stop(completed);
      }
    }
  }

  // -------------------------------------------------------------------------
  // 5. Durable publication, including the flushes and the read-back.
  // -------------------------------------------------------------------------
  if (!store_root.empty()) {
    // The directory is created if it is absent, so the benchmark can be run with
    // a path that does not exist yet. A failure to create it is reported rather
    // than allowed to surface later as a store error.
    {
      std::error_code created;
      std::filesystem::create_directories(store_root, created);
      if (created) {
        std::printf("store root cannot be created: %s\n", created.message().c_str());
        return 1;
      }
    }
    cfm::StoreOptions options;
    options.root = store_root;
    options.mode = cfm::StoreMode::ReadWrite;
    cfm::Result<cfm::StoreId> store_id = cfm::StoreId::parse("benchmark.store");
    if (!store_id.has_value()) {
      std::printf("store identity failed to parse\n");
      return 1;
    }
    cfm::Result<cfm::Store> store = cfm::Store::create(options, store_id.value());
    if (!store.has_value()) {
      std::printf("store creation failed: %s\n", store.error().to_string().c_str());
      return 1;
    }
    const std::uint64_t durable_iterations = iterations > 200 ? 200 : iterations;
    std::uint64_t completed = 0;
    Measurement measurement("store.publish.durable", "REAL file system",
                            decimal(durable_iterations) + " committed generations, durable flush");
    measurement.start();
    for (std::uint64_t iteration = 0; iteration < durable_iterations; ++iteration) {
      cfm::PublicationRequest request;
      request.epoch = store->epoch();
      request.incarnation = store->incarnation();
      request.mutation = *cfm::MutationId::parse("benchmark." + decimal(iteration));
      request.attempt = *cfm::AttemptOrdinal::parse(1);
      request.body = state;
      cfm::Result<cfm::PublicationReceipt> receipt = store->publish(request);
      if (!receipt.has_value()) {
        std::printf("publication failed: %s\n", receipt.error().to_string().c_str());
        return 1;
      }
      if (receipt->durability != cfm::PublicationDurability::Durable) {
        std::printf("publication did not establish durability\n");
        return 1;
      }
      ++completed;
    }
    measurement.stop(completed);

    std::uint64_t read_completed = 0;
    Measurement read_measurement("store.head.verify", "REAL file system",
                                 "re-read, integrity-checked head");
    read_measurement.start();
    for (std::uint64_t iteration = 0; iteration < durable_iterations; ++iteration) {
      cfm::Result<cfm::CoolingFailureState> head = store->head();
      if (!head.has_value()) {
        std::printf("head read failed: %s\n", head.error().to_string().c_str());
        return 1;
      }
      ++read_completed;
    }
    read_measurement.stop(read_completed);

    std::uint64_t verify_completed = 0;
    Measurement verify_measurement("store.verify.deep", "REAL file system",
                                   "every retained generation re-verified");
    verify_measurement.start();
    for (std::uint64_t iteration = 0; iteration < durable_iterations; ++iteration) {
      cfm::Result<cfm::VerifyReport> report = store->verify(cfm::VerifyOptions{});
      if (!report.has_value() || !report->ok()) {
        std::printf("verification failed\n");
        return 1;
      }
      ++verify_completed;
    }
    verify_measurement.stop(verify_completed);
    cfm::Result<void> closed = store->close();
    if (!closed.has_value()) {
      std::printf("store close failed\n");
      return 1;
    }
  } else {
    std::printf("%-42s %12s  %8s  %10s  [skipped: pass a store directory to measure it]\n",
                "store.publish.durable", "-", "-", "-");
  }

  std::printf("\nProvenance: SYNTHETIC cooling evidence and facility; REAL processes, file system and\n");
  std::printf("clock. Durability figures include the device flush and the read-back verification the\n");
  std::printf("library performs, and therefore depend on the storage device used.\n");
  return 0;
}
