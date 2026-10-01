// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Chiller plant loss, shared by two loops.
//
// A plant scope loses its chillers. Two downstream loops depend on it, one
// entirely and one for a minority of its declared supply. The example shows that
// the attribution follows the declared share: the wholly dependent loop is
// classified as sharing a confirmed loss, the partly dependent loop is not.
//
// Everything here is SYNTHETIC: the observations are values this program wrote
// into an observation set. No chiller, BMS or sensor was contacted.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/canonical.hpp"
#include "dccp/cooling_failure_manager/classify.hpp"
#include "dccp/cooling_failure_manager/decision.hpp"
#include "dccp/cooling_failure_manager/evidence.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/recovery.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

namespace cfm = dccp::cooling_failure_manager;

namespace {

int failures = 0;

void check(bool condition, const char* what) {
  if (!condition) {
    std::printf("FAIL %s\n", what);
    ++failures;
  }
}

void note(std::string_view text) { std::printf("%s\n", std::string(text).c_str()); }

cfm::ScopeId must_scope(std::string_view text) { return *cfm::ScopeId::parse(text); }
cfm::ObservationId must_observation(std::string_view text) { return *cfm::ObservationId::parse(text); }
cfm::DeclaredQuantity must_quantity(std::int64_t value, std::string_view unit) {
  return *cfm::DeclaredQuantity::make(value, unit);
}

/// Records one scalar observation on one channel.
void record(cfm::ObservationSet& set, std::string_view id, const cfm::ScopeId& scope,
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
void record_leak(cfm::ObservationSet& set, std::string_view id, const cfm::ScopeId& scope,
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
void record_status(cfm::ObservationSet& set, std::string_view id, const cfm::ScopeId& scope,
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

}  // namespace

int main() {
  const cfm::ScopeId plant = must_scope("plant.a");
  const cfm::ScopeId primary = must_scope("loop.primary");
  const cfm::ScopeId secondary = must_scope("loop.secondary");

  cfm::CoolingScope plant_scope;
  plant_scope.id = plant;
  plant_scope.kind = cfm::ScopeKind::Plant;
  plant_scope.display_name = "Primary chiller plant";
  plant_scope.policy.envelope.declared_demand = must_quantity(4000000, "W");
  plant_scope.policy.envelope.min_flow = must_quantity(50000, "mL/s");
  plant_scope.policy.envelope.min_thermal_margin = must_quantity(2000, "mK");
  plant_scope.policy.requirements.push_back(
      cfm::EvidenceRequirement{cfm::ObservationChannel::ChillerStatus, cfm::DurationMilliseconds(60000)});
  plant_scope.policy.requirements.push_back(
      cfm::EvidenceRequirement{cfm::ObservationChannel::ThermalCapacityMeter, cfm::DurationMilliseconds(60000)});
  plant_scope.policy.requirements.push_back(
      cfm::EvidenceRequirement{cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(60000)});
  plant_scope.policy.recovery_dwell = cfm::DurationMilliseconds(300000);
  plant_scope.policy.recovery_hysteresis = cfm::DurationMilliseconds(120000);

  cfm::CoolingScope primary_scope;
  primary_scope.id = primary;
  primary_scope.kind = cfm::ScopeKind::Loop;
  primary_scope.display_name = "Primary loop";
  primary_scope.policy.envelope.min_flow = must_quantity(30000, "mL/s");
  primary_scope.policy.envelope.declared_demand = must_quantity(2000000, "W");
  primary_scope.policy.requirements.push_back(
      cfm::EvidenceRequirement{cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(60000)});
  primary_scope.dependencies.push_back(
      cfm::ScopeDependency{plant, cfm::DependencyKind::SuppliesCoolant, 1000000});

  cfm::CoolingScope secondary_scope;
  secondary_scope.id = secondary;
  secondary_scope.kind = cfm::ScopeKind::Loop;
  secondary_scope.display_name = "Secondary loop";
  secondary_scope.policy.envelope.min_flow = must_quantity(10000, "mL/s");
  secondary_scope.policy.requirements.push_back(
      cfm::EvidenceRequirement{cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(60000)});
  secondary_scope.dependencies.push_back(
      cfm::ScopeDependency{plant, cfm::DependencyKind::SharesPlant, 200000});

  cfm::CoolingFailureState skeleton;
  skeleton.evaluated_at = cfm::DecisionClock(10000);
  skeleton.scopes = {plant_scope, primary_scope, secondary_scope};

  cfm::ObservationSet observations;
  record_status(observations, "obs.chiller", plant, cfm::ObservationChannel::ChillerStatus, 2, 9000, "bms-chiller");
  record(observations, "obs.capacity", plant, cfm::ObservationChannel::ThermalCapacityMeter, 1000, "W", 9000,
         "plant-meter");
  record(observations, "obs.plant-flow", plant, cfm::ObservationChannel::FlowMeter, 900, "mL/s", 9000, "plant-flow");
  record(observations, "obs.primary-flow", primary, cfm::ObservationChannel::FlowMeter, 800, "mL/s", 9000,
         "primary-flow");
  record(observations, "obs.secondary-flow", secondary, cfm::ObservationChannel::FlowMeter, 12000, "mL/s", 9000,
         "secondary-flow");

  cfm::DecisionPolicy policy;
  policy.evidence_window = cfm::DurationMilliseconds(60000);
  policy.confirm_min_observations = 1;
  policy.safety_escalation_severity = cfm::Severity::Critical;

  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy;
  input.clock = cfm::DecisionClock(10000);

  cfm::Result<cfm::DecisionOutcome> outcome = cfm::evaluate(input);
  check(outcome.has_value(), "the evaluation succeeded");
  if (!outcome.has_value()) {
    std::printf("error: %s\n", outcome.error().to_string().c_str());
    return 1;
  }

  const cfm::ScopeDecision* plant_decision = cfm::find_decision(outcome->state, plant);
  check(plant_decision != nullptr, "the plant has a decision");
  if (plant_decision != nullptr) {
    const bool plant_loss =
        std::find(plant_decision->confirmed_classes.begin(), plant_decision->confirmed_classes.end(),
                  cfm::FailureClass::PlantLoss) != plant_decision->confirmed_classes.end();
    check(plant_loss, "the plant is confirmed lost");
    check(plant_decision->severity == cfm::Severity::Critical, "plant loss is critical");
    check(plant_decision->urgency == cfm::Urgency::Immediate, "plant loss is immediate");
    note("plant: severity=" + std::string(cfm::to_token(plant_decision->severity)));
    for (const std::string& line : plant_decision->explanation) {
      note("  " + line);
    }
  }

  const cfm::ScopeDecision* primary_decision = cfm::find_decision(outcome->state, primary);
  check(primary_decision != nullptr, "the primary loop has a decision");
  if (primary_decision != nullptr) {
    const bool shared =
        std::find(primary_decision->confirmed_classes.begin(), primary_decision->confirmed_classes.end(),
                  cfm::FailureClass::SharedSourceFailure) != primary_decision->confirmed_classes.end();
    check(shared, "a wholly dependent loop shares the confirmed upstream loss");
    check(!primary_decision->shared_sources.empty(), "the shared source is named");
    note("primary: shared-sources=" + std::to_string(primary_decision->shared_sources.size()));
  }

  const cfm::ScopeDecision* secondary_decision = cfm::find_decision(outcome->state, secondary);
  check(secondary_decision != nullptr, "the secondary loop has a decision");
  if (secondary_decision != nullptr) {
    const bool shared =
        std::find(secondary_decision->confirmed_classes.begin(), secondary_decision->confirmed_classes.end(),
                  cfm::FailureClass::SharedSourceFailure) != secondary_decision->confirmed_classes.end();
    check(!shared, "a loop with a majority of its declared supply elsewhere is not confirmed lost");
    note("secondary: confirmed=" + std::to_string(secondary_decision->confirmed_classes.size()) +
         " suspected=" + std::to_string(secondary_decision->suspected_classes.size()));
  }

  note("");
  note("Attribution is not shared-memory inheritance: it is recomputed from the declared dependency");
  note("shares on every evaluation, so a topology change is reflected in the next decision.");

  if (failures == 0) {
    std::printf("example chiller_plant_loss ok\n");
    return 0;
  }
  std::printf("example chiller_plant_loss FAILED: %d check(s)\n", failures);
  return 1;
}
