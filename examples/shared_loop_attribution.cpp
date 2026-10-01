// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Shared upstream loop: one loss, three dependent scopes, three different answers.
//
// This example makes the attribution rule inspectable. The same upstream loss is
// attributed to a rack, a row and a thermal zone with different declared shares,
// and the example prints the confirmed/suspected split that follows from those
// shares. It also shows the report this component produces when a dependency
// cycle would make attribution unbounded: the cycle is refused by structural
// validation rather than traversed.
//
// Everything here is SYNTHETIC.

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
#include "dccp/cooling_failure_manager/store.hpp"
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
  const cfm::ScopeId loop = must_scope("loop.shared");
  const cfm::ScopeId rack = must_scope("rack.7");
  const cfm::ScopeId row = must_scope("row.b");
  const cfm::ScopeId zone = must_scope("zone.3");

  cfm::CoolingScope loop_scope;
  loop_scope.id = loop;
  loop_scope.kind = cfm::ScopeKind::Loop;
  loop_scope.policy.envelope.min_flow = must_quantity(40000, "mL/s");
  loop_scope.policy.envelope.min_differential_pressure = must_quantity(60000, "Pa-dp");
  loop_scope.policy.requirements = {
      cfm::EvidenceRequirement{cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(60000)},
      cfm::EvidenceRequirement{cfm::ObservationChannel::DifferentialPressure, cfm::DurationMilliseconds(60000)},
  };

  auto dependent = [&loop](const cfm::ScopeId& id, cfm::ScopeKind kind, std::int64_t share) {
    cfm::CoolingScope scope;
    scope.id = id;
    scope.kind = kind;
    scope.policy.envelope.min_flow = must_quantity(1000, "mL/s");
    scope.dependencies.push_back(
        cfm::ScopeDependency{loop, cfm::DependencyKind::SuppliesCoolant, share});
    return scope;
  };

  cfm::CoolingFailureState skeleton;
  skeleton.evaluated_at = cfm::DecisionClock(5000);
  skeleton.scopes = {loop_scope, dependent(rack, cfm::ScopeKind::Rack, 1000000),
                     dependent(row, cfm::ScopeKind::Row, 750000),
                     dependent(zone, cfm::ScopeKind::ThermalZone, 250000)};

  cfm::ObservationSet observations;
  record(observations, "obs.loop.flow", loop, cfm::ObservationChannel::FlowMeter, 0, "mL/s", 4000, "loop-flow");
  record(observations, "obs.loop.dp", loop, cfm::ObservationChannel::DifferentialPressure, 0, "Pa-dp", 4000,
         "loop-dp");

  cfm::DecisionPolicy policy;
  policy.evidence_window = cfm::DurationMilliseconds(60000);

  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy;
  input.clock = cfm::DecisionClock(5000);

  cfm::Result<cfm::DecisionOutcome> outcome = cfm::evaluate(input);
  check(outcome.has_value(), "the evaluation succeeded");
  if (!outcome.has_value()) {
    std::printf("error: %s\n", outcome.error().to_string().c_str());
    return 1;
  }

  const cfm::ScopeId dependents[3] = {rack, row, zone};
  const std::int64_t shares[3] = {1000000, 750000, 250000};
  for (std::size_t index = 0; index < 3; ++index) {
    const cfm::ScopeDecision* decision = cfm::find_decision(outcome->state, dependents[index]);
    check(decision != nullptr, "each dependent scope has a decision");
    if (decision == nullptr) {
      continue;
    }
    const bool confirmed =
        std::find(decision->confirmed_classes.begin(), decision->confirmed_classes.end(),
                  cfm::FailureClass::SharedSourceFailure) != decision->confirmed_classes.end();
    const bool suspected =
        std::find(decision->suspected_classes.begin(), decision->suspected_classes.end(),
                  cfm::FailureClass::SharedSourceFailure) != decision->suspected_classes.end();
    note(std::string("share ") + std::to_string(shares[index]) + " ppm -> " +
         (confirmed ? "confirmed" : (suspected ? "suspected" : "neither")));
    if (shares[index] >= 500000) {
      check(confirmed, "a share at or above half the declared supply is a confirmed loss");
    } else {
      check(!confirmed, "a share below half the declared supply is not a confirmed loss");
    }
  }

  // The same graph with a cycle must be refused rather than traversed forever.
  cfm::CoolingFailureState cyclic = skeleton;
  cyclic.scopes[0].dependencies.push_back(
      cfm::ScopeDependency{rack, cfm::DependencyKind::SharesReturn, 100000});
  const cfm::Result<void> validated = cfm::validate_structure(cyclic);
  check(!validated.has_value(), "a dependency cycle is refused by structural validation");
  if (!validated.has_value()) {
    note(std::string("cycle refusal: ") + validated.error().to_string());
  }

  note("");
  note("Attribution is bounded work. The traversal is depth-limited and visit-limited, and a");
  note("cycle is refused before it is ever traversed, so a hostile graph cannot stall a decision.");

  if (failures == 0) {
    std::printf("example shared_loop_attribution ok\n");
    return 0;
  }
  std::printf("example shared_loop_attribution FAILED: %d check(s)\n", failures);
  return 1;
}
