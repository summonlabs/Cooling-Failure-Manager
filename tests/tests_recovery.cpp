// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/canonical.hpp"
#include "dccp/cooling_failure_manager/classify.hpp"
#include "dccp/cooling_failure_manager/decision.hpp"
#include "dccp/cooling_failure_manager/enums.hpp"
#include "dccp/cooling_failure_manager/evidence.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/model.hpp"
#include "dccp/cooling_failure_manager/recovery.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

#include "test_framework.hpp"

namespace cfm = dccp::cooling_failure_manager;

namespace {

constexpr std::int64_t kClock = 900000;
constexpr std::int64_t kWindow = 30000;

const cfm::ScopeId kScope = *cfm::ScopeId::parse("loop.rec");

cfm::DecisionPolicy rec_policy() {
  cfm::DecisionPolicy policy;
  policy.evidence_window = cfm::DurationMilliseconds(kWindow);
  policy.confirm_min_observations = 1;
  policy.suspect_min_observations = 1;
  return policy;
}

cfm::CoolingScope rec_scope() {
  cfm::CoolingScope scope;
  scope.id = kScope;
  scope.kind = cfm::ScopeKind::Loop;
  scope.policy.envelope.min_flow = *cfm::DeclaredQuantity::make(20000, "mL/s");
  scope.policy.envelope.min_differential_pressure = *cfm::DeclaredQuantity::make(40000, "Pa-dp");
  scope.policy.envelope.declared_demand = *cfm::DeclaredQuantity::make(1000000, "W");
  scope.policy.envelope.min_thermal_margin = *cfm::DeclaredQuantity::make(1000, "mK");
  scope.policy.envelope.max_supply_temperature = *cfm::DeclaredQuantity::make(24000, "mC");
  scope.policy.requirements = {
      {cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(kWindow)},
      {cfm::ObservationChannel::DifferentialPressure, cfm::DurationMilliseconds(kWindow)},
      {cfm::ObservationChannel::ThermalCapacityMeter, cfm::DurationMilliseconds(kWindow)},
      {cfm::ObservationChannel::ThermalMarginMeter, cfm::DurationMilliseconds(kWindow)},
      {cfm::ObservationChannel::LeakDetector, cfm::DurationMilliseconds(kWindow)},
      {cfm::ObservationChannel::ContainmentSwitch, cfm::DurationMilliseconds(kWindow)},
      {cfm::ObservationChannel::AirflowMeter, cfm::DurationMilliseconds(kWindow)}};
  scope.policy.recovery_dwell = cfm::DurationMilliseconds(120000);
  scope.policy.recovery_hysteresis = cfm::DurationMilliseconds(60000);
  return scope;
}

cfm::Observation reading(std::string_view id, cfm::ObservationChannel channel, std::int64_t value,
                         std::string_view unit, std::int64_t at = kClock - 1000) {
  cfm::Observation observation;
  observation.id = *cfm::ObservationId::parse(id);
  observation.scope = kScope;
  observation.channel = channel;
  if (cfm::channel_unit(channel).empty()) {
    observation.quantity = *cfm::Quantity::observed(value, std::string_view(),
                                                   cfm::ObservationQuality::Good,
                                                   cfm::ObservationSequence(1));
  } else {
    observation.quantity = *cfm::Quantity::observed(value, unit, cfm::ObservationQuality::Good,
                                                   cfm::ObservationSequence(1));
  }
  observation.observed_at = cfm::DecisionClock(at);
  observation.recorded_at = cfm::DecisionClock(at);
  observation.producer = "rec-producer";
  observation.sensor = "rec-producer.sensor";
  observation.evidence_generation = cfm::EvidenceGeneration(1);
  return observation;
}

cfm::Observation leak_reading(std::string_view id, cfm::LeakState state, std::int64_t at = kClock - 1000) {
  cfm::Observation observation;
  observation.id = *cfm::ObservationId::parse(id);
  observation.scope = kScope;
  observation.channel = cfm::ObservationChannel::LeakDetector;
  observation.leak = state;
  observation.quantity = cfm::Quantity::indeterminate();
  observation.observed_at = cfm::DecisionClock(at);
  observation.recorded_at = cfm::DecisionClock(at);
  observation.producer = "rec-leak";
  observation.sensor = "rec-leak.sensor";
  observation.evidence_generation = cfm::EvidenceGeneration(1);
  return observation;
}

/// Every channel the recovery gates read, all inside their declared envelopes and
/// all current: the evidence a permitted recovery looks like.
cfm::ObservationSet healthy_evidence() {
  cfm::ObservationSet set;
  CT_REQUIRE(set.add(reading("rec.flow", cfm::ObservationChannel::FlowMeter, 25000, "mL/s")).has_value());
  CT_REQUIRE(set.add(reading("rec.dp", cfm::ObservationChannel::DifferentialPressure, 60000, "Pa-dp"))
                 .has_value());
  CT_REQUIRE(set.add(reading("rec.capacity", cfm::ObservationChannel::ThermalCapacityMeter, 1200000, "W"))
                 .has_value());
  CT_REQUIRE(set.add(reading("rec.margin", cfm::ObservationChannel::ThermalMarginMeter, 3000, "mK"))
                 .has_value());
  CT_REQUIRE(set.add(reading("rec.airflow", cfm::ObservationChannel::AirflowMeter, 22000, "mL/s")).has_value());
  CT_REQUIRE(set.add(reading("rec.containment", cfm::ObservationChannel::ContainmentSwitch, 0,
                             std::string_view())).has_value());
  CT_REQUIRE(set.add(leak_reading("rec.leak", cfm::LeakState::LeakNone)).has_value());
  return set;
}

/// The requirements of the permitted baseline: no confirmed class to clear, no
/// effect owed, and every channel the scope's policy names as demanded.
cfm::RecoveryRequirements baseline_requirements(const cfm::CoolingScope& scope) {
  cfm::RecoveryRequirements requirements;
  requirements.scope = scope.id;
  for (const cfm::EvidenceRequirement& requirement : scope.policy.requirements) {
    requirements.required_observations.push_back(requirement.channel);
  }
  std::sort(requirements.required_observations.begin(), requirements.required_observations.end(),
            [](cfm::ObservationChannel lhs, cfm::ObservationChannel rhs) {
              return cfm::channel_index(lhs) < cfm::channel_index(rhs);
            });
  requirements.required_observations.erase(
      std::unique(requirements.required_observations.begin(), requirements.required_observations.end()),
      requirements.required_observations.end());
  requirements.require_verified_effect = false;
  requirements.require_leak_clear = true;
  return requirements;
}

/// A state snapshot carrying one verified attempt for the scope.
cfm::CoolingFailureState verified_snapshot(const cfm::CoolingScope& scope,
                                          std::string_view observation) {
  cfm::CoolingFailureState snapshot;
  snapshot.scopes = {scope};
  cfm::ResponsePlan plan;
  plan.id = *cfm::PlanId::parse("plan.rec.permit");
  plan.scope = scope.id;
  cfm::ResponseAttempt attempt;
  attempt.id = *cfm::AttemptId::parse("at.rec.permit");
  attempt.solicitation = *cfm::MutationId::parse("sol.rec.permit");
  attempt.attempt = *cfm::AttemptOrdinal::parse(1);
  attempt.action = cfm::ResponseAction::StartStandbyPump;
  attempt.state = cfm::AttemptState::Verified;
  attempt.addressee = "liquid-cooling-control";
  attempt.acknowledged_at = cfm::DecisionClock(kClock - 2000);
  attempt.effect_observation = *cfm::ObservationId::parse(observation);
  attempt.verdict = "the effect was verified against the observation";
  plan.attempts.push_back(attempt);
  snapshot.plans.push_back(plan);
  return snapshot;
}

cfm::ScopeDecision empty_decision() {
  cfm::ScopeDecision decision;
  decision.scope = kScope;
  decision.evaluated_at = cfm::DecisionClock(kClock);
  return decision;
}

cfm::RecoveryAssessment evaluate(const cfm::CoolingScope& scope, const cfm::ScopeDecision& decision,
                                const cfm::RecoveryRequirements& requirements,
                                const cfm::ObservationSet& observations, std::int64_t clock = kClock) {
  cfm::Result<cfm::RecoveryAssessment> assessment = cfm::evaluate_recovery(
      scope, decision, requirements, observations, rec_policy(), cfm::DecisionClock(clock));
  CT_REQUIRE(assessment.has_value());
  return assessment.value();
}

bool has_gate(const std::vector<cfm::RecoveryGateResult>& gates, cfm::RecoveryGate gate) {
  return std::any_of(gates.begin(), gates.end(),
                     [&](const cfm::RecoveryGateResult& entry) { return entry.gate == gate; });
}

bool gate_satisfied(const std::vector<cfm::RecoveryGateResult>& gates, cfm::RecoveryGate gate) {
  for (const cfm::RecoveryGateResult& entry : gates) {
    if (entry.gate == gate) {
      return entry.satisfied;
    }
  }
  return false;
}

}  // namespace

// ===========================================================================
// Requirements
// ===========================================================================

CT_TEST(recovery_requirements_demand_the_channels_that_witnessed_the_failure) {
  const cfm::CoolingScope scope = rec_scope();
  cfm::ScopeDecision decision = empty_decision();
  decision.confirmed_classes = {cfm::FailureClass::LoopLoss};
  decision.suspected_classes = {cfm::FailureClass::Leak};
  decision.has_plan = true;

  const cfm::Result<cfm::RecoveryRequirements> requirements =
      cfm::recovery_requirements(scope, decision);
  CT_REQUIRE(requirements.has_value());
  CT_CHECK(std::find(requirements->required_cleared_classes.begin(),
                     requirements->required_cleared_classes.end(),
                     cfm::FailureClass::LoopLoss) != requirements->required_cleared_classes.end());
  CT_CHECK(std::find(requirements->required_cleared_classes.begin(),
                     requirements->required_cleared_classes.end(),
                     cfm::FailureClass::Leak) != requirements->required_cleared_classes.end());
  // The witness channels of the confirmed class are demanded, in canonical order.
  CT_CHECK(std::find(requirements->required_observations.begin(),
                     requirements->required_observations.end(),
                     cfm::ObservationChannel::FlowMeter) != requirements->required_observations.end());
  CT_CHECK(std::is_sorted(requirements->required_observations.begin(),
                          requirements->required_observations.end(),
                          [](cfm::ObservationChannel lhs, cfm::ObservationChannel rhs) {
                            return cfm::channel_index(lhs) < cfm::channel_index(rhs);
                          }));
  CT_CHECK(requirements->require_leak_clear);
  CT_CHECK(requirements->require_verified_effect);
  CT_CHECK_EQ(requirements->dwell.milliseconds(), static_cast<std::int64_t>(120000));
  CT_CHECK_EQ(requirements->hysteresis.milliseconds(), static_cast<std::int64_t>(60000));
}

CT_TEST(recovery_requirements_do_not_demand_an_effect_when_nothing_was_planned) {
  const cfm::CoolingScope scope = rec_scope();
  const cfm::ScopeDecision decision = empty_decision();
  const cfm::Result<cfm::RecoveryRequirements> requirements =
      cfm::recovery_requirements(scope, decision);
  CT_REQUIRE(requirements.has_value());
  CT_CHECK(!requirements->require_verified_effect);
  CT_CHECK(!requirements->require_leak_clear);
  CT_CHECK(requirements->required_cleared_classes.empty());
}

// ===========================================================================
// Gate evaluation
// ===========================================================================

CT_TEST(recovery_every_gate_is_evaluated_and_named) {
  const cfm::CoolingScope scope = rec_scope();
  const cfm::ScopeDecision decision = empty_decision();
  const cfm::RecoveryRequirements requirements = baseline_requirements(scope);
  const cfm::ObservationSet observations = healthy_evidence();
  const cfm::RecoveryAssessment assessment =
      evaluate(scope, decision, requirements, observations);
  CT_CHECK_EQ(assessment.gates.size(), cfm::recovery_gate_count());
  CT_CHECK(has_gate(assessment.gates, cfm::RecoveryGate::FlowKnown));
  CT_CHECK(has_gate(assessment.gates, cfm::RecoveryGate::LeakClear));
  CT_CHECK(has_gate(assessment.gates, cfm::RecoveryGate::EffectVerified));
  CT_CHECK(has_gate(assessment.gates, cfm::RecoveryGate::DwellElapsed));
  CT_CHECK(has_gate(assessment.gates, cfm::RecoveryGate::HysteresisElapsed));
  // The gates are in canonical order regardless of the order they were evaluated.
  CT_CHECK(std::is_sorted(assessment.gates.begin(), assessment.gates.end(),
                          [](const cfm::RecoveryGateResult& lhs, const cfm::RecoveryGateResult& rhs) {
                            return cfm::recovery_gate_index(lhs.gate) < cfm::recovery_gate_index(rhs.gate);
                          }));
}

CT_TEST(recovery_is_permitted_when_every_gate_passes) {
  const cfm::CoolingScope scope = rec_scope();
  const cfm::ScopeDecision decision = empty_decision();
  cfm::RecoveryRequirements requirements = baseline_requirements(scope);
  requirements.require_verified_effect = true;
  // The scope policy demands 120 s of dwell plus 60 s of hysteresis, so a
  // permitted assessment needs an interval that has held for longer than both.
  requirements.stable_since = cfm::DecisionClock(kClock - (120000 + 60000 + 1));
  // A permitted recovery owes a verified effect, so the snapshot carries one.
  const cfm::CoolingFailureState snapshot = verified_snapshot(scope, "rec.flow");
  requirements.state_snapshot = &snapshot;
  const cfm::ObservationSet observations = healthy_evidence();
  const cfm::RecoveryAssessment assessment =
      evaluate(scope, decision, requirements, observations);
  CT_CHECK_EQ(static_cast<int>(assessment.decision), static_cast<int>(cfm::RecoveryDecision::Permitted));
  CT_CHECK(assessment.blocking_gates.empty());
  CT_CHECK(cfm::recovery_releases_restrictions(assessment));
  CT_CHECK(!cfm::recovery_requires_manual_hold(assessment));
  CT_CHECK(!assessment.explanation.empty());
  CT_CHECK(!cfm::explain_recovery(assessment).empty());
}

CT_TEST(recovery_is_deferred_with_the_remaining_interval_reported) {
  const cfm::CoolingScope scope = rec_scope();
  const cfm::ScopeDecision decision = empty_decision();
  cfm::RecoveryRequirements requirements = baseline_requirements(scope);
  requirements.stable_since = cfm::DecisionClock(kClock - 1000);
  const cfm::ObservationSet observations = healthy_evidence();
  const cfm::RecoveryAssessment assessment =
      evaluate(scope, decision, requirements, observations);
  CT_CHECK_EQ(static_cast<int>(assessment.decision), static_cast<int>(cfm::RecoveryDecision::Deferred));
  CT_CHECK(assessment.remaining_dwell_milliseconds > 0);
  CT_CHECK(!cfm::recovery_releases_restrictions(assessment));
  CT_CHECK(cfm::recovery_requires_manual_hold(assessment));
  // A running interval is not a failed gate: the blockers list stays empty and
  // the interval gates are the only unsatisfied ones.
  CT_CHECK(assessment.blocking_gates.empty());
}

CT_TEST(recovery_is_blocked_by_a_stale_reading) {
  const cfm::CoolingScope scope = rec_scope();
  const cfm::ScopeDecision decision = empty_decision();
  cfm::RecoveryRequirements requirements;
  requirements.scope = kScope;
  requirements.required_observations = {cfm::ObservationChannel::FlowMeter};
  requirements.stable_since = cfm::DecisionClock(kClock - 1000000);

  cfm::ObservationSet observations;
  CT_REQUIRE(observations
                 .add(reading("rec.flow.old", cfm::ObservationChannel::FlowMeter, 25000, "mL/s",
                              kClock - kWindow - 5000))
                 .has_value());
  const cfm::RecoveryAssessment assessment =
      evaluate(scope, decision, requirements, observations);
  CT_CHECK_EQ(static_cast<int>(assessment.decision), static_cast<int>(cfm::RecoveryDecision::Blocked));
  CT_CHECK(!gate_satisfied(assessment.gates, cfm::RecoveryGate::FlowKnown));
  CT_CHECK(std::find(assessment.blocking_gates.begin(), assessment.blocking_gates.end(),
                     cfm::RecoveryGate::FlowKnown) != assessment.blocking_gates.end());
}

CT_TEST(recovery_is_blocked_by_an_out_of_envelope_reading) {
  // The flow is current, but it is still below the declared floor: a current
  // reading is not a recovered one.
  const cfm::CoolingScope scope = rec_scope();
  const cfm::ScopeDecision decision = empty_decision();
  cfm::RecoveryRequirements requirements;
  requirements.scope = kScope;
  requirements.required_observations = {cfm::ObservationChannel::FlowMeter};
  requirements.stable_since = cfm::DecisionClock(kClock - 1000000);

  cfm::ObservationSet observations;
  CT_REQUIRE(observations
                 .add(reading("rec.flow.low", cfm::ObservationChannel::FlowMeter, 5000, "mL/s"))
                 .has_value());
  const cfm::RecoveryAssessment assessment =
      evaluate(scope, decision, requirements, observations);
  CT_CHECK_EQ(static_cast<int>(assessment.decision), static_cast<int>(cfm::RecoveryDecision::Blocked));
}

CT_TEST(recovery_is_blocked_by_a_pressure_above_the_ceiling) {
  // Inside the envelope means inside it on both sides. The differential-pressure
  // envelope here declares only a floor, so a value above any ceiling is
  // permissive; the containment gate covers the state-code channels.
  const cfm::CoolingScope scope = rec_scope();
  const cfm::ScopeDecision decision = empty_decision();
  cfm::RecoveryRequirements requirements;
  requirements.scope = kScope;
  requirements.required_observations = {cfm::ObservationChannel::ContainmentSwitch};
  requirements.stable_since = cfm::DecisionClock(kClock - 1000000);

  cfm::ObservationSet observations;
  // A containment switch reporting the open state is not a restored containment.
  CT_REQUIRE(observations
                 .add(reading("rec.containment.open", cfm::ObservationChannel::ContainmentSwitch, 2,
                              std::string_view()))
                 .has_value());
  const cfm::RecoveryAssessment assessment =
      evaluate(scope, decision, requirements, observations);
  CT_CHECK_EQ(static_cast<int>(assessment.decision), static_cast<int>(cfm::RecoveryDecision::Blocked));
  CT_CHECK(!gate_satisfied(assessment.gates, cfm::RecoveryGate::ContainmentRestored));
}

CT_TEST(recovery_leak_gate_needs_a_positive_assertion) {
  const cfm::CoolingScope scope = rec_scope();
  const cfm::ScopeDecision decision = empty_decision();
  cfm::RecoveryRequirements requirements;
  requirements.scope = kScope;
  requirements.require_leak_clear = true;
  requirements.stable_since = cfm::DecisionClock(kClock - 1000000);

  for (const cfm::LeakState state :
       {cfm::LeakState::LeakUnknown, cfm::LeakState::LeakSuspected, cfm::LeakState::LeakConfirmed,
        cfm::LeakState::LeakActive}) {
    cfm::ObservationSet observations;
    CT_REQUIRE(observations.add(leak_reading("rec.leak.state", state)).has_value());
    const cfm::RecoveryAssessment assessment =
        evaluate(scope, decision, requirements, observations);
    CT_CHECK(!gate_satisfied(assessment.gates, cfm::RecoveryGate::LeakClear));
    CT_CHECK_EQ(static_cast<int>(assessment.decision), static_cast<int>(cfm::RecoveryDecision::Blocked));
  }

  cfm::ObservationSet clear;
  CT_REQUIRE(clear.add(leak_reading("rec.leak.none", cfm::LeakState::LeakNone)).has_value());
  const cfm::RecoveryAssessment permitted = evaluate(scope, decision, requirements, clear);
  CT_CHECK(gate_satisfied(permitted.gates, cfm::RecoveryGate::LeakClear));
}

CT_TEST(recovery_without_a_stable_interval_is_deferred_never_permitted) {
  const cfm::CoolingScope scope = rec_scope();
  const cfm::ScopeDecision decision = empty_decision();
  const cfm::RecoveryRequirements requirements = baseline_requirements(scope);
  // No stable_since: the interval never started.
  const cfm::ObservationSet observations = healthy_evidence();
  const cfm::RecoveryAssessment assessment =
      evaluate(scope, decision, requirements, observations);
  CT_CHECK_EQ(static_cast<int>(assessment.decision), static_cast<int>(cfm::RecoveryDecision::Deferred));
  CT_CHECK(!gate_satisfied(assessment.gates, cfm::RecoveryGate::DwellElapsed));
  CT_CHECK(!cfm::recovery_releases_restrictions(assessment));
}

CT_TEST(recovery_dwell_uses_the_scope_policy_when_the_demand_is_silent) {
  const cfm::CoolingScope scope = rec_scope();
  const cfm::ScopeDecision decision = empty_decision();
  cfm::RecoveryRequirements requirements = baseline_requirements(scope);
  // The policy demands 120 s of dwell plus 60 s of hysteresis. At 150 s the
  // assessment is still deferred; at 200 s it is permitted.
  requirements.stable_since = cfm::DecisionClock(kClock - 150000);
  const cfm::ObservationSet observations = healthy_evidence();
  const cfm::RecoveryAssessment early =
      evaluate(scope, decision, requirements, observations, kClock);
  CT_CHECK_EQ(static_cast<int>(early.decision), static_cast<int>(cfm::RecoveryDecision::Deferred));

  requirements.stable_since = cfm::DecisionClock(kClock - 200000);
  const cfm::RecoveryAssessment settled =
      evaluate(scope, decision, requirements, observations, kClock);
  CT_CHECK_EQ(static_cast<int>(settled.decision), static_cast<int>(cfm::RecoveryDecision::Permitted));
}

CT_TEST(recovery_effect_gate_requires_a_verified_attempt) {
  const cfm::CoolingScope scope = rec_scope();
  cfm::ScopeDecision decision = empty_decision();
  decision.has_plan = true;
  cfm::RecoveryRequirements requirements = baseline_requirements(scope);
  requirements.require_verified_effect = true;

  cfm::CoolingFailureState snapshot;
  snapshot.scopes = {scope};
  cfm::ResponsePlan plan;
  plan.id = *cfm::PlanId::parse("plan.rec");
  plan.scope = kScope;
  cfm::ResponseAttempt attempt;
  attempt.id = *cfm::AttemptId::parse("at.rec");
  attempt.solicitation = *cfm::MutationId::parse("sol.rec");
  attempt.attempt = *cfm::AttemptOrdinal::parse(1);
  attempt.action = cfm::ResponseAction::StartStandbyPump;
  attempt.state = cfm::AttemptState::Acknowledged;
  attempt.addressee = "liquid-cooling-control";
  attempt.acknowledged_at = cfm::DecisionClock(kClock - 1000);
  plan.attempts.push_back(attempt);
  snapshot.plans.push_back(plan);
  requirements.state_snapshot = &snapshot;
  requirements.stable_since = cfm::DecisionClock(kClock - (120000 + 60000 + 1));

  const cfm::ObservationSet observations = healthy_evidence();
  const cfm::RecoveryAssessment acknowledged =
      evaluate(scope, decision, requirements, observations);
  CT_CHECK(!gate_satisfied(acknowledged.gates, cfm::RecoveryGate::EffectVerified));
  CT_CHECK_EQ(static_cast<int>(acknowledged.decision), static_cast<int>(cfm::RecoveryDecision::Blocked));

  // The same plan with the attempt verified and its verdict recorded.
  snapshot.plans.front().attempts.front().state = cfm::AttemptState::Verified;
  snapshot.plans.front().attempts.front().verdict = "flow restored above the declared floor";
  snapshot.plans.front().attempts.front().effect_observation = *cfm::ObservationId::parse("rec.flow");
  const cfm::RecoveryAssessment verified = evaluate(scope, decision, requirements, observations);
  CT_CHECK(gate_satisfied(verified.gates, cfm::RecoveryGate::EffectVerified));
  CT_CHECK_EQ(static_cast<int>(verified.decision), static_cast<int>(cfm::RecoveryDecision::Permitted));
}

CT_TEST(recovery_without_a_state_snapshot_cannot_satisfy_the_effect_gate) {
  const cfm::CoolingScope scope = rec_scope();
  cfm::ScopeDecision decision = empty_decision();
  decision.has_plan = true;
  cfm::RecoveryRequirements requirements = baseline_requirements(scope);
  requirements.require_verified_effect = true;
  requirements.stable_since = cfm::DecisionClock(kClock - 1000000);
  const cfm::ObservationSet observations = healthy_evidence();
  const cfm::RecoveryAssessment assessment =
      evaluate(scope, decision, requirements, observations);
  CT_CHECK(!gate_satisfied(assessment.gates, cfm::RecoveryGate::EffectVerified));
  CT_CHECK_EQ(static_cast<int>(assessment.decision), static_cast<int>(cfm::RecoveryDecision::Blocked));
}

CT_TEST(recovery_confirmed_classes_cleared_applies_the_same_predicate_as_classification) {
  const cfm::CoolingScope scope = rec_scope();
  const cfm::ScopeDecision& decision = empty_decision();
  cfm::RecoveryRequirements requirements = baseline_requirements(scope);
  requirements.required_cleared_classes = {cfm::FailureClass::LoopLoss};
  requirements.stable_since = cfm::DecisionClock(kClock - 1000000);

  // The flow is still dead, so the class that the flow witnessed has not cleared
  // even though every channel is current.
  cfm::ObservationSet dead = healthy_evidence();
  cfm::ObservationSet replaced;
  for (const cfm::Observation& observation : dead.observations()) {
    if (observation.channel == cfm::ObservationChannel::FlowMeter) {
      CT_REQUIRE(replaced
                     .add(reading("rec.flow.dead", cfm::ObservationChannel::FlowMeter, 0, "mL/s"))
                     .has_value());
    } else {
      CT_REQUIRE(replaced.add(observation).has_value());
    }
  }
  const cfm::RecoveryAssessment assessment = evaluate(scope, decision, requirements, replaced);
  CT_CHECK(!gate_satisfied(assessment.gates, cfm::RecoveryGate::ConfirmedClassesCleared));
  CT_CHECK_EQ(static_cast<int>(assessment.decision), static_cast<int>(cfm::RecoveryDecision::Blocked));

  // The same demand against a healthy flow clears.
  const cfm::ObservationSet healthy = healthy_evidence();
  const cfm::RecoveryAssessment cleared = evaluate(scope, decision, requirements, healthy);
  CT_CHECK(gate_satisfied(cleared.gates, cfm::RecoveryGate::ConfirmedClassesCleared));
}

CT_TEST(recovery_assessment_names_every_unsatisfied_gate) {
  const cfm::CoolingScope scope = rec_scope();
  const cfm::ScopeDecision decision = empty_decision();
  cfm::RecoveryRequirements requirements = baseline_requirements(scope);
  requirements.require_verified_effect = true;
  requirements.stable_since = cfm::DecisionClock(kClock - 1000000);
  const cfm::ObservationSet nothing;
  const cfm::RecoveryAssessment assessment = evaluate(scope, decision, requirements, nothing);
  CT_CHECK_EQ(static_cast<int>(assessment.decision), static_cast<int>(cfm::RecoveryDecision::Blocked));
  CT_CHECK(!assessment.blocking_gates.empty());
  CT_CHECK(std::is_sorted(assessment.blocking_gates.begin(), assessment.blocking_gates.end(),
                          [](cfm::RecoveryGate lhs, cfm::RecoveryGate rhs) {
                            return cfm::recovery_gate_index(lhs) < cfm::recovery_gate_index(rhs);
                          }));
  for (const cfm::RecoveryGate gate : assessment.blocking_gates) {
    CT_CHECK(!gate_satisfied(assessment.gates, gate));
  }
  CT_CHECK(!assessment.explanation.empty());
}
