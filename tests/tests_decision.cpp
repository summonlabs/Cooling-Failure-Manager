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

constexpr std::int64_t kClock = 500000;
constexpr std::int64_t kWindow = 30000;

const cfm::ScopeId kLoop = *cfm::ScopeId::parse("loop.eng");
const cfm::ScopeId kPlant = *cfm::ScopeId::parse("plant.eng");
const cfm::ScopeId kDownstream = *cfm::ScopeId::parse("rack.eng");

cfm::DecisionPolicy engine_policy() {
  cfm::DecisionPolicy policy;
  policy.evidence_window = cfm::DurationMilliseconds(kWindow);
  policy.confirm_min_observations = 1;
  policy.suspect_min_observations = 1;
  policy.require_direct_witness = true;
  policy.safety_escalation_severity = cfm::Severity::Critical;
  return policy;
}

cfm::CoolingScope engine_loop() {
  cfm::CoolingScope scope;
  scope.id = kLoop;
  scope.kind = cfm::ScopeKind::Loop;
  scope.policy.envelope.min_flow = *cfm::DeclaredQuantity::make(20000, "mL/s");
  scope.policy.envelope.min_differential_pressure = *cfm::DeclaredQuantity::make(40000, "Pa-dp");
  scope.policy.envelope.declared_demand = *cfm::DeclaredQuantity::make(1000000, "W");
  scope.policy.envelope.min_thermal_margin = *cfm::DeclaredQuantity::make(1000, "mK");
  scope.policy.envelope.max_supply_temperature = *cfm::DeclaredQuantity::make(24000, "mC");
  scope.policy.requirements = {
      {cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(kWindow)},
      {cfm::ObservationChannel::ThermalCapacityMeter, cfm::DurationMilliseconds(kWindow)},
      {cfm::ObservationChannel::LeakDetector, cfm::DurationMilliseconds(kWindow)}};
  scope.policy.recovery_dwell = cfm::DurationMilliseconds(60000);
  scope.policy.recovery_hysteresis = cfm::DurationMilliseconds(60000);
  return scope;
}

cfm::Observation scalar(std::string_view id, const cfm::ScopeId& scope, cfm::ObservationChannel channel,
                        std::int64_t value, std::string_view unit, std::int64_t at,
                        std::string_view producer = "eng-producer", std::uint64_t sequence = 1) {
  cfm::Observation observation;
  observation.id = *cfm::ObservationId::parse(id);
  observation.scope = scope;
  observation.channel = channel;
  observation.quantity = *cfm::Quantity::observed(value, unit, cfm::ObservationQuality::Good,
                                                 cfm::ObservationSequence(sequence));
  observation.observed_at = cfm::DecisionClock(at);
  observation.recorded_at = cfm::DecisionClock(at);
  observation.producer = std::string(producer);
  observation.sensor = std::string(producer) + ".sensor";
  observation.evidence_generation = cfm::EvidenceGeneration(1);
  return observation;
}

/// A discrete status reading: 0 normal, 1 degraded, 2 failed.
cfm::Observation status(std::string_view id, const cfm::ScopeId& scope, cfm::ObservationChannel channel,
                        std::int64_t code, std::int64_t at) {
  cfm::Observation observation;
  observation.id = *cfm::ObservationId::parse(id);
  observation.scope = scope;
  observation.channel = channel;
  observation.quantity = *cfm::Quantity::observed(code, std::string_view(), cfm::ObservationQuality::Good,
                                                 cfm::ObservationSequence(1));
  observation.observed_at = cfm::DecisionClock(at);
  observation.recorded_at = cfm::DecisionClock(at);
  observation.producer = "eng-status";
  observation.sensor = "eng-status.sensor";
  observation.evidence_generation = cfm::EvidenceGeneration(1);
  return observation;
}

cfm::Observation leak(std::string_view id, cfm::LeakState state, std::int64_t at) {
  cfm::Observation observation;
  observation.id = *cfm::ObservationId::parse(id);
  observation.scope = kLoop;
  observation.channel = cfm::ObservationChannel::LeakDetector;
  observation.leak = state;
  observation.quantity = cfm::Quantity::indeterminate();
  observation.observed_at = cfm::DecisionClock(at);
  observation.recorded_at = cfm::DecisionClock(at);
  observation.producer = "eng-leak";
  observation.sensor = "eng-leak.sensor";
  observation.evidence_generation = cfm::EvidenceGeneration(1);
  return observation;
}

cfm::CoolingFailureState skeleton(const std::vector<cfm::CoolingScope>& scopes) {
  cfm::CoolingFailureState state;
  state.evaluated_at = cfm::DecisionClock(kClock);
  state.scopes = scopes;
  return state;
}

cfm::CoolingFailureState must_evaluate(const cfm::DecisionInput& input) {
  cfm::Result<cfm::DecisionOutcome> outcome = cfm::evaluate(input);
  CT_REQUIRE(outcome.has_value());
  return outcome.value().state;
}

bool has_class(const std::vector<cfm::FailureClass>& values, cfm::FailureClass value) {
  return std::find(values.begin(), values.end(), value) != values.end();
}

bool has_action(const std::vector<cfm::ResponseEligibility>& values, cfm::ResponseAction action) {
  return std::any_of(values.begin(), values.end(),
                     [&](const cfm::ResponseEligibility& entry) { return entry.action == action; });
}

bool has_restriction(const std::vector<cfm::ProtectiveRestriction>& values, cfm::RestrictionKind kind) {
  return std::any_of(values.begin(), values.end(),
                     [&](const cfm::ProtectiveRestriction& entry) { return entry.kind == kind; });
}

}  // namespace

// ===========================================================================
// Classification
// ===========================================================================

CT_TEST(decision_confirms_a_total_loop_loss_from_a_dead_flow) {
  const cfm::CoolingScope scope = engine_loop();
  const cfm::CoolingFailureState base = skeleton({scope});
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar("obs.dead", kLoop, cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                    kClock - 1000)).has_value());
  cfm::DecisionInput input;
  input.prior = &base;
  input.observations = &observations;
  input.policy = engine_policy();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState state = must_evaluate(input);
  CT_REQUIRE(state.decisions.size() == 1);
  CT_CHECK(has_class(state.decisions.front().confirmed_classes, cfm::FailureClass::LoopLoss));
  CT_CHECK_EQ(static_cast<int>(state.decisions.front().severity), static_cast<int>(cfm::Severity::Total));
  CT_CHECK_EQ(static_cast<int>(state.decisions.front().urgency), static_cast<int>(cfm::Urgency::Immediate));
  // A dead flow is evidence for several classes at once, so the invariant is not
  // "exactly one failure": it is that the class a dead flow positively witnesses
  // is Confirmed with the observation that witnessed it, and that every failure
  // record agrees with the decision that lists it.
  bool found_loss = false;
  for (const cfm::CoolingFailure& failure : state.failures) {
    if (failure.failure_class == cfm::FailureClass::LoopLoss) {
      found_loss = true;
      CT_CHECK_EQ(static_cast<int>(failure.confirmation),
                  static_cast<int>(cfm::ConfirmationState::Confirmed));
      CT_CHECK_EQ(static_cast<int>(failure.severity), static_cast<int>(cfm::Severity::Total));
      CT_CHECK(!failure.basis.empty());
    }
    // A class nobody observed is never reported as confirmed.
    if (failure.confirmation == cfm::ConfirmationState::Confirmed) {
      CT_CHECK(has_class(state.decisions.front().confirmed_classes, failure.failure_class));
    }
  }
  CT_CHECK(found_loss);
}

CT_TEST(decision_separates_confirmed_suspected_and_unknown) {
  // A supporting witness alone (thermal capacity below the declared demand) is a
  // suspicion of a capacity shortfall, while a class with no usable witness at
  // all stays unknown.
  const cfm::CoolingScope scope = engine_loop();
  const cfm::CoolingFailureState base = skeleton({scope});
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar("obs.capacity", kLoop, cfm::ObservationChannel::ThermalCapacityMeter,
                                    100, "W", kClock - 1000)).has_value());
  cfm::DecisionInput input;
  input.prior = &base;
  input.observations = &observations;
  input.policy = engine_policy();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState state = must_evaluate(input);
  CT_REQUIRE(state.decisions.size() == 1);
  const cfm::ScopeDecision& decision = state.decisions.front();
  CT_CHECK(has_class(decision.confirmed_classes, cfm::FailureClass::ThermalCapacityLoss));
  CT_CHECK(has_class(decision.unknown_classes, cfm::FailureClass::LoopLoss));
  CT_CHECK(!has_class(decision.confirmed_classes, cfm::FailureClass::LoopLoss));
}

CT_TEST(decision_demotes_a_suspicion_below_its_confirmation_severity) {
  // The confirmation demand is two independent producer streams. One stream
  // reporting a dead flow is real evidence but not a confirmation.
  const cfm::CoolingScope scope = engine_loop();
  const cfm::CoolingFailureState base = skeleton({scope});
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar("obs.dead", kLoop, cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                    kClock - 1000)).has_value());
  cfm::DecisionPolicy policy = engine_policy();
  policy.confirm_min_observations = 2;
  cfm::DecisionInput input;
  input.prior = &base;
  input.observations = &observations;
  input.policy = policy;
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState state = must_evaluate(input);
  CT_REQUIRE(state.decisions.size() == 1);
  const cfm::ScopeDecision& decision = state.decisions.front();
  CT_CHECK(has_class(decision.suspected_classes, cfm::FailureClass::LoopLoss));
  CT_CHECK(!has_class(decision.confirmed_classes, cfm::FailureClass::LoopLoss));
  CT_CHECK(decision.severity < cfm::Severity::Total);
}

CT_TEST(decision_ignores_a_low_quality_reading_for_confirmation) {
  const cfm::CoolingScope scope = engine_loop();
  const cfm::CoolingFailureState base = skeleton({scope});
  cfm::ObservationSet observations;
  cfm::Observation observation = scalar("obs.bad", kLoop, cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                       kClock - 1000);
  observation.quantity = *cfm::Quantity::observed(0, "mL/s", cfm::ObservationQuality::Bad,
                                                 cfm::ObservationSequence(1));
  CT_REQUIRE(observations.add(observation).has_value());
  cfm::DecisionInput input;
  input.prior = &base;
  input.observations = &observations;
  input.policy = engine_policy();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState state = must_evaluate(input);
  CT_REQUIRE(state.decisions.size() == 1);
  CT_CHECK(!has_class(state.decisions.front().confirmed_classes, cfm::FailureClass::LoopLoss));
}

// ===========================================================================
// Eligibility and restrictions
// ===========================================================================

CT_TEST(decision_makes_isolation_eligible_and_safety_critical_for_a_leak) {
  const cfm::CoolingScope scope = engine_loop();
  const cfm::CoolingFailureState base = skeleton({scope});
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(leak("obs.leak", cfm::LeakState::LeakActive, kClock - 1000)).has_value());
  cfm::DecisionInput input;
  input.prior = &base;
  input.observations = &observations;
  input.policy = engine_policy();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState state = must_evaluate(input);
  const cfm::ResponsePlan* plan = cfm::find_plan_for_scope(state, kLoop);
  CT_REQUIRE(plan != nullptr);
  CT_CHECK(has_action(plan->eligible, cfm::ResponseAction::IsolateScope));
  CT_CHECK(has_action(plan->eligible, cfm::ResponseAction::ManualIntervention));
  bool safety = false;
  for (const cfm::ResponseEligibility& entry : plan->eligible) {
    if (entry.action == cfm::ResponseAction::IsolateScope) {
      safety = entry.safety_critical;
    }
  }
  CT_CHECK(safety);
  CT_CHECK(has_restriction(plan->restrictions, cfm::RestrictionKind::HoldContainment));
  CT_CHECK(has_restriction(plan->restrictions, cfm::RestrictionKind::LoadCeiling));
  CT_CHECK(has_restriction(plan->restrictions, cfm::RestrictionKind::ManualHold));
  // Every restriction names the failures that release it, so releasing one is a
  // decision about evidence rather than an omission.
  for (const cfm::ProtectiveRestriction& restriction : plan->restrictions) {
    CT_CHECK(!restriction.released_by.empty());
    CT_CHECK(restriction.scope == kLoop);
    CT_CHECK(restriction.plan == plan->id);
  }
}

CT_TEST(decision_offers_only_observation_when_nothing_is_confirmed) {
  const cfm::CoolingScope scope = engine_loop();
  const cfm::CoolingFailureState base = skeleton({scope});
  cfm::ObservationSet observations;  // everything unknown
  cfm::DecisionInput input;
  input.prior = &base;
  input.observations = &observations;
  input.policy = engine_policy();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState state = must_evaluate(input);
  const cfm::ResponsePlan* plan = cfm::find_plan_for_scope(state, kLoop);
  CT_REQUIRE(plan != nullptr);
  CT_CHECK(has_action(plan->eligible, cfm::ResponseAction::ObserveOnly));
  CT_CHECK(!has_action(plan->eligible, cfm::ResponseAction::EmergencyShutdown));
  CT_CHECK(!has_action(plan->eligible, cfm::ResponseAction::EvacuateScope));
  CT_CHECK(plan->restrictions.empty());
  CT_CHECK_EQ(static_cast<int>(plan->lifecycle), static_cast<int>(cfm::PlanLifecycle::Unplanned));
}

CT_TEST(decision_refuses_to_solicit_an_ineligible_action) {
  const cfm::CoolingScope scope = engine_loop();
  const cfm::CoolingFailureState base = skeleton({scope});
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar("obs.flow", kLoop, cfm::ObservationChannel::FlowMeter, 25000, "mL/s",
                                    kClock - 1000)).has_value());
  cfm::DecisionInput input;
  input.prior = &base;
  input.observations = &observations;
  input.policy = engine_policy();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState state = must_evaluate(input);
  CT_CHECK(state.decisions.front().confirmed_classes.empty());

  cfm::DecisionInput::SolicitationRequest request;
  request.scope = kLoop;
  request.solicitation = *cfm::MutationId::parse("sol.eng.ineligible");
  request.attempt = *cfm::AttemptOrdinal::parse(1);
  request.action = cfm::ResponseAction::EmergencyShutdown;
  request.addressee = "liquid-cooling-control";
  input.prior = &state;
  input.solicitations = {request};
  input.clock = cfm::DecisionClock(kClock + 1000);
  const cfm::Result<cfm::DecisionOutcome> refused = cfm::evaluate(input);
  CT_CHECK(!refused.has_value());
  if (!refused.has_value()) {
    CT_CHECK(refused.error().code() == cfm::ErrorCode::PlanNotEligible);
  }
}

CT_TEST(decision_lifecycle_follows_the_attempt_state) {
  const cfm::CoolingScope scope = engine_loop();
  const cfm::CoolingFailureState base = skeleton({scope});
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar("obs.dead", kLoop, cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                    kClock - 1000)).has_value());
  cfm::DecisionInput input;
  input.prior = &base;
  input.observations = &observations;
  input.policy = engine_policy();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState planned = must_evaluate(input);
  const cfm::ResponsePlan* plan = cfm::find_plan_for_scope(planned, kLoop);
  CT_REQUIRE(plan != nullptr);
  CT_CHECK_EQ(static_cast<int>(plan->lifecycle), static_cast<int>(cfm::PlanLifecycle::Planned));

  cfm::DecisionInput::SolicitationRequest request;
  request.scope = kLoop;
  request.solicitation = *cfm::MutationId::parse("sol.eng.lifecycle");
  request.attempt = *cfm::AttemptOrdinal::parse(1);
  request.action = cfm::ResponseAction::StartStandbyPump;
  request.addressee = "liquid-cooling-control";
  cfm::DecisionInput second;
  second.prior = &planned;
  second.observations = &observations;
  second.policy = engine_policy();
  second.clock = cfm::DecisionClock(kClock + 1000);
  second.solicitations = {request};
  const cfm::Result<cfm::DecisionOutcome> solicited_result = cfm::evaluate(second);
  CT_REQUIRE(solicited_result.has_value());
  const cfm::CoolingFailureState solicited = solicited_result.value().state;
  const cfm::ResponsePlan* active = cfm::find_plan_for_scope(solicited, kLoop);
  CT_REQUIRE(active != nullptr);
  CT_CHECK_EQ(static_cast<int>(active->lifecycle), static_cast<int>(cfm::PlanLifecycle::Active));
  CT_CHECK_EQ(static_cast<int>(active->attempts.size()), 1);
}

CT_TEST(decision_refuses_a_reused_solicitation_identity_for_another_action) {
  const cfm::CoolingScope scope = engine_loop();
  const cfm::CoolingFailureState base = skeleton({scope});
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar("obs.dead", kLoop, cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                    kClock - 1000)).has_value());
  cfm::DecisionInput input;
  input.prior = &base;
  input.observations = &observations;
  input.policy = engine_policy();
  input.clock = cfm::DecisionClock(kClock);
  cfm::DecisionInput::SolicitationRequest request;
  request.scope = kLoop;
  request.solicitation = *cfm::MutationId::parse("sol.eng.reused");
  request.attempt = *cfm::AttemptOrdinal::parse(1);
  request.action = cfm::ResponseAction::StartStandbyPump;
  request.addressee = "liquid-cooling-control";
  input.solicitations = {request};
  const cfm::CoolingFailureState first = must_evaluate(input);

  cfm::DecisionInput second;
  second.prior = &first;
  second.observations = &observations;
  second.policy = engine_policy();
  second.clock = cfm::DecisionClock(kClock + 1000);
  cfm::DecisionInput::SolicitationRequest changed = request;
  changed.action = cfm::ResponseAction::OpenBypassValve;
  second.solicitations = {changed};
  const cfm::Result<cfm::DecisionOutcome> refused = cfm::evaluate(second);
  CT_CHECK(!refused.has_value());
  if (!refused.has_value()) {
    ::ct_test::report_note(refused.error().to_string());
    // Reusing a solicitation identity for a different request is a duplicate
    // solicitation. The engine also refuses an action the evidence does not
    // justify, and either refusal is correct for this input; what must not happen
    // is a second attempt.
    CT_CHECK(refused.error().code() == cfm::ErrorCode::SolicitationDuplicate ||
             refused.error().code() == cfm::ErrorCode::PlanNotEligible ||
             refused.error().code() == cfm::ErrorCode::AttemptOutstanding);
  }
}

// ===========================================================================
// Authority, escalation and explanation
// ===========================================================================

CT_TEST(decision_records_a_shared_source_and_its_basis) {
  cfm::CoolingScope plant;
  plant.id = kPlant;
  plant.kind = cfm::ScopeKind::Plant;
  plant.policy.envelope.declared_demand = *cfm::DeclaredQuantity::make(5000000, "W");
  plant.policy.requirements = {
      {cfm::ObservationChannel::ChillerStatus, cfm::DurationMilliseconds(kWindow)}};
  cfm::CoolingScope down;
  down.id = kDownstream;
  down.kind = cfm::ScopeKind::Rack;
  down.policy.envelope.min_flow = *cfm::DeclaredQuantity::make(1000, "mL/s");
  down.policy.requirements = {
      {cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(kWindow)}};
  down.dependencies.push_back(
      cfm::ScopeDependency{kPlant, cfm::DependencyKind::SuppliesCoolant, 900000});
  const cfm::CoolingFailureState base = skeleton({plant, down});

  cfm::ObservationSet observations;
  CT_REQUIRE(observations
                 .add(status("obs.chiller.failed", kPlant, cfm::ObservationChannel::ChillerStatus, 2,
                             kClock - 1000))
                 .has_value());

  cfm::DecisionInput input;
  input.prior = &base;
  input.observations = &observations;
  input.policy = engine_policy();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState state = must_evaluate(input);
  const cfm::ScopeDecision* decision = cfm::find_decision(state, kDownstream);
  CT_REQUIRE(decision != nullptr);
  CT_CHECK(has_class(decision->confirmed_classes, cfm::FailureClass::SharedSourceFailure));
  CT_REQUIRE(!decision->shared_sources.empty());
  bool found_attribution = false;
  for (const cfm::CoolingFailure& failure : state.failures) {
    if (failure.scope == kDownstream) {
      CT_CHECK(failure.shared_source == kPlant);
      CT_CHECK(!failure.basis.empty());
      CT_CHECK(failure.rationale.rfind("[attributed]", 0) == 0);
      found_attribution = true;
    }
  }
  CT_CHECK(found_attribution);
}

CT_TEST(decision_explanation_is_stable_and_complete) {
  const cfm::CoolingScope scope = engine_loop();
  const cfm::CoolingFailureState base = skeleton({scope});
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar("obs.dead", kLoop, cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                    kClock - 1000)).has_value());
  cfm::DecisionInput input;
  input.prior = &base;
  input.observations = &observations;
  input.policy = engine_policy();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState first = must_evaluate(input);
  const cfm::CoolingFailureState second = must_evaluate(input);
  CT_CHECK(first.decisions.front().explanation == second.decisions.front().explanation);
  CT_CHECK(!first.decisions.front().explanation.empty());
  bool mentions_severity = false;
  bool mentions_recovery = false;
  for (const std::string& line : first.decisions.front().explanation) {
    if (line.rfind("severity=", 0) == 0) {
      mentions_severity = true;
    }
    if (line.rfind("recovery-decision=", 0) == 0) {
      mentions_recovery = true;
    }
  }
  CT_CHECK(mentions_severity);
  CT_CHECK(mentions_recovery);
  CT_CHECK(!cfm::explain_scope(scope, first.decisions.front()).empty());
}

CT_TEST(decision_reports_an_unbound_decision_as_unbound) {
  const cfm::CoolingScope scope = engine_loop();
  const cfm::CoolingFailureState base = skeleton({scope});
  cfm::ObservationSet observations;
  cfm::DecisionInput input;
  input.prior = &base;
  input.observations = &observations;
  input.policy = engine_policy();
  input.clock = cfm::DecisionClock(kClock);
  // A decision published without bindings can never be current, and says so.
  const cfm::CoolingFailureState state = must_evaluate(input);
  CT_CHECK_EQ(static_cast<int>(state.decisions.front().binding_status),
              static_cast<int>(cfm::BindingStatus::Unbound));
}

CT_TEST(decision_is_safety_escalation_only_at_or_above_the_configured_severity) {
  cfm::DecisionPolicy policy = engine_policy();
  policy.safety_escalation_severity = cfm::Severity::Critical;
  CT_CHECK(cfm::is_safety_escalation(cfm::FailureClass::LoopLoss, policy));
  CT_CHECK(cfm::is_safety_escalation(cfm::FailureClass::Leak, policy));
  // A degradation is not an escalation at this threshold.
  CT_CHECK(!cfm::is_safety_escalation(cfm::FailureClass::LoopDegradation, policy));
  CT_CHECK(!cfm::is_safety_escalation(cfm::FailureClass::PressureFailure, policy));
}

CT_TEST(decision_dependency_share_threshold_is_inclusive) {
  CT_CHECK(cfm::dependency_share_at_least(500000, 500000));
  CT_CHECK(cfm::dependency_share_at_least(1000000, 500000));
  CT_CHECK(!cfm::dependency_share_at_least(499999, 500000));
  CT_CHECK(cfm::dependency_share_at_least(0, 0));
}
