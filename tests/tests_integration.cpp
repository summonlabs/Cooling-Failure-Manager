// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Integration tests: the invariants that only hold if the parts agree.
//
// Each case here crosses at least two translation units. The unit suites prove
// what one module does; these cases prove that the component's central promises
// survive the seams - that an absent reading never becomes a healthy one, that an
// acknowledgement never becomes an effect, that a recovery is never inferred from
// elapsed time, and that a decision is a pure function of its inputs.

#include <algorithm>
#include <cstdint>
#include <filesystem>
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
#include "dccp/cooling_failure_manager/store.hpp"
#include "dccp/cooling_failure_manager/text.hpp"
#include "dccp/cooling_failure_manager/version.hpp"

#include "child_process.hpp"
#include "test_framework.hpp"

namespace cfm = dccp::cooling_failure_manager;

namespace {

constexpr std::int64_t kClock = 1000000000;
constexpr std::int64_t kWindow = 60000;

const cfm::ScopeId kLoop = *cfm::ScopeId::parse("loop.it");
const cfm::ScopeId kPlant = *cfm::ScopeId::parse("plant.it");

cfm::DecisionPolicy policy_with_window() {
  cfm::DecisionPolicy policy;
  policy.evidence_window = cfm::DurationMilliseconds(kWindow);
  policy.confirm_min_observations = 1;
  policy.suspect_min_observations = 1;
  policy.require_direct_witness = true;
  policy.safety_escalation_severity = cfm::Severity::Critical;
  return policy;
}

/// A loop whose flow floor is declared, with the channels its class rules witness.
cfm::CoolingScope make_loop(bool with_envelope = true) {
  cfm::CoolingScope scope;
  scope.id = kLoop;
  scope.kind = cfm::ScopeKind::Loop;
  scope.display_name = "Integration loop";
  if (with_envelope) {
    scope.policy.envelope.min_flow = *cfm::DeclaredQuantity::make(30000, "mL/s");
    scope.policy.envelope.min_differential_pressure = *cfm::DeclaredQuantity::make(50000, "Pa-dp");
    scope.policy.envelope.declared_demand = *cfm::DeclaredQuantity::make(2000000, "W");
    scope.policy.envelope.min_thermal_margin = *cfm::DeclaredQuantity::make(2000, "mK");
    scope.policy.envelope.max_supply_temperature = *cfm::DeclaredQuantity::make(25000, "mC");
  }
  // Requirements are held in canonical channel order: a state has one spelling,
  // and validate_structure refuses a second one.
  scope.policy.requirements = {
      {cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(kWindow)},
      {cfm::ObservationChannel::DifferentialPressure, cfm::DurationMilliseconds(kWindow)},
      {cfm::ObservationChannel::CoolantTemperature, cfm::DurationMilliseconds(kWindow)},
      {cfm::ObservationChannel::LeakDetector, cfm::DurationMilliseconds(kWindow)},
      {cfm::ObservationChannel::ThermalCapacityMeter, cfm::DurationMilliseconds(kWindow)},
      {cfm::ObservationChannel::ThermalMarginMeter, cfm::DurationMilliseconds(kWindow)}};
  scope.policy.recovery_dwell = cfm::DurationMilliseconds(300000);
  scope.policy.recovery_hysteresis = cfm::DurationMilliseconds(120000);
  return scope;
}

cfm::Observation scalar_observation(std::string_view id, cfm::ObservationChannel channel,
                                    std::int64_t value, std::string_view unit, std::int64_t at,
                                    std::string_view producer = "it-producer",
                                    cfm::ObservationQuality quality = cfm::ObservationQuality::Good,
                                    std::uint64_t sequence = 1) {
  cfm::Observation observation;
  observation.id = *cfm::ObservationId::parse(id);
  observation.scope = kLoop;
  observation.channel = channel;
  observation.quantity = *cfm::Quantity::observed(value, unit, quality, cfm::ObservationSequence(sequence));
  observation.observed_at = cfm::DecisionClock(at);
  observation.recorded_at = cfm::DecisionClock(at);
  observation.producer = std::string(producer);
  observation.sensor = std::string(producer) + ".sensor";
  observation.evidence_generation = cfm::EvidenceGeneration(1);
  return observation;
}

cfm::Observation leak_observation(std::string_view id, cfm::LeakState leak, std::int64_t at,
                                  std::string_view producer = "it-leak") {
  cfm::Observation observation;
  observation.id = *cfm::ObservationId::parse(id);
  observation.scope = kLoop;
  observation.channel = cfm::ObservationChannel::LeakDetector;
  observation.leak = leak;
  observation.quantity = cfm::Quantity::indeterminate();
  observation.observed_at = cfm::DecisionClock(at);
  observation.recorded_at = cfm::DecisionClock(at);
  observation.producer = std::string(producer);
  observation.sensor = std::string(producer) + ".sensor";
  observation.evidence_generation = cfm::EvidenceGeneration(1);
  return observation;
}

cfm::CoolingFailureState skeleton_with(const cfm::CoolingScope& scope) {
  cfm::CoolingFailureState state;
  state.evaluated_at = cfm::DecisionClock(kClock);
  state.scopes = {scope};
  return state;
}

bool contains(const std::vector<cfm::FailureClass>& values, cfm::FailureClass value) {
  return std::find(values.begin(), values.end(), value) != values.end();
}

/// Evaluates one synthetic scenario and aborts the test on failure, because every
/// later assertion in a case depends on the state being valid.
cfm::CoolingFailureState must_evaluate(const cfm::DecisionInput& input) {
  cfm::Result<cfm::DecisionOutcome> outcome = cfm::evaluate(input);
  CT_REQUIRE(outcome.has_value());
  return outcome.value().state;
}

}  // namespace

// ===========================================================================
// I1: an absent reading is unknown, never healthy and never zero
// ===========================================================================

CT_TEST(it_absent_flow_is_unsupported_not_healthy) {
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;  // deliberately empty
  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy_with_window();
  input.clock = cfm::DecisionClock(kClock);

  const cfm::CoolingFailureState state = must_evaluate(input);
  CT_REQUIRE(state.decisions.size() == 1);
  const cfm::ScopeDecision& decision = state.decisions.front();
  CT_CHECK(decision.confirmed_classes.empty());
  CT_CHECK(decision.suspected_classes.empty());
  CT_CHECK(contains(decision.unknown_classes, cfm::FailureClass::LoopLoss));
  CT_CHECK(decision.severity == cfm::Severity::None);
  CT_CHECK(!decision.evidence_gaps.empty());
  // The flow channel is named as a gap, which is the answer to "what evidence is
  // required" - not a report that flow is fine.
  CT_CHECK(std::find(decision.evidence_gaps.begin(), decision.evidence_gaps.end(),
                     cfm::ObservationChannel::FlowMeter) != decision.evidence_gaps.end());
}

CT_TEST(it_indeterminate_reading_is_never_zero) {
  const cfm::Quantity indeterminate = cfm::Quantity::indeterminate();
  CT_CHECK(!indeterminate.has_value());
  CT_CHECK(!indeterminate.is_usable());
  CT_CHECK(!indeterminate.value_if_observed().has_value());
  const cfm::Result<std::int64_t> value = indeterminate.observed_value();
  CT_CHECK(!value.has_value());
  CT_CHECK(value.error().code() == cfm::ErrorCode::EvidenceMissing);

  // The same reading recorded as evidence: recorded, named as a gap, and never
  // allowed to confirm a failure that a zero would have confirmed.
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  cfm::Observation observation = scalar_observation("obs.indeterminate",
                                                   cfm::ObservationChannel::FlowMeter, 0, "mL/s", kClock - 1000);
  observation.quantity = cfm::Quantity::indeterminate();
  CT_REQUIRE(observations.add(observation).has_value());

  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy_with_window();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState state = must_evaluate(input);
  CT_REQUIRE(state.decisions.size() == 1);
  CT_CHECK(!contains(state.decisions.front().confirmed_classes, cfm::FailureClass::LoopLoss));
  CT_CHECK(std::find(state.decisions.front().evidence_gaps.begin(),
                     state.decisions.front().evidence_gaps.end(),
                     cfm::ObservationChannel::FlowMeter) !=
           state.decisions.front().evidence_gaps.end());
}

CT_TEST(it_zero_flow_confirms_a_loss_when_the_floor_is_declared) {
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar_observation("obs.dead", cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                                kClock - 1000)).has_value());
  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy_with_window();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState state = must_evaluate(input);
  CT_REQUIRE(state.decisions.size() == 1);
  CT_CHECK(contains(state.decisions.front().confirmed_classes, cfm::FailureClass::LoopLoss));
  CT_CHECK(state.decisions.front().severity == cfm::Severity::Total);
}

CT_TEST(it_undeclared_envelope_cannot_confirm_an_envelope_bound_class) {
  // A scope that declares no flow floor still has a LOOP LOSS confirmed by a dead
  // flow, because "the flow is zero" needs no declared limit to be a fact. What
  // it cannot do is confirm a class whose witness is an envelope bound: an
  // undeclared limit is not a violated limit, so a merely low flow on a scope
  // with no declared floor is not a degradation.
  const cfm::CoolingScope scope = make_loop(false);
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar_observation("obs.low", cfm::ObservationChannel::FlowMeter, 500, "mL/s",
                                                kClock - 1000)).has_value());
  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy_with_window();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState state = must_evaluate(input);
  CT_REQUIRE(state.decisions.size() == 1);
  const cfm::ScopeDecision& decision = state.decisions.front();
  CT_CHECK(!contains(decision.confirmed_classes, cfm::FailureClass::LoopDegradation));
  CT_CHECK(!contains(decision.confirmed_classes, cfm::FailureClass::ThermalCapacityLoss));
  CT_CHECK(contains(decision.unknown_classes, cfm::FailureClass::LoopDegradation));
}

// ===========================================================================
// Freshness, ordering and conflicting evidence
// ===========================================================================

CT_TEST(it_stale_flow_is_not_current_evidence) {
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar_observation("obs.stale", cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                                kClock - kWindow - 1)).has_value());
  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy_with_window();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState state = must_evaluate(input);
  CT_REQUIRE(state.decisions.size() == 1);
  CT_CHECK(!contains(state.decisions.front().confirmed_classes, cfm::FailureClass::LoopLoss));
  CT_REQUIRE(!state.evidence.empty());
  bool saw_stale = false;
  for (const cfm::EvidenceAssessment& entry : state.evidence) {
    if (entry.channel == cfm::ObservationChannel::FlowMeter) {
      CT_CHECK_EQ(static_cast<int>(entry.status), static_cast<int>(cfm::EvidenceStatus::Stale));
      CT_CHECK_EQ(static_cast<int>(entry.freshness), static_cast<int>(cfm::Freshness::Stale));
      saw_stale = true;
    }
  }
  CT_CHECK(saw_stale);
}

CT_TEST(it_a_future_reading_is_future_and_its_age_is_negative) {
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar_observation("obs.future", cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                                kClock + 5000)).has_value());
  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy_with_window();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState state = must_evaluate(input);
  bool saw_future = false;
  for (const cfm::EvidenceAssessment& entry : state.evidence) {
    if (entry.channel == cfm::ObservationChannel::FlowMeter) {
      CT_CHECK_EQ(static_cast<int>(entry.status), static_cast<int>(cfm::EvidenceStatus::Future));
      CT_CHECK_EQ(static_cast<int>(entry.freshness), static_cast<int>(cfm::Freshness::Future));
      // A negative age is preserved, never clamped to zero: a reading from the
      // future is a clock or provenance defect, not a fresh reading.
      CT_CHECK(entry.age_milliseconds < 0);
      saw_future = true;
    }
  }
  CT_CHECK(saw_future);
  CT_CHECK(!contains(state.decisions.front().confirmed_classes, cfm::FailureClass::LoopLoss));
}

CT_TEST(it_conflicting_streams_are_conflicting_and_unusable) {
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  // Two producers, the same sequence number, two different readings.
  CT_REQUIRE(observations.add(scalar_observation("obs.a", cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                                kClock - 1000, "producer-a", cfm::ObservationQuality::Good, 7))
                 .has_value());
  CT_REQUIRE(observations.add(scalar_observation("obs.b", cfm::ObservationChannel::FlowMeter, 44000, "mL/s",
                                                kClock - 1000, "producer-b", cfm::ObservationQuality::Good, 7))
                 .has_value());
  CT_CHECK(observations.has_conflict(kLoop, cfm::ObservationChannel::FlowMeter));

  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy_with_window();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState state = must_evaluate(input);
  // Neither reading may be used: the component reports the disagreement rather
  // than choosing the answer it prefers.
  CT_CHECK(!contains(state.decisions.front().confirmed_classes, cfm::FailureClass::LoopLoss));
  bool saw_conflict = false;
  for (const cfm::EvidenceAssessment& entry : state.evidence) {
    if (entry.status == cfm::EvidenceStatus::Conflicting) {
      saw_conflict = true;
    }
  }
  CT_CHECK(saw_conflict);
}

// ===========================================================================
// I2: acknowledgement is not an effect
// ===========================================================================

CT_TEST(it_acknowledgement_never_becomes_an_effect) {
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar_observation("obs.dead", cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                                kClock - 1000)).has_value());
  cfm::DecisionPolicy policy = policy_with_window();

  cfm::DecisionInput first;
  first.prior = &skeleton;
  first.observations = &observations;
  first.policy = policy;
  first.clock = cfm::DecisionClock(kClock);
  cfm::CoolingFailureState state = must_evaluate(first);

  cfm::DecisionInput::SolicitationRequest solicitation;
  solicitation.scope = kLoop;
  solicitation.solicitation = *cfm::MutationId::parse("sol.it.1");
  solicitation.attempt = *cfm::AttemptOrdinal::parse(1);
  solicitation.action = cfm::ResponseAction::StartStandbyPump;
  solicitation.addressee = "liquid-cooling-control";

  cfm::DecisionInput second;
  second.prior = &state;
  second.observations = &observations;
  second.policy = policy;
  second.clock = cfm::DecisionClock(kClock + 1000);
  second.solicitations = {solicitation};
  cfm::CoolingFailureState solicited = must_evaluate(second);
  const cfm::ResponsePlan* plan = cfm::find_plan_for_scope(solicited, kLoop);
  CT_REQUIRE(plan != nullptr);
  CT_REQUIRE(plan->attempts.size() == 1);
  const cfm::AttemptId attempt = plan->attempts.front().id;
  CT_CHECK_EQ(static_cast<int>(plan->attempts.front().state),
              static_cast<int>(cfm::AttemptState::Solicited));

  cfm::DecisionInput::AttemptReport acknowledged;
  acknowledged.attempt = attempt;
  acknowledged.state = cfm::AttemptState::Acknowledged;
  acknowledged.at = cfm::DecisionClock(kClock + 2000);
  cfm::DecisionInput third;
  third.prior = &solicited;
  third.observations = &observations;
  third.policy = policy;
  third.clock = cfm::DecisionClock(kClock + 2000);
  third.attempt_reports = {acknowledged};
  const cfm::CoolingFailureState acked = must_evaluate(third);
  const cfm::ResponsePlan* acked_plan = cfm::find_plan_for_scope(acked, kLoop);
  CT_REQUIRE(acked_plan != nullptr);
  CT_REQUIRE(acked_plan->attempts.size() == 1);
  CT_CHECK_EQ(static_cast<int>(acked_plan->attempts.front().state),
              static_cast<int>(cfm::AttemptState::Acknowledged));
  CT_CHECK(acked_plan->attempts.front().effect_observation.empty());
  // The acknowledgement did not advance the confirmation: flow is still dead and
  // the class is still confirmed, because accepting a request changes nothing
  // about the coolant.
  CT_CHECK(contains(acked.decisions.front().confirmed_classes, cfm::FailureClass::LoopLoss));
}

CT_TEST(it_a_verified_effect_requires_the_named_observation) {
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar_observation("obs.dead", cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                                kClock - 1000)).has_value());
  cfm::DecisionPolicy policy = policy_with_window();

  cfm::DecisionInput first;
  first.prior = &skeleton;
  first.observations = &observations;
  first.policy = policy;
  first.clock = cfm::DecisionClock(kClock);
  cfm::CoolingFailureState state = must_evaluate(first);

  cfm::DecisionInput::SolicitationRequest solicitation;
  solicitation.scope = kLoop;
  solicitation.solicitation = *cfm::MutationId::parse("sol.it.2");
  solicitation.attempt = *cfm::AttemptOrdinal::parse(1);
  solicitation.action = cfm::ResponseAction::StartStandbyPump;
  solicitation.addressee = "liquid-cooling-control";
  cfm::DecisionInput second;
  second.prior = &state;
  second.observations = &observations;
  second.policy = policy;
  second.clock = cfm::DecisionClock(kClock + 1000);
  second.solicitations = {solicitation};
  const cfm::CoolingFailureState solicited = must_evaluate(second);
  const cfm::ResponsePlan* plan = cfm::find_plan_for_scope(solicited, kLoop);
  CT_REQUIRE(plan != nullptr && !plan->attempts.empty());
  const cfm::AttemptId attempt = plan->attempts.front().id;

  // Claiming a verified effect without an observation is refused outright.
  cfm::DecisionInput::AttemptReport claim;
  claim.attempt = attempt;
  claim.state = cfm::AttemptState::Verified;
  claim.at = cfm::DecisionClock(kClock + 2000);
  claim.verdict = "trust me";
  cfm::DecisionInput third;
  third.prior = &solicited;
  third.observations = &observations;
  third.policy = policy;
  third.clock = cfm::DecisionClock(kClock + 2000);
  third.attempt_reports = {claim};
  cfm::Result<cfm::DecisionOutcome> refused = cfm::evaluate(third);
  CT_CHECK(!refused.has_value());
  if (!refused.has_value()) {
    ::ct_test::report_note("claim without observation: " + refused.error().to_string());
    CT_CHECK(refused.error().code() == cfm::ErrorCode::EffectClaimedWithoutEvidence);
  }

  // Naming an observation that is not recorded evidence is refused too.
  cfm::DecisionInput::AttemptReport unrecorded = claim;
  unrecorded.effect_observation = *cfm::ObservationId::parse("obs.does-not-exist");
  cfm::DecisionInput fourth = third;
  fourth.attempt_reports = {unrecorded};
  const cfm::Result<cfm::DecisionOutcome> refused_again = cfm::evaluate(fourth);
  CT_CHECK(!refused_again.has_value());
  if (!refused_again.has_value()) {
    ::ct_test::report_note("claim with unknown observation: " + refused_again.error().to_string());
    CT_CHECK(refused_again.error().code() == cfm::ErrorCode::EffectClaimedWithoutEvidence);
  }

  // Naming a recorded observation of the right scope makes the claim checkable.
  cfm::DecisionInput::AttemptReport backed = claim;
  backed.effect_observation = *cfm::ObservationId::parse("obs.dead");
  cfm::DecisionInput fifth = third;
  fifth.attempt_reports = {backed};
  cfm::Result<cfm::DecisionOutcome> accepted = cfm::evaluate(fifth);
  if (!accepted.has_value()) {
    ::ct_test::report_note("accepted claim refused: " + accepted.error().to_string());
  }
  CT_CHECK(accepted.has_value());
}

// ===========================================================================
// I5: determinism
// ===========================================================================

CT_TEST(it_a_decision_is_deterministic_under_input_reordering) {
  const cfm::CoolingScope scope = make_loop();
  cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet forward;
  cfm::ObservationSet backward;
  const cfm::Observation observations[] = {
      scalar_observation("obs.1", cfm::ObservationChannel::FlowMeter, 0, "mL/s", kClock - 1000),
      scalar_observation("obs.2", cfm::ObservationChannel::DifferentialPressure, 0, "Pa-dp", kClock - 2000),
      scalar_observation("obs.3", cfm::ObservationChannel::ThermalCapacityMeter, 100, "W", kClock - 3000),
      leak_observation("obs.4", cfm::LeakState::LeakActive, kClock - 4000)};
  for (const cfm::Observation& observation : observations) {
    CT_REQUIRE(forward.add(observation).has_value());
  }
  for (std::size_t index = 4; index > 0; --index) {
    CT_REQUIRE(backward.add(observations[index - 1]).has_value());
  }

  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.policy = policy_with_window();
  input.clock = cfm::DecisionClock(kClock);
  input.observations = &forward;
  const cfm::CoolingFailureState first = must_evaluate(input);
  input.observations = &backward;
  const cfm::CoolingFailureState second = must_evaluate(input);

  CT_CHECK(cfm::encode_state(first) == cfm::encode_state(second));
  CT_CHECK(cfm::state_digest(first) == cfm::state_digest(second));
  CT_REQUIRE(first.decisions.size() == 1);
  CT_REQUIRE(second.decisions.size() == 1);
  CT_CHECK(first.decisions.front().explanation == second.decisions.front().explanation);
}

CT_TEST(it_repeated_evaluation_of_the_same_inputs_is_a_fixed_point) {
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar_observation("obs.dead", cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                                kClock - 1000)).has_value());
  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy_with_window();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState first = must_evaluate(input);

  // Feeding the previous decision back in must not accumulate failures, plans or
  // evidence: the engine replaces what it derived rather than adding to it.
  cfm::DecisionInput again = input;
  again.prior = &first;
  const cfm::CoolingFailureState second = must_evaluate(again);
  CT_CHECK_EQ(second.failures.size(), first.failures.size());
  CT_CHECK_EQ(second.plans.size(), first.plans.size());
  CT_CHECK_EQ(second.evidence.size(), first.evidence.size());
  CT_CHECK_EQ(second.decisions.size(), first.decisions.size());
  CT_CHECK(cfm::encode_state(second) == cfm::encode_state(first));
}

CT_TEST(it_canonical_encoding_survives_a_full_round_trip) {
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar_observation("obs.dead", cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                                kClock - 1000)).has_value());
  CT_REQUIRE(observations.add(leak_observation("obs.leak", cfm::LeakState::LeakConfirmed, kClock - 1000))
                 .has_value());
  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy_with_window();
  input.clock = cfm::DecisionClock(kClock);
  input.bindings.set("cooling-topology", *cfm::AuthorityRef::make("cooling-topology", "site.a",
                                                                 cfm::ExternalGeneration(4)));
  const cfm::CoolingFailureState state = must_evaluate(input);

  const std::string encoded = cfm::encode_state(state);
  const cfm::Result<cfm::CoolingFailureState> decoded = cfm::decode_state(encoded);
  if (!decoded.has_value()) {
    ::ct_test::report_note("decode refusal: " + decoded.error().to_string());
  }
  CT_REQUIRE(decoded.has_value());
  CT_CHECK(cfm::encode_state(decoded.value()) == encoded);
  CT_CHECK(cfm::state_digest(decoded.value()) == cfm::state_digest(state));

  // A single flipped byte anywhere in the body is detected, never repaired.
  for (std::size_t offset : {encoded.size() / 4, encoded.size() / 2, encoded.size() - 20}) {
    std::string damaged = encoded;
    damaged[offset] = static_cast<char>(damaged[offset] ^ 0x01);
    const cfm::Result<cfm::CoolingFailureState> broken = cfm::decode_state(damaged);
    CT_CHECK(!broken.has_value());
  }
}

// ===========================================================================
// Recovery gates
// ===========================================================================

CT_TEST(it_recovery_is_blocked_without_positive_leak_clearance) {
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  // Flow is restored and capacity is restored, but the leak detector never
  // positively reports "no leak".
  CT_REQUIRE(observations.add(scalar_observation("obs.flow", cfm::ObservationChannel::FlowMeter, 45000, "mL/s",
                                                kClock - 1000)).has_value());
  CT_REQUIRE(observations.add(scalar_observation("obs.dp", cfm::ObservationChannel::DifferentialPressure, 80000,
                                                "Pa-dp", kClock - 1000)).has_value());
  CT_REQUIRE(observations.add(scalar_observation("obs.capacity", cfm::ObservationChannel::ThermalCapacityMeter,
                                                2400000, "W", kClock - 1000)).has_value());
  CT_REQUIRE(observations.add(leak_observation("obs.leak", cfm::LeakState::LeakUnknown, kClock - 1000))
                 .has_value());

  cfm::DecisionPolicy policy = policy_with_window();
  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy;
  input.clock = cfm::DecisionClock(kClock);
  input.recovery_requests = {kLoop};
  input.stable_since = {{kLoop, cfm::DecisionClock(kClock - 1000000)}};
  const cfm::CoolingFailureState state = must_evaluate(input);
  CT_REQUIRE(state.decisions.size() == 1);
  const cfm::ScopeDecision& decision = state.decisions.front();
  CT_CHECK(!contains(decision.confirmed_classes, cfm::FailureClass::Leak));
  // An unknown leak state is not a cleared leak, so the recovery is not permitted.
  CT_CHECK_EQ(static_cast<int>(decision.recovery), static_cast<int>(cfm::RecoveryDecision::Blocked));
}

CT_TEST(it_recovery_is_deferred_until_the_dwell_elapses) {
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar_observation("obs.flow", cfm::ObservationChannel::FlowMeter, 45000, "mL/s",
                                                kClock - 1000)).has_value());
  CT_REQUIRE(observations.add(scalar_observation("obs.dp", cfm::ObservationChannel::DifferentialPressure, 80000,
                                                "Pa-dp", kClock - 1000)).has_value());
  CT_REQUIRE(observations.add(scalar_observation("obs.capacity", cfm::ObservationChannel::ThermalCapacityMeter,
                                                2400000, "W", kClock - 1000)).has_value());
  CT_REQUIRE(observations.add(leak_observation("obs.leak", cfm::LeakState::LeakNone, kClock - 1000)).has_value());
  CT_REQUIRE(observations.add(scalar_observation("obs.temp", cfm::ObservationChannel::CoolantTemperature, 20000,
                                                "mC", kClock - 1000)).has_value());
  CT_REQUIRE(observations.add(scalar_observation("obs.containment", cfm::ObservationChannel::ContainmentSwitch, 0,
                                                std::string_view(), kClock - 1000)).has_value());
  CT_REQUIRE(observations.add(scalar_observation("obs.margin", cfm::ObservationChannel::ThermalMarginMeter, 3000,
                                                "mK", kClock - 1000)).has_value());

  cfm::DecisionPolicy policy = policy_with_window();
  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy;
  input.clock = cfm::DecisionClock(kClock);
  input.recovery_requests = {kLoop};

  // The stable interval started one second ago; the policy demands five minutes
  // plus two minutes of hysteresis, so nothing has held long enough yet.
  input.stable_since = {{kLoop, cfm::DecisionClock(kClock - 1000)}};
  const cfm::CoolingFailureState early = must_evaluate(input);
  CT_REQUIRE(early.decisions.size() == 1);
  CT_CHECK_EQ(static_cast<int>(early.decisions.front().recovery),
              static_cast<int>(cfm::RecoveryDecision::Deferred));

  // The same evidence, held long enough. The scope policy demands five minutes of
  // dwell plus two minutes of hysteresis, so the interval must be older than both.
  input.stable_since = {{kLoop, cfm::DecisionClock(kClock - (300000 + 120000 + 1))}};
  const cfm::Result<cfm::DecisionOutcome> settled_result = cfm::evaluate(input);
  if (!settled_result.has_value()) {
    ::ct_test::report_note("settled evaluation refused: " + settled_result.error().to_string());
  }
  CT_REQUIRE(settled_result.has_value());
  const cfm::CoolingFailureState settled = settled_result.value().state;
  CT_REQUIRE(settled.decisions.size() == 1);
  CT_CHECK_EQ(static_cast<int>(settled.decisions.front().recovery),
              static_cast<int>(cfm::RecoveryDecision::Permitted));
}

CT_TEST(it_recovery_is_never_inferred_from_elapsed_time_alone) {
  // The stable interval has elapsed, but the evidence is stale. Time passing is
  // not evidence, so the recovery stays blocked.
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar_observation("obs.flow", cfm::ObservationChannel::FlowMeter, 45000, "mL/s",
                                                kClock - kWindow - 10000)).has_value());
  cfm::DecisionPolicy policy = policy_with_window();
  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy;
  input.clock = cfm::DecisionClock(kClock);
  input.recovery_requests = {kLoop};
  input.stable_since = {{kLoop, cfm::DecisionClock(kClock - 1000000)}};
  const cfm::CoolingFailureState state = must_evaluate(input);
  CT_REQUIRE(state.decisions.size() == 1);
  CT_CHECK_EQ(static_cast<int>(state.decisions.front().recovery),
              static_cast<int>(cfm::RecoveryDecision::Blocked));
}

// ===========================================================================
// Shared source attribution
// ===========================================================================

CT_TEST(it_only_a_total_loss_is_attributed_downstream) {
  cfm::CoolingScope plant;
  plant.id = kPlant;
  plant.kind = cfm::ScopeKind::Plant;
  plant.policy.envelope.declared_demand = *cfm::DeclaredQuantity::make(4000000, "W");
  plant.policy.requirements = {
      {cfm::ObservationChannel::ChillerStatus, cfm::DurationMilliseconds(kWindow)},
      {cfm::ObservationChannel::ThermalCapacityMeter, cfm::DurationMilliseconds(kWindow)}};

  cfm::CoolingScope loop = make_loop();
  loop.dependencies.push_back(
      cfm::ScopeDependency{kPlant, cfm::DependencyKind::SuppliesCoolant, 1000000});

  cfm::CoolingFailureState skeleton;
  skeleton.evaluated_at = cfm::DecisionClock(kClock);
  skeleton.scopes = {plant, loop};

  cfm::DecisionPolicy policy = policy_with_window();
  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.policy = policy;
  input.clock = cfm::DecisionClock(kClock);

  // Case A: one chiller unit degraded. That is a degradation, not a loss.
  cfm::ObservationSet degraded;
  cfm::Observation chiller;
  chiller.id = *cfm::ObservationId::parse("obs.chiller");
  chiller.scope = kPlant;
  chiller.channel = cfm::ObservationChannel::ChillerStatus;
  chiller.quantity = *cfm::Quantity::observed(1, std::string_view(), cfm::ObservationQuality::Good,
                                             cfm::ObservationSequence(1));
  chiller.observed_at = cfm::DecisionClock(kClock - 1000);
  chiller.recorded_at = cfm::DecisionClock(kClock - 1000);
  chiller.producer = "bms";
  chiller.evidence_generation = cfm::EvidenceGeneration(1);
  CT_REQUIRE(degraded.add(chiller).has_value());
  input.observations = &degraded;
  const cfm::CoolingFailureState first = must_evaluate(input);
  const cfm::ScopeDecision* loop_decision = cfm::find_decision(first, kLoop);
  CT_REQUIRE(loop_decision != nullptr);
  CT_CHECK(!contains(loop_decision->confirmed_classes, cfm::FailureClass::SharedSourceFailure));

  // Case B: the plant is confirmed lost. A wholly dependent loop inherits it.
  cfm::ObservationSet lost;
  cfm::Observation failed = chiller;
  failed.quantity = *cfm::Quantity::observed(2, std::string_view(), cfm::ObservationQuality::Good,
                                            cfm::ObservationSequence(2));
  CT_REQUIRE(lost.add(failed).has_value());
  input.observations = &lost;
  const cfm::CoolingFailureState second = must_evaluate(input);
  const cfm::ScopeDecision* second_loop = cfm::find_decision(second, kLoop);
  CT_REQUIRE(second_loop != nullptr);
  CT_CHECK(contains(second_loop->confirmed_classes, cfm::FailureClass::SharedSourceFailure));
  CT_REQUIRE(!second_loop->shared_sources.empty());
  CT_CHECK(second_loop->shared_sources.front() == kPlant);
}

// ===========================================================================
// Authority binding
// ===========================================================================

CT_TEST(it_a_stale_binding_forbids_recovery_but_not_escalation) {
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar_observation("obs.dead", cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                                kClock - 1000)).has_value());

  cfm::DecisionPolicy policy = policy_with_window();
  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy;
  input.clock = cfm::DecisionClock(kClock);
  input.bindings.set("cooling-topology", *cfm::AuthorityRef::make("cooling-topology", "site.a",
                                                                 cfm::ExternalGeneration(4)));
  // The owner has moved on to generation 5.
  input.observed_bindings.current.set(
      "cooling-topology", *cfm::AuthorityRef::make("cooling-topology", "site.a", cfm::ExternalGeneration(5)));

  const cfm::CoolingFailureState state = must_evaluate(input);
  CT_REQUIRE(state.decisions.size() == 1);
  CT_CHECK_EQ(static_cast<int>(state.decisions.front().binding_status),
              static_cast<int>(cfm::BindingStatus::Stale));

  const cfm::BindingAssessment assessment =
      cfm::assess_bindings(input.bindings, input.observed_bindings);
  CT_CHECK(!cfm::binding_assessment_allows_recovery(assessment));
  // The escalation itself is still justified: a stale binding does not make dead
  // coolant safe.
  CT_CHECK(contains(state.decisions.front().confirmed_classes, cfm::FailureClass::LoopLoss));
  CT_REQUIRE(!state.decisions.front().restrictions.empty());
}

CT_TEST(it_a_missing_binding_is_unbound_rather_than_current) {
  const cfm::AuthoritySet published = [] {
    cfm::AuthoritySet set;
    (void)set.set("cooling-topology",
                  *cfm::AuthorityRef::make("cooling-topology", "site.a", cfm::ExternalGeneration(1)));
    return set;
  }();
  cfm::BindingObservation nothing;
  const cfm::BindingAssessment assessment = cfm::assess_bindings(published, nothing);
  CT_CHECK_EQ(static_cast<int>(assessment.status), static_cast<int>(cfm::BindingStatus::Unbound));
  CT_CHECK(!cfm::binding_assessment_allows_recovery(assessment));
  CT_REQUIRE(assessment.findings.size() == 1);
  CT_CHECK_EQ(static_cast<int>(assessment.findings.front().status),
              static_cast<int>(cfm::BindingStatus::Unbound));
}

// ===========================================================================
// The store: crash recovery, replay and unresolved attempts
// ===========================================================================

namespace {

/// A store directory inside the test binary's working directory. It is removed
/// first so a previous run cannot make a case pass or fail, and each case uses its
/// own name so no two cases can disturb one another.
std::string fresh_store_root(std::string_view name) {
  // The store root is an absolute path because a relative root would name a
  // different store in every process that used it. It lives beside the test
  // executable rather than in the working directory, so a run leaves the checkout
  // untouched; the case removes it first so a previous run cannot affect it.
  static const std::filesystem::path base = [] {
    const std::filesystem::path beside =
        std::filesystem::path(ct_test::current_executable_path()).parent_path() / "it-stores";
    std::error_code ignored;
    std::filesystem::create_directories(beside, ignored);
    return beside;
  }();
  const std::string root = (base / std::string(name)).string();
  std::error_code ignored;
  std::filesystem::remove_all(root, ignored);
  return root;
}

cfm::Result<cfm::Store> open_store(const std::string& root, cfm::StoreMode mode) {
  cfm::StoreOptions options;
  options.root = root;
  options.mode = mode;
  return cfm::Store::open(options);
}

cfm::Result<cfm::Store> create_store(const std::string& root) {
  // The caller owns the decision to create a directory; the store owns everything
  // inside it.
  std::error_code ignored;
  std::filesystem::create_directories(root, ignored);
  cfm::StoreOptions options;
  options.root = root;
  cfm::Result<cfm::StoreId> id = cfm::StoreId::parse("it.store");
  if (!id.has_value()) {
    return id.error();
  }
  return cfm::Store::create(options, id.value());
}

cfm::PublicationRequest request_for(const cfm::CoolingFailureState& body, std::string_view mutation,
                                   std::uint32_t ordinal = 1) {
  cfm::PublicationRequest request;
  request.mutation = *cfm::MutationId::parse(mutation);
  request.attempt = *cfm::AttemptOrdinal::parse(ordinal);
  request.body = body;
  return request;
}

}  // namespace

CT_TEST(it_store_rejects_a_second_writer_without_racing) {
  const std::string root = fresh_store_root("single-writer");
  cfm::Result<cfm::Store> first = create_store(root);
  CT_REQUIRE(first.has_value());
  const cfm::Result<cfm::Store> second = open_store(root, cfm::StoreMode::ReadWrite);
  CT_CHECK(!second.has_value());
  if (!second.has_value()) {
    CT_CHECK(second.error().code() == cfm::ErrorCode::StoreLocked);
  }
  // A read-only handle is not a writer and must still be admitted.
  const cfm::Result<cfm::Store> reader = open_store(root, cfm::StoreMode::ReadOnly);
  CT_CHECK(reader.has_value());
  CT_REQUIRE(first->close().has_value());
}

CT_TEST(it_replay_is_resolved_before_the_stale_fence) {
  const std::string root = fresh_store_root("replay");
  cfm::Result<cfm::Store> store = create_store(root);
  CT_REQUIRE(store.has_value());

  cfm::CoolingFailureState body;
  body.evaluated_at = cfm::DecisionClock(1);
  cfm::PublicationRequest request = request_for(body, "it.replay.1");
  request.epoch = store->epoch();
  request.incarnation = store->incarnation();
  cfm::Result<cfm::PublicationReceipt> first = store->publish(request);
  CT_REQUIRE(first.has_value());
  CT_CHECK(!first->replayed);
  CT_CHECK_EQ(first->generation.value(), static_cast<std::uint64_t>(1));

  // The same attempt, planned under an epoch that is no longer current. It is the
  // same already-committed operation, so the replay is resolved first and the
  // fence is never reached.
  cfm::PublicationRequest stale = request;
  stale.epoch = cfm::WriterEpoch(9999);
  stale.incarnation = cfm::WriterIncarnation(9999);
  const cfm::Result<cfm::PublicationReceipt> replay = store->publish(stale);
  CT_REQUIRE(replay.has_value());
  CT_CHECK(replay->replayed);
  CT_CHECK_EQ(replay->generation.value(), first->generation.value());
  CT_CHECK(replay->digest == first->digest);

  // A different content under the same identity is a conflict, not a replay.
  cfm::CoolingFailureState other;
  other.evaluated_at = cfm::DecisionClock(2);
  cfm::PublicationRequest conflicting = request_for(other, "it.replay.1");
  conflicting.epoch = store->epoch();
  conflicting.incarnation = store->incarnation();
  const cfm::Result<cfm::PublicationReceipt> conflict = store->publish(conflicting);
  CT_CHECK(!conflict.has_value());
  if (!conflict.has_value()) {
    CT_CHECK(conflict.error().code() == cfm::ErrorCode::IdempotencyConflict);
  }

  // A stale base generation with new content is still fenced.
  cfm::PublicationRequest fenced = request_for(other, "it.replay.2");
  fenced.epoch = store->epoch();
  fenced.incarnation = store->incarnation();
  fenced.base_generation = cfm::StateGeneration(50);
  const cfm::Result<cfm::PublicationReceipt> refused = store->publish(fenced);
  CT_CHECK(!refused.has_value());
  if (!refused.has_value()) {
    CT_CHECK(refused.error().code() == cfm::ErrorCode::StaleBaseGeneration);
  }
  CT_REQUIRE(store->close().has_value());
}

CT_TEST(it_an_unresolved_attempt_blocks_a_fresh_publication) {
  // Build a state that carries an attempt which was solicited and never answered.
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar_observation("obs.dead", cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                                kClock - 1000)).has_value());
  cfm::DecisionPolicy policy = policy_with_window();
  cfm::DecisionInput first_input;
  first_input.prior = &skeleton;
  first_input.observations = &observations;
  first_input.policy = policy;
  first_input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState first = must_evaluate(first_input);

  cfm::DecisionInput::SolicitationRequest solicitation;
  solicitation.scope = kLoop;
  solicitation.solicitation = *cfm::MutationId::parse("sol.it.unresolved");
  solicitation.attempt = *cfm::AttemptOrdinal::parse(1);
  solicitation.action = cfm::ResponseAction::StartStandbyPump;
  solicitation.addressee = "liquid-cooling-control";
  cfm::DecisionInput second_input;
  second_input.prior = &first;
  second_input.observations = &observations;
  second_input.policy = policy;
  second_input.clock = cfm::DecisionClock(kClock + 1000);
  second_input.solicitations = {solicitation};
  const cfm::CoolingFailureState solicited = must_evaluate(second_input);
  // The attempt is in flight: solicited and unanswered. Nothing has adopted it as
  // unresolved yet, because the authority that solicited it is still the live one.
  // The store is where an in-flight attempt blocks a blind redispatch, so the
  // assertion belongs there rather than on the decision.
  CT_CHECK(solicited.unresolved_attempts.empty());
  const cfm::ResponsePlan* in_flight_plan = cfm::find_plan_for_scope(solicited, kLoop);
  CT_REQUIRE(in_flight_plan != nullptr);
  CT_REQUIRE(in_flight_plan->attempts.size() == 1);
  CT_CHECK_EQ(static_cast<int>(in_flight_plan->attempts.front().state),
              static_cast<int>(cfm::AttemptState::Solicited));

  const std::string root = fresh_store_root("unresolved");
  cfm::Result<cfm::Store> store = create_store(root);
  CT_REQUIRE(store.has_value());
  cfm::PublicationRequest publish = request_for(solicited, "it.unresolved.1");
  publish.epoch = store->epoch();
  publish.incarnation = store->incarnation();
  CT_REQUIRE(store->publish(publish).has_value());

  // A fresh publication that does not resolve the attempt is refused: the lost
  // response must not become a second consequential action.
  cfm::PublicationRequest blind = request_for(solicited, "it.unresolved.2");
  blind.epoch = store->epoch();
  blind.incarnation = store->incarnation();
  const cfm::Result<cfm::PublicationReceipt> refused = store->publish(blind);
  CT_CHECK(!refused.has_value());
  if (!refused.has_value()) {
    CT_CHECK(refused.error().code() == cfm::ErrorCode::AttemptOutstanding);
  }

  // The explicit reconciliation is the way through, and it records that the
  // outcome is unknown rather than guessing one.
  cfm::AuthoritySet authority;
  const cfm::Result<std::size_t> reconciled = store->reconcile_unresolved(
      authority, *cfm::MutationId::parse("it.reconcile"), *cfm::AttemptOrdinal::parse(1));
  CT_REQUIRE(reconciled.has_value());
  CT_CHECK_EQ(*reconciled, static_cast<std::size_t>(1));
  cfm::Result<cfm::CoolingFailureState> head = store->head();
  CT_REQUIRE(head.has_value());
  CT_REQUIRE(head->unresolved_attempts.size() == 1);
  const cfm::ResponsePlan* plan = cfm::find_plan_for_scope(head.value(), kLoop);
  CT_REQUIRE(plan != nullptr);
  CT_REQUIRE(!plan->attempts.empty());
  CT_CHECK_EQ(static_cast<int>(plan->attempts.front().state),
              static_cast<int>(cfm::AttemptState::Unresolved));
  CT_CHECK(plan->attempts.front().adopted_after_restart);
  CT_REQUIRE(store->close().has_value());
}

CT_TEST(it_a_decision_survives_close_and_reopen_with_its_digest) {
  const cfm::CoolingScope scope = make_loop();
  const cfm::CoolingFailureState skeleton = skeleton_with(scope);
  cfm::ObservationSet observations;
  CT_REQUIRE(observations.add(scalar_observation("obs.dead", cfm::ObservationChannel::FlowMeter, 0, "mL/s",
                                                kClock - 1000)).has_value());
  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy_with_window();
  input.clock = cfm::DecisionClock(kClock);
  const cfm::CoolingFailureState state = must_evaluate(input);
  const cfm::Digest digest = cfm::state_digest(state);

  const std::string root = fresh_store_root("reopen");
  cfm::Result<cfm::Store> store = create_store(root);
  CT_REQUIRE(store.has_value());
  const cfm::WriterEpoch epoch = store->epoch();
  const cfm::WriterIncarnation incarnation = store->incarnation();
  cfm::PublicationRequest publish = request_for(state, "it.reopen.1");
  publish.epoch = epoch;
  publish.incarnation = incarnation;
  cfm::Result<cfm::PublicationReceipt> publish_receipt = store->publish(publish);
  CT_REQUIRE(publish_receipt.has_value());
  CT_REQUIRE(store->close().has_value());

  cfm::Result<cfm::Store> reopened = open_store(root, cfm::StoreMode::ReadWrite);
  CT_REQUIRE(reopened.has_value());
  // A successor does not inherit the predecessor's authority.
  CT_CHECK(reopened->epoch().value() > epoch.value());
  CT_CHECK(reopened->incarnation().value() > incarnation.value());
  cfm::Result<cfm::CoolingFailureState> head = reopened->head();
  CT_REQUIRE(head.has_value());
  // The store assigns the generation it published, so the authoritative digest is
  // the digest of the state OF RECORD: the body with the store's generation, which
  // the receipt names. Comparing the pre-publication digest of the caller's body
  // would be comparing a different state.
  CT_CHECK(cfm::state_digest(head.value()) == publish_receipt->digest);
  CT_CHECK_EQ(head->generation.value(), static_cast<std::uint64_t>(1));
  // Everything the caller published is still there, byte for byte, once the
  // store-assigned generation is put back.
  cfm::CoolingFailureState expected = state;
  expected.generation = head->generation;
  expected.parent_generation = head->parent_generation;
  CT_CHECK(cfm::encode_state(head.value()) == cfm::encode_state(expected));
  (void)digest;
  cfm::Result<cfm::VerifyReport> report = reopened->verify(cfm::VerifyOptions{});
  CT_REQUIRE(report.has_value());
  CT_CHECK(report->ok());
  CT_REQUIRE(reopened->close().has_value());
}

// ===========================================================================
// Boundaries and structural validation
// ===========================================================================

CT_TEST(it_a_structure_that_names_a_missing_scope_is_refused) {
  cfm::CoolingFailureState state;
  cfm::CoolingFailure failure;
  failure.id = *cfm::FailureId::parse("fl.orphan");
  failure.scope = *cfm::ScopeId::parse("scope.absent");
  failure.failure_class = cfm::FailureClass::LoopLoss;
  failure.confirmation = cfm::ConfirmationState::Confirmed;
  failure.severity = cfm::Severity::Total;
  failure.rationale = "recorded by hand";
  state.failures.push_back(failure);
  const cfm::Result<void> validated = cfm::validate_structure(state);
  CT_CHECK(!validated.has_value());
  if (!validated.has_value()) {
    CT_CHECK(validated.error().code() == cfm::ErrorCode::ScopeNotFound);
  }
}

CT_TEST(it_a_verified_attempt_without_an_effect_observation_is_refused) {
  cfm::CoolingFailureState state;
  state.scopes.push_back(make_loop());
  cfm::ResponsePlan plan;
  plan.id = *cfm::PlanId::parse("plan.it");
  plan.scope = kLoop;
  plan.lifecycle = cfm::PlanLifecycle::Active;
  cfm::ResponseAttempt attempt;
  attempt.id = *cfm::AttemptId::parse("at.it");
  attempt.solicitation = *cfm::MutationId::parse("sol.it.structural");
  attempt.attempt = *cfm::AttemptOrdinal::parse(1);
  attempt.action = cfm::ResponseAction::StartStandbyPump;
  attempt.state = cfm::AttemptState::Verified;
  attempt.addressee = "liquid-cooling-control";
  attempt.acknowledged_at = cfm::DecisionClock(1);
  plan.attempts.push_back(attempt);
  state.plans.push_back(plan);

  const cfm::Result<void> validated = cfm::validate_structure(state);
  CT_CHECK(!validated.has_value());
  if (!validated.has_value()) {
    ::ct_test::report_note("structural refusal: " + validated.error().to_string());
    CT_CHECK(validated.error().code() == cfm::ErrorCode::EffectClaimedWithoutEvidence);
  }
}

CT_TEST(it_limits_are_enforced_on_the_observation_set) {
  cfm::ObservationSet set;
  const cfm::Observation observation = scalar_observation("obs.duplicate", cfm::ObservationChannel::FlowMeter,
                                                        1000, "mL/s", kClock - 1000);
  CT_REQUIRE(set.add(observation).has_value());
  const cfm::Result<void> duplicate = set.add(observation);
  CT_CHECK(!duplicate.has_value());
  if (!duplicate.has_value()) {
    CT_CHECK(duplicate.error().code() == cfm::ErrorCode::DuplicateIdentifier);
  }

  // A batch that contains a duplicate changes nothing at all.
  std::vector<cfm::Observation> batch = {
      scalar_observation("obs.batch.1", cfm::ObservationChannel::FlowMeter, 1000, "mL/s", kClock - 1000),
      scalar_observation("obs.batch.1", cfm::ObservationChannel::FlowMeter, 2000, "mL/s", kClock - 1000)};
  const std::size_t before = set.size();
  const cfm::Result<void> refused = set.add_all(batch);
  CT_CHECK(!refused.has_value());
  CT_CHECK_EQ(set.size(), before);
}
