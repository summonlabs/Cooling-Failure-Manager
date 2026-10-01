// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// CDU leak: isolation first, recovery only on proven leak clearance.
//
// A coolant distribution unit reports a breach. The example follows the response
// from the first observation to a permitted recovery, and shows the four facts
// this component keeps apart: what was eligible, what was solicited, what was
// acknowledged, and what was actually verified.
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
  const cfm::ScopeId cdu = must_scope("cdu.a");

  cfm::CoolingScope scope;
  scope.id = cdu;
  scope.kind = cfm::ScopeKind::Cdu;
  scope.display_name = "CDU A";
  scope.policy.envelope.min_flow = must_quantity(20000, "mL/s");
  scope.policy.envelope.min_differential_pressure = must_quantity(50000, "Pa-dp");
  scope.policy.envelope.declared_demand = must_quantity(1500000, "W");
  scope.policy.requirements = {
      cfm::EvidenceRequirement{cfm::ObservationChannel::CduStatus, cfm::DurationMilliseconds(30000)},
      cfm::EvidenceRequirement{cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(30000)},
      cfm::EvidenceRequirement{cfm::ObservationChannel::LeakDetector, cfm::DurationMilliseconds(30000)},
      cfm::EvidenceRequirement{cfm::ObservationChannel::ThermalCapacityMeter, cfm::DurationMilliseconds(30000)},
  };
  scope.policy.recovery_dwell = cfm::DurationMilliseconds(600000);
  scope.policy.recovery_hysteresis = cfm::DurationMilliseconds(300000);

  cfm::CoolingFailureState skeleton;
  skeleton.evaluated_at = cfm::DecisionClock(100000);
  skeleton.scopes = {scope};

  cfm::DecisionPolicy policy;
  policy.evidence_window = cfm::DurationMilliseconds(30000);
  policy.safety_escalation_severity = cfm::Severity::Critical;

  // --- phase 1: the breach is observed ------------------------------------
  cfm::ObservationSet breached;
  record_status(breached, "obs.cdu-status.1", cdu, cfm::ObservationChannel::CduStatus, 2, 99000, "cdu-agent");
  record(breached, "obs.flow.1", cdu, cfm::ObservationChannel::FlowMeter, 4000, "mL/s", 99000, "cdu-flow");
  record_leak(breached, "obs.leak.1", cdu, cfm::LeakState::LeakActive, 99000, "cdu-leak");
  record(breached, "obs.capacity.1", cdu, cfm::ObservationChannel::ThermalCapacityMeter, 200000, "W", 99000,
         "cdu-capacity");

  cfm::DecisionInput phase_one;
  phase_one.prior = &skeleton;
  phase_one.observations = &breached;
  phase_one.policy = policy;
  phase_one.clock = cfm::DecisionClock(100000);

  cfm::Result<cfm::DecisionOutcome> first = cfm::evaluate(phase_one);
  check(first.has_value(), "the first evaluation succeeded");
  if (!first.has_value()) {
    std::printf("error: %s\n", first.error().to_string().c_str());
    return 1;
  }
  const cfm::ScopeDecision* decision = cfm::find_decision(first->state, cdu);
  check(decision != nullptr, "the CDU has a decision");
  if (decision == nullptr) {
    return 1;
  }
  check(std::find(decision->confirmed_classes.begin(), decision->confirmed_classes.end(),
                  cfm::FailureClass::Leak) != decision->confirmed_classes.end(),
        "an active leak is a confirmed leak");
  check(decision->severity == cfm::Severity::Critical, "an active leak is critical");
  note("phase 1 classes: confirmed=" + std::to_string(decision->confirmed_classes.size()) +
       " recovery=" + std::string(cfm::to_token(decision->recovery)));

  const cfm::ResponsePlan* plan = cfm::find_plan_for_scope(first->state, cdu);
  check(plan != nullptr, "the CDU has a plan");
  if (plan == nullptr) {
    return 1;
  }
  bool isolate_eligible = false;
  bool safety_critical = false;
  for (const cfm::ResponseEligibility& eligibility : plan->eligible) {
    if (eligibility.action == cfm::ResponseAction::IsolateScope) {
      isolate_eligible = true;
      safety_critical = eligibility.safety_critical;
    }
    note("eligible " + std::string(cfm::to_token(eligibility.action)) + " rank=" +
         std::to_string(eligibility.rank) + " rule=" + eligibility.rule_id);
  }
  check(isolate_eligible, "isolation is eligible for a confirmed leak");
  check(safety_critical, "isolation is a safety escalation, so it may be requested immediately");
  check(!plan->restrictions.empty(), "a confirmed leak forces protective restrictions");

  // --- phase 2: isolation is solicited and acknowledged -------------------
  cfm::DecisionInput phase_two = phase_one;
  phase_two.prior = &first->state;
  phase_two.clock = cfm::DecisionClock(101000);
  cfm::DecisionInput::SolicitationRequest solicitation;
  solicitation.scope = cdu;
  solicitation.solicitation = *cfm::MutationId::parse("sol.isolate.cdu-a");
  solicitation.attempt = *cfm::AttemptOrdinal::parse(1);
  solicitation.action = cfm::ResponseAction::IsolateScope;
  solicitation.addressee = "liquid-cooling-control";
  phase_two.solicitations = {solicitation};

  cfm::Result<cfm::DecisionOutcome> second = cfm::evaluate(phase_two);
  check(second.has_value(), "the solicitation evaluation succeeded");
  if (!second.has_value()) {
    std::printf("error: %s\n", second.error().to_string().c_str());
    return 1;
  }
  const cfm::ResponsePlan* solicited = cfm::find_plan_for_scope(second->state, cdu);
  check(solicited != nullptr && solicited->attempts.size() == 1, "one attempt was created");
  const cfm::AttemptId attempt_id = solicited != nullptr && !solicited->attempts.empty()
                                        ? solicited->attempts.front().id
                                        : cfm::AttemptId();
  if (solicited != nullptr && !solicited->attempts.empty()) {
    check(solicited->attempts.front().state == cfm::AttemptState::Solicited,
          "a fresh solicitation is Solicited, not Acknowledged");
  }

  // An acknowledgement is recorded, and is still not an effect.
  cfm::DecisionInput phase_three = phase_two;
  phase_three.prior = &second->state;
  phase_three.clock = cfm::DecisionClock(102000);
  cfm::DecisionInput::AttemptReport acknowledgement;
  acknowledgement.attempt = attempt_id;
  acknowledgement.state = cfm::AttemptState::Acknowledged;
  acknowledgement.at = cfm::DecisionClock(102000);
  phase_three.attempt_reports = {acknowledgement};
  cfm::Result<cfm::DecisionOutcome> third = cfm::evaluate(phase_three);
  check(third.has_value(), "the acknowledgement evaluation succeeded");
  if (third.has_value()) {
    const cfm::ResponsePlan* acked = cfm::find_plan_for_scope(third->state, cdu);
    if (acked != nullptr && !acked->attempts.empty()) {
      check(acked->attempts.front().state == cfm::AttemptState::Acknowledged,
            "the acknowledgement is recorded as an acknowledgement");
      check(acked->attempts.front().effect_observation.empty(),
            "an acknowledgement names no effect observation");
    }
  }

  // --- phase 4: the effect is observed, then verified ---------------------
  cfm::ObservationSet recovered = breached;
  record_leak(recovered, "obs.leak.2", cdu, cfm::LeakState::LeakNone, 300000, "cdu-leak");
  record(  // the flow reading is replaced by a later one on the same channel
      recovered, "obs.flow.2", cdu, cfm::ObservationChannel::FlowMeter, 24000, "mL/s", 300000, "cdu-flow");
  record_status(recovered, "obs.cdu-status.2", cdu, cfm::ObservationChannel::CduStatus, 0, 300000, "cdu-agent");
  record(recovered, "obs.capacity.2", cdu, cfm::ObservationChannel::ThermalCapacityMeter, 1600000, "W", 300000,
         "cdu-capacity");

  cfm::DecisionInput phase_four = phase_three;
  // The prior state is held in a named local so the pointer cannot outlive the
  // Result that owns it.
  const cfm::CoolingFailureState& prior_three = third.has_value() ? third->state : second->state;
  phase_four.prior = &prior_three;
  phase_four.observations = &recovered;
  phase_four.clock = cfm::DecisionClock(301000);
  cfm::DecisionInput::AttemptReport observed;
  observed.attempt = attempt_id;
  observed.state = cfm::AttemptState::EffectObserved;
  observed.at = cfm::DecisionClock(301000);
  observed.effect_observation = must_observation("obs.flow.2");
  phase_four.attempt_reports = {observed};
  cfm::Result<cfm::DecisionOutcome> fourth = cfm::evaluate(phase_four);
  check(fourth.has_value(), "the effect-observed evaluation succeeded");
  if (!fourth.has_value()) {
    std::printf("error: %s\n", fourth.error().to_string().c_str());
    return 1;
  }

  cfm::DecisionInput phase_five = phase_four;
  const cfm::CoolingFailureState& prior_four = fourth->state;
  phase_five.prior = &prior_four;
  phase_five.clock = cfm::DecisionClock(302000);
  cfm::DecisionInput::AttemptReport verified;
  verified.attempt = attempt_id;
  verified.state = cfm::AttemptState::Verified;
  verified.at = cfm::DecisionClock(302000);
  verified.effect_observation = must_observation("obs.flow.2");
  verified.verdict = "flow recovered above the declared floor on the CDU flow meter";
  phase_five.attempt_reports = {verified};
  cfm::Result<cfm::DecisionOutcome> fifth = cfm::evaluate(phase_five);
  check(fifth.has_value(), "the verified evaluation succeeded");
  if (!fifth.has_value()) {
    std::printf("error: %s\n", fifth.error().to_string().c_str());
    return 1;
  }

  // --- phase 6: a recovery is requested ----------------------------------
  cfm::DecisionInput phase_six = phase_five;
  const cfm::CoolingFailureState& prior_five = fifth->state;
  phase_six.prior = &prior_five;
  phase_six.clock = cfm::DecisionClock(303000);
  phase_six.recovery_requests = {cdu};
  phase_six.stable_since = {{cdu, cfm::DecisionClock(302000)}};
  cfm::Result<cfm::DecisionOutcome> sixth = cfm::evaluate(phase_six);
  check(sixth.has_value(), "the recovery evaluation succeeded");
  if (!sixth.has_value()) {
    std::printf("error: %s\n", sixth.error().to_string().c_str());
    return 1;
  }
  const cfm::ScopeDecision* recovery = cfm::find_decision(sixth->state, cdu);
  check(recovery != nullptr, "the CDU still has a decision");
  if (recovery != nullptr) {
    note("phase 6 recovery=" + std::string(cfm::to_token(recovery->recovery)));
    check(recovery->recovery == cfm::RecoveryDecision::Blocked,
          "a recovery requested one second after the readings returned is blocked");
    check(!recovery->confirmed_classes.empty(),
          "the class is not cleared merely because the readings look healthy again");
  }

  note("");
  note("The point of the sequence is the gap between the phases: an acknowledgement moved the");
  note("plan forward by exactly one step, and only a verified effect plus a cleared class plus");
  note("a completed dwell can permit a recovery.");

  if (failures == 0) {
    std::printf("example cdu_leak_response ok\n");
    return 0;
  }
  std::printf("example cdu_leak_response FAILED: %d check(s)\n", failures);
  return 1;
}
