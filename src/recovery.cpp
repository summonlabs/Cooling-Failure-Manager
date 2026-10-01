// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The recovery gate engine.
//
// A recovery is the one transition in this component that gives capability back,
// so it is the one transition that demands positive evidence rather than the
// absence of a signal. Every gate below is a named proof obligation evaluated
// against observations that are current at the decision clock; nothing here is
// inferred from elapsed time, from an acknowledgement, from a threshold crossing
// that has not been observed, or from temperature alone.
//
// The three outcomes are deliberately distinct and never collapsed:
//   * Permitted - every gate passed on current evidence;
//   * Deferred  - every gate that can be checked now passed, but a dwell or
//                 hysteresis interval is still running, and the assessment says
//                 how long is left;
//   * Blocked   - at least one gate failed, and the assessment names it.
//
// Deferred is not a soft Blocked and Blocked is not a pending Deferred: an
// operator reading the assessment learns either "wait" or "the evidence is
// wrong", and never has to guess which.

#include "dccp/cooling_failure_manager/recovery.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "dccp/cooling_failure_manager/classify.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

namespace dccp::cooling_failure_manager {

// ===========================================================================
// Small checked helpers
// ===========================================================================

namespace {

/// Checked addition of two bounded durations. Both operands are already bounded
/// by limits::kMaxWindowMilliseconds, so the sum of two of them can only overflow
/// a signed 64-bit integer if an operand escaped validation; the check exists so
/// that an escaped value is refused rather than wrapped into a negative window.
std::int64_t checked_add(std::int64_t lhs, std::int64_t rhs) {
  if (lhs < 0 || rhs < 0) {
    return limits::kMaxWindowMilliseconds;
  }
  if (lhs > limits::kMaxWindowMilliseconds - rhs) {
    return limits::kMaxWindowMilliseconds;
  }
  return lhs + rhs;
}

std::string quote(std::string_view text) { return escape_text(text); }

void sort_channels(std::vector<ObservationChannel>& channels) {
  std::sort(channels.begin(), channels.end(), [](ObservationChannel lhs, ObservationChannel rhs) {
    return channel_index(lhs) < channel_index(rhs);
  });
  channels.erase(std::unique(channels.begin(), channels.end()), channels.end());
}

void add_unique_class(std::vector<FailureClass>& values, FailureClass value) {
  if (std::find(values.begin(), values.end(), value) == values.end()) {
    values.push_back(value);
  }
}

/// The channels a failure class's recovery must see current. It is the union of
/// the class's witness channels: the same channels that evidenced the failure
/// must evidence its clearance, because a class cleared by a channel that never
/// witnessed it would be cleared by something other than evidence.
void required_channels_for_class(std::vector<ObservationChannel>& out, FailureClass failure_class) {
  const FailureRule& rule = failure_rule(failure_class);
  for (std::size_t index = 0; index < rule.witness_count; ++index) {
    out.push_back(rule.witnesses[index].channel);
  }
}

/// The decision-time state of one channel on one scope.
struct ChannelState {
  const Observation* observation = nullptr;
  ObservationUsability usability;
};

ChannelState channel_state(const ScopeId& scope, ObservationChannel channel,
                           const ObservationSet& observations, const DecisionPolicy& policy,
                           const DecisionClock& clock) {
  ChannelState state;
  const bool conflicting = observations.has_conflict(scope, channel);
  state.observation = observations.latest(scope, channel, clock, policy.evidence_window);
  state.usability = assess_observation(state.observation, clock, policy.evidence_window, conflicting);
  return state;
}

/// True when the channel carries a current reading that positively reports the
/// recovered state.
///
/// The direction of every comparison comes from the scope's own declared
/// envelope, never from a constant in this file: a recovered flow must be at or
/// above the floor the scope declared, and a recovered supply temperature must be
/// at or below the ceiling it declared. A channel with no declared bound can
/// never be recovered, because an undeclared threshold is not a satisfied one.
bool channel_recovered(const CoolingScope& scope, ObservationChannel channel,
                       const Observation* observation) {
  if (observation == nullptr) {
    return false;
  }
  const EnvelopeBound bound = envelope_bound_for(scope.policy, channel);
  const std::optional<std::int64_t> value = observation->quantity.value_if_observed();
  switch (channel) {
    case ObservationChannel::LeakDetector:
      // Leak recovery is a positive assertion from the detector, never silence.
      return leak_state_is_clear(observation->leak);
    case ObservationChannel::PumpStatus:
    case ObservationChannel::ValvePosition:
    case ObservationChannel::ChillerStatus:
    case ObservationChannel::CduStatus:
    case ObservationChannel::CrahCracStatus:
    case ObservationChannel::ContainmentSwitch:
      // Status channels report a state code: 0 is normal, 1 is degraded, 2 is
      // failed. A recovered status is exactly the normal code; a degraded unit is
      // not a recovered one.
      return value.has_value() && *value == 0;
    case ObservationChannel::CoolantTemperature:
    case ObservationChannel::AirTemperature:
      return bound.has_ceiling && value.has_value() && *value <= bound.ceiling_value;
    case ObservationChannel::AbsolutePressure:
    case ObservationChannel::DifferentialPressure:
      // Pressure is recovered when it is inside the declared envelope, not merely
      // when it is above a floor: a pressure above the ceiling is a failure too.
      if (!value.has_value() || (!bound.has_floor && !bound.has_ceiling)) {
        return false;
      }
      if (bound.has_floor && *value < bound.floor_value) {
        return false;
      }
      if (bound.has_ceiling && *value > bound.ceiling_value) {
        return false;
      }
      return true;
    case ObservationChannel::FlowMeter:
    case ObservationChannel::AirflowMeter:
    case ObservationChannel::ThermalCapacityMeter:
    case ObservationChannel::ThermalMarginMeter:
      return bound.has_floor && value.has_value() && *value >= bound.floor_value;
    case ObservationChannel::ThermalLoadMeter:
    case ObservationChannel::HumiditySensor:
      // Neither channel is evidence of restored cooling capability on its own:
      // demand is not capacity, and humidity is not a cooling function.
      return false;
  }
  return false;
}

/// The witness inputs a channel presents, so the class-cleared gate can reuse the
/// exactly same predicate that would confirm the class. A class that would still
/// be confirmed cannot be cleared by the same reading.
WitnessInputs cleared_inputs_for(const CoolingScope& scope, const Observation* observation,
                                ObservationChannel channel) {
  WitnessInputs inputs;
  const EnvelopeBound bound = envelope_bound_for(scope.policy, channel);
  inputs.has_floor = bound.has_floor;
  inputs.declared_floor = bound.floor_value;
  inputs.has_ceiling = bound.has_ceiling;
  inputs.declared_ceiling = bound.ceiling_value;
  if (observation == nullptr) {
    return inputs;
  }
  inputs.leak = observation->leak;
  // See decision.cpp: a leak channel carries an assertion, not a scalar, so its
  // usability is the usability of that assertion.
  inputs.usable = channel_is_leak(channel) ? observation->leak != LeakState::LeakUnknown
                                           : observation->quantity.is_usable();
  const std::optional<std::int64_t> value = observation->quantity.value_if_observed();
  if (value.has_value()) {
    inputs.has_value = true;
    inputs.value = *value;
  }
  return inputs;
}

/// True when a gate applies to this scope at all.
///
/// A gate that demands evidence nobody ever demanded for the scope cannot be
/// satisfied, and evaluating it unconditionally would make a recovery impossible
/// for every scope that does not happen to instrument that channel. A gate
/// therefore applies when the recovery demand, the scope's own declared evidence
/// requirements, or one of the classes being cleared names its channel. A gate
/// that does not apply is reported as satisfied with the reason stated, so an
/// operator can see that it was considered and waived rather than forgotten.
bool gate_required(const RecoveryRequirements& requirements, const ScopePolicy& policy,
                   ObservationChannel channel) {
  if (std::find(requirements.required_observations.begin(), requirements.required_observations.end(),
                channel) != requirements.required_observations.end()) {
    return true;
  }
  for (const EvidenceRequirement& requirement : policy.requirements) {
    if (requirement.channel == channel) {
      return true;
    }
  }
  for (FailureClass failure_class : requirements.required_cleared_classes) {
    std::vector<ObservationChannel> witnesses;
    required_channels_for_class(witnesses, failure_class);
    if (std::find(witnesses.begin(), witnesses.end(), channel) != witnesses.end()) {
      return true;
    }
  }
  return false;
}

/// A gate that does not apply to this scope.
RecoveryGateResult not_applicable_gate(RecoveryGate gate, std::string detail) {
  RecoveryGateResult result;
  result.gate = gate;
  result.satisfied = true;
  result.status = EvidenceStatus::Current;
  result.detail = std::move(detail);
  return result;
}

std::string join_lines(const std::vector<std::string>& lines) {
  std::string joined;
  for (std::size_t index = 0; index < lines.size(); ++index) {
    if (index != 0) {
      joined += "\n";
    }
    joined += lines[index];
  }
  return joined;
}

std::string join_tokens(const std::vector<std::string>& values) {
  std::string joined;
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0) {
      joined += ",";
    }
    joined += values[index];
  }
  return joined;
}

/// The plan of one scope in the state being evaluated, when one exists.
const ResponsePlan* plan_of(const CoolingFailureState& state, const ScopeId& scope) {
  for (const ResponsePlan& plan : state.plans) {
    if (plan.scope == scope) {
      return &plan;
    }
  }
  return nullptr;
}

}  // namespace

Result<RecoveryRequirements> recovery_requirements(const CoolingScope& scope,
                                                   const ScopeDecision& decision) {
  RecoveryRequirements requirements;
  requirements.scope = scope.id;
  requirements.dwell = scope.policy.recovery_dwell;
  requirements.hysteresis = scope.policy.recovery_hysteresis;

  // The scope's declared evidence requirements come first: they are the channels
  // its owner said must be watched, independent of which failures occurred.
  for (const EvidenceRequirement& requirement : scope.policy.requirements) {
    requirements.required_observations.push_back(requirement.channel);
  }

  // Every class that is currently Confirmed or Suspected must be positively
  // cleared by the channels that witnessed it. Deriving the demand from the
  // active classification is what stops a recovery from being evaluated against
  // a weaker demand than the failure that caused it.
  for (FailureClass failure_class : decision.confirmed_classes) {
    add_unique_class(requirements.required_cleared_classes, failure_class);
    required_channels_for_class(requirements.required_observations, failure_class);
  }
  for (FailureClass failure_class : decision.suspected_classes) {
    add_unique_class(requirements.required_cleared_classes, failure_class);
    required_channels_for_class(requirements.required_observations, failure_class);
  }
  // A class whose evidence is missing is NOT added to the demand. The demand is
  // the evidence the failure is cleared by, and a failure that was never
  // confirmed has no clearance to prove; adding every unevaluable class would
  // demand every channel in the taxonomy and make a recovery impossible for any
  // scope that does not instrument the whole facility. Missing evidence is
  // reported where it belongs: in the decision's evidence-gap list, which names
  // the channels that are not current whether or not a recovery was requested.

  // A leak may never be cleared by silence. Whenever the classification implicates
  // a leak, the recovery must present a positive "no leak".
  // A leak is implicated when it is confirmed, when it is suspected, or when its
  // evidence is simply missing. The third case matters: "nobody told me whether
  // coolant is escaping" is not "no coolant is escaping", so a recovery is still
  // required to present a positive clearance before it may be permitted.
  const bool leak_implicated =
      std::find(decision.confirmed_classes.begin(), decision.confirmed_classes.end(),
                FailureClass::Leak) != decision.confirmed_classes.end() ||
      std::find(decision.suspected_classes.begin(), decision.suspected_classes.end(),
                FailureClass::Leak) != decision.suspected_classes.end() ||
      std::find(decision.unknown_classes.begin(), decision.unknown_classes.end(),
                FailureClass::Leak) != decision.unknown_classes.end();
  requirements.require_leak_clear = leak_implicated;
  if (leak_implicated) {
    requirements.required_observations.push_back(ObservationChannel::LeakDetector);
  }

  // A verified effect is demanded whenever this scope has a plan, because a plan
  // exists exactly when a response was justified. A scope with no plan owes no
  // effect, and demanding one would make the requirement unsatisfiable for its own
  // sake.
  requirements.require_verified_effect = decision.has_plan;

  sort_channels(requirements.required_observations);
  std::sort(requirements.required_cleared_classes.begin(),
            requirements.required_cleared_classes.end(), [](FailureClass lhs, FailureClass rhs) {
              return failure_class_index(lhs) < failure_class_index(rhs);
            });
  requirements.required_cleared_classes.erase(
      std::unique(requirements.required_cleared_classes.begin(),
                  requirements.required_cleared_classes.end()),
      requirements.required_cleared_classes.end());
  if (requirements.required_observations.size() > limits::kMaxRecoveryDemandCount) {
    return Error(ErrorCode::LimitExceeded,
                 "the recovery demand names more channels than the bound allows")
        .with_subject(scope.id.str());
  }
  return requirements;
}

Result<RecoveryRequirements> recovery_requirements_with_classes(
    const CoolingScope& scope, const ScopeDecision& decision, RecoveryRequirements requirements) {
  // The scope's declared requirements and the classes that must be cleared are
  // both sources of the channel demand. A caller that adds a clearance must have
  // the channels that witness it demanded too, or the recovery would be blocked
  // for want of evidence that was never requested.
  for (FailureClass failure_class : requirements.required_cleared_classes) {
    required_channels_for_class(requirements.required_observations, failure_class);
  }
  sort_channels(requirements.required_observations);
  if (requirements.required_observations.size() > limits::kMaxRecoveryDemandCount) {
    return Error(ErrorCode::LimitExceeded,
                 "the recovery demand names more channels than the bound allows")
        .with_subject(scope.id.str());
  }
  (void)decision;
  return requirements;
}

Result<RecoveryAssessment> evaluate_recovery(const CoolingScope& scope, const ScopeDecision& decision,
                                             const RecoveryRequirements& requirements,
                                             const ObservationSet& observations,
                                             const DecisionPolicy& policy,
                                             const DecisionClock& clock) {
  RecoveryAssessment assessment;
  assessment.scope = scope.id;
  assessment.evaluated_at = clock;
  assessment.decision = RecoveryDecision::Blocked;
  assessment.binding_status = decision.binding_status;

  if (requirements.required_observations.size() > limits::kMaxRecoveryDemandCount) {
    return Error(ErrorCode::LimitExceeded, "the recovery demand exceeded its bound")
        .with_subject(scope.id.str());
  }

  bool blocked = false;
  bool deferred = false;
  std::int64_t remaining = 0;

  // -- Gate 1: every demanded channel is current -----------------------------
  {
    RecoveryGateResult gate;
    gate.gate = RecoveryGate::EvidenceCurrent;
    gate.satisfied = true;
    gate.status = EvidenceStatus::Current;
    std::vector<std::string> not_current;
    for (ObservationChannel channel : requirements.required_observations) {
      const ChannelState state = channel_state(scope.id, channel, observations, policy, clock);
      if (state.usability.status != EvidenceStatus::Current) {
        gate.satisfied = false;
        gate.status = state.usability.status;
        not_current.push_back(std::string(to_token(channel)) + "=" +
                              std::string(to_token(state.usability.status)));
      }
    }
    gate.detail = gate.satisfied ? "every demanded channel is current"
                                 : "channels that are not current: " + join_tokens(not_current);
    if (!gate.satisfied) {
      blocked = true;
    }
    assessment.gates.push_back(std::move(gate));
  }

  // -- Gate 2: flow is known -------------------------------------------------
  if (!gate_required(requirements, scope.policy, ObservationChannel::FlowMeter)) {
    assessment.gates.push_back(not_applicable_gate(
        RecoveryGate::FlowKnown, "no flow evidence is demanded for this scope"));
  } else {
    RecoveryGateResult gate;
    gate.gate = RecoveryGate::FlowKnown;
    const ChannelState state =
        channel_state(scope.id, ObservationChannel::FlowMeter, observations, policy, clock);
    gate.satisfied = state.usability.status == EvidenceStatus::Current;
    gate.status = state.usability.status;
    gate.detail = "flow evidence status=" + std::string(to_token(state.usability.status)) +
                  " observation=" +
                  (state.observation != nullptr ? quote(state.observation->id.str()) : "none");
    if (!gate.satisfied) {
      blocked = true;
    }
    assessment.gates.push_back(std::move(gate));
  }

  // -- Gate 3: pressure is known ---------------------------------------------
  if (!gate_required(requirements, scope.policy, ObservationChannel::DifferentialPressure) &&
      !gate_required(requirements, scope.policy, ObservationChannel::AbsolutePressure)) {
    assessment.gates.push_back(not_applicable_gate(
        RecoveryGate::PressureKnown, "no pressure evidence is demanded for this scope"));
  } else {
    RecoveryGateResult gate;
    gate.gate = RecoveryGate::PressureKnown;
    const ChannelState differential =
        channel_state(scope.id, ObservationChannel::DifferentialPressure, observations, policy, clock);
    const ChannelState absolute =
        channel_state(scope.id, ObservationChannel::AbsolutePressure, observations, policy, clock);
    const bool differential_current = differential.usability.status == EvidenceStatus::Current;
    const bool absolute_current = absolute.usability.status == EvidenceStatus::Current;
    gate.satisfied = differential_current || absolute_current;
    gate.status = differential_current ? differential.usability.status : absolute.usability.status;
    gate.detail = "differential-pressure=" +
                  std::string(to_token(differential.usability.status)) + " absolute-pressure=" +
                  std::string(to_token(absolute.usability.status)) +
                  " (either channel satisfies the gate; neither satisfies it alone when both are stale)";
    if (!gate.satisfied) {
      blocked = true;
    }
    assessment.gates.push_back(std::move(gate));
  }

  // -- Gate 4: leak clear ----------------------------------------------------
  if (!requirements.require_leak_clear) {
    assessment.gates.push_back(not_applicable_gate(
        RecoveryGate::LeakClear, "no leak evidence is implicated by the current classification"));
  } else {
    RecoveryGateResult gate;
    gate.gate = RecoveryGate::LeakClear;
    const ChannelState state =
        channel_state(scope.id, ObservationChannel::LeakDetector, observations, policy, clock);
    const bool current = state.usability.status == EvidenceStatus::Current;
    const bool clear =
        state.observation != nullptr && leak_state_is_clear(state.observation->leak);
    gate.satisfied = current && clear;
    gate.status = state.usability.status;
    gate.detail = std::string("leak-state=") +
                  std::string(to_token(state.observation != nullptr ? state.observation->leak
                                                                   : LeakState::LeakUnknown)) +
                  " status=" + std::string(to_token(state.usability.status)) +
                  " (a missing or unknown leak state never clears the gate)";
    if (!gate.satisfied) {
      blocked = true;
    }
    assessment.gates.push_back(std::move(gate));
  }

  // -- Gate 5: thermal capacity restored -------------------------------------
  if (!gate_required(requirements, scope.policy, ObservationChannel::ThermalCapacityMeter)) {
    assessment.gates.push_back(not_applicable_gate(
        RecoveryGate::ThermalCapacityRestored, "no thermal capacity evidence is demanded for this scope"));
  } else {
    RecoveryGateResult gate;
    gate.gate = RecoveryGate::ThermalCapacityRestored;
    const ChannelState state =
        channel_state(scope.id, ObservationChannel::ThermalCapacityMeter, observations, policy, clock);
    const bool current = state.usability.status == EvidenceStatus::Current;
    const bool restored =
        current && channel_recovered(scope, ObservationChannel::ThermalCapacityMeter, state.observation);
    gate.satisfied = restored;
    gate.status = state.usability.status;
    gate.detail = restored
                      ? "measured capacity is at or above the declared demand"
                      : "measured capacity is below the declared demand, unobserved, or unmeasurable";
    if (!gate.satisfied) {
      blocked = true;
    }
    assessment.gates.push_back(std::move(gate));
  }

  // -- Gate 6: thermal margin restored ---------------------------------------
  if (!gate_required(requirements, scope.policy, ObservationChannel::ThermalMarginMeter)) {
    assessment.gates.push_back(not_applicable_gate(
        RecoveryGate::ThermalMarginRestored, "no thermal margin evidence is demanded for this scope"));
  } else {
    RecoveryGateResult gate;
    gate.gate = RecoveryGate::ThermalMarginRestored;
    const ChannelState state =
        channel_state(scope.id, ObservationChannel::ThermalMarginMeter, observations, policy, clock);
    const bool current = state.usability.status == EvidenceStatus::Current;
    const bool restored =
        current && channel_recovered(scope, ObservationChannel::ThermalMarginMeter, state.observation);
    gate.satisfied = restored;
    gate.status = state.usability.status;
    gate.detail = restored
                      ? "thermal margin is inside the declared envelope"
                      : "thermal margin is outside the declared envelope, unobserved, or unmeasurable";
    if (!gate.satisfied) {
      blocked = true;
    }
    assessment.gates.push_back(std::move(gate));
  }

  // -- Gate 7: airflow restored ----------------------------------------------
  if (!gate_required(requirements, scope.policy, ObservationChannel::AirflowMeter)) {
    assessment.gates.push_back(not_applicable_gate(
        RecoveryGate::AirflowRestored, "no airflow evidence is demanded for this scope"));
  } else {
    RecoveryGateResult gate;
    gate.gate = RecoveryGate::AirflowRestored;
    const ChannelState state =
        channel_state(scope.id, ObservationChannel::AirflowMeter, observations, policy, clock);
    const bool current = state.usability.status == EvidenceStatus::Current;
    const bool restored =
        current && channel_recovered(scope, ObservationChannel::AirflowMeter, state.observation);
    gate.satisfied = restored;
    gate.status = state.usability.status;
    gate.detail = restored ? "airflow is at or above the declared floor"
                           : "airflow is below the declared floor, unobserved, or unmeasurable";
    if (!gate.satisfied) {
      blocked = true;
    }
    assessment.gates.push_back(std::move(gate));
  }

  // -- Gate 8: containment restored ------------------------------------------
  if (!gate_required(requirements, scope.policy, ObservationChannel::ContainmentSwitch)) {
    assessment.gates.push_back(not_applicable_gate(
        RecoveryGate::ContainmentRestored, "no containment evidence is demanded for this scope"));
  } else {
    RecoveryGateResult gate;
    gate.gate = RecoveryGate::ContainmentRestored;
    const ChannelState state =
        channel_state(scope.id, ObservationChannel::ContainmentSwitch, observations, policy, clock);
    const bool current = state.usability.status == EvidenceStatus::Current;
    const bool restored =
        current && channel_recovered(scope, ObservationChannel::ContainmentSwitch, state.observation);
    gate.satisfied = restored;
    gate.status = state.usability.status;
    gate.detail = restored ? "containment is positively reported closed on current evidence"
                           : "containment is not positively reported closed on current evidence";
    if (!gate.satisfied) {
      blocked = true;
    }
    assessment.gates.push_back(std::move(gate));
  }

  // -- Gate 9: every previously confirmed or suspected class is cleared -------
  {
    RecoveryGateResult gate;
    gate.gate = RecoveryGate::ConfirmedClassesCleared;
    gate.satisfied = true;
    gate.status = EvidenceStatus::Current;
    std::vector<std::string> outstanding;
    for (FailureClass failure_class : requirements.required_cleared_classes) {
      std::vector<ObservationChannel> witnesses;
      required_channels_for_class(witnesses, failure_class);
      sort_channels(witnesses);
      bool cleared = !witnesses.empty();
      EvidenceStatus worst = EvidenceStatus::Current;
      for (ObservationChannel channel : witnesses) {
        const ChannelState state = channel_state(scope.id, channel, observations, policy, clock);
        if (state.usability.status != EvidenceStatus::Current) {
          cleared = false;
          if (worst == EvidenceStatus::Current) {
            worst = state.usability.status;
          }
          continue;
        }
        // The very same predicate that would confirm the class is applied here:
        // a witness that still satisfies its class's null signal means the class
        // has not cleared, whatever the wall clock says.
        const WitnessInputs inputs = cleared_inputs_for(scope, state.observation, channel);
        const WitnessReading reading = evaluate_witness(failure_class, channel, inputs);
        if (reading.triggered) {
          cleared = false;
        }
      }
      if (!cleared) {
        outstanding.push_back(std::string(to_token(failure_class)));
        gate.satisfied = false;
        gate.status = worst;
      }
    }
    gate.detail = gate.satisfied
                      ? "every previously confirmed or suspected class is positively cleared"
                      : "classes not cleared: " + join_tokens(outstanding);
    if (!gate.satisfied) {
      blocked = true;
    }
    assessment.gates.push_back(std::move(gate));
  }

  // -- Gate 10: the intended effect was verified ------------------------------
  //
  // The decision being evaluated is the current one, so the plan's attempts are
  // read from the state the decision was derived from. A decision that carries no
  // plan owes no effect.
  {
    RecoveryGateResult gate;
    gate.gate = RecoveryGate::EffectVerified;
    if (!requirements.require_verified_effect) {
      gate.satisfied = true;
      gate.status = EvidenceStatus::Current;
      gate.detail = "no response was solicited, so no effect is owed";
    } else {
      const ResponsePlan* plan = requirements.state_snapshot != nullptr
                                     ? plan_of(*requirements.state_snapshot, scope.id)
                                     : nullptr;
      bool verified = false;
      std::vector<std::string> in_flight;
      if (plan != nullptr) {
        for (const ResponseAttempt& attempt : plan->attempts) {
          if (attempt.state == AttemptState::Verified && !attempt.verdict.empty()) {
            verified = true;
          } else if (attempt.state != AttemptState::Verified && attempt.state != AttemptState::Refuted &&
                     attempt.state != AttemptState::Withdrawn) {
            in_flight.push_back(std::string(to_token(attempt.state)));
          }
        }
      }
      gate.satisfied = verified;
      gate.status = verified ? EvidenceStatus::Current : EvidenceStatus::Missing;
      gate.detail = verified
                        ? "a solicited response reported a verified effect with its verdict"
                        : "no attempt of this scope reached a verified effect; outstanding=" +
                              join_tokens(in_flight);
      if (!gate.satisfied) {
        blocked = true;
      }
    }
    assessment.gates.push_back(std::move(gate));
  }

  // -- Gates 11 and 12: dwell and hysteresis ---------------------------------
  //
  // These are the only gates that produce Deferred, and only when every other
  // gate has passed. A running dwell is not evidence of anything; it is a
  // statement about how long the evidence has held.
  const DurationMilliseconds dwell =
      requirements.dwell.milliseconds() > 0 ? requirements.dwell : scope.policy.recovery_dwell;
  const DurationMilliseconds hysteresis = requirements.hysteresis.milliseconds() > 0
                                              ? requirements.hysteresis
                                              : scope.policy.recovery_hysteresis;
  const std::int64_t required_total = checked_add(dwell.milliseconds(), hysteresis.milliseconds());

  {
    RecoveryGateResult gate;
    gate.gate = RecoveryGate::DwellElapsed;
    if (!requirements.stable_since.present()) {
      gate.satisfied = false;
      gate.status = EvidenceStatus::Missing;
      gate.detail = "no stable interval has started, so the dwell cannot be satisfied";
      if (!blocked) {
        deferred = true;
        remaining = required_total;
      }
    } else {
      CFM_TRY(elapsed, clock.since(requirements.stable_since));
      if (!blocked && elapsed >= dwell.milliseconds()) {
        gate.satisfied = true;
        gate.status = EvidenceStatus::Current;
        gate.detail = "the stable interval has held for " + to_decimal(elapsed) +
                      " ms, at or beyond the required " + to_decimal(dwell.milliseconds()) + " ms";
      } else if (!blocked) {
        deferred = true;
        remaining = dwell.milliseconds() - elapsed;
        gate.status = EvidenceStatus::Current;
        gate.detail = "the stable interval has held for " + to_decimal(elapsed) + " ms of the required " +
                      to_decimal(dwell.milliseconds()) + " ms";
      } else {
        gate.status = EvidenceStatus::Missing;
        gate.detail = "the dwell is not evaluated because at least one evidence gate is unsatisfied";
      }
    }
    assessment.gates.push_back(std::move(gate));
  }

  {
    RecoveryGateResult gate;
    gate.gate = RecoveryGate::HysteresisElapsed;
    if (!requirements.stable_since.present()) {
      gate.satisfied = false;
      gate.status = EvidenceStatus::Missing;
      gate.detail = "no stable interval has started, so the hysteresis cannot be satisfied";
      if (!blocked) {
        deferred = true;
      }
    } else {
      CFM_TRY(elapsed, clock.since(requirements.stable_since));
      if (!blocked && elapsed >= required_total) {
        gate.satisfied = true;
        gate.status = EvidenceStatus::Current;
        gate.detail = "the readings have held without regression for " + to_decimal(elapsed) +
                      " ms, at or beyond the required " + to_decimal(required_total) + " ms";
      } else if (!blocked) {
        deferred = true;
        const std::int64_t still_needed = required_total - elapsed;
        if (still_needed > remaining) {
          remaining = still_needed;
        }
        gate.status = EvidenceStatus::Current;
        gate.detail = "the readings have held for " + to_decimal(elapsed) + " ms of the required " +
                      to_decimal(required_total) + " ms";
      } else {
        gate.status = EvidenceStatus::Missing;
        gate.detail =
            "the hysteresis is not evaluated because at least one evidence gate is unsatisfied";
      }
    }
    assessment.gates.push_back(std::move(gate));
  }

  // -- The verdict -----------------------------------------------------------
  std::sort(assessment.gates.begin(), assessment.gates.end(),
            [](const RecoveryGateResult& lhs, const RecoveryGateResult& rhs) {
              return recovery_gate_index(lhs.gate) < recovery_gate_index(rhs.gate);
            });
  // The verdict separates the two reasons a recovery is not permitted. A gate
  // that failed on evidence is a blocker, and the assessment names it. A dwell or
  // hysteresis interval that is still running is not a failure of evidence: it is
  // a statement that the evidence has not yet held for long enough, and it is
  // reported as Deferred with the remaining interval. Only the evidence gates
  // block.
  for (const RecoveryGateResult& gate : assessment.gates) {
    if (gate.satisfied) {
      continue;
    }
    const bool waiting_gate = gate.gate == RecoveryGate::DwellElapsed ||
                              gate.gate == RecoveryGate::HysteresisElapsed;
    if (waiting_gate) {
      deferred = true;
      continue;
    }
    blocked = true;
    assessment.blocking_gates.push_back(gate.gate);
  }
  if (blocked) {
    assessment.decision = RecoveryDecision::Blocked;
  } else if (deferred) {
    assessment.decision = RecoveryDecision::Deferred;
    assessment.remaining_dwell_milliseconds = remaining > 0 ? remaining : 0;
  } else {
    assessment.decision = RecoveryDecision::Permitted;
  }
  if (assessment.blocking_gates.size() > limits::kMaxRecoveryGateCount) {
    return Error(ErrorCode::LimitExceeded, "the blocking gate list exceeded its bound")
        .with_subject(scope.id.str());
  }
  assessment.explanation = join_lines(explain_recovery(assessment));
  return assessment;
}

std::vector<std::string> explain_recovery(const RecoveryAssessment& assessment) {
  std::vector<std::string> lines;
  lines.push_back(std::string("recovery scope=") + quote(assessment.scope.str()) + " decision=" +
                  std::string(to_token(assessment.decision)) + " at=" +
                  to_decimal(assessment.evaluated_at.milliseconds()));
  if (assessment.decision == RecoveryDecision::Deferred) {
    lines.push_back(std::string("recovery remaining=") +
                    to_decimal(assessment.remaining_dwell_milliseconds) + " ms");
  }
  for (const RecoveryGateResult& gate : assessment.gates) {
    lines.push_back(std::string("gate ") + std::string(to_token(gate.gate)) +
                    (gate.satisfied ? " satisfied" : " unsatisfied") + " status=" +
                    std::string(to_token(gate.status)) + " " + gate.detail);
  }
  for (RecoveryGate gate : assessment.blocking_gates) {
    lines.push_back(std::string("blocking-gate=") + std::string(to_token(gate)));
  }
  return lines;
}

bool recovery_releases_restrictions(const RecoveryAssessment& assessment) noexcept {
  return assessment.decision == RecoveryDecision::Permitted;
}

bool recovery_requires_manual_hold(const RecoveryAssessment& assessment) noexcept {
  // A blocking gate list that contains anything other than the dwell and
  // hysteresis gates means the scope has not demonstrated recovery; the manual
  // hold is kept until the evidence gates pass. A deferred assessment keeps the
  // hold too: waiting is not recovering.
  if (assessment.decision != RecoveryDecision::Permitted) {
    return true;
  }
  return false;
}

}  // namespace dccp::cooling_failure_manager
