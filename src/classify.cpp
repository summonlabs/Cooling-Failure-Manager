// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/cooling_failure_manager/classify.hpp"

#include <cstddef>
#include <string_view>

namespace dccp::cooling_failure_manager {
namespace {

// ---------------------------------------------------------------------------
// Compile-time taxonomy bounds
// ---------------------------------------------------------------------------
//
// Every enumeration this file indexes by enumerator value is contiguous from
// zero, so the value of its last enumerator plus one is its cardinality. The
// assertions below pin the expected cardinality: adding an enumerator grows the
// derived constant and fails the build, which forces the rule table and its
// tests to be extended in the same change instead of indexing past the end at
// run time.

inline constexpr std::size_t kFailureClassCount =
    static_cast<std::size_t>(FailureClass::ThermalRunaway) + 1u;
inline constexpr std::size_t kObservationChannelCount =
    static_cast<std::size_t>(ObservationChannel::HumiditySensor) + 1u;
inline constexpr std::size_t kResponseActionCount =
    static_cast<std::size_t>(ResponseAction::ManualIntervention) + 1u;
inline constexpr std::size_t kRecoveryGateCount =
    static_cast<std::size_t>(RecoveryGate::HysteresisElapsed) + 1u;
inline constexpr std::size_t kRestrictionKindCount =
    static_cast<std::size_t>(RestrictionKind::ManualHold) + 1u;

static_assert(kFailureClassCount == 15, "a new FailureClass needs a rule row and a witness test");
static_assert(kObservationChannelCount == 17, "a new ObservationChannel needs a canonical unit");
static_assert(kResponseActionCount == 14, "a new ResponseAction needs an index and a token");
static_assert(kRecoveryGateCount == 12, "a new RecoveryGate needs an index and a token");
static_assert(kRestrictionKindCount == 7, "a new RestrictionKind needs an index and a token");

// ---------------------------------------------------------------------------
// Channel classification
// ---------------------------------------------------------------------------

/// Status-only channels: the reading is a discrete state code rather than a
/// measurement, interpreted by this table as 0 = normal (or closed as
/// commanded), 1 = degraded (or partially open), 2 = failed (or open). A status
/// channel carries no unit and no scalar envelope bound, and an observed state
/// is evidence in its own right, so it needs no evidence generation to be
/// Current.
constexpr bool is_status_channel(ObservationChannel channel) noexcept {
  switch (channel) {
    case ObservationChannel::PumpStatus:
    case ObservationChannel::ValvePosition:
    case ObservationChannel::ChillerStatus:
    case ObservationChannel::CduStatus:
    case ObservationChannel::CrahCracStatus:
    case ObservationChannel::ContainmentSwitch:
      return true;
    default:
      return false;
  }
}

constexpr ChannelWitness make_witness(ObservationChannel channel, WitnessRole role,
                                      NullSignal signal) noexcept {
  ChannelWitness witness;
  witness.channel = channel;
  witness.role = role;
  witness.signal = signal;
  // A leak threshold below LeakSuspected would make LeakPresent fire on a
  // positively clear reading, so the conservative threshold is the default for
  // every witness that does not compare a leak state at all.
  witness.leak_threshold = LeakState::LeakSuspected;
  return witness;
}

constexpr ChannelWitness make_leak_witness(ObservationChannel channel, WitnessRole role,
                                           LeakState threshold) noexcept {
  ChannelWitness witness = make_witness(channel, role, NullSignal::LeakPresent);
  witness.leak_threshold = threshold;
  return witness;
}

// ---------------------------------------------------------------------------
// The failure-classification rule table
// ---------------------------------------------------------------------------
//
// One row per FailureClass, in enumerator order. The table is the normative
// taxonomy: classification, witness evaluation, severity, urgency and the
// protective consequence of a class are all read from here, so a class can never
// be confirmed by control flow that the table does not describe. Witnesses are
// listed in canonical channel order (ascending channel index); the order inside
// the row never changes a verdict, because evaluate_witness() looks a witness up
// by channel, but it makes the row a canonical value that can be compared and
// encoded.
//
// total_loss=true means the class is a loss of the whole cooling function rather
// than a degradation of it. forces_restriction=true means a confirmed class
// forces a protective restriction. safety_escalation=true means the class may be
// responded to immediately, without waiting for the dwell windows a recovery
// waits for. requires_direct_witness is the class's own requirement, ANDed with
// the policy's requirement by the decision engine.

constexpr FailureRule kFailureRules[kFailureClassCount] = {
    // PlantLoss: the heat-rejection plant that serves the scope is gone. The
    // direct witnesses are a failed chiller status and a measured thermal
    // capacity below the declared demand; an above-ceiling coolant supply
    // temperature supports a suspicion but a warm supply can also come from a
    // load surge, so it never confirms plant loss on its own.
    FailureRule{FailureClass::PlantLoss, Severity::Critical, Urgency::Immediate, TimeToImpact::Minutes,
                true, true, true,
                {make_witness(ObservationChannel::CoolantTemperature, WitnessRole::Supporting,
                              NullSignal::AboveDeclaredCeiling),
                 make_witness(ObservationChannel::ChillerStatus, WitnessRole::Direct,
                              NullSignal::StatusFailed),
                 make_witness(ObservationChannel::ThermalCapacityMeter, WitnessRole::Direct,
                              NullSignal::BelowDeclaredFloor)},
                3, true, "plant.loss"},

    // PumpFailure: a pump stopped, dead-headed or lost its drive. A dead pump is
    // evidenced by flow OR by pump status, so requires_direct_witness is false
    // and the flow witness is Direct: either channel alone is a direct
    // observation of the pumping function, and a dead pump is a safety condition
    // that must not wait for a second channel to agree.
    FailureRule{FailureClass::PumpFailure, Severity::Impaired, Urgency::Imminent,
                TimeToImpact::TensOfMinutes, false, true, true,
                {make_witness(ObservationChannel::FlowMeter, WitnessRole::Direct,
                              NullSignal::BelowDeclaredFloor),
                 make_witness(ObservationChannel::PumpStatus, WitnessRole::Direct,
                              NullSignal::StatusFailed)},
                2, false, "pump.failure"},

    // LoopDegradation: the loop still moves coolant but below its declared
    // floor. It does not force a restriction by itself; the severity floor and
    // the classification decide that.
    FailureRule{FailureClass::LoopDegradation, Severity::Degraded, Urgency::Elevated,
                TimeToImpact::Hours, false, false, false,
                {make_witness(ObservationChannel::FlowMeter, WitnessRole::Direct,
                              NullSignal::BelowDeclaredFloor),
                 make_witness(ObservationChannel::DifferentialPressure, WitnessRole::Supporting,
                              NullSignal::BelowDeclaredFloor)},
                2, true, "loop.degradation"},

    // LoopLoss: the loop is positively dead on both direct witnesses. Dead is
    // stronger than below-floor: a reading of exactly zero is the instrument
    // reporting no movement at all.
    FailureRule{FailureClass::LoopLoss, Severity::Total, Urgency::Immediate, TimeToImpact::Minutes, true,
                true, true,
                {make_witness(ObservationChannel::FlowMeter, WitnessRole::Direct, NullSignal::Dead),
                 make_witness(ObservationChannel::DifferentialPressure, WitnessRole::Direct,
                              NullSignal::Dead)},
                2, true, "loop.loss"},

    // ChillerFailure: one chiller unit failed inside a live plant. A degraded
    // chiller status is direct evidence of that unit; a warm supply temperature
    // only supports it, because the remaining units can usually hold the load
    // for a while.
    FailureRule{FailureClass::ChillerFailure, Severity::Impaired, Urgency::Imminent,
                TimeToImpact::TensOfMinutes, false, true, true,
                {make_witness(ObservationChannel::CoolantTemperature, WitnessRole::Supporting,
                              NullSignal::AboveDeclaredCeiling),
                 make_witness(ObservationChannel::ChillerStatus, WitnessRole::Direct,
                              NullSignal::StatusDegraded)},
                2, true, "chiller.failure"},

    // CduFailure: the coolant distribution unit failed. Flow below floor and a
    // leak both support the suspicion; the CduStatus channel is the direct
    // observation of the unit itself.
    FailureRule{FailureClass::CduFailure, Severity::Critical, Urgency::Immediate, TimeToImpact::Minutes,
                true, true, true,
                {make_witness(ObservationChannel::FlowMeter, WitnessRole::Supporting,
                              NullSignal::BelowDeclaredFloor),
                 make_leak_witness(ObservationChannel::LeakDetector, WitnessRole::Supporting,
                                   LeakState::LeakSuspected),
                 make_witness(ObservationChannel::CduStatus, WitnessRole::Direct,
                              NullSignal::StatusFailed)},
                3, true, "cdu.failure"},

    // ValveFlowFailure: a valve, a flow path or the differential pressure across
    // the scope failed. Only the valve position is a direct observation of the
    // valve; the two pressure/flow channels support it.
    FailureRule{FailureClass::ValveFlowFailure, Severity::Impaired, Urgency::Imminent,
                TimeToImpact::TensOfMinutes, false, true, false,
                {make_witness(ObservationChannel::FlowMeter, WitnessRole::Supporting,
                              NullSignal::BelowDeclaredFloor),
                 make_witness(ObservationChannel::DifferentialPressure, WitnessRole::Supporting,
                              NullSignal::BelowDeclaredFloor),
                 make_witness(ObservationChannel::ValvePosition, WitnessRole::Direct,
                              NullSignal::StatusFailed)},
                3, true, "valve.flow"},

    // PressureFailure: the loop pressure left its declared service envelope on
    // either side. Both pressure channels witness the same envelope, so the
    // absolute channel is direct and the differential channel supports it.
    FailureRule{FailureClass::PressureFailure, Severity::Impaired, Urgency::Elevated,
                TimeToImpact::Hours, false, true, false,
                {make_witness(ObservationChannel::DifferentialPressure, WitnessRole::Supporting,
                              NullSignal::OutsideDeclaredEnvelope),
                 make_witness(ObservationChannel::AbsolutePressure, WitnessRole::Direct,
                              NullSignal::OutsideDeclaredEnvelope)},
                2, true, "pressure.envelope"},

    // CrahCracFailure: one air handler unit failed while the group still runs.
    // The unit's own status is direct; low airflow supports it, because a
    // damper, a filter or a duct can also reduce airflow with the unit running.
    FailureRule{FailureClass::CrahCracFailure, Severity::Impaired, Urgency::Imminent,
                TimeToImpact::TensOfMinutes, false, true, true,
                {make_witness(ObservationChannel::CrahCracStatus, WitnessRole::Direct,
                              NullSignal::StatusFailed),
                 make_witness(ObservationChannel::AirflowMeter, WitnessRole::Supporting,
                              NullSignal::BelowDeclaredFloor)},
                2, true, "crah.failure"},

    // AirflowLoss: air movement stopped although no unit reported a failure. The
    // dead airflow meter is direct; the below-floor entry on the same channel
    // describes the weaker, non-zero degradation and is evaluated first by
    // evaluate_witness(), which finds the Direct entry for the channel.
    FailureRule{FailureClass::AirflowLoss, Severity::Critical, Urgency::Immediate, TimeToImpact::Minutes,
                false, true, true,
                {make_witness(ObservationChannel::AirflowMeter, WitnessRole::Direct, NullSignal::Dead),
                 make_witness(ObservationChannel::AirflowMeter, WitnessRole::Supporting,
                              NullSignal::BelowDeclaredFloor)},
                2, true, "airflow.loss"},

    // ContainmentBreach: the hot/cold aisle boundary or the plenum is open. The
    // switch is the direct witness; a rising air temperature supports the
    // breach but is also caused by a failed air handler.
    FailureRule{FailureClass::ContainmentBreach, Severity::Impaired, Urgency::Imminent,
                TimeToImpact::TensOfMinutes, false, true, true,
                {make_witness(ObservationChannel::AirTemperature, WitnessRole::Supporting,
                              NullSignal::AboveDeclaredCeiling),
                 make_witness(ObservationChannel::ContainmentSwitch, WitnessRole::Direct,
                              NullSignal::StatusFailed)},
                2, true, "containment.breach"},

    // Leak: coolant is escaping. A leak at or above LeakSuspected is direct
    // evidence; nothing else witnesses a leak class, because this component has
    // no way to observe coolant loss other than the leak channel.
    FailureRule{FailureClass::Leak, Severity::Critical, Urgency::Immediate, TimeToImpact::Minutes, false,
                true, true,
                {make_leak_witness(ObservationChannel::LeakDetector, WitnessRole::Direct,
                                   LeakState::LeakSuspected)},
                1, true, "leak"},

    // ThermalCapacityLoss: measured capacity no longer covers the declared
    // demand. The capacity meter is direct; a margin below its declared floor
    // supports it.
    FailureRule{FailureClass::ThermalCapacityLoss, Severity::Impaired, Urgency::Elevated,
                TimeToImpact::Hours, false, true, false,
                {make_witness(ObservationChannel::ThermalCapacityMeter, WitnessRole::Direct,
                              NullSignal::BelowDeclaredFloor),
                 make_witness(ObservationChannel::ThermalMarginMeter, WitnessRole::Supporting,
                              NullSignal::BelowDeclaredFloor)},
                2, true, "capacity.loss"},

    // SharedSourceFailure: a plant or loop shared by several scopes failed. This
    // class is normally attributed from a confirmed upstream failure by the
    // attribution path in decision.cpp rather than witnessed locally, so it
    // declares no Direct witness and requires_direct_witness is true: a local
    // reading can raise a suspicion but only the attribution path confirms it.
    FailureRule{FailureClass::SharedSourceFailure, Severity::Critical, Urgency::Immediate,
                TimeToImpact::Minutes, true, true, true,
                {make_witness(ObservationChannel::FlowMeter, WitnessRole::Supporting,
                              NullSignal::BelowDeclaredFloor)},
                1, true, "shared.source"},

    // ThermalRunaway: temperature diverges although capacity is still declared
    // available. A coolant supply above its ceiling is direct; an air
    // temperature above its ceiling supports it.
    FailureRule{FailureClass::ThermalRunaway, Severity::Critical, Urgency::Immediate,
                TimeToImpact::Minutes, true, true, true,
                {make_witness(ObservationChannel::CoolantTemperature, WitnessRole::Direct,
                              NullSignal::AboveDeclaredCeiling),
                 make_witness(ObservationChannel::AirTemperature, WitnessRole::Supporting,
                              NullSignal::AboveDeclaredCeiling)},
                2, true, "thermal.runaway"},
};

/// Rule returned for a class value outside the taxonomy. A value outside the
/// enumeration is a defect in the caller, never a classification, so the
/// fallback fails in the safe direction: it forces a restriction and escalates
/// for safety, and it declares no witness at all, so an unclassifiable class can
/// never be confirmed from a reading.
constexpr FailureRule kUnclassifiableRule{
    FailureClass::PlantLoss, Severity::Critical, Urgency::Immediate, TimeToImpact::Unobserved,
    false,   true,           true,     {},   0,             true,
    "unknown.class"};

// ---------------------------------------------------------------------------
// Compile-time proofs over the rule table
// ---------------------------------------------------------------------------
//
// These assertions are the table's own proof obligations. Each one states an
// invariant the rest of the library relies on, so a row edited without regard
// for the invariant fails the build rather than surprising a caller.

constexpr bool rows_are_in_class_order() noexcept {
  for (std::size_t index = 0; index < kFailureClassCount; ++index) {
    if (kFailureRules[index].failure_class != static_cast<FailureClass>(index)) {
      return false;
    }
  }
  return true;
}

constexpr bool every_row_has_a_witness() noexcept {
  for (const FailureRule& rule : kFailureRules) {
    if (rule.witness_count == 0 || rule.witness_count > 4) {
      return false;
    }
  }
  return true;
}

constexpr bool unused_witness_slots_are_empty() noexcept {
  for (const FailureRule& rule : kFailureRules) {
    for (std::size_t index = rule.witness_count; index < 4; ++index) {
      if (rule.witnesses[index].signal != NullSignal::None) {
        return false;
      }
    }
  }
  return true;
}

constexpr bool witnesses_are_in_canonical_channel_order() noexcept {
  for (const FailureRule& rule : kFailureRules) {
    for (std::size_t index = 1; index < rule.witness_count; ++index) {
      if (static_cast<unsigned>(rule.witnesses[index - 1].channel) >
          static_cast<unsigned>(rule.witnesses[index].channel)) {
        return false;
      }
    }
  }
  return true;
}

/// Two direct witnesses on one channel would be an ambiguous rule: the lookup
/// could not say which signal decides. Supporting entries may share a channel
/// with a direct entry (AirflowLoss uses the pair deliberately).
constexpr bool direct_witness_channels_are_distinct() noexcept {
  for (const FailureRule& rule : kFailureRules) {
    for (std::size_t lhs = 0; lhs < rule.witness_count; ++lhs) {
      if (rule.witnesses[lhs].role != WitnessRole::Direct) {
        continue;
      }
      for (std::size_t rhs = lhs + 1; rhs < rule.witness_count; ++rhs) {
        if (rule.witnesses[rhs].role == WitnessRole::Direct &&
            rule.witnesses[lhs].channel == rule.witnesses[rhs].channel) {
          return false;
        }
      }
    }
  }
  return true;
}

/// A witness that cannot be confirmed from a reading must not be able to fire.
constexpr bool every_witness_has_a_signal() noexcept {
  for (const FailureRule& rule : kFailureRules) {
    for (std::size_t index = 0; index < rule.witness_count; ++index) {
      if (rule.witnesses[index].signal == NullSignal::None) {
        return false;
      }
    }
  }
  return true;
}

/// A leak threshold of LeakNone would make triggered and contradicting true at
/// once for a positively clear reading, so it is refused here.
constexpr bool leak_thresholds_are_decisive() noexcept {
  for (const FailureRule& rule : kFailureRules) {
    for (std::size_t index = 0; index < rule.witness_count; ++index) {
      const ChannelWitness& witness = rule.witnesses[index];
      if (witness.signal == NullSignal::LeakPresent && witness.leak_threshold == LeakState::LeakNone) {
        return false;
      }
    }
  }
  return true;
}

/// Every class with severity Critical or Total escalates for safety. The
/// converse deliberately does not hold: a dead pump or a failed air handler is
/// Impaired by severity yet must be answered immediately, so those classes list
/// safety_escalation=true while their severity is Impaired.
constexpr bool critical_classes_escalate() noexcept {
  for (const FailureRule& rule : kFailureRules) {
    const bool critical = rule.severity == Severity::Critical || rule.severity == Severity::Total;
    if (critical && !rule.safety_escalation) {
      return false;
    }
  }
  return true;
}

constexpr bool escalation_forces_a_restriction() noexcept {
  for (const FailureRule& rule : kFailureRules) {
    if (rule.safety_escalation && !rule.forces_restriction) {
      return false;
    }
  }
  return true;
}

constexpr bool total_loss_forces_a_restriction() noexcept {
  for (const FailureRule& rule : kFailureRules) {
    if (rule.total_loss && !rule.forces_restriction) {
      return false;
    }
  }
  return true;
}

/// total_loss is a property of the taxonomy, not of a row: it must agree with
/// failure_class_is_total_loss() in enums.cpp. The assertion cannot call that
/// function at compile time, so the agreement is checked in tests_classify.cpp
/// against the same list.
constexpr bool rule_ids_are_non_empty_and_unique() noexcept {
  for (std::size_t lhs = 0; lhs < kFailureClassCount; ++lhs) {
    if (kFailureRules[lhs].rule_id.empty()) {
      return false;
    }
    for (std::size_t rhs = lhs + 1; rhs < kFailureClassCount; ++rhs) {
      if (kFailureRules[lhs].rule_id == kFailureRules[rhs].rule_id) {
        return false;
      }
    }
  }
  return true;
}

static_assert(rows_are_in_class_order(), "the rule table must be in FailureClass enumerator order");
static_assert(every_row_has_a_witness(), "every rule needs between 1 and 4 witnesses");
static_assert(unused_witness_slots_are_empty(), "witness slots past witness_count must be unused");
static_assert(witnesses_are_in_canonical_channel_order(),
              "rule witnesses must be listed in ascending channel index order");
static_assert(direct_witness_channels_are_distinct(),
              "two direct witnesses on one channel would be an ambiguous rule");
static_assert(every_witness_has_a_signal(), "every witness must carry a signal");
static_assert(leak_thresholds_are_decisive(),
              "a leak threshold of LeakNone would make triggered and contradicting overlap");
static_assert(critical_classes_escalate(), "a Critical or Total class must escalate for safety");
static_assert(escalation_forces_a_restriction(),
              "a class that may be answered immediately must also force a restriction");
static_assert(total_loss_forces_a_restriction(), "a whole-function loss must force a restriction");
static_assert(rule_ids_are_non_empty_and_unique(), "rule identities must be non-empty and unique");

// ---------------------------------------------------------------------------
// Envelope binding helpers
// ---------------------------------------------------------------------------

void set_floor(EnvelopeBound& bound, const DeclaredQuantity& quantity) noexcept {
  if (quantity.declared()) {
    bound.has_floor = true;
    bound.floor_value = quantity.value();
    bound.floor_unit = quantity.unit();
  }
}

void set_ceiling(EnvelopeBound& bound, const DeclaredQuantity& quantity) noexcept {
  if (quantity.declared()) {
    bound.has_ceiling = true;
    bound.ceiling_value = quantity.value();
    bound.ceiling_unit = quantity.unit();
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// Rule lookup
// ---------------------------------------------------------------------------

const FailureRule& failure_rule(FailureClass failure_class) noexcept {
  const std::size_t index = static_cast<std::size_t>(failure_class);
  if (index >= kFailureClassCount) {
    return kUnclassifiableRule;
  }
  return kFailureRules[index];
}

// ---------------------------------------------------------------------------
// Witness evaluation
// ---------------------------------------------------------------------------

WitnessReading evaluate_witness(FailureClass failure_class, ObservationChannel channel,
                                const WitnessInputs& inputs) noexcept {
  WitnessReading reading;
  const FailureRule& rule = failure_rule(failure_class);
  for (std::size_t index = 0; index < rule.witness_count; ++index) {
    if (rule.witnesses[index].channel == channel) {
      reading.witness = &rule.witnesses[index];
      break;
    }
  }
  if (reading.witness == nullptr) {
    return reading;
  }

  // An unusable reading proves nothing in either direction: a suspect or bad
  // sample is recorded evidence, never a confirmation and never a refutation.
  if (!inputs.usable) {
    return reading;
  }

  const ChannelWitness& witness = *reading.witness;
  switch (witness.signal) {
    case NullSignal::None:
      // A channel named without a signal describes a supporting channel only;
      // it can never fire through this path.
      return reading;

    case NullSignal::BelowDeclaredFloor:
      // An undeclared floor is not a violated floor: without a declared limit
      // the reading cannot be compared, so a scope with no declared flow floor
      // can never confirm LoopLoss or LoopDegradation from flow alone.
      if (!inputs.has_value || !inputs.has_floor) {
        return reading;
      }
      reading.triggered = inputs.value <= inputs.declared_floor;
      reading.contradicting = inputs.value > inputs.declared_floor;
      return reading;

    case NullSignal::AboveDeclaredCeiling:
      if (!inputs.has_value || !inputs.has_ceiling) {
        return reading;
      }
      reading.triggered = inputs.value >= inputs.declared_ceiling;
      reading.contradicting = inputs.value < inputs.declared_ceiling;
      return reading;

    case NullSignal::OutsideDeclaredEnvelope: {
      if (!inputs.has_value) {
        return reading;
      }
      const bool has_any_bound = inputs.has_floor || inputs.has_ceiling;
      if (!has_any_bound) {
        return reading;
      }
      const bool below = inputs.has_floor && inputs.value < inputs.declared_floor;
      const bool above = inputs.has_ceiling && inputs.value > inputs.declared_ceiling;
      reading.triggered = below || above;
      reading.contradicting = !reading.triggered;
      return reading;
    }

    case NullSignal::Dead:
      if (!inputs.has_value) {
        return reading;
      }
      reading.triggered = inputs.value == 0;
      reading.contradicting = inputs.value > 0;
      return reading;

    case NullSignal::StatusFailed:
      if (!inputs.has_value) {
        return reading;
      }
      reading.triggered = inputs.value >= 2;
      reading.contradicting = inputs.value < 2;
      return reading;

    case NullSignal::StatusDegraded:
      if (!inputs.has_value) {
        return reading;
      }
      reading.triggered = inputs.value >= 1;
      reading.contradicting = inputs.value < 1;
      return reading;

    case NullSignal::LeakPresent:
      reading.triggered = inputs.leak >= witness.leak_threshold;
      reading.contradicting = inputs.leak == LeakState::LeakNone;
      return reading;
  }
  // Unreachable for every enumerator above; a value outside the enumeration is
  // a defect in the library, and refuses to trigger rather than guessing.
  return reading;
}

// ---------------------------------------------------------------------------
// Declared envelope and channel vocabulary
// ---------------------------------------------------------------------------

EnvelopeBound envelope_bound_for(const ScopePolicy& policy, ObservationChannel channel) noexcept {
  EnvelopeBound bound;
  switch (channel) {
    case ObservationChannel::FlowMeter:
    case ObservationChannel::AirflowMeter:
      // Airflow shares the scope's flow floor: the scope declares one minimum
      // movement of its cooling medium, and an air handler group declares the
      // same field as its minimum air movement. Both are millilitres per second.
      set_floor(bound, policy.envelope.min_flow);
      break;

    case ObservationChannel::DifferentialPressure:
    case ObservationChannel::AbsolutePressure:
      // ThermalEnvelope declares exactly one pressure floor. An absolute
      // pressure witness therefore has a floor and no ceiling: the envelope
      // declares no absolute-pressure ceiling, and an undeclared limit is not a
      // limit this component may invent.
      set_floor(bound, policy.envelope.min_differential_pressure);
      break;

    case ObservationChannel::CoolantTemperature:
    case ObservationChannel::AirTemperature:
      set_ceiling(bound, policy.envelope.max_supply_temperature);
      break;

    case ObservationChannel::ThermalCapacityMeter:
      set_floor(bound, policy.envelope.declared_demand);
      break;

    case ObservationChannel::ThermalMarginMeter:
      set_floor(bound, policy.envelope.min_thermal_margin);
      break;

    case ObservationChannel::ThermalLoadMeter:
      set_ceiling(bound, policy.envelope.declared_demand);
      break;

    default:
      // Status and leak channels carry a discrete state, not a scalar with a
      // declared bound.
      break;
  }
  return bound;
}

ChannelThreshold channel_threshold(const ScopePolicy& policy, ObservationChannel channel) noexcept {
  ChannelThreshold threshold;
  const std::string_view unit = channel_unit(channel);
  threshold.unit = unit;

  const EnvelopeBound bound = envelope_bound_for(policy, channel);
  // A declared bound is a threshold for this channel only when it carries the
  // channel's own canonical unit. This component never converts between units,
  // so a floor declared in another unit is not a limit on this channel, and
  // reporting it as one would be exactly the silent unit guess the library
  // refuses everywhere else.
  if (!unit.empty()) {
    if (bound.has_floor && bound.floor_unit == unit) {
      threshold.has_threshold = true;
      threshold.threshold = bound.floor_value;
    } else if (bound.has_ceiling && bound.ceiling_unit == unit) {
      threshold.has_threshold = true;
      threshold.threshold = bound.ceiling_value;
    }
  }
  return threshold;
}

std::string_view channel_unit(ObservationChannel channel) noexcept {
  if (channel_is_leak(channel) || is_status_channel(channel)) {
    return {};
  }
  switch (channel) {
    case ObservationChannel::FlowMeter:
    case ObservationChannel::AirflowMeter:
      return "mL/s";
    case ObservationChannel::DifferentialPressure:
    case ObservationChannel::AbsolutePressure:
      return "Pa";
    case ObservationChannel::CoolantTemperature:
    case ObservationChannel::AirTemperature:
      return "mC";
    case ObservationChannel::HumiditySensor:
      return "ppm";
    case ObservationChannel::ThermalCapacityMeter:
    case ObservationChannel::ThermalLoadMeter:
      return "W";
    case ObservationChannel::ThermalMarginMeter:
      return "mK";
    default:
      // A channel value outside the enumeration has no canonical unit; an
      // unknown channel is never given one, so no reading can be compared
      // against it.
      return {};
  }
}

bool channel_is_leak(ObservationChannel channel) noexcept {
  return channel == ObservationChannel::LeakDetector;
}

// ---------------------------------------------------------------------------
// Canonical indices
// ---------------------------------------------------------------------------
//
// Every enumeration below is contiguous from zero, so the enumerator value is
// its canonical index. A value outside the enumeration keeps its raw value: the
// index is an ordering key, and ordering must stay total even for a value the
// taxonomy does not describe.

std::size_t channel_index(ObservationChannel channel) noexcept {
  return static_cast<std::size_t>(channel);
}

std::size_t failure_class_index(FailureClass failure_class) noexcept {
  return static_cast<std::size_t>(failure_class);
}

std::size_t response_action_index(ResponseAction action) noexcept {
  return static_cast<std::size_t>(action);
}

std::size_t recovery_gate_index(RecoveryGate gate) noexcept {
  return static_cast<std::size_t>(gate);
}

std::size_t restriction_kind_index(RestrictionKind kind) noexcept {
  return static_cast<std::size_t>(kind);
}

}  // namespace dccp::cooling_failure_manager
