// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Proof obligations for the failure-classification rule table: the taxonomy it
// states, the witness list of every class, the evaluation of every signal, the
// declared-envelope mapping and the canonical channel vocabulary. The table is
// the normative statement of what this component can confirm, so it is checked
// row by row rather than sampled.

#include "test_framework.hpp"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/classify.hpp"
#include "dccp/cooling_failure_manager/enums.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/result.hpp"

namespace {

namespace cfm = dccp::cooling_failure_manager;

constexpr std::size_t kClassCount = 15;
constexpr std::size_t kChannelCount = 17;

void expect_code(const cfm::Error& error, cfm::ErrorCode expected, const std::string& what) {
  CT_CHECK_MSG(error.code() == expected,
               what + ": expected " + std::string(cfm::error_code_name(expected)) + ", observed " +
                   std::string(cfm::error_code_name(error.code())) + " [" + error.to_string() + "]");
}

cfm::FailureClass class_at(std::size_t index) { return static_cast<cfm::FailureClass>(index); }
cfm::ObservationChannel channel_at(std::size_t index) {
  return static_cast<cfm::ObservationChannel>(index);
}

/// The documented taxonomy, one row per class, in enumerator order.
struct ExpectedRule {
  cfm::Severity severity;
  cfm::Urgency urgency;
  cfm::TimeToImpact time_to_impact;
  bool total_loss;
  bool forces_restriction;
  bool safety_escalation;
  bool requires_direct_witness;
  std::string_view rule_id;
};

const ExpectedRule kExpectedRules[kClassCount] = {
    /* PlantLoss           */ {cfm::Severity::Critical, cfm::Urgency::Immediate,
                               cfm::TimeToImpact::Minutes, true, true, true, true, "plant.loss"},
    /* PumpFailure         */ {cfm::Severity::Impaired, cfm::Urgency::Imminent,
                               cfm::TimeToImpact::TensOfMinutes, false, true, true, false,
                               "pump.failure"},
    /* LoopDegradation     */ {cfm::Severity::Degraded, cfm::Urgency::Elevated,
                               cfm::TimeToImpact::Hours, false, false, false, true, "loop.degradation"},
    /* LoopLoss            */ {cfm::Severity::Total, cfm::Urgency::Immediate, cfm::TimeToImpact::Minutes,
                               true, true, true, true, "loop.loss"},
    /* ChillerFailure      */ {cfm::Severity::Impaired, cfm::Urgency::Imminent,
                               cfm::TimeToImpact::TensOfMinutes, false, true, true, true,
                               "chiller.failure"},
    /* CduFailure          */ {cfm::Severity::Critical, cfm::Urgency::Immediate,
                               cfm::TimeToImpact::Minutes, true, true, true, true, "cdu.failure"},
    /* ValveFlowFailure    */ {cfm::Severity::Impaired, cfm::Urgency::Imminent,
                               cfm::TimeToImpact::TensOfMinutes, false, true, false, true,
                               "valve.flow"},
    /* PressureFailure     */ {cfm::Severity::Impaired, cfm::Urgency::Elevated, cfm::TimeToImpact::Hours,
                               false, true, false, true, "pressure.envelope"},
    /* CrahCracFailure     */ {cfm::Severity::Impaired, cfm::Urgency::Imminent,
                               cfm::TimeToImpact::TensOfMinutes, false, true, true, true, "crah.failure"},
    /* AirflowLoss         */ {cfm::Severity::Critical, cfm::Urgency::Immediate,
                               cfm::TimeToImpact::Minutes, false, true, true, true, "airflow.loss"},
    /* ContainmentBreach   */ {cfm::Severity::Impaired, cfm::Urgency::Imminent,
                               cfm::TimeToImpact::TensOfMinutes, false, true, true, true,
                               "containment.breach"},
    /* Leak                */ {cfm::Severity::Critical, cfm::Urgency::Immediate,
                               cfm::TimeToImpact::Minutes, false, true, true, true, "leak"},
    /* ThermalCapacityLoss */ {cfm::Severity::Impaired, cfm::Urgency::Elevated, cfm::TimeToImpact::Hours,
                               false, true, false, true, "capacity.loss"},
    /* SharedSourceFailure */ {cfm::Severity::Critical, cfm::Urgency::Immediate,
                               cfm::TimeToImpact::Minutes, true, true, true, true, "shared.source"},
    /* ThermalRunaway      */ {cfm::Severity::Critical, cfm::Urgency::Immediate,
                               cfm::TimeToImpact::Minutes, true, true, true, true, "thermal.runaway"},
};

/// The documented witness lists, in canonical channel order. Comparing the whole
/// list rather than looking channels up one at a time also proves that no extra
/// witness was added and that the order is canonical.
struct ExpectedWitness {
  cfm::ObservationChannel channel;
  cfm::WitnessRole role;
  cfm::NullSignal signal;
  cfm::LeakState leak_threshold;
};

void expect_witness_list(cfm::FailureClass failure_class,
                         std::initializer_list<ExpectedWitness> expected) {
  const cfm::FailureRule& rule = cfm::failure_rule(failure_class);
  const std::string what = std::string("witness list of rule ") + std::string(rule.rule_id);
  CT_CHECK_MSG(rule.witness_count == expected.size(),
               what + ": expected " + std::to_string(expected.size()) + " witnesses, observed " +
                   std::to_string(rule.witness_count));
  if (rule.witness_count != expected.size()) {
    return;
  }
  std::size_t index = 0;
  for (const ExpectedWitness& item : expected) {
    const cfm::ChannelWitness& witness = rule.witnesses[index];
    CT_CHECK_MSG(witness.channel == item.channel,
                 what + ": witness " + std::to_string(index) + " channel mismatch");
    CT_CHECK_MSG(witness.role == item.role, what + ": witness " + std::to_string(index) +
                                                " role mismatch");
    CT_CHECK_MSG(witness.signal == item.signal,
                 what + ": witness " + std::to_string(index) + " signal mismatch");
    CT_CHECK_MSG(witness.leak_threshold == item.leak_threshold,
                 what + ": witness " + std::to_string(index) + " leak threshold mismatch");
    ++index;
  }
}

cfm::WitnessInputs usable_value(std::int64_t value) {
  cfm::WitnessInputs inputs;
  inputs.value = value;
  inputs.has_value = true;
  inputs.usable = true;
  return inputs;
}

}  // namespace

CT_TEST(classify_taxonomy_table_is_internally_consistent) {
  CT_CHECK_EQ(cfm::failure_class_count(), kClassCount);
  CT_CHECK_EQ(cfm::observation_channel_count(), kChannelCount);

  const cfm::FailureClass* order = cfm::failure_class_order();
  CT_REQUIRE(order != nullptr);
  for (std::size_t index = 0; index < kClassCount; ++index) {
    CT_CHECK_EQ(static_cast<std::size_t>(order[index]), index);
  }

  for (std::size_t index = 0; index < kClassCount; ++index) {
    const cfm::FailureClass failure_class = class_at(index);
    const cfm::FailureRule& rule = cfm::failure_rule(failure_class);
    const std::string what = "rule " + std::string(rule.rule_id);

    CT_CHECK_MSG(rule.failure_class == failure_class, what + ": row is not in enumerator order");
    CT_CHECK_MSG(!rule.rule_id.empty(), what + ": rule identity must not be empty");
    CT_CHECK_MSG(rule.witness_count >= 1 && rule.witness_count <= 4,
                 what + ": witness count must be within [1, 4]");

    // Unused witness slots must be inert: a stale entry past witness_count must
    // never be reachable by a lookup.
    for (std::size_t slot = rule.witness_count; slot < 4; ++slot) {
      CT_CHECK_MSG(rule.witnesses[slot].signal == cfm::NullSignal::None,
                   what + ": unused witness slot " + std::to_string(slot) + " carries a signal");
    }

    std::size_t direct_channels = 0;
    for (std::size_t slot = 0; slot < rule.witness_count; ++slot) {
      const cfm::ChannelWitness& witness = rule.witnesses[slot];
      CT_CHECK_MSG(witness.signal != cfm::NullSignal::None,
                   what + ": witness " + std::to_string(slot) + " carries no signal");
      if (slot > 0) {
        CT_CHECK_MSG(cfm::channel_index(rule.witnesses[slot - 1].channel) <=
                         cfm::channel_index(witness.channel),
                     what + ": witnesses are not in canonical channel order");
      }
      if (witness.role == cfm::WitnessRole::Direct) {
        for (std::size_t other = slot + 1; other < rule.witness_count; ++other) {
          if (rule.witnesses[other].role == cfm::WitnessRole::Direct) {
            CT_CHECK_MSG(rule.witnesses[other].channel != witness.channel,
                         what + ": two direct witnesses share one channel");
          }
        }
        ++direct_channels;
      }
      if (witness.signal == cfm::NullSignal::LeakPresent) {
        // A threshold of LeakNone would make a positively clear reading both
        // triggered and contradicting, which no rule may allow.
        CT_CHECK_MSG(witness.leak_threshold != cfm::LeakState::LeakNone,
                     what + ": a leak witness must not use LeakNone as its threshold");
      }
    }

    if (rule.total_loss) {
      CT_CHECK_MSG(rule.forces_restriction, what + ": a whole-function loss must force a restriction");
    }
    const bool critical =
        rule.severity == cfm::Severity::Critical || rule.severity == cfm::Severity::Total;
    if (critical) {
      CT_CHECK_MSG(rule.safety_escalation, what + ": a Critical or Total class must escalate for safety");
    }
    if (rule.safety_escalation) {
      CT_CHECK_MSG(rule.forces_restriction,
                   what + ": a class answered immediately must also force a restriction");
    }
  }
}

CT_TEST(classify_total_loss_agrees_with_the_enumeration_helper) {
  // The rule table and failure_class_is_total_loss() must state the same
  // taxonomy. The table drives confirmation while the helper decides which
  // upstream failure is attributed downstream, so two answers for one class would
  // let a class be confirmed under one rule and attributed under another.
  std::string disagreement;
  for (std::size_t index = 0; index < kClassCount; ++index) {
    const cfm::FailureRule& rule = cfm::failure_rule(class_at(index));
    const bool helper = cfm::failure_class_is_total_loss(class_at(index));
    if (rule.total_loss == helper) {
      continue;
    }
    if (!disagreement.empty()) {
      disagreement += ", ";
    }
    disagreement += std::string(rule.rule_id) + "(table=" + (rule.total_loss ? "true" : "false") +
                    ", helper=" + (helper ? "true" : "false") + ")";
  }
  CT_CHECK_MSG(disagreement.empty(),
               "the rule table and failure_class_is_total_loss() disagree about: " + disagreement);
}

CT_TEST(classify_taxonomy_matches_the_documented_rules) {
  // Severity, urgency, time to impact and the normative flags, class by class.
  // The reverse implication safety_escalation => Critical-or-Total is
  // deliberately NOT asserted: a dead pump, a failed chiller, a failed air
  // handler and an open containment boundary are Impaired by severity and are
  // still answered immediately, which is why those four rows carry
  // safety_escalation=true with an Impaired severity.
  for (std::size_t index = 0; index < kClassCount; ++index) {
    const cfm::FailureRule& rule = cfm::failure_rule(class_at(index));
    const ExpectedRule& expected = kExpectedRules[index];
    const std::string what = "rule " + std::string(expected.rule_id);

    CT_CHECK_MSG(rule.rule_id == expected.rule_id, what + ": rule identity mismatch");
    CT_CHECK_MSG(rule.severity == expected.severity, what + ": severity mismatch");
    CT_CHECK_MSG(rule.urgency == expected.urgency, what + ": urgency mismatch");
    CT_CHECK_MSG(rule.time_to_impact == expected.time_to_impact, what + ": time to impact mismatch");
    CT_CHECK_MSG(rule.total_loss == expected.total_loss, what + ": total_loss mismatch");
    CT_CHECK_MSG(rule.forces_restriction == expected.forces_restriction,
                 what + ": forces_restriction mismatch");
    CT_CHECK_MSG(rule.safety_escalation == expected.safety_escalation,
                 what + ": safety_escalation mismatch");
    CT_CHECK_MSG(rule.requires_direct_witness == expected.requires_direct_witness,
                 what + ": requires_direct_witness mismatch");
  }
}

CT_TEST(classify_witness_lists_match_the_documented_channels) {
  expect_witness_list(cfm::FailureClass::PlantLoss,
                      {{cfm::ObservationChannel::CoolantTemperature, cfm::WitnessRole::Supporting,
                        cfm::NullSignal::AboveDeclaredCeiling, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::ChillerStatus, cfm::WitnessRole::Direct,
                        cfm::NullSignal::StatusFailed, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::ThermalCapacityMeter, cfm::WitnessRole::Direct,
                        cfm::NullSignal::BelowDeclaredFloor, cfm::LeakState::LeakSuspected}});
  expect_witness_list(cfm::FailureClass::PumpFailure,
                      {{cfm::ObservationChannel::FlowMeter, cfm::WitnessRole::Direct,
                        cfm::NullSignal::BelowDeclaredFloor, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::PumpStatus, cfm::WitnessRole::Direct,
                        cfm::NullSignal::StatusFailed, cfm::LeakState::LeakSuspected}});
  expect_witness_list(cfm::FailureClass::LoopDegradation,
                      {{cfm::ObservationChannel::FlowMeter, cfm::WitnessRole::Direct,
                        cfm::NullSignal::BelowDeclaredFloor, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::DifferentialPressure, cfm::WitnessRole::Supporting,
                        cfm::NullSignal::BelowDeclaredFloor, cfm::LeakState::LeakSuspected}});
  expect_witness_list(cfm::FailureClass::LoopLoss,
                      {{cfm::ObservationChannel::FlowMeter, cfm::WitnessRole::Direct,
                        cfm::NullSignal::Dead, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::DifferentialPressure, cfm::WitnessRole::Direct,
                        cfm::NullSignal::Dead, cfm::LeakState::LeakSuspected}});
  expect_witness_list(cfm::FailureClass::ChillerFailure,
                      {{cfm::ObservationChannel::CoolantTemperature, cfm::WitnessRole::Supporting,
                        cfm::NullSignal::AboveDeclaredCeiling, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::ChillerStatus, cfm::WitnessRole::Direct,
                        cfm::NullSignal::StatusDegraded, cfm::LeakState::LeakSuspected}});
  expect_witness_list(cfm::FailureClass::CduFailure,
                      {{cfm::ObservationChannel::FlowMeter, cfm::WitnessRole::Supporting,
                        cfm::NullSignal::BelowDeclaredFloor, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::LeakDetector, cfm::WitnessRole::Supporting,
                        cfm::NullSignal::LeakPresent, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::CduStatus, cfm::WitnessRole::Direct,
                        cfm::NullSignal::StatusFailed, cfm::LeakState::LeakSuspected}});
  expect_witness_list(cfm::FailureClass::ValveFlowFailure,
                      {{cfm::ObservationChannel::FlowMeter, cfm::WitnessRole::Supporting,
                        cfm::NullSignal::BelowDeclaredFloor, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::DifferentialPressure, cfm::WitnessRole::Supporting,
                        cfm::NullSignal::BelowDeclaredFloor, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::ValvePosition, cfm::WitnessRole::Direct,
                        cfm::NullSignal::StatusFailed, cfm::LeakState::LeakSuspected}});
  expect_witness_list(cfm::FailureClass::PressureFailure,
                      {{cfm::ObservationChannel::DifferentialPressure, cfm::WitnessRole::Supporting,
                        cfm::NullSignal::OutsideDeclaredEnvelope, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::AbsolutePressure, cfm::WitnessRole::Direct,
                        cfm::NullSignal::OutsideDeclaredEnvelope, cfm::LeakState::LeakSuspected}});
  expect_witness_list(cfm::FailureClass::CrahCracFailure,
                      {{cfm::ObservationChannel::CrahCracStatus, cfm::WitnessRole::Direct,
                        cfm::NullSignal::StatusFailed, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::AirflowMeter, cfm::WitnessRole::Supporting,
                        cfm::NullSignal::BelowDeclaredFloor, cfm::LeakState::LeakSuspected}});
  expect_witness_list(cfm::FailureClass::AirflowLoss,
                      {{cfm::ObservationChannel::AirflowMeter, cfm::WitnessRole::Direct,
                        cfm::NullSignal::Dead, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::AirflowMeter, cfm::WitnessRole::Supporting,
                        cfm::NullSignal::BelowDeclaredFloor, cfm::LeakState::LeakSuspected}});
  expect_witness_list(cfm::FailureClass::ContainmentBreach,
                      {{cfm::ObservationChannel::AirTemperature, cfm::WitnessRole::Supporting,
                        cfm::NullSignal::AboveDeclaredCeiling, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::ContainmentSwitch, cfm::WitnessRole::Direct,
                        cfm::NullSignal::StatusFailed, cfm::LeakState::LeakSuspected}});
  expect_witness_list(cfm::FailureClass::Leak,
                      {{cfm::ObservationChannel::LeakDetector, cfm::WitnessRole::Direct,
                        cfm::NullSignal::LeakPresent, cfm::LeakState::LeakSuspected}});
  expect_witness_list(cfm::FailureClass::ThermalCapacityLoss,
                      {{cfm::ObservationChannel::ThermalCapacityMeter, cfm::WitnessRole::Direct,
                        cfm::NullSignal::BelowDeclaredFloor, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::ThermalMarginMeter, cfm::WitnessRole::Supporting,
                        cfm::NullSignal::BelowDeclaredFloor, cfm::LeakState::LeakSuspected}});
  expect_witness_list(cfm::FailureClass::SharedSourceFailure,
                      {{cfm::ObservationChannel::FlowMeter, cfm::WitnessRole::Supporting,
                        cfm::NullSignal::BelowDeclaredFloor, cfm::LeakState::LeakSuspected}});
  expect_witness_list(cfm::FailureClass::ThermalRunaway,
                      {{cfm::ObservationChannel::CoolantTemperature, cfm::WitnessRole::Direct,
                        cfm::NullSignal::AboveDeclaredCeiling, cfm::LeakState::LeakSuspected},
                       {cfm::ObservationChannel::AirTemperature, cfm::WitnessRole::Supporting,
                        cfm::NullSignal::AboveDeclaredCeiling, cfm::LeakState::LeakSuspected}});
}

CT_TEST(classify_direct_witnesses_decide_dead_status_and_degraded_codes) {
  // Dead: exactly zero is a dead channel; any positive reading argues against it.
  {
    const cfm::WitnessReading dead = cfm::evaluate_witness(cfm::FailureClass::LoopLoss,
                                                          cfm::ObservationChannel::FlowMeter,
                                                          usable_value(0));
    CT_REQUIRE(dead.witness != nullptr);
    CT_CHECK(dead.triggered);
    CT_CHECK(!dead.contradicting);

    const cfm::WitnessReading flowing = cfm::evaluate_witness(
        cfm::FailureClass::LoopLoss, cfm::ObservationChannel::FlowMeter, usable_value(1));
    CT_CHECK(!flowing.triggered);
    CT_CHECK(flowing.contradicting);
  }

  // StatusFailed uses the documented state codes: 0 normal, 1 degraded, 2 failed.
  for (std::int64_t code = 0; code <= 4; ++code) {
    const cfm::WitnessReading reading = cfm::evaluate_witness(
        cfm::FailureClass::PumpFailure, cfm::ObservationChannel::PumpStatus, usable_value(code));
    CT_REQUIRE(reading.witness != nullptr);
    CT_CHECK_MSG(reading.triggered == (code >= 2),
                 "PumpStatus StatusFailed must trigger at state code 2 and above, code " +
                     std::to_string(code));
    CT_CHECK_MSG(reading.contradicting == (code < 2),
                 "PumpStatus StatusFailed must contradict below state code 2, code " +
                     std::to_string(code));
    CT_CHECK(!(reading.triggered && reading.contradicting));
  }

  // StatusDegraded triggers from the partial state upwards.
  for (std::int64_t code = 0; code <= 3; ++code) {
    const cfm::WitnessReading reading = cfm::evaluate_witness(
        cfm::FailureClass::ChillerFailure, cfm::ObservationChannel::ChillerStatus, usable_value(code));
    CT_REQUIRE(reading.witness != nullptr);
    CT_CHECK_MSG(reading.triggered == (code >= 1),
                 "ChillerStatus StatusDegraded must trigger at state code 1 and above, code " +
                     std::to_string(code));
    CT_CHECK_MSG(reading.contradicting == (code < 1),
                 "ChillerStatus StatusDegraded must contradict at state code 0, code " +
                     std::to_string(code));
  }

  // A status channel with no reading at all proves nothing.
  cfm::WitnessInputs absent;
  absent.usable = true;
  const cfm::WitnessReading no_reading = cfm::evaluate_witness(
      cfm::FailureClass::PumpFailure, cfm::ObservationChannel::PumpStatus, absent);
  CT_CHECK(!no_reading.triggered);
  CT_CHECK(!no_reading.contradicting);
}

CT_TEST(classify_envelope_witnesses_need_a_declared_bound) {
  // BelowDeclaredFloor: the floor itself triggers, anything strictly above argues
  // against the class.
  {
    cfm::WitnessInputs inputs = usable_value(400);
    inputs.declared_floor = 400;
    inputs.has_floor = true;
    const cfm::WitnessReading at_floor = cfm::evaluate_witness(
        cfm::FailureClass::LoopDegradation, cfm::ObservationChannel::FlowMeter, inputs);
    CT_REQUIRE(at_floor.witness != nullptr);
    CT_CHECK(at_floor.triggered);
    CT_CHECK(!at_floor.contradicting);

    inputs.value = 401;
    const cfm::WitnessReading above = cfm::evaluate_witness(
        cfm::FailureClass::LoopDegradation, cfm::ObservationChannel::FlowMeter, inputs);
    CT_CHECK(!above.triggered);
    CT_CHECK(above.contradicting);

    // A declared floor is not a violated floor when the reading is absent.
    inputs.value = 0;
    inputs.has_value = false;
    const cfm::WitnessReading no_value = cfm::evaluate_witness(
        cfm::FailureClass::LoopDegradation, cfm::ObservationChannel::FlowMeter, inputs);
    CT_CHECK(!no_value.triggered);
    CT_CHECK(!no_value.contradicting);
  }

  // AboveDeclaredCeiling: the ceiling itself triggers.
  {
    cfm::WitnessInputs inputs = usable_value(22000);
    inputs.declared_ceiling = 22000;
    inputs.has_ceiling = true;
    const cfm::WitnessReading at_ceiling = cfm::evaluate_witness(
        cfm::FailureClass::ThermalRunaway, cfm::ObservationChannel::CoolantTemperature, inputs);
    CT_REQUIRE(at_ceiling.witness != nullptr);
    CT_CHECK(at_ceiling.triggered);
    CT_CHECK(!at_ceiling.contradicting);

    inputs.value = 21999;
    const cfm::WitnessReading below = cfm::evaluate_witness(
        cfm::FailureClass::ThermalRunaway, cfm::ObservationChannel::CoolantTemperature, inputs);
    CT_CHECK(!below.triggered);
    CT_CHECK(below.contradicting);

    inputs.has_value = false;
    const cfm::WitnessReading no_value = cfm::evaluate_witness(
        cfm::FailureClass::ThermalRunaway, cfm::ObservationChannel::CoolantTemperature, inputs);
    CT_CHECK(!no_value.triggered);
    CT_CHECK(!no_value.contradicting);
  }
}

CT_TEST(classify_outside_envelope_uses_every_declared_bound) {
  // Absolute pressure witnesses PressureFailure through OutsideDeclaredEnvelope.
  const cfm::FailureClass cls = cfm::FailureClass::PressureFailure;
  const cfm::ObservationChannel channel = cfm::ObservationChannel::AbsolutePressure;

  cfm::WitnessInputs floor_only = usable_value(999);
  floor_only.declared_floor = 1000;
  floor_only.has_floor = true;
  const cfm::WitnessReading below = cfm::evaluate_witness(cls, channel, floor_only);
  CT_REQUIRE(below.witness != nullptr);
  CT_CHECK(below.triggered);
  CT_CHECK(!below.contradicting);

  floor_only.value = 1000;
  const cfm::WitnessReading at_floor = cfm::evaluate_witness(cls, channel, floor_only);
  CT_CHECK(!at_floor.triggered);
  CT_CHECK(at_floor.contradicting);

  cfm::WitnessInputs ceiling_only = usable_value(1001);
  ceiling_only.declared_ceiling = 1000;
  ceiling_only.has_ceiling = true;
  const cfm::WitnessReading above = cfm::evaluate_witness(cls, channel, ceiling_only);
  CT_CHECK(above.triggered);
  CT_CHECK(!above.contradicting);

  ceiling_only.value = 1000;
  const cfm::WitnessReading at_ceiling = cfm::evaluate_witness(cls, channel, ceiling_only);
  CT_CHECK(!at_ceiling.triggered);
  CT_CHECK(at_ceiling.contradicting);

  cfm::WitnessInputs both = usable_value(500);
  both.declared_floor = 1000;
  both.declared_ceiling = 2000;
  both.has_floor = true;
  both.has_ceiling = true;
  CT_CHECK(cfm::evaluate_witness(cls, channel, both).triggered);

  both.value = 2500;
  CT_CHECK(cfm::evaluate_witness(cls, channel, both).triggered);

  both.value = 1500;
  const cfm::WitnessReading inside = cfm::evaluate_witness(cls, channel, both);
  CT_CHECK(!inside.triggered);
  CT_CHECK(inside.contradicting);

  // An envelope with no declared bound at all cannot be violated, and it cannot
  // be satisfied either.
  cfm::WitnessInputs bare = usable_value(0);
  bare.has_value = true;
  const cfm::WitnessReading undeclared = cfm::evaluate_witness(cls, channel, bare);
  CT_CHECK(!undeclared.triggered);
  CT_CHECK(!undeclared.contradicting);
}

CT_TEST(classify_undeclared_flow_floor_cannot_confirm_loop_loss) {
  // LoopLoss witnesses flow with Dead, which needs a value but no declared
  // bound - the reading alone decides. The sensitivity that matters is the
  // declared-floor classes: with no floor declared, a flow reading cannot
  // confirm LoopDegradation, and a suspect reading cannot confirm anything.
  cfm::WitnessInputs inputs = usable_value(0);
  inputs.has_value = true;
  const cfm::WitnessReading degradation = cfm::evaluate_witness(
      cfm::FailureClass::LoopDegradation, cfm::ObservationChannel::FlowMeter, inputs);
  CT_REQUIRE(degradation.witness != nullptr);
  CT_CHECK(!degradation.triggered);
  CT_CHECK(!degradation.contradicting);

  const cfm::WitnessReading loss =
      cfm::evaluate_witness(cfm::FailureClass::LoopLoss, cfm::ObservationChannel::FlowMeter, inputs);
  CT_CHECK(loss.triggered);

  // The pump flow witness is a declared-floor witness, so without a declared
  // floor it proves nothing even for a dead reading: the class can still be
  // confirmed through the pump status channel, which needs no declared bound.
  const cfm::WitnessReading pump = cfm::evaluate_witness(
      cfm::FailureClass::PumpFailure, cfm::ObservationChannel::FlowMeter, inputs);
  CT_REQUIRE(pump.witness != nullptr);
  CT_CHECK(!pump.triggered);
  CT_CHECK(!pump.contradicting);

  const cfm::WitnessReading pump_status = cfm::evaluate_witness(
      cfm::FailureClass::PumpFailure, cfm::ObservationChannel::PumpStatus, usable_value(2));
  CT_CHECK(pump_status.triggered);

  const cfm::WitnessReading capacity = cfm::evaluate_witness(
      cfm::FailureClass::ThermalCapacityLoss, cfm::ObservationChannel::ThermalCapacityMeter, inputs);
  CT_REQUIRE(capacity.witness != nullptr);
  CT_CHECK(!capacity.triggered);
  CT_CHECK(!capacity.contradicting);
}

CT_TEST(classify_unusable_reading_proves_nothing_in_either_direction) {
  // A suspect or bad sample is recorded evidence, but it is never a
  // confirmation and never a refutation. The check runs over every class and
  // every channel with inputs that would otherwise trigger, so no rule can
  // escape it.
  for (std::size_t class_index = 0; class_index < kClassCount; ++class_index) {
    for (std::size_t channel = 0; channel < kChannelCount; ++channel) {
      cfm::WitnessInputs inputs = usable_value(0);
      inputs.declared_floor = 1000;
      inputs.has_floor = true;
      inputs.declared_ceiling = -1000;
      inputs.has_ceiling = true;
      inputs.declared_demand = 1000;
      inputs.has_demand = true;
      inputs.leak = cfm::LeakState::LeakActive;
      inputs.usable = false;

      const cfm::WitnessReading reading =
          cfm::evaluate_witness(class_at(class_index), channel_at(channel), inputs);
      CT_CHECK_MSG(!reading.triggered, "an unusable reading triggered rule " +
                                           std::string(cfm::failure_rule(class_at(class_index)).rule_id));
      CT_CHECK_MSG(!reading.contradicting,
                   "an unusable reading contradicted rule " +
                       std::string(cfm::failure_rule(class_at(class_index)).rule_id));
    }
  }
}

CT_TEST(classify_leak_witness_uses_the_class_threshold) {
  struct Case {
    cfm::LeakState leak;
    bool triggered;
    bool contradicting;
  };
  // LeakSuspected is the threshold: LeakNone positively argues against a leak,
  // LeakUnknown says nothing at all.
  const Case leak_cases[] = {
      {cfm::LeakState::LeakUnknown, false, false},
      {cfm::LeakState::LeakNone, false, true},
      {cfm::LeakState::LeakSuspected, true, false},
      {cfm::LeakState::LeakConfirmed, true, false},
      {cfm::LeakState::LeakActive, true, false},
  };

  for (const Case& item : leak_cases) {
    cfm::WitnessInputs inputs;
    inputs.usable = true;
    inputs.leak = item.leak;
    const cfm::WitnessReading reading = cfm::evaluate_witness(
        cfm::FailureClass::Leak, cfm::ObservationChannel::LeakDetector, inputs);
    CT_REQUIRE(reading.witness != nullptr);
    CT_CHECK_MSG(reading.triggered == item.triggered,
                 "Leak rule at leak state " + std::to_string(static_cast<unsigned>(item.leak)));
    CT_CHECK_MSG(reading.contradicting == item.contradicting,
                 "Leak rule at leak state " + std::to_string(static_cast<unsigned>(item.leak)));
    CT_CHECK(!(reading.triggered && reading.contradicting));

    // The supporting leak witness of CduFailure evaluates the same way: the role
    // decides whether a confirmation may rest on it, not whether it fires.
    const cfm::WitnessReading supporting = cfm::evaluate_witness(
        cfm::FailureClass::CduFailure, cfm::ObservationChannel::LeakDetector, inputs);
    CT_REQUIRE(supporting.witness != nullptr);
    CT_CHECK_MSG(supporting.triggered == item.triggered,
                 "CduFailure supporting leak witness at leak state " +
                     std::to_string(static_cast<unsigned>(item.leak)));
  }
}

CT_TEST(classify_witness_lookup_is_exact_per_channel) {
  // A channel that the class does not name returns a null witness, so a caller
  // can tell "not a witness" from "witness that did not fire".
  const cfm::WitnessReading humidity = cfm::evaluate_witness(
      cfm::FailureClass::ThermalRunaway, cfm::ObservationChannel::HumiditySensor, usable_value(990000));
  CT_CHECK(humidity.witness == nullptr);
  CT_CHECK(!humidity.triggered);
  CT_CHECK(!humidity.contradicting);

  // AirflowLoss names the airflow channel twice. The lookup returns the first
  // entry in canonical order, which is the Direct Dead witness, so a dead meter
  // reports the strong signal rather than the weak one.
  const cfm::WitnessReading airflow = cfm::evaluate_witness(
      cfm::FailureClass::AirflowLoss, cfm::ObservationChannel::AirflowMeter, usable_value(0));
  CT_REQUIRE(airflow.witness != nullptr);
  CT_CHECK(airflow.witness->role == cfm::WitnessRole::Direct);
  CT_CHECK(airflow.witness->signal == cfm::NullSignal::Dead);
  CT_CHECK(airflow.triggered);

  // SharedSourceFailure has a supporting flow witness and no direct one: it is
  // confirmed by the attribution path, never by a local reading.
  const cfm::WitnessReading shared = cfm::evaluate_witness(
      cfm::FailureClass::SharedSourceFailure, cfm::ObservationChannel::FlowMeter, usable_value(0));
  CT_REQUIRE(shared.witness != nullptr);
  CT_CHECK(shared.witness->role == cfm::WitnessRole::Supporting);
  CT_CHECK(cfm::failure_rule(cfm::FailureClass::SharedSourceFailure).requires_direct_witness);
  for (std::size_t slot = 0;
       slot < cfm::failure_rule(cfm::FailureClass::SharedSourceFailure).witness_count; ++slot) {
    CT_CHECK(cfm::failure_rule(cfm::FailureClass::SharedSourceFailure).witnesses[slot].role !=
             cfm::WitnessRole::Direct);
  }

  // Every class and channel combination is total: it either names the class's
  // witness or reports none, and never both flips.
  for (std::size_t class_index = 0; class_index < kClassCount; ++class_index) {
    const cfm::FailureRule& rule = cfm::failure_rule(class_at(class_index));
    for (std::size_t channel = 0; channel < kChannelCount; ++channel) {
      const cfm::WitnessReading reading =
          cfm::evaluate_witness(class_at(class_index), channel_at(channel), usable_value(0));
      bool named = false;
      for (std::size_t slot = 0; slot < rule.witness_count; ++slot) {
        if (rule.witnesses[slot].channel == channel_at(channel)) {
          named = true;
        }
      }
      CT_CHECK_MSG((reading.witness != nullptr) == named,
                   "witness lookup disagrees with the table for rule " + std::string(rule.rule_id) +
                       " channel " + std::to_string(channel));
    }
  }

  // A class value outside the taxonomy is not classifiable: it declares no
  // witness, forces a restriction and escalates, so it can never be confirmed by
  // a reading and never silently ignored.
  const cfm::FailureRule& unknown = cfm::failure_rule(static_cast<cfm::FailureClass>(200));
  CT_CHECK_EQ(unknown.witness_count, static_cast<std::size_t>(0));
  CT_CHECK(unknown.forces_restriction);
  CT_CHECK(unknown.safety_escalation);
  for (std::size_t channel = 0; channel < kChannelCount; ++channel) {
    const cfm::WitnessReading reading = cfm::evaluate_witness(
        static_cast<cfm::FailureClass>(200), channel_at(channel), usable_value(0));
    CT_CHECK(reading.witness == nullptr);
    CT_CHECK(!reading.triggered);
    CT_CHECK(!reading.contradicting);
  }
}

CT_TEST(classify_channel_units_and_leak_channel_are_exact) {
  struct UnitCase {
    cfm::ObservationChannel channel;
    const char* unit;
  };
  const UnitCase cases[] = {
      {cfm::ObservationChannel::FlowMeter, "mL/s"},
      {cfm::ObservationChannel::AirflowMeter, "mL/s"},
      {cfm::ObservationChannel::DifferentialPressure, "Pa"},
      {cfm::ObservationChannel::AbsolutePressure, "Pa"},
      {cfm::ObservationChannel::CoolantTemperature, "mC"},
      {cfm::ObservationChannel::AirTemperature, "mC"},
      {cfm::ObservationChannel::HumiditySensor, "ppm"},
      {cfm::ObservationChannel::ThermalCapacityMeter, "W"},
      {cfm::ObservationChannel::ThermalLoadMeter, "W"},
      {cfm::ObservationChannel::ThermalMarginMeter, "mK"},
      {cfm::ObservationChannel::LeakDetector, ""},
      {cfm::ObservationChannel::PumpStatus, ""},
      {cfm::ObservationChannel::ValvePosition, ""},
      {cfm::ObservationChannel::ChillerStatus, ""},
      {cfm::ObservationChannel::CduStatus, ""},
      {cfm::ObservationChannel::CrahCracStatus, ""},
      {cfm::ObservationChannel::ContainmentSwitch, ""},
  };
  CT_CHECK_EQ(sizeof(cases) / sizeof(cases[0]), kChannelCount);
  for (const UnitCase& item : cases) {
    CT_CHECK_MSG(cfm::channel_unit(item.channel) == item.unit,
                 "channel " + std::to_string(static_cast<unsigned>(item.channel)) + " unit mismatch");
    CT_CHECK_MSG(cfm::channel_is_leak(item.channel) == (item.channel == cfm::ObservationChannel::LeakDetector),
                 "channel " + std::to_string(static_cast<unsigned>(item.channel)) +
                     " leak classification mismatch");
  }

  // A value outside the enumeration has no canonical unit and is not a leak
  // channel; it is never mistaken for a status channel with an empty unit.
  CT_CHECK(cfm::channel_unit(static_cast<cfm::ObservationChannel>(200)).empty());
  CT_CHECK(!cfm::channel_is_leak(static_cast<cfm::ObservationChannel>(200)));
}

CT_TEST(classify_envelope_bound_mapping_is_exact) {
  cfm::ScopePolicy policy;
  auto temperature = cfm::DeclaredQuantity::make(22000, "mC");
  auto margin = cfm::DeclaredQuantity::make(-500, "mK");
  auto flow = cfm::DeclaredQuantity::make(750, "mL/s");
  auto pressure = cfm::DeclaredQuantity::make(1200, "Pa");
  auto demand = cfm::DeclaredQuantity::make(50000, "W");
  CT_REQUIRE(temperature.has_value());
  CT_REQUIRE(margin.has_value());
  CT_REQUIRE(flow.has_value());
  CT_REQUIRE(pressure.has_value());
  CT_REQUIRE(demand.has_value());
  policy.envelope.max_supply_temperature = *temperature;
  policy.envelope.min_thermal_margin = *margin;
  policy.envelope.min_flow = *flow;
  policy.envelope.min_differential_pressure = *pressure;
  policy.envelope.declared_demand = *demand;

  const cfm::EnvelopeBound flow_bound =
      cfm::envelope_bound_for(policy, cfm::ObservationChannel::FlowMeter);
  CT_CHECK(flow_bound.has_floor);
  CT_CHECK_EQ(flow_bound.floor_value, static_cast<std::int64_t>(750));
  CT_CHECK(flow_bound.floor_unit == "mL/s");
  CT_CHECK(!flow_bound.has_ceiling);

  // Airflow shares the declared flow floor.
  const cfm::EnvelopeBound airflow_bound =
      cfm::envelope_bound_for(policy, cfm::ObservationChannel::AirflowMeter);
  CT_CHECK(airflow_bound.has_floor);
  CT_CHECK_EQ(airflow_bound.floor_value, static_cast<std::int64_t>(750));
  CT_CHECK(airflow_bound.floor_unit == "mL/s");

  // Both pressure channels read the single declared pressure floor, and an
  // absolute-pressure witness has no ceiling because the envelope declares none.
  for (const cfm::ObservationChannel channel :
       {cfm::ObservationChannel::DifferentialPressure, cfm::ObservationChannel::AbsolutePressure}) {
    const cfm::EnvelopeBound bound = cfm::envelope_bound_for(policy, channel);
    CT_CHECK(bound.has_floor);
    CT_CHECK_EQ(bound.floor_value, static_cast<std::int64_t>(1200));
    CT_CHECK(bound.floor_unit == "Pa");
    CT_CHECK(!bound.has_ceiling);
  }

  // Both temperature channels read the supply ceiling and declare no floor.
  for (const cfm::ObservationChannel channel :
       {cfm::ObservationChannel::CoolantTemperature, cfm::ObservationChannel::AirTemperature}) {
    const cfm::EnvelopeBound bound = cfm::envelope_bound_for(policy, channel);
    CT_CHECK(!bound.has_floor);
    CT_CHECK(bound.has_ceiling);
    CT_CHECK_EQ(bound.ceiling_value, static_cast<std::int64_t>(22000));
    CT_CHECK(bound.ceiling_unit == "mC");
  }

  const cfm::EnvelopeBound capacity_bound =
      cfm::envelope_bound_for(policy, cfm::ObservationChannel::ThermalCapacityMeter);
  CT_CHECK(capacity_bound.has_floor);
  CT_CHECK_EQ(capacity_bound.floor_value, static_cast<std::int64_t>(50000));
  CT_CHECK(capacity_bound.floor_unit == "W");

  const cfm::EnvelopeBound margin_bound =
      cfm::envelope_bound_for(policy, cfm::ObservationChannel::ThermalMarginMeter);
  CT_CHECK(margin_bound.has_floor);
  CT_CHECK_EQ(margin_bound.floor_value, static_cast<std::int64_t>(-500));
  CT_CHECK(margin_bound.floor_unit == "mK");

  const cfm::EnvelopeBound load_bound =
      cfm::envelope_bound_for(policy, cfm::ObservationChannel::ThermalLoadMeter);
  CT_CHECK(!load_bound.has_floor);
  CT_CHECK(load_bound.has_ceiling);
  CT_CHECK_EQ(load_bound.ceiling_value, static_cast<std::int64_t>(50000));
  CT_CHECK(load_bound.ceiling_unit == "W");

  // Channels with no declared bound report none at all, and never a zero limit.
  for (const cfm::ObservationChannel channel :
       {cfm::ObservationChannel::HumiditySensor, cfm::ObservationChannel::LeakDetector,
        cfm::ObservationChannel::PumpStatus, cfm::ObservationChannel::ValvePosition,
        cfm::ObservationChannel::ChillerStatus, cfm::ObservationChannel::CduStatus,
        cfm::ObservationChannel::CrahCracStatus, cfm::ObservationChannel::ContainmentSwitch}) {
    const cfm::EnvelopeBound bound = cfm::envelope_bound_for(policy, channel);
    CT_CHECK(!bound.has_floor);
    CT_CHECK(!bound.has_ceiling);
  }

  // An envelope with nothing declared yields no bound anywhere.
  const cfm::ScopePolicy empty_policy;
  for (std::size_t channel = 0; channel < kChannelCount; ++channel) {
    const cfm::EnvelopeBound bound = cfm::envelope_bound_for(empty_policy, channel_at(channel));
    CT_CHECK(!bound.has_floor);
    CT_CHECK(!bound.has_ceiling);
  }
}

CT_TEST(classify_channel_threshold_requires_unit_agreement) {
  cfm::ScopePolicy policy;
  auto flow = cfm::DeclaredQuantity::make(750, "mL/s");
  CT_REQUIRE(flow.has_value());
  policy.envelope.min_flow = *flow;
  auto temperature = cfm::DeclaredQuantity::make(22000, "mC");
  CT_REQUIRE(temperature.has_value());
  policy.envelope.max_supply_temperature = *temperature;

  const cfm::ChannelThreshold flow_threshold =
      cfm::channel_threshold(policy, cfm::ObservationChannel::FlowMeter);
  CT_CHECK(flow_threshold.has_threshold);
  CT_CHECK_EQ(flow_threshold.threshold, static_cast<std::int64_t>(750));
  CT_CHECK(flow_threshold.unit == "mL/s");

  const cfm::ChannelThreshold airflow_threshold =
      cfm::channel_threshold(policy, cfm::ObservationChannel::AirflowMeter);
  CT_CHECK(airflow_threshold.has_threshold);
  CT_CHECK_EQ(airflow_threshold.threshold, static_cast<std::int64_t>(750));

  const cfm::ChannelThreshold temperature_threshold =
      cfm::channel_threshold(policy, cfm::ObservationChannel::CoolantTemperature);
  CT_CHECK(temperature_threshold.has_threshold);
  CT_CHECK_EQ(temperature_threshold.threshold, static_cast<std::int64_t>(22000));
  CT_CHECK(temperature_threshold.unit == "mC");

  // An undeclared bound is no threshold, and the channel's canonical unit is
  // still reported.
  const cfm::ChannelThreshold pressure_threshold =
      cfm::channel_threshold(policy, cfm::ObservationChannel::DifferentialPressure);
  CT_CHECK(!pressure_threshold.has_threshold);
  CT_CHECK(pressure_threshold.unit == "Pa");

  // A declared value in a unit that is not the channel's unit is not a threshold
  // for that channel: this component never converts between units.
  cfm::ScopePolicy mismatched;
  auto margin_in_flow_slot = cfm::DeclaredQuantity::make(500, "mK");
  CT_REQUIRE(margin_in_flow_slot.has_value());
  mismatched.envelope.min_flow = *margin_in_flow_slot;
  const cfm::ChannelThreshold mismatched_threshold =
      cfm::channel_threshold(mismatched, cfm::ObservationChannel::FlowMeter);
  CT_CHECK(!mismatched_threshold.has_threshold);
  CT_CHECK(mismatched_threshold.unit == "mL/s");

  // Status and leak channels never carry a scalar threshold.
  for (const cfm::ObservationChannel channel :
       {cfm::ObservationChannel::LeakDetector, cfm::ObservationChannel::PumpStatus,
        cfm::ObservationChannel::ContainmentSwitch}) {
    const cfm::ChannelThreshold threshold = cfm::channel_threshold(policy, channel);
    CT_CHECK(!threshold.has_threshold);
    CT_CHECK(threshold.unit.empty());
  }
}

CT_TEST(classify_indices_agree_with_the_enumerations) {
  for (std::size_t index = 0; index < kChannelCount; ++index) {
    CT_CHECK_EQ(cfm::channel_index(channel_at(index)), index);
  }
  for (std::size_t index = 0; index < kClassCount; ++index) {
    CT_CHECK_EQ(cfm::failure_class_index(class_at(index)), index);
  }
  for (std::size_t index = 0; index < cfm::response_action_count(); ++index) {
    CT_CHECK_EQ(cfm::response_action_index(static_cast<cfm::ResponseAction>(index)), index);
  }
  for (std::size_t index = 0; index < cfm::recovery_gate_count(); ++index) {
    CT_CHECK_EQ(cfm::recovery_gate_index(static_cast<cfm::RecoveryGate>(index)), index);
  }
  for (std::size_t index = 0; index < cfm::restriction_kind_count(); ++index) {
    CT_CHECK_EQ(cfm::restriction_kind_index(static_cast<cfm::RestrictionKind>(index)), index);
  }

  // The count helpers and the enumerator-derived cardinalities agree, which is
  // what makes an index usable as a table key.
  CT_CHECK_EQ(cfm::observation_channel_count(), kChannelCount);
  CT_CHECK_EQ(cfm::failure_class_count(), kClassCount);
  CT_CHECK_EQ(static_cast<std::size_t>(cfm::ResponseAction::ManualIntervention) + 1u,
              cfm::response_action_count());
  CT_CHECK_EQ(static_cast<std::size_t>(cfm::RecoveryGate::HysteresisElapsed) + 1u,
              cfm::recovery_gate_count());
  CT_CHECK_EQ(static_cast<std::size_t>(cfm::RestrictionKind::ManualHold) + 1u,
              cfm::restriction_kind_count());
  CT_CHECK_EQ(static_cast<std::size_t>(cfm::FailureClass::ThermalRunaway) + 1u, kClassCount);
  CT_CHECK_EQ(static_cast<std::size_t>(cfm::ObservationChannel::HumiditySensor) + 1u, kChannelCount);

  // Every channel of the canonical order is the enumerator of its index.
  const cfm::ObservationChannel* order = cfm::observation_channel_order();
  CT_REQUIRE(order != nullptr);
  for (std::size_t index = 0; index < kChannelCount; ++index) {
    CT_CHECK_EQ(static_cast<std::size_t>(order[index]), index);
  }
  for (std::size_t index = 0; index < cfm::response_action_count(); ++index) {
    CT_CHECK_EQ(static_cast<std::size_t>(cfm::response_action_order()[index]), index);
  }
  for (std::size_t index = 0; index < cfm::recovery_gate_count(); ++index) {
    CT_CHECK_EQ(static_cast<std::size_t>(cfm::recovery_gate_order()[index]), index);
  }
  for (std::size_t index = 0; index < cfm::restriction_kind_count(); ++index) {
    CT_CHECK_EQ(static_cast<std::size_t>(cfm::restriction_kind_order()[index]), index);
  }
}

CT_TEST(classify_randomized_witness_outcomes_are_never_ambiguous) {
  const std::uint64_t seed = ct_test::case_seed("classify_randomized_witness_outcomes_are_never_ambiguous");
  ct_test::Rng rng(seed);
  ct_test::report_note("seed=" + std::to_string(seed) + " iterations=20000");

  for (std::uint32_t iteration = 0; iteration < 20000; ++iteration) {
    const std::size_t class_index = rng.below(static_cast<std::uint32_t>(kClassCount));
    const std::size_t channel = rng.below(static_cast<std::uint32_t>(kChannelCount));

    cfm::WitnessInputs inputs;
    inputs.value = static_cast<std::int64_t>(rng.below(2001)) - 1000;
    inputs.has_value = rng.chance(4, 5);
    inputs.declared_floor = static_cast<std::int64_t>(rng.below(2001)) - 1000;
    inputs.has_floor = rng.chance(2, 3);
    inputs.declared_ceiling = static_cast<std::int64_t>(rng.below(2001)) - 1000;
    inputs.has_ceiling = rng.chance(2, 3);
    inputs.declared_demand = static_cast<std::int64_t>(rng.below(2001)) - 1000;
    inputs.has_demand = rng.chance(1, 2);
    inputs.leak = static_cast<cfm::LeakState>(rng.below(5));
    inputs.usable = rng.chance(3, 4);

    const cfm::FailureClass failure_class = class_at(class_index);
    const cfm::ObservationChannel observation_channel = channel_at(channel);
    const cfm::WitnessReading reading =
        cfm::evaluate_witness(failure_class, observation_channel, inputs);

    const std::string parameters =
        " rule=" + std::string(cfm::failure_rule(failure_class).rule_id) +
        " channel=" + std::to_string(channel) + " value=" + std::to_string(inputs.value) +
        " has_value=" + std::to_string(inputs.has_value) +
        " floor=" + std::to_string(inputs.has_floor ? inputs.declared_floor : 0) +
        " has_floor=" + std::to_string(inputs.has_floor) +
        " ceiling=" + std::to_string(inputs.has_ceiling ? inputs.declared_ceiling : 0) +
        " has_ceiling=" + std::to_string(inputs.has_ceiling) +
        " leak=" + std::to_string(static_cast<unsigned>(inputs.leak)) +
        " usable=" + std::to_string(inputs.usable) + " iteration=" + std::to_string(iteration);

    CT_CHECK_MSG(!(reading.triggered && reading.contradicting),
                 "a witness reported both triggered and contradicting:" + parameters);
    if (!inputs.usable) {
      CT_CHECK_MSG(!reading.triggered, "an unusable reading triggered:" + parameters);
      CT_CHECK_MSG(!reading.contradicting, "an unusable reading contradicted:" + parameters);
    }
    if (reading.witness == nullptr) {
      CT_CHECK_MSG(!reading.triggered && !reading.contradicting,
                   "a channel that is not a witness produced a verdict:" + parameters);
    }
  }
}
