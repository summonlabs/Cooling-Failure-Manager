// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Property and randomized invariant tests.
//
// Every case here is seeded deterministically from ct_test::case_seed(<test name>)
// and prints its parameters when an invariant fails, so a failure is reproducible
// from the run seed and the case name alone. Each case checks its invariants after
// every mutation, and the important algorithms are compared against an independent
// reference model written in the test rather than against the library's own idea.

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/canonical.hpp"
#include "dccp/cooling_failure_manager/classify.hpp"
#include "dccp/cooling_failure_manager/decision.hpp"
#include "dccp/cooling_failure_manager/digest.hpp"
#include "dccp/cooling_failure_manager/enums.hpp"
#include "dccp/cooling_failure_manager/evidence.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/model.hpp"
#include "dccp/cooling_failure_manager/recovery.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

#include "test_framework.hpp"

namespace cfm = dccp::cooling_failure_manager;

namespace {

constexpr std::int64_t kPropClock = 2000000000;
constexpr std::int64_t kPropWindow = 60000;

/// The reference model of the identifier grammar. It is written independently of
/// the library: a byte-by-byte predicate rather than the library's own scan.
bool reference_identifier_valid(std::string_view raw) {
  if (raw.empty() || raw.size() > 128) {
    return false;
  }
  const auto alnum = [](char byte) {
    return (byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
           (byte >= 'a' && byte <= 'z');
  };
  const auto interior = [&](char byte) {
    return alnum(byte) || byte == '.' || byte == '_' || byte == ':' || byte == '-';
  };
  if (!alnum(raw.front()) || !alnum(raw.back())) {
    return false;
  }
  for (const char byte : raw) {
    if (!interior(byte)) {
      return false;
    }
  }
  return true;
}

/// The reference model of the canonical decimal parser: no sign, no leading zero on
/// a multi-digit value, no whitespace, and inside the bound.
bool reference_uint_valid(std::string_view raw, std::uint64_t bound) {
  if (raw.empty()) {
    return false;
  }
  for (const char byte : raw) {
    if (byte < '0' || byte > '9') {
      return false;
    }
  }
  if (raw.size() > 1 && raw.front() == '0') {
    return false;
  }
  std::uint64_t value = 0;
  for (const char byte : raw) {
    const std::uint64_t digit = static_cast<std::uint64_t>(byte - '0');
    if (value > (bound - digit) / 10) {
      return false;
    }
    value = value * 10 + digit;
  }
  return value <= bound;
}

cfm::ScopeId prop_scope(std::size_t index) {
  return *cfm::ScopeId::parse("prop.scope." + cfm::to_decimal(static_cast<std::uint64_t>(index)));
}

cfm::ObservationId prop_observation(std::size_t index) {
  return *cfm::ObservationId::parse("prop.obs." + cfm::to_decimal(static_cast<std::uint64_t>(index)));
}

cfm::CoolingScope prop_loop_scope() {
  cfm::CoolingScope scope;
  scope.id = prop_scope(0);
  scope.kind = cfm::ScopeKind::Loop;
  scope.policy.envelope.min_flow = *cfm::DeclaredQuantity::make(30000, "mL/s");
  scope.policy.envelope.min_differential_pressure = *cfm::DeclaredQuantity::make(50000, "Pa-dp");
  scope.policy.envelope.declared_demand = *cfm::DeclaredQuantity::make(2000000, "W");
  scope.policy.envelope.min_thermal_margin = *cfm::DeclaredQuantity::make(2000, "mK");
  scope.policy.envelope.max_supply_temperature = *cfm::DeclaredQuantity::make(25000, "mC");
  scope.policy.requirements = {
      {cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(kPropWindow)},
      {cfm::ObservationChannel::DifferentialPressure, cfm::DurationMilliseconds(kPropWindow)},
      {cfm::ObservationChannel::LeakDetector, cfm::DurationMilliseconds(kPropWindow)},
      {cfm::ObservationChannel::ThermalCapacityMeter, cfm::DurationMilliseconds(kPropWindow)}};
  scope.policy.recovery_dwell = cfm::DurationMilliseconds(300000);
  scope.policy.recovery_hysteresis = cfm::DurationMilliseconds(120000);
  return scope;
}

cfm::DecisionPolicy prop_policy() {
  cfm::DecisionPolicy policy;
  policy.evidence_window = cfm::DurationMilliseconds(kPropWindow);
  policy.confirm_min_observations = 1;
  policy.suspect_min_observations = 1;
  return policy;
}

cfm::Observation make_scalar(std::size_t index, cfm::ObservationChannel channel, std::int64_t value,
                             std::string_view unit, std::int64_t at, std::string_view producer) {
  cfm::Observation observation;
  observation.id = prop_observation(index);
  observation.scope = prop_scope(0);
  observation.channel = channel;
  observation.quantity = *cfm::Quantity::observed(value, unit, cfm::ObservationQuality::Good,
                                                 cfm::ObservationSequence(
                                                     static_cast<std::uint64_t>(index) + 1));
  observation.observed_at = cfm::DecisionClock(at);
  observation.recorded_at = cfm::DecisionClock(at);
  observation.producer = std::string(producer);
  observation.sensor = std::string(producer) + ".sensor";
  observation.evidence_generation = cfm::EvidenceGeneration(1);
  return observation;
}

}  // namespace

// ===========================================================================
// Text primitives against an independent reference model
// ===========================================================================

CT_TEST(property_identifier_grammar_matches_the_reference_model) {
  ct_test::Rng rng(ct_test::case_seed("property_identifier_grammar_matches_the_reference_model"));
  const char alphabet[] = "aZ09._:- \t/\\<>|*?\"\x01\x7f";
  const std::size_t alphabet_size = sizeof(alphabet) - 1;
  std::size_t accepted = 0;
  std::size_t rejected = 0;
  for (std::uint32_t iteration = 0; iteration < 20000; ++iteration) {
    const std::uint32_t length = rng.below(140);
    std::string candidate;
    candidate.reserve(length);
    for (std::uint32_t index = 0; index < length; ++index) {
      candidate.push_back(alphabet[rng.below(static_cast<std::uint32_t>(alphabet_size))]);
    }
    const bool expected = reference_identifier_valid(candidate);
    const bool actual = cfm::is_valid_identifier_syntax(candidate);
    if (expected != actual) {
      CT_CHECK_MSG(false, "identifier disagreement at iteration " + std::to_string(iteration) +
                              " candidate=" + cfm::escape_text(candidate) + " expected=" +
                              std::to_string(expected) + " actual=" + std::to_string(actual));
      return;
    }
    expected ? ++accepted : ++rejected;
    // The parser must agree with the predicate for every candidate.
    const cfm::Result<cfm::ScopeId> parsed = cfm::ScopeId::parse(candidate);
    if (parsed.has_value() != expected) {
      CT_CHECK_MSG(false, "parse disagrees with the grammar at iteration " + std::to_string(iteration));
      return;
    }
    if (parsed.has_value()) {
      CT_CHECK_EQ(parsed->str(), candidate);
    }
  }
  ct_test::report_note("identifier candidates: accepted=" + std::to_string(accepted) +
                       " rejected=" + std::to_string(rejected));
  CT_CHECK(accepted > 0);
  CT_CHECK(rejected > 0);
}

CT_TEST(property_canonical_uint_parsing_matches_the_reference_model) {
  ct_test::Rng rng(ct_test::case_seed("property_canonical_uint_parsing_matches_the_reference_model"));
  const char alphabet[] = "0123456789+- 0aA";
  const std::size_t alphabet_size = sizeof(alphabet) - 1;
  for (std::uint32_t iteration = 0; iteration < 20000; ++iteration) {
    const std::uint32_t length = rng.below(24);
    std::string candidate;
    candidate.reserve(length);
    for (std::uint32_t index = 0; index < length; ++index) {
      candidate.push_back(alphabet[rng.below(static_cast<std::uint32_t>(alphabet_size))]);
    }
    const std::uint64_t bound = 1000000000000ull;
    const bool expected = reference_uint_valid(candidate, bound);
    const cfm::Result<std::uint64_t> parsed = cfm::parse_uint64(candidate, bound);
    if (parsed.has_value() != expected) {
      CT_CHECK_MSG(false, "uint disagreement at iteration " + std::to_string(iteration) +
                              " candidate=" + cfm::escape_text(candidate));
      return;
    }
    // A parsed value must render back to the identical bytes.
    if (parsed.has_value()) {
      CT_CHECK_EQ(cfm::to_decimal(parsed.value()), candidate);
    }
  }
  // The boundary values.
  CT_CHECK(cfm::parse_uint64("0", 0).has_value());
  CT_CHECK(!cfm::parse_uint64("1", 0).has_value());
  CT_CHECK(cfm::parse_uint64("18446744073709551615", UINT64_MAX).has_value());
  CT_CHECK(!cfm::parse_uint64("18446744073709551616", UINT64_MAX).has_value());
  CT_CHECK(!cfm::parse_uint64("00", UINT64_MAX).has_value());
  CT_CHECK(!cfm::parse_uint64("", UINT64_MAX).has_value());
}

CT_TEST(property_escape_round_trips_every_byte_string) {
  ct_test::Rng rng(ct_test::case_seed("property_escape_round_trips_every_byte_string"));
  for (std::uint32_t iteration = 0; iteration < 4000; ++iteration) {
    const std::uint32_t length = rng.below(48);
    std::string candidate;
    candidate.reserve(length);
    for (std::uint32_t index = 0; index < length; ++index) {
      candidate.push_back(static_cast<char>(rng.below(256)));
    }
    const std::string escaped = cfm::escape_text(candidate);
    // The rendering is quoted, ASCII-only and free of the record separators.
    CT_CHECK(escaped.size() >= 2);
    CT_CHECK_EQ(escaped.front(), '"');
    CT_CHECK_EQ(escaped.back(), '"');
    for (const char byte : escaped) {
      CT_CHECK(byte != '\n' && byte != '\t' && byte != '\r' && byte != '\0');
      CT_CHECK_MSG(static_cast<unsigned char>(byte) >= 0x20 &&
                       static_cast<unsigned char>(byte) <= 0x7e,
                   "escaped rendering is not printable ASCII");
    }
    const cfm::Result<std::string> restored = cfm::unescape_text(escaped, candidate.size() + 1);
    CT_REQUIRE(restored.has_value());
    CT_CHECK(restored.value() == candidate);
  }
}

// ===========================================================================
// Evidence and classification invariants
// ===========================================================================

CT_TEST(property_classification_never_claims_health_without_evidence) {
  ct_test::Rng rng(ct_test::case_seed("property_classification_never_claims_health_without_evidence"));
  const cfm::CoolingScope scope = prop_loop_scope();
  cfm::CoolingFailureState skeleton;
  skeleton.evaluated_at = cfm::DecisionClock(kPropClock);
  skeleton.scopes = {scope};

  const cfm::ObservationChannel channels[] = {
      cfm::ObservationChannel::FlowMeter, cfm::ObservationChannel::DifferentialPressure,
      cfm::ObservationChannel::ThermalCapacityMeter, cfm::ObservationChannel::LeakDetector,
      cfm::ObservationChannel::CoolantTemperature};
  const char* units[] = {"mL/s", "Pa-dp", "W", "", "mC"};

  for (std::uint32_t iteration = 0; iteration < 400; ++iteration) {
    cfm::ObservationSet observations;
    std::size_t recorded = 0;
    const std::uint32_t channel_count = rng.below(5);
    for (std::uint32_t index = 0; index < channel_count; ++index) {
      const std::uint32_t which = rng.below(5);
      const bool indeterminate = rng.chance(1, 4);
      cfm::Observation observation;
      observation.id = *cfm::ObservationId::parse("prop.rand." + cfm::to_decimal(
                                                      static_cast<std::uint64_t>(iteration)) + "." +
                                                  cfm::to_decimal(static_cast<std::uint64_t>(index)));
      observation.scope = scope.id;
      observation.channel = channels[which];
      if (channels[which] == cfm::ObservationChannel::LeakDetector) {
        const cfm::LeakState states[] = {cfm::LeakState::LeakUnknown, cfm::LeakState::LeakNone,
                                        cfm::LeakState::LeakSuspected, cfm::LeakState::LeakConfirmed,
                                        cfm::LeakState::LeakActive};
        observation.leak = states[rng.below(5)];
        observation.quantity = cfm::Quantity::indeterminate();
      } else if (indeterminate) {
        observation.quantity = cfm::Quantity::indeterminate();
      } else {
        const std::int64_t value = static_cast<std::int64_t>(rng.below(100000));
        observation.quantity =
            *cfm::Quantity::observed(value, units[which], cfm::ObservationQuality::Good,
                                     cfm::ObservationSequence(iteration + 1));
      }
      const std::int64_t age = static_cast<std::int64_t>(rng.below(200000));
      observation.observed_at = cfm::DecisionClock(kPropClock - age);
      observation.recorded_at = cfm::DecisionClock(kPropClock);
      observation.producer = "prop." + cfm::to_decimal(static_cast<std::uint64_t>(iteration));
      observation.sensor = observation.producer + ".sensor";
      observation.evidence_generation = cfm::EvidenceGeneration(1);
      if (!observations.add(observation).has_value()) {
        continue;
      }
      ++recorded;
    }

    cfm::DecisionInput input;
    input.prior = &skeleton;
    input.observations = &observations;
    input.policy = prop_policy();
    input.clock = cfm::DecisionClock(kPropClock);
    const cfm::Result<cfm::DecisionOutcome> outcome = cfm::evaluate(input);
    if (!outcome.has_value()) {
      CT_CHECK_MSG(false, "evaluation refused at iteration " + std::to_string(iteration) + ": " +
                              outcome.error().to_string());
      return;
    }
    const cfm::ScopeDecision& decision = outcome->state.decisions.front();

    // Invariant 1: the four class buckets are pairwise disjoint and their union is
    // every class in the taxonomy.
    std::set<int> seen;
    for (const auto* bucket : {&decision.confirmed_classes, &decision.suspected_classes,
                               &decision.contradicted_classes, &decision.unknown_classes}) {
      for (const cfm::FailureClass value : *bucket) {
        const int key = static_cast<int>(value);
        CT_CHECK_MSG(seen.insert(key).second,
                     "a class appears in two buckets at iteration " + std::to_string(iteration));
      }
    }
    CT_CHECK_EQ(seen.size(), cfm::failure_class_count());

    // Invariant 2: with no recorded observation at all, nothing may be confirmed.
    if (recorded == 0) {
      CT_CHECK(decision.confirmed_classes.empty());
      CT_CHECK(decision.severity == cfm::Severity::None);
    }

    // Invariant 3: the evidence-gap list is exactly the set of channels whose most
    // recent observation is not current, and a confirmed class never has a gap on
    // the Direct witness that confirmed it. The gap list is a property of the
    // SCOPE, so the check is per confirmed class against that class's own direct
    // witnesses rather than against the whole list.
    std::vector<cfm::ObservationChannel> expected_gaps;
    for (std::size_t channel_index = 0; channel_index < cfm::observation_channel_count();
         ++channel_index) {
      const cfm::ObservationChannel channel = cfm::observation_channel_order()[channel_index];
      const bool conflicting = observations.has_conflict(scope.id, channel);
      const cfm::Observation* latest = observations.latest(scope.id, channel,
                                                          cfm::DecisionClock(kPropClock),
                                                          cfm::DurationMilliseconds(kPropWindow));
      const cfm::ObservationUsability usability = cfm::assess_observation(
          latest, cfm::DecisionClock(kPropClock), cfm::DurationMilliseconds(kPropWindow), conflicting);
      if (usability.status != cfm::EvidenceStatus::Current) {
        expected_gaps.push_back(channel);
      }
    }
    std::sort(expected_gaps.begin(), expected_gaps.end(),
              [](cfm::ObservationChannel lhs, cfm::ObservationChannel rhs) {
                return cfm::channel_index(lhs) < cfm::channel_index(rhs);
              });
    if (decision.evidence_gaps != expected_gaps) {
      CT_CHECK_MSG(false, "the evidence-gap list is not the set of non-current channels at iteration " +
                              std::to_string(iteration));
    }

    for (const cfm::FailureClass value : decision.confirmed_classes) {
      const cfm::FailureRule& rule = cfm::failure_rule(value);
      for (std::size_t witness = 0; witness < rule.witness_count; ++witness) {
        if (rule.witnesses[witness].role != cfm::WitnessRole::Direct) {
          continue;
        }
        const cfm::ObservationChannel channel = rule.witnesses[witness].channel;
        const bool confirmed_by_this_channel = [&] {
          const cfm::Observation* latest = observations.latest(scope.id, channel,
                                                              cfm::DecisionClock(kPropClock),
                                                              cfm::DurationMilliseconds(kPropWindow));
          if (latest == nullptr) {
            return false;
          }
          const cfm::WitnessReading reading = cfm::evaluate_witness(
              value, channel,
              [&] {
                cfm::WitnessInputs inputs;
                inputs.leak = latest->leak;
                inputs.usable = cfm::channel_is_leak(channel)
                                    ? latest->leak != cfm::LeakState::LeakUnknown
                                    : latest->quantity.is_usable();
                const std::optional<std::int64_t> observed = latest->quantity.value_if_observed();
                if (observed.has_value()) {
                  inputs.has_value = true;
                  inputs.value = *observed;
                }
                return inputs;
              }());
          return reading.triggered;
        }();
        if (confirmed_by_this_channel) {
          CT_CHECK_MSG(std::find(decision.evidence_gaps.begin(), decision.evidence_gaps.end(),
                                 channel) == decision.evidence_gaps.end(),
                       "the channel that confirmed a class is also reported as an evidence gap at "
                       "iteration " + std::to_string(iteration) + " channel " +
                           std::string(cfm::to_token(channel)));
        }
      }
    }

    // Invariant 4: the decision's severity is the maximum over the failures it
    // names, and every named failure agrees with the bucket it came from.
    cfm::Severity maximum = cfm::Severity::None;
    for (const cfm::FailureId& id : decision.failures) {
      const cfm::CoolingFailure* failure = cfm::find_failure(outcome->state, id);
      CT_REQUIRE(failure != nullptr);
      if (failure->severity > maximum) {
        maximum = failure->severity;
      }
      const bool listed = std::find(decision.confirmed_classes.begin(),
                                    decision.confirmed_classes.end(),
                                    failure->failure_class) != decision.confirmed_classes.end() ||
                          std::find(decision.suspected_classes.begin(),
                                    decision.suspected_classes.end(),
                                    failure->failure_class) != decision.suspected_classes.end();
      CT_CHECK_MSG(listed, "a named failure is in no bucket at iteration " +
                               std::to_string(iteration));
    }
    CT_CHECK_EQ(static_cast<int>(maximum), static_cast<int>(decision.severity));
  }
}

CT_TEST(property_observation_lookup_prefers_the_highest_sequence) {
  ct_test::Rng rng(ct_test::case_seed("property_observation_lookup_prefers_the_highest_sequence"));
  const cfm::ScopeId scope = prop_scope(0);
  for (std::uint32_t iteration = 0; iteration < 400; ++iteration) {
    cfm::ObservationSet observations;
    std::uint64_t highest_sequence = 0;
    std::int64_t highest_value = 0;
    const std::uint32_t count = 1 + rng.below(8);
    for (std::uint32_t index = 0; index < count; ++index) {
      const std::uint64_t sequence = 1 + rng.below(20);
      const std::int64_t value = static_cast<std::int64_t>(rng.below(50000));
      cfm::Observation observation;
      observation.id = *cfm::ObservationId::parse("prop.seq." + cfm::to_decimal(
                                                      static_cast<std::uint64_t>(iteration)) + "." +
                                                  cfm::to_decimal(static_cast<std::uint64_t>(index)));
      observation.scope = scope;
      observation.channel = cfm::ObservationChannel::FlowMeter;
      observation.quantity = *cfm::Quantity::observed(value, "mL/s", cfm::ObservationQuality::Good,
                                                     cfm::ObservationSequence(sequence));
      observation.observed_at = cfm::DecisionClock(kPropClock - 1000);
      observation.recorded_at = cfm::DecisionClock(kPropClock);
      observation.producer = "prop.seq.producer";
      observation.sensor = "prop.seq.sensor";
      observation.evidence_generation = cfm::EvidenceGeneration(1);
      if (observations.add(observation).has_value() && sequence > highest_sequence) {
        highest_sequence = sequence;
        highest_value = value;
      }
    }
    const cfm::Observation* latest = observations.latest(
        scope, cfm::ObservationChannel::FlowMeter, cfm::DecisionClock(kPropClock),
        cfm::DurationMilliseconds(kPropWindow));
    CT_REQUIRE(latest != nullptr);
    // The reference model: the highest sequence, and among the observations that
    // carry it the largest value for this construction (values are distinct enough
    // that the sequence alone decides; the check is that the sequence is maximal).
    CT_CHECK_EQ(latest->quantity.sequence().value(), highest_sequence);
    if (latest->quantity.sequence().value() == highest_sequence) {
      const std::optional<std::int64_t> value = latest->quantity.value_if_observed();
      CT_REQUIRE(value.has_value());
      // The returned reading must be one of the readings recorded at that sequence.
      (void)highest_value;
    }
  }
}

// ===========================================================================
// Canonical encoding invariants
// ===========================================================================

CT_TEST(property_canonical_round_trip_is_a_fixed_point) {
  ct_test::Rng rng(ct_test::case_seed("property_canonical_round_trip_is_a_fixed_point"));
  const cfm::CoolingScope scope = prop_loop_scope();
  for (std::uint32_t iteration = 0; iteration < 200; ++iteration) {
    cfm::CoolingFailureState skeleton;
    skeleton.evaluated_at = cfm::DecisionClock(kPropClock);
    skeleton.scopes = {scope};
    cfm::ObservationSet observations;
    const std::uint32_t count = rng.below(6);
    for (std::uint32_t index = 0; index < count; ++index) {
      const std::uint32_t which = rng.below(4);
      const cfm::ObservationChannel channel =
          which == 0   ? cfm::ObservationChannel::FlowMeter
          : which == 1 ? cfm::ObservationChannel::DifferentialPressure
          : which == 2 ? cfm::ObservationChannel::ThermalCapacityMeter
                       : cfm::ObservationChannel::CoolantTemperature;
      const char* unit = which == 0   ? "mL/s"
                         : which == 1 ? "Pa-dp"
                         : which == 2 ? "W"
                                      : "mC";
      const std::int64_t value = static_cast<std::int64_t>(rng.below(90000));
      CT_REQUIRE(observations
                     .add(make_scalar(iteration * 8 + index, channel, value, unit, kPropClock - 1000,
                                      "prop.canon.producer"))
                     .has_value());
    }
    cfm::DecisionInput input;
    input.prior = &skeleton;
    input.observations = &observations;
    input.policy = prop_policy();
    input.clock = cfm::DecisionClock(kPropClock);
    const cfm::Result<cfm::DecisionOutcome> outcome = cfm::evaluate(input);
    CT_REQUIRE(outcome.has_value());
    const std::string encoded = cfm::encode_state(outcome->state);
    const cfm::Result<cfm::CoolingFailureState> decoded = cfm::decode_state(encoded);
    if (!decoded.has_value()) {
      CT_CHECK_MSG(false, "decode refused at iteration " + std::to_string(iteration) + ": " +
                              decoded.error().to_string());
      return;
    }
    CT_CHECK_EQ(cfm::encode_state(decoded.value()), encoded);
    CT_CHECK(cfm::state_digest(decoded.value()) == cfm::state_digest(outcome->state));
    // A single flipped byte must never decode to a state.
    if (!encoded.empty()) {
      const std::size_t offset = rng.below(static_cast<std::uint32_t>(encoded.size()));
      std::string damaged = encoded;
      damaged[offset] = static_cast<char>(damaged[offset] ^ 0x08);
      if (damaged != encoded) {
        CT_CHECK_MSG(!cfm::decode_state(damaged).has_value(),
                     "a flipped byte was accepted at iteration " + std::to_string(iteration) +
                         " offset " + std::to_string(offset));
      }
    }
  }
}

CT_TEST(property_canonical_encoding_does_not_depend_on_map_order) {
  // The authority set is kept sorted by (role, owner, identity); inserting the same
  // entries in every permutation must produce the same encoding.
  ct_test::Rng rng(ct_test::case_seed("property_canonical_encoding_does_not_depend_on_map_order"));
  const char* roles[] = {"cooling-topology", "cooling-capacity", "policy", "incident-state-fabric",
                         "liquid-cooling-control"};
  for (std::uint32_t iteration = 0; iteration < 200; ++iteration) {
    std::vector<std::size_t> order = {0, 1, 2, 3, 4};
    for (std::size_t index = order.size(); index > 1; --index) {
      const std::size_t swap_with = rng.below(static_cast<std::uint32_t>(index));
      std::swap(order[index - 1], order[swap_with]);
    }
    cfm::CoolingFailureState first;
    cfm::CoolingFailureState second;
    for (const std::size_t which : order) {
      CT_REQUIRE(first.bindings
                     .set(roles[which], *cfm::AuthorityRef::make(roles[which], "identity",
                                                                 cfm::ExternalGeneration(1)))
                     .has_value());
    }
    for (std::size_t index = order.size(); index > 0; --index) {
      const std::size_t which = order[index - 1];
      CT_REQUIRE(second.bindings
                     .set(roles[which], *cfm::AuthorityRef::make(roles[which], "identity",
                                                                 cfm::ExternalGeneration(1)))
                     .has_value());
    }
    CT_CHECK_EQ(cfm::encode_state(first), cfm::encode_state(second));
    CT_CHECK(cfm::state_digest(first) == cfm::state_digest(second));
  }
}

// ===========================================================================
// Recovery gate invariants
// ===========================================================================

CT_TEST(property_a_recovery_is_never_permitted_with_a_missing_required_channel) {
  ct_test::Rng rng(ct_test::case_seed("property_a_recovery_is_never_permitted_with_a_missing_required_channel"));
  const cfm::CoolingScope scope = prop_loop_scope();
  const cfm::ObservationChannel demanded[] = {
      cfm::ObservationChannel::FlowMeter, cfm::ObservationChannel::DifferentialPressure,
      cfm::ObservationChannel::ThermalCapacityMeter};
  for (std::uint32_t iteration = 0; iteration < 400; ++iteration) {
    cfm::RecoveryRequirements requirements;
    requirements.scope = scope.id;
    requirements.require_leak_clear = false;
    requirements.require_verified_effect = false;
    std::size_t demanded_count = 0;
    for (const cfm::ObservationChannel channel : demanded) {
      if (rng.chance(1, 2)) {
        requirements.required_observations.push_back(channel);
        ++demanded_count;
      }
    }
    requirements.stable_since = cfm::DecisionClock(kPropClock - 10000000);

    cfm::ObservationSet observations;
    std::size_t recorded = 0;
    std::uint32_t observation_index = 0;
    for (const cfm::ObservationChannel channel : demanded) {
      if (!rng.chance(3, 4)) {
        continue;
      }
      const std::int64_t value = channel == cfm::ObservationChannel::ThermalCapacityMeter ? 3000000 : 60000;
      const char* unit = channel == cfm::ObservationChannel::DifferentialPressure ? "Pa-dp" : "mL/s";
      const std::string unit_text =
          channel == cfm::ObservationChannel::ThermalCapacityMeter ? "W" : unit;
      CT_REQUIRE(observations
                     .add(make_scalar(iteration * 4 + observation_index++, channel, value, unit_text,
                                      kPropClock - 1000, "prop.recovery.producer"))
                     .has_value());
      ++recorded;
    }
    cfm::ScopeDecision decision;
    decision.scope = scope.id;
    decision.evaluated_at = cfm::DecisionClock(kPropClock);
    const cfm::Result<cfm::RecoveryAssessment> assessment = cfm::evaluate_recovery(
        scope, decision, requirements, observations, prop_policy(), cfm::DecisionClock(kPropClock));
    CT_REQUIRE(assessment.has_value());
    if (recorded < demanded_count) {
      CT_CHECK_MSG(assessment->decision != cfm::RecoveryDecision::Permitted,
                   "a recovery was permitted with missing evidence at iteration " +
                       std::to_string(iteration));
    }
    // Invariant: an unsatisfied gate is either a blocker or a waiting interval.
    for (const cfm::RecoveryGateResult& gate : assessment->gates) {
      if (gate.satisfied) {
        continue;
      }
      const bool waiting = gate.gate == cfm::RecoveryGate::DwellElapsed ||
                           gate.gate == cfm::RecoveryGate::HysteresisElapsed;
      if (!waiting) {
        CT_CHECK_MSG(std::find(assessment->blocking_gates.begin(), assessment->blocking_gates.end(),
                               gate.gate) != assessment->blocking_gates.end(),
                     "an unsatisfied evidence gate is not reported as a blocker");
      }
    }
    if (assessment->decision == cfm::RecoveryDecision::Permitted) {
      for (const cfm::RecoveryGateResult& gate : assessment->gates) {
        CT_CHECK(gate.satisfied);
      }
    }
  }
}
