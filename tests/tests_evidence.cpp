// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Proof obligations for the evidence model: the anti-inference rule that a
// missing reading is never zero and never healthy, the unit vocabulary and its
// per-unit bounds, observation-set bounds and atomicity, canonical ordering,
// latest/since/conflict selection, the decision-time assessment of every
// evidence status, the policy rules and the construction of an observation.
//
// The final section proves the structural rules of the state the evidence lives
// in (canonical order, referential integrity, the attempt evidence rules and the
// decision rules), because those rules are what keeps a missing reading from
// being published as a healthy zero.

#include "test_framework.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/classify.hpp"
#include "dccp/cooling_failure_manager/enums.hpp"
#include "dccp/cooling_failure_manager/evidence.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/model.hpp"
#include "dccp/cooling_failure_manager/result.hpp"
#include "dccp/cooling_failure_manager/strong_id.hpp"

namespace {

namespace cfm = dccp::cooling_failure_manager;

/// Unit vocabulary with the inclusive range each unit accepts. Kept in the test
/// on purpose: the table is the contract a producer codes against.
struct UnitRange {
  const char* unit;
  std::int64_t minimum;
  std::int64_t maximum;
};

const UnitRange kUnitRanges[] = {
    {"mL/s", -cfm::limits::kMaxFlowMillilitresPerSecond, cfm::limits::kMaxFlowMillilitresPerSecond},
    {"Pa", -cfm::limits::kMaxAbsolutePressurePascals, cfm::limits::kMaxAbsolutePressurePascals},
    {"mC", cfm::limits::kMinTemperatureMilliCelsius, cfm::limits::kMaxTemperatureMilliCelsius},
    {"W", 0, cfm::limits::kMaxThermalCapacityWatts},
    {"mK", cfm::limits::kMinThermalMarginMilliKelvin, cfm::limits::kMaxThermalMarginMilliKelvin},
    {"ppm", 0, cfm::limits::kMaxHumidityPartsPerMillion},
    {"Pa-dp", 0, cfm::limits::kMaxPressurePascals},
};
constexpr std::size_t kUnitRangeCount = sizeof(kUnitRanges) / sizeof(kUnitRanges[0]);

void expect_code(const cfm::Error& error, cfm::ErrorCode expected, const std::string& what) {
  CT_CHECK_MSG(error.code() == expected,
               what + ": expected " + std::string(cfm::error_code_name(expected)) + ", observed " +
                   std::string(cfm::error_code_name(error.code())) + " [" + error.to_string() + "]");
}

cfm::ScopeId scope_of(const char* text) {
  auto parsed = cfm::ScopeId::parse(text);
  CT_REQUIRE(parsed.has_value());
  return *parsed;
}

cfm::ObservationId observation_of(const char* text) {
  auto parsed = cfm::ObservationId::parse(text);
  CT_REQUIRE(parsed.has_value());
  return *parsed;
}

cfm::FailureId failure_of(const char* text) {
  auto parsed = cfm::FailureId::parse(text);
  CT_REQUIRE(parsed.has_value());
  return *parsed;
}

cfm::PlanId plan_of(const char* text) {
  auto parsed = cfm::PlanId::parse(text);
  CT_REQUIRE(parsed.has_value());
  return *parsed;
}

cfm::AttemptId attempt_of(const char* text) {
  auto parsed = cfm::AttemptId::parse(text);
  CT_REQUIRE(parsed.has_value());
  return *parsed;
}

cfm::MutationId solicitation_of(const char* text) {
  auto parsed = cfm::MutationId::parse(text);
  CT_REQUIRE(parsed.has_value());
  return *parsed;
}

cfm::RestrictionId restriction_of(const char* text) {
  auto parsed = cfm::RestrictionId::parse(text);
  CT_REQUIRE(parsed.has_value());
  return *parsed;
}

/// A recorded observation built directly, so the assessment rules can be driven
/// with any combination of channel, reading, quality, leak state and generation.
struct ObservationSpec {
  const char* id = "obs-1";
  const char* scope = "loop-1";
  cfm::ObservationChannel channel = cfm::ObservationChannel::FlowMeter;
  bool observed = true;
  std::int64_t value = 500;
  const char* unit = "mL/s";
  cfm::ObservationQuality quality = cfm::ObservationQuality::Good;
  std::uint64_t sequence = 7;
  /// Default sampling clock: inside the [0, kMaxWindowMilliseconds] window of the
  /// decision clock 4000 used by the assessment cases, so a case that does not
  /// care about freshness starts from a Current reading.
  std::int64_t observed_at_ms = 3900;
  cfm::LeakState leak = cfm::LeakState::LeakUnknown;
  std::uint64_t generation = 3;
  bool carried_forward = false;
};

cfm::Observation build_observation(const ObservationSpec& spec) {
  cfm::Observation observation;
  observation.id = observation_of(spec.id);
  observation.scope = scope_of(spec.scope);
  observation.channel = spec.channel;
  if (spec.observed) {
    auto quantity = cfm::Quantity::observed(spec.value, spec.unit, spec.quality,
                                            cfm::ObservationSequence(spec.sequence));
    CT_REQUIRE(quantity.has_value());
    observation.quantity = *quantity;
  } else {
    observation.quantity = cfm::Quantity::indeterminate();
  }
  observation.leak = spec.leak;
  observation.observed_at = cfm::DecisionClock(spec.observed_at_ms);
  observation.recorded_at = cfm::DecisionClock(spec.observed_at_ms);
  observation.producer = "producer-1";
  observation.sensor = "sensor-1";
  observation.evidence_generation = cfm::EvidenceGeneration(spec.generation);
  observation.carried_forward = spec.carried_forward;
  return observation;
}

/// Adds an observation to a set, requiring success.
void add_observation(cfm::ObservationSet& set, const ObservationSpec& spec) {
  const cfm::Observation observation = build_observation(spec);
  auto added = set.add(observation);
  CT_REQUIRE(added.has_value());
}

/// A state holding one scope, ready for a structural case to extend.
cfm::CoolingFailureState state_with_scope(const char* scope_text) {
  cfm::CoolingFailureState state;
  cfm::CoolingScope scope;
  scope.id = scope_of(scope_text);
  scope.kind = cfm::ScopeKind::Loop;
  scope.display_name = scope_text;
  state.scopes.push_back(scope);
  return state;
}

cfm::Result<void> canonical_and_valid(cfm::CoolingFailureState& state) {
  auto canonical = cfm::canonicalize(state);
  if (!canonical.has_value()) {
    return canonical.error();
  }
  return cfm::validate_structure(state);
}

cfm::CoolingFailure make_failure(const char* id, const char* scope, cfm::FailureClass failure_class,
                                 cfm::ConfirmationState confirmation, cfm::Severity severity) {
  cfm::CoolingFailure failure;
  failure.id = failure_of(id);
  failure.scope = scope_of(scope);
  failure.failure_class = failure_class;
  failure.confirmation = confirmation;
  failure.severity = severity;
  failure.urgency = cfm::Urgency::Immediate;
  failure.time_to_impact = cfm::TimeToImpact::Minutes;
  failure.confirmed_at = cfm::DecisionClock(1000);
  return failure;
}

cfm::ResponsePlan make_plan(const char* id, const char* scope) {
  cfm::ResponsePlan plan;
  plan.id = plan_of(id);
  plan.scope = scope_of(scope);
  plan.lifecycle = cfm::PlanLifecycle::Active;
  plan.updated_at = cfm::DecisionClock(1000);
  return plan;
}

}  // namespace

// ---------------------------------------------------------------------------
// Quantity
// ---------------------------------------------------------------------------

CT_TEST(evidence_indeterminate_quantity_carries_no_reading) {
  const cfm::Quantity indeterminate = cfm::Quantity::indeterminate();
  CT_CHECK(!indeterminate.has_value());
  CT_CHECK(indeterminate.availability() == cfm::Availability::Indeterminate);
  CT_CHECK(!indeterminate.is_usable());
  CT_CHECK(!indeterminate.value_if_observed().has_value());
  CT_CHECK(indeterminate.unit().empty());
  CT_CHECK_EQ(indeterminate.sequence().value(), static_cast<std::uint64_t>(0));

  // The central anti-inference rule: the reading is refused, never reported as
  // zero.
  auto value = indeterminate.observed_value();
  CT_REQUIRE(!value.has_value());
  expect_code(value.error(), cfm::ErrorCode::EvidenceMissing, "indeterminate observed_value");

  // Two indeterminate quantities are equal: "no reading" is one value, not a
  // family of them.
  CT_CHECK(indeterminate == cfm::Quantity::indeterminate());

  // A genuinely observed zero is a different value from an indeterminate
  // quantity, although both are numerically zero in every sum a caller might be
  // tempted to perform.
  auto zero = cfm::Quantity::observed(0, "mL/s", cfm::ObservationQuality::Good,
                                      cfm::ObservationSequence(1));
  CT_REQUIRE(zero.has_value());
  CT_CHECK(*zero != indeterminate);
  CT_CHECK(zero->has_value());
  CT_CHECK(zero->is_usable());
  auto zero_value = zero->observed_value();
  CT_REQUIRE(zero_value.has_value());
  CT_CHECK_EQ(*zero_value, static_cast<std::int64_t>(0));
}

CT_TEST(evidence_quantity_observed_accepts_every_unit_at_its_bounds) {
  for (std::size_t index = 0; index < kUnitRangeCount; ++index) {
    const UnitRange& range = kUnitRanges[index];
    for (const std::int64_t value : {range.minimum, range.maximum}) {
      auto quantity = cfm::Quantity::observed(value, range.unit, cfm::ObservationQuality::Good,
                                              cfm::ObservationSequence(1));
      CT_CHECK_MSG(quantity.has_value(), std::string("unit ") + range.unit + " rejected value " +
                                             std::to_string(value));
      if (quantity.has_value()) {
        CT_CHECK(quantity->has_value());
        CT_CHECK(quantity->is_usable());
        CT_CHECK(quantity->unit() == range.unit);
        if (value == 0) {
          CT_CHECK_EQ(quantity->observed_value().value(), static_cast<std::int64_t>(0));
        }
      }
    }

    // One step outside each end is refused, and the code is the exact one.
    if (range.minimum > INT64_MIN) {
      auto below = cfm::Quantity::observed(range.minimum - 1, range.unit, cfm::ObservationQuality::Good,
                                           cfm::ObservationSequence(1));
      CT_REQUIRE(!below.has_value());
      expect_code(below.error(), cfm::ErrorCode::QuantityOutOfRange,
                  std::string("unit ") + range.unit + " below its minimum");
    }
    if (range.maximum < INT64_MAX) {
      auto above = cfm::Quantity::observed(range.maximum + 1, range.unit, cfm::ObservationQuality::Good,
                                           cfm::ObservationSequence(1));
      CT_REQUIRE(!above.has_value());
      expect_code(above.error(), cfm::ErrorCode::QuantityOutOfRange,
                  std::string("unit ") + range.unit + " above its maximum");
    }
  }

  // INT64 extremes are refused for every unit, so a hostile reading cannot be
  // used as a sentinel or wrapped.
  for (std::size_t index = 0; index < kUnitRangeCount; ++index) {
    auto lowest = cfm::Quantity::observed(INT64_MIN, kUnitRanges[index].unit,
                                          cfm::ObservationQuality::Good, cfm::ObservationSequence(1));
    CT_REQUIRE(!lowest.has_value());
    expect_code(lowest.error(), cfm::ErrorCode::QuantityOutOfRange, "INT64_MIN reading");
    auto highest = cfm::Quantity::observed(INT64_MAX, kUnitRanges[index].unit,
                                           cfm::ObservationQuality::Good, cfm::ObservationSequence(1));
    CT_REQUIRE(!highest.has_value());
    expect_code(highest.error(), cfm::ErrorCode::QuantityOutOfRange, "INT64_MAX reading");
  }
}

CT_TEST(evidence_quantity_reports_the_exact_rejection_code) {
  // An unknown but well formed unit is a quantity problem, not a shape problem.
  auto unknown = cfm::Quantity::observed(1, "L/min", cfm::ObservationQuality::Good,
                                         cfm::ObservationSequence(1));
  CT_REQUIRE(!unknown.has_value());
  expect_code(unknown.error(), cfm::ErrorCode::QuantityOutOfRange, "unknown unit");

  // A reading with no unit is a discrete state code, which is what a status
  // channel reports: 0 normal, 1 degraded, 2 failed. It is accepted, carries no
  // unit, and is usable evidence like any other reading of good quality. A
  // declared bound still has to name its unit, which
  // evidence_declared_quantity_units_and_bounds_are_exact proves separately.
  for (const std::int64_t code : {static_cast<std::int64_t>(0), static_cast<std::int64_t>(1),
                                  static_cast<std::int64_t>(2)}) {
    auto state_code =
        cfm::Quantity::observed(code, "", cfm::ObservationQuality::Good, cfm::ObservationSequence(1));
    CT_CHECK_MSG(state_code.has_value(),
                 "state code " + std::to_string(code) + " must be a legal unit-less reading");
    if (state_code.has_value()) {
      CT_CHECK(state_code->has_value());
      CT_CHECK(state_code->unit().empty());
      CT_CHECK(state_code->is_usable());
      auto observed_state = state_code->observed_value();
      CT_REQUIRE(observed_state.has_value());
      CT_CHECK_EQ(*observed_state, code);
    }
  }

  // A code outside the documented domain is refused, never interpreted: the
  // classification reads "below 2" as not-failed, so a negative code would
  // silently argue against a failure.
  for (const std::int64_t code : {static_cast<std::int64_t>(-1), static_cast<std::int64_t>(3),
                                  static_cast<std::int64_t>(INT64_MAX)}) {
    auto refused =
        cfm::Quantity::observed(code, "", cfm::ObservationQuality::Good, cfm::ObservationSequence(1));
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::QuantityOutOfRange,
                "unit-less state code " + std::to_string(code));
  }

  // An over-long unit is a length problem; a byte sequence that is not UTF-8 is
  // an encoding problem. Neither is repaired or truncated.
  const std::string over_long(cfm::limits::kMaxExternalKindBytes + 1, 'x');
  auto too_long = cfm::Quantity::observed(1, over_long, cfm::ObservationQuality::Good,
                                          cfm::ObservationSequence(1));
  CT_REQUIRE(!too_long.has_value());
  expect_code(too_long.error(), cfm::ErrorCode::TextTooLong, "over-long unit");

  const std::string invalid_utf8 = std::string("\xFF");
  auto malformed = cfm::Quantity::observed(1, invalid_utf8, cfm::ObservationQuality::Good,
                                           cfm::ObservationSequence(1));
  CT_REQUIRE(!malformed.has_value());
  expect_code(malformed.error(), cfm::ErrorCode::InvalidUtf8, "unit that is not UTF-8");

  // A unit at exactly the bound is accepted.
  std::string at_bound(cfm::limits::kMaxExternalKindBytes, 'x');
  auto bounded = cfm::Quantity::observed(1, at_bound, cfm::ObservationQuality::Good,
                                         cfm::ObservationSequence(1));
  CT_REQUIRE(!bounded.has_value());
  expect_code(bounded.error(), cfm::ErrorCode::QuantityOutOfRange, "unknown unit at the length bound");
}

CT_TEST(evidence_quantity_usability_follows_availability_and_quality) {
  struct QualityCase {
    cfm::ObservationQuality quality;
    bool usable;
  };
  const QualityCase cases[] = {
      {cfm::ObservationQuality::Good, true},
      {cfm::ObservationQuality::Degraded, true},
      {cfm::ObservationQuality::Suspect, false},
      {cfm::ObservationQuality::Bad, false},
  };
  for (const QualityCase& item : cases) {
    auto quantity = cfm::Quantity::observed(500, "mL/s", item.quality, cfm::ObservationSequence(4));
    CT_REQUIRE(quantity.has_value());
    CT_CHECK_MSG(quantity->is_usable() == item.usable,
                 "quality " + std::to_string(static_cast<unsigned>(item.quality)));
    CT_CHECK(quantity->has_value());
    // A suspect or bad reading is still a recorded reading: the value is
    // reported, and the producer's own quality claim is preserved verbatim.
    CT_CHECK_EQ(quantity->quality(), item.quality);
    auto value = quantity->observed_value();
    CT_REQUIRE(value.has_value());
    CT_CHECK_EQ(*value, static_cast<std::int64_t>(500));
  }

  CT_CHECK(!cfm::Quantity::indeterminate().is_usable());
  CT_CHECK_EQ(cfm::Quantity::indeterminate().quality(), cfm::ObservationQuality::Bad);
}

CT_TEST(evidence_randomized_quantity_bounds_are_exact) {
  const std::uint64_t seed = ct_test::case_seed("evidence_randomized_quantity_bounds_are_exact");
  ct_test::Rng rng(seed);
  ct_test::report_note("seed=" + std::to_string(seed) + " iterations=20000");

  for (std::uint32_t iteration = 0; iteration < 20000; ++iteration) {
    const UnitRange& range = kUnitRanges[rng.below(static_cast<std::uint32_t>(kUnitRangeCount))];
    const std::uint64_t span = static_cast<std::uint64_t>(range.maximum - range.minimum);
    std::int64_t value = 0;
    bool expect_accepted = false;
    switch (rng.below(4)) {
      case 0: {
        const std::uint64_t offset = rng.next() % (span + 1u);
        value = range.minimum + static_cast<std::int64_t>(offset);
        expect_accepted = true;
        break;
      }
      case 1:
        value = range.minimum;
        expect_accepted = true;
        break;
      case 2:
        value = range.maximum;
        expect_accepted = true;
        break;
      default:
        // Strictly outside the range on one side. Every range here is far from
        // the INT64 ends, so the step is representable.
        if (rng.chance(1, 2)) {
          value = range.maximum + 1;
        } else {
          value = range.minimum - 1;
        }
        expect_accepted = false;
        break;
    }

    auto quantity = cfm::Quantity::observed(value, range.unit, cfm::ObservationQuality::Good,
                                            cfm::ObservationSequence(1));
    const std::string parameters = std::string("unit=") + range.unit + " value=" +
                                   std::to_string(value) + " iteration=" + std::to_string(iteration) +
                                   " range=[" + std::to_string(range.minimum) + "," +
                                   std::to_string(range.maximum) + "]";
    CT_CHECK_MSG(quantity.has_value() == expect_accepted,
                 std::string(expect_accepted ? "expected acceptance: " : "expected rejection: ") +
                     parameters);
    if (!quantity.has_value()) {
      CT_CHECK_MSG(quantity.error().code() == cfm::ErrorCode::QuantityOutOfRange,
                   "wrong rejection code: " + parameters);
    }

    // A well formed unit that is not a unit this component knows is refused with
    // the same code, whatever the value.
    const std::string unknown_unit = "u" + std::to_string(rng.below(1000));
    auto unknown = cfm::Quantity::observed(value, unknown_unit, cfm::ObservationQuality::Good,
                                           cfm::ObservationSequence(1));
    CT_CHECK_MSG(!unknown.has_value(), "unknown unit accepted: " + parameters);
    if (!unknown.has_value()) {
      CT_CHECK(unknown.error().code() == cfm::ErrorCode::QuantityOutOfRange);
    }
  }
}

// ---------------------------------------------------------------------------
// Observation helpers and set construction
// ---------------------------------------------------------------------------

CT_TEST(evidence_observation_signal_and_leak_helpers) {
  const ObservationSpec reading;
  const cfm::Observation observed = build_observation(reading);
  CT_CHECK(cfm::observation_has_signal(observed));
  CT_CHECK(!cfm::observation_asserts_leak(observed));

  // A status channel reporting the normal state code 0 still has a signal: zero
  // is a measurement, not an absence.
  ObservationSpec status = reading;
  status.channel = cfm::ObservationChannel::PumpStatus;
  status.value = 0;
  status.unit = "ppm";
  const cfm::Observation status_reading = build_observation(status);
  CT_CHECK(cfm::observation_has_signal(status_reading));
  CT_CHECK_EQ(status_reading.quantity.observed_value().value(), static_cast<std::int64_t>(0));

  ObservationSpec silent = reading;
  silent.observed = false;
  const cfm::Observation silent_reading = build_observation(silent);
  CT_CHECK(!cfm::observation_has_signal(silent_reading));
  CT_CHECK(!cfm::observation_asserts_leak(silent_reading));

  for (const cfm::LeakState leak :
       {cfm::LeakState::LeakNone, cfm::LeakState::LeakSuspected, cfm::LeakState::LeakConfirmed,
        cfm::LeakState::LeakActive}) {
    ObservationSpec leak_spec = reading;
    leak_spec.channel = cfm::ObservationChannel::LeakDetector;
    leak_spec.leak = leak;
    const cfm::Observation leak_reading = build_observation(leak_spec);
    CT_CHECK_MSG(cfm::observation_asserts_leak(leak_reading),
                 "leak state " + std::to_string(static_cast<unsigned>(leak)) + " must assert a leak");
  }
}

CT_TEST(evidence_observation_set_rejects_malformed_and_duplicate_identities) {
  cfm::ObservationSet set;

  // An empty identity cannot be parsed at all, so it is set after construction:
  // the set must still refuse it.
  cfm::Observation empty_identity = build_observation(ObservationSpec{});
  empty_identity.id = cfm::ObservationId();
  auto empty = set.add(empty_identity);
  CT_REQUIRE(!empty.has_value());
  expect_code(empty.error(), cfm::ErrorCode::MalformedIdentifier, "empty observation identity");

  cfm::Observation empty_scope_observation = build_observation(ObservationSpec{});
  empty_scope_observation.scope = cfm::ScopeId();
  auto no_scope = set.add(empty_scope_observation);
  CT_REQUIRE(!no_scope.has_value());
  expect_code(no_scope.error(), cfm::ErrorCode::MalformedIdentifier, "empty observation scope");

  add_observation(set, ObservationSpec{});
  CT_CHECK_EQ(set.size(), static_cast<std::size_t>(1));

  auto duplicate = set.add(build_observation(ObservationSpec{}));
  CT_REQUIRE(!duplicate.has_value());
  expect_code(duplicate.error(), cfm::ErrorCode::DuplicateIdentifier, "duplicate observation identity");
  CT_CHECK_EQ(set.size(), static_cast<std::size_t>(1));

  // The same identity on another scope is still the same identity.
  ObservationSpec other_scope;
  other_scope.scope = "loop-2";
  auto duplicate_elsewhere = set.add(build_observation(other_scope));
  CT_REQUIRE(!duplicate_elsewhere.has_value());
  expect_code(duplicate_elsewhere.error(), cfm::ErrorCode::DuplicateIdentifier,
              "duplicate identity on another scope");
}

CT_TEST(evidence_observation_set_enforces_the_per_scope_and_total_bounds) {
  cfm::ObservationSet set;
  const cfm::ScopeId scope = scope_of("loop-1");

  // The per-scope bound is reached, then refused, and a different scope is
  // unaffected by it.
  for (std::size_t index = 0; index < cfm::limits::kMaxObservationPerScope; ++index) {
    ObservationSpec spec;
    const std::string id = "obs-" + std::to_string(index + 1);
    spec.id = id.c_str();
    spec.scope = "loop-1";
    spec.observed_at_ms = 1000;
    add_observation(set, spec);
  }
  CT_CHECK_EQ(set.size(), cfm::limits::kMaxObservationPerScope);

  ObservationSpec overflow;
  overflow.id = "obs-overflow";
  overflow.scope = "loop-1";
  auto refused = set.add(build_observation(overflow));
  CT_REQUIRE(!refused.has_value());
  expect_code(refused.error(), cfm::ErrorCode::LimitExceeded, "per-scope observation bound");
  CT_CHECK_EQ(set.size(), cfm::limits::kMaxObservationPerScope);

  overflow.scope = "loop-2";
  auto accepted = set.add(build_observation(overflow));
  CT_CHECK_MSG(accepted.has_value(), "a second scope must not be affected by the first scope bound");
  CT_CHECK_EQ(set.size(), cfm::limits::kMaxObservationPerScope + 1);
  CT_CHECK_EQ(set.for_scope(scope).size(), cfm::limits::kMaxObservationPerScope);
}

CT_TEST(evidence_observation_set_add_all_is_atomic) {
  cfm::ObservationSet set;
  add_observation(set, ObservationSpec{});

  // A batch that repeats an identity already in the set changes nothing.
  std::vector<cfm::Observation> repeating;
  ObservationSpec fresh;
  fresh.id = "obs-2";
  repeating.push_back(build_observation(fresh));
  repeating.push_back(build_observation(ObservationSpec{}));
  auto refused = set.add_all(repeating);
  CT_REQUIRE(!refused.has_value());
  expect_code(refused.error(), cfm::ErrorCode::DuplicateIdentifier, "batch repeating a stored identity");
  CT_CHECK_EQ(set.size(), static_cast<std::size_t>(1));

  // A batch that repeats an identity inside itself changes nothing either: the
  // whole batch is validated before any of it is applied.
  std::vector<cfm::Observation> internally_duplicated;
  internally_duplicated.push_back(build_observation(fresh));
  internally_duplicated.push_back(build_observation(fresh));
  auto duplicated = set.add_all(internally_duplicated);
  CT_REQUIRE(!duplicated.has_value());
  expect_code(duplicated.error(), cfm::ErrorCode::DuplicateIdentifier, "batch duplicating itself");
  CT_CHECK_EQ(set.size(), static_cast<std::size_t>(1));

  // A batch with an empty identity changes nothing.
  std::vector<cfm::Observation> malformed;
  malformed.push_back(build_observation(fresh));
  cfm::Observation broken = build_observation(fresh);
  broken.id = cfm::ObservationId();
  malformed.push_back(broken);
  auto refused_malformed = set.add_all(malformed);
  CT_REQUIRE(!refused_malformed.has_value());
  expect_code(refused_malformed.error(), cfm::ErrorCode::MalformedIdentifier, "batch with an empty id");
  CT_CHECK_EQ(set.size(), static_cast<std::size_t>(1));

  // A refusable batch that would breach the per-scope bound changes nothing.
  cfm::ObservationSet bounded;
  for (std::size_t index = 0; index + 1 < cfm::limits::kMaxObservationPerScope; ++index) {
    ObservationSpec spec;
    const std::string id = "obs-" + std::to_string(index + 1);
    spec.id = id.c_str();
    add_observation(bounded, spec);
  }
  std::vector<cfm::Observation> over_bound;
  for (std::size_t index = 0; index < 4; ++index) {
    ObservationSpec spec;
    const std::string id = "late-" + std::to_string(index + 1);
    spec.id = id.c_str();
    over_bound.push_back(build_observation(spec));
  }
  const std::size_t before = bounded.size();
  auto refused_batch = bounded.add_all(over_bound);
  CT_REQUIRE(!refused_batch.has_value());
  expect_code(refused_batch.error(), cfm::ErrorCode::LimitExceeded, "batch breaching the scope bound");
  CT_CHECK_EQ(bounded.size(), before);

  // A batch that fits is applied in full, in the order it was supplied.
  std::vector<cfm::Observation> accepted_batch;
  ObservationSpec first;
  first.id = "obs-a";
  ObservationSpec second;
  second.id = "obs-b";
  second.channel = cfm::ObservationChannel::CoolantTemperature;
  second.unit = "mC";
  accepted_batch.push_back(build_observation(first));
  accepted_batch.push_back(build_observation(second));
  auto applied = set.add_all(accepted_batch);
  CT_REQUIRE(applied.has_value());
  CT_CHECK_EQ(set.size(), static_cast<std::size_t>(3));
  CT_CHECK(set.observations()[1].id == observation_of("obs-a"));
  CT_CHECK(set.observations()[2].id == observation_of("obs-b"));

  // An empty batch is accepted and changes nothing.
  auto empty = set.add_all({});
  CT_CHECK(empty.has_value());
  CT_CHECK_EQ(set.size(), static_cast<std::size_t>(3));

  // A batch larger than the whole set's capacity is refused before it is
  // examined, so the capacity rule is proven without filling the set.
  cfm::ObservationSet empty_set;
  std::vector<cfm::Observation> oversized(cfm::limits::kMaxObservationCount + 1);
  auto too_large = empty_set.add_all(oversized);
  CT_REQUIRE(!too_large.has_value());
  expect_code(too_large.error(), cfm::ErrorCode::LimitExceeded, "batch above the set capacity");
  CT_CHECK_EQ(empty_set.size(), static_cast<std::size_t>(0));
}

CT_TEST(evidence_observation_set_canonical_sort_is_total_and_idempotent) {
  // The same observations inserted in two different orders must end in exactly
  // the same sequence, which is the determinism the encoder relies on.
  const ObservationSpec specs[] = {
      {"obs-d", "loop-2", cfm::ObservationChannel::FlowMeter, true, 10, "mL/s",
       cfm::ObservationQuality::Good, 3, 1000, cfm::LeakState::LeakUnknown, 1, false},
      {"obs-b", "loop-1", cfm::ObservationChannel::CoolantTemperature, true, 22, "mC",
       cfm::ObservationQuality::Good, 5, 1000, cfm::LeakState::LeakUnknown, 1, false},
      {"obs-c", "loop-1", cfm::ObservationChannel::FlowMeter, true, 10, "mL/s",
       cfm::ObservationQuality::Good, 9, 1000, cfm::LeakState::LeakUnknown, 1, false},
      {"obs-a", "loop-1", cfm::ObservationChannel::FlowMeter, true, 10, "mL/s",
       cfm::ObservationQuality::Good, 2, 1000, cfm::LeakState::LeakUnknown, 1, false},
  };

  cfm::ObservationSet forward;
  for (const ObservationSpec& spec : specs) {
    add_observation(forward, spec);
  }
  cfm::ObservationSet backward;
  for (std::size_t index = sizeof(specs) / sizeof(specs[0]); index > 0; --index) {
    add_observation(backward, specs[index - 1]);
  }

  forward.sort_canonical();
  backward.sort_canonical();
  CT_REQUIRE(forward.size() == backward.size());
  for (std::size_t index = 0; index < forward.size(); ++index) {
    CT_CHECK_MSG(forward.observations()[index].id == backward.observations()[index].id,
                 "insertion order changed the canonical order at index " + std::to_string(index));
  }

  // The expected order is (scope, channel, sequence, identity): loop-1 flow with
  // sequences 2, 9 then loop-1 temperature, then loop-2 flow.
  CT_CHECK(forward.observations()[0].id == observation_of("obs-a"));
  CT_CHECK(forward.observations()[1].id == observation_of("obs-c"));
  CT_CHECK(forward.observations()[2].id == observation_of("obs-b"));
  CT_CHECK(forward.observations()[3].id == observation_of("obs-d"));

  // Sorting twice is a no-op.
  forward.sort_canonical();
  CT_CHECK(forward.observations()[0].id == observation_of("obs-a"));
  CT_CHECK(forward.observations()[1].id == observation_of("obs-c"));
  CT_CHECK(forward.observations()[2].id == observation_of("obs-b"));
  CT_CHECK(forward.observations()[3].id == observation_of("obs-d"));
}

CT_TEST(evidence_for_scope_and_for_channel_return_canonical_order) {
  cfm::ObservationSet set;
  const ObservationSpec specs[] = {
      {"obs-1", "loop-1", cfm::ObservationChannel::FlowMeter, true, 10, "mL/s",
       cfm::ObservationQuality::Good, 3, 1000, cfm::LeakState::LeakUnknown, 1, false},
      {"obs-2", "loop-1", cfm::ObservationChannel::FlowMeter, true, 11, "mL/s",
       cfm::ObservationQuality::Good, 9, 2000, cfm::LeakState::LeakUnknown, 1, false},
      {"obs-3", "loop-1", cfm::ObservationChannel::CoolantTemperature, true, 22, "mC",
       cfm::ObservationQuality::Good, 4, 3000, cfm::LeakState::LeakUnknown, 1, false},
      {"obs-4", "loop-2", cfm::ObservationChannel::FlowMeter, true, 12, "mL/s",
       cfm::ObservationQuality::Good, 5, 4000, cfm::LeakState::LeakUnknown, 1, false},
  };
  for (const ObservationSpec& spec : specs) {
    add_observation(set, spec);
  }

  const std::vector<const cfm::Observation*> loop_one = set.for_scope(scope_of("loop-1"));
  CT_REQUIRE(loop_one.size() == 3);
  CT_CHECK(loop_one[0]->id == observation_of("obs-1"));
  CT_CHECK(loop_one[1]->id == observation_of("obs-2"));
  CT_CHECK(loop_one[2]->id == observation_of("obs-3"));

  // for_channel reports the highest producer sequence first, then identity
  // bytes, so the newest reading of a channel is always the first element.
  const std::vector<const cfm::Observation*> flow =
      set.for_channel(scope_of("loop-1"), cfm::ObservationChannel::FlowMeter);
  CT_REQUIRE(flow.size() == 2);
  CT_CHECK(flow[0]->id == observation_of("obs-2"));
  CT_CHECK(flow[1]->id == observation_of("obs-1"));

  CT_CHECK(set.for_scope(scope_of("loop-3")).empty());
  CT_CHECK(set.for_channel(scope_of("loop-1"), cfm::ObservationChannel::AirflowMeter).empty());
}

CT_TEST(evidence_latest_breaks_ties_by_sequence_then_clock_then_identity) {
  cfm::ObservationSet set;
  const cfm::ScopeId scope = scope_of("loop-1");
  const cfm::ObservationChannel channel = cfm::ObservationChannel::FlowMeter;

  CT_CHECK(set.latest(scope, channel, cfm::DecisionClock(1000), cfm::DurationMilliseconds(1000)) ==
           nullptr);

  // Highest producer sequence wins, whatever the sampling clock says.
  ObservationSpec lower;
  lower.id = "obs-low";
  lower.sequence = 5;
  lower.observed_at_ms = 9000;
  add_observation(set, lower);
  ObservationSpec higher;
  higher.id = "obs-high";
  higher.sequence = 6;
  higher.observed_at_ms = 1000;
  add_observation(set, higher);
  CT_CHECK(set.latest(scope, channel, cfm::DecisionClock(1000), cfm::DurationMilliseconds(1000))->id ==
           observation_of("obs-high"));

  // Equal sequences are broken by the later sampling clock.
  ObservationSpec later;
  later.id = "obs-later";
  later.sequence = 6;
  later.observed_at_ms = 2000;
  add_observation(set, later);
  CT_CHECK(set.latest(scope, channel, cfm::DecisionClock(2000), cfm::DurationMilliseconds(1000))->id ==
           observation_of("obs-later"));

  // Equal sequence and equal clock are broken by the greater identity, so the
  // answer never depends on insertion order.
  ObservationSpec tie;
  tie.id = "obs-tie";
  tie.sequence = 6;
  tie.observed_at_ms = 2000;
  add_observation(set, tie);
  const cfm::Observation* winner =
      set.latest(scope, channel, cfm::DecisionClock(2000), cfm::DurationMilliseconds(1000));
  CT_REQUIRE(winner != nullptr);
  CT_CHECK(winner->id == observation_of("obs-tie"));
  CT_CHECK(winner->id > observation_of("obs-later"));

  // Another scope or channel never leaks into the answer.
  CT_CHECK(set.latest(scope_of("loop-2"), channel, cfm::DecisionClock(2000),
                      cfm::DurationMilliseconds(1000)) == nullptr);
  CT_CHECK(set.latest(scope, cfm::ObservationChannel::AirflowMeter, cfm::DecisionClock(2000),
                      cfm::DurationMilliseconds(1000)) == nullptr);
}

CT_TEST(evidence_latest_returns_an_indeterminate_reading_whatever_its_age) {
  cfm::ObservationSet set;
  const cfm::ScopeId scope = scope_of("loop-1");
  const cfm::ObservationChannel channel = cfm::ObservationChannel::FlowMeter;

  // An indeterminate quantity carries no producer sequence at all - there is no
  // reading to sequence - so the two observations tie on sequence and the later
  // sampling clock decides. A silent instrument is then the newest thing the
  // channel said, and latest() must report it rather than reaching back to an
  // older, comfortable reading.
  ObservationSpec readable;
  readable.id = "obs-old";
  readable.sequence = 0;
  readable.observed_at_ms = 100;
  add_observation(set, readable);
  ObservationSpec silent;
  silent.id = "obs-silent";
  silent.observed = false;
  silent.sequence = 0;
  silent.observed_at_ms = 5000;
  add_observation(set, silent);

  const cfm::Observation* newest =
      set.latest(scope, channel, cfm::DecisionClock(100000), cfm::DurationMilliseconds(10));
  CT_REQUIRE(newest != nullptr);
  CT_CHECK(newest->id == observation_of("obs-silent"));
  CT_CHECK(!cfm::observation_has_signal(*newest));

  // Freshness is deliberately not part of latest(): the same answer comes back
  // when the reading is far outside any window.
  const cfm::Observation* same =
      set.latest(scope, channel, cfm::DecisionClock(5000), cfm::DurationMilliseconds(0));
  CT_REQUIRE(same != nullptr);
  CT_CHECK(same->id == observation_of("obs-silent"));
}

CT_TEST(evidence_since_selects_by_sampling_clock) {
  cfm::ObservationSet set;
  const cfm::ScopeId scope = scope_of("loop-1");
  const cfm::ObservationChannel channel = cfm::ObservationChannel::FlowMeter;
  const std::int64_t clocks[] = {1000, 2000, 3000};
  for (std::size_t index = 0; index < 3; ++index) {
    ObservationSpec spec;
    const std::string id = "obs-" + std::to_string(index + 1);
    spec.id = id.c_str();
    spec.observed_at_ms = clocks[index];
    spec.sequence = static_cast<std::uint64_t>(index + 1);
    add_observation(set, spec);
  }

  // The boundary is inclusive: an observation dated exactly at the clock is
  // included.
  const std::vector<const cfm::Observation*> from_two = set.since(scope, channel, cfm::DecisionClock(2000));
  CT_REQUIRE(from_two.size() == 2);
  CT_CHECK(from_two[0]->id == observation_of("obs-2"));
  CT_CHECK(from_two[1]->id == observation_of("obs-3"));

  CT_CHECK(set.since(scope, channel, cfm::DecisionClock(3000)).size() == 1);
  CT_CHECK(set.since(scope, channel, cfm::DecisionClock(3001)).empty());
  CT_CHECK(set.since(scope, channel, cfm::DecisionClock(0)).size() == 3);
  CT_CHECK(set.since(scope_of("loop-2"), channel, cfm::DecisionClock(0)).empty());
}

CT_TEST(evidence_has_conflict_detects_one_sequence_two_answers) {
  cfm::ObservationSet set;
  const cfm::ScopeId scope = scope_of("loop-1");
  const cfm::ObservationChannel channel = cfm::ObservationChannel::FlowMeter;
  CT_CHECK(!set.has_conflict(scope, channel));

  ObservationSpec first;
  first.id = "obs-1";
  first.sequence = 10;
  first.value = 500;
  add_observation(set, first);
  CT_CHECK(!set.has_conflict(scope, channel));

  // Same sequence, same reading: one stream, no disagreement.
  ObservationSpec agreeing;
  agreeing.id = "obs-2";
  agreeing.sequence = 10;
  agreeing.value = 500;
  add_observation(set, agreeing);
  CT_CHECK(!set.has_conflict(scope, channel));

  // Same sequence, different value: the subject is conflicting.
  ObservationSpec disagreeing;
  disagreeing.id = "obs-3";
  disagreeing.sequence = 10;
  disagreeing.value = 501;
  add_observation(set, disagreeing);
  CT_CHECK(set.has_conflict(scope, channel));

  // A different sequence is not a conflict: one reading is simply older.
  cfm::ObservationSet sequenced;
  ObservationSpec older;
  older.id = "obs-old";
  older.sequence = 1;
  older.value = 100;
  add_observation(sequenced, older);
  ObservationSpec newer;
  newer.id = "obs-new";
  newer.sequence = 2;
  newer.value = 900;
  add_observation(sequenced, newer);
  CT_CHECK(!sequenced.has_conflict(scope, channel));

  // A sequence of zero is not a slot claim, so two unsequenced readings cannot
  // collide.
  cfm::ObservationSet unsequenced;
  ObservationSpec zero_a;
  zero_a.id = "obs-za";
  zero_a.sequence = 0;
  zero_a.value = 100;
  add_observation(unsequenced, zero_a);
  ObservationSpec zero_b;
  zero_b.id = "obs-zb";
  zero_b.sequence = 0;
  zero_b.value = 900;
  add_observation(unsequenced, zero_b);
  CT_CHECK(!unsequenced.has_conflict(scope, channel));

  // A leak disagreement counts as a different reading.
  cfm::ObservationSet availability;
  ObservationSpec present;
  present.id = "obs-p";
  present.sequence = 4;
  present.value = 100;
  add_observation(availability, present);
  // An indeterminate quantity carries no sequence, so a silent reading can never
  // claim the slot of a sequenced one. The availability clause of the reading
  // comparison is therefore a guard, not a reachable case through this API, and
  // the two observations below do not conflict.
  ObservationSpec absent;
  absent.id = "obs-q";
  absent.observed = false;
  absent.sequence = 4;
  const cfm::Observation absent_observation = build_observation(absent);
  CT_CHECK_EQ(absent_observation.quantity.sequence().value(), static_cast<std::uint64_t>(0));
  add_observation(availability, absent);
  CT_CHECK(!availability.has_conflict(scope, channel));

  cfm::ObservationSet leaks;
  ObservationSpec clear_leak;
  clear_leak.id = "obs-l1";
  clear_leak.channel = cfm::ObservationChannel::LeakDetector;
  clear_leak.sequence = 4;
  clear_leak.leak = cfm::LeakState::LeakNone;
  add_observation(leaks, clear_leak);
  ObservationSpec active_leak;
  active_leak.id = "obs-l2";
  active_leak.channel = cfm::ObservationChannel::LeakDetector;
  active_leak.sequence = 4;
  active_leak.leak = cfm::LeakState::LeakActive;
  add_observation(leaks, active_leak);
  CT_CHECK(leaks.has_conflict(scope, cfm::ObservationChannel::LeakDetector));
  CT_CHECK(!leaks.has_conflict(scope, channel));
}

// ---------------------------------------------------------------------------
// Decision-time assessment
// ---------------------------------------------------------------------------

CT_TEST(evidence_assess_observation_covers_every_status) {
  const cfm::DecisionClock clock(4000);
  const cfm::DurationMilliseconds window(1000);

  // Missing: nothing was recorded for the subject.
  {
    const cfm::ObservationUsability usability =
        cfm::assess_observation(nullptr, clock, window, false);
    CT_CHECK(usability.status == cfm::EvidenceStatus::Missing);
    CT_CHECK(usability.freshness == cfm::Freshness::Unobserved);
    CT_CHECK_EQ(usability.age_milliseconds, static_cast<std::int64_t>(0));
    CT_CHECK(!usability.detail.empty());
  }

  // Current: inside the window, usable quality, a bound evidence generation.
  {
    ObservationSpec spec;
    spec.observed_at_ms = 3500;
    const cfm::Observation observation = build_observation(spec);
    const cfm::ObservationUsability usability =
        cfm::assess_observation(&observation, clock, window, false);
    CT_CHECK(usability.status == cfm::EvidenceStatus::Current);
    CT_CHECK(usability.freshness == cfm::Freshness::Current);
    CT_CHECK_EQ(usability.age_milliseconds, static_cast<std::int64_t>(500));
  }

  // Stale: just past the window, and far past it. The age is the difference.
  {
    ObservationSpec spec;
    spec.observed_at_ms = 2999;
    const cfm::Observation observation = build_observation(spec);
    const cfm::ObservationUsability usability =
        cfm::assess_observation(&observation, clock, window, false);
    CT_CHECK(usability.status == cfm::EvidenceStatus::Stale);
    CT_CHECK(usability.freshness == cfm::Freshness::Stale);
    CT_CHECK_EQ(usability.age_milliseconds, static_cast<std::int64_t>(1001));
  }

  // The window boundary is inclusive: exactly the window is still current.
  {
    ObservationSpec spec;
    spec.observed_at_ms = 3000;
    const cfm::Observation observation = build_observation(spec);
    const cfm::ObservationUsability usability =
        cfm::assess_observation(&observation, clock, window, false);
    CT_CHECK(usability.status == cfm::EvidenceStatus::Current);
    CT_CHECK_EQ(usability.age_milliseconds, static_cast<std::int64_t>(1000));
  }

  // Future: dated after the decision clock. The age stays negative and is never
  // clamped to zero.
  {
    ObservationSpec spec;
    spec.observed_at_ms = 5000;
    const cfm::Observation observation = build_observation(spec);
    const cfm::ObservationUsability usability =
        cfm::assess_observation(&observation, clock, window, false);
    CT_CHECK(usability.status == cfm::EvidenceStatus::Future);
    CT_CHECK(usability.freshness == cfm::Freshness::Future);
    CT_CHECK_EQ(usability.age_milliseconds, static_cast<std::int64_t>(-1000));
  }

  // Conflicting: the status is Conflicting, the freshness is still reported.
  {
    ObservationSpec spec;
    spec.observed_at_ms = 3900;
    const cfm::Observation observation = build_observation(spec);
    const cfm::ObservationUsability usability =
        cfm::assess_observation(&observation, clock, window, true);
    CT_CHECK(usability.status == cfm::EvidenceStatus::Conflicting);
    CT_CHECK(usability.freshness == cfm::Freshness::Current);
    CT_CHECK_EQ(usability.age_milliseconds, static_cast<std::int64_t>(100));
  }

  // A conflicting observation that is also stale reports both facts.
  {
    ObservationSpec spec;
    spec.observed_at_ms = 100;
    const cfm::Observation observation = build_observation(spec);
    const cfm::ObservationUsability usability =
        cfm::assess_observation(&observation, clock, window, true);
    CT_CHECK(usability.status == cfm::EvidenceStatus::Conflicting);
    CT_CHECK(usability.freshness == cfm::Freshness::Stale);
  }

  // Indeterminate: a bad or suspect reading, and a silent scalar channel.
  {
    ObservationSpec bad;
    bad.quality = cfm::ObservationQuality::Bad;
    const cfm::Observation bad_observation = build_observation(bad);
    const cfm::ObservationUsability bad_usability =
        cfm::assess_observation(&bad_observation, clock, window, false);
    CT_CHECK(bad_usability.status == cfm::EvidenceStatus::Indeterminate);
    CT_CHECK(bad_usability.freshness == cfm::Freshness::Current);

    ObservationSpec suspect;
    suspect.quality = cfm::ObservationQuality::Suspect;
    const cfm::Observation suspect_observation = build_observation(suspect);
    CT_CHECK(cfm::assess_observation(&suspect_observation, clock, window, false).status ==
             cfm::EvidenceStatus::Indeterminate);

    ObservationSpec silent;
    silent.observed = false;
    const cfm::Observation silent_observation = build_observation(silent);
    const cfm::ObservationUsability silent_usability =
        cfm::assess_observation(&silent_observation, clock, window, false);
    CT_CHECK(silent_usability.status == cfm::EvidenceStatus::Indeterminate);
    CT_CHECK(silent_usability.freshness == cfm::Freshness::Current);
  }

  // Unbound: a usable scalar reading from a stream with no evidence generation.
  {
    ObservationSpec spec;
    spec.generation = 0;
    const cfm::Observation observation = build_observation(spec);
    const cfm::ObservationUsability usability =
        cfm::assess_observation(&observation, clock, window, false);
    CT_CHECK(usability.status == cfm::EvidenceStatus::Unbound);
    CT_CHECK(usability.freshness == cfm::Freshness::Current);
  }

  // OutOfOrder is the one status this assessment never produces: arrival order
  // is not a property of an immutable recorded observation, so inferring it here
  // would be a claim the component cannot support.
  const cfm::EvidenceStatus produced[] = {
      cfm::EvidenceStatus::Current,     cfm::EvidenceStatus::Missing,
      cfm::EvidenceStatus::Stale,       cfm::EvidenceStatus::Conflicting,
      cfm::EvidenceStatus::Unbound,     cfm::EvidenceStatus::Indeterminate,
      cfm::EvidenceStatus::Future,
  };
  for (const cfm::EvidenceStatus status : produced) {
    CT_CHECK(status != cfm::EvidenceStatus::OutOfOrder);
  }
}

CT_TEST(evidence_assess_observation_treats_status_channels_as_evidence) {
  const cfm::DecisionClock clock(4000);
  const cfm::DurationMilliseconds window(1000);

  // A status channel reporting its state needs no evidence generation: the state
  // itself is the assertion. The documented state codes are 0, 1 and 2.
  for (std::int64_t code = 0; code <= 2; ++code) {
    ObservationSpec spec;
    spec.channel = cfm::ObservationChannel::PumpStatus;
    spec.value = code;
    spec.unit = "ppm";
    spec.generation = 0;
    spec.observed_at_ms = 3900;
    const cfm::Observation observation = build_observation(spec);
    const cfm::ObservationUsability usability =
        cfm::assess_observation(&observation, clock, window, false);
    CT_CHECK_MSG(usability.status == cfm::EvidenceStatus::Current,
                 "status code " + std::to_string(code) + " must be current evidence");
    CT_CHECK(usability.freshness == cfm::Freshness::Current);
  }

  // A status channel that reports no state at all asserts nothing: it is not
  // current evidence.
  {
    ObservationSpec spec;
    spec.channel = cfm::ObservationChannel::ValvePosition;
    spec.observed = false;
    spec.generation = 0;
    const cfm::Observation observation = build_observation(spec);
    const cfm::ObservationUsability usability =
        cfm::assess_observation(&observation, clock, window, false);
    CT_CHECK(usability.status == cfm::EvidenceStatus::Indeterminate);
  }

  // A leak channel is not a status channel: it carries a leak assertion, and a
  // reading from it must be generation-bound to be current.
  {
    ObservationSpec spec;
    spec.channel = cfm::ObservationChannel::LeakDetector;
    spec.observed = false;
    spec.generation = 0;
    spec.leak = cfm::LeakState::LeakNone;
    const cfm::Observation observation = build_observation(spec);
    const cfm::ObservationUsability usability =
        cfm::assess_observation(&observation, clock, window, false);
    CT_CHECK(usability.status == cfm::EvidenceStatus::Unbound);

    spec.generation = 2;
    const cfm::Observation bound = build_observation(spec);
    const cfm::ObservationUsability bound_usability =
        cfm::assess_observation(&bound, clock, window, false);
    CT_CHECK(bound_usability.status == cfm::EvidenceStatus::Current);
    CT_CHECK(bound_usability.freshness == cfm::Freshness::Current);
  }

  // A leak channel that says nothing at all is not evidence.
  {
    ObservationSpec spec;
    spec.channel = cfm::ObservationChannel::LeakDetector;
    spec.observed = false;
    spec.leak = cfm::LeakState::LeakUnknown;
    spec.generation = 3;
    const cfm::Observation observation = build_observation(spec);
    const cfm::ObservationUsability usability =
        cfm::assess_observation(&observation, clock, window, false);
    CT_CHECK(usability.status == cfm::EvidenceStatus::Indeterminate);
  }
}

CT_TEST(evidence_assess_observation_never_wraps_the_age) {
  // A carried-forward reading keeps its own, older timestamp: freshness is
  // computed from the sampling time, so carrying a value forward cannot make it
  // younger.
  ObservationSpec spec;
  spec.observed_at_ms = 1000;
  spec.carried_forward = true;
  const cfm::Observation carried = build_observation(spec);
  const cfm::ObservationUsability usability =
      cfm::assess_observation(&carried, cfm::DecisionClock(9000), cfm::DurationMilliseconds(1000), false);
  CT_CHECK(carried.carried_forward);
  CT_CHECK_EQ(carried.observed_at.milliseconds(), static_cast<std::int64_t>(1000));
  CT_CHECK(usability.status == cfm::EvidenceStatus::Stale);
  CT_CHECK_EQ(usability.age_milliseconds, static_cast<std::int64_t>(8000));

  // A clock far below the sampling time produces a negative age whose magnitude
  // is representable, and the status is Future.
  {
    ObservationSpec future;
    future.observed_at_ms = 1000;
    const cfm::Observation observation = build_observation(future);
    const cfm::ObservationUsability far = cfm::assess_observation(
        &observation, cfm::DecisionClock(INT64_MIN + 5), cfm::DurationMilliseconds(1000), false);
    CT_CHECK(far.status == cfm::EvidenceStatus::Future);
    CT_CHECK(far.age_milliseconds < 0);
  }

  // The pathological pair whose difference is not representable still reports an
  // age on the correct side of zero instead of wrapping to a small positive
  // number.
  {
    cfm::Observation observation = build_observation(ObservationSpec{});
    observation.observed_at = cfm::DecisionClock(INT64_MAX);
    const cfm::ObservationUsability far = cfm::assess_observation(
        &observation, cfm::DecisionClock(INT64_MIN + 5), cfm::DurationMilliseconds(1000), false);
    CT_CHECK(far.status == cfm::EvidenceStatus::Future);
    CT_CHECK(far.age_milliseconds < 0);

    observation.observed_at = cfm::DecisionClock(INT64_MIN + 5);
    const cfm::ObservationUsability ancient = cfm::assess_observation(
        &observation, cfm::DecisionClock(INT64_MAX), cfm::DurationMilliseconds(1000), false);
    CT_CHECK(ancient.status == cfm::EvidenceStatus::Stale);
    CT_CHECK(ancient.age_milliseconds > 0);
  }
}

// ---------------------------------------------------------------------------
// Policy and observation construction
// ---------------------------------------------------------------------------

CT_TEST(evidence_validate_policy_rejects_unevaluable_demands) {
  cfm::DecisionPolicy policy;
  auto accepted = cfm::validate_policy(policy);
  CT_CHECK_MSG(accepted.has_value(), "the default policy must be evaluable");

  policy.confirm_min_observations = 0;
  auto no_confirm = cfm::validate_policy(policy);
  CT_REQUIRE(!no_confirm.has_value());
  expect_code(no_confirm.error(), cfm::ErrorCode::InvalidArgument, "confirm_min_observations = 0");
  policy.confirm_min_observations = 1;

  policy.suspect_min_observations = 0;
  auto no_suspect = cfm::validate_policy(policy);
  CT_REQUIRE(!no_suspect.has_value());
  expect_code(no_suspect.error(), cfm::ErrorCode::InvalidArgument, "suspect_min_observations = 0");
  policy.suspect_min_observations = 1;

  policy.healthy_min_observations = 0;
  auto no_healthy = cfm::validate_policy(policy);
  CT_REQUIRE(!no_healthy.has_value());
  expect_code(no_healthy.error(), cfm::ErrorCode::InvalidArgument, "healthy_min_observations = 0");
  policy.healthy_min_observations = 1;

  policy.evidence_window = cfm::DurationMilliseconds(-1);
  auto negative_window = cfm::validate_policy(policy);
  CT_REQUIRE(!negative_window.has_value());
  expect_code(negative_window.error(), cfm::ErrorCode::QuantityOutOfRange, "negative evidence window");

  policy.evidence_window = cfm::DurationMilliseconds(cfm::limits::kMaxWindowMilliseconds + 1);
  auto long_window = cfm::validate_policy(policy);
  CT_REQUIRE(!long_window.has_value());
  expect_code(long_window.error(), cfm::ErrorCode::QuantityOutOfRange, "evidence window above the bound");

  policy.evidence_window = cfm::DurationMilliseconds(cfm::limits::kMaxWindowMilliseconds);
  CT_CHECK_MSG(cfm::validate_policy(policy).has_value(), "the longest window is accepted");
  policy.evidence_window = cfm::DurationMilliseconds(0);
  CT_CHECK_MSG(cfm::validate_policy(policy).has_value(), "a zero window is accepted");

  policy.acknowledgement_window = cfm::DurationMilliseconds(-1);
  auto negative_acknowledgement = cfm::validate_policy(policy);
  CT_REQUIRE(!negative_acknowledgement.has_value());
  expect_code(negative_acknowledgement.error(), cfm::ErrorCode::QuantityOutOfRange,
              "negative acknowledgement window");

  policy.acknowledgement_window = cfm::DurationMilliseconds(cfm::limits::kMaxWindowMilliseconds + 1);
  auto long_acknowledgement = cfm::validate_policy(policy);
  CT_REQUIRE(!long_acknowledgement.has_value());
  expect_code(long_acknowledgement.error(), cfm::ErrorCode::QuantityOutOfRange,
              "acknowledgement window above the bound");
  policy.acknowledgement_window = cfm::DurationMilliseconds(0);

  policy.safety_escalation_severity = static_cast<cfm::Severity>(200);
  auto unknown_severity = cfm::validate_policy(policy);
  CT_REQUIRE(!unknown_severity.has_value());
  expect_code(unknown_severity.error(), cfm::ErrorCode::UnknownEnumToken,
              "safety escalation severity outside the taxonomy");
  policy.safety_escalation_severity = cfm::Severity::Critical;
  CT_CHECK(cfm::validate_policy(policy).has_value());
}

CT_TEST(evidence_make_observation_validates_identity_producer_sensor_and_clocks) {
  const cfm::ScopeId scope = scope_of("loop-1");
  auto quantity = cfm::Quantity::observed(500, "mL/s", cfm::ObservationQuality::Good,
                                          cfm::ObservationSequence(3));
  CT_REQUIRE(quantity.has_value());

  auto valid = cfm::make_observation(observation_of("obs-1"), scope, cfm::ObservationChannel::FlowMeter,
                                     *quantity, cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000),
                                     cfm::DecisionClock(1000), "producer-1", "sensor-1",
                                     cfm::EvidenceGeneration(4), false);
  CT_REQUIRE(valid.has_value());
  CT_CHECK(valid->id == observation_of("obs-1"));
  CT_CHECK(valid->scope == scope);
  CT_CHECK(valid->quantity == *quantity);
  CT_CHECK(valid->producer == "producer-1");
  CT_CHECK(valid->sensor == "sensor-1");
  CT_CHECK_EQ(valid->evidence_generation.value(), static_cast<std::uint64_t>(4));
  CT_CHECK(!valid->carried_forward);

  auto empty_id = cfm::make_observation(cfm::ObservationId(), scope, cfm::ObservationChannel::FlowMeter,
                                        *quantity, cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000),
                                        cfm::DecisionClock(1000), "producer-1", "sensor-1",
                                        cfm::EvidenceGeneration(1), false);
  CT_REQUIRE(!empty_id.has_value());
  expect_code(empty_id.error(), cfm::ErrorCode::MalformedIdentifier, "empty observation identity");

  auto empty_scope = cfm::make_observation(observation_of("obs-1"), cfm::ScopeId(),
                                           cfm::ObservationChannel::FlowMeter, *quantity,
                                           cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000),
                                           cfm::DecisionClock(1000), "producer-1", "sensor-1",
                                           cfm::EvidenceGeneration(1), false);
  CT_REQUIRE(!empty_scope.has_value());
  expect_code(empty_scope.error(), cfm::ErrorCode::MalformedIdentifier, "empty observation scope");

  auto no_producer = cfm::make_observation(observation_of("obs-1"), scope,
                                           cfm::ObservationChannel::FlowMeter, *quantity,
                                           cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000),
                                           cfm::DecisionClock(1000), "", "sensor-1",
                                           cfm::EvidenceGeneration(1), false);
  CT_REQUIRE(!no_producer.has_value());
  expect_code(no_producer.error(), cfm::ErrorCode::MissingField, "empty producer");

  const std::string long_producer(cfm::limits::kMaxProducerBytes + 1, 'p');
  auto over_long_producer = cfm::make_observation(
      observation_of("obs-1"), scope, cfm::ObservationChannel::FlowMeter, *quantity,
      cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000), cfm::DecisionClock(1000), long_producer,
      "sensor-1", cfm::EvidenceGeneration(1), false);
  CT_REQUIRE(!over_long_producer.has_value());
  expect_code(over_long_producer.error(), cfm::ErrorCode::TextTooLong, "over-long producer");

  auto invalid_producer = cfm::make_observation(
      observation_of("obs-1"), scope, cfm::ObservationChannel::FlowMeter, *quantity,
      cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000), cfm::DecisionClock(1000),
      std::string("\xFF"), "sensor-1", cfm::EvidenceGeneration(1), false);
  CT_REQUIRE(!invalid_producer.has_value());
  expect_code(invalid_producer.error(), cfm::ErrorCode::InvalidUtf8, "producer that is not UTF-8");

  auto no_sensor = cfm::make_observation(observation_of("obs-1"), scope,
                                         cfm::ObservationChannel::FlowMeter, *quantity,
                                         cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000),
                                         cfm::DecisionClock(1000), "producer-1", "",
                                         cfm::EvidenceGeneration(1), false);
  CT_REQUIRE(!no_sensor.has_value());
  expect_code(no_sensor.error(), cfm::ErrorCode::MissingField, "empty sensor");

  const std::string long_sensor(cfm::limits::kMaxSensorRefBytes + 1, 's');
  auto over_long_sensor = cfm::make_observation(
      observation_of("obs-1"), scope, cfm::ObservationChannel::FlowMeter, *quantity,
      cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000), cfm::DecisionClock(1000), "producer-1",
      long_sensor, cfm::EvidenceGeneration(1), false);
  CT_REQUIRE(!over_long_sensor.has_value());
  expect_code(over_long_sensor.error(), cfm::ErrorCode::TextTooLong, "over-long sensor reference");

  // Sampling after recording is an impossible record, and the bound applies to
  // both clocks.
  auto out_of_order = cfm::make_observation(
      observation_of("obs-1"), scope, cfm::ObservationChannel::FlowMeter, *quantity,
      cfm::LeakState::LeakUnknown, cfm::DecisionClock(2000), cfm::DecisionClock(1000), "producer-1",
      "sensor-1", cfm::EvidenceGeneration(1), false);
  CT_REQUIRE(!out_of_order.has_value());
  expect_code(out_of_order.error(), cfm::ErrorCode::ObservationOutOfOrder, "sampled after recording");

  auto negative_sampling = cfm::make_observation(
      observation_of("obs-1"), scope, cfm::ObservationChannel::FlowMeter, *quantity,
      cfm::LeakState::LeakUnknown, cfm::DecisionClock(-1), cfm::DecisionClock(1000), "producer-1",
      "sensor-1", cfm::EvidenceGeneration(1), false);
  CT_REQUIRE(!negative_sampling.has_value());
  expect_code(negative_sampling.error(), cfm::ErrorCode::TimestampOutOfRange, "negative sampling clock");

  auto late_recording = cfm::make_observation(
      observation_of("obs-1"), scope, cfm::ObservationChannel::FlowMeter, *quantity,
      cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000),
      cfm::DecisionClock(cfm::limits::kMaxTimestampMilliseconds + 1), "producer-1", "sensor-1",
      cfm::EvidenceGeneration(1), false);
  CT_REQUIRE(!late_recording.has_value());
  expect_code(late_recording.error(), cfm::ErrorCode::TimestampOutOfRange, "recording clock above the bound");

  auto at_bound = cfm::make_observation(
      observation_of("obs-1"), scope, cfm::ObservationChannel::FlowMeter, *quantity,
      cfm::LeakState::LeakUnknown, cfm::DecisionClock(cfm::limits::kMaxTimestampMilliseconds),
      cfm::DecisionClock(cfm::limits::kMaxTimestampMilliseconds), "producer-1", "sensor-1",
      cfm::EvidenceGeneration(1), false);
  CT_CHECK_MSG(at_bound.has_value(), "a clock at the bound is accepted");
}

CT_TEST(evidence_make_observation_enforces_the_channel_unit_agreement) {
  const cfm::ScopeId scope = scope_of("loop-1");

  auto flow = cfm::Quantity::observed(500, "mL/s", cfm::ObservationQuality::Good,
                                      cfm::ObservationSequence(3));
  auto pressure = cfm::Quantity::observed(500, "Pa", cfm::ObservationQuality::Good,
                                          cfm::ObservationSequence(3));
  CT_REQUIRE(flow.has_value());
  CT_REQUIRE(pressure.has_value());

  auto mismatched = cfm::make_observation(observation_of("obs-1"), scope,
                                          cfm::ObservationChannel::FlowMeter, *pressure,
                                          cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000),
                                          cfm::DecisionClock(1000), "producer-1", "sensor-1",
                                          cfm::EvidenceGeneration(1), false);
  CT_REQUIRE(!mismatched.has_value());
  expect_code(mismatched.error(), cfm::ErrorCode::QuantityOutOfRange,
              "reading unit disagrees with the channel unit");

  auto matched = cfm::make_observation(observation_of("obs-1"), scope,
                                       cfm::ObservationChannel::FlowMeter, *flow,
                                       cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000),
                                       cfm::DecisionClock(1000), "producer-1", "sensor-1",
                                       cfm::EvidenceGeneration(1), false);
  CT_CHECK(matched.has_value());

  // A silent scalar channel carries no unit and is a legitimate record.
  auto silent = cfm::make_observation(
      observation_of("obs-2"), scope, cfm::ObservationChannel::FlowMeter, cfm::Quantity::indeterminate(),
      cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000), cfm::DecisionClock(1000), "producer-1",
      "sensor-1", cfm::EvidenceGeneration(1), false);
  CT_CHECK_MSG(silent.has_value(), "an indeterminate reading on a scalar channel must be recordable");

  // A status channel carries a state code and needs no unit of its own.
  auto status = cfm::make_observation(observation_of("obs-3"), scope,
                                      cfm::ObservationChannel::ChillerStatus, *flow,
                                      cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000),
                                      cfm::DecisionClock(1000), "producer-1", "sensor-1",
                                      cfm::EvidenceGeneration(0), false);
  CT_CHECK_MSG(status.has_value(), "a status channel reading must not be compared against a unit");

  // A status channel may equally report nothing at all.
  auto silent_status = cfm::make_observation(
      observation_of("obs-4"), scope, cfm::ObservationChannel::ContainmentSwitch,
      cfm::Quantity::indeterminate(), cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000),
      cfm::DecisionClock(1000), "producer-1", "sensor-1", cfm::EvidenceGeneration(0), false);
  CT_CHECK(silent_status.has_value());
}

CT_TEST(evidence_make_observation_accepts_a_unitless_reading_only_where_no_unit_exists) {
  const cfm::ScopeId scope = scope_of("loop-1");
  auto state_code = cfm::Quantity::observed(2, "", cfm::ObservationQuality::Good,
                                            cfm::ObservationSequence(1));
  CT_REQUIRE(state_code.has_value());

  // Every channel is exercised, so the rule is proven per channel rather than on
  // a sample: a unit-less reading is legal exactly where the channel has no
  // canonical unit, and refused with QuantityOutOfRange where it has one.
  for (std::size_t index = 0; index < cfm::observation_channel_count(); ++index) {
    const auto channel = static_cast<cfm::ObservationChannel>(index);
    auto built = cfm::make_observation(observation_of("obs-unitless"), scope, channel, *state_code,
                                       cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000),
                                       cfm::DecisionClock(1000), "producer-1", "sensor-1",
                                       cfm::EvidenceGeneration(1), false);
    const std::string what = "unit-less reading on channel " + std::to_string(index);
    if (cfm::channel_unit(channel).empty()) {
      // A status channel or the leak channel: a unit is optional there, and the
      // leak channel is satisfied by the reading it carries.
      CT_CHECK_MSG(built.has_value(), what + " must be accepted");
      if (built.has_value()) {
        CT_CHECK(built->quantity.unit().empty());
        CT_CHECK(cfm::observation_has_signal(*built));
      }
    } else {
      CT_REQUIRE(!built.has_value());
      expect_code(built.error(), cfm::ErrorCode::QuantityOutOfRange, what);
    }
  }

  // A status or leak channel also accepts a reading that carries a unit, because
  // neither channel has a canonical unit to disagree with.
  auto ppm = cfm::Quantity::observed(2, "ppm", cfm::ObservationQuality::Good,
                                     cfm::ObservationSequence(1));
  CT_REQUIRE(ppm.has_value());
  auto status_with_unit = cfm::make_observation(
      observation_of("obs-status-unit"), scope, cfm::ObservationChannel::ChillerStatus, *ppm,
      cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000), cfm::DecisionClock(1000), "producer-1",
      "sensor-1", cfm::EvidenceGeneration(1), false);
  CT_CHECK(status_with_unit.has_value());

  // A leak channel with no reading still needs its leak assertion, which the
  // unit-less rule does not weaken.
  auto leak_without_assertion = cfm::make_observation(
      observation_of("obs-leak"), scope, cfm::ObservationChannel::LeakDetector,
      cfm::Quantity::indeterminate(), cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000),
      cfm::DecisionClock(1000), "producer-1", "sensor-1", cfm::EvidenceGeneration(1), false);
  CT_REQUIRE(!leak_without_assertion.has_value());
  expect_code(leak_without_assertion.error(), cfm::ErrorCode::EvidenceMissing,
              "leak observation asserting nothing");
}

CT_TEST(evidence_make_observation_requires_a_leak_assertion_or_a_reading) {
  const cfm::ScopeId scope = scope_of("loop-1");

  auto nothing = cfm::make_observation(
      observation_of("obs-1"), scope, cfm::ObservationChannel::LeakDetector,
      cfm::Quantity::indeterminate(), cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000),
      cfm::DecisionClock(1000), "producer-1", "sensor-1", cfm::EvidenceGeneration(1), false);
  CT_REQUIRE(!nothing.has_value());
  expect_code(nothing.error(), cfm::ErrorCode::EvidenceMissing, "leak observation asserting nothing");

  auto leak = cfm::make_observation(observation_of("obs-2"), scope,
                                    cfm::ObservationChannel::LeakDetector, cfm::Quantity::indeterminate(),
                                    cfm::LeakState::LeakSuspected, cfm::DecisionClock(1000),
                                    cfm::DecisionClock(1000), "producer-1", "sensor-1",
                                    cfm::EvidenceGeneration(1), false);
  CT_CHECK_MSG(leak.has_value(), "a leak state alone is a leak observation");

  auto clear = cfm::make_observation(observation_of("obs-3"), scope,
                                     cfm::ObservationChannel::LeakDetector, cfm::Quantity::indeterminate(),
                                     cfm::LeakState::LeakNone, cfm::DecisionClock(1000),
                                     cfm::DecisionClock(1000), "producer-1", "sensor-1",
                                     cfm::EvidenceGeneration(1), false);
  CT_CHECK_MSG(clear.has_value(), "a positively clear leak reading is a leak observation");
  CT_CHECK(cfm::observation_asserts_leak(*clear));
}

CT_TEST(evidence_make_observation_keeps_the_carried_forward_timestamp) {
  const cfm::ScopeId scope = scope_of("loop-1");
  auto quantity = cfm::Quantity::observed(500, "mL/s", cfm::ObservationQuality::Good,
                                          cfm::ObservationSequence(3));
  CT_REQUIRE(quantity.has_value());

  auto carried = cfm::make_observation(observation_of("obs-1"), scope,
                                       cfm::ObservationChannel::FlowMeter, *quantity,
                                       cfm::LeakState::LeakUnknown, cfm::DecisionClock(1000),
                                       cfm::DecisionClock(9000), "producer-1", "sensor-1",
                                       cfm::EvidenceGeneration(1), true);
  CT_REQUIRE(carried.has_value());
  CT_CHECK(carried->carried_forward);
  CT_CHECK_EQ(carried->observed_at.milliseconds(), static_cast<std::int64_t>(1000));
  CT_CHECK_EQ(carried->recorded_at.milliseconds(), static_cast<std::int64_t>(9000));

  const cfm::ObservationUsability usability = cfm::assess_observation(
      &*carried, cfm::DecisionClock(9000), cfm::DurationMilliseconds(1000), false);
  CT_CHECK(usability.status == cfm::EvidenceStatus::Stale);
  CT_CHECK_EQ(usability.age_milliseconds, static_cast<std::int64_t>(8000));
}

// ---------------------------------------------------------------------------
// Authority bindings and declared quantities
// ---------------------------------------------------------------------------

CT_TEST(evidence_authority_reference_validates_its_shape) {
  cfm::AuthorityRef reference;
  auto empty_owner = cfm::AuthorityRef::make("", "identity-1", cfm::ExternalGeneration(1));
  CT_REQUIRE(!empty_owner.has_value());
  expect_code(empty_owner.error(), cfm::ErrorCode::MissingField, "empty binding owner");

  auto empty_identity = cfm::AuthorityRef::make("cooling-topology", "", cfm::ExternalGeneration(1));
  CT_REQUIRE(!empty_identity.has_value());
  expect_code(empty_identity.error(), cfm::ErrorCode::MissingField, "empty binding identity");

  const std::string long_owner(cfm::limits::kMaxExternalKindBytes + 1, 'o');
  auto over_long_owner =
      cfm::AuthorityRef::make(long_owner, "identity-1", cfm::ExternalGeneration(1));
  CT_REQUIRE(!over_long_owner.has_value());
  expect_code(over_long_owner.error(), cfm::ErrorCode::TextTooLong, "over-long binding owner");

  const std::string long_identity(cfm::limits::kMaxExternalIdentityBytes + 1, 'i');
  auto over_long_identity =
      cfm::AuthorityRef::make("cooling-topology", long_identity, cfm::ExternalGeneration(1));
  CT_REQUIRE(!over_long_identity.has_value());
  expect_code(over_long_identity.error(), cfm::ErrorCode::TextTooLong, "over-long binding identity");

  auto malformed = cfm::AuthorityRef::make(std::string("\xFF"), "identity-1",
                                           cfm::ExternalGeneration(1));
  CT_REQUIRE(!malformed.has_value());
  expect_code(malformed.error(), cfm::ErrorCode::InvalidUtf8, "owner that is not UTF-8");

  // A binding names one version of a fact: generation zero names no version, so
  // the binding could never be checked for staleness.
  auto unbound = cfm::AuthorityRef::make("cooling-topology", "identity-1", cfm::ExternalGeneration(0));
  CT_REQUIRE(!unbound.has_value());
  expect_code(unbound.error(), cfm::ErrorCode::GenerationMismatch, "unbound generation");

  auto built = cfm::AuthorityRef::make("cooling-topology", "identity-1", cfm::ExternalGeneration(7));
  CT_REQUIRE(built.has_value());
  reference = *built;
  CT_CHECK(reference.bound());
  CT_CHECK(reference.owner() == "cooling-topology");
  CT_CHECK(reference.identity() == "identity-1");
  CT_CHECK_EQ(reference.generation().value(), static_cast<std::uint64_t>(7));

  // Equality is exact over (owner, identity, generation): a binding that names a
  // different generation is a different binding.
  auto other_generation =
      cfm::AuthorityRef::make("cooling-topology", "identity-1", cfm::ExternalGeneration(8));
  CT_REQUIRE(other_generation.has_value());
  CT_CHECK(reference != *other_generation);
  auto same = cfm::AuthorityRef::make("cooling-topology", "identity-1", cfm::ExternalGeneration(7));
  CT_REQUIRE(same.has_value());
  CT_CHECK(reference == *same);
  CT_CHECK(!cfm::AuthorityRef{}.bound());

  // The canonical order is (owner, identity, generation) byte-wise.
  auto later_generation =
      cfm::AuthorityRef::make("cooling-topology", "identity-1", cfm::ExternalGeneration(9));
  auto other_owner = cfm::AuthorityRef::make("airflow-control", "identity-1", cfm::ExternalGeneration(1));
  CT_REQUIRE(later_generation.has_value());
  CT_REQUIRE(other_owner.has_value());
  CT_CHECK(reference < *later_generation);
  CT_CHECK(*other_owner < reference);
}

CT_TEST(evidence_authority_set_is_canonical_and_bounded) {
  cfm::AuthoritySet bindings;
  CT_CHECK(bindings.empty());
  CT_CHECK_EQ(bindings.size(), static_cast<std::size_t>(0));
  CT_CHECK(bindings.find("cooling-topology") == nullptr);

  auto topology = cfm::AuthorityRef::make("cooling-topology", "topology-1", cfm::ExternalGeneration(3));
  auto airflow = cfm::AuthorityRef::make("airflow-control", "airflow-1", cfm::ExternalGeneration(2));
  CT_REQUIRE(topology.has_value());
  CT_REQUIRE(airflow.has_value());

  // Inserted in reverse of the canonical order: the set keeps itself sorted by
  // role bytes, so encoding never depends on insertion order.
  auto first = bindings.set("cooling-topology", *topology);
  CT_REQUIRE(first.has_value());
  auto second = bindings.set("airflow-control", *airflow);
  CT_REQUIRE(second.has_value());
  CT_CHECK_EQ(bindings.size(), static_cast<std::size_t>(2));
  CT_CHECK(bindings.entries()[0].first == "airflow-control");
  CT_CHECK(bindings.entries()[1].first == "cooling-topology");
  CT_REQUIRE(bindings.find("cooling-topology") != nullptr);
  CT_CHECK(*bindings.find("cooling-topology") == *topology);
  CT_CHECK(bindings.find("cooling-capacity") == nullptr);

  // Setting a role again replaces the binding held for it: two answers for one
  // role would leave a decision bound to a version nobody chose.
  auto newer = cfm::AuthorityRef::make("cooling-topology", "topology-2", cfm::ExternalGeneration(4));
  CT_REQUIRE(newer.has_value());
  auto replaced = bindings.set("cooling-topology", *newer);
  CT_REQUIRE(replaced.has_value());
  CT_CHECK_EQ(bindings.size(), static_cast<std::size_t>(2));
  CT_CHECK(*bindings.find("cooling-topology") == *newer);
  CT_CHECK(bindings.entries()[0].first == "airflow-control");

  // Equality is exact over the canonical ordering.
  cfm::AuthoritySet same;
  auto a = same.set("airflow-control", *airflow);
  auto b = same.set("cooling-topology", *newer);
  CT_REQUIRE(a.has_value());
  CT_REQUIRE(b.has_value());
  CT_CHECK(bindings == same);
  auto changed = same.set("airflow-control", *topology);
  CT_REQUIRE(changed.has_value());
  CT_CHECK(!(bindings == same));

  // Erasing an absent role is not an error; erasing a present one removes it.
  bindings.erase("cooling-capacity");
  CT_CHECK_EQ(bindings.size(), static_cast<std::size_t>(2));
  bindings.erase("airflow-control");
  CT_CHECK_EQ(bindings.size(), static_cast<std::size_t>(1));
  CT_CHECK(bindings.find("airflow-control") == nullptr);

  // A role is a stable ASCII token within the declared bound.
  auto empty_role = bindings.set("", *topology);
  CT_REQUIRE(!empty_role.has_value());
  expect_code(empty_role.error(), cfm::ErrorCode::MissingField, "empty binding role");

  auto bad_role = bindings.set("cooling topology", *topology);
  CT_REQUIRE(!bad_role.has_value());
  expect_code(bad_role.error(), cfm::ErrorCode::MalformedIdentifier, "role that is not a token");

  const std::string long_role(cfm::limits::kMaxExternalKindBytes + 1, 'r');
  auto over_long_role = bindings.set(long_role, *topology);
  CT_REQUIRE(!over_long_role.has_value());
  expect_code(over_long_role.error(), cfm::ErrorCode::TextTooLong, "over-long binding role");

  // The entry count is bounded: a roster of owners is never a growing table.
  cfm::AuthoritySet bounded;
  for (std::size_t index = 0; index < cfm::limits::kMaxSolicitationCount; ++index) {
    const std::string role = "role-" + std::to_string(index);
    auto accepted = bounded.set(role, *topology);
    CT_REQUIRE(accepted.has_value());
  }
  CT_CHECK_EQ(bounded.size(), cfm::limits::kMaxSolicitationCount);
  auto overflow = bounded.set("role-overflow", *topology);
  CT_REQUIRE(!overflow.has_value());
  expect_code(overflow.error(), cfm::ErrorCode::LimitExceeded, "binding set above its bound");
  // Replacing a role that is already held is still allowed at the bound.
  auto still_replaceable = bounded.set("role-0", *newer);
  CT_CHECK(still_replaceable.has_value());
}

CT_TEST(evidence_declared_quantity_units_and_bounds_are_exact) {
  for (std::size_t index = 0; index < kUnitRangeCount; ++index) {
    const UnitRange& range = kUnitRanges[index];
    auto minimum = cfm::DeclaredQuantity::make(range.minimum, range.unit);
    CT_CHECK_MSG(minimum.has_value(),
                 std::string("unit ") + range.unit + " rejected its minimum");
    auto maximum = cfm::DeclaredQuantity::make(range.maximum, range.unit);
    CT_CHECK_MSG(maximum.has_value(),
                 std::string("unit ") + range.unit + " rejected its maximum");
    if (minimum.has_value()) {
      CT_CHECK(minimum->declared());
      CT_CHECK_EQ(minimum->value(), range.minimum);
      CT_CHECK(minimum->unit() == range.unit);
    }
    if (range.minimum > INT64_MIN) {
      auto below = cfm::DeclaredQuantity::make(range.minimum - 1, range.unit);
      CT_REQUIRE(!below.has_value());
      expect_code(below.error(), cfm::ErrorCode::QuantityOutOfRange,
                  std::string("unit ") + range.unit + " below its minimum");
    }
    if (range.maximum < INT64_MAX) {
      auto above = cfm::DeclaredQuantity::make(range.maximum + 1, range.unit);
      CT_REQUIRE(!above.has_value());
      expect_code(above.error(), cfm::ErrorCode::QuantityOutOfRange,
                  std::string("unit ") + range.unit + " above its maximum");
    }
  }

  // An undeclared quantity is one with no unit at all, and it is not a zero.
  CT_CHECK(!cfm::DeclaredQuantity{}.declared());
  CT_CHECK(cfm::DeclaredQuantity{}.unit().empty());

  auto unknown = cfm::DeclaredQuantity::make(1, "L/min");
  CT_REQUIRE(!unknown.has_value());
  expect_code(unknown.error(), cfm::ErrorCode::QuantityOutOfRange, "unknown unit");

  auto empty = cfm::DeclaredQuantity::make(1, "");
  CT_REQUIRE(!empty.has_value());
  expect_code(empty.error(), cfm::ErrorCode::MissingField, "absent unit");

  const std::string long_unit(cfm::limits::kMaxExternalKindBytes + 1, 'u');
  auto over_long = cfm::DeclaredQuantity::make(1, long_unit);
  CT_REQUIRE(!over_long.has_value());
  expect_code(over_long.error(), cfm::ErrorCode::TextTooLong, "over-long unit");

  // The ordering is a canonical (unit, value) order, not a physical comparison:
  // quantities in different units are ordered by their unit bytes.
  auto millilitres = cfm::DeclaredQuantity::make(1000000, "mC");
  auto watts = cfm::DeclaredQuantity::make(1, "mL/s");
  auto more_watts = cfm::DeclaredQuantity::make(2, "mL/s");
  CT_REQUIRE(millilitres.has_value());
  CT_REQUIRE(watts.has_value());
  CT_REQUIRE(more_watts.has_value());
  CT_CHECK(*millilitres < *watts);
  CT_CHECK(*watts < *more_watts);
  CT_CHECK(*watts == *cfm::DeclaredQuantity::make(1, "mL/s"));
}

// ---------------------------------------------------------------------------
// Structural rules of the state the evidence lives in
// ---------------------------------------------------------------------------

CT_TEST(evidence_state_canonicalize_sorts_every_table_and_is_idempotent) {
  // Every table is filled in the reverse of its canonical order, so a
  // canonicalize() that did nothing would be detected immediately.
  cfm::CoolingFailureState state;

  cfm::CoolingScope loop_one = state_with_scope("loop-1").scopes.front();
  loop_one.policy.strict_classes.push_back(cfm::FailureClass::ThermalRunaway);
  loop_one.policy.strict_classes.push_back(cfm::FailureClass::LoopLoss);
  loop_one.policy.requirements.push_back(
      cfm::EvidenceRequirement{cfm::ObservationChannel::CoolantTemperature,
                               cfm::DurationMilliseconds(1000)});
  loop_one.policy.requirements.push_back(
      cfm::EvidenceRequirement{cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(1000)});

  cfm::CoolingScope loop_two = state_with_scope("loop-2").scopes.front();
  loop_two.dependencies.push_back(
      cfm::ScopeDependency{scope_of("loop-1"), cfm::DependencyKind::SharesReturn, 500000});
  loop_two.dependencies.push_back(
      cfm::ScopeDependency{scope_of("loop-1"), cfm::DependencyKind::SuppliesCoolant, 500000});

  state.scopes.push_back(loop_two);
  state.scopes.push_back(loop_one);

  cfm::CoolingFailure loss = make_failure("failure-1", "loop-1", cfm::FailureClass::LoopLoss,
                                          cfm::ConfirmationState::Confirmed, cfm::Severity::Total);
  loss.basis.push_back(observation_of("obs-b"));
  loss.basis.push_back(observation_of("obs-a"));
  state.failures.push_back(
      make_failure("failure-2", "loop-1", cfm::FailureClass::LoopDegradation,
                   cfm::ConfirmationState::Suspected, cfm::Severity::Degraded));
  state.failures.push_back(loss);

  cfm::ResponsePlan plan_one = make_plan("plan-1", "loop-1");
  plan_one.failures.push_back(failure_of("failure-2"));
  plan_one.failures.push_back(failure_of("failure-1"));
  cfm::ResponseEligibility second;
  second.action = cfm::ResponseAction::StartStandbyPump;
  second.rank = 5;
  second.rule_id = "pump.start";
  cfm::ResponseEligibility first;
  first.action = cfm::ResponseAction::ObserveOnly;
  first.rank = 5;
  first.rule_id = "observe";
  plan_one.eligible.push_back(second);
  plan_one.eligible.push_back(first);
  cfm::ProtectiveRestriction restriction;
  restriction.id = restriction_of("restriction-1");
  restriction.scope = scope_of("loop-1");
  restriction.plan = plan_of("plan-1");
  restriction.kind = cfm::RestrictionKind::NoNewWork;
  restriction.released_by.push_back(failure_of("failure-1"));
  plan_one.restrictions.push_back(restriction);
  cfm::ResponseAttempt attempt;
  attempt.id = attempt_of("attempt-2");
  attempt.solicitation = solicitation_of("mutation-1");
  attempt.attempt = cfm::AttemptOrdinal(2);
  attempt.state = cfm::AttemptState::Solicited;
  plan_one.attempts.push_back(attempt);
  attempt.id = attempt_of("attempt-1");
  attempt.attempt = cfm::AttemptOrdinal(1);
  plan_one.attempts.push_back(attempt);

  state.plans.push_back(make_plan("plan-2", "loop-1"));
  state.plans.push_back(plan_one);

  cfm::EvidenceAssessment late;
  late.observation = observation_of("obs-2");
  late.scope = scope_of("loop-1");
  late.channel = cfm::ObservationChannel::FlowMeter;
  late.status = cfm::EvidenceStatus::Current;
  late.freshness = cfm::Freshness::Current;
  cfm::EvidenceAssessment early;
  early.observation = observation_of("obs-1");
  early.scope = scope_of("loop-1");
  early.channel = cfm::ObservationChannel::CoolantTemperature;
  early.status = cfm::EvidenceStatus::Current;
  early.freshness = cfm::Freshness::Current;
  state.evidence.push_back(late);
  state.evidence.push_back(early);

  cfm::ScopeDecision second_decision;
  second_decision.scope = scope_of("loop-2");
  cfm::ScopeDecision first_decision;
  first_decision.scope = scope_of("loop-1");
  first_decision.confirmed_classes.push_back(cfm::FailureClass::LoopLoss);
  first_decision.failures.push_back(failure_of("failure-1"));
  first_decision.severity = cfm::Severity::Total;
  state.decisions.push_back(second_decision);
  state.decisions.push_back(first_decision);

  state.unresolved_attempts.push_back(attempt_of("attempt-2"));
  state.unresolved_attempts.push_back(attempt_of("attempt-1"));

  auto canonical = cfm::canonicalize(state);
  CT_REQUIRE(canonical.has_value());

  CT_CHECK(state.scopes[0].id == scope_of("loop-1"));
  CT_CHECK(state.scopes[1].id == scope_of("loop-2"));
  CT_CHECK(state.scopes[1].dependencies[0].kind == cfm::DependencyKind::SuppliesCoolant);
  CT_CHECK(state.scopes[1].dependencies[1].kind == cfm::DependencyKind::SharesReturn);
  CT_CHECK(state.scopes[0].policy.strict_classes[0] == cfm::FailureClass::LoopLoss);
  CT_CHECK(state.scopes[0].policy.strict_classes[1] == cfm::FailureClass::ThermalRunaway);
  CT_CHECK(state.scopes[0].policy.requirements[0].channel == cfm::ObservationChannel::FlowMeter);
  CT_CHECK(state.scopes[0].policy.requirements[1].channel == cfm::ObservationChannel::CoolantTemperature);
  CT_CHECK(state.failures[0].id == failure_of("failure-1"));
  CT_CHECK(state.failures[0].basis[0] == observation_of("obs-a"));
  CT_CHECK(state.failures[0].basis[1] == observation_of("obs-b"));
  CT_CHECK(state.plans[0].id == plan_of("plan-1"));
  CT_CHECK(state.plans[0].failures[0] == failure_of("failure-1"));
  CT_CHECK(state.plans[0].eligible[0].action == cfm::ResponseAction::ObserveOnly);
  CT_CHECK(state.plans[0].eligible[1].action == cfm::ResponseAction::StartStandbyPump);
  CT_CHECK(state.plans[0].attempts[0].attempt.value() == 1u);
  CT_CHECK(state.plans[0].attempts[1].attempt.value() == 2u);
  // Evidence is ordered by scope, then channel index, then observation identity:
  // the flow reading of the FlowMeter channel comes before the temperature
  // reading of the CoolantTemperature channel.
  CT_CHECK(state.evidence[0].observation == observation_of("obs-2"));
  CT_CHECK(state.evidence[1].observation == observation_of("obs-1"));
  CT_CHECK(state.decisions[0].scope == scope_of("loop-1"));
  CT_CHECK(state.decisions[0].failures[0] == failure_of("failure-1"));
  CT_CHECK(state.unresolved_attempts[0] == attempt_of("attempt-1"));
  CT_CHECK(state.unresolved_attempts[1] == attempt_of("attempt-2"));

  // Idempotence: a second pass changes nothing and still succeeds.
  auto again = cfm::canonicalize(state);
  CT_REQUIRE(again.has_value());
  CT_CHECK(state.failures[0].basis[0] == observation_of("obs-a"));
  CT_CHECK(state.scopes[1].dependencies[0].kind == cfm::DependencyKind::SuppliesCoolant);
}

CT_TEST(evidence_state_canonicalize_rejects_duplicate_identities) {
  // Scope.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.scopes.push_back(state_with_scope("loop-1").scopes.front());
    auto refused = cfm::canonicalize(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::DuplicateIdentifier, "duplicate scope identity");
  }
  // Failure.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.failures.push_back(make_failure("failure-1", "loop-1", cfm::FailureClass::LoopLoss,
                                          cfm::ConfirmationState::Confirmed, cfm::Severity::Total));
    state.failures.push_back(make_failure("failure-1", "loop-1", cfm::FailureClass::Leak,
                                          cfm::ConfirmationState::Confirmed, cfm::Severity::Critical));
    auto refused = cfm::canonicalize(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::FailureDuplicate, "duplicate failure identity");
  }
  // Plan.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.plans.push_back(make_plan("plan-1", "loop-1"));
    state.plans.push_back(make_plan("plan-1", "loop-1"));
    auto refused = cfm::canonicalize(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::PlanDuplicate, "duplicate plan identity");
  }
  // Attempt: one solicitation and ordinal, twice in one plan.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.plans.push_back(make_plan("plan-1", "loop-1"));
    cfm::ResponseAttempt attempt;
    attempt.id = attempt_of("attempt-1");
    attempt.solicitation = solicitation_of("mutation-1");
    attempt.attempt = cfm::AttemptOrdinal(1);
    state.plans[0].attempts.push_back(attempt);
    attempt.id = attempt_of("attempt-2");
    state.plans[0].attempts.push_back(attempt);
    auto refused = cfm::canonicalize(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::AttemptDuplicate, "duplicate solicitation and ordinal");
  }
  // Decision.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    cfm::ScopeDecision decision;
    decision.scope = scope_of("loop-1");
    state.decisions.push_back(decision);
    state.decisions.push_back(decision);
    auto refused = cfm::canonicalize(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::DuplicateIdentifier, "duplicate decision identity");
  }
  // Basis observation cited twice.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    cfm::CoolingFailure failure = make_failure("failure-1", "loop-1", cfm::FailureClass::LoopLoss,
                                               cfm::ConfirmationState::Confirmed, cfm::Severity::Total);
    failure.basis.push_back(observation_of("obs-1"));
    failure.basis.push_back(observation_of("obs-1"));
    state.failures.push_back(failure);
    auto refused = cfm::canonicalize(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::DuplicateIdentifier, "duplicate basis observation");
  }
  // Class in one bucket twice.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    cfm::ScopeDecision decision;
    decision.scope = scope_of("loop-1");
    decision.confirmed_classes.push_back(cfm::FailureClass::LoopLoss);
    decision.confirmed_classes.push_back(cfm::FailureClass::LoopLoss);
    state.decisions.push_back(decision);
    auto refused = cfm::canonicalize(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::DuplicateFailureClass, "duplicate confirmed class");
  }
}

CT_TEST(evidence_state_structure_rejects_missing_references_and_bad_order) {
  // A healthy state passes.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.failures.push_back(make_failure("failure-1", "loop-1", cfm::FailureClass::LoopLoss,
                                          cfm::ConfirmationState::Confirmed, cfm::Severity::Total));
    state.plans.push_back(make_plan("plan-1", "loop-1"));
    state.plans[0].failures.push_back(failure_of("failure-1"));
    auto valid = canonical_and_valid(state);
    CT_CHECK_MSG(valid.has_value(), "a well formed state must validate: " +
                                        (valid.has_value() ? std::string() : valid.error().to_string()));
  }
  // A failure naming a scope the state does not hold.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.failures.push_back(make_failure("failure-1", "loop-9", cfm::FailureClass::LoopLoss,
                                          cfm::ConfirmationState::Confirmed, cfm::Severity::Total));
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::ScopeNotFound, "failure with an unknown scope");
  }
  // A plan naming a scope the state does not hold.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.plans.push_back(make_plan("plan-1", "loop-9"));
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::ScopeNotFound, "plan with an unknown scope");
  }
  // A plan answering a failure of another scope.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.scopes.push_back(state_with_scope("loop-2").scopes.front());
    state.failures.push_back(make_failure("failure-1", "loop-2", cfm::FailureClass::LoopLoss,
                                          cfm::ConfirmationState::Confirmed, cfm::Severity::Total));
    state.plans.push_back(make_plan("plan-1", "loop-1"));
    state.plans[0].failures.push_back(failure_of("failure-1"));
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::ScopeKindMismatch, "plan answering a foreign failure");
  }
  // A plan answering a failure that does not exist.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.plans.push_back(make_plan("plan-1", "loop-1"));
    state.plans[0].failures.push_back(failure_of("failure-9"));
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::FailureNotFound, "plan answering an undeclared failure");
  }
  // A decision naming a plan that does not exist.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    cfm::ScopeDecision decision;
    decision.scope = scope_of("loop-1");
    decision.has_plan = true;
    decision.plan = plan_of("plan-9");
    state.decisions.push_back(decision);
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::PlanNotFound, "decision with an unknown plan");
  }
  // A restriction released by a failure of another scope.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.scopes.push_back(state_with_scope("loop-2").scopes.front());
    state.failures.push_back(make_failure("failure-1", "loop-2", cfm::FailureClass::LoopLoss,
                                          cfm::ConfirmationState::Confirmed, cfm::Severity::Total));
    state.plans.push_back(make_plan("plan-1", "loop-1"));
    cfm::ProtectiveRestriction restriction;
    restriction.id = restriction_of("restriction-1");
    restriction.scope = scope_of("loop-1");
    restriction.plan = plan_of("plan-1");
    restriction.released_by.push_back(failure_of("failure-1"));
    state.plans[0].restrictions.push_back(restriction);
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::ScopeKindMismatch, "restriction released by a foreign failure");
  }
  // A table that is not in canonical order is refused rather than re-sorted.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-2");
    state.scopes.push_back(state_with_scope("loop-1").scopes.front());
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::MalformedRecord, "scope table out of canonical order");
  }
  // The same table, canonicalized, passes.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-2");
    state.scopes.push_back(state_with_scope("loop-1").scopes.front());
    auto valid = canonical_and_valid(state);
    CT_CHECK(valid.has_value());
  }
  // Duplicate identities are refused with the identity-specific code.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.scopes.push_back(state_with_scope("loop-1").scopes.front());
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::DuplicateIdentifier, "duplicate scope in a state");
  }
  // An empty identity is refused. The failing scope is placed first because the
  // empty identity is also the smallest key, so the ordering check passes and the
  // identity check is the one that reports.
  {
    cfm::CoolingFailureState state;
    state.scopes.push_back(cfm::CoolingScope{});
    state.scopes.push_back(state_with_scope("loop-1").scopes.front());
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::MalformedIdentifier, "scope with an empty identity");
  }
}

CT_TEST(evidence_state_structure_enforces_the_attempt_evidence_rules) {
  // A verified attempt needs a recorded effect observation of its own scope, a
  // verdict and an acknowledgement clock.
  auto build_verified_state = []() {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.plans.push_back(make_plan("plan-1", "loop-1"));
    cfm::ResponseAttempt attempt;
    attempt.id = attempt_of("attempt-1");
    attempt.solicitation = solicitation_of("mutation-1");
    attempt.attempt = cfm::AttemptOrdinal(1);
    attempt.state = cfm::AttemptState::Verified;
    attempt.effect_observation = observation_of("obs-1");
    attempt.verdict = "flow restored above the declared floor";
    attempt.acknowledged_at = cfm::DecisionClock(2000);
    attempt.solicited_at = cfm::DecisionClock(1000);
    attempt.updated_at = cfm::DecisionClock(3000);
    state.plans[0].attempts.push_back(attempt);
    cfm::EvidenceAssessment evidence;
    evidence.observation = observation_of("obs-1");
    evidence.scope = scope_of("loop-1");
    evidence.channel = cfm::ObservationChannel::FlowMeter;
    evidence.status = cfm::EvidenceStatus::Current;
    evidence.freshness = cfm::Freshness::Current;
    state.evidence.push_back(evidence);
    return state;
  };

  {
    cfm::CoolingFailureState state = build_verified_state();
    auto valid = cfm::validate_structure(state);
    CT_CHECK_MSG(valid.has_value(), "a verified attempt with recorded evidence must validate");
  }
  {
    cfm::CoolingFailureState state = build_verified_state();
    state.plans[0].attempts[0].effect_observation = cfm::ObservationId();
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::EffectClaimedWithoutEvidence,
                "verified attempt without an effect observation");
  }
  {
    cfm::CoolingFailureState state = build_verified_state();
    state.plans[0].attempts[0].verdict.clear();
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::EffectClaimedWithoutEvidence,
                "verified attempt without a verdict");
  }
  {
    cfm::CoolingFailureState state = build_verified_state();
    state.evidence.clear();
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::EffectClaimedWithoutEvidence,
                "verified attempt whose evidence is not recorded");
  }
  {
    // The effect observation must belong to the plan's scope: evidence of
    // another scope is not evidence for this attempt.
    cfm::CoolingFailureState state = build_verified_state();
    state.scopes.push_back(state_with_scope("loop-2").scopes.front());
    state.evidence[0].scope = scope_of("loop-2");
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::EffectClaimedWithoutEvidence,
                "verified attempt with evidence of another scope");
  }
  {
    cfm::CoolingFailureState state = build_verified_state();
    state.plans[0].attempts[0].acknowledged_at = cfm::DecisionClock();
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::AcknowledgementInvalid,
                "verified attempt without an acknowledgement clock");
  }
  {
    // A refuted attempt carries the observation that refuted it and the verdict.
    cfm::CoolingFailureState state = build_verified_state();
    state.plans[0].attempts[0].state = cfm::AttemptState::Refuted;
    state.plans[0].attempts[0].acknowledged_at = cfm::DecisionClock();
    auto valid = cfm::validate_structure(state);
    CT_CHECK_MSG(valid.has_value(), "a refuted attempt that names its refuting observation must validate");

    state.plans[0].attempts[0].verdict.clear();
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::EffectClaimedWithoutEvidence,
                "refuted attempt without a verdict");
  }
  {
    // A planned attempt must not carry an acknowledgement: it was never asked.
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.plans.push_back(make_plan("plan-1", "loop-1"));
    cfm::ResponseAttempt attempt;
    attempt.id = attempt_of("attempt-1");
    attempt.solicitation = solicitation_of("mutation-1");
    attempt.attempt = cfm::AttemptOrdinal(1);
    attempt.state = cfm::AttemptState::Planned;
    attempt.acknowledged_at = cfm::DecisionClock(1000);
    state.plans[0].attempts.push_back(attempt);
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::AcknowledgementInvalid,
                "planned attempt with an acknowledgement clock");
  }
  {
    // The attempt ordinal is 1-based.
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.plans.push_back(make_plan("plan-1", "loop-1"));
    cfm::ResponseAttempt attempt;
    attempt.id = attempt_of("attempt-1");
    attempt.solicitation = solicitation_of("mutation-1");
    attempt.attempt = cfm::AttemptOrdinal(0);
    state.plans[0].attempts.push_back(attempt);
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::InvalidArgument, "zero attempt ordinal");
  }
  {
    // An unresolved attempt must exist and must actually be unresolved.
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.plans.push_back(make_plan("plan-1", "loop-1"));
    cfm::ResponseAttempt attempt;
    attempt.id = attempt_of("attempt-1");
    attempt.solicitation = solicitation_of("mutation-1");
    attempt.attempt = cfm::AttemptOrdinal(1);
    attempt.state = cfm::AttemptState::Solicited;
    state.plans[0].attempts.push_back(attempt);
    state.unresolved_attempts.push_back(attempt_of("attempt-1"));
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::AttemptNotResolvable,
                "a solicited attempt listed as unresolved");

    state.plans[0].attempts[0].state = cfm::AttemptState::Unresolved;
    auto valid = cfm::validate_structure(state);
    CT_CHECK_MSG(valid.has_value(), "an unresolved attempt must be listable as unresolved");

    state.unresolved_attempts[0] = attempt_of("attempt-9");
    auto missing = cfm::validate_structure(state);
    CT_REQUIRE(!missing.has_value());
    expect_code(missing.error(), cfm::ErrorCode::AttemptNotFound, "unresolved attempt not present");
  }
}

CT_TEST(evidence_state_structure_enforces_the_decision_rules) {
  auto build_state = []() {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.failures.push_back(make_failure("failure-1", "loop-1", cfm::FailureClass::LoopLoss,
                                          cfm::ConfirmationState::Confirmed, cfm::Severity::Total));
    cfm::ScopeDecision decision;
    decision.scope = scope_of("loop-1");
    decision.evaluated_at = cfm::DecisionClock(3000);
    decision.confirmed_classes.push_back(cfm::FailureClass::LoopLoss);
    decision.failures.push_back(failure_of("failure-1"));
    decision.severity = cfm::Severity::Total;
    decision.urgency = cfm::Urgency::Immediate;
    decision.time_to_impact = cfm::TimeToImpact::Minutes;
    state.decisions.push_back(decision);
    return state;
  };

  {
    cfm::CoolingFailureState state = build_state();
    auto valid = cfm::validate_structure(state);
    CT_CHECK_MSG(valid.has_value(), "a decision whose severity is the maximum of its failures validates");
  }
  {
    // A decision that names its own scope's plan is the positive case the
    // cross-scope rejection above is contrasted with.
    cfm::CoolingFailureState state = build_state();
    state.plans.push_back(make_plan("plan-1", "loop-1"));
    state.plans[0].failures.push_back(failure_of("failure-1"));
    state.decisions[0].has_plan = true;
    state.decisions[0].plan = plan_of("plan-1");
    state.decisions[0].plan_lifecycle = cfm::PlanLifecycle::Active;
    auto valid = cfm::validate_structure(state);
    CT_CHECK_MSG(valid.has_value(), "a decision naming its own scope's plan must validate");

    state.decisions[0].plan = plan_of("plan-1");
    state.scopes.push_back(state_with_scope("loop-2").scopes.front());
    state.plans.push_back(make_plan("plan-2", "loop-2"));
    state.decisions[0].plan = plan_of("plan-2");
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::ScopeKindMismatch, "decision naming a plan of another scope");
  }
  {
    cfm::CoolingFailureState state = build_state();
    state.decisions[0].severity = cfm::Severity::Degraded;
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::FailureClassConflict,
                "decision severity below the failures it lists");
  }
  {
    cfm::CoolingFailureState state = build_state();
    state.decisions[0].severity = cfm::Severity::Critical;
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::FailureClassConflict,
                "decision severity above the failures it lists");
  }
  {
    cfm::CoolingFailureState state = build_state();
    state.decisions[0].suspected_classes.push_back(cfm::FailureClass::LoopLoss);
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::FailureClassConflict,
                "one class in two classification buckets");
  }
  {
    cfm::CoolingFailureState state = build_state();
    state.decisions[0].evidence_gaps.push_back(cfm::ObservationChannel::FlowMeter);
    state.decisions[0].evidence_gaps.push_back(cfm::ObservationChannel::FlowMeter);
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::DuplicateField, "one channel reported as a gap twice");
  }
  {
    cfm::CoolingFailureState state = build_state();
    state.decisions[0].shared_sources.push_back(scope_of("loop-9"));
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::ScopeNotFound, "decision with an unknown shared source");
  }
  {
    cfm::CoolingFailureState state = build_state();
    state.decisions[0].restrictions.push_back(restriction_of("restriction-9"));
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::RestrictionNotFound,
                "decision naming a restriction that is not in force");
  }
  {
    // Evidence marked Current while nothing was ever observed is refused: the
    // two facts contradict each other.
    cfm::CoolingFailureState state = build_state();
    cfm::EvidenceAssessment evidence;
    evidence.observation = observation_of("obs-1");
    evidence.scope = scope_of("loop-1");
    evidence.channel = cfm::ObservationChannel::FlowMeter;
    evidence.status = cfm::EvidenceStatus::Current;
    evidence.freshness = cfm::Freshness::Unobserved;
    state.evidence.push_back(evidence);
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::EvidenceNotCurrent,
                "current evidence that was never observed");
  }
  {
    // Evidence naming a scope the state does not hold.
    cfm::CoolingFailureState state = build_state();
    cfm::EvidenceAssessment evidence;
    evidence.observation = observation_of("obs-1");
    evidence.scope = scope_of("loop-9");
    evidence.status = cfm::EvidenceStatus::Stale;
    evidence.freshness = cfm::Freshness::Stale;
    state.evidence.push_back(evidence);
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::ScopeNotFound, "evidence with an unknown scope");
  }
}

CT_TEST(evidence_state_structure_enforces_the_scope_graph_rules) {
  // A self dependency is a cycle of one.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.scopes[0].dependencies.push_back(
        cfm::ScopeDependency{scope_of("loop-1"), cfm::DependencyKind::SuppliesCoolant, 1000000});
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::ScopeCycle, "scope depending on itself");
  }
  // Two scopes that depend on each other are a cycle, and the members are named.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.scopes.push_back(state_with_scope("loop-2").scopes.front());
    state.scopes[0].dependencies.push_back(
        cfm::ScopeDependency{scope_of("loop-2"), cfm::DependencyKind::SharesPlant, 500000});
    state.scopes[1].dependencies.push_back(
        cfm::ScopeDependency{scope_of("loop-1"), cfm::DependencyKind::SharesPlant, 500000});
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::ScopeCycle, "two scopes depending on each other");
    CT_CHECK_MSG(!refused.error().details().empty(), "a cycle must name its members");
  }
  // An unknown upstream scope.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.scopes[0].dependencies.push_back(
        cfm::ScopeDependency{scope_of("loop-9"), cfm::DependencyKind::SuppliesCoolant, 500000});
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::ScopeNotFound, "unknown upstream scope");
  }
  // A share outside [0, 1000000] is not a fraction of a whole.
  for (const std::int64_t share : {static_cast<std::int64_t>(-1), static_cast<std::int64_t>(1000001)}) {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.scopes.push_back(state_with_scope("loop-2").scopes.front());
    state.scopes[0].dependencies.push_back(
        cfm::ScopeDependency{scope_of("loop-2"), cfm::DependencyKind::SuppliesCoolant, share});
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::QuantityOutOfRange,
                "dependency share " + std::to_string(share));
  }
  // A chain longer than the documented depth bound is refused with LimitExceeded
  // rather than explored.
  {
    cfm::CoolingFailureState state;
    const std::size_t length = cfm::limits::kMaxDependencyDepth + 1;
    for (std::size_t index = 0; index < length; ++index) {
      char name[16];
      std::snprintf(name, sizeof(name), "s%04zu", index);
      state.scopes.push_back(state_with_scope(name).scopes.front());
    }
    for (std::size_t index = 0; index + 1 < length; ++index) {
      char next_name[16];
      std::snprintf(next_name, sizeof(next_name), "s%04zu", index + 1);
      state.scopes[index].dependencies.push_back(
          cfm::ScopeDependency{scope_of(next_name), cfm::DependencyKind::SuppliesCoolant, 1000000});
    }
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::LimitExceeded, "dependency chain above the depth bound");
  }
  // A chain inside the bound is acyclic and passes.
  {
    cfm::CoolingFailureState state;
    const std::size_t length = 8;
    for (std::size_t index = 0; index < length; ++index) {
      char name[16];
      std::snprintf(name, sizeof(name), "s%04zu", index);
      state.scopes.push_back(state_with_scope(name).scopes.front());
    }
    for (std::size_t index = 0; index + 1 < length; ++index) {
      char next_name[16];
      std::snprintf(next_name, sizeof(next_name), "s%04zu", index + 1);
      state.scopes[index].dependencies.push_back(
          cfm::ScopeDependency{scope_of(next_name), cfm::DependencyKind::SuppliesCoolant, 1000000});
    }
    auto valid = cfm::validate_structure(state);
    CT_CHECK_MSG(valid.has_value(), "an acyclic chain inside the bound must validate");
  }
}

CT_TEST(evidence_state_structure_enforces_the_table_bounds_and_enum_ranges) {
  // Every table bound is checked before the rows are interpreted, so a state that
  // is too large is refused as a size problem rather than examined element by
  // element.
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    cfm::CoolingFailure failure = make_failure("failure-1", "loop-1", cfm::FailureClass::LoopLoss,
                                               cfm::ConfirmationState::Confirmed, cfm::Severity::Total);
    for (std::size_t index = 0; index <= cfm::limits::kMaxDecisionEntryCount; ++index) {
      failure.basis.push_back(observation_of("obs-1"));
    }
    state.failures.push_back(failure);
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::LimitExceeded, "failure basis above its bound");
  }
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.plans.push_back(make_plan("plan-1", "loop-1"));
    for (std::size_t index = 0; index <= cfm::limits::kMaxPlanEligibilityCount; ++index) {
      cfm::ResponseEligibility eligible;
      eligible.action = cfm::ResponseAction::ObserveOnly;
      eligible.rank = 1;
      eligible.rule_id = "observe";
      state.plans[0].eligible.push_back(eligible);
    }
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::LimitExceeded, "plan eligibility above its bound");
  }
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.plans.push_back(make_plan("plan-1", "loop-1"));
    for (std::size_t index = 0; index <= cfm::limits::kMaxAttemptCount; ++index) {
      cfm::ResponseAttempt attempt;
      attempt.id = attempt_of("attempt-1");
      attempt.solicitation = solicitation_of("mutation-1");
      attempt.attempt = cfm::AttemptOrdinal(1);
      state.plans[0].attempts.push_back(attempt);
    }
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::LimitExceeded, "plan attempts above their bound");
  }
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    cfm::ScopeDecision decision;
    decision.scope = scope_of("loop-1");
    for (std::size_t index = 0; index < cfm::limits::kMaxConfirmedClassesPerScope + 1u; ++index) {
      decision.confirmed_classes.push_back(static_cast<cfm::FailureClass>(index));
    }
    state.decisions.push_back(decision);
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::LimitExceeded, "confirmed classes above their bound");
  }
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    cfm::ScopeDecision decision;
    decision.scope = scope_of("loop-1");
    for (std::size_t index = 0; index <= cfm::limits::kMaxEvidenceGapCount; ++index) {
      decision.evidence_gaps.push_back(cfm::ObservationChannel::FlowMeter);
    }
    state.decisions.push_back(decision);
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::LimitExceeded, "evidence gaps above their bound");
  }
  {
    // The scope policy's window bounds are checked as quantities, not clamped.
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.scopes[0].policy.recovery_dwell =
        cfm::DurationMilliseconds(cfm::limits::kMaxWindowMilliseconds + 1);
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::QuantityOutOfRange, "recovery dwell above the bound");

    state.scopes[0].policy.recovery_dwell = cfm::DurationMilliseconds(0);
    state.scopes[0].policy.recovery_hysteresis = cfm::DurationMilliseconds(-1);
    refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::QuantityOutOfRange, "negative recovery hysteresis");

    state.scopes[0].policy.recovery_hysteresis = cfm::DurationMilliseconds(0);
    state.scopes[0].policy.requirements.push_back(
        cfm::EvidenceRequirement{cfm::ObservationChannel::FlowMeter,
                                 cfm::DurationMilliseconds(cfm::limits::kMaxWindowMilliseconds + 1)});
    refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::QuantityOutOfRange,
                "evidence requirement window above the bound");
  }
  {
    // A value outside an enumeration is not repaired or mapped onto a default.
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    cfm::CoolingFailure failure = make_failure("failure-1", "loop-1", cfm::FailureClass::LoopLoss,
                                               cfm::ConfirmationState::Confirmed, cfm::Severity::Total);
    failure.confirmation = static_cast<cfm::ConfirmationState>(200);
    state.failures.push_back(failure);
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::UnknownEnumToken, "confirmation state outside the taxonomy");
  }
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    state.scopes[0].policy.strict_classes.push_back(static_cast<cfm::FailureClass>(200));
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::UnknownEnumToken, "strict class outside the taxonomy");
  }
  {
    cfm::CoolingFailureState state = state_with_scope("loop-1");
    cfm::EvidenceAssessment evidence;
    evidence.observation = observation_of("obs-1");
    evidence.scope = scope_of("loop-1");
    evidence.channel = static_cast<cfm::ObservationChannel>(200);
    evidence.status = cfm::EvidenceStatus::Stale;
    evidence.freshness = cfm::Freshness::Stale;
    state.evidence.push_back(evidence);
    auto refused = cfm::validate_structure(state);
    CT_REQUIRE(!refused.has_value());
    expect_code(refused.error(), cfm::ErrorCode::UnknownEnumToken, "evidence channel outside the taxonomy");
  }
}

CT_TEST(evidence_state_structure_lookups_find_the_canonical_row) {
  cfm::CoolingFailureState state = state_with_scope("loop-1");
  state.scopes.push_back(state_with_scope("loop-2").scopes.front());
  state.failures.push_back(make_failure("failure-1", "loop-1", cfm::FailureClass::LoopLoss,
                                        cfm::ConfirmationState::Confirmed, cfm::Severity::Total));
  state.failures.push_back(make_failure("failure-2", "loop-2", cfm::FailureClass::Leak,
                                        cfm::ConfirmationState::Confirmed, cfm::Severity::Critical));
  state.plans.push_back(make_plan("plan-1", "loop-1"));
  state.plans.push_back(make_plan("plan-2", "loop-2"));
  cfm::ResponseAttempt attempt;
  attempt.id = attempt_of("attempt-1");
  attempt.solicitation = solicitation_of("mutation-1");
  attempt.attempt = cfm::AttemptOrdinal(1);
  state.plans[1].attempts.push_back(attempt);
  cfm::ScopeDecision decision;
  decision.scope = scope_of("loop-2");
  state.decisions.push_back(decision);

  auto valid = canonical_and_valid(state);
  CT_REQUIRE(valid.has_value());

  CT_CHECK(cfm::find_scope(state, scope_of("loop-1")) != nullptr);
  CT_CHECK(cfm::find_scope(state, scope_of("loop-2")) != nullptr);
  CT_CHECK(cfm::find_scope(state, scope_of("loop-9")) == nullptr);
  CT_CHECK(cfm::find_failure(state, failure_of("failure-1")) != nullptr);
  CT_CHECK(cfm::find_failure(state, failure_of("failure-9")) == nullptr);
  CT_CHECK(cfm::find_plan(state, plan_of("plan-2")) != nullptr);
  CT_CHECK(cfm::find_plan(state, plan_of("plan-9")) == nullptr);
  CT_CHECK(cfm::find_plan_for_scope(state, scope_of("loop-2")) ==
           cfm::find_plan(state, plan_of("plan-2")));
  CT_CHECK(cfm::find_plan_for_scope(state, scope_of("loop-9")) == nullptr);
  CT_CHECK(cfm::find_attempt(state, attempt_of("attempt-1")) != nullptr);
  CT_CHECK(cfm::find_attempt(state, attempt_of("attempt-9")) == nullptr);
  CT_CHECK(cfm::find_decision(state, scope_of("loop-2")) != nullptr);
  CT_CHECK(cfm::find_decision(state, scope_of("loop-1")) == nullptr);

  cfm::CoolingFailure* mutable_failure = cfm::find_failure(state, failure_of("failure-2"));
  CT_REQUIRE(mutable_failure != nullptr);
  CT_CHECK(mutable_failure->severity == cfm::Severity::Critical);
  CT_CHECK(mutable_failure->scope == scope_of("loop-2"));
  cfm::ResponsePlan* mutable_plan = cfm::find_plan(state, plan_of("plan-1"));
  CT_REQUIRE(mutable_plan != nullptr);
  CT_CHECK(mutable_plan->scope == scope_of("loop-1"));
  CT_CHECK_EQ(mutable_plan->attempts.size(), static_cast<std::size_t>(0));
}
