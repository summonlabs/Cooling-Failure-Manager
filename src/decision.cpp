// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The cooling-failure decision engine.
//
// This translation unit is the whole of the component's classification and
// response authority. It is a pure function of its inputs: it reads no clock, no
// environment, no file and no global state, so the same inputs always produce
// the same state and the same explanation bytes.
//
// The engine never destroys evidence. Every observation, failure record, plan,
// restriction and attempt present in the prior state is carried into the
// outcome; only the derived fields (classification, eligibility, restrictions,
// attempt states and recovery verdicts) are recomputed. An unresolved attempt
// therefore stays unresolved until something explicitly resolves it, which is
// what makes a blind redispatch after a restart impossible rather than merely
// discouraged.
//
// Three rules shape almost every statement below:
//   * an absent reading is unknown, never healthy and never zero, so a class
//     whose witness channel declares no bound is Unsupported rather than
//     Healthy, and a silent instrument is an evidence gap rather than a zero;
//   * eligibility, solicitation, acknowledgement, observed effect and verified
//     effect are five separate facts, so a plan never reports one as another;
//   * an accepted request is not proof that coolant moved, so the engine never
//     promotes an acknowledgement into an effect.

#include "dccp/cooling_failure_manager/decision.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "dccp/cooling_failure_manager/classify.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/recovery.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

namespace dccp::cooling_failure_manager {
namespace {

/// The engine's entry points. They are declared here, defined inside this
/// translation unit, and re-exported by the forwarding functions at the end of
/// the file. The split lets the engine call its own classification and
/// eligibility logic without going through the public overload set, and it makes
/// the component's contract visible in one place at the bottom of the file.
Result<DecisionOutcome> evaluate_impl(const DecisionInput& input);
Result<DecisionOutcome> finish_evaluation_impl(const DecisionInput& input, DecisionOutcome outcome);
BindingAssessment assess_bindings_impl(const AuthoritySet& published, const BindingObservation& observed);
Result<std::vector<ResponseEligibility>> eligible_actions_impl(const CoolingScope& scope,
                                                               const ScopeDecision& decision,
                                                               const DecisionPolicy& policy);
Result<std::vector<ProtectiveRestriction>> required_restrictions_impl(
    const CoolingScope& scope, const ScopeDecision& decision,
    const std::vector<CoolingFailure>& failures, const DecisionPolicy& policy);
std::vector<std::string> explain_scope_impl(const CoolingScope& scope, const ScopeDecision& decision);
Result<std::vector<std::pair<ScopeId, ScopeId>>> shared_source_attribution_impl(
    const CoolingFailureState& state, const std::vector<ScopeId>& scopes_with_total_loss);
Result<ScopeDecision> classify_scope_impl(const ScopeId& scope, const DecisionInput& input);


// ---------------------------------------------------------------------------
// Small deterministic helpers
// ---------------------------------------------------------------------------

std::string quote(std::string_view text) { return escape_text(text); }

std::string decimal(std::int64_t value) { return to_decimal(value); }

/// Marker on an attribution failure's rationale. It exists so the engine can
/// tell an attribution it computed itself (and must therefore recompute or
/// retract) from a failure a caller recorded as an observation of the world
/// (which it must never discard).
constexpr std::string_view kAttributionMarker = "[attributed]";

bool is_engine_attribution(const CoolingFailure& failure) {
  return failure.rationale.rfind(kAttributionMarker, 0) == 0;
}

/// True when the engine composed this failure identity itself. The two prefixes it
/// composes are the classification record (fl.) and the attribution record (sf.);
/// a caller is free to use any other spelling, and its records are never replaced.
bool is_engine_derived(const CoolingFailure& failure) {
  return failure.id.str().rfind("fl.", 0) == 0 || failure.id.str().rfind("sf.", 0) == 0;
}

/// Every observation channel, in canonical order, computed once.
const std::vector<ObservationChannel>& all_channels() {
  static const std::vector<ObservationChannel> channels = [] {
    std::vector<ObservationChannel> out;
    const ObservationChannel* order = observation_channel_order();
    const std::size_t count = observation_channel_count();
    out.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
      out.push_back(order[index]);
    }
    return out;
  }();
  return channels;
}

/// Every failure class, in canonical order, computed once.
const std::vector<FailureClass>& all_classes() {
  static const std::vector<FailureClass> classes = [] {
    std::vector<FailureClass> out;
    const FailureClass* order = failure_class_order();
    const std::size_t count = failure_class_count();
    out.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
      out.push_back(order[index]);
    }
    return out;
  }();
  return classes;
}

bool contains_class(const std::vector<FailureClass>& values, FailureClass value) {
  return std::find(values.begin(), values.end(), value) != values.end();
}

void add_unique(std::vector<FailureClass>& values, FailureClass value) {
  if (!contains_class(values, value)) {
    values.push_back(value);
  }
}

/// One severity step down. A suspicion is never reported at the severity its
/// confirmation would carry, because the consequences of acting on a suspicion
/// and on a confirmation are not the same.
Severity downgrade_severity(Severity severity) {
  switch (severity) {
    case Severity::Total:
      return Severity::Critical;
    case Severity::Critical:
      return Severity::Impaired;
    case Severity::Impaired:
      return Severity::Degraded;
    case Severity::Degraded:
    case Severity::None:
      break;
  }
  return Severity::None;
}

/// The witness inputs one channel presents for one class on one scope.
///
/// The declared envelope comes from the scope's policy, so a class whose witness
/// channel has no declared bound can never be triggered. An undeclared limit is
/// not a violated limit, and inventing one would make this component the owner
/// of a threshold its owner never declared.
WitnessInputs witness_inputs_for(const CoolingScope& scope, const Observation* observation,
                                 ObservationChannel channel) {
  WitnessInputs inputs;
  const EnvelopeBound bound = envelope_bound_for(scope.policy, channel);
  if (bound.has_floor) {
    inputs.has_floor = true;
    inputs.declared_floor = bound.floor_value;
  }
  if (bound.has_ceiling) {
    inputs.has_ceiling = true;
    inputs.declared_ceiling = bound.ceiling_value;
  }
  const ChannelThreshold threshold = channel_threshold(scope.policy, channel);
  if (threshold.has_threshold && channel == ObservationChannel::ThermalCapacityMeter) {
    inputs.has_demand = true;
    inputs.declared_demand = threshold.threshold;
  }
  if (observation == nullptr) {
    return inputs;
  }
  inputs.leak = observation->leak;
  // A leak detector asserts a leak state rather than a scalar, so its usability is
  // the usability of that assertion: a positive or negative leak state is
  // evidence, and LeakUnknown is not. Reading usability from the quantity alone
  // would make every leak assertion permanently unusable, because a leak channel
  // carries no scalar at all.
  if (channel_is_leak(channel)) {
    inputs.usable = observation->leak != LeakState::LeakUnknown;
  } else {
    inputs.usable = observation->quantity.is_usable();
  }
  const std::optional<std::int64_t> value = observation->quantity.value_if_observed();
  if (value.has_value()) {
    inputs.has_value = true;
    inputs.value = *value;
  }
  return inputs;
}

/// The checked product of two declared shares in parts per million. A product
/// below one part per million is not a supply relationship at all, so it is
/// reported as zero and the path is not followed.
std::int64_t checked_share_product(std::int64_t lhs, std::int64_t rhs) {
  if (lhs <= 0 || rhs <= 0 || lhs > 1000000 || rhs > 1000000) {
    return 0;
  }
  const std::int64_t product = (lhs * rhs) / 1000000;
  return product > 0 ? product : 0;
}

void sort_ids(std::vector<ObservationId>& ids) {
  std::sort(ids.begin(), ids.end());
  ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
}

void sort_channels(std::vector<ObservationChannel>& channels) {
  std::sort(channels.begin(), channels.end(), [](ObservationChannel lhs, ObservationChannel rhs) {
    return channel_index(lhs) < channel_index(rhs);
  });
  channels.erase(std::unique(channels.begin(), channels.end()), channels.end());
}

// ---------------------------------------------------------------------------
// Per-class classification
// ---------------------------------------------------------------------------

/// The classification of one failure class on one scope, with the reason for it.
struct ClassOutcome {
  FailureClass failure_class = FailureClass::LoopLoss;
  ConfirmationState state = ConfirmationState::Unknown;
  Severity severity = Severity::None;
  Urgency urgency = Urgency::Routine;
  TimeToImpact time_to_impact = TimeToImpact::Unobserved;
  std::vector<ObservationId> basis;
  std::vector<ObservationChannel> missing_channels;
  std::vector<ObservationChannel> contradicted_channels;
};

/// Witnesses that are present and usable, grouped by the stream that produced
/// them.
///
/// The confirmation demand counts DISTINCT PRODUCER STREAMS rather than witness
/// entries: one stream reporting the same condition on two channels is one
/// observation of the world, not two, and counting it twice would let a single
/// instrument confirm a failure on its own.
struct StreamVotes {
  std::vector<std::string> producers;
  std::size_t direct_triggers = 0;
  std::size_t supporting_triggers = 0;

  void add_stream(const Observation& observation) {
    if (std::find(producers.begin(), producers.end(), observation.producer) == producers.end()) {
      producers.push_back(observation.producer);
    }
  }
  std::size_t streams() const noexcept { return producers.size(); }
};

ClassOutcome classify_class(const CoolingScope& scope, const ObservationSet& observations,
                            const DecisionPolicy& policy, const DecisionClock& clock,
                            FailureClass failure_class) {
  ClassOutcome outcome;
  outcome.failure_class = failure_class;
  const FailureRule& rule = failure_rule(failure_class);
  outcome.urgency = rule.urgency;
  outcome.time_to_impact = rule.time_to_impact;

  StreamVotes triggered;
  bool any_evaluable = false;
  bool any_declaration_gap = false;
  bool any_contradiction = false;
  bool every_evaluable_contradicts = true;
  // A supporting witness is a channel that can distinguish this class from
  // another, not a channel that can establish it. It may only raise a suspicion
  // once the class's own primary witness has been observed: otherwise a generic
  // channel such as a flow reading would raise a suspicion of every class that
  // happens to list it, and a low flow would be reported as a suspected CDU
  // failure, valve failure and pump failure at once even though none of those
  // units was ever observed. Silence about the primary channel is an evidence gap
  // for this class, not a suspicion of it.
  bool direct_witness_observed = false;
  bool supporting_witness_present = false;

  for (std::size_t witness_index = 0; witness_index < rule.witness_count; ++witness_index) {
    const ChannelWitness& witness = rule.witnesses[witness_index];
    const Observation* observation =
        observations.latest(scope.id, witness.channel, clock, policy.evidence_window);
    const WitnessInputs inputs = witness_inputs_for(scope, observation, witness.channel);

    const bool envelope_bound_missing =
        (witness.signal == NullSignal::BelowDeclaredFloor && !inputs.has_floor) ||
        (witness.signal == NullSignal::AboveDeclaredCeiling && !inputs.has_ceiling) ||
        (witness.signal == NullSignal::OutsideDeclaredEnvelope && !inputs.has_floor && !inputs.has_ceiling);
    if (envelope_bound_missing) {
      any_declaration_gap = true;
      outcome.missing_channels.push_back(witness.channel);
      every_evaluable_contradicts = false;
      continue;
    }
    // A recorded reading only counts as evidence when it is CURRENT at the
    // decision clock. Something that was true ten minutes ago is not a statement
    // about now: a stale dead flow neither confirms the loss nor argues against
    // it, and the class is reported as unknown until fresh evidence arrives.
    const bool conflicting = observations.has_conflict(scope.id, witness.channel);
    const ObservationUsability usability =
        assess_observation(observation, clock, policy.evidence_window, conflicting);
    if (observation == nullptr || !inputs.usable || usability.status != EvidenceStatus::Current) {
      outcome.missing_channels.push_back(witness.channel);
      every_evaluable_contradicts = false;
      continue;
    }

    const WitnessReading reading = evaluate_witness(failure_class, witness.channel, inputs);
    any_evaluable = true;
    outcome.basis.push_back(observation->id);
    if (witness.role == WitnessRole::Direct) {
      direct_witness_observed = true;
    } else if (witness.role == WitnessRole::Supporting) {
      // A supporting witness that is not usable as evidence is not a supporting
      // witness at all: an unusable reading supports nothing.
      supporting_witness_present = true;
    }
    if (reading.triggered) {
      if (witness.role == WitnessRole::Direct) {
        triggered.add_stream(*observation);
        ++triggered.direct_triggers;
      }
      every_evaluable_contradicts = false;
    } else if (reading.contradicting) {
      any_contradiction = true;
      outcome.contradicted_channels.push_back(witness.channel);
    } else {
      every_evaluable_contradicts = false;
    }
  }

  // A supporting witness only counts when the class's own primary witness was
  // observed on this evaluation.
  if (direct_witness_observed && supporting_witness_present) {
    for (std::size_t witness_index = 0; witness_index < rule.witness_count; ++witness_index) {
      const ChannelWitness& witness = rule.witnesses[witness_index];
      if (witness.role != WitnessRole::Supporting) {
        continue;
      }
      const Observation* observation =
          observations.latest(scope.id, witness.channel, clock, policy.evidence_window);
      if (observation == nullptr) {
        continue;
      }
      const WitnessInputs inputs = witness_inputs_for(scope, observation, witness.channel);
      if (!inputs.usable) {
        continue;
      }
      const bool conflicting = observations.has_conflict(scope.id, witness.channel);
      if (assess_observation(observation, clock, policy.evidence_window, conflicting).status !=
          EvidenceStatus::Current) {
        continue;
      }
      const WitnessReading reading = evaluate_witness(failure_class, witness.channel, inputs);
      if (reading.triggered) {
        triggered.add_stream(*observation);
        ++triggered.supporting_triggers;
      }
    }
  }

  sort_ids(outcome.basis);
  sort_channels(outcome.missing_channels);
  sort_channels(outcome.contradicted_channels);

  if (!any_evaluable) {
    // Nothing usable was observed. Unsupported when the class cannot be evidenced
    // at all with the declared envelope, Unknown otherwise. Both are non-healthy:
    // neither is a licence to act as though cooling were normal.
    outcome.state = any_declaration_gap ? ConfirmationState::Unsupported : ConfirmationState::Unknown;
    outcome.severity = Severity::None;
    return outcome;
  }

  const std::uint32_t confirm_demand =
      policy.confirm_min_observations == 0 ? 1u : policy.confirm_min_observations;
  const std::uint32_t suspect_demand =
      policy.suspect_min_observations == 0 ? 1u : policy.suspect_min_observations;

  // A class confirms only when a witness the rule marks Direct triggered with
  // usable evidence and the policy's demand for independent producer streams is
  // met. When the policy or the rule demands a direct witness, a run of
  // supporting witnesses can never add up to a confirmation.
  if (triggered.direct_triggers > 0 && triggered.streams() >= confirm_demand) {
    outcome.state = ConfirmationState::Confirmed;
    outcome.severity = rule.severity;
    return outcome;
  }
  if (triggered.direct_triggers > 0 || triggered.supporting_triggers > 0) {
    if (triggered.streams() >= suspect_demand) {
      outcome.state = ConfirmationState::Suspected;
      outcome.severity = downgrade_severity(rule.severity);
      return outcome;
    }
    // A witness triggered but the policy demands more independent streams before
    // even a suspicion may be raised. The evidence is recorded, the class stays
    // Unknown, and the missing streams are named.
    outcome.state = ConfirmationState::Unknown;
    outcome.severity = Severity::None;
    return outcome;
  }
  if (any_contradiction && every_evaluable_contradicts) {
    outcome.state = ConfirmationState::Contradicted;
    outcome.severity = Severity::None;
    return outcome;
  }
  outcome.state = ConfirmationState::Unknown;
  outcome.severity = Severity::None;
  return outcome;
}

// ---------------------------------------------------------------------------
// Shared upstream attribution
// ---------------------------------------------------------------------------

/// One entry of a dependency traversal: the scope reached, the fraction of its
/// declared cooling that the path to it carries, and the hop count of the path.
struct ReachedScope {
  ScopeId scope;
  std::int64_t share_parts_per_million = 0;
  std::size_t depth = 0;
};

/// The scopes that depend on the given set of lost scopes, and the fraction of
/// each one's declared cooling that the lost supply carries.
///
/// The traversal walks a scope's dependencies *upstream*: from a lost plant it
/// finds every scope whose declared dependencies include something already known
/// to be lost, and records the product of the declared shares along the path.
/// Doing this the other way round - walking the lost scope's own dependency list -
/// would answer "what does the lost scope depend on", which is the opposite
/// question and is why attribution must be tested in both directions.
///
/// The traversal is breadth-first over a sorted frontier so a scope reached by
/// several paths keeps the last share written for it deterministically, bounded in
/// depth by limits::kMaxDependencyDepth and in total visits by
/// limits::kMaxScopeDependencyCount, so a dense or hostile graph cannot make
/// attribution unbounded work. A scope that is itself lost is not reported as
/// depending on another lost scope: its own failure is the more specific fact.
Result<std::vector<ReachedScope>> dependents_of(const CoolingFailureState& state,
                                               const std::vector<ScopeId>& lost) {
  std::vector<ReachedScope> reached;
  std::vector<ReachedScope> frontier;
  for (const ScopeId& scope : lost) {
    frontier.push_back(ReachedScope{scope, 1000000, 0});
  }
  std::sort(frontier.begin(), frontier.end(),
            [](const ReachedScope& lhs, const ReachedScope& rhs) { return lhs.scope < rhs.scope; });
  std::size_t visits = 0;

  for (std::size_t depth = 0; depth < limits::kMaxDependencyDepth && !frontier.empty(); ++depth) {
    std::vector<ReachedScope> next;
    for (const ReachedScope& current : frontier) {
      for (const CoolingScope& candidate : state.scopes) {
        if (++visits > limits::kMaxScopeDependencyCount) {
          return Error(ErrorCode::LimitExceeded, "dependency traversal exceeded its visit bound")
              .with_subject(current.scope.str());
        }
        if (candidate.id == current.scope) {
          continue;
        }
        for (const ScopeDependency& dependency : candidate.dependencies) {
          if (!(dependency.upstream == current.scope)) {
            continue;
          }
          // The share over the path is the product of the declared shares, checked
          // before it is formed so a chain of near-certain shares cannot overflow.
          const std::int64_t share =
              checked_share_product(current.share_parts_per_million, dependency.share_parts_per_million);
          if (share <= 0) {
            continue;
          }
          const bool already_lost =
              std::find(lost.begin(), lost.end(), candidate.id) != lost.end();
          if (already_lost) {
            continue;
          }
          auto found = std::find_if(reached.begin(), reached.end(), [&](const ReachedScope& entry) {
            return entry.scope == candidate.id;
          });
          if (found == reached.end()) {
            reached.push_back(ReachedScope{candidate.id, share, depth + 1});
            next.push_back(ReachedScope{candidate.id, share, depth + 1});
          } else if (share > found->share_parts_per_million) {
            found->share_parts_per_million = share;
            found->depth = depth + 1;
            next.push_back(ReachedScope{candidate.id, share, depth + 1});
          }
        }
      }
    }
    std::sort(next.begin(), next.end(), [](const ReachedScope& lhs, const ReachedScope& rhs) {
      return lhs.scope < rhs.scope;
    });
    // A scope may appear more than once in a front when several paths reach it;
    // only the strongest share per scope is carried forward.
    std::vector<ReachedScope> unique;
    for (const ReachedScope& entry : next) {
      auto found = std::find_if(unique.begin(), unique.end(),
                                [&](const ReachedScope& other) { return other.scope == entry.scope; });
      if (found == unique.end()) {
        unique.push_back(entry);
      } else if (entry.share_parts_per_million > found->share_parts_per_million) {
        *found = entry;
      }
    }
    frontier = std::move(unique);
  }
  std::sort(reached.begin(), reached.end(), [](const ReachedScope& lhs, const ReachedScope& rhs) {
    return lhs.scope < rhs.scope;
  });
  return reached;
}

/// The failure identity an attribution produces for one downstream scope and one
/// upstream scope. A pure function of the pair, so re-evaluating the same inputs
/// regenerates the same identity instead of accumulating duplicates.
Result<FailureId> attribution_id(const ScopeId& downstream, const ScopeId& upstream) {
  std::string text = "sf.";
  text += downstream.str();
  text += ".";
  text += upstream.str();
  if (text.size() > limits::kMaxIdentifierBytes) {
    return Error(ErrorCode::MalformedIdentifier,
                 "an attribution identity would exceed the identifier length bound")
        .with_subject(text.substr(0, 160));
  }
  return FailureId::parse(text);
}

/// The worst confirmed total-loss failure of one scope.
struct LossSummary {
  bool found = false;
  Severity severity = Severity::None;
  Urgency urgency = Urgency::Routine;
  TimeToImpact time_to_impact = TimeToImpact::Unobserved;
  FailureId worst;
};

LossSummary worst_total_loss(const CoolingFailureState& state, const ScopeId& scope) {
  LossSummary summary;
  for (const CoolingFailure& failure : state.failures) {
    if (!(failure.scope == scope)) {
      continue;
    }
    if (failure.confirmation != ConfirmationState::Confirmed) {
      continue;
    }
    if (!failure_class_is_total_loss(failure.failure_class)) {
      continue;
    }
    const bool better = !summary.found || failure.severity > summary.severity ||
                        (failure.severity == summary.severity && failure.id < summary.worst);
    if (better) {
      summary.worst = failure.id;
      summary.severity = failure.severity;
      summary.urgency = failure.urgency;
      summary.time_to_impact = failure.time_to_impact;
    }
    summary.found = true;
  }
  return summary;
}

// ---------------------------------------------------------------------------
// Response eligibility
// ---------------------------------------------------------------------------

/// The stable rank of an action. Lower ranks are considered first. The ordering
/// encodes the preference documented in the README: protect coolant and
/// containment before restoring supply, and reduce load before waiting.
std::int32_t action_rank(ResponseAction action, bool safety_critical) {
  std::int32_t base = 0;
  switch (action) {
    case ResponseAction::ManualIntervention:
      base = 5;
      break;
    case ResponseAction::EmergencyShutdown:
      base = 10;
      break;
    case ResponseAction::EvacuateScope:
      base = 20;
      break;
    case ResponseAction::IsolateScope:
      base = 30;
      break;
    case ResponseAction::CloseIsolationValve:
      base = 40;
      break;
    case ResponseAction::OpenBypassValve:
      base = 100;
      break;
    case ResponseAction::StartStandbyPump:
      base = 110;
      break;
    case ResponseAction::StartStandbyChiller:
      base = 120;
      break;
    case ResponseAction::FailoverCoolingSource:
      base = 130;
      break;
    case ResponseAction::RaiseFanSpeed:
      base = 140;
      break;
    case ResponseAction::ReduceThermalLoad:
      base = 300;
      break;
    case ResponseAction::ThrottleWorkload:
      base = 310;
      break;
    case ResponseAction::VerifyEvidence:
      base = 800;
      break;
    case ResponseAction::ObserveOnly:
      base = 900;
      break;
  }
  return safety_critical ? base : base + 1000;
}

ResponseEligibility make_eligibility(ResponseAction action, EffectClass effect, bool safety_critical,
                                     std::string_view rule_id) {
  ResponseEligibility eligibility;
  eligibility.action = action;
  eligibility.effect_class = effect;
  eligibility.safety_critical = safety_critical;
  eligibility.rule_id = std::string(rule_id);
  eligibility.rank = action_rank(action, safety_critical);
  return eligibility;
}

/// The proof obligation a class's response carries. Accepting a request for this
/// action is never evidence that the effect happened; only an observation can be.
EffectClass effect_for_class(FailureClass failure_class) {
  switch (failure_class) {
    case FailureClass::PlantLoss:
    case FailureClass::ChillerFailure:
    case FailureClass::ThermalCapacityLoss:
    case FailureClass::SharedSourceFailure:
      return EffectClass::ThermalCapacityRestored;
    case FailureClass::PumpFailure:
    case FailureClass::LoopDegradation:
    case FailureClass::LoopLoss:
    case FailureClass::CduFailure:
    case FailureClass::ValveFlowFailure:
      return EffectClass::FlowRestored;
    case FailureClass::PressureFailure:
      return EffectClass::PressureRestored;
    case FailureClass::CrahCracFailure:
    case FailureClass::AirflowLoss:
    case FailureClass::ThermalRunaway:
      return EffectClass::TemperatureContained;
    case FailureClass::ContainmentBreach:
      return EffectClass::ContainmentRestored;
    case FailureClass::Leak:
      return EffectClass::LeakContained;
  }
  return EffectClass::None;
}

/// The escalation a confirmed class requires immediately.
struct EscalationRule {
  FailureClass failure_class;
  ResponseAction actions[4];
  std::size_t action_count;
  std::string_view rule_id;
};

constexpr EscalationRule kEscalations[] = {
    {FailureClass::PlantLoss,
     {ResponseAction::FailoverCoolingSource, ResponseAction::StartStandbyChiller,
      ResponseAction::ReduceThermalLoad, ResponseAction::ManualIntervention},
     4, "escalate.plant-loss"},
    {FailureClass::LoopLoss,
     {ResponseAction::StartStandbyPump, ResponseAction::OpenBypassValve,
      ResponseAction::ReduceThermalLoad, ResponseAction::IsolateScope},
     4, "escalate.loop-loss"},
    {FailureClass::CduFailure,
     {ResponseAction::IsolateScope, ResponseAction::CloseIsolationValve,
      ResponseAction::ReduceThermalLoad, ResponseAction::ManualIntervention},
     4, "escalate.cdu-failure"},
    {FailureClass::ChillerFailure,
     {ResponseAction::StartStandbyChiller, ResponseAction::ReduceThermalLoad, ResponseAction::ObserveOnly,
      ResponseAction::ObserveOnly},
     2, "escalate.chiller-failure"},
    {FailureClass::PumpFailure,
     {ResponseAction::StartStandbyPump, ResponseAction::OpenBypassValve, ResponseAction::ReduceThermalLoad,
      ResponseAction::ObserveOnly},
     3, "escalate.pump-failure"},
    {FailureClass::ValveFlowFailure,
     {ResponseAction::OpenBypassValve, ResponseAction::VerifyEvidence, ResponseAction::ObserveOnly,
      ResponseAction::ObserveOnly},
     2, "escalate.valve-flow"},
    {FailureClass::PressureFailure,
     {ResponseAction::OpenBypassValve, ResponseAction::VerifyEvidence, ResponseAction::ObserveOnly,
      ResponseAction::ObserveOnly},
     2, "escalate.pressure"},
    {FailureClass::CrahCracFailure,
     {ResponseAction::RaiseFanSpeed, ResponseAction::ReduceThermalLoad, ResponseAction::ThrottleWorkload,
      ResponseAction::ObserveOnly},
     3, "escalate.crah-crac"},
    {FailureClass::AirflowLoss,
     {ResponseAction::EvacuateScope, ResponseAction::EmergencyShutdown, ResponseAction::ThrottleWorkload,
      ResponseAction::ManualIntervention},
     4, "escalate.airflow-loss"},
    {FailureClass::ContainmentBreach,
     {ResponseAction::RaiseFanSpeed, ResponseAction::ReduceThermalLoad, ResponseAction::ManualIntervention,
      ResponseAction::ObserveOnly},
     3, "escalate.containment-breach"},
    {FailureClass::Leak,
     {ResponseAction::IsolateScope, ResponseAction::CloseIsolationValve, ResponseAction::EvacuateScope,
      ResponseAction::ManualIntervention},
     4, "escalate.leak"},
    {FailureClass::ThermalCapacityLoss,
     {ResponseAction::ReduceThermalLoad, ResponseAction::ThrottleWorkload,
      ResponseAction::VerifyEvidence, ResponseAction::ObserveOnly},
     3, "escalate.thermal-capacity-loss"},
    {FailureClass::SharedSourceFailure,
     {ResponseAction::FailoverCoolingSource, ResponseAction::ReduceThermalLoad,
      ResponseAction::ManualIntervention, ResponseAction::ObserveOnly},
     3, "escalate.shared-source"},
    {FailureClass::ThermalRunaway,
     {ResponseAction::EvacuateScope, ResponseAction::EmergencyShutdown, ResponseAction::IsolateScope,
      ResponseAction::ManualIntervention},
     4, "escalate.thermal-runaway"},
    {FailureClass::LoopDegradation,
     {ResponseAction::VerifyEvidence, ResponseAction::ReduceThermalLoad, ResponseAction::OpenBypassValve,
      ResponseAction::ObserveOnly},
     3, "escalate.loop-degradation"},
};

const EscalationRule* escalation_for(FailureClass failure_class) {
  for (const EscalationRule& rule : kEscalations) {
    if (rule.failure_class == failure_class) {
      return &rule;
    }
  }
  return nullptr;
}

/// Adds an eligibility, keeping the best rank when the same action is eligible
/// for several reasons and recording the rule that produced the best one.
void add_eligibility(std::vector<ResponseEligibility>& out, const ResponseEligibility& candidate) {
  auto found = std::find_if(out.begin(), out.end(), [&](const ResponseEligibility& existing) {
    return existing.action == candidate.action;
  });
  if (found == out.end()) {
    out.push_back(candidate);
    return;
  }
  if (candidate.rank < found->rank) {
    found->rank = candidate.rank;
    found->effect_class = candidate.effect_class;
    found->safety_critical = candidate.safety_critical;
    found->rule_id = candidate.rule_id;
  }
}

// ---------------------------------------------------------------------------
// Restrictions
// ---------------------------------------------------------------------------

/// The stable identity of one restriction kind on one scope. A pure function of
/// the pair, so re-evaluating the same inputs regenerates the same identity
/// instead of accumulating duplicates.
Result<RestrictionId> restriction_id(const ScopeId& scope, RestrictionKind kind) {
  std::string text = "rs.";
  text += scope.str();
  text += ".";
  text += to_token(kind);
  if (text.size() > limits::kMaxIdentifierBytes) {
    return Error(ErrorCode::MalformedIdentifier,
                 "a restriction identity would exceed the identifier length bound")
        .with_subject(text.substr(0, 160));
  }
  return RestrictionId::parse(text);
}

// ---------------------------------------------------------------------------
// Attempt state machine
// ---------------------------------------------------------------------------

/// The legal transitions of one attempt. The machine is deliberately narrow: an
/// attempt can never jump from Solicited to Verified, because verification needs
/// an observed effect first, and a terminal state is never left.
bool transition_allowed(AttemptState from, AttemptState to) {
  if (from == to) {
    return true;
  }
  switch (from) {
    case AttemptState::Planned:
      return to == AttemptState::Solicited || to == AttemptState::Withdrawn ||
             to == AttemptState::Unresolved || to == AttemptState::Failed;
    case AttemptState::Solicited:
      // An owner may report a verified effect straight from Solicited: an
      // automatic subsystem can accept, act and attest in one step, and refusing
      // that report would force a caller to invent an acknowledgement it never
      // received. What is NOT allowed is a verified claim without the observation
      // and the verdict that make it checkable, which the caller-side rule below
      // enforces independently of the transition.
      return to == AttemptState::Acknowledged || to == AttemptState::Refused ||
             to == AttemptState::Failed || to == AttemptState::EffectObserved ||
             to == AttemptState::Verified || to == AttemptState::Withdrawn ||
             to == AttemptState::Unresolved;
    case AttemptState::Acknowledged:
      return to == AttemptState::EffectObserved || to == AttemptState::Failed ||
             to == AttemptState::Refuted || to == AttemptState::Withdrawn ||
             to == AttemptState::Unresolved;
    case AttemptState::EffectObserved:
      return to == AttemptState::Verified || to == AttemptState::Refuted ||
             to == AttemptState::Unresolved;
    case AttemptState::Unresolved:
      return to == AttemptState::Verified || to == AttemptState::Refuted ||
             to == AttemptState::Failed || to == AttemptState::Withdrawn;
    case AttemptState::Refused:
    case AttemptState::Failed:
    case AttemptState::Verified:
    case AttemptState::Refuted:
    case AttemptState::Withdrawn:
      return false;
  }
  return false;
}

/// True when the attempt asserts that an effect exists. Such an attempt must
/// name the observation that shows it: a claim of effect without evidence is
/// exactly what this component exists to refuse.
bool state_claims_effect(AttemptState state) {
  return state == AttemptState::EffectObserved || state == AttemptState::Verified ||
         state == AttemptState::Refuted;
}

bool state_is_in_flight(AttemptState state) {
  return state == AttemptState::Planned || state == AttemptState::Solicited ||
         state == AttemptState::Acknowledged || state == AttemptState::EffectObserved;
}

const ResponseAttempt* find_attempt_in(const CoolingFailureState& state, const AttemptId& id) {
  for (const ResponsePlan& plan : state.plans) {
    for (const ResponseAttempt& attempt : plan.attempts) {
      if (attempt.id == id) {
        return &attempt;
      }
    }
  }
  return nullptr;
}

/// True when the observation named by an attempt exists in the state's evidence
/// table and belongs to the plan's scope.
bool effect_observation_present(const CoolingFailureState& state, const ScopeId& scope,
                                const ObservationId& observation) {
  if (observation.empty()) {
    return false;
  }
  for (const EvidenceAssessment& entry : state.evidence) {
    if (entry.observation == observation && entry.scope == scope) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Evidence table
// ---------------------------------------------------------------------------

/// Builds the evidence assessment table for every recorded observation of every
/// declared scope, in canonical (scope, channel, observation) order.
///
/// The table is what makes a decision reproducible: it records, for each piece
/// of evidence, the decision-time status that produced the classification, so a
/// later reader can tell why a class was Unknown instead of guessing.
std::vector<EvidenceAssessment> build_evidence_table(const CoolingFailureState& state,
                                                     const ObservationSet& observations,
                                                     const DecisionPolicy& policy,
                                                     const DecisionClock& clock) {
  std::vector<EvidenceAssessment> table;
  for (const CoolingScope& scope : state.scopes) {
    for (ObservationChannel channel : all_channels()) {
      const bool conflicting = observations.has_conflict(scope.id, channel);
      const std::vector<const Observation*> entries =
          observations.for_channel(scope.id, channel);
      if (entries.empty()) {
        continue;
      }
      for (const Observation* observation : entries) {
        if (observation == nullptr) {
          continue;
        }
        const ObservationUsability usability =
            assess_observation(observation, clock, policy.evidence_window, conflicting);
        EvidenceAssessment entry;
        entry.observation = observation->id;
        entry.scope = scope.id;
        entry.channel = channel;
        entry.status = usability.status;
        entry.freshness = usability.freshness;
        entry.availability = observation->quantity.availability();
        entry.quality = observation->quantity.quality();
        entry.age_milliseconds = usability.age_milliseconds;
        entry.detail = usability.detail;
        table.push_back(std::move(entry));
      }
    }
  }
  std::sort(table.begin(), table.end(), [](const EvidenceAssessment& lhs, const EvidenceAssessment& rhs) {
    if (!(lhs.scope == rhs.scope)) {
      return lhs.scope < rhs.scope;
    }
    if (channel_index(lhs.channel) != channel_index(rhs.channel)) {
      return channel_index(lhs.channel) < channel_index(rhs.channel);
    }
    return lhs.observation < rhs.observation;
  });
  return table;
}

/// The channels that are not Current for one scope, in canonical order.
std::vector<ObservationChannel> evidence_gaps_for(const CoolingFailureState& state,
                                                  const CoolingScope& scope,
                                                  const ObservationSet& observations,
                                                  const DecisionPolicy& policy,
                                                  const DecisionClock& clock) {
  std::vector<ObservationChannel> gaps;
  for (ObservationChannel channel : all_channels()) {
    const bool conflicting = observations.has_conflict(scope.id, channel);
    const Observation* observation =
        observations.latest(scope.id, channel, clock, policy.evidence_window);
    const ObservationUsability usability =
        assess_observation(observation, clock, policy.evidence_window, conflicting);
    if (usability.status != EvidenceStatus::Current) {
      gaps.push_back(channel);
    }
  }
  sort_channels(gaps);
  (void)state;
  return gaps;
}

// ---------------------------------------------------------------------------
// One scope's plan
// ---------------------------------------------------------------------------

/// The failures that justify one scope's plan: every Confirmed or Suspected
/// record for that scope, in canonical identity order.
std::vector<FailureId> plan_failures_for(const CoolingFailureState& state, const ScopeId& scope) {
  std::vector<FailureId> failures;
  for (const CoolingFailure& failure : state.failures) {
    if (!(failure.scope == scope)) {
      continue;
    }
    if (failure.confirmation == ConfirmationState::Confirmed ||
        failure.confirmation == ConfirmationState::Suspected) {
      failures.push_back(failure.id);
    }
  }
  std::sort(failures.begin(), failures.end());
  failures.erase(std::unique(failures.begin(), failures.end()), failures.end());
  return failures;
}

/// The stable identity of the plan of one scope. A pure function of the scope,
/// so a re-evaluation updates the same plan instead of creating a second one.
Result<PlanId> plan_id_for(const ScopeId& scope) {
  std::string text = "plan.";
  text += scope.str();
  if (text.size() > limits::kMaxIdentifierBytes) {
    return Error(ErrorCode::MalformedIdentifier,
                 "a plan identity would exceed the identifier length bound")
        .with_subject(text.substr(0, 160));
  }
  return PlanId::parse(text);
}

/// The stable identity of the attempt a solicitation creates.
Result<AttemptId> attempt_id_for(const ScopeId& scope, const MutationId& solicitation,
                                 const AttemptOrdinal& ordinal) {
  std::string text = "at.";
  text += scope.str();
  text += ".";
  text += solicitation.str();
  text += ".";
  text += to_decimal(static_cast<std::uint64_t>(ordinal.value()));
  if (text.size() > limits::kMaxIdentifierBytes) {
    return Error(ErrorCode::MalformedIdentifier,
                 "an attempt identity would exceed the identifier length bound")
        .with_subject(text.substr(0, 160));
  }
  return AttemptId::parse(text);
}


}  // namespace

// ===========================================================================
// Public predicates
// ===========================================================================
//
// These two answer questions about a policy and a class rather than about one
// scope's evidence, and they are part of the component's contract, so they live
// outside the engine's namespace.

bool dependency_share_at_least(std::int64_t share_parts_per_million, std::int64_t threshold) noexcept {
  return share_parts_per_million >= threshold;
}

bool is_safety_escalation(FailureClass failure_class, const DecisionPolicy& policy) noexcept {
  // The question is "may this confirmation be answered immediately, without
  // waiting for the dwell windows a recovery waits for?", and two independent
  // things can make the answer yes:
  //   * the class is one that is answered immediately at its own severity - a dead
  //     pump, a failed chiller unit, a failed air handler and an open containment
  //     boundary are all urgent without being total losses;
  //   * the confirmation is at or above the severity the policy names as an
  //     escalation threshold.
  // The predicate deliberately does not require both: requiring the class flag
  // alone would ignore a policy that escalates earlier, and requiring the
  // threshold alone would ignore the classes whose own urgency is higher than
  // their severity suggests.
  const FailureRule& rule = failure_rule(failure_class);
  return rule.safety_escalation ||
         severity_at_least(rule.severity, policy.safety_escalation_severity);
}

bool binding_assessment_allows_recovery_impl(const BindingAssessment& assessment) noexcept {
  return binding_status_is_current(assessment.status);
}

namespace {

BindingAssessment assess_bindings_impl(const AuthoritySet& published, const BindingObservation& observed) {
  BindingAssessment assessment;
  // The worst finding wins. Unbound ranks worst because a decision that was made
  // against a binding nobody supplies any more has no authority at all, whereas
  // a stale binding at least names the fact that moved on.
  auto rank = [](BindingStatus status) -> int {
    switch (status) {
      case BindingStatus::Current:
        return 0;
      case BindingStatus::Mismatched:
        return 3;
      case BindingStatus::Stale:
        return 2;
      case BindingStatus::Unbound:
        return 4;
    }
    return 4;
  };
  assessment.status = BindingStatus::Current;
  for (const std::pair<std::string, AuthorityRef>& entry : published.entries()) {
    BindingFinding finding;
    finding.role = entry.first;
    finding.bound = entry.second;
    const AuthorityRef* current = observed.current.find(entry.first);
    if (current == nullptr) {
      finding.status = BindingStatus::Unbound;
      finding.detail = "no binding is currently supplied for this role";
    } else if (!(*current == entry.second)) {
      finding.status = BindingStatus::Stale;
      finding.observed = current->generation();
      finding.detail = "the binding supplied for this role names a different fact or generation";
    } else {
      finding.status = BindingStatus::Current;
      finding.observed = current->generation();
      finding.detail = "the binding matches the generation the decision was made against";
    }
    if (rank(finding.status) > rank(assessment.status)) {
      assessment.status = finding.status;
    }
    assessment.findings.push_back(std::move(finding));
  }
  if (published.empty()) {
    assessment.status = BindingStatus::Unbound;
    assessment.explanation =
        "the decision was published without authority bindings, so it can never be current";
    return assessment;
  }
  if (assessment.status == BindingStatus::Current) {
    assessment.explanation = "every published binding matches a currently supplied binding";
  } else {
    assessment.explanation =
        "at least one published binding is not currently supplied at the generation the decision "
        "was made against";
  }
  return assessment;
}

Result<std::vector<ResponseEligibility>> eligible_actions_impl(const CoolingScope& scope,
                                                          const ScopeDecision& decision,
                                                          const DecisionPolicy& policy) {
  std::vector<ResponseEligibility> eligible;

  const bool has_confirmed = !decision.confirmed_classes.empty();
  const bool has_suspected = !decision.suspected_classes.empty();

  if (!has_confirmed && !has_suspected) {
    // Nothing is confirmed or suspected. The only justified action is to keep
    // looking, and to say so explicitly rather than leaving an empty plan that a
    // reader could mistake for a decision that nothing needs doing.
    add_eligibility(eligible, make_eligibility(ResponseAction::ObserveOnly, EffectClass::None, false,
                                               "hold.observe"));
    if (!decision.unknown_classes.empty()) {
      add_eligibility(eligible, make_eligibility(ResponseAction::VerifyEvidence, EffectClass::None,
                                                 false, "hold.verify-evidence"));
    }
    std::sort(eligible.begin(), eligible.end(), [](const ResponseEligibility& lhs,
                                                   const ResponseEligibility& rhs) {
      if (lhs.rank != rhs.rank) {
        return lhs.rank < rhs.rank;
      }
      if (response_action_index(lhs.action) != response_action_index(rhs.action)) {
        return response_action_index(lhs.action) < response_action_index(rhs.action);
      }
      return lhs.rule_id < rhs.rule_id;
    });
    return eligible;
  }

  for (FailureClass failure_class : all_classes()) {
    const bool confirmed = contains_class(decision.confirmed_classes, failure_class);
    const bool suspected = contains_class(decision.suspected_classes, failure_class);
    if (!confirmed && !suspected) {
      continue;
    }
    const EscalationRule* rule = escalation_for(failure_class);
    if (rule == nullptr) {
      continue;
    }
    const FailureRule& class_rule = failure_rule(failure_class);
    // A suspicion is answered with evidence gathering and load reduction, never
    // with the full escalation a confirmation justifies. Escalating on a
    // suspicion would make the component's protective authority depend on a
    // reading it has explicitly declared insufficient.
    const bool escalate = confirmed;
    for (std::size_t index = 0; index < rule->action_count; ++index) {
      const ResponseAction action = rule->actions[index];
      const bool safety_critical = escalate && class_rule.safety_escalation &&
                                   severity_at_least(class_rule.severity,
                                                     policy.safety_escalation_severity);
      if (!escalate && !(response_action_is_load_reduction(action) ||
                         action == ResponseAction::VerifyEvidence ||
                         action == ResponseAction::ObserveOnly ||
                         action == ResponseAction::RaiseFanSpeed ||
                         action == ResponseAction::OpenBypassValve)) {
        continue;
      }
      add_eligibility(eligible, make_eligibility(action, effect_for_class(failure_class),
                                                 safety_critical, rule->rule_id));
    }
    if (!escalate) {
      add_eligibility(eligible, make_eligibility(ResponseAction::VerifyEvidence,
                                                 effect_for_class(failure_class), false,
                                                 "suspect.verify-evidence"));
    }
  }
  if (eligible.empty()) {
    add_eligibility(eligible, make_eligibility(ResponseAction::ObserveOnly, EffectClass::None, false,
                                               "hold.observe"));
  }
  std::sort(eligible.begin(), eligible.end(),
            [](const ResponseEligibility& lhs, const ResponseEligibility& rhs) {
              if (lhs.rank != rhs.rank) {
                return lhs.rank < rhs.rank;
              }
              if (response_action_index(lhs.action) != response_action_index(rhs.action)) {
                return response_action_index(lhs.action) < response_action_index(rhs.action);
              }
              return lhs.rule_id < rhs.rule_id;
            });
  if (eligible.size() > limits::kMaxPlanEligibilityCount) {
    return Error(ErrorCode::LimitExceeded, "the eligible action list exceeded its bound")
        .with_subject(scope.id.str());
  }
  return eligible;
}

Result<std::vector<ProtectiveRestriction>> required_restrictions_impl(
    const CoolingScope& scope, const ScopeDecision& decision,
    const std::vector<CoolingFailure>& failures, const DecisionPolicy& policy) {
  (void)policy;
  std::vector<RestrictionKind> kinds;

  const bool has_confirmed = !decision.confirmed_classes.empty();
  if (has_confirmed) {
    kinds.push_back(RestrictionKind::LoadCeiling);
    kinds.push_back(RestrictionKind::NoCapacityCommitment);
  }
  if (!decision.confirmed_classes.empty() || !decision.suspected_classes.empty()) {
    kinds.push_back(RestrictionKind::NoNewWork);
  }

  for (FailureClass failure_class : decision.confirmed_classes) {
    const bool isolate = failure_class == FailureClass::LoopLoss ||
                         failure_class == FailureClass::CduFailure ||
                         failure_class == FailureClass::Leak ||
                         failure_class == FailureClass::ValveFlowFailure ||
                         failure_class == FailureClass::PressureFailure ||
                         failure_class == FailureClass::PumpFailure;
    if (isolate) {
      kinds.push_back(RestrictionKind::IsolateCoolantPath);
    }
    if (failure_class == FailureClass::ContainmentBreach || failure_class == FailureClass::Leak) {
      kinds.push_back(RestrictionKind::HoldContainment);
    }
    if (failure_class == FailureClass::PlantLoss || failure_class == FailureClass::ChillerFailure ||
        failure_class == FailureClass::SharedSourceFailure) {
      kinds.push_back(RestrictionKind::ReservedStandby);
    }
  }
  if (severity_at_least(decision.severity, Severity::Critical)) {
    kinds.push_back(RestrictionKind::ManualHold);
  }

  std::sort(kinds.begin(), kinds.end(), [](RestrictionKind lhs, RestrictionKind rhs) {
    return restriction_kind_index(lhs) < restriction_kind_index(rhs);
  });
  kinds.erase(std::unique(kinds.begin(), kinds.end()), kinds.end());

  std::vector<ProtectiveRestriction> restrictions;
  for (RestrictionKind kind : kinds) {
    const Result<RestrictionId> id = restriction_id(scope.id, kind);
    if (!id.has_value()) {
      return id.error();
    }
    ProtectiveRestriction restriction;
    restriction.id = id.value();
    restriction.scope = scope.id;
    restriction.kind = kind;
    if (kind == RestrictionKind::LoadCeiling) {
      restriction.ceiling = scope.policy.envelope.declared_demand;
    }
    for (const CoolingFailure& failure : failures) {
      if (!(failure.scope == scope.id)) {
        continue;
      }
      if (failure.confirmation == ConfirmationState::Confirmed ||
          failure.confirmation == ConfirmationState::Suspected) {
        restriction.released_by.push_back(failure.id);
      }
    }
    std::sort(restriction.released_by.begin(), restriction.released_by.end());
    restriction.released_by.erase(
        std::unique(restriction.released_by.begin(), restriction.released_by.end()),
        restriction.released_by.end());
    restrictions.push_back(std::move(restriction));
  }
  std::sort(restrictions.begin(), restrictions.end(),
            [](const ProtectiveRestriction& lhs, const ProtectiveRestriction& rhs) {
              return lhs.id < rhs.id;
            });
  return restrictions;
}

std::vector<std::string> explain_scope_impl(const CoolingScope& scope, const ScopeDecision& decision) {
  std::vector<std::string> lines;
  lines.push_back("scope " + quote(scope.id.str()) + " kind=" + std::string(to_token(scope.kind)) +
                  " at=" + decimal(decision.evaluated_at.milliseconds()));
  lines.push_back("severity=" + std::string(to_token(decision.severity)) +
                  " urgency=" + std::string(to_token(decision.urgency)) +
                  " time-to-impact=" + std::string(to_token(decision.time_to_impact)));
  lines.push_back("binding=" + std::string(to_token(decision.binding_status)) +
                  " plan=" + std::string(to_token(decision.plan_lifecycle)) +
                  " recovery=" + std::string(to_token(decision.recovery)));
  for (FailureClass failure_class : decision.confirmed_classes) {
    lines.push_back("confirmed class=" + std::string(to_token(failure_class)) +
                    " rule=" + std::string(failure_rule(failure_class).rule_id));
  }
  for (FailureClass failure_class : decision.suspected_classes) {
    lines.push_back("suspected class=" + std::string(to_token(failure_class)) +
                    " rule=" + std::string(failure_rule(failure_class).rule_id));
  }
  for (FailureClass failure_class : decision.contradicted_classes) {
    lines.push_back("contradicted class=" + std::string(to_token(failure_class)));
  }
  for (FailureClass failure_class : decision.unknown_classes) {
    lines.push_back("unknown class=" + std::string(to_token(failure_class)));
  }
  for (const ScopeId& source : decision.shared_sources) {
    lines.push_back("shared-source scope=" + quote(source.str()));
  }
  for (FailureId const& failure : decision.failures) {
    lines.push_back("failure id=" + quote(failure.str()));
  }
  for (const RestrictionId& restriction : decision.restrictions) {
    lines.push_back("restriction id=" + quote(restriction.str()));
  }
  for (ObservationChannel channel : decision.evidence_gaps) {
    lines.push_back("evidence-gap channel=" + std::string(to_token(channel)));
  }
  return lines;
}

Result<std::vector<std::pair<ScopeId, ScopeId>>> shared_source_attribution_impl(
    const CoolingFailureState& state, const std::vector<ScopeId>& scopes_with_total_loss) {
  std::vector<std::pair<ScopeId, ScopeId>> pairs;
  std::vector<ScopeId> origins = scopes_with_total_loss;
  std::sort(origins.begin(), origins.end());
  origins.erase(std::unique(origins.begin(), origins.end()), origins.end());
  // The pairs are (dependent, lost scope), derived from which scopes declare a
  // dependency on a lost scope and not from the lost scope's own dependencies.
  for (const ScopeId& origin : origins) {
    for (const CoolingScope& candidate : state.scopes) {
      if (candidate.id == origin) {
        continue;
      }
      for (const ScopeDependency& dependency : candidate.dependencies) {
        if (dependency.upstream == origin && dependency.share_parts_per_million > 0) {
          pairs.emplace_back(candidate.id, origin);
        }
      }
    }
  }
  std::sort(pairs.begin(), pairs.end(),
            [](const std::pair<ScopeId, ScopeId>& lhs, const std::pair<ScopeId, ScopeId>& rhs) {
              if (!(lhs.first == rhs.first)) {
                return lhs.first < rhs.first;
              }
              return lhs.second < rhs.second;
            });
  pairs.erase(std::unique(pairs.begin(), pairs.end()), pairs.end());
  return pairs;
}

Result<ScopeDecision> classify_scope_impl(const ScopeId& scope_id, const DecisionInput& input) {
  if (input.observations == nullptr) {
    return Error(ErrorCode::InvalidArgument, "an evaluation needs an observation set");
  }
  const ObservationSet& observations = *input.observations;
  CoolingFailureState working;
  if (input.prior != nullptr) {
    working.scopes = input.prior->scopes;
    working.failures = input.prior->failures;
    working.plans = input.prior->plans;
    working.evidence = input.prior->evidence;
    working.decisions = input.prior->decisions;
  } else {
    working.scopes.clear();
  }
  const CoolingScope* scope = find_scope(working, scope_id);
  if (scope == nullptr) {
    return Error(ErrorCode::ScopeNotFound, "the scope is not declared in the prior state")
        .with_subject(scope_id.str());
  }
  CFM_TRYV(validate_policy(input.policy));

  ScopeDecision decision;
  decision.scope = scope_id;
  decision.evaluated_at = input.clock;
  decision.binding_status =
      assess_bindings_impl(input.bindings, input.observed_bindings).status;

  for (FailureClass failure_class : all_classes()) {
    if (decision.confirmed_classes.size() >= limits::kMaxConfirmedClassesPerScope &&
        !decision.confirmed_classes.empty()) {
      return Error(ErrorCode::LimitExceeded,
                   "more confirmed classes than the per-scope bound allows")
          .with_subject(scope_id.str());
    }
    const ClassOutcome outcome =
        classify_class(*scope, observations, input.policy, input.clock, failure_class);
    switch (outcome.state) {
      case ConfirmationState::Confirmed:
        add_unique(decision.confirmed_classes, failure_class);
        if (severity_at_least(outcome.severity, decision.severity)) {
          decision.severity = outcome.severity;
          decision.urgency = outcome.urgency;
          decision.time_to_impact = outcome.time_to_impact;
        }
        break;
      case ConfirmationState::Suspected:
        add_unique(decision.suspected_classes, failure_class);
        if (!severity_at_least(decision.severity, Severity::Degraded) &&
            severity_at_least(outcome.severity, Severity::Degraded)) {
          decision.severity = outcome.severity;
          decision.urgency = outcome.urgency;
          decision.time_to_impact = outcome.time_to_impact;
        }
        break;
      case ConfirmationState::Contradicted:
        add_unique(decision.contradicted_classes, failure_class);
        break;
      case ConfirmationState::Unknown:
      case ConfirmationState::Unsupported:
      case ConfirmationState::Healthy:
        add_unique(decision.unknown_classes, failure_class);
        break;
    }
  }

  decision.failures = plan_failures_for(working, scope_id);
  decision.evidence_gaps =
      evidence_gaps_for(working, *scope, observations, input.policy, input.clock);
  decision.explanation = explain_scope_impl(*scope, decision);
  return decision;
}

// ---------------------------------------------------------------------------
// Attribution threshold
// ---------------------------------------------------------------------------

/// The declared share at or above which a downstream scope is treated as having
/// lost its cooling function rather than merely sharing a plant. Half the
/// declared supply is the documented threshold: below it the downstream scope
/// still has a majority of its declared cooling from another source, so the
/// attribution is reported as a suspicion and the class is named in the
/// downstream scope's Suspected bucket instead of its Confirmed bucket.
constexpr std::int64_t kAttributionConfirmSharePpm = 500000;

bool share_confirms(std::int64_t share_parts_per_million) noexcept {
  return share_parts_per_million >= kAttributionConfirmSharePpm;
}

// ---------------------------------------------------------------------------
// Plan finalisation
// ---------------------------------------------------------------------------

/// Builds one scope's plan from the classification this evaluation derived, the
/// restrictions it requires, the solicitations it was asked to issue and the
/// attempt outcomes it was told about.
///
/// The plan is derived, never accumulated: an attempt is carried forward from
/// the prior plan with its state machine applied, and an attempt that was in
/// flight when a different authority held the store is marked Unresolved once
/// and stays that way until something explicitly resolves it.
Result<ResponsePlan> build_plan(const CoolingFailureState& state, const CoolingScope& scope,
                                const ScopeDecision& decision, const DecisionInput& input) {
  ResponsePlan plan;
  CFM_TRY(plan_identity, plan_id_for(scope.id));
  plan.id = plan_identity;
  plan.scope = scope.id;
  plan.updated_at = input.clock;
  plan.failures = plan_failures_for(state, scope.id);
  CFM_TRY(eligible, eligible_actions_impl(scope, decision, input.policy));
  plan.eligible = std::move(eligible);
  CFM_TRY(restrictions, required_restrictions_impl(scope, decision, state.failures, input.policy));
  plan.restrictions = std::move(restrictions);
  for (ProtectiveRestriction& restriction : plan.restrictions) {
    restriction.plan = plan.id;
  }

  // Carry every attempt of the prior plan forward, then apply the reports.
  if (input.prior != nullptr) {
    if (const ResponsePlan* prior = find_plan_for_scope(*input.prior, scope.id)) {
      plan.attempts = prior->attempts;
      plan.has_solicited_action = prior->has_solicited_action;
      plan.solicited_action = prior->solicited_action;
    }
  }

  // An attempt that was in flight under a previous writer authority was not
  // observed by this authority and is therefore of unknown outcome. It is marked
  // once, it is never redispatched, and only an explicit report may resolve it.
  if (input.authority_changed) {
    for (ResponseAttempt& attempt : plan.attempts) {
      if (state_is_in_flight(attempt.state) && !attempt.adopted_after_restart) {
        attempt.state = AttemptState::Unresolved;
        attempt.adopted_after_restart = true;
        attempt.updated_at = input.clock;
      }
    }
  }

  for (const DecisionInput::AttemptReport& report : input.attempt_reports) {
    auto found = std::find_if(plan.attempts.begin(), plan.attempts.end(),
                              [&](const ResponseAttempt& attempt) {
                                return attempt.id == report.attempt;
                              });
    if (found == plan.attempts.end()) {
      // A report for an attempt of another scope is not this plan's business;
      // the caller learns about it from that scope's plan.
      continue;
    }
    if (!transition_allowed(found->state, report.state)) {
      return Error(ErrorCode::AttemptAlreadyTerminal,
                   "the reported attempt state is not reachable from its current state")
          .with_subject(report.attempt.str())
          .with_detail(std::string("from ") + std::string(to_token(found->state)) + " to " +
                       std::string(to_token(report.state)));
    }
    if (state_claims_effect(report.state)) {
      if (report.effect_observation.empty()) {
        return Error(ErrorCode::EffectClaimedWithoutEvidence,
                     "an attempt may not claim an effect without naming the observation that shows it")
            .with_subject(report.attempt.str());
      }
      if (!effect_observation_present(state, scope.id, report.effect_observation)) {
        return Error(ErrorCode::EffectClaimedWithoutEvidence,
                     "the named effect observation is not recorded evidence for this scope")
            .with_subject(report.effect_observation.str());
      }
      if (report.verdict.empty() &&
          (report.state == AttemptState::Verified || report.state == AttemptState::Refuted)) {
        return Error(ErrorCode::EffectClaimedWithoutEvidence,
                     "a verified or refuted effect must carry the verdict that verified it")
            .with_subject(report.attempt.str());
      }
      found->effect_observation = report.effect_observation;
    }
    found->state = report.state;
    found->verdict = report.verdict;
    found->adopted_after_restart = false;
    found->updated_at = report.at;
    if (report.state == AttemptState::Acknowledged || report.state == AttemptState::EffectObserved ||
        report.state == AttemptState::Verified || report.state == AttemptState::Refuted) {
      if (!found->acknowledged_at.present()) {
        found->acknowledged_at = report.at;
      }
    }
  }

  for (const DecisionInput::SolicitationRequest& request : input.solicitations) {
    if (!(request.scope == scope.id)) {
      continue;
    }
    // A solicitation names the action it requests. The engine refuses to emit a
    // request for an action that is not eligible for the scope: soliciting
    // something the classification does not justify would give the request an
    // authority the evidence never established.
    const bool is_eligible =
        std::any_of(plan.eligible.begin(), plan.eligible.end(),
                    [&](const ResponseEligibility& entry) { return entry.action == request.action; });
    if (!is_eligible) {
      return Error(ErrorCode::PlanNotEligible,
                   "the requested action is not eligible for this scope under the current evidence")
          .with_subject(scope.id.str())
          .with_detail(std::string("action=") + std::string(to_token(request.action)));
    }
    // A scope with an attempt whose outcome nobody observed may not also carry a
    // new request: the lost response and the new request would be two
    // consequential actions for one decision. The unresolved attempt must be
    // resolved explicitly first.
    const bool has_unresolved =
        std::any_of(plan.attempts.begin(), plan.attempts.end(), [](const ResponseAttempt& attempt) {
          return attempt.state == AttemptState::Unresolved;
        });
    if (has_unresolved) {
      return Error(ErrorCode::AttemptOutstanding,
                   "this scope has an attempt whose outcome is unresolved; resolve it before "
                   "soliciting another response")
          .with_subject(scope.id.str())
          .with_detail(std::string("requested action=") + std::string(to_token(request.action)));
    }
    if (plan.attempts.size() >= limits::kMaxAttemptCount) {
      return Error(ErrorCode::LimitExceeded, "the attempt table of one plan exceeded its bound")
          .with_subject(scope.id.str());
    }
    CFM_TRY(attempt_identity,
            attempt_id_for(scope.id, request.solicitation, request.attempt));
    auto existing = std::find_if(plan.attempts.begin(), plan.attempts.end(),
                                 [&](const ResponseAttempt& attempt) {
                                   return attempt.solicitation == request.solicitation &&
                                          attempt.attempt == request.attempt;
                                 });
    if (existing != plan.attempts.end()) {
      // Re-soliciting the same (mutation, ordinal) is a retry of one attempt, not
      // a second request: the identity is a pure function of the pair, so the
      // retry lands on the same attempt and is refused if it named another action.
      if (existing->action != request.action) {
        return Error(ErrorCode::SolicitationDuplicate,
                     "the same solicitation identity was reused for a different action")
            .with_subject(request.solicitation.str());
      }
      if (existing->addressee != request.addressee) {
        return Error(ErrorCode::SolicitationDuplicate,
                     "the same solicitation identity was reused for a different addressee")
            .with_subject(request.solicitation.str());
      }
      continue;
    }
    ResponseAttempt attempt;
    attempt.id = attempt_identity;
    attempt.solicitation = request.solicitation;
    attempt.attempt = request.attempt;
    attempt.action = request.action;
    for (const ResponseEligibility& entry : plan.eligible) {
      if (entry.action == request.action) {
        attempt.effect_class = entry.effect_class;
        break;
      }
    }
    attempt.state = AttemptState::Solicited;
    attempt.addressee = request.addressee;
    attempt.solicited_at = input.clock;
    attempt.updated_at = input.clock;
    plan.attempts.push_back(std::move(attempt));
    plan.has_solicited_action = true;
    plan.solicited_action = request.action;
  }

  std::sort(plan.attempts.begin(), plan.attempts.end(),
            [](const ResponseAttempt& lhs, const ResponseAttempt& rhs) {
              if (!(lhs.solicitation == rhs.solicitation)) {
                return lhs.solicitation < rhs.solicitation;
              }
              return lhs.attempt.value() < rhs.attempt.value();
            });
  std::sort(plan.restrictions.begin(), plan.restrictions.end(),
            [](const ProtectiveRestriction& lhs, const ProtectiveRestriction& rhs) {
              return lhs.id < rhs.id;
            });
  return plan;
}

// finish_evaluation performs the plan, restriction, attempt and recovery part of
// an evaluation once the failure set is final. It is declared here and defined
// below so that evaluate() reads as the five ordered phases it performs.

// ===========================================================================
// Recovery explanation
// ===========================================================================

/// The per-gate and per-attempt explanation lines of one plan. They are built
/// from the plan the engine just derived rather than stored, so the lines and the
/// verdict can never disagree.
std::vector<std::string> explain_recovery_lines(const ScopeDecision& decision,
                                                const ResponsePlan& plan) {
  std::vector<std::string> lines;
  lines.push_back(std::string("plan=") + quote(plan.id.str()) + " lifecycle=" +
                  std::string(to_token(plan.lifecycle)) + " attempts=" +
                  to_decimal(static_cast<std::uint64_t>(plan.attempts.size())) + " restrictions=" +
                  to_decimal(static_cast<std::uint64_t>(plan.restrictions.size())));
  for (const ResponseEligibility& entry : plan.eligible) {
    lines.push_back(std::string("eligible action=") + std::string(to_token(entry.action)) +
                    " effect=" + std::string(to_token(entry.effect_class)) +
                    " rank=" + to_decimal(static_cast<std::int64_t>(entry.rank)) +
                    " rule=" + quote(entry.rule_id) +
                    (entry.safety_critical ? " safety-critical=1" : " safety-critical=0"));
  }
  for (const ResponseAttempt& attempt : plan.attempts) {
    lines.push_back(std::string("attempt id=") + quote(attempt.id.str()) + " action=" +
                    std::string(to_token(attempt.action)) + " state=" +
                    std::string(to_token(attempt.state)) +
                    (attempt.adopted_after_restart ? " adopted-after-restart=1"
                                                   : " adopted-after-restart=0"));
  }
  (void)decision;
  return lines;
}

/// finish_evaluation performs the plan, restriction, attempt and recovery phases of
/// an evaluation, once the failure set is final. It is defined below so that
/// evaluate() reads as the ordered phases it performs.
Result<DecisionOutcome> finish_evaluation(const DecisionInput& input, DecisionOutcome outcome);

Result<DecisionOutcome> evaluate_impl(const DecisionInput& input) {
  if (input.observations == nullptr) {
    return Error(ErrorCode::InvalidArgument, "an evaluation needs an observation set");
  }
  CFM_TRYV(validate_policy(input.policy));
  const ObservationSet& observations = *input.observations;

  DecisionOutcome outcome;
  CoolingFailureState& state = outcome.state;
  if (input.prior != nullptr) {
    state = *input.prior;
  } else {
    state = CoolingFailureState{};
  }

  // The evaluation clock and the bindings are inputs, not facts about the world:
  // the engine records what it was told rather than reading them itself.
  state.evaluated_at = input.clock;
  state.bindings = input.bindings;
  state.parent_generation = state.generation;
  state.decisions.clear();

  if (state.scopes.size() > limits::kMaxScopeCount) {
    return Error(ErrorCode::LimitExceeded, "the scope table exceeded its bound");
  }

  // -------------------------------------------------------------------------
  // 1. Record the evidence the decision is computed from.
  // -------------------------------------------------------------------------
  state.evidence = build_evidence_table(state, observations, input.policy, input.clock);

  // -------------------------------------------------------------------------
  // 2. Classify every declared scope. This is the authoritative classification.
  // -------------------------------------------------------------------------
  struct ScopeClassification {
    ScopeId scope;
    ClassOutcome outcomes[16];
    std::size_t outcome_count = 0;
  };
  std::vector<ScopeClassification> classifications;
  classifications.reserve(state.scopes.size());

  for (const CoolingScope& scope : state.scopes) {
    ScopeClassification record;
    record.scope = scope.id;
    for (FailureClass failure_class : all_classes()) {
      if (record.outcome_count >= 16) {
        break;
      }
      record.outcomes[record.outcome_count] =
          classify_class(scope, observations, input.policy, input.clock, failure_class);
      ++record.outcome_count;
    }
    classifications.push_back(std::move(record));
  }

  // -------------------------------------------------------------------------
  // 3. Replace the engine's own failure records with the ones this evaluation
  //    derives, and keep every caller-recorded failure untouched.
  // -------------------------------------------------------------------------
  std::vector<CoolingFailure> kept;
  kept.reserve(state.failures.size());
  for (const CoolingFailure& failure : state.failures) {
    // The engine composes the identities of the records it derives itself, so it
    // can recognise and replace them exactly. Anything else was recorded by a
    // caller and is preserved byte for byte.
    if (!is_engine_derived(failure)) {
      kept.push_back(failure);
    }
  }
  state.failures = std::move(kept);

  // The engine's derived failure records are exactly the ones whose identity it
  // composes itself: fl.<scope>.<class> for a classification and
  // sf.<downstream>.<upstream> for an attribution. They are removed wholesale
  // before being re-derived, because the previous evaluation published its own
  // records in the prior state and re-deriving over them would duplicate them.
  // A caller-recorded failure uses an identity of its own choosing and is never
  // touched.
  std::vector<CoolingFailure> derived;
  for (const ScopeClassification& record : classifications) {
    for (std::size_t index = 0; index < record.outcome_count; ++index) {
      const ClassOutcome& class_outcome = record.outcomes[index];
      if (class_outcome.state != ConfirmationState::Confirmed &&
          class_outcome.state != ConfirmationState::Suspected) {
        continue;
      }
      std::string text = "fl.";
      text += record.scope.str();
      text += ".";
      text += to_token(class_outcome.failure_class);
      if (text.size() > limits::kMaxIdentifierBytes) {
        return Error(ErrorCode::MalformedIdentifier,
                     "a failure identity would exceed the identifier length bound")
            .with_subject(text.substr(0, 160));
      }
      CFM_TRY(failure_id, FailureId::parse(text));
      CoolingFailure failure;
      failure.id = failure_id;
      failure.scope = record.scope;
      failure.failure_class = class_outcome.failure_class;
      failure.confirmation = class_outcome.state;
      failure.severity = class_outcome.severity;
      failure.urgency = class_outcome.urgency;
      failure.time_to_impact = class_outcome.time_to_impact;
      failure.confirmed_at = input.clock;
      failure.basis = class_outcome.basis;
      failure.rationale = std::string("observed on ") +
                          std::string(to_token(class_outcome.failure_class)) +
                          " witnesses; rule=" +
                          std::string(failure_rule(class_outcome.failure_class).rule_id);
      derived.push_back(std::move(failure));
    }
  }

  // -------------------------------------------------------------------------
  // 4. Attribute shared upstream losses to the scopes that depend on them.
  //
  //    A scope whose own cooling function is already confirmed lost keeps its
  //    local, more specific classification: attributing a shared-source failure
  //    on top of it would add no information and would double-count the loss.
  //    A scope that is merely Suspected locally still receives the attribution,
  //    because a shared loss is a different fact from a local suspicion.
  // -------------------------------------------------------------------------
  std::vector<ScopeId> lost_scopes;
  for (const CoolingFailure& failure : derived) {
    if (failure.confirmation == ConfirmationState::Confirmed &&
        failure_class_is_total_loss(failure.failure_class)) {
      lost_scopes.push_back(failure.scope);
    }
  }
  std::sort(lost_scopes.begin(), lost_scopes.end());
  lost_scopes.erase(std::unique(lost_scopes.begin(), lost_scopes.end()), lost_scopes.end());

  struct Attribution {
    ScopeId downstream;
    ScopeId upstream;
    std::int64_t share = 0;
    FailureId upstream_failure;
    Severity severity = Severity::None;
    Urgency urgency = Urgency::Routine;
    TimeToImpact time_to_impact = TimeToImpact::Unobserved;
    std::vector<ObservationId> basis;
  };
  std::vector<Attribution> attributions;
  std::vector<ScopeId> locally_lost;
  for (const CoolingFailure& failure : derived) {
    if (failure.confirmation != ConfirmationState::Confirmed) {
      continue;
    }
    if (!failure_class_is_total_loss(failure.failure_class)) {
      continue;
    }
    if (failure.failure_class == FailureClass::SharedSourceFailure) {
      continue;
    }
    locally_lost.push_back(failure.scope);
  }
  std::sort(locally_lost.begin(), locally_lost.end());
  locally_lost.erase(std::unique(locally_lost.begin(), locally_lost.end()), locally_lost.end());

  // For each scope that depends on a lost scope, attribute the loss. The share is
  // the product of the declared shares along the strongest path from a lost scope,
  // so a scope that is only partly served by the failed upstream keeps the fraction
  // it actually loses.
  // The failure set this decision will publish: the caller's records plus the ones
  // this evaluation derived. Attribution reads it rather than the state's own
  // failure table, because at this point the derived records have not been merged
  // into that table yet and the derived ones are exactly what was just confirmed.
  CoolingFailureState classified = state;
  classified.failures = state.failures;
  for (const CoolingFailure& failure : derived) {
    classified.failures.push_back(failure);
  }

  std::vector<std::pair<ScopeId, std::int64_t>> upstream_shares;
  CFM_TRY(reached_dependents, dependents_of(state, lost_scopes));
  for (const ReachedScope& entry : reached_dependents) {
    upstream_shares.emplace_back(entry.scope, entry.share_parts_per_million);
  }
  std::sort(upstream_shares.begin(), upstream_shares.end(),
            [](const std::pair<ScopeId, std::int64_t>& lhs, const std::pair<ScopeId, std::int64_t>& rhs) {
              return lhs.first < rhs.first;
            });
  CFM_TRY(attribution_pairs, shared_source_attribution_impl(classified, lost_scopes));
  for (const std::pair<ScopeId, ScopeId>& pair : attribution_pairs) {
    const ScopeId& downstream = pair.first;
    const ScopeId& upstream = pair.second;
    if (std::find(locally_lost.begin(), locally_lost.end(), downstream) != locally_lost.end()) {
      // The scope's own confirmed failure is the more specific fact; attributing
      // the upstream loss on top would double-count it.
      continue;
    }
    const LossSummary summary = worst_total_loss(classified, upstream);
    if (!summary.found) {
      continue;
    }
    std::int64_t share = 0;
    for (const std::pair<ScopeId, std::int64_t>& entry : upstream_shares) {
      if (entry.first == downstream && entry.second > share) {
        share = entry.second;
      }
    }
    if (share <= 0) {
      continue;
    }
    Attribution attribution;
    attribution.downstream = downstream;
    attribution.upstream = upstream;
    attribution.share = share;
    attribution.upstream_failure = summary.worst;
    attribution.severity = summary.severity;
    attribution.urgency = summary.urgency;
    attribution.time_to_impact = summary.time_to_impact;
    attributions.push_back(std::move(attribution));
  }
  std::sort(attributions.begin(), attributions.end(),
            [](const Attribution& lhs, const Attribution& rhs) {
              if (!(lhs.downstream == rhs.downstream)) {
                return lhs.downstream < rhs.downstream;
              }
              return lhs.upstream < rhs.upstream;
            });
  attributions.erase(std::unique(attributions.begin(), attributions.end(),
                                 [](const Attribution& lhs, const Attribution& rhs) {
                                   return lhs.downstream == rhs.downstream &&
                                          lhs.upstream == rhs.upstream;
                                 }),
                     attributions.end());

  // A downstream scope that is already Suspected for something keeps the higher
  // of the two severities; a share below half is never reported as a
  // confirmation, because a scope that is only partly served by the failed
  // upstream has not necessarily lost its cooling function.
  for (Attribution& attribution : attributions) {
    std::vector<ObservationId> basis;
    for (const CoolingFailure& failure : derived) {
      if (failure.scope == attribution.upstream && failure.id == attribution.upstream_failure) {
        basis = failure.basis;
        break;
      }
    }
    const bool confirmed = share_confirms(attribution.share);
    std::string rationale = std::string(kAttributionMarker) + " upstream=" +
                            quote(attribution.upstream.str()) + " share-ppm=" +
                            decimal(attribution.share) + " upstream-failure=" +
                            quote(attribution.upstream_failure.str());
    CFM_TRY(failure_id, attribution_id(attribution.downstream, attribution.upstream));
    CoolingFailure failure;
    failure.id = failure_id;
    failure.scope = attribution.downstream;
    failure.failure_class = FailureClass::SharedSourceFailure;
    failure.confirmation = confirmed ? ConfirmationState::Confirmed
                                     : ConfirmationState::Suspected;
    failure.severity = confirmed ? attribution.severity
                                 : downgrade_severity(attribution.severity);
    failure.urgency = attribution.urgency;
    failure.time_to_impact = attribution.time_to_impact;
    failure.confirmed_at = input.clock;
    failure.basis = basis;
    failure.shared_source = attribution.upstream;
    failure.rationale = std::move(rationale);
    derived.push_back(std::move(failure));
  }

  for (CoolingFailure& failure : derived) {
    state.failures.push_back(std::move(failure));
  }
  if (state.failures.size() > limits::kMaxFailureCount) {
    return Error(ErrorCode::LimitExceeded, "the failure table exceeded its bound");
  }
  std::sort(state.failures.begin(), state.failures.end(),
            [](const CoolingFailure& lhs, const CoolingFailure& rhs) { return lhs.id < rhs.id; });
  for (std::size_t index = 1; index < state.failures.size(); ++index) {
    if (state.failures[index - 1].id == state.failures[index].id) {
      return Error(ErrorCode::FailureDuplicate, "two failure records share one identity")
          .with_subject(state.failures[index].id.str());
    }
  }

  return finish_evaluation_impl(input, std::move(outcome));
}

// ===========================================================================
// Plan, restriction, attempt and recovery finalisation
// ===========================================================================


/// The plan lifecycle implied by the classification, the restrictions and the
/// attempt states. It is derived, never stored as caller intent.
PlanLifecycle derive_lifecycle(const ScopeDecision& decision, const ResponsePlan& plan,
                               bool has_blocking_restriction) {
  const bool has_failures = !decision.confirmed_classes.empty() ||
                            !decision.suspected_classes.empty();
  if (!has_failures) {
    if (!plan.attempts.empty() || !plan.restrictions.empty()) {
      return PlanLifecycle::Withdrawn;
    }
    return PlanLifecycle::Unplanned;
  }
  switch (decision.recovery) {
    case RecoveryDecision::Permitted:
      return PlanLifecycle::Recovered;
    case RecoveryDecision::Deferred:
      return PlanLifecycle::Recovering;
    case RecoveryDecision::Blocked:
    case RecoveryDecision::NotRequested:
      break;
  }
  if (!decision.confirmed_classes.empty()) {
    // A confirmed failure is answered first by a request. Once a request exists
    // the plan is Active: an accepted request is not proof of an effect, so the
    // plan cannot advance past Active on an acknowledgement alone.
    if (!plan.attempts.empty()) {
      return PlanLifecycle::Active;
    }
    return PlanLifecycle::Planned;
  }
  if (!plan.attempts.empty() || has_blocking_restriction) {
    return PlanLifecycle::Active;
  }
  return PlanLifecycle::Planned;
}

Result<DecisionOutcome> finish_evaluation_impl(const DecisionInput& input, DecisionOutcome outcome) {
  CoolingFailureState& state = outcome.state;

  // -------------------------------------------------------------------------
  // 5. Build one plan per declared scope, carrying attempts and restrictions
  //    forward and applying the reported outcomes.
  // -------------------------------------------------------------------------
  std::vector<ResponsePlan> plans;
  std::vector<ScopeDecision> decisions;
  std::vector<AttemptId> unresolved;

  for (const CoolingScope& scope : state.scopes) {
    ScopeDecision decision;
    decision.scope = scope.id;
    decision.evaluated_at = input.clock;
    decision.binding_status = assess_bindings_impl(input.bindings, input.observed_bindings).status;

    for (FailureClass failure_class : all_classes()) {
      bool confirmed = false;
      bool suspected = false;
      Severity severity = Severity::None;
      Urgency urgency = Urgency::Routine;
      TimeToImpact time_to_impact = TimeToImpact::Unobserved;
      for (const CoolingFailure& failure : state.failures) {
        if (!(failure.scope == scope.id) || failure.failure_class != failure_class) {
          continue;
        }
        if (failure.confirmation == ConfirmationState::Confirmed) {
          confirmed = true;
        } else if (failure.confirmation == ConfirmationState::Suspected) {
          suspected = true;
        } else {
          continue;
        }
        if (severity_at_least(failure.severity, severity)) {
          severity = failure.severity;
          urgency = failure.urgency;
          time_to_impact = failure.time_to_impact;
        }
      }
      if (confirmed) {
        add_unique(decision.confirmed_classes, failure_class);
      } else if (suspected) {
        add_unique(decision.suspected_classes, failure_class);
      } else {
        const ClassOutcome outcome_record =
            classify_class(scope, *input.observations, input.policy, input.clock, failure_class);
        switch (outcome_record.state) {
          case ConfirmationState::Contradicted:
            add_unique(decision.contradicted_classes, failure_class);
            break;
          case ConfirmationState::Healthy:
          case ConfirmationState::Unknown:
          case ConfirmationState::Unsupported:
          case ConfirmationState::Confirmed:
          case ConfirmationState::Suspected:
            add_unique(decision.unknown_classes, failure_class);
            break;
        }
        continue;
      }
      if (severity_at_least(severity, decision.severity)) {
        decision.severity = severity;
        decision.urgency = urgency;
        decision.time_to_impact = time_to_impact;
      }
      if (confirmed) {
        decision.severity = severity_at_least(severity, decision.severity) ? severity : decision.severity;
      }
    }

    // The shared-source attribution is part of the classification: a scope whose
    // upstream plant is confirmed lost is classified as sharing that loss.
    for (const CoolingFailure& failure : state.failures) {
      if (!(failure.scope == scope.id)) {
        continue;
      }
      if (failure.confirmation != ConfirmationState::Confirmed) {
        continue;
      }
      if (failure.failure_class != FailureClass::SharedSourceFailure) {
        continue;
      }
      if (!(failure.shared_source == ScopeId())) {
        if (std::find(decision.shared_sources.begin(), decision.shared_sources.end(),
                      failure.shared_source) == decision.shared_sources.end()) {
          decision.shared_sources.push_back(failure.shared_source);
        }
      }
      if (severity_at_least(failure.severity, decision.severity)) {
        decision.severity = failure.severity;
        decision.urgency = failure.urgency;
        decision.time_to_impact = failure.time_to_impact;
      }
    }
    std::sort(decision.shared_sources.begin(), decision.shared_sources.end());

    for (const CoolingFailure& failure : state.failures) {
      if (!(failure.scope == scope.id)) {
        continue;
      }
      if (failure.confirmation == ConfirmationState::Confirmed ||
          failure.confirmation == ConfirmationState::Suspected) {
        if (std::find(decision.failures.begin(), decision.failures.end(), failure.id) ==
            decision.failures.end()) {
          decision.failures.push_back(failure.id);
        }
      }
    }
    std::sort(decision.failures.begin(), decision.failures.end());
    decision.evidence_gaps =
        evidence_gaps_for(state, scope, *input.observations, input.policy, input.clock);

    // -----------------------------------------------------------------------
    // Recovery: only an explicit request is evaluated, and only against the
    // evidence that exists now. A scope is never promoted to Recovered because
    // time passed or because a request was accepted.
    // -----------------------------------------------------------------------
    const bool recovery_requested =
        std::find(input.recovery_requests.begin(), input.recovery_requests.end(), scope.id) !=
        input.recovery_requests.end();
    // A recovery is evaluated whenever one is requested AND the scope has
    // something to recover from: a confirmed failure, a suspicion, or a class
    // whose evidence is missing. A contradicted class is not something to recover
    // from - the evidence already argues against it - and a scope with nothing
    // outstanding is permitted because there is nothing to gate, which is itself
    // worth saying explicitly.
    std::size_t unevidenced_classes = 0;
    for (const FailureClass failure_class : decision.unknown_classes) {
      if (!contains_class(decision.contradicted_classes, failure_class)) {
        ++unevidenced_classes;
      }
    }
    const bool recovery_outstanding = !decision.failures.empty() ||
                                      !decision.confirmed_classes.empty() ||
                                      !decision.suspected_classes.empty() ||
                                      unevidenced_classes > 0;
    if (recovery_requested && recovery_outstanding) {
      CFM_TRY(requirements, recovery_requirements(scope, decision));
      // Every class this scope must prove clear is added FIRST, and the demand is
      // then recomputed from that full set. Doing it in the other order would
      // compose a class list whose witness channels were never demanded, and the
      // recovery would be blocked for want of evidence nobody asked for.
      //
      // A class whose evidence is missing is demanded: absence of evidence is not
      // evidence of absence. A class the evidence actively contradicts is not: it
      // has already been argued against, and demanding a positive clearance for it
      // would make every recovery unsatisfiable.
      for (const FailureClass failure_class : decision.confirmed_classes) {
        add_unique(requirements.required_cleared_classes, failure_class);
      }
      for (const FailureClass failure_class : decision.suspected_classes) {
        add_unique(requirements.required_cleared_classes, failure_class);
      }
      // A class whose evidence is missing is NOT demanded for clearance. The
      // demand is the evidence that clears the failure the recovery is recovering
      // from, and a failure that was never evidenced has no clearance to prove.
      // Demanding every unevidenced class would demand every channel in the
      // taxonomy and make a recovery impossible for any scope that does not
      // instrument the whole facility. The unevidenced classes are reported where
      // they belong: in the decision's unknown-class list.
      CFM_TRY(extended, recovery_requirements_with_classes(scope, decision, requirements));
      requirements = std::move(extended);
      std::sort(requirements.required_cleared_classes.begin(),
                requirements.required_cleared_classes.end(),
                [](FailureClass lhs, FailureClass rhs) {
                  return failure_class_index(lhs) < failure_class_index(rhs);
                });
      requirements.state_snapshot = &state;
      for (const std::pair<ScopeId, DecisionClock>& entry : input.stable_since) {
        if (entry.first == scope.id) {
          requirements.stable_since = entry.second;
        }
      }
      CFM_TRY(assessment, evaluate_recovery(scope, decision, requirements, *input.observations,
                                            input.policy, input.clock));
      decision.recovery = assessment.decision;
    } else if (recovery_requested) {
      decision.recovery = RecoveryDecision::Permitted;
    } else {
      decision.recovery = RecoveryDecision::NotRequested;
    }

    CFM_TRY(plan, build_plan(state, scope, decision, input));
    const bool has_blocking_restriction = !plan.restrictions.empty();
    const PlanLifecycle lifecycle = derive_lifecycle(decision, plan, has_blocking_restriction);
    plan.lifecycle = lifecycle;
    if (decision.recovery == RecoveryDecision::Permitted && !plan.restrictions.empty()) {
      // Every gate passed on current evidence, so the protective restrictions are
      // released in the same decision that permits the recovery. Releasing them
      // is itself a recorded decision: the plan keeps its attempt history.
      plan.restrictions.clear();
    }
    decision.plan_lifecycle = lifecycle;
    if (lifecycle != PlanLifecycle::Unplanned) {
      decision.plan = plan.id;
      decision.has_plan = true;
      for (const ProtectiveRestriction& restriction : plan.restrictions) {
        decision.restrictions.push_back(restriction.id);
      }
      std::sort(decision.restrictions.begin(), decision.restrictions.end());
    }
    for (const ResponseAttempt& attempt : plan.attempts) {
      // Only an attempt whose outcome is explicitly unknown is reported as
      // unresolved. An attempt that is merely in flight is the normal state of a
      // live request, and the store refuses a fresh publication for it separately,
      // at the publication boundary where a lost response actually matters.
      if (attempt.state == AttemptState::Unresolved) {
        unresolved.push_back(attempt.id);
      }
    }
    decision.explanation = explain_scope_impl(scope, decision);
    // The binding state and the recovery verdict are part of the explanation, so
    // a reader never has to re-derive them from the numbers.
    decision.explanation.push_back(
        std::string("recovery-decision=") + std::string(to_token(decision.recovery)) +
        " binding=" + std::string(to_token(decision.binding_status)));
    for (const std::string& line : explain_recovery_lines(decision, plan)) {
      decision.explanation.push_back(line);
    }

    decisions.push_back(std::move(decision));
    plans.push_back(std::move(plan));
  }

  std::sort(plans.begin(), plans.end(),
            [](const ResponsePlan& lhs, const ResponsePlan& rhs) { return lhs.id < rhs.id; });
  std::sort(decisions.begin(), decisions.end(), [](const ScopeDecision& lhs, const ScopeDecision& rhs) {
    return lhs.scope < rhs.scope;
  });
  std::sort(unresolved.begin(), unresolved.end());
  unresolved.erase(std::unique(unresolved.begin(), unresolved.end()), unresolved.end());

  state.plans = std::move(plans);
  state.decisions = std::move(decisions);
  state.unresolved_attempts = std::move(unresolved);

  if (state.plans.size() > limits::kMaxScopeCount) {
    return Error(ErrorCode::LimitExceeded, "the plan table exceeded its bound");
  }

  // -------------------------------------------------------------------------
  // 6. Canonicalise everything and validate the whole state before it leaves the
  //    engine, so a caller can never receive a state the engine itself would
  //    refuse.
  // -------------------------------------------------------------------------
  CFM_TRYV(canonicalize(state));
  CFM_TRYV(validate_structure(state));

  outcome.changed = true;
  if (input.prior != nullptr) {
    outcome.changed = !(outcome.state.evaluated_at == input.prior->evaluated_at) ||
                      outcome.state.evidence.size() != input.prior->evidence.size() ||
                      outcome.state.failures.size() != input.prior->failures.size() ||
                      outcome.state.scopes.size() != input.prior->scopes.size();
  }
  for (const ScopeDecision& decision : outcome.state.decisions) {
    outcome.explanation.push_back(std::string("evaluated scope=") + quote(decision.scope.str()));
    for (const FailureClass failure_class : decision.confirmed_classes) {
      outcome.explanation.push_back(std::string("  confirmed=") +
                                    std::string(to_token(failure_class)));
    }
    for (const FailureClass failure_class : decision.suspected_classes) {
      outcome.explanation.push_back(std::string("  suspected=") +
                                    std::string(to_token(failure_class)));
    }
    for (const FailureClass failure_class : decision.unknown_classes) {
      outcome.explanation.push_back(std::string("  unknown=") +
                                    std::string(to_token(failure_class)));
    }
    for (const ObservationChannel channel : decision.evidence_gaps) {
      outcome.explanation.push_back(std::string("  evidence-gap=") +
                                    std::string(to_token(channel)));
    }
  }
  return outcome;
}

}  // namespace

// ===========================================================================
// Public forwarding surface
// ===========================================================================
//
// The public functions of the header forward to the engine's internal
// implementations. The split exists so that the engine can call its own
// classification and eligibility logic without going through the public
// overload set, and so that a reader can see at a glance which names are part of
// the component's contract and which are its internals. The internal names carry
// an _impl suffix for exactly that reason.

Result<DecisionOutcome> evaluate(const DecisionInput& input) { return evaluate_impl(input); }

BindingAssessment assess_bindings(const AuthoritySet& published, const BindingObservation& observed) {
  return assess_bindings_impl(published, observed);
}

bool binding_assessment_allows_recovery(const BindingAssessment& assessment) noexcept {
  return binding_assessment_allows_recovery_impl(assessment);
}

Result<std::vector<ResponseEligibility>> eligible_actions(const CoolingScope& scope,
                                                          const ScopeDecision& decision,
                                                          const DecisionPolicy& policy) {
  return eligible_actions_impl(scope, decision, policy);
}

Result<std::vector<ProtectiveRestriction>> required_restrictions(
    const CoolingScope& scope, const ScopeDecision& decision,
    const std::vector<CoolingFailure>& failures, const DecisionPolicy& policy) {
  return required_restrictions_impl(scope, decision, failures, policy);
}

std::vector<std::string> explain_scope(const CoolingScope& scope, const ScopeDecision& decision) {
  return explain_scope_impl(scope, decision);
}

Result<std::vector<std::pair<ScopeId, ScopeId>>> shared_source_attribution(
    const CoolingFailureState& state, const std::vector<ScopeId>& scopes_with_total_loss) {
  return shared_source_attribution_impl(state, scopes_with_total_loss);
}

Result<ScopeDecision> classify_scope(const ScopeId& scope, const DecisionInput& input) {
  return classify_scope_impl(scope, input);
}

}  // namespace dccp::cooling_failure_manager
