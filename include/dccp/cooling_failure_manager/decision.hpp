// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_COOLING_FAILURE_MANAGER_DECISION_HPP
#define DCCP_COOLING_FAILURE_MANAGER_DECISION_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "dccp/cooling_failure_manager/enums.hpp"
#include "dccp/cooling_failure_manager/evidence.hpp"
#include "dccp/cooling_failure_manager/model.hpp"
#include "dccp/cooling_failure_manager/result.hpp"

namespace dccp::cooling_failure_manager {

// ===========================================================================
// Evidence channel assessment
// ===========================================================================

/// Bindings currently supplied by adjacent owners.
///
/// The assessment compares bindings by (role, owner, identity, generation). A
/// role the decision was made against but that is absent now is Unbound, not
/// Current: the library never infers continued authority from the fact that a
/// binding was once supplied.
struct BindingObservation {
  AuthoritySet current;
};

/// Compares the bindings a decision was published under with the bindings
/// currently supplied.
BindingAssessment assess_bindings(const AuthoritySet& published, const BindingObservation& observed);

/// True when the assessment permits the decision to be acted on. Recovery and
/// any state-changing continuation require a Current assessment; an escalation
/// may proceed under a non-current assessment, and says so in its explanation.
bool binding_assessment_allows_recovery(const BindingAssessment& assessment) noexcept;

// ===========================================================================
// The decision engine
// ===========================================================================

/// Everything one evaluation is computed from. The inputs are immutable: the
/// engine never writes to them, so the same inputs always produce the same
/// state.
struct DecisionInput {
  /// Prior state, or nullptr for a first evaluation.
  const CoolingFailureState* prior = nullptr;
  const ObservationSet* observations = nullptr;
  DecisionPolicy policy;
  DecisionClock clock{};
  /// Bindings the evaluation is made against.
  AuthoritySet bindings;
  /// Bindings currently supplied, used for the stale-authority check.
  BindingObservation observed_bindings;

  /// True when this evaluation is running under a writer authority that did not
  /// observe the previous one (a restart, a new epoch, a new incarnation).
  ///
  /// When it is true, every attempt that was still in flight under the previous
  /// authority is moved to Unresolved exactly once: the outcome of a request
  /// nobody watched is unknown, and an unknown outcome must never be redispatched
  /// as though nothing had happened.
  bool authority_changed = false;
  /// Bounded request to solicit, if any.
  struct SolicitationRequest {
    std::string addressee;
    MutationId solicitation;
    AttemptOrdinal attempt;
    // A solicitation names the action it requests; the engine refuses to
    // solicit an action that is not eligible for the scope.
    ResponseAction action = ResponseAction::ObserveOnly;
    ScopeId scope;
  };
  std::vector<SolicitationRequest> solicitations;
  /// Attempt outcomes reported for attempts already in flight.
  struct AttemptReport {
    AttemptId attempt;
    AttemptState state = AttemptState::Solicited;
    DecisionClock at{};
    ObservationId effect_observation;
    std::string verdict;
  };
  std::vector<AttemptReport> attempt_reports;
  /// Clock at which each scope's stable interval started, supplied by the
  /// caller. An absent entry means the interval has not started.
  std::vector<std::pair<ScopeId, DecisionClock>> stable_since;
  /// Recovery requests. Only a scope named here is evaluated for recovery; a
  /// scope with a confirmed failure is never silently promoted to Recovered.
  std::vector<ScopeId> recovery_requests;
};

/// The outcome of one evaluation.
struct DecisionOutcome {
  CoolingFailureState state;
  /// True when the evaluation changed anything relative to the prior state.
  bool changed = false;
  /// Stable machine-readable lines describing what the evaluation decided, in
  /// canonical order. Identical inputs always produce identical lines.
  std::vector<std::string> explanation;
};

/// Evaluates one cooling-failure decision.
///
/// The evaluation is a pure function of its inputs. It performs no I/O, reads no
/// clock and touches no global state, so a decision can be recomputed and
/// compared byte for byte.
///
/// It preserves every recorded observation, every failure record, every attempt
/// and every restriction from the prior state, and only re-derives the
/// classification, eligibility, restriction set, attempt states and recovery
/// verdicts. Nothing is dropped because it became inconvenient: an unresolved
/// attempt stays unresolved until it is explicitly reconciled.
Result<DecisionOutcome> evaluate(const DecisionInput& input);

/// Recomputes only the classification of one scope from the same inputs. Used by
/// verification and by the tests to check that a published decision is the
/// decision the engine would make now.
Result<ScopeDecision> classify_scope(const ScopeId& scope, const DecisionInput& input);

/// The eligible response actions for one scope, in canonical order.
///
/// Eligibility is derived from the confirmed classes and from the scope's
/// protective state. An action is eligible whether or not it has been
/// solicited: eligibility, solicitation and observed effect are three separate
/// facts.
Result<std::vector<ResponseEligibility>> eligible_actions(const CoolingScope& scope,
                                                          const ScopeDecision& decision,
                                                          const DecisionPolicy& policy);

/// The protective restrictions that must be in force for one scope.
Result<std::vector<ProtectiveRestriction>> required_restrictions(
    const CoolingScope& scope, const ScopeDecision& decision,
    const std::vector<CoolingFailure>& failures, const DecisionPolicy& policy);

/// Stable explanation lines for one scope decision, in canonical order.
std::vector<std::string> explain_scope(const CoolingScope& scope, const ScopeDecision& decision);

/// True when a confirmed class is severe enough to escalate immediately.
bool is_safety_escalation(FailureClass failure_class, const DecisionPolicy& policy) noexcept;

/// Implements the shared upstream failure rule: a confirmed failure of an
/// upstream scope is attributed to every downstream scope that depends on it,
/// with the dependency's declared share, and the downstream scope's decision
/// records the shared source.
Result<std::vector<std::pair<ScopeId, ScopeId>>> shared_source_attribution(
    const CoolingFailureState& state, const std::vector<ScopeId>& scopes_with_total_loss);

/// True when a scope's declared dependency share for one upstream scope is at
/// least the given fraction in parts per million.
bool dependency_share_at_least(std::int64_t share_parts_per_million, std::int64_t threshold) noexcept;

}  // namespace dccp::cooling_failure_manager

#endif  // DCCP_COOLING_FAILURE_MANAGER_DECISION_HPP
