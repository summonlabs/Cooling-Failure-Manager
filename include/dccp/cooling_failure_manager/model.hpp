// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_COOLING_FAILURE_MANAGER_MODEL_HPP
#define DCCP_COOLING_FAILURE_MANAGER_MODEL_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/digest.hpp"
#include "dccp/cooling_failure_manager/enums.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/result.hpp"
#include "dccp/cooling_failure_manager/strong_id.hpp"

namespace dccp::cooling_failure_manager {

// ===========================================================================
// Authority bindings
// ===========================================================================

/// One reference to a fact owned by another component, bound to the exact
/// generation of that fact.
///
/// A binding is provenance, never permission. Two bindings are equal only when
/// the owner, the identity *and* the generation all match. This component never
/// advances an ExternalGeneration: it records what it was told and reports when
/// the owner has moved on.
class AuthorityRef {
 public:
  AuthorityRef() noexcept = default;

  /// owner: component that owns the fact ("cooling-topology", "incident-state-fabric", ...).
  /// identity: the owner's object identity, preserved verbatim.
  /// generation: the owner's generation of that object.
  static Result<AuthorityRef> make(std::string_view owner, std::string_view identity,
                                   ExternalGeneration generation);

  const std::string& owner() const noexcept { return owner_; }
  const std::string& identity() const noexcept { return identity_; }
  ExternalGeneration generation() const noexcept { return generation_; }
  bool bound() const noexcept { return !owner_.empty() && !identity_.empty(); }

  friend bool operator==(const AuthorityRef&, const AuthorityRef&) noexcept = default;

  /// Byte-wise ordering by (owner, identity, generation). Canonical ordering is
  /// what makes encoded bytes independent of insertion order.
  friend std::strong_ordering operator<=>(const AuthorityRef& lhs, const AuthorityRef& rhs) noexcept;

 private:
  std::string owner_;
  std::string identity_;
  ExternalGeneration generation_{};
};

/// The complete set of bindings a decision was made against.
///
/// Bindings are held sorted by (role, owner, identity) so encoding is
/// independent of the order in which a caller supplied them.
class AuthoritySet {
 public:
  AuthoritySet() = default;

  /// Adds or replaces the binding held for a role. Role names are stable,
  /// ASCII-only tokens ("cooling-topology", "cooling-capacity", ...).
  Result<void> set(std::string_view role, AuthorityRef reference);

  /// Removes the binding for a role. Absent roles are not an error.
  void erase(std::string_view role);

  /// The binding recorded for a role, when one exists.
  const AuthorityRef* find(std::string_view role) const noexcept;

  /// Bindings in canonical order.
  const std::vector<std::pair<std::string, AuthorityRef>>& entries() const noexcept { return entries_; }

  std::size_t size() const noexcept { return entries_.size(); }
  bool empty() const noexcept { return entries_.empty(); }

  /// Byte-wise equality over the canonical ordering.
  friend bool operator==(const AuthoritySet&, const AuthoritySet&) noexcept;

 private:
  std::vector<std::pair<std::string, AuthorityRef>> entries_;
};

/// Roles this component understands. A binding under an unknown role is
/// accepted and preserved (so a producer can bind a fact this component does not
/// yet classify) but is reported by verification as an unclassified binding.
namespace roles {
inline constexpr std::string_view kCoolingTopology = "cooling-topology";
inline constexpr std::string_view kCoolingCapacity = "cooling-capacity";
inline constexpr std::string_view kAirflowControl = "airflow-control";
inline constexpr std::string_view kLiquidCoolingControl = "liquid-cooling-control";
inline constexpr std::string_view kThermalZoneManager = "thermal-zone-manager";
inline constexpr std::string_view kCoolingFailover = "cooling-failover";
inline constexpr std::string_view kThermalEmergencyManager = "thermal-emergency-manager";
inline constexpr std::string_view kIncidentStateFabric = "incident-state-fabric";
inline constexpr std::string_view kFailureDomainRegistry = "facility-failure-domain-registry";
inline constexpr std::string_view kPolicy = "cooling-failure-policy";
}  // namespace roles

// ===========================================================================
// Declared scope state
// ===========================================================================

/// A declared scalar bound or reading, in the units of its channel.
///
/// Declared values are *inputs* supplied by their owner (design limits, service
/// envelopes, contract demand). This component compares observations against
/// declared bounds; it never derives a design limit, never converts between
/// load and capacity, and never performs the capacity arithmetic owned by
/// Cooling Capacity.
class DeclaredQuantity {
 public:
  DeclaredQuantity() noexcept = default;

  static Result<DeclaredQuantity> make(std::int64_t value, std::string_view unit);

  std::int64_t value() const noexcept { return value_; }
  const std::string& unit() const noexcept { return unit_; }
  bool declared() const noexcept { return !unit_.empty(); }

  friend bool operator==(const DeclaredQuantity&, const DeclaredQuantity&) noexcept = default;
  friend std::strong_ordering operator<=>(const DeclaredQuantity&, const DeclaredQuantity&) noexcept;

 private:
  std::int64_t value_ = 0;
  std::string unit_;
};

/// Thermal envelope declared for one scope.
struct ThermalEnvelope {
  /// Highest coolant supply temperature the scope may be served with.
  DeclaredQuantity max_supply_temperature{};
  /// Lowest acceptable thermal margin; margin below this is out of envelope.
  DeclaredQuantity min_thermal_margin{};
  /// Lowest acceptable flow through the scope.
  DeclaredQuantity min_flow{};
  /// Lowest acceptable differential pressure across the scope.
  DeclaredQuantity min_differential_pressure{};
  /// Contract heat-rejection demand of the scope.
  DeclaredQuantity declared_demand{};
};

/// One channel the scope's owner requires as evidence, with the classification
/// gates that channel feeds.
struct EvidenceRequirement {
  ObservationChannel channel = ObservationChannel::FlowMeter;
  /// Maximum acceptable age of an observation on this channel. A window of zero
  /// means the observation must be dated exactly at the decision clock.
  DurationMilliseconds window{};
};

/// Declared policy for one scope: what evidence the scope requires, which
/// confirmation thresholds apply, and how a recovery must be proven.
struct ScopePolicy {
  std::vector<EvidenceRequirement> requirements;
  /// Classes whose confirmation must never be inferred without a positive
  /// observation on the class's own channel.
  std::vector<FailureClass> strict_classes;
  /// Minimum interval the scope must hold its recovered readings before a
  /// recovery may be permitted.
  DurationMilliseconds recovery_dwell{};
  /// Additional interval after the dwell during which the readings must not
  /// regress; a regression inside this window restarts the dwell.
  DurationMilliseconds recovery_hysteresis{};
  /// Thermal envelope used by the recovery gates and by capacity confirmations.
  ThermalEnvelope envelope{};
  /// Highest confirmed severity for which this scope permits continued service.
  /// A confirmed failure above this floor forces protective restrictions.
  Severity service_severity_floor = Severity::Degraded;
};

/// One dependency of a scope on another scope in *this* component's scope graph.
///
/// The structural cooling topology is owned by Cooling Topology. This graph is
/// the projection this component needs in order to attribute a shared upstream
/// failure and to propagate a protective restriction; it makes no claim to be
/// the authoritative topology.
struct ScopeDependency {
  ScopeId upstream;
  DependencyKind kind = DependencyKind::SuppliesCoolant;
  /// Fraction of the downstream scope's cooling that this dependency supplies,
  /// in parts per million. 1000000 means "entirely".
  std::int64_t share_parts_per_million = 0;
};

/// A cooling scope this component tracks failure state for.
struct CoolingScope {
  ScopeId id;
  ScopeKind kind = ScopeKind::Loop;
  std::string display_name;
  /// Bindings that identify the scope in its owner's namespaces, so a decision
  /// can be fenced against the exact topology generation it was made under.
  AuthoritySet bindings;
  ScopePolicy policy;
  /// Dependencies in canonical order (upstream identity, then kind).
  std::vector<ScopeDependency> dependencies;
};

// ===========================================================================
// Failure records
// ===========================================================================

/// One confirmed or suspected cooling failure class on one scope.
struct CoolingFailure {
  FailureId id;
  ScopeId scope;
  FailureClass failure_class = FailureClass::LoopLoss;
  ConfirmationState confirmation = ConfirmationState::Unknown;
  Severity severity = Severity::None;
  Urgency urgency = Urgency::Routine;
  TimeToImpact time_to_impact = TimeToImpact::Unobserved;
  /// Decision clock at which the confirmation was observed.
  DecisionClock confirmed_at{};
  /// Observation identities that justify the confirmation, in canonical order.
  std::vector<ObservationId> basis;
  /// The shared upstream scope whose failure this record attributes, when the
  /// class is SharedSourceFailure or when a shared dependency was implicated.
  ScopeId shared_source;
  std::string rationale;
};

// ===========================================================================
// Response plans
// ===========================================================================

/// One cooling mitigation that the decision engine found eligible.
struct ResponseEligibility {
  ResponseAction action = ResponseAction::ObserveOnly;
  EffectClass effect_class = EffectClass::None;
  /// True when the action is justified by a safety rule that does not wait for
  /// the dwell windows that a recovery does wait for.
  bool safety_critical = false;
  /// Stable rule identity that produced the eligibility, so an explanation can
  /// name its rule rather than restating a narrative.
  std::string rule_id;
  /// Lower is considered first. Ties are broken by action token.
  std::int32_t rank = 0;
};

/// One bounded protective restriction in force on a scope.
struct ProtectiveRestriction {
  RestrictionId id;
  ScopeId scope;
  RestrictionKind kind = RestrictionKind::LoadCeiling;
  /// Only meaningful for LoadCeiling: the ceiling in the envelope's demand unit.
  DeclaredQuantity ceiling{};
  /// Failures whose resolution releases this restriction, in canonical order.
  std::vector<FailureId> released_by;
  PlanId plan;
};

/// One solicitation of a mitigation, and its outcome.
///
/// The attempt records what *this* component asked for and what it observed.
/// Acknowledgement, observed effect and verified effect are three separate
/// fields because they are three separate facts.
struct ResponseAttempt {
  AttemptId id;
  MutationId solicitation;  ///< caller-supplied idempotency key of this solicitation
  AttemptOrdinal attempt;   ///< 1-based attempt ordinal of that key
  ResponseAction action = ResponseAction::ObserveOnly;
  EffectClass effect_class = EffectClass::None;
  AttemptState state = AttemptState::Planned;
  /// Owner the request was addressed to.
  std::string addressee;
  /// Clock at which the request was issued.
  DecisionClock solicited_at{};
  /// Clock at which the addressee answered, when it did.
  DecisionClock acknowledged_at{};
  /// Clock of the last state change.
  DecisionClock updated_at{};
  /// Observation that reports the effect, when one exists.
  ObservationId effect_observation;
  /// The verdict that verified or refuted the effect, when one exists.
  std::string verdict;
  /// True when the attempt was adopted from an unresolved record at restart
  /// rather than created by a live solicitation.
  bool adopted_after_restart = false;
};

/// The response this component decided on for one scope.
struct ResponsePlan {
  PlanId id;
  ScopeId scope;
  PlanLifecycle lifecycle = PlanLifecycle::Unplanned;
  /// Decision clock of the last accepted change to this plan.
  DecisionClock updated_at{};
  /// Failures this plan answers, in canonical order.
  std::vector<FailureId> failures;
  /// Eligible actions, ordered by (rank, action token).
  std::vector<ResponseEligibility> eligible;
  /// The action that was actually solicited, when one was.
  ResponseAction solicited_action = ResponseAction::ObserveOnly;
  bool has_solicited_action = false;
  /// Restrictions in force, in canonical order.
  std::vector<ProtectiveRestriction> restrictions;
  /// Attempts in canonical order (solicitation identity, ordinal).
  std::vector<ResponseAttempt> attempts;
  std::string explanation;
};

// ===========================================================================
// Recovery gates
// ===========================================================================

/// One named proof obligation of a recovery, with its evaluation.
struct RecoveryGateResult {
  RecoveryGate gate = RecoveryGate::EvidenceCurrent;
  bool satisfied = false;
  EvidenceStatus status = EvidenceStatus::Missing;
  /// Canonical explanation of this one gate's outcome.
  std::string detail;
};

/// The evidence a recovery must present before it may be permitted.
struct RecoveryDemand {
  ScopeId scope;
  /// Channels that must be Current for this recovery.
  std::vector<ObservationChannel> required_observations;
  /// Classes that must no longer be Confirmed.
  std::vector<FailureClass> required_cleared_classes;
  /// True when leak evidence must positively report no leak.
  bool require_leak_clear = true;
  /// True when a verified effect is required rather than an acknowledgement.
  bool require_verified_effect = true;
  /// Dwell interval; zero means the scope policy's dwell applies.
  DurationMilliseconds dwell{};
  /// Hysteresis interval; zero means the scope policy's hysteresis applies.
  DurationMilliseconds hysteresis{};
  /// Clock at which the stable interval started, supplied by the caller. An
  /// absent value means the interval has not started and the gate is Deferred.
  DecisionClock stable_since{};
};

/// The recovery verdict for one scope.
struct RecoveryAssessment {
  ScopeId scope;
  RecoveryDecision decision = RecoveryDecision::NotRequested;
  DecisionClock evaluated_at{};
  std::vector<RecoveryGateResult> gates;
  /// Gates that are unsatisfied, in canonical gate order.
  std::vector<RecoveryGate> blocking_gates;
  /// Milliseconds still to wait when the decision is Deferred.
  std::int64_t remaining_dwell_milliseconds = 0;
  BindingStatus binding_status = BindingStatus::Unbound;
  std::string explanation;
};

// ===========================================================================
// Authority binding assessment
// ===========================================================================

/// One binding whose owner has moved on, or that was never supplied.
struct BindingFinding {
  std::string role;
  AuthorityRef bound;
  ExternalGeneration observed{};
  BindingStatus status = BindingStatus::Unbound;
  std::string detail;
};

/// The result of checking a decision's bindings against currently supplied
/// bindings.
struct BindingAssessment {
  BindingStatus status = BindingStatus::Unbound;
  std::vector<BindingFinding> findings;
  std::string explanation;
};

// ===========================================================================
// The decision
// ===========================================================================

/// Authoritative cooling-failure state for one scope, as published.
struct ScopeDecision {
  ScopeId scope;
  /// Decision clock this decision was made at.
  DecisionClock evaluated_at{};
  /// Confirmed and suspected classes, in canonical class order.
  std::vector<FailureClass> confirmed_classes;
  std::vector<FailureClass> suspected_classes;
  /// Classes that were actively contradicted by usable evidence.
  std::vector<FailureClass> contradicted_classes;
  /// Classes whose evidence is missing or unusable, in canonical class order.
  std::vector<FailureClass> unknown_classes;
  Severity severity = Severity::None;
  Urgency urgency = Urgency::Routine;
  TimeToImpact time_to_impact = TimeToImpact::Unobserved;
  /// Failures that justify the classification, in canonical identity order.
  std::vector<FailureId> failures;
  /// Shared upstream scopes implicated, in canonical order.
  std::vector<ScopeId> shared_sources;
  BindingStatus binding_status = BindingStatus::Unbound;
  PlanLifecycle plan_lifecycle = PlanLifecycle::Unplanned;
  /// Plan identity when a plan exists for this scope.
  PlanId plan;
  bool has_plan = false;
  /// Restrictions in force for this scope, in canonical order.
  std::vector<RestrictionId> restrictions;
  RecoveryDecision recovery = RecoveryDecision::NotRequested;
  /// Every channel that is not Current, in canonical channel order. This is the
  /// "what current evidence is required before recovery" answer.
  std::vector<ObservationChannel> evidence_gaps;
  /// Stable machine-readable explanation lines, in canonical order.
  std::vector<std::string> explanation;
};

/// One observation as recorded, with its decision-time status.
struct EvidenceAssessment {
  ObservationId observation;
  ScopeId scope;
  ObservationChannel channel = ObservationChannel::FlowMeter;
  EvidenceStatus status = EvidenceStatus::Missing;
  Freshness freshness = Freshness::Unobserved;
  Availability availability = Availability::Indeterminate;
  ObservationQuality quality = ObservationQuality::Bad;
  std::int64_t age_milliseconds = 0;
  std::string detail;
};

/// The complete published surface of one decision.
struct CoolingFailureState {
  /// Generation this state was published as.
  StateGeneration generation{};
  /// Generation this state was derived from; generation 0 for a first
  /// publication.
  StateGeneration parent_generation{};
  DecisionClock evaluated_at{};
  /// Bindings the decision was made against.
  AuthoritySet bindings;
  std::vector<CoolingScope> scopes;
  std::vector<CoolingFailure> failures;
  std::vector<ResponsePlan> plans;
  /// Evidence records, in canonical (scope, observation identity) order.
  std::vector<EvidenceAssessment> evidence;
  std::vector<ScopeDecision> decisions;
  /// Unresolved attempts that survived a restart, in canonical order. They are
  /// never redispatched automatically.
  std::vector<AttemptId> unresolved_attempts;
};

// ---------------------------------------------------------------------------
// Canonical ordering and lookup helpers
// ---------------------------------------------------------------------------

/// Sorts every table of a state into its canonical order and rejects duplicate
/// identities. Idempotent: sorting an already canonical state changes nothing.
Result<void> canonicalize(CoolingFailureState& state);

const CoolingScope* find_scope(const CoolingFailureState& state, const ScopeId& id) noexcept;
const CoolingFailure* find_failure(const CoolingFailureState& state, const FailureId& id) noexcept;
CoolingFailure* find_failure(CoolingFailureState& state, const FailureId& id) noexcept;
const ResponsePlan* find_plan(const CoolingFailureState& state, const PlanId& id) noexcept;
ResponsePlan* find_plan(CoolingFailureState& state, const PlanId& id) noexcept;
const ResponsePlan* find_plan_for_scope(const CoolingFailureState& state, const ScopeId& scope) noexcept;
const ResponseAttempt* find_attempt(const CoolingFailureState& state, const AttemptId& id) noexcept;
const ScopeDecision* find_decision(const CoolingFailureState& state, const ScopeId& scope) noexcept;

/// Structural validation that does not depend on a decision clock: identities,
/// ordering, referential integrity, bounds and declared-policy shape.
///
/// Validation is deliberately strict. A state that names a scope it does not
/// contain, a plan that answers a failure of another scope, or an attempt that
/// claims a verified effect without an effect observation is rejected rather
/// than repaired.
Result<void> validate_structure(const CoolingFailureState& state);

}  // namespace dccp::cooling_failure_manager

#endif  // DCCP_COOLING_FAILURE_MANAGER_MODEL_HPP
